/*
 * ipmi_sel.c
 *
 * MontaVista IPMI code for handling the system event log
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <malloc.h>
#include <string.h>

#include <ipmi/ipmiif.h>
#include <ipmi/ipmi_sel.h>
#include <ipmi/ipmi_msgbits.h>
#include <ipmi/ipmi_mc.h>
#include <ipmi/ipmi_err.h>
#include <ipmi/ipmi_int.h>
#include "opq.h"

#define MAX_SEL_FETCH_RETRIES 10

typedef struct sel_fetch_handler_s
{
    ipmi_sels_fetched_t handler;
    void                *cb_data;

    struct sel_fetch_handler_s *next;
} sel_fetch_handler_t;

enum fetch_state_e { IDLE, FETCHING, HANDLERS };

struct ipmi_sel_info_s
{
    ipmi_mc_t *mc;

    /* LUN we are attached with. */
    int         lun;

    uint8_t  major_version;
    uint8_t  minor_version;
    uint8_t  entries;
    uint32_t last_addition_timestamp;
    uint32_t last_erase_timestamp;
    int      overflow : 1;
    int      supports_delete_sel : 1;
    int      supports_partial_add_sel : 1;
    int      supports_reserve_sel : 1;
    int      supports_get_sel_allocation : 1;

    int      fetched : 1;

    /* Has the SEL been destroyed?  This is here because of race
       conditions in shutdown.  If we are currently in the process of
       fetching SELs, we will allow a destroy operation to complete,
       but we don't actually destroy the data until the SEL fetch
       reaches a point were it can be stopped safely. */
    int      destroyed : 1;
    /* Something to call when the destroy is complete. */
    ipmi_sel_destroyed_t destroy_handler;
    void                 *destroy_cb_data;

    enum fetch_state_e fetch_state;

    /* When fetching the data in event-driven mode, these are the
       variables that track what is going on. */
    int                    curr_rec_id;
    int                    next_rec_id;
    unsigned int           reservation;
    int                    curr_sel_num; /* Current array index. */
    int                    working_num_sels;
    ipmi_sel_t             *working_sels;
    int                    sels_changed;
    int                    fetch_retry_count;
    sel_fetch_handler_t    *fetch_handlers;

    /* A lock, primarily for handling race conditions fetching the data. */
    os_hnd_lock_t *sel_lock;

    os_handler_t *os_hnd;

    ipmi_sel_t *sels;
    int        num_sels;

};

static inline void sel_lock(ipmi_sel_info_t *sel)
{
    if (sel->os_hnd->lock)
	sel->os_hnd->lock(sel->os_hnd, sel->sel_lock);
}

static inline void sel_unlock(ipmi_sel_info_t *sel)
{
    if (sel->os_hnd->lock)
	sel->os_hnd->unlock(sel->os_hnd, sel->sel_lock);
}

int
ipmi_sel_alloc(ipmi_mc_t       *mc,
	       unsigned int    lun,
	       ipmi_sel_info_t **new_sel)
{
    ipmi_sel_info_t *sel = NULL;
    int             rv;

    if (lun >= 4)
	return EINVAL;

    ipmi_read_lock();
    if ((rv = ipmi_mc_validate(mc)))
	goto out_unlock;

    sel = malloc(sizeof(*sel));
    if (!sel) {
	rv = ENOMEM;
	goto out_unlock;
    }

    sel->mc = mc;
    sel->destroyed = 0;
    sel->os_hnd = ipmi_mc_get_os_hnd(mc);
    sel->sel_lock = NULL;
    sel->fetched = 0;
    sel->fetch_state = IDLE;
    sel->sels = NULL;
    sel->num_sels = 0;
    sel->destroy_handler = NULL;
    sel->lun = lun;
    sel->fetch_handlers = NULL;
    sel->working_sels = NULL;

    if (sel->os_hnd->create_lock) {
	rv = sel->os_hnd->create_lock(sel->os_hnd, &sel->sel_lock);
	if (rv)
	    goto out_unlock;
    }

 out_unlock:
    if (rv) {
	if (sel) {
	    if (sel->sel_lock)
		sel->os_hnd->destroy_lock(sel->os_hnd, sel->sel_lock);
	    free(sel);
	}
    } else {
	*new_sel = sel;
    }
    ipmi_read_unlock();
    return rv;
}

static void
internal_destroy_sel(ipmi_sel_info_t *sel)
{
    /* We don't have to have a valid ipmi to destroy an SEL, the are
       designed to live after the ipmi has been destroyed. */
    sel_unlock(sel);

    if (sel->sel_lock)
	sel->os_hnd->destroy_lock(sel->os_hnd, sel->sel_lock);

    /* Do this after we have gotten rid of all external dependencies,
       but before it is free. */
    if (sel->destroy_handler)
	sel->destroy_handler(sel, sel->destroy_cb_data);

    if (sel->sels)
	free(sel->sels);
    free(sel);
}

int
ipmi_sel_destroy(ipmi_sel_info_t      *sel,
		 ipmi_sel_destroyed_t handler,
		 void                 *cb_data)
{
    /* We don't need the read lock, because the sels are stand-alone
       after they are created (except for fetching SELs, of course). */
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }
    sel->destroyed = 1;
    sel->destroy_handler = handler;
    sel->destroy_cb_data = cb_data;
    if (sel->fetch_state != IDLE) {
	/* It's currently in fetch state, so let it be destroyed in
           the handler, since we can't cancel the handler or
           operation. */
	sel_unlock(sel);
	return 0;
    }

    /* This unlocks the lock. */
    internal_destroy_sel(sel);
    return 0;
}

static void
fetch_complete(ipmi_sel_info_t *sel, int err)
{
    sel_fetch_handler_t *elem, *next;

    sel_lock(sel);
    if (err) {
	if (sel->working_sels) {
	    free(sel->working_sels);
	    sel->working_sels = NULL;
	}
    } else {
	sel->num_sels = sel->curr_sel_num;
	sel->sels = sel->working_sels;
    }

    elem = sel->fetch_handlers;
    sel->fetch_handlers = NULL;
    sel->fetched = 1;
    sel->fetch_state = HANDLERS;
    while (elem) {
	next = elem->next;
	elem->next = NULL;
	elem->handler(sel,
		      err,
		      sel->sels_changed,
		      sel->num_sels,
		      elem->cb_data);
	free(elem);
	elem = next;
    }

    if (sel->destroyed) {
	internal_destroy_sel(sel);
	/* Previous call releases lock. */
	return;
    }

    if (sel->fetch_state == HANDLERS)
	/* The fetch process wasn't restarted, so go to IDLE. */
	sel->fetch_state = IDLE;

    sel_unlock(sel);
}

static int start_fetch(ipmi_sel_info_t *sel);

static void
handle_sel_data(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *rsp_data)
{
    ipmi_sel_info_t *sel = (ipmi_sel_info_t *) rsp_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;
    int             curr;


    if (sel->destroyed) {
	fetch_complete(sel, ECANCELED);
	free(sel->working_sels);
	free(sel);
	return;
    }

    if (!mc) {
        fetch_complete(sel, ENXIO);
	return;
    }
	
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* We lost our reservation, restart the operation.  Only do
           this so many times, in order to guarantee that this
           completes. */
	free(sel->working_sels);
	sel->fetch_retry_count++;
	if (sel->fetch_retry_count > MAX_SEL_FETCH_RETRIES) {
	    fetch_complete(sel, EBUSY);
	} else {
	    rv = start_fetch(sel);
	    if (rv)
		fetch_complete(sel, rv);
	}
	return;
    }
    if (rsp->data[0] != 0) {
	fetch_complete(sel, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	return;
    }

    curr = sel->curr_sel_num;

    sel->next_rec_id = ipmi_get_uint16(rsp->data+1);
    sel->working_sels[curr].record_id = ipmi_get_uint16(rsp->data+3);
    sel->working_sels[curr].type = rsp->data[5];
    memcpy(sel->working_sels[curr].data, rsp->data+6, 13);

    sel->curr_sel_num++;
    if (sel->next_rec_id == 0xFFFF) {
	fetch_complete(sel, 0);
	return;
    }
    if (sel->curr_sel_num >= sel->working_num_sels) {
	fetch_complete(sel, EINVAL);
	return;
    }
    sel->curr_rec_id = sel->next_rec_id;

    /* Request some more data. */
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_GET_SEL_ENTRY_CMD;
    cmd_msg.data_len = 6;
    ipmi_set_uint16(cmd_msg.data, sel->reservation);
    ipmi_set_uint16(cmd_msg.data+2, sel->curr_rec_id);
    cmd_msg.data[4] = 0;
    cmd_msg.data[5] = 0xff;
    rv = ipmi_send_command(sel->mc, sel->lun, &cmd_msg, handle_sel_data, sel);
    if (rv)
	    fetch_complete(sel, rv);
}

static void
handle_sel_info(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *rsp_data)
{
    ipmi_sel_info_t *sel = (ipmi_sel_info_t *) rsp_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;
    int32_t         add_timestamp;
    int32_t         erase_timestamp;


    if (sel->destroyed) {
	fetch_complete(sel, ECANCELED);
	free(sel);
	return;
    }

    if (!mc) {
        fetch_complete(sel, ENXIO);
	return;
    }
	
    if (rsp->data[0] != 0) {
	fetch_complete(sel, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	return;
    }

    if (rsp->data_len < 15) {
	fetch_complete(sel, EINVAL);
	return;
    }

    /* Pull pertinant info from the response. */
    sel_lock(sel);
    sel->major_version = rsp->data[1] & 0xf;
    sel->major_version = (rsp->data[1] >> 4) & 0xf;
    sel->working_num_sels = ipmi_get_uint16(rsp->data+2);
    sel->overflow = (rsp->data[14] & 0x80) == 0x80;
    sel->supports_delete_sel = (rsp->data[14] & 0x08) == 0x08;
    sel->supports_partial_add_sel = (rsp->data[14] & 0x04) == 0x04;
    sel->supports_reserve_sel = (rsp->data[14] & 0x02) == 0x02;
    sel->supports_get_sel_allocation = (rsp->data[14] & 0x01) == 0x01;
    sel_unlock(sel);
    
    add_timestamp = ipmi_get_uint32(rsp->data + 6);
    erase_timestamp = ipmi_get_uint32(rsp->data + 10);

    /* If the timestamps still match, no need to re-fetch the repository */
    if (sel->fetched
	&& (add_timestamp == sel->last_addition_timestamp)
	&& (erase_timestamp == sel->last_erase_timestamp))
    {
	fetch_complete(sel, 0);
	return;
    }

    sel->last_addition_timestamp = add_timestamp;
    sel->last_erase_timestamp = erase_timestamp;

    sel->sels_changed = 1;

    if (sel->working_num_sels == 0) {
	/* No sels, so there's nothing to do. */
	if (sel->sels) {
	    free(sel->sels);
	    sel->sels = NULL;
	}
	fetch_complete(sel, 0);
	return;
    }

    sel->working_sels = malloc(sizeof(ipmi_sel_t) * sel->working_num_sels);
    if (!sel->working_sels) {
	fetch_complete(sel, ENOMEM);
	return;
    }

    sel->next_rec_id = 0;
    sel->curr_rec_id = 0;
    sel->curr_sel_num = 0;

    /* Fetch the first SEL entry. */
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_GET_SEL_ENTRY_CMD;
    cmd_msg.data_len = 6;
    ipmi_set_uint16(cmd_msg.data, sel->reservation);
    ipmi_set_uint16(cmd_msg.data+2, sel->curr_rec_id);
    cmd_msg.data[4] = 0;
    cmd_msg.data[5] = 0xff;
    rv = ipmi_send_command(sel->mc, sel->lun, &cmd_msg, handle_sel_data, sel);
    if (rv)
	fetch_complete(sel, rv);
}

static void
handle_reservation(ipmi_mc_t  *mc,
		   ipmi_msg_t *rsp,
		   void       *rsp_data)
{
    ipmi_sel_info_t *sel = (ipmi_sel_info_t *) rsp_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;


    if (sel->destroyed) {
	fetch_complete(sel, ECANCELED);
	free(sel);
	return;
    }

    if (!mc) {
        fetch_complete(sel, ENXIO);
	return;
    }
	
    if (rsp->data[0] != 0) {
	fetch_complete(sel, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	return;
    }
    if (rsp->data_len < 3) {
	fetch_complete(sel, EINVAL);
	return;
    }

    sel->reservation = ipmi_get_uint16(rsp->data+1);

    /* Fetch the repository info. */
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_GET_SEL_INFO_CMD;
    cmd_msg.data_len = 0;
    rv = ipmi_send_command(sel->mc, sel->lun, &cmd_msg, handle_sel_info, sel);
    if (rv)
	fetch_complete(sel, rv);
}

static int
start_fetch(ipmi_sel_info_t *sel)
{
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;

    sel->working_sels = NULL;
    sel->fetch_state = FETCHING;
    sel->sels_changed = 0;

    /* Get a reservation first. */
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_RESERVE_SEL_CMD;
    cmd_msg.data_len = 0;
    return ipmi_send_command(sel->mc, sel->lun, &cmd_msg,
			     handle_reservation, sel);
}

int
ipmi_sel_get(ipmi_sel_info_t     *sel,
	     ipmi_sels_fetched_t handler,
	     void                *cb_data)
{
    sel_fetch_handler_t *elem;
    int                 rv;


    elem = malloc(sizeof(*elem));
    if (!elem) {
	ipmi_log("ipmi_sel_get: could not allocate the sel element\n");
	return ENOMEM;
    }

    elem->handler = handler;
    elem->cb_data = cb_data;

    ipmi_read_lock();
    if ((rv = ipmi_mc_validate(sel->mc))) {
	ipmi_log("ipmi_sel_get: MC is not valid\n");
	goto out_unlock2;
    }

    if (!ipmi_mc_sel_device_support(sel->mc)) {
	ipmi_log("ipmi_sel_get: No support for the system event log\n");
	rv = ENOSYS;
	goto out_unlock2;
    }

    sel_lock(sel);
    if (sel->fetch_state != FETCHING) {
	/* If we are not currently fetching sels, then start the
	   process.  If we are already fetching sels, then the current
	   fetch process will handle it. */
	sel->fetch_retry_count = 0;
	rv = start_fetch(sel);
	if (rv)
	    goto out_unlock;
    }

    /* Add it to the list of waiting fetch handlers. */
    elem->next = sel->fetch_handlers;
    sel->fetch_handlers = elem;

 out_unlock:
    sel_unlock(sel);
 out_unlock2:
    ipmi_read_unlock();
    if (rv)
	free(elem);
    return rv;
}



typedef struct sel_cb_handler_data_s
{
    ipmi_sel_info_t       *sel;
    ipmi_sel_op_done_cb_t handler;
    void                  *cb_data;
} sel_cb_handler_data_t;

static void
handle_sel_delete(ipmi_mc_t  *mc,
		  ipmi_msg_t *rsp,
		  void       *rsp_data)
{
    sel_cb_handler_data_t *data = (sel_cb_handler_data_t *) rsp_data;
    int                   rv = 0;
    
    if (data->sel->destroyed) {
	free(data);
	return;
    }

    /* Special return codes. */
    if (rsp->data[0] == 0x80)
	rv = ENOSYS;
    else if (rsp->data[0] == 0x81)
	rv = EBUSY;
    else if (rsp->data[0])
	rv = IPMI_IPMI_ERR_VAL(rsp->data[0]);

    data->handler(data->sel, data->cb_data, rv);

    free(data);
}

static int
del_sel(ipmi_mc_t             *mc,
	ipmi_sel_info_t       *sel,
	int                   index,
	sel_cb_handler_data_t *data)
{
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;
    
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_DELETE_SEL_ENTRY_CMD;
    cmd_msg.data_len = 4;
    ipmi_set_uint16(cmd_msg.data, sel->reservation);
    ipmi_set_uint16(cmd_msg.data+2, sel->sels[index].record_id);
    rv = ipmi_send_command(sel->mc, sel->lun, &cmd_msg, handle_sel_delete, data);

    return rv;
}

int
ipmi_sel_delete_by_recid(ipmi_sel_info_t       *sel,
			 unsigned int          recid,
			 ipmi_sel_op_done_cb_t handler,
			 void                  *cb_data)
{
    int                   rv;
    sel_cb_handler_data_t *data;
    int                   i;


    data = malloc(sizeof(*data));
    if (!data)
	return ENOMEM;

    data->sel = sel;
    data->handler = handler;
    data->cb_data = cb_data;

    ipmi_read_lock();
    if ((rv = ipmi_mc_validate(sel->mc)))
	goto out_unlock2;

    sel_lock(sel);
    if (sel->destroyed) {
	rv = EINVAL;
	goto out_unlock;
    }

    rv = EINVAL;
    for (i=0; i<sel->num_sels; i++) {
	if (sel->sels[i].record_id == recid) {
	    rv = 0;
	    break;
	}
    }

    if (rv)
	goto out_unlock;

    rv = del_sel(sel->mc, sel, i, data);

 out_unlock:
    sel_unlock(sel);
 out_unlock2:
    if (rv)
	free(data);
    ipmi_read_unlock();
    return rv;
}

int
ipmi_sel_delete_by_index(ipmi_sel_info_t       *sel,
			 int                   index,
			 ipmi_sel_op_done_cb_t handler,
			 void                  *cb_data)
{
    int                   rv;
    sel_cb_handler_data_t *data;


    data = malloc(sizeof(*data));
    if (!data)
	return ENOMEM;

    data->sel = sel;
    data->handler = handler;
    data->cb_data = cb_data;

    ipmi_read_lock();
    if ((rv = ipmi_mc_validate(sel->mc)))
	goto out_unlock2;

    sel_lock(sel);
    if (sel->destroyed) {
	rv = EINVAL;
	goto out_unlock;
    }

    if (index >= sel->num_sels) {
	rv = EINVAL;
	goto out_unlock;
    }

    rv = del_sel(sel->mc, sel, index, data);

 out_unlock:
    sel_unlock(sel);
 out_unlock2:
    if (rv)
	free(data);
    ipmi_read_unlock();
    return rv;
}

int
ipmi_get_sel_count(ipmi_sel_info_t *sel,
		   unsigned int    *count)
{
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *count = sel->num_sels;

    sel_unlock(sel);
    return 0;
}

int
ipmi_get_sel_by_recid(ipmi_sel_info_t *sel,
		      unsigned int    recid,
		      ipmi_sel_t      *return_sel)
{
    int i;
    int rv = ENOENT;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    for (i=0; i<sel->num_sels; i++) {
	if (sel->sels[i].record_id == recid) {
	    rv = 0;
	    *return_sel = sel->sels[i];
	    break;
	}
    }

    sel_unlock(sel);
    return rv;
}

int
ipmi_get_sel_by_type(ipmi_sel_info_t *sel,
		     int             type,
		     ipmi_sel_t      *return_sel)
{
    int i;
    int rv = ENOENT;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    for (i=0; i<sel->num_sels; i++) {
	if (sel->sels[i].type == type) {
	    rv = 0;
	    *return_sel = sel->sels[i];
	    break;
	}
    }

    sel_unlock(sel);
    return rv;
}

int ipmi_get_sel_by_index(ipmi_sel_info_t *sel,
			  int             index,
			  ipmi_sel_t      *return_sel)
{
    int rv = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    if (index >= sel->num_sels)
	rv = ENOENT;
    else
	*return_sel = sel->sels[index];

    sel_unlock(sel);
    return rv;
}

int ipmi_get_all_sels(ipmi_sel_info_t *sel,
		      int             *array_size,
		      ipmi_sel_t      *array)
{
    int i;
    int rv = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    if (*array_size < sel->num_sels) {
	rv = E2BIG;
    } else {
	for (i=0; i<sel->num_sels; i++) {
	    *array = sel->sels[i];
	    array++;
	}
	*array_size = sel->num_sels;
    }

    sel_unlock(sel);
    return rv;
}

int
ipmi_sel_get_major_version(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);

    *val = sel->major_version;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_minor_version(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);

    *val = sel->minor_version;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_overflow(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);

    *val = sel->overflow;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_supports_delete_sel(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);

    *val = sel->supports_delete_sel;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_supports_partial_add_sel(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);

    *val = sel->supports_partial_add_sel;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_supports_reserve_sel(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);

    *val = sel->supports_reserve_sel;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_supports_get_sel_allocation(ipmi_sel_info_t *sel,
					 int             *val)
{
    sel_lock(sel);

    *val = sel->supports_get_sel_allocation;

    sel_unlock(sel);
    return 0;
}
