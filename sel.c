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
#include "ilist.h"

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
    int                    sels_changed;
    int                    fetch_retry_count;
    sel_fetch_handler_t    *fetch_handlers;

    /* A lock, primarily for handling race conditions fetching the data. */
    os_hnd_lock_t *sel_lock;

    os_handler_t *os_hnd;

    ilist_t      *logs;
    unsigned int num_sels;

    ipmi_sel_new_log_handler_cb new_log_handler;
    void                        *new_log_cb_data;
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

static void
free_log(ilist_iter_t *iter, void *item, void *cb_data)
{
    free(item);
}
static void
free_logs(ilist_t *logs)
{
    ilist_iter(logs, free_log, NULL);
}

static int
recid_search_cmp(void *item, void *cb_data)
{
    ipmi_log_t   *log = item;
    unsigned int recid = *((int *) cb_data);

    return log->record_id == recid;
}
static ipmi_log_t *
find_log(ilist_t *list, unsigned int recid)
{
    return ilist_search(list, recid_search_cmp, &recid);
}

static int
log_cmp(ipmi_log_t *log1, ipmi_log_t *log2)
{
    if (log1->record_id > log2->record_id)
	return 1;
    if (log1->record_id < log2->record_id)
	return -1;
    if (log1->type > log2->type)
	return 1;
    if (log1->type < log2->type)
	return -1;
    return memcmp(log1->data, log2->data, 13);
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
    memset(sel, 0, sizeof(*sel));

    sel->logs = alloc_ilist();
    if (!sel->logs) {
	rv = ENOMEM;
	goto out_unlock;
    }

    sel->mc = mc;
    sel->destroyed = 0;
    sel->os_hnd = ipmi_mc_get_os_hnd(mc);
    sel->sel_lock = NULL;
    sel->fetched = 0;
    sel->fetch_state = IDLE;
    sel->num_sels = 0;
    sel->destroy_handler = NULL;
    sel->lun = lun;
    sel->fetch_handlers = NULL;
    sel->new_log_handler = NULL;

    if (sel->os_hnd->create_lock) {
	rv = sel->os_hnd->create_lock(sel->os_hnd, &sel->sel_lock);
	if (rv)
	    goto out_unlock;
    }

 out_unlock:
    if (rv) {
	if (sel) {
	    if (sel->logs)
		free_ilist(sel->logs);
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

    free_logs(sel->logs);
    if (sel->logs)
	free_ilist(sel->logs);

    if (sel->sel_lock)
	sel->os_hnd->destroy_lock(sel->os_hnd, sel->sel_lock);

    /* Do this after we have gotten rid of all external dependencies,
       but before it is free. */
    if (sel->destroy_handler)
	sel->destroy_handler(sel, sel->destroy_cb_data);

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
    int             log_is_new = 0;
    ipmi_log_t      *log;
    ipmi_log_t      del_log;
    unsigned int    record_id;


    if (sel->destroyed) {
	fetch_complete(sel, ECANCELED);
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

    sel->next_rec_id = ipmi_get_uint16(rsp->data+1);

    del_log.record_id = ipmi_get_uint16(rsp->data+3);
    del_log.type = rsp->data[5];
    memcpy(del_log.data, rsp->data+6, 13);

    sel_lock(sel);
    record_id = ipmi_get_uint16(rsp->data+3);
    log = find_log(sel->logs, record_id);
    if (!log) {
	log = malloc(sizeof(*log));
	if (!log) {
	    sel_unlock(sel);
	    fetch_complete(sel, ENOMEM);
	    return;
	}
	if (!ilist_add_tail(sel->logs, log, NULL)) {
	    free(log);
	    sel_unlock(sel);
	    fetch_complete(sel, ENOMEM);
	    return;
	}
	*log = del_log;
	log_is_new = 1;
	sel->num_sels++;
    } else if (log_cmp(&del_log, log) != 0) {
	*log = del_log;
	log_is_new = 1;
    }
    sel_unlock(sel);

    if (sel->next_rec_id == 0xFFFF) {
	fetch_complete(sel, 0);
	goto out;
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

 out:
    if (log_is_new)
	if (sel->new_log_handler)
	    sel->new_log_handler(sel, &del_log, sel->new_log_cb_data);

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
    int             fetched_num_sels;


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
    fetched_num_sels = ipmi_get_uint16(rsp->data+2);
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

    if (fetched_num_sels == 0) {
	/* No sels, so there's nothing to do. */
	fetch_complete(sel, 0);
	return;
    }

    sel->next_rec_id = 0;
    sel->curr_rec_id = 0;

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
sel_handle_reservation(ipmi_mc_t  *mc,
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
	ipmi_log("sel_handle_reservation:"
		 " Failed getting reservation\n");
	fetch_complete(sel, ENOSYS);
    } else if (rsp->data_len < 3) {
	ipmi_log("sel_handle_reservation:"
		 " got invalid reservation length\n");
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

    sel->fetch_state = FETCHING;
    sel->sels_changed = 0;

    if (sel->supports_reserve_sel) {
	/* Get a reservation first. */
	cmd_msg.data = cmd_data;
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_RESERVE_SEL_CMD;
	cmd_msg.data_len = 0;
	return ipmi_send_command(sel->mc, sel->lun, &cmd_msg,
				 sel_handle_reservation, sel);
    } else {
	/* Bypass the reservation, it's not supported. */
	sel->reservation = 0;

	/* Fetch the repository info. */
	cmd_msg.data = cmd_data;
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_GET_SEL_INFO_CMD;
	cmd_msg.data_len = 0;
	return ipmi_send_command(sel->mc, sel->lun,
				 &cmd_msg, handle_sel_info, sel);
    }
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
	/* The SEL is being erased, so by definition the log will be
           gone. */
	rv = 0;
    else if (rsp->data[0])
	rv = IPMI_IPMI_ERR_VAL(rsp->data[0]);

    data->handler(data->sel, data->cb_data, rv);

    free(data);
}

static int
send_del_sel(ipmi_mc_t             *mc,
	     int                   lun,
	     int                   record_id,
	     sel_cb_handler_data_t *data)
{
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;
    
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_DELETE_SEL_ENTRY_CMD;
    cmd_msg.data_len = 4;
    ipmi_set_uint16(cmd_msg.data, 0);
    ipmi_set_uint16(cmd_msg.data+2, record_id);
    rv = ipmi_send_command(mc, lun, &cmd_msg, handle_sel_delete, data);

    return rv;
}

int
ipmi_sel_del_log(ipmi_sel_info_t       *sel,
		 ipmi_log_t            *log,
		 ipmi_sel_op_done_cb_t handler,
		 void                  *cb_data)
{
    int                   rv;
    sel_cb_handler_data_t *data;
    ipmi_log_t            *real_log;
    ilist_iter_t          iter;
    ipmi_mc_t             *mc;
    int                   lun;

    data = malloc(sizeof(*data));
    if (!data)
	return ENOMEM;

    sel_lock(sel);
    if (sel->destroyed) {
	rv = EINVAL;
	goto out_unlock;
    }

    ilist_init_iter(&iter, sel->logs);
    real_log = ilist_search_iter(&iter, recid_search_cmp, &(log->record_id));
    if (!real_log) {
	rv = EINVAL;
	goto out_unlock;
    }

    if (log_cmp(log, real_log) != 0) {
	rv = EINVAL;
	goto out_unlock;
    }

    ilist_delete(&iter);
    sel->num_sels--;

    mc = sel->mc;
    lun = sel->lun;
    sel_unlock(sel);

    ipmi_read_lock();
    if ((rv = ipmi_mc_validate(sel->mc)))
	goto out_unlock2;

    data->sel = sel;
    data->handler = handler;
    data->cb_data = cb_data;

    rv = send_del_sel(mc, lun, log->record_id, data);

 out_unlock2:
    ipmi_read_unlock();

 out:
    if (rv)
	free(data);
    return rv;

 out_unlock:
    sel_unlock(sel);
    goto out;
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
ipmi_sel_get_first_log(ipmi_sel_info_t *sel, ipmi_log_t *log)
{
    ilist_iter_t iter;
    int          rv = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }
    ilist_init_iter(&iter, sel->logs);
    if (ilist_first(&iter))
	*log = *((ipmi_log_t *) ilist_get(&iter));
    else
	rv = ENODEV;
    sel_unlock(sel);
    return rv;
}

int
ipmi_sel_get_last_log(ipmi_sel_info_t *sel, ipmi_log_t *log)
{
    ilist_iter_t iter;
    int          rv = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }
    ilist_init_iter(&iter, sel->logs);
    if (ilist_last(&iter))
	*log = *((ipmi_log_t *) ilist_get(&iter));
    else
	rv = ENODEV;
    sel_unlock(sel);
    return rv;
}

int
ipmi_sel_get_next_log(ipmi_sel_info_t *sel, ipmi_log_t *log)
{
    ilist_iter_t iter;
    int          rv = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }
    ilist_init_iter(&iter, sel->logs);
    if (ilist_search_iter(&iter, recid_search_cmp, &(log->record_id))) {
	if (ilist_next(&iter))
	    *log = *((ipmi_log_t *) ilist_get(&iter));
	else
	    rv = ENODEV;
    } else {
	rv = EINVAL;
    }
    sel_unlock(sel);
    return rv;
}

int
ipmi_sel_get_prev_log(ipmi_sel_info_t *sel, ipmi_log_t *log)
{
    ilist_iter_t iter;
    int          rv = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }
    ilist_init_iter(&iter, sel->logs);
    if (ilist_search_iter(&iter, recid_search_cmp, &(log->record_id))) {
	if (ilist_prev(&iter))
	    *log = *((ipmi_log_t *) ilist_get(&iter));
	else
	    rv = ENODEV;
    } else {
	rv = EINVAL;
    }
    sel_unlock(sel);
    return rv;
}

int ipmi_get_all_sels(ipmi_sel_info_t *sel,
		      int             *array_size,
		      ipmi_log_t      *array)
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
    } else if (sel->num_sels == 0) {
	rv = 0;
    } else {
	ilist_iter_t iter;

	ilist_init_iter(&iter, sel->logs);
	if (! ilist_first(&iter)) {
	    rv = EINVAL;
	    goto out_unlock;
	}
	for (i=0; ; ) {
	    *array = *((ipmi_log_t *) ilist_get(&iter));
	    array++;
	    i++;
	    if (i<sel->num_sels) {
		if (! ilist_next(&iter)) {
		    rv = EINVAL;
		    goto out_unlock;
		}
	    } else
		break;
	}
	*array_size = sel->num_sels;
    }

 out_unlock:
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

int
ipmi_sel_set_new_log_handler(ipmi_sel_info_t             *sel,
			     ipmi_sel_new_log_handler_cb handler,
			     void                        *cb_data)
{
    sel->new_log_handler = handler;
    sel->new_log_cb_data = cb_data;
    return 0;
}

int
ipmi_sel_log_add(ipmi_sel_info_t *sel,
		 ipmi_log_t      *new_log)
{
    int        rv = 0;
    ipmi_log_t *log;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    log = find_log(sel->logs, new_log->record_id);
    if (!log) {
	log = malloc(sizeof(*log));
	if (!log) {
	    rv = ENOMEM;
	    goto out_unlock;
	}
	if (!ilist_add_tail(sel->logs, log, NULL)) {
	    rv = ENOMEM;
	    goto out_unlock;
	}
	*log = *new_log;
	sel->num_sels++;
    } else {
	*log = *new_log;
    }

 out_unlock:
    sel_unlock(sel);
    return rv;
}
