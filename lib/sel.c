/*
 * sel.c
 *
 * MontaVista IPMI code for handling the system event log
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
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

#include <string.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_sel.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/opq.h>
#include <OpenIPMI/ilist.h>

#define MAX_SEL_FETCH_RETRIES 10

typedef struct sel_fetch_handler_s
{
    ipmi_sel_info_t     *sel;
    ipmi_sels_fetched_t handler;
    void                *cb_data;
    int                 rv;

    struct sel_fetch_handler_s *next;
} sel_fetch_handler_t;

/* Holds an event in the list of events. */
typedef struct sel_event_holder_s
{
    int          deleted;
    ipmi_event_t event;
} sel_event_holder_t;

struct ipmi_sel_info_s
{
    ipmi_mcid_t mc;

    /* LUN we are attached with. */
    int         lun;

    uint8_t  major_version;
    uint8_t  minor_version;
    uint8_t  entries;
    uint32_t last_addition_timestamp;
    uint32_t last_erase_timestamp;
    unsigned int overflow : 1;
    unsigned int supports_delete_sel : 1;
    unsigned int supports_partial_add_sel : 1;
    unsigned int supports_reserve_sel : 1;
    unsigned int supports_get_sel_allocation : 1;

    unsigned int fetched : 1;

    /* Has the SEL been destroyed?  This is here because of race
       conditions in shutdown.  If we are currently in the process of
       fetching SELs, we will allow a destroy operation to complete,
       but we don't actually destroy the data until the SEL fetch
       reaches a point were it can be stopped safely. */
    unsigned int destroyed : 1;
    unsigned int in_destroy : 1;

    /* Is a fetch in the queue or currently running? */
    unsigned int in_fetch : 1;

    /* Something to call when the destroy is complete. */
    ipmi_sel_destroyed_t destroy_handler;
    void                 *destroy_cb_data;


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

    /* This is the actual list of events and the number of non-deleted
       events and the number of deleted events.  Note that events may
       contain more items than num_sels, num_sels only counts the
       number of non-deleted events in the list.  del_sels+num_sels
       should be the number of events. */
    ilist_t      *events;
    unsigned int num_sels;
    unsigned int del_sels;

    /* We serialize operations through here, since we are dealing with
       a locked resource. */
    opq_t *opq;

    ipmi_sel_new_event_handler_cb new_event_handler;
    void                          *new_event_cb_data;
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
free_event(ilist_iter_t *iter, void *item, void *cb_data)
{
    ipmi_mem_free(item);
}
static void
free_events(ilist_t *events)
{
    ilist_iter(events, free_event, NULL);
}

static int
recid_search_cmp(void *item, void *cb_data)
{
    sel_event_holder_t *holder = item;
    unsigned int       recid = *((int *) cb_data);

    return holder->event.record_id == recid;
}
static sel_event_holder_t *
find_event(ilist_t *list, unsigned int recid)
{
    return ilist_search(list, recid_search_cmp, &recid);
}

static int
event_cmp(ipmi_event_t *event1, ipmi_event_t *event2)
{
    int rv;

    rv = ipmi_cmp_mc_id(event1->mcid, event2->mcid);
    if (rv)
	return rv;
    if (event1->record_id > event2->record_id)
	return 1;
    if (event1->record_id < event2->record_id)
	return -1;
    if (event1->type > event2->type)
	return 1;
    if (event1->type < event2->type)
	return -1;
    return memcmp(event1->data, event2->data, 13);
}

int
ipmi_sel_alloc(ipmi_mc_t       *mc,
	       unsigned int    lun,
	       ipmi_sel_info_t **new_sel)
{
    ipmi_sel_info_t *sel = NULL;
    int             rv = 0;
    ipmi_domain_t   *domain;

    CHECK_MC_LOCK(mc);

    domain = ipmi_mc_get_domain(mc);

    if (lun >= 4)
	return EINVAL;

    sel = ipmi_mem_alloc(sizeof(*sel));
    if (!sel) {
	rv = ENOMEM;
	goto out;
    }
    memset(sel, 0, sizeof(*sel));

    sel->events = alloc_ilist();
    if (!sel->events) {
	rv = ENOMEM;
	goto out;
    }

    sel->mc = ipmi_mc_convert_to_id(mc);
    sel->destroyed = 0;
    sel->in_destroy = 0;
    sel->os_hnd = ipmi_domain_get_os_hnd(domain);
    sel->sel_lock = NULL;
    sel->fetched = 0;
    sel->in_fetch = 0;
    sel->num_sels = 0;
    sel->del_sels = 0;
    sel->destroy_handler = NULL;
    sel->lun = lun;
    sel->fetch_handlers = NULL;
    sel->new_event_handler = NULL;

    sel->opq = opq_alloc(sel->os_hnd);
    if (!sel->opq) {
	rv = ENOMEM;
	goto out;
    }

    if (sel->os_hnd->create_lock) {
	rv = sel->os_hnd->create_lock(sel->os_hnd, &sel->sel_lock);
	if (rv)
	    goto out;
    }

 out:
    if (rv) {
	if (sel) {
	    if (sel->events)
		free_ilist(sel->events);
	    if (sel->opq)
		opq_destroy(sel->opq);
	    if (sel->sel_lock)
		sel->os_hnd->destroy_lock(sel->os_hnd, sel->sel_lock);
	    ipmi_mem_free(sel);
	}
    } else {
	*new_sel = sel;
    }
    return rv;
}

static void
internal_destroy_sel(ipmi_sel_info_t *sel)
{
    sel->in_destroy = 1;

    /* We don't have to have a valid ipmi to destroy an SEL, the are
       designed to live after the ipmi has been destroyed. */
    sel_unlock(sel);

    free_events(sel->events);
    if (sel->events)
	free_ilist(sel->events);

    if (sel->opq)
	opq_destroy(sel->opq);

    if (sel->sel_lock)
	sel->os_hnd->destroy_lock(sel->os_hnd, sel->sel_lock);

    /* Do this after we have gotten rid of all external dependencies,
       but before it is free. */
    if (sel->destroy_handler)
	sel->destroy_handler(sel, sel->destroy_cb_data);

    ipmi_mem_free(sel);
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
    if (opq_stuff_in_progress(sel->opq)) {
	/* It's currently doing something with callbacks, so let it be
           destroyed in the handler, since we can't cancel the handler
           or operation. */
	sel_unlock(sel);
	return 0;
    }

    /* This unlocks the lock. */
    internal_destroy_sel(sel);
    return 0;
}

/* This should be called with the sel locked.  It will unlock the sel
   before returning. */
static void
fetch_complete(ipmi_sel_info_t *sel, int err)
{
    sel_fetch_handler_t *elem, *next;

    if (sel->in_destroy)
	goto out;

    elem = sel->fetch_handlers;
    sel->fetch_handlers = NULL;
    sel->fetched = 1;
    sel->in_fetch = 0;
    while (elem) {
	next = elem->next;
	elem->next = NULL;
	if (elem->handler)
	    elem->handler(sel,
		          err,
		          sel->sels_changed,
		          sel->num_sels,
		          elem->cb_data);
	ipmi_mem_free(elem);
	elem = next;
    }

    if (sel->destroyed) {
	internal_destroy_sel(sel);
	/* Previous call releases lock. */
	return;
    }

    opq_op_done(sel->opq);

 out:
    sel_unlock(sel);
}

static void
free_deleted_event(ilist_iter_t *iter, void *item, void *cb_data)
{
    sel_event_holder_t *holder = item;

    if (holder->deleted) {
	ilist_delete(iter);
	ipmi_mem_free(holder);
    }
}
static void
free_deleted_events(ilist_t *events)
{
    ilist_iter(events, free_deleted_event, NULL);
}

static void
handle_sel_clear(ipmi_mc_t  *mc,
		 ipmi_msg_t *rsp,
		 void       *rsp_data)
{
    sel_fetch_handler_t *elem = rsp_data;
    ipmi_sel_info_t     *sel = elem->sel;

    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SEL info was destroyed while an operation was in"
		 " progress(1)");
	fetch_complete(sel, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SEL op was in progress");
        fetch_complete(sel, ENXIO);
	goto out;
    }

    if (rsp->data[0] == 0) {
	/* Success!  We can free the data. */
	free_deleted_events(sel->events);
	sel->del_sels = 0;
    }

    fetch_complete(sel, 0);
 out:
    return;
}

static int
send_sel_clear(sel_fetch_handler_t *elem, ipmi_mc_t *mc)
{
    ipmi_sel_info_t *sel = elem->sel;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_CLEAR_SEL_CMD;
    cmd_msg.data_len = 6;
    ipmi_set_uint16(cmd_msg.data, sel->reservation);
    cmd_msg.data[2] = 'C';
    cmd_msg.data[3] = 'L';
    cmd_msg.data[4] = 'R';
    cmd_msg.data[5] = 0xaa;

    return ipmi_mc_send_command(mc, sel->lun, &cmd_msg,
				handle_sel_clear, elem);
}

static void start_fetch(void *cb_data, int shutdown);

static void
handle_sel_data(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *rsp_data)
{
    sel_fetch_handler_t *elem = rsp_data;
    ipmi_sel_info_t     *sel = elem->sel;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;
    int                 event_is_new = 0;
    sel_event_holder_t  *holder;
    ipmi_event_t        del_event;
    unsigned int        record_id;


    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SEL info was destroyed while an operation was in"
		 " progress(2)");
	fetch_complete(sel, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_data: MC went away while SEL op was in progress");
        fetch_complete(sel, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* We lost our reservation, restart the operation.  Only do
           this so many times, in order to guarantee that this
           completes. */
	sel->fetch_retry_count++;
	if (sel->fetch_retry_count > MAX_SEL_FETCH_RETRIES) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "handle_sel_data: "
		     "Too many lost reservations in SEL fetch");
	    fetch_complete(sel, EBUSY);
	    goto out;
	} else {
	    start_fetch(elem, 0);
	    goto out_unlock;
	}
    }
    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_data: IPMI error from SEL fetch: %x",
		 rsp->data[0]);
	fetch_complete(sel, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    sel->next_rec_id = ipmi_get_uint16(rsp->data+1);

    del_event.mcid = ipmi_mc_convert_to_id(mc);
    del_event.record_id = ipmi_get_uint16(rsp->data+3);
    del_event.type = rsp->data[5];
    memcpy(del_event.data, rsp->data+6, 13);

    record_id = ipmi_get_uint16(rsp->data+3);
    holder = find_event(sel->events, record_id);
    if (!holder) {
	holder = ipmi_mem_alloc(sizeof(*holder));
	if (!holder) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "handle_sel_data: "
		     "Could not allocate log information for SEL");
	    fetch_complete(sel, ENOMEM);
	    goto out;
	}
	if (!ilist_add_tail(sel->events, holder, NULL)) {
	    ipmi_mem_free(holder);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "handle_sel_data: "
		     "Could not link log onto the log linked list");
	    fetch_complete(sel, ENOMEM);
	    goto out;
	}
	holder->event = del_event;
	holder->deleted = 0;
	event_is_new = 1;
	sel->num_sels++;
    } else if (event_cmp(&del_event, &(holder->event)) != 0) {
	/* It's a new event in an old slot, so overwrite the old
           event. */
	holder->event = del_event;
	if (holder->deleted) {
	    holder->deleted = 0;
	    sel->num_sels++;
	    sel->del_sels--;
	}
	event_is_new = 1;
    }

    if (sel->next_rec_id == 0xFFFF) {
	/* To avoid confusion, deliver the event before we deliver fetch
           complete. */
	if (event_is_new)
	    if (sel->new_event_handler)
		sel->new_event_handler(sel,
				       mc,
				       &del_event,
				       sel->new_event_cb_data);
	/* If the operation completed successfully and everything in
	   our SEL is deleted, then clear it with our old
	   reservation. */
	if ((sel->num_sels == 0) && (!ilist_empty(sel->events))) {
	    /* We don't care if this fails, because it will just
	       happen again later if it does. */
	    rv = send_sel_clear(elem, mc);
	    if (rv) {
		fetch_complete(sel, 0);
		goto out;
	    }
	    rv = 0;
	    goto out_unlock;
	} else {
	    fetch_complete(sel, 0);
	    goto out;
	}
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
    rv = ipmi_mc_send_command(mc, sel->lun, &cmd_msg, handle_sel_data, elem);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_data: Could not send SEL fetch command: %x", rv);
	fetch_complete(sel, rv);
	goto out;
    }

    if (event_is_new)
	if (sel->new_event_handler)
	    sel->new_event_handler(sel, mc, &del_event, sel->new_event_cb_data);
 out_unlock:
    sel_unlock(sel);
 out:
    return;
}

static void
handle_sel_info(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *rsp_data)
{
    sel_fetch_handler_t *elem = rsp_data;
    ipmi_sel_info_t     *sel = elem->sel;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;
    int32_t             add_timestamp;
    int32_t             erase_timestamp;
    int                 fetched_num_sels;

    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_info: "
		 "SEL info was destroyed while an operation was in progress");
	fetch_complete(sel, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_info: MC went away while SEL op was in progress");
        fetch_complete(sel, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_info: IPMI error from SEL info fetch: %x",
		 rsp->data[0]);
	fetch_complete(sel, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    if (rsp->data_len < 15) {
	ipmi_log(IPMI_LOG_ERR_INFO, "handle_sel_info: SEL info too short");
	fetch_complete(sel, EINVAL);
	goto out;
    }

    /* Pull pertinant info from the response. */
    sel->major_version = rsp->data[1] & 0xf;
    sel->minor_version = (rsp->data[1] >> 4) & 0xf;
    fetched_num_sels = ipmi_get_uint16(rsp->data+2);
    sel->overflow = (rsp->data[14] & 0x80) == 0x80;
    sel->supports_delete_sel = (rsp->data[14] & 0x08) == 0x08;
    sel->supports_partial_add_sel = (rsp->data[14] & 0x04) == 0x04;
    sel->supports_reserve_sel = (rsp->data[14] & 0x02) == 0x02;
    sel->supports_get_sel_allocation = (rsp->data[14] & 0x01) == 0x01;
    
    add_timestamp = ipmi_get_uint32(rsp->data + 6);
    erase_timestamp = ipmi_get_uint32(rsp->data + 10);

    /* If the timestamps still match, no need to re-fetch the repository */
    if (sel->fetched
	&& (add_timestamp == sel->last_addition_timestamp)
	&& (erase_timestamp == sel->last_erase_timestamp))
    {
	/* If the operation completed successfully and everything in
	   our SEL is deleted, then clear it with our old
	   reservation. */
	if ((sel->num_sels == 0) && (!ilist_empty(sel->events))) {
	    /* We don't care if this fails, because it will just
	       happen again later if it does. */
	    rv = send_sel_clear(elem, mc);
	    if (rv) {
		fetch_complete(sel, 0);
		goto out;
	    }
	    goto out_unlock;
	} else {
	    fetch_complete(sel, 0);
	    goto out;
	}
    }

    sel->last_addition_timestamp = add_timestamp;
    sel->last_erase_timestamp = erase_timestamp;

    sel->sels_changed = 1;

    if (fetched_num_sels == 0) {
	/* No sels, so there's nothing to do. */
	fetch_complete(sel, 0);
	goto out;
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
    rv = ipmi_mc_send_command(mc, sel->lun, &cmd_msg, handle_sel_data, elem);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_info: Could not send first SEL fetch command: %x",
		 rv);
	fetch_complete(sel, rv);
	goto out;
    }
 out_unlock:
    sel_unlock(sel);
 out:
    return;
}

static void
sel_handle_reservation(ipmi_mc_t  *mc,
		       ipmi_msg_t *rsp,
		       void       *rsp_data)
{
    sel_fetch_handler_t *elem = rsp_data;
    ipmi_sel_info_t     *sel = elem->sel;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;

    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel_handle_reservation: "
		 "SEL info was destroyed while an operation was in progress");
	fetch_complete(sel, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel_handle_reservation: "
		 "MC went away while SEL op was in progress");
        fetch_complete(sel, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel_handle_reservation: Failed getting reservation");
	fetch_complete(sel, ENOSYS);
	goto out;
    } else if (rsp->data_len < 3) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel_handle_reservation: got invalid reservation length");
	fetch_complete(sel, EINVAL);
	goto out;
    }

    sel->reservation = ipmi_get_uint16(rsp->data+1);

    /* Fetch the repository info. */
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_GET_SEL_INFO_CMD;
    cmd_msg.data_len = 0;
    rv = ipmi_mc_send_command(mc, sel->lun, &cmd_msg, handle_sel_info, elem);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel_handle_reservation: "
		 "Could not send SEL info command: %x", rv);
	fetch_complete(sel, rv);
	goto out;
    }
    sel_unlock(sel);
 out:
    return;
}

static void
start_fetch_cb(ipmi_mc_t *mc, void *cb_data)
{
    sel_fetch_handler_t *elem = cb_data;
    ipmi_sel_info_t     *sel = elem->sel;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;

    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_fetch: "
		 "SEL info was destroyed while an operation was in progress");
	fetch_complete(sel, ECANCELED);
	goto out;
    }

    if (sel->supports_reserve_sel) {
	/* Get a reservation first. */
	cmd_msg.data = cmd_data;
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_RESERVE_SEL_CMD;
	cmd_msg.data_len = 0;
	rv = ipmi_mc_send_command(mc, sel->lun, &cmd_msg,
				  sel_handle_reservation, elem);
    } else {
	/* Bypass the reservation, it's not supported. */
	sel->reservation = 0;

	/* Fetch the repository info. */
	cmd_msg.data = cmd_data;
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_GET_SEL_INFO_CMD;
	cmd_msg.data_len = 0;
	rv = ipmi_mc_send_command(mc, sel->lun,
				  &cmd_msg, handle_sel_info, elem);
    }

    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_fetch: could not send cmd: %x",
		 rv);
	fetch_complete(sel, ECANCELED);
	goto out;
    }

    sel_unlock(sel);
 out:
    return;
}

static void
start_fetch(void *cb_data, int shutdown)
{
    sel_fetch_handler_t *elem = cb_data;
    int                 rv;

    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_fetch: "
		 "SEL info was destroyed while an operation was in progress");
	sel_lock(elem->sel);
	fetch_complete(elem->sel, ECANCELED);
	return;
    }

    /* The read lock must be claimed before the sel lock to avoid
       deadlock. */
    rv = ipmi_mc_pointer_cb(elem->sel->mc, start_fetch_cb, elem);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO, "start_fetch: MC is not valid");
	sel_lock(elem->sel);
	fetch_complete(elem->sel, rv);
    }
}

static void
ipmi_sel_get_cb(ipmi_mc_t *mc, void *cb_data)
{
    sel_fetch_handler_t *elem = cb_data;
    ipmi_sel_info_t     *sel = elem->sel;

    if (!ipmi_mc_sel_device_support(mc)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_sel_get: No support for the system event log");
	elem->rv = ENOSYS;
	return;
    }

    sel_lock(sel);
    if (! sel->in_fetch) {
	/* If we are not currently fetching sels, then start the
	   process.  If we are already fetching sels, then the current
	   fetch process will handle it. */
	sel->fetch_retry_count = 0;
	sel->in_fetch = 1;
	sel->sels_changed = 0;

	if (!opq_new_op(sel->opq, start_fetch, elem, 0)) {
	    elem->rv = ENOMEM;
	    goto out_unlock;
	}
	elem->next = NULL;
	sel->fetch_handlers = elem;
    } else if (elem->handler) {
	/* Add it to the list of waiting fetch handlers, if it has a
	   handler. */
	elem->next = sel->fetch_handlers;
	sel->fetch_handlers = elem;
    } else {
	elem->rv = EEXIST;
    }

 out_unlock:
    sel_unlock(sel);
}

int
ipmi_sel_get(ipmi_sel_info_t     *sel,
	     ipmi_sels_fetched_t handler,
	     void                *cb_data)
{
    sel_fetch_handler_t *elem;
    int                 rv;

    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_sel_get: could not allocate the sel element");
	return ENOMEM;
    }

    elem->handler = handler;
    elem->cb_data = cb_data;
    elem->sel = sel;
    elem->rv = 0;

    rv = ipmi_mc_pointer_cb(sel->mc, ipmi_sel_get_cb, elem);
    if (!rv)
	rv = elem->rv;
    if (rv)
	ipmi_mem_free(elem);
    if (rv == EEXIST)
	/* EEXIST means that a operation was already running, and no
	   handler was given.  We want to free the element, but we
	   still want to return success. */
	rv = 0;

    return rv;
}

/* Don't do this forever. */
#define MAX_DEL_RESERVE_RETRIES		10

typedef struct sel_cb_handler_data_s
{
    ipmi_sel_info_t       *sel;
    ipmi_sel_op_done_cb_t handler;
    void                  *cb_data;
    unsigned int          reservation;
    unsigned int          record_id;
    unsigned int          lun;
    unsigned int          count;
    ipmi_event_t          event;
} sel_cb_handler_data_t;

static int send_reserve_sel(sel_cb_handler_data_t *data, ipmi_mc_t *mc);

static void
sel_op_done(sel_cb_handler_data_t *data,
	    int                   rv)
{
    ipmi_sel_info_t *sel = data->sel;

    if (data->handler)
	data->handler(sel, data->cb_data, rv);

    if (sel->in_destroy) {
	/* Nothing to do */
	sel_unlock(sel);
    } else if (sel->destroyed) {
	/* This will unlock the lock. */
	internal_destroy_sel(sel);
    } else {
	opq_op_done(sel->opq);
	sel_unlock(sel);
    }
    ipmi_mem_free(data);
}

static void
handle_sel_delete(ipmi_mc_t  *mc,
		  ipmi_msg_t *rsp,
		  void       *rsp_data)
{
    sel_cb_handler_data_t *data = (sel_cb_handler_data_t *) rsp_data;
    ipmi_sel_info_t       *sel = data->sel;
    int                   rv = 0;
    
    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_delete: "
		 "SEL info was destroyed while an operation was in progress");
	sel_op_done(data, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_delete: "
		 "MC went away while SEL fetch was in progress");
	sel_op_done(data, ENXIO);
	goto out;
    }

    /* Special return codes. */
    if (rsp->data[0] == 0x80) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_delete: Operation not supported on SEL delete");
	rv = ENOSYS;
    } else if (rsp->data[0] == 0x81) {
	/* The SEL is being erased, so by definition the log will be
           gone. */
	rv = 0;
    } else if (rsp->data[0] == IPMI_NOT_PRESENT_CC) {
	/* The entry is already gone, so just return no error. */
	rv = 0;
    } else if ((data->count < MAX_DEL_RESERVE_RETRIES)
	       && (rsp->data[0] == IPMI_INVALID_RESERVATION_CC))
    {
	/* Lost our reservation, retry the operation. */
	data->count++;
	rv = send_reserve_sel(data, mc);
	if (!rv)
	    goto out_unlock;
    } else if (rsp->data[0]) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_delete: "
		 "IPMI error from SEL delete: %x", rsp->data[0]);
	rv = IPMI_IPMI_ERR_VAL(rsp->data[0]);
    } else {
	/* We deleted the entry, so remove it from our database. */
	sel_event_holder_t *real_holder;
	ilist_iter_t       iter;

	ilist_init_iter(&iter, sel->events);
	ilist_unpositioned(&iter);
	real_holder = ilist_search_iter(&iter, recid_search_cmp,
					&(data->record_id));
	if (real_holder) {
	    ilist_delete(&iter);
	    ipmi_mem_free(real_holder);
	    sel->del_sels--;
	}
    }

    sel_op_done(data, rv);

 out:
    return;

 out_unlock:
    sel_unlock(sel);
}

static int
send_del_sel(sel_cb_handler_data_t *data, ipmi_mc_t *mc)
{
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;
    
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_DELETE_SEL_ENTRY_CMD;
    cmd_msg.data_len = 4;
    ipmi_set_uint16(cmd_msg.data, data->reservation);
    ipmi_set_uint16(cmd_msg.data+2, data->record_id);
    rv = ipmi_mc_send_command(mc, data->lun,
			      &cmd_msg, handle_sel_delete, data);

    return rv;
}

static void
handle_sel_check(ipmi_mc_t  *mc,
		 ipmi_msg_t *rsp,
		 void       *rsp_data)
{
    sel_cb_handler_data_t *data = (sel_cb_handler_data_t *) rsp_data;
    ipmi_sel_info_t       *sel = data->sel;
    int                   rv = 0;
    
    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_check: "
		 "SEL info was destroyed while an operation was in progress");
	sel_op_done(data, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_check: "
		 "MC went away while SEL fetch was in progress");
	sel_op_done(data, ENXIO);
	goto out;
    }

    /* Special return codes. */
    if (rsp->data[0] == IPMI_NOT_PRESENT_CC) {
	/* The entry is already gone, so just return no error. */
	sel_op_done(data, 0);
	goto out;
    } else if (rsp->data[0]) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sel_check: IPMI error from SEL get: %x",
		 rsp->data[0]);
	sel_op_done(data, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    } else {
	ipmi_event_t ch_event;

	ch_event.mcid = ipmi_mc_convert_to_id(mc);
	ch_event.record_id = ipmi_get_uint16(rsp->data+3);
	ch_event.type = rsp->data[5];
	memcpy(ch_event.data, rsp->data+6, 13);

	if (event_cmp(&ch_event, &(data->event)) != 0) {
	    /* The event's don't match, so just finish. */
	    sel_op_done(data, 0);
	    goto out;
	}

	rv = send_del_sel(data, mc);
	if (rv) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "Could not send SEL delete command: %x", rv);
	    sel_op_done(data, rv);
	    goto out;
	}
    }

    sel_unlock(sel);

 out:
    return;
}

/* First get the entry, to make sure we are deleting the right one. */
static int
send_check_sel(sel_cb_handler_data_t *data, ipmi_mc_t *mc)
{
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;
    
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_GET_SEL_ENTRY_CMD;
    cmd_msg.data_len = 6;
    ipmi_set_uint16(cmd_msg.data, 0);
    ipmi_set_uint16(cmd_msg.data+2, data->record_id);
    cmd_msg.data[4] = 0;
    cmd_msg.data[5] = 0xff;
    rv = ipmi_mc_send_command(mc, data->lun,
			      &cmd_msg, handle_sel_check, data);

    return rv;
}

static void
sel_reserved_for_delete(ipmi_mc_t  *mc,
			ipmi_msg_t *rsp,
			void       *rsp_data)
{
    sel_cb_handler_data_t *data = rsp_data;
    ipmi_sel_info_t       *sel = data->sel;
    int                   rv;

    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel_reserved_for_delete: "
		 "SEL info was destroyed while an operation was in progress");
	sel_op_done(data, ECANCELED);
	goto out;
    }
    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SEL fetch was in progress");
	sel_op_done(data, ENXIO);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "IPMI error from SEL delete reservation: %x", rsp->data[0]);
	sel_op_done(data, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    data->reservation = ipmi_get_uint16(rsp->data+1);
    rv = send_check_sel(data, mc);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Could not send SEL get command: %x", rv);
	sel_op_done(data, rv);
	goto out;
    }

    sel_unlock(sel);
 out:
    return;
}

static int
send_reserve_sel(sel_cb_handler_data_t *data, ipmi_mc_t *mc)
{
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_RESERVE_SEL_CMD;
    cmd_msg.data_len = 0;
    rv = ipmi_mc_send_command(mc, data->lun,
			      &cmd_msg, sel_reserved_for_delete, data);

    return rv;
}

static void
start_del_sel_cb(ipmi_mc_t *mc, void *cb_data)
{
    sel_cb_handler_data_t *data = cb_data;
    ipmi_sel_info_t       *sel = data->sel;
    int                   rv;

    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_del_sel_cb: "
		 "SEL info was destroyed while an operation was in progress");
	sel_op_done(data, ECANCELED);
	goto out;
    }

    if (data->sel->supports_reserve_sel)
	rv = send_reserve_sel(data, mc);
    else
	rv = send_check_sel(data, mc);

    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_del_sel_cb: could not send cmd: %x",
		 rv);
	sel_op_done(data, rv);
	goto out;
    }

    sel_unlock(sel);
 out:
    return;
}

static void
start_del_sel(void *cb_data, int shutdown)
{
    sel_cb_handler_data_t *data = cb_data;
    ipmi_sel_info_t       *sel = data->sel;
    int                   rv;

    sel_lock(sel);
    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_del_sel: "
		 "SEL info was destroyed while an operation was in progress");
	sel_op_done(data, ECANCELED);
	goto out;
    }

    rv = ipmi_mc_pointer_cb(sel->mc, start_del_sel_cb, data);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_del_sel: MC went away during delete");
	sel_op_done(data, ECANCELED);
	goto out;
    }
    sel_unlock(sel);
 out:
    return;
}

typedef struct sel_del_event_info_s
{
    ipmi_sel_info_t       *sel;
    ipmi_event_t          *event;
    ipmi_sel_op_done_cb_t handler;
    void                  *cb_data;
    int                   cmp_event;
    int                   rv;
} sel_del_event_info_t;

static void
sel_del_event_cb(ipmi_mc_t *mc, void *cb_data)
{
    sel_del_event_info_t  *info = cb_data;
    ipmi_sel_info_t       *sel = info->sel;
    ipmi_event_t          *event = info->event;
    int                   cmp_event = info->cmp_event;
    sel_cb_handler_data_t *data;
    sel_event_holder_t    *real_holder;
    ilist_iter_t          iter;
    int                   lun;

    sel_lock(sel);
    if (sel->destroyed) {
	info->rv = EINVAL;
	goto out_unlock;
    }

    ilist_init_iter(&iter, sel->events);
    ilist_unpositioned(&iter);
    real_holder = ilist_search_iter(&iter, recid_search_cmp,
				    &(event->record_id));
    if (!real_holder) {
	info->rv = EINVAL;
	goto out_unlock;
    }

    if (cmp_event && (event_cmp(event, &(real_holder->event)) != 0)) {
	info->rv = EINVAL;
	goto out_unlock;
    }

    if (real_holder->deleted) {
	info->rv = EINVAL;
	goto out_unlock;
    }

    real_holder->deleted = 1;
    sel->num_sels--;
    sel->del_sels++;

    lun = sel->lun;

    if (sel->supports_delete_sel) {
	/* We can delete the entry immediately, just do it. */
	data = ipmi_mem_alloc(sizeof(*data));
	if (!data)
	    /* We will eventually free this anyway, so no need to
               worry. */
	    goto out_unlock;

	data->sel = sel;
	data->handler = info->handler;
	data->cb_data = info->cb_data;
	data->lun = lun;
	data->record_id = event->record_id;
	data->count = 0;
	data->event = *event;

	/* We don't return a return code, because we don't really
           care.  If this fails, it will just be handled later. */
	if (!opq_new_op(sel->opq, start_del_sel, data, 0))
	    ipmi_mem_free(data);
    } else {
	/* Don't really delete the event, but report is as done. */
	info->handler(sel, info->cb_data, 0);
    }

 out_unlock:
    sel_unlock(sel);
}

static int
sel_del_event(ipmi_sel_info_t       *sel,
	      ipmi_event_t          *event,
	      ipmi_sel_op_done_cb_t handler,
	      void                  *cb_data,
	      int                   cmp_event)
{
    sel_del_event_info_t info;
    int                  rv;

    info.sel = sel;
    info.event = event;
    info.handler = handler;
    info.cb_data = cb_data;
    info.cmp_event = cmp_event;
    info.rv = 0;
    rv = ipmi_mc_pointer_cb(sel->mc, sel_del_event_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

int
ipmi_sel_del_event(ipmi_sel_info_t       *sel,
		   ipmi_event_t          *event,
		   ipmi_sel_op_done_cb_t handler,
		   void                  *cb_data)
{
    return sel_del_event(sel, event, handler, cb_data, 1);
}

int
ipmi_sel_del_event_by_recid(ipmi_sel_info_t       *sel,
			    unsigned int          record_id,
			    ipmi_sel_op_done_cb_t handler,
			    void                  *cb_data)
{
    ipmi_event_t event;

    event.record_id = record_id;
    return sel_del_event(sel, &event, handler, cb_data, 0);
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
ipmi_get_sel_entries_used(ipmi_sel_info_t *sel,
			  unsigned int    *count)
{
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *count = sel->num_sels + sel->del_sels;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_first_event(ipmi_sel_info_t *sel, ipmi_event_t *event)
{
    ilist_iter_t iter;
    int          rv = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }
    ilist_init_iter(&iter, sel->events);
    if (ilist_first(&iter)) {
	sel_event_holder_t *holder = ilist_get(&iter);

	while (holder->deleted) {
	    if (! ilist_next(&iter)) {
		rv = ENODEV;
		break;
	    }
	    holder = ilist_get(&iter);
	}
	if (!rv)
	    *event = holder->event;
    } else
	rv = ENODEV;
    sel_unlock(sel);
    return rv;
}

int
ipmi_sel_get_last_event(ipmi_sel_info_t *sel, ipmi_event_t *event)
{
    ilist_iter_t iter;
    int          rv = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }
    ilist_init_iter(&iter, sel->events);
    if (ilist_last(&iter)) {
	sel_event_holder_t *holder = ilist_get(&iter);

	while (holder->deleted) {
	    if (! ilist_prev(&iter)) {
		rv = ENODEV;
		break;
	    }
	    holder = ilist_get(&iter);
	}
	if (!rv)
	    *event = holder->event;
    } else
	rv = ENODEV;
    sel_unlock(sel);
    return rv;
}

int
ipmi_sel_get_next_event(ipmi_sel_info_t *sel, ipmi_event_t *event)
{
    ilist_iter_t iter;
    int          rv = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }
    ilist_init_iter(&iter, sel->events);
    ilist_unpositioned(&iter);
    if (ilist_search_iter(&iter, recid_search_cmp, &(event->record_id))) {
	if (ilist_next(&iter)) {
	    sel_event_holder_t *holder = ilist_get(&iter);

	    while (holder->deleted) {
		if (! ilist_next(&iter)) {
		    rv = ENODEV;
		    break;
		}
		holder = ilist_get(&iter);
	    }
	    if (!rv)
		*event = holder->event;
	} else
	    rv = ENODEV;
    } else {
	rv = EINVAL;
    }
    sel_unlock(sel);
    return rv;
}

int
ipmi_sel_get_prev_event(ipmi_sel_info_t *sel, ipmi_event_t *event)
{
    ilist_iter_t iter;
    int          rv = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }
    ilist_init_iter(&iter, sel->events);
    ilist_unpositioned(&iter);
    if (ilist_search_iter(&iter, recid_search_cmp, &(event->record_id))) {
	if (ilist_prev(&iter)) {
	    sel_event_holder_t *holder = ilist_get(&iter);

	    while (holder->deleted) {
		if (! ilist_prev(&iter)) {
		    rv = ENODEV;
		    break;
		}
		holder = ilist_get(&iter);
	    }
	    if (!rv)
		*event = holder->event;
	} else
	    rv = ENODEV;
    } else {
	rv = EINVAL;
    }
    sel_unlock(sel);
    return rv;
}

int
ipmi_sel_get_event_by_recid(ipmi_sel_info_t *sel,
                            unsigned int    record_id,
                            ipmi_event_t    *event)
{
    int                rv = 0;
    sel_event_holder_t *holder;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    holder = find_event(sel->events, record_id);
    if (!holder) {
	rv = EINVAL;
	goto out_unlock;
    }

    if (holder->deleted) {
        rv = ENODEV;
        goto out_unlock;
    }

    *event = holder->event;

 out_unlock:
    sel_unlock(sel);
    return rv;
}

int ipmi_get_all_sels(ipmi_sel_info_t *sel,
		      int             *array_size,
		      ipmi_event_t    *array)
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

	ilist_init_iter(&iter, sel->events);
	if (! ilist_first(&iter)) {
	    rv = EINVAL;
	    goto out_unlock;
	}
	for (i=0; ; ) {
	    sel_event_holder_t *holder = ilist_get(&iter);

	    if (! holder->deleted) {
		*array = holder->event;
		array++;
	    }
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
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *val = sel->major_version;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_minor_version(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *val = sel->minor_version;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_overflow(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *val = sel->overflow;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_supports_delete_sel(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *val = sel->supports_delete_sel;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_supports_partial_add_sel(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *val = sel->supports_partial_add_sel;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_supports_reserve_sel(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *val = sel->supports_reserve_sel;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_supports_get_sel_allocation(ipmi_sel_info_t *sel,
					 int             *val)
{
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *val = sel->supports_get_sel_allocation;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_last_addition_timestamp(ipmi_sel_info_t *sel,
                                     int             *val)
{
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *val = sel->last_addition_timestamp;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_set_new_event_handler(ipmi_sel_info_t               *sel,
			       ipmi_sel_new_event_handler_cb handler,
			       void                          *cb_data)
{
    sel->new_event_handler = handler;
    sel->new_event_cb_data = cb_data;
    return 0;
}

int
ipmi_sel_event_add(ipmi_sel_info_t *sel,
		   ipmi_event_t    *new_event)
{
    int                rv = 0;
    sel_event_holder_t *holder;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    holder = find_event(sel->events, new_event->record_id);
    if (!holder) {
	holder = ipmi_mem_alloc(sizeof(*holder));
	if (!holder) {
	    rv = ENOMEM;
	    goto out_unlock;
	}
	if (!ilist_add_tail(sel->events, holder, NULL)) {
	    rv = ENOMEM;
	    goto out_unlock;
	}
	holder->event = *new_event;
	sel->num_sels++;
    } else if (event_cmp(&holder->event, new_event) == 0) {
	/* A duplicate event, just ignore it and return the right
	   error. */
	rv = EEXIST;
    } else {
	holder->event = *new_event;
	if (holder->deleted) {
	    holder->deleted = 0;
	    sel->num_sels++;
	    sel->del_sels--;
	}
    }

 out_unlock:
    sel_unlock(sel);
    return rv;
}

typedef struct sel_add_cb_handler_data_s
{
    ipmi_sel_info_t           *sel;
    ipmi_sel_add_op_done_cb_t handler;
    void                      *cb_data;
    unsigned int              record_id;
    ipmi_event_t              event;
    int                       rv;
} sel_add_cb_handler_data_t;

static void
sel_add_op_done(sel_add_cb_handler_data_t *data,
		int                       rv)
{
    ipmi_sel_info_t *sel = data->sel;

    if (data->handler)
	data->handler(sel, data->cb_data, rv, data->record_id);

    if (sel->in_destroy) {
	/* Nothing to do */
	sel_unlock(sel);
    } else if (sel->destroyed) {
	/* This will unlock the lock. */
	internal_destroy_sel(sel);
    } else {
	opq_op_done(sel->opq);
	sel_unlock(sel);
    }
    ipmi_mem_free(data);
}

static void
sel_add_event_done(ipmi_mc_t  *mc,
		   ipmi_msg_t *rsp,
		   void       *rsp_data)
{
    sel_add_cb_handler_data_t *info = rsp_data;
    ipmi_sel_info_t           *sel = info->sel;

    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel.c(sel_add_event_done): "
		 "SEL info was destroyed while an operation was in progress");
	sel_add_op_done(info, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel.c(sel_add_event_done): "
		 "MC went away while SEL op was in progress");
        sel_add_op_done(info, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel.c(sel_add_event_done): "
		 "IPMI error from SEL info fetch: %x",
		 rsp->data[0]);
	sel_add_op_done(info, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    if (rsp->data_len < 3) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel.c(sel_add_event_done): "
		 "SEL add response too short");
	sel_add_op_done(info, EINVAL);
	goto out;
    }

    info->record_id = ipmi_get_uint16(rsp->data+1);
    sel_add_op_done(info, 0);
 out:
    return;
}

static void
sel_add_event_cb(ipmi_mc_t *mc, void *cb_data)
{
    sel_add_cb_handler_data_t *info = cb_data;
    ipmi_sel_info_t           *sel = info->sel;
    ipmi_event_t              *event = &info->event;
    unsigned char             data[16];
    ipmi_msg_t                msg;

    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_ADD_SEL_ENTRY_CMD;
    msg.data = data;
    msg.data_len = 16;

    ipmi_set_uint16(data, event->record_id);
    data[2] = event->type;
    memcpy(data+3, event->data, IPMI_MAX_SEL_DATA);

    info->rv = ipmi_mc_send_command(mc, sel->lun, &msg, sel_add_event_done,
				    info);
}

static void
sel_add_event_op(void *cb_data, int shutdown)
{
    sel_add_cb_handler_data_t *info = cb_data;
    ipmi_sel_info_t           *sel = info->sel;
    int                       rv;

    sel_lock(sel);
    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel.c(sel_add_event_op): "
		 "SEL info was destroyed while an operation was in progress");
	sel_add_op_done(info, ECANCELED);
	goto out;
    }

    rv = ipmi_mc_pointer_cb(sel->mc, sel_add_event_cb, info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel.c(sel_add_event_op): "
		 "MC went away during delete");
	sel_add_op_done(info, ECANCELED);
	goto out;
    } else if (info->rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sel.c(sel_add_event_cb): could not send cmd: %x",
		 rv);
	sel_add_op_done(info, info->rv);
	goto out;
    }

    sel_unlock(sel);
 out:
    return;
}

int
ipmi_sel_add_event_to_sel(ipmi_sel_info_t           *sel,
			  ipmi_event_t              *event_to_add,
			  ipmi_sel_add_op_done_cb_t done,
			  void                      *cb_data)
{
    sel_add_cb_handler_data_t *info = cb_data;
    int                       rv = 0;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->sel = sel;
    info->event = *event_to_add;
    info->handler = done;
    info->cb_data = cb_data;
    info->record_id = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	rv = EINVAL;
	goto out_unlock;
    }

    /* Schedule this to run at the end of the queue. */
    if (!opq_new_op(sel->opq, sel_add_event_op, info, 0)) {
	rv = ENOMEM;
	goto out_unlock;
    }

 out_unlock:
    sel_unlock(sel);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}
