/*
 * sel.c
 *
 * MontaVista IPMI code for handling the system event log
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004,2005 MontaVista Software Inc.
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
#include <stdio.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_err.h>

#include <OpenIPMI/internal/opq.h>
#include <OpenIPMI/internal/ilist.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/ipmi_event.h>
#include <OpenIPMI/internal/ipmi_sel.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_mc.h>

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
    unsigned int deleted : 1;
    unsigned int cancelled : 1;
    unsigned int refcount;
    ipmi_event_t *event;
} sel_event_holder_t;

static sel_event_holder_t *
sel_event_holder_alloc(void)
{
    sel_event_holder_t *holder = ipmi_mem_alloc(sizeof(*holder));

    if (!holder)
	return NULL;
    holder->deleted = 0;
    holder->cancelled = 0;
    holder->refcount = 1;
    holder->event = NULL;
    return holder;
}

static void
sel_event_holder_get(sel_event_holder_t *holder)
{
    holder->refcount++;
}

static void
sel_event_holder_put(sel_event_holder_t *holder)
{
    holder->refcount--;
    if (holder->refcount == 0) {
	ipmi_event_free(holder->event);
	ipmi_mem_free(holder);
    }
}

typedef struct sel_clear_req_s
{
    ipmi_event_t *last_event;
    struct sel_clear_req_s *next;
} sel_clear_req_t;

#define SEL_NAME_LEN (IPMI_MC_NAME_LEN + 32)

struct ipmi_sel_info_s
{
    ipmi_mcid_t mc;

    /* LUN we are attached with. */
    int         lun;

    uint8_t  major_version;
    uint8_t  minor_version;
    uint16_t entries;
    uint32_t last_addition_timestamp;
    uint32_t last_erase_timestamp;

    /* These are here to store the timestamps until the operation
       completes.  Successfully.  Otherwise, if we restart the fetch,
       it will have the timestamps set wrong and won't do the
       fetch. */
    uint32_t curr_addition_timestamp;
    uint32_t curr_erase_timestamp;

    uint16_t free_bytes;
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
    unsigned int           curr_rec_id;
    unsigned int           next_rec_id;
    unsigned int           reservation;
    int                    sels_changed;
    unsigned int           fetch_retry_count;
    sel_fetch_handler_t    *fetch_handlers;

    /* When we start a fetch, we start with this id.  This is the last
       one we successfully fetches (or 0 if it is not valid) so we can
       find the next valid id to fetch. */
    unsigned int           start_rec_id;
    unsigned char          start_rec_id_data[14];

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

    char name[SEL_NAME_LEN];

    ipmi_domain_stat_t *sel_good_scans;
    ipmi_domain_stat_t *sel_scan_lost_reservation;
    ipmi_domain_stat_t *sel_fail_scan_lost_reservation;
    ipmi_domain_stat_t *sel_received_events;
    ipmi_domain_stat_t *sel_fetch_errors;

    ipmi_domain_stat_t *sel_good_clears;
    ipmi_domain_stat_t *sel_clear_lost_reservation;
    ipmi_domain_stat_t *sel_clear_errors;

    ipmi_domain_stat_t *sel_good_deletes;
    ipmi_domain_stat_t *sel_delete_lost_reservation;
    ipmi_domain_stat_t *sel_fail_delete_lost_reservation;
    ipmi_domain_stat_t *sel_delete_errors;
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
    sel_event_holder_t *holder = item;
    sel_event_holder_put(holder);
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
    unsigned int       recid = *((unsigned int *) cb_data);

    return ipmi_event_get_record_id(holder->event) == recid;
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
    unsigned int        record_id1, record_id2;
    unsigned int        type1, type2;
    unsigned int        data_len1, data_len2;
    const unsigned char *ptr1, *ptr2;

    rv = ipmi_cmp_mc_id(ipmi_event_get_mcid(event1),
			ipmi_event_get_mcid(event2));
    if (rv)
	return rv;
    record_id1 = ipmi_event_get_record_id(event1);
    record_id2 = ipmi_event_get_record_id(event2);
    if (record_id1 > record_id2)
	return 1;
    if (record_id1 < record_id2)
	return -1;
    type1 = ipmi_event_get_type(event1);
    type2 = ipmi_event_get_type(event2);
    if (type1 > type2)
	return 1;
    if (type1 < type2)
	return -1;
    data_len1 = ipmi_event_get_data_len(event1);
    data_len2 = ipmi_event_get_data_len(event2);
    if (data_len1 > data_len2)
	return 1;
    if (data_len1 < data_len2)
	return -1;
    ptr1 = ipmi_event_get_data_ptr(event1);
    ptr2 = ipmi_event_get_data_ptr(event2);
    return memcmp(ptr1, ptr2, data_len1);
}

int
ipmi_sel_alloc(ipmi_mc_t       *mc,
	       unsigned int    lun,
	       ipmi_sel_info_t **new_sel)
{
    ipmi_sel_info_t *sel = NULL;
    int             rv = 0;
    ipmi_domain_t   *domain;
    int             i;

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

    i = ipmi_mc_get_name(mc, sel->name, sizeof(sel->name));
    snprintf(sel->name+i, sizeof(sel->name)-i, "(sel)");

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
	ipmi_domain_stat_register(domain, "sel_good_scans",
				  _ipmi_mc_name(mc),
				  &sel->sel_good_scans);
	ipmi_domain_stat_register(domain, "sel_scan_lost_reservation",
				  _ipmi_mc_name(mc),
				  &sel->sel_scan_lost_reservation);
	ipmi_domain_stat_register(domain, "sel_fail_scan_lost_reservation",
				  _ipmi_mc_name(mc),
				  &sel->sel_fail_scan_lost_reservation);
	ipmi_domain_stat_register(domain, "sel_received_events",
				  _ipmi_mc_name(mc),
				  &sel->sel_received_events);
	ipmi_domain_stat_register(domain, "sel_fetch_errors",
				  _ipmi_mc_name(mc),
				  &sel->sel_fetch_errors);
	ipmi_domain_stat_register(domain, "sel_good_clears",
				  _ipmi_mc_name(mc),
				  &sel->sel_good_clears);
	ipmi_domain_stat_register(domain, "sel_clear_lost_reservation",
				  _ipmi_mc_name(mc),
				  &sel->sel_clear_lost_reservation);
	ipmi_domain_stat_register(domain, "sel_clear_errors",
				  _ipmi_mc_name(mc),
				  &sel->sel_clear_errors);
	ipmi_domain_stat_register(domain, "sel_good_deletes",
				  _ipmi_mc_name(mc),
				  &sel->sel_good_deletes);
	ipmi_domain_stat_register(domain, "sel_delete_lost_reservation",
				  _ipmi_mc_name(mc),
				  &sel->sel_delete_lost_reservation);
	ipmi_domain_stat_register(domain, "sel_fail_delete_lost_reservation",
				  _ipmi_mc_name(mc),
				  &sel->sel_fail_delete_lost_reservation);
	ipmi_domain_stat_register(domain, "sel_delete_errors",
				  _ipmi_mc_name(mc),
				  &sel->sel_delete_errors);
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

    if (sel->events) {
	free_events(sel->events);
	free_ilist(sel->events);
    }
    sel_unlock(sel);

    if (sel->opq)
	opq_destroy(sel->opq);

    if (sel->sel_lock)
	sel->os_hnd->destroy_lock(sel->os_hnd, sel->sel_lock);

    if (sel->sel_good_scans)
	ipmi_domain_stat_put(sel->sel_good_scans);
    if (sel->sel_scan_lost_reservation)
	ipmi_domain_stat_put(sel->sel_scan_lost_reservation);
    if (sel->sel_fail_scan_lost_reservation)
	ipmi_domain_stat_put(sel->sel_fail_scan_lost_reservation);
    if (sel->sel_received_events)
	ipmi_domain_stat_put(sel->sel_received_events);
    if (sel->sel_fetch_errors)
	ipmi_domain_stat_put(sel->sel_fetch_errors);
    if (sel->sel_good_clears)
	ipmi_domain_stat_put(sel->sel_good_clears);
    if (sel->sel_clear_lost_reservation)
	ipmi_domain_stat_put(sel->sel_clear_lost_reservation);
    if (sel->sel_clear_errors)
	ipmi_domain_stat_put(sel->sel_clear_errors);
    if (sel->sel_good_deletes)
	ipmi_domain_stat_put(sel->sel_good_deletes);
    if (sel->sel_delete_lost_reservation)
	ipmi_domain_stat_put(sel->sel_delete_lost_reservation);
    if (sel->sel_fail_delete_lost_reservation)
	ipmi_domain_stat_put(sel->sel_fail_delete_lost_reservation);
    if (sel->sel_delete_errors)
	ipmi_domain_stat_put(sel->sel_delete_errors);

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
fetch_complete(ipmi_sel_info_t *sel, int err, int do_opq_done)
{
    sel_fetch_handler_t *elem, *next;
    int                 sels_changed;
    unsigned int        num_sels;

    if (sel->in_destroy)
	goto out;

    sels_changed = sel->sels_changed;
    num_sels = sel->num_sels;

    elem = sel->fetch_handlers;
    sel->fetch_handlers = NULL;
    sel->fetched = 1;
    sel->in_fetch = 0;
    sel_unlock(sel);

    while (elem) {
	next = elem->next;
	elem->next = NULL;
	if (elem->handler)
	    elem->handler(sel,
		          err,
		          sels_changed,
		          num_sels,
		          elem->cb_data);
	ipmi_mem_free(elem);
	elem = next;
    }

    if (sel->destroyed) {
	sel_lock(sel);
	internal_destroy_sel(sel);
	/* Previous call releases lock. */
	return;
    }

    if (do_opq_done)
	opq_op_done(sel->opq);
    return;

 out:
    sel_unlock(sel);
}

static void
free_deleted_event(ilist_iter_t *iter, void *item, void *cb_data)
{
    sel_event_holder_t *holder = item;
    ipmi_sel_info_t    *sel = cb_data;

    if (holder->deleted) {
	ilist_delete(iter);
	holder->cancelled = 1;
	sel->del_sels--;
	sel_event_holder_put(holder);
    }
}

static void
free_deleted_events(ipmi_sel_info_t *sel)
{
    ilist_iter(sel->events, free_deleted_event, sel);
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
		 "%ssel.c(handle_sel_clear): "
		 "SEL info was destroyed while an operation was in"
		 " progress(1)", sel->name);
	fetch_complete(sel, ECANCELED, 1);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_clear): "
		 "MC went away while SEL op was in progress",
		 sel->name);
        fetch_complete(sel, ECANCELED, 1);
	goto out;
    }

    if (rsp->data[0] == 0) {
	if (sel->sel_good_clears)
	    ipmi_domain_stat_add(sel->sel_good_clears, 1);

	/* Success!  We can free the data. */
	free_deleted_events(sel);
	sel->del_sels = 0;
    } else if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	if (sel->sel_clear_lost_reservation)
	    ipmi_domain_stat_add(sel->sel_clear_lost_reservation, 1);
    } else {
	if (sel->sel_clear_errors)
	    ipmi_domain_stat_add(sel->sel_clear_errors, 1);
    }

    fetch_complete(sel, 0, 1);
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

static int start_fetch(void *cb_data, int shutdown);

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
    ipmi_event_t        *del_event;
    unsigned int        record_id;
    ipmi_time_t         timestamp;
    sel_event_holder_t  *holder;


    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_data): "
		 "SEL info was destroyed while an operation was in"
		 " progress(2)", sel->name);
	fetch_complete(sel, ECANCELED, 1);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_data): "
		 "handle_sel_data: MC went away while SEL op was in progress",
		 sel->name);
        fetch_complete(sel, ECANCELED, 1);
	goto out;
    }
	
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* We lost our reservation, restart the operation.  Only do
           this so many times, in order to guarantee that this
           completes.  Note that we do this so many times *per fetch*,
           we do not reset the counter if we get a successful
           operation.  This is because if this happens a lot during a
           fetch, there is heavy contention for the SEL and someone
           needs to drop out to allow everyone else to continue. */
	sel->fetch_retry_count++;
	if (sel->sel_scan_lost_reservation)
	    ipmi_domain_stat_add(sel->sel_scan_lost_reservation, 1);
	if (sel->fetch_retry_count > MAX_SEL_FETCH_RETRIES) {
	    if (sel->sel_fail_scan_lost_reservation)
		ipmi_domain_stat_add(sel->sel_fail_scan_lost_reservation, 1);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%ssel.c(handle_sel_data): "
		     "Too many lost reservations in SEL fetch",
		     sel->name);
	    fetch_complete(sel, EAGAIN, 1);
	    goto out;
	} else {
	    sel_unlock(sel);
	    start_fetch(elem, 0);
	    goto out;
	}
    }
    if ((rsp->data[0] == 0) && (rsp->data_len < 19)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_data): "
		 "Received a short SEL data message",
		 sel->name);
	fetch_complete(sel, EINVAL, 1);
	goto out;
    }

    if ((rsp->data[0] != 0)
	|| ((sel->start_rec_id != 0) && (sel->start_rec_id == sel->curr_rec_id)
	    && (memcmp(sel->start_rec_id_data, rsp->data+5, 14) != 0)))
    {
	/* We got an error fetching the current id, or the current
	   id's data was for our "start" record and it doesn't match
	   the one we fetched, so it has changed.  We have to start
	   over or handle the error. */
	if (sel->start_rec_id != 0) {
	    /* If we get a fetch error and it is not a lost
	       reservation, it may be that another system deleted our
	       "current" record.  Start over from the beginning of the
	       SEL. */
	    sel->start_rec_id = 0;
	    sel->curr_rec_id = 0;
	    del_event = NULL;
	    goto start_request_sel_data;
	}
	if (sel->sel_fetch_errors)
	    ipmi_domain_stat_add(sel->sel_fetch_errors, 1);
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_data): "
		 "IPMI error from SEL fetch: %x",
		 sel->name, rsp->data[0]);
	fetch_complete(sel, IPMI_IPMI_ERR_VAL(rsp->data[0]), 1);
	goto out;
    }

    sel->next_rec_id = ipmi_get_uint16(rsp->data+1);

    record_id = ipmi_get_uint16(rsp->data+3);

    if (rsp->data[5] < 0xe0)
	timestamp = ipmi_seconds_to_time(ipmi_get_uint32(rsp->data+6));
    else
	timestamp = -1;
    del_event = ipmi_event_alloc(ipmi_mc_convert_to_id(mc),
				 record_id,
				 rsp->data[5],
				 timestamp,
				 rsp->data+6,
				 13);
    if (!del_event) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_data): "
		 "Could not allocate event for SEL",
		 sel->name);
	fetch_complete(sel, ENOMEM, 1);
	goto out;
    }

    if ((timestamp > 0) && (timestamp < ipmi_mc_get_startup_SEL_time(mc)))
	ipmi_event_set_is_old(del_event, 1);

    holder = find_event(sel->events, record_id);
    if (!holder) {
	holder = sel_event_holder_alloc();
	if (!holder) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%ssel.c(handle_sel_data): "
		     "Could not allocate log information for SEL",
		     sel->name);
	    fetch_complete(sel, ENOMEM, 1);
	    goto out;
	}
	if (!ilist_add_tail(sel->events, holder, NULL)) {
	    ipmi_mem_free(holder);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%ssel.c(handle_sel_data): "
		     "Could not link log onto the log linked list",
		     sel->name);
	    fetch_complete(sel, ENOMEM, 1);
	    goto out;
	}
	holder->event = del_event;
	holder->deleted = 0;
	event_is_new = 1;
	sel->num_sels++;
	if (sel->sel_received_events)
	    ipmi_domain_stat_add(sel->sel_received_events, 1);
    } else if (event_cmp(del_event, holder->event) != 0) {
	/* It's a new event in an old slot, so overwrite the old
           event. */
	
	ipmi_event_free(holder->event);
	holder->event = del_event;
	if (holder->deleted) {
	    holder->deleted = 0;
	    sel->num_sels++;
	    sel->del_sels--;
	}
	event_is_new = 1;
	if (sel->sel_received_events)
	    ipmi_domain_stat_add(sel->sel_received_events, 1);
    } else {
	ipmi_event_free(del_event);
    }

    if (sel->next_rec_id == 0xFFFF) {
	/* Only set the timestamps if the SEL fetch completed
	   successfully.  If we were unsuccessful, we want to redo the
	   operation so don't set the timestamps. */
	sel->last_addition_timestamp = sel->curr_addition_timestamp;
	sel->last_erase_timestamp = sel->curr_erase_timestamp;

	/* To avoid confusion, deliver the event before we deliver fetch
           complete. */
	if (event_is_new && sel->new_event_handler) {
	    ipmi_sel_new_event_handler_cb handler = sel->new_event_handler;
	    void                          *cb_data = sel->new_event_cb_data;
	    sel_unlock(sel);
	    handler(sel, mc, del_event, cb_data);
	    sel_lock(sel);
	}

	if (sel->sel_good_scans)
	    ipmi_domain_stat_add(sel->sel_good_scans, 1);

	/* If the operation completed successfully and everything in
	   our SEL is deleted, then clear it with our old reservation.
	   We also do the clear if the overflow flag is set; on some
	   systems this operation clears the overflow flag. */
	if ((sel->num_sels == 0)
	    && ((!ilist_empty(sel->events)) || sel->overflow))
	{
	    /* We don't care if this fails, because it will just
	       happen again later if it does. */
	    rv = send_sel_clear(elem, mc);
	    if (rv) {
		fetch_complete(sel, 0, 1);
		goto out;
	    }
	    rv = 0;
	    goto out_unlock;
	} else {
	    fetch_complete(sel, 0, 1);
	    goto out;
	}
    }
    sel->start_rec_id = sel->curr_rec_id;
    memcpy(sel->start_rec_id_data, rsp->data+5, 14);
    sel->curr_rec_id = sel->next_rec_id;

 start_request_sel_data:
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
		 "%ssel.c(handle_sel_clear): "
		 "Could not send SEL fetch command: %x", sel->name, rv);
	fetch_complete(sel, rv, 1);
	goto out;
    }

    if (event_is_new && sel->new_event_handler) {
	ipmi_sel_new_event_handler_cb handler = sel->new_event_handler;
	void                          *cb_data = sel->new_event_cb_data;
	sel_unlock(sel);
	handler(sel, mc, del_event, cb_data);
	sel_lock(sel);
    }
 out_unlock:
    sel_unlock(sel);
 out:
    return;
}

/* Cheap hacks for broken hardware. */
static void
sel_fixups(ipmi_mc_t *mc, ipmi_sel_info_t *sel)
{
    unsigned int mfg_id, product_id;

    /* Fixups */
    mfg_id = ipmi_mc_manufacturer_id(mc);
    product_id = ipmi_mc_product_id(mc);
    if ((mfg_id == 0x157) && (product_id == 0x841))
	/* Intel ATCA CMM mistakenly reports that it supports delete SEL */
	sel->supports_delete_sel = 0;
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
    uint32_t            add_timestamp;
    uint32_t            erase_timestamp;
    int                 fetched_num_sels;

    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_info): "
		 "SEL info was destroyed while an operation was in progress",
		 sel->name);
	fetch_complete(sel, ECANCELED, 1);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_info): "
		 "MC went away while SEL op was in progress",
		 sel->name);
        fetch_complete(sel, ECANCELED, 1);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	if (sel->sel_fetch_errors)
	    ipmi_domain_stat_add(sel->sel_fetch_errors, 1);
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_info): "
		 "IPMI error from SEL info fetch: %x",
		 sel->name, rsp->data[0]);
	fetch_complete(sel, IPMI_IPMI_ERR_VAL(rsp->data[0]), 1);
	goto out;
    }

    if (rsp->data_len < 15) {
	if (sel->sel_fetch_errors)
	    ipmi_domain_stat_add(sel->sel_fetch_errors, 1);
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_info): SEL info too short", sel->name);
	fetch_complete(sel, EINVAL, 1);
	goto out;
    }

    /* Pull pertinant info from the response. */
    sel->major_version = rsp->data[1] & 0xf;
    sel->minor_version = (rsp->data[1] >> 4) & 0xf;
    fetched_num_sels = ipmi_get_uint16(rsp->data+2);
    sel->entries = fetched_num_sels;
    sel->free_bytes = ipmi_get_uint16(rsp->data+4);
    sel->overflow = (rsp->data[14] & 0x80) == 0x80;
    sel->supports_delete_sel = (rsp->data[14] & 0x08) == 0x08;
    sel->supports_partial_add_sel = (rsp->data[14] & 0x04) == 0x04;
    sel->supports_reserve_sel = (rsp->data[14] & 0x02) == 0x02;
    sel->supports_get_sel_allocation = (rsp->data[14] & 0x01) == 0x01;
    
    add_timestamp = ipmi_get_uint32(rsp->data + 6);
    erase_timestamp = ipmi_get_uint32(rsp->data + 10);

    sel_fixups(mc, sel);

    /* If the timestamps still match, no need to re-fetch the
       repository.  Note that we only check the add timestamp.  We
       don't care if things were deleted. */
    if (sel->fetched && (add_timestamp == sel->last_addition_timestamp)) {
	/* If the operation completed successfully and everything in
	   our SEL is deleted, then clear it with our old reservation.
	   We also do the clear if the overflow flag is set; on some
	   systems this operation clears the overflow flag. */
	if ((sel->num_sels == 0)
	    && ((!ilist_empty(sel->events)) || sel->overflow))
	{
	    /* We don't care if this fails, because it will just
	       happen again later if it does. */
	    rv = send_sel_clear(elem, mc);
	    if (rv) {
		fetch_complete(sel, 0, 1);
		goto out;
	    }
	    goto out_unlock;
	} else {
	    fetch_complete(sel, 0, 1);
	    goto out;
	}
    }

    sel->curr_addition_timestamp = add_timestamp;
    sel->curr_erase_timestamp = erase_timestamp;

    sel->sels_changed = 1;
    sel->next_rec_id = 0;

    if (fetched_num_sels == 0) {
	/* No sels, so there's nothing to do. */

	/* Set the timestamps here, because they are not the same, but
	   there was nothing to do. */
	sel->last_addition_timestamp = sel->curr_addition_timestamp;
	sel->last_erase_timestamp = sel->curr_erase_timestamp;
	sel->start_rec_id = 0;
	sel->curr_rec_id = 0;

	fetch_complete(sel, 0, 1);
	goto out;
    }

    /* Fetch the first SEL entry. */
    sel->curr_rec_id = sel->start_rec_id;
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
		 "%ssel.c(handle_sel_info): "
		 "Could not send first SEL fetch command: %x",
		 sel->name, rv);
	fetch_complete(sel, rv, 1);
	goto out;
    }
 out_unlock:
    sel_unlock(sel);
 out:
    return;
}

static int
send_get_sel_info(sel_fetch_handler_t *elem, ipmi_mc_t *mc)
{
    ipmi_sel_info_t *sel = elem->sel;
    ipmi_msg_t      cmd_msg;

    /* Fetch the repository info. */
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_GET_SEL_INFO_CMD;
    cmd_msg.data = NULL;
    cmd_msg.data_len = 0;
    return ipmi_mc_send_command(mc, sel->lun, &cmd_msg, handle_sel_info, elem);
}

static void
sel_handle_reservation(ipmi_mc_t  *mc,
		       ipmi_msg_t *rsp,
		       void       *rsp_data)
{
    sel_fetch_handler_t *elem = rsp_data;
    ipmi_sel_info_t     *sel = elem->sel;
    int                 rv;

    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_handle_reservation): "
		 "SEL info was destroyed while an operation was in progress",
		 sel->name);
	fetch_complete(sel, ECANCELED, 1);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_handle_reservation): "
		 "MC went away while SEL op was in progress",
		 sel->name);
        fetch_complete(sel, ECANCELED, 1);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	if (sel->sel_fetch_errors)
	    ipmi_domain_stat_add(sel->sel_fetch_errors, 1);
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_handle_reservation): "
		 "Failed getting reservation", sel->name);
	fetch_complete(sel, ENOSYS, 1);
	goto out;
    } else if (rsp->data_len < 3) {
	if (sel->sel_fetch_errors)
	    ipmi_domain_stat_add(sel->sel_fetch_errors, 1);
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_handle_reservation): "
		 "got invalid reservation length", sel->name);
	fetch_complete(sel, EINVAL, 1);
	goto out;
    }

    sel->reservation = ipmi_get_uint16(rsp->data+1);

    rv = send_get_sel_info(elem, mc);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_handle_reservation): "
		 "Could not send SEL info command: %x", sel->name, rv);
	fetch_complete(sel, rv, 1);
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

    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(start_fetch_cb): "
		 "SEL info was destroyed while an operation was in progress",
		 sel->name);
	elem->rv = ECANCELED;
	goto out;
    }

    if (sel->supports_reserve_sel) {
	/* Get a reservation first. */
	cmd_msg.data = cmd_data;
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_RESERVE_SEL_CMD;
	cmd_msg.data_len = 0;
	rv = ipmi_mc_send_command_sideeff(mc, sel->lun, &cmd_msg,
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
		 "%ssel.c(start_fetch_cb): could not send cmd: %x",
		 sel->name, rv);
	elem->rv = rv;
	goto out;
    }

 out:
    return;
}

static int
start_fetch(void *cb_data, int shutdown)
{
    sel_fetch_handler_t *elem = cb_data;
    int                 rv;

    sel_lock(elem->sel);
    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(start_fetch): "
		 "SEL info was destroyed while an operation was in progress",
		 elem->sel->name);
	fetch_complete(elem->sel, ECANCELED, 0);
	return OPQ_HANDLER_ABORTED;
    }

    /* The read lock must be claimed before the sel lock to avoid
       deadlock. */
    rv = ipmi_mc_pointer_cb(elem->sel->mc, start_fetch_cb, elem);
    if (rv)
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(start_fetch): MC is not valid", elem->sel->name);
    else
	rv = elem->rv;

    if (rv) {
	fetch_complete(elem->sel, rv, 0);
	return OPQ_HANDLER_ABORTED;
    }

    sel_unlock(elem->sel);

    return OPQ_HANDLER_STARTED;
}

/* We have to have this because the allocate element can go away (the
   operation can complete) before returning to the user. */
typedef struct sel_get_cb_s
{
    sel_fetch_handler_t *elem;
    int                 rv;
} sel_get_cb_t;

static void
ipmi_sel_get_cb(ipmi_mc_t *mc, void *cb_data)
{
    sel_get_cb_t        *info = cb_data;
    sel_fetch_handler_t *elem = info->elem;
    ipmi_sel_info_t     *sel = elem->sel;

    if (!ipmi_mc_sel_device_support(mc)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(ipmi_sel_get_cb): "
		 "No support for the system event log", sel->name);
	info->rv = ENOSYS;
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

	elem->next = NULL;
	sel->fetch_handlers = elem;
	sel_unlock(sel);
	/* Always put a fetch ahead of everything else.  If there are
	   deletes in progress and a clear gets done, we can complete
	   all the deletes. */
	if (!opq_new_op_prio(sel->opq, start_fetch, elem, 0, OPQ_ADD_HEAD,
			    NULL))
	{
	    sel->fetch_handlers = NULL;
	    info->rv = ENOMEM;
	}
	goto out;
    } else if (elem->handler) {
	/* Add it to the list of waiting fetch handlers, if it has a
	   handler. */
	elem->next = sel->fetch_handlers;
	sel->fetch_handlers = elem;
    } else {
	/* No handler and fetch was already in progress.  Return an
	   error so the caller knows what happened. */
	info->rv = EEXIST;
    }

    sel_unlock(sel);
 out:
    return;
}

int
ipmi_sel_get(ipmi_sel_info_t     *sel,
	     ipmi_sels_fetched_t handler,
	     void                *cb_data)
{
    sel_get_cb_t        info;
    sel_fetch_handler_t *elem;
    int                 rv;

    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(ipmi_sel_get): "
		 "could not allocate the sel element", sel->name);
	return ENOMEM;
    }

    elem->handler = handler;
    elem->cb_data = cb_data;
    elem->sel = sel;
    elem->rv = 0;
    info.elem = elem;
    info.rv = 0;

    rv = ipmi_mc_pointer_cb(sel->mc, ipmi_sel_get_cb, &info);
    if (!rv)
	rv = info.rv;
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

typedef struct sel_del_handler_data_s
{
    ipmi_sel_info_t       *sel;
    ipmi_sel_op_done_cb_t handler;
    void                  *cb_data;
    unsigned int          reservation;
    unsigned int          record_id;
    unsigned int          lun;
    unsigned int          count;
    ipmi_event_t          *event;
    sel_event_holder_t    *holder;

    /* If true, we do a clear operation if the given record is the
       last record in the SEL. */
    int                   do_clear;
} sel_del_handler_data_t;

static int send_reserve_sel_for_delete(sel_del_handler_data_t *data,
				       ipmi_mc_t *mc);

static void
sel_op_done(sel_del_handler_data_t *data,
	    int                    rv,
	    int                    do_op_done)
{
    ipmi_sel_info_t *sel = data->sel;

    if (data->holder)
	sel_event_holder_put(data->holder);

    sel_unlock(sel);

    if (data->handler)
	data->handler(sel, data->cb_data, rv);

    sel_lock(sel);

    if (sel->in_destroy) {
	/* Nothing to do */
	sel_unlock(sel);
    } else if (sel->destroyed) {
	/* This will unlock the lock. */
	internal_destroy_sel(sel);
    } else {
	sel_unlock(sel);
	if (do_op_done)
	    opq_op_done(sel->opq);
    }
    if (data->event)
	ipmi_event_free(data->event);
    ipmi_mem_free(data);
}

static void
free_all_event(ilist_iter_t *iter, void *item, void *cb_data)
{
    sel_event_holder_t *holder = item;
    ipmi_sel_info_t    *sel = cb_data;

    if (holder->deleted) {
	sel->del_sels--;
	holder->cancelled = 1;
    }
    ilist_delete(iter);
    sel_event_holder_put(holder);
}

static void
free_all_events(ipmi_sel_info_t *sel)
{
    ilist_iter(sel->events, free_all_event, sel);
}

static void
handle_del_sel_clear(ipmi_mc_t  *mc,
		     ipmi_msg_t *rsp,
		     void       *rsp_data)
{
    sel_del_handler_data_t *data = rsp_data;
    ipmi_sel_info_t        *sel = data->sel;

    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_del_sel_clear): "
		 "SEL info was destroyed while an operation was in progress",
		 sel->name);
	sel_op_done(data, ECANCELED, 1);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_del_sel_clear): "
		 "MC went away while SEL fetch was in progress",
		 sel->name);
	sel_op_done(data, ECANCELED, 1);
	goto out;
    }

    if (rsp->data[0]) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_del_sel_clear): "
		 "IPMI error clearing SEL: 0x%x",
		 sel->name, rsp->data[0]);
	sel_op_done(data, IPMI_IPMI_ERR_VAL(rsp->data[0]), 1);
	goto out;
    }

    free_all_events(sel);
    sel->num_sels = 0;

    sel_op_done(data, 0, 1);

 out:
    return;
}

static int
send_del_clear(sel_del_handler_data_t *data, ipmi_mc_t *mc)
{
    ipmi_sel_info_t *sel = data->sel;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_CLEAR_SEL_CMD;
    cmd_msg.data_len = 6;
    ipmi_set_uint16(cmd_msg.data, data->reservation);
    cmd_msg.data[2] = 'C';
    cmd_msg.data[3] = 'L';
    cmd_msg.data[4] = 'R';
    cmd_msg.data[5] = 0xaa;

    return ipmi_mc_send_command(mc, sel->lun, &cmd_msg,
				handle_del_sel_clear, data);
}

static void
handle_sel_delete(ipmi_mc_t  *mc,
		  ipmi_msg_t *rsp,
		  void       *rsp_data)
{
    sel_del_handler_data_t *data = rsp_data;
    ipmi_sel_info_t        *sel = data->sel;
    int                    rv = 0;
    
    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_delete): "
		 "SEL info was destroyed while an operation was in progress",
		 sel->name);
	sel_op_done(data, ECANCELED, 1);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_delete): "
		 "MC went away while SEL fetch was in progress",
		 sel->name);
	sel_op_done(data, ECANCELED, 1);
	goto out;
    }

    /* Special return codes. */
    if (rsp->data[0] == 0x80) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_delete): "
		 "Operation not supported on SEL delete",
		 sel->name);
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
	if (sel->sel_delete_lost_reservation)
	    ipmi_domain_stat_add(sel->sel_delete_lost_reservation, 1);
	/* Lost our reservation, retry the operation. */
	data->count++;
	rv = send_reserve_sel_for_delete(data, mc);
	if (!rv)
	    goto out_unlock;
    } else if (rsp->data[0]) {
	if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	    if (sel->sel_fail_delete_lost_reservation)
		ipmi_domain_stat_add(sel->sel_fail_delete_lost_reservation, 1);
	} else {
	    if (sel->sel_delete_errors)
		ipmi_domain_stat_add(sel->sel_delete_errors, 1);
	}
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_delete): "
		 "IPMI error from SEL delete: %x", sel->name, rsp->data[0]);
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
	    sel_event_holder_put(real_holder);
	    sel->del_sels--;
	}
    }

    sel_op_done(data, rv, 1);

 out:
    return;

 out_unlock:
    sel_unlock(sel);
}

static int
send_del_sel(sel_del_handler_data_t *data, ipmi_mc_t *mc)
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
    sel_del_handler_data_t *data = rsp_data;
    ipmi_sel_info_t        *sel = data->sel;
    int                    rv = 0;
    
    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_check): "
		 "SEL info was destroyed while SEL delete element was in"
		 " progress",
		 sel->name);
	sel_op_done(data, ECANCELED, 1);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_check): "
		 "MC went away while SEL delete element was in progress",
		 sel->name);
	sel_op_done(data, ECANCELED, 1);
	goto out;
    }

    /* Special return codes. */
    if (rsp->data[0] == IPMI_NOT_PRESENT_CC) {
	/* The entry is already gone, so just return no error. */
	sel_op_done(data, 0, 1);
	goto out;
    } else if (rsp->data[0]) {
	if (sel->sel_delete_errors)
	    ipmi_domain_stat_add(sel->sel_delete_errors, 1);
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(handle_sel_check): IPMI error from SEL check: %x",
		 sel->name, rsp->data[0]);
	sel_op_done(data, IPMI_IPMI_ERR_VAL(rsp->data[0]), 1);
	goto out;
    } else {
	ipmi_event_t *ch_event;
	ipmi_time_t  timestamp;

	if (rsp->data[5] < 0xe0)
	    timestamp = ipmi_get_uint32(rsp->data+6);
	else
	    timestamp = -1;
	ch_event = ipmi_event_alloc(ipmi_mc_convert_to_id(mc),
				    ipmi_get_uint16(rsp->data+3),
				    rsp->data[5],
				    timestamp,
				    rsp->data+6,
				    13);
	if (!ch_event) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%ssel.c(handle_sel_check): Could not allocate memory",
		     sel->name);
	    sel_op_done(data, ENOMEM, 1);
	    goto out;
	}

	if (data->event && (event_cmp(ch_event, data->event) != 0)) {
	    /* The event's don't match, so just finish. */
	    ipmi_event_free(ch_event);
	    sel_op_done(data, 0, 1);
	    goto out;
	}
	ipmi_event_free(ch_event);

	if (data->do_clear) {
	    /* Make sure that there is no next event. */
	    uint16_t next_ev = ipmi_get_uint16(rsp->data+1);

	    if (next_ev != 0xffff) {
		/* A new event was added after this one.  Fail the op. */
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "%ssel.c(handle_sel_check): "
			 "Clear SEL failed, new events in SEL",
			 sel->name);
		sel_op_done(data, EAGAIN, 1);
		goto out;
	    }

	    rv = send_del_clear(data, mc);
	    if (rv) {
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "%ssel.c(handle_sel_check): "
			 "Could not send SEL clear command: %x",
			 sel->name, rv);
		sel_op_done(data, rv, 1);
		goto out;
	    }
	} else {
	    rv = send_del_sel(data, mc);
	    if (rv) {
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "%ssel.c(handle_sel_check): "
			 "Could not send SEL delete command: %x",
			 sel->name, rv);
		sel_op_done(data, rv, 1);
		goto out;
	    } else if (data->record_id == sel->start_rec_id)
		/* We are deleting our "current" record (used for finding
		   the next record), make sure we start again from
		   scratch on the next fetch. */
		sel->start_rec_id = 0;
	}
    }
	

    sel_unlock(sel);

 out:
    return;
}

/* First get the entry, to make sure we are deleting the right one. */
static int
send_check_sel(sel_del_handler_data_t *data, ipmi_mc_t *mc)
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
    sel_del_handler_data_t *data = rsp_data;
    ipmi_sel_info_t        *sel = data->sel;
    int                    rv;

    sel_lock(sel);
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_reserved_for_delete): "
		 "SEL info was destroyed while SEL delete element was in"
		 " progress",
		 sel->name);
	sel_op_done(data, ECANCELED, 1);
	goto out;
    }
    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_reserved_for_delete): "
		 "MC went away while SEL delete element was in progress",
		 sel->name);
	sel_op_done(data, ECANCELED, 1);
	goto out;
    }

    if (rsp->data[0] != 0) {
	if (sel->sel_delete_errors)
	    ipmi_domain_stat_add(sel->sel_delete_errors, 1);
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_reserved_for_delete): "
		 "IPMI error from SEL delete reservation: %x",
		 sel->name, rsp->data[0]);
	sel_op_done(data, IPMI_IPMI_ERR_VAL(rsp->data[0]), 1);
	goto out;
    }

    data->reservation = ipmi_get_uint16(rsp->data+1);
    if (!data->do_clear || data->event) {
	rv = send_check_sel(data, mc);
	if (rv) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%ssel.c(sel_reserved_for_delete): "
		     "Could not send SEL get command: %x", sel->name, rv);
	    sel_op_done(data, rv, 1);
	    goto out;
	}
    } else {
	/* We are clearing the SEL and the user didn't supply an
	   event.  Don't worry about checking anything. */
	rv = send_del_clear(data, mc);
	if (rv) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%ssel.c(sel_reserved_for_delete): "
		     "Could not send SEL clear command: %x", sel->name, rv);
	    sel_op_done(data, rv, 1);
	    goto out;
	}
    }

    sel_unlock(sel);
 out:
    return;
}

static int
send_reserve_sel_for_delete(sel_del_handler_data_t *data, ipmi_mc_t *mc)
{
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_RESERVE_SEL_CMD;
    cmd_msg.data_len = 0;
    rv = ipmi_mc_send_command_sideeff(mc, data->lun,
				      &cmd_msg, sel_reserved_for_delete, data);

    return rv;
}

static void
start_del_sel_cb(ipmi_mc_t *mc, void *cb_data)
{
    sel_del_handler_data_t *data = cb_data;
    ipmi_sel_info_t        *sel = data->sel;
    int                    rv;

    /* Called with SEL lock held. */
    if (sel->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(start_del_sel_cb): "
		 "SEL info was destroyed while an operation was in progress",
		 sel->name);
	sel_op_done(data, ECANCELED, 1);
	goto out;
    }

    if (data->sel->supports_reserve_sel)
	rv = send_reserve_sel_for_delete(data, mc);
    else
	rv = send_check_sel(data, mc);

    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(start_del_sel_cb): could not send cmd: %x",
		 sel->name, rv);
	sel_op_done(data, rv, 1);
	goto out;
    }

    sel_unlock(sel);
 out:
    return;
}

static int
start_del_sel(void *cb_data, int shutdown)
{
    sel_del_handler_data_t *data = cb_data;
    ipmi_sel_info_t        *sel = data->sel;
    int                    rv;

    sel_lock(sel);
    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(start_del_sel): "
		 "SEL info was destroyed while an operation was in progress",
		 sel->name);
	sel_op_done(data, ECANCELED, 0);
	return OPQ_HANDLER_ABORTED;
    }

    if (data->holder && data->holder->cancelled) {
	/* Deleted by a clear, everything is ok. */
	sel_op_done(data, 0, 0);
	return OPQ_HANDLER_ABORTED;
    }

    rv = ipmi_mc_pointer_cb(sel->mc, start_del_sel_cb, data);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(start_del_sel_cb): MC went away during delete",
		 sel->name);
	sel_op_done(data, ECANCELED, 0);
	return OPQ_HANDLER_ABORTED;
    }

    return OPQ_HANDLER_STARTED;
}

typedef struct sel_del_event_info_s
{
    ipmi_sel_info_t       *sel;
    ipmi_event_t          *event;
    unsigned int          record_id;
    ipmi_sel_op_done_cb_t handler;
    void                  *cb_data;
    int                   cmp_event;
    int                   rv;
    int                   do_clear;
} sel_del_event_info_t;

static void
sel_del_event_cb(ipmi_mc_t *mc, void *cb_data)
{
    sel_del_event_info_t  *info = cb_data;
    ipmi_sel_info_t       *sel = info->sel;
    ipmi_event_t          *event = info->event;
    int                   cmp_event = info->cmp_event;
    sel_event_holder_t    *real_holder = NULL;
    ilist_iter_t          iter;
    int                   start_fetch = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	info->rv = EINVAL;
	goto out_unlock;
    }

    if (event) {
	ilist_init_iter(&iter, sel->events);
	ilist_unpositioned(&iter);
	real_holder = ilist_search_iter(&iter, recid_search_cmp,
				    &info->record_id);
	if (!real_holder) {
	    info->rv = EINVAL;
	    goto out_unlock;
	}

	if (cmp_event && (event_cmp(event, real_holder->event) != 0)) {
	    info->rv = EINVAL;
	    goto out_unlock;
	}

	if (! info->do_clear) {
	    if (real_holder->deleted) {
		info->rv = EINVAL;
		goto out_unlock;
	    }

	    real_holder->deleted = 1;
	    sel->num_sels--;
	    sel->del_sels++;

	    start_fetch = (sel->num_sels == 0) && (sel->del_sels > 1);
	}
    }

    /* Note that at this point we cannot check num_sels to see if it
       is zero and do a bulk clear.  A new event might be added to the
       SEL after this point, thus failing the bulk clear, and that
       would prevent the individual delete from happening.  But we can
       start a fetch if the value reaches zero, which is just as
       good. */

    if (sel->supports_delete_sel || info->do_clear) {
	sel_del_handler_data_t *data;
	opq_elem_t             *elem;

	/* We can delete the entry immediately, just do it. */
	data = ipmi_mem_alloc(sizeof(*data));
	elem = opq_alloc_elem();
	if (!data || !elem) {
	    if (! info->do_clear) {
		real_holder->deleted = 0;
		sel->num_sels++;
		sel->del_sels--;
	    }
	    info->rv = ENOMEM;
	    if (data)
		ipmi_mem_free(data);
	    if (elem)
		opq_free_elem(elem);
	    goto out_unlock;
	}

	data->sel = sel;
	data->handler = info->handler;
	data->cb_data = info->cb_data;
	data->lun = sel->lun;
	data->record_id = info->record_id;
	data->count = 0;
	data->event = event;
	data->holder = real_holder;
	if (real_holder)
	    sel_event_holder_get(real_holder);
	data->do_clear = info->do_clear;
	event = NULL;

	sel_unlock(sel);
	opq_new_op_prio(sel->opq, start_del_sel, data, 0, OPQ_ADD_TAIL, elem);
    } else {
	sel_unlock(sel);
	/* Don't really delete the event, but report is as done. */
	info->handler(sel, info->cb_data, 0);
	ipmi_event_free(event);
    }

    if (start_fetch)
	ipmi_sel_get(sel, NULL, NULL);
    return;

 out_unlock:
    sel_unlock(sel);
}

static int
sel_del_event(ipmi_sel_info_t       *sel,
	      ipmi_event_t          *event,
	      unsigned int          record_id,
	      ipmi_sel_op_done_cb_t handler,
	      void                  *cb_data,
	      int                   cmp_event,
	      int                   do_clear)
{
    sel_del_event_info_t info;
    int                  rv;

    info.sel = sel;
    info.event = ipmi_event_dup(event);
    info.record_id = record_id;
    info.handler = handler;
    info.cb_data = cb_data;
    info.cmp_event = cmp_event;
    info.rv = 0;
    info.do_clear = do_clear;
    rv = ipmi_mc_pointer_cb(sel->mc, sel_del_event_cb, &info);
    if (!rv)
	rv = info.rv;
    if (rv)
	ipmi_event_free(info.event);
    return rv;
}

int
ipmi_sel_del_event(ipmi_sel_info_t       *sel,
		   ipmi_event_t          *event,
		   ipmi_sel_op_done_cb_t handler,
		   void                  *cb_data)
{
    return sel_del_event(sel, event, ipmi_event_get_record_id(event),
			 handler, cb_data, 1, 0);
}

int
ipmi_sel_del_event_by_recid(ipmi_sel_info_t       *sel,
			    unsigned int          record_id,
			    ipmi_sel_op_done_cb_t handler,
			    void                  *cb_data)
{
    return sel_del_event(sel, NULL, record_id, handler, cb_data, 0, 0);
}

int
ipmi_sel_clear(ipmi_sel_info_t       *sel,
	       ipmi_event_t          *last_event,
	       ipmi_sel_op_done_cb_t handler,
	       void                  *cb_data)
{
    int cmp_event = (last_event != NULL);
    unsigned int record_id = 0;
    if (last_event)
	record_id = ipmi_event_get_record_id(last_event);
    return sel_del_event(sel, last_event, record_id, handler, cb_data,
			 cmp_event, 1);
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

ipmi_event_t *
ipmi_sel_get_first_event(ipmi_sel_info_t *sel)
{
    ilist_iter_t iter;
    ipmi_event_t *rv = NULL;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return NULL;
    }
    ilist_init_iter(&iter, sel->events);
    if (ilist_first(&iter)) {
	sel_event_holder_t *holder = ilist_get(&iter);

	while (holder->deleted) {
	    if (! ilist_next(&iter))
		goto out;
	    holder = ilist_get(&iter);
	}
	rv = ipmi_event_dup(holder->event);
    }
 out:
    sel_unlock(sel);
    return rv;
}

ipmi_event_t *
ipmi_sel_get_last_event(ipmi_sel_info_t *sel)
{
    ilist_iter_t iter;
    ipmi_event_t *rv = NULL;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return NULL;
    }
    ilist_init_iter(&iter, sel->events);
    if (ilist_last(&iter)) {
	sel_event_holder_t *holder = ilist_get(&iter);

	while (holder->deleted) {
	    if (! ilist_prev(&iter))
		goto out;
	    holder = ilist_get(&iter);
	}
	rv = ipmi_event_dup(holder->event);
    }
 out:
    sel_unlock(sel);
    return rv;
}

ipmi_event_t *
ipmi_sel_get_next_event(ipmi_sel_info_t *sel, const ipmi_event_t *event)
{
    ilist_iter_t iter;
    ipmi_event_t *rv = NULL;
    unsigned int record_id;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return NULL;
    }
    ilist_init_iter(&iter, sel->events);
    ilist_unpositioned(&iter);
    record_id = ipmi_event_get_record_id(event);
    if (ilist_search_iter(&iter, recid_search_cmp, &record_id)) {
	if (ilist_next(&iter)) {
	    sel_event_holder_t *holder = ilist_get(&iter);

	    while (holder->deleted) {
		if (! ilist_next(&iter))
		    goto out;
		holder = ilist_get(&iter);
	    }
	    rv = ipmi_event_dup(holder->event);
	}
    }
 out:
    sel_unlock(sel);
    return rv;
}

ipmi_event_t *
ipmi_sel_get_prev_event(ipmi_sel_info_t *sel, const ipmi_event_t *event)
{
    ilist_iter_t iter;
    ipmi_event_t *rv = NULL;
    unsigned int record_id;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return NULL;
    }
    ilist_init_iter(&iter, sel->events);
    ilist_unpositioned(&iter);
    record_id = ipmi_event_get_record_id(event);
    if (ilist_search_iter(&iter, recid_search_cmp, &record_id)) {
	if (ilist_prev(&iter)) {
	    sel_event_holder_t *holder = ilist_get(&iter);

	    while (holder->deleted) {
		if (! ilist_prev(&iter))
		    goto out;
		holder = ilist_get(&iter);
	    }
	    rv = ipmi_event_dup(holder->event);
	}
    }
 out:
    sel_unlock(sel);
    return rv;
}

ipmi_event_t *
ipmi_sel_get_event_by_recid(ipmi_sel_info_t *sel,
                            unsigned int    record_id)
{
    ipmi_event_t       *rv = NULL;
    sel_event_holder_t *holder;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return NULL;
    }

    holder = find_event(sel->events, record_id);
    if (!holder)
	goto out_unlock;

    if (holder->deleted)
        goto out_unlock;

    rv = ipmi_event_dup(holder->event);

 out_unlock:
    sel_unlock(sel);
    return rv;
}

int
ipmi_get_all_sels(ipmi_sel_info_t *sel,
		  int             *array_size,
		  ipmi_event_t    **array)
{
    unsigned int i;
    int          rv = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    if (*array_size < (int) sel->num_sels) {
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
		array[i] = ipmi_event_dup(holder->event);
	    }
	    i++;
	    if (i < sel->num_sels) {
		if (! ilist_next(&iter)) {
		    rv = EINVAL;
		    i--;
		    while (i >= 0)
			ipmi_event_free(array[i]);
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
ipmi_sel_get_num_entries(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *val = sel->entries;

    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_get_free_bytes(ipmi_sel_info_t *sel, int *val)
{
    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    *val = sel->free_bytes;

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
    sel_lock(sel);
    sel->new_event_handler = handler;
    sel->new_event_cb_data = cb_data;
    sel_unlock(sel);
    return 0;
}

int
ipmi_sel_event_add(ipmi_sel_info_t *sel,
		   ipmi_event_t    *new_event)
{
    int                rv = 0;
    sel_event_holder_t *holder;
    unsigned int       record_id;

    sel_lock(sel);
    if (sel->destroyed) {
	sel_unlock(sel);
	return EINVAL;
    }

    record_id = ipmi_event_get_record_id(new_event);
    holder = find_event(sel->events, record_id);
    if (!holder) {
	holder = sel_event_holder_alloc();
	if (!holder) {
	    rv = ENOMEM;
	    goto out_unlock;
	}
	if (!ilist_add_tail(sel->events, holder, NULL)) {
	    rv = ENOMEM;
	    goto out_unlock;
	}
	holder->event = ipmi_event_dup(new_event);
	sel->num_sels++;
    } else if (event_cmp(holder->event, new_event) == 0) {
	/* A duplicate event, just ignore it and return the right
	   error. */
	rv = EEXIST;
    } else {
	ipmi_event_free(holder->event);
	holder->event = ipmi_event_dup(new_event);
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
    ipmi_event_t              *event;
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
	sel_unlock(sel);
	opq_op_done(sel->opq);
    }
    if (data->event)
	ipmi_event_free(data->event);
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
		 "%ssel.c(sel_add_event_done): "
		 "SEL info was destroyed while an operation was in progress",
		 sel->name);
	sel_add_op_done(info, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_add_event_done): "
		 "MC went away while SEL op was in progress", sel->name);
        sel_add_op_done(info, ECANCELED);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_add_event_done): "
		 "IPMI error from SEL info fetch: %x",
		 sel->name, rsp->data[0]);
	sel_add_op_done(info, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    if (rsp->data_len < 3) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_add_event_done): SEL add response too short",
		 sel->name);
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
    ipmi_event_t              *event = info->event;
    unsigned char             data[16];
    ipmi_msg_t                msg;

    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_ADD_SEL_ENTRY_CMD;
    msg.data = data;
    msg.data_len = 16;

    ipmi_set_uint16(data, ipmi_event_get_record_id(event));
    data[2] = ipmi_event_get_type(event);
    memcpy(data+3, ipmi_event_get_data_ptr(event), 13);

    info->rv = ipmi_mc_send_command(mc, sel->lun, &msg, sel_add_event_done,
				    info);
}

static int
sel_add_event_op(void *cb_data, int shutdown)
{
    sel_add_cb_handler_data_t *info = cb_data;
    ipmi_sel_info_t           *sel = info->sel;
    int                       rv;

    sel_lock(sel);
    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_add_event_op): "
		 "SEL info was destroyed while an operation was in progress",
		 sel->name);
	sel_add_op_done(info, ECANCELED);
	goto out;
    }

    rv = ipmi_mc_pointer_cb(sel->mc, sel_add_event_cb, info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_add_event_op): MC went away during delete",
		 sel->name);
	sel_add_op_done(info, ECANCELED);
	goto out;
    } else if (info->rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssel.c(sel_add_event_cb): could not send cmd: %x",
		 sel->name, rv);
	sel_add_op_done(info, info->rv);
	goto out;
    }

    sel_unlock(sel);
 out:
    return OPQ_HANDLER_STARTED;
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
    info->event = ipmi_event_dup(event_to_add);
    info->handler = done;
    info->cb_data = cb_data;
    info->record_id = 0;

    sel_lock(sel);
    if (sel->destroyed) {
	rv = EINVAL;
	goto out_unlock;
    }

    sel_unlock(sel);

    /* Schedule this to run at the end of the queue. */
    if (!opq_new_op(sel->opq, sel_add_event_op, info, 0)) {
	rv = ENOMEM;
	goto out_unlock;
    }
    goto out;

 out_unlock:
    sel_unlock(sel);

 out:
    if (rv)
	ipmi_mem_free(info);
    return rv;
}
