/*
 * sdr.c
 *
 * MontaVista IPMI code for handling SDRs
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
#include <OpenIPMI/ipmi_sdr.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/opq.h>
#include <OpenIPMI/ilist.h>

/* Max bytes to try to get at a time. */
#define MAX_SDR_FETCH 20

/* Do up to this many retries when the reservation is lost. */
#define MAX_SDR_FETCH_RETRIES 10

/* Number of outstanding fetch requests we can have out. */
#define MAX_SDR_FETCH_OUTSTANDING 3

typedef struct sdr_fetch_handler_s
{
    ipmi_sdr_info_t     *sdrs;
    ipmi_sdrs_fetched_t handler;
    void                *cb_data;
} sdr_fetch_handler_t;

enum fetch_state_e { IDLE, FETCHING, HANDLERS };

typedef struct fetch_info_s
{
    unsigned int fetch_retry_num;

    ipmi_sdr_info_t *sdrs;

    unsigned int sdr_rec;
    unsigned int idx;
    unsigned int offset;
    unsigned int read_len;
    unsigned char data[MAX_SDR_FETCH+2];

    ilist_item_t link;
} fetch_info_t;

struct ipmi_sdr_info_s
{
    /* The thing holding the SDR repository. */
    ipmi_mcid_t mc;

    /* The OS handler for this SDR. */
    os_handler_t *os_hnd;

    /* LUN we are attached with. */
    int         lun;

    /* Is this for sensor SDRs or main SDRs. */
    int         sensor;

    /* A lock, primarily for handling race conditions fetching the data. */
    ipmi_lock_t *sdr_lock;

    opq_t *sdr_wait_q;
    int   wait_err;

    /* Information from the SDR Repository Info command, non-sensor
       mode only. */
    uint8_t  major_version;
    uint8_t  minor_version;
    uint32_t last_addition_timestamp;
    uint32_t last_erase_timestamp;
    unsigned int overflow : 1;
    unsigned int update_mode : 2;
    unsigned int supports_delete_sdr : 1;
    unsigned int supports_partial_add_sdr : 1;
    unsigned int supports_reserve_sdr : 1;
    unsigned int supports_get_sdr_repository_allocation : 1;

    /* Information from the GET DEVICE SDR INFO command, sensor mode
       only. */
    unsigned int dynamic_population : 1;
    char lun_has_sensors[4];

    /* Have the SDRs previously been fetched? */
    unsigned int fetched : 1;

    /* Has the SDR been destroyed?  This is here because of race
       conditions in shutdown.  If we are currently in the process of
       fetching SDRs, we will allow a destroy operation to complete,
       but we don't actually destroy the data until the SDR fetch
       reaches a point were it can be stopped safely. */
    unsigned int destroyed : 1;
    /* Something to call when the destroy is complete. */
    ipmi_sdr_destroyed_t destroy_handler;
    void                 *destroy_cb_data;

    /* Are we currently fetching SDRs? */
    enum fetch_state_e fetch_state;

    /* When fetching the data in event-driven mode, these are the
       variables that track what is going on. */
    int                    curr_rec_id;
    int                    read_offset; /* Next data to read, -1 if
                                           the header */

    int                    curr_read_rec_id;
    int                    next_read_rec_id;
    int                    curr_read_idx;
    int                    next_read_offset; /* -1 if header */
    int                    read_size;

    unsigned int           reservation;
    int                    working_num_sdrs;
    ipmi_sdr_t             *working_sdrs;
    int                    sdrs_changed;
    int                    fetch_retry_count;
    int                    sdr_retry_count;
    int                    fetch_err;

    int                    sdr_data_write;
    int                    write_sdr_num;

    /* List of fetch info items for an in-progress fetch.  The free
       list holds fetch structures that are not currently in use, the
       outstanding list holds ones that have been sent but have not
       received a response, and the process queue holds one received
       out of order. */
    ilist_t *free_fetch;
    ilist_t *outstanding_fetch;
    ilist_t *process_fetch;

    /* This is used so that start_fetch will only start when nothing
       is outstanding from other fetches.  This avoids getting
       messages that are not valid, running out of buffers, and other
       confusing things. */
    int waiting_start_fetch;

    /* This timer is used to restart the SDR fetch operation.  If it
       fails due to a lost reservation, wait a random amount of time
       and restart it. */
    os_hnd_timer_id_t *restart_timer;

    /* The actual current copy of the SDR repository. */
    unsigned int num_sdrs;
    unsigned int sdr_array_size;
    ipmi_sdr_t *sdrs;
};


static inline void sdr_lock(ipmi_sdr_info_t *sdrs)
{
    ipmi_lock(sdrs->sdr_lock);
}

static inline void sdr_unlock(ipmi_sdr_info_t *sdrs)
{
    ipmi_unlock(sdrs->sdr_lock);
}

static void
free_fetch(ilist_iter_t *iter, void *item, void *cb_data)
{
    ilist_delete(iter);
    ipmi_mem_free(item);
}

static void
cancel_fetch(ilist_iter_t *iter, void *item, void *cb_data)
{
    fetch_info_t *info = item;

    info->fetch_retry_num = -1;
    ilist_delete(iter);
}

static void
cleanup_fetch_items(ipmi_sdr_info_t *sdrs)
{
    ilist_iter(sdrs->free_fetch, free_fetch, NULL);
    ilist_iter(sdrs->process_fetch, free_fetch, NULL);
    ilist_iter(sdrs->outstanding_fetch, cancel_fetch, NULL);
}

int
ipmi_sdr_info_alloc(ipmi_domain_t   *domain,
		    ipmi_mc_t       *mc,
		    unsigned int    lun,
		    int             sensor,
		    ipmi_sdr_info_t **new_sdrs)
{
    ipmi_sdr_info_t *sdrs = NULL;
    int             rv;
    fetch_info_t    *info;
    int             i;
    os_handler_t    *os_hnd = ipmi_domain_get_os_hnd(domain);

    CHECK_MC_LOCK(mc);

    if (lun >= 4)
	return EINVAL;

    sdrs = ipmi_mem_alloc(sizeof(*sdrs));
    if (!sdrs) {
	rv = ENOMEM;
	goto out;
    }
    memset(sdrs, 0, sizeof(*sdrs));


    sdrs->mc = ipmi_mc_convert_to_id(mc);
    sdrs->os_hnd = os_hnd;
    sdrs->destroyed = 0;
    sdrs->sdr_lock = NULL;
    sdrs->fetched = 0;
    sdrs->fetch_state = IDLE;
    sdrs->sdrs = NULL;
    sdrs->num_sdrs = 0;
    sdrs->sdr_array_size = 0;
    sdrs->destroy_handler = NULL;
    sdrs->lun = lun;
    sdrs->sensor = sensor;
    sdrs->sdr_wait_q = NULL;

    /* Assume we have a dynamic population until told otherwise. */
    sdrs->dynamic_population = 1;

    rv = ipmi_create_lock(domain, &sdrs->sdr_lock);
    if (rv)
	goto out_done;

    rv = os_hnd->alloc_timer(os_hnd, &(sdrs->restart_timer));
    if (rv)
	goto out_done;

    sdrs->free_fetch = alloc_ilist();
    if (!sdrs->free_fetch) {
	rv = ENOMEM;
	goto out_done;
    }

    sdrs->outstanding_fetch = alloc_ilist();
    if (!sdrs->outstanding_fetch) {
	rv = ENOMEM;
	goto out_done;
    }

    for (i=0; i<MAX_SDR_FETCH_OUTSTANDING; i++) {
	info = ipmi_mem_alloc(sizeof(*info));
	info->sdrs = sdrs;
	if (!info) {
	    rv = ENOMEM;
	    goto out_done;
	}
	ilist_add_tail(sdrs->free_fetch, info, &info->link);
    }

    sdrs->process_fetch = alloc_ilist();
    if (!sdrs->process_fetch) {
	rv = ENOMEM;
	goto out_done;
    }

    sdrs->sdr_wait_q = opq_alloc(os_hnd);
    if (! sdrs->sdr_wait_q) {
	rv = ENOMEM;
	goto out_done;
    }

 out_done:
    if (rv) {
	if (sdrs) {
	    if (sdrs->free_fetch) {
		ilist_iter(sdrs->free_fetch, free_fetch, NULL);
		free_ilist(sdrs->free_fetch);
	    }
	    if (sdrs->outstanding_fetch)
		free_ilist(sdrs->outstanding_fetch);
	    if (sdrs->process_fetch)
		free_ilist(sdrs->process_fetch);
	    if (sdrs->sdr_lock)
		ipmi_destroy_lock(sdrs->sdr_lock);
	    ipmi_mem_free(sdrs);
	}
    } else {
	*new_sdrs = sdrs;
    }
 out:
    return rv;
}

static void
internal_destroy_sdr_info(ipmi_sdr_info_t *sdrs)
{
    /* We don't have to have a valid ipmi to destroy an SDR, they are
       designed to live after the ipmi has been destroyed. */

    cleanup_fetch_items(sdrs);

    sdr_unlock(sdrs);

    free_ilist(sdrs->free_fetch);
    free_ilist(sdrs->outstanding_fetch);
    free_ilist(sdrs->process_fetch);

    /* We don't have to worry about stopping the timer, this can't be
       called if the timer is running, because a fetch operation would
       be in progress if that was the case. */
    sdrs->os_hnd->free_timer(sdrs->os_hnd, sdrs->restart_timer);

    opq_destroy(sdrs->sdr_wait_q);

    ipmi_destroy_lock(sdrs->sdr_lock);

    /* Do this after we have gotten rid of all external dependencies,
       but before it is free. */
    if (sdrs->destroy_handler)
	sdrs->destroy_handler(sdrs, sdrs->destroy_cb_data);

    if (sdrs->sdrs)
	ipmi_mem_free(sdrs->sdrs);
    ipmi_mem_free(sdrs);
}

int
ipmi_sdr_info_destroy(ipmi_sdr_info_t      *sdrs,
		      ipmi_sdr_destroyed_t handler,
		      void                 *cb_data)
{
    /* We don't need the read lock, because the sdrs are stand-alone
       after they are created (except for fetching SDRs, of course). */
    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	sdr_unlock(sdrs);
	return EINVAL;
    }
    sdrs->destroyed = 1;
    sdrs->destroy_handler = handler;
    sdrs->destroy_cb_data = cb_data;
    if (sdrs->fetch_state != IDLE) {
	/* It's currently in fetch state, so let it be destroyed in
           the handler, since we can't cancel the handler or
           operation. */
	sdr_unlock(sdrs);
	return 0;
    }

    /* This unlocks the lock. */
    internal_destroy_sdr_info(sdrs);
    return 0;
}

/* Must be called with the SDR locked.  This will unlock the SDR
   before calling the callback, and will return with the sdr unlocked. */
static void
fetch_complete(ipmi_sdr_info_t *sdrs, int err)
{
    sdrs->wait_err = err;
    if (err) {
	if (sdrs->working_sdrs) {
	    ipmi_mem_free(sdrs->working_sdrs);
	    sdrs->working_sdrs = NULL;
	}
    } else {
	sdrs->fetched = 1;
	sdrs->num_sdrs = sdrs->curr_read_idx+1;
	sdrs->sdr_array_size = sdrs->num_sdrs;
	sdrs->sdrs = sdrs->working_sdrs;
	sdrs->working_sdrs = NULL;
    }
    sdrs->fetch_state = HANDLERS;
    sdr_unlock(sdrs);

    opq_op_done(sdrs->sdr_wait_q);

    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	internal_destroy_sdr_info(sdrs);
	/* The previous call unlocks the lock. */
	return;
    }

    if (sdrs->fetch_state == HANDLERS)
	/* The fetch process wasn't restarted, so go to IDLE. */
	sdrs->fetch_state = IDLE;

    sdr_unlock(sdrs);
}

static int start_fetch(ipmi_sdr_info_t *sdrs, ipmi_mc_t *mc, int delay);

static void
handle_reservation_check(ipmi_mc_t  *mc,
			 ipmi_msg_t *rsp,
			 void       *rsp_data)
{
    int             rv;
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) rsp_data;

    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in"
		 " progress(1)");
	fetch_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress(1)");
	fetch_complete(sdrs, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* We lost our reservation, restart the operation.  Only do
           this so many times, in order to guarantee that this
           completes. */
	sdrs->fetch_retry_count++;
	if (sdrs->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "Lost reservation too many times trying to"
		     " fetch the SDRs");
	    fetch_complete(sdrs, EBUSY);
	    goto out;
	} else {
	    if (sdrs->working_sdrs) {
		ipmi_mem_free(sdrs->working_sdrs);
		sdrs->working_sdrs = NULL;
	    }
	    rv = start_fetch(sdrs, mc, 1);
	    if (rv) {
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "Could not start the SDR fetch: %x", rv);
		fetch_complete(sdrs, rv);
		goto out;
	    }
	}
	sdr_unlock(sdrs);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "IPMI error from SDR fetch reservation check: %x",
		 rsp->data[0]);
	fetch_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    fetch_complete(sdrs, 0);
 out:
    return;
}

/* Must be called with the sdr lock held, it will release it and
   return with the lock not held. */
static void
start_reservation_check(ipmi_sdr_info_t *sdrs, ipmi_mc_t *mc)
{
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;

    /* We block the wait queue so any new members after this will be
       always fetch all the SDRs.  Then we do one final fetch to check
       our reservation.  There are possible race conditions where an
       event comes in right at the end of an SDR fetch, if we didn't
       do this, it's possible that we would not re-fetch the SDRs when
       they have changed due to an event. */
    opq_add_block(sdrs->sdr_wait_q);
    
    cmd_msg.data = cmd_data;
    if (sdrs->sensor) {
	cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	cmd_msg.cmd = IPMI_GET_DEVICE_SDR_CMD;
    } else {
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_GET_SDR_CMD;
    }
    cmd_msg.data_len = 6;
    ipmi_set_uint16(cmd_msg.data, sdrs->reservation);
    ipmi_set_uint16(cmd_msg.data+2, 0);
    cmd_msg.data[4] = 0;
    cmd_msg.data[5] = 1; /* Only care about the reservation */
    rv = ipmi_mc_send_command(mc, sdrs->lun, &cmd_msg,
			      handle_reservation_check, sdrs);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Could not send command to get an SDR: %x", rv);
	fetch_complete(sdrs, rv);
	return;
    }
    sdr_unlock(sdrs);
}

#define SDR_HEADER_SIZE 5
static void
process_sdr_info(ipmi_sdr_info_t *sdrs, fetch_info_t *info)
{
    ipmi_sdr_t *sdr;

    sdr = &sdrs->working_sdrs[info->idx];
    if (info->offset == 0) {
	sdr->record_id = ipmi_get_uint16(info->data+2);
	sdr->major_version = info->data[4] & 0xf;
	sdr->minor_version = (info->data[4] >> 4) & 0xf;
	sdr->type = info->data[5];
	sdr->length = info->data[6];
    } else {
	memcpy(&sdr->data[info->offset-SDR_HEADER_SIZE],
	       info->data+2, info->read_len);
    }
    if (info->offset+info->read_len == sdr->length+SDR_HEADER_SIZE) {
	sdrs->curr_rec_id = ipmi_get_uint16(info->data);
	sdrs->read_offset = 0;
    } else {
	sdrs->read_offset += info->read_len;
    }
}

typedef struct process_info_s
{
    ipmi_sdr_info_t *sdrs;
    int processed;
} process_info_t;

static void
check_and_process_info(ilist_iter_t *iter, void *item, void *cb_data)
{
    process_info_t  *pinfo = cb_data;
    ipmi_sdr_info_t *sdrs = pinfo->sdrs;
    fetch_info_t    *info = item;

    if ((info->sdr_rec == sdrs->curr_rec_id)
	&& (info->offset == sdrs->read_offset))
    {
	if (iter)
	    ilist_delete(iter);
	pinfo->processed = 1;
	process_sdr_info(sdrs, info);
	ilist_add_tail(sdrs->free_fetch, info, &info->link);
    }
}

typedef struct cancel_same_or_newer_s
{
    ipmi_sdr_info_t *sdrs;
    int             idx;
} cancel_same_or_newer_t;

static void
cancel_if_same_or_newer(ilist_iter_t *iter, void *item, void *cb_data)
{
    cancel_same_or_newer_t *info = cb_data;
    fetch_info_t           *finfo = item;

    if (finfo->idx >= info->idx)
	finfo->fetch_retry_num = -1;
}

static void
free_if_same_or_newer(ilist_iter_t *iter, void *item, void *cb_data)
{
    cancel_same_or_newer_t *info = cb_data;
    fetch_info_t           *finfo = item;

    if (finfo->idx >= info->idx) {
	ilist_delete(iter);
	ilist_add_tail(info->sdrs->free_fetch, finfo, &finfo->link);
    }
}

static void
cancel_same_or_newer(ipmi_sdr_info_t *sdrs, int idx)
{
    cancel_same_or_newer_t info;

    info.sdrs = sdrs;
    info.idx = idx;
    ilist_iter(sdrs->outstanding_fetch, cancel_if_same_or_newer, &info);
    ilist_iter(sdrs->process_fetch, free_if_same_or_newer, &info);
}

static void handle_sdr_data(ipmi_mc_t  *mc,
			    ipmi_msg_t *rsp,
			    void       *rsp_data);

static int
info_send(ipmi_sdr_info_t *sdrs, fetch_info_t *info, ipmi_mc_t *mc)
{
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;

    cmd_msg.data = cmd_data;
    if (sdrs->sensor) {
	cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	cmd_msg.cmd = IPMI_GET_DEVICE_SDR_CMD;
    } else {
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_GET_SDR_CMD;
    }
    cmd_msg.data_len = 6;
    ipmi_set_uint16(cmd_msg.data, sdrs->reservation);
    ipmi_set_uint16(cmd_msg.data+2, info->sdr_rec);
    cmd_msg.data[4] = info->offset;
    cmd_msg.data[5] = info->read_len;

    rv = ipmi_mc_send_command(mc, sdrs->lun, &cmd_msg,
			      handle_sdr_data, info);
    if (rv) {
	ilist_add_tail(sdrs->free_fetch, info, &info->link);
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "initial_sdr_fetch: Couldn't send first SDR fetch: %x", rv);
	ilist_add_tail(sdrs->free_fetch, info, &info->link);
	fetch_complete(sdrs, rv);
    } else {
	ilist_add_tail(sdrs->outstanding_fetch, info, &info->link);
    }

    return rv;
}

static void
handle_sdr_data(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *rsp_data)
{
    fetch_info_t    *info = rsp_data;
    ipmi_sdr_info_t *sdrs = info->sdrs;
    process_info_t  pinfo;
    int             rv;

    sdr_lock(sdrs);
    if (! ilist_remove_item_from_list(sdrs->outstanding_fetch, info)) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "Got SDR data but the info was not in the"
		 " outstanding operation list");
	goto out_unlock;
    }

    if (sdrs->destroyed) {
	ilist_add_tail(sdrs->free_fetch, info, &info->link);
	if (!ilist_empty(sdrs->outstanding_fetch))
	    goto out_unlock;

	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in"
		 " progress(2)");
	fetch_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ilist_add_tail(sdrs->free_fetch, info, &info->link);
	if (!ilist_empty(sdrs->outstanding_fetch))
	    goto out_unlock;

	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress(2)");
	fetch_complete(sdrs, ENXIO);
	goto out;
    }

    if (sdrs->waiting_start_fetch) {
	/* A start fetch operation is waiting for the outstanding
           queue to clear, so free this and try again. */
	ilist_add_tail(sdrs->free_fetch, info, &info->link);

	rv = start_fetch(sdrs, mc, 1);
	if (rv) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "Could not start the SDR fetch: %x", rv);
	    fetch_complete(sdrs, rv);
	    goto out;
	}
	goto out_unlock;
    }
	
    if (info->fetch_retry_num != sdrs->fetch_retry_count) {
	ilist_add_tail(sdrs->free_fetch, info, &info->link);

	if (sdrs->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    if (!ilist_empty(sdrs->outstanding_fetch))
		goto out_unlock;

	    fetch_complete(sdrs, sdrs->fetch_err);
	    goto out;
	}

	goto out_nextmsg;
    }

    if (rsp->data[0] == 0x80) {
	/* Data changed during fetch, retry.  Only do this so many
           times before giving up. */
	sdrs->sdr_retry_count++;
	if (sdrs->sdr_retry_count > MAX_SDR_FETCH_RETRIES) {
	    /* Cause the operation to be terminated. */
	    sdrs->fetch_retry_count = MAX_SDR_FETCH_RETRIES+1;
	    ilist_add_tail(sdrs->free_fetch, info, &info->link);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "To many retries trying to fetch SDRs");

	    sdrs->fetch_err = EBUSY;

	    if (!ilist_empty(sdrs->outstanding_fetch))
		goto out_unlock;

	    fetch_complete(sdrs, EBUSY);
	    goto out;
	}

	/* Cancel any current or newer pending operations. */
	cancel_same_or_newer(sdrs, info->idx);

	/* Re-start the fetch on the SDR. */
	sdrs->next_read_offset = -1;
	sdrs->read_size = -1;
	sdrs->next_read_rec_id = info->sdr_rec;
	sdrs->curr_read_idx = info->idx-1;

	ilist_add_tail(sdrs->free_fetch, info, &info->link);
	goto out_nextmsg;
    }

    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* We lost our reservation, restart the operation.  Only do
           this so many times, in order to guarantee that this
           completes. */
	ilist_add_tail(sdrs->free_fetch, info, &info->link);
	sdrs->fetch_retry_count++;
	if (sdrs->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "Lost reservation too many times trying to fetch SDRs");

	    sdrs->fetch_err = EBUSY;

	    if (!ilist_empty(sdrs->outstanding_fetch))
		goto out_unlock;

	    fetch_complete(sdrs, EBUSY);
	    goto out;
	} else {
	    if (sdrs->working_sdrs) {
		ipmi_mem_free(sdrs->working_sdrs);
		sdrs->working_sdrs = NULL;
	    }
	    rv = start_fetch(sdrs, mc, 1);
	    if (rv) {
		/* Cause the fetch to be aborted. */
		sdrs->fetch_retry_count = MAX_SDR_FETCH_RETRIES+1;
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "Could not start SDR fetch: %x", rv);

		sdrs->fetch_err = rv;

		if (!ilist_empty(sdrs->outstanding_fetch))
		    goto out_unlock;

		fetch_complete(sdrs, rv);
		goto out;
	    }
	}
	goto out_unlock;
    }

    if ((info->sdr_rec == 0)
	&& ((rsp->data[0] == IPMI_UNKNOWN_ERR_CC)
	    || (rsp->data[0] == IPMI_NOT_PRESENT_CC)))
    {
	/* We got an error fetching the first SDR, so the repository is
	   probably empty.  Just go on. */
	ilist_add_tail(sdrs->free_fetch, info, &info->link);
	start_reservation_check(sdrs, mc);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ilist_add_tail(sdrs->free_fetch, info, &info->link);
	sdrs->fetch_retry_count = MAX_SDR_FETCH_RETRIES+1;

	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR fetch error getting sdr 0x%x: %x",
		 info->sdr_rec,
		 rsp->data[0]);

	sdrs->fetch_err = IPMI_IPMI_ERR_VAL(rsp->data[0]);

	if (!ilist_empty(sdrs->outstanding_fetch))
	    goto out_unlock;

	fetch_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    if (rsp->data_len != info->read_len+3) {
	/* We got back an invalid amount of data, abort */
	ilist_add_tail(sdrs->free_fetch, info, &info->link);
	sdrs->fetch_retry_count = MAX_SDR_FETCH_RETRIES+1;
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Got an invalid amount of SDR data: %d, expected %d",
		 rsp->data_len, info->read_len+3);

	sdrs->fetch_err = EINVAL;

	if (!ilist_empty(sdrs->outstanding_fetch))
	    goto out_unlock;

	fetch_complete(sdrs, EINVAL);
	goto out;
    }

    /* We have a good response */

    /* First handle the info for fetching data. */
    if (info->offset == 0) {
	/* We read a header. */
	sdrs->read_size = rsp->data[7] + SDR_HEADER_SIZE;
	sdrs->next_read_rec_id = ipmi_get_uint16(rsp->data+1);
	sdrs->next_read_offset = info->read_len;
    }

    /* Now process it for the user. */
    memcpy(info->data, rsp->data+1, rsp->data_len-1);

    pinfo.processed = 0;
    pinfo.sdrs = sdrs;
    check_and_process_info(NULL, info, &pinfo);
    if (pinfo.processed) {
	/* Since we may have processed a previous one, check the ones
	   we have already received that were received out of
	   order. */
	ilist_iter(sdrs->process_fetch, check_and_process_info, &pinfo);
    } else {
	ilist_iter_t iter;
	int          pos;
	fetch_info_t *ninfo;
	int          found = 0;

	/* It is not the reponse we are expecting, just throw it onto
           the queue in order to be handled later. */
	ilist_init_iter(&iter, sdrs->process_fetch);
	pos = ilist_last(&iter);
	while (pos) {
	    ninfo = ilist_get(&iter);
	    if ((info->idx > ninfo->idx) || (info->offset > ninfo->offset)) {
		found = 1;
		break;
	    }
	    pos = ilist_prev(&iter);
	}

	if (found)
	    ilist_add_after(&iter, info, &info->link);
	else
	    ilist_add_before(&iter, info, &info->link);
    }

 out_nextmsg:
    while (!ilist_empty(sdrs->free_fetch)) {
	/* We have some free buffers, see what we can do with them. */

	if (sdrs->next_read_offset == 0)
	    /* We need to get the SDR header before we can go on. */
	    break;

	if (sdrs->next_read_offset == sdrs->read_size) {
	    /* Done with this SDR, time to go to the next. */
	    if (sdrs->next_read_rec_id == 0xffff) {
		/* This is the last SDR.  However, we don't go to the
		   next stage until all the outstanding fetches are
		   complete. */
		if (ilist_empty(sdrs->outstanding_fetch)) {
		    start_reservation_check(sdrs, mc);
		    goto out;
		}
		break;
	    }

	    if ((sdrs->curr_read_idx+1) >= sdrs->working_num_sdrs) {
		if (sdrs->sensor && (sdrs->working_num_sdrs < 512)) {
		    /* The get device SDR command (stupidly) only
		       reports the number of sensors, not the number
		       of SDRs.  So we have to be able to expand, but
		       keep it within reason (thus the "512" check
		       above). */
		    int new_num_sdrs = sdrs->working_num_sdrs + 10;
		    ipmi_sdr_t *new_sdrs;

		    new_sdrs = ipmi_mem_alloc(sizeof(ipmi_sdr_t)
					      * new_num_sdrs);
		    if (!new_sdrs) {
			ipmi_log(IPMI_LOG_ERR_INFO,
				 "SDR respository had more SDRs than"
				 " originally thougt, but could not expand"
				 " the SDR array because out of memory");
			fetch_complete(sdrs, ENOMEM);
			goto out;
		    }
		    memcpy(new_sdrs, sdrs->working_sdrs,
			   sdrs->working_num_sdrs * sizeof(ipmi_sdr_t));
		    ipmi_mem_free(sdrs->working_sdrs);
		    sdrs->working_sdrs = new_sdrs;
		    sdrs->working_num_sdrs = new_num_sdrs;
		} else {
		    ipmi_log(IPMI_LOG_ERR_INFO,
			     "Fetched more SDRs than the info said there were");
		
		    sdrs->fetch_err = EINVAL;
	    
		    if (!ilist_empty(sdrs->outstanding_fetch))
			goto out_unlock;
	    
		    fetch_complete(sdrs, EINVAL);
		    goto out;
		}
	    }
	}

	info = ilist_remove_first(sdrs->free_fetch);
	info->fetch_retry_num = sdrs->fetch_retry_count;

	if (sdrs->next_read_offset == sdrs->read_size) {
	    /* header is the next read. */
	    sdrs->curr_read_rec_id = sdrs->next_read_rec_id;
	    sdrs->curr_read_idx++;
	    sdrs->next_read_offset = 0;
	    info->offset = sdrs->next_read_offset;
	    info->read_len = SDR_HEADER_SIZE;
	} else {
	    info->read_len = sdrs->read_size - sdrs->next_read_offset;
	    if (info->read_len > MAX_SDR_FETCH)
		info->read_len = MAX_SDR_FETCH;
	    info->offset = sdrs->next_read_offset;
	    sdrs->next_read_offset += info->read_len;
	}
	
	info->sdr_rec = sdrs->curr_read_rec_id;
	info->idx = sdrs->curr_read_idx;
	rv = info_send(sdrs, info, mc);
	if (rv) {
	    sdrs->fetch_retry_count = MAX_SDR_FETCH_RETRIES+1;
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "Could not send SDR fetch: %x", rv);
	    
	    sdrs->fetch_err = rv;
	    
	    if (!ilist_empty(sdrs->outstanding_fetch))
		goto out_unlock;
	    
	    fetch_complete(sdrs, rv);
	    goto out;
	}
    }

 out_unlock:
    sdr_unlock(sdrs);
 out:
    return;
}

static int
initial_sdr_fetch(ipmi_sdr_info_t *sdrs, ipmi_mc_t *mc)
{
    fetch_info_t    *info;

    info = ilist_remove_first(sdrs->free_fetch);
    if (!info) {
	/* Technically this cannot fail, but just in case... */
	return ENOMEM;
    }
    info->sdr_rec = sdrs->curr_rec_id;
    info->offset = 0;
    info->read_len = SDR_HEADER_SIZE;
    info->fetch_retry_num = sdrs->fetch_retry_count;
    info->idx = sdrs->curr_read_idx;
    return info_send(sdrs, info, mc);
}

static void
handle_reservation(ipmi_mc_t  *mc,
		   ipmi_msg_t *rsp,
		   void       *rsp_data)
{
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) rsp_data;
    int             rv;


    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in"
		 " progress(3)");
	fetch_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress(3)");
	fetch_complete(sdrs, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	if (sdrs->sensor && (rsp->data[0] == IPMI_INVALID_CMD_CC)) {
	    /* This is a special case.  We always attempt a
               reservation with a device SDR (since there is nothing
               telling us if this is supported), if it fails then we
               just go on without the reservation. */
	    sdrs->supports_reserve_sdr = 0;
	    sdrs->reservation = 0;
	    goto reservation_set;
	}
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Error getting SDR fetch reservation: %x", rsp->data[0]);
	fetch_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }
    if (rsp->data_len < 3) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR Reservation data not long enough");
	fetch_complete(sdrs, EINVAL);
	goto out;
    }

    sdrs->reservation = ipmi_get_uint16(rsp->data+1);

 reservation_set:
    /* Fetch the first part of the SDR. */
    rv = initial_sdr_fetch(sdrs, mc);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "initial SDR fetch failed: %x", rv);
	fetch_complete(sdrs, EINVAL);
	goto out;
    }

    sdr_unlock(sdrs);
 out:
    return;
}

static void
handle_sdr_info(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *rsp_data)
{
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) rsp_data;
    ipmi_msg_t      cmd_msg;
    int             rv;
    int32_t         add_timestamp;
    int32_t         erase_timestamp;


    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in"
		 " progress(4)");
	fetch_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress(4)");
	fetch_complete(sdrs, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	if (sdrs->sensor) {
	    /* The device doesn't support the get device SDR info
               command, so just assume some defaults. */
	    sdrs->working_num_sdrs = 256;
	    sdrs->dynamic_population = 0;

	    /* Assume it uses reservations, if the reservation returns
               an error, then say that it doesn't. */
	    sdrs->supports_reserve_sdr = 1;

	    (sdrs->lun_has_sensors)[0] = 1;
	    (sdrs->lun_has_sensors)[1] = 0;
	    (sdrs->lun_has_sensors)[2] = 0;
	    (sdrs->lun_has_sensors)[3] = 0;

	    add_timestamp = 0;
	    erase_timestamp = 0;
	} else {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "IPMI Error getting SDR info: %x", rsp->data[0]);
	    fetch_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	    goto out;
	}
    } else if (sdrs->sensor) {
	if (rsp->data_len < 3) {
	    ipmi_log(IPMI_LOG_ERR_INFO, "SDR info is not long enough");
	    fetch_complete(sdrs, EINVAL);
	    goto out;
	}

	sdrs->working_num_sdrs = rsp->data[1];
	sdrs->dynamic_population = (rsp->data[2] & 0x80) == 0x80;

	/* Assume it uses reservations, if the reservation returns
	   an error, then say that it doesn't. */
	sdrs->supports_reserve_sdr = 1;

	(sdrs->lun_has_sensors)[0] = (rsp->data[2] & 0x01) == 0x01;
	(sdrs->lun_has_sensors)[1] = (rsp->data[2] & 0x01) == 0x02;
	(sdrs->lun_has_sensors)[2] = (rsp->data[2] & 0x01) == 0x04;
	(sdrs->lun_has_sensors)[3] = (rsp->data[2] & 0x01) == 0x08;

	if (sdrs->dynamic_population) {
	    if (rsp->data_len < 7) {
		ipmi_log(IPMI_LOG_ERR_INFO, "SDR info is not long enough");
		fetch_complete(sdrs, EINVAL);
		goto out;
	    }
	    add_timestamp = ipmi_get_uint32(rsp->data + 3);
	} else {
	    add_timestamp = 0;
	}
	erase_timestamp = 0;
    } else {
	if (rsp->data_len < 15) {
	    ipmi_log(IPMI_LOG_ERR_INFO, "SDR info is not long enough");
	    fetch_complete(sdrs, EINVAL);
	    goto out;
	}

	/* Pull pertinant info from the response. */
	sdrs->major_version = rsp->data[1] & 0xf;
	sdrs->minor_version = (rsp->data[1] >> 4) & 0xf;
	sdrs->working_num_sdrs = ipmi_get_uint16(rsp->data+2);
	sdrs->overflow = (rsp->data[14] & 0x80) == 0x80;
	sdrs->update_mode = (rsp->data[14] >> 5) & 0x3;
	sdrs->supports_delete_sdr = (rsp->data[14] & 0x08) == 0x08;
	sdrs->supports_partial_add_sdr = (rsp->data[14] & 0x04) == 0x04;
	sdrs->supports_reserve_sdr = (rsp->data[14] & 0x02) == 0x02;
	sdrs->supports_get_sdr_repository_allocation
	    = (rsp->data[14] & 0x01) == 0x01;

	add_timestamp = ipmi_get_uint32(rsp->data + 6);
	erase_timestamp = ipmi_get_uint32(rsp->data + 10);
    }

    /* If the timestamps still match, no need to re-fetch the repository */
    if (sdrs->fetched
	&& (add_timestamp == sdrs->last_addition_timestamp)
	&& (erase_timestamp == sdrs->last_erase_timestamp))
    {
	/* Set these so the fetch complete handler will put them back. */
	sdrs->curr_read_idx = sdrs->num_sdrs-1;
	sdrs->working_sdrs = sdrs->sdrs;
	fetch_complete(sdrs, 0);
	goto out;
    }

    sdrs->last_addition_timestamp = add_timestamp;
    sdrs->last_erase_timestamp = erase_timestamp;

    sdrs->sdrs_changed = 1;

    if (sdrs->working_num_sdrs == 0) {
	/* No sdrs, so there's nothing to do. */
	if (sdrs->sdrs) {
	    ipmi_mem_free(sdrs->sdrs);
	    sdrs->sdrs = NULL;
	}
	sdrs->curr_read_idx = -1;
	fetch_complete(sdrs, 0);
	goto out;
    }

    sdrs->working_sdrs = ipmi_mem_alloc(sizeof(ipmi_sdr_t)
					* sdrs->working_num_sdrs);
    if (!sdrs->working_sdrs) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Could not allocate working SDR information");
	fetch_complete(sdrs, ENOMEM);
	goto out;
    }

    sdrs->curr_rec_id = 0;
    sdrs->read_offset = 0; /* First thing is to read the header. */

    sdrs->next_read_rec_id = 0;
    sdrs->curr_read_rec_id = 0;
    sdrs->curr_read_idx = 0;
    sdrs->next_read_offset = 0; /* First thing is to read the header. */

    if (sdrs->supports_reserve_sdr) {
	/* Now get the reservation. */
	if (sdrs->sensor) {
	    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	    cmd_msg.cmd = IPMI_RESERVE_DEVICE_SDR_REPOSITORY_CMD;
	} else {
	    cmd_msg.netfn = IPMI_STORAGE_NETFN;
	    cmd_msg.cmd = IPMI_RESERVE_SDR_REPOSITORY_CMD;
	}
	cmd_msg.data = NULL;
	cmd_msg.data_len = 0;
	rv = ipmi_mc_send_command(mc, sdrs->lun, &cmd_msg,
				  handle_reservation, sdrs);
	if (rv) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "handle_sdr_info: Couldn't send SDR reservation: %x", rv);
	    fetch_complete(sdrs, rv);
	    goto out;
	}
    } else {
	/* No reservation support, just go on and start fetching. */
	sdrs->reservation = 0;

	/* Fetch the first part of the SDR. */
	rv = initial_sdr_fetch(sdrs, mc);
	if (rv)
	    goto out;
    }
    sdr_unlock(sdrs);
 out:
    return;
}

static void restart_timer_cb(void *cb_data, os_hnd_timer_id_t *id);

static int
start_fetch(ipmi_sdr_info_t *sdrs, ipmi_mc_t *mc, int delay)
{
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;

    sdrs->working_sdrs = NULL;
    sdrs->fetch_state = FETCHING;
    sdrs->sdrs_changed = 0;

    if (!ilist_empty(sdrs->outstanding_fetch)) {
	sdrs->waiting_start_fetch = 1;
	return 0;
    }

    sdrs->waiting_start_fetch = 0;

    if (delay) {
	/* Start the fetch operation after a random delay. */
	struct timeval tv;

	sdrs->os_hnd->get_random(sdrs->os_hnd,
				 &tv.tv_sec,
				 sizeof(tv.tv_sec));
	/* Wait a random value between 10 and 30 seconds */
	tv.tv_sec = (tv.tv_sec % 20) + 10;
	tv.tv_usec = 0;
	sdrs->os_hnd->start_timer(sdrs->os_hnd,
				  sdrs->restart_timer,
				  &tv,
				  restart_timer_cb,
				  sdrs);
	return 0;
    } else {
	/* Get a reservation first. */
	cmd_msg.data = cmd_data;
	if (sdrs->sensor) {
	    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	    cmd_msg.cmd = IPMI_GET_DEVICE_SDR_INFO_CMD;
	} else {
	    cmd_msg.netfn = IPMI_STORAGE_NETFN;
	    cmd_msg.cmd = IPMI_GET_SDR_REPOSITORY_INFO_CMD;
	}
	cmd_msg.data_len = 0;
	return ipmi_mc_send_command(mc, sdrs->lun, &cmd_msg,
				    handle_sdr_info, sdrs);
    }
}

static void
handle_start_fetch_cb(ipmi_mc_t *mc, void *cb_data)
{
    int             rv;
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) cb_data;

    sdrs->wait_err = 0;
    sdrs->fetch_retry_count = 0;
    sdrs->sdr_retry_count = 0;
    sdr_lock(sdrs);
    rv = start_fetch(sdrs, mc, 0);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_start_fetch: error requesting SDR reserveration: %x",
		 rv);
	sdrs->wait_err = rv;
	fetch_complete(sdrs, rv);
    } else {
	sdr_unlock(sdrs);
    }
}

static void
handle_start_fetch(void *cb_data, int shutdown)
{
    int             rv;
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) cb_data;

    if (shutdown)
	return;

    rv = ipmi_mc_pointer_cb(sdrs->mc, handle_start_fetch_cb, sdrs);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_start_fetch: error finding MC: %x",
		 rv);
	sdrs->wait_err = rv;
	fetch_complete(sdrs, rv);
    }
}

static void
restart_timer_cb(void *cb_data, os_hnd_timer_id_t *id)
{
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) cb_data;

    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in"
		 " progress(1)");
	fetch_complete(sdrs, ECANCELED);
	return;
    }

    handle_start_fetch(sdrs, 0);
}

static void
handle_fetch_done(void *cb_data, int shutdown)
{
    sdr_fetch_handler_t *elem = (sdr_fetch_handler_t *) cb_data;

    elem->handler(elem->sdrs,
		  elem->sdrs->wait_err,
		  elem->sdrs->sdrs_changed,
		  elem->sdrs->num_sdrs,
		  elem->cb_data);
    ipmi_mem_free(elem);
}

typedef struct sdr_fetch_info_s
{
    ipmi_sdr_info_t     *sdrs;
    ipmi_sdrs_fetched_t handler;
    void                *cb_data;
    int                 rv;
} sdr_fetch_info_t;

static void
sdr_fetch_cb(ipmi_mc_t *mc, void *cb_data)
{
    sdr_fetch_info_t    *info = cb_data;
    ipmi_sdr_info_t     *sdrs = info->sdrs;
    sdr_fetch_handler_t *elem;

    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem) {
	info->rv = ENOMEM;
	return;
    }

    elem->sdrs = sdrs;
    elem->handler = info->handler;
    elem->cb_data = info->cb_data;

    if (sdrs->sensor) {
	if (! ipmi_mc_provides_device_sdrs(mc)) {
	    info->rv = ENOSYS;
	    goto out;
	}
    } else {
	if (! ipmi_mc_sdr_repository_support(mc)) {
	    info->rv = ENOSYS;
	    goto out;
	}
    }

    sdr_lock(sdrs);
    if (! opq_new_op_with_done(sdrs->sdr_wait_q,
			       handle_start_fetch,
			       sdrs,
			       handle_fetch_done,
			       elem))
    {
	info->rv = ENOMEM;
    }
    sdr_unlock(sdrs);

 out:
    if (info->rv)
	ipmi_mem_free(elem);
}

int
ipmi_sdr_fetch(ipmi_sdr_info_t     *sdrs,
	       ipmi_sdrs_fetched_t handler,
	       void                *cb_data)
{
    int              rv;
    sdr_fetch_info_t info;

    if (! sdrs->dynamic_population)
	return ENOSYS;

    info.sdrs = sdrs;
    info.handler = handler;
    info.cb_data = cb_data;
    info.rv = 0;

    /* Convert the mc id to an mc. */
    rv = ipmi_mc_pointer_cb(sdrs->mc, sdr_fetch_cb, &info);
    if (rv)
	return rv;
    return info.rv;
}

int
ipmi_get_sdr_count(ipmi_sdr_info_t *sdrs,
		   unsigned int    *count)
{
    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    *count = sdrs->num_sdrs;

    sdr_unlock(sdrs);
    return 0;
}

int
ipmi_get_sdr_by_recid(ipmi_sdr_info_t *sdrs,
		      int             recid,
		      ipmi_sdr_t      *return_sdr)
{
    int i;
    int rv = ENOENT;

    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    for (i=0; i<sdrs->num_sdrs; i++) {
	if (sdrs->sdrs[i].record_id == recid) {
	    rv = 0;
	    *return_sdr = sdrs->sdrs[i];
	    break;
	}
    }

    sdr_unlock(sdrs);
    return rv;
}

int
ipmi_get_sdr_by_type(ipmi_sdr_info_t *sdrs,
		     int             type,
		     ipmi_sdr_t      *return_sdr)
{
    int i;
    int rv = ENOENT;

    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    for (i=0; i<sdrs->num_sdrs; i++) {
	if (sdrs->sdrs[i].type == type) {
	    rv = 0;
	    *return_sdr = sdrs->sdrs[i];
	    break;
	}
    }

    sdr_unlock(sdrs);
    return rv;
}

int
ipmi_get_sdr_by_index(ipmi_sdr_info_t *sdrs,
		      int             index,
		      ipmi_sdr_t      *return_sdr)
{
    int rv = 0;

    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    if (index >= sdrs->num_sdrs)
	rv = ENOENT;
    else
	*return_sdr = sdrs->sdrs[index];

    sdr_unlock(sdrs);
    return rv;
}

int
ipmi_set_sdr_by_index(ipmi_sdr_info_t *sdrs,
		      int             index,
		      ipmi_sdr_t      *sdr)
{
    int rv = 0;

    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    if (index >= sdrs->num_sdrs)
	rv = ENOENT;
    else
	sdrs->sdrs[index] = *sdr;

    sdr_unlock(sdrs);
    return rv;
}

int ipmi_get_all_sdrs(ipmi_sdr_info_t *sdrs,
		      int             *array_size,
		      ipmi_sdr_t      *array)
{
    int i;
    int rv = 0;

    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    if (*array_size < sdrs->num_sdrs) {
	rv = E2BIG;
    } else {
	for (i=0; i<sdrs->num_sdrs; i++) {
	    *array = sdrs->sdrs[i];
	    array++;
	}
	*array_size = sdrs->num_sdrs;
    }

    sdr_unlock(sdrs);
    return rv;
}

int
ipmi_sdr_get_major_version(ipmi_sdr_info_t *sdrs, int *val)
{
    sdr_lock(sdrs);
    if (sdrs->sensor) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    *val = sdrs->major_version;

    sdr_unlock(sdrs);
    return 0;
}

int
ipmi_sdr_get_minor_version(ipmi_sdr_info_t *sdrs, int *val)
{
    sdr_lock(sdrs);
    if (sdrs->sensor) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    *val = sdrs->minor_version;

    sdr_unlock(sdrs);
    return 0;
}

int
ipmi_sdr_get_overflow(ipmi_sdr_info_t *sdrs, int *val)
{
    sdr_lock(sdrs);
    if (sdrs->sensor) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    *val = sdrs->overflow;

    sdr_unlock(sdrs);
    return 0;
}

int
ipmi_sdr_get_update_mode(ipmi_sdr_info_t *sdrs, int *val)
{
    sdr_lock(sdrs);
    if (sdrs->sensor) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    *val = sdrs->update_mode;

    sdr_unlock(sdrs);
    return 0;
}

int
ipmi_sdr_get_supports_delete_sdr(ipmi_sdr_info_t *sdrs, int *val)
{
    sdr_lock(sdrs);
    if (sdrs->sensor) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    *val = sdrs->supports_delete_sdr;

    sdr_unlock(sdrs);
    return 0;
}

int
ipmi_sdr_get_supports_partial_add_sdr(ipmi_sdr_info_t *sdrs, int *val)
{
    sdr_lock(sdrs);
    if (sdrs->sensor) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    *val = sdrs->supports_partial_add_sdr;

    sdr_unlock(sdrs);
    return 0;
}

int
ipmi_sdr_get_supports_reserve_sdr(ipmi_sdr_info_t *sdrs, int *val)
{
    sdr_lock(sdrs);
    if (sdrs->sensor) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    *val = sdrs->supports_reserve_sdr;

    sdr_unlock(sdrs);
    return 0;
}

int
ipmi_sdr_get_supports_get_sdr_repository_allocation(ipmi_sdr_info_t *sdrs,
						    int             *val)
{
    sdr_lock(sdrs);
    if (sdrs->sensor) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    *val = sdrs->supports_get_sdr_repository_allocation;

    sdr_unlock(sdrs);
    return 0;
}

int
ipmi_sdr_get_dynamic_population(ipmi_sdr_info_t *sdrs, int *val)
{
    sdr_lock(sdrs);
    if (!sdrs->sensor) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    *val = sdrs->dynamic_population;

    sdr_unlock(sdrs);
    return 0;
}

int
ipmi_sdr_get_lun_has_sensors(ipmi_sdr_info_t *sdrs, unsigned int lun, int *val)
{
    if (lun >= 4)
	return EINVAL;

    sdr_lock(sdrs);
    if (!sdrs->sensor) {
	sdr_unlock(sdrs);
	return EINVAL;
    }

    *val = sdrs->lun_has_sensors[lun];

    sdr_unlock(sdrs);
    return 0;
}

int
ipmi_sdr_add(ipmi_sdr_info_t *sdrs,
	     ipmi_sdr_t      *sdr)
{
    int rv = 0;
    int pos;

    sdr_lock(sdrs);
    if (sdrs->num_sdrs >= sdrs->sdr_array_size) {
	ipmi_sdr_t *new_array;
	new_array = ipmi_mem_alloc(sizeof(ipmi_sdr_t) * sdrs->sdr_array_size + 10);
	if (!new_array) {
	    rv = ENOMEM;
	    goto out_unlock;
	}
	memcpy(new_array, sdrs->sdrs, sizeof(ipmi_sdr_t)*sdrs->sdr_array_size);
	ipmi_mem_free(sdrs->sdrs);
	sdrs->sdrs = new_array;
	sdrs->sdr_array_size += 10;
    }

    pos = sdrs->num_sdrs;
    (sdrs->num_sdrs)++;

    memcpy(&((sdrs->sdrs)[pos]), sdr, sizeof(*sdr));

 out_unlock:
    sdr_unlock(sdrs);
    return rv;
}


typedef struct sdr_save_handler_s
{
    ipmi_sdr_info_t  *sdrs;
    ipmi_sdr_save_cb handler;
    void             *cb_data;
} sdr_save_handler_t;

/* Must be called with the sdr lock held.  This will release and
   reaquire the sdr lock. */
static void
save_complete(ipmi_sdr_info_t *sdrs, int err)
{
    sdrs->wait_err = err;
    sdrs->fetch_state = HANDLERS;
    sdr_unlock(sdrs);

    opq_op_done(sdrs->sdr_wait_q);

    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in"
		 " progress(5)");
	internal_destroy_sdr_info(sdrs);
	/* The previous call unlocks the lock. */
	return;
    }

    if (sdrs->fetch_state == HANDLERS)
	/* The fetch process wasn't restarted, so go to IDLE. */
	sdrs->fetch_state = IDLE;

    sdr_unlock(sdrs);
}

static int start_save(ipmi_sdr_info_t *sdrs, ipmi_mc_t *mc);

static void handle_sdr_write(ipmi_mc_t  *mc,
			     ipmi_msg_t *rsp,
			     void       *rsp_data);

static void handle_sdr_write_done(ipmi_mc_t  *mc,
				  ipmi_msg_t *rsp,
				  void       *rsp_data);

static int
start_sdr_write(ipmi_sdr_info_t *sdrs,
		ipmi_sdr_t      *sdr,
		ipmi_mc_t       *mc)
{
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;

    /* Save the first part of the SDR. */
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_PARTIAL_ADD_SDR_CMD;
    ipmi_set_uint16(cmd_msg.data, sdrs->reservation);
    ipmi_set_uint16(cmd_msg.data+2, sdrs->curr_rec_id);
    cmd_msg.data[4] = 0;
    cmd_msg.data[6] = 0;
    cmd_msg.data[7] = 0;
    cmd_msg.data[8] = sdr->major_version | (sdr->minor_version << 4);
    cmd_msg.data[9] = sdr->type;
    cmd_msg.data[10] = sdr->length;
    if (sdr->length >= (MAX_SDR_FETCH - 5)) {
	cmd_msg.data[5] = 1;
	memcpy(cmd_msg.data+11, sdr->data, sdr->length);
	cmd_msg.data_len = 11 + sdr->length;
	return ipmi_mc_send_command(mc, sdrs->lun, &cmd_msg,
				    handle_sdr_write_done, sdr);
    } else {
	cmd_msg.data[5] = 0;
	memcpy(cmd_msg.data+11, sdr->data, (MAX_SDR_FETCH - 5));
	cmd_msg.data_len = 11 + (MAX_SDR_FETCH - 5);
	sdrs->sdr_data_write = MAX_SDR_FETCH - 5;
	return ipmi_mc_send_command(mc, sdrs->lun, &cmd_msg,
				    handle_sdr_write, sdr);
    }
}

static void
handle_sdr_write(ipmi_mc_t  *mc,
		 ipmi_msg_t *rsp,
		 void       *rsp_data)
{
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) rsp_data;
    ipmi_sdr_t      *sdr = &(sdrs->sdrs[sdrs->write_sdr_num]);
    int             rv;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             wleft;

    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in"
		 " progress(6)");
	save_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress(5)");
	save_complete(sdrs, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* Arg, lost my reservation, start over. */
	sdrs->fetch_retry_count++;
	if (sdrs->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "handle_sdr_write: Lost reservation too many times");
	    save_complete(sdrs, EBUSY);
	    goto out;
	} else {
	    rv = start_save(sdrs, mc);
	    if (rv) {
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "handle_sdr_write: Could not restart save operation");
		save_complete(sdrs, rv);
		goto out;
	    }
	}
	goto out_unlock;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sdr_write: Error from write operation: %x",
		 rsp->data[0]);
	save_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_PARTIAL_ADD_SDR_CMD;
    ipmi_set_uint16(cmd_msg.data, sdrs->reservation);
    ipmi_set_uint16(cmd_msg.data+2, sdrs->curr_rec_id);
    cmd_msg.data[4] = sdrs->sdr_data_write;
    wleft = sdr->length - sdrs->sdr_data_write;
    if (wleft >= MAX_SDR_FETCH) {
	cmd_msg.data[5] = 1;
	memcpy(cmd_msg.data+6, sdr->data+sdrs->sdr_data_write, wleft);
	cmd_msg.data_len = 6 + wleft;
	rv = ipmi_mc_send_command(mc, sdrs->lun, &cmd_msg,
				  handle_sdr_write_done, sdr);
    } else {
	cmd_msg.data[5] = 0;
	memcpy(cmd_msg.data+6, sdr->data+sdrs->sdr_data_write, MAX_SDR_FETCH);
	cmd_msg.data_len = 6 + MAX_SDR_FETCH;
	sdrs->sdr_data_write += MAX_SDR_FETCH;
	rv = ipmi_mc_send_command(mc, sdrs->lun, &cmd_msg,
				  handle_sdr_write, sdr);
    }

    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sdr_write: Could not send next write: %x", rv);
	save_complete(sdrs, rv);
	goto out;
    }
 out_unlock:
    sdr_unlock(sdrs);
 out:
    return;
}

static void
handle_sdr_write_done(ipmi_mc_t  *mc,
		      ipmi_msg_t *rsp,
		      void       *rsp_data)
{
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) rsp_data;
    int             rv;


    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in"
		 " progress(7)");
	save_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress(6)");
	save_complete(sdrs, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* Arg, lost my reservation, start over. */
	sdrs->fetch_retry_count++;
	if (sdrs->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "handle_sdr_write_done: Lost reservation too many times");
	    save_complete(sdrs, EBUSY);
	    goto out;
	} else {
	    rv = start_save(sdrs, mc);
	    if (rv) {
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "handle_sdr_write_done:"
			 " Could not restart save operation");
		save_complete(sdrs, rv);
		goto out;
	    }
	}
	goto out_unlock;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sdr_write_done: Error from write operation: %x",
		 rsp->data[0]);
	save_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    (sdrs->write_sdr_num)++;
    if (sdrs->write_sdr_num >= sdrs->num_sdrs) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sdr_write_done: Error from write operation: %x",
		 rsp->data[0]);
	save_complete(sdrs, 0);
	goto out;
    }

    rv = start_sdr_write(sdrs, &(sdrs->sdrs[sdrs->write_sdr_num]), mc);
    if (rv) {
	save_complete(sdrs, rv);
	goto out;
    }
 out_unlock:
    sdr_unlock(sdrs);
 out:
    return;
}

static void
handle_sdr_clear(ipmi_mc_t  *mc,
		 ipmi_msg_t *rsp,
		 void       *rsp_data)
{
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) rsp_data;
    int             rv;


    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in"
		 " progress(8)");
	save_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress(7)");
	save_complete(sdrs, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	save_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    if (sdrs->num_sdrs == 0) {
	save_complete(sdrs, 0);
	goto out;
    }

    sdrs->curr_rec_id = 0;
    sdrs->write_sdr_num = 0;
    sdrs->sdr_data_write = 0;

    /* Save the first part of the SDR. */
    rv = start_sdr_write(sdrs, &(sdrs->sdrs[0]), mc);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sdr_write_done: Could not send next write: %x", rv);
	save_complete(sdrs, rv);
	goto out;
    }
    sdr_unlock(sdrs);
 out:
    return;
}

static void
handle_save_reservation(ipmi_mc_t  *mc,
			ipmi_msg_t *rsp,
			void       *rsp_data)
{
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) rsp_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;


    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in"
		 " progress(9)");
	save_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress(8)");
	save_complete(sdrs, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_save_reservation: Error getting reservation: %x",
		 rsp->data[0]);
	save_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }
    if (rsp->data_len < 3) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Reservation data not long enough");
	save_complete(sdrs, EINVAL);
	goto out;
    }

    sdrs->reservation = ipmi_get_uint16(rsp->data+1);

    /* Clear the repository. */
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_CLEAR_SDR_REPOSITORY_CMD;
    cmd_data[0] = rsp->data[1];
    cmd_data[1] = rsp->data[2];
    cmd_data[2] = 'C';
    cmd_data[3] = 'L';
    cmd_data[4] = 'R';
    cmd_data[5] = 0xaa;
    cmd_msg.data_len = 6;
    rv = ipmi_mc_send_command(mc, sdrs->lun, &cmd_msg,
			      handle_sdr_clear, sdrs);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_save_reservation: Couldn't send SDR clear: %x", rv);
	save_complete(sdrs, rv);
	goto out;
    }
    sdr_unlock(sdrs);
 out:
    return;
}

static int
start_save(ipmi_sdr_info_t *sdrs, ipmi_mc_t *mc)
{
    unsigned char cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t    cmd_msg;

    sdrs->fetch_state = FETCHING;

    /* Get a reservation first. */
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_RESERVE_SDR_REPOSITORY_CMD;
    cmd_msg.data_len = 0;
    return ipmi_mc_send_command(mc, sdrs->lun, &cmd_msg,
				handle_save_reservation, sdrs);
}

static void
handle_start_save_cb(ipmi_mc_t *mc, void *cb_data)
{
    int             rv;
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) cb_data;

    sdrs->wait_err = 0;
    sdr_lock(sdrs);
    rv = start_save(sdrs, mc);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_start_save: error requesting reserveration: %x", rv);
	sdrs->wait_err = rv;
	save_complete(sdrs, rv);
    } else {
	sdr_unlock(sdrs);
    }
}

static void
handle_start_save(void *cb_data, int shutdown)
{
    int             rv;
    ipmi_sdr_info_t *sdrs = cb_data;

    if (shutdown)
	return;

    rv = ipmi_mc_pointer_cb(sdrs->mc, handle_start_save_cb, sdrs);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_start_save: error finding MC: %x",
		 rv);
	sdrs->wait_err = rv;
	fetch_complete(sdrs, rv);
    }
}

static void
handle_save_done(void *cb_data, int shutdown)
{
    sdr_save_handler_t *elem = cb_data;

    elem->handler(elem->sdrs,
		  elem->sdrs->wait_err,
		  elem->cb_data);
    ipmi_mem_free(elem);
}

typedef struct sdr_save_info_s
{
    ipmi_sdr_info_t  *sdrs;
    ipmi_sdr_save_cb done;
    void             *cb_data;
    int              rv;
} sdr_save_info_t;

static void
sdr_save_cb(ipmi_mc_t *mc, void *cb_data)
{
    sdr_save_info_t    *info = cb_data;
    ipmi_sdr_info_t    *sdrs = info->sdrs;
    sdr_save_handler_t *elem;


    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem) {
	info->rv = ENOMEM;
	return;
    }

    elem->sdrs = sdrs;
    elem->handler = info->done;
    elem->cb_data = info->cb_data;

    if (!ipmi_mc_sdr_repository_support(mc)) {
	info->rv = ENOSYS;
	goto out;
    }

    sdr_lock(sdrs);
    if (! opq_new_op_with_done(sdrs->sdr_wait_q,
			       handle_start_save,
			       sdrs,
			       handle_save_done,
			       elem))
    {
	info->rv = ENOMEM;
    }
    sdr_unlock(sdrs);

 out:
    ipmi_read_unlock();
    if (info->rv)
	ipmi_mem_free(elem);
}

int
ipmi_sdr_save(ipmi_sdr_info_t  *sdrs,
	      ipmi_sdr_save_cb done,
	      void             *cb_data)
{
    int             rv;
    sdr_save_info_t info;

    info.sdrs = sdrs;
    info.done = done;
    info.cb_data = cb_data;
    info.rv = 0;

    /* Convert the mc id to an mc. */
    rv = ipmi_mc_pointer_cb(sdrs->mc, sdr_save_cb, &info);
    if (rv)
	return rv;
    return info.rv;
}
