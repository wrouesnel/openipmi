/*
 * ipmi_sdr.c
 *
 * MontaVista IPMI code for handling SDRs
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

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_sdr.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include "opq.h"

#define MAX_SDR_FETCH 20
#define MAX_SDR_FETCH_RETRIES 10

typedef struct sdr_fetch_handler_s
{
    ipmi_sdr_info_t     *sdrs;
    ipmi_sdrs_fetched_t handler;
    void                *cb_data;
} sdr_fetch_handler_t;

enum fetch_state_e { IDLE, FETCHING, HANDLERS };

struct ipmi_sdr_info_s
{
    /* The thing holding the SDR repository. */
    ipmi_mc_t   *mc;

    /* LUN we are attached with. */
    int         lun;

    /* Is this for sensor SDRs nor generic SDRs. */
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
    int overflow : 1;
    int update_mode : 2;
    int supports_delete_sdr : 1;
    int supports_partial_add_sdr : 1;
    int supports_reserve_sdr : 1;
    int supports_get_sdr_repository_allocation : 1;

    /* Information from the GET DEVICDE SDR INFO command, sensor mode
       only. */
    int dynamic_population : 1;
    char lun_has_sensors[4];

    /* Have the SDRs previously been fetched? */
    int fetched : 1;

    /* Has the SDR been destroyed?  This is here because of race
       conditions in shutdown.  If we are currently in the process of
       fetching SDRs, we will allow a destroy operation to complete,
       but we don't actually destroy the data until the SDR fetch
       reaches a point were it can be stopped safely. */
    int destroyed : 1;
    /* Something to call when the destroy is complete. */
    ipmi_sdr_destroyed_t destroy_handler;
    void                 *destroy_cb_data;

    /* Are we currently fetching SDRs? */
    enum fetch_state_e fetch_state;

    /* When fetching the data in event-driven mode, these are the
       variables that track what is going on. */
    int                    curr_rec_id;
    int                    next_rec_id;
    int                    sdr_data_read; /* Data read so far in the SDR. */
    unsigned int           reservation;
    int                    curr_sdr_num; /* Current array index. */
    int                    working_num_sdrs;
    ipmi_sdr_t             *working_sdrs;
    int                    sdrs_changed;
    int                    fetch_retry_count;

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

int
ipmi_sdr_info_alloc(ipmi_mc_t       *mc,
		    unsigned int    lun,
		    int             sensor,
		    ipmi_sdr_info_t **new_sdrs)
{
    ipmi_sdr_info_t *sdrs = NULL;
    int             rv;

    CHECK_MC_LOCK(mc);

    if (lun >= 4)
	return EINVAL;

    sdrs = malloc(sizeof(*sdrs));
    if (!sdrs) {
	rv = ENOMEM;
	goto out;
    }

    sdrs->mc = mc;
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

    rv = ipmi_create_lock(mc, &sdrs->sdr_lock);
    if (rv)
	goto out_done;

    sdrs->sdr_wait_q = opq_alloc(ipmi_mc_get_os_hnd(mc));
    if (! sdrs->sdr_wait_q) {
	rv = ENOMEM;
	goto out_done;
    }

 out_done:
    if (rv) {
	if (sdrs) {
	    if (sdrs->sdr_lock)
		ipmi_destroy_lock(sdrs->sdr_lock);
	    free(sdrs);
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

    sdr_unlock(sdrs);

    opq_destroy(sdrs->sdr_wait_q);

    ipmi_destroy_lock(sdrs->sdr_lock);

    /* Do this after we have gotten rid of all external dependencies,
       but before it is free. */
    if (sdrs->destroy_handler)
	sdrs->destroy_handler(sdrs, sdrs->destroy_cb_data);

    if (sdrs->sdrs)
	free(sdrs->sdrs);
    free(sdrs);
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
	    free(sdrs->working_sdrs);
	    sdrs->working_sdrs = NULL;
	}
    } else {
	sdrs->fetched = 1;
	sdrs->num_sdrs = sdrs->curr_sdr_num;
	sdrs->sdr_array_size = sdrs->curr_sdr_num;
	sdrs->sdrs = sdrs->working_sdrs;
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

static int start_fetch(ipmi_sdr_info_t *sdrs);

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
		 "SDR info was destroyed while an operation was in progress");
	free(sdrs->working_sdrs);
	fetch_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress");
	fetch_complete(sdrs, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* We lost our reservation, restart the operation.  Only do
           this so many times, in order to guarantee that this
           completes. */
	free(sdrs->working_sdrs);
	sdrs->fetch_retry_count++;
	if (sdrs->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "Lost reservation too many times trying to"
		     " fetch the SDRs");
	    fetch_complete(sdrs, EBUSY);
	    goto out;
	} else {
	    rv = start_fetch(sdrs);
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
}

/* Must be called with the sdr lock held, it will release it and
   return with the lock not held. */
static void
start_reservation_check(ipmi_sdr_info_t *sdrs)
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
    ipmi_set_uint16(cmd_msg.data+2, sdrs->curr_rec_id);
    cmd_msg.data[4] = 0;
    cmd_msg.data[5] = 1; /* Only care about the reservation */
    rv = ipmi_send_command(sdrs->mc, sdrs->lun, &cmd_msg,
			   handle_reservation_check, sdrs);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Could not send command to get an SDR: %x", rv);
	fetch_complete(sdrs, rv);
	return;
    }
    sdr_unlock(sdrs);
}

static void
handle_sdr_data(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *rsp_data)
{
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) rsp_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;
    int             curr;


    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in progress");
	free(sdrs->working_sdrs);
	fetch_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress");
	fetch_complete(sdrs, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] == 0x80) {
	/* Data changed during fetch, retry.  Only do this so many
           times before giving up. */
	sdrs->fetch_retry_count++;
	if (sdrs->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "To many retries trying to fetch SDRs");
	    fetch_complete(sdrs, EBUSY);
	    goto out;
	}
	sdrs->sdr_data_read = 0;
	goto restart_this_sdr;
    }
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* We lost our reservation, restart the operation.  Only do
           this so many times, in order to guarantee that this
           completes. */
	free(sdrs->working_sdrs);
	sdrs->fetch_retry_count++;
	if (sdrs->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "Lost reservation too many times trying to fetch SDRs");
	    fetch_complete(sdrs, EBUSY);
	    goto out;
	} else {
	    rv = start_fetch(sdrs);
	    if (rv) {
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "Could not start SDR fetch: %x", rv);
		fetch_complete(sdrs, rv);
		goto out;
	    }
	}
	goto out_unlock;
    }

    curr = sdrs->curr_sdr_num;

    if ((curr == 0)
	&& ((rsp->data[0] == IPMI_UNKNOWN_ERR_CC)
	    || (rsp->data[0] == IPMI_NOT_PRESENT_CC)))
    {
	/* We got an error fetchding the first SDR, so the repository is
	   probably empty.  Just go on. */
	start_reservation_check(sdrs);
	goto out;
    }
    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR fetch error getting sdr 0x%x: %x",
		 sdrs->curr_rec_id,
		 rsp->data[0]);
	fetch_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    if (sdrs->sdr_data_read == 0) {
	/* This is the first part of the SDR, so extract it. */
	if (rsp->data_len < 8) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "SDR data was too small to be a valid SDR in sdr 0x%x",
		     sdrs->curr_rec_id);
	    fetch_complete(sdrs, EINVAL);
	    goto out;
	}
	if ((rsp->data[6] == 1) || (rsp->data[6] == 2)) {
	    /* It's a sensor SDR, so fetch it. */
	    sdrs->next_rec_id = ipmi_get_uint16(rsp->data+1);
	    sdrs->working_sdrs[curr].record_id = ipmi_get_uint16(rsp->data+3);
	    sdrs->working_sdrs[curr].major_version = rsp->data[5] & 0xf;
	    sdrs->working_sdrs[curr].minor_version = (rsp->data[5] >> 4) & 0xf;
	    sdrs->working_sdrs[curr].type = rsp->data[6];
	    sdrs->working_sdrs[curr].length = rsp->data[7];
	    sdrs->sdr_data_read += rsp->data_len - 8;
	    memcpy(sdrs->working_sdrs[curr].data,
		   rsp->data + 8,
		   sdrs->sdr_data_read);
	} else {
	    /* Ignore non-sensor SDRs, just go to the next one. */
	    sdrs->curr_rec_id = ipmi_get_uint16(rsp->data+1);
	    goto restart_this_sdr;
	}
    } else {
	/* Intermediate part of the SDR. */
	if (rsp->data_len < 4) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "Intermediate data fetch was too small in sdr 0x%x",
		     sdrs->curr_rec_id);
	    fetch_complete(sdrs, EINVAL);
	    goto out;
	}

	if ((sdrs->sdr_data_read + rsp->data_len - 3) > MAX_SDR_DATA) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "Intermediate data fetch was too large in sdr 0x%x",
		     sdrs->curr_rec_id);
	    fetch_complete(sdrs, EINVAL);
	    goto out;
	}

	memcpy(sdrs->working_sdrs[curr].data+sdrs->sdr_data_read,
	       rsp->data + 3,
	       rsp->data_len - 3);
	sdrs->sdr_data_read += rsp->data_len - 3;
    }

    if (sdrs->sdr_data_read >= sdrs->working_sdrs[curr].length) {
	sdrs->curr_sdr_num++;
	if (sdrs->next_rec_id == 0xFFFF) {
	    start_reservation_check(sdrs);
	    goto out;
	}
	if (sdrs->curr_sdr_num >= sdrs->working_num_sdrs) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "Fetched more SDRs than the info said there were");
	    fetch_complete(sdrs, EINVAL);
	    goto out;
	}
	sdrs->curr_rec_id = sdrs->next_rec_id;
	sdrs->sdr_data_read = 0;
    }

 restart_this_sdr:
    /* Request some more data. */
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
    ipmi_set_uint16(cmd_msg.data+2, sdrs->curr_rec_id);
    if (sdrs->sdr_data_read)
	cmd_msg.data[4] = sdrs->sdr_data_read + 5;
    else
	cmd_msg.data[4] = 0;
    cmd_msg.data[5] = MAX_SDR_FETCH;
    rv = ipmi_send_command(sdrs->mc, sdrs->lun, &cmd_msg,
			   handle_sdr_data, sdrs);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sdr_data: Couldn't send next SDR fetch: %x", rv);
	fetch_complete(sdrs, rv);
	goto out;
    }

 out_unlock:
    sdr_unlock(sdrs);
 out:
}

static void
handle_sdr_info(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *rsp_data)
{
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) rsp_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;
    int32_t         add_timestamp;
    int32_t         erase_timestamp;


    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in progress");
	fetch_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress");
	fetch_complete(sdrs, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "IPMI Error getting SDR info: %x", rsp->data[0]);
	fetch_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }

    if (sdrs->sensor) {
	if (rsp->data_len < 3) {
	    ipmi_log(IPMI_LOG_ERR_INFO, "SDR info is not long enough");
	    fetch_complete(sdrs, EINVAL);
	    goto out;
	}

	sdrs->working_num_sdrs = rsp->data[1];
	sdrs->dynamic_population = (rsp->data[2] & 0x80) == 0x80;
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
	sdrs->major_version = (rsp->data[1] >> 4) & 0xf;
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
	sdrs->curr_sdr_num = sdrs->num_sdrs;
	sdrs->working_sdrs = sdrs->sdrs;
	start_reservation_check(sdrs);
	goto out;
    }

    sdrs->last_addition_timestamp = add_timestamp;
    sdrs->last_erase_timestamp = erase_timestamp;

    sdrs->sdrs_changed = 1;

    if (sdrs->working_num_sdrs == 0) {
	/* No sdrs, so there's nothing to do. */
	if (sdrs->sdrs) {
	    free(sdrs->sdrs);
	    sdrs->sdrs = NULL;
	}
	sdrs->curr_sdr_num = 0;
	fetch_complete(sdrs, 0);
	goto out;
    }

    sdrs->working_sdrs = malloc(sizeof(ipmi_sdr_t) * sdrs->working_num_sdrs);
    if (!sdrs->working_sdrs) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Could not allocate working SDR information");
	fetch_complete(sdrs, ENOMEM);
	goto out;
    }

    sdrs->next_rec_id = 0;
    sdrs->curr_rec_id = 0;
    sdrs->curr_sdr_num = 0;
    sdrs->sdr_data_read = 0;

    /* Fetch the first part of the SDR. */
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
    ipmi_set_uint16(cmd_msg.data+2, sdrs->curr_rec_id);
    cmd_msg.data[4] = 0;
    cmd_msg.data[5] = MAX_SDR_FETCH;
    rv = ipmi_send_command(sdrs->mc, sdrs->lun, &cmd_msg,
			   handle_sdr_data, sdrs);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sdr_info: Couldn't send first SDR fetch: %x", rv);
	fetch_complete(sdrs, rv);
	goto out;
    }
    sdr_unlock(sdrs);
 out:
}

static void
handle_reservation(ipmi_mc_t  *mc,
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
		 "SDR info was destroyed while an operation was in progress");
	fetch_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress");
	fetch_complete(sdrs, ENXIO);
	goto out;
    }
	
    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Error getting fetch reservation: %x", rsp->data[0]);
	fetch_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	goto out;
    }
    if (rsp->data_len < 3) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Reservation data not long enough");
	fetch_complete(sdrs, EINVAL);
	goto out;
    }

    sdrs->reservation = ipmi_get_uint16(rsp->data+1);

    /* Fetch the repository info. */
    cmd_msg.data = cmd_data;
    if (sdrs->sensor) {
	cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	cmd_msg.cmd = IPMI_GET_DEVICE_SDR_INFO_CMD;
    } else {
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_GET_SDR_REPOSITORY_INFO_CMD;
    }
    cmd_msg.data_len = 0;
    rv = ipmi_send_command(sdrs->mc, sdrs->lun, &cmd_msg,
			   handle_sdr_info, sdrs);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_reservation: Couldn't send SDR info get: %x", rv);
	fetch_complete(sdrs, rv);
	goto out;
    }
    sdr_unlock(sdrs);
 out:
}

static int
start_fetch(ipmi_sdr_info_t *sdrs)
{
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;

    sdrs->working_sdrs = NULL;
    sdrs->fetch_state = FETCHING;
    sdrs->sdrs_changed = 0;

    /* Get a reservation first. */
    cmd_msg.data = cmd_data;
    if (sdrs->sensor) {
	cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	cmd_msg.cmd = IPMI_RESERVE_DEVICE_SDR_REPOSITORY_CMD;
    } else {
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_RESERVE_SDR_REPOSITORY_CMD;
    }
    cmd_msg.data_len = 0;
    return ipmi_send_command(sdrs->mc, sdrs->lun, &cmd_msg,
			     handle_reservation, sdrs);
}

static void
handle_start_fetch(void *cb_data, int shutdown)
{
    int             rv;
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) cb_data;

    if (shutdown)
	return;

    sdrs->wait_err = 0;
    sdr_lock(sdrs);
    rv = start_fetch(sdrs);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_start_fetch: error requesting reserveration: %x", rv);
	sdrs->wait_err = rv;
	fetch_complete(sdrs, rv);
    } else {
	sdr_unlock(sdrs);
    }
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
    free(elem);
}

int
ipmi_sdr_fetch(ipmi_sdr_info_t     *sdrs,
	       ipmi_sdrs_fetched_t handler,
	       void                *cb_data)
{
    sdr_fetch_handler_t *elem;
    int                 rv;


    elem = malloc(sizeof(*elem));
    if (!elem)
	return ENOMEM;

    elem->sdrs = sdrs;
    elem->handler = handler;
    elem->cb_data = cb_data;

    ipmi_read_lock();
    if ((rv = ipmi_mc_validate(sdrs->mc)))
	goto out_unlock2;

    if (! ipmi_mc_sdr_repository_support(sdrs->mc)) {
	rv = ENOSYS;
	goto out_unlock2;
    }

    sdr_lock(sdrs);
    if (! opq_new_op_with_done(sdrs->sdr_wait_q,
			       handle_start_fetch,
			       sdrs,
			       handle_fetch_done,
			       elem))
    {
	rv = ENOMEM;
    }
    sdr_unlock(sdrs);

 out_unlock2:
    ipmi_read_unlock();
    if (rv)
	free(elem);
    return rv;
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

int ipmi_get_sdr_by_index(ipmi_sdr_info_t *sdrs,
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
	new_array = malloc(sizeof(ipmi_sdr_t) * sdrs->sdr_array_size + 10);
	if (!new_array) {
	    rv = ENOMEM;
	    goto out_unlock;
	}
	memcpy(new_array, sdrs->sdrs, sizeof(ipmi_sdr_t)*sdrs->sdr_array_size);
	free(sdrs->sdrs);
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
		 "SDR info was destroyed while an operation was in progress");
	internal_destroy_sdr_info(sdrs);
	/* The previous call unlocks the lock. */
	return;
    }

    if (sdrs->fetch_state == HANDLERS)
	/* The fetch process wasn't restarted, so go to IDLE. */
	sdrs->fetch_state = IDLE;

    sdr_unlock(sdrs);
}

static int start_save(ipmi_sdr_info_t *sdrs);

static void handle_sdr_write(ipmi_mc_t  *mc,
			     ipmi_msg_t *rsp,
			     void       *rsp_data);

static void handle_sdr_write_done(ipmi_mc_t  *mc,
				  ipmi_msg_t *rsp,
				  void       *rsp_data);

static int
start_sdr_write(ipmi_sdr_info_t *sdrs,
		ipmi_sdr_t      *sdr)
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
	return ipmi_send_command(sdrs->mc, sdrs->lun, &cmd_msg,
				 handle_sdr_write_done, sdr);
    } else {
	cmd_msg.data[5] = 0;
	memcpy(cmd_msg.data+11, sdr->data, (MAX_SDR_FETCH - 5));
	cmd_msg.data_len = 11 + (MAX_SDR_FETCH - 5);
	sdrs->sdr_data_read = MAX_SDR_FETCH - 5;
	return ipmi_send_command(sdrs->mc, sdrs->lun, &cmd_msg,
				 handle_sdr_write, sdr);
    }
}

static void
handle_sdr_write(ipmi_mc_t  *mc,
		 ipmi_msg_t *rsp,
		 void       *rsp_data)
{
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) rsp_data;
    ipmi_sdr_t      *sdr = &(sdrs->sdrs[sdrs->curr_sdr_num]);
    int             rv;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             wleft;

    sdr_lock(sdrs);
    if (sdrs->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "SDR info was destroyed while an operation was in progress");
	save_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress");
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
	    rv = start_save(sdrs);
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
    cmd_msg.data[4] = sdrs->sdr_data_read;
    wleft = sdr->length - sdrs->sdr_data_read;
    if (wleft >= MAX_SDR_FETCH) {
	cmd_msg.data[5] = 1;
	memcpy(cmd_msg.data+6, sdr->data+sdrs->sdr_data_read, wleft);
	cmd_msg.data_len = 6 + wleft;
	rv = ipmi_send_command(sdrs->mc, sdrs->lun, &cmd_msg,
			       handle_sdr_write_done, sdr);
    } else {
	cmd_msg.data[5] = 0;
	memcpy(cmd_msg.data+6, sdr->data+sdrs->sdr_data_read, MAX_SDR_FETCH);
	cmd_msg.data_len = 6 + MAX_SDR_FETCH;
	sdrs->sdr_data_read += MAX_SDR_FETCH;
	rv = ipmi_send_command(sdrs->mc, sdrs->lun, &cmd_msg,
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
		 "SDR info was destroyed while an operation was in progress");
	save_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress");
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
	    rv = start_save(sdrs);
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

    (sdrs->curr_sdr_num)++;
    if (sdrs->curr_sdr_num >= sdrs->num_sdrs) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sdr_write_done: Error from write operation: %x",
		 rsp->data[0]);
	save_complete(sdrs, 0);
	goto out;
    }

    rv = start_sdr_write(sdrs, &(sdrs->sdrs[sdrs->curr_sdr_num]));
    if (rv) {
	save_complete(sdrs, rv);
	goto out;
    }
 out_unlock:
    sdr_unlock(sdrs);
 out:
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
		 "SDR info was destroyed while an operation was in progress");
	save_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress");
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
    sdrs->curr_sdr_num = 0;
    sdrs->sdr_data_read = 0;

    /* Save the first part of the SDR. */
    rv = start_sdr_write(sdrs, &(sdrs->sdrs[0]));
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_sdr_write_done: Could not send next write: %x", rv);
	save_complete(sdrs, rv);
	goto out;
    }
    sdr_unlock(sdrs);
 out:
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
		 "SDR info was destroyed while an operation was in progress");
	save_complete(sdrs, ECANCELED);
	goto out;
    }

    if (!mc ) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC went away while SDR fetch was in progress");
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
    rv = ipmi_send_command(sdrs->mc, sdrs->lun, &cmd_msg,
			   handle_sdr_clear, sdrs);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "handle_save_reservation: Couldn't send SDR clear: %x", rv);
	save_complete(sdrs, rv);
	goto out;
    }
    sdr_unlock(sdrs);
 out:
}

static int
start_save(ipmi_sdr_info_t *sdrs)
{
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;

    sdrs->fetch_state = FETCHING;

    /* Get a reservation first. */
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_RESERVE_SDR_REPOSITORY_CMD;
    cmd_msg.data_len = 0;
    return ipmi_send_command(sdrs->mc, sdrs->lun, &cmd_msg,
			     handle_save_reservation, sdrs);
}

static void
handle_start_save(void *cb_data, int shutdown)
{
    int             rv;
    ipmi_sdr_info_t *sdrs = cb_data;

    if (shutdown)
	return;

    sdrs->wait_err = 0;
    sdr_lock(sdrs);
    rv = start_save(sdrs);
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
handle_save_done(void *cb_data, int shutdown)
{
    sdr_save_handler_t *elem = cb_data;

    elem->handler(elem->sdrs,
		  elem->sdrs->wait_err,
		  elem->cb_data);
    free(elem);
}

int
ipmi_sdr_save(ipmi_sdr_info_t  *sdrs,
	      ipmi_sdr_save_cb done,
	      void             *cb_data)
{
    sdr_save_handler_t *elem;
    int                rv;


    elem = malloc(sizeof(*elem));
    if (!elem)
	return ENOMEM;

    elem->sdrs = sdrs;
    elem->handler = done;
    elem->cb_data = cb_data;

    ipmi_read_lock();
    if ((rv = ipmi_mc_validate(sdrs->mc)))
	goto out_unlock2;

    if (!ipmi_mc_sdr_repository_support(sdrs->mc)) {
	rv = ENOSYS;
	goto out_unlock2;
    }

    sdr_lock(sdrs);
    if (! opq_new_op_with_done(sdrs->sdr_wait_q,
			       handle_start_save,
			       sdrs,
			       handle_save_done,
			       elem))
    {
	rv = ENOMEM;
    }
    sdr_unlock(sdrs);

 out_unlock2:
    ipmi_read_unlock();
    if (rv)
	free(elem);
    return rv;
}
