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

#include <ipmi/ipmiif.h>
#include <ipmi/ipmi_sdr.h>
#include <ipmi/ipmi_msgbits.h>
#include <ipmi/ipmi_mc.h>
#include <ipmi/ipmi_err.h>
#include <ipmi/ipmi_int.h>
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


static inline void sdr_lock(ipmi_sdr_info_t *sdr)
{
    ipmi_lock(sdr->sdr_lock);
}

static inline void sdr_unlock(ipmi_sdr_info_t *sdr)
{
    ipmi_unlock(sdr->sdr_lock);
}

int
ipmi_sdr_alloc(ipmi_mc_t       *mc,
	       unsigned int    lun,
	       int             sensor,
	       ipmi_sdr_info_t **new_sdr)
{
    ipmi_sdr_info_t *sdr = NULL;
    int             rv;

    if (lun >= 4)
	return EINVAL;

    ipmi_read_lock();
    if ((rv = ipmi_mc_validate(mc)))
	goto out_unlock;

    sdr = malloc(sizeof(*sdr));
    if (!sdr) {
	rv = ENOMEM;
	goto out_unlock;
    }

    sdr->mc = mc;
    sdr->destroyed = 0;
    sdr->sdr_lock = NULL;
    sdr->fetched = 0;
    sdr->fetch_state = IDLE;
    sdr->sdrs = NULL;
    sdr->num_sdrs = 0;
    sdr->sdr_array_size = 0;
    sdr->destroy_handler = NULL;
    sdr->lun = lun;
    sdr->sensor = sensor;
    sdr->sdr_wait_q = NULL;

    rv = ipmi_create_lock(mc, &sdr->sdr_lock);
    if (rv)
	goto out_done;

    sdr->sdr_wait_q = opq_alloc(ipmi_mc_get_os_hnd(mc));
    if (! sdr->sdr_wait_q) {
	rv = ENOMEM;
	goto out_done;
    }

 out_done:
    if (rv) {
	if (sdr) {
	    if (sdr->sdr_lock)
		ipmi_destroy_lock(sdr->sdr_lock);
	    free(sdr);
	}
    } else {
	*new_sdr = sdr;
    }
 out_unlock:
    ipmi_read_unlock();
    return rv;
}

static void
internal_destroy_sdr(ipmi_sdr_info_t *sdr)
{
    /* We don't have to have a valid ipmi to destroy an SDR, they are
       designed to live after the ipmi has been destroyed. */

    sdr_unlock(sdr);

    opq_destroy(sdr->sdr_wait_q);

    ipmi_destroy_lock(sdr->sdr_lock);

    /* Do this after we have gotten rid of all external dependencies,
       but before it is free. */
    if (sdr->destroy_handler)
	sdr->destroy_handler(sdr, sdr->destroy_cb_data);

    if (sdr->sdrs)
	free(sdr->sdrs);
    free(sdr);
}

int
ipmi_sdr_destroy(ipmi_sdr_info_t      *sdr,
		 ipmi_sdr_destroyed_t handler,
		 void                 *cb_data)
{
    /* We don't need the read lock, because the sdrs are stand-alone
       after they are created (except for fetching SDRs, of course). */
    sdr_lock(sdr);
    if (sdr->destroyed) {
	sdr_unlock(sdr);
	return EINVAL;
    }
    sdr->destroyed = 1;
    sdr->destroy_handler = handler;
    sdr->destroy_cb_data = cb_data;
    if (sdr->fetch_state != IDLE) {
	/* It's currently in fetch state, so let it be destroyed in
           the handler, since we can't cancel the handler or
           operation. */
	sdr_unlock(sdr);
	return 0;
    }

    /* This unlocks the lock. */
    internal_destroy_sdr(sdr);
    return 0;
}

static void
fetch_complete(ipmi_sdr_info_t *sdr, int err)
{
    sdr_lock(sdr);
    sdr->wait_err = err;
    if (err) {
	if (sdr->working_sdrs) {
	    free(sdr->working_sdrs);
	    sdr->working_sdrs = NULL;
	}
    } else {
	sdr->fetched = 1;
	sdr->num_sdrs = sdr->curr_sdr_num;
	sdr->sdr_array_size = sdr->curr_sdr_num;
	sdr->sdrs = sdr->working_sdrs;
    }
    sdr->fetch_state = HANDLERS;
    sdr_unlock(sdr);

    opq_op_done(sdr->sdr_wait_q);

    sdr_lock(sdr);
    if (sdr->destroyed) {
	internal_destroy_sdr(sdr);
	/* The previous call unlocks the lock. */
	return;
    }

    if (sdr->fetch_state == HANDLERS)
	/* The fetch process wasn't restarted, so go to IDLE. */
	sdr->fetch_state = IDLE;

    sdr_unlock(sdr);
}

static int start_fetch(ipmi_sdr_info_t *sdr);

static void
handle_reservation_check(ipmi_mc_t  *mc,
			 ipmi_msg_t *rsp,
			 void       *rsp_data)
{
    int             rv;
    ipmi_sdr_info_t *sdr = (ipmi_sdr_info_t *) rsp_data;

    if (sdr->destroyed) {
	fetch_complete(sdr, ECANCELED);
	free(sdr->working_sdrs);
	internal_destroy_sdr(sdr);
	return;
    }

    if (!mc) {
	fetch_complete(sdr, ENXIO);
	return;
    }
	
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* We lost our reservation, restart the operation.  Only do
           this so many times, in order to guarantee that this
           completes. */
	free(sdr->working_sdrs);
	sdr->fetch_retry_count++;
	if (sdr->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    fetch_complete(sdr, EBUSY);
	} else {
	    rv = start_fetch(sdr);
	    if (rv)
		fetch_complete(sdr, rv);
	}
	return;
    }

    if (rsp->data[0] != 0) {
	fetch_complete(sdr, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	return;
    }

    fetch_complete(sdr, 0);
}

static void
start_reservation_check(ipmi_sdr_info_t *sdr)
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
    opq_add_block(sdr->sdr_wait_q);
    
    cmd_msg.data = cmd_data;
    if (sdr->sensor) {
	cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	cmd_msg.cmd = IPMI_GET_DEVICE_SDR_CMD;
    } else {
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_GET_SDR_CMD;
    }
    cmd_msg.data_len = 6;
    ipmi_set_uint16(cmd_msg.data, sdr->reservation);
    ipmi_set_uint16(cmd_msg.data+2, sdr->curr_rec_id);
    cmd_msg.data[4] = 0;
    cmd_msg.data[5] = 1; /* Only care about the reservation */
    rv = ipmi_send_command(sdr->mc, sdr->lun, &cmd_msg,
			   handle_reservation_check, sdr);
    if (rv)
	    fetch_complete(sdr, rv);
}

static void
handle_sdr_data(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *rsp_data)
{
    ipmi_sdr_info_t *sdr = (ipmi_sdr_info_t *) rsp_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;
    int             curr;


    if (sdr->destroyed) {
	fetch_complete(sdr, ECANCELED);
	free(sdr->working_sdrs);
	internal_destroy_sdr(sdr);
	return;
    }

    if (!mc) {
	fetch_complete(sdr, ENXIO);
	return;
    }
	
    if (rsp->data[0] == 0x80) {
	/* Data changed during fetch, retry.  Only do this so many
           times before giving up. */
	sdr->fetch_retry_count++;
	if (sdr->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    fetch_complete(sdr, EBUSY);
	    return;
	}
	sdr->sdr_data_read = 0;
	goto restart_this_sdr;
    }
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* We lost our reservation, restart the operation.  Only do
           this so many times, in order to guarantee that this
           completes. */
	free(sdr->working_sdrs);
	sdr->fetch_retry_count++;
	if (sdr->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    fetch_complete(sdr, EBUSY);
	} else {
	    rv = start_fetch(sdr);
	    if (rv)
		fetch_complete(sdr, rv);
	}
	return;
    }

    curr = sdr->curr_sdr_num;

    if ((curr == 0)
	&& ((rsp->data[0] == IPMI_UNKNOWN_ERR_CC)
	    || (rsp->data[0] == IPMI_NOT_PRESENT_CC)))
    {
	/* We got an error fetchding the first SDR, so the repository is
	   probably empty.  Just go on. */
	start_reservation_check(sdr);
	return;
    }
    if (rsp->data[0] != 0) {
	fetch_complete(sdr, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	return;
    }

    if (sdr->sdr_data_read == 0) {
	/* This is the first part of the SDR, so extract it. */
	if (rsp->data_len < 8) {
	    fetch_complete(sdr, EINVAL);
	    return;
	}
	if ((rsp->data[6] == 1) || (rsp->data[6] == 2)) {
	    /* It's a sensor SDR, so fetch it. */
	    sdr->next_rec_id = ipmi_get_uint16(rsp->data+1);
	    sdr->working_sdrs[curr].record_id = ipmi_get_uint16(rsp->data+3);
	    sdr->working_sdrs[curr].major_version = rsp->data[5] & 0xf;
	    sdr->working_sdrs[curr].minor_version = (rsp->data[5] >> 4) & 0xf;
	    sdr->working_sdrs[curr].type = rsp->data[6];
	    sdr->working_sdrs[curr].length = rsp->data[7];
	    sdr->sdr_data_read += rsp->data_len - 8;
	    memcpy(sdr->working_sdrs[curr].data,
		   rsp->data + 8,
		   sdr->sdr_data_read);
	} else {
	    /* Ignore non-sensor SDRs, just go to the next one. */
	    sdr->curr_rec_id = ipmi_get_uint16(rsp->data+1);
	    goto restart_this_sdr;
	}
    } else {
	/* Intermediate part of the SDR. */
	if (rsp->data_len < 4) {
	    fetch_complete(sdr, EINVAL);
	    return;
	}

	if ((sdr->sdr_data_read + rsp->data_len - 3) > MAX_SDR_DATA) {
	    fetch_complete(sdr, EINVAL);
	    return;
	}

	memcpy(sdr->working_sdrs[curr].data+sdr->sdr_data_read,
	       rsp->data + 3,
	       rsp->data_len - 3);
	sdr->sdr_data_read += rsp->data_len - 3;
    }

    if (sdr->sdr_data_read >= sdr->working_sdrs[curr].length) {
	sdr->curr_sdr_num++;
	if (sdr->next_rec_id == 0xFFFF) {
	    start_reservation_check(sdr);
	    return;
	}
	if (sdr->curr_sdr_num >= sdr->working_num_sdrs) {
	    fetch_complete(sdr, EINVAL);
	    return;
	}
	sdr->curr_rec_id = sdr->next_rec_id;
	sdr->sdr_data_read = 0;
    }

 restart_this_sdr:
    /* Request some more data. */
    cmd_msg.data = cmd_data;
    if (sdr->sensor) {
	cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	cmd_msg.cmd = IPMI_GET_DEVICE_SDR_CMD;
    } else {
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_GET_SDR_CMD;
    }
    cmd_msg.data_len = 6;
    ipmi_set_uint16(cmd_msg.data, sdr->reservation);
    ipmi_set_uint16(cmd_msg.data+2, sdr->curr_rec_id);
    if (sdr->sdr_data_read)
	cmd_msg.data[4] = sdr->sdr_data_read + 5;
    else
	cmd_msg.data[4] = 0;
    cmd_msg.data[5] = MAX_SDR_FETCH;
    rv = ipmi_send_command(sdr->mc, sdr->lun, &cmd_msg, handle_sdr_data, sdr);
    if (rv)
	    fetch_complete(sdr, rv);
}

static void
handle_sdr_info(ipmi_mc_t  *ipmi,
		ipmi_msg_t *rsp,
		void       *rsp_data)
{
    ipmi_sdr_info_t *sdr = (ipmi_sdr_info_t *) rsp_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;
    int32_t         add_timestamp;
    int32_t         erase_timestamp;


    if (sdr->destroyed) {
	fetch_complete(sdr, ECANCELED);
	internal_destroy_sdr(sdr);
	return;
    }

    if (!ipmi) {
	fetch_complete(sdr, ENXIO);
	return;
    }
	
    if (rsp->data[0] != 0) {
	fetch_complete(sdr, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	return;
    }

    if (sdr->sensor) {
	if (rsp->data_len < 3) {
	    fetch_complete(sdr, EINVAL);
	    return;
	}

	sdr_lock(sdr);
	sdr->working_num_sdrs = rsp->data[1];
	sdr->dynamic_population = (rsp->data[2] & 0x80) == 0x80;
	(sdr->lun_has_sensors)[0] = (rsp->data[2] & 0x01) == 0x01;
	(sdr->lun_has_sensors)[1] = (rsp->data[2] & 0x01) == 0x02;
	(sdr->lun_has_sensors)[2] = (rsp->data[2] & 0x01) == 0x04;
	(sdr->lun_has_sensors)[3] = (rsp->data[2] & 0x01) == 0x08;
	sdr_unlock(sdr);

	if (sdr->dynamic_population) {
	    if (rsp->data_len < 7) {
		fetch_complete(sdr, EINVAL);
		return;
	    }
	    add_timestamp = ipmi_get_uint32(rsp->data + 3);
	} else {
	    add_timestamp = 0;
	}
	erase_timestamp = 0;
    } else {
	if (rsp->data_len < 15) {
	    fetch_complete(sdr, EINVAL);
	    return;
	}

	/* Pull pertinant info from the response. */
	sdr_lock(sdr);
	sdr->major_version = rsp->data[1] & 0xf;
	sdr->major_version = (rsp->data[1] >> 4) & 0xf;
	sdr->working_num_sdrs = ipmi_get_uint16(rsp->data+2);
	sdr->overflow = (rsp->data[14] & 0x80) == 0x80;
	sdr->update_mode = (rsp->data[14] >> 5) & 0x3;
	sdr->supports_delete_sdr = (rsp->data[14] & 0x08) == 0x08;
	sdr->supports_partial_add_sdr = (rsp->data[14] & 0x04) == 0x04;
	sdr->supports_reserve_sdr = (rsp->data[14] & 0x02) == 0x02;
	sdr->supports_get_sdr_repository_allocation
	    = (rsp->data[14] & 0x01) == 0x01;
	sdr_unlock(sdr);

	add_timestamp = ipmi_get_uint32(rsp->data + 6);
	erase_timestamp = ipmi_get_uint32(rsp->data + 10);
    }

    /* If the timestamps still match, no need to re-fetch the repository */
    if (sdr->fetched
	&& (add_timestamp == sdr->last_addition_timestamp)
	&& (erase_timestamp == sdr->last_erase_timestamp))
    {
	/* Set these so the fetch complete handler will put them back. */
	sdr->curr_sdr_num = sdr->num_sdrs;
	sdr->working_sdrs = sdr->sdrs;
	start_reservation_check(sdr);
	return;
    }

    sdr->last_addition_timestamp = add_timestamp;
    sdr->last_erase_timestamp = erase_timestamp;

    sdr->sdrs_changed = 1;

    if (sdr->working_num_sdrs == 0) {
	/* No sdrs, so there's nothing to do. */
	if (sdr->sdrs) {
	    free(sdr->sdrs);
	    sdr->sdrs = NULL;
	}
	sdr->curr_sdr_num = 0;
	fetch_complete(sdr, 0);
	return;
    }

    sdr->working_sdrs = malloc(sizeof(ipmi_sdr_t) * sdr->working_num_sdrs);
    if (!sdr->working_sdrs) {
	fetch_complete(sdr, ENOMEM);
	return;
    }

    sdr->next_rec_id = 0;
    sdr->curr_rec_id = 0;
    sdr->curr_sdr_num = 0;
    sdr->sdr_data_read = 0;

    /* Fetch the first part of the SDR. */
    cmd_msg.data = cmd_data;
    if (sdr->sensor) {
	cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	cmd_msg.cmd = IPMI_GET_DEVICE_SDR_CMD;
    } else {
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_GET_SDR_CMD;
    }
    cmd_msg.data_len = 6;
    ipmi_set_uint16(cmd_msg.data, sdr->reservation);
    ipmi_set_uint16(cmd_msg.data+2, sdr->curr_rec_id);
    cmd_msg.data[4] = 0;
    cmd_msg.data[5] = MAX_SDR_FETCH;
    rv = ipmi_send_command(sdr->mc, sdr->lun, &cmd_msg, handle_sdr_data, sdr);
    if (rv)
	fetch_complete(sdr, rv);
}

static void
handle_reservation(ipmi_mc_t  *ipmi,
		   ipmi_msg_t *rsp,
		   void       *rsp_data)
{
    ipmi_sdr_info_t *sdr = (ipmi_sdr_info_t *) rsp_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;


    if (sdr->destroyed) {
	fetch_complete(sdr, ECANCELED);
	internal_destroy_sdr(sdr);
	return;
    }

    if (!ipmi) {
	fetch_complete(sdr, ENXIO);
	return;
    }
	
    if (rsp->data[0] != 0) {
	fetch_complete(sdr, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	return;
    }
    if (rsp->data_len < 3) {
	fetch_complete(sdr, EINVAL);
	return;
    }

    sdr->reservation = ipmi_get_uint16(rsp->data+1);

    /* Fetch the repository info. */
    cmd_msg.data = cmd_data;
    if (sdr->sensor) {
	cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	cmd_msg.cmd = IPMI_GET_DEVICE_SDR_INFO_CMD;
    } else {
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_GET_SDR_REPOSITORY_INFO_CMD;
    }
    cmd_msg.data_len = 0;
    rv = ipmi_send_command(sdr->mc, sdr->lun, &cmd_msg, handle_sdr_info, sdr);
    if (rv)
	fetch_complete(sdr, rv);
}

static int
start_fetch(ipmi_sdr_info_t *sdr)
{
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;

    sdr->working_sdrs = NULL;
    sdr->fetch_state = FETCHING;
    sdr->sdrs_changed = 0;

    /* Get a reservation first. */
    cmd_msg.data = cmd_data;
    if (sdr->sensor) {
	cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	cmd_msg.cmd = IPMI_RESERVE_DEVICE_SDR_REPOSITORY_CMD;
    } else {
	cmd_msg.netfn = IPMI_STORAGE_NETFN;
	cmd_msg.cmd = IPMI_RESERVE_SDR_REPOSITORY_CMD;
    }
    cmd_msg.data_len = 0;
    return ipmi_send_command(sdr->mc, sdr->lun, &cmd_msg,
			     handle_reservation, sdr);
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
    sdr_unlock(sdrs);
    if (rv) {
	sdrs->wait_err = rv;
	fetch_complete(sdrs, rv);
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
ipmi_get_sdr_count(ipmi_sdr_info_t *sdr,
		   unsigned int    *count)
{
    sdr_lock(sdr);
    if (sdr->destroyed) {
	sdr_unlock(sdr);
	return EINVAL;
    }

    *count = sdr->num_sdrs;

    sdr_unlock(sdr);
    return 0;
}

int
ipmi_get_sdr_by_recid(ipmi_sdr_info_t *sdr,
		      int             recid,
		      ipmi_sdr_t      *return_sdr)
{
    int i;
    int rv = ENOENT;

    sdr_lock(sdr);
    if (sdr->destroyed) {
	sdr_unlock(sdr);
	return EINVAL;
    }

    for (i=0; i<sdr->num_sdrs; i++) {
	if (sdr->sdrs[i].record_id == recid) {
	    rv = 0;
	    *return_sdr = sdr->sdrs[i];
	    break;
	}
    }

    sdr_unlock(sdr);
    return rv;
}

int
ipmi_get_sdr_by_type(ipmi_sdr_info_t *sdr,
		     int             type,
		     ipmi_sdr_t      *return_sdr)
{
    int i;
    int rv = ENOENT;

    sdr_lock(sdr);
    if (sdr->destroyed) {
	sdr_unlock(sdr);
	return EINVAL;
    }

    for (i=0; i<sdr->num_sdrs; i++) {
	if (sdr->sdrs[i].type == type) {
	    rv = 0;
	    *return_sdr = sdr->sdrs[i];
	    break;
	}
    }

    sdr_unlock(sdr);
    return rv;
}

int ipmi_get_sdr_by_index(ipmi_sdr_info_t *sdr,
			  int             index,
			  ipmi_sdr_t      *return_sdr)
{
    int rv = 0;

    sdr_lock(sdr);
    if (sdr->destroyed) {
	sdr_unlock(sdr);
	return EINVAL;
    }

    if (index >= sdr->num_sdrs)
	rv = ENOENT;
    else
	*return_sdr = sdr->sdrs[index];

    sdr_unlock(sdr);
    return rv;
}

int ipmi_get_all_sdrs(ipmi_sdr_info_t *sdr,
		      int             *array_size,
		      ipmi_sdr_t      *array)
{
    int i;
    int rv = 0;

    sdr_lock(sdr);
    if (sdr->destroyed) {
	sdr_unlock(sdr);
	return EINVAL;
    }

    if (*array_size < sdr->num_sdrs) {
	rv = E2BIG;
    } else {
	for (i=0; i<sdr->num_sdrs; i++) {
	    *array = sdr->sdrs[i];
	    array++;
	}
	*array_size = sdr->num_sdrs;
    }

    sdr_unlock(sdr);
    return rv;
}

int
ipmi_sdr_get_major_version(ipmi_sdr_info_t *sdr, int *val)
{
    sdr_lock(sdr);
    if (sdr->sensor)
	return EINVAL;

    *val = sdr->major_version;

    sdr_unlock(sdr);
    return 0;
}

int
ipmi_sdr_get_minor_version(ipmi_sdr_info_t *sdr, int *val)
{
    sdr_lock(sdr);
    if (sdr->sensor)
	return EINVAL;

    *val = sdr->minor_version;

    sdr_unlock(sdr);
    return 0;
}

int
ipmi_sdr_get_overflow(ipmi_sdr_info_t *sdr, int *val)
{
    sdr_lock(sdr);
    if (sdr->sensor)
	return EINVAL;

    *val = sdr->overflow;

    sdr_unlock(sdr);
    return 0;
}

int
ipmi_sdr_get_update_mode(ipmi_sdr_info_t *sdr, int *val)
{
    sdr_lock(sdr);
    if (sdr->sensor)
	return EINVAL;

    *val = sdr->update_mode;

    sdr_unlock(sdr);
    return 0;
}

int
ipmi_sdr_get_supports_delete_sdr(ipmi_sdr_info_t *sdr, int *val)
{
    sdr_lock(sdr);
    if (sdr->sensor)
	return EINVAL;

    *val = sdr->supports_delete_sdr;

    sdr_unlock(sdr);
    return 0;
}

int
ipmi_sdr_get_supports_partial_add_sdr(ipmi_sdr_info_t *sdr, int *val)
{
    sdr_lock(sdr);
    if (sdr->sensor)
	return EINVAL;

    *val = sdr->supports_partial_add_sdr;

    sdr_unlock(sdr);
    return 0;
}

int
ipmi_sdr_get_supports_reserve_sdr(ipmi_sdr_info_t *sdr, int *val)
{
    sdr_lock(sdr);
    if (sdr->sensor)
	return EINVAL;

    *val = sdr->supports_reserve_sdr;

    sdr_unlock(sdr);
    return 0;
}

int
ipmi_sdr_get_supports_get_sdr_repository_allocation(ipmi_sdr_info_t *sdr,
						    int             *val)
{
    sdr_lock(sdr);
    if (sdr->sensor)
	return EINVAL;

    *val = sdr->supports_get_sdr_repository_allocation;

    sdr_unlock(sdr);
    return 0;
}

int
ipmi_sdr_get_dynamic_population(ipmi_sdr_info_t *sdr, int *val)
{
    sdr_lock(sdr);
    if (!sdr->sensor)
	return EINVAL;

    *val = sdr->dynamic_population;

    sdr_unlock(sdr);
    return 0;
}

int
ipmi_sdr_get_lun_has_sensors(ipmi_sdr_info_t *sdr, unsigned int lun, int *val)
{
    if (lun >= 4)
	return EINVAL;

    sdr_lock(sdr);
    if (!sdr->sensor)
	return EINVAL;

    *val = sdr->lun_has_sensors[lun];

    sdr_unlock(sdr);
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
	memcpy(new_array, sdrs->sdrs, sizeof(ipmi_sdr_t) * sdrs->sdr_array_size);
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

static void
save_complete(ipmi_sdr_info_t *sdr, int err)
{
    sdr_lock(sdr);
    sdr->wait_err = err;
    sdr->fetch_state = HANDLERS;
    sdr_unlock(sdr);

    opq_op_done(sdr->sdr_wait_q);

    sdr_lock(sdr);
    if (sdr->destroyed) {
	internal_destroy_sdr(sdr);
	/* The previous call unlocks the lock. */
	return;
    }

    if (sdr->fetch_state == HANDLERS)
	/* The fetch process wasn't restarted, so go to IDLE. */
	sdr->fetch_state = IDLE;

    sdr_unlock(sdr);
}

static int start_save(ipmi_sdr_info_t *sdr);

static void handle_sdr_write(ipmi_mc_t  *ipmi,
			     ipmi_msg_t *rsp,
			     void       *rsp_data);

static void handle_sdr_write_done(ipmi_mc_t  *ipmi,
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
handle_sdr_write(ipmi_mc_t  *ipmi,
		 ipmi_msg_t *rsp,
		 void       *rsp_data)
{
    ipmi_sdr_info_t *sdrs = (ipmi_sdr_info_t *) rsp_data;
    ipmi_sdr_t      *sdr = &(sdrs->sdrs[sdrs->curr_sdr_num]);
    int             rv;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             wleft;

    if (sdrs->destroyed) {
	save_complete(sdrs, ECANCELED);
	internal_destroy_sdr(sdrs);
	return;
    }

    if (!ipmi) {
	save_complete(sdrs, ENXIO);
	return;
    }
	
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* Arg, lost my reservation, start over. */
	sdrs->fetch_retry_count++;
	if (sdrs->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    save_complete(sdrs, EBUSY);
	} else {
	    rv = start_save(sdrs);
	    if (rv)
		save_complete(sdrs, rv);
	}
	return;
    }

    if (rsp->data[0] != 0) {
	save_complete(sdrs, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	return;
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

    if (rv)
	save_complete(sdrs, rv);
}

static void
handle_sdr_write_done(ipmi_mc_t  *ipmi,
		      ipmi_msg_t *rsp,
		      void       *rsp_data)
{
    ipmi_sdr_info_t *sdr = (ipmi_sdr_info_t *) rsp_data;
    int             rv;


    if (sdr->destroyed) {
	save_complete(sdr, ECANCELED);
	internal_destroy_sdr(sdr);
	return;
    }

    if (!ipmi) {
	save_complete(sdr, ENXIO);
	return;
    }
	
    if (rsp->data[0] == IPMI_INVALID_RESERVATION_CC) {
	/* Arg, lost my reservation, start over. */
	sdr->fetch_retry_count++;
	if (sdr->fetch_retry_count > MAX_SDR_FETCH_RETRIES) {
	    save_complete(sdr, EBUSY);
	} else {
	    rv = start_save(sdr);
	    if (rv)
		save_complete(sdr, rv);
	}
	return;
    }

    if (rsp->data[0] != 0) {
	save_complete(sdr, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	return;
    }

    (sdr->curr_sdr_num)++;
    if (sdr->curr_sdr_num >= sdr->num_sdrs) {
	save_complete(sdr, 0);
	return;
    }

    rv = start_sdr_write(sdr, &(sdr->sdrs[sdr->curr_sdr_num]));
    if (rv)
	save_complete(sdr, rv);
}

static void
handle_sdr_clear(ipmi_mc_t  *ipmi,
		 ipmi_msg_t *rsp,
		 void       *rsp_data)
{
    ipmi_sdr_info_t *sdr = (ipmi_sdr_info_t *) rsp_data;
    int             rv;


    if (sdr->destroyed) {
	save_complete(sdr, ECANCELED);
	internal_destroy_sdr(sdr);
	return;
    }

    if (!ipmi) {
	save_complete(sdr, ENXIO);
	return;
    }
	
    if (rsp->data[0] != 0) {
	save_complete(sdr, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	return;
    }

    if (sdr->num_sdrs == 0) {
	save_complete(sdr, 0);
	return;
    }

    sdr->curr_rec_id = 0;
    sdr->curr_sdr_num = 0;
    sdr->sdr_data_read = 0;

    /* Save the first part of the SDR. */
    rv = start_sdr_write(sdr, &(sdr->sdrs[0]));
    if (rv)
	save_complete(sdr, rv);
}

static void
handle_save_reservation(ipmi_mc_t  *ipmi,
			ipmi_msg_t *rsp,
			void       *rsp_data)
{
    ipmi_sdr_info_t *sdr = (ipmi_sdr_info_t *) rsp_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;


    if (sdr->destroyed) {
	save_complete(sdr, ECANCELED);
	internal_destroy_sdr(sdr);
	return;
    }

    if (!ipmi) {
	save_complete(sdr, ENXIO);
	return;
    }
	
    if (rsp->data[0] != 0) {
	save_complete(sdr, IPMI_IPMI_ERR_VAL(rsp->data[0]));
	return;
    }
    if (rsp->data_len < 3) {
	save_complete(sdr, EINVAL);
	return;
    }

    sdr->reservation = ipmi_get_uint16(rsp->data+1);

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
    rv = ipmi_send_command(sdr->mc, sdr->lun, &cmd_msg, handle_sdr_clear, sdr);
    if (rv)
	save_complete(sdr, rv);
}

static int
start_save(ipmi_sdr_info_t *sdr)
{
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;

    sdr->fetch_state = FETCHING;

    /* Get a reservation first. */
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_STORAGE_NETFN;
    cmd_msg.cmd = IPMI_RESERVE_SDR_REPOSITORY_CMD;
    cmd_msg.data_len = 0;
    return ipmi_send_command(sdr->mc, sdr->lun, &cmd_msg,
			     handle_save_reservation, sdr);
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
    sdr_unlock(sdrs);
    if (rv) {
	sdrs->wait_err = rv;
	save_complete(sdrs, rv);
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
