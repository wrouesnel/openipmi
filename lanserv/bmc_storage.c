/*
 * bmc_storage.c
 *
 * MontaVista IPMI code for emulating a MC.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2003,2012 MontaVista Software Inc.
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
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include "bmc.h"

#include <errno.h>
#include <malloc.h>
#include <string.h>

#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>

/*
 * SEL handling commands.
 */

#define IPMI_SEL_SUPPORTS_DELETE         (1 << 3)
#define IPMI_SEL_SUPPORTS_RESERVE        (1 << 1)
#define IPMI_SEL_SUPPORTS_GET_ALLOC_INFO (1 << 0)

static sel_entry_t *
find_sel_event_by_recid(lmc_data_t  *mc,
			uint16_t    record_id,
			sel_entry_t **prev)
{
    sel_entry_t *entry;
    sel_entry_t *p_entry = NULL;

    entry = mc->sel.entries;
    while (entry) {
	if (record_id == entry->record_id)
	    break;
	p_entry = entry;
	entry = entry->next;
    }
    if (prev)
	*prev = p_entry;
    return entry;
}

int
ipmi_mc_enable_sel(lmc_data_t    *mc,
		   int           max_entries,
		   unsigned char flags)
{
    mc->sel.entries = NULL;
    mc->sel.count = 0;
    mc->sel.max_count = max_entries;
    mc->sel.last_add_time = 0;
    mc->sel.last_erase_time = 0;
    mc->sel.flags = flags & 0xb;
    mc->sel.reservation = 0;
    mc->sel.next_entry = 1;
    return 0;
}
		    

int
ipmi_mc_add_to_sel(lmc_data_t    *mc,
		   unsigned char record_type,
		   unsigned char event[13],
		   unsigned int  *recid)
{
    sel_entry_t    *e;
    struct timeval t;
    uint16_t       start_record_id;

    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE))
	return ENOTSUP;

    if (mc->sel.count >= mc->sel.max_count)
	return EAGAIN;

    e = malloc(sizeof(*e));
    if (!e)
	return ENOMEM;

    /* FIXME - this is inefficient, but simple */
    e->record_id = mc->sel.next_entry;
    mc->sel.next_entry++;
    start_record_id = e->record_id;
    while ((mc->sel.next_entry == 0)
	   || find_sel_event_by_recid(mc, e->record_id, NULL))
    {
	e->record_id++;
	if (e->record_id == start_record_id)
	    return EAGAIN;
	mc->sel.next_entry++;
    }

    gettimeofday(&t, NULL);

    ipmi_set_uint16(e->data, e->record_id);
    e->data[2] = record_type;
    if (record_type < 0xe0) {
	ipmi_set_uint32(e->data+3, t.tv_sec + mc->sel.time_offset);
	memcpy(e->data+7, event+4, 9);
    } else {
	memcpy(e->data+3, event, 13);
    }

    e->next = NULL;
    if (!mc->sel.entries) {
	mc->sel.entries = e;
    } else {
	sel_entry_t *f = mc->sel.entries;
	while (f->next)
	    f = f->next;
	f->next = e;
    }

    mc->sel.count++;

    mc->sel.last_add_time = t.tv_sec + mc->sel.time_offset;

    if (recid)
	*recid = e->record_id;
    return 0;
}

void
mc_new_event(lmc_data_t *mc,
	     unsigned char record_type,
	     unsigned char event[13])
{
    unsigned int recid;
    int rv;

    if (IPMI_MC_EVENT_LOG_ENABLED(mc)) {
	rv = ipmi_mc_add_to_sel(mc, record_type, event, &recid);
	if (rv)
	    recid = 0xffff;
    } else
	recid = 0xffff;
    if (!mc->ev_in_q && IPMI_MC_EVENT_MSG_BUF_ENABLED(mc)) {
	channel_t *chan = mc->channels[15];
	mc->ev_in_q = 1;
	ipmi_set_uint16(mc->evq, recid);
	mc->evq[2] = record_type;
	memcpy(mc->evq + 3, event, 13);
	mc->msg_flags |= IPMI_MC_MSG_FLAG_EVT_BUF_FULL;
	if (chan->set_atn)
	    chan->set_atn(chan, 1, IPMI_MC_EVBUF_FULL_INT_ENABLED(mc));
    }
}

static void
handle_get_sel_info(lmc_data_t    *mc,
		    msg_t         *msg,
		    unsigned char *rdata,
		    unsigned int  *rdata_len)
{
    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    memset(rdata, 0, 15);
    rdata[1] = 0x51;
    ipmi_set_uint16(rdata+2, mc->sel.count);
    ipmi_set_uint16(rdata+4, (mc->sel.max_count - mc->sel.count) * 16);
    ipmi_set_uint32(rdata+6, mc->sel.last_add_time);
    ipmi_set_uint32(rdata+10, mc->sel.last_erase_time);
    rdata[14] = mc->sel.flags;

    /* Clear the overflow flag. */
    /* FIXME - is this the right way to clear this?  There doesn't
       seem to be another way. */
    mc->sel.flags &= ~0x80;

    *rdata_len = 15;
}

static void
handle_get_sel_allocation_info(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len)
{
    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (!(mc->sel.flags & IPMI_SEL_SUPPORTS_GET_ALLOC_INFO)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    memset(rdata, 0, 10);
    ipmi_set_uint16(rdata+1, mc->sel.max_count * 16);
    ipmi_set_uint16(rdata+3, 16);
    ipmi_set_uint32(rdata+5, (mc->sel.max_count - mc->sel.count) * 16);
    ipmi_set_uint32(rdata+7, (mc->sel.max_count - mc->sel.count) * 16);
    rdata[9] = 1;

    *rdata_len = 10;
}

static void
handle_reserve_sel(lmc_data_t    *mc,
		   msg_t         *msg,
		   unsigned char *rdata,
		   unsigned int  *rdata_len)
{
    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (!(mc->sel.flags & IPMI_SEL_SUPPORTS_RESERVE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    mc->sel.reservation++;
    if (mc->sel.reservation == 0)
	mc->sel.reservation++;
    rdata[0] = 0;
    ipmi_set_uint16(rdata+1, mc->sel.reservation);
    *rdata_len = 3;
}

static void
handle_get_sel_entry(lmc_data_t    *mc,
		     msg_t         *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len)
{
    uint16_t    record_id;
    int         offset;
    int         count;
    sel_entry_t *entry;

    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 6, rdata, rdata_len))
	return;

    if (mc->sel.flags & IPMI_SEL_SUPPORTS_RESERVE) {
	uint16_t reservation = ipmi_get_uint16(msg->data+0);

	if ((reservation != 0) && (reservation != mc->sel.reservation)) {
	    rdata[0] = IPMI_INVALID_RESERVATION_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    record_id = ipmi_get_uint16(msg->data+2);
    offset = msg->data[4];
    count = msg->data[5];

    if (offset >= 16) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (record_id == 0) {
	entry = mc->sel.entries;
    } else if (record_id == 0xffff) {
	entry = mc->sel.entries;
	if (entry) {
	    while (entry->next) {
		entry = entry->next;
	    }
	}
    } else {
	entry = find_sel_event_by_recid(mc, record_id, NULL);
    }

    if (entry == NULL) {
	rdata[0] = IPMI_NOT_PRESENT_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    if (entry->next)
	ipmi_set_uint16(rdata+1, entry->next->record_id);
    else {
	rdata[1] = 0xff;
	rdata[2] = 0xff;
    }

    if ((offset+count) > 16)
	count = 16 - offset;
    memcpy(rdata+3, entry->data+offset, count);
    *rdata_len = count + 3;
}

static void
handle_add_sel_entry(lmc_data_t    *mc,
		     msg_t         *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len)
{
    int          rv;
    unsigned int r;

    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 16, rdata, rdata_len))
	return;

    rv = ipmi_mc_add_to_sel(mc, msg->data[2], msg->data+3, &r);
    if (rv == EAGAIN) {
	rdata[0] = IPMI_OUT_OF_SPACE_CC;
    } else if (rv) {
	rdata[0] = IPMI_UNKNOWN_ERR_CC;
    } else {
	rdata[0] = 0;
	ipmi_set_uint16(rdata+1, r);
    }
    *rdata_len = 3;
}

static void
handle_delete_sel_entry(lmc_data_t    *mc,
			msg_t         *msg,
			unsigned char *rdata,
			unsigned int  *rdata_len)
{
    uint16_t    record_id;
    sel_entry_t *entry, *p_entry;

    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (!(mc->sel.flags & IPMI_SEL_SUPPORTS_DELETE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 4, rdata, rdata_len))
	return;

    if (mc->sel.flags & IPMI_SEL_SUPPORTS_RESERVE) {
	uint16_t reservation = ipmi_get_uint16(msg->data+0);

	if ((reservation != 0) && (reservation != mc->sel.reservation)) {
	    rdata[0] = IPMI_INVALID_RESERVATION_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    record_id = ipmi_get_uint16(msg->data+2);

    if (record_id == 0) {
	entry = mc->sel.entries;
	p_entry = NULL;
    } else if (record_id == 0xffff) {
	entry = mc->sel.entries;
	p_entry = NULL;
	if (entry) {
	    while (entry->next) {
		p_entry = entry;
		entry = entry->next;
	    }
	}
    } else {
	entry = find_sel_event_by_recid(mc, record_id, &p_entry);
    }
    if (!entry) {
	rdata[0] = IPMI_NOT_PRESENT_CC;
	*rdata_len = 1;
	return;
    }

    if (p_entry)
	p_entry->next = entry->next;
    else
	mc->sel.entries = entry->next;

    rdata[0] = 0;
    ipmi_set_uint16(rdata+1, entry->record_id);
    *rdata_len = 3;

    mc->sel.count--;
    free(entry);
}

static void
handle_clear_sel(lmc_data_t    *mc,
		 msg_t         *msg,
		 unsigned char *rdata,
		 unsigned int  *rdata_len)
{
    sel_entry_t    *entry, *n_entry;
    unsigned char  op;
    struct timeval t;

    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 6, rdata, rdata_len))
	return;

    if (mc->sel.flags & IPMI_SEL_SUPPORTS_RESERVE) {
	uint16_t reservation = ipmi_get_uint16(msg->data+0);

	if ((reservation != 0) && (reservation != mc->sel.reservation)) {
	    rdata[0] = IPMI_INVALID_RESERVATION_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    if ((msg->data[2] != 'C')
	|| (msg->data[3] != 'L')
	|| (msg->data[4] != 'R'))
    {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    op = msg->data[5];
    if ((op != 0) && (op != 0xaa))
    {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[1] = 1;
    if (op == 0xaa) {
	entry = mc->sel.entries;
	mc->sel.entries = NULL;
	mc->sel.count = 0;
	while (entry) {
	    n_entry = entry->next;
	    free(entry);
	    entry = n_entry;
	}
    }

    gettimeofday(&t, NULL);
    mc->sel.last_erase_time = t.tv_sec + mc->sel.time_offset;

    rdata[0] = 0;
    *rdata_len = 2;
}

static void
handle_get_sel_time(lmc_data_t    *mc,
		    msg_t         *msg,
		    unsigned char *rdata,
		    unsigned int  *rdata_len)
{
    struct timeval t;

    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    gettimeofday(&t, NULL);
    rdata[0] = 0;
    ipmi_set_uint32(rdata+1, t.tv_sec + mc->sel.time_offset);
    *rdata_len = 5;
}

static void
handle_set_sel_time(lmc_data_t    *mc,
		    msg_t         *msg,
		    unsigned char *rdata,
		    unsigned int  *rdata_len)
{
    struct timeval t;

    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 4, rdata, rdata_len))
	return;

    gettimeofday(&t, NULL);
    mc->sel.time_offset = ipmi_get_uint32(msg->data) - t.tv_sec;

    rdata[0] = 0;
    *rdata_len = 1;
}

/*
 * SDR handling commands
 */

#define IPMI_SDR_OVERFLOW_FLAG				(1 << 7)
#define IPMI_SDR_GET_MODAL(v)   (((v) >> 5) & 0x3)
#define IPMI_SDR_MODAL_UNSPECIFIED	0
#define IPMI_SDR_NON_MODAL_ONLY		1
#define IPMI_SDR_MODAL_ONLY		2
#define IPMI_SDR_MODAL_BOTH		3

sdr_t *
find_sdr_by_recid(lmc_data_t *mc,
		  sdrs_t     *sdrs,
		  uint16_t   record_id,
		  sdr_t      **prev)
{
    sdr_t *entry;
    sdr_t *p_entry = NULL;

    entry = sdrs->sdrs;
    while (entry) {
	if (record_id == entry->record_id)
	    break;
	p_entry = entry;
	entry = entry->next;
    }
    if (prev)
	*prev = p_entry;
    return entry;
}

sdr_t *
new_sdr_entry(lmc_data_t *mc, sdrs_t *sdrs, unsigned char length)
{
    sdr_t    *entry;
    uint16_t start_recid;

    start_recid = sdrs->next_entry;
    while (find_sdr_by_recid(mc, sdrs, sdrs->next_entry, NULL)) {
	sdrs->next_entry++;
	if (sdrs->next_entry == 0xffff)
	    sdrs->next_entry = 1;
	if (sdrs->next_entry == start_recid)
	    return NULL;
    }

    entry = malloc(sizeof(*entry));
    if (!entry)
	return NULL;

    entry->data = malloc(length + 6);
    if (!entry->data)
	return NULL;

    entry->record_id = sdrs->next_entry;

    sdrs->next_entry++;

    ipmi_set_uint16(entry->data, entry->record_id);

    entry->length = length + 6;
    entry->next = NULL;
    return entry;
}

void
add_sdr_entry(lmc_data_t *mc, sdrs_t *sdrs, sdr_t *entry)
{
    sdr_t          *p;
    struct timeval t;

    entry->next = NULL;
    p = sdrs->sdrs;
    if (!p)
	sdrs->sdrs = entry;
    else {
	while (p->next)
	    p = p->next;
	p->next = entry;
    }

    gettimeofday(&t, NULL);
    sdrs->last_add_time = t.tv_sec + mc->main_sdrs.time_offset;
    sdrs->sdr_count++;
}

static void
free_sdr(sdr_t *sdr)
{
    free(sdr->data);
    free(sdr);
}

int
ipmi_mc_add_main_sdr(lmc_data_t    *mc,
		     unsigned char *data,
		     unsigned int  data_len)
{
    sdr_t *entry;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV))
	return ENOSYS;

    if ((data_len < 5) || (data_len != (((unsigned int) data[4]) + 5)))
	return EINVAL;

    entry = new_sdr_entry(mc, &mc->main_sdrs, data_len);
    if (!entry)
	return ENOMEM;

    add_sdr_entry(mc, &mc->main_sdrs, entry);

    memcpy(entry->data+2, data+2, data_len-2);
    return 0;
}

int
ipmi_mc_add_device_sdr(lmc_data_t    *mc,
		       unsigned char lun,
		       unsigned char *data,
		       unsigned int  data_len)
{
    struct timeval t;
    sdr_t          *entry;

    if (lun >= 4)
	return EINVAL;

    if (!(mc->has_device_sdrs)) {
	return ENOSYS;
    }

    entry = new_sdr_entry(mc, &mc->device_sdrs[lun], data_len);
    if (!entry)
	return ENOMEM;

    add_sdr_entry(mc, &mc->device_sdrs[lun], entry);

    memcpy(entry->data+2, data+2, data_len-2);

    gettimeofday(&t, NULL);
    mc->sensor_population_change_time = t.tv_sec + mc->main_sdrs.time_offset;
    mc->lun_has_sensors[lun] = 1;
    mc->num_sensors_per_lun[lun]++;
    return 0;
}

static void
handle_get_sdr_repository_info(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len)
{
    unsigned int space;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    rdata[0] = 0;
    rdata[1] = 0x51;
    ipmi_set_uint16(rdata+2, mc->main_sdrs.sdr_count);
    space = MAX_SDR_LENGTH * (MAX_NUM_SDRS - mc->main_sdrs.sdr_count);
    if (space > 0xfffe)
	space = 0xfffe;
    ipmi_set_uint16(rdata+4, space);
    ipmi_set_uint32(rdata+6, mc->main_sdrs.last_add_time);
    ipmi_set_uint32(rdata+10, mc->main_sdrs.last_erase_time);
    rdata[14] = mc->main_sdrs.flags;
    *rdata_len = 15;
}

static void
handle_get_sdr_repository_alloc_info(lmc_data_t    *mc,
				     msg_t         *msg,
				     unsigned char *rdata,
				     unsigned int  *rdata_len)
{
    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (!(mc->main_sdrs.flags & IPMI_SDR_GET_SDR_ALLOC_INFO_SDR_SUPPORTED)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    rdata[0] = 0;
    ipmi_set_uint16(rdata+1, MAX_NUM_SDRS);
    ipmi_set_uint16(rdata+3, MAX_SDR_LENGTH);
    ipmi_set_uint16(rdata+5, MAX_NUM_SDRS - mc->main_sdrs.sdr_count);
    ipmi_set_uint16(rdata+7, MAX_NUM_SDRS - mc->main_sdrs.sdr_count);
    rdata[9] = 1;
    *rdata_len = 10;
}

static void
handle_reserve_sdr_repository(lmc_data_t    *mc,
			      msg_t         *msg,
			      unsigned char *rdata,
			      unsigned int  *rdata_len)
{
    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (!(mc->main_sdrs.flags & IPMI_SDR_RESERVE_SDR_SUPPORTED)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    mc->main_sdrs.reservation++;
    if (mc->main_sdrs.reservation == 0)
	mc->main_sdrs.reservation++;

    rdata[0] = 0;
    ipmi_set_uint16(rdata+1, mc->main_sdrs.reservation);
    *rdata_len = 3;

    /* If adding an SDR and the reservation changes, we have to
       destroy the working SDR addition. */
    if (mc->part_add_sdr) {
	free_sdr(mc->part_add_sdr);
	mc->part_add_sdr = NULL;
    }
}

static void
handle_get_sdr(lmc_data_t    *mc,
	       msg_t         *msg,
	       unsigned char *rdata,
	       unsigned int  *rdata_len)
{
    uint16_t     record_id;
    unsigned int offset;
    unsigned int count;
    sdr_t        *entry;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 6, rdata, rdata_len))
	return;

    if (mc->main_sdrs.flags & IPMI_SDR_RESERVE_SDR_SUPPORTED) {
	uint16_t reservation = ipmi_get_uint16(msg->data+0);

	if ((reservation != 0) && (reservation != mc->main_sdrs.reservation)) {
	    rdata[0] = IPMI_INVALID_RESERVATION_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    record_id = ipmi_get_uint16(msg->data+2);
    offset = msg->data[4];
    count = msg->data[5];

    if (record_id == 0) {
	entry = mc->main_sdrs.sdrs;
    } else if (record_id == 0xffff) {
	entry = mc->main_sdrs.sdrs;
	if (entry) {
	    while (entry->next) {
		entry = entry->next;
	    }
	}
    } else {
	entry = find_sdr_by_recid(mc, &mc->main_sdrs, record_id, NULL);
    }

    if (entry == NULL) {
	rdata[0] = IPMI_NOT_PRESENT_CC;
	*rdata_len = 1;
	return;
    }

    if (offset >= entry->length) {
	rdata[0] = IPMI_PARAMETER_OUT_OF_RANGE_CC;
	*rdata_len = 1;
	return;
    }

    if ((offset+count) > entry->length)
	count = entry->length - offset;
    if (count+3 > *rdata_len) {
	/* Too much data to put into response. */
	rdata[0] = IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    if (entry->next)
	ipmi_set_uint16(rdata+1, entry->next->record_id);
    else {
	rdata[1] = 0xff;
	rdata[2] = 0xff;
    }

    memcpy(rdata+3, entry->data+offset, count);
    *rdata_len = count + 3;
}

static void
handle_add_sdr(lmc_data_t    *mc,
	       msg_t         *msg,
	       unsigned char *rdata,
	       unsigned int  *rdata_len)
{
    int            modal;
    sdr_t          *entry;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    modal = IPMI_SDR_GET_MODAL(mc->main_sdrs.flags);
    if ((modal == IPMI_SDR_NON_MODAL_ONLY)
	&& !mc->in_update_mode)
    {
	rdata[0] = IPMI_NOT_SUPPORTED_IN_PRESENT_STATE_CC;
	*rdata_len = 1;
	return;
    }

    if (check_msg_length(msg, 6, rdata, rdata_len))
	return;

    if (msg->len != (unsigned int) msg->data[5] + 6) {
	rdata[0] = 0x80; /* Length is invalid. */
	*rdata_len = 1;
	return;
    }

    entry = new_sdr_entry(mc, &mc->main_sdrs, msg->data[5]);
    if (!entry) {
	rdata[0] = IPMI_OUT_OF_SPACE_CC;
	*rdata_len = 1;
	return;
    }
    add_sdr_entry(mc, &mc->main_sdrs, entry);

    memcpy(entry->data+2, msg->data+2, entry->length-2);

    rdata[0] = 0;
    ipmi_set_uint16(rdata+1, entry->record_id);
    *rdata_len = 3;
}

static void
handle_partial_add_sdr(lmc_data_t    *mc,
		       msg_t         *msg,
		       unsigned char *rdata,
		       unsigned int  *rdata_len)
{
    uint16_t     record_id;
    unsigned int offset;
    int          modal;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (!(mc->main_sdrs.flags & IPMI_SDR_PARTIAL_ADD_SDR_SUPPORTED)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (mc->main_sdrs.flags & IPMI_SDR_RESERVE_SDR_SUPPORTED) {
	uint16_t reservation = ipmi_get_uint16(msg->data+0);

	if ((reservation != 0) && (reservation != mc->main_sdrs.reservation)) {
	    rdata[0] = IPMI_INVALID_RESERVATION_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    modal = IPMI_SDR_GET_MODAL(mc->main_sdrs.flags);
    if ((modal == IPMI_SDR_NON_MODAL_ONLY)
	&& !mc->in_update_mode)
    {
	rdata[0] = IPMI_NOT_SUPPORTED_IN_PRESENT_STATE_CC;
	*rdata_len = 1;
	return;
    }

    offset = msg->data[4];
    record_id = ipmi_get_uint16(rdata+2);
    if (record_id == 0) {
	/* New add. */
	if (check_msg_length(msg, 12, rdata, rdata_len))
	    return;
	if (offset != 0) {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}
	if (msg->len > (unsigned int) msg->data[11] + 12) {
	    rdata[0] = 0x80; /* Invalid data length */
	    *rdata_len = 1;
	    return;
	}
	if (mc->part_add_sdr) {
	    /* Still working on a previous one, return an error and
	       abort. */
	    free_sdr(mc->part_add_sdr);
	    mc->part_add_sdr = NULL;
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
	mc->part_add_sdr = new_sdr_entry(mc, &mc->main_sdrs, msg->data[11]);
	memcpy(mc->part_add_sdr->data+2, msg->data+8, msg->len - 8);
	mc->part_add_next = msg->len - 8;
    } else {
	if (!mc->part_add_next) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
	if (offset != mc->part_add_next) {
	    free_sdr(mc->part_add_sdr);
	    mc->part_add_sdr = NULL;
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}
	if ((offset + msg->len - 6) > mc->part_add_sdr->length) {
	    free_sdr(mc->part_add_sdr);
	    mc->part_add_sdr = NULL;
	    rdata[0] = 0x80; /* Invalid data length */
	    *rdata_len = 1;
	    return;
	}
	memcpy(mc->part_add_sdr->data+offset, msg->data+6, msg->len-6);
	mc->part_add_next += msg->len - 6;
    }

    if ((msg->data[5] & 0xf) == 1) {
	/* End of the operation. */
	if (mc->part_add_next != mc->part_add_sdr->length) {
	    free_sdr(mc->part_add_sdr);
	    mc->part_add_sdr = NULL;
	    rdata[0] = 0x80; /* Invalid data length */
	    *rdata_len = 1;
	    return;
	}
	add_sdr_entry(mc, &mc->main_sdrs, mc->part_add_sdr);
	mc->part_add_sdr = NULL;
    }

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_delete_sdr(lmc_data_t    *mc,
		  msg_t         *msg,
		  unsigned char *rdata,
		  unsigned int  *rdata_len)
{
    uint16_t       record_id;
    sdr_t          *entry, *p_entry;
    struct timeval t;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 4, rdata, rdata_len))
	return;

    if (mc->main_sdrs.flags & IPMI_SDR_RESERVE_SDR_SUPPORTED) {
	uint16_t reservation = ipmi_get_uint16(msg->data+0);

	if ((reservation != 0) && (reservation != mc->main_sdrs.reservation)) {
	    rdata[0] = IPMI_INVALID_RESERVATION_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    record_id = ipmi_get_uint16(rdata+2);

    if (record_id == 0) {
	entry = mc->main_sdrs.sdrs;
	p_entry = NULL;
    } else if (record_id == 0xffff) {
	entry = mc->main_sdrs.sdrs;
	p_entry = NULL;
	if (entry) {
	    while (entry->next) {
		p_entry = entry;
		entry = entry->next;
	    }
	}
    } else {
	entry = find_sdr_by_recid(mc, &mc->main_sdrs, record_id, &p_entry);
    }
    if (!entry) {
	rdata[0] = IPMI_NOT_PRESENT_CC;
	*rdata_len = 1;
	return;
    }

    if (p_entry)
	p_entry->next = entry->next;
    else
	mc->main_sdrs.sdrs = entry->next;

    rdata[0] = 0;
    ipmi_set_uint16(rdata+1, entry->record_id);
    *rdata_len = 3;

    free_sdr(entry);

    gettimeofday(&t, NULL);
    mc->main_sdrs.last_erase_time = t.tv_sec + mc->main_sdrs.time_offset;
    mc->main_sdrs.sdr_count--;
}

static void
handle_clear_sdr_repository(lmc_data_t    *mc,
			    msg_t         *msg,
			    unsigned char *rdata,
			    unsigned int  *rdata_len)
{
    sdr_t          *entry, *n_entry;
    struct timeval t;
    unsigned char  op;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 6, rdata, rdata_len))
	return;

    if (mc->main_sdrs.flags & IPMI_SDR_RESERVE_SDR_SUPPORTED) {
	uint16_t reservation = ipmi_get_uint16(msg->data+0);

	if ((reservation != 0) && (reservation != mc->main_sdrs.reservation)) {
	    rdata[0] = IPMI_INVALID_RESERVATION_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    if ((msg->data[2] != 'C')
	|| (msg->data[3] != 'L')
	|| (msg->data[4] != 'R'))
    {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    op = msg->data[5];
    if ((op != 0) && (op != 0xaa))
    {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[1] = 1;
    if (op == 0) {
	entry = mc->main_sdrs.sdrs;
	while (entry) {
	    n_entry = entry->next;
	    free_sdr(entry);
	    entry = n_entry;
	}
    }

    rdata[0] = 0;
    *rdata_len = 2;

    gettimeofday(&t, NULL);
    mc->main_sdrs.last_erase_time = t.tv_sec + mc->main_sdrs.time_offset;
}

static void
handle_get_sdr_repository_time(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len)
{
    struct timeval t;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    gettimeofday(&t, NULL);
    rdata[0] = 0;
    ipmi_set_uint32(rdata+1, t.tv_sec + mc->main_sdrs.time_offset);
    *rdata_len = 5;
}

static void
handle_set_sdr_repository_time(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len)
{
    struct timeval t;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 4, rdata, rdata_len))
	return;

    gettimeofday(&t, NULL);
    mc->main_sdrs.time_offset = ipmi_get_uint32(msg->data) - t.tv_sec;

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_enter_sdr_repository_update(lmc_data_t    *mc,
				   msg_t         *msg,
				   unsigned char *rdata,
				   unsigned int  *rdata_len)
{
    int modal;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    modal = IPMI_SDR_GET_MODAL(mc->main_sdrs.flags);
    if ((modal == IPMI_SDR_MODAL_UNSPECIFIED)
	|| (modal == IPMI_SDR_NON_MODAL_ONLY))
    {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    mc->in_update_mode = 1;

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_exit_sdr_repository_update(lmc_data_t    *mc,
				  msg_t         *msg,
				  unsigned char *rdata,
				  unsigned int  *rdata_len)
{
    int modal;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    modal = IPMI_SDR_GET_MODAL(mc->main_sdrs.flags);
    if ((modal == IPMI_SDR_MODAL_UNSPECIFIED)
	|| (modal == IPMI_SDR_NON_MODAL_ONLY))
    {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    mc->in_update_mode = 0;

    rdata[0] = 0;
    *rdata_len = 1;
}

int
ipmi_mc_set_frudata_handler(lmc_data_t *mc, unsigned int fru,
			    get_frudata_f handler, free_frudata_f freefunc)
{
    if (fru > 0xff)
	return EINVAL;
    mc->frus[fru].get = handler;
    mc->frus[fru].free = freefunc;
    return 0;
}

static void
fru_session_closed(lmc_data_t *mc, uint32_t session_id, void *cb_data)
{
    fru_session_t *ses = cb_data;
    fru_data_t *fru = ses->fru;

    if (fru->sessions == ses) {
	fru->sessions = ses->next;
    } else {
	fru_session_t *p = fru->sessions;
	while (p && p->next != ses)
	    p = p->next;
	if (p && p->next != ses)
	    p->next = ses->next;
    }
    fru->free(mc, ses->data_to_free);
    free(ses);
}

static void
handle_get_fru_inventory_area_info(lmc_data_t    *mc,
				   msg_t         *msg,
				   unsigned char *rdata,
				   unsigned int  *rdata_len)
{
    unsigned char devid;
    fru_data_t *fru;
    unsigned int size;
    unsigned char *data;
    int rv;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    devid = msg->data[0];
    if (devid >= 255) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    fru = &mc->frus[devid];
    if (fru->get) {
	channel_t *channel;
	fru_session_t *ses;
	int link_in = 0;

	ses = fru->sessions;
	while (ses) {
	    if (ses->sid == msg->sid)
		break;
	    ses = ses->next;
	}
	if (!ses) {
	    ses = malloc(sizeof(*ses));
	    if (!ses) {
		rdata[0] = IPMI_OUT_OF_SPACE_CC;
		*rdata_len = 1;
		return;
	    }
	    memset(ses, 0, sizeof(*ses));
	    ses->sid = msg->sid;
	    ses->fru = fru;
	    link_in = 1;
	}

	/* Set up to free the FRU data when the session closes. */
	channel = msg->orig_channel;
	rv = channel->set_associated_mc(channel, msg->sid, 0, mc,
					NULL, fru_session_closed, ses);
	if (rv == EBUSY) {
	    rdata[0] = IPMI_NODE_BUSY_CC;
	    *rdata_len = 1;
	    return;
	} else if (rv) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}

	data = fru->get(mc, &size);
	if (!data) {
	    channel->set_associated_mc(channel, msg->sid, 0, NULL,
				       NULL, NULL, NULL);
	    rdata[0] = IPMI_OUT_OF_SPACE_CC;
	    *rdata_len = 1;
	    return;
	}

	if (ses->data_to_free)
	    fru->free(mc, ses->data_to_free);

	ses->data_to_free = data;
	if (size > 65535) {
	    ses->data = data + (size - 65535);
	    size = 65535;
	} else {
	    ses->data = data;
	}
	ses->length = size;

	if (link_in) {
	    ses->next = fru->sessions;
	    fru->sessions = ses;
	}
    } else {
	size = fru->length;
	data = fru->data;
    }

    if (!data) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    ipmi_set_uint16(rdata+1, size);
    rdata[3] = 0; /* We only support byte access for now. */
    *rdata_len = 4;
}

static void
handle_read_fru_data(lmc_data_t    *mc,
		     msg_t         *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len)
{
    unsigned char devid;
    unsigned int  offset;
    unsigned int  count;
    unsigned char *data;
    unsigned int  size;
    fru_session_t *ses;
    fru_data_t *fru;

    if (check_msg_length(msg, 4, rdata, rdata_len))
	return;

    devid = msg->data[0];
    if (devid >= 255) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    fru = &mc->frus[devid];
    offset = ipmi_get_uint16(msg->data+1);
    count = msg->data[3];

    data = fru->data;
    size = fru->length;
    ses = fru->sessions;
    while (ses && (ses->sid != msg->sid))
	ses = ses->next;
    if (ses) {
	data = ses->data;
	size = ses->length;
    }

    if (!data) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (offset >= size) {
	rdata[0] = IPMI_PARAMETER_OUT_OF_RANGE_CC;
	*rdata_len = 1;
	return;
    }

    if ((offset+count) > size)
	count = size - offset;
    if (count+2 > *rdata_len) {
	/* Too much data to put into response. */
	rdata[0] = IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = count;
    memcpy(rdata + 2, data + offset, count);
    *rdata_len = 2 + count;
}

static void
handle_write_fru_data(lmc_data_t    *mc,
		      msg_t         *msg,
		      unsigned char *rdata,
		      unsigned int  *rdata_len)
{
    unsigned char devid;
    unsigned int  offset;
    unsigned int  count;

    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    devid = msg->data[0];
    if ((devid >= 255) || (!mc->frus[devid].data)) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    offset = ipmi_get_uint16(msg->data+1);
    count = msg->len - 3;

    if (offset >= mc->frus[devid].length) {
	rdata[0] = IPMI_PARAMETER_OUT_OF_RANGE_CC;
	*rdata_len = 1;
	return;
    }

    if ((offset+count) > mc->frus[devid].length) {
	/* Too much data to put into FRU. */
	rdata[0] = IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC;
	*rdata_len = 1;
	return;
    }

    memcpy(mc->frus[devid].data+offset, msg->data+3, count);
    rdata[0] = 0;
    rdata[1] = count;
    *rdata_len = 2;
}

int
ipmi_mc_get_fru_data(lmc_data_t    *mc,
		     unsigned char device_id,
		     unsigned int  *length,
		     unsigned char **data)
{
    if (!(mc->device_support & IPMI_DEVID_FRU_INVENTORY_DEV))
	return ENOSYS;

    if (device_id >= 255)
	return EINVAL;

    if (!mc->frus[device_id].data)
	return EINVAL;

    *data = mc->frus[device_id].data;
    *length = mc->frus[device_id].length;
    return 0;
}

int
ipmi_mc_add_fru_data(lmc_data_t    *mc,
		     unsigned char device_id,
		     unsigned int  length,
		     unsigned char *data,
		     unsigned int  data_len)
{
    if (!(mc->device_support & IPMI_DEVID_FRU_INVENTORY_DEV))
	return ENOSYS;

    if (device_id >= 255)
	return EINVAL;

    if (data_len > length)
	return EINVAL;

    if (mc->frus[device_id].data) {
	free(mc->frus[device_id].data);
	mc->frus[device_id].length = 0;
    }

    mc->frus[device_id].data = malloc(length);
    if (!mc->frus[device_id].data)
	return ENOMEM;
    mc->frus[device_id].length = length;
    memset(mc->frus[device_id].data, 0, length);
    memcpy(mc->frus[device_id].data, data, data_len);
    return 0;
}

/* We don't currently care about partial sel adds, since they are
   pretty stupid. */
cmd_handler_f storage_netfn_handlers[256] = {
    [IPMI_GET_SEL_INFO_CMD] = handle_get_sel_info,
    [IPMI_GET_SEL_ALLOCATION_INFO_CMD] = handle_get_sel_allocation_info,
    [IPMI_RESERVE_SEL_CMD] = handle_reserve_sel,
    [IPMI_GET_SEL_ENTRY_CMD] = handle_get_sel_entry,
    [IPMI_ADD_SEL_ENTRY_CMD] = handle_add_sel_entry,
    [IPMI_DELETE_SEL_ENTRY_CMD] = handle_delete_sel_entry,
    [IPMI_CLEAR_SEL_CMD] = handle_clear_sel,
    [IPMI_GET_SEL_TIME_CMD] = handle_get_sel_time,
    [IPMI_SET_SEL_TIME_CMD] = handle_set_sel_time,
    [IPMI_GET_SDR_REPOSITORY_INFO_CMD] = handle_get_sdr_repository_info,
    [IPMI_GET_SDR_REPOSITORY_ALLOC_INFO_CMD] = handle_get_sdr_repository_alloc_info,
    [IPMI_RESERVE_SDR_REPOSITORY_CMD] = handle_reserve_sdr_repository,
    [IPMI_GET_SDR_CMD] = handle_get_sdr,
    [IPMI_ADD_SDR_CMD] = handle_add_sdr,
    [IPMI_PARTIAL_ADD_SDR_CMD] = handle_partial_add_sdr,
    [IPMI_DELETE_SDR_CMD] = handle_delete_sdr,
    [IPMI_CLEAR_SDR_REPOSITORY_CMD] = handle_clear_sdr_repository,
    [IPMI_GET_SDR_REPOSITORY_TIME_CMD] = handle_get_sdr_repository_time,
    [IPMI_SET_SDR_REPOSITORY_TIME_CMD] = handle_set_sdr_repository_time,
    [IPMI_ENTER_SDR_REPOSITORY_UPDATE_CMD] = handle_enter_sdr_repository_update,
    [IPMI_EXIT_SDR_REPOSITORY_UPDATE_CMD] = handle_exit_sdr_repository_update,
    [IPMI_GET_FRU_INVENTORY_AREA_INFO_CMD] = handle_get_fru_inventory_area_info,
    [IPMI_READ_FRU_DATA_CMD] = handle_read_fru_data,
    [IPMI_WRITE_FRU_DATA_CMD] = handle_write_fru_data
};
