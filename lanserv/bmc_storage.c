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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/persist.h>

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

static int
handle_sel(const char *name, void *data, unsigned int len, void *cb_data)
{
    sel_entry_t *e, *n;
    lmc_data_t *mc = cb_data;

    if (len != 16) {
	mc->sysinfo->log(mc->sysinfo, INFO, NULL,
			 "Got invalid SEL entry for %2.2x, name is %s",
			 ipmi_mc_get_ipmb(mc), name);
	goto out;
    }

    n = malloc(sizeof(*n));
    if (!n)
	return ENOMEM;

    memcpy(n->data, data, 16);
    n->record_id = n->data[0] | (n->data[1] << 8);
    n->next = NULL;

    e = mc->sel.entries;
    if (!e)
	mc->sel.entries = n;
    else {
	while (e->next)
	    e = e->next;
	e->next = n;
    }
    mc->sel.count++;

  out:
    return ITER_PERSIST_CONTINUE;
}

static int
handle_sel_time(const char *name, long val, void *cb_data)
{
    lmc_data_t *mc = cb_data;

    if (strcmp(name, "last_add_time") == 0)
	mc->sel.last_add_time = val;
    else if (strcmp(name, "last_erase_time") == 0)
	mc->sel.last_erase_time = val;
    return ITER_PERSIST_CONTINUE;
}

int
ipmi_mc_enable_sel(lmc_data_t    *mc,
		   int           max_entries,
		   unsigned char flags)
{
    persist_t *p;

    mc->sel.entries = NULL;
    mc->sel.count = 0;
    mc->sel.max_count = max_entries;
    mc->sel.last_add_time = 0;
    mc->sel.last_erase_time = 0;
    mc->sel.flags = flags & 0xb;
    mc->sel.reservation = 0;
    mc->sel.next_entry = 1;

    p = read_persist("sel.%2.2x", ipmi_mc_get_ipmb(mc));
    if (!p)
	return 0;

    iterate_persist(p, mc, handle_sel, handle_sel_time);
    free_persist(p);
    return 0;
}
		    
static void
rewrite_sels(lmc_data_t *mc)
{
    persist_t *p = NULL;
    sel_entry_t *e;
    int err;

    p = alloc_persist("sel.%2.2x", ipmi_mc_get_ipmb(mc));
    if (!p) {
	err = ENOMEM;
	goto out_err;
    }

    err = add_persist_int(p, mc->sel.last_add_time, "last_add_time");
    if (err)
	goto out_err;

    err = add_persist_int(p, mc->sel.last_erase_time, "last_erase_time");
    if (err)
	goto out_err;

    for (e = mc->sel.entries; e; e = e->next) {
	err = add_persist_data(p, e->data, 16, "%d", e->record_id);
	if (err)
	    goto out_err;
    }

    err = write_persist(p);
    if (err)
	goto out_err;
    free_persist(p);
    return;

  out_err:
    mc->sysinfo->log(mc->sysinfo, OS_ERROR, NULL,
		     "Unable to write persistent SELs for MC %d: %d",
		     ipmi_mc_get_ipmb(mc), err);
    if (p)
	free_persist(p);
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

    if (mc->sel.count >= mc->sel.max_count) {
	mc->sel.flags |= 0x80;
	return EAGAIN;
    }

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

    mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &t);

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

    rewrite_sels(mc);

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
		    unsigned int  *rdata_len,
		    void          *cb_data)
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

    *rdata_len = 15;
}

static void
handle_get_sel_allocation_info(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len,
			       void          *cb_data)
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
		   unsigned int  *rdata_len,
		   void          *cb_data)
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
		     unsigned int  *rdata_len,
		     void          *cb_data)
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
		     unsigned int  *rdata_len,
		     void          *cb_data)
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
			unsigned int  *rdata_len,
			void          *cb_data)
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

    /* Clear the overflow flag. */
    mc->sel.flags &= ~0x80;

    rdata[0] = 0;
    ipmi_set_uint16(rdata+1, entry->record_id);
    *rdata_len = 3;

    mc->sel.count--;
    free(entry);

    rewrite_sels(mc);
}

static void
handle_clear_sel(lmc_data_t    *mc,
		 msg_t         *msg,
		 unsigned char *rdata,
		 unsigned int  *rdata_len,
		 void          *cb_data)
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

    mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &t);
    mc->sel.last_erase_time = t.tv_sec + mc->sel.time_offset;

    rdata[0] = 0;
    *rdata_len = 2;

    /* Clear the overflow flag. */
    mc->sel.flags &= ~0x80;

    rewrite_sels(mc);
}

static void
handle_get_sel_time(lmc_data_t    *mc,
		    msg_t         *msg,
		    unsigned char *rdata,
		    unsigned int  *rdata_len,
		    void          *cb_data)
{
    struct timeval t;

    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &t);
    rdata[0] = 0;
    ipmi_set_uint32(rdata+1, t.tv_sec + mc->sel.time_offset);
    *rdata_len = 5;
}

static void
handle_set_sel_time(lmc_data_t    *mc,
		    msg_t         *msg,
		    unsigned char *rdata,
		    unsigned int  *rdata_len,
		    void          *cb_data)
{
    struct timeval t;

    if (!(mc->device_support & IPMI_DEVID_SEL_DEVICE)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 4, rdata, rdata_len))
	return;

    mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &t);
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
find_sdr_by_recid(sdrs_t     *sdrs,
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
new_sdr_entry(sdrs_t *sdrs, unsigned char length)
{
    sdr_t    *entry;
    uint16_t start_recid;

    start_recid = sdrs->next_entry;
    while (find_sdr_by_recid(sdrs, sdrs->next_entry, NULL)) {
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

static void
rewrite_sdrs(lmc_data_t *mc, sdrs_t *sdrs)
{
    persist_t *p = NULL;
    sdr_t *sdr;
    int err;

    p = alloc_persist("sdr.%2.2x.main", ipmi_mc_get_ipmb(mc));
    if (!p) {
	err = ENOMEM;
	goto out_err;
    }

    err = add_persist_int(p, sdrs->last_add_time, "last_add_time");
    if (err)
	goto out_err;

    err = add_persist_int(p, sdrs->last_erase_time, "last_erase_time");
    if (err)
	goto out_err;

    for (sdr = sdrs->sdrs; sdr; sdr = sdr->next) {
	unsigned int recid = ipmi_get_uint16(sdr->data);
	err = add_persist_data(p, sdr->data, sdr->length, "%d", recid);
	if (err)
	    goto out_err;
    }

    err = write_persist(p);
    if (err)
	goto out_err;
    free_persist(p);
    return;

  out_err:
    mc->sysinfo->log(mc->sysinfo, OS_ERROR, NULL,
		     "Unable to write persistent SDRs for MC %d: %d",
		     ipmi_mc_get_ipmb(mc), err);
    if (p)
	free_persist(p);
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

    mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &t);
    sdrs->last_add_time = t.tv_sec + mc->main_sdrs.time_offset;
    sdrs->sdr_count++;

    rewrite_sdrs(mc, sdrs);
}

static void
free_sdr(sdr_t *sdr)
{
    free(sdr->data);
    free(sdr);
}

static int
handle_sdr(const char *name, void *data, unsigned int len, void *cb_data)
{
    sdr_t *sdr, *p;
    sdrs_t *sdrs = cb_data;

    sdr = new_sdr_entry(sdrs, len);
    if (!sdr)
	return ENOMEM;
    memcpy(sdr->data, data, len);

    sdr->next = NULL;
    p = sdrs->sdrs;
    if (!p)
	sdrs->sdrs = sdr;
    else {
	while (p->next)
	    p = p->next;
	p->next = sdr;
    }
    sdrs->sdr_count++;

    return ITER_PERSIST_CONTINUE;
}

static int
handle_sdr_time(const char *name, long val, void *cb_data)
{
    sdrs_t *sdrs = cb_data;

    if (strcmp(name, "last_add_time") == 0)
	sdrs->last_add_time = val;
    else if (strcmp(name, "last_erase_time") == 0)
	sdrs->last_erase_time = val;
    return ITER_PERSIST_CONTINUE;
}

void
read_mc_sdrs(lmc_data_t *mc, sdrs_t *sdrs, const char *sdrtype)
{
    persist_t *p;

    p = read_persist("sdr.%2.2x.%s", ipmi_mc_get_ipmb(mc), sdrtype);
    if (!p)
	return;

    iterate_persist(p, sdrs, handle_sdr, handle_sdr_time);
    free_persist(p);
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

    entry = new_sdr_entry(&mc->main_sdrs, data_len);
    if (!entry)
	return ENOMEM;

    memcpy(entry->data+2, data+2, data_len-2);

    add_sdr_entry(mc, &mc->main_sdrs, entry);

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

    entry = new_sdr_entry(&mc->device_sdrs[lun], data_len);
    if (!entry)
	return ENOMEM;

    add_sdr_entry(mc, &mc->device_sdrs[lun], entry);

    memcpy(entry->data+2, data+2, data_len-2);

    mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &t);
    mc->sensor_population_change_time = t.tv_sec + mc->main_sdrs.time_offset;
    mc->lun_has_sensors[lun] = 1;
    mc->num_sensors_per_lun[lun]++;
    return 0;
}

static void
handle_get_sdr_repository_info(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len,
			       void          *cb_data)
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
				     unsigned int  *rdata_len,
				     void          *cb_data)
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
			      unsigned int  *rdata_len,
			      void          *cb_data)
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
	       unsigned int  *rdata_len,
	       void          *cb_data)
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
	entry = find_sdr_by_recid(&mc->main_sdrs, record_id, NULL);
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
	rdata[0] = IPMI_CANNOT_RETURN_REQ_LENGTH_CC;
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
	       unsigned int  *rdata_len,
	       void          *cb_data)
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

    entry = new_sdr_entry(&mc->main_sdrs, msg->data[5]);
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
		       unsigned int  *rdata_len,
		       void          *cb_data)
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
	mc->part_add_sdr = new_sdr_entry(&mc->main_sdrs, msg->data[11]);
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

void
iterate_sdrs(lmc_data_t *mc,
	     sdrs_t     *sdrs,
	     int (*func)(lmc_data_t *mc, unsigned char *sdr,
			 unsigned int len, void *cb_data),
	     void *cb_data)
{
    sdr_t *entry;

    for (entry = sdrs->sdrs; entry; entry = entry->next)
	func(mc, entry->data, entry->length, cb_data);
}

static void
handle_delete_sdr(lmc_data_t    *mc,
		  msg_t         *msg,
		  unsigned char *rdata,
		  unsigned int  *rdata_len,
		  void          *cb_data)
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
	entry = find_sdr_by_recid(&mc->main_sdrs, record_id, &p_entry);
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

    mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &t);
    mc->main_sdrs.last_erase_time = t.tv_sec + mc->main_sdrs.time_offset;
    mc->main_sdrs.sdr_count--;
    rewrite_sdrs(mc, &mc->main_sdrs);
}

static void
handle_clear_sdr_repository(lmc_data_t    *mc,
			    msg_t         *msg,
			    unsigned char *rdata,
			    unsigned int  *rdata_len,
			    void          *cb_data)
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

    mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &t);
    mc->main_sdrs.last_erase_time = t.tv_sec + mc->main_sdrs.time_offset;
    rewrite_sdrs(mc, &mc->main_sdrs);
}

static void
handle_get_sdr_repository_time(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len,
			       void          *cb_data)
{
    struct timeval t;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &t);
    rdata[0] = 0;
    ipmi_set_uint32(rdata+1, t.tv_sec + mc->main_sdrs.time_offset);
    *rdata_len = 5;
}

static void
handle_set_sdr_repository_time(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len,
			       void          *cb_data)
{
    struct timeval t;

    if (!(mc->device_support & IPMI_DEVID_SDR_REPOSITORY_DEV)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 4, rdata, rdata_len))
	return;

    mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &t);
    mc->main_sdrs.time_offset = ipmi_get_uint32(msg->data) - t.tv_sec;

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_enter_sdr_repository_update(lmc_data_t    *mc,
				   msg_t         *msg,
				   unsigned char *rdata,
				   unsigned int  *rdata_len,
				   void          *cb_data)
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
				  unsigned int  *rdata_len,
				  void          *cb_data)
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

/*
 * FRU Inventory handling
 */

fru_data_t *
find_fru(lmc_data_t *mc, unsigned int devid)
{
    fru_data_t *fru = mc->frulist;

    while (fru && fru->devid != devid)
	fru = fru->next;

    return fru;
}

int
ipmi_mc_set_frudata_handler(lmc_data_t *mc, unsigned int devid,
			    get_frudata_f handler, free_frudata_f freefunc)
{
    fru_data_t *fru = find_fru(mc, devid);

    if (!fru)
	return EINVAL;
    fru->get = handler;
    fru->free = freefunc;
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
				   unsigned int  *rdata_len,
				   void          *cb_data)
{
    unsigned char devid;
    fru_data_t *fru;
    unsigned int size;
    unsigned char *data;
    int rv;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    devid = msg->data[0];

    fru = find_fru(mc, devid);
    if (!fru) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

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

static int
fru_sem_trywait(fru_data_t *fru)
{
    struct timespec ts;
    int rv;

    /* Wait 250ms for the semaphore. */
  restart:
    ts.tv_sec = 0;
    ts.tv_nsec = 250000000;
    rv = sem_timedwait(&fru->sem, &ts);
    if (rv) {
	if (rv == EINTR)
	    goto restart;
	if (rv == ETIMEDOUT)
	    rv = EAGAIN;
	else
	    rv = errno;
	return rv;
    }
    return 0;
}

static void
handle_read_fru_data(lmc_data_t    *mc,
		     msg_t         *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len,
		     void          *cb_data)
{
    unsigned char devid;
    unsigned int  offset;
    unsigned int  count;
    unsigned char *data = NULL;
    unsigned int  size;
    fru_session_t *ses;
    fru_data_t *fru;
    int           rv;

    if (check_msg_length(msg, 4, rdata, rdata_len))
	return;

    devid = msg->data[0];
    fru = find_fru(mc, devid);
    if (!fru) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rv = fru_sem_trywait(fru);
    if (rv) {
	if (rv == EAGAIN)
	    rdata[0] = IPMI_NODE_BUSY_CC;
	else
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	*rdata_len = 1;
	return;
    }

    offset = ipmi_get_uint16(msg->data+1);
    count = msg->data[3];

    size = fru->length;

    if (!fru->fru_io_cb) {
	data = fru->data;
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
	    goto out_unlock;
	}

	if (offset >= size) {
	    rdata[0] = IPMI_PARAMETER_OUT_OF_RANGE_CC;
	    *rdata_len = 1;
	    goto out_unlock;
	}
    }

    if ((offset+count) > size)
	count = size - offset;
    if (count+2 > *rdata_len) {
	/* Too much data to put into response. */
	rdata[0] = IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC;
	*rdata_len = 1;
	goto out_unlock;
    }

    if (fru->fru_io_cb) {
	int rv;

	rv = fru->fru_io_cb(fru->data, FRU_IO_READ, rdata + 2, offset, count);
	if (rv) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    goto out_unlock;
	}
    } else {
	memcpy(rdata + 2, data + offset, count);
    }

    rdata[0] = 0;
    rdata[1] = count;
    *rdata_len = 2 + count;

  out_unlock:
    sem_post(&fru->sem);
}

static void
handle_write_fru_data(lmc_data_t    *mc,
		      msg_t         *msg,
		      unsigned char *rdata,
		      unsigned int  *rdata_len,
		      void          *cb_data)
{
    unsigned char device_id;
    unsigned int  offset;
    unsigned int  count;
    fru_data_t    *fru;
    int           rv;

    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    device_id = msg->data[0];
    fru = find_fru(mc, device_id);
    if (!fru) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rv = fru_sem_trywait(fru);
    if (rv) {
	if (rv == EAGAIN)
	    rdata[0] = IPMI_NODE_BUSY_CC;
	else
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	*rdata_len = 1;
	return;
    }

    offset = ipmi_get_uint16(msg->data+1);
    count = msg->len - 3;

    if (offset >= fru->length) {
	rdata[0] = IPMI_PARAMETER_OUT_OF_RANGE_CC;
	*rdata_len = 1;
	goto out_unlock;
    }

    if ((offset+count) > fru->length) {
	/* Too much data to put into FRU. */
	rdata[0] = IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC;
	*rdata_len = 1;
	goto out_unlock;
    }

    if (fru->fru_io_cb) {
	int rv;

	rv = fru->fru_io_cb(fru->data, FRU_IO_WRITE, msg->data + 3, offset,
			    count);
	if (rv) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    goto out_unlock;
	}
    } else {
	memcpy(fru->data+offset, msg->data+3, count);
    }
    rdata[0] = 0;
    rdata[1] = count;
    *rdata_len = 2;

  out_unlock:
    sem_post(&fru->sem);
}

int
ipmi_mc_get_fru_data_len(lmc_data_t    *mc,
			 unsigned char device_id,
			 unsigned int  *length)
{
    fru_data_t *fru;

    if (!(mc->device_support & IPMI_DEVID_FRU_INVENTORY_DEV))
	return ENOSYS;

    if (device_id >= 255)
	return EINVAL;

    fru = find_fru(mc, device_id);
    if (!fru || !fru->data)
	return EINVAL;

    *length = fru->length;

    return 0;
}

int
ipmi_mc_get_fru_data(lmc_data_t    *mc,
		     unsigned char device_id,
		     unsigned int  length,
		     unsigned char *data)
{
    fru_data_t *fru;
    int        rv;

    if (!(mc->device_support & IPMI_DEVID_FRU_INVENTORY_DEV))
	return ENOSYS;

    fru = find_fru(mc, device_id);
    if (!fru)
	return EINVAL;

    if (length > fru->length)
	return EINVAL;

    rv = fru_sem_trywait(fru);
    if (rv)
	return errno;

    if (fru->fru_io_cb) {
	rv = fru->fru_io_cb(fru->data, FRU_IO_READ, data, 0, length);
    } else {
	memcpy(data, fru->data, length);
    }

    sem_post(&fru->sem);
    return rv;
}

int
ipmi_mc_add_fru_data(lmc_data_t    *mc,
		     unsigned char device_id,
		     unsigned int  length,
		     fru_io_cb     fru_io_cb,
		     void          *data)
{
    fru_data_t *fru;

    if (device_id > 255)
	return EINVAL;

    fru = find_fru(mc, device_id);
    if (!fru) {
	int rv;
	fru = malloc(sizeof(*fru));
	memset(fru, 0, sizeof(*fru));
	rv = sem_init(&fru->sem, 0, 1);
	if (rv) {
	    rv = errno;
	    free(fru);
	    return rv;
	}
	fru->devid = device_id;
	fru->next = mc->frulist;
	mc->frulist = fru;
    }

    if (fru->data) {
	free(fru->data);
	fru->length = 0;
    }

    if (fru_io_cb) {
	fru->fru_io_cb = fru_io_cb;
	fru->data = data;
    } else if (length) {
	fru->data = malloc(length);
	if (!fru->data)
	    return ENOMEM;
	memcpy(fru->data, data, length);
    } else
	fru->data = NULL;

    fru->length = length;

    return 0;
}

int
ipmi_mc_fru_sem_wait(lmc_data_t *mc, unsigned char device_id)
{
    int rv;
    fru_data_t *fru = find_fru(mc, device_id);
    if (!fru)
	return EINVAL;
    rv = sem_wait(&fru->sem);
    if (rv)
	return errno;
    return 0;
}

int
ipmi_mc_fru_sem_trywait(lmc_data_t *mc, unsigned char device_id)
{
    int rv;
    fru_data_t *fru = find_fru(mc, device_id);
    if (!fru)
	return EINVAL;
    rv = fru_sem_trywait(fru);
    if (rv)
	return errno;
    return 0;
}

int
ipmi_mc_fru_sem_post(lmc_data_t *mc, unsigned char device_id)
{
    int rv;
    fru_data_t *fru = find_fru(mc, device_id);
    if (!fru)
	return EINVAL;
    rv = sem_post(&fru->sem);
    if (rv)
	return errno;
    return 0;
}

struct fru_file_io_info {
    lmc_data_t   *mc;
    char         *filename;
    unsigned int file_offset;
    unsigned int length;
};

static int fru_file_io_cb(void *cb_data,
			  enum fru_io_cb_op op,
			  unsigned char *data,
			  unsigned int offset,
			  unsigned int length)
{
    struct fru_file_io_info *info = cb_data;
    int fd;
    int rv = 0;
    int l;

    if (offset + length > info->length)
	return EINVAL;

    switch (op) {
    case FRU_IO_READ:
	fd = open(info->filename, O_RDONLY);
	if (fd == -1) {
	    rv = errno;
	    info->mc->sysinfo->log(info->mc->sysinfo, OS_ERROR, NULL,
				   "fru_io: (read) error on open of %s: %s",
				   info->filename, strerror(rv));
	    return rv;
	}
	if (lseek(fd, info->file_offset + offset, SEEK_SET) == -1) {
	    rv = errno;
	    close(fd);
	    info->mc->sysinfo->log(info->mc->sysinfo, OS_ERROR, NULL,
				   "fru_io: (read) error on lseek"
				   " of %s to %u: %s",
				   info->filename, info->file_offset + offset,
				   strerror(rv));
	    return rv;
	}
    restart_read:
	l = read(fd, data, length);
	if (l == -1) {
	    if (errno == EINTR)
		goto restart_read;
	    rv = errno;
	    info->mc->sysinfo->log(info->mc->sysinfo, OS_ERROR, NULL,
				   "fru_io: error on read of %u bytes of %s"
				   " at %u: %s",
				   length, info->filename,
				   info->file_offset + offset,
				   strerror(rv));
	} else if (l == 0) {
	    rv = EIO;
	    info->mc->sysinfo->log(info->mc->sysinfo, OS_ERROR, NULL,
				   "fru_io: end of file read of %u bytes of %s"
				   " at %u: %s",
				   length, info->filename,
				   info->file_offset + offset,
				   strerror(rv));
	} else if (((unsigned int) l) != length) {
	    length -= l;
	    data += l;
	    goto restart_read;
	}
	close(fd);
	break;

    case FRU_IO_WRITE:
	fd = open(info->filename, O_WRONLY);
	if (fd == -1) {
	    rv = errno;
	    info->mc->sysinfo->log(info->mc->sysinfo, OS_ERROR, NULL,
				   "fru_io: (write) error on open of %s: %s",
				   info->filename, strerror(rv));
	    return rv;
	}
	if (lseek(fd, info->file_offset + offset, SEEK_SET) == -1) {
	    rv = errno;
	    close(fd);
	    info->mc->sysinfo->log(info->mc->sysinfo, OS_ERROR, NULL,
				   "fru_io: (write) error on lseek"
				   " of %s to %u: %s",
				   info->filename, info->file_offset + offset,
				   strerror(rv));
	    return rv;
	}
    restart_write:
	l = write(fd, data, length);
	if (l == -1) {
	    if (errno == EINTR)
		goto restart_write;
	    rv = errno;
	    info->mc->sysinfo->log(info->mc->sysinfo, OS_ERROR, NULL,
				   "fru_io: error on write of %u bytes of %s"
				   " at %u: %s",
				   length, info->filename,
				   info->file_offset + offset,
				   strerror(rv));
	} else if (l == 0) {
	    rv = EIO;
	    info->mc->sysinfo->log(info->mc->sysinfo, OS_ERROR, NULL,
				   "fru_io: end of file write of %u bytes of %s"
				   " at %u: %s",
				   length, info->filename,
				   info->file_offset + offset,
				   strerror(rv));
	} else if (((unsigned int) l) != length) {
	    length -= l;
	    data += l;
	    goto restart_write;
	}
	close(fd);
	break;

    default:
	return EINVAL;
    }

    return rv;
}

int ipmi_mc_add_fru_file(lmc_data_t    *mc,
			 unsigned char device_id,
			 unsigned int  length,
			 unsigned int  file_offset,
			 const char    *filename)
{
    struct fru_file_io_info *info;
    int rv;
    
    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->filename = strdup(filename);
    if (!info->filename) {
	free(info);
	return ENOMEM;
    }
    info->mc = mc;
    info->length = length;
    info->file_offset = file_offset;

    rv = ipmi_mc_add_fru_data(mc, device_id, length, fru_file_io_cb, info);
    if (rv) {
	free(info->filename);
	free(info);
    }

    return rv;
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
