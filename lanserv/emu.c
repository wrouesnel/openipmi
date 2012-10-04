/*
 * emu.c
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

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <stdio.h>

#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_picmg.h>
#include <OpenIPMI/ipmi_bits.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/extcmd.h>

#include "emu.h"

static void ipmi_mc_start_cmd(lmc_data_t *mc);

#define WATCHDOG_SENSOR_NUM 0

typedef struct sel_entry_s
{
    uint16_t           record_id;
    unsigned char      data[16];
    struct sel_entry_s *next;
} sel_entry_t;

typedef struct sel_s
{
    sel_entry_t   *entries;
    int           count;
    int           max_count;
    uint32_t      last_add_time;
    uint32_t      last_erase_time;
    unsigned char flags;
    uint16_t      reservation;
    uint16_t      next_entry;
    long          time_offset;
} sel_t;

#define MAX_SDR_LENGTH 261
#define MAX_NUM_SDRS   1024
typedef struct sdr_s
{
    uint16_t      record_id;
    unsigned int  length;
    unsigned char *data;
    struct sdr_s  *next;
} sdr_t;

typedef struct sdrs_s
{
    uint16_t      reservation;
    uint16_t      sdr_count;
    uint16_t      sensor_count;
    uint32_t      last_add_time;
    uint32_t      last_erase_time;
    long          time_offset;
    unsigned char flags;
    uint16_t      next_entry;
    unsigned int  sdrs_length;

    /* A linked list of SDR entries. */
    sdr_t         *sdrs;
} sdrs_t;

typedef struct sensor_s sensor_t;
struct sensor_s
{
    unsigned char num;
    unsigned int  lun              : 2;
    unsigned int  scanning_enabled : 1;
    unsigned int  events_enabled   : 1;

    unsigned char sensor_type;
    unsigned char event_reading_code;

    unsigned char value;

    unsigned char hysteresis_support;
    unsigned char positive_hysteresis;
    unsigned char negative_hysteresis;

    unsigned char threshold_support;
    unsigned char threshold_supported[6];
    unsigned char thresholds[6];

    /* 1st array is 0 for assertion, 1 for deassertion. */
    unsigned char event_support;
    unsigned char event_supported[2][15];
    unsigned char event_enabled[2][15];

    unsigned char event_status[15];

    /* Called when the sensor changes values. */
    void (*sensor_update_handler)(lmc_data_t *mc, sensor_t *sensor);
};

typedef struct fru_data_s fru_data_t;

typedef struct fru_session_s
{
    unsigned char *data_to_free;
    unsigned char *data;
    unsigned int length;
    unsigned int sid;
    fru_data_t *fru;
    struct fru_session_s *next;
    
} fru_session_t;

struct fru_data_s
{
    unsigned int  length;
    unsigned char *data;
    fru_session_t *sessions;
    get_frudata_f get;
    free_frudata_f free;
};

typedef struct led_data_s
{
    unsigned char off_dur;
    unsigned char def_off_dur;
    unsigned char on_dur;
    unsigned char def_on_dur;
    unsigned char color;
    unsigned char color_sup;
    unsigned char loc_cnt;
    unsigned char loc_cnt_sup;
    unsigned char def_loc_cnt_color;
    unsigned char def_override_color;
} led_data_t;

struct lmc_data_s
{
    emu_data_t *emu;

    char enabled;
    char configured; 

    unsigned char ipmb;

    unsigned char guid_set;
    unsigned char guid[16];

    channel_t *channels[IPMI_MAX_CHANNELS];

    channel_t sys_channel;
    channel_t ipmb_channel;

    int users_changed;
    user_t users[MAX_USERS + 1];

    pef_data_t pef;
    pef_data_t pef_rollback;

    ipmi_tick_handler_t tick_handler;
    ipmi_child_quit_t child_quit_handler;
    startcmd_t startcmd;

    unsigned char evq[16];
    char  ev_in_q;

    /* Get Device Id contents. */
    unsigned char device_id;       /* byte 2 */
    unsigned char has_device_sdrs; /* byte 3, bit 7 */
    unsigned char device_revision; /* byte 3, bits 0-6 */
    unsigned char major_fw_rev;    /* byte 4, bits 0-6 */
    unsigned char minor_fw_rev;    /* byte 5 */
    unsigned char device_support;  /* byte 7 */
    unsigned char mfg_id[3];	   /* bytes 8-10 */
    unsigned char product_id[2];   /* bytes 11-12 */

#define IPMI_MC_MSG_FLAG_WATCHDOG_TIMEOUT_MASK	(1 << 3)
#define IPMI_MC_MSG_FLAG_EVT_BUF_FULL		(1 << 1)
#define IPMI_MC_MSG_FLAG_RCV_MSG_QUEUE		(1 << 0)
#define IPMI_MC_MSG_FLAG_WATCHDOG_TIMEOUT_MASK_SET(mc) \
    (IPMI_MC_MSG_FLAG_WATCHDOG_TIMEOUT_MASK & (mc)->msg_flags)
#define IPMI_MC_MSG_FLAG_EVT_BUF_FULL_SET(mc) \
    (IPMI_MC_MSG_FLAG_EVT_BUF_FULL & (mc)->msg_flags)
#define IPMI_MC_MSG_FLAG_RCV_MSG_QUEUE_SET(mc) \
    (IPMI_MC_MSG_FLAG_RCV_MSG_QUEUE & (mc)->msg_flags)
    unsigned char msg_flags;

#define IPMI_MC_RCV_MSG_QUEUE_INT_BIT	0
#define IPMI_MC_EVBUF_FULL_INT_BIT	1
#define IPMI_MC_EVENT_MSG_BUF_BIT	2
#define IPMI_MC_EVENT_LOG_BIT		3
#define IPMI_MC_MSG_INTS_ON(mc) ((mc)->global_enables & \
				 (1 << IPMI_MC_RCV_MSG_QUEUE_INT_BIT))
#define IPMI_MC_EVBUF_FULL_INT_ENABLED(mc) ((mc)->global_enables & \
					(1 << IPMI_MC_EVBUF_FULL_INT_BIT))
#define IPMI_MC_EVENT_LOG_ENABLED(mc) ((mc)->global_enables & \
				       (1 << IPMI_MC_EVENT_LOG_BIT))
#define IPMI_MC_EVENT_MSG_BUF_ENABLED(mc) ((mc)->global_enables & \
					   (1 << IPMI_MC_EVENT_MSG_BUF_BIT))
    unsigned char global_enables;

    sys_data_t *sysinfo;

    msg_t *recv_q_head;
    msg_t *recv_q_tail;

    sel_t sel;

    sdrs_t main_sdrs;
    sdr_t  *part_add_sdr;
    unsigned int part_add_next;
    int    in_update_mode;

    unsigned char event_receiver;
    unsigned char event_receiver_lun;

    sdrs_t device_sdrs[4];
    unsigned int dynamic_sensor_population : 1;
    unsigned int sensors_enabled : 1;
    unsigned char lun_has_sensors[4];
    unsigned char num_sensors_per_lun[4];
    sensor_t *(sensors[4][255]);
    uint32_t sensor_population_change_time;

    fru_data_t frus[255];

    ipmi_sol_t sol;

    int (*chassis_control_set_func)(lmc_data_t *mc, int op, unsigned char val,
				    void *cb_data);
    int (*chassis_control_get_func)(lmc_data_t *mc, int op, unsigned char *val,
				    void *cb_data);
    void *chassis_control_cb_data;
    char *chassis_control_prog;

    unsigned char power_value;
#define MAX_LEDS 8
#define MIN_ATCA_LEDS 2
    unsigned int  num_leds;
    led_data_t leds[MAX_LEDS];

    /* Will be NULL if not valid. */
    sensor_t      *hs_sensor;

#define IPMI_MC_WATCHDOG_USE_MASK 0xc7
#define IPMI_MC_WATCHDOG_ACTION_MASK 0x77
#define IPMI_MC_WATCHDOG_GET_USE(s) ((s)->watchdog_use & 0x7)
#define IPMI_MC_WATCHDOG_GET_DONT_LOG(s) (((s)->watchdog_use >> 7) & 0x1)
#define IPMI_MC_WATCHDOG_GET_DONT_STOP(s) (((s)->watchdog_use >> 6) & 0x1)
#define IPMI_MC_WATCHDOG_GET_PRE_ACTION(s) (((s)->watchdog_action >> 4) & 0x7)
#define IPMI_MC_WATCHDOG_PRE_NONE		0
#define IPMI_MC_WATCHDOG_PRE_SMI		1
#define IPMI_MC_WATCHDOG_PRE_NMI		2
#define IPMI_MC_WATCHDOG_PRE_MSG_INT		3
#define IPMI_MC_WATCHDOG_GET_ACTION(s) ((s)->watchdog_action & 0x7)
#define IPMI_MC_WATCHDOG_ACTION_NONE		0
#define IPMI_MC_WATCHDOG_ACTION_RESET		1
#define IPMI_MC_WATCHDOG_ACTION_POWER_DOWN	2
#define IPMI_MC_WATCHDOG_ACTION_POWER_CYCLE	3
    unsigned char watchdog_use;
    unsigned char watchdog_action;
    unsigned char watchdog_pretimeout;
    unsigned char watchdog_expired;
    int watchdog_running;
    int watchdog_preaction_ran;
    int watchdog_initialized;
    struct timeval watchdog_time; /* Set time */
    struct timeval watchdog_expiry; /* Timeout time */
    ipmi_timer_t *watchdog_timer;
};

typedef struct atca_site_s
{
    unsigned char valid;
    unsigned char hw_address;
    unsigned char site_type;
    unsigned char site_number;
} atca_site_t;

#define MAX_EMU_ADDR		16
#define MAX_EMU_ADDR_DATA	64
typedef struct emu_addr_s
{
    unsigned char valid;
    unsigned char addr_type;
    unsigned char addr_data[MAX_EMU_ADDR_DATA];
    unsigned int  addr_len;
} emu_addr_t;

struct emu_data_s
{
    sys_data_t *sysinfo;

    int users_changed;

    int          atca_mode;
    atca_site_t  atca_sites[128]; /* Indexed by HW address. */
    uint32_t     atca_fru_inv_curr_timestamp;
    uint16_t     atca_fru_inv_curr_lock_id;
    int          atca_fru_inv_locked;
    int          atca_fru_inv_lock_timeout;

    unsigned char *temp_fru_inv_data;
    unsigned int  temp_fru_inv_data_len;

    void *user_data;

    ipmi_emu_sleep_cb sleeper;

    struct timeval last_addr_change_time;
    emu_addr_t addr[MAX_EMU_ADDR];
};

static void picmg_led_set(lmc_data_t *mc, sensor_t *sensor);
static void set_bit(lmc_data_t *mc, sensor_t *sensor, unsigned char bit,
		    unsigned char value,
		    unsigned char evd1, unsigned char evd2, unsigned char evd3,
		    int gen_event);

/* Device ID support bits */
#define IPMI_DEVID_CHASSIS_DEVICE	(1 << 7)
#define IPMI_DEVID_BRIDGE		(1 << 6)
#define IPMI_DEVID_IPMB_EVENT_GEN	(1 << 5)
#define IPMI_DEVID_IPMB_EVENT_RCV	(1 << 4)
#define IPMI_DEVID_FRU_INVENTORY_DEV	(1 << 3)
#define IPMI_DEVID_SEL_DEVICE		(1 << 2)
#define IPMI_DEVID_SDR_REPOSITORY_DEV	(1 << 1)
#define IPMI_DEVID_SENSOR_DEV		(1 << 0)

void
ipmi_emu_tick(emu_data_t *emu, unsigned int seconds)
{
    if (emu->atca_fru_inv_locked) {
	emu->atca_fru_inv_lock_timeout -= seconds;
	if (emu->atca_fru_inv_lock_timeout < 0) {
	    emu->atca_fru_inv_locked = 0;
	    free(emu->temp_fru_inv_data);
	    emu->temp_fru_inv_data = NULL;
	}
    }

    if (emu->users_changed) {
	emu->users_changed = 0;
	write_persist_users(emu->sysinfo);
    }
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

static void
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
handle_invalid_cmd(lmc_data_t    *mc,
		   unsigned char *rdata,
		   unsigned int  *rdata_len)
{
    rdata[0] = IPMI_INVALID_CMD_CC;
    *rdata_len = 1;
}

static int
check_msg_length(msg_t         *msg,
		 unsigned int  len,
		 unsigned char *rdata,
		 unsigned int  *rdata_len)
{
    if (msg->len < len) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return 1;
    }

    return 0;
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
#define IPMI_SDR_DELETE_SDR_SUPPORTED			(1 << 3)
#define IPMI_SDR_PARTIAL_ADD_SDR_SUPPORTED		(1 << 2)
#define IPMI_SDR_RESERVE_SDR_SUPPORTED			(1 << 1)
#define IPMI_SDR_GET_SDR_ALLOC_INFO_SDR_SUPPORTED	(1 << 0)

static sdr_t *
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

static sdr_t *
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

static void
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
static cmd_handler_f storage_netfn_handlers[256] = {
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

static void
handle_get_device_id(lmc_data_t    *mc,
		     msg_t         *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len)
{
    memset(rdata, 0, 12);
    rdata[1] = mc->device_id;
    rdata[2] = ((mc->has_device_sdrs << 0x7)
		| (mc->device_revision & 0xf));
    rdata[3] = mc->major_fw_rev & 0x7f;
    rdata[4] = mc->minor_fw_rev;
    rdata[5] = 0x51;
    rdata[6] = mc->device_support;
    memcpy(rdata+7, mc->mfg_id, 3);
    memcpy(rdata+10, mc->product_id, 2);
    *rdata_len = 12;
}

/* Returns tenths of a second (deciseconds). */
static long
diff_timeval_dc(struct timeval *tv1, struct timeval *tv2)
{
    long rv;

    rv = (tv1->tv_sec - tv2->tv_sec) * 10;
    rv += (tv1->tv_usec - tv2->tv_usec + 50000) / 100000;
    return rv;
}

static void
add_timeval(struct timeval *tv1, struct timeval *tv2)
{
    tv1->tv_sec += tv2->tv_sec;
    tv1->tv_usec += tv2->tv_usec;
    while (tv1->tv_usec >= 1000000) {
	tv1->tv_usec -= 1000000;
	tv1->tv_sec += 1;
    }
    while (tv1->tv_usec <= 0) {
	tv1->tv_usec += 1000000;
	tv1->tv_sec -= 1;
    }
}

static void
sub_timeval(struct timeval *tv1, struct timeval *tv2)
{
    tv1->tv_sec -= tv2->tv_sec;
    tv1->tv_usec -= tv2->tv_usec;
    while (tv1->tv_usec >= 1000000) {
	tv1->tv_usec -= 1000000;
	tv1->tv_sec += 1;
    }
    while (tv1->tv_usec <= 0) {
	tv1->tv_usec += 1000000;
	tv1->tv_sec -= 1;
    }
}

static void
handle_get_watchdog_timer(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len)
{
    long v = 0;
    static struct timeval zero_tv = {0, 0};

    if (!mc->watchdog_timer) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    if (mc->watchdog_running) {
	struct timeval now;
	gettimeofday(&now, NULL);
	v = diff_timeval_dc(&mc->watchdog_expiry, &now);
	if (v < 0)
	    v = 0;
    }
    rdata[0] = 0;
    rdata[1] = mc->watchdog_use;
    rdata[2] = mc->watchdog_action;
    rdata[3] = mc->watchdog_pretimeout;
    rdata[4] = mc->watchdog_expired;
    ipmi_set_uint16(rdata + 7, v);
    v = diff_timeval_dc(&mc->watchdog_time, &zero_tv);
    ipmi_set_uint16(rdata + 5, v);
    *rdata_len = 7;
}

static void
watchdog_timeout(void *cb_data)
{
    lmc_data_t *mc = cb_data;
    channel_t *bchan = mc->channels[15];
    sensor_t *sens = mc->sensors[0][WATCHDOG_SENSOR_NUM];

    if (!mc->watchdog_running)
	goto out;

    if (! mc->watchdog_preaction_ran) {
	struct timeval tv, now;

	switch (IPMI_MC_WATCHDOG_GET_PRE_ACTION(mc)) {
	case IPMI_MC_WATCHDOG_PRE_NMI:
	    mc->msg_flags |= IPMI_MC_MSG_FLAG_WATCHDOG_TIMEOUT_MASK;
	    bchan->hw_op(bchan, HW_OP_SEND_NMI);
	    set_bit(mc, sens, 8, 1, 0xc8, (2 << 4) | 0xf, 0xff, 1);
	    break;

	case IPMI_MC_WATCHDOG_PRE_MSG_INT:
	    mc->msg_flags |= IPMI_MC_MSG_FLAG_WATCHDOG_TIMEOUT_MASK;
	    if (bchan->set_atn && !IPMI_MC_MSG_FLAG_EVT_BUF_FULL_SET(mc))
		bchan->set_atn(bchan, 1, IPMI_MC_MSG_INTS_ON(mc));
	    set_bit(mc, sens, 8, 1, 0xc8, (3 << 4) | 0xf, 0xff, 1);
	    break;

	default:
	    goto do_full_expiry;
	}

	mc->watchdog_preaction_ran = 1;
	/* Issued the pretimeout, do the rest of the timeout now. */
	gettimeofday(&now, NULL);
	tv = mc->watchdog_expiry;
	sub_timeval(&tv, &now);
	if (tv.tv_sec == 0) {
	    tv.tv_sec = 0;
	    tv.tv_usec = 0;
	}
	mc->sysinfo->start_timer(mc->watchdog_timer, &tv);
	goto out;
    }

 do_full_expiry:
    mc->watchdog_running = 0; /* Stop the watchdog on a timeout */
    mc->watchdog_expired |= (1 << IPMI_MC_WATCHDOG_GET_USE(mc));
    switch (IPMI_MC_WATCHDOG_GET_ACTION(mc)) {
    case IPMI_MC_WATCHDOG_ACTION_NONE:
	set_bit(mc, sens, 0, 1, 0xc0, mc->watchdog_use & 0xf, 0xff, 1);
	break;

    case IPMI_MC_WATCHDOG_ACTION_RESET:
	set_bit(mc, sens, 1, 1, 0xc1, mc->watchdog_use & 0xf, 0xff, 1);
	bchan->hw_op(bchan, HW_OP_RESET);
	break;

    case IPMI_MC_WATCHDOG_ACTION_POWER_DOWN:
	set_bit(mc, sens, 2, 1, 0xc2, mc->watchdog_use & 0xf, 0xff, 1);
	bchan->hw_op(bchan, HW_OP_POWEROFF);
	break;

    case IPMI_MC_WATCHDOG_ACTION_POWER_CYCLE:
	set_bit(mc, sens, 2, 1, 0xc3, mc->watchdog_use & 0xf, 0xff, 1);
	bchan->hw_op(bchan, HW_OP_POWEROFF);
	/* FIXME - add poweron. */
	break;
    }

 out:
    return;
}

static void
do_watchdog_reset(lmc_data_t *mc)
{
    struct timeval tv;

    if (IPMI_MC_WATCHDOG_GET_ACTION(mc) ==
	IPMI_MC_WATCHDOG_ACTION_NONE) {
	mc->watchdog_running = 0;
	return;
    }
    mc->watchdog_preaction_ran = 0;

    /* Timeout is in tenths of a second, offset is in seconds */
    gettimeofday(&mc->watchdog_expiry, NULL);
    add_timeval(&mc->watchdog_expiry, &mc->watchdog_time);
    tv = mc->watchdog_time;
    if (IPMI_MC_WATCHDOG_GET_PRE_ACTION(mc) != IPMI_MC_WATCHDOG_PRE_NONE) {
	tv.tv_sec -= mc->watchdog_pretimeout;
	if (tv.tv_sec < 0) {
	    tv.tv_sec = 0;
	    tv.tv_usec = 0;
	}
    }
    mc->watchdog_running = 1;
    mc->sysinfo->start_timer(mc->watchdog_timer, &tv);
}

static void
handle_set_watchdog_timer(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len)
{
    unsigned int val;
    channel_t *bchan;

    if (!mc->watchdog_timer) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    if (check_msg_length(msg, 6, rdata, rdata_len))
	return;

    val = msg->data[0] & 0x7; /* Validate use */
    if (val == 0 || val > 5) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;

    bchan = mc->channels[15];
    val = msg->data[1] & 0x7; /* Validate action */
    switch (val) {
    case IPMI_MC_WATCHDOG_ACTION_NONE:
	break;
	
    case IPMI_MC_WATCHDOG_ACTION_RESET:
	rdata[0] = !HW_OP_CAN_RESET(bchan);
	break;
	
    case IPMI_MC_WATCHDOG_ACTION_POWER_DOWN:
    case IPMI_MC_WATCHDOG_ACTION_POWER_CYCLE:
	rdata[0] = !HW_OP_CAN_POWER(bchan);
	break;
	
    default:
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
    }
    if (rdata[0]) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }
    
    val = (msg->data[1] >> 4) & 0x7; /* Validate preaction */
    switch (val) {
    case IPMI_MC_WATCHDOG_PRE_MSG_INT:
    case IPMI_MC_WATCHDOG_PRE_NONE:
	break;
	
    case IPMI_MC_WATCHDOG_PRE_NMI:
	if (!HW_OP_CAN_NMI(bchan)) {
	    /* NMI not supported. */
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}
    default:
	/* We don't support PRE_SMI */
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }
    
    mc->watchdog_initialized = 1;
    mc->watchdog_use = msg->data[0] & IPMI_MC_WATCHDOG_USE_MASK;
    mc->watchdog_action = msg->data[1] & IPMI_MC_WATCHDOG_ACTION_MASK;
    mc->watchdog_pretimeout = msg->data[2];
    mc->watchdog_expired &= ~msg->data[3];
    val = msg->data[4] | (((uint16_t) msg->data[5]) << 8);
    mc->watchdog_time.tv_sec = val / 10;
    mc->watchdog_time.tv_usec = (val % 10) * 100000;
    if (mc->watchdog_running & IPMI_MC_WATCHDOG_GET_DONT_STOP(mc))
	do_watchdog_reset(mc);
    else
	mc->watchdog_running = 0;
}

static void
handle_reset_watchdog_timer(lmc_data_t    *mc,
			    msg_t         *msg,
			    unsigned char *rdata,
			    unsigned int  *rdata_len)
{
    if (!mc->watchdog_timer) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->watchdog_initialized) {
	rdata[0] = 0x80;
	*rdata_len = 1;
	return;
    }

    do_watchdog_reset(mc);
}

static void
handle_get_channel_info(lmc_data_t    *mc,
			msg_t         *msg,
			unsigned char *rdata,
			unsigned int  *rdata_len)
{
    unsigned char lchan;
    unsigned char medium_type;
    unsigned char protocol_type;
    unsigned char session_support;
    unsigned char active_sessions;

    if (msg->len < 1) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    lchan = msg->data[0];
    if (lchan == 0xe)
	lchan = msg->channel;
    else if (lchan >= IPMI_MAX_CHANNELS) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->channels[lchan]) {
	if (lchan == 0) {
	    /* The IPMB channel is always there. */
	    medium_type = IPMI_CHANNEL_MEDIUM_IPMB;
	    protocol_type = IPMI_CHANNEL_PROTOCOL_IPMB;
	    session_support = IPMI_CHANNEL_SESSION_LESS;
	    active_sessions = 0;
	} else {
	    rdata[0] = IPMI_NOT_PRESENT_CC;
	    *rdata_len = 1;
	    return;
	}
    } else {
	medium_type = mc->channels[lchan]->medium_type;
	protocol_type = mc->channels[lchan]->protocol_type;
	session_support = mc->channels[lchan]->session_support;
	active_sessions = mc->channels[lchan]->active_sessions;
    }

    rdata[0] = 0;
    rdata[1] = lchan;
    rdata[2] = medium_type;
    rdata[3] = protocol_type;
    rdata[4] = (session_support << 6) | active_sessions;
    rdata[5] = 0xf2;
    rdata[6] = 0x1b;
    rdata[7] = 0x00;
    rdata[8] = 0x00;
    rdata[9] = 0x00;
    *rdata_len = 10;
}

static void
handle_get_channel_access(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len)
{
    unsigned char lchan;
    channel_t *chan;
    uint8_t   upd;

    if (msg->len < 2) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    lchan = msg->data[0];
    if (lchan == 0xe)
	lchan = msg->channel;
    else if (lchan >= IPMI_MAX_CHANNELS) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->channels[lchan]) {
	if (lchan == 0) {
	    rdata[0] = 0;
	    rdata[1] = 0;
	    rdata[2] = 0;
	    *rdata_len = 3;
	    return;
	}
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }
    chan = mc->channels[lchan];

    upd = (msg->data[1] >> 6) & 0x3;

    rdata[0] = 0;
    if (upd == 2) {
	rdata[1] = ((chan->PEF_alerting << 5) | 0x2);
	rdata[2] = chan->privilege_limit;
	*rdata_len = 3;
    } else if (upd == 1) {
	rdata[1] = ((chan->PEF_alerting_nonv << 5) | 0x2);
	rdata[2] = chan->privilege_limit_nonv;
	*rdata_len = 3;
    } else {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }
}

static void
handle_set_global_enables(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len)
{
    unsigned char old_evint = IPMI_MC_EVBUF_FULL_INT_ENABLED(mc);
    unsigned char old_int = IPMI_MC_MSG_INTS_ON(mc);
    channel_t *bchan;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    rdata[0] = 0;
    *rdata_len = 1;

    mc->global_enables = msg->data[0];
    bchan = mc->channels[15];
    if (!bchan || !bchan->set_atn)
	return;

    if (!old_int && IPMI_MC_MSG_INTS_ON(mc) && HW_OP_CAN_IRQ(bchan))
	bchan->hw_op(bchan, HW_OP_IRQ_ENABLE);
    else if (old_int && !IPMI_MC_MSG_INTS_ON(mc) && HW_OP_CAN_IRQ(bchan))
	bchan->hw_op(bchan, HW_OP_IRQ_DISABLE);

    if ((!old_evint && IPMI_MC_EVBUF_FULL_INT_ENABLED(mc) && mc->ev_in_q) ||
	(old_int && !IPMI_MC_MSG_INTS_ON(mc) && mc->recv_q_tail))
	bchan->set_atn(bchan, 1, IPMI_MC_EVBUF_FULL_INT_ENABLED(mc));
}

static void
handle_get_global_enables(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len)
{
    rdata[0] = 0;
    rdata[1] = mc->global_enables;
    *rdata_len = 2;
}

static void
cleanup_ascii_16(uint8_t *c)
{
    int i;

    i = 0;
    while ((i < 16) && (*c != 0)) {
	c++;
	i++;
    }
    while (i < 16) {
	*c = 0;
	c++;
	i++;
    }
}

static void
set_users_changed(lmc_data_t *mc)
{
    mc->users_changed = 1;
    mc->emu->users_changed = 1;
}

static void
handle_set_user_access(lmc_data_t    *mc,
		       msg_t         *msg,
		       unsigned char *rdata,
		       unsigned int  *rdata_len)
{
    uint8_t user;
    uint8_t priv;
    uint8_t newv;
    int     changed = 0;

    if (msg->len < 3) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->sysinfo) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    user = msg->data[1] & 0x3f;
    if (user == 0) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    priv = msg->data[2] & 0xf;
    /* Allow privilege level F as the "no access" privilege */
    if (((priv == 0) || (priv > 4)) && (priv != 0xf)) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (msg->data[0] & 0x80) {
	newv = (msg->data[0] >> 4) & 1;
	if (newv != mc->users[user].valid) {
	    mc->users[user].valid = newv;
	    changed = 1;
	}
	newv = (msg->data[0] >> 5) & 1;
	if (newv != mc->users[user].link_auth) {
	    mc->users[user].link_auth = newv;
	    changed = 1;
	}
	newv = (msg->data[0] >> 6) & 1;
	if (newv != mc->users[user].cb_only) {
	    mc->users[user].cb_only = newv;
	    changed = 1;
	}
    }

    if (priv != mc->users[user].privilege) {
	mc->users[user].privilege = priv;
	changed = 1;
    }

    if (msg->len >= 4) {
	/* Got the session limit byte. */
	newv = msg->data[3] & 0xf;
	if (newv != mc->users[user].max_sessions) {
	    mc->users[user].max_sessions = newv;
	    changed = 1;
	}
    }

    if (changed)
	set_users_changed(mc);

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_user_access(lmc_data_t    *mc,
		       msg_t         *msg,
		       unsigned char *rdata,
		       unsigned int  *rdata_len)
{
    int     i;
    uint8_t user;

    if (msg->len < 2) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->sysinfo) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    user = msg->data[1] & 0x3f;
    if (user == 0) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = MAX_USERS;

    /* Number of enabled users. */
    rdata[2] = 0;
    for (i=1; i<=MAX_USERS; i++) {
	if (mc->users[i].valid)
	    rdata[2]++;
    }

    /* Only fixed user name is user 1. */
    rdata[3] = mc->users[1].valid;

    rdata[4] = ((mc->users[user].valid << 4)
		| (mc->users[user].link_auth << 5)
		| (mc->users[user].cb_only << 6)
		| mc->users[user].privilege);
    *rdata_len = 5;
}

static void
handle_set_user_name(lmc_data_t    *mc,
		     msg_t         *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len)
{
    uint8_t user;

    if (msg->len < 17) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->sysinfo) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    user = msg->data[0] & 0x3f;
    if (user <= 1) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    memcpy(mc->users[user].username, msg->data+1, 16);
    cleanup_ascii_16(mc->users[user].username);

    set_users_changed(mc);

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_user_name(lmc_data_t    *mc,
		     msg_t         *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len)
{
    uint8_t user;

    if (msg->len < 1) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->sysinfo) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    user = msg->data[0] & 0x3f;
    if ((user <= 1) || (user > MAX_USERS)) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    memcpy(rdata+1, mc->users[user].username, 16);
    *rdata_len = 17;
}

static void
handle_set_user_password(lmc_data_t    *mc,
			 msg_t         *msg,
			 unsigned char *rdata,
			 unsigned int  *rdata_len)
{
    uint8_t user;
    uint8_t op;

    if (msg->len < 2) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->sysinfo) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    user = msg->data[0] & 0x3f;
    if (user == 0) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    op = msg->data[1] & 0x3;
    if (op == 0) {
	mc->users[user].valid = 0;
    } else if (op == 1) {
	mc->users[user].valid = 1;
    } else {
	if (msg->len < 18) {
	    rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	    *rdata_len = 1;
	    return;
	}
	if (op == 2) {
	    memcpy(mc->users[user].pw, msg->data+2, 16);
	} else {
	    /* Nothing to do for test password, we accept anything. */
	}
    }

    set_users_changed(mc);

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_set_channel_access(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len)
{
    unsigned char lchan;
    channel_t *chan;

    if (msg->len < 3) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    lchan = msg->data[0];
    if (lchan == 0xe)
	lchan = msg->channel;
    else if (lchan >= IPMI_MAX_CHANNELS) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->sysinfo || !mc->channels[lchan]) {
	rdata[0] = IPMI_NOT_PRESENT_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->sysinfo || !mc->channels[lchan]) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }
    chan = mc->channels[lchan];

    if (!chan->set_chan_access) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    chan->set_chan_access(chan, msg, rdata, rdata_len);
}

static void
handle_read_event_msg_buffer(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len)
{
    channel_t *chan = mc->channels[15];

    if (!mc->sysinfo) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->ev_in_q) {
	rdata[0] = 0x80;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    memcpy(rdata + 1, mc->evq, 16);
    *rdata_len = 17;
    mc->ev_in_q = 0;
    mc->msg_flags &= ~IPMI_MC_MSG_FLAG_EVT_BUF_FULL;
    if (chan->set_atn)
	chan->set_atn(chan, 0, IPMI_MC_EVBUF_FULL_INT_ENABLED(mc));
}

static void
handle_get_msg_flags(lmc_data_t    *mc,
		     msg_t         *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len)
{
    rdata[0] = 0;
    rdata[1] = mc->msg_flags;
    *rdata_len = 2;
}

static void
handle_clear_msg_flags(lmc_data_t    *mc,
		       msg_t         *msg,
		       unsigned char *rdata,
		       unsigned int  *rdata_len)
{
    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    mc->msg_flags &= ~msg->data[0];
    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_msg(lmc_data_t    *mc,
	       msg_t         *msg,
	       unsigned char *rdata,
	       unsigned int  *rdata_len)
{
    msg_t *qmsg;

    if (!mc->sysinfo) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    qmsg = mc->recv_q_head;
    if (!qmsg) {
	rdata[0] = 0x80;
	*rdata_len = 0;
	return;
    }

    if (qmsg->len + 2 > *rdata_len) {
	rdata[0] = IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC;
	*rdata_len = 1;
	return;
    }

    mc->recv_q_head = qmsg->next;
    if (!qmsg->next) {
	channel_t *bchan = mc->channels[15];
	mc->recv_q_tail = NULL;
	if (bchan->set_atn)
	    bchan->set_atn(bchan, 0, IPMI_MC_MSG_INTS_ON(mc));
    }

    rdata[0] = 0;
    rdata[1] = 0; /* Always channel 0 for now, FIXME - privilege level? */
    /*
     * Note that we chop off the first byte because the destination
     * address is not in the get message response.
     */
    memcpy(rdata + 2, qmsg->data + 1, qmsg->len + 1);
    *rdata_len = qmsg->len - 1 + 2;
    free(qmsg);
}

static void
handle_get_payload_activation_status(lmc_data_t    *mc,
				     msg_t         *msg,
				     unsigned char *rdata,
				     unsigned int  *rdata_len)
{
    channel_t *channel = mc->channels[msg->channel];

    if (!mc->sol.configured || !channel->set_associated_mc) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    if (msg->len < 1) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    *rdata_len = 4;

    if ((msg->data[0] & 0xf) == IPMI_RMCPP_PAYLOAD_TYPE_SOL) {
	rdata[1] = 1; /* Only one SOL session at a time */
	rdata[2] = mc->sol.active;
	rdata[3] = 0;
    } else {
	rdata[1] = 0;
	rdata[2] = 0;
	rdata[3] = 0;
    }
}

static void
handle_get_payload_instance_info(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len)
{
    channel_t *channel = mc->channels[msg->channel];

    if (msg->len < 2) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->sol.configured || !channel->set_associated_mc) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    if ((msg->data[0] & 0xf) != IPMI_RMCPP_PAYLOAD_TYPE_SOL) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (msg->data[1] != 1) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    ipmi_set_uint32(rdata + 1, mc->sol.session_id);
    rdata[5] = 1;
    memset(rdata + 6, 0, 7);
    *rdata_len = 13;
}

static void
handle_get_channel_payload_support(lmc_data_t    *mc,
				   msg_t         *msg,
				   unsigned char *rdata,
				   unsigned int  *rdata_len)
{
    channel_t *channel;

    if (msg->len < 1) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    channel = mc->channels[msg->data[0] & 0xf];

    rdata[0] = 0;
    rdata[1] = ((1 << 1) |
		((mc->sol.configured && channel->set_associated_mc) << 2));
    memset(rdata + 2, 0, 7);
    *rdata_len = 9;
}

static void
handle_activate_payload(lmc_data_t    *mc,
			msg_t         *msg,
			unsigned char *rdata,
			unsigned int  *rdata_len)
{
    channel_t *channel = msg->orig_channel;

    if (!mc->sol.configured || !channel->set_associated_mc) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    if (msg->len < 6) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if ((msg->data[0] & 0xf) != IPMI_RMCPP_PAYLOAD_TYPE_SOL) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if ((msg->data[0] & 0xf) != IPMI_RMCPP_PAYLOAD_TYPE_SOL) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    ipmi_sol_activate(mc, channel, msg, rdata, rdata_len);
}

static void
handle_deactivate_payload(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len)
{
    channel_t *channel = msg->orig_channel;

    if (!mc->sol.configured || !channel->set_associated_mc) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    if (msg->len < 6) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if ((msg->data[0] & 0xf) != IPMI_RMCPP_PAYLOAD_TYPE_SOL) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if ((msg->data[0] & 0xf) != IPMI_RMCPP_PAYLOAD_TYPE_SOL) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    ipmi_sol_deactivate(mc, channel, msg, rdata, rdata_len);
}

static cmd_handler_f app_netfn_handlers[256] = {
    [IPMI_GET_DEVICE_ID_CMD] = handle_get_device_id,
    [IPMI_GET_WATCHDOG_TIMER_CMD] = handle_get_watchdog_timer,
    [IPMI_SET_WATCHDOG_TIMER_CMD] = handle_set_watchdog_timer,
    [IPMI_RESET_WATCHDOG_TIMER_CMD] = handle_reset_watchdog_timer,
    [IPMI_GET_CHANNEL_INFO_CMD] = handle_get_channel_info,
    [IPMI_GET_CHANNEL_ACCESS_CMD] = handle_get_channel_access,
    [IPMI_SET_BMC_GLOBAL_ENABLES_CMD] = handle_set_global_enables,
    [IPMI_GET_BMC_GLOBAL_ENABLES_CMD] = handle_get_global_enables,
    [IPMI_SET_USER_ACCESS_CMD] = handle_set_user_access,
    [IPMI_GET_USER_ACCESS_CMD] = handle_get_user_access,
    [IPMI_SET_USER_NAME_CMD] = handle_set_user_name,
    [IPMI_GET_USER_NAME_CMD] = handle_get_user_name,
    [IPMI_SET_USER_PASSWORD_CMD] = handle_set_user_password,
    [IPMI_SET_CHANNEL_ACCESS_CMD] = handle_set_channel_access,
    [IPMI_READ_EVENT_MSG_BUFFER_CMD] = handle_read_event_msg_buffer,
    [IPMI_GET_MSG_CMD] = handle_get_msg,
    [IPMI_GET_MSG_FLAGS_CMD] = handle_get_msg_flags,
    [IPMI_CLEAR_MSG_FLAGS_CMD] = handle_clear_msg_flags,
    [IPMI_GET_PAYLOAD_ACTIVATION_STATUS_CMD] = handle_get_payload_activation_status,
    [IPMI_GET_PAYLOAD_INSTANCE_INFO_CMD] = handle_get_payload_instance_info,
    [IPMI_GET_CHANNEL_PAYLOAD_SUPPORT_CMD] = handle_get_channel_payload_support,
    [IPMI_ACTIVATE_PAYLOAD_CMD] = handle_activate_payload,
    [IPMI_DEACTIVATE_PAYLOAD_CMD] = handle_deactivate_payload
};

static void
handle_get_chassis_capabilities(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len)
{
    rdata[0] = 0;
    rdata[1] = 0;
    rdata[2] = mc->sysinfo->bmc_ipmb;
    rdata[3] = mc->sysinfo->bmc_ipmb;
    rdata[4] = mc->sysinfo->bmc_ipmb;
    rdata[5] = mc->sysinfo->bmc_ipmb;
}

static extcmd_map_t boot_map[] = {
    { 0, "none" },
    { 1, "pxe" },
    { 2, "default" },
    { 0, NULL }
};

/* Matches the CHASSIS_CONTROL defines. */
static extcmd_info_t chassis_prog[] = {
    { "power", extcmd_int, NULL, 0 },
    { "reset", extcmd_int, NULL, 0 },
    { "boot", extcmd_uchar, boot_map, 0 },
};

static void
handle_get_chassis_status(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len)
{
    rdata[0] = 0;
    if (mc->chassis_control_get_func) {
	unsigned char val;
	int rv;
	rv = mc->chassis_control_get_func(mc, CHASSIS_CONTROL_POWER, &val,
					  mc->chassis_control_cb_data);
	if (rv) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
	rdata[1] = val;
    } else if (mc->chassis_control_prog) {
	int val;
	if (extcmd_getvals(mc->sysinfo, &val, mc->chassis_control_prog,
			   &chassis_prog[CHASSIS_CONTROL_POWER], 1)) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
	rdata[1] = val;
    } else {
	rdata[1] = mc->startcmd.vmpid != 0;
    }
    rdata[2] = 0;
    rdata[3] = 0;
    *rdata_len = 4;
}

static void
handle_chassis_control(lmc_data_t    *mc,
		       msg_t         *msg,
		       unsigned char *rdata,
		       unsigned int  *rdata_len)
{
    if (msg->len < 1) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    *rdata_len = 1;

    switch(msg->data[0] & 0xf) {
    case 0: /* power down */
	if (mc->chassis_control_set_func) {
	    int rv;
	    rv = mc->chassis_control_set_func(mc, CHASSIS_CONTROL_POWER, 0,
					      mc->chassis_control_cb_data);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (mc->chassis_control_prog) {
	    int val = 0;
	    if (extcmd_setvals(mc->sysinfo, &val, mc->chassis_control_prog,
			       &chassis_prog[CHASSIS_CONTROL_POWER], NULL, 1)) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (HW_OP_CAN_POWER(mc->channels[15]))
	    mc->channels[15]->hw_op(mc->channels[15], HW_OP_POWEROFF);
	else
	    goto no_support;
	break;

    case 1: /* power up */
	if (mc->chassis_control_set_func) {
	    int rv;
	    rv = mc->chassis_control_set_func(mc, CHASSIS_CONTROL_POWER, 1,
					      mc->chassis_control_cb_data);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (mc->chassis_control_prog) {
	    int val = 1;
	    if (extcmd_setvals(mc->sysinfo, &val, mc->chassis_control_prog,
			       &chassis_prog[CHASSIS_CONTROL_POWER], NULL, 1)) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (HW_OP_CAN_POWER(mc->channels[15]))
	    mc->channels[15]->hw_op(mc->channels[15], HW_OP_POWERON);
	else
	    goto no_support;
	break;

    case 3: /* hard reset */
	if (mc->chassis_control_set_func) {
	    int rv;
	    rv = mc->chassis_control_set_func(mc, CHASSIS_CONTROL_RESET, 1,
					      mc->chassis_control_cb_data);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (mc->chassis_control_prog) {
	    int val = 1;
	    if (extcmd_setvals(mc->sysinfo, &val, mc->chassis_control_prog,
			       &chassis_prog[CHASSIS_CONTROL_RESET], NULL, 1)) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (HW_OP_CAN_RESET(mc->channels[15]))
	    mc->channels[15]->hw_op(mc->channels[15], HW_OP_RESET);
	else
	    goto no_support;
	break;

    case 2: /* power cycle */
    case 4: /* pulse diag interrupt */
    case 5: /* initiate soft-shutdown via overtemp */
    no_support:
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }
}

static void
set_system_boot_options(lmc_data_t    *mc,
			msg_t         *msg,
			unsigned char *rdata,
			unsigned int  *rdata_len)
{
    unsigned char val;

    if (msg->len < 1) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    *rdata_len = 1;

    switch (msg->data[0] & 0x3f) {
    case 1:
	if (msg->len < 2) {
	    rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	    *rdata_len = 1;
	    return;
	}
	switch (msg->data[2] & 0x3) {
	case 0:
	case 1:
	    /* Just ignore this for now. */
	    break;

	default:
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    break;
	}
	break;

    case 5: /* Boot flags */
	if (msg->len < 6) {
	    rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	    *rdata_len = 1;
	    return;
	}
	val = (msg->data[2] >> 2) & 0xf;
	
	if (mc->chassis_control_set_func) {
	    int rv;
	    rv = mc->chassis_control_set_func(mc, CHASSIS_CONTROL_BOOT, val,
					      mc->chassis_control_cb_data);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (mc->chassis_control_prog) {
	    if (extcmd_setvals(mc->sysinfo, &val, mc->chassis_control_prog,
			       &chassis_prog[CHASSIS_CONTROL_BOOT], NULL, 1)) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	}
	break;

    default:
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	break;
    }
}

static void
get_system_boot_options(lmc_data_t    *mc,
			msg_t         *msg,
			unsigned char *rdata,
			unsigned int  *rdata_len)
{
    unsigned char val;

    if (msg->len < 3) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = 1;
    rdata[2] = msg->data[0] & 0x3f;
    *rdata_len = 3;

    switch (msg->data[0] & 0x3f) {
    case 1:
	/* Dummy this out for now */
	rdata[3] = 0;
	*rdata_len = 4;
	break;

    case 5: /* Boot flags */
	if (mc->chassis_control_set_func) {
	    int rv;
	    rv = mc->chassis_control_get_func(mc, CHASSIS_CONTROL_BOOT, &val,
					      mc->chassis_control_cb_data);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (mc->chassis_control_prog) {
	    if (extcmd_getvals(mc->sysinfo, &val, mc->chassis_control_prog,
			       &chassis_prog[CHASSIS_CONTROL_BOOT], 1)) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}

	rdata[3] = 0;
	rdata[4] = val << 2;
	rdata[5] = 0;
	rdata[6] = 0;
	rdata[7] = 0;
	*rdata_len = 8;
	break;

    default:
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	break;
    }
}

static int
check_chassis_capable(lmc_data_t *mc)
{
    return (mc->device_support & IPMI_DEVID_CHASSIS_DEVICE);
}

static cmd_handler_f chassis_netfn_handlers[256] = {
    [IPMI_GET_CHASSIS_CAPABILITIES_CMD] = handle_get_chassis_capabilities,
    [IPMI_GET_CHASSIS_STATUS_CMD] = handle_get_chassis_status,
    [IPMI_CHASSIS_CONTROL_CMD] = handle_chassis_control,
    [IPMI_SET_SYSTEM_BOOT_OPTIONS_CMD] = set_system_boot_options,
    [IPMI_GET_SYSTEM_BOOT_OPTIONS_CMD] = get_system_boot_options
};

static void
handle_ipmi_set_lan_config_parms(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len)
{
    unsigned char lchan;
    channel_t *chan;

    if (msg->len < 3) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    lchan = msg->data[0];
    if (lchan == 0xe)
	lchan = msg->channel;
    else if (lchan >= IPMI_MAX_CHANNELS) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->channels[lchan]) {
	rdata[0] = IPMI_NOT_PRESENT_CC;
	*rdata_len = 1;
	return;
    }
    chan = mc->channels[lchan];

    if (!chan->set_lan_parms) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    chan->set_lan_parms(chan, msg, rdata, rdata_len);
}

static void
handle_ipmi_get_lan_config_parms(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len)
{
    unsigned char lchan;
    channel_t *chan;

    if (msg->len < 4) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    lchan = msg->data[0];
    if (lchan == 0xe)
	lchan = msg->channel;
    else if (lchan >= IPMI_MAX_CHANNELS) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->channels[lchan]) {
	rdata[0] = IPMI_NOT_PRESENT_CC;
	*rdata_len = 1;
	return;
    }

    chan = mc->channels[lchan];

    if (!chan->get_lan_parms) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    chan->get_lan_parms(chan, msg, rdata, rdata_len);
}

static void
handle_set_sol_config_parms(lmc_data_t    *mc,
			    msg_t         *msg,
			    unsigned char *rdata,
			    unsigned int  *rdata_len)
{
    unsigned char err = 0;
    unsigned char val;
    int write_config = 0;
    ipmi_sol_t *sol = &mc->sol;

    if (!mc->sol.configured) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (msg->len < 3) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    /*
     * There is a channel in this message, but as far as I can tell,
     * it is completely without point.  The data is generic to the
     * management controller.  So just ignore it.
     */

    switch (msg->data[1]) {
    case 0:
	switch (msg->data[2] & 0x3) {
	case 0:
	    if (sol->set_in_progress) {
		/* Rollback */
		memcpy(&mc->sol.solparm, &mc->sol.solparm_rollback,
		       sizeof(solparm_t));
		write_config = 1;
	    }
	    break;

	case 1:
	    if (sol->set_in_progress)
		err = 0x81; /* Another user is writing. */
	    else {
		/* Save rollback data */
		memcpy(&mc->sol.solparm_rollback, &mc->sol.solparm,
		       sizeof(solparm_t));
		sol->set_in_progress = 1;
	    }
	    break;

	case 2:
	    sol->set_in_progress = 0;
	    break;

	case 3:
	    err = IPMI_INVALID_DATA_FIELD_CC;
	}
	break;

    case 1:
	sol->solparm.enabled = msg->data[2] & 1;
	write_config = 1;
	break;

    case 5:
	val = msg->data[2] & 0xf;
	if ((val < 6) || (val > 0xa)) {
	    err = IPMI_INVALID_DATA_FIELD_CC;
	} else {
	    sol->solparm.bitrate_nonv = val;
	    write_config = 1;
	}
	break;

    case 6:
	val = msg->data[2] & 0xf;
	if ((val < 6) || (val > 0xa)) {
	    err = IPMI_INVALID_DATA_FIELD_CC;
	} else {
	    sol->solparm.bitrate = val;
	    if (sol->update_bitrate)
		sol->update_bitrate(mc);
	}
	break;

    default:
	err = 0x80; /* Parm not supported */
    }

    if (write_config)
	write_sol_config(mc);

    rdata[0] = err;
    *rdata_len = 1;
}

static void
handle_get_sol_config_parms(lmc_data_t    *mc,
			    msg_t         *msg,
			    unsigned char *rdata,
			    unsigned int  *rdata_len)
{
    ipmi_sol_t *sol = &mc->sol;
    unsigned char databyte = 0;

    if (!mc->sol.configured) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (msg->len < 4) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    /*
     * There is a channel in this message, but as far as I can tell,
     * it is completely without point.  The data is generic to the
     * management controller.  So just ignore it.
     */

    switch (msg->data[1]) {
    case 0:
	databyte = sol->set_in_progress;
	break;

    case 1:
	databyte = sol->solparm.enabled;
	break;

    case 5:
	databyte = sol->solparm.bitrate_nonv;
	break;

    case 6:
	databyte = sol->solparm.bitrate;
	break;

    default:
	rdata[0] = 0x80; /* Parm not supported */
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = 0x11;
    rdata[2] = databyte;
    *rdata_len = 3;
}

static cmd_handler_f transport_netfn_handlers[256] = {
    [IPMI_SET_LAN_CONFIG_PARMS_CMD] = handle_ipmi_set_lan_config_parms,
    [IPMI_GET_LAN_CONFIG_PARMS_CMD] = handle_ipmi_get_lan_config_parms,
    [IPMI_SET_SOL_CONFIGURATION_PARAMETERS] = handle_set_sol_config_parms,
    [IPMI_GET_SOL_CONFIGURATION_PARAMETERS] = handle_get_sol_config_parms
};

static void
handle_get_event_receiver(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len)
{
    if (!(mc->device_support & IPMI_DEVID_IPMB_EVENT_GEN)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    rdata[0] = 0;
    rdata[1] = mc->event_receiver;
    rdata[2] = mc->event_receiver_lun & 0x3;
    *rdata_len = 3;
}

static void
handle_set_event_receiver(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len)
{
    if (!(mc->device_support & IPMI_DEVID_IPMB_EVENT_GEN)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    mc->event_receiver = msg->data[0] & 0xfe;
    mc->event_receiver_lun = msg->data[1] & 0x3;

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_device_sdr_info(lmc_data_t    *mc,
			   msg_t         *msg,
			   unsigned char *rdata,
			   unsigned int  *rdata_len)
{
    if (! mc->has_device_sdrs) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    rdata[0] = 0;
    rdata[1] = mc->num_sensors_per_lun[msg->rs_lun];
    rdata[2] = ((mc->dynamic_sensor_population << 7)
		| (mc->lun_has_sensors[3] << 3)
		| (mc->lun_has_sensors[2] << 2)
		| (mc->lun_has_sensors[1] << 1)
		| (mc->lun_has_sensors[0] << 0));
    if (!mc->dynamic_sensor_population) {
	*rdata_len = 3;
	return;
    }

    ipmi_set_uint32(rdata+3, mc->sensor_population_change_time);
    *rdata_len = 7;
}

static void
handle_reserve_device_sdr_repository(lmc_data_t    *mc,
				     msg_t         *msg,
				     unsigned char *rdata,
				     unsigned int  *rdata_len)
{
    if (!(mc->has_device_sdrs)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (!(mc->dynamic_sensor_population)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    mc->device_sdrs[msg->rs_lun].reservation++;
    if (mc->device_sdrs[msg->rs_lun].reservation == 0)
	mc->device_sdrs[msg->rs_lun].reservation++;

    rdata[0] = 0;
    ipmi_set_uint16(rdata+1, mc->device_sdrs[msg->rs_lun].reservation);
    *rdata_len = 3;
}

static void
handle_get_device_sdr(lmc_data_t    *mc,
		      msg_t         *msg,
		      unsigned char *rdata,
		      unsigned int  *rdata_len)
{
    uint16_t     record_id;
    unsigned int offset;
    unsigned int count;
    sdr_t        *entry;

    if (!(mc->has_device_sdrs)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 6, rdata, rdata_len))
	return;

    if (mc->dynamic_sensor_population) {
	uint16_t reservation = ipmi_get_uint16(msg->data+0);

	if ((reservation != 0)
	    && (reservation != mc->device_sdrs[msg->rs_lun].reservation))
	{
	    rdata[0] = IPMI_INVALID_RESERVATION_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    record_id = ipmi_get_uint16(msg->data+2);
    offset = msg->data[4];
    count = msg->data[5];

    if (record_id == 0) {
	entry = mc->device_sdrs[msg->rs_lun].sdrs;
    } else if (record_id == 0xffff) {
	entry = mc->device_sdrs[msg->rs_lun].sdrs;
	if (entry) {
	    while (entry->next) {
		entry = entry->next;
	    }
	}
    } else {
	entry = find_sdr_by_recid(mc, &mc->device_sdrs[msg->rs_lun],
				  record_id, NULL);
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
handle_set_sensor_hysteresis(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len)
{
    int      sens_num;
    sensor_t *sensor;

    if (check_msg_length(msg, 4, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if (sensor->hysteresis_support != IPMI_HYSTERESIS_SUPPORT_SETTABLE) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    sensor->positive_hysteresis = msg->data[2];
    sensor->negative_hysteresis = msg->data[3];

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_sensor_hysteresis(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len)
{
    int      sens_num;
    sensor_t *sensor;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if ((sensor->hysteresis_support != IPMI_HYSTERESIS_SUPPORT_SETTABLE)
	&& (sensor->hysteresis_support != IPMI_HYSTERESIS_SUPPORT_READABLE))
    {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = sensor->positive_hysteresis;
    rdata[2] = sensor->negative_hysteresis;
    *rdata_len = 3;
}

static void
do_event(lmc_data_t    *mc,
	 sensor_t      *sensor,
	 int           gen_event,
	 unsigned char direction,
	 unsigned char byte1,
	 unsigned char byte2,
	 unsigned char byte3)
{
    lmc_data_t    *dest_mc;
    unsigned char data[13];
    int           rv;

    if ((mc->event_receiver == 0)
	|| (!sensor->events_enabled)
	|| (!gen_event))
	return;

    rv = ipmi_emu_get_mc_by_addr(mc->emu, mc->event_receiver, &dest_mc);
    if (rv)
	return;

    /* Timestamp is ignored. */
    data[0] = 0;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;

    data[4] = mc->ipmb;
    data[5] = sensor->lun;
    data[6] = 0x04; /* Event message revision for IPMI 1.5. */
    data[7] = sensor->sensor_type;
    data[8] = sensor->num;
    data[9] = (direction << 7) | sensor->event_reading_code;
    data[10] = byte1;
    data[11] = byte2;
    data[12] = byte3;

    mc_new_event(dest_mc, 0x02, data);
}

static void
set_bit(lmc_data_t *mc, sensor_t *sensor, unsigned char bit,
	unsigned char value,
	unsigned char evd1, unsigned char evd2, unsigned char evd3,
	int gen_event)
{
    if (value != sensor->event_status[bit]) {
	/* The bit value has changed. */
	sensor->event_status[bit] = value;
	if (value && sensor->event_enabled[0][bit]) {
	    do_event(mc, sensor, gen_event, IPMI_ASSERTION,
		     0x00 | bit, 0, 0);
	} else if (!value && sensor->event_enabled[1][bit]) {
	    do_event(mc, sensor, gen_event, IPMI_DEASSERTION,
		     0x00 | bit, 0, 0);
	}
    }
}

static void
check_thresholds(lmc_data_t *mc, sensor_t *sensor, int gen_event)
{
    int i;
    int bits_to_set = 0;
    int bits_to_clear = 0;

    for (i=0; i<3; i++) {
	if (sensor->threshold_supported[i])
	{
	    if (sensor->value <= sensor->thresholds[i])
		bits_to_set |= (1 << i);
	    else if ((sensor->value - sensor->negative_hysteresis)
		     > sensor->thresholds[i])
		bits_to_clear |= (1 << i);
	}
    }
    for (; i<6; i++) {
	if (sensor->threshold_supported[i]) {
	    if (sensor->value >= sensor->thresholds[i])
		bits_to_set |= (1 << i);
	    else if ((sensor->value + sensor->positive_hysteresis)
		     < sensor->thresholds[i])
		bits_to_clear |= (1 << i);
	}
    }

    /* We don't support lower assertions for high thresholds or higher
       assertions for low thresholds because that's just stupid. */
    for (i=0; i<3; i++) {
	if (((bits_to_set >> i) & 1) && !sensor->event_status[i]) {
	    /* This bit was not set, but we need to set it. */
	    sensor->event_status[i] = 1;
	    if (sensor->event_enabled[0][i*2]) {
		do_event(mc, sensor, gen_event, IPMI_ASSERTION,
			 0x50 | (i*2), sensor->value, sensor->thresholds[i]);
	    }
	} else if (((bits_to_clear >> i) & 1) && sensor->event_status[i]) {
	    /* This bit was not clear, but we need to clear it. */
	    sensor->event_status[i] = 0;
	    if (sensor->event_enabled[1][i*2]) {
		do_event(mc, sensor, gen_event, IPMI_DEASSERTION,
			 0x50 | (i*2), sensor->value, sensor->thresholds[i]);
	    }
	}
    }
    for (; i<6; i++) {
	if (((bits_to_set >> i) & 1) && !sensor->event_status[i]) {
	    /* This bit was not set, but we need to set it. */
	    sensor->event_status[i] = 1;
	    if (sensor->event_enabled[0][i*2+1]) {
		do_event(mc, sensor, gen_event, IPMI_ASSERTION,
			 0x50 | (i*2+1), sensor->value, sensor->thresholds[i]);
	    }
	} else if (((bits_to_clear >> i) & 1) && sensor->event_status[i]) {
	    /* This bit was not clear, but we need to clear it. */
	    sensor->event_status[i] = 0;
	    if (sensor->event_enabled[1][i*2+1]) {
		do_event(mc, sensor, gen_event, IPMI_DEASSERTION,
			 0x50 | (i*2+1), sensor->value, sensor->thresholds[i]);
	    }
	}
    }
}

static void
handle_set_sensor_thresholds(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len)
{
    int      sens_num;
    sensor_t *sensor;
    int      i;

    if (check_msg_length(msg, 8, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if ((sensor->event_reading_code != IPMI_EVENT_READING_TYPE_THRESHOLD)
	|| (sensor->threshold_support != IPMI_THRESHOLD_ACCESS_SUPPORT_SETTABLE))
    {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    for (i=0; i<6; i++) {
	if ((msg->data[1] & (1 << i)) && (!sensor->threshold_supported[i])) {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    for (i=0; i<6; i++) {
	if (msg->data[1] & (1 << i)) {
	    sensor->thresholds[i] = msg->data[i+2];
	}
    }

    check_thresholds(mc, sensor, 1);

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_sensor_thresholds(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len)
{
    int      sens_num;
    sensor_t *sensor;
    int      i;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if ((sensor->event_reading_code != IPMI_EVENT_READING_TYPE_THRESHOLD)
	|| ((sensor->threshold_support != IPMI_THRESHOLD_ACCESS_SUPPORT_SETTABLE)
	    && (sensor->threshold_support != IPMI_THRESHOLD_ACCESS_SUPPORT_READABLE)))
    {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = 0;
    for (i=0; i<6; i++) {
	if (sensor->threshold_supported[i]) {
	    rdata[1] |= 1 << i;
	    rdata[2+i] = sensor->thresholds[i];
	} else
	    rdata[2+i] = 0;
    }
    *rdata_len = 8;
}

static void
handle_set_sensor_event_enable(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len)
{
    int           sens_num;
    sensor_t      *sensor;
    unsigned int  i;
    int           j, e;
    unsigned char op;

    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if ((sensor->event_support == IPMI_EVENT_SUPPORT_NONE)
	|| (sensor->event_support == IPMI_EVENT_SUPPORT_GLOBAL_ENABLE))
    {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    op = (msg->data[1] >> 4) & 0x3;
    if (sensor->event_support == IPMI_EVENT_SUPPORT_ENTIRE_SENSOR) {
	if (op != 0) {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    if (op == 3) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor->events_enabled = (msg->data[1] >> 7) & 1;
    sensor->scanning_enabled = (msg->data[1] >> 6) & 1;
	
    if (op == 0)
	return;
    else if (op == 1)
	/* Enable selected events */
	op = 1;
    else
	/* Disable selected events */
	op = 0;

    e = 0;
    for (i=2; i<=3; i++) {
	if (msg->len <= i)
	    break;
	for (j=0; j<8; j++, e++) {
	    if (e >= 15)
		break;
	    if ((msg->data[i] >> j) & 1)
		sensor->event_enabled[0][e] = op;
	}
    }
    e = 0;
    for (i=4; i<=5; i++) {
	if (msg->len <= i)
	    break;
	for (j=0; j<8; j++, e++) {
	    if (e >= 15)
		break;
	    if ((msg->data[i] >> j) & 1)
		sensor->event_enabled[1][e] = op;
	}
    }

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_sensor_event_enable(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len)
{
    int           sens_num;
    sensor_t      *sensor;
    int           i, j, e;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if ((sensor->event_support == IPMI_EVENT_SUPPORT_NONE)
	|| (sensor->event_support == IPMI_EVENT_SUPPORT_GLOBAL_ENABLE))
    {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = ((sensor->events_enabled << 7)
		| (sensor->scanning_enabled << 6));
	
    if (sensor->event_support == IPMI_EVENT_SUPPORT_ENTIRE_SENSOR) {
	*rdata_len = 2;
	return;
    }

    e = 0;
    for (i=2; i<=3; i++) {
	rdata[i] = 0;
	for (j=0; j<8; j++, e++) {
	    if (e >= 15)
		break;
	    rdata[i] |= sensor->event_enabled[0][e] << j;
	}
    }
    e = 0;
    for (i=4; i<=5; i++) {
	rdata[i] = 0;
	for (j=0; j<8; j++, e++) {
	    if (e >= 15)
		break;
	    rdata[i] |= sensor->event_enabled[1][e] << j;
	}
    }

    *rdata_len = 6;
}

static void
handle_set_sensor_type(lmc_data_t    *mc,
		       msg_t         *msg,
		       unsigned char *rdata,
		       unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_get_sensor_type(lmc_data_t    *mc,
		       msg_t         *msg,
		       unsigned char *rdata,
		       unsigned int  *rdata_len)
{
    int           sens_num;
    sensor_t      *sensor;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    rdata[0] = 0;
    rdata[1] = sensor->sensor_type;
    rdata[2] = sensor->event_reading_code;
    *rdata_len = 3;
}

static void
handle_get_sensor_reading(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len)
{
    int      sens_num;
    sensor_t *sensor;
    int      i, j, e;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];

    rdata[0] = 0;
    rdata[1] = sensor->value;
    rdata[2] = ((sensor->events_enabled << 7)
		| (sensor->scanning_enabled << 6));
    e = 0;
    for (i=3; i<=4; i++) {
	rdata[i] = 0;
	for (j=0; j<8; j++, e++) {
	    if (e >= 15)
		break;
	    rdata[i] |= sensor->event_status[e] << j;
	}
    }
    *rdata_len = 5;
}

int
ipmi_mc_sensor_set_bit(lmc_data_t   *mc,
		       unsigned char lun,
		       unsigned char sens_num,
		       unsigned char bit,
		       unsigned char value,
		       int           gen_event)
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    if (bit >= 15)
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];

    set_bit(mc, sensor, bit, value, 0, 0, 0, gen_event);

    if (sensor->sensor_update_handler)
	sensor->sensor_update_handler(mc, sensor);

    return 0;
}

int
ipmi_mc_sensor_set_bit_clr_rest(lmc_data_t   *mc,
				unsigned char lun,
				unsigned char sens_num,
				unsigned char bit,
				int           gen_event)
{
    sensor_t *sensor;
    int      i;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    if (bit >= 15)
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];

    /* Clear all the other bits. */
    for (i=0; i<15; i++) {
	if ((i != bit) && (sensor->event_status[i]))
	    set_bit(mc, sensor, i, 0, 0, 0, 0, gen_event);
    }

    sensor->value = bit;
    set_bit(mc, sensor, bit, 1, 0, 0, 0, gen_event);

    if (sensor->sensor_update_handler)
	sensor->sensor_update_handler(mc, sensor);

    return 0;
}

int
ipmi_mc_sensor_set_value(lmc_data_t    *mc,
			 unsigned char lun,
			 unsigned char sens_num,
			 unsigned char value,
			 int           gen_event)
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];

    sensor->value = value;

    if (sensor->sensor_update_handler)
	sensor->sensor_update_handler(mc, sensor);

    check_thresholds(mc, sensor, gen_event);

    return 0;
}

int
ipmi_mc_sensor_set_hysteresis(lmc_data_t    *mc,
			      unsigned char lun,
			      unsigned char sens_num,
			      unsigned char support,
			      unsigned char positive,
			      unsigned char negative)
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];

    sensor->hysteresis_support = support;
    sensor->positive_hysteresis = positive;
    sensor->negative_hysteresis = negative;

    return 0;
}

int
ipmi_mc_sensor_set_threshold(lmc_data_t    *mc,
			     unsigned char lun,
			     unsigned char sens_num,
			     unsigned char support,
			     unsigned char supported[6],
			     unsigned char values[6])
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];
    sensor->threshold_support = support;
    memcpy(sensor->threshold_supported, supported, 6);
    memcpy(sensor->thresholds, values, 6);

    return 0;
}

int
ipmi_mc_sensor_set_event_support(lmc_data_t    *mc,
				 unsigned char lun,
				 unsigned char sens_num,
				 unsigned char events_enable,
				 unsigned char scanning,
				 unsigned char support,
				 unsigned char assert_supported[15],
				 unsigned char deassert_supported[15],
				 unsigned char assert_enabled[15],
				 unsigned char deassert_enabled[15])
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];

    sensor->events_enabled = events_enable;
    sensor->scanning_enabled = scanning;
    sensor->event_support = support;
    memcpy(sensor->event_supported[0], assert_supported, 15);
    memcpy(sensor->event_supported[1], deassert_supported, 15);
    memcpy(sensor->event_enabled[0], assert_enabled, 15);
    memcpy(sensor->event_enabled[1], deassert_enabled, 15);

    return 0;
}

int
ipmi_mc_add_sensor(lmc_data_t    *mc,
		   unsigned char lun,
		   unsigned char sens_num,
		   unsigned char type,
		   unsigned char event_reading_code)
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = malloc(sizeof(*sensor));
    if (!sensor)
	return ENOMEM;
    memset(sensor, 0, sizeof(*sensor));

    sensor->lun = lun;
    sensor->num = sens_num;
    sensor->sensor_type = type;
    sensor->event_reading_code = event_reading_code;
    mc->sensors[lun][sens_num] = sensor;

    if (mc->emu->atca_mode && (type == 0xf0)) {
	/* This is the ATCA hot-swap sensor. */
	mc->hs_sensor = sensor;
	sensor->sensor_update_handler = picmg_led_set;
    }

    return 0;
}

static void
handle_ipmi_get_pef_capabilities(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len)
{
    if (!mc->sysinfo) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = 0x51; /* version */
    rdata[2] = 0x3f; /* support everything but OEM */
    rdata[3] = MAX_EVENT_FILTERS;
    *rdata_len = 4;
}

static void
handle_ipmi_set_pef_config_parms(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len)
{
    unsigned char err = 0;
    int           set, block;
    sys_data_t    *sys = mc->sysinfo;

    if (msg->len < 2) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if (!sys) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    switch (msg->data[0] & 0x7f)
    {
    case 0:
	switch (msg->data[1] & 0x3)
	{
	case 0:
	    if (mc->pef.set_in_progress) {
		/* rollback */
		memcpy(&mc->pef, &mc->pef_rollback,
		       sizeof(mc->pef));
	    }
	    /* No affect otherwise */
	    break;

	case 1:
	    if (mc->pef.set_in_progress)
		err = 0x81; /* Another user is writing. */
	    else {
		/* Save rollback data */
		memcpy(&mc->pef_rollback, &mc->pef,
		       sizeof(mc->pef));
		mc->pef.set_in_progress = 1;
	    }
	    break;

	case 2:
	    if (mc->pef.commit)
		mc->pef.commit(sys);
	    memset(&mc->pef.changed, 0, sizeof(mc->pef.changed));
	    mc->pef.set_in_progress = 0;
	    break;

	case 3:
	    err = IPMI_INVALID_DATA_FIELD_CC;
	}
	break;

    case 5:
    case 8:
    case 11:
	err = 0x82; /* Read-only data */
	break;

    case 1:
	mc->pef.pef_control = msg->data[1];
	mc->pef.changed.pef_control = 1;
	break;

    case 2:
	mc->pef.pef_action_global_control = msg->data[1];
	mc->pef.changed.pef_action_global_control = 1;
	break;

    case 3:
	mc->pef.pef_startup_delay = msg->data[1];
	mc->pef.changed.pef_startup_delay = 1;
	break;

    case 4:
	mc->pef.pef_alert_startup_delay = msg->data[1];
	mc->pef.changed.pef_alert_startup_delay = 1;
	break;

    case 6:
	set = msg->data[1] & 0x7f;
	if (msg->len < 22)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if ((set <= 0) || (set >= mc->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(mc->pef.event_filter_table[set], msg->data+1, 21);
	    mc->pef.changed.event_filter_table[set] = 1;
	}
	break;

    case 7:
	set = msg->data[1] & 0x7f;
	if (msg->len < 3)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if ((set <= 0) || (set >= mc->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(mc->pef.event_filter_data1[set], msg->data+1, 2);
	    mc->pef.changed.event_filter_data1[set] = 1;
	}
	break;

    case 9:
	set = msg->data[1] & 0x7f;
	if (msg->len < 5)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if ((set <= 0) || (set >= mc->pef.num_alert_policies))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(mc->pef.alert_policy_table[set], msg->data+1, 4);
	    mc->pef.changed.alert_policy_table[set] = 1;
	}
	break;

    case 10:
	if (msg->len < 18)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(mc->pef.system_guid, msg->data+1, 17);
	    mc->pef.changed.system_guid = 1;
	}
	break;

    case 12:
	set = msg->data[1] & 0x7f;
	if (msg->len < 4)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if (set >= mc->pef.num_alert_strings)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(mc->pef.alert_string_keys[set], msg->data+1, 3);
	    mc->pef.changed.alert_string_keys[set] = 1;
	}
	break;

    case 13:
	set = msg->data[1] & 0x7f;
	if (msg->len < 4)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if (set >= mc->pef.num_alert_strings)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else if (msg->data[2] == 0)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    int dlen = msg->len - 3;
	    set = msg->data[1] & 0x7f;
	    block = msg->data[2] - 1;
	    if (((block*16) + dlen) > MAX_ALERT_STRING_LEN) {
		err = IPMI_PARAMETER_OUT_OF_RANGE_CC;
		break;
	    }
	    memcpy(mc->pef.alert_strings[set]+(block*16), msg->data+3, dlen);
	    mc->pef.changed.alert_strings[set] = 1;
	}
	break;

    default:
	err = 0x80; /* Parm not supported */
    }

    rdata[0] = err;
    *rdata_len = 1;
}

static void
handle_ipmi_get_pef_config_parms(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len)
{
    int           set, block;
    unsigned char databyte = 0;
    unsigned char *data = NULL;
    unsigned int  length = 0;
    unsigned char err = 0;
    unsigned char tmpdata[18];

    sys_data_t    *sys = mc->sysinfo;

    if (msg->len < 3) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if (!sys) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    switch (msg->data[0] & 0x7f)
    {
    case 0:
	databyte = mc->pef.set_in_progress;
	break;

    case 5:
	databyte = mc->pef.num_event_filters - 1;
	break;

    case 8:
	databyte = mc->pef.num_alert_policies - 1;
	break;

    case 11:
	databyte = mc->pef.num_alert_strings - 1;
	break;

    case 1:
	databyte = mc->pef.pef_control;
	break;

    case 2:
	databyte = mc->pef.pef_action_global_control;
	break;

    case 3:
	databyte = mc->pef.pef_startup_delay;
	break;

    case 4:
	databyte = mc->pef.pef_alert_startup_delay;
	break;

    case 6:
	set = msg->data[1] & 0x7f;
	if ((set <= 0) || (set >= mc->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = mc->pef.event_filter_table[set];
	    length = 21;
	}
	break;

    case 7:
	set = msg->data[1] & 0x7f;
	if ((set <= 0) || (set >= mc->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = mc->pef.event_filter_data1[set];
	    length = 2;
	}
	break;

    case 9:
	set = msg->data[1] & 0x7f;
	if ((set <= 0) || (set >= mc->pef.num_alert_policies))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = mc->pef.alert_policy_table[set];
	    length = 4;
	}
	break;

    case 10:
	data = mc->pef.system_guid;
	length = 17;
	break;

    case 12:
	set = msg->data[1] & 0x7f;
	if (set >= mc->pef.num_alert_strings)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = mc->pef.alert_string_keys[set];
	    length = 3;
	}
	break;

    case 13:
	set = msg->data[1] & 0x7f;
	if (set >= mc->pef.num_alert_strings)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else if (msg->data[2] == 0)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    block = msg->data[2] - 1;
	    if ((block*16) > MAX_ALERT_STRING_LEN) {
		err = IPMI_PARAMETER_OUT_OF_RANGE_CC;
		break;
	    }
	    tmpdata[0] = set;
	    tmpdata[1] = block + 1;
	    memcpy(tmpdata+2, mc->pef.alert_strings[set]+(block*16), 16);
	    data = tmpdata;
	    length = 18;
	}
	break;

    default:
	err = 0x80; /* Parm not supported */
    }

    rdata[0] = err;
    if (err) {
	*rdata_len = 1;
	return;
    }

    rdata[1] = 0x11; /* rev */
    if (msg->data[0] & 0x80) {
	*rdata_len = 2;
    } else if (data) {
	memcpy(rdata + 2, data, length);
	*rdata_len = length + 2;
    } else {
	rdata[2] = databyte;
	*rdata_len = 3;
    }
}

static cmd_handler_f sensor_event_netfn_handlers[256] = {
    [IPMI_GET_EVENT_RECEIVER_CMD] = handle_get_event_receiver,
    [IPMI_SET_EVENT_RECEIVER_CMD] = handle_set_event_receiver,
    [IPMI_GET_DEVICE_SDR_INFO_CMD] = handle_get_device_sdr_info,
    [IPMI_RESERVE_DEVICE_SDR_REPOSITORY_CMD] = handle_reserve_device_sdr_repository,
    [IPMI_GET_DEVICE_SDR_CMD] = handle_get_device_sdr,
    [IPMI_SET_SENSOR_HYSTERESIS_CMD] = handle_set_sensor_hysteresis,
    [IPMI_GET_SENSOR_HYSTERESIS_CMD] = handle_get_sensor_hysteresis,
    [IPMI_SET_SENSOR_THRESHOLD_CMD] = handle_set_sensor_thresholds,
    [IPMI_GET_SENSOR_THRESHOLD_CMD] = handle_get_sensor_thresholds,
    [IPMI_SET_SENSOR_EVENT_ENABLE_CMD] = handle_set_sensor_event_enable,
    [IPMI_GET_SENSOR_EVENT_ENABLE_CMD] = handle_get_sensor_event_enable,
    [IPMI_SET_SENSOR_TYPE_CMD] = handle_set_sensor_type,
    [IPMI_GET_SENSOR_TYPE_CMD] = handle_get_sensor_type,
    [IPMI_GET_SENSOR_READING_CMD] = handle_get_sensor_reading,
    [IPMI_GET_PEF_CAPABILITIES_CMD] = handle_ipmi_get_pef_capabilities,
    [IPMI_SET_PEF_CONFIG_PARMS_CMD] = handle_ipmi_set_pef_config_parms,
    [IPMI_GET_PEF_CONFIG_PARMS_CMD] = handle_ipmi_get_pef_config_parms,
    [IPMI_GET_SENSOR_EVENT_STATUS_CMD] = NULL,
    [IPMI_REARM_SENSOR_EVENTS_CMD] = NULL,
    [IPMI_GET_SENSOR_READING_FACTORS_CMD] = NULL
};

int
ipmi_mc_set_power(lmc_data_t *mc, unsigned char power, int gen_event)
{
    lmc_data_t    *dest_mc;
    unsigned char data[13];
    int           rv;

    if (mc->power_value == power)
	return 0;

    mc->power_value = power;

    if ((mc->event_receiver == 0)
	|| (!gen_event))
	return 0;

    rv = ipmi_emu_get_mc_by_addr(mc->emu, mc->event_receiver, &dest_mc);
    if (rv)
	return 0;

    /* Timestamp is ignored. */
    data[0] = 0;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;

    data[4] = 0x20; /* These come from 0x20. */
    data[5] = 0;
    data[6] = 0x01; /* Version 1. */
    data[7] = 0;
    data[8] = 0x40; /* IPMB of the device being powered. */
    data[9] = 0;
    data[10] = power;
    data[11] = 0;
    data[12] = 0;

    mc_new_event(dest_mc, 0xc0, data);
	
    return 0;
}

static void
handle_set_power(lmc_data_t    *mc,
		 msg_t         *msg,
		 unsigned char *rdata,
		 unsigned int  *rdata_len)
{
    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    ipmi_mc_set_power(mc, msg->data[0], 1);

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_power(lmc_data_t    *mc,
		 msg_t         *msg,
		 unsigned char *rdata,
		 unsigned int  *rdata_len)
{
    rdata[0] = 0;
    rdata[1] = mc->power_value;
    *rdata_len = 2;
}

static void
handle_set_hs_led(lmc_data_t    *mc,
		  msg_t         *msg,
		  unsigned char *rdata,
		  unsigned int  *rdata_len)
{
    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    mc->leds[0].color = msg->data[0];

    printf("Setting hotswap LED to %d\n", msg->data[0]);

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_hs_led(lmc_data_t    *mc,
		  msg_t         *msg,
		  unsigned char *rdata,
		  unsigned int  *rdata_len)
{
    rdata[0] = 0;
    rdata[1] = mc->leds[0].color;
    *rdata_len = 2;
}

static cmd_handler_f oem0_netfn_handlers[256] = {
    [0x01] = handle_set_power,
    [0x02] = handle_get_power,
    [0x03] = handle_set_hs_led,
    [0x04] = handle_get_hs_led
};

static void
handle_picmg_get_properties(lmc_data_t    *mc,
			    msg_t         *msg,
			    unsigned char *rdata,
			    unsigned int  *rdata_len)
{
    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = 0x22; /* Version 2.2 */
    rdata[3] = 0; /* Only have one FRU. */
    rdata[4] = 0; /* As defined by spec. */
    *rdata_len = 5;
}

static void
handle_picmg_get_address_info(lmc_data_t    *mc,
			      msg_t         *msg,
			      unsigned char *rdata,
			      unsigned int  *rdata_len)
{
    atca_site_t  *sites = mc->emu->atca_sites;
    unsigned char hw_addr = mc->ipmb >> 1;
    unsigned char devid = 0;
    int           i;

    if (msg->len == 3) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (msg->len >= 2)
	devid = msg->data[1];

    if (msg->len >= 4) {
	switch (msg->data[2]) {
	case 0:
	    hw_addr = msg->data[3];
	    break;

	case 1:
	    hw_addr = msg->data[3] >> 1;
	    break;

	case 3:
	    if (msg->len < 5) {
		rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
		*rdata_len = 1;
		return;
	    }
	    for (i=0; i<128; i++) {
		if (sites[i].valid
		    && (sites[i].site_type == msg->data[4])
		    && (sites[i].site_number == msg->data[3]))
		{
		    break;
		}
	    }
	    if (i == 128) {
		rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
		*rdata_len = 1;
		return;
	    }
	    hw_addr = i;
	    break;
		
	default:
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    if ((hw_addr >= 128) || (!sites[hw_addr].valid) || (devid > 0)) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = hw_addr;
    rdata[3] = hw_addr << 1;
    rdata[4] = 0xff;
    rdata[5] = devid;
    rdata[6] = sites[hw_addr].site_number;
    rdata[7] = sites[hw_addr].site_type;
    *rdata_len = 8;
}

static void
handle_picmg_cmd_fru_control(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len)
{
    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    if (msg->data[2] >= 4) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    /* Nothing to reset. */
    printf("Fru control set to %d\n", msg->data[2]);

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    *rdata_len = 2;
}

static void
handle_picmg_cmd_get_fru_led_properties(lmc_data_t    *mc,
					msg_t         *msg,
					unsigned char *rdata,
					unsigned int  *rdata_len)
{
    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    if (mc->num_leds <= 2) {
	mc->num_leds = 2;
	rdata[2] = 0x03; /* We support the first 2 LEDs. */
	rdata[3] = 0x00;
    } else if (mc->num_leds == 3) {
	rdata[2] = 0x07; /* We support the first 3 LEDs. */
	rdata[3] = 0x00;
    } else {
	rdata[2] = 0xf; /* We support the first 4 LEDs. */
	rdata[3] = mc->num_leds = 4; /* How many more do we support? */
    }
    *rdata_len = 4;
}

static void
handle_picmg_cmd_get_led_color_capabilities(lmc_data_t    *mc,
					    msg_t         *msg,
					    unsigned char *rdata,
					    unsigned int  *rdata_len)
{
    unsigned int led;

    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    led = msg->data[2];
    if (led >= mc->num_leds) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = mc->leds[led].color_sup;
    rdata[3] = mc->leds[led].def_loc_cnt_color;
    rdata[4] = mc->leds[led].def_override_color;

    *rdata_len = 5;
}

static void
picmg_led_set(lmc_data_t *mc, sensor_t *sensor)
{
    printf("ATCA hot-swap state is %d\n", sensor->value);

    switch (sensor->value) {
    case 0:
    case 3:
    case 4:
	/* off */
	mc->leds[0].def_off_dur = 0;
	mc->leds[0].def_on_dur = 0;
	break;

    case 1:
	/* on */
	mc->leds[0].def_off_dur = 0xff;
	mc->leds[0].def_on_dur = 0;
	break;

    case 2:
	/* long blink */
	mc->leds[0].def_off_dur = 10;
	mc->leds[0].def_on_dur = 90;
	break;

    case 5:
    case 6:
	/* short blink */
	mc->leds[0].def_off_dur = 90;
	mc->leds[0].def_on_dur = 10;
	break;
		
    case 7:
	/* Nothing to do */
	break;
    }

    if (mc->leds[0].loc_cnt) {
	mc->leds[0].off_dur = mc->leds[0].def_off_dur;
	mc->leds[0].on_dur = mc->leds[0].def_on_dur;
	printf("Setting ATCA LED %d to %s %x %x %x\n",
	       0,
	       mc->leds[0].loc_cnt ? "local_control" : "override",
	       mc->leds[0].off_dur,
	       mc->leds[0].on_dur,
	       mc->leds[0].color);
    }
}

static void
handle_picmg_cmd_set_fru_led_state(lmc_data_t    *mc,
				   msg_t         *msg,
				   unsigned char *rdata,
				   unsigned int  *rdata_len)
{
    unsigned int led;

    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    led = msg->data[2];
    if (led >= mc->num_leds) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    switch (msg->data[3]) {
    case 0xfc: /* Local control */
	if (!mc->leds[led].loc_cnt_sup) {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}

	mc->leds[led].loc_cnt = 1;

	mc->leds[led].off_dur = mc->leds[led].def_off_dur;
	mc->leds[led].on_dur = mc->leds[led].def_on_dur;
	mc->leds[led].color = mc->leds[led].def_loc_cnt_color;
	break;

    case 0xfb:
    case 0xfd:
    case 0xfe:
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;

    default: /* Override mode */
	mc->leds[led].loc_cnt = 0;
	mc->leds[led].off_dur = msg->data[3];
	mc->leds[led].on_dur = msg->data[4];
	if (msg->data[5] == 0xf)
	    mc->leds[led].color = mc->leds[led].def_override_color;
	else if (msg->data[5] != 0xe) /* 0xe is don't change. */
	    mc->leds[led].color = msg->data[5];
    }

    printf("Setting ATCA LED %d to %s %x %x %x\n",
	   led,
	   mc->leds[led].loc_cnt ? "local_control" : "override",
	   mc->leds[led].off_dur,
	   mc->leds[led].on_dur,
	   mc->leds[led].color);

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    *rdata_len = 2;
}

static void
handle_picmg_cmd_get_fru_led_state(lmc_data_t    *mc,
				   msg_t         *msg,
				   unsigned char *rdata,
				   unsigned int  *rdata_len)
{
    unsigned int led;

    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    led = msg->data[2];
    if (led >= mc->num_leds) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = 0x00;
    if (mc->leds[led].loc_cnt_sup)
	rdata[2] |= 0x01; /* Local control support */

    if (mc->leds[led].loc_cnt) {
	rdata[3] = mc->leds[led].off_dur;
	rdata[4] = mc->leds[led].on_dur;
	rdata[5] = mc->leds[led].color;
	*rdata_len = 6;
    } else {
	rdata[2] |= 0x02; /* override state. */
	rdata[3] = mc->leds[led].def_off_dur;
	rdata[4] = mc->leds[led].def_on_dur;
	rdata[5] = mc->leds[led].def_loc_cnt_color;
	rdata[6] = mc->leds[led].off_dur;
	rdata[7] = mc->leds[led].on_dur;
	rdata[8] = mc->leds[led].color;
	*rdata_len = 9;
    }
}

static void
handle_picmg_cmd_get_shelf_address_info(lmc_data_t    *mc,
					msg_t         *msg,
					unsigned char *rdata,
					unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_shelf_address_info(lmc_data_t    *mc,
					msg_t         *msg,
					unsigned char *rdata,
					unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_ipmb_state(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_fru_activation_policy(lmc_data_t    *mc,
					   msg_t         *msg,
					   unsigned char *rdata,
					   unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_fru_activation_policy(lmc_data_t    *mc,
					   msg_t         *msg,
					   unsigned char *rdata,
					   unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_fru_activation(lmc_data_t    *mc,
				    msg_t         *msg,
				    unsigned char *rdata,
				    unsigned int  *rdata_len)
{
    int      op;
    sensor_t *hssens;

    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    if (! mc->hs_sensor) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    op = msg->data[2];
    if (op >= 2) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    hssens = mc->hs_sensor;
    switch (op) {
    case 0:
	if ((hssens->event_status[3])
	    || (hssens->event_status[4])
	    || (hssens->event_status[5]))
	{
	    /* Transition to m6. */
	    ipmi_mc_sensor_set_bit_clr_rest(mc, hssens->lun, hssens->num,
					    6, 1);

	    /* Transition to m1. */
	    ipmi_mc_sensor_set_bit_clr_rest(mc, hssens->lun, hssens->num,
					    1, 1);
	}
	break;

    case 1:
	if (hssens->event_status[2]) {
	    /* Transition to m3. */
	    ipmi_mc_sensor_set_bit_clr_rest(mc, hssens->lun, hssens->num,
					    3, 1);

	    /* Transition to m4. */
	    ipmi_mc_sensor_set_bit_clr_rest(mc, hssens->lun, hssens->num,
					    4, 1);
	}
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    *rdata_len = 2;
}

static void
handle_picmg_cmd_get_device_locator_record(lmc_data_t    *mc,
					   msg_t         *msg,
					   unsigned char *rdata,
					   unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_port_state(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_port_state(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_compute_power_properties(lmc_data_t    *mc,
					  msg_t         *msg,
					  unsigned char *rdata,
					  unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_power_level(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_power_level(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_renegotiate_power(lmc_data_t    *mc,
				   msg_t         *msg,
				   unsigned char *rdata,
				   unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_fan_speed_properties(lmc_data_t    *mc,
					  msg_t         *msg,
					  unsigned char *rdata,
					  unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_fan_level(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_fan_level(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_bused_resource(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_ipmb_link_info(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_shelf_power_allocation(lmc_data_t    *mc,
					msg_t         *msg,
					unsigned char *rdata,
					unsigned int  *rdata_len)
{
    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    if (msg->data[1] > 1) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    ipmi_set_uint16(rdata+2, 0);
    if (msg->data[1] == 0) {
	ipmi_set_uint16(rdata+4, 105);
	ipmi_set_uint16(rdata+6, 227);
	*rdata_len = 8;
    } else {
	ipmi_set_uint16(rdata+4, 227);
	*rdata_len = 6;
    }
}

static void
handle_picmg_cmd_shelf_manager_ipmb_address(lmc_data_t    *mc,
					    msg_t         *msg,
					    unsigned char *rdata,
					    unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_fan_policy(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_fan_policy(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}


static void
handle_picmg_cmd_fru_control_capabilities(lmc_data_t    *mc,
					  msg_t         *msg,
					  unsigned char *rdata,
					  unsigned int  *rdata_len)
{
    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = 0x0e;
    *rdata_len = 3;
}

static void
handle_picmg_cmd_fru_inventory_device_lock_control(lmc_data_t    *mc,
						   msg_t         *msg,
						   unsigned char *rdata,
						   unsigned int  *rdata_len)
{
    emu_data_t *emu = mc->emu;
    uint16_t   lock_id;

    if (mc->ipmb != 0x20) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 5, rdata, rdata_len))
	return;

    if (msg->data[1] != 254) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;

    switch (msg->data[2]) {
    case 0:
	rdata[2] = 0;
	rdata[3] = 0;
	ipmi_set_uint32(rdata+4, emu->atca_fru_inv_curr_timestamp);
	*rdata_len = 8;
	break;

    case 1:
	if (emu->atca_fru_inv_locked) {
	    rdata[0] = 0x81;
	    *rdata_len = 1;
	    break;
	}
	if (mc->frus[254].length == 0) {
	    rdata[0] = IPMI_NOT_SUPPORTED_IN_PRESENT_STATE_CC;
	    *rdata_len = 1;
	    break;
	}
	emu->temp_fru_inv_data = malloc(mc->frus[254].length);
	if (!emu->temp_fru_inv_data) {
	    rdata[0] = IPMI_OUT_OF_SPACE_CC;
	    *rdata_len = 1;
	    break;
	}
	emu->temp_fru_inv_data_len = mc->frus[254].length;
	memcpy(emu->temp_fru_inv_data, mc->frus[254].data, 
	       emu->temp_fru_inv_data_len);

	emu->atca_fru_inv_locked = 1;
	emu->atca_fru_inv_curr_lock_id++;
	ipmi_set_uint16(rdata+2, emu->atca_fru_inv_curr_lock_id);
	ipmi_set_uint32(rdata+4, emu->atca_fru_inv_curr_timestamp);
	*rdata_len = 8;
	emu->atca_fru_inv_lock_timeout = 20;
	break;

    case 2:
	lock_id = ipmi_get_uint16(msg->data+3);
	if (!emu->atca_fru_inv_locked
	    || (lock_id != emu->atca_fru_inv_curr_lock_id))
	{
	    rdata[0] = 0x81;
	    *rdata_len = 1;
	    break;
	}
	emu->atca_fru_inv_locked = 0;
	rdata[2] = 0;
	rdata[3] = 0;
	ipmi_set_uint32(rdata+4, emu->atca_fru_inv_curr_timestamp);
	*rdata_len = 8;
	free(emu->temp_fru_inv_data);
	emu->temp_fru_inv_data = NULL;
	break;

    case 3:
	lock_id = ipmi_get_uint16(msg->data+3);
	if (!emu->atca_fru_inv_locked
	    || (lock_id != emu->atca_fru_inv_curr_lock_id))
	{
	    rdata[0] = 0x81;
	    *rdata_len = 1;
	    break;
	}
	emu->atca_fru_inv_locked = 0;
	rdata[2] = 0;
	rdata[3] = 0;
	ipmi_set_uint32(rdata+4, emu->atca_fru_inv_curr_timestamp);
	*rdata_len = 8;
	emu->atca_fru_inv_curr_timestamp++;
	/* FIXME - validate data. */
	memcpy(mc->frus[254].data, emu->temp_fru_inv_data,
	       emu->temp_fru_inv_data_len);
	free(emu->temp_fru_inv_data);
	emu->temp_fru_inv_data = NULL;
	break;

    default:
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	break;
    }
}

static void
handle_picmg_cmd_fru_inventory_device_write(lmc_data_t    *mc,
					    msg_t         *msg,
					    unsigned char *rdata,
					    unsigned int  *rdata_len)
{
    emu_data_t   *emu = mc->emu;
    uint16_t     lock_id;
    unsigned int offset;
    unsigned int count;

    if (mc->ipmb != 0x20) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 6, rdata, rdata_len))
	return;

    if (msg->data[1] != 254) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    lock_id = ipmi_get_uint16(msg->data+2);
    if (!emu->atca_fru_inv_locked
	|| (lock_id != emu->atca_fru_inv_curr_lock_id))
    {
	rdata[0] = 0x80;
	*rdata_len = 1;
	return;
    }

    /* Reset the timer. */
    emu->atca_fru_inv_lock_timeout = 20;

    offset = ipmi_get_uint16(msg->data+4);
    count = msg->len - 6;

    if (offset >= emu->temp_fru_inv_data_len) {
	rdata[0] = IPMI_PARAMETER_OUT_OF_RANGE_CC;
	*rdata_len = 1;
	return;
    }

    if ((offset+count) > emu->temp_fru_inv_data_len) {
	/* Too much data to put into FRU. */
	rdata[0] = IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC;
	*rdata_len = 1;
	return;
    }

    memcpy(emu->temp_fru_inv_data+offset, msg->data+6, count);

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = count;
    *rdata_len = 3;
}

static void
handle_picmg_cmd_get_shelf_manager_ip_addresses(lmc_data_t    *mc,
						msg_t         *msg,
						unsigned char *rdata,
						unsigned int  *rdata_len)
{
    emu_data_t   *emu = mc->emu;
    unsigned int addr;
    unsigned int count;
    emu_addr_t   *ap = NULL;
    int          i;

    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    addr = msg->data[1];
    
    for (count=0, i=0; i<MAX_EMU_ADDR; i++) {
	if (emu->addr[i].valid) {
	    if (count == addr)
		ap = &(emu->addr[i]);
	    count++;
	}
    }

    if (addr >= count) {
	rdata[0] = IPMI_PARAMETER_OUT_OF_RANGE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    ipmi_set_uint32(rdata+1, emu->last_addr_change_time.tv_sec);
    rdata[5] = count;
    rdata[6] = 0x03;
    rdata[7] = addr - 1;
    rdata[8] = 20;

    rdata[9] = ap->addr_type;
    if (addr == 0)
	rdata[9] |= 0x80;
    memcpy(rdata+10, ap->addr_data, ap->addr_len);
    *rdata_len = 10 + ap->addr_len;
}

int
ipmi_emu_atca_enable(emu_data_t *emu)
{
    emu->atca_mode = 1;
    return 0;
}

int
ipmi_emu_atca_set_site(emu_data_t    *emu,
		       unsigned char hw_address,
		       unsigned char site_type,
		       unsigned char site_number)
{
    if (hw_address >= 128)
	return EINVAL;

    emu->atca_sites[hw_address].valid = 1;
    emu->atca_sites[hw_address].hw_address = hw_address;
    emu->atca_sites[hw_address].site_type = site_type;
    emu->atca_sites[hw_address].site_number = site_number;
    return 0;
}

static void
handle_picmg_msg(lmc_data_t    *mc,
		 msg_t         *msg,
		 unsigned char *rdata,
		 unsigned int  *rdata_len)
{
    switch(msg->cmd) {
    case IPMI_PICMG_CMD_GET_PROPERTIES:
	handle_picmg_get_properties(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_ADDRESS_INFO:
	handle_picmg_get_address_info(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_FRU_CONTROL:
	handle_picmg_cmd_fru_control(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_FRU_LED_PROPERTIES:
	handle_picmg_cmd_get_fru_led_properties(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_LED_COLOR_CAPABILITIES:
	handle_picmg_cmd_get_led_color_capabilities(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_SET_FRU_LED_STATE:
	handle_picmg_cmd_set_fru_led_state(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_FRU_LED_STATE:
	handle_picmg_cmd_get_fru_led_state(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_SHELF_ADDRESS_INFO:
	handle_picmg_cmd_get_shelf_address_info(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_SET_SHELF_ADDRESS_INFO:
	handle_picmg_cmd_set_shelf_address_info(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_SET_IPMB_STATE:
	handle_picmg_cmd_set_ipmb_state(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_SET_FRU_ACTIVATION_POLICY:
	handle_picmg_cmd_set_fru_activation_policy(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_FRU_ACTIVATION_POLICY:
	handle_picmg_cmd_get_fru_activation_policy(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_SET_FRU_ACTIVATION:
	handle_picmg_cmd_set_fru_activation(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_DEVICE_LOCATOR_RECORD:
	handle_picmg_cmd_get_device_locator_record(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_SET_PORT_STATE:
	handle_picmg_cmd_set_port_state(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_PORT_STATE:
	handle_picmg_cmd_get_port_state(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_COMPUTE_POWER_PROPERTIES:
	handle_picmg_cmd_compute_power_properties(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_SET_POWER_LEVEL:
	handle_picmg_cmd_set_power_level(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_POWER_LEVEL:
	handle_picmg_cmd_get_power_level(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_RENEGOTIATE_POWER:
	handle_picmg_cmd_renegotiate_power(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_FAN_SPEED_PROPERTIES:
	handle_picmg_cmd_get_fan_speed_properties(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_SET_FAN_LEVEL:
	handle_picmg_cmd_set_fan_level(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_FAN_LEVEL:
	handle_picmg_cmd_get_fan_level(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_BUSED_RESOURCE:
	handle_picmg_cmd_bused_resource(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_IPMB_LINK_INFO:
	handle_picmg_cmd_ipmb_link_info(mc, msg, rdata, rdata_len);
	break;
      
    case IPMI_PICMG_CMD_SHELF_POWER_ALLOCATION:
	handle_picmg_cmd_shelf_power_allocation(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_SHELF_MANAGER_IPMB_ADDRESS:
	handle_picmg_cmd_shelf_manager_ipmb_address(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_SET_FAN_POLICY:
	handle_picmg_cmd_set_fan_policy(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_FAN_POLICY:
	handle_picmg_cmd_get_fan_policy(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_FRU_CONTROL_CAPABILITIES:
	handle_picmg_cmd_fru_control_capabilities(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_FRU_INVENTORY_DEVICE_LOCK_CONTROL:
	handle_picmg_cmd_fru_inventory_device_lock_control(mc, msg, rdata,
							   rdata_len);
	break;

    case IPMI_PICMG_CMD_FRU_INVENTORY_DEVICE_WRITE:
	handle_picmg_cmd_fru_inventory_device_write(mc, msg, rdata, rdata_len);
	break;

    case IPMI_PICMG_CMD_GET_SHELF_MANAGER_IP_ADDRESSES:
	handle_picmg_cmd_get_shelf_manager_ip_addresses(mc, msg, rdata,
							rdata_len);
	break;

    default:
	handle_invalid_cmd(mc, rdata, rdata_len);
	break;
    }
}

static void
handle_group_extension_netfn(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len)
{
    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    switch (msg->data[0]) {
    case IPMI_PICMG_GRP_EXT:
	if (mc->emu->atca_mode)
	    handle_picmg_msg(mc, msg, rdata, rdata_len);
	else
	    handle_invalid_cmd(mc, rdata, rdata_len);
	break;

    default:
	handle_invalid_cmd(mc, rdata, rdata_len);
	break;
    }
}

static uint8_t
ipmb_checksum(uint8_t *data, int size, uint8_t start)
{
	uint8_t csum = start;
	
	for (; size > 0; size--, data++)
		csum += *data;

	return -csum;
}

typedef struct netfn_handler_s {
    cmd_handler_f *handlers;
    cmd_handler_f main_handler;
    int (*check_capable)(lmc_data_t *mc);
} netfn_handler_t;

static netfn_handler_t netfn_handlers[32] = {
    [IPMI_APP_NETFN >> 1] = { .handlers = app_netfn_handlers },
    [IPMI_STORAGE_NETFN >> 1] = { .handlers = storage_netfn_handlers },
    [IPMI_CHASSIS_NETFN >> 1] = { .handlers = chassis_netfn_handlers,
			     .check_capable = check_chassis_capable },
    [IPMI_TRANSPORT_NETFN >> 1] = { .handlers = transport_netfn_handlers },
    [IPMI_SENSOR_EVENT_NETFN >> 1] = { .handlers = sensor_event_netfn_handlers },
    [IPMI_GROUP_EXTENSION_NETFN >> 1] = { .main_handler = handle_group_extension_netfn },
    [0x30 >> 1] = { .handlers = oem0_netfn_handlers }
};

int
ipmi_emu_register_cmd_handler(unsigned char netfn, unsigned char cmd,
			      cmd_handler_f handler)
{
    unsigned int ni = netfn >> 1;

    if (netfn >= 32)
	return EINVAL;

    if (!netfn_handlers[ni].handlers) {
	netfn_handlers[ni].handlers = malloc(256 * sizeof(cmd_handler_f));
	if (!netfn_handlers[ni].handlers)
	    return ENOMEM;
	memset(netfn_handlers[ni].handlers, 0, 256 * sizeof(cmd_handler_f));
    }

    netfn_handlers[ni].handlers[cmd] = handler;
    return 0;
}

void
ipmi_emu_handle_msg(emu_data_t    *emu,
		    lmc_data_t    *srcmc,
		    msg_t         *omsg,
		    unsigned char *ordata,
		    unsigned int  *ordata_len)
{
    lmc_data_t *mc;
    msg_t smsg, *rmsg = NULL;
    msg_t *msg;
    unsigned char *data = NULL;
    unsigned char *rdata;
    unsigned int  *rdata_len;

    if (emu->sysinfo->debug & DEBUG_MSG)
	emu->sysinfo->log(emu->sysinfo, DEBUG, omsg, "Receive message:");
    if (omsg->netfn == IPMI_APP_NETFN && omsg->cmd == IPMI_SEND_MSG_CMD) {
	/* Encapsulated IPMB, do special handling. */
	unsigned char slave;
	unsigned int  data_len;

	if (check_msg_length(omsg, 8, ordata, ordata_len))
	    return;
	if ((omsg->data[0] & 0x3f) != 0) {
	    ordata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *ordata_len = 1;
	    return;
	}

	data = omsg->data + 1;
	data_len = omsg->len - 1;
	if (data[0] == 0) {
	    /* Broadcast, just skip the first byte, but check len. */
	    data++;
	    data_len--;
	    if (data_len < 7) {
		ordata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
		*ordata_len = 1;
		return;
	    }
	}
	slave = data[0];
	mc = emu->sysinfo->ipmb_addrs[slave];
	if (!mc || !mc->enabled) {
	    ordata[0] = 0x83; /* NAK on Write */
	    *ordata_len = 1;
	    return;
	}

	rmsg = malloc(sizeof(*rmsg) + IPMI_SIM_MAX_MSG_LENGTH);
	if (!rmsg) {
	    ordata[0] = IPMI_OUT_OF_SPACE_CC;
	    *ordata_len = 1;
	    return;
	}

	*rmsg = *omsg;

	rmsg->data = ((unsigned char *) rmsg) + sizeof(*rmsg);
	rmsg->len = IPMI_SIM_MAX_MSG_LENGTH - 7; /* header and checksum */
	rmsg->netfn = (data[1] & 0xfc) >> 2;
	rmsg->cmd = data[5];
	rdata = rmsg->data + 6;
	rdata_len = &rmsg->len;
	rmsg->data[0] = emu->sysinfo->bmc_ipmb;
	rmsg->data[1] = ((data[1] & 0xfc) | 0x4) | (data[4] & 0x3);
	rmsg->data[2] = ipmb_checksum(rdata+1, 2, 0);
	rmsg->data[3] = data[0];
	rmsg->data[4] = (data[4] & 0xfc) | (data[1] & 0x03);
	rmsg->data[5] = data[5];

	smsg.src_addr = omsg->src_addr;
	smsg.src_len = omsg->src_len;
	smsg.netfn = data[1] >> 2;
	smsg.rs_lun = data[1] & 0x3;
	smsg.cmd = data[5];
	smsg.data = data + 6;
	smsg.len = data_len - 7; /* Subtract off the header and
				    the end checksum */
	smsg.channel = 0; /* IPMB channel is 0 */
	smsg.orig_channel = omsg->orig_channel;
	smsg.sid = omsg->sid;
	msg = &smsg;
    } else {
	mc = srcmc;
	if (!mc || !mc->enabled) {
	    ordata[0] = 0xff;
	    *ordata_len = 1;
	    return;
	}
	rdata = ordata;
	rdata_len = ordata_len;
	msg = omsg;
    }

    if (netfn_handlers[msg->netfn >> 1].check_capable &&
	!netfn_handlers[msg->netfn >> 1].check_capable(mc))
	handle_invalid_cmd(mc, rdata, rdata_len);
    else if (netfn_handlers[msg->netfn >> 1].main_handler)
	netfn_handlers[msg->netfn >> 1].main_handler(mc, msg, rdata, rdata_len);
    else if (netfn_handlers[msg->netfn >> 1].handlers &&
	     netfn_handlers[msg->netfn >> 1].handlers[msg->cmd])
	netfn_handlers[msg->netfn >> 1].handlers[msg->cmd](mc, msg, rdata,
							   rdata_len);
    else
	handle_invalid_cmd(mc, rdata, rdata_len);

    if (omsg->netfn == IPMI_APP_NETFN && omsg->cmd == IPMI_SEND_MSG_CMD) {
	/* An encapsulated command, put the response into the receive q. */
	channel_t *bchan = srcmc->channels[15];

	if (bchan->recv_in_q) {
	    if (bchan->recv_in_q(srcmc->channels[15], rmsg))
		return;
	}

	ordata[0] = 0;
	*ordata_len = 1;

	if (emu->sysinfo->debug & DEBUG_MSG)
	    debug_log_raw_msg(emu->sysinfo, rdata, *rdata_len,
			      "Response message:");

	rmsg->len += 6;
	rmsg->data[rmsg->len] = ipmb_checksum(rmsg->data, rmsg->len, 0);
	rmsg->len += 1;
	if (srcmc->recv_q_tail) {
	    rmsg->next = srcmc->recv_q_tail;
	    srcmc->recv_q_tail = rmsg;
	} else {
	    channel_t *bchan = srcmc->channels[15];

	    rmsg->next = NULL;
	    srcmc->recv_q_head = rmsg;
	    srcmc->recv_q_tail = rmsg;
	    if (bchan->set_atn)
		bchan->set_atn(bchan, 1, IPMI_MC_MSG_INTS_ON(mc));
	}
    } else if (emu->sysinfo->debug & DEBUG_MSG)
	debug_log_raw_msg(emu->sysinfo, ordata, *ordata_len,
			  "Response message:");
}

msg_t *
ipmi_mc_get_next_recv_q(lmc_data_t *mc)
{
    msg_t *rv;

    if (!mc->recv_q_head)
	return NULL;
    rv = mc->recv_q_head;
    mc->recv_q_head = rv->next;
    if (!mc->recv_q_head) {
	mc->recv_q_tail = NULL;
    }
    return rv;
}

emu_data_t *
ipmi_emu_alloc(void *user_data, ipmi_emu_sleep_cb sleeper, sys_data_t *sysinfo)
{
    emu_data_t *data = malloc(sizeof(*data));

    if (data) {
	memset(data, 0, sizeof(*data));
	data->user_data = user_data;
	data->sleeper = sleeper;
	data->sysinfo = sysinfo;
    }
	
    return data;
}

int
ipmi_emu_set_addr(emu_data_t *emu, unsigned int addr_num,
		  unsigned char addr_type,
		  void *addr_data, unsigned int addr_len)
{
    emu_addr_t *addr;

    if (addr_num >= MAX_EMU_ADDR)
	return EINVAL;

    addr = &(emu->addr[addr_num]);
    if (addr_len > sizeof(addr->addr_data))
	return EINVAL;

    gettimeofday(&emu->last_addr_change_time, NULL);
    addr->addr_type = addr_type;
    memcpy(addr->addr_data, addr_data, addr_len);
    addr->addr_len = addr_len;
    addr->valid = 1;
    return 0;
}

int
ipmi_emu_clear_addr(emu_data_t *emu, unsigned int addr_num)
{
    emu_addr_t *addr;

    if (addr_num >= MAX_EMU_ADDR)
	return EINVAL;

    addr = &(emu->addr[addr_num]);
    addr->valid = 0;
    return 0;
}

void
ipmi_emu_sleep(emu_data_t *emu, struct timeval *time)
{
    emu->sleeper(emu, time);
}

void *
ipmi_emu_get_user_data(emu_data_t *emu)
{
    return emu->user_data;
}

void
ipmi_mc_destroy(lmc_data_t *mc)
{
    sel_entry_t *entry, *n_entry;

    entry = mc->sel.entries;
    while (entry) {
	n_entry = entry->next;
	free(entry);
	entry = n_entry;
    }
    free(mc);
}

int
ipmi_emu_set_mc_guid(lmc_data_t *mc,
		     unsigned char guid[16],
		     int force)
{
    if (force || !mc->guid_set)
	memcpy(mc->guid, guid, 16);
    mc->guid_set = 1;
    return 0;
}

void
ipmi_mc_disable(lmc_data_t *mc)
{
    mc->enabled = 0;
}

void
ipmi_mc_enable(lmc_data_t *mc)
{
    unsigned int i;
    sys_data_t *sys = mc->sysinfo;

    mc->enabled = 1;

    for (i = 0; i < IPMI_MAX_CHANNELS; i++) {
	channel_t *chan = mc->channels[i];
	int err = 0;

	if (!chan)
	    continue;

	chan->smi_send = sys->csmi_send;
	chan->oem.user_data = sys->info;
	chan->alloc = sys->calloc;
	chan->free = sys->cfree;
	chan->log = sys->clog;
	chan->mc = mc;

	if (chan->medium_type == IPMI_CHANNEL_MEDIUM_8023_LAN)
	    err = sys->lan_channel_init(sys->info, chan);
	else if (chan->medium_type == IPMI_CHANNEL_MEDIUM_RS232)
	    err = sys->ser_channel_init(sys->info, chan);
	else 
	    chan_init(chan);
	if (err) {
	    chan->log(chan, SETUP_ERROR, NULL,
		      "Unable to initialize channel for "
		      "IPMB 0x%2.2x, channel %d: %d",
		      mc->ipmb, chan->channel_num, err);
	}
    }

    if (mc->startcmd.startnow && mc->startcmd.startcmd)
	ipmi_mc_start_cmd(mc);
}

int
ipmi_mc_set_num_leds(lmc_data_t   *mc,
		     unsigned int count)
{
    if (count > MAX_LEDS)
	return EINVAL;
    if (mc->emu->atca_mode && (count < MIN_ATCA_LEDS))
	return EINVAL;

    mc->num_leds = count;
    return 0;
}

static void
unpack_bitmask(unsigned char *bits, unsigned int mask, unsigned int len)
{
    while (len) {
	*bits = mask & 1;
	bits++;
	mask >>= 1;
	len--;
    }
}

static int
init_sensor_from_sdr(lmc_data_t *mc, sdr_t *sdr)
{
    int err;
    unsigned int len = sdr->data[4];
    unsigned char num = sdr->data[7];
    unsigned char lun = sdr->data[6] & 0x3;
    unsigned char type = sdr->data[12];
    unsigned char ev_read_code = sdr->data[13];
    unsigned char assert_sup[15], deassert_sup[15];
    unsigned char assert_en[15], deassert_en[15];
    unsigned char scan_on = (sdr->data[10] >> 6) & 1;
    unsigned char events_on = (sdr->data[10] >> 5) & 1;
    unsigned char event_sup = sdr->data[11] & 0x3;

    if (len < 20)
	return 0;
    if ((sdr->data[3] < 1) || (sdr->data[3] > 2))
	return 0; /* Not a sensor SDR we set from */
    
    err = ipmi_mc_add_sensor(mc, lun, num, type, ev_read_code);
    if (err)
	return err;

    unpack_bitmask(assert_sup, sdr->data[14] | (sdr->data[15] << 8), 15);
    unpack_bitmask(deassert_sup, sdr->data[16] | (sdr->data[17] << 8), 15);
    unpack_bitmask(assert_en, sdr->data[14] | (sdr->data[15] << 8), 15);
    unpack_bitmask(deassert_en, sdr->data[16] | (sdr->data[17] << 8), 15);

    err = ipmi_mc_sensor_set_event_support(mc, lun, num,
					   events_on,
					   scan_on,
					   event_sup,
					   assert_sup,
					   deassert_sup,
					   assert_en,
					   deassert_en);
    return err;
}

static const uint8_t init_sdrs[] = {
    /* Watchdog device */
    0x00, 0x00, 0x51, 0x02,   40, 0x20, 0x00, WATCHDOG_SENSOR_NUM,
    0x23, 0x01, 0x63, 0x00, 0x23, 0x6f, 0x0f, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8,
    'W',  'a',  't',  'c',  'h',  'd',  'o',  'g',
    /* End */
    0xff, 0xff, 0x00, 0x00, 0x00
};

static int
init_sys(emu_data_t *emu, lmc_data_t *mc)
{
    unsigned int i;
    int err;

    err = mc->sysinfo->alloc_timer(mc->sysinfo, watchdog_timeout,
				   mc, &mc->watchdog_timer);
    if (err) {
	free(mc);
	return err;
    }

    for (i = 0;;) {
	unsigned int len;
	unsigned int recid;
	sdr_t *entry;

	if ((i + 5) > sizeof(init_sdrs)) {
	    //printf("IPMI: Problem with recid 0x%4.4x\n", i);
	    err = -1;
	    break;
	}
	len = init_sdrs[i + 4];
	recid = init_sdrs[i] | (init_sdrs[i + 1] << 8);
	if (recid == 0xffff)
	    break;
	if ((i + len) > sizeof(init_sdrs)) {
	    //printf("IPMI: Problem with recid 0x%4.4x\n", i);
	    err = -1;
	    break;
	}

	entry = new_sdr_entry(mc, &mc->main_sdrs, len);
	if (!entry) {
	    err = ENOMEM;
	    break;
	}

	add_sdr_entry(mc, &mc->main_sdrs, entry);

	memcpy(entry->data + 2, init_sdrs + i + 2, len - 2);
	entry->data[5] = mc->ipmb;

	err = init_sensor_from_sdr(mc, entry);
	if (err)
	    break;

	i += len;
    }

    return err;
}

static void
ipmi_mc_start_cmd(lmc_data_t *mc)
{
    if (!mc->startcmd.startcmd) {
	mc->sysinfo->log(mc->sysinfo, OS_ERROR, NULL,
			 "Power on issued, no start command set");
	return;
    }

    if (mc->startcmd.vmpid)
	/* Already running */
	return;

    ipmi_do_start_cmd(&mc->startcmd);
}

static void
chan_start_cmd(channel_t *chan)
{
    ipmi_mc_start_cmd(chan->mc);
}

static void
ipmi_mc_stop_cmd(lmc_data_t *mc, int do_it_now)
{
    if (mc->startcmd.wait_poweroff)
	/* Already powering off. */
	return;
    if (!do_it_now)
	mc->startcmd.wait_poweroff = mc->startcmd.poweroff_wait_time;
    else
	mc->startcmd.wait_poweroff = 1; /* Just power off now. */
}

static void
chan_stop_cmd(channel_t *chan, int do_it_now)
{
    ipmi_mc_stop_cmd(chan->mc, do_it_now);
}

channel_t **
ipmi_mc_get_channelset(lmc_data_t *mc)
{
    return mc->channels;
}

ipmi_sol_t *
ipmi_mc_get_sol(lmc_data_t *mc)
{
    return &mc->sol;
}

unsigned char
ipmi_mc_get_ipmb(lmc_data_t *mc)
{
    return mc->ipmb;
}

int
ipmi_mc_users_changed(lmc_data_t *mc)
{
    int rv = mc->users_changed;
    mc->users_changed = 0;
    return rv;
}

user_t *
ipmi_mc_get_users(lmc_data_t *mc)
{
    return mc->users;
}

pef_data_t *
ipmi_mc_get_pef(lmc_data_t *mc)
{
    return &mc->pef;
}

startcmd_t *
ipmi_mc_get_startcmdinfo(lmc_data_t *mc)
{
    return &mc->startcmd;
}

int
ipmi_mc_alloc_unconfigured(sys_data_t *sys, unsigned char ipmb,
			   lmc_data_t **rmc)
{
    lmc_data_t *mc;
    unsigned int i;
    
    mc = sys->ipmb_addrs[ipmb];
    if (mc) {
	if (mc->configured) {
	    sys->log(sys, SETUP_ERROR, NULL,
		     "MC IPMB specified twice: 0x%x.", ipmb);
	    return EBUSY;
	}
	goto out;
    }

    mc = malloc(sizeof(*mc));
    if (!mc)
	return ENOMEM;
    memset(mc, 0, sizeof(*mc));
    mc->ipmb = ipmb;
    sys->ipmb_addrs[ipmb] = mc;

    mc->startcmd.poweroff_wait_time = 60;
    mc->startcmd.kill_wait_time = 20;
    mc->startcmd.startnow = 0;

    for (i=0; i<=MAX_USERS; i++) {
	mc->users[i].idx = i;
    }

    mc->pef.num_event_filters = MAX_EVENT_FILTERS;
    for (i=0; i<MAX_EVENT_FILTERS; i++) {
	mc->pef.event_filter_table[i][0] = i;
	mc->pef.event_filter_data1[i][0] = i;
    }
    mc->pef.num_alert_policies = MAX_ALERT_POLICIES;
    for (i=0; i<MAX_ALERT_POLICIES; i++)
	mc->pef.alert_policy_table[i][0] = i;
    mc->pef.num_alert_strings = MAX_ALERT_STRINGS;
    for (i=0; i<MAX_ALERT_STRINGS; i++) {
	mc->pef.alert_string_keys[i][0] = i;
    }

 out:
    *rmc = mc;
    return 0;
}

static void
handle_tick(void *info, unsigned int seconds)
{
    lmc_data_t *mc = info;

    if (mc->startcmd.wait_poweroff) {
	if (mc->startcmd.vmpid == 0) {
	    mc->startcmd.wait_poweroff = 0;
	} else if (mc->startcmd.wait_poweroff > 0) {
	    /* Waiting for the first kill */
	    mc->startcmd.wait_poweroff--;
	    if (mc->startcmd.wait_poweroff == 0) {
		ipmi_do_kill(&mc->startcmd, 0);
		mc->startcmd.wait_poweroff = -mc->startcmd.kill_wait_time;
	    }
	} else {
	    mc->startcmd.wait_poweroff++;
	    if (mc->startcmd.wait_poweroff == 0)
		ipmi_do_kill(&mc->startcmd, 1);
	}
    }
}

static void
handle_child_quit(void *info, pid_t pid)
{
    lmc_data_t *mc = info;

    if (mc->startcmd.vmpid == pid) {
	mc->startcmd.vmpid = 0;
	mc->startcmd.wait_poweroff = 0;
    }
}

int
ipmi_emu_add_mc(emu_data_t    *emu,
		unsigned char ipmb,
		unsigned char device_id,
		unsigned char has_device_sdrs,
		unsigned char device_revision,
		unsigned char major_fw_rev,
		unsigned char minor_fw_rev,
		unsigned char device_support,
		unsigned char mfg_id[3],
		unsigned char product_id[2],
		unsigned char dynamic_sensor_population)
{
    lmc_data_t     *mc;
    struct timeval t;
    int            i;
    sys_data_t     *sys = emu->sysinfo;

    i = ipmi_mc_alloc_unconfigured(sys, ipmb, &mc);
    if (i)
	return i;

    mc->sysinfo = sys;
    mc->emu = emu;
    mc->ipmb = ipmb;

    mc->device_id = device_id;
    mc->has_device_sdrs = has_device_sdrs;
    mc->device_revision = device_revision;
    mc->major_fw_rev = major_fw_rev;
    mc->minor_fw_rev = minor_fw_rev;
    mc->device_support = device_support;
    mc->dynamic_sensor_population = dynamic_sensor_population;
    memcpy(mc->mfg_id, mfg_id, 3);
    memcpy(mc->product_id, product_id, 2);

    /* Enable the event log by default. */
    mc->global_enables = 1 << IPMI_MC_EVENT_LOG_BIT;

    /* Start the time at zero. */
    gettimeofday(&t, NULL);
    mc->sel.time_offset = 0;
    mc->main_sdrs.time_offset = 0;
    mc->main_sdrs.next_entry = 1;
    mc->main_sdrs.flags |= IPMI_SDR_RESERVE_SDR_SUPPORTED;
    for (i=0; i<4; i++) {
	mc->device_sdrs[i].time_offset = 0;
	mc->device_sdrs[i].next_entry = 1;
    }

    mc->event_receiver = sys->bmc_ipmb;
    mc->event_receiver_lun = 0;

    mc->hs_sensor = NULL;

    if (emu->atca_mode) {
	mc->num_leds = 2;

	/* By default only blue LED has local control. */
	mc->leds[0].loc_cnt = 1;
	mc->leds[0].loc_cnt_sup = 1;

	mc->leds[0].def_loc_cnt_color = 1; /* Blue LED */
	mc->leds[0].def_override_color = 1;
	mc->leds[0].color_sup = 0x2;
	mc->leds[0].color = 0x1;

	for (i=1; i<MAX_LEDS; i++) {
	    /* Others default to red */
	    mc->leds[i].def_loc_cnt_color = 2;
	    mc->leds[i].def_override_color = 2;
	    mc->leds[i].color_sup = 0x2;
	    mc->leds[i].color = 0x2;
	}
    }

    mc->ipmb_channel.medium_type = IPMI_CHANNEL_MEDIUM_IPMB;
    mc->ipmb_channel.channel_num = 0;
    mc->ipmb_channel.protocol_type = IPMI_CHANNEL_PROTOCOL_IPMB;
    mc->ipmb_channel.session_support = IPMI_CHANNEL_SESSION_LESS;
    mc->ipmb_channel.active_sessions = 0;
    mc->channels[0] = &mc->ipmb_channel;

    if (ipmb == emu->sysinfo->bmc_ipmb) {
	int err;

	if (!mc->channels[15]) {
	    /* No one specified a system channel, make one up */
	    mc->sys_channel.medium_type = IPMI_CHANNEL_MEDIUM_SYS_INTF;
	    mc->sys_channel.channel_num = 15;
	    mc->sys_channel.protocol_type = IPMI_CHANNEL_PROTOCOL_KCS;
	    mc->sys_channel.session_support = IPMI_CHANNEL_SESSION_LESS;
	    mc->sys_channel.active_sessions = 0;
	    mc->channels[15] = &mc->sys_channel;
	}

	mc->sysinfo = emu->sysinfo;
	err = init_sys(emu, mc);
    }

    if (mc->startcmd.startcmd) {
	mc->child_quit_handler.info = mc;
	mc->child_quit_handler.handler = handle_child_quit;
	ipmi_register_child_quit_handler(&mc->child_quit_handler);
	mc->tick_handler.info = mc;
	mc->tick_handler.handler = handle_tick;
	ipmi_register_tick_handler(&mc->tick_handler);
	mc->channels[15]->start_cmd = chan_start_cmd;
	mc->channels[15]->stop_cmd = chan_stop_cmd;
    }

    mc->configured = 1;

    return 0;
}

void
ipmi_mc_set_device_id(lmc_data_t *mc, unsigned char device_id)
{
    mc->device_id = device_id;
}

unsigned char
ipmi_mc_get_device_id(lmc_data_t *mc)
{
    return mc->device_id;
}

void
ipmi_set_has_device_sdrs(lmc_data_t *mc, unsigned char has_device_sdrs)
{
    mc->has_device_sdrs = has_device_sdrs;
}

unsigned char
ipmi_get_has_device_sdrs(lmc_data_t *mc)
{
    return mc->has_device_sdrs;
}

void
ipmi_set_device_revision(lmc_data_t *mc, unsigned char device_revision)
{
    mc->device_revision = device_revision;
}

unsigned char
ipmi_get_device_revision(lmc_data_t *mc)
{
    return mc->device_revision;
}

void
ipmi_set_major_fw_rev(lmc_data_t *mc, unsigned char major_fw_rev)
{
    mc->major_fw_rev = major_fw_rev;
}

unsigned char
ipmi_get_major_fw_rev(lmc_data_t *mc)
{
    return mc->major_fw_rev;
}

void
ipmi_set_minor_fw_rev(lmc_data_t *mc, unsigned char minor_fw_rev)
{
    mc->minor_fw_rev = minor_fw_rev;
}

unsigned char
ipmi_get_minor_fw_rev(lmc_data_t *mc)
{
    return mc->minor_fw_rev;
}

void
ipmi_set_device_support(lmc_data_t *mc, unsigned char device_support)
{
    mc->device_support = device_support;
}

unsigned char
ipmi_get_device_support(lmc_data_t *mc)
{
    return mc->device_support;
}

void
ipmi_set_mfg_id(lmc_data_t *mc, unsigned char mfg_id[3])
{
    memcpy(mc->mfg_id, mfg_id, 3);
}

void
ipmi_get_mfg_id(lmc_data_t *mc, unsigned char mfg_id[3])
{
    memcpy(mfg_id, mc->mfg_id, 3);
}

void
ipmi_set_product_id(lmc_data_t *mc, unsigned char product_id[2])
{
    memcpy(mc->product_id, product_id, 2);
}

void
ipmi_set_chassis_control_prog(lmc_data_t *mc, char *prog)
{
    mc->chassis_control_prog = prog;
}

void
ipmi_mc_set_chassis_control_func(lmc_data_t *mc,
				 int (*set)(lmc_data_t *mc, int op,
					    unsigned char val,
					    void *cb_data),
				 int (*get)(lmc_data_t *mc, int op,
					    unsigned char *val,
					    void *cb_data),
				 void *cb_data)
{
    mc->chassis_control_set_func = set;
    mc->chassis_control_get_func = get;
    mc->chassis_control_cb_data = cb_data;
}

void
ipmi_get_product_id(lmc_data_t *mc, unsigned char product_id[2])
{
    memcpy(product_id, mc->product_id, 2);
}

int
ipmi_emu_get_mc_by_addr(emu_data_t *emu, unsigned char ipmb, lmc_data_t **mc)
{
    if (!emu->sysinfo->ipmb_addrs[ipmb])
	return ENOSYS;
    *mc = emu->sysinfo->ipmb_addrs[ipmb];
    return 0;
}

int
ipmi_emu_set_bmc_mc(emu_data_t *emu, unsigned char ipmb)
{
    lmc_data_t *mc;

    if (ipmb & 1)
	return EINVAL;
    emu->sysinfo->bmc_ipmb = ipmb;
    if (!ipmi_emu_get_mc_by_addr(emu, ipmb, &mc))
	mc->sysinfo = emu->sysinfo;
    return 0;
}

lmc_data_t *
ipmi_emu_get_bmc_mc(emu_data_t *emu)
{
    lmc_data_t *mc;
    
    if (!ipmi_emu_get_mc_by_addr(emu, emu->sysinfo->bmc_ipmb, &mc))
	return mc;
    return NULL;
}

void
emu_set_debug_level(emu_data_t *emu, unsigned int debug_level)
{
    emu->sysinfo->debug = debug_level;
}
