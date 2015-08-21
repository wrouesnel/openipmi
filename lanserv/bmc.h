/*
 * bmc.h
 *
 * MontaVista IPMI LAN server include file
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2012 MontaVista Software Inc.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * Lesser General Public License (GPL) Version 2 or the modified BSD
 * license below.  The following disclamer applies to both licenses:
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
 * GNU Lesser General Public Licence
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Modified BSD Licence
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *   3. The name of the author may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 */

#ifndef __BMC_H_
#define __BMC_H_

#include <stdint.h>
#include <semaphore.h>
#include <OpenIPMI/mcserv.h>
#include "emu.h"

#define WATCHDOG_SENSOR_NUM 0

#define OPENIPMI_IANA		40820 /* OpenIPMI's own number */

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
    lmc_data_t *mc;

    unsigned char num;
    unsigned int  lun              : 2;
    unsigned int  scanning_enabled : 1;
    unsigned int  events_enabled   : 1;
    unsigned int  enabled          : 1;

    unsigned char sensor_type;
    unsigned char event_reading_code;

    unsigned char value;

    unsigned char hysteresis_support;
    unsigned char positive_hysteresis;
    unsigned char negative_hysteresis;

    unsigned char threshold_support;
    uint16_t threshold_supported; /* Bitmask */
    unsigned char thresholds[6];

    int event_only;

    unsigned char event_support;

    /* 0 for assertion, 1 for deassertion. */
    uint16_t event_supported[2];
    uint16_t event_enabled[2];
    int (*rearm_handler)(void *cb_data, uint16_t assert, uint16_t deassert);
    void *rearm_cb_data;


    /* Current bit values */
    uint16_t event_status;

    /* Called when the sensor changes values. */
    void (*sensor_update_handler)(lmc_data_t *mc, sensor_t *sensor);

    ipmi_timer_t *poll_timer;
    struct timeval poll_timer_time;
    int (*poll)(void *cb_data, unsigned int *val, const char **errstr);
    void *cb_data;
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
    unsigned int   devid;
    fru_io_cb      fru_io_cb;
    unsigned int   length;
    unsigned char  *data;
    fru_session_t  *sessions;
    get_frudata_f  get;
    free_frudata_f free;
    sem_t          sem;
    fru_data_t     *next;
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
    unsigned char aux_fw_rev[4];   /* bytes 13-16 */

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

    fru_data_t *frulist;

    ipmi_sol_t sol;

    int (*chassis_control_set_func)(lmc_data_t *mc, int op, unsigned char *val,
				    void *cb_data);
    int (*chassis_control_get_func)(lmc_data_t *mc, int op, unsigned char *val,
				    void *cb_data);
    ipmi_timer_t *power_timer;
    void *chassis_control_cb_data;
    const char *chassis_control_prog;

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

/* Device ID support bits */
#define IPMI_DEVID_CHASSIS_DEVICE	(1 << 7)
#define IPMI_DEVID_BRIDGE		(1 << 6)
#define IPMI_DEVID_IPMB_EVENT_GEN	(1 << 5)
#define IPMI_DEVID_IPMB_EVENT_RCV	(1 << 4)
#define IPMI_DEVID_FRU_INVENTORY_DEV	(1 << 3)
#define IPMI_DEVID_SEL_DEVICE		(1 << 2)
#define IPMI_DEVID_SDR_REPOSITORY_DEV	(1 << 1)
#define IPMI_DEVID_SENSOR_DEV		(1 << 0)

fru_data_t *find_fru(lmc_data_t *mc, unsigned int devid);

int start_poweron_timer(lmc_data_t *mc);

sdr_t *find_sdr_by_recid(sdrs_t     *sdrs,
			 uint16_t   record_id,
			 sdr_t      **prev);

sdr_t *new_sdr_entry(sdrs_t *sdrs, unsigned char length);
void add_sdr_entry(lmc_data_t *mc, sdrs_t *sdrs, sdr_t *entry);
void read_mc_sdrs(lmc_data_t *mc, sdrs_t *sdrs, const char *sdrtype);

void iterate_sdrs(lmc_data_t *mc,
		  sdrs_t     *sdrs,
		  int (*func)(lmc_data_t *mc, unsigned char *sdr,
			      unsigned int len, void *cb_data),
		  void *cb_data);

void mc_new_event(lmc_data_t *mc,
		  unsigned char record_type,
		  unsigned char event[13]);

#define IPMI_SDR_DELETE_SDR_SUPPORTED			(1 << 3)
#define IPMI_SDR_PARTIAL_ADD_SDR_SUPPORTED		(1 << 2)
#define IPMI_SDR_RESERVE_SDR_SUPPORTED			(1 << 1)
#define IPMI_SDR_GET_SDR_ALLOC_INFO_SDR_SUPPORTED	(1 << 0)

void picmg_led_set(lmc_data_t *mc, sensor_t *sensor);
void set_sensor_bit(lmc_data_t *mc, sensor_t *sensor, unsigned char bit,
		    unsigned char value,
		    unsigned char evd1, unsigned char evd2, unsigned char evd3,
		    int gen_event);

void watchdog_timeout(void *cb_data);

extern cmd_handler_f storage_netfn_handlers[256];
extern cmd_handler_f app_netfn_handlers[256];
extern cmd_handler_f chassis_netfn_handlers[256];
extern cmd_handler_f transport_netfn_handlers[256];
extern cmd_handler_f sensor_event_netfn_handlers[256];
extern cmd_handler_f oem0_netfn_handlers[256];

void handle_picmg_msg(lmc_data_t    *mc,
		      msg_t         *msg,
		      unsigned char *rdata,
		      unsigned int  *rdata_len);

#define set_bit(m, b, v) (m) = (v) ? ((m) | (1 << (b))) : ((m) & ~(1 << (b)))
#define bit_set(m, b) (!!((m) & (1 << (b))))

#endif /* __BMC_H_ */
