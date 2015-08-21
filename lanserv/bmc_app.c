/*
 * bmc_app.c
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
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_lan.h>

static void
handle_get_device_id(lmc_data_t    *mc,
		     msg_t         *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len,
		     void          *cb_data)
{
    memset(rdata, 0, 12);
    rdata[1] = mc->device_id;
    rdata[2] = ((mc->has_device_sdrs << 0x7)
		| (mc->device_revision & 0xf));
    rdata[3] = mc->major_fw_rev & 0x7f;
    rdata[4] = mc->minor_fw_rev;
    rdata[5] = 0x02;
    rdata[6] = mc->device_support;
    memcpy(rdata+7, mc->mfg_id, 3);
    memcpy(rdata+10, mc->product_id, 2);
    memcpy(rdata+12, mc->aux_fw_rev, 4);
    *rdata_len = 16;
}

void
ipmi_mc_set_dev_revision(lmc_data_t *mc, unsigned char dev_revision)
{
    mc->device_revision = dev_revision;
}

void
ipmi_mc_set_fw_revision(lmc_data_t *mc, unsigned char fw_revision_major,
			unsigned char fw_revision_minor)
{
    mc->major_fw_rev = fw_revision_major;
    mc->minor_fw_rev = fw_revision_minor;
}

void
ipmi_mc_set_aux_fw_revision(lmc_data_t *mc, unsigned char aux_fw_revision[4])
{
    memcpy(mc->aux_fw_rev, aux_fw_revision, 4);
}

void
ipmi_mc_setfw_versions() {
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
			  unsigned int  *rdata_len,
			  void          *cb_data)
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
	mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &now);
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

void
watchdog_timeout(void *cb_data)
{
    lmc_data_t *mc = cb_data;
    channel_t *bchan = mc->channels[15];
    sensor_t *sens = mc->sensors[0][WATCHDOG_SENSOR_NUM];

    if (!mc->watchdog_running)
	goto out;

    if( !sens ) {
	// NOTE(noelbk): The watchdog sensor should have been defined
	// earlier, but don't SEGFAULT if it isn't
	goto out;
    }

    if (! mc->watchdog_preaction_ran) {
	struct timeval tv, now;

	switch (IPMI_MC_WATCHDOG_GET_PRE_ACTION(mc)) {
	case IPMI_MC_WATCHDOG_PRE_NMI:
	    mc->msg_flags |= IPMI_MC_MSG_FLAG_WATCHDOG_TIMEOUT_MASK;
	    bchan->hw_op(bchan, HW_OP_SEND_NMI);
	    set_sensor_bit(mc, sens, 8, 1, 0xc8, (2 << 4) | 0xf, 0xff, 1);
	    break;

	case IPMI_MC_WATCHDOG_PRE_MSG_INT:
	    mc->msg_flags |= IPMI_MC_MSG_FLAG_WATCHDOG_TIMEOUT_MASK;
	    if (bchan->set_atn && !IPMI_MC_MSG_FLAG_EVT_BUF_FULL_SET(mc))
		bchan->set_atn(bchan, 1, IPMI_MC_MSG_INTS_ON(mc));
	    set_sensor_bit(mc, sens, 8, 1, 0xc8, (3 << 4) | 0xf, 0xff, 1);
	    break;

	default:
	    goto do_full_expiry;
	}

	mc->watchdog_preaction_ran = 1;
	/* Issued the pretimeout, do the rest of the timeout now. */
	mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo, &now);
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
	set_sensor_bit(mc, sens, 0, 1, 0xc0, mc->watchdog_use & 0xf, 0xff, 1);
	break;

    case IPMI_MC_WATCHDOG_ACTION_RESET:
	set_sensor_bit(mc, sens, 1, 1, 0xc1, mc->watchdog_use & 0xf, 0xff, 1);
	bchan->hw_op(bchan, HW_OP_RESET);
	break;

    case IPMI_MC_WATCHDOG_ACTION_POWER_DOWN:
	set_sensor_bit(mc, sens, 2, 1, 0xc2, mc->watchdog_use & 0xf, 0xff, 1);
	bchan->hw_op(bchan, HW_OP_POWEROFF);
	break;

    case IPMI_MC_WATCHDOG_ACTION_POWER_CYCLE:
	set_sensor_bit(mc, sens, 3, 1, 0xc3, mc->watchdog_use & 0xf, 0xff, 1);
	bchan->hw_op(bchan, HW_OP_POWEROFF);
	start_poweron_timer(mc);
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
    mc->emu->sysinfo->get_monotonic_time(mc->emu->sysinfo,
					 &mc->watchdog_expiry);
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
			  unsigned int  *rdata_len,
			  void          *cb_data)
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
			    unsigned int  *rdata_len,
			    void          *cb_data)
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
    rdata[0] = 0x00;
    *rdata_len = 1;
}

static void
handle_get_channel_info(lmc_data_t    *mc,
			msg_t         *msg,
			unsigned char *rdata,
			unsigned int  *rdata_len,
			void          *cb_data)
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
			  unsigned int  *rdata_len,
			  void          *cb_data)
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
			  unsigned int  *rdata_len,
			  void          *cb_data)
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
			  unsigned int  *rdata_len,
			  void          *cb_data)
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
		       unsigned int  *rdata_len,
		       void          *cb_data)
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
		       unsigned int  *rdata_len,
		       void          *cb_data)
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
		     unsigned int  *rdata_len,
		     void          *cb_data)
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
		     unsigned int  *rdata_len,
		     void          *cb_data)
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
			 unsigned int  *rdata_len,
			 void          *cb_data)
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
			  unsigned int  *rdata_len,
			  void          *cb_data)
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
			     unsigned int  *rdata_len,
			     void          *cb_data)
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
		     unsigned int  *rdata_len,
		     void          *cb_data)
{
    rdata[0] = 0;
    rdata[1] = mc->msg_flags;
    *rdata_len = 2;
}

static void
handle_clear_msg_flags(lmc_data_t    *mc,
		       msg_t         *msg,
		       unsigned char *rdata,
		       unsigned int  *rdata_len,
		       void          *cb_data)
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
	       unsigned int  *rdata_len,
	       void          *cb_data)
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
	*rdata_len = 1;
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
				     unsigned int  *rdata_len,
				     void          *cb_data)
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
				 unsigned int  *rdata_len,
				 void          *cb_data)
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
				   unsigned int  *rdata_len,
				   void          *cb_data)
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
			unsigned int  *rdata_len,
			void          *cb_data)
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
			  unsigned int  *rdata_len,
			  void          *cb_data)
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

cmd_handler_f app_netfn_handlers[256] = {
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
