/*
 * serial_ipmi.c
 *
 * MontaVista IPMI LAN server serial port interface.
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

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/serserv.h>

#define EVENT_BUFFER_GLOBAL_ENABLE	(1 << 2)
#define EVENT_LOG_GLOBAL_ENABLE		(1 << 3)
#define SUPPORTED_GLOBAL_ENABLES	(EVENT_BUFFER_GLOBAL_ENABLE | \
					 EVENT_LOG_GLOBAL_ENABLE)

static unsigned char hex2char[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

static int fromhex(unsigned char c)
{
    if (isdigit(c))
	return c - '0';
    else if (isxdigit(c))
	return tolower(c) - 'a' + 10;
    else
	return -1;
}

static unsigned char
ipmb_checksum(const unsigned char *data, int size)
{
	unsigned char csum = 0;

	for (; size > 0; size--, data++)
		csum += *data;

	return -csum;
}

static int
unformat_ipmb_msg(msg_t *msg, unsigned char *msgd, unsigned int len,
		  serserv_data_t *si)
{
    if (len < 7) {
	fprintf(stderr, "Message too short\n");
	return -1;
    }

    if (ipmb_checksum(msgd, len) != 0) {
	fprintf(stderr, "Message checksum failure\n");
	return -1;
    }
    len--;

    msg->rs_addr = msgd[0];
    msg->netfn = msgd[1] >> 2;
    msg->rs_lun = msgd[1] & 3;
    msg->rq_addr = msgd[3];
    msg->rq_seq = msgd[4] >> 2;
    msg->rq_lun = msgd[4] & 3;
    msg->cmd = msgd[5];

    msg->len = len - 6;
    msg->data = msgd + 6;

    msg->src_addr = NULL;
    msg->src_len = 0;

    return 0;
}

static void
format_ipmb_rsp(msg_t *msg, unsigned char *msgd,
		unsigned int *msgd_len, serserv_data_t *mi)
{
    msgd[0] = msg->rs_addr;
    msgd[1] = (msg->netfn << 2) | msg->rs_lun;
    msgd[2] = ipmb_checksum(msgd, 2);
    msgd[3] = msg->rq_addr;
    msgd[4] = (msg->rq_seq << 2) | msg->rq_lun;
    msgd[5] = msg->cmd;
    memcpy(msgd + 6, msg->data, msg->len);
    *msgd_len = msg->len + 6;
    msgd[*msgd_len] = ipmb_checksum(msgd + 3, (*msgd_len) - 3);
    (*msgd_len)++;
}

static void
queue_ipmb(msg_t *msg, serserv_data_t *si)
{
    if (si->do_attn)
	si->send_out(si, si->attn_chars, si->attn_chars_len);
}

static void
queue_event(msg_t *emsg, serserv_data_t *si)
{
    if (si->do_attn)
	si->send_out(si, si->attn_chars, si->attn_chars_len);
}

/***********************************************************************
 *
 * Radisys ASCII codec.
 *
 ***********************************************************************/

#define RA_MAX_CHARS_SIZE (((IPMI_SIM_MAX_MSG_LENGTH + 1) * 3) + 4)

struct ra_data {
    unsigned char recv_chars[RA_MAX_CHARS_SIZE];
    unsigned int  recv_chars_len;
    int           recv_chars_too_many;
};

static void ra_format_msg(const unsigned char *msg, unsigned int msg_len,
			  serserv_data_t *si)
{
    unsigned int i;
    unsigned int len;
    unsigned char c[RA_MAX_CHARS_SIZE];

    len = 0;
    for (i = 0; i < msg_len; i++) {
	c[len] = hex2char[msg[i] >> 4];
	len++;
	c[len] = hex2char[msg[i] & 0xf];
	len++;
    }
    c[len] = 0x0d;
    len++;

    si->send_out(si, c, len);
}

static void
ra_ipmb_handler(msg_t *msg, serserv_data_t *si)
{
    /* FIXME - this is not right */
    ra_format_msg(msg->data, msg->len, si);
}

/*
 * Called when the '0x0d' is seen.
 */
static int ra_unformat_msg(unsigned char *r, unsigned int len,
			   serserv_data_t *si)
{
    unsigned char o[IPMI_SIM_MAX_MSG_LENGTH];
    msg_t msg;
    unsigned int p = 0;
    unsigned int i = 0;
    int          rv;

    while (p < len) {
	rv = fromhex(r[p]);
	if (rv < 0)
	    return rv;
	o[i] = rv << 4;
	p++;
	if (p >= len)
	    return -1;
	rv = fromhex(r[p]);
	if (rv < 0)
	    return rv;
	o[i] |= rv;
	p++;
	i++;
    }

    rv = unformat_ipmb_msg(&msg, o, i, si);
    if (rv)
	return rv;
    if ((msg.rs_addr == si->bmcinfo->bmc_ipmb) || (msg.rs_addr == 1))
	channel_smi_send(&si->channel, &msg);
    else {
	/* FIXME - handle_ipmb_msg(o + p, i, mi, mi); */
    }
    return 0;
}

static void
ra_handle_char(unsigned char ch, serserv_data_t *si)
{
    struct ra_data *info = si->codec_info;
    unsigned int len = info->recv_chars_len;
    unsigned char *r;
    int           rv;

    if (ch == 0x0d) {
	/* End of command, handle it. */
	if (info->recv_chars_too_many) {
	    /* Input data overrun. */
	    fprintf(stderr, "Data overrun\n");
	    info->recv_chars_too_many = 0;
	    info->recv_chars_len = 0;
	    return;
	}
	rv = ra_unformat_msg(info->recv_chars, info->recv_chars_len, si);
	info->recv_chars_too_many = 0;
	info->recv_chars_len = 0;
	if (rv) {
	    /* Bad input data. */
	    fprintf(stderr, "Bad input data\n");
	    return;
	}
	return;
    }

    if (info->recv_chars_too_many)
	return;

    r = info->recv_chars;

    if (len >= sizeof(info->recv_chars)) {
	info->recv_chars_too_many = 1;
    } else if ((len > 0) && isspace(r[len-1]) && isspace(ch)) {
	/* Ignore multiple spaces together. */
    } else {
	r[len] = ch;
	info->recv_chars_len++;
    }
}

static void
ra_send(msg_t *omsg, serserv_data_t *si)
{
    unsigned char msg[IPMI_SIM_MAX_MSG_LENGTH + 7];
    unsigned int msg_len;

    format_ipmb_rsp(omsg, msg, &msg_len, si);

    ra_format_msg(msg, msg_len, si);
}

int
ra_setup(serserv_data_t *si)
{
    struct ra_data *info;
    info = malloc(sizeof(*info));
    if (!info)
	return -1;

    info->recv_chars_len = 0;
    info->recv_chars_too_many = 0;
    si->codec_info = info;
    return 0;
}

/***********************************************************************
 *
 * Direct Mode codec.
 *
 ***********************************************************************/

#define DM_START_CHAR		0xA0
#define DM_STOP_CHAR		0xA5
#define DM_PACKET_HANDSHAKE	0xA6
#define DM_DATA_ESCAPE_CHAR	0xAA

struct dm_data {
    unsigned char recv_msg[IPMI_SIM_MAX_MSG_LENGTH + 4];
    unsigned int  recv_msg_len;
    int           recv_msg_too_many;
    int           in_recv_msg;
    int           in_escape;
};

static void
dm_handle_msg(unsigned char *imsg, unsigned int len, serserv_data_t *si)
{
    int rv;
    msg_t msg;

    rv = unformat_ipmb_msg(&msg, imsg, len, si);
    if (rv)
	return;
    channel_smi_send(&si->channel, &msg);
}

static void
dm_handle_char(unsigned char ch, serserv_data_t *si)
{
    struct dm_data *info = si->codec_info;
    unsigned int len = info->recv_msg_len;
    unsigned char c;

    switch (ch) {
    case DM_START_CHAR:
	if (info->in_recv_msg)
	    fprintf(stderr, "Msg started in the middle of another\n");
	info->in_recv_msg = 1;
	info->recv_msg_len = 0;
	info->recv_msg_too_many = 0;
	info->in_escape = 0;
	break;

    case DM_STOP_CHAR:
	if (!info->in_recv_msg)
	    fprintf(stderr, "Empty message\n");
	else if (info->in_escape) {
	    info->in_recv_msg = 0;
	    fprintf(stderr, "Message ended in escape\n");
	} else if (info->recv_msg_too_many) {
	    fprintf(stderr, "Message too long\n");
	    info->in_recv_msg = 0;
	} else {
	    dm_handle_msg(info->recv_msg, info->recv_msg_len, si);
	    info->in_recv_msg = 0;
	}
	info->in_escape = 0;

	c = DM_PACKET_HANDSHAKE;
	si->send_out(si, &c, 1);
	break;

    case DM_PACKET_HANDSHAKE:
	info->in_escape = 0;
	break;

    case DM_DATA_ESCAPE_CHAR:
	if (!info->recv_msg_too_many)
	    info->in_escape = 1;
	break;

    default:
	if (!info->in_recv_msg)
	    /* Ignore characters outside of messages. */
	    break;

	if (info->in_escape) {
	    info->in_escape = 0;
	    switch (ch) {
	    case 0xB0: ch = DM_START_CHAR; break;
	    case 0xB5: ch = DM_STOP_CHAR; break;
	    case 0xB6: ch = DM_PACKET_HANDSHAKE; break;
	    case 0xBA: ch = DM_DATA_ESCAPE_CHAR; break;
	    case 0x3B: ch = 0x1b; break;
	    default:
		fprintf(stderr, "Invalid escape char: 0x%x\n", ch);
		info->recv_msg_too_many = 1;
		return;
	    }
	}

	if (!info->recv_msg_too_many) {
	    if (len >= sizeof(info->recv_msg)) {
		info->recv_msg_too_many = 1;
		break;
	    }
	    
	    info->recv_msg[len] = ch;
	    info->recv_msg_len++;
	}
	break;
    }
}

static void
dm_send(msg_t *imsg, serserv_data_t *si)
{
    unsigned int i;
    unsigned int len = 0;
    unsigned char c[(IPMI_SIM_MAX_MSG_LENGTH + 7) * 2];
    unsigned char msg[IPMI_SIM_MAX_MSG_LENGTH + 7];
    unsigned int msg_len;

    format_ipmb_rsp(imsg, msg, &msg_len, si);

    c[len++] = 0xA0;
    for (i = 0; i < msg_len; i++) {
	switch (msg[i]) {
	case 0xA0:
	    c[len++] = 0xAA;
	    c[len++] = 0xB0;
	    break;

	case 0xA5:
	    c[len++] = 0xAA;
	    c[len++] = 0xB5;
	    break;

	case 0xA6:
	    c[len++] = 0xAA;
	    c[len++] = 0xB6;
	    break;

	case 0xAA:
	    c[len++] = 0xAA;
	    c[len++] = 0xBA;
	    break;

	case 0x1B:
	    c[len++] = 0xAA;
	    c[len++] = 0x3B;
	    break;

	default:
	    c[len++] = msg[i];
	}

    }
    c[len++] = 0xA5;

    si->send_out(si, c, len);
}

static int
dm_setup(serserv_data_t *si)
{
    struct dm_data *info;

    info = malloc(sizeof(*info));
    if (!info)
	return -1;
    memset(info, 0, sizeof(*info));
    si->codec_info = info;
    return 0;
}


/***********************************************************************
 *
 * Terminal Mode codec.
 *
 ***********************************************************************/

#define TM_MAX_CHARS_SIZE (((IPMI_SIM_MAX_MSG_LENGTH + 1) * 3) + 4)

struct tm_data {
    unsigned char recv_chars[TM_MAX_CHARS_SIZE];
    unsigned int  recv_chars_len;
    int           recv_chars_too_many;
};

static void
tm_send(msg_t *msg, serserv_data_t *si)
{
    unsigned int i;
    unsigned int len;
    unsigned char c[TM_MAX_CHARS_SIZE];
    unsigned char t;

    len = 0;
    c[len] = '[';
    len++;

    t = msg->netfn << 2 | msg->rs_lun;
    c[len] = hex2char[t >> 4];
    len++;
    c[len] = hex2char[t & 0xf];
    len++;

    /*
     * Insert the sequence number and bridge bits.  Bridge bits
     * are always zero.
     */
    t = msg->rq_seq << 2;
    c[len] = hex2char[t >> 4];
    len++;
    c[len] = hex2char[t & 0xf];
    len++;

    c[len] = hex2char[msg->cmd >> 4];
    len++;
    c[len] = hex2char[msg->cmd & 0xf];
    len++;

    /* Now the rest of the message. */
    for (i = 0; ; ) {
	c[len] = hex2char[msg->data[i] >> 4];
	len++;
	c[len] = hex2char[msg->data[i] & 0xf];
	len++;
	i++;
	if (i == msg->len)
	    break;
	c[len] = ' ';
	len++;
    }
    c[len] = ']';
    len++;
    c[len] = 0x0a;
    len++;

    si->send_out(si, c, len);
}

/*
 * Called when the ']' is seen, the leading '[' is removed, too.  We
 * get this with a leading space and no more than one space between
 * items.
 */
static int tm_unformat_msg(unsigned char *r, unsigned int len,
			   serserv_data_t *si)
{
    unsigned char o[IPMI_SIM_MAX_MSG_LENGTH];
    msg_t         msg;
    unsigned int  p = 0;
    unsigned int  i = 0;
    int           rv;

#define SKIP_SPACE if (isspace(r[p])) p++
#define ENSURE_MORE if (p >= len) return -1

	SKIP_SPACE;
	while (p < len) {
		if (i >= sizeof(o))
			return -1;
		ENSURE_MORE;
		rv = fromhex(r[p]);
		if (rv < 0)
			return rv;
		o[i] = rv << 4;
		p++;
		ENSURE_MORE;
		rv = fromhex(r[p]);
		if (rv < 0)
			return rv;
		o[i] |= rv;
		p++;
		i++;
		SKIP_SPACE;
	}

	if (i < 3)
	    return -1;

	msg.netfn = o[0] >> 2;
	msg.rq_lun = o[0] & 3;
	msg.rq_seq = o[1] >> 2;
	msg.cmd = o[2];
	msg.data = o + 3;
	msg.len = i - 3;
	msg.src_addr = NULL;
	msg.src_len = 0;

	channel_smi_send(&si->channel, &msg);
	return 0;
#undef SKIP_SPACE
#undef ENSURE_MORE
}

static void
tm_handle_char(unsigned char ch, serserv_data_t *si)
{
    struct tm_data *info = si->codec_info;
    unsigned int len = info->recv_chars_len;
    unsigned char *r;
    int           rv;

    if (ch == '[') {
	/*
	 * Start of a command.  Note that if a command is
	 * already in progress (len != 0) we abort it.
	 */
	if (len != 0)
	    fprintf(stderr, "Msg started in the middle of another\n");
	
	/* Convert the leading '[' to a space, that's innocuous. */
	info->recv_chars[0] = ' ';
	info->recv_chars_len = 1;
	info->recv_chars_too_many = 0;
	return;
    }

    if (len == 0)
	/* Ignore everything outside [ ]. */
	return;

    if (ch == ']') {
	/* End of command, handle it. */
	if (info->recv_chars_too_many) {
	    /* Input data overrun. */
	    fprintf(stderr, "Data overrun\n");
	    info->recv_chars_too_many = 0;
	    info->recv_chars_len = 0;
	    return;
	}
	rv = tm_unformat_msg(info->recv_chars, info->recv_chars_len, si);
	info->recv_chars_too_many = 0;
	info->recv_chars_len = 0;
	if (rv) {
	    /* Bad input data. */
	    fprintf(stderr, "Bad input data\n");
	    return;
	}
	return;
    }

    if (info->recv_chars_too_many)
	return;

    r = info->recv_chars;

    if (len >= sizeof(info->recv_chars)) {
	info->recv_chars_too_many = 1;
    } else if ((len > 0) && isspace(r[len-1]) && isspace(ch)) {
	/* Ignore multiple spaces together. */
    } else {
	r[len] = ch;
	info->recv_chars_len++;
    }
}

static int
tm_setup(serserv_data_t *si)
{
    struct tm_data *info;

    info = malloc(sizeof(*info));
    if (!info)
	return -1;

    info->recv_chars_len = 0;
    info->recv_chars_too_many = 0;
    si->codec_info = info;
    return 0;
}


/***********************************************************************
 *
 * codec structure
 *
 ***********************************************************************/
static ser_codec_t codecs[] = {
    { "TerminalMode",
      tm_handle_char, tm_send, tm_setup, queue_event, queue_ipmb },
    { "Direct",
      dm_handle_char, dm_send, dm_setup, queue_event, queue_ipmb },
    { "RadisysAscii",
      ra_handle_char, ra_send, ra_setup, NULL, ra_ipmb_handler },
    { NULL }
};

static ser_codec_t *
ser_lookup_codec(char *name)
{
    unsigned int i;

    for (i = 0; codecs[i].name; i++) {
	if (strcmp(codecs[i].name, name) == 0)
	    return &codecs[i];
    }
    return NULL;
}

#define PP_GET_SERIAL_INTF_CMD	0x01
#define PP_SET_SERIAL_INTF_CMD	0x02
static unsigned char pp_oem_chars[] = { 0x00, 0x40, 0x0a };
static int
pp_oem_handler(channel_t *chan, msg_t *msg, unsigned char *rdata,
	       unsigned int *rdata_len)
{
    serserv_data_t *ser = chan->chan_info;

    if (msg->netfn != IPMI_OEM_GROUP_NETFN)
	return 0;

    if ((msg->len < 3) || (memcmp(msg->data, pp_oem_chars, 3) != 0))
	return 0;
		     
    switch (msg->cmd) {
    case PP_GET_SERIAL_INTF_CMD:
	rdata[0] = 0;
	memcpy(rdata + 1, pp_oem_chars, 3);
	rdata[4] = 0;
	if (msg->data[3] == 1)
	    rdata[4] |= ser->echo;
	*rdata_len = 5;
	return 1;

    case PP_SET_SERIAL_INTF_CMD:
	if (msg->len < 5)
	    rdata[0] = 0xcc;
	else if (msg->data[3] == 1) {
	    ser->echo = msg->data[4] & 1;
	    rdata[0] = 0;
	}
	memcpy(rdata + 1, pp_oem_chars, 3);
	*rdata_len = 4;
	return 1;
    }

    return 0;
}

static void
pp_oem_init(serserv_data_t *ser)
{
    ser->echo = 1;
    ser->channel.oem_intf_recv_handler = pp_oem_handler;
}

#define RA_CONTROLLER_OEM_NETFN	0x3e
#define RA_GET_IPMB_ADDR_CMD	0x12
static int
ra_oem_handler(channel_t *chan, msg_t *msg, unsigned char *rdata,
	       unsigned int *rdata_len)
{
    serserv_data_t *ser = chan->chan_info;

    if (msg->netfn == RA_CONTROLLER_OEM_NETFN) {
	switch (msg->cmd) {
	case RA_GET_IPMB_ADDR_CMD:
	    rdata[0] = 0;
	    rdata[1] = ser->my_ipmb;
	    *rdata_len = 2;
	    return 1;
	}
    } else if (msg->netfn == IPMI_APP_NETFN) {
	switch (msg->cmd) {
	case IPMI_GET_MSG_FLAGS_CMD:
	    /* No message flag support. */
	    rdata[0] = 0xc1;
	    *rdata_len = 1;
	    return 1;
	}
    }

    return 0;
}

static void
ra_oem_init(serserv_data_t *ser)
{
    ser->channel.oem_intf_recv_handler = ra_oem_handler;
}

static ser_oem_handler_t oem_handlers[] = {
    { "PigeonPoint",		pp_oem_handler,		pp_oem_init },
    { "Radisys",		ra_oem_handler,		ra_oem_init },
    { NULL }
};

static ser_oem_handler_t *
ser_lookup_oem(char *name)
{
    unsigned int i;

    for (i = 0; oem_handlers[i].name; i++) {
	if (strcmp(oem_handlers[i].name, name) == 0)
	    return &oem_handlers[i];
    }
    return NULL;
}

static void
ser_return_rsp(channel_t *chan, msg_t *imsg, rsp_msg_t *rsp)
{
    serserv_data_t *ser = chan->chan_info;
    msg_t msg;

    msg.netfn = rsp->netfn;
    msg.cmd = rsp->cmd;
    msg.data = rsp->data;
    msg.len = rsp->data_len;
    msg.rq_lun = imsg->rs_lun;
    msg.rq_addr = imsg->rs_addr;
    msg.rs_lun = imsg->rq_lun;
    msg.rs_addr = imsg->rq_addr;
    msg.rq_seq = imsg->rq_seq;
    ser->codec->send(&msg, ser);
}

void
serserv_handle_data(serserv_data_t *ser, uint8_t *data, unsigned int len)
{
    unsigned int i;

    for (i = 0; i < len; i++)
	ser->codec->handle_char(data[i], ser);
}

int
serserv_init(serserv_data_t *ser)
{
    ser->channel.return_rsp = ser_return_rsp;

    ser->codec->setup(ser);
    if (ser->oem)
	ser->oem->init(ser);

    chan_init(&ser->channel);
    return 0;
}

int
serserv_read_config(char **tokptr, bmc_data_t *bmc, char **errstr)
{
    serserv_data_t *ser;
    char *tok, *tok2, *endp;
    int err;
    unsigned int chan_num;

printf("Reading config\n");
    ser = malloc(sizeof(*ser));
    if (!ser) {
	*errstr = "Out of memory";
	return -1;
    }
    memset(ser, 0, sizeof(*ser));

    tok = strtok_r(NULL, " \t\n", tokptr);
    if (!tok) {
	*errstr = "No channel given";
	goto out_err;
    }
    ser->channel.session_support = IPMI_CHANNEL_SESSION_LESS;
    ser->channel.medium_type = IPMI_CHANNEL_MEDIUM_RS232;
    if (strcmp(tok, "kcs") == 0) {
	chan_num = 15;
	ser->channel.protocol_type = IPMI_CHANNEL_PROTOCOL_KCS;
    } else if (strcmp(tok, "bt") == 0) {
	chan_num = 15;
	ser->channel.protocol_type = IPMI_CHANNEL_PROTOCOL_BT_v15;
    } else if (strcmp(tok, "smic") == 0) {
	chan_num = 15;
	ser->channel.protocol_type = IPMI_CHANNEL_PROTOCOL_SMIC;
    } else {
	chan_num = strtoul(tok, &endp, 0);
	if (*endp != '\0') {
	    *errstr = "Channel not a valid number";
	    goto out_err;
	}
	ser->channel.protocol_type = IPMI_CHANNEL_PROTOCOL_TMODE;
    }
    if (chan_num != 15) {
	*errstr = "Only BMC channel (channel 15, or kcs/bt/smic) is"
	    " supported for serial";
	goto out_err;
    }

    if (bmc->channels[chan_num] != &bmc->sys_channel) {
	*errstr = "System channel already defined";
	goto out_err;
    }
    ser->channel.channel_num = chan_num;

    err = get_sock_addr(tokptr, &ser->addr.addr, &ser->addr.addr_len,
			NULL, errstr);
    if (err)
	return err;

    tok = strtok_r(NULL, " \t\n", tokptr);
    while (tok) {
	if (strcmp(tok, "connect") == 0) {
	    ser->do_connect = 1;
	    continue;
	}

	tok2 = strtok_r(NULL, " \t\n", tokptr);
	if (strcmp(tok, "codec") == 0) {
	    if (!tok2) {
		*errstr = "Missing parameter for codec";
		return -1;
	    }
	    ser->codec = ser_lookup_codec(tok2);
	    if (!ser->codec) {
		*errstr = "Invalid codec";
		return -1;
	    }
	} else if (strcmp(tok, "oem") == 0) {
	    if (!tok2) {
		*errstr = "Missing parameter for oem";
		return -1;
	    }
	    ser->oem = ser_lookup_oem(tok2);
	    if (!ser->oem) {
		*errstr = "Invalid oem setting";
		return -1;
	    }
	} else if (strcmp(tok, "attn") == 0) {
	    unsigned int pos = 0;
	    char *tokptr2 = NULL;

	    if (!tok2) {
		*errstr = "Missing parameter for attn";
		return -1;
	    }

	    ser->do_attn = 1;
	    tok2 = strtok_r(tok2, ",", &tokptr2);
	    while (tok2) {
		if (pos >= sizeof(ser->attn_chars)) {
		    *errstr = "Too many attn characters";
		    return -1;
		}
		ser->attn_chars[pos] = strtoul(tok2, &endp, 0);
		if (*endp != '\0') {
		    *errstr = "Invalid attn value";
		    return -1;
		}
		pos++;
		tok2 = strtok_r(NULL, ",", &tokptr2);
	    }
	    ser->attn_chars_len = pos;
	} else if (strcmp(tok, "ipmb") == 0) {
	    char *endp;
	    ser->my_ipmb = strtoul(tok2, &endp, 0);
	    if (*endp != '\0') {
		*errstr = "Invalid IPMB address";
		return -1;
	    }
	} else {
	    *errstr = "Invalid setting, not connect, codec, oem, attn, or ipmb";
	    return -1;
	}

	tok = strtok_r(NULL, " \t\n", tokptr);
    }

    if (!ser->codec) {
	*errstr = "codec not specified";
	goto out_err;
    }

    ser->bmcinfo = bmc;
    ser->channel.chan_info = ser;

    bmc->channels[chan_num] = &ser->channel;
    return 0;

 out_err:
    free(ser);
    return -1;
}
