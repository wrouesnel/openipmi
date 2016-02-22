/*
 * lanserv_ipmi.c
 *
 * MontaVista IPMI IPMI LAN interface protocol engine
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2003,2004,2005 MontaVista Software Inc.
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

#include <config.h>

#include <string.h>
#include <stdlib.h>

#ifdef HAVE_OPENSSL
#include <openssl/hmac.h>
#endif

#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/lanserv.h>

#include <OpenIPMI/internal/md5.h>

#include <OpenIPMI/persist.h>
#include <OpenIPMI/extcmd.h>

static int
is_authval_null(uint8_t *val)
{
    int i;
    for (i=0; i<16; i++)
	if (val[i] != 0)
	    return 0;
    return 1;
}

static user_t *
find_user(lanserv_data_t *lan, uint8_t *user, int name_only_lookup, int priv)
{
    int    i;
    user_t *rv = NULL;

    for (i=1; i<=MAX_USERS; i++) {
	if (lan->users[i].valid
	    && (memcmp(user, lan->users[i].username, 16) == 0))
	{
	    if (name_only_lookup ||
		(lan->users[i].privilege == priv)) {
		rv = &(lan->users[i]);
		break;
	    }
	}
    }

    return rv;
}

static session_t *
sid_to_session(lanserv_data_t *lan, unsigned int sid)
{
    int       idx;
    session_t *session;

    if (sid & 1)
	return NULL;
    idx = (sid >> 1) & SESSION_MASK;
    if (idx > MAX_SESSIONS)
	return NULL;
    session = lan->sessions + idx;
    if (!session->active)
	return NULL;
    if (session->sid != sid)
	return NULL;
    return session;
}

static void
close_session(lanserv_data_t *lan, session_t *session)
{
    unsigned int i;

    for (i = 0; i < LANSERV_NUM_CLOSERS; i++) {
	if (session->closers[i].close_cb) {
	    session->closers[i].close_cb(
		session->closers[i].mc,
		session->sid, session->closers[i].close_cb_data);
	    session->closers[i].close_cb = NULL;
	    session->closers[i].mc = NULL;
	}
    }

    session->active = 0;
    if (session->authtype <= 4)
	ipmi_auths[session->authtype].authcode_cleanup(session->authdata);
    if (session->integh)
	session->integh->cleanup(lan, session);
    if (session->confh)
	session->confh->cleanup(lan, session);
    lan->channel.active_sessions--;
    if (session->src_addr) {
	lan->channel.free(&lan->channel, session->src_addr);
	session->src_addr = NULL;
    }
}

static int
auth_gen(session_t *ses,
	 uint8_t   *out,
	 uint8_t   *sid,
	 uint8_t   *seq,
	 uint8_t   *data1,
	 int       data1_len,
	 uint8_t   *data2,
	 int       data2_len,
	 uint8_t   *data3,
	 int       data3_len)
{
    int rv;
    ipmi_auth_sg_t l[] =
    { { sid,   4  },
      { data1, data1_len },
      { data2, data2_len },
      { data3, data3_len },
      { seq,   4 },
      { NULL,  0 }};

    rv = ipmi_auths[ses->authtype].authcode_gen(ses->authdata, l, out);
    return rv;
}

static int
auth_check(session_t *ses,
	   uint8_t   *sid,
	   uint8_t   *seq,
	   uint8_t   *data,
	   int       data_len,
	   uint8_t  *code)
{
    int rv;
    ipmi_auth_sg_t l[] =
    { { sid,  4  },
      { data, data_len },
      { seq,  4 },
      { NULL, 0 }};

    rv = ipmi_auths[ses->authtype].authcode_check(ses->authdata, l, code);
    return rv;
}
	 
static int
gen_challenge(lanserv_data_t *lan,
	      uint8_t    *out,
	      uint32_t   sid)
{
    int rv;

    ipmi_auth_sg_t l[] =
    { { &sid, 4  },
      { NULL,    0 }};

    rv = ipmi_md5_authcode_gen(lan->challenge_auth, l, out);
    return rv;
}

static int
check_challenge(lanserv_data_t *lan,
		uint32_t   sid,
		uint8_t    *code)
{
    int rv;

    ipmi_auth_sg_t l[] =
    { { &sid, 4  },
      { NULL,    0 }};

    rv = ipmi_md5_authcode_check(lan->challenge_auth, l, code);
    return rv;
}

#define IPMI_LAN_MAX_HEADER_SIZE 64
#define IPMI_LAN_MAX_TRAILER_SIZE 960

static void
raw_send(lanserv_data_t *lan,
	 struct iovec *vec, unsigned int vecs,
	 void *addr, int addr_len)
{
    if (lan->sysinfo->debug & DEBUG_RAW_MSG) {
	char *str;
	int slen;
	int pos;
#define format "Raw LAN msg:"
	char dummy;
	unsigned int i, j;
	unsigned int len = 0;

	debug_log_raw_msg(lan->sysinfo, addr, addr_len,
			  "Raw LAN send to:");
	for (i = 0; i < vecs; i++)
	    len += vec[i].iov_len;
	slen = snprintf(&dummy, 1, format);
	slen += len * 3 + 3;
	str = malloc(slen);
	if (!str)
	    goto send;
	pos = sprintf(str, format);
#undef format
	str[pos++] = '\n';
	str[pos++] = '\0';
	for (i = 0; i < vecs; i++) {
	    for (j = 0; j < vec[i].iov_len; j++)
		pos += sprintf(str + pos, " %2.2x",
			       ((unsigned char *) vec[i].iov_base)[j]);
	}

	lan->sysinfo->log(lan->sysinfo, DEBUG, NULL, "%s", str);
	free(str);
    }
 send:
    lan->send_out(lan, vec, vecs, addr, addr_len);
}

static void
return_rmcpp_rsp(lanserv_data_t *lan, session_t *session, msg_t *msg,
		 unsigned int payload, unsigned char *data, unsigned int len,
		 unsigned char iana[3], unsigned int payload_id)
{
    uint8_t d[IPMI_LAN_MAX_HEADER_SIZE+IPMI_LAN_MAX_HEADER_SIZE
	      +IPMI_LAN_MAX_TRAILER_SIZE+1];
    uint8_t *pos = d + IPMI_LAN_MAX_HEADER_SIZE;
    uint8_t *tpos;
    unsigned int hdr_left = IPMI_LAN_MAX_HEADER_SIZE;
    unsigned int dlen = IPMI_LAN_MAX_HEADER_SIZE + IPMI_LAN_MAX_TRAILER_SIZE;
    unsigned int mlen;
    struct iovec vec[3];
    uint32_t sid, seq, *seqp;
    int rv;
    unsigned int s;

    if (!session)
	session = sid_to_session(lan, msg->sid);

    if (len > dlen)
	return;
    memcpy(pos, data, len);

    if (payload == 0) {
	/* Add the IPMI header - fixme -cheap hack */
	if (hdr_left < 6)
	    return;
	hdr_left -= 6;
	pos -= 6;
	dlen += 6; /* Adding header, increase total length */
	len += 6;
	pos[0] = msg->rq_addr;
	pos[1] = ((msg->netfn | 1) << 2) | msg->rq_lun;
	pos[2] = -ipmb_checksum(pos, 2, 0);
	pos[3] = msg->rs_addr;
	pos[4] = (msg->rq_seq << 2) | msg->rs_lun;
	pos[5] = msg->cmd;
	pos[len] = -ipmb_checksum(pos+3, len-3, 0);
	len++;
    }

    if (session && !session->in_startup) {
	if (session->conf) {
	    rv = session->confh->encrypt(lan, session,
					 &pos, &hdr_left, &len, &dlen);
	    if (rv) {
		lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
			 "Message failure:"
			 " encryption failed: 0x%x", rv);
		return;
	    }
	}
    }

    mlen = len;
    if (session && !session->in_startup && session->integ) {
	unsigned int count;
	/* Pad to the next multiple of 4, including the pad length and
	   next header. */
	count = 0;
	while ((mlen+2) % 4) {
	    if (mlen == dlen)
		return;
	    pos[mlen] = 0xff;
	    count++;
	    mlen++;
	}
	if (mlen == dlen)
	    return;
	pos[mlen] = count;
	mlen++;
	if (mlen == dlen)
	    return;
	pos[mlen] = 0x07; /* Next header */
	mlen++;
    }

    if (payload == 2)
	s = 22;
    else
	s = 16;
    if (hdr_left < s)
	return;
    hdr_left -= s;
    pos -= s;
    dlen += s; /* Adding header, increase total length */
    mlen += s;
    pos[0] = 0x06;
    pos[1] = 0;
    pos[2] = 0xff;
    pos[3] = 0x07;
    pos[4] = IPMI_AUTHTYPE_RMCP_PLUS;
    pos[5] = payload;
    if (!session || session->in_startup) {
	sid = 0;
	seq = 0;
	seqp = NULL;
    } else {
	sid = session->rem_sid;
	if (session->integ != 0) {
	    seq = session->xmit_seq;
	    seqp = &session->xmit_seq;
	    pos[5] |= 0x40;
	} else {
	    seq = session->unauth_xmit_seq;
	    seqp = &session->unauth_xmit_seq;
	}
	if (session->conf != 0)
	    pos[5] |= 0x80;
    }

    tpos = pos + 6;
    if (payload == 2) {
	memcpy(tpos, iana, 3);
	tpos[3] = 0;
	ipmi_set_uint16(tpos+4, payload_id);
	tpos += 6;
    }

    ipmi_set_uint32(tpos, sid);
    tpos += 4;
    ipmi_set_uint32(tpos, seq);
    tpos += 4;
    ipmi_set_uint16(tpos, seq);
    ipmi_set_uint16(tpos, len);

    if (session && !session->in_startup && session->integ) {
	rv = session->integh->add(lan, session,
				  pos, &mlen, dlen);
	if (rv) {
	    lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		     "Message failure:"
		     " encryption failed: 0x%x", rv);
	    return;
	}
    }

    if (seqp) {
	(*seqp)++;
	if (*seqp == 0)
	    *seqp = 1;
    }

    vec[0].iov_base = pos;
    vec[0].iov_len = mlen;

    raw_send(lan, vec, 1, msg->src_addr, msg->src_len);
}

static void
return_rsp(lanserv_data_t *lan, msg_t *msg, session_t *session, rsp_msg_t *rsp)
{
    uint8_t      data[IPMI_LAN_MAX_HEADER_SIZE];
    struct iovec vec[3];
    uint8_t      csum;
    session_t    dummy_session;
    uint8_t      *pos;
    int          len;
    int          rv;

    if (!session)
	session = sid_to_session(lan, msg->sid);

    if (session && session->rmcpplus) {
	return_rmcpp_rsp(lan, session, msg, msg->rmcpp.payload,
			 rsp->data, rsp->data_len, NULL, 0);
	return;
    } else if (msg->sid == 0) {
	session = &dummy_session;
	session->active = 1;
	session->authtype = IPMI_AUTHTYPE_NONE;
	session->xmit_seq = 0;
	session->sid = 0;
    }

    if (!session)
	return;

    data[0] = 6; /* RMCP version. */
    data[1] = 0;
    data[2] = 0xff; /* No seq num */
    data[3] = 7; /* IPMI msg class */
    data[4] = session->authtype;
    ipmi_set_uint32(data+5, session->xmit_seq);
    session->xmit_seq++;
    if (session->xmit_seq == 0)
	session->xmit_seq++;
    ipmi_set_uint32(data+9, session->sid);
    if (session->authtype == IPMI_AUTHTYPE_NONE)
	pos = data+13;
    else
	pos = data+29;
    len = rsp->data_len + 7;
    *pos = len;
    pos++;

    pos[0] = msg->rq_addr;
    pos[1] = (rsp->netfn << 2) | msg->rq_lun;
    pos[2] = -ipmb_checksum(pos, 2, 0);
    pos[3] = msg->rs_addr;
    pos[4] = (msg->rq_seq << 2) | msg->rs_lun;
    pos[5] = rsp->cmd;

    csum = ipmb_checksum(pos+3, 3, 0);
    csum = -ipmb_checksum(rsp->data, rsp->data_len, csum);

    vec[0].iov_base = data;

    if (session->authtype == IPMI_AUTHTYPE_NONE)
	vec[0].iov_len = 14 + 6;
    else {
	rv = auth_gen(session, data+13,
		      data+9, data+5,
		      pos, 6,
		      rsp->data, rsp->data_len,
		      &csum, 1);
	if (rv) {
	    /* FIXME - what to do? */
	    return;
	}
	vec[0].iov_len = 30 + 6;
    }

    vec[1].iov_base = rsp->data;
    vec[1].iov_len = rsp->data_len;
    vec[2].iov_base = &csum;
    vec[2].iov_len = 1;

    raw_send(lan, vec, 3, msg->src_addr, msg->src_len);
}

static void
lan_return_rsp(channel_t *chan, msg_t *msg, rsp_msg_t *rsp)
{
    lanserv_data_t *lan = chan->chan_info;
    rsp_msg_t    rrsp;

    return_rsp(lan, msg, NULL, rsp);

    msg = ipmi_mc_get_next_recv_q(chan->mc);
    if (!msg)
	return;
    while (msg) {
	/* Extract relevant header information and remove the header and
	   checksum. */
	msg->rq_addr = msg->data[0];
	msg->rq_lun = msg->data[1] & 0x3;
	msg->rs_addr = msg->data[3];
	msg->rs_lun = msg->data[4] & 0x3;
	rrsp.netfn = msg->netfn | 1;
	rrsp.cmd = msg->data[5];
	rrsp.data = msg->data + 6;
	rrsp.data_len = msg->len - 7;

	return_rsp(lan, msg, NULL, &rrsp);

	chan->free(chan, msg);

	msg = ipmi_mc_get_next_recv_q(chan->mc);
    }
    if (chan->recv_in_q)
	chan->recv_in_q(chan, 0);
}

static void
return_rsp_data(lanserv_data_t *lan, msg_t *msg, session_t *session,
		uint8_t *data, int len)
{
    rsp_msg_t rsp;

    rsp.netfn = msg->netfn | 1;
    rsp.cmd = msg->cmd;
    rsp.data = data;
    rsp.data_len = len;

    return_rsp(lan, msg, session, &rsp);
}

static void
return_err(lanserv_data_t *lan, msg_t *msg, session_t *session, uint8_t err)
{
    rsp_msg_t rsp;

    rsp.netfn = msg->netfn | 1;
    rsp.cmd = msg->cmd;
    rsp.data = &err;
    rsp.data_len = 1;
    return_rsp(lan, msg, session, &rsp);
}

static void
handle_get_system_guid(lanserv_data_t *lan, session_t *session, msg_t *msg)
{
    unsigned char rdata[17];
    unsigned int rdata_len = sizeof(rdata);

    if (lan->guid) {
	if (rdata_len < 17) {
	    rdata[0] = IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC;
	    rdata_len = 1;
	    goto out;
	}
	rdata[0] = 0;
	memcpy(rdata + 1, lan->guid, 16);
	rdata_len = 17;
    } else {
	rdata[0] = IPMI_INVALID_CMD_CC;
	rdata_len = 1;
    }
 out:
    return_rsp_data(lan, msg, session, rdata, rdata_len);
}

static void
handle_get_channel_auth_capabilities(lanserv_data_t *lan, msg_t *msg)
{
    uint8_t   data[9];
    uint8_t   chan;
    uint8_t   priv;
    int       do_rmcpp;

    if (msg->len < 2) {
	return_err(lan, msg, NULL, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    do_rmcpp = (msg->data[0] >> 7) & 1;
    chan = msg->data[0] & 0xf;
    priv = msg->data[1] & 0xf;
    if (chan == 0xe)
	chan = lan->channel.channel_num;
    if (chan != lan->channel.channel_num) {
	return_err(lan, msg, NULL, IPMI_INVALID_DATA_FIELD_CC);
    } else if (priv > lan->channel.privilege_limit) {
	return_err(lan, msg, NULL, IPMI_INVALID_DATA_FIELD_CC);
    } else {
	if (! lan->guid)
	    do_rmcpp = 0; /* Must have a GUID to do RMCP+ */
	data[0] = 0;
	data[1] = chan;
	data[2] = lan->channel.priv_info[priv-1].allowed_auths;
	if (do_rmcpp)
	    data[2] |= 0x80;
	data[3] = 0x04; /* per-message authentication is on,
			   user-level authenitcation is on,
			   non-null user names disabled,
			   no anonymous support. */
	if (lan->users[1].valid) {
	    if (is_authval_null(lan->users[1].pw))
		data[3] |= 0x01; /* Anonymous login. */
	    else
		data[3] |= 0x02; /* Null user supported. */
	}
	if (lan->bmc_key)
	    data[3] |= 0x20;
	data[4] = 0;
	if (do_rmcpp)
	    data[4] |= 0x3; /* Support RMCP and RMCP+ */
	data[5] = lan->channel.manufacturer_id & 0xff;
	data[6] = (lan->channel.manufacturer_id >> 8) & 0xff;
	data[7] = (lan->channel.manufacturer_id >> 16) & 0xff;
	data[8] = 0;
	return_rsp_data(lan, msg, NULL, data, 9);
    }
}

static void
handle_get_session_challenge(lanserv_data_t *lan, msg_t *msg)
{
    uint8_t  data[21];
    user_t   *user;
    uint32_t sid;
    uint8_t  authtype;
    int      rv;

    if (msg->len < 17) {
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "Session challenge failed: message too short");
	return_err(lan, msg, NULL, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    authtype = msg->data[0] & 0xf;
    user = find_user(lan, msg->data+1, 1, 0);
    if (!user) {
	lan->sysinfo->log(lan->sysinfo, SESSION_CHALLENGE_FAILED, msg,
		 "Session challenge failed: Invalid user");
	if (is_authval_null(msg->data+1))
	    return_err(lan, msg, NULL, 0x82); /* no null user */
	else
	    return_err(lan, msg, NULL, 0x81); /* no user */
	return;
    }

    if (!(user->allowed_auths & (1 << authtype))) {
	lan->sysinfo->log(lan->sysinfo, SESSION_CHALLENGE_FAILED, msg,
		 "Session challenge failed: Invalid authorization type");
	return_err(lan, msg, NULL, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    if (lan->channel.active_sessions >= MAX_SESSIONS) {
	lan->sysinfo->log(lan->sysinfo, SESSION_CHALLENGE_FAILED, msg,
		 "Session challenge failed: To many open sessions");
	return_err(lan, msg, NULL, IPMI_OUT_OF_SPACE_CC);
	return;
    }

    data[0] = 0;

    sid = (lan->next_challenge_seq << (USER_BITS_REQ+1)) | (user->idx << 1) | 1;
    lan->next_challenge_seq++;
    ipmi_set_uint32(data+1, sid);

    rv = gen_challenge(lan, data+5, sid);
    if (rv) {
	lan->sysinfo->log(lan->sysinfo, SESSION_CHALLENGE_FAILED, msg,
		 "Session challenge failed: Error generating challenge");
	return_err(lan, msg, NULL, IPMI_UNKNOWN_ERR_CC);
    } else {
	return_rsp_data(lan, msg, NULL, data, 21);
    }
}

static unsigned char cipher_suites[] = {
    0xc0, 0x00, 0x00, 0x40, 0x80,
    0xc0, 0x01, 0x01, 0x40, 0x80,
    0xc0, 0x02, 0x01, 0x41, 0x80,
    0xc0, 0x03, 0x01, 0x41, 0x81,
    0xc0, 0x04, 0x01, 0x41, 0x82,
    0xc0, 0x05, 0x01, 0x41, 0x83,
    0xc0, 0x06, 0x02, 0x40, 0x80,
    0xc0, 0x07, 0x02, 0x42, 0x80,
    0xc0, 0x08, 0x02, 0x42, 0x81,
    0xc0, 0x09, 0x02, 0x42, 0x82,
    0xc0, 0x0a, 0x02, 0x42, 0x83,
    0xc0, 0x0b, 0x02, 0x43, 0x80,
    0xc0, 0x0c, 0x02, 0x43, 0x81,
    0xc0, 0x0d, 0x02, 0x43, 0x82,
    0xc0, 0x0e, 0x02, 0x43, 0x83
};

static unsigned char cipher_algos[] = {
    0x00, 0x01, 0x02,
    0x40, 0x41, 0x42, 0x43,
    0x80, 0x81, 0x82, 0x83
};

static void
handle_get_channel_cipher_suites(lanserv_data_t *lan, msg_t *msg)
{
    unsigned int chan;
    channel_t **channels, *channel;
    unsigned char *adata, data[18];
    unsigned int start, size;

    if (msg->len < 3) {
	return_err(lan, msg, NULL, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    chan = msg->data[0] & 0xf;
    if (chan == 0xe)
	chan = lan->channel.channel_num;

    channels = ipmi_mc_get_channelset(lan->channel.mc);
    channel = channels[chan];
    if (!channel) {
	return_err(lan, msg, NULL, IPMI_NOT_PRESENT_CC);
	return;
    }

    if (channel->medium_type != IPMI_CHANNEL_MEDIUM_8023_LAN) {
	return_err(lan, msg, NULL, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    /*
     * The cipher suites are all fixed, so just need to validate the
     * channel and return our hard-coded info.
     */

    if (msg->data[2] & 0x80) {
	adata = cipher_suites;
	size = sizeof(cipher_suites);
    } else {
	adata = cipher_algos;
	size = sizeof(cipher_algos);
    }

    start = (msg->data[2] & 0x1f) * 16;
    if (start >= size) {
	start = 0;
	size = 0;
    } else {
	size = size - start;
    }
    if (size > 16)
	size = 16;

    data[0] = 0;
    data[1] = chan;
    memcpy(data + 2, adata + start, size);

    return_rsp_data(lan, msg, NULL, data, size + 2);
}

static void
handle_no_session(lanserv_data_t *lan, msg_t *msg)
{
    /* Should be a session challenge, validate everything else. */
    if (msg->seq != 0) {
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "No session message failed: Invalid seq");
	return;
    }

    if (msg->authtype != IPMI_AUTHTYPE_NONE) {
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "No session message failed: Invalid authtype: %d",
		 msg->authtype);
	return;
    }

    switch (msg->cmd) {
    case IPMI_GET_SYSTEM_GUID_CMD:
	handle_get_system_guid(lan, NULL, msg);
	break;

    case IPMI_GET_CHANNEL_AUTH_CAPABILITIES_CMD:
	handle_get_channel_auth_capabilities(lan, msg);
	break;

    case IPMI_GET_SESSION_CHALLENGE_CMD:
	handle_get_session_challenge(lan, msg);
	break;

    case IPMI_GET_CHANNEL_CIPHER_SUITES_CMD:
	handle_get_channel_cipher_suites(lan, msg);
	break;

    default:
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
			  "No session message failed: Invalid command: 0x%x",
			  msg->cmd);
	return_err(lan, msg, NULL, IPMI_NOT_SUPPORTED_IN_PRESENT_STATE_CC);
	break;
    }
}

static void *
ialloc(void *info, int size)
{
    lanserv_data_t *lan = info;
    return lan->channel.alloc(&lan->channel, size);
}

static void
ifree(void *info, void *data)
{
    lanserv_data_t *lan = info;
    lan->channel.free(&lan->channel, data);
}

static session_t *
find_free_session(lanserv_data_t *lan)
{
    int i;
    /* Find a free session.  Session 0 is invalid. */
    for (i=1; i<=MAX_SESSIONS; i++) {
	if (! lan->sessions[i].active)
	    return &(lan->sessions[i]);
    }
    return NULL;
}

static void
handle_temp_session(lanserv_data_t *lan, msg_t *msg)
{
    uint8_t   seq_data[4];
    int       user_idx;
    user_t    *user;
    uint8_t   auth, priv;
    session_t *session = NULL;
    session_t dummy_session;
    int       rv;
    uint32_t  xmit_seq;
    uint8_t   data[11];
    unsigned char tsid[4];
    unsigned char tseq[4];

    if (msg->cmd != IPMI_ACTIVATE_SESSION_CMD) {
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 " message failed: Invalid command: 0x%x", msg->cmd);
	return;
    }

    if (msg->len < 22) {
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "Activate session failed: message too short");
	return;
    }

    rv = check_challenge(lan, msg->sid, msg->data+2);
    if (rv) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: challenge failed");
	return;
    }

    user_idx = (msg->sid >> 1) & USER_MASK;
    if ((user_idx > MAX_USERS) || (user_idx == 0)) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: Invalid sid: 0x%x", msg->sid);
	return;
    }

    auth = msg->data[0] & 0xf;
    user = &(lan->users[user_idx]);
    if (! (user->valid)) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: Invalid user idx: 0x%x", user_idx);
	return;
    }
    if (! (user->allowed_auths & (1 << auth))) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: Requested auth %d was invalid for"
		 " user 0x%x",
		 auth, user_idx);
	return;
    }
    if (! (user->allowed_auths & (1 << msg->authtype))) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: Message auth %d was invalid for"
		 " user 0x%x",
		 msg->authtype, user_idx);
	return;
    }

    if (lan->channel.active_sessions >= MAX_SESSIONS) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Session challenge failed: To many open sessions");
	return;
    }

    xmit_seq = ipmi_get_uint32(msg->data+18);

    memset(&dummy_session, 0, sizeof(dummy_session));
    dummy_session.active = 1;
    dummy_session.authtype = msg->authtype;
    dummy_session.xmit_seq = xmit_seq;
    dummy_session.sid = msg->sid;

    rv = ipmi_auths[msg->authtype].authcode_init(user->pw,
						 &dummy_session.authdata,
						 lan,
						 ialloc, ifree);
    if (rv) {
	lan->sysinfo->log(lan->sysinfo, AUTH_FAILED, msg,
		 "Activate session failed: Message auth init failed");
	return;
    }

    /* The "-6, +7" is cheating a little, but we need the last checksum
       to correctly calculate the code. */
    ipmi_set_uint32(tsid, msg->sid);
    ipmi_set_uint32(tseq, msg->seq);
    rv = auth_check(&dummy_session, tsid, tseq, msg->data-6, msg->len+7,
		    msg->rmcp.authcode);
    if (rv) {
	lan->sysinfo->log(lan->sysinfo, AUTH_FAILED, msg,
		 "Activate session failed: Message auth failed");
	goto out_free;
    }

    /* Note that before this point, we cannot return an error, there's
       no way to generate an authcode for it. */

    if (xmit_seq == 0) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: Invalid sequence number");
	return_err(lan, msg, &dummy_session, 0x85); /* Invalid seq id */
	goto out_free;
    }

    priv = msg->data[1] & 0xf;
    if ((user->privilege == 0xf)
	|| (priv > user->privilege)
	|| (priv > lan->channel.privilege_limit))
    {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: Privilege %d for user 0x%d failed",
		 priv, user_idx);
	return_err(lan, msg, &dummy_session, 0x86); /* Privilege error */
	goto out_free;
    }

    if (! (lan->channel.priv_info[priv-1].allowed_auths & (1 << auth))) {
	/* Authentication level not permitted for this privilege */
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: Auth level %d invalid for"
		 " privilege %d",
		 auth, priv);
	return_err(lan, msg, &dummy_session, IPMI_INVALID_DATA_FIELD_CC);
	goto out_free;
    }

    session = find_free_session(lan);

    if (!session) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: out of free sessions");
	return_err(lan, msg, &dummy_session, 0x81); /* No session slot */
	goto out_free;
    }

    session->src_addr = lan->channel.alloc(&lan->channel, msg->src_len);
    if (!session->src_addr) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: out of memory");
	return_err(lan, msg, &dummy_session, IPMI_UNKNOWN_ERR_CC);
	goto out_free;
    }
    memcpy(session->src_addr, msg->src_addr, msg->src_len);
    session->src_len = msg->src_len;

    session->active = 1;
    session->rmcpplus = 0;
    session->authtype = auth;
    session->authdata = dummy_session.authdata;
    rv = lan->gen_rand(lan, seq_data, 4);
    if (rv) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: Could not generate random number");
	return_err(lan, msg, &dummy_session, IPMI_UNKNOWN_ERR_CC);
	goto out_free;
    }
    session->recv_seq = ipmi_get_uint32(seq_data) & ~1;
    if (!session->recv_seq)
	session->recv_seq = 2;
    session->xmit_seq = xmit_seq;
    session->max_priv = priv;
    session->priv = IPMI_PRIVILEGE_USER; /* Start at user privilege. */
    session->userid = user->idx;
    session->time_left = lan->default_session_timeout;

    lan->channel.active_sessions++;
    lan->sysinfo->log(lan->sysinfo, NEW_SESSION, msg,
	     "Activate session: Session opened for user 0x%x, max priv %d",
	     user_idx, priv);

    if (lan->sid_seq == 0)
	lan->sid_seq++;
    session->sid = ((lan->sid_seq << (SESSION_BITS_REQ+1))
		    | (session->handle << 1));
    lan->sid_seq++;

    data[0] = 0;
    data[1] = auth;
    
    ipmi_set_uint32(data+2, session->sid);
    ipmi_set_uint32(data+6, session->recv_seq);

    data[10] = session->max_priv;

    return_rsp_data(lan, msg, &dummy_session, data, 11);
    return;

 out_free:
    ipmi_auths[msg->authtype].authcode_cleanup(dummy_session.authdata);
}

/* The command handling below is for active sessions. */

static void
handle_smi_msg(lanserv_data_t *lan, session_t *session, msg_t *msg)
{
    int   rv;

    rv = channel_smi_send(&lan->channel, msg);
    if (rv == ENOMEM)
	return_err(lan, msg, NULL, IPMI_UNKNOWN_ERR_CC);
    else if (rv == EMSGSIZE)
	return_err(lan, msg, session,
		   IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC);
    else if (rv)
	return_err(lan, msg, session, IPMI_UNKNOWN_ERR_CC);
}

static void
handle_activate_session_cmd(lanserv_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t data[11];

    if (msg->len < 22) {
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "Activate session failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    /* We are already connected, we ignore everything but the outbound
       sequence number. */
    session->xmit_seq = ipmi_get_uint32(msg->data+18);

    data[0] = 0;
    data[1] = session->authtype;
    
    ipmi_set_uint32(data+2, session->sid);
    ipmi_set_uint32(data+6, session->recv_seq);

    data[10] = session->max_priv;

    return_rsp_data(lan, msg, session, data, 11);
}

static void
handle_set_session_privilege(lanserv_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t data[2];
    uint8_t priv;

    if (msg->len < 1) {
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "Set session priv failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    priv = msg->data[0] & 0xf;

    if (priv == 0)
	priv = session->priv;

    if (priv == IPMI_PRIVILEGE_CALLBACK) {
	return_err(lan, msg, session, 0x80); /* Can't drop below user priv. */
	return;
    }

    if (priv > session->max_priv) {
	return_err(lan, msg, session, 0x81); /* Cannot set the priv this high. */
	return;
    }

    session->priv = priv;

    data[0] = 0;
    data[1] = priv;

    return_rsp_data(lan, msg, session, data, 2);
}

static void		
handle_close_session(lanserv_data_t *lan, session_t *session, msg_t *msg)
{
    uint32_t  sid;
    session_t *nses = session;

    if (msg->len < 4) {
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "Close session failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    sid = ipmi_get_uint32(msg->data);

    if (sid != session->sid) {
	if (session->priv != IPMI_PRIVILEGE_ADMIN) {
	    /* Only admins can close other people's sessions. */
	    return_err(lan, msg, session, IPMI_INSUFFICIENT_PRIVILEGE_CC);
	    return;
	}
	nses = sid_to_session(lan, sid);
	if (!nses) {
	    return_err(lan, msg, session, 0x87); /* session not found */
	    return;
	}	    
    }

    lan->sysinfo->log(lan->sysinfo, SESSION_CLOSED, msg,
	     "Session closed: Closed due to request");

    return_err(lan, msg, session, 0);

    close_session(lan, nses);
}

static void
handle_get_session_info(lanserv_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t   idx;
    session_t *nses = NULL;
    uint8_t   data[19];

    if (msg->len < 1) {
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "Get session failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    idx = msg->data[0];
    if (idx == 0xff) {
	unsigned int sid;

	if (msg->len < 5) {
	    return_err(lan, msg, session,
		       IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	    return;
	}

	sid = ipmi_get_uint32(msg->data+1);
	nses = sid_to_session(lan, sid);
    } else if (idx == 0xfe) {
	int handle;

	if (msg->len < 2) {
	    return_err(lan, msg, session,
		       IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	    return;
	}
	
	handle = msg->data[1];
	if (handle >= MAX_SESSIONS) {
	    return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	    return;
	}
	if (lan->sessions[handle].active)
	    nses = &lan->sessions[handle];
    } else if (idx == 0) {
	nses = session;
    } else {
	int i;

	if (idx <= lan->channel.active_sessions) {
	    for (i=0; i<=MAX_SESSIONS; i++) {
		if (lan->sessions[i].active) {
		    idx--;
		    if (idx == 0) {
			nses = &lan->sessions[i];
			break;
		    }
		}
	    }
	}
    }

    data[0] = 0;
    data[2] = MAX_SESSIONS;
    data[3] = lan->channel.active_sessions;
    if (nses) {
	data[1] = nses->handle;
	data[4] = nses->userid;
	data[5] = nses->priv;
	data[6] = lan->channel.channel_num | (session->rmcpplus << 4);
	return_rsp_data(lan, msg, session, data, 7);
    } else {
	data[1] = 0;
	return_rsp_data(lan, msg, session, data, 4);
    }

    /* FIXME - We don't currently return the IP information, because
       it's hard to get.  Maybe later. */

}

static extcmd_map_t ip_src_map[] = {
    { 0, "unknown" },
    { 1, "static" },
    { 2, "dhcp" },
    { 3, "bios" },
    { 4, "other" },
    { 0, NULL }
};

#define BASETYPE lanparm_data_t
static extcmd_info_t lanread_vals[] = {
    EXTCMD_MEMB(ip_addr, extcmd_ip),
    EXTCMD_MEMB_MAPUCHAR(ip_addr_src, ip_src_map),
    EXTCMD_MEMB(mac_addr, extcmd_mac),
    EXTCMD_MEMB(subnet_mask, extcmd_ip),
    EXTCMD_MEMB(default_gw_ip_addr, extcmd_ip),
    EXTCMD_MEMB(default_gw_mac_addr, extcmd_mac),
    EXTCMD_MEMB(backup_gw_ip_addr, extcmd_ip),
    EXTCMD_MEMB(backup_gw_mac_addr, extcmd_mac)
};
#undef BASETYPE

static void
write_lan_config(lanserv_data_t *lan)
{
    if (lan->persist_changed) {
	persist_t *p;

	p = alloc_persist("lanparm.mc%2.2x.%d",
			  ipmi_mc_get_ipmb(lan->channel.mc),
			  lan->channel.channel_num);
	if (!p)
	    return;

	add_persist_data(p, lan->lanparm.max_priv_for_cipher_suite, 9,
			 "max_priv_for_cipher");
	add_persist_int(p, lan->channel.privilege_limit, "privilege_limit");

	write_persist(p);
	free_persist(p);
	lan->persist_changed = 0;
    }

    if (extcmd_setvals(lan->sysinfo, &lan->lanparm, lan->config_prog,
		       lanread_vals, lan->lanparm_changed, lanread_len)) {
	lan->sysinfo->log(lan->sysinfo, OS_ERROR, NULL,
			  "Error writing external LANPARM values");
    } else {
	memset(lan->lanparm_changed, 0, sizeof(lan->lanparm_changed));
    }
}

static void
set_channel_access(channel_t *chan, msg_t *msg, unsigned char *rdata,
		   unsigned int *rdata_len)
{
    uint8_t    upd1, upd2;
    int        write_nonv = 0;
    uint8_t    newv;
    lanserv_data_t *lan = chan->chan_info;

    upd1 = (msg->data[1] >> 6) & 0x3;
    if ((upd1 == 1) || (upd1 == 2)) {
	newv = (msg->data[1] >> 4) & 1;
	if (newv) {
	    /* Don't support per-msg authentication */
	    rdata[0] = 0x83;
	    *rdata_len = 1;
	    return;
	}

	newv = (msg->data[1] >> 3) & 1;
	if (newv) {
	    /* Don't support unauthenticated user-level access */
	    rdata[0] = 0x83;
	    *rdata_len = 1;
	    return;
	}

	newv = (msg->data[1] >> 0) & 7;
	if (newv != 0x2) {
	    /* Only support "always available" channel */
	    rdata[0] = 0x83;
	    *rdata_len = 1;
	    return;
	}

#if 0
	if (upd1 == 1) {
	    lan->channel.PEF_alerting
		= (msg->data[1] >> 5) & 1;
	} else {
	    lan->channel.PEF_alerting_nonv
		= (msg->data[1] >> 5) & 1;
	    write_nonv = 1;
	}
#endif
    } else if (upd1 != 0) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    upd2 = (msg->data[2] >> 6) & 0x3;
    if ((upd2 == 1) || (upd2 == 2)) {
	newv = (msg->data[2] >> 0) & 0xf;
	if ((newv == 0) || (newv > 4)) {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}

	if (upd2 == 1) {
	    lan->channel.privilege_limit_nonv
		= newv;
	    write_nonv = 1;
	} else {
	    lan->channel.privilege_limit = newv;
	}
    } else if (upd2 != 0) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (write_nonv) {
	lan->persist_changed = 1;
	write_lan_config(lan);
    }

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
set_lan_config_parms(channel_t *chan, msg_t *msg, unsigned char *rdata,
		     unsigned int *rdata_len)
{
    unsigned char err = 0;
    lanserv_data_t *lan = chan->chan_info;
    int rv;
    unsigned char oldval;

    /*
     * Note that in all of these, if a set is in progress and the data
     * value has been modified (but not committed), it will return the
     * modified value, not the one from the external command.
     */

    switch (msg->data[1])
    {
    case 0:
	switch (msg->data[2] & 0x3)
	{
	case 0:
	    if (lan->lanparm.set_in_progress) {
		/* rollback */
		memcpy(&lan->lanparm, &lan->lanparm_rollback,
		       sizeof(lan->lanparm));
		lan->lanparm.set_in_progress = 0;
	    }
	    /* No effect otherwise */
	    break;

	case 1:
	    if (lan->lanparm.set_in_progress)
		err = 0x81; /* Another user is writing. */
	    else {
		/* Save rollback data */
		memcpy(&lan->lanparm_rollback, &lan->lanparm,
		       sizeof(lan->lanparm));
		lan->lanparm.set_in_progress = 1;
	    }
	    break;

	case 2:
	    if (!lan->lanparm.set_in_progress) {
		err = 0x81; /* Not in proper state. */
	    } else {
		/* Re-save rollback data */
		memcpy(&lan->lanparm_rollback, &lan->lanparm,
		       sizeof(lan->lanparm));
		write_lan_config(lan);
	    }
	    break;

	case 3:
	    err = IPMI_INVALID_DATA_FIELD_CC;
	}
	break;

    case 1:
    case 2:
    case 17:
    case 22:
    case 23:
	err = 0x82; /* Read-only data */
	break;

    case 3:
	if (msg->len < 6)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.ip_addr, msg->data+2, 4);
	    lan->lanparm_changed[ip_addr_o] = 1;
	}
	break;

    case 4:
	oldval = lan->lanparm.ip_addr_src;
	lan->lanparm.ip_addr_src = msg->data[2];
	/* Check to see if the system supports this value */
	rv = extcmd_checkvals(lan->sysinfo, &lan->lanparm, lan->config_prog,
			      lanread_vals + ip_addr_src_o, 1);
	if (rv) {
	    lan->lanparm.ip_addr_src = oldval;
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}
	lan->lanparm_changed[ip_addr_src_o] = 1;
	break;

    case 5:
	if (msg->len < 8)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.mac_addr, msg->data+2, 6);
	    lan->lanparm_changed[mac_addr_o] = 1;
	}
	break;

    case 6:
	if (msg->len < 6)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.subnet_mask, msg->data+2, 4);
	    lan->lanparm_changed[subnet_mask_o] = 1;
	}
	break;

    case 7:
	if (msg->len < 5)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.ipv4_hdr_parms, msg->data+2, 3);
	}
	break;

    case 12:
	if (msg->len < 6)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.default_gw_ip_addr, msg->data+2, 4);
	    lan->lanparm_changed[default_gw_ip_addr_o] = 1;
	}
	break;

    case 13:
	if (msg->len < 8)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.default_gw_mac_addr, msg->data+2, 6);
	    lan->lanparm_changed[default_gw_mac_addr_o] = 1;
	}
	break;

    case 14:
	if (msg->len < 6)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.backup_gw_ip_addr, msg->data+2, 4);
	    lan->lanparm_changed[backup_gw_ip_addr_o] = 1;
	}
	break;

    case 15:
	if (msg->len < 8)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.backup_gw_mac_addr, msg->data+2, 6);
	    lan->lanparm_changed[backup_gw_mac_addr_o] = 1;
	}
	break;

    case 16:
	/* Just ignore this. */
	break;

    case 20:
	if (msg->len < 4)
	    err = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.vlan_id, msg->data+2, 2);
	}
	break;

    case 21:
	lan->lanparm.vlan_priority = msg->data[2];
	break;

    case 24:
	if (msg->len < 11)
	    err = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.max_priv_for_cipher_suite, msg->data+2, 9);
	    lan->persist_changed = 1;
	}
	break;

    default:
	err = 0x80; /* Parm not supported */
    }

    rdata[0] = err;
    *rdata_len = 1;
}

static void
get_lan_config_parms(channel_t *chan, msg_t *msg, unsigned char *rdata,
		     unsigned int *rdata_len)
{
    unsigned char databyte = 0;
    unsigned char databytes[5];
    unsigned char *data = NULL;
    unsigned int  length = 0;
    lanserv_data_t *lan = chan->chan_info;
    int rv;

    switch (msg->data[1])
    {
    case 0:
	databyte = lan->lanparm.set_in_progress;
	break;

    case 1:
	databyte = 0x1f; /* We support all authentications. */
	break;

    case 2:
	data = databytes;
	data[0] = chan->priv_info[0].allowed_auths;
	data[1] = chan->priv_info[1].allowed_auths;
	data[2] = chan->priv_info[2].allowed_auths;
	data[3] = chan->priv_info[3].allowed_auths;
	data[4] = 0;
	length = 5;
	break;

    case 17:
	databyte = lan->lanparm.num_destinations;
	break;

    case 3:
	if (!lan->lanparm.set_in_progress ||
	    !lan->lanparm_changed[ip_addr_o]) {
	    rv = extcmd_getvals(lan->sysinfo, &lan->lanparm, lan->config_prog,
				lanread_vals + ip_addr_o, 1);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	}
	data = lan->lanparm.ip_addr;
	length = 4;
	break;

    case 4:
	if (!lan->lanparm.set_in_progress ||
	    !lan->lanparm_changed[ip_addr_src_o]) {
	    rv = extcmd_getvals(lan->sysinfo, &lan->lanparm, lan->config_prog,
				lanread_vals + ip_addr_src_o, 1);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	}
	databyte = lan->lanparm.ip_addr_src;
	break;

    case 5:
	if (!lan->lanparm.set_in_progress ||
	    !lan->lanparm_changed[mac_addr_o]) {
	    rv = extcmd_getvals(lan->sysinfo, &lan->lanparm, lan->config_prog,
				lanread_vals + mac_addr_o, 1);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	}
	data = lan->lanparm.mac_addr;
	length = 6;
	break;

    case 6:
	if (!lan->lanparm.set_in_progress ||
	    !lan->lanparm_changed[subnet_mask_o]) {
	    rv = extcmd_getvals(lan->sysinfo, &lan->lanparm, lan->config_prog,
				lanread_vals + subnet_mask_o, 1);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	}
	data = lan->lanparm.subnet_mask;
	length = 4;
	break;

    case 7:
	/* FIXME - this is not handled */
	data = lan->lanparm.ipv4_hdr_parms;
	length = 3;
	break;

    case 12:
	if (!lan->lanparm.set_in_progress ||
	    !lan->lanparm_changed[default_gw_ip_addr_o]) {
	    rv = extcmd_getvals(lan->sysinfo, &lan->lanparm, lan->config_prog,
				lanread_vals + default_gw_ip_addr_o, 1);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	}
	data = lan->lanparm.default_gw_ip_addr;
	length = 4;
	break;

    case 13:
	if (!lan->lanparm.set_in_progress ||
	    !lan->lanparm_changed[default_gw_mac_addr_o]) {
	    rv = extcmd_getvals(lan->sysinfo, &lan->lanparm, lan->config_prog,
				lanread_vals + default_gw_mac_addr_o, 1);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	}
	data = lan->lanparm.default_gw_mac_addr;
	length = 6;
	break;

    case 14:
	if (!lan->lanparm.set_in_progress ||
	    !lan->lanparm_changed[backup_gw_ip_addr_o]) {
	    rv = extcmd_getvals(lan->sysinfo, &lan->lanparm, lan->config_prog,
				lanread_vals + backup_gw_ip_addr_o, 1);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	}
	data = lan->lanparm.backup_gw_ip_addr;
	length = 4;
	break;

    case 15:
	if (!lan->lanparm.set_in_progress ||
	    !lan->lanparm_changed[backup_gw_mac_addr_o]) {
	    rv = extcmd_getvals(lan->sysinfo, &lan->lanparm, lan->config_prog,
				lanread_vals + backup_gw_mac_addr_o, 1);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	}
	data = lan->lanparm.backup_gw_mac_addr;
	length = 6;
	break;

    case 16:
	/* Dummy value, we don't support this. */
	data = (unsigned char *) "public\0\0\0\0\0\0\0\0\0\0\0\0";
	length = 18;
	break;

    case 20:
	/* FIXME - no VLAN support */
	data = lan->lanparm.vlan_id;
	length = 2;
	break;

    case 21:
	/* FIXME - no VLAN support */
	databyte = lan->lanparm.vlan_priority;
	break;

    case 22:
	databyte = lan->lanparm.num_cipher_suites;
	break;

    case 23:
	data = lan->lanparm.cipher_suite_entry;
	length = 17;
	break;

    case 24:
	data = lan->lanparm.max_priv_for_cipher_suite;
	length = 9;
	break;

    default:
	rdata[0] = 0x80; /* Parm not supported */
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = 0x11;
    *rdata_len = 2;
    if (msg->data[0] & 0x80)
	return;

    if (data) {
	memcpy(rdata + 2, data, length);
	*rdata_len += length;
    } else {
	rdata[2] = databyte;
	*rdata_len = 3;
    }
}

static void
handle_normal_session(lanserv_data_t *lan, msg_t *msg)
{
    session_t *session = sid_to_session(lan, msg->sid);
    int       rv;

    if (session == NULL) {
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "Normal session message failure: Invalid SID");
	return;
    }

    session->time_left = lan->default_session_timeout;

    if (lan->channel.oem.oem_handle_msg &&
	lan->channel.oem.oem_handle_msg(&lan->channel, msg))
	/* OEM code handled the message. */
	return;

    rv = IPMI_PRIV_INVALID;
    if (lan->channel.oem.oem_check_permitted)
	rv = lan->channel.oem.oem_check_permitted(session->priv, msg->netfn,
						  msg->cmd);
    if (rv == IPMI_PRIV_INVALID)
	rv = ipmi_cmd_permitted(session->priv, msg->netfn, msg->cmd);

    switch (rv) {
    case IPMI_PRIV_PERMITTED:
	break;

    case IPMI_PRIV_SEND:
	/* The spec says that operator privilege is require to
	   send on other channels, but that doesn't make any
	   sense.  Instead, we look at the message to tell if the
	   operation is permitted. */
	rv = ipmi_cmd_permitted(session->priv,
				msg->data[2]>>2, /* netfn */
				msg->data[6]);   /* cmd */
	if (rv == IPMI_PRIV_PERMITTED)
	    break;

	/* fallthrough */

    case IPMI_PRIV_DENIED:
    case IPMI_PRIV_BOOT: /* FIXME - this can sometimes be permitted. */
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "Normal session message failure: no privilege");
	return_err(lan, msg, session, IPMI_INSUFFICIENT_PRIVILEGE_CC);
	return;

    case IPMI_PRIV_INVALID:
    default:
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "Normal session message failure: Internal error 1");
	return_err(lan, msg, session, IPMI_UNKNOWN_ERR_CC);
	return;
    }

    if (msg->netfn == IPMI_APP_NETFN) {
	switch (msg->cmd)
	{
	case IPMI_GET_SYSTEM_GUID_CMD:
	    handle_get_system_guid(lan, session, msg);
	    break;

	case IPMI_GET_CHANNEL_CIPHER_SUITES_CMD:
	    handle_get_channel_cipher_suites(lan, msg);
	    break;

	case IPMI_GET_CHANNEL_AUTH_CAPABILITIES_CMD:
	case IPMI_GET_SESSION_CHALLENGE_CMD:
	    return_err(lan, msg, session,
		       IPMI_NOT_SUPPORTED_IN_PRESENT_STATE_CC);
	    break;
		
	case IPMI_ACTIVATE_SESSION_CMD:
	    handle_activate_session_cmd(lan, session, msg);
	    break;

	case IPMI_SET_SESSION_PRIVILEGE_CMD:
	    handle_set_session_privilege(lan, session, msg);
	    break;
		
	case IPMI_CLOSE_SESSION_CMD:
	    handle_close_session(lan, session, msg);
	    break;

	case IPMI_GET_SESSION_INFO_CMD:
	    handle_get_session_info(lan, session, msg);
	    break;

	default:
	    goto normal_msg;
	}
    } else {
    normal_msg:
	handle_smi_msg(lan, session, msg);
    }
}

static void
handle_ipmi_payload(lanserv_data_t *lan, msg_t *msg)
{
    if (msg->len < 7) {
	lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		 "LAN msg failure: Length field too short");
	return;
    }

    if (ipmb_checksum(msg->data, 3, 0) != 0) {
	lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		 "LAN msg failure: Checksum 1 failed");
	return;
    }
    if (ipmb_checksum(msg->data+3, msg->len-3, 0) != 0) {
	lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		 "LAN msg failure: Checksum 2 failed");
	return;
    }
    msg->len--; /* Remove the final checksum */

    msg->rs_addr = msg->data[0];
    msg->netfn = msg->data[1] >> 2;
    msg->rs_lun = msg->data[1] & 0x3;
    msg->rq_addr = msg->data[3];
    msg->rq_seq = msg->data[4] >> 2;
    msg->rq_lun = msg->data[4] & 0x3;
    msg->cmd = msg->data[5];

    msg->data += 6;
    msg->len -= 6;

    if (msg->sid == 0) {
	handle_no_session(lan, msg);
    } else if (msg->sid & 1) {
	/* We use odd SIDs for temporary ones. */
	/* Temp sessions have to be set up before the auth is done, so
	   we can't do that here. */
	handle_temp_session(lan, msg);
    } else {
	handle_normal_session(lan, msg);
    }
}

#ifdef HAVE_OPENSSL
static int 
rakp_hmac_sha1_init(lanserv_data_t *lan, session_t *session)
{
    session->auth_data.akey = EVP_sha1();
    session->auth_data.akey_len = 20;
    session->auth_data.integ_len = 12;
    return 0;
}

static int 
rakp_hmac_md5_init(lanserv_data_t *lan, session_t *session)
{
    session->auth_data.akey = EVP_md5();
    session->auth_data.akey_len = 16;
    session->auth_data.integ_len = 16;
    return 0;
}

static int
rakp_hmac_set2(lanserv_data_t *lan, session_t *session,
	       unsigned char *data,  unsigned int *data_len,
	       unsigned int max_len)
{
    unsigned char       idata[74];
    unsigned int        ilen;
    const unsigned char *p;
    user_t              *user;
    auth_data_t         *a = &session->auth_data;

    if (((*data_len) + a->akey_len) > max_len)
	return E2BIG;

    ipmi_set_uint32(idata+0, session->rem_sid);
    ipmi_set_uint32(idata+4, session->sid);
    memcpy(idata+8, a->rem_rand, 16);
    memcpy(idata+24, a->rand, 16);
    memcpy(idata+40, lan->guid, 16);
    idata[56] = a->role;
    idata[57] = a->username_len;
    memcpy(idata+58, a->username, idata[57]);
    user = &(lan->users[session->userid]);

    HMAC(a->akey, user->pw, a->akey_len,
	 idata, 58+idata[57], data + *data_len, &ilen);

    *data_len += a->akey_len;

    /* Now generate the SIK */
    memcpy(idata+0, a->rem_rand, 16);
    memcpy(idata+16, a->rand, 16);
    idata[32] = a->role;
    idata[33] = a->username_len;
    memcpy(idata+34, a->username, idata[33]);
    if (lan->bmc_key)
	p = lan->bmc_key;
    else
	p = user->pw;
    HMAC(a->akey, p, a->akey_len, idata, 34+idata[33], a->sik, &ilen);

    /* Now generate k1 and k2. */
    memset(idata, 1, a->akey_len);
    HMAC(a->akey, a->sik, a->akey_len, idata, a->akey_len, a->k1, &ilen);
    memset(idata, 2, a->akey_len);
    HMAC(a->akey, a->sik, a->akey_len, idata, a->akey_len, a->k2, &ilen);

    return 0;
}

static int
rakp_hmac_check3(lanserv_data_t *lan, session_t *session,
		 unsigned char *data,  unsigned int *data_len)
{
    unsigned char       idata[38];
    unsigned int        ilen;
    unsigned char       integ[20];
    user_t              *user = &(lan->users[session->userid]);
    auth_data_t         *a = &session->auth_data;

    if (((*data_len) - a->akey_len) < 8)
	return E2BIG;

    memcpy(idata+0, a->rand, 16);
    ipmi_set_uint32(idata+16, session->rem_sid);
    idata[20] = a->role;
    idata[21] = a->username_len;
    memcpy(idata+22, a->username, idata[21]);

    HMAC(a->akey, user->pw, a->akey_len, idata, 22+idata[21], integ, &ilen);
    if (memcmp(integ, data+(*data_len)-a->akey_len, a->akey_len) != 0)
	return EINVAL;

    *data_len -= a->akey_len;
    return 0;
}

static int
rakp_hmac_set4(lanserv_data_t *lan, session_t *session,
	       unsigned char *data,  unsigned int *data_len,
	       unsigned int max_len)
{
    unsigned char       idata[36];
    unsigned int        ilen;
    auth_data_t         *a = &session->auth_data;
    unsigned char       integ[20];

    if (((*data_len) + a->akey_len) > max_len)
	return E2BIG;

    memcpy(idata+0, a->rem_rand, 16);
    ipmi_set_uint32(idata+16, session->sid);
    memcpy(idata+20, lan->guid, 16);

    HMAC(a->akey, a->sik, a->akey_len, idata, 36, integ, &ilen);
    memcpy(data+*data_len, integ, a->integ_len);

    *data_len += a->integ_len;
    return 0;
}

static auth_handlers_t rakp_hmac_sha1 =
{
    .init = rakp_hmac_sha1_init,
    .set2 = rakp_hmac_set2,
    .check3 = rakp_hmac_check3,
    .set4 = rakp_hmac_set4
};

static auth_handlers_t rakp_hmac_md5 =
{
    .init = rakp_hmac_md5_init,
    .set2 = rakp_hmac_set2,
    .check3 = rakp_hmac_check3,
    .set4 = rakp_hmac_set4
};
#define RAKP_INIT , &rakp_hmac_sha1, &rakp_hmac_md5

static int
hmac_sha1_init(lanserv_data_t *lan, session_t *session)
{
    session->auth_data.ikey2 = EVP_sha1();
    session->auth_data.ikey = session->auth_data.k1;
    session->auth_data.ikey_len = 20;
    session->auth_data.integ_len = 12;
    return 0;
}

static int
hmac_md5_init(lanserv_data_t *lan, session_t *session)
{
    user_t *user = &(lan->users[session->userid]);
    session->auth_data.ikey2 = EVP_md5();
    session->auth_data.ikey = user->pw;
    session->auth_data.ikey_len = 16;
    session->auth_data.integ_len = 16;
    return 0;
}

static void
hmac_cleanup(lanserv_data_t *lan, session_t *session)
{
}

static int 
hmac_add(lanserv_data_t *lan, session_t *session,
	 unsigned char *pos,
	 unsigned int *data_len, unsigned int data_size)
{
    auth_data_t   *a = &session->auth_data;
    unsigned int  ilen;
    unsigned char integ[20];

    if (((*data_len) + a->ikey_len) > data_size)
	return E2BIG;

    HMAC(a->ikey2, a->ikey, a->ikey_len, pos+4, (*data_len)-4, integ, &ilen);
    memcpy(pos+(*data_len), integ, a->integ_len);
    *data_len += a->integ_len;
    return 0;
}

static int
hmac_check(lanserv_data_t *lan, session_t *session, msg_t *msg)
{
    unsigned char integ[20];
    auth_data_t   *a = &session->auth_data;
    unsigned int  ilen;

    if ((msg->len-5) < a->integ_len)
	return E2BIG;

    HMAC(a->ikey2, a->ikey, a->ikey_len, msg->data, msg->len-a->integ_len,
	 integ, &ilen);
    if (memcmp(msg->data+msg->len-a->integ_len, integ, a->integ_len) != 0)
	return EINVAL;
    return 0;
}

static void *
auth_alloc(void *info, int size)
{
    return malloc(size);
}

static void
auth_free(void *info, void *data)
{
    free(data);
}

static int
md5_init(lanserv_data_t *lan, session_t *session)
{
    user_t          *user = &(lan->users[session->userid]);
    int             rv;
    ipmi_authdata_t idata;

    rv = ipmi_md5_authcode_initl(user->pw, 20, &idata, NULL,
				 auth_alloc, auth_free);
    if (rv)
	return rv;
    session->auth_data.idata = idata;
    session->auth_data.ikey_len = 16;
    return 0;
}

static void
md5_cleanup(lanserv_data_t *lan, session_t *session)
{
    ipmi_md5_authcode_cleanup(session->auth_data.idata);
    session->auth_data.idata = NULL;
}

static int 
md5_add(lanserv_data_t *lan, session_t *session,
	 unsigned char *pos,
	 unsigned int *data_len, unsigned int data_size)
{
    auth_data_t    *a = &session->auth_data;
    ipmi_auth_sg_t data[2];
    int            rv;

    if (((*data_len) + a->ikey_len) > data_size)
	return E2BIG;

    data[0].data = pos+4;
    data[0].len = (*data_len)-4;
    data[1].data = NULL;
    rv = ipmi_md5_authcode_gen(a->idata, data, pos+(*data_len));
    if (rv)
	return rv;
    *data_len += a->ikey_len;
    return 0;
}

static int
md5_check(lanserv_data_t *lan, session_t *session, msg_t *msg)
{
    auth_data_t    *a = &session->auth_data;
    ipmi_auth_sg_t data[2];
    int            rv;

    if ((msg->len-5) < a->ikey_len)
	return E2BIG;

    data[0].data = msg->data;
    data[0].len = msg->len - a->ikey_len;
    data[1].data = NULL;
    rv = ipmi_md5_authcode_check(a->idata, data,
				 msg->data + msg->len - a->ikey_len);
    return rv;
}

static integ_handlers_t hmac_sha1_integ =
{ hmac_sha1_init, hmac_cleanup, hmac_add, hmac_check };
static integ_handlers_t hmac_md5_integ =
{ hmac_md5_init, hmac_cleanup, hmac_add, hmac_check };
static integ_handlers_t md5_integ =
{ md5_init, md5_cleanup, md5_add, md5_check };
#define HMAC_INIT , &hmac_sha1_integ, &hmac_md5_integ
#define MD5_INIT , &md5_integ

static int
aes_cbc_init(lanserv_data_t *lan, session_t *session)
{
    session->auth_data.ckey = session->auth_data.k2;
    session->auth_data.ckey_len = 16;
    return 0;
}

static void
aes_cbc_cleanup(lanserv_data_t *lan, session_t *session)
{
}

static int
aes_cbc_encrypt(lanserv_data_t *lan, session_t *session,
		unsigned char **pos, unsigned int *hdr_left,
		unsigned int *data_len, unsigned int *data_size)
{
    auth_data_t    *a = &session->auth_data;
    unsigned int   l = *data_len;
    unsigned char  *d;
    unsigned char  *iv;
    unsigned int   i;
    EVP_CIPHER_CTX ctx;
    int            rv;
    int            outlen;
    int            tmplen;
    unsigned char  *padpos;
    unsigned char  padval;
    unsigned int   padlen;

    if (*hdr_left < 16)
	return E2BIG;

    /* Calculate the number of padding bytes -> e.  Note that the pad
       length byte is included, thus the +1.  We don't add the pad,
       AES does, but we need to know what it is. */
    /* Calculate the number of padding bytes -> e.  Note that the pad
       length byte is included, thus the +1.  We then do the padding. */
    padlen = 15 - (l % 16);
    l += padlen + 1;
    if (l > *data_size)
	return E2BIG;

    /* We store the unencrypted data here, then crypt into the real
       data. */
    d = malloc(l);
    if (!d)
	return ENOMEM;

    memcpy(d, *pos, *data_len);

    /* Now add the padding. */
    padpos = d + *data_len;
    padval = 1;
    for (i=0; i<padlen; i++, padpos++, padval++)
	*padpos = padval;
    *padpos = padlen;

    /* Now create the initialization vector, including making room for it. */
    iv = (*pos) - 16;
    rv = lan->gen_rand(lan, iv, 16);
    if (rv) {
	free(d);
	return rv;
    }
    *hdr_left -= 16;
    *data_size += 16;

    /* Ok, we're set to do the crypt operation. */
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, a->ckey, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    if (!EVP_EncryptUpdate(&ctx, *pos, &outlen, d, l)) {
	rv = ENOMEM;
	goto out_cleanup;
    }
    if (!EVP_EncryptFinal_ex(&ctx, (*pos) + outlen, &tmplen)) {
	rv = ENOMEM; /* right? */
	goto out_cleanup;
    }
    outlen += tmplen;

    *pos = iv;
    *data_len = outlen + 16;

 out_cleanup:
    EVP_CIPHER_CTX_cleanup(&ctx);
    free(d);
    return rv;
}

static int
aes_cbc_decrypt(lanserv_data_t *lan, session_t *session, msg_t *msg)
{
    auth_data_t    *a = &session->auth_data;
    unsigned int   l = msg->len;
    unsigned char  *d;
    EVP_CIPHER_CTX ctx;
    int            outlen;
    unsigned char  *pad;
    int            padlen;
    int            rv = 0;

    if (l < 32)
	/* Not possible with this algorithm. */
	return EINVAL;
    l -= 16;

    /* We store the encrypted data here, then decrypt into the real
       data. */
    d = malloc(l);
    if (!d)
	return ENOMEM;

    memcpy(d, msg->data+16, l);

    /* Ok, we're set to do the decrypt operation. */
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, a->k2, msg->data);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    if (!EVP_DecryptUpdate(&ctx, msg->data+16, &outlen, d, l)) {
	rv = EINVAL;
	goto out_cleanup;
    }

    if (outlen < 16) {
	rv = EINVAL;
	goto out_cleanup;
    }

    /* Now remove the padding */
    pad = msg->data + 16 + outlen - 1;
    padlen = *pad;
    if (padlen >= 16) {
	rv = EINVAL;
	goto out_cleanup;
    }
    outlen--;
    pad--;
    while (padlen) {
	if (*pad != padlen) {
	    rv = EINVAL;
	    goto out_cleanup;
	}
	outlen--;
	pad--;
	padlen--;
    }
    
    msg->data += 16; /* Remove the init vector */
    msg->len = outlen;

 out_cleanup:
    EVP_CIPHER_CTX_cleanup(&ctx);
    free(d);
    return rv;
}

static conf_handlers_t aes_cbc_conf =
{ aes_cbc_init, aes_cbc_cleanup, aes_cbc_encrypt, aes_cbc_decrypt };
#define AES_CBC_INIT , &aes_cbc_conf

unsigned int default_auth = 1; /* RAKP-HMAC-SHA1 */
unsigned int default_integ = 1; /* HMAC-SHA1-96 */
unsigned int default_conf = 1; /* AES-CBC-128 */
#else
#define RAKP_INIT , NULL, NULL
#define MD5_INIT , NULL
#define HMAC_INIT , NULL
#define AES_CBC_INIT , NULL
unsigned int default_auth = 0;
unsigned int default_integ = 0;
unsigned int default_conf = 0;
#endif
integ_handlers_t *integs[64] =
{
    NULL HMAC_INIT MD5_INIT
};
conf_handlers_t *confs[64] =
{
    NULL AES_CBC_INIT
};
auth_handlers_t *auths[64] =
{
    NULL RAKP_INIT
};

struct valid_cypher_suites_s
{
    int auth, integ, conf;
} valid_cipher_suites[] =
{
    { 0, 0, 0 },
    { 1, 0, 0 },
    { 1, 1, 0 },
    { 1, 1, 1 },
    { 1, 1, 2 },
    { 1, 1, 3 },
    { 2, 0, 0 },
    { 2, 2, 0 },
    { 2, 2, 1 },
    { 2, 2, 2 },
    { 2, 2, 3 },
    { 2, 3, 0 },
    { 2, 3, 1 },
    { 2, 3, 2 },
    { 2, 3, 3 },
    { -1, -1. -1 }
};

static void
handle_open_session_payload(lanserv_data_t *lan, msg_t *msg)
{
    unsigned char data[36];
    unsigned char priv, max_priv;
    unsigned char auth;
    unsigned char integ;
    unsigned char conf;
    session_t     *session = NULL;
    uint32_t      rem_sid;
    unsigned char err;
    int           i;
    int           rv;

    if (msg->sid != 0) {
	err = IPMI_RMCPP_INVALID_SESSION_ID;
	goto out_err;
    }
    if (msg->len < 32) {
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    }

    priv = msg->data[1] & 0xf;
    if (priv > 4) {
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    }

    rem_sid = ipmi_get_uint32(msg->data+4);
    if (rem_sid == 0) {
	err = IPMI_RMCPP_INVALID_SESSION_ID;
	goto out_err;
    }

    if (msg->data[8] != 0) {
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    }
    if (msg->data[11] == 0)
	auth = default_auth;
    else if (msg->data[11] != 8) {
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    } else
	auth = msg->data[12] & 0x3f;
    if (auth && !auths[auth]) {
	err = IPMI_RMCPP_INVALID_AUTHENTICATION_ALGORITHM;
	goto out_err;
    }

    if (msg->data[16] != 1) {
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    }
    if (msg->data[19] == 0)
	integ = default_integ;
    else if (msg->data[19] != 8) {
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    } else
	integ = msg->data[20] & 0x3f;
    if (integ && !integs[integ]) {
	err = IPMI_RMCPP_INVALID_INTEGRITY_ALGORITHM;
	goto out_err;
    }

    if (msg->data[24] != 2) {
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    }
    if (msg->data[27] == 0)
	conf = default_conf;
    else if (msg->data[27] != 8) {
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    } else
	conf = msg->data[28] & 0x3f;
    if (conf && !confs[conf]) {
	err = IPMI_RMCPP_INVALID_CONFIDENTIALITY_ALGORITHM;
	goto out_err;
    }

    for (i=0; ; i++) {
	if (valid_cipher_suites[i].auth == -1)
	    break;
	if ((valid_cipher_suites[i].auth == auth)
	    && (valid_cipher_suites[i].integ == integ)
	    && (valid_cipher_suites[i].conf == conf))
	    break;
    }
    if (valid_cipher_suites[i].auth == -1) {
	err = IPMI_RMCPP_NO_CIPHER_SUITE_MATCHES;
	goto out_err;
    }

    max_priv = lan->lanparm.max_priv_for_cipher_suite[priv >> 1];
    if (max_priv & 1)
	max_priv >>= 4;
    max_priv &= 0xf;
    if (priv > max_priv) {
	err = IPMI_RMCPP_UNAUTHORIZED_ROLE_OR_PRIVILEGE;
	goto out_err;
    }

    session = find_free_session(lan);
    if (!session) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: out of free sessions");
	err = IPMI_RMCPP_INSUFFICIENT_RESOURCES_FOR_SESSION;
	goto out_err;
    }

    session->src_addr = lan->channel.alloc(&lan->channel, msg->src_len);
    if (!session->src_addr) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: out of memory");
	err = IPMI_RMCPP_INSUFFICIENT_RESOURCES_FOR_SESSION;
	goto out_err;
    }
    memcpy(session->src_addr, msg->src_addr, msg->src_len);
    session->src_len = msg->src_len;

    session->active = 1;
    session->in_startup = 1;
    session->rmcpplus = 1;
    session->authtype = IPMI_AUTHTYPE_RMCP_PLUS;
    rv = lan->gen_rand(lan, session->auth_data.rand, 16);
    if (rv) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "Activate session failed: Could not generate random number");
	err = IPMI_RMCPP_INSUFFICIENT_RESOURCES_FOR_SESSION;
	goto out_err;
    }
    session->recv_seq = 1;
    session->xmit_seq = 1;
    session->unauth_recv_seq = 1;
    session->unauth_xmit_seq = 1;
    session->rem_sid = rem_sid;

    session->auth = auth;
    session->authh = auths[auth];
    if (session->authh)
	session->authh->init(lan, session);
    session->integ = integ;
    session->integh = integs[integ];
    session->conf = conf;
    session->confh = confs[conf];

    session->userid = 0;
    session->time_left = lan->default_session_timeout;

    session->sid = ((lan->sid_seq << (SESSION_BITS_REQ+1))
		    | (session->handle << 1));
    lan->sid_seq++;

    lan->sysinfo->log(lan->sysinfo, NEW_SESSION, msg,
	     "Activate session: Session started, max priv %d", priv);

    memset(data, 0, sizeof(data));
    data[0] = msg->data[0];
    data[1] = 0;
    data[2] = priv;
    ipmi_set_uint32(data+4, session->rem_sid);
    ipmi_set_uint32(data+8, session->sid);
    data[12] = 0;
    data[15] = 8;
    data[16] = auth;
    data[20] = 1;
    data[23] = 8;
    data[24] = integ;
    data[28] = 2;
    data[31] = 8;
    data[32] = conf;

    lan->channel.active_sessions++;

    return_rmcpp_rsp(lan, session, msg, 0x11, data, 36, NULL, 0);
    return;
 out_err:

    data[0] = msg->data[0];
    data[1] = err;
    return_rmcpp_rsp(lan, session, msg, 0x11, data, 2, NULL, 0);
    if (session)
	close_session(lan, session);
}

static void
handle_rakp1_payload(lanserv_data_t *lan, msg_t *msg)
{
    unsigned char data[64];
    unsigned char priv;
    session_t     *session = NULL;
    uint32_t      sid;
    unsigned char err = 0;
    unsigned char username[17];
    int           name_only_lookup;
    unsigned char name_len;
    user_t        *user;
    unsigned int  len;

    if (msg->sid != 0)
	return;
    if (msg->len < 28)
	return;
    sid = ipmi_get_uint32(msg->data+4);
    if (sid == 0)
	return;
    session = sid_to_session(lan, sid);
    if (!session)
	return;

    memcpy(session->auth_data.rem_rand, msg->data+8, 16);
    session->auth_data.role = msg->data[24];

    priv = msg->data[24] & 0xf;
    if (priv > 4) {
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    }

    name_only_lookup = (msg->data[24] >> 4) & 1;

    name_len = msg->data[27];
    if (name_len > 16) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "RAKP msg: name length too long: %d", name_len);
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    }
    if ((unsigned int) (28+name_len) > msg->len) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "RAKP msg: name length doesn't match: %d", name_len);
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    }

    session->max_priv = priv;
    session->priv = IPMI_PRIVILEGE_USER; /* Start at user privilege. */

    memset(username, 0, sizeof(username));
    memcpy(username, msg->data+28, name_len);
    user = find_user(lan, username, name_only_lookup, priv);
    if (!user) {
	lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		 "RAKP msg: invalid user: %s", username);
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    }

    session->userid = user->idx;
    session->auth_data.username_len = name_len;
    memcpy(session->auth_data.username, username, 16);

    if (session->integh) {
	int rv = session->integh->init(lan, session);
	if (rv) {
	    err = IPMI_RMCPP_INSUFFICIENT_RESOURCES_FOR_SESSION;
	    goto out_err;
	}
    }
    if (session->confh) {
	int rv = session->confh->init(lan, session);
	if (rv) {
	    err = IPMI_RMCPP_INSUFFICIENT_RESOURCES_FOR_SESSION;
	    goto out_err;
	}
    }

 out_err:
    memset(data, 0, sizeof(data));
    data[0] = msg->data[0];
    data[1] = err;
    ipmi_set_uint32(data+4, session->rem_sid);
    memcpy(data+8, session->auth_data.rand, 16);
    memcpy(data+24, lan->guid, 16);
    len = 40;
    if (session->authh) {
	int rv;
	rv = session->authh->set2(lan, session, data, &len, sizeof(data));
	if (rv) {
	    lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		     "RAKP msg: set2 failed: 0x%x", rv);
	    return;
	}
    }
    
    return_rmcpp_rsp(lan, session, msg, 0x13, data, len, NULL, 0);

    if (err)
	close_session(lan, session);
}

static void
handle_rakp3_payload(lanserv_data_t *lan, msg_t *msg)
{
    unsigned char data[32];
    session_t     *session = NULL;
    uint32_t      sid;
    unsigned char err = 0;
    unsigned int  len;

    if (msg->sid != 0)
	return;
    if (msg->len < 8)
	return;

    sid = ipmi_get_uint32(msg->data+4);
    if (sid == 0)
	return;
    session = sid_to_session(lan, sid);
    if (!session)
	return;

    if (session->authh) {
	int rv;
	rv = session->authh->check3(lan, session, msg->data, &msg->len);
	if (rv) {
	    lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		     "RAKP msg: check3 failed: 0x%x", rv);
	    err = 0x0f; /* Invalid integrity check */
	    goto out_err;
	}
    }

    if (msg->data[1]) {
	/* Other end reported an error, shut down. */
	close_session(lan, session);
	return;
    }

 out_err:
    memset(data, 0, sizeof(data));
    data[0] = msg->data[0];
    data[1] = err;
    ipmi_set_uint32(data+4, session->rem_sid);
    len = 8;
    if (session->authh) {
	int rv;
	rv = session->authh->set4(lan, session, data, &len, sizeof(data));
	if (rv) {
	    lan->sysinfo->log(lan->sysinfo, NEW_SESSION_FAILED, msg,
		     "RAKP msg: set4 failed: 0x%x", rv);
	}
    }
    
    return_rmcpp_rsp(lan, session, msg, 0x15, data, len, NULL, 0);

    if (err)
	close_session(lan, session);
    else
	session->in_startup = 0;
}

ipmi_payload_handler_cb payload_handlers[64] =
{
    [0] = handle_ipmi_payload,
    [0x10] = handle_open_session_payload,
    [0x12] = handle_rakp1_payload,
    [0x14] = handle_rakp3_payload,
};

int
ipmi_register_payload(unsigned int payload_id, ipmi_payload_handler_cb handler)
{
    if (payload_id >= 64)
	return EINVAL;
    if (payload_handlers[payload_id])
	return EBUSY;
    payload_handlers[payload_id] = handler;
    return 0;
}

static int
decrypt_message(lanserv_data_t *lan, session_t *session, msg_t *msg)
{
    if (!msg->rmcpp.encrypted) {
	if (session->conf != 0) {
	    lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		     "Message failure:"
		     " Unencrypted msg on encrypted session");
	    return EINVAL;
	}
	return 0;
    }

    return session->confh->decrypt(lan, session, msg);
}

static int
check_message_integrity(lanserv_data_t *lan, session_t *session, msg_t *msg)
{
    if (!msg->rmcpp.authenticated) {
	if (session->integ != 0) {
	    lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		     "Message failure:"
		     " Unauthenticated msg on authenticated session");
	    return EINVAL;
	}
	return 0;
    } else if (session->integ == 0) {
	lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "Message failure:"
		 " Authenticated msg on unauthenticated session");
	return EINVAL;
    }

    return session->integh->check(lan, session, msg);
}

static void
ipmi_handle_rmcpp_msg(lanserv_data_t *lan, msg_t *msg)
{
    unsigned int len;
    uint32_t     *seq;
    msg_t        imsg;

    imsg.data = msg->data-1;
    imsg.len = msg->len+1;

    if (msg->len < 11) {
	lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		 "LAN msg failure: message too short");
	return;
    }
    msg->rmcpp.payload = msg->data[0] & 0x3f;
    msg->rmcpp.encrypted = (msg->data[0] >> 7) & 1;
    msg->rmcpp.authenticated = (msg->data[0] >> 6) & 1;
    msg->data++;
    if (msg->rmcpp.payload == 2) {
	if (msg->len < 17) {
	    lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		     "LAN msg failure: message too short");
	    return;
	}
	memcpy(msg->rmcpp.iana, msg->data + 1, 3);
	msg->data += 4;
	msg->rmcpp.payload_id = ipmi_get_uint16(msg->data);
	msg->data += 2;
    }
    msg->sid = ipmi_get_uint32(msg->data);
    msg->data += 4;
    msg->seq = ipmi_get_uint32(msg->data);
    msg->data += 4;
    len = ipmi_get_uint16(msg->data);
    msg->data += 2;
    if (len > msg->len) {
	lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		 "LAN msg failure: Length field invalid: %d, %d",
		 len, msg->len);
	return; /* The length field is not valid.  We allow extra
		   bytes, but reject if not enough. */
    }

    msg->rmcpp.authdata_len = msg->len - len;
    msg->rmcpp.authdata = msg->data + len;
    msg->len = len;

    if (msg->sid == 0) {
	if (msg->rmcpp.authenticated || msg->rmcpp.encrypted) {
	    lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		     "LAN msg failure:"
		     " Got encrypted or authenticated SID 0 msg");
	    return;
	}
    } else {
	session_t    *session = sid_to_session(lan, msg->sid);
	int          rv;
	int          diff;

	if (session == NULL) {
	    lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		     "Normal session message failure: Invalid SID");
	    return;
	}

	if (!session->rmcpplus) {
	    lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		     "Normal session message failure:"
		     " RMCP+ msg on RMCP session");
	    return;
	}

	imsg.rmcpp.encrypted = msg->rmcpp.encrypted;
	imsg.rmcpp.authenticated = msg->rmcpp.authenticated;

	rv = check_message_integrity(lan, session, &imsg);
	if (rv) {
	    lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		     "LAN msg failure:"
		     " Message integrity failed");
	    return;
	}

	rv = decrypt_message(lan, session, msg);
	if (rv) {
	    lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		     "LAN msg failure:"
		     " Message decryption failed");
	    return;
	}

	/* Check that the session sequence number is valid.  We make
	   sure it is within 8 of the last highest received sequence
	   number, per the spec. */
	if (msg->rmcpp.authenticated)
	    seq = &session->recv_seq;
	else
	    seq = &session->unauth_recv_seq;
	diff = msg->seq - *seq;
	if ((diff < -16) || (diff > 15)) {
	    lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		     "Normal session message failure: SEQ out of range");
	    return;
	}

	/* We wait until after the message is authenticated to set the
	   sequence number, to prevent spoofing. */
	if (msg->seq > *seq)
	    *seq = msg->seq;
    }

    if (payload_handlers[msg->rmcpp.payload])
	payload_handlers[msg->rmcpp.payload](lan, msg);
}

static void
ipmi_handle_rmcp_msg(lanserv_data_t *lan, msg_t *msg)
{
    unsigned char *tsid;
    unsigned char *tseq;

    if (msg->len < 9) {
	lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		 "LAN msg failure: message too short");
	return;
    }

    tseq = msg->data+0;
    msg->seq = ipmi_get_uint32(msg->data+0);
    tsid = msg->data+4;
    msg->sid = ipmi_get_uint32(msg->data+4);

    if (msg->authtype != IPMI_AUTHTYPE_NONE) {
	if (msg->len < 25) {
	    lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		     "LAN msg failure: message too short");
	    return;
	}

	memcpy(msg->rmcp.authcode_data, msg->data + 8, 16);
	msg->rmcp.authcode = msg->rmcp.authcode_data;
	msg->data += 24;
	msg->len -= 24;
    } else {
	msg->rmcp.authcode = NULL;
	msg->data += 8;
	msg->len -= 8;
    }
    if (msg->len < msg->data[0]) {
	lan->sysinfo->log(lan->sysinfo, LAN_ERR, msg,
		 "LAN msg failure: Length field invalid");
	return; /* The length field is not valid.  We allow extra
		   bytes, but reject if not enough. */
    }
    msg->len = msg->data[0];
    msg->data++;

    /* Validate even, non-zero sids here.  The odd sids are temporary
       sessions and get authenticated in that handling. */
    if ((msg->sid > 0) && ((msg->sid & 1) == 0)) {
	/* The "-6, +7" is cheating a little, but we need the last
	   checksum to correctly calculate the code. */
	session_t *session = sid_to_session(lan, msg->sid);
	int       rv;
	int       diff;

	if (session == NULL) {
	    lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		     "Normal session message failure: Invalid SID");
	    return;
	}

	if (session->rmcpplus) {
	    lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		     "Normal session message failure:"
		     " RMCP msg on RMCP+ session");
	    return;
	}

	rv = auth_check(session, tsid, tseq, msg->data, msg->len,
			msg->rmcp.authcode);
	if (rv) {
	    lan->sysinfo->log(lan->sysinfo, AUTH_FAILED, msg,
		     "Normal session message failure: auth failure");
	    return;
	}

	/* Check that the session sequence number is valid.  We make sure
	   it is within 8 of the last highest received sequence number,
	   per the spec. */
	diff = msg->seq - session->recv_seq;
	if ((diff < -8) || (diff > 8)) {
	    lan->sysinfo->log(lan->sysinfo, INVALID_MSG, msg,
		 "Normal session message failure: SEQ out of range");
	    return;
	}

	/* We wait until after the message is authenticated to set the
	   sequence number, to prevent spoofing. */
	if (msg->seq > session->recv_seq)
	    session->recv_seq = msg->seq;
    }

    handle_ipmi_payload(lan, msg);
}

void
ipmi_handle_lan_msg(lanserv_data_t *lan,
		    uint8_t *data, int len,
		    void *from_addr, int from_len)
{
    msg_t   msg;

    msg.src_addr = from_addr;
    msg.src_len = from_len;

    msg.oem_data = 0;

    if (len < 5) {
	lan->sysinfo->log(lan->sysinfo, LAN_ERR, &msg,
		 "LAN msg failure: message too short");
	return;
    }

    if (data[2] != 0xff) {
	lan->sysinfo->log(lan->sysinfo, LAN_ERR, &msg,
		 "LAN msg failure: seq not ff");
	return; /* Sequence # must be ff (no ack) */
    }

    msg.authtype = data[4];
    msg.data = data+5;
    msg.len = len - 5;
    msg.channel = lan->channel.channel_num;
    msg.orig_channel = &lan->channel;

    if (msg.authtype == IPMI_AUTHTYPE_RMCP_PLUS) {
	ipmi_handle_rmcpp_msg(lan, &msg);
    } else {
	ipmi_handle_rmcp_msg(lan, &msg);
    }

}

static void
ipmi_lan_tick(void *info, unsigned int time_since_last)
{
    lanserv_data_t *lan = info;
    int i;

    for (i=1; i<=MAX_SESSIONS; i++) {
	if (lan->sessions[i].active) {
	    if (lan->sessions[i].time_left <= time_since_last) {
		msg_t msg = { 0 }; /* A fake message to hold the address. */

		msg.src_addr = lan->sessions[i].src_addr;
		msg.src_len = lan->sessions[i].src_len;
		lan->sysinfo->log(lan->sysinfo, SESSION_CLOSED, &msg,
			 "Session closed: Closed due to timeout");
		close_session(lan, &(lan->sessions[i]));
	    } else {
		lan->sessions[i].time_left -= time_since_last;
	    }
	}
    }
}

static int
read_lan_config(lanserv_data_t *lan)
{
    unsigned int i;
    persist_t *p;
    void *data;
    unsigned int len;
    long iv;

    p = read_persist("lanparm.mc%2.2x.%d", ipmi_mc_get_ipmb(lan->channel.mc),
		     lan->channel.channel_num);

    if (p && !read_persist_data(p, &data, &len, "max_priv_for_cipher")) {
	if (len > 9)
	    len = 9;
	memcpy(lan->lanparm.max_priv_for_cipher_suite, data, len);
	free_persist_data(data);
    } else {
	for (i = 0; i < 9; i++)
	    lan->lanparm.max_priv_for_cipher_suite[i]
		= IPMI_PRIVILEGE_ADMIN | (IPMI_PRIVILEGE_ADMIN << 4);
    }

    if (p && !read_persist_int(p, &iv, "privilege_limit")) {
	lan->channel.privilege_limit_nonv = iv;
	lan->channel.privilege_limit = iv;
    } else {
	lan->channel.privilege_limit_nonv = IPMI_PRIVILEGE_ADMIN;
	lan->channel.privilege_limit = IPMI_PRIVILEGE_ADMIN;
    }

    if (p)
	free_persist(p);

    return 0;
}

static int
set_associated_mc(channel_t *chan, uint32_t session_id,
		  unsigned int payload, lmc_data_t *mc,
		  uint16_t *port,
		  void (*close)(lmc_data_t *mc, uint32_t session_id,
				void *cb_data),
		  void *cb_data)
{
    lanserv_data_t *lan = chan->chan_info;
    session_t *session = sid_to_session(lan, session_id);
    lmc_data_t *emc;

    if (payload >= LANSERV_NUM_CLOSERS)
	return EINVAL;

    if (!session)
	return EINVAL;

    emc = session->closers[payload].mc;
    if (emc && mc && (mc != emc))
	return EBUSY;

    session->closers[payload].close_cb = close;
    session->closers[payload].close_cb_data = cb_data;
    session->closers[payload].mc = mc;
    if (port)
	*port = lan->port;
    return 0;
}

static lmc_data_t *
get_associated_mc(channel_t *chan, uint32_t session_id, unsigned int payload)
{
    lanserv_data_t *lan = chan->chan_info;
    session_t *session = sid_to_session(lan, session_id);

    if (payload >= LANSERV_NUM_CLOSERS)
	return NULL;

    return session->closers[payload].mc;
}

int
ipmi_lan_init(lanserv_data_t *lan)
{
    unsigned int i;
    int rv;
    uint8_t challenge_data[16];

    for (i=0; i<=MAX_SESSIONS; i++) {
	lan->sessions[i].handle = i;
    }

    rv = read_lan_config(lan);
    if (rv)
	return rv;

    lan->lanparm.num_destinations = 0; /* LAN alerts not supported */

    lan->lanparm.num_cipher_suites = 15;
    for (i=0; i<17; i++)
	lan->lanparm.cipher_suite_entry[i] = i;

    lan->channel.return_rsp = lan_return_rsp;
    lan->channel.get_lan_parms = get_lan_config_parms;
    lan->channel.set_lan_parms = set_lan_config_parms;
    lan->channel.set_chan_access = set_channel_access;
    lan->channel.set_associated_mc = set_associated_mc;
    lan->channel.get_associated_mc = get_associated_mc;

    /* Force user 1 to be a null user. */
    memset(lan->users[1].username, 0, 16);

    rv = lan->gen_rand(lan, challenge_data, 16);
    if (rv)
	goto out;

    rv = ipmi_md5_authcode_init(challenge_data, &(lan->challenge_auth),
				lan, ialloc, ifree);
    if (rv)
	goto out;

    lan->sid_seq = 0;
    lan->next_challenge_seq = 0;

    /* Default the timeout to 30 seconds. */
    if (lan->default_session_timeout == 0)
	lan->default_session_timeout = 30;

    chan_init(&lan->channel);

    lan->tick_handler.handler = ipmi_lan_tick;
    lan->tick_handler.info = lan;
    ipmi_register_tick_handler(&lan->tick_handler);

 out:
    return rv;
}
