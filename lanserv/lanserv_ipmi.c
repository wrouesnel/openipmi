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
#include <OpenIPMI/lanserv.h>

#include <OpenIPMI/internal/md5.h>


#if 0
static void
dump_data(const unsigned char *d, int l, const char *n)
{
    int i;
    printf("%s:", n);
    for (i=0; i<l; i++) {
	if ((i%16) == 0)
	    printf("\n ");
	printf(" %2.2x", d[i]);
    }
    printf("\n");
}
#endif

/* Deal with multi-byte data, IPMI (little-endian) style. */
static unsigned int ipmi_get_uint16(uint8_t *data)
{
    return (data[0]
	    | (data[1] << 8));
}

static void ipmi_set_uint16(uint8_t *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
}

static unsigned int ipmi_get_uint32(uint8_t *data)
{
    return (data[0]
	    | (data[1] << 8)
	    | (data[2] << 16)
	    | (data[3] << 24));
}

static void ipmi_set_uint32(uint8_t *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
    data[2] = (val >> 16) & 0xff;
    data[3] = (val >> 24) & 0xff;
}

static int
is_authval_null(uint8_t *val)
{
    int i;
    for (i=0; i<16; i++)
	if (val[i] != 0)
	    return 0;
    return 1;
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

static oem_handler_t *oem_handlers = NULL;

void
ipmi_register_oem(oem_handler_t *handler)
{
    handler->next = oem_handlers;
    oem_handlers = handler;
}

static void
check_oem_handlers(lan_data_t *lan)
{
    oem_handler_t *c;

    c = oem_handlers;
    while (c) {
	if ((c->manufacturer_id == lan->manufacturer_id)
	    && (c->product_id == lan->product_id))
	{
	    c->handler(lan, c->cb_data);
	    break;
	}
	c = c->next;
    }
}

static user_t *
find_user(lan_data_t *lan, uint8_t *user, int name_only_lookup, int priv)
{
    int    i;
    user_t *rv = NULL;

    for (i=1; i<=MAX_USERS; i++) {
	if (lan->users[i].valid
	    && (memcmp(user, lan->users[i].username, 16) == 0))
	{
	    if (name_only_lookup || (lan->users[i].privilege == priv)) {
		rv = &(lan->users[i]);
		break;
	    }
	}
    }

    return rv;
}

static uint8_t
ipmb_checksum(uint8_t *data, int size, uint8_t start)
{
	uint8_t csum = start;
	
	for (; size > 0; size--, data++)
		csum += *data;

	return csum;
}


static session_t *
sid_to_session(lan_data_t *lan, unsigned int sid)
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
close_session(lan_data_t *lan, session_t *session)
{
    session->active = 0;
    if (session->authtype <= 4)
	ipmi_auths[session->authtype].authcode_cleanup(session->authdata);
    if (session->integh)
	session->integh->cleanup(lan, session);
    if (session->confh)
	session->confh->cleanup(lan, session);
    lan->active_sessions--;
    if (session->src_addr) {
	lan->free(lan, session->src_addr);
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
gen_challenge(lan_data_t *lan,
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
check_challenge(lan_data_t *lan,
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
#define IPMI_LAN_MAX_TRAILER_SIZE 64

static void
return_rmcpp_rsp(lan_data_t *lan, session_t *session, msg_t *msg,
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
		lan->log(INVALID_MSG, msg,
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
	    lan->log(INVALID_MSG, msg,
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

    lan->lan_send(lan, vec, 1, msg->src_addr, msg->src_len);
}

static void
return_rsp(lan_data_t *lan, msg_t *msg, session_t *session, rsp_msg_t *rsp)
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
	return_rmcpp_rsp(lan, session, msg, 0, rsp->data, rsp->data_len,
			 NULL, 0);
	return;
    } else if (msg->sid == 0) {
	session = &dummy_session;
	session->active = 1;
	session->authtype = IPMI_AUTHTYPE_NONE;
	session->xmit_seq = 0;
	session->sid = 0;
    }

    if (lan->oem_handle_rsp && lan->oem_handle_rsp(lan, msg, session, rsp))
	/* OEM code handled the response. */
	return;

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
    pos[2] = - ipmb_checksum(pos, 2, 0);
    pos[3] = msg->rs_addr;
    pos[4] = (msg->rq_seq << 2) | msg->rs_lun;
    pos[5] = rsp->cmd;

    csum = ipmb_checksum(pos+3, 3, 0);
    csum = - ipmb_checksum(rsp->data, rsp->data_len, csum);

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

    lan->lan_send(lan, vec, 3, msg->src_addr, msg->src_len);
}

static void
return_rsp_data(lan_data_t *lan, msg_t *msg, session_t *session,
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
return_err(lan_data_t *lan, msg_t *msg, session_t *session, uint8_t err)
{
    rsp_msg_t rsp;

    rsp.netfn = msg->netfn | 1;
    rsp.cmd = msg->cmd;
    rsp.data = &err;
    rsp.data_len = 1;
    return_rsp(lan, msg, session, &rsp);
}

static void
handle_get_system_guid(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t data[17];

    if (lan->guid) {
	data[0] = 0;
	memcpy(data+1, lan->guid, 16);
	return_rsp_data(lan, msg, session, data, 17);
    } else {
	lan->log(INVALID_MSG, msg,
		 "Invalid command: 0x%x", msg->cmd);
	return_err(lan, msg, session, IPMI_INVALID_CMD_CC);
    }
}

static void
handle_get_channel_auth_capabilities(lan_data_t *lan, msg_t *msg)
{
    uint8_t data[9];
    uint8_t chan;
    uint8_t priv;
    int     do_rmcpp;

    if (msg->len < 2) {
	lan->log(INVALID_MSG, msg,
		 "Get channel auth failed: message too short");
	return_err(lan, msg, NULL, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    do_rmcpp = (msg->data[0] >> 7) & 1;
    chan = msg->data[0] & 0xf;
    priv = msg->data[1] & 0xf;
    if (chan == 0xe)
	chan = MAIN_CHANNEL;
    if (chan != MAIN_CHANNEL) {
	lan->log(INVALID_MSG, msg,
		 "Get channel auth failed: Invalid channel: %d", chan);
	return_err(lan, msg, NULL, IPMI_INVALID_DATA_FIELD_CC);
    } else if (priv > lan->channel.privilege_limit) {
	lan->log(INVALID_MSG, msg,
		 "Get channel auth failed: Invalid privilege: %d", priv);
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
	data[5] = lan->manufacturer_id & 0xff;
	data[6] = (lan->manufacturer_id >> 8) & 0xff;
	data[7] = (lan->manufacturer_id >> 16) & 0xff;
	data[8] = 0;
	return_rsp_data(lan, msg, NULL, data, 9);
    }
}

static void
handle_get_session_challenge(lan_data_t *lan, msg_t *msg)
{
    uint8_t  data[21];
    user_t   *user;
    uint32_t sid;
    uint8_t  authtype;
    int      rv;

    if (msg->len < 17) {
	lan->log(INVALID_MSG, msg,
		 "Session challenge failed: message too short");
	return_err(lan, msg, NULL, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    authtype = msg->data[0] & 0xf;
    user = find_user(lan, msg->data+1, 1, 0);
    if (!user) {
	lan->log(SESSION_CHALLENGE_FAILED, msg,
		 "Session challenge failed: Invalid user");
	if (is_authval_null(msg->data+1))
	    return_err(lan, msg, NULL, 0x82); /* no null user */
	else
	    return_err(lan, msg, NULL, 0x81); /* no user */
	return;
    }

    if (!(user->allowed_auths & (1 << authtype))) {
	lan->log(SESSION_CHALLENGE_FAILED, msg,
		 "Session challenge failed: Invalid authorization type");
	return_err(lan, msg, NULL, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    data[0] = 0;

    sid = (lan->next_challenge_seq << (USER_BITS_REQ+1)) | (user->idx << 1) | 1;
    lan->next_challenge_seq++;
    ipmi_set_uint32(data+1, sid);

    rv = gen_challenge(lan, data+5, sid);
    if (rv) {
	lan->log(SESSION_CHALLENGE_FAILED, msg,
		 "Session challenge failed: Error generating challenge");
	return_err(lan, msg, NULL, IPMI_UNKNOWN_ERR_CC);
    } else {
	return_rsp_data(lan, msg, NULL, data, 21);
    }
}

static void
handle_no_session(lan_data_t *lan, msg_t *msg)
{
    /* Should be a session challenge, validate everything else. */
    if (msg->seq != 0) {
	lan->log(INVALID_MSG, msg,
		 "No session message failed: Invalid seq");
	return;
    }

    if (msg->authtype != IPMI_AUTHTYPE_NONE) {
	lan->log(INVALID_MSG, msg,
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

	default:
	    lan->log(INVALID_MSG, msg,
		     "No session message failed: Invalid command: 0x%x",
		     msg->cmd);
	    return_err(lan, msg, NULL, IPMI_NOT_SUPPORTED_IN_PRESENT_STATE_CC);
	    break;
    }
}

static void *
ialloc(void *info, int size)
{
    lan_data_t *lan = info;
    return lan->alloc(lan, size);
}

static void
ifree(void *info, void *data)
{
    lan_data_t *lan = info;
    lan->free(lan, data);
}

static session_t *
find_free_session(lan_data_t *lan)
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
handle_temp_session(lan_data_t *lan, msg_t *msg)
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
	lan->log(INVALID_MSG, msg,
		 " message failed: Invalid command: 0x%x", msg->cmd);
	return;
    }

    if (msg->len < 22) {
	lan->log(INVALID_MSG, msg,
		 "Activate session failed: message too short");
	return;
    }

    rv = check_challenge(lan, msg->sid, msg->data+2);
    if (rv) {
	lan->log(NEW_SESSION_FAILED, msg,
		 "Activate session failed: challenge failed");
	return;
    }

    user_idx = (msg->sid >> 1) & USER_MASK;
    if ((user_idx > MAX_USERS) || (user_idx == 0)) {
	lan->log(NEW_SESSION_FAILED, msg,
		 "Activate session failed: Invalid sid: 0x%x", msg->sid);
	return;
    }

    auth = msg->data[0] & 0xf;
    user = &(lan->users[user_idx]);
    if (! (user->valid)) {
	lan->log(NEW_SESSION_FAILED, msg,
		 "Activate session failed: Invalid user idx: 0x%x", user_idx);
	return;
    }
    if (! (user->allowed_auths & (1 << auth))) {
	lan->log(NEW_SESSION_FAILED, msg,
		 "Activate session failed: Requested auth %d was invalid for"
		 " user 0x%x",
		 auth, user_idx);
	return;
    }
    if (! (user->allowed_auths & (1 << msg->authtype))) {
	lan->log(NEW_SESSION_FAILED, msg,
		 "Activate session failed: Message auth %d was invalid for"
		 " user 0x%x",
		 msg->authtype, user_idx);
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
	lan->log(AUTH_FAILED, msg,
		 "Activate session failed: Message auth init failed");
	return;
    }

    /* The "-6, +7" is cheating a little, but we need the last checksum
       to correctly calculate the code. */
    ipmi_set_uint32(tsid, msg->sid);
    ipmi_set_uint32(tseq, msg->seq);
    rv = auth_check(&dummy_session, tsid, tseq, msg->data-6, msg->len+7,
		    msg->authcode);
    if (rv) {
	lan->log(AUTH_FAILED, msg,
		 "Activate session failed: Message auth failed");
	goto out_free;
    }

    /* Note that before this point, we cannot return an error, there's
       no way to generate an authcode for it. */

    if (xmit_seq == 0) {
	lan->log(NEW_SESSION_FAILED, msg,
		 "Activate session failed: Invalid sequence number");
	return_err(lan, msg, &dummy_session, 0x85); /* Invalid seq id */
	goto out_free;
    }

    priv = msg->data[1] & 0xf;
    if ((user->privilege == 0xf)
	|| (priv > user->privilege)
	|| (priv > lan->channel.privilege_limit))
    {
	lan->log(NEW_SESSION_FAILED, msg,
		 "Activate session failed: Privilege %d for user 0x%d failed",
		 priv, user_idx);
	return_err(lan, msg, &dummy_session, 0x86); /* Privilege error */
	goto out_free;
    }

    if (! (lan->channel.priv_info[priv-1].allowed_auths & (1 << auth))) {
	/* Authentication level not permitted for this privilege */
	lan->log(NEW_SESSION_FAILED, msg,
		 "Activate session failed: Auth level %d invalid for"
		 " privilege %d",
		 auth, priv);
	return_err(lan, msg, &dummy_session, IPMI_INVALID_DATA_FIELD_CC);
	goto out_free;
    }

    session = find_free_session(lan);

    if (!session) {
	lan->log(NEW_SESSION_FAILED, msg,
		 "Activate session failed: out of free sessions");
	return_err(lan, msg, &dummy_session, 0x81); /* No session slot */
	goto out_free;
    }

    session->src_addr = lan->alloc(lan, msg->src_len);
    if (!session->src_addr) {
	lan->log(NEW_SESSION_FAILED, msg,
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
	lan->log(NEW_SESSION_FAILED, msg,
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

    lan->log(NEW_SESSION, msg,
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

    lan->active_sessions++;

    return_rsp_data(lan, msg, &dummy_session, data, 11);
    return;

 out_free:
    ipmi_auths[msg->authtype].authcode_cleanup(dummy_session.authdata);
}

/* The command handling below is for active sessions. */

static void
handle_smi_msg(lan_data_t *lan, session_t *session, msg_t *msg)
{
    msg_t *nmsg;
    int   rv;

    nmsg = lan->alloc(lan, sizeof(*nmsg)+msg->src_len+msg->len);
    if (!nmsg) {
	lan->log(OS_ERROR, msg,
		 "SMI message: out of memory");
	return_err(lan, msg, NULL, IPMI_UNKNOWN_ERR_CC);
	return;
    }

    memcpy(nmsg, msg, sizeof(*nmsg));
    nmsg->src_addr = ((char *) nmsg) + sizeof(*nmsg);
    memcpy(nmsg->src_addr, msg->src_addr, msg->src_len);
    nmsg->data  = ((uint8_t *) nmsg->src_addr) + msg->src_len;
    memcpy(nmsg->data, msg->data, msg->len);
    
    rv = lan->smi_send(lan, nmsg);
    if (rv) {
	lan->log(OS_ERROR, msg,
		 "SMI send: error %d", rv);
	lan->free(lan, nmsg);
	if (rv == EMSGSIZE)
	    return_err(lan, msg, session,
		       IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC);
	else
	    return_err(lan, msg, session, IPMI_UNKNOWN_ERR_CC);
	return;
    }
}

static void
handle_activate_session_cmd(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t data[11];

    if (msg->len < 22) {
	lan->log(INVALID_MSG, msg,
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
handle_set_session_privilege(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t data[2];
    uint8_t priv;

    if (msg->len < 1) {
	lan->log(INVALID_MSG, msg,
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
handle_close_session(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint32_t  sid;
    session_t *nses = session;

    if (msg->len < 4) {
	lan->log(INVALID_MSG, msg,
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

    lan->log(SESSION_CLOSED, msg,
	     "Session closed: Closed due to request");

    return_err(lan, msg, session, 0);

    close_session(lan, nses);
}

static void
handle_get_session_info(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t   idx;
    session_t *nses = NULL;
    uint8_t   data[19];

    if (msg->len < 1) {
	lan->log(INVALID_MSG, msg,
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

	if (idx <= lan->active_sessions) {
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
    data[3] = lan->active_sessions;
    if (nses) {
	data[1] = nses->handle;
	data[4] = nses->userid;
	data[5] = nses->priv;
	data[6] = MAIN_CHANNEL | (session->rmcpplus << 4);
	return_rsp_data(lan, msg, session, data, 7);
    } else {
	data[1] = 0;
	return_rsp_data(lan, msg, session, data, 4);
    }

    /* FIXME - We don't currently return the IP information, because
       it's hard to get.  Maybe later. */

}

static void
handle_get_authcode(lan_data_t *lan, session_t *session, msg_t *msg)
{
    lan->log(INVALID_MSG, msg,
	     "Get authcode failure: invalid command");
    /* This is optional, and we don't do it yet. */
    return_err(lan, msg, session, IPMI_INVALID_CMD_CC);
}

static void
handle_set_channel_access(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t upd1, upd2;
    int     write_nonv = 0;
    uint8_t newv;

    if (msg->len < 3) {
	lan->log(INVALID_MSG, msg,
		 "Set channel access failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    if ((msg->data[0] & 0xf) != MAIN_CHANNEL) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    upd1 = (msg->data[1] >> 6) & 0x3;
    if ((upd1 == 1) || (upd1 == 2)) {
	newv = (msg->data[1] >> 4) & 1;
	if (newv) {
	    /* Don't support per-msg authentication */
	    return_err(lan, msg, session, 0x83);
	    return;
	}
	    
	newv = (msg->data[1] >> 3) & 1;
	if (newv) {
	    /* Don't support unauthenticated user-level access */
	    return_err(lan, msg, session, 0x83);
	    return;
	}
	    
	newv = (msg->data[1] >> 0) & 7;
	if (newv != 0x2) {
	    /* Only support "always available" channel */
	    return_err(lan, msg, session, 0x83);
	    return;
	}

	if (upd1 == 1) {
	    lan->channel.PEF_alerting = (msg->data[1] >> 5) & 1;
	} else {
	    lan->nonv_channel.PEF_alerting = (msg->data[1] >> 5) & 1;
	    write_nonv = 1;
	}
    } else if (upd1 != 0) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    upd2 = (msg->data[2] >> 6) & 0x3;
    if ((upd2 == 1) || (upd2 == 2)) {
	newv = (msg->data[2] >> 0) & 0xf;
	if ((newv == 0) || (newv > 4)) {
	    return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	    return;
	}

	if (upd2 == 1) {
	    lan->nonv_channel.privilege_limit = newv;
	    write_nonv = 1;
	} else {
	    lan->channel.privilege_limit = newv;
	}
    } else if (upd2 != 0) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    if (write_nonv)
	lan->write_config(lan);

    return_err(lan, msg, session, 0);
}

static void
handle_get_channel_access(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t   data[3];
    uint8_t   upd;
    channel_t *channel;

    if (msg->len < 2) {
	lan->log(INVALID_MSG, msg,
		 "Get channel access failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    if ((msg->data[0] & 0xf) != MAIN_CHANNEL) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    upd = (msg->data[1] >> 6) & 0x3;

    if (upd == 2) {
	channel = &(lan->channel);
    } else if (upd == 1) {
	channel = &(lan->nonv_channel);
    } else {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    data[0] = 0;
    data[1] = ((channel->PEF_alerting << 5) | 0x2);
    data[2] = channel->privilege_limit;

    return_rsp_data(lan, msg, session, data, 3);
}

static void
handle_get_channel_info(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t data[10];
    uint8_t chan;

    if (msg->len < 1) {
	lan->log(INVALID_MSG, msg,
		 "Get channel info failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    chan = msg->data[0] & 0xf;

    if (chan == 0xe)
	chan = MAIN_CHANNEL;
    if (chan == MAIN_CHANNEL) {
	data[0] = 0;
	data[1] = chan;
	data[2] = 4; /* 802.3 LAN */
	data[3] = 1; /* IPMB, for some reason. */
	data[4] = (2 << 6) | lan->active_sessions;
	data[5] = 0xf2; /* IPMI IANA */
	data[6] = 0x1b;
	data[7] = 0x00;
	data[8] = 0x00;
	data[9] = 0x00;
	return_rsp_data(lan, msg, session, data, 10);
    } else {
	/* Send it on. */
	handle_smi_msg(lan, session, msg);
    }
}

static void
handle_set_user_access(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t user;
    uint8_t priv;
    uint8_t newv;
    int     changed = 0;

    if (msg->len < 3) {
	lan->log(INVALID_MSG, msg,
		 "Set user access failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    if ((msg->data[0] & 0xf) != MAIN_CHANNEL) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    user = msg->data[1] & 0x3f;
    if (user == 0) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    priv = msg->data[2] & 0xf;
    /* Allow privilege level F as the "no access" privilege */
    if (((priv == 0) || (priv > 4)) && (priv != 0xf)) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    if (msg->data[0] & 0x80) {
	newv = (msg->data[0] >> 4) & 1;
	if (newv != lan->users[user].valid) {
	    lan->users[user].valid = newv;
	    changed = 1;
	}
	newv = (msg->data[0] >> 5) & 1;
	if (newv != lan->users[user].link_auth) {
	    lan->users[user].link_auth = newv;
	    changed = 1;
	}
	newv = (msg->data[0] >> 6) & 1;
	if (newv != lan->users[user].cb_only) {
	    lan->users[user].cb_only = newv;
	    changed = 1;
	}
    }

    if (priv != lan->users[user].privilege) {
	lan->users[user].privilege = priv;
	changed = 1;
    }

    if (msg->len >= 4) {
	/* Got the session limit byte. */
	newv = msg->data[3] & 0xf;
	if (newv != lan->users[user].max_sessions) {
	    lan->users[user].max_sessions = newv;
	    changed = 1;
	}
    }

    if (changed)
	lan->write_config(lan);

    return_err(lan, msg, session, 0);
}

static void
handle_get_user_access(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t data[5];
    int     i;
    uint8_t user;

    if (msg->len < 2) {
	lan->log(INVALID_MSG, msg,
		 "Get user access failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    if ((msg->data[0] & 0xf) != MAIN_CHANNEL) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    user = msg->data[1] & 0x3f;
    if (user == 0) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    data[0] = 0;
    data[1] = MAX_USERS;

    /* Number of enabled users. */
    data[2] = 0;
    for (i=1; i<=MAX_USERS; i++) {
	if (lan->users[i].valid)
	    data[2]++;
    }

    /* Only fixed user name is user 1. */
    data[3] = lan->users[1].valid;

    data[4] = ((lan->users[user].valid << 4)
	       | (lan->users[user].link_auth << 5)
	       | (lan->users[user].cb_only << 6)
	       | lan->users[user].privilege);

    return_rsp_data(lan, msg, session, data, 5);
}

static void
handle_set_user_name(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t user;

    if (msg->len < 17) {
	lan->log(INVALID_MSG, msg,
		 "Set user name failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    user = msg->data[0] & 0x3f;
    if (user <= 1) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    memcpy(lan->users[user].username, msg->data+1, 16);
    cleanup_ascii_16(lan->users[user].username);

    return_err(lan, msg, session, 0);
}

static void
handle_get_user_name(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t user;
    uint8_t data[17];

    if (msg->len < 1) {
	lan->log(INVALID_MSG, msg,
		 "Get user name failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    user = msg->data[0] & 0x3f;
    if (user <= 1) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    data[0] = 0;
    memcpy(data+1, lan->users[user].username, 16);

    return_rsp_data(lan, msg, session, data, 17);
}

static void
handle_set_user_password(lan_data_t *lan, session_t *session, msg_t *msg)
{
    uint8_t user;
    uint8_t op;

    if (msg->len < 2) {
	lan->log(INVALID_MSG, msg,
		 "Set user password failure: message too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    user = msg->data[0] & 0x3f;
    if (user == 0) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    op = msg->data[1] & 0x3;
    if (op == 0) {
	lan->users[user].valid = 0;
    } else if (op == 1) {
	lan->users[user].valid = 1;
    } else {
	if (msg->len < 18) {
	    lan->log(INVALID_MSG, msg,
		     "Set user password failure: message too short");
	    return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	    return;
	}
	if (op == 2) {
	    memcpy(lan->users[user].pw, msg->data+2, 16);
	} else {
	    /* Nothing to do for test password, we accept anything. */
	}
    }

    return_err(lan, msg, session, 0);
}

static void
handle_ipmi_set_lan_config_parms(lan_data_t *lan,
				 session_t  *session,
				 msg_t      *msg)
{
    unsigned char err = 0;
    int           idx;

    if (msg->len < 3) {
	lan->log(INVALID_MSG, msg, "Set lan config parm too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    if ((msg->data[0] & 0xf) != MAIN_CHANNEL) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

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
	    }
	    /* No affect otherwise */
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
	    if (lan->lanparm.commit)
		lan->lanparm.commit(lan);
	    memset(&lan->lanparm.changed, 0, sizeof(lan->lanparm.changed));
	    lan->lanparm.set_in_progress = 0;
	    break;

	case 3:
	    err = IPMI_INVALID_DATA_FIELD_CC;
	}
	break;

    case 1:
    case 17:
    case 22:
    case 23:
	err = 0x82; /* Read-only data */
	break;

    case 2:
	if (msg->len < 7)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.auth_type_enables, msg->data+2, 5);
	    lan->lanparm.changed.auth_type_enables = 1;
	}
	break;

    case 3:
	if (msg->len < 6)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.ip_addr, msg->data+2, 4);
	    lan->lanparm.changed.ip_addr = 1;
	}
	break;

    case 4:
	lan->lanparm.ip_addr_src = msg->data[2];
	lan->lanparm.changed.ip_addr_src = 1;
	break;

    case 5:
	if (msg->len < 8)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.mac_addr, msg->data+2, 6);
	    lan->lanparm.changed.mac_addr = 1;
	}
	break;

    case 6:
	if (msg->len < 6)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.subnet_mask, msg->data+2, 4);
	    lan->lanparm.changed.subnet_mask = 1;
	}
	break;

    case 7:
	if (msg->len < 5)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.ipv4_hdr_parms, msg->data+2, 3);
	    lan->lanparm.changed.ipv4_hdr_parms = 1;
	}
	break;

    case 8:
	if (msg->len < 4)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.primary_rmcp_port, msg->data+2, 2);
	    lan->lanparm.changed.primary_rmcp_port = 1;
	}
	break;

    case 9:
	if (msg->len < 4)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.secondary_rmcp_port, msg->data+2, 2);
	    lan->lanparm.changed.secondary_rmcp_port = 1;
	}
	break;

    case 10:
	lan->lanparm.bmc_gen_arp_ctl = msg->data[2];
	lan->lanparm.changed.bmc_gen_arp_ctl = 1;
	break;

    case 11:
	lan->lanparm.garp_interval = msg->data[2];
	lan->lanparm.changed.garp_interval = 1;
	break;

    case 12:
	if (msg->len < 6)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.default_gw_ip_addr, msg->data+2, 4);
	    lan->lanparm.changed.default_gw_ip_addr = 1;
	}
	break;

    case 13:
	if (msg->len < 8)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.default_gw_mac_addr, msg->data+2, 6);
	    lan->lanparm.changed.default_gw_mac_addr = 1;
	}
	break;

    case 14:
	if (msg->len < 6)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.backup_gw_ip_addr, msg->data+2, 4);
	    lan->lanparm.changed.backup_gw_ip_addr = 1;
	}
	break;

    case 15:
	if (msg->len < 8)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.backup_gw_mac_addr, msg->data+2, 6);
	    lan->lanparm.changed.backup_gw_mac_addr = 1;
	}
	break;

    case 16:
	if (msg->len < 20)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.community_string, msg->data+2, 18);
	    lan->lanparm.changed.community_string = 1;
	}
	break;

    case 18:
	idx = msg->data[2] & 0xf;
	if (msg->len < 6)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if (idx > lan->lanparm.num_destinations)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    memcpy(lan->lanparm.dest[idx].type, msg->data+2, 4);
	    lan->lanparm.changed.dest_type[idx] = 1;
	}
	break;

    case 19:
	idx = msg->data[2] & 0xf;
	if (msg->len < 15)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if (idx > lan->lanparm.num_destinations)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    memcpy(lan->lanparm.dest[idx].addr, msg->data+2, 13);
	    lan->lanparm.changed.dest_addr[idx] = 1;
	}
	break;

    case 20:
	if (msg->len < 4)
	    err = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.vlan_id, msg->data+2, 2);
	    lan->lanparm.changed.vlan_id = 1;
	}
	break;

    case 21:
	lan->lanparm.vlan_priority = msg->data[2];
	lan->lanparm.changed.vlan_priority = 1;
	break;

    case 24:
	if (msg->len < 11)
	    err = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->lanparm.max_priv_for_cipher_suite, msg->data+2, 9);
	    lan->lanparm.changed.max_priv_for_cipher_suite = 1;
	}
	break;

    case 25:
	idx = msg->data[2] & 0xf;
	if (msg->len < 6)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if (idx > lan->lanparm.num_destinations)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    memcpy(lan->lanparm.dest[idx].vlan, msg->data+2, 4);
	    lan->lanparm.changed.dest_vlan[idx] = 1;
	}
	break;

    default:
	err = 0x80; /* Parm not supported */
    }

    return_err(lan, msg, session, err);
}

static void
return_lan_config_data(lan_data_t *lan, unsigned int rev, int rev_only,
		       msg_t *msg, session_t *session,
		       unsigned char *data, unsigned int data_len)
{
    rsp_msg_t rsp;
    unsigned char d[36];
    unsigned int  d_len;

    d[0] = 0;
    d[1] = rev;
    if (rev_only) {
	d_len = 2;
    } else {
	memcpy(d+2, data, data_len);
	d_len = data_len + 2;
    }
	
    rsp.netfn = IPMI_TRANSPORT_NETFN | 1;
    rsp.cmd = IPMI_GET_LAN_CONFIG_PARMS_CMD;
    rsp.data = d;
    rsp.data_len = d_len;
    return_rsp(lan, msg, session, &rsp);
}


static void
handle_ipmi_get_lan_config_parms(lan_data_t *lan,
				 session_t  *session,
				 msg_t      *msg)
{
    int           idx;
    unsigned char databyte = 0;
    unsigned char *data = NULL;
    unsigned int  length = 0;

    if (msg->len < 4) {
	lan->log(INVALID_MSG, msg, "Get lan config parm too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    if ((msg->data[0] & 0xf) != MAIN_CHANNEL) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    switch (msg->data[1])
    {
    case 0:
	databyte = lan->lanparm.set_in_progress;
	break;

    case 1:
	databyte = lan->lanparm.auth_type_support;
	break;

    case 17:
	databyte = lan->lanparm.num_destinations;
	break;

    case 2:
	data = lan->lanparm.auth_type_enables;
	length = 5;
	break;

    case 3:
	data = lan->lanparm.ip_addr;
	length = 4;
	break;

    case 4:
	databyte = lan->lanparm.ip_addr_src;
	break;

    case 5:
	data = lan->lanparm.mac_addr;
	length = 6;
	break;

    case 6:
	data = lan->lanparm.subnet_mask;
	length = 4;
	break;

    case 7:
	data = lan->lanparm.ipv4_hdr_parms;
	length = 3;
	break;

    case 8:
	data = lan->lanparm.primary_rmcp_port;
	length = 2;
	break;

    case 9:
	data = lan->lanparm.secondary_rmcp_port;
	length = 2;
	break;

    case 10:
	databyte = lan->lanparm.bmc_gen_arp_ctl;
	break;

    case 11:
	databyte = lan->lanparm.garp_interval;
	break;

    case 12:
	data = lan->lanparm.default_gw_ip_addr;
	length = 4;
	break;

    case 13:
	data = lan->lanparm.default_gw_mac_addr;
	length = 6;
	break;

    case 14:
	data = lan->lanparm.backup_gw_ip_addr;
	length = 4;
	break;

    case 15:
	data = lan->lanparm.backup_gw_mac_addr;
	length = 6;
	break;

    case 16:
	data = lan->lanparm.community_string;
	length = 18;
	break;

    case 18:
	idx = msg->data[2] & 0xf;
	if (idx > lan->lanparm.num_destinations) {
	    return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	    return;
	} else {
	    data = lan->lanparm.dest[idx].type;
	    length = 4;
	}
	break;

    case 19:
	idx = msg->data[2] & 0xf;
	if (idx > lan->lanparm.num_destinations) {
	    return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	    return;
	} else {
	    data = lan->lanparm.dest[idx].addr;
	    length = 13;
	}
	break;

    case 20:
	data = lan->lanparm.vlan_id;
	length = 2;
	break;

    case 21:
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

    case 25:
	idx = msg->data[2] & 0xf;
	if (idx > lan->lanparm.num_destinations) {
	    return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	    return;
	} else {
	    data = lan->lanparm.dest[idx].vlan;
	    length = 4;
	}
	break;

    default:
	return_err(lan, msg, session, 0x80); /* Parm not supported */
	return;
    }

    if (data) {
	return_lan_config_data(lan, 0x11, msg->data[0] & 0x80,
			       msg, session, data, length);
    } else {
	return_lan_config_data(lan, 0x11, msg->data[0] & 0x80,
			       msg, session, &databyte, 1);
    }
}

static void
handle_ipmi_get_pef_capabilities(lan_data_t *lan,
				 session_t  *session,
				 msg_t      *msg)
{
    unsigned char data[4];

    data[0] = 0;
    data[1] = 0x51; /* version */
    data[2] = 0x3f; /* support everything but OEM */
    data[3] = MAX_EVENT_FILTERS;

    return return_rsp_data(lan, msg, session, data, 4);
}

static void
handle_ipmi_set_pef_config_parms(lan_data_t *lan,
				 session_t  *session,
				 msg_t      *msg)
{
    unsigned char err = 0;
    int           set, block;

    if (msg->len < 2) {
	lan->log(INVALID_MSG, msg, "Set pef config parm too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    switch (msg->data[0] & 0x7f)
    {
    case 0:
	switch (msg->data[1] & 0x3)
	{
	case 0:
	    if (lan->pef.set_in_progress) {
		/* rollback */
		memcpy(&lan->pef, &lan->pef_rollback,
		       sizeof(lan->pef));
	    }
	    /* No affect otherwise */
	    break;

	case 1:
	    if (lan->pef.set_in_progress)
		err = 0x81; /* Another user is writing. */
	    else {
		/* Save rollback data */
		memcpy(&lan->pef_rollback, &lan->pef,
		       sizeof(lan->pef));
		lan->pef.set_in_progress = 1;
	    }
	    break;

	case 2:
	    if (lan->pef.commit)
		lan->pef.commit(lan);
	    memset(&lan->pef.changed, 0, sizeof(lan->pef.changed));
	    lan->pef.set_in_progress = 0;
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
	lan->pef.pef_control = msg->data[1];
	lan->pef.changed.pef_control = 1;
	break;

    case 2:
	lan->pef.pef_action_global_control = msg->data[1];
	lan->pef.changed.pef_action_global_control = 1;
	break;

    case 3:
	lan->pef.pef_startup_delay = msg->data[1];
	lan->pef.changed.pef_startup_delay = 1;
	break;

    case 4:
	lan->pef.pef_alert_startup_delay = msg->data[1];
	lan->pef.changed.pef_alert_startup_delay = 1;
	break;

    case 6:
	set = msg->data[1] & 0x7f;
	if (msg->len < 22)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if ((set <= 0) || (set >= lan->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(lan->pef.event_filter_table[set], msg->data+1, 21);
	    lan->pef.changed.event_filter_table[set] = 1;
	}
	break;

    case 7:
	set = msg->data[1] & 0x7f;
	if (msg->len < 3)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if ((set <= 0) || (set >= lan->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(lan->pef.event_filter_data1[set], msg->data+1, 2);
	    lan->pef.changed.event_filter_data1[set] = 1;
	}
	break;

    case 9:
	set = msg->data[1] & 0x7f;
	if (msg->len < 5)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if ((set <= 0) || (set >= lan->pef.num_alert_policies))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(lan->pef.alert_policy_table[set], msg->data+1, 4);
	    lan->pef.changed.alert_policy_table[set] = 1;
	}
	break;

    case 10:
	if (msg->len < 18)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(lan->pef.system_guid, msg->data+1, 17);
	    lan->pef.changed.system_guid = 1;
	}
	break;

    case 12:
	set = msg->data[1] & 0x7f;
	if (msg->len < 4)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if (set >= lan->pef.num_alert_strings)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(lan->pef.alert_string_keys[set], msg->data+1, 3);
	    lan->pef.changed.alert_string_keys[set] = 1;
	}
	break;

    case 13:
	set = msg->data[1] & 0x7f;
	if (msg->len < 4)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if (set >= lan->pef.num_alert_strings)
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
	    memcpy(lan->pef.alert_strings[set]+(block*16), msg->data+3, dlen);
	    lan->pef.changed.alert_strings[set] = 1;
	}
	break;

    default:
	err = 0x80; /* Parm not supported */
    }

    return_err(lan, msg, session, err);
}

static void
return_pef_config_data(lan_data_t *lan, unsigned int rev, int rev_only,
		       msg_t *msg, session_t *session,
		       unsigned char *data, unsigned int data_len)
{
    rsp_msg_t rsp;
    unsigned char d[36];
    unsigned int  d_len;

    d[0] = 0;
    d[1] = rev;
    if (rev_only) {
	d_len = 2;
    } else {
	memcpy(d+2, data, data_len);
	d_len = data_len + 2;
    }
	
    rsp.netfn = IPMI_SENSOR_EVENT_NETFN | 1;
    rsp.cmd = IPMI_GET_PEF_CONFIG_PARMS_CMD;
    rsp.data = d;
    rsp.data_len = d_len;
    return_rsp(lan, msg, session, &rsp);
}


static void
handle_ipmi_get_pef_config_parms(lan_data_t *lan,
				 session_t  *session,
				 msg_t      *msg)
{
    int           set, block;
    unsigned char databyte = 0;
    unsigned char *data = NULL;
    unsigned int  length = 0;
    unsigned char err = 0;
    unsigned char tmpdata[18];

    if (msg->len < 3) {
	lan->log(INVALID_MSG, msg, "Get pef config parm too short");
	return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    switch (msg->data[0] & 0x7f)
    {
    case 0:
	databyte = lan->pef.set_in_progress;
	break;

    case 5:
	databyte = lan->pef.num_event_filters - 1;
	break;

    case 8:
	databyte = lan->pef.num_alert_policies - 1;
	break;

    case 11:
	databyte = lan->pef.num_alert_strings - 1;
	break;

    case 1:
	databyte = lan->pef.pef_control;
	break;

    case 2:
	databyte = lan->pef.pef_action_global_control;
	break;

    case 3:
	databyte = lan->pef.pef_startup_delay;
	break;

    case 4:
	databyte = lan->pef.pef_alert_startup_delay;
	break;

    case 6:
	set = msg->data[1] & 0x7f;
	if ((set <= 0) || (set >= lan->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = lan->pef.event_filter_table[set];
	    length = 21;
	}
	break;

    case 7:
	set = msg->data[1] & 0x7f;
	if ((set <= 0) || (set >= lan->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = lan->pef.event_filter_data1[set];
	    length = 2;
	}
	break;

    case 9:
	set = msg->data[1] & 0x7f;
	if ((set <= 0) || (set >= lan->pef.num_alert_policies))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = lan->pef.alert_policy_table[set];
	    length = 4;
	}
	break;

    case 10:
	data = lan->pef.system_guid;
	length = 17;
	break;

    case 12:
	set = msg->data[1] & 0x7f;
	if (set >= lan->pef.num_alert_strings)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = lan->pef.alert_string_keys[set];
	    length = 3;
	}
	break;

    case 13:
	set = msg->data[1] & 0x7f;
	if (set >= lan->pef.num_alert_strings)
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
	    memcpy(tmpdata+2, lan->pef.alert_strings[set]+(block*16), 16);
	    data = tmpdata;
	    length = 18;
	}
	break;

    default:
	err = 0x80; /* Parm not supported */
    }

    if (err) {
	return_err(lan, msg, session, err);
    } else if (data) {
	return_pef_config_data(lan, 0x11, msg->data[0] & 0x80,
			       msg, session, data, length);
    } else {
	return_pef_config_data(lan, 0x11, msg->data[0] & 0x80,
			       msg, session, &databyte, 1);
    }
}

static void
handle_normal_session(lan_data_t *lan, msg_t *msg)
{
    session_t *session = sid_to_session(lan, msg->sid);
    int       rv;

    if (session == NULL) {
	lan->log(INVALID_MSG, msg,
		 "Normal session message failure: Invalid SID");
	return;
    }

    session->time_left = lan->default_session_timeout;

    if (lan->oem_handle_msg && lan->oem_handle_msg(lan, msg, session))
	/* OEM code handled the message. */
	return;

    rv = IPMI_PRIV_INVALID;
    if (lan->oem_check_permitted)
	rv = lan->oem_check_permitted(session->priv, msg->netfn, msg->cmd);
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
	lan->log(INVALID_MSG, msg,
		 "Normal session message failure: no privilege");
	return_err(lan, msg, session, IPMI_INSUFFICIENT_PRIVILEGE_CC);
	return;

    case IPMI_PRIV_INVALID:
    default:
	lan->log(INVALID_MSG, msg,
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

	case IPMI_GET_AUTHCODE_CMD:
	    handle_get_authcode(lan, session, msg);
	    break;

	case IPMI_SET_CHANNEL_ACCESS_CMD:
	    handle_set_channel_access(lan, session, msg);
	    break;

	case IPMI_GET_CHANNEL_ACCESS_CMD:
	    handle_get_channel_access(lan, session, msg);
	    break;

	case IPMI_GET_CHANNEL_INFO_CMD:
	    handle_get_channel_info(lan, session, msg);
	    break;

	case IPMI_SET_USER_ACCESS_CMD:
	    handle_set_user_access(lan, session, msg);
	    break;

	case IPMI_GET_USER_ACCESS_CMD:
	    handle_get_user_access(lan, session, msg);
	    break;

	case IPMI_SET_USER_NAME_CMD:
	    handle_set_user_name(lan, session, msg);
	    break;

	case IPMI_GET_USER_NAME_CMD:
	    handle_get_user_name(lan, session, msg);
	    break;

	case IPMI_SET_USER_PASSWORD_CMD:
	    handle_set_user_password(lan, session, msg);
	    break;

	default:
	    handle_smi_msg(lan, session, msg);
	}
    } else if (msg->netfn == IPMI_TRANSPORT_NETFN) {
	switch (msg->cmd)
	{
	case IPMI_SET_LAN_CONFIG_PARMS_CMD:
	    handle_ipmi_set_lan_config_parms(lan, session, msg);
	    break;

	case IPMI_GET_LAN_CONFIG_PARMS_CMD:
	    handle_ipmi_get_lan_config_parms(lan, session, msg);
	    break;

	default:
	    lan->log(INVALID_MSG, msg,
		     "Normal session message failure: Invalid cmd: 0x%x",
		     msg->cmd);
	    return_err(lan, msg, session, IPMI_INVALID_CMD_CC);
	    break;
	}
    } else if (msg->netfn == IPMI_SENSOR_EVENT_NETFN) {
	switch (msg->cmd)
	{
	case IPMI_GET_PEF_CAPABILITIES_CMD:
	    handle_ipmi_get_pef_capabilities(lan, session, msg);
	    break;

	case IPMI_SET_PEF_CONFIG_PARMS_CMD:
	    handle_ipmi_set_pef_config_parms(lan, session, msg);
	    break;

	case IPMI_GET_PEF_CONFIG_PARMS_CMD:
	    handle_ipmi_get_pef_config_parms(lan, session, msg);
	    break;

	default:
	    goto normal_msg;
	}
    } else {
    normal_msg:
	handle_smi_msg(lan, session, msg);
    }
}

void
handle_ipmi_payload(lan_data_t *lan, msg_t *msg)
{
    if (msg->len < 7) {
	lan->log(LAN_ERR, msg,
		 "LAN msg failure: Length field too short");
	return;
    }

    if (ipmb_checksum(msg->data, 3, 0) != 0) {
	lan->log(LAN_ERR, msg,
		 "LAN msg failure: Checksum 1 failed");
	return;
    }
    if (ipmb_checksum(msg->data+3, msg->len-3, 0) != 0) {
	lan->log(LAN_ERR, msg,
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

    if (lan->debug) {
	lan->log(DEBUG, msg, "msg: netfn = 0x%2.2x cmd=%2.2x",
		 msg->netfn, msg->cmd);
    }

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
rakp_hmac_sha1_init(lan_data_t *lan, session_t *session)
{
    session->auth_data.akey = EVP_sha1();
    session->auth_data.akey_len = 20;
    session->auth_data.integ_len = 12;
    return 0;
}

static int 
rakp_hmac_md5_init(lan_data_t *lan, session_t *session)
{
    session->auth_data.akey = EVP_md5();
    session->auth_data.akey_len = 16;
    session->auth_data.integ_len = 16;
    return 0;
}

static int
rakp_hmac_set2(lan_data_t *lan, session_t *session,
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
rakp_hmac_check3(lan_data_t *lan, session_t *session,
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
rakp_hmac_set4(lan_data_t *lan, session_t *session,
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
hmac_sha1_init(lan_data_t *lan, session_t *session)
{
    session->auth_data.ikey2 = EVP_sha1();
    session->auth_data.ikey = session->auth_data.k1;
    session->auth_data.ikey_len = 20;
    session->auth_data.integ_len = 12;
    return 0;
}

static int
hmac_md5_init(lan_data_t *lan, session_t *session)
{
    user_t *user = &(lan->users[session->userid]);
    session->auth_data.ikey2 = EVP_md5();
    session->auth_data.ikey = user->pw;
    session->auth_data.ikey_len = 16;
    session->auth_data.integ_len = 16;
    return 0;
}

static void
hmac_cleanup(lan_data_t *lan, session_t *session)
{
}

static int 
hmac_add(lan_data_t *lan, session_t *session,
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
hmac_check(lan_data_t *lan, session_t *session, msg_t *msg)
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
md5_init(lan_data_t *lan, session_t *session)
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
md5_cleanup(lan_data_t *lan, session_t *session)
{
    ipmi_md5_authcode_cleanup(session->auth_data.idata);
    session->auth_data.idata = NULL;
}

static int 
md5_add(lan_data_t *lan, session_t *session,
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
md5_check(lan_data_t *lan, session_t *session, msg_t *msg)
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
aes_cbc_init(lan_data_t *lan, session_t *session)
{
    session->auth_data.ckey = session->auth_data.k2;
    session->auth_data.ckey_len = 16;
    return 0;
}

static void
aes_cbc_cleanup(lan_data_t *lan, session_t *session)
{
}

static int
aes_cbc_encrypt(lan_data_t *lan, session_t *session,
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
aes_cbc_decrypt(lan_data_t *lan, session_t *session, msg_t *msg)
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

void
handle_open_session_payload(lan_data_t *lan, msg_t *msg)
{
    unsigned char data[36];
    unsigned char priv;
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

    session = find_free_session(lan);
    if (!session) {
	lan->log(NEW_SESSION_FAILED, msg,
		 "Activate session failed: out of free sessions");
	err = IPMI_RMCPP_INSUFFICIENT_RESOURCES_FOR_SESSION;
	goto out_err;
    }

    session->src_addr = lan->alloc(lan, msg->src_len);
    if (!session->src_addr) {
	lan->log(NEW_SESSION_FAILED, msg,
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
	lan->log(NEW_SESSION_FAILED, msg,
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

    lan->log(NEW_SESSION, msg,
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

    lan->active_sessions++;

    return_rmcpp_rsp(lan, session, msg, 0x11, data, 36, NULL, 0);
    return;
 out_err:

    data[0] = msg->data[0];
    data[1] = err;
    return_rmcpp_rsp(lan, session, msg, 0x11, data, 2, NULL, 0);
    if (session)
	close_session(lan, session);
}

void handle_rakp1_payload(lan_data_t *lan, msg_t *msg)
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
	lan->log(NEW_SESSION_FAILED, msg,
		 "RAKP msg: name length too long: %d", name_len);
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out_err;
    }
    if ((unsigned int) (28+name_len) > msg->len) {
	lan->log(NEW_SESSION_FAILED, msg,
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
	lan->log(NEW_SESSION_FAILED, msg,
		 "RAKP msg: invalid user: %s", user);
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
	    lan->log(NEW_SESSION_FAILED, msg,
		     "RAKP msg: set2 failed: 0x%x", rv);
	    return;
	}
    }
    
    return_rmcpp_rsp(lan, session, msg, 0x13, data, len, NULL, 0);

    if (err)
	close_session(lan, session);
}

void handle_rakp3_payload(lan_data_t *lan, msg_t *msg)
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
	    lan->log(NEW_SESSION_FAILED, msg,
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
	    lan->log(NEW_SESSION_FAILED, msg,
		     "RAKP msg: set4 failed: 0x%x", rv);
	}
    }
    
    return_rmcpp_rsp(lan, session, msg, 0x15, data, len, NULL, 0);

    if (err)
	close_session(lan, session);
    else
	session->in_startup = 0;
}

typedef void (*payload_handler_cb)(lan_data_t *lan, msg_t *msg);

payload_handler_cb payload_handlers[64] =
{
    [0] = handle_ipmi_payload,
    [0x10] = handle_open_session_payload,
    [0x12] = handle_rakp1_payload,
    [0x14] = handle_rakp3_payload,
};

int
decrypt_message(lan_data_t *lan, session_t *session, msg_t *msg)
{
    if (!msg->encrypted) {
	if (session->conf != 0) {
	    lan->log(INVALID_MSG, msg,
		     "Message failure:"
		     " Unencrypted msg on encrypted session");
	    return EINVAL;
	}
	return 0;
    }

    return session->confh->decrypt(lan, session, msg);
}

int
check_message_integrity(lan_data_t *lan, session_t *session, msg_t *msg)
{
    if (!msg->authenticated) {
	if (session->integ != 0) {
	    lan->log(INVALID_MSG, msg,
		     "Message failure:"
		     " Unauthenticated msg on authenticated session");
	    return EINVAL;
	}
	return 0;
    } else if (session->integ == 0) {
	lan->log(INVALID_MSG, msg,
		 "Message failure:"
		 " Authenticated msg on unauthenticated session");
	return EINVAL;
    }

    return session->integh->check(lan, session, msg);
}

void
ipmi_handle_rmcpp_msg(lan_data_t *lan, msg_t *msg)
{
    unsigned int len;
    uint32_t     *seq;
    msg_t        imsg;

    imsg.data = msg->data-1;
    imsg.len = msg->len+1;

    if (msg->len < 11) {
	lan->log(LAN_ERR, msg,
		 "LAN msg failure: message too short");
	return;
    }
    msg->payload = msg->data[0] & 0x3f;
    msg->encrypted = (msg->data[0] >> 7) & 1;
    msg->authenticated = (msg->data[0] >> 6) & 1;
    msg->data++;
    if (msg->payload == 2) {
	if (msg->len < 17) {
	    lan->log(LAN_ERR, msg,
		     "LAN msg failure: message too short");
	    return;
	}
	memcpy(msg->iana, msg->data+1, 3);
	msg->data+= 4;
	msg->payload_id = ipmi_get_uint16(msg->data);
	msg->data += 2;
    }
    msg->sid = ipmi_get_uint32(msg->data);
    msg->data += 4;
    msg->seq = ipmi_get_uint32(msg->data);
    msg->data += 4;
    len = ipmi_get_uint16(msg->data);
    msg->data += 2;
    if (len > msg->len) {
	lan->log(LAN_ERR, msg,
		 "LAN msg failure: Length field invalid: %d, %d",
		 len, msg->len);
	return; /* The length field is not valid.  We allow extra
		   bytes, but reject if not enough. */
    }

    msg->authdata_len = msg->len - len;
    msg->authdata = msg->data + len;
    msg->len = len;

    if (msg->sid == 0) {
	if (msg->authenticated || msg->encrypted) {
	    lan->log(LAN_ERR, msg,
		     "LAN msg failure:"
		     " Got encrypted or authenticated SID 0 msg");
	    return;
	}
    } else {
	session_t    *session = sid_to_session(lan, msg->sid);
	int          rv;
	int          diff;

	if (session == NULL) {
	    lan->log(INVALID_MSG, msg,
		     "Normal session message failure: Invalid SID");
	    return;
	}

	if (!session->rmcpplus) {
	    lan->log(INVALID_MSG, msg,
		     "Normal session message failure:"
		     " RMCP+ msg on RMCP session");
	    return;
	}

	imsg.encrypted = msg->encrypted;
	imsg.authenticated = msg->authenticated;

	rv = check_message_integrity(lan, session, &imsg);
	if (rv) {
	    lan->log(LAN_ERR, msg,
		     "LAN msg failure:"
		     " Message integrity failed");
	    return;
	}

	rv = decrypt_message(lan, session, msg);
	if (rv) {
	    lan->log(LAN_ERR, msg,
		     "LAN msg failure:"
		     " Message decryption failed");
	    return;
	}

	/* Check that the session sequence number is valid.  We make
	   sure it is within 8 of the last highest received sequence
	   number, per the spec. */
	if (msg->authenticated)
	    seq = &session->recv_seq;
	else
	    seq = &session->unauth_recv_seq;
	diff = msg->seq - *seq;
	if ((diff < -16) || (diff > 15)) {
	    lan->log(INVALID_MSG, msg,
		     "Normal session message failure: SEQ out of range");
	    return;
	}

	/* We wait until after the message is authenticated to set the
	   sequence number, to prevent spoofing. */
	if (msg->seq > *seq)
	    *seq = msg->seq;
    }

    if (payload_handlers[msg->payload])
	payload_handlers[msg->payload](lan, msg);
}

void
ipmi_handle_rmcp_msg(lan_data_t *lan, msg_t *msg)
{
    unsigned char *tsid;
    unsigned char *tseq;

    if (msg->len < 9) {
	lan->log(LAN_ERR, msg,
		 "LAN msg failure: message too short");
	return;
    }

    tseq = msg->data+0;
    msg->seq = ipmi_get_uint32(msg->data+0);
    tsid = msg->data+4;
    msg->sid = ipmi_get_uint32(msg->data+4);

    if (msg->authtype != IPMI_AUTHTYPE_NONE) {
	if (msg->len < 25) {
	    lan->log(LAN_ERR, msg,
		     "LAN msg failure: message too short");
	    return;
	}

	memcpy(msg->authcode_data, msg->data + 8, 16);
	msg->authcode = msg->authcode_data;
	msg->data += 24;
	msg->len -= 24;
    } else {
	msg->authcode = NULL;
	msg->data += 8;
	msg->len -= 8;
    }
    if (msg->len < msg->data[0]) {
	lan->log(LAN_ERR, msg,
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
	    lan->log(INVALID_MSG, msg,
		     "Normal session message failure: Invalid SID");
	    return;
	}

	if (session->rmcpplus) {
	    lan->log(INVALID_MSG, msg,
		     "Normal session message failure:"
		     " RMCP msg on RMCP+ session");
	    return;
	}

	rv = auth_check(session, tsid, tseq, msg->data, msg->len,
			msg->authcode);
	if (rv) {
	    lan->log(AUTH_FAILED, msg,
		     "Normal session message failure: auth failure");
	    return;
	}

	/* Check that the session sequence number is valid.  We make sure
	   it is within 8 of the last highest received sequence number,
	   per the spec. */
	diff = msg->seq - session->recv_seq;
	if ((diff < -8) || (diff > 8)) {
	    lan->log(INVALID_MSG, msg,
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
ipmi_handle_lan_msg(lan_data_t *lan,
		    uint8_t *data, int len,
		    void *from_addr, int from_len)
{
    msg_t   msg;

    msg.src_addr = from_addr;
    msg.src_len = from_len;

    msg.oem_data = 0;

    if (len < 5) {
	lan->log(LAN_ERR, &msg,
		 "LAN msg failure: message too short");
	return;
    }

    if (data[2] != 0xff) {
	lan->log(LAN_ERR, &msg,
		 "LAN msg failure: seq not ff");
	return; /* Sequence # must be ff (no ack) */
    }

    msg.authtype = data[4];
    msg.data = data+5;
    msg.len = len - 5;

    if (msg.authtype == IPMI_AUTHTYPE_RMCP_PLUS) {
	ipmi_handle_rmcpp_msg(lan, &msg);
    } else {
	ipmi_handle_rmcp_msg(lan, &msg);
    }

}

void
ipmi_handle_smi_rsp(lan_data_t *lan, msg_t *msg,
		    uint8_t *rsp, int rsp_len)
{
    return_rsp_data(lan, msg, NULL, rsp, rsp_len);
    lan->free(lan, msg);
}

void
ipmi_lan_tick(lan_data_t *lan, unsigned int time_since_last)
{
    int i;
    msg_t msg; /* A fake message to hold the address. */

    for (i=1; i<=MAX_SESSIONS; i++) {
	if (lan->sessions[i].active) {
	    if (lan->sessions[i].time_left <= time_since_last) {
		msg.src_addr = lan->sessions[i].src_addr;
		msg.src_len = lan->sessions[i].src_len;
		lan->log(SESSION_CLOSED, &msg,
			 "Session closed: Closed due to timeout");
		close_session(lan, &(lan->sessions[i]));
	    } else {
		lan->sessions[i].time_left -= time_since_last;
	    }
	}
    }
}

static int
lan_look_for_get_devid(lan_data_t *lan, msg_t *msg, session_t *session,
		       rsp_msg_t *rsp)
{
    if ((rsp->netfn == (IPMI_APP_NETFN | 1))
	&& (rsp->cmd == IPMI_GET_DEVICE_ID_CMD)
	&& (rsp->data_len >= 12)
	&& (rsp->data[0] == 0))
    {
	lan->oem_handle_rsp = NULL;
	lan->manufacturer_id = (rsp->data[7]
				| (rsp->data[8] << 8)
				| (rsp->data[9] << 16));
	lan->product_id = rsp->data[10] | (rsp->data[11] << 8);
	check_oem_handlers(lan);

	/* Will be set to 1 if we sent it. */
	return msg->oem_data;
    }
    return 0;
}

int
ipmi_oem_send_msg(lan_data_t    *lan,
		  unsigned char netfn,
		  unsigned char cmd,
		  unsigned char *data,
		  unsigned int  len,
		  long          oem_data)
{
    msg_t *nmsg;
    int   rv;

    nmsg = lan->alloc(lan, sizeof(*nmsg)+len);
    if (!nmsg) {
	lan->log(OS_ERROR, NULL,
		 "SMI message: out of memory");
	return ENOMEM;
    }

    memset(nmsg, 0, sizeof(*nmsg));
    nmsg->oem_data = oem_data;
    nmsg->netfn = netfn;
    nmsg->cmd = cmd;
    nmsg->data = ((unsigned char *) nmsg) + sizeof(*nmsg);
    nmsg->len = len;
    if (len > 0)
	memcpy(nmsg->data, data, len);
    
    rv = lan->smi_send(lan, nmsg);
    if (rv) {
	lan->log(OS_ERROR, nmsg,
		 "SMI send: error %d", rv);
	lan->free(lan, nmsg);
    }

    return rv;
}

int
ipmi_lan_init(lan_data_t *lan)
{
    int     i;
    uint8_t challenge_data[16];

    for (i=0; i<=MAX_USERS; i++) {
	lan->users[i].idx = i;
    }

    for (i=0; i<=MAX_SESSIONS; i++) {
	lan->sessions[i].handle = i;
    }

    lan->lanparm.num_destinations = 15;
    for (i=0; i<16; i++) {
	lan->lanparm.dest[i].addr[0] = i;
	lan->lanparm.dest[i].type[0] = i;
	lan->lanparm.dest[i].vlan[0] = i;
    }

    lan->lanparm.num_cipher_suites = 15;
    for (i=0; i<17; i++)
	lan->lanparm.cipher_suite_entry[i] = i;

    lan->pef.num_event_filters = MAX_EVENT_FILTERS;
    for (i=0; i<MAX_EVENT_FILTERS; i++) {
	lan->pef.event_filter_table[i][0] = i;
	lan->pef.event_filter_data1[i][0] = i;
    }
    lan->pef.num_alert_policies = MAX_ALERT_POLICIES;
    for (i=0; i<MAX_ALERT_POLICIES; i++)
	lan->pef.alert_policy_table[i][0] = i;
    lan->pef.num_alert_strings = MAX_ALERT_STRINGS;
    for (i=0; i<MAX_ALERT_STRINGS; i++) {
	lan->pef.alert_string_keys[i][0] = i;
    }

    /* Force user 1 to be a null user. */
    memset(lan->users[1].username, 0, 16);

    i = lan->gen_rand(lan, challenge_data, 16);
    if (i)
	return i;

    i = ipmi_md5_authcode_init(challenge_data, &(lan->challenge_auth),
			       lan, ialloc, ifree);
    if (i)
	return i;

    lan->sid_seq = 0;
    lan->next_challenge_seq = 0;

    /* If the calling code already hasn't set up an OEM handler, we
       set up our own to look for a get device id.  When we find a get
       device ID, we call the OEM code to install their own. */
    if (lan->oem_handle_rsp == NULL) {
	int rv;

	lan->oem_handle_rsp = lan_look_for_get_devid;

	/* Send a get device id to the low-level code so we can
           discover who we are. */
	rv = ipmi_oem_send_msg(lan, IPMI_APP_NETFN, IPMI_GET_DEVICE_ID_CMD,
			       NULL, 0, 1);
    }

    /* Default the timeout to 30 seconds. */
    if (lan->default_session_timeout == 0)
	lan->default_session_timeout = 30;

    return 0;
}
