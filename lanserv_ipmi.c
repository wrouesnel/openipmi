/*
 * lanserv_ipmi.c
 *
 * MontaVista IPMI IPMI LAN interface protocol engine
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
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

#include <stdlib.h>

#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/lanserv.h>
#include "md5.h"


#if 0
static void
dump_hex(uint8_t *data, int len)
{
    int i;
    for (i=0; i<len; i++) {
	if ((i != 0) && ((i % 16) == 0)) {
	    printf("\n  ");
	}
	printf(" %2.2x", data[i]);
    }
}
#endif

/* Deal with multi-byte data, IPMI (little-endian) style. */
#if 0 /* These are currently not used. */
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
#endif

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
find_user(lan_data_t *lan, uint8_t *user)
{
    int    i;
    user_t *rv = NULL;

    for (i=1; i<=MAX_USERS; i++) {
	if (lan->users[i].valid
	    && (memcmp(user, lan->users[i].username, 16) == 0))
	{
	    rv = &(lan->users[i]);
	    break;
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

	return -csum;
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
    ipmi_auths[session->authtype].authcode_cleanup(session->authdata);
    lan->active_sessions--;
    lan->free(lan, session->src_addr);
    session->src_addr = NULL;
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

#define IPMI_LAN_MAX_HEADER_SIZE 36

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

    if (msg->sid == 0) {
	session = &dummy_session;
	session->active = 1;
	session->authtype = IPMI_AUTHTYPE_NONE;
	session->xmit_seq = 0;
	session->sid = 0;
    } else if (session == NULL) {
	/* We need the session.. */
	/* We should not get temporary sessions here. */
	session = sid_to_session(lan, msg->sid);
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
    pos[2] = ipmb_checksum(pos, 2, 0);
    pos[3] = msg->rs_addr;
    pos[4] = (msg->rq_seq << 2) | msg->rs_lun;
    pos[5] = rsp->cmd;

    csum = ipmb_checksum(pos+3, 3, 0);
    csum = ipmb_checksum(rsp->data, rsp->data_len, csum);

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

    if (msg->len < 2) {
	lan->log(INVALID_MSG, msg,
		 "Get channel auth failed: message too short");
	return_err(lan, msg, NULL, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

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
	data[0] = 0;
	data[1] = chan;
	data[2] = lan->channel.priv_info[priv-1].allowed_auths;
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
	data[4] = 0;
	data[5] = 0;
	data[6] = 0;
	data[7] = 0;
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
    user = find_user(lan, msg->data+1);
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

static void
handle_temp_session(lan_data_t *lan, msg_t *msg, uint8_t *raw)
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
    int       i;

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
    rv = auth_check(&dummy_session, raw+9, raw+5, msg->data-6, msg->len+7,
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

    /* find a free session.  Session 0 is invalid. */
    for (i=1; i<=MAX_SESSIONS; i++) {
	if (! lan->sessions[i].active) {
	    session = &(lan->sessions[i]);
	    break;
	}
    }

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
    session->authtype = auth;
    session->authdata = dummy_session.authdata;
    rv = lan->gen_rand(lan, seq_data, 4);
    if (rv < 0) {
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
    session->sid = (lan->sid_seq << (SESSION_BITS_REQ+1)) | (session->idx << 1);
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
    close_session(lan, nses);

    return_err(lan, msg, session, 0);
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
    } else {
	if (idx == 0xfe) {
	    if (msg->len < 2) {
		return_err(lan, msg, session,
			   IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
		return;
	    }

	    idx = msg->data[1];
	} else if (idx == 0) {
	    idx = session->idx;
	} else {
	    int i;

	    if (idx <= lan->active_sessions) {
		for (i=0; i<=MAX_SESSIONS; i++) {
		    if (lan->sessions[i].active) {
			idx--;
			if (idx == 0) {
			    nses = &(lan->sessions[i]);
			    break;
			}
		    }
		}
	    }
	}
    }

    if (nses) {
	data[1] = session->idx;
	data[4] = session->userid;
	data[5] = session->priv;
    } else {
	data[1] = 0;
	data[4] = 0;
	data[5] = 0;
    }

    data[0] = 0;
    data[2] = MAX_SESSIONS;
    data[3] = lan->active_sessions;
    data[6] = MAIN_CHANNEL;

    /* FIXME - We don't currently return the IP information, because
       it's hard to get.  Maybe later. */

    return_rsp_data(lan, msg, session, data, 7);
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
	newv = (msg->data[1] >> 0) & 0xf;
	if ((newv == 0) || (newv > 4)) {
	    return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	    return;
	}

	if (upd2 == 1) {
	    lan->channel.privilege_limit = newv;
	} else {
	    lan->nonv_channel.privilege_limit = newv;
	    write_nonv = 1;
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

    if (msg->len < 3) {
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
	/* The other bits are callback/PPP oriented, and we ignore
           them. */
	newv = (msg->data[0] >> 4) & 1;
	if (newv != lan->users[user].valid) {
	    lan->users[user].valid = newv;
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

    data[4] = (lan->users[user].valid << 4) | lan->users[user].privilege;

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
    lan->log(INVALID_MSG, msg,
	     "Set LAN config parms failure: invalid cmd");
    /* FIXME -  This is manditory, and we don't do it yet. */
    return_err(lan, msg, session, IPMI_INVALID_CMD_CC);
}

static void
handle_ipmi_get_lan_config_parms(lan_data_t *lan,
				 session_t  *session,
				 msg_t      *msg)
{
    lan->log(INVALID_MSG, msg,
	     "Get LAN config parms failure: invalid cmd");
    /* FIXME -  This is manditory, and we don't do it yet. */
    return_err(lan, msg, session, IPMI_INVALID_CMD_CC);
}

static void
handle_normal_session(lan_data_t *lan, msg_t *msg, uint8_t *raw)
{
    session_t *session = sid_to_session(lan, msg->sid);
    int       rv;
    int       diff;

    if (session == NULL) {
	lan->log(INVALID_MSG, msg,
		 "Normal session message failure: Invalid SID");
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

    /* The "-6, +7" is cheating a little, but we need the last
       checksum to correctly calculate the code. */
    rv = auth_check(session, raw+9, raw+5, msg->data-6, msg->len+7,
		    msg->authcode);
    if (rv) {
	lan->log(AUTH_FAILED, msg,
		 "Normal session message failure: auth failure");
	return;
    }

    /* We wait until after the message is authenticated to set the
       sequence number, to prevent spoofing. */
    if (msg->seq > session->recv_seq)
	session->recv_seq = msg->seq;

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
    } else {
	handle_smi_msg(lan, session, msg);
    }
}

void
ipmi_handle_lan_msg(lan_data_t *lan,
		    uint8_t *data, int len,
		    void *from_addr, int from_len)
{
    uint8_t *pos;
    msg_t   msg;

    msg.src_addr = from_addr;
    msg.src_len = from_len;

    msg.oem_data = 0;

    if (len < 14) {
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
    msg.seq = ipmi_get_uint32(data+5);
    msg.sid = ipmi_get_uint32(data+9);

    if (msg.authtype != IPMI_AUTHTYPE_NONE) {
	if (len < 30) {
	    lan->log(LAN_ERR, &msg,
		     "LAN msg failure: message too short");
	    return;
	}

	memcpy(msg.authcode_data, data + 13, 16);
	msg.authcode = msg.authcode_data;
	pos = data + 29;
	len -= 30;
    } else {
	msg.authcode = NULL;
	pos = data + 13;
	len -= 14;
    }
    if (len < *pos) {
	lan->log(LAN_ERR, &msg,
		 "LAN msg failure: Length field invalid");
	return; /* The length field is not valid.  We allow extra
                   bytes, but reject if not enough. */
    }
    len = *pos;
    pos++;

    if (len < 7) {
	lan->log(LAN_ERR, &msg,
		 "LAN msg failure: Length field too short");
	return;
    }

    if (ipmb_checksum(pos, 3, 0) != 0) {
	lan->log(LAN_ERR, &msg,
		 "LAN msg failure: Checksum 1 failed");
	return;
    }
    if (ipmb_checksum(pos+3, len-3, 0) != 0) {
	lan->log(LAN_ERR, &msg,
		 "LAN msg failure: Checksum 2 failed");
	return;
    }
    len--; /* Remove the final checksum */

    msg.rs_addr = pos[0];
    msg.netfn = pos[1] >> 2;
    msg.rs_lun = pos[1] & 0x3;
    msg.rq_addr = pos[3];
    msg.rq_seq = pos[4] >> 2;
    msg.rq_lun = pos[4] & 0x3;
    msg.cmd = pos[5];

    msg.data = pos + 6;
    msg.len = len - 6;

    if (lan->debug) {
	lan->log(DEBUG, &msg, "msg: netfn = 0x%2.2x cmd=%2.2x",
		 msg.netfn, msg.cmd);
    }

    if (msg.sid == 0) {
	handle_no_session(lan, &msg);
    } else if (msg.sid & 1) {
	/* We use odd SIDs for temporary ones. */
	handle_temp_session(lan, &msg, data);
    } else {
	handle_normal_session(lan, &msg, data);
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
	lan->sessions[i].idx = i;
    }

    /* Force user 1 to be a null user. */
    memset(lan->users[1].username, 0, 16);

    i = lan->gen_rand(lan, challenge_data, 16);
    if (i < 0)
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
