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


#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_err.h>
#include "md5.h"

#include "lanserv.h"

#if 0
static void
dump_hex(unsigned char *data, int len)
{
    int i;
    for (i=0; i<len; i++) {
	if ((i != 0) && ((i % 16) == 0)) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n  ");
	}
	ipmi_log(IPMI_LOG_DEBUG_CONT, " %2.2x", data[i]);
    }
}
#endif

/* Deal with multi-byte data, IPMI (little-endian) style. */
#if 0 /* These are currently not used. */
static unsigned int ipmi_get_uint16(unsigned char *data)
{
    return (data[0]
	    | (data[1] << 8));
}

static void ipmi_set_uint16(unsigned char *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
}
#endif

static unsigned int ipmi_get_uint32(unsigned char *data)
{
    return (data[0]
	    | (data[1] << 8)
	    | (data[2] << 16)
	    | (data[3] << 24));
}

static void ipmi_set_uint32(unsigned char *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
    data[2] = (val >> 16) & 0xff;
    data[3] = (val >> 24) & 0xff;
}

static int
is_authval_null(unsigned char *val)
{
    int i;
    for (i=0; i<16; i++)
	if (val[i] != 0)
	    return 0;
    return 1;
}

static void
cleanup_ascii_16(unsigned char *c)
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

static user_t *
find_user(lan_data_t *lan, unsigned char *user)
{
    int    i;
    user_t *rv = NULL;

    for (i=1; i<MAX_USERS; i++) {
	if (lan->users[i].valid
	    && (memcmp(user, lan->users[i].username, 16) == 0))
	{
	    rv = &(lan->users[i]);
	    break;
	}
    }

    return rv;
}

static unsigned char
ipmb_checksum(unsigned char *data, int size)
{
	unsigned char csum = 0;
	
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
    if (idx >= MAX_SESSIONS)
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
}

static int
auth_gen(session_t     *ses,
	 unsigned char *out,
	 unsigned char *data,
	 unsigned int  data_len)
{
    int rv;
    ipmi_auth_sg_t l[] =
    { { &ses->sid,              4  },
      { data,                   data_len },
      { &ses->xmit_seq,		4 },
      { NULL,                   0 }};

    rv = ipmi_auths[ses->authtype].authcode_gen(ses->authdata, l, out);
    return rv;
}

static int
auth_check(session_t     *ses,
	   uint32_t      seq,
	   unsigned char *data,
	   unsigned int  data_len,
	   unsigned char *code)
{
    int rv;
    ipmi_auth_sg_t l[] =
    { { &ses->sid, 4  },
      { data,      data_len },
      { &seq,      4 },
      { NULL,      0 }};

    rv = ipmi_auths[ses->authtype].authcode_check(ses->authdata, l, code);
    return rv;
}
	 
static int
gen_challenge(lan_data_t    *lan,
	      unsigned char *out,
	      unsigned int  sid)
{
    int rv;

    ipmi_auth_sg_t l[] =
    { { &sid, 4  },
      { NULL,    0 }};

    rv = ipmi_md5_authcode_gen(lan->challenge_auth, l, out);
    return rv;
}

static int
check_challenge(lan_data_t    *lan,
		unsigned int  sid,
		unsigned char *code)
{
    int rv;

    ipmi_auth_sg_t l[] =
    { { &sid, 4  },
      { NULL,    0 }};

    rv = ipmi_md5_authcode_check(lan->challenge_auth, l, code);
    return rv;
}

static void
return_rsp(lan_data_t *lan, msg_t *msg, session_t *session, ipmi_msg_t *rsp)
{
    unsigned char data[IPMI_MAX_LAN_LEN];
    session_t     dummy_session;
    unsigned char *pos;
    int           len;
    int           rv;

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
	if (!session)
	    return;
    }

    if (rsp->data_len > IPMI_MAX_MSG_LENGTH) {
	rsp->data_len = IPMI_MAX_MSG_LENGTH;
	rsp->data[0] = IPMI_REQUEST_DATA_TRUNCATED_CC;
    }

    data[0] = 6; /* RMCP version. */
    data[1] = 1;
    data[2] = 0xff; /* No seq num */
    data[3] = 7; /* IPMI msg class */
    data[4] = session->authtype;
    if (session->xmit_seq == 0)
	session->xmit_seq++;
    ipmi_set_uint32(data+5, session->xmit_seq);
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
    pos[2] = ipmb_checksum(pos, 2);
    pos[3] = msg->rs_addr;
    pos[4] = (msg->rq_seq << 2) | msg->rs_lun;
    pos[5] = rsp->cmd;
    memcpy(msg+6, rsp->data, rsp->data_len);
    pos[len-1] = ipmb_checksum(pos+3, len-4);

    if (session->authtype == IPMI_AUTHTYPE_NONE)
	len += 14;
    else {
	rv = auth_gen(session, data+13, pos, len);
	if (rv) {
	    /* FIXME - what to do? */
	    return;
	}
	len += 30;
    }

    lan->lan_send(lan->lan_info, data, len, msg->src_addr, msg->src_len);
}

static void
return_rsp_data(lan_data_t *lan, msg_t *msg, session_t *session,
		unsigned char *data, int len)
{
    ipmi_msg_t rsp;

    rsp.netfn = msg->netfn | 1;
    rsp.cmd = msg->cmd;
    rsp.data = data;
    rsp.data_len = len;

    return_rsp(lan, msg, session, &rsp);
}

static void
return_err(lan_data_t *lan, msg_t *msg, session_t *session, unsigned char err)
{
    ipmi_msg_t rsp;

    rsp.netfn = msg->netfn | 1;
    rsp.cmd = msg->cmd;
    rsp.data = &err;
    rsp.data_len = 1;
    return_rsp(lan, msg, session, &rsp);
}

static void
handle_get_system_guid(lan_data_t *lan, session_t *session, msg_t *msg)
{
    unsigned char data[17];

    if (lan->guid) {
	data[0] = 0;
	memcpy(data+1, lan->guid, 16);
	return_rsp_data(lan, msg, session, data, 17);
    } else {
	return_err(lan, msg, session, IPMI_INVALID_CMD_CC);
    }
}

static void
handle_get_channel_auth_capabilities(lan_data_t *lan, msg_t *msg)
{
    unsigned char data[9];
    int           chan;
    int           priv;

    if (msg->len < 2) {
	return_err(lan, msg, NULL, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    chan = msg->data[0] & 0xf;
    priv = msg->data[1] & 0xf;
    if (chan == 0xe)
	chan = MAIN_CHANNEL;
    if (chan != MAIN_CHANNEL) {
	return_err(lan, msg, NULL, IPMI_INVALID_DATA_FIELD_CC);
    } else if (priv > lan->channel.priviledge_limit) {
	return_err(lan, msg, NULL, IPMI_INVALID_DATA_FIELD_CC);
    } else {
	data[0] = 0;
	data[1] = chan;
	data[2] = lan->channel.priv_info[priv].allowed_auths;
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
    unsigned char data[21];
    user_t        *user;
    unsigned int  sid;
    unsigned char authtype;
    int           rv;

    if (msg->len < 17) {
	return_err(lan, msg, NULL, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	return;
    }

    authtype = msg->data[0] & 0xf;
    user = find_user(lan, msg->data+1);
    if (!user) {
	if (is_authval_null(msg->data+1))
	    return_err(lan, msg, NULL, 0x82); /* no null user */
	else
	    return_err(lan, msg, NULL, 0x81); /* no user */
	return;
    }

    if (!(user->allowed_auths & (1 << authtype))) {
	return_err(lan, msg, NULL, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    data[0] = 0;

    sid = (lan->next_challenge_seq << (USER_BITS_REQ+1)) | (user->idx << 1) | 1;
    lan->next_challenge_seq++;
    ipmi_set_uint32(data+1, sid);

    rv = gen_challenge(lan, data+5, sid);
    if (rv)
	return_err(lan, msg, NULL, IPMI_UNKNOWN_ERR_CC);
    else
	return_rsp_data(lan, msg, NULL, data, 21);
}

static void
handle_no_session(lan_data_t *lan, msg_t *msg)
{
    switch (msg->cmd) {
	case IPMI_GET_SYSTEM_GUID_CMD:
	    handle_get_system_guid(lan, NULL, msg);
	    break;

	case IPMI_GET_CHANNEL_AUTH_CAPABILITIES_CMD:
	    handle_get_channel_auth_capabilities(lan, msg);
	    break;

	case IPMI_GET_SESSION_CHALLENGE_CMD:
	    handle_get_session_challenge(lan, msg);

	default:
	    return_err(lan, msg, NULL, IPMI_NOT_SUPPORTED_IN_PRESENT_STATE_CC);
	    break;
    }
}

static void
handle_temp_session(lan_data_t *lan, msg_t *msg)
{
    unsigned char seq_data[4];
    int           user_idx;
    user_t        *user;
    unsigned char auth, priv;
    session_t     *session = NULL;
    session_t     dummy_session;
    int           rv;
    unsigned int  xmit_seq;
    unsigned char data[11];
    int           i;

    if (msg->cmd != IPMI_ACTIVATE_SESSION_CMD)
	return;

    if (msg->len < 22)
	return;

    rv = check_challenge(lan, msg->sid, msg->data+2);
    if (rv)
	return;

    user_idx = (msg->sid >> 1) & USER_MASK;
    if ((user_idx > MAX_USERS) || (user_idx == 0))
	return;

    auth = msg->data[0] & 0xf;
    user = &(lan->users[user_idx]);
    if (! (user->valid))
	return;
    if (! (user->allowed_auths & (1 << auth)))
	return;
    if (! (user->allowed_auths & (1 << msg->authtype)))
	return;

    xmit_seq = ipmi_get_uint32(msg->data+18);

    dummy_session.active = 1;
    dummy_session.authtype = msg->authtype;
    dummy_session.xmit_seq = xmit_seq;
    dummy_session.sid = msg->sid;

    rv = ipmi_auths[msg->authtype].authcode_init(user->pw,
						 &dummy_session.authdata);
    if (rv)
	return;

    rv = auth_check(&dummy_session, msg->seq, msg->data, msg->len,
		    msg->authcode);
    if (rv)
	goto out_free;

    /* Note that before this point, we cannot return an error, there's
       no way to generate an authcode for it. */

    if (xmit_seq == 0) {
	return_err(lan, msg, &dummy_session, 0x85); /* Invalid seq id */
	goto out_free;
    }

    priv = msg->data[1] & 0xf;
    if ((user->priviledge == 0xf) || (priv > user->priviledge)) {
	return_err(lan, msg, &dummy_session, 0x86); /* Priviledge error */
	goto out_free;
    }

    /* find a free session.  Session 0 is invalid. */
    for (i=1; i<MAX_SESSIONS; i++) {
	if (! lan->sessions[i].active) {
	    session = &(lan->sessions[i]);
	    break;
	}
    }

    if (!session) {
	return_err(lan, msg, &dummy_session, 0x81); /* No session slot */
	goto out_free;
    }

    session->active = 1;
    session->authtype = auth;
    session->authdata = dummy_session.authdata;
    lan->gen_rand(seq_data, 4);
    session->recv_seq = ipmi_get_uint32(seq_data) & ~1;
    if (!session->recv_seq)
	session->recv_seq = 2;
    session->xmit_seq = xmit_seq;
    session->max_priv = priv;
    session->priv = IPMI_PRIVILEGE_USER; /* Start at user privilege. */
    session->userid = user->idx;

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
    ipmi_addr_t   addr;
    ipmi_msg_t    imsg;
    msg_t         *nmsg;
    int           addr_len;
    int           rv;

    nmsg = lan->alloc(sizeof(*nmsg)+msg->src_len);
    if (!nmsg) {
	return_err(lan, msg, NULL, IPMI_UNKNOWN_ERR_CC);
	return;
    }

    nmsg->src_addr = ((char *) nmsg) + sizeof(*nmsg);
    memcpy(nmsg->src_addr, msg->src_addr, msg->src_len);
    
    if (msg->cmd == IPMI_SEND_MSG_CMD) {
	ipmi_ipmb_addr_t *ipmb = (void *) &addr;
	int              pos;
	/* Send message has special handling */
	
	if (msg->len < 8) {
	    return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	    return;
	}

	ipmb->addr_type = IPMI_IPMB_ADDR_TYPE;
	ipmb->channel = msg->data[0] & 0xf;
	pos = 1;
	if (msg->data[pos] == 0) {
	    ipmb->addr_type = IPMI_IPMB_BROADCAST_ADDR_TYPE;
	    pos++;
	}
	ipmb->slave_addr = msg->data[pos];
	ipmb->lun = msg->data[pos+1] & 0x3;
	addr_len = sizeof(*ipmb);
	imsg.netfn = msg->data[pos+1] >> 2;
	imsg.cmd = msg->data[pos+5];
	imsg.data = msg->data+pos+6;
	imsg.data_len = msg->len-(pos + 7); /* Subtract last checksum, too */
    } else {
	/* Normal message to the BMC. */
	ipmi_system_interface_addr_t *si = (void *) &addr;

	si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si->channel = 0xf;
	si->lun = msg->rs_lun;
	addr_len = sizeof(*si);
	imsg.netfn = msg->netfn;
	imsg.cmd = msg->cmd;
	imsg.data = msg->data;
	imsg.data_len = msg->len;
    }

    rv = lan->smi_send(lan->smi_info, &imsg, nmsg, &addr, addr_len);
    if (rv) {
	lan->free(nmsg);
	return_err(lan, msg, NULL, IPMI_UNKNOWN_ERR_CC);
	return;
    }
}

static void
handle_activate_session_cmd(lan_data_t *lan, session_t *session, msg_t *msg)
{
    unsigned char data[11];

    if (msg->len < 22) {
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
    unsigned char data[2];
    unsigned char priv;

    if (msg->len < 1) {
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
    unsigned int sid;

    session_t    *nses = session;

    if (msg->len < 4) {
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

    close_session(lan, nses);

    return_err(lan, msg, session, 0);
}

static void
handle_get_session_info(lan_data_t *lan, session_t *session, msg_t *msg)
{
    unsigned char idx;
    session_t     *nses = NULL;
    unsigned char data[19];

    if (msg->len < 1) {
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
		for (i=0; i<MAX_SESSIONS; i++) {
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
    /* This is optional, and we don't do it yet. */
    return_err(lan, msg, session, IPMI_INVALID_CMD_CC);
}

static void
handle_set_channel_access(lan_data_t *lan, session_t *session, msg_t *msg)
{
    unsigned char upd1, upd2;
    int           write_nonv = 0;
    unsigned int  newv;

    if (msg->len < 3) {
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
	    lan->channel.priviledge_limit = newv;
	} else {
	    lan->nonv_channel.priviledge_limit = newv;
	    write_nonv = 1;
	}
    } else if (upd2 != 0) {
	return_err(lan, msg, session, IPMI_INVALID_DATA_FIELD_CC);
	return;
    }

    if (write_nonv)
	lan->write_config(lan->config_info, lan);

    return_err(lan, msg, session, 0);
}

static void
handle_get_channel_access(lan_data_t *lan, session_t *session, msg_t *msg)
{
    unsigned char data[3];
    unsigned char upd;
    channel_t     *channel;

    if (msg->len < 3) {
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
    data[2] = channel->priviledge_limit;

    return_rsp_data(lan, msg, session, data, 3);
}

static void
handle_get_channel_info(lan_data_t *lan, session_t *session, msg_t *msg)
{
    unsigned char data[10];
    unsigned char chan;

    if (msg->len < 1) {
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
    unsigned char user;
    unsigned char priv;
    unsigned char newv;
    int           changed = 0;

    if (msg->len < 3) {
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
    /* Allow priviledge level F as the "no access" privilege */
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

    if (priv != lan->users[user].priviledge) {
	lan->users[user].priviledge = priv;
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
	lan->write_config(lan->config_info, lan);

    return_err(lan, msg, session, 0);
}

static void
handle_get_user_access(lan_data_t *lan, session_t *session, msg_t *msg)
{
    unsigned char data[5];
    int           i;
    unsigned char user;

    if (msg->len < 2) {
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
    for (i=1; i<MAX_USERS; i++) {
	if (lan->users[i].valid)
	    data[2]++;
    }

    /* Only fixed user name is user 1. */
    data[3] = lan->users[1].valid;

    data[4] = (lan->users[user].valid << 4) | lan->users[user].priviledge;

    return_rsp_data(lan, msg, session, data, 5);
}

static void
handle_set_user_name(lan_data_t *lan, session_t *session, msg_t *msg)
{
    unsigned char user;

    if (msg->len < 17) {
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
    unsigned char user;
    unsigned char data[17];

    if (msg->len < 17) {
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
    unsigned char user;
    unsigned char op;

    if (msg->len < 2) {
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
    /* FIXME -  This is manditory, and we don't do it yet. */
    return_err(lan, msg, session, IPMI_INVALID_CMD_CC);
}

static void
handle_ipmi_get_lan_config_parms(lan_data_t *lan,
				 session_t  *session,
				 msg_t      *msg)
{
    /* FIXME -  This is manditory, and we don't do it yet. */
    return_err(lan, msg, session, IPMI_INVALID_CMD_CC);
}

static void
handle_normal_session(lan_data_t *lan, msg_t *msg)
{
    session_t *session = sid_to_session(lan, msg->sid);
    int       rv;

    if (session == NULL)
	return;

    rv = auth_check(session, msg->seq, msg->data, msg->len, msg->authcode);
    if (rv)
	return;

    rv = ipmi_cmd_permitted(session->priv, msg->netfn, msg->cmd);
    switch (rv) {
	case IPMI_PRIV_PERMITTED:
	    break;

	case IPMI_PRIV_SEND:
	    /* The spec says that operator priviledge is require to
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
	    return_err(lan, msg, NULL, IPMI_INSUFFICIENT_PRIVILEGE_CC);
	    return;

	case IPMI_PRIV_INVALID:
	default:
	    return_err(lan, msg, NULL, IPMI_UNKNOWN_ERR_CC);
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
		return_err(lan, msg, session, IPMI_INVALID_CMD_CC);
		break;
	}
    } else {
	handle_smi_msg(lan, session, msg);
    }
}

void
ipmi_handle_lan_msg(lan_data_t *lan,
		    unsigned char *data, int len,
		    void *from_addr, int from_len)
{
    unsigned char *pos;
    msg_t         msg;

    if (len < 14)
	return;

    if (data[2] != 0xff)
	return; /* Sequence # must be ff (no ack) */

    msg.authtype = data[4];
    msg.seq = ipmi_get_uint32(data+5);
    msg.sid = ipmi_get_uint32(data+9);

    if (msg.authtype != IPMI_AUTHTYPE_NONE) {
	if (len < 30)
	    return;

	memcpy(msg.authcode_data, data + 13, 16);
	msg.authcode = msg.authcode_data;
	pos = data + 29;
	len -= 30;
    } else {
	msg.authcode = NULL;
	pos = data + 13;
	len -= 14;
    }
    if (len < *pos)
	return; /* The length field is not valid.  We allow extra
                   bytes, but reject if not enough. */
    len = *pos;
    pos++;

    if ((len < 7) || (len > IPMI_MAX_MSG_LENGTH+7))
	return;

    if (ipmb_checksum(pos, 3) != 0)
	return;
    if (ipmb_checksum(pos+3, len-3) != 0)
	return;
    len--; /* Remove the final checksum */

    memcpy(&msg.src_addr, from_addr, from_len);
    msg.src_len = from_len;
    msg.rs_addr = pos[0];
    msg.netfn = pos[1] >> 2;
    msg.rs_lun = pos[1] & 0x3;
    msg.rq_addr = pos[3];
    msg.rq_seq = pos[4] >> 2;
    msg.rq_lun = pos[4] & 0x3;
    msg.cmd = pos[5];

    memcpy(msg.data, pos+6, len-6);
    msg.len = len;

    if (msg.sid == 0) {
	/* Should be a session challenge, validate everything else. */
	if ((msg.seq != 0) || (msg.authtype != IPMI_AUTHTYPE_NONE))
	    return;

	handle_no_session(lan, &msg);
    } else if (msg.sid & 1) {
	/* We use odd SIDs for temporary ones. */
	handle_temp_session(lan, &msg);
    } else {
	handle_normal_session(lan, &msg);
    }
}

void
ipmi_handle_smi_msg(lan_data_t  *lan,
		    ipmi_addr_t *addr,
		    ipmi_msg_t  *imsg,
		    void        *cb_data)
{
    msg_t         *msg = cb_data;
    session_t     *session;
    unsigned char data[IPMI_MAX_MSG_LENGTH+8];

    session = sid_to_session(lan, msg->sid);
    if (!session)
	goto out;

    if (addr->addr_type == IPMI_IPMB_ADDR_TYPE) {
	ipmi_ipmb_addr_t *ipmb = (void *) addr; 

	if (imsg->data_len > IPMI_MAX_MSG_LENGTH) {
	    imsg->data[0] = IPMI_REQUEST_DATA_TRUNCATED_CC;
	    imsg->data_len = IPMI_MAX_MSG_LENGTH;
	}

	data[0] = 0;
	data[1] = (imsg->netfn << 2) | 2;
	data[2] = ipmb_checksum(data+1, 1);
	data[3] = ipmb->slave_addr;
//	data[4] = 
    }

 out:
    lan->free(msg);
}
