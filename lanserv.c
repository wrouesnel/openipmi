/*
 * lanserv.c
 *
 * MontaVista IPMI code for creating a LAN interface to an SMI interface.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <OpenIPMI/ipmi_types.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_err.h>
#include "md5.h"

#define IPMI_MAX_LAN_LEN (IPMI_MAX_MSG_LENGTH + 42)

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

/*
 * Restrictions: <=64 sessions
 *               <=64 users (per spec, 6 bits)
 */
#define MAX_USERS		64
#define USER_BITS_REQ		6 /* Bits required to hold a user. */
#define USER_MASK		0x3f
#define MAX_SESSIONS		64
#define SESSION_BITS_REQ	6 /* Bits required to hold a session. */
#define SESSION_MASK		0x3f


typedef struct msg_s
{
    void *src_addr;
    int  src_len;

    unsigned int  seq;
    unsigned int  sid;
    unsigned char *authcode;
    unsigned char authcode_data[16];
    unsigned char authtype;

    unsigned char netfn;
    unsigned char rs_addr;
    unsigned char rs_lun;
    unsigned char rq_addr;
    unsigned char rq_lun;
    unsigned char rq_seq;
    unsigned char cmd;

    unsigned char data[IPMI_MAX_MSG_LENGTH-7];
    int           len;
} msg_t;

#define NUM_PRIV_LEVEL 5
typedef struct channel_s
{
    unsigned int available : 1;

    unsigned int PEF_alerting : 1;
    unsigned int per_msg_auth : 1;

    /* We don't support user-level authentication disable, and access
       mode is always available and cannot be set. */

    unsigned int priviledge_limit : 4;
    struct {
	unsigned char allowed_auths;
    } priv_info[NUM_PRIV_LEVEL];
} channel_t;

typedef struct session_s
{
    unsigned int active : 1;

    int           idx; /* My idx in the table. */

    unsigned char   authtype;
    ipmi_authdata_t authdata;
    unsigned int    recv_seq;
    unsigned int    xmit_seq;
    unsigned int    sid;

    unsigned int  max_priv;
} session_t;

typedef struct user_s
{
    unsigned char valid;
    unsigned char username[16];
    unsigned char pw[16];
    unsigned char priviledge;
    unsigned int  allowed_auths;

    /* Set by the user code. */
    int           idx; /* My idx in the table. */
} user_t;

typedef struct lan_data_s
{
    user_t users[MAX_USERS];

    session_t sessions[MAX_SESSIONS];

    channel_t channel;

    unsigned char *guid;


    void *lan_info;
    void (*lan_send)(void *lan_info, unsigned char *data, int len,
		     void *addr, int addr_len);

    void *smi_info;
    int (*smi_send)(void *smi, unsigned char *data, int len,
		    ipmi_addr_t *addr, int addr_len);

    /* Generate 'size' bytes of random data into 'data'. */
    void (*gen_rand)(void *data, int size);

    /* Don't fill in the below in the user code. */

    /* Used to make the sid somewhat unique. */
    unsigned int sid_seq;

    ipmi_authdata_t challenge_auth;
    unsigned int next_challenge_seq;
} lan_data_t;

/* Deal with multi-byte data, IPMI (little-endian) style. */
unsigned int ipmi_get_uint16(unsigned char *data)
{
    return (data[0]
	    | (data[1] << 8));
}

void ipmi_set_uint16(unsigned char *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
}

unsigned int ipmi_get_uint32(unsigned char *data)
{
    return (data[0]
	    | (data[1] << 8)
	    | (data[2] << 16)
	    | (data[3] << 24));
}

void ipmi_set_uint32(unsigned char *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
    data[2] = (val >> 16) & 0xff;
    data[3] = (val >> 24) & 0xff;
}

/* Deal with multi-byte data, RMCP (big-endian) style. */
unsigned int rmcp_get_uint16(unsigned char *data)
{
    return (data[1]
	    | (data[0] << 8));
}

void rmcp_set_uint16(unsigned char *data, int val)
{
    data[1] = val & 0xff;
    data[0] = (val >> 8) & 0xff;
}

unsigned int rmcp_get_uint32(unsigned char *data)
{
    return (data[3]
	    | (data[2] << 8)
	    | (data[1] << 16)
	    | (data[0] << 24));
}

void rmcp_set_uint32(unsigned char *data, int val)
{
    data[3] = val & 0xff;
    data[2] = (val >> 8) & 0xff;
    data[1] = (val >> 16) & 0xff;
    data[0] = (val >> 24) & 0xff;
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

static user_t *
find_user(lan_data_t *lan, unsigned char *user)
{
    int    i;
    user_t *rv = NULL;

    for (i=0; i<MAX_USERS; i++) {
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


int lan_port = 623;

#define ASF_IANA 4542
void
handle_asf(lan_data_t *lan,
	   unsigned char *data, int len,
	   void *from_addr, int from_len)
{
    unsigned char rsp[28];

    if (len < 12)
	return;

    if (ipmi_get_uint32(data+4) != ASF_IANA)
	return; /* Not ASF IANA */

    if (data[8] != 0x80)
	return; /* Not a presence ping. */

    /* Ok, it's a valid RMCP/ASF Presence Ping, start working on the
       response. */
    rsp[0] = 6;
    rsp[1] = 0;
    rsp[2] = 0xff; /* No ack, the ack is not required, so we don't do it. */
    rsp[3] = 6; /* ASF class */
    rmcp_set_uint32(rsp+4, ASF_IANA);
    rsp[8] = 0x40; /* Presense Pong */
    rsp[9] = data[9]; /* Message tag */
    rsp[10] = 0;
    rsp[11] = 16; /* Data length */
    rmcp_set_uint32(rsp+12, ASF_IANA); /* no special capabilities */
    rmcp_set_uint32(rsp+16, 0); /* no special capabilities */
    rsp[20] = 0x81; /* We support IPMI */
    rsp[21] = 0x0; /* No supported interactions */
    memset(rsp+22, 0, 6); /* Reserved. */

    /* Return the response. */
    lan->lan_send(lan->lan_info, data, 28, from_addr, from_len);
}

session_t *
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

void
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

    if (rsp->data_len > IPMI_MAX_MSG_LENGTH + 7) {
	rsp->data_len = IPMI_MAX_MSG_LENGTH + 7;
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

void
return_err(lan_data_t *lan, msg_t *msg, session_t *session, unsigned char err)
{
    ipmi_msg_t rsp;

    rsp.netfn = msg->netfn | 1;
    rsp.cmd = msg->cmd;
    rsp.data = &err;
    rsp.data_len = 1;
    return_rsp(lan, msg, session, &rsp);
}

void
handle_get_system_guid(lan_data_t *lan, msg_t *msg)
{
    ipmi_msg_t    rsp;
    unsigned char data[17];

    if (lan->guid) {
	rsp.netfn = msg->netfn;
	rsp.cmd = msg->cmd;
	rsp.data = data;
	rsp.data_len = 17;
	data[0] = 0;
	memcpy(data+1, lan->guid, 16);
	return_rsp(lan, msg, NULL, &rsp);
    } else {
	return_err(lan, msg, NULL, IPMI_INVALID_CMD_CC);
    }
}

void
handle_get_channel_auth_capabilities(lan_data_t *lan, msg_t *msg)
{
    ipmi_msg_t    rsp;
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
	chan = 0xf;
    if (chan != 0xf) {
	return_err(lan, msg, NULL, IPMI_INVALID_DATA_FIELD_CC);
    } else if (priv > lan->channel.priviledge_limit) {
	return_err(lan, msg, NULL, IPMI_INVALID_DATA_FIELD_CC);
    } else {
	rsp.netfn = msg->netfn;
	rsp.cmd = msg->cmd;
	rsp.data = data;
	rsp.data_len = 17;
	data[0] = 0;
	data[1] = chan;
	data[2] = lan->channel.priv_info[priv].allowed_auths;
	data[3] = 0x04; /* per-message authentication is on,
			   user-level authenitcation is on,
			   non-null user names disabled,
			   no anonymous support. */
	if (lan->users[0].valid) {
	    if (is_authval_null(lan->users[0].pw))
		data[3] |= 0x01; /* Anonymous login. */
	    else
		data[3] |= 0x02; /* Null user supported. */
	}
	data[4] = 0;
	data[5] = 0;
	data[6] = 0;
	data[7] = 0;
	data[8] = 0;
	return_rsp(lan, msg, NULL, &rsp);
    }
}

void
handle_get_session_challenge(lan_data_t *lan, msg_t *msg)
{
    ipmi_msg_t    rsp;
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

    rsp.netfn = msg->netfn;
    rsp.cmd = msg->cmd;
    rsp.data = data;
    rsp.data_len = 17;
    data[0] = 0;

    sid = (lan->next_challenge_seq << (USER_BITS_REQ+1)) | (user->idx << 1) | 1;
    lan->next_challenge_seq++;
    ipmi_set_uint32(data+1, sid);

    rv = gen_challenge(lan, data+5, sid);
    if (rv)
	return_err(lan, msg, NULL, IPMI_UNKNOWN_ERR_CC);
    else
	return_rsp(lan, msg, NULL, &rsp);
}

void
handle_no_session(lan_data_t *lan, msg_t *msg)
{
    switch (msg->cmd) {
	case IPMI_GET_SYSTEM_GUID_CMD:
	    handle_get_system_guid(lan, msg);
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

void
handle_odd_session(lan_data_t *lan, msg_t *msg)
{
    unsigned char seq_data[4];
    int           user_idx;
    user_t        *user;
    unsigned char auth, priv;
    session_t     *session = NULL;
    session_t     dummy_session;
    int           rv;
    unsigned int  xmit_seq;
    ipmi_msg_t    rsp;
    unsigned char data[11];
    int           i;

    if (msg->cmd != IPMI_ACTIVATE_SESSION_CMD)
	/* Cannot return an error, there's no way to generate an
           authcode for it. */
	return;

    if (msg->len < 22)
	return;

    rv = check_challenge(lan, msg->sid, msg->data+2);
    if (rv)
	return;

    user_idx = (msg->sid >> 1) & USER_MASK;
    if (user_idx > MAX_USERS)
	return;

    auth = msg->data[0] & 0xf;
    user = &(lan->users[user_idx]);
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

    if (xmit_seq == 0) {
	return_err(lan, msg, &dummy_session, 0x85); /* Invalid seq id */
	goto out_free;
    }

    priv = msg->data[1] & 0xf;
    if (priv > user->priviledge) {
	return_err(lan, msg, &dummy_session, 0x86); /* Priviledge error */
	goto out_free;
    }

    /* find a free session. */
    for (i=0; i<MAX_SESSIONS; i++) {
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

    if (lan->sid_seq == 0)
	lan->sid_seq++;
    session->sid = (lan->sid_seq << (SESSION_BITS_REQ+1)) | (session->idx << 1);
    lan->sid_seq++;

    rsp.netfn = msg->netfn;
    rsp.cmd = msg->cmd;
    rsp.data = data;
    rsp.data_len = 17;
    data[0] = 0;
    data[1] = auth;
    
    ipmi_set_uint32(data+2, session->sid);
    ipmi_set_uint32(data+6, session->recv_seq);

    data[10] = session->max_priv;

    return_rsp(lan, msg, &dummy_session, &rsp);
    return;

 out_free:
    ipmi_auths[msg->authtype].authcode_cleanup(dummy_session.authdata);
}

void
handle_activate_session_cmd(lan_data_t *lan, msg_t *msg)
{
}

void
handle_set_session_privilege(lan_data_t *lan, msg_t *msg)
{
}

void		
handle_close_session(lan_data_t *lan, msg_t *msg)
{
}

void
handle_get_session_info(lan_data_t *lan, msg_t *msg)
{
}

void
handle_get_authcode(lan_data_t *lan, msg_t *msg)
{
}

void
handle_set_channel_access(lan_data_t *lan, msg_t *msg)
{
}

void
handle_get_channel_access(lan_data_t *lan, msg_t *msg)
{
}

void
handle_get_channel_info(lan_data_t *lan, msg_t *msg)
{
}

void
handle_set_user_access(lan_data_t *lan, msg_t *msg)
{
}

void
handle_get_user_access(lan_data_t *lan, msg_t *msg)
{
}

void
handle_set_user_name(lan_data_t *lan, msg_t *msg)
{
}

void
handle_get_user_name(lan_data_t *lan, msg_t *msg)
{
}

void
handle_set_user_password(lan_data_t *lan, msg_t *msg)
{
}

void
handle_normal_msg(lan_data_t *lan, msg_t *msg)
{
}

void
handle_ipmi_set_lan_configuration_parameters(lan_data_t *lan, msg_t *msg)
{
}

void
handle_ipmi_get_lan_configuration_parameters(lan_data_t *lan, msg_t *msg)
{
}



void
handle_lan_msg(lan_data_t *lan, msg_t *msg)
{
    session_t *session = sid_to_session(lan, msg->sid);
    int       rv;

    if (session == NULL)
	return;

    rv = auth_check(session, msg->seq, msg->data, msg->len, msg->authcode);
    if (rv)
	return;

    if (msg->netfn == IPMI_APP_NETFN) {
	switch (msg->cmd)
	{
	    case IPMI_GET_SYSTEM_GUID_CMD:
		handle_get_system_guid(lan, msg);
		break;

	    case IPMI_GET_CHANNEL_AUTH_CAPABILITIES_CMD:
	    case IPMI_GET_SESSION_CHALLENGE_CMD:
		return_err(lan, msg, NULL,
			   IPMI_NOT_SUPPORTED_IN_PRESENT_STATE_CC);
		break;
		
	    case IPMI_ACTIVATE_SESSION_CMD:
		handle_activate_session_cmd(lan, msg);
		break;

	    case IPMI_SET_SESSION_PRIVILEGE_CMD:
		handle_set_session_privilege(lan, msg);
		break;
		
	    case IPMI_CLOSE_SESSION_CMD:
		handle_close_session(lan, msg);
		break;

	    case IPMI_GET_SESSION_INFO_CMD:
		handle_get_session_info(lan, msg);
		break;

	    case IPMI_GET_AUTHCODE_CMD:
		handle_get_authcode(lan, msg);
		break;

	    case IPMI_SET_CHANNEL_ACCESS_CMD:
		handle_set_channel_access(lan, msg);
		break;

	    case IPMI_GET_CHANNEL_ACCESS_CMD:
		handle_get_channel_access(lan, msg);
		break;

	    case IPMI_GET_CHANNEL_INFO_CMD:
		handle_get_channel_info(lan, msg);
		break;

	    case IPMI_SET_USER_ACCESS_CMD:
		handle_set_user_access(lan, msg);
		break;

	    case IPMI_GET_USER_ACCESS_CMD:
		handle_get_user_access(lan, msg);
		break;

	    case IPMI_SET_USER_NAME_CMD:
		handle_set_user_name(lan, msg);
		break;

	    case IPMI_GET_USER_NAME_CMD:
		handle_get_user_name(lan, msg);
		break;

	    case IPMI_SET_USER_PASSWORD_CMD:
		handle_set_user_password(lan, msg);
		break;

	    default:
		handle_normal_msg(lan, msg);
	}
    } else if (msg->netfn == IPMI_TRANSPORT_NETFN) {
	switch (msg->cmd)
	{
	    case IPMI_SET_LAN_CONFIG_PARMS_CMD:
		handle_ipmi_set_lan_configuration_parameters(lan, msg);
		break;

	    case IPMI_GET_LAN_CONFIG_PARMS_CMD:
		handle_ipmi_get_lan_configuration_parameters(lan, msg);
		break;

	    default:
		return_err(lan, msg, NULL, IPMI_INVALID_CMD_CC);
		break;
	}
    } else {
	handle_normal_msg(lan, msg);
    }
}

void
handle_ipmi(lan_data_t *lan,
	    unsigned char *data, int len,
	    struct sockaddr *from_addr, socklen_t from_len)
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

    if ((len < 7) || (len > IPMI_MAX_MSG_LENGTH))
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
	handle_odd_session(lan, &msg);
    } else {
	handle_lan_msg(lan, &msg);
    }
}


/**********************************************************************/

int smi_fd;
int lan_fd;

unsigned int __ipmi_log_mask = 0;

void
ipmi_log(enum ipmi_log_type_e log_type, char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

void
handle_msg(lan_data_t *lan)
{
    int                len;
    struct sockaddr    from_addr;
    socklen_t          from_len;
    unsigned char      data[IPMI_MAX_LAN_LEN];

    from_len = sizeof(from_addr);
    len = recvfrom(lan_fd, data, sizeof(data), 0, &from_addr, &from_len);
    if (len < 0) {
	if (errno != EINTR) {
	    perror("Error receiving message");
	    exit(1);
	}
	return;
    }

    if (len < 4)
	return;

    if (data[0] != 6)
	return; /* Invalid version */

    /* Check the message class. */
    switch (data[3]) {
	case 6:
	    handle_asf(lan, data, len, &from_addr, from_len);
	    break;

	case 7:
	    handle_ipmi(lan, data, len, &from_addr, from_len);
	    break;
    }
}

static int
ipmi_open(void)
{
    int ipmi_fd;

    ipmi_fd = open("/dev/ipmidev/0", O_RDWR);
    if (ipmi_fd == -1) {
	ipmi_fd = open("/dev/ipmi0", O_RDWR);
	if (ipmi_fd == -1) {
	    perror("Could not open ipmi device /dev/ipmidev/0 or /dev/ipmi0");
	    exit(1);
	}
    }

    return ipmi_fd;
}

static int
open_lan_fd(void)
{
    int                fd;
    struct sockaddr_in addr;
    int                rv;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
	perror("Unable to create socket");
	exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(lan_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    rv = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
    if (rv == -1)
    {
	fprintf(stderr, "Unable to bind to LAN port (%d): %s\n",
		lan_port, strerror(errno));
	exit(1);
    }

    return fd;
}

int
main(int argc, char *argv[])
{
    lan_data_t lan;

    smi_fd = ipmi_open();
    lan_fd = open_lan_fd();

    for (;;) {
	handle_msg(&lan);
    }
}
