/*
 * lanserv.h
 *
 * MontaVista IPMI LAN server include file
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

#ifndef __LANSERV_H
#define __LANSERV_H

#include <sys/uio.h> /* for iovec */
#include <stdint.h>

#include <OpenIPMI/ipmi_auth.h>

/*
 * Restrictions: <=64 sessions
 *               <=64 users (per spec, 6 bits)
 */
#define MAX_USERS		63
#define USER_BITS_REQ		6 /* Bits required to hold a user. */
#define USER_MASK		0x3f
#define MAX_SESSIONS		63
#define SESSION_BITS_REQ	6 /* Bits required to hold a session. */
#define SESSION_MASK		0x3f

#define MAIN_CHANNEL	0x7

typedef struct msg_s
{
    void *src_addr;
    int  src_len;

    long oem_data; /* For use by OEM handlers.  This will be set to
                      zero by the calling code. */

    uint32_t      seq;
    uint32_t      sid;
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

    unsigned char *data;
    int           len;

    unsigned long ll_data; /* For use by the low-level code. */
} msg_t;

typedef struct rsp_msg
{
    uint8_t        netfn;
    uint8_t        cmd;
    unsigned short data_len;
    uint8_t        *data;
} rsp_msg_t;

#define NUM_PRIV_LEVEL 4
typedef struct channel_s
{
    unsigned int available : 1;

    unsigned int PEF_alerting : 1;
    unsigned int per_msg_auth : 1;

    /* We don't support user-level authentication disable, and access
       mode is always available and cannot be set. */

    unsigned int privilege_limit : 4;
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
    uint32_t        recv_seq;
    uint32_t        xmit_seq;
    uint32_t        sid;
    unsigned char   userid;

    unsigned char priv;
    unsigned char max_priv;

    /* The number of seconds left before the session is shut down. */
    unsigned int time_left;

    /* Address of the message that started the sessions. */
    void *src_addr;
    int  src_len;
} session_t;

typedef struct user_s
{
    unsigned char valid;
    unsigned char username[16];
    unsigned char pw[16];
    unsigned char privilege;
    unsigned char max_sessions;
    unsigned char curr_sessions;
    uint16_t      allowed_auths;

    /* Set by the user code. */
    int           idx; /* My idx in the table. */
} user_t;

typedef struct lan_data_s lan_data_t;
struct lan_data_s
{
    /* user 0 is not used. */
    user_t users[MAX_USERS+1];

    channel_t channel;
    channel_t nonv_channel; /* What to write to nonv ram. */

    /* The amount of time in seconds before a session will be shut
       down if there is no activity. */
    unsigned int default_session_timeout;

    unsigned char *guid;

    void *user_info;

    /* Information about the MC we are hooked to. */
    unsigned int  manufacturer_id;
    unsigned int  product_id;

    void (*lan_send)(lan_data_t *lan,
		     struct iovec *data, int vecs,
		     void *addr, int addr_len);

    int (*smi_send)(lan_data_t *lan, msg_t *msg);

    /* Generate 'size' bytes of random data into 'data'. */
    int (*gen_rand)(lan_data_t *lan, void *data, int size);

    /* Allocate and free data. */
    void *(*alloc)(lan_data_t *lan, int size);
    void (*free)(lan_data_t *lan, void *data);

    void *oem_data;

    /* IPMB address changed.  Can be called by OEM code if it detects
       an IPMB address change.  It should be ignored if NULL. */
    void (*ipmb_addr_change)(lan_data_t *lan, unsigned char addr);

    /* Write the configuration file (done when a non-volatile
       change is done, or when a user name/password is written. */
    void (*write_config)(lan_data_t *lan);

#define NEW_SESSION			1
#define NEW_SESSION_FAILED		2
#define SESSION_CLOSED			3
#define SESSION_CHALLENGE		4
#define SESSION_CHALLENGE_FAILED	5
#define AUTH_FAILED			6
#define INVALID_MSG			7
#define OS_ERROR			8
#define LAN_ERR				9
#define INFO				10
#define DEBUG				11
    void (*log)(int type, msg_t *msg, char *format, ...);

    int debug;

    /* Do OEM message handling; this is called after the message is
       authenticated.  Should return 0 if the standard handling should
       continue, or non-zero if the message should not go through
       normal handling.  This field may be NULL, and it will be
       ignored. */
    int (*oem_handle_msg)(lan_data_t *lan, msg_t *msg, session_t *session);

    /* Called before a response is sent.  Should return 0 if the
       standard handling should continue, or non-zero if the OEM
       handled the response itself.  Note that this code should *not
       free the message, the lanserv_ipmi code will handle that. */
    int (*oem_handle_rsp)(lan_data_t *lan, msg_t *msg,
			  session_t *session, rsp_msg_t *rsp);

    /* Check the privilege of a command to see if it is permitted. */
    int (*oem_check_permitted)(unsigned char priv,
			       unsigned char netfn,
			       unsigned char cmd);

    /* Don't fill in the below in the user code. */

    /* session 0 is not used. */
    session_t sessions[MAX_SESSIONS+1];

    /* Used to make the sid somewhat unique. */
    uint32_t sid_seq;

    unsigned int active_sessions;

    ipmi_authdata_t challenge_auth;
    unsigned int next_challenge_seq;
};


typedef void (*handle_oem_cb)(lan_data_t *lan, void *cb_data);
typedef struct oem_handler_s
{
    unsigned int  manufacturer_id;
    unsigned int  product_id;
    handle_oem_cb handler;
    void          *cb_data;

    struct oem_handler_s *next;
} oem_handler_t;

/* Register a new OEM handler. */
void ipmi_register_oem(oem_handler_t *handler);

/* A helper function to allow OEM code to send messages. */
int ipmi_oem_send_msg(lan_data_t    *lan,
		      unsigned char netfn,
		      unsigned char cmd,
		      unsigned char *data,
		      unsigned int  len,
		      long          oem_data);

void handle_asf(lan_data_t *lan,
		unsigned char *data, int len,
		void *from_addr, int from_len);

void ipmi_handle_lan_msg(lan_data_t *lan,
			 unsigned char *data, int len,
			 void *from_addr, int from_len);

void ipmi_handle_smi_rsp(lan_data_t *lan, msg_t *msg,
			 unsigned char *rsp, int rsp_len);

/* Call this periodically to time things.  time_since_last is the
   number of seconds since the last call to this. */
void ipmi_lan_tick(lan_data_t *lan, unsigned int time_since_last);

int ipmi_lan_init(lan_data_t *lan);

#endif /* __LANSERV_H */
