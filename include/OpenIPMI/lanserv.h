/*
 * lanserv.h
 *
 * MontaVista IPMI LAN server include file
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

#ifndef __LANSERV_H
#define __LANSERV_H

#include <sys/uio.h> /* for iovec */
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <resolv.h>

#include <OpenIPMI/ipmi_auth.h>

#ifdef __cplusplus
extern "C" {
#endif

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

typedef struct session_s session_t;
typedef struct lan_data_s lan_data_t;

typedef struct msg_s
{
    void *src_addr;
    int  src_len;

    long oem_data; /* For use by OEM handlers.  This will be set to
                      zero by the calling code. */

    unsigned char authtype;
    uint32_t      seq;
    uint32_t      sid;

    /* RMCP parms */
    unsigned char *authcode;
    unsigned char authcode_data[16];

    /* RMCP+ parms */
    unsigned char payload;
    unsigned char encrypted;
    unsigned char authenticated;
    unsigned char iana[3];
    uint16_t      payload_id;
    unsigned char *authdata;
    unsigned int  authdata_len;

    unsigned char netfn;
    unsigned char rs_addr;
    unsigned char rs_lun;
    unsigned char rq_addr;
    unsigned char rq_lun;
    unsigned char rq_seq;
    unsigned char cmd;

    unsigned char *data;
    unsigned int  len;

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

typedef struct integ_handlers_s
{
    int (*init)(lan_data_t *lan, session_t *session);
    void (*cleanup)(lan_data_t *lan, session_t *session);
    int (*add)(lan_data_t *lan, session_t *session,
	       unsigned char *pos,
	       unsigned int *data_len, unsigned int data_size);
    int (*check)(lan_data_t *lan, session_t *session, msg_t *msg);
} integ_handlers_t;

typedef struct conf_handlers_s
{
    int (*init)(lan_data_t *lan, session_t *session);
    void (*cleanup)(lan_data_t *lan, session_t *session);
    int (*encrypt)(lan_data_t *lan, session_t *session,
		   unsigned char **pos, unsigned int *hdr_left,
		   unsigned int *data_len, unsigned int *data_size);
    int (*decrypt)(lan_data_t *lan, session_t *session, msg_t *msg);
} conf_handlers_t;

typedef struct auth_handlers_s
{
    int (*init)(lan_data_t *lan, session_t *session);
    int (*set2)(lan_data_t *lan, session_t *session,
		unsigned char *data, unsigned int *data_len,
		unsigned int max_len);
    int (*check3)(lan_data_t *lan, session_t *session,
		  unsigned char *data, unsigned int *data_len);
    int (*set4)(lan_data_t *lan, session_t *session,
		unsigned char *data, unsigned int *data_len,
		unsigned int max_len);
} auth_handlers_t;

typedef struct auth_data_s
{
    unsigned char rand[16];
    unsigned char rem_rand[16];
    unsigned char role;
    unsigned char username_len;
    unsigned char username[16];
    unsigned char sik[20];
    unsigned char k1[20];
    unsigned char k2[20];
    unsigned int  akey_len;
    unsigned int  integ_len;
    void          *adata;
    const void    *akey;
    unsigned int  ikey_len;
    void          *idata;
    const void    *ikey;
    const void    *ikey2;
    unsigned int  ckey_len;
    void          *cdata;
    const void    *ckey;
} auth_data_t;

struct session_s
{
    unsigned int active : 1;
    unsigned int in_startup : 1;
    unsigned int rmcpplus : 1;

    int           handle; /* My index in the table. */

    uint32_t        recv_seq;
    uint32_t        xmit_seq;
    uint32_t        sid;
    unsigned char   userid;

    /* RMCP data */
    unsigned char   authtype;
    ipmi_authdata_t authdata;

    /* RMCP+ data */
    uint32_t        unauth_recv_seq;
    uint32_t        unauth_xmit_seq;
    uint32_t        rem_sid;
    unsigned int    auth;
    unsigned int    conf;
    unsigned int    integ;
    integ_handlers_t *integh;
    conf_handlers_t  *confh;
    auth_handlers_t  *authh;
    auth_data_t      auth_data;

    unsigned char priv;
    unsigned char max_priv;

    /* The number of seconds left before the session is shut down. */
    unsigned int time_left;

    /* Address of the message that started the sessions. */
    void *src_addr;
    int  src_len;
};

typedef struct user_s
{
    unsigned char valid;
    unsigned char link_auth;
    unsigned char cb_only;
    unsigned char username[16];
    unsigned char pw[20];
    unsigned char privilege;
    unsigned char max_sessions;
    unsigned char curr_sessions;
    uint16_t      allowed_auths;

    /* Set by the user code. */
    int           idx; /* My idx in the table. */
} user_t;

typedef struct lanparm_dest_data_s
{
    unsigned char type[4];
    unsigned char addr[13];
    unsigned char vlan[4];
} lanparm_dest_data_t;

typedef struct lanparm_data_s lanparm_data_t;
struct lanparm_data_s
{
    unsigned int set_in_progress : 2;
    void (*commit)(lan_data_t *lan); /* Called when the commit occurs. */
    unsigned int auth_type_support : 6; /* Read-only */
    unsigned int ip_addr_src : 4;
    unsigned int bmc_gen_arp_ctl : 2;
    unsigned int garp_interval : 8;
    unsigned int num_destinations : 4; /* Read-only */
    lanparm_dest_data_t dest[16];

    unsigned char auth_type_enables[5];
    unsigned char ip_addr[4];
    unsigned char mac_addr[6];
    unsigned char subnet_mask[4];
    unsigned char ipv4_hdr_parms[3];
    unsigned char primary_rmcp_port[2];
    unsigned char secondary_rmcp_port[2];
    unsigned char default_gw_ip_addr[4];
    unsigned char default_gw_mac_addr[6];
    unsigned char backup_gw_ip_addr[4];
    unsigned char backup_gw_mac_addr[6];
    unsigned char community_string[18];

    unsigned char vlan_id[2];
    unsigned char vlan_priority;
    unsigned int  num_cipher_suites : 4;
    unsigned char cipher_suite_entry[17];
    unsigned char max_priv_for_cipher_suite[9];

    /* Tells what has changed, so the commit can do something about it. */
    struct {
	unsigned int ip_addr_src : 1;
	unsigned int bmc_gen_arp_ctl : 1;
	unsigned int garp_interval : 1;
	unsigned int auth_type_enables : 1;
	unsigned int ip_addr : 1;
	unsigned int mac_addr : 1;
	unsigned int subnet_mask : 1;
	unsigned int ipv4_hdr_parms : 1;
	unsigned int primary_rmcp_port : 1;
	unsigned int secondary_rmcp_port : 1;
	unsigned int default_gw_ip_addr : 1;
	unsigned int default_gw_mac_addr : 1;
	unsigned int backup_gw_ip_addr : 1;
	unsigned int backup_gw_mac_addr : 1;
	unsigned int community_string : 1;
	unsigned int vlan_id : 1;
	unsigned int vlan_priority : 1;
	unsigned int max_priv_for_cipher_suite : 1;
	unsigned char dest_type[16];
	unsigned char dest_addr[16];
	unsigned char dest_vlan[16];
    } changed;
};

#define MAX_EVENT_FILTERS 16
#define MAX_ALERT_POLICIES 16
#define MAX_ALERT_STRINGS 16
#define MAX_ALERT_STRING_LEN 64

typedef struct pef_data_s
{
    unsigned int set_in_progress : 2;
    void (*commit)(lan_data_t *lan); /* Called when the commit occurs. */

    unsigned char pef_control;
    unsigned char pef_action_global_control;
    unsigned char pef_startup_delay;
    unsigned char pef_alert_startup_delay;
    unsigned char num_event_filters;
    unsigned char event_filter_table[MAX_EVENT_FILTERS][21];
    unsigned char event_filter_data1[MAX_EVENT_FILTERS][2];
    unsigned char num_alert_policies;
    unsigned char alert_policy_table[MAX_ALERT_POLICIES][4];
    unsigned char system_guid[17];
    unsigned char num_alert_strings;
    unsigned char alert_string_keys[MAX_ALERT_STRINGS][3];
    unsigned char alert_strings[MAX_ALERT_STRINGS][MAX_ALERT_STRING_LEN];

    /* Tells what has changed, so the commit can do something about it. */
    struct {
	unsigned int pef_control : 1;
	unsigned int pef_action_global_control : 1;
	unsigned int pef_startup_delay : 1;
	unsigned int pef_alert_startup_delay : 1;
	unsigned int system_guid : 1;
	unsigned char event_filter_table[MAX_EVENT_FILTERS];
	unsigned char event_filter_data1[MAX_EVENT_FILTERS];
	unsigned char alert_policy_table[MAX_ALERT_POLICIES];
	unsigned int alert_string_keys[MAX_ALERT_STRINGS];
	unsigned int alert_strings[MAX_ALERT_STRINGS];
    } changed;
} pef_data_t;

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
    unsigned char *bmc_key;

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

    lanparm_data_t lanparm;
    lanparm_data_t lanparm_rollback;

    pef_data_t pef;
    pef_data_t pef_rollback;
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

typedef struct sockaddr_ip_s {
    union
        {
    	    struct sockaddr s_addr;
            struct sockaddr_in  s_addr4;
#ifdef PF_INET6
            struct sockaddr_in6 s_addr6;
#endif
        } s_ipsock;
/*    socklen_t addr_len;*/
} sockaddr_ip_t;

/* Read in a configuration file and fill in the lan and address info. */
int lanserv_read_config(lan_data_t    *lan,
			char          *config_file,
			sockaddr_ip_t addr[],
			socklen_t     addr_len[],
			int           *num_addr);

/* Call this periodically to time things.  time_since_last is the
   number of seconds since the last call to this. */
void ipmi_lan_tick(lan_data_t *lan, unsigned int time_since_last);

int ipmi_lan_init(lan_data_t *lan);

#ifdef __cplusplus
}
#endif

#endif /* __LANSERV_H */
