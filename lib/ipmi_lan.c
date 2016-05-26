/*
 * ipmi_lan.c
 *
 * MontaVista IPMI code for handling IPMI LAN connections
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004 MontaVista Software Inc.
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

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_lan.h>

#include <OpenIPMI/internal/ipmi_event.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/locked_list.h>

#if defined(DEBUG_MSG) || defined(DEBUG_RAWMSG)
static void
dump_hex(void *vdata, int len)
{
    unsigned char *data = vdata;
    int i;
    for (i=0; i<len; i++) {
	if ((i != 0) && ((i % 16) == 0)) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n  ");
	}
	ipmi_log(IPMI_LOG_DEBUG_CONT, " %2.2x", data[i]);
    }
}
#endif

#define LAN_AUDIT_TIMEOUT 10000000

/* Timeout to wait for IPMI responses, in microseconds.  For commands
   with side effects, we wait 5 seconds, not one. */
#define LAN_RSP_TIMEOUT 1000000
#define LAN_RSP_TIMEOUT_SIDEEFF 5000000

/* # of times to try a message before we fail it. */
#define LAN_RSP_RETRIES 6

/* Number of microseconds of consecutive failures allowed on an IP
   before it is considered failed. */
#define IP_FAIL_TIME 7000000

/* Number of consecutive failures that must occur before an IP is
   considered failed. */
#define IP_FAIL_COUNT 4

/* The default for the maximum number of messages that are allowed to be
   outstanding.  This is a pretty conservative number. */
#define DEFAULT_MAX_OUTSTANDING_MSG_COUNT 2
#define MAX_POSSIBLE_OUTSTANDING_MSG_COUNT 63

typedef struct lan_data_s lan_data_t;

typedef struct audit_timer_info_s
{
    int        cancelled;
    ipmi_con_t *ipmi;
} audit_timer_info_t;

typedef struct lan_timer_info_s
{
    int               cancelled;
    ipmi_con_t        *ipmi;
    os_hnd_timer_id_t *timer;
    unsigned int      seq;
} lan_timer_info_t;

typedef struct lan_wait_queue_s
{
    lan_timer_info_t      *info;
    ipmi_addr_t           addr;
    unsigned int          addr_len;
    ipmi_msg_t            msg;
    unsigned char         data[IPMI_MAX_MSG_LENGTH];
    ipmi_ll_rsp_handler_t rsp_handler;
    ipmi_msgi_t           *rsp_item;
    int                   side_effects;

    struct lan_wait_queue_s *next;
} lan_wait_queue_t;

#define MAX_IP_ADDR 2

/* We must keep this number small, if it's too big and a failure
   occurs, we will be outside the sequence number before we switch. */
#define SENDS_BETWEEN_IP_SWITCHES 3

/* Because sizeof(sockaddr_in6) > sizeof(sockaddr_in), this structure
 * is used as a replacement of struct sockaddr. */
typedef struct sockaddr_ip_s {
    union
        {
	    struct sockaddr	s_addr;
            struct sockaddr_in  s_addr4;
#ifdef PF_INET6
            struct sockaddr_in6 s_addr6;
#endif
        } s_ipsock;
    socklen_t ip_addr_len;
} sockaddr_ip_t;

struct ipmi_rmcpp_auth_s
{
    lan_data_t *lan;
    int        addr_num;

    uint8_t       role;

    /* Filled in by the auth algorithm. */
    unsigned char my_rand[16];
    unsigned int  my_rand_len;
    unsigned char mgsys_rand[16];
    unsigned int  mgsys_rand_len;
    unsigned char mgsys_guid[16];
    unsigned int  mgsys_guid_len;
    unsigned char sik[20];
    unsigned int  sik_len;
    unsigned char k1[20];
    unsigned int  k1_len;
    unsigned char k2[20];
    unsigned int  k2_len;
};

typedef struct lan_conn_parms_s
{
    unsigned int  num_ip_addr;
    char          *ip_addr_str[MAX_IP_ADDR];
    char          *ip_port_str[MAX_IP_ADDR];
    sockaddr_ip_t ip_addr[MAX_IP_ADDR];
    unsigned int  authtype;
    unsigned int  privilege;
    unsigned char username[IPMI_USERNAME_MAX];
    unsigned int  username_len;
    unsigned char password[IPMI_PASSWORD_MAX];
    unsigned int  password_len;
    unsigned int  conf;
    unsigned int  integ;
    unsigned int  auth;
    unsigned int  name_lookup_only;
    unsigned char bmc_key[IPMI_PASSWORD_MAX];
    unsigned int  bmc_key_len;
} lan_conn_parms_t;

typedef struct lan_link_s lan_link_t;
struct lan_link_s
{
    lan_link_t *next, *prev;
    lan_data_t *lan;
};

typedef struct lan_fd_s lan_fd_t;

typedef struct lan_stat_info_s
{
#define STAT_RECV_PACKETS	0
#define STAT_XMIT_PACKETS	1
#define STAT_REXMITS		2
#define STAT_TIMED_OUT		3
#define STAT_INVALID_RMCP	4
#define STAT_TOO_SHORT		5
#define STAT_INVALID_AUTH	6
#define STAT_BAD_SESSION_ID	7
#define STAT_AUTH_FAIL		8
#define STAT_DUPLICATES		9
#define STAT_SEQ_OUT_OF_RANGE	10
#define STAT_ASYNC_EVENTS	11
#define STAT_CONN_DOWN		12
#define STAT_CONN_UP		13
#define STAT_BAD_SIZE		14
#define STAT_DECRYPT_FAIL	15
#define STAT_INVALID_PAYLOAD	16
#define STAT_SEQ_ERR		17
#define STAT_RSP_NO_CMD		18
#define NUM_STATS 19
    /* Statistics */
    void *stats[NUM_STATS];
} lan_stat_info_t;

static const char *lan_stat_names[NUM_STATS] =
{
    "lan_recv_packets",
    "lan_xmit_packets",
    "lan_rexmits",
    "lan_timed_out",
    "lan_invalid_rmcp",
    "lan_too_short",
    "lan_invalid_auth",
    "lan_bad_session_id",
    "lan_auth_fail",
    "lan_duplicates",
    "lan_seq_out_of_range",
    "lan_async_events",
    "lan_conn_down",
    "lan_conn_up",
    "lan_bad_size",
    "lan_decrypt_fail",
    "lan_invalid_payload",
    "lan_seq_err",
    "lan_rsp_no_cmd"
};


/* Per-IP specific information. */
typedef struct lan_ip_data_s
{
    int                        working;
    unsigned int               consecutive_failures;
    struct timeval             failure_time;

    /* For both RMCP and RMCP+.  For RMCP+, the session id is the one
       I receive and the sequence numbers are the authenticated
       ones. */
    unsigned char              working_authtype;
    uint32_t                   session_id;
    uint32_t                   outbound_seq_num;
    uint32_t                   inbound_seq_num;
    uint32_t                   recv_msg_map;

    /* RMCP+ specific info */
    uint32_t                   unauth_out_seq_num;
    uint32_t                   unauth_in_seq_num;
    uint32_t                   unauth_recv_msg_map;
    unsigned char              working_integ;
    unsigned char              working_conf;
    uint32_t                   mgsys_session_id;
    ipmi_rmcpp_auth_t          ainfo;

    /* Used to hold the session id before the connection is up. */
    uint32_t                   precon_session_id;
    uint32_t                   precon_mgsys_session_id;

    ipmi_rmcpp_confidentiality_t *conf_info;
    void                         *conf_data;

    ipmi_rmcpp_integrity_t       *integ_info;
    void                         *integ_data;

    /* Use for linked-lists of IP addresses. */
    lan_link_t                 ip_link;
} lan_ip_data_t;


#if IPMI_MAX_MSG_LENGTH > 80
# define LAN_MAX_RAW_MSG IPMI_MAX_MSG_LENGTH
#else
# define LAN_MAX_RAW_MSG 80 /* Enough to hold the rmcp+ session messages */
#endif
struct lan_data_s
{
    unsigned int	       refcount;
    unsigned int	       users;

    ipmi_con_t                 *ipmi;
    lan_fd_t                   *fd;
    int                        fd_slot;

    unsigned char              slave_addr[MAX_IPMI_USED_CHANNELS];
    int                        is_active;

    /* Have we already been started? */
    int                        started;

    /* Are we currently in cleanup?  Don't allow any outgoing messages. */
    int                        in_cleanup;

    /* Protects modifiecations to working, curr_ip_addr, RMCP
       sequence numbers, the con_change_handler, and other
       connection-related data.  Note that if the seq_num_lock must
       also be held, it must be locked before this lock.  */
    ipmi_lock_t                *ip_lock;

    /* If 0, we don't have a connection to the BMC right now. */
    int                        connected;

    /* If 0, we have not yet initialized */
    int                        initialized;

    /* If 0, the OEM handlers have not been called. */
    int                        oem_conn_handlers_called;

    /* Number of packets sent on the connection.  Used to track when
       to switch between IP addresses. */
    unsigned int               num_sends;

    /* The IP address we are currently using. */
    unsigned int               curr_ip_addr;

    /* Data about each IP address */
    lan_ip_data_t              ip[MAX_IP_ADDR];

    /* We keep a session on each LAN connection.  I don't think all
       systems require that, but it's safer. */

    /* From the get channel auth */
    unsigned char              oem_iana[3];
    unsigned char              oem_aux;

    /* Parms we were configured with. */
    lan_conn_parms_t           cparm;

    /* IPMI LAN 1.5 specific info. */
    unsigned char              chosen_authtype;
    unsigned char              challenge_string[16];
    ipmi_authdata_t            authdata;

    /* RMCP+ specific info */
    unsigned int               use_two_keys : 1;

    struct {
	unsigned int          inuse : 1;
	ipmi_addr_t           addr;
	unsigned int          addr_len;
	
	ipmi_msg_t            msg;
	unsigned char         data[LAN_MAX_RAW_MSG];
	ipmi_ll_rsp_handler_t rsp_handler;
	ipmi_msgi_t           *rsp_item;
	int                   use_orig_addr;
	ipmi_addr_t           orig_addr;
	unsigned int          orig_addr_len;
	os_hnd_timer_id_t     *timer;
	lan_timer_info_t      *timer_info;
	int                   retries_left;
	int                   side_effects;

	/* If -1, just use the normal algorithm.  If not -1, force to
           this address. */
	int                   addr_num;

	/* The number of the last IP address sent on. */
	int                   last_ip_num;
    } seq_table[64];
    ipmi_lock_t               *seq_num_lock;

    /* The current sequence number.  Note that we reserve sequence
       number 0 for our own neferous purposes. */
    unsigned int              last_seq;

    /* The number of messages that are outstanding with the remote
       MC. */
    unsigned int outstanding_msg_count;

    /* The maximum number of outstanding messages.  This must NEVER be
       larger than 63 (64 sequence numbers minus 1 for our reserved
       sequence zero. */
    unsigned int max_outstanding_msg_count;

    /* List of messages waiting to be sent. */
    lan_wait_queue_t *wait_q, *wait_q_tail;

    locked_list_t              *event_handlers;

    os_hnd_timer_id_t          *audit_timer;
    audit_timer_info_t         *audit_info;

    /* Handles connection shutdown reporting. */
    ipmi_ll_con_closed_cb close_done;
    void                  *close_cb_data;

    /* This lock is used to assure that the conn changes occur in
       proper order.  The user code is called with this lock held, but
       it should be harmless to the user as this is the only use for
       it.  But the user cannot do a wait on I/O in the handler. */
    ipmi_lock_t            *con_change_lock;
    locked_list_t          *con_change_handlers;

    locked_list_t          *ipmb_change_handlers;

    lan_link_t link;

    locked_list_t *lan_stat_list;
};


/************************************************************************
 *
 * Authentication and encryption information and functions.
 *
 ***********************************************************************/
extern ipmi_payload_t _ipmi_payload;

static int
open_format_msg(ipmi_con_t        *ipmi,
		const ipmi_addr_t *addr,
		unsigned int      addr_len,
		const ipmi_msg_t  *msg,
		unsigned char     *out_data,
		unsigned int      *out_data_len,
		int               *out_of_session,
		unsigned char     seq)
{
    unsigned char *tmsg = out_data;

    if (msg->data_len > *out_data_len)
	return E2BIG;

    memcpy(tmsg, msg->data, msg->data_len);
    tmsg[0] = seq; /* We use the message tag for the sequence # */
    *out_of_session = 1;
    *out_data_len = msg->data_len;
    return 0;
}

static int
open_get_recv_seq(ipmi_con_t    *ipmi,
		  unsigned char *data,
		  unsigned int  data_len,
		  unsigned char *seq)
{
    if (data_len < 1) { /* Minimum size of an IPMI msg. */
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "%sDropped message because too small(7)",
		     IPMI_CONN_NAME(ipmi));
	return EINVAL;
    }
    *seq = data[0];
    return 0;
}

static int
open_handle_recv(ipmi_con_t    *ipmi,
		 ipmi_msgi_t   *rspi,
		 ipmi_addr_t   *orig_addr,
		 unsigned int  orig_addr_len,
		 ipmi_msg_t    *orig_msg,
		 unsigned char *data,
		 unsigned int  data_len)
{
    ipmi_msg_t *msg = &(rspi->msg);
    if (data_len > sizeof(rspi->data))
	return E2BIG;
    memcpy(rspi->data, data, data_len);
    msg->data = rspi->data;
    msg->data_len = data_len;
    return 0;
}

static void
open_handle_recv_async(ipmi_con_t    *ipmi,
		       unsigned char *tmsg,
		       unsigned int  data_len)
{
}

static int
open_get_msg_tag(unsigned char *tmsg,
		 unsigned int  data_len,
		 unsigned char *tag)
{
    if (data_len < 8)
	return EINVAL;
    *tag = ipmi_get_uint32(tmsg+4) - 1; /* session id */
    return 0;
}

static ipmi_payload_t open_payload =
{ open_format_msg, open_get_recv_seq, open_handle_recv,
  open_handle_recv_async, open_get_msg_tag };

static ipmi_payload_t *payloads[64] =
{
    &_ipmi_payload,
    [IPMI_RMCPP_PAYLOAD_TYPE_OPEN_SESSION_REQUEST] = &open_payload,
    [IPMI_RMCPP_PAYLOAD_TYPE_OPEN_SESSION_RESPONSE] = &open_payload
};

typedef struct payload_entry_s payload_entry_t;
struct payload_entry_s
{
    unsigned int   payload_type;
    unsigned char  iana[3];
    unsigned int   payload_id;
    ipmi_payload_t *payload;

    payload_entry_t *next;
};

/* Note that we only add payloads to the head, so no lock is required
   except for addition. */
static ipmi_lock_t *lan_payload_lock = NULL;
payload_entry_t *oem_payload_list = NULL;

int
ipmi_rmcpp_register_payload(unsigned int   payload_type,
			    ipmi_payload_t *payload)
{
    if ((payload_type == IPMI_RMCPP_PAYLOAD_TYPE_IPMI)
	|| (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OEM_EXPLICIT)
	|| (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OPEN_SESSION_REQUEST)
	|| (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OPEN_SESSION_RESPONSE)
	|| (payload_type >= 64)
	|| ((payload_type >= 0x20) && (payload_type <= 0x27))) /* No OEM here*/
    {
	return EINVAL;
    }
    ipmi_lock(lan_payload_lock);
    if (payloads[payload_type] && payload) {
	ipmi_unlock(lan_payload_lock);
	return EAGAIN;
    }

    payloads[payload_type] = payload;
    ipmi_unlock(lan_payload_lock);
    return 0;
}

int
ipmi_rmcpp_register_oem_payload(unsigned int   payload_type,
				unsigned char  iana[3],
				unsigned int   payload_id,
				ipmi_payload_t *payload)
{
    payload_entry_t *e;
    payload_entry_t *c;

    e = ipmi_mem_alloc(sizeof(*e));
    if (!e)
	return ENOMEM;
    e->payload_type = payload_type;
    memcpy(e->iana, iana, 3);
    if (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OEM_EXPLICIT)
	e->payload_id = payload_id;
    else
	e->payload_id = 0;
    e->payload = payload;

    ipmi_lock(lan_payload_lock);
    c = oem_payload_list;
    while (c) {
	if ((c->payload_type == payload_type)
	    && (memcmp(c->iana, iana, 3) == 0)
	    && (c->payload_id == payload_id))
	{
	    ipmi_unlock(lan_payload_lock);
	    ipmi_mem_free(e);
	    return EAGAIN;
	}
	c = c->next;
    }
    e->next = oem_payload_list;
    oem_payload_list = e;
    ipmi_unlock(lan_payload_lock);
    return 0;
}

static ipmi_lock_t *lan_auth_lock = NULL;

typedef struct auth_entry_s auth_entry_t;
struct auth_entry_s
{
    unsigned int  auth_num;
    unsigned char iana[3];
    ipmi_rmcpp_authentication_t *auth;
    auth_entry_t  *next;
};
static auth_entry_t *oem_auth_list = NULL;

static ipmi_rmcpp_authentication_t *auths[64];

int
ipmi_rmcpp_register_authentication(unsigned int                auth_num,
				   ipmi_rmcpp_authentication_t *auth)
{
    if (auth_num >= 64)
	return EINVAL;
    if (auths[auth_num] && auth)
	return EAGAIN;
    
    auths[auth_num] = auth;
    return 0;
}

int
ipmi_rmcpp_register_oem_authentication(unsigned int                auth_num,
				       unsigned char               iana[3],
				       ipmi_rmcpp_authentication_t *auth)
{
    auth_entry_t *e;
    auth_entry_t *c;

    e = ipmi_mem_alloc(sizeof(*e));
    if (!e)
	return ENOMEM;
    e->auth_num = auth_num;
    memcpy(e->iana, iana, 3);
    e->auth = auth;

    ipmi_lock(lan_auth_lock);
    c = oem_auth_list;
    while (c) {
	if ((c->auth_num == auth_num)
	    && (memcmp(c->iana, iana, 3) == 0))
	{
	    ipmi_unlock(lan_auth_lock);
	    ipmi_mem_free(e);
	    return EAGAIN;
	}
    }
    e->next = oem_auth_list;
    oem_auth_list = e;
    ipmi_unlock(lan_auth_lock);
    return 0;
}

typedef struct conf_entry_s conf_entry_t;
struct conf_entry_s
{
    unsigned int  conf_num;
    unsigned char iana[3];
    ipmi_rmcpp_confidentiality_t *conf;
    conf_entry_t  *next;
};
static conf_entry_t *oem_conf_list = NULL;

static int
conf_none_init(ipmi_con_t *ipmi, ipmi_rmcpp_auth_t *ainfo, void **conf_data)
{
    *conf_data = NULL;
    return 0;
}

static void
conf_none_free(ipmi_con_t *ipmi, void *conf_data)
{
}

static int
conf_none_encrypt(ipmi_con_t    *ipmi,
		  void          *conf_data,
		  unsigned char **payload,
		  unsigned int  *header_len,
		  unsigned int  *payload_len,
		  unsigned int  *max_payload_len)
{
    return 0;
}

static int
conf_none_decrypt(ipmi_con_t    *ipmi,
		  void          *conf_data,
		  unsigned char **payload,
		  unsigned int  *payload_len)
{
    return 0;
}
static ipmi_rmcpp_confidentiality_t conf_none =
{ conf_none_init, conf_none_free, conf_none_encrypt, conf_none_decrypt};

static ipmi_rmcpp_confidentiality_t *confs[64] =
{
    &conf_none
};

int ipmi_rmcpp_register_confidentiality(unsigned int                 conf_num,
					ipmi_rmcpp_confidentiality_t *conf)
{
    if ((conf_num == 0) || (conf_num >= 64))
	return EINVAL;
    if (confs[conf_num] && conf)
	return EAGAIN;
    
    confs[conf_num] = conf;
    return 0;
}

int
ipmi_rmcpp_register_oem_confidentiality(unsigned int                 conf_num,
					unsigned char                iana[3],
					ipmi_rmcpp_confidentiality_t *conf)
{
    conf_entry_t *e;
    conf_entry_t *c;

    e = ipmi_mem_alloc(sizeof(*e));
    if (!e)
	return ENOMEM;
    e->conf_num = conf_num;
    memcpy(e->iana, iana, 3);
    e->conf = conf;

    ipmi_lock(lan_auth_lock);
    c = oem_conf_list;
    while (c) {
	if ((c->conf_num == conf_num)
	    && (memcmp(c->iana, iana, 3) == 0))
	{
	    ipmi_unlock(lan_auth_lock);
	    ipmi_mem_free(e);
	    return EAGAIN;
	}
    }
    e->next = oem_conf_list;
    oem_conf_list = e;
    ipmi_unlock(lan_auth_lock);
    return 0;
}

typedef struct integ_entry_s integ_entry_t;
struct integ_entry_s
{
    unsigned int  integ_num;
    unsigned char iana[3];
    ipmi_rmcpp_integrity_t *integ;
    integ_entry_t  *next;
};
static integ_entry_t *oem_integ_list = NULL;

static int
integ_none_init(ipmi_con_t       *ipmi,
		ipmi_rmcpp_auth_t *ainfo,
		void             **integ_data)
{
    *integ_data = NULL;
    return 0;
}

static void
integ_none_free(ipmi_con_t *ipmi,
		void       *integ_data)
{
}

static int
integ_none_pad(ipmi_con_t    *ipmi,
	       void          *integ_data,
	       unsigned char *payload,
	       unsigned int  *payload_len,
	       unsigned int  max_payload_len)
{
    return 0;
}

static int
integ_none_add(ipmi_con_t    *ipmi,
	       void          *integ_data,
	       unsigned char *payload,
	       unsigned int  *payload_len,
	       unsigned int  max_payload_len)
{
    return 0;
}

static int
integ_none_check(ipmi_con_t    *ipmi,
		 void          *integ_data,
		 unsigned char *payload,
		 unsigned int  payload_len,
		 unsigned int  total_len)
{
    return 0;
}

static ipmi_rmcpp_integrity_t integ_none =
{ integ_none_init, integ_none_free, integ_none_pad, integ_none_add,
  integ_none_check };

static ipmi_rmcpp_integrity_t *integs[64] =
{
    &integ_none
};

int ipmi_rmcpp_register_integrity(unsigned int           integ_num,
				  ipmi_rmcpp_integrity_t *integ)
{
    if ((integ_num == 0) || (integ_num >= 64))
	return EINVAL;
    if (integs[integ_num] && integ)
	return EAGAIN;
    
    integs[integ_num] = integ;
    return 0;
}

int
ipmi_rmcpp_register_oem_integrity(unsigned int           integ_num,
				  unsigned char          iana[3],
				  ipmi_rmcpp_integrity_t *integ)
{
    integ_entry_t *e;
    integ_entry_t *c;

    e = ipmi_mem_alloc(sizeof(*e));
    if (!e)
	return ENOMEM;
    e->integ_num = integ_num;
    memcpy(e->iana, iana, 3);
    e->integ = integ;

    ipmi_lock(lan_auth_lock);
    c = oem_integ_list;
    while (c) {
	if ((c->integ_num == integ_num)
	    && (memcmp(c->iana, iana, 3) == 0))
	{
	    ipmi_unlock(lan_auth_lock);
	    ipmi_mem_free(e);
	    return EAGAIN;
	}
    }
    e->next = oem_integ_list;
    oem_integ_list = e;
    ipmi_unlock(lan_auth_lock);
    return 0;
}

uint32_t
ipmi_rmcpp_auth_get_my_session_id(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->lan->ip[ainfo->addr_num].precon_session_id;
}

uint32_t
ipmi_rmcpp_auth_get_mgsys_session_id(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->lan->ip[ainfo->addr_num].precon_mgsys_session_id;
}

uint8_t
ipmi_rmcpp_auth_get_role(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->role;
}

const unsigned char *
ipmi_rmcpp_auth_get_username(ipmi_rmcpp_auth_t *ainfo,
			     unsigned int      *max_len)
{
    *max_len = 16;
    return ainfo->lan->cparm.username;
}

unsigned int
ipmi_rmcpp_auth_get_username_len(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->lan->cparm.username_len;
}

const unsigned char *
ipmi_rmcpp_auth_get_password(ipmi_rmcpp_auth_t *ainfo,
			     unsigned int      *max_len)
{
    *max_len = 20;
    return ainfo->lan->cparm.password;
}

unsigned int
ipmi_rmcpp_auth_get_password_len(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->lan->cparm.password_len;
}

int
ipmi_rmcpp_auth_get_use_two_keys(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->lan->use_two_keys;
}

const unsigned char *
ipmi_rmcpp_auth_get_bmc_key(ipmi_rmcpp_auth_t *ainfo,
			    unsigned int      *max_len)
{
    *max_len = 20;
    if (ainfo->lan->use_two_keys)
	return ainfo->lan->cparm.bmc_key;
    else
	return ainfo->lan->cparm.password;
}

unsigned int
ipmi_rmcpp_auth_get_bmc_key_len(ipmi_rmcpp_auth_t *ainfo)
{
    if (ainfo->lan->use_two_keys)
	return ainfo->lan->cparm.bmc_key_len;
    else
	return ainfo->lan->cparm.password_len;
}

/* From the get channel auth. */
const unsigned char *
ipmi_rmcpp_auth_get_oem_iana(ipmi_rmcpp_auth_t *ainfo,
			     unsigned int      *len)
{
    *len = 3;
    return ainfo->lan->oem_iana;
}

unsigned char
ipmi_rmcpp_auth_get_oem_aux(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->lan->oem_aux;
}

/* Should be filled in by the auth algorithm. */
unsigned char *
ipmi_rmcpp_auth_get_my_rand(ipmi_rmcpp_auth_t *ainfo,
			    unsigned int      *max_len)
{
    *max_len = 16;
    return ainfo->my_rand;
}

unsigned int
ipmi_rmcpp_auth_get_my_rand_len(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->my_rand_len;
}

void
ipmi_rmcpp_auth_set_my_rand_len(ipmi_rmcpp_auth_t *ainfo,
				unsigned int      length)
{
    ainfo->my_rand_len = length;
}

unsigned char *
ipmi_rmcpp_auth_get_mgsys_rand(ipmi_rmcpp_auth_t *ainfo,
			       unsigned int      *max_len)
{
    *max_len = 16;
    return ainfo->mgsys_rand;
}

unsigned int
ipmi_rmcpp_auth_get_mgsys_rand_len(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->mgsys_rand_len;
}

void
ipmi_rmcpp_auth_set_mgsys_rand_len(ipmi_rmcpp_auth_t *ainfo,
				   unsigned int      length)
{
    ainfo->mgsys_rand_len = length;
}

unsigned char *
ipmi_rmcpp_auth_get_mgsys_guid(ipmi_rmcpp_auth_t *ainfo,
			       unsigned int      *max_len)
{
    *max_len = 16;
    return ainfo->mgsys_guid;
}

unsigned int
ipmi_rmcpp_auth_get_mgsys_guid_len(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->mgsys_guid_len;
}

void
ipmi_rmcpp_auth_set_mgsys_guid_len(ipmi_rmcpp_auth_t *ainfo,
				   unsigned int      length)
{
    ainfo->mgsys_guid_len = length;
}

unsigned char *
ipmi_rmcpp_auth_get_sik(ipmi_rmcpp_auth_t *ainfo,
			unsigned int      *max_len)
{
    *max_len = 20;
    return ainfo->sik;
}

unsigned int
ipmi_rmcpp_auth_get_sik_len(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->sik_len;
}

void
ipmi_rmcpp_auth_set_sik_len(ipmi_rmcpp_auth_t *ainfo,
			    unsigned int      length)
{
    ainfo->sik_len = length;
}

unsigned char *
ipmi_rmcpp_auth_get_k1(ipmi_rmcpp_auth_t *ainfo,
		       unsigned int      *max_len)
{
    *max_len = 20;
    return ainfo->k1;
}

unsigned int
ipmi_rmcpp_auth_get_k1_len(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->k1_len;
}

void
ipmi_rmcpp_auth_set_k1_len(ipmi_rmcpp_auth_t *ainfo,
			   unsigned int      length)
{
    ainfo->k1_len = length;
}

unsigned char *
ipmi_rmcpp_auth_get_k2(ipmi_rmcpp_auth_t *ainfo,
		       unsigned int      *max_len)
{
    *max_len = 20;
    return ainfo->k2;
}

unsigned int
ipmi_rmcpp_auth_get_k2_len(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->k2_len;
}

void
ipmi_rmcpp_auth_set_k2_len(ipmi_rmcpp_auth_t *ainfo,
			   unsigned int      length)
{
    ainfo->k2_len = length;
}


static void check_command_queue(ipmi_con_t *ipmi, lan_data_t *lan);
static int send_auth_cap(ipmi_con_t *ipmi, lan_data_t *lan, int addr_num,
			 int force_ipmiv15);

static os_handler_t *lan_os_hnd;

#define MAX_CONS_PER_FD	32
struct lan_fd_s
{
    int            fd;
    os_hnd_fd_id_t *fd_wait_id;
    unsigned int   cons_in_use;
    lan_data_t     *lan[MAX_CONS_PER_FD];
    lan_fd_t       *next, *prev;
    ipmi_lock_t    *con_lock;

    /* Main list info. */
    ipmi_lock_t    *lock;
    lan_fd_t       **free_list;
    lan_fd_t       *list;
};

/* This is a list, but the only searching is to find an fd with a free
   slot (when creating a new lan).  This is O(1) because the first
   entry is guaranteed to have a free slot if any have free slots.
   Note that once one of these is created, it is never destroyed
   (destruction is very difficult because of the race conditions). */
static ipmi_lock_t *fd_list_lock = NULL;
static lan_fd_t fd_list;
static lan_fd_t *fd_free_list;
#ifdef PF_INET6
static ipmi_lock_t *fd6_list_lock = NULL;
static lan_fd_t fd6_list;
static lan_fd_t *fd6_free_list;
#endif

static void data_handler(int            fd,
			 void           *cb_data,
			 os_hnd_fd_id_t *id);

static int
lan_addr_same(sockaddr_ip_t *a1, sockaddr_ip_t *a2)
{
    if (a1->ip_addr_len != a2->ip_addr_len)
	return 0;

    if (a1->s_ipsock.s_addr.sa_family != a2->s_ipsock.s_addr.sa_family) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Address family mismatch: %d %d",
		     a1->s_ipsock.s_addr.sa_family,
		     a2->s_ipsock.s_addr.sa_family);
	return 0;
    }

    switch (a1->s_ipsock.s_addr.sa_family) {
    case PF_INET:
	{
	    struct sockaddr_in *ip1 = &a1->s_ipsock.s_addr4;
	    struct sockaddr_in *ip2 = &a2->s_ipsock.s_addr4;

	    if ((ip1->sin_port == ip2->sin_port)
		&& (ip1->sin_addr.s_addr == ip2->sin_addr.s_addr))
		return 1;
	}
	break;

#ifdef PF_INET6
    case PF_INET6:
	{
	    struct sockaddr_in6 *ip1 = &a1->s_ipsock.s_addr6;
	    struct sockaddr_in6 *ip2 = &a2->s_ipsock.s_addr6;
	    if ((ip1->sin6_port == ip2->sin6_port)
		&& (bcmp(ip1->sin6_addr.s6_addr, ip2->sin6_addr.s6_addr,
			 sizeof(struct in6_addr)) == 0))
		return 1;
	}
	break;
#endif
    default:
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lan: Unknown protocol family: 0x%x",
		 a1->s_ipsock.s_addr.sa_family);
	break;
    }

    return 0;
}

static void
move_to_lan_list_end(lan_fd_t *item)
{
    lan_fd_t *list = item->list;

    item->next->prev = item->prev;
    item->prev->next = item->next;
    item->next = list;
    item->prev = list->prev;
    list->prev->next = item;
    list->prev = item;
}

static void
move_to_lan_list_head(lan_fd_t *item)
{
    lan_fd_t *list = item->list;

    item->next->prev = item->prev;
    item->prev->next = item->next;
    item->next = list->next;
    item->prev = list;
    list->next->prev = item;
    list->next = item;
}

static lan_fd_t *
find_free_lan_fd(int family, lan_data_t *lan, int *slot)
{
    ipmi_lock_t *lock;
    lan_fd_t    *list, *item;
    lan_fd_t    **free_list;
    int         rv;
    int         i;

    if (family == PF_INET) {
	lock = fd_list_lock;
	list = &fd_list;
	free_list = &fd_free_list;
    }
#ifdef PF_INET6
    else if (family == PF_INET6) {
	lock = fd6_list_lock;
	list = &fd6_list;
	free_list = &fd6_free_list;
    }
#endif
    else {
	return NULL;
    }

    ipmi_lock(lock);
    item = list->next;
 retry:
    if (item->cons_in_use < MAX_CONS_PER_FD) {
	int tslot = -1;
	/* Got an entry with a slot, just reuse it. */
	for (i=0; i<MAX_CONS_PER_FD; i++) {
	    if (item->lan[i]) {
		/* Check for a matching IP address.  Can't have two
		   systems with the same address in the same fd entry. */
		unsigned int j, k;
		lan_data_t   *l = item->lan[i];

		for (j=0; j<l->cparm.num_ip_addr; j++) {
		    for (k=0; k<lan->cparm.num_ip_addr; k++) {
			if (lan_addr_same(&l->cparm.ip_addr[j],
					  &lan->cparm.ip_addr[k]))
			{
			    /* Found the same address in the same
			       lan_data file.  Try another one. */
			    item = item->next;
			    goto retry;
			}
		    }
		}
	    } else if (tslot < 0)
		tslot = i;
	}
	if (tslot < 0) {
	    lan_fd_t *next = item->next;
	    /* Can't happen, but log and fix it up. */
	    ipmi_log(IPMI_LOG_SEVERE, "ipmi_lan.c: Internal error, count"
		     " in lan fd list item incorrect, but we can recover.");
	    item->cons_in_use = MAX_CONS_PER_FD;
	    move_to_lan_list_end(item);
	    item = next;
	    goto retry;
	}
	item->cons_in_use++;
	item->lan[tslot] = lan;
	*slot = tslot;

	if (item->cons_in_use == MAX_CONS_PER_FD)
	    /* Out of connections in this item, move it to the end of
	       the list. */
	    move_to_lan_list_end(item);
    } else {
	/* No free entries, create one */
	if (*free_list) {
	    /* Pull them off the free list first. */
	    item = *free_list;
	    *free_list = item->next;
	} else {
	    item = ipmi_mem_alloc(sizeof(*item));
	    if (item) {
		memset(item, 0, sizeof(*item));
		rv = ipmi_create_global_lock(&item->con_lock);
		if (rv) {
		    ipmi_mem_free(item);
		    goto out_unlock;
		}
		item->lock = lock;
		item->free_list = free_list;
		item->list = list;
	    }
	}
	if (!item)
	    goto out_unlock;

	item->next = item;
	item->prev = item;

	item->fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (item->fd == -1) {
	    item->next = *free_list;
	    *free_list = item;
	    item = NULL;
	    goto out_unlock;
	}

	/* Bind is not necessary, we don't care what port we are. */

	/* We want it to be non-blocking. */
	rv = fcntl(item->fd, F_SETFL, O_NONBLOCK);
	if (rv) {
	    close(item->fd);
	    item->next = *free_list;
	    *free_list = item;
	    item = NULL;
	    goto out_unlock;
	}

	rv = lan_os_hnd->add_fd_to_wait_for(lan_os_hnd,
					    item->fd,
					    data_handler, 
					    item,
					    NULL,
					    &(item->fd_wait_id));
	if (rv) {
	    close(item->fd);
	    item->next = *free_list;
	    *free_list = item;
	    item = NULL;
	    goto out_unlock;
	}

	item->cons_in_use++;
	item->lan[0] = lan;
	*slot = 0;

	/* This will have free items, put it at the head of the list. */
	move_to_lan_list_head(item);
    }
 out_unlock:
    ipmi_unlock(lock);
    return item;
}

static void
release_lan_fd(lan_fd_t *item, int slot)
{
    ipmi_lock(item->lock);
    item->lan[slot] = NULL;
    item->cons_in_use--;
    if (item->cons_in_use == 0) {
	lan_os_hnd->remove_fd_to_wait_for(lan_os_hnd, item->fd_wait_id);
	close(item->fd);
	item->next->prev = item->prev;
	item->prev->next = item->next;
	item->next = *(item->free_list);
	*(item->free_list) = item;
    } else {
	/* This has free connections, move it to the head of the
	   list. */
	move_to_lan_list_head(item);
    }
    ipmi_unlock(item->lock);
}

/*
 * We keep two hash tables, one by IP address and one by connection
 * address.
 */
#define LAN_HASH_SIZE 256
#define LAN_HASH_SHIFT 6
static ipmi_lock_t *lan_list_lock = NULL;
static lan_link_t lan_list[LAN_HASH_SIZE];
static lan_link_t lan_ip_list[LAN_HASH_SIZE];

static unsigned int
hash_lan(const ipmi_con_t *ipmi)
{
    unsigned int idx;

    idx = (((unsigned long) ipmi)
	   >> (sizeof(unsigned long) + LAN_HASH_SHIFT));
    idx %= LAN_HASH_SIZE;
    return idx;
}

static unsigned int
hash_lan_addr(const struct sockaddr *addr)
{
    unsigned int idx;
    switch (addr->sa_family)
    {
    case PF_INET:
	{
	    struct sockaddr_in *iaddr = (struct sockaddr_in *) addr;
	    idx = ntohl(iaddr->sin_addr.s_addr) % LAN_HASH_SIZE;
	    break;
	}
#ifdef PF_INET6
    case PF_INET6:
	{
	    /* Use the lower 4 bytes of the IPV6 address. */
	    struct sockaddr_in6 *iaddr = (struct sockaddr_in6 *) addr;
	    idx = htonl(*((uint32_t *) &iaddr->sin6_addr.s6_addr[12]));
	    idx %= LAN_HASH_SIZE;
	    break;
	}
#endif
    default:
	idx = 0;
    }
    idx %= LAN_HASH_SIZE;
    return idx;
}

static void
lan_add_con(lan_data_t *lan)
{
    unsigned int idx;
    lan_link_t   *head;
    unsigned int i;

    ipmi_lock(lan_list_lock);
    idx = hash_lan(lan->ipmi);
    head = &lan_list[idx];
    lan->link.lan = lan;
    lan->link.next = head;
    lan->link.prev = head->prev;
    head->prev->next = &lan->link;
    head->prev = &lan->link;

    for (i=0; i<lan->cparm.num_ip_addr; i++) {
	struct sockaddr *addr = &lan->cparm.ip_addr[i].s_ipsock.s_addr;

	idx = hash_lan_addr(addr);

	head = &lan_ip_list[idx];
	lan->ip[i].ip_link.lan = lan;
	lan->ip[i].ip_link.next = head;
	lan->ip[i].ip_link.prev = head->prev;
	head->prev->next = &lan->ip[i].ip_link;
	head->prev = &lan->ip[i].ip_link;
    }
    ipmi_unlock(lan_list_lock);
}

/* Must be called with the lan list lock held. */
static void
lan_remove_con_nolock(lan_data_t *lan)
{
    unsigned int i;
    if (!lan->link.lan)
	/* Hasn't been initialized. */
	return;
    lan->link.prev->next = lan->link.next;
    lan->link.next->prev = lan->link.prev;
    lan->link.lan = NULL;
    for (i=0; i<lan->cparm.num_ip_addr; i++) {
	lan->ip[i].ip_link.prev->next = lan->ip[i].ip_link.next;
	lan->ip[i].ip_link.next->prev = lan->ip[i].ip_link.prev;
	lan->ip[i].ip_link.lan = NULL;
    }
}

static lan_data_t *
lan_find_con(ipmi_con_t *ipmi)
{
    unsigned int idx;
    lan_link_t   *l;

    ipmi_lock(lan_list_lock);
    idx = hash_lan(ipmi);
    l = lan_list[idx].next;
    while (l->lan) {
	if (l->lan->ipmi == ipmi)
	    break;
	l = l->next;
    }
    if (l->lan)
	l->lan->refcount++;
    ipmi_unlock(lan_list_lock);

    return l->lan;
}

static inline int
cmp_timeval(struct timeval *tv1, struct timeval *tv2)
{
    if (tv1->tv_sec < tv2->tv_sec)
        return -1;
 
    if (tv1->tv_sec > tv2->tv_sec)
        return 1;

    if (tv1->tv_usec < tv2->tv_usec)
        return -1; 
   
    if (tv1->tv_usec > tv2->tv_usec)
        return 1;

    return 0;
}

typedef struct lan_add_stat_info_s
{
    int statnum;
    int count;
} lan_add_stat_info_t;

int
add_stat_cb(void *cb_data, void *item1, void *item2)
{
    ipmi_ll_stat_info_t *info = item2;
    lan_stat_info_t     *stat = item1;
    lan_add_stat_info_t *sinfo = cb_data;

    if (stat->stats[sinfo->statnum])
	ipmi_ll_con_stat_call_adder(info, stat->stats[sinfo->statnum],
				    sinfo->count);
    return LOCKED_LIST_ITER_CONTINUE;
}

static inline void
add_stat(ipmi_con_t *ipmi, int stat, int count)
{
    lan_data_t          *lan = ipmi->con_data;
    lan_add_stat_info_t sinfo;

    sinfo.statnum = stat;
    sinfo.count = count;
    locked_list_iterate(lan->lan_stat_list, add_stat_cb, &sinfo);
}

static inline void
diff_timeval(struct timeval *dest,
             struct timeval *left,
             struct timeval *right)
{
    if (   (left->tv_sec < right->tv_sec)
        || (   (left->tv_sec == right->tv_sec)
            && (left->tv_usec < right->tv_usec)))
    {
        /* If left < right, just force to zero, don't allow negative
           numbers. */
        dest->tv_sec = 0;
        dest->tv_usec = 0;
        return;
    }

    dest->tv_sec = left->tv_sec - right->tv_sec;
    dest->tv_usec = left->tv_usec - right->tv_usec;
    while (dest->tv_usec < 0) {
        dest->tv_usec += 1000000;
        dest->tv_sec--;
    }
}

/* Must be called with the ipmi read or write lock. */
static int lan_valid_ipmi(ipmi_con_t *ipmi)
{
    return (lan_find_con(ipmi) != NULL);
}

static void lan_cleanup(ipmi_con_t *ipmi);

static void
lan_put(ipmi_con_t *ipmi)
{
    lan_data_t *lan = ipmi->con_data;
    int        done;

    ipmi_lock(lan_list_lock);
    lan->refcount--;
    done = lan->refcount == 0;

    /* If done, remove it before we release the lock. */
    if (done)
	lan_remove_con_nolock(lan);
    ipmi_unlock(lan_list_lock);

    if (done)
	lan_cleanup(ipmi);
}

static int
auth_gen(lan_data_t    *lan,
	 unsigned char *out,
	 uint8_t       *ses_id,
	 uint8_t       *seq,
	 unsigned char *data,
	 unsigned int  data_len,
	 int           addr_num)
{
    int rv;
    ipmi_auth_sg_t l[] =
    { { ses_id, 4 },
      { data,   data_len },
      { seq,    4 },
      { NULL,   0 }};

    rv = ipmi_auths[lan->ip[addr_num].working_authtype]
	.authcode_gen(lan->authdata, l, out);
    return rv;
}

static int
auth_check(lan_data_t    *lan,
	   uint8_t       *ses_id,
	   uint8_t       *seq,
	   unsigned char *data,
	   unsigned int  data_len,
	   unsigned char *code,
	   int           addr_num)
{
    int rv;
    ipmi_auth_sg_t l[] =
    { { ses_id, 4  },
      { data,   data_len },
      { seq,    4 },
      { NULL,   0 }};

    rv = ipmi_auths[lan->ip[addr_num].working_authtype]
	.authcode_check(lan->authdata, l, code);
    return rv;
}

#define IPMI_MAX_LAN_LEN    (IPMI_MAX_MSG_LENGTH + 128)
#define IPMI_LAN_MAX_HEADER 128

static int
rmcpp_format_msg(lan_data_t *lan, int addr_num,
		 unsigned int payload_type, int in_session,
		 unsigned char **msgdata, unsigned int *data_len,
		 unsigned int  max_data_len, unsigned int header_len,
		 unsigned char *oem_iana, unsigned int oem_payload_id,
		 const ipmi_con_option_t *options)
{
    unsigned char *tmsg;
    int           rv;
    unsigned int  header_used;
    unsigned char *data;
    unsigned int  payload_len;
    uint32_t      *seqp;
    int           do_auth = 1;
    int           do_conf = 1;

    if (options) {
	while (options->option != IPMI_CON_OPTION_LIST_END) {
	    switch (options->option) {
	    case IPMI_CON_MSG_OPTION_AUTH:
		do_auth = options->ival;
		break;

	    case IPMI_CON_MSG_OPTION_CONF:
		do_conf = options->ival;
		break;

	    default:
		/* Ignore unknown options. */
		break;
	    }
	    options++;
	}
    }

    do_conf = (do_conf && in_session
	       && (lan->ip[addr_num].working_conf
		   != IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE));
    do_auth = (do_auth && in_session
	       && (lan->ip[addr_num].working_integ
		   != IPMI_LANP_INTEGRITY_ALGORITHM_NONE));

    if (do_conf) {
#if 0
	if (! lan->ip[addr_num].working)
	    return EAGAIN;
#endif

	/* Note: This may encrypt the data, the old data will be lost. */
	rv = lan->ip[addr_num].conf_info->conf_encrypt
	    (lan->ipmi,
	     lan->ip[addr_num].conf_data,
	     msgdata,
	     &header_len, data_len,
	     &max_data_len);
	if (rv)
	    return rv;
    }

    payload_len = *data_len;

    if (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OEM_EXPLICIT)
	header_used = 22;
    else
	header_used = 16;

    if (header_used > header_len)
	return E2BIG;

    data = *msgdata - header_used;
    *data_len += header_used;
    max_data_len += header_used;

    data[0] = 6; /* RMCP version 1.0. */
    data[1] = 0;
    data[2] = 0xff;
    data[3] = 0x07;
    data[4] = lan->ip[addr_num].working_authtype;
    data[5] = payload_type;
    tmsg = data+6;
    if (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OEM_EXPLICIT) {
	memcpy(tmsg, oem_iana, 3);
	tmsg += 3;
	*tmsg = 0;
	tmsg++;
	ipmi_set_uint16(tmsg, oem_payload_id);
	tmsg += 2;
    }
    if (in_session) {
	if (do_conf)
	    data[5] |= 0x80;
	if (do_auth) {
	    seqp = &(lan->ip[addr_num].outbound_seq_num);
	    data[5] |= 0x40;
	} else {
	    seqp = &(lan->ip[addr_num].unauth_out_seq_num);
	}
	ipmi_set_uint32(tmsg, lan->ip[addr_num].mgsys_session_id);
	tmsg += 4;
	ipmi_set_uint32(tmsg, *seqp);
	tmsg += 4;
    } else {
	ipmi_set_uint32(tmsg, 0); /* session id */
	tmsg += 4;
	ipmi_set_uint32(tmsg, 0); /* session sequence number */
	tmsg += 4;
	seqp = NULL;
    }

    /* Payload length doesn't include the padding. */
    ipmi_set_uint16(tmsg, payload_len);

    if (do_auth) {
	rv = lan->ip[addr_num].integ_info->integ_pad
	    (lan->ipmi,
	     lan->ip[addr_num].integ_data,
	     data, data_len,
	     max_data_len);
	if (rv)
	    return rv;

	rv = lan->ip[addr_num].integ_info->integ_add
	    (lan->ipmi,
	     lan->ip[addr_num].integ_data,
	     data, data_len,
	     max_data_len);
	if (rv)
	    return rv;
    }

    if (seqp) {
	(*seqp)++;
	if (*seqp == 0)
	    *seqp = 1;
    }

    *msgdata = data;

    return 0;
}

static int
lan15_format_msg(lan_data_t *lan, int addr_num,
		 unsigned char **msgdata, unsigned int *data_len)
{
    unsigned char *data;
    int           rv;

    if (lan->ip[addr_num].working_authtype == IPMI_AUTHTYPE_NONE)
	data = *msgdata - 14;
    else
	data = *msgdata - 30;

    data[0] = 6; /* RMCP version 1.0. */
    data[1] = 0;
    data[2] = 0xff;
    data[3] = 0x07;
    data[4] = lan->ip[addr_num].working_authtype;
    ipmi_set_uint32(data+5, lan->ip[addr_num].outbound_seq_num);
    ipmi_set_uint32(data+9, lan->ip[addr_num].session_id);

    /* FIXME - need locks for the sequence numbers. */

    /* Increment the outbound number, but make sure it's not zero.  If
       it's already zero, ignore it, we are in pre-setup. */
    if (lan->ip[addr_num].outbound_seq_num != 0) {
	(lan->ip[addr_num].outbound_seq_num)++;
	if (lan->ip[addr_num].outbound_seq_num == 0)
	    (lan->ip[addr_num].outbound_seq_num)++;
    }

    if (lan->ip[addr_num].working_authtype == IPMI_AUTHTYPE_NONE) {
	/* No authentication, so no authcode. */
	data[13] = *data_len;
	*data_len += 14;
    } else {
	data[29] = *data_len;
	rv = auth_gen(lan, data+13, data+9, data+5, *msgdata, *data_len,
		      addr_num);
	if (rv)
	    return rv;
	*data_len += 30;
    }
    *msgdata = data;

    return 0;
}

static int
lan_send_addr(lan_data_t              *lan,
	      const ipmi_addr_t       *addr,
	      int                     addr_len,
	      const ipmi_msg_t        *msg,
	      uint8_t                 seq,
	      int                     addr_num,
	      const ipmi_con_option_t *options)
{
    unsigned char  data[IPMI_MAX_LAN_LEN+IPMI_LAN_MAX_HEADER];
    unsigned char  *tmsg;
    unsigned int   pos;
    int            rv;
    unsigned int   payload_type;
    int            out_of_session = 0;
    ipmi_payload_t *payload = NULL;
    unsigned char  oem_iana[3] = {0, 0, 0};
    unsigned int   oem_payload_id = 0;

    if ((addr->addr_type >= IPMI_RMCPP_ADDR_START)
	&& (addr->addr_type <= IPMI_RMCPP_ADDR_END))
    {
	/*
	 * Let through the dodgy IPMI 1.5 Serial-over-LAN packets, but block
	 * anything else that tries to send an RMCP+ packet to a non-RMCP+
	 * host.
	 */
	if ((addr->addr_type != IPMI_RMCPP_ADDR_SOL)
		&& (lan->ip[addr_num].working_authtype != IPMI_AUTHTYPE_RMCP_PLUS))
	    return EINVAL;
	payload_type = addr->addr_type - IPMI_RMCPP_ADDR_START;
    } else {
	switch (addr->addr_type) {
	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
	case IPMI_IPMB_ADDR_TYPE:
	case IPMI_IPMB_BROADCAST_ADDR_TYPE:
	    payload_type = IPMI_RMCPP_PAYLOAD_TYPE_IPMI;
	    break;
	default:
	    return EINVAL;
	}
    }

    if ((payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OEM_EXPLICIT)
	|| ((payload_type >= 0x20) && (payload_type <= 0x27)))
    {
	ipmi_rmcpp_addr_t *rmcpp_addr = (ipmi_rmcpp_addr_t *) addr;
	payload_entry_t *e;

	if (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OEM_EXPLICIT) {
	    memcpy(oem_iana, rmcpp_addr->oem_iana, 3);
	    oem_payload_id = rmcpp_addr->oem_payload_id;
	} else {
	    memcpy(oem_iana, lan->oem_iana, 3);
	    oem_payload_id = 0;
	}

	/* No lock required, only payload additions are allowed. */
	e = oem_payload_list;
	while (e) {
	    if ((e->payload_type == payload_type)
		&& (memcmp(e->iana, oem_iana, 3) == 0)
		&& (e->payload_id == oem_payload_id))
	    {
		payload = e->payload;
		break;
	    }
	    e = e->next;
	}
    } else {
	payload = payloads[payload_type];
    }

    tmsg = data + IPMI_LAN_MAX_HEADER;
    if (!payload) {
	return ENOSYS;
    } else {
	pos = IPMI_MAX_LAN_LEN;
	rv = payload->format_for_xmit(lan->ipmi, addr, addr_len,
				      msg, tmsg, &pos,
				      &out_of_session, seq);
	if (rv)
	    return rv;
    }

    if (lan->ip[addr_num].working_authtype == IPMI_AUTHTYPE_RMCP_PLUS) {
	rv = rmcpp_format_msg(lan, addr_num,
			      payload_type, !out_of_session,
			      &tmsg, &pos,
			      IPMI_MAX_LAN_LEN, IPMI_LAN_MAX_HEADER,
			      oem_iana, oem_payload_id, options);
    } else {
	rv = lan15_format_msg(lan, addr_num, &tmsg, &pos);
	if (addr->addr_type == IPMI_RMCPP_ADDR_SOL)
		/*
		 * We're sending SoL over IPMI 1.5, which requires that we set
		 * a "reserved" bit.  This is dodgy.
		 */
		tmsg[4] |= 0x80;
    }
    if (rv)
	return rv;

    if (DEBUG_RAWMSG) {
	char buf1[32], buf2[32];
	ipmi_log(IPMI_LOG_DEBUG_START, "%soutgoing seq %d\n addr =",
		 IPMI_CONN_NAME(lan->ipmi), seq);
	dump_hex((unsigned char *) &(lan->cparm.ip_addr[addr_num]),
		 sizeof(sockaddr_ip_t));
        ipmi_log(IPMI_LOG_DEBUG_CONT,
                 "\n msg  = netfn=%s cmd=%s data_len=%d.",
		 ipmi_get_netfn_string(msg->netfn, buf1, 32),
                 ipmi_get_command_string(msg->netfn, msg->cmd, buf2, 32),
		 msg->data_len);
	if (pos) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =\n  ");
	    dump_hex(tmsg, pos);
	}
	ipmi_log(IPMI_LOG_DEBUG_END, " ");
    }

    add_stat(lan->ipmi, STAT_XMIT_PACKETS, 1);

    rv = sendto(lan->fd->fd, tmsg, pos, 0,
		(struct sockaddr *) &(lan->cparm.ip_addr[addr_num].s_ipsock),
		lan->cparm.ip_addr[addr_num].ip_addr_len);
    if (rv == -1)
	rv = errno;
    else
	rv = 0;

    return rv;
}

static int
lan_send(lan_data_t              *lan,
	 const ipmi_addr_t       *addr,
	 int                     addr_len,
	 const ipmi_msg_t        *msg,
	 uint8_t                 seq,
	 int                     *send_ip_num,
	 const ipmi_con_option_t *options)
{
    int curr_ip_addr;

    ipmi_lock(lan->ip_lock);
    if (msg->netfn & 1) {
	/* For unacknowledged packets, don't switch addresses.  They
	   don't contribute to detecting that the link is down. */
	curr_ip_addr = lan->curr_ip_addr;
    } else if (lan->connected) {
	lan->num_sends++;

	/* We periodically switch between IP addresses, just to make sure
	   they are all operational. */
	if ((lan->num_sends % SENDS_BETWEEN_IP_SWITCHES) == 0) {
	    unsigned int addr_num = lan->curr_ip_addr + 1;
	    if (addr_num >= lan->cparm.num_ip_addr)
		addr_num = 0;
	    while (addr_num != lan->curr_ip_addr) {
		if (lan->ip[addr_num].working)
		    break;
		addr_num++;
		if (addr_num >= lan->cparm.num_ip_addr)
		    addr_num = 0;
	    }
	    lan->curr_ip_addr = addr_num;
	}
    } else {
	/* Just rotate between IP addresses if we are not yet connected */
	unsigned int addr_num = lan->curr_ip_addr + 1;
	if (addr_num >= lan->cparm.num_ip_addr)
	    addr_num = 0;
	lan->curr_ip_addr = addr_num;
    }
    curr_ip_addr = lan->curr_ip_addr;
    ipmi_unlock(lan->ip_lock);

    *send_ip_num = curr_ip_addr;

    return lan_send_addr(lan, addr, addr_len, msg, seq, curr_ip_addr, options);
}

typedef struct call_ipmb_change_handler_s
{
    lan_data_t   *lan;
    int           err;
    const unsigned char *ipmb_addr;
    unsigned int  num_ipmb_addr;
    int           active;
    unsigned int  hacks;
} call_ipmb_change_handler_t;

static int
call_ipmb_change_handler(void *cb_data, void *item1, void *item2)
{
    call_ipmb_change_handler_t *info = cb_data;
    ipmi_ll_ipmb_addr_cb       handler = item1;

    handler(info->lan->ipmi, info->err, info->ipmb_addr, info->num_ipmb_addr,
	    info->active, info->hacks, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_ipmb_change_handlers(lan_data_t *lan, int err,
			  const unsigned char ipmb_addr[],
			  unsigned int num_ipmb_addr,
			  int active, unsigned int hacks)
{
    call_ipmb_change_handler_t info;

    info.lan = lan;
    info.err = err;
    info.ipmb_addr = ipmb_addr;
    info.num_ipmb_addr = num_ipmb_addr;
    info.active = active;
    info.hacks = hacks;
    locked_list_iterate(lan->ipmb_change_handlers, call_ipmb_change_handler,
			&info);
}

static int
lan_add_ipmb_addr_handler(ipmi_con_t           *ipmi,
			  ipmi_ll_ipmb_addr_cb handler,
			  void                 *cb_data)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    if (locked_list_add(lan->ipmb_change_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

static int
lan_remove_ipmb_addr_handler(ipmi_con_t           *ipmi,
			     ipmi_ll_ipmb_addr_cb handler,
			     void                 *cb_data)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    if (locked_list_remove(lan->ipmb_change_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

static void
ipmb_handler(ipmi_con_t   *ipmi,
	     int          err,
	     const unsigned char ipmb_addr[],
	     unsigned int num_ipmb_addr,
	     int          active,
	     unsigned int hacks,
	     void         *cb_data)
{
    lan_data_t *lan;
    int        changed = 0;
    int        i;

    if (err)
	return;

    lan = (lan_data_t *) ipmi->con_data;

    for (i=0; i<MAX_IPMI_USED_CHANNELS; i++) {
	if (! ipmb_addr[i])
	    continue;
	if (ipmb_addr[i] != lan->slave_addr[i]) {
	    lan->slave_addr[i] = ipmb_addr[i];
	    ipmi->ipmb_addr[i] = ipmb_addr[i];
	    changed = 1;
	}
    }
    if (changed || (lan->is_active != active))  {
	lan->is_active = active;
	ipmi->hacks = hacks;
	call_ipmb_change_handlers(lan, err, ipmb_addr, num_ipmb_addr,
				  active, hacks);
    }
}

static void
audit_timeout_handler(void              *cb_data,
		      os_hnd_timer_id_t *id)
{
    audit_timer_info_t           *info = cb_data;
    ipmi_con_t                   *ipmi = info->ipmi;
    lan_data_t                   *lan;
    struct timeval               timeout;
    ipmi_msg_t                   msg;
    unsigned int                 i;
    ipmi_system_interface_addr_t si;
    int                          start_up[MAX_IP_ADDR];


    /* If we were cancelled, just free the data and ignore the call. */
    if (info->cancelled)
	goto out_done;

    if (!lan_valid_ipmi(ipmi))
	goto out_done;

    lan = ipmi->con_data;

    /* Send message to all addresses we think are down.  If the
       connection is down, this will bring it up, otherwise it
       will keep it alive. */
    ipmi_lock(lan->ip_lock);
    for (i=0; i<lan->cparm.num_ip_addr; i++)
	    start_up[i] = ! lan->ip[i].working;
    ipmi_unlock(lan->ip_lock);

    for (i=0; i<lan->cparm.num_ip_addr; i++) {
	if (start_up[i])
	    send_auth_cap(ipmi, lan, i, 0);
    }

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_DEVICE_ID_CMD;
    msg.data = NULL;
    msg.data_len = 0;
		
    /* Send a message to check the working of the interface. */
    if (ipmi->get_ipmb_addr) {
	/* If we have a way to query the IPMB address, do so
           periodically. */
	ipmi->get_ipmb_addr(ipmi, ipmb_handler, NULL);
    } else {
	si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si.channel = 0xf;
	si.lun = 0;
	ipmi->send_command(ipmi, (ipmi_addr_t *) &si, sizeof(si),
			   &msg, NULL, NULL);
    }

    timeout.tv_sec = LAN_AUDIT_TIMEOUT / 1000000;
    timeout.tv_usec = LAN_AUDIT_TIMEOUT % 1000000;
    ipmi->os_hnd->start_timer(ipmi->os_hnd,
			      id,
			      &timeout,
			      audit_timeout_handler,
			      cb_data);

    /* Make sure the timer info doesn't get freed. */
    info = NULL;

    lan_put(ipmi);

 out_done:
    if (info) {
	ipmi->os_hnd->free_timer(ipmi->os_hnd, id);
	ipmi_mem_free(info);
    }
    return;
}

typedef struct call_con_change_handler_s
{
    lan_data_t  *lan;
    int          err;
    unsigned int port;
    int          any_port_up;
} call_con_change_handler_t;

static int
call_con_change_handler(void *cb_data, void *item1, void *item2)
{
    call_con_change_handler_t  *info = cb_data;
    ipmi_ll_con_changed_cb     handler = item1;

    handler(info->lan->ipmi, info->err, info->port, info->any_port_up, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_con_change_handlers(lan_data_t *lan, int err, unsigned int port,
			 int any_port_up)
{
    call_con_change_handler_t info;

    info.lan = lan;
    info.err = err;
    info.port = port;
    info.any_port_up = any_port_up;
    locked_list_iterate(lan->con_change_handlers, call_con_change_handler,
			&info);
}

void
_ipmi_lan_con_change_lock(ipmi_con_t *ipmi)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;
    ipmi_lock(lan->ip_lock);
    ipmi_lock(lan->con_change_lock);
    ipmi_unlock(lan->ip_lock);
}

void
_ipmi_lan_con_change_unlock(ipmi_con_t *ipmi)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;
    ipmi_unlock(lan->con_change_lock);
}

void
_ipmi_lan_call_con_change_handlers(ipmi_con_t   *ipmi,
				   int          err,
				   unsigned int port)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    call_con_change_handlers(lan, err, port, lan->connected);
}

static int
lan_add_con_change_handler(ipmi_con_t             *ipmi,
			   ipmi_ll_con_changed_cb handler,
			   void                   *cb_data)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    if (locked_list_add(lan->con_change_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

static int
lan_remove_con_change_handler(ipmi_con_t             *ipmi,
			      ipmi_ll_con_changed_cb handler,
			      void                   *cb_data)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    if (locked_list_remove(lan->con_change_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

static void
connection_up(lan_data_t *lan, int addr_num, int new_con)
{
    add_stat(lan->ipmi, STAT_CONN_UP, 1);

    ipmi_lock(lan->ip_lock);
    if ((! lan->ip[addr_num].working) && new_con) {
	lan->ip[addr_num].working = 1;

	ipmi_log(IPMI_LOG_INFO,
		 "%sipmi_lan.c(connection_up): "
		 "Connection %d to the BMC is up",
		 IPMI_CONN_NAME(lan->ipmi), addr_num);
    }

    if (new_con) {
	ipmi_log(IPMI_LOG_INFO,
		 "%sipmi_lan.c(connection_up): "
		 "Connection to the BMC restored",
		 IPMI_CONN_NAME(lan->ipmi));
	lan->curr_ip_addr = addr_num;
    }

    if (lan->connected) {
	ipmi_lock(lan->con_change_lock);
	ipmi_unlock(lan->ip_lock);
	call_con_change_handlers(lan, 0, addr_num, 1);
	ipmi_unlock(lan->con_change_lock);
    } else {
	ipmi_unlock(lan->ip_lock);
    }    
}

static void
reset_session_data(lan_data_t *lan, int addr_num)
{
    lan_ip_data_t *ip = &lan->ip[addr_num];

    ip->outbound_seq_num = 0;
    ip->inbound_seq_num = 0;
    ip->session_id = 0;
    ip->mgsys_session_id = 0;
    ip->precon_session_id = 0;
    ip->precon_mgsys_session_id = 0;
    ip->recv_msg_map = 0;
    ip->unauth_recv_msg_map = 0;
    ip->working_authtype = 0;
    ip->unauth_out_seq_num = 0;
    ip->unauth_in_seq_num = 0;
    if (ip->conf_data) {
	ip->conf_info->conf_free(lan->ipmi, ip->conf_data);
	ip->conf_data = NULL;
    }
    ip->conf_info = NULL;
    if (ip->integ_data) {
	ip->integ_info->integ_free(lan->ipmi, ip->integ_data);
	ip->integ_data = NULL;
    }
    ip->integ_info = NULL;
    ip->working_conf = IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE;
    ip->working_integ = IPMI_LANP_INTEGRITY_ALGORITHM_NONE;
}

static void
lost_connection(lan_data_t *lan, unsigned int addr_num)
{
    unsigned int i;

    ipmi_lock(lan->ip_lock);
    if (! lan->ip[addr_num].working) {
	ipmi_unlock(lan->ip_lock);
	return;
    }

    add_stat(lan->ipmi, STAT_CONN_DOWN, 1);

    lan->ip[addr_num].working = 0;

    reset_session_data(lan, addr_num);

    ipmi_log(IPMI_LOG_WARNING,
	     "%sipmi_lan.c(lost_connection): "
	     "Connection %d to the BMC is down",
	     IPMI_CONN_NAME(lan->ipmi), addr_num);

    if (lan->curr_ip_addr == addr_num) {
	/* Scan to see if any address is operational. */
	for (i=0; i<lan->cparm.num_ip_addr; i++) {
	    if (lan->ip[i].working) {
		lan->curr_ip_addr = i;
		break;
	    }
	}

	if (i >= lan->cparm.num_ip_addr) {
	    /* There were no operational connections, report that. */
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%sipmi_lan.c(lost_connection): "
		     "All connections to the BMC are down",
		     IPMI_CONN_NAME(lan->ipmi));

	    lan->connected = 0;
	}
    }

    {
	int connected = lan->connected;
	
	ipmi_lock(lan->con_change_lock);
	ipmi_unlock(lan->ip_lock);
	call_con_change_handlers(lan, ETIMEDOUT, addr_num, connected);
	ipmi_unlock(lan->con_change_lock);
    }
}

static void
rsp_timeout_handler(void              *cb_data,
		    os_hnd_timer_id_t *id)
{
    lan_timer_info_t      *info = cb_data;
    ipmi_con_t            *ipmi = info->ipmi;
    lan_data_t            *lan;
    int                   seq;
    ipmi_ll_rsp_handler_t handler;
    ipmi_msgi_t           *rspi;
    int                   ip_num = 0;
    int                   call_lost_con = 0;

    if (!lan_valid_ipmi(ipmi))
	return;

    lan = ipmi->con_data;
    seq = info->seq;

    ipmi_lock(lan->seq_num_lock);

    /* If we were cancelled, just free the data and ignore it. */
    if (info->cancelled) {
	ipmi_unlock(lan->seq_num_lock);
	goto out;
    }

    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	ipmi_log(IPMI_LOG_DEBUG, "%sTimeout for seq #%d",
		 IPMI_CONN_NAME(ipmi), seq);

    if (! lan->seq_table[seq].inuse) {
	ipmi_unlock(lan->seq_num_lock);
	goto out;
    }

    if (DEBUG_RAWMSG) {
	ip_num = lan->seq_table[seq].last_ip_num;
	ipmi_log(IPMI_LOG_DEBUG,
		 "%sSeq #%d\n"
		 "  addr_type=%d, ip_num=%d, fails=%d\n"
		 "  fail_start_time=%ld.%6.6ld",
		 IPMI_CONN_NAME(ipmi), 
		 seq, lan->seq_table[seq].addr.addr_type,
		 lan->seq_table[seq].last_ip_num,
		 lan->ip[ip_num].consecutive_failures,
		 lan->ip[ip_num].failure_time.tv_sec,
		 lan->ip[ip_num].failure_time.tv_usec);
    }

    if (lan->seq_table[seq].addr.addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE)
    {
	/* We only count timeouts on messages to the system interface.
           Otherwise, if we sent a bunch of messages to the IPMB that
           timed out, we might trigger this code accidentally. */
	ip_num = lan->seq_table[seq].last_ip_num;
	ipmi_lock(lan->ip_lock);
	if (lan->ip[ip_num].working) {
	    if (lan->ip[ip_num].consecutive_failures == 0) {
		/* Set the time when the connection will be considered
                   failed. */
		ipmi->os_hnd->get_monotonic_time(ipmi->os_hnd,
					       &(lan->ip[ip_num].failure_time));
		lan->ip[ip_num].failure_time.tv_sec += IP_FAIL_TIME / 1000000;
		lan->ip[ip_num].failure_time.tv_usec += IP_FAIL_TIME % 1000000;
		if (lan->ip[ip_num].failure_time.tv_usec > 1000000) {
		    lan->ip[ip_num].failure_time.tv_sec += 1;
		    lan->ip[ip_num].failure_time.tv_usec -= 1000000;
		}
		lan->ip[ip_num].consecutive_failures = 1;
	    } else if (!lan->seq_table[seq].side_effects) {
		/* Don't use messages with side effects for failure
		   detection. */
		lan->ip[ip_num].consecutive_failures++;
		if (lan->ip[ip_num].consecutive_failures >= IP_FAIL_COUNT) {
		    /* Consider this for a failure, check after unlocking */
		    call_lost_con = 1;
		}
	    }
	}
	ipmi_unlock(lan->ip_lock);

	if (call_lost_con) {
	    struct timeval now;
	    ipmi->os_hnd->get_monotonic_time(ipmi->os_hnd, &now);
	    if (cmp_timeval(&now, &lan->ip[ip_num].failure_time) <= 0) {
		/* Not a failure yet. */
		call_lost_con = 0;
	    }
	}
    }

    rspi = lan->seq_table[seq].rsp_item;

    if (lan->seq_table[seq].retries_left > 0)
    {
	struct timeval timeout;
	int            rv;

	lan->seq_table[seq].retries_left--;

	add_stat(ipmi, STAT_REXMITS, 1);

	/* Note that we will need a new session seq # here, we can't reuse
	   the old one.  If the message got lost on the way back, the other
	   end would silently ignore resends of the seq #. */
	if (lan->seq_table[seq].addr_num >= 0)
	    rv = lan_send_addr(lan,
			       &(lan->seq_table[seq].addr),
			       lan->seq_table[seq].addr_len,
			       &(lan->seq_table[seq].msg),
			       seq,
			       lan->seq_table[seq].addr_num,
			       NULL);
	else
	    rv = lan_send(lan,
			  &(lan->seq_table[seq].addr),
			  lan->seq_table[seq].addr_len,
			  &(lan->seq_table[seq].msg),
			  seq,
			  &(lan->seq_table[seq].last_ip_num),
			  NULL);

	if (rv) {
	    /* If we get an error resending the message, report an unknown
	       error. */
	    rspi->data[0] = IPMI_UNKNOWN_ERR_CC;
	} else {
	    if (!lan->seq_table[seq].side_effects) {
		timeout.tv_sec = LAN_RSP_TIMEOUT / 1000000;
		timeout.tv_usec = LAN_RSP_TIMEOUT % 1000000;
	    } else {
		timeout.tv_sec = LAN_RSP_TIMEOUT_SIDEEFF / 1000000;
		timeout.tv_usec = LAN_RSP_TIMEOUT_SIDEEFF % 1000000;
	    }
	    ipmi->os_hnd->start_timer(ipmi->os_hnd,
				      id,
				      &timeout,
				      rsp_timeout_handler,
				      cb_data);

	    ipmi_unlock(lan->seq_num_lock);
	    if (call_lost_con)
		lost_connection(lan, ip_num);
	    lan_put(ipmi);
	    return;
	}
    } else {
	add_stat(ipmi, STAT_TIMED_OUT, 1);

	rspi->data[0] = IPMI_TIMEOUT_CC;
    }

    rspi->msg.netfn = lan->seq_table[seq].msg.netfn | 1;
    rspi->msg.cmd = lan->seq_table[seq].msg.cmd;
    rspi->msg.data = rspi->data;
    rspi->msg.data_len = 1;

    if (lan->seq_table[seq].use_orig_addr) {
	/* We did an address translation, so translate back. */
	memcpy(&rspi->addr, &lan->seq_table[seq].orig_addr,
	       lan->seq_table[seq].orig_addr_len);
	rspi->addr_len = lan->seq_table[seq].orig_addr_len;
    } else {
	memcpy(&rspi->addr,
	       &(lan->seq_table[seq].addr),
	       lan->seq_table[seq].addr_len);
	rspi->addr_len = lan->seq_table[seq].addr_len;
    }

    handler = lan->seq_table[seq].rsp_handler;

    lan->seq_table[seq].inuse = 0;

    check_command_queue(ipmi, lan);
    ipmi_unlock(lan->seq_num_lock);

    ipmi->os_hnd->free_timer(ipmi->os_hnd, id);

    /* Convert broadcasts back into normal sends. */
    if (rspi->addr.addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE)
	rspi->addr.addr_type = IPMI_IPMB_ADDR_TYPE;

    if (call_lost_con)
	lost_connection(lan, ip_num);

    ipmi_handle_rsp_item(ipmi, rspi, handler);

 out:
    lan_put(ipmi);
    ipmi_mem_free(info);
}

typedef struct call_event_handler_s
{
    lan_data_t        *lan;
    const ipmi_addr_t *addr;
    unsigned int      addr_len;
    ipmi_event_t      *event;
} call_event_handler_t;

static int
call_event_handler(void *cb_data, void *item1, void *item2)
{
    call_event_handler_t  *info = cb_data;
    ipmi_ll_evt_handler_t handler = item1;

    handler(info->lan->ipmi, info->addr, info->addr_len, info->event, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
lan_add_event_handler(ipmi_con_t            *ipmi,
		      ipmi_ll_evt_handler_t handler,
		      void                  *cb_data)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    if (locked_list_add(lan->event_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

static int
lan_remove_event_handler(ipmi_con_t            *ipmi,
			 ipmi_ll_evt_handler_t handler,
			 void                  *cb_data)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    if (locked_list_remove(lan->event_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

static ipmi_mcid_t invalid_mcid = IPMI_MCID_INVALID;

static void
handle_async_event(ipmi_con_t        *ipmi,
		   const ipmi_addr_t *addr,
		   unsigned int      addr_len,
		   const ipmi_msg_t  *msg)
{
    lan_data_t           *lan = (lan_data_t *) ipmi->con_data;
    ipmi_event_t         *event = NULL;
    ipmi_time_t          timestamp;
    call_event_handler_t info;

    add_stat(ipmi, STAT_ASYNC_EVENTS, 1);

    if (msg) {
	unsigned int type = msg->data[2];
	unsigned int record_id = ipmi_get_uint16(msg->data);

	if (type < 0xe0)
	    timestamp = ipmi_seconds_to_time(ipmi_get_uint32(msg->data+3));
	else
	    timestamp = -1;
	event = ipmi_event_alloc(invalid_mcid,
				 record_id,
				 type,
				 timestamp,
				 msg->data+3, 13);
	if (!event)
	    /* We missed it here, but the SEL fetch should catch it later. */
	    return;
    }

    info.lan = lan;
    info.addr = addr;
    info.addr_len = addr_len;
    info.event = event;
    locked_list_iterate(lan->event_handlers, call_event_handler, &info);

    if (event)
	ipmi_event_free(event);
}

/* Must be called with the message sequence lock held. */
static int
handle_msg_send(lan_timer_info_t      *info,
		int                   addr_num,
		const ipmi_addr_t     *iaddr,
		unsigned int          addr_len,
		const ipmi_msg_t      *msg,
		ipmi_ll_rsp_handler_t rsp_handler,
		ipmi_msgi_t           *rspi,
		int                   side_effects)
{
    ipmi_con_t        *ipmi = info->ipmi;
    lan_data_t        *lan = ipmi->con_data;
    unsigned int      seq;
    struct timeval    timeout;
    int               rv;
    char              addr_data[sizeof(ipmi_addr_t)];
    char              addr_data2[sizeof(ipmi_addr_t)];
    ipmi_addr_t       *addr = (ipmi_addr_t *) addr_data;
    const ipmi_addr_t *orig_addr = NULL;
    unsigned int      orig_addr_len = 0;

    *addr = *iaddr;

    seq = (lan->last_seq + 1) % 64;
    if (seq == 0)
	seq++;
    while (lan->seq_table[seq].inuse) {
	if (seq == lan->last_seq) {
	    /* This cannot really happen if max_outstanding_msg_count <= 63. */
	    ipmi_log(IPMI_LOG_FATAL,
		     "%sipmi_lan.c(handle_msg_send): "
		     "ipmi_lan: Attempted to start too many messages",
		     IPMI_CONN_NAME(ipmi));
	    abort();
	}

	seq = (seq + 1) % 64;
	if (seq == 0)
	    seq++;
    }

    if (DEBUG_MSG) {
	char buf1[32], buf2[32];
	ipmi_log(IPMI_LOG_DEBUG_START, "%soutgoing msg to IPMI addr =",
		 IPMI_CONN_NAME(ipmi));
	dump_hex((unsigned char *) addr, addr_len);
	ipmi_log(IPMI_LOG_DEBUG_CONT,
		 "\n msg  = netfn=%s cmd=%s data_len=%d",
		 ipmi_get_netfn_string(msg->netfn, buf1, 32),
		 ipmi_get_command_string(msg->netfn, msg->cmd, buf2, 32),
		 msg->data_len);
	if (msg->data_len) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data(len=%d.) =\n  ",
		     msg->data_len);
	    dump_hex(msg->data, msg->data_len);
	}
	ipmi_log(IPMI_LOG_DEBUG_END, " ");
    }

    if ((addr->addr_type == IPMI_IPMB_ADDR_TYPE)
	|| (addr->addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE))
    {
	ipmi_ipmb_addr_t *ipmb = (ipmi_ipmb_addr_t *) addr;

	if (ipmb->channel >= MAX_IPMI_USED_CHANNELS) {
	    ipmi->os_hnd->free_timer(ipmi->os_hnd, info->timer);
	    ipmi_mem_free(info);
	    rv = EINVAL;
	    goto out;
	}

	if (ipmb->slave_addr == lan->slave_addr[ipmb->channel]) {
	    ipmi_system_interface_addr_t *si = (void *) addr_data2;
	    /* Most systems don't handle sending to your own slave
               address, so we have to translate here. */

	    si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	    si->channel = IPMI_BMC_CHANNEL;
	    si->lun = ipmb->lun;
	    orig_addr = addr;
	    orig_addr_len = addr_len;
	    addr = (ipmi_addr_t *) si;
	    addr_len = sizeof(*si);
	}
    }

    info->seq = seq;
    lan->seq_table[seq].inuse = 1;
    lan->seq_table[seq].side_effects = side_effects;
    lan->seq_table[seq].addr_num = addr_num;
    lan->seq_table[seq].rsp_handler = rsp_handler;
    lan->seq_table[seq].rsp_item = rspi;
    memcpy(&(lan->seq_table[seq].addr), addr, addr_len);
    lan->seq_table[seq].addr_len = addr_len;
    lan->seq_table[seq].msg = *msg;
    lan->seq_table[seq].msg.data = lan->seq_table[seq].data;
    memcpy(lan->seq_table[seq].data, msg->data, msg->data_len);
    lan->seq_table[seq].timer_info = info;
    if (addr->addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE)
	lan->seq_table[seq].retries_left = 0;
    else
	lan->seq_table[seq].retries_left = LAN_RSP_RETRIES;
    if (orig_addr) {
	lan->seq_table[seq].use_orig_addr = 1;
	memcpy(&(lan->seq_table[seq].orig_addr), orig_addr, orig_addr_len);
	lan->seq_table[seq].orig_addr_len = orig_addr_len;

	/* In case it's a broadcast. */
	lan->seq_table[seq].orig_addr.addr_type = IPMI_IPMB_ADDR_TYPE;
    } else {
	lan->seq_table[seq].use_orig_addr = 0;
    }

    if (!side_effects) {
	timeout.tv_sec = LAN_RSP_TIMEOUT / 1000000;
	timeout.tv_usec = LAN_RSP_TIMEOUT % 1000000;
    } else {
	timeout.tv_sec = LAN_RSP_TIMEOUT_SIDEEFF / 1000000;
	timeout.tv_usec = LAN_RSP_TIMEOUT_SIDEEFF % 1000000;
    }
    lan->seq_table[seq].timer = info->timer;
    rv = ipmi->os_hnd->start_timer(ipmi->os_hnd,
				   lan->seq_table[seq].timer,
				   &timeout,
				   rsp_timeout_handler,
				   info);
    if (rv) {
	lan->seq_table[seq].inuse = 0;
	ipmi->os_hnd->free_timer(ipmi->os_hnd,
				 lan->seq_table[seq].timer);
	lan->seq_table[seq].timer = NULL;
	ipmi_mem_free(info);
	goto out;
    }

    lan->last_seq = seq;

    if (addr_num >= 0) {
	rv = lan_send_addr(lan, addr, addr_len, msg, seq, addr_num, NULL);
	lan->seq_table[seq].last_ip_num = addr_num;
    } else {
	rv = lan_send(lan, addr, addr_len, msg, seq,
		      &(lan->seq_table[seq].last_ip_num),
		      NULL);
    }
    if (rv) {
	int err;

	lan->seq_table[seq].inuse = 0;
	err = ipmi->os_hnd->stop_timer(ipmi->os_hnd,
				       lan->seq_table[seq].timer);
	/* Special handling, if we can't remove the timer, then it
           will time out on us, so we need to not free the command and
           instead let the timeout handle freeing it. */
	if (err) {
	    info->cancelled = 1;
	} else {
	    ipmi->os_hnd->free_timer(ipmi->os_hnd,
				     lan->seq_table[seq].timer);
	    lan->seq_table[seq].timer = NULL;
	    ipmi_mem_free(info);
	}
    }
 out:
    return rv;
}

static void
check_command_queue(ipmi_con_t *ipmi, lan_data_t *lan)
{
    int              rv;
    lan_wait_queue_t *q_item;
    int              started = 0;

    while (!started && (lan->wait_q != NULL)) {
	/* Commands are waiting to be started, remove the queue item
           and start it. */
	q_item = lan->wait_q;
	lan->wait_q = q_item->next;
	if (lan->wait_q == NULL)
	    lan->wait_q_tail = NULL;

	rv = handle_msg_send(q_item->info, -1, &q_item->addr, q_item->addr_len,
			     &(q_item->msg), q_item->rsp_handler,
			     q_item->rsp_item, q_item->side_effects);
	if (rv) {
	    ipmi_unlock(lan->seq_num_lock);

	    /* Send an error response to the user. */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sipmi_lan.c(check_command_queue): "
		     "Command was not able to be sent due to error 0x%x",
		     IPMI_CONN_NAME(ipmi), rv);
	    
	    q_item->msg.netfn |= 1; /* Convert it to a response. */
	    q_item->msg.data[0] = IPMI_UNKNOWN_ERR_CC;
	    q_item->msg.data_len = 1;
	    q_item->info = NULL;
	    ipmi_handle_rsp_item_copyall(ipmi, q_item->rsp_item,
					 &q_item->addr, q_item->addr_len,
					 &q_item->msg, q_item->rsp_handler);
	    ipmi_lock(lan->seq_num_lock);
	} else {
	    /* We successfully sent a message, break out of the loop. */
	    started = 1;
	}
	ipmi_mem_free(q_item);
    }

    if (!started)
	lan->outstanding_msg_count--;
}

/* Per the spec, RMCP and RMCP+ have different allowed sequence number
   ranges, so adjust for this. */
static int
check_session_seq_num(lan_data_t *lan, uint32_t seq,
		      uint32_t *in_seq, uint32_t *map,
		      int gt_allowed, int lt_allowed)
{
    /* Check the sequence number. */
    if ((int) (seq - *in_seq) >= 0 && (int) (seq - *in_seq) <= gt_allowed) {
	/* It's after the current sequence number, but within gt_allowed.
	   We move the sequence number forward. */
	*map <<= seq - *in_seq;
	*map |= 1;
	*in_seq = seq;
    } else if ((int) (*in_seq - seq) >= 0 && (int) (*in_seq - seq) <= lt_allowed) {
	/* It's before the current sequence number, but within lt_allowed. */
	uint32_t bit = 1 << (*in_seq - seq);
	if (*map & bit) {
	    /* We've already received the message, so discard it. */
	    add_stat(lan->ipmi, STAT_DUPLICATES, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "%sDropped message duplicate",
			 IPMI_CONN_NAME(lan->ipmi));
	    return EINVAL;
	}

	*map |= bit;
    } else {
	/* It's outside the current sequence number range, discard
	   the packet. */
	add_stat(lan->ipmi, STAT_SEQ_OUT_OF_RANGE, 1);
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "%sDropped message out of seq range",
		     IPMI_CONN_NAME(lan->ipmi));
	return EINVAL;
    }

    return 0;
}

static int
check_15_session_seq_num(lan_data_t *lan, uint32_t seq,
			 uint32_t *in_seq, uint32_t *map)
{
    return check_session_seq_num(lan, seq, in_seq, map, 8, 8);
}

static int
check_20_session_seq_num(lan_data_t *lan, uint32_t seq,
			 uint32_t *in_seq, uint32_t *map)
{
    return check_session_seq_num(lan, seq, in_seq, map, 15, 16);
}

static void
handle_payload(ipmi_con_t    *ipmi,
	       lan_data_t    *lan,
	       int           addr_num,
	       int           payload_type,
	       unsigned char *tmsg,
	       unsigned int  payload_len)
{
    ipmi_ll_rsp_handler_t handler;
    ipmi_msgi_t           *rspi;
    unsigned char         seq;
    int                   rv;
    int                   (*handle_send_rsp)(ipmi_con_t *con, ipmi_msg_t *msg);

    handle_send_rsp = NULL;

    if (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OPEN_SESSION_RESPONSE) {
	if (payload_len < 1) {
	    add_stat(ipmi, STAT_TOO_SHORT, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "%sPayload length to short",
			 IPMI_CONN_NAME(ipmi));
	    goto out;
	}

	/* We use the message tag field to store the sequence #. */
	seq = tmsg[0] & 0x3f;
    } else if (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OEM_EXPLICIT) {
#if 0
	/* FIXME - add handling of OEM payloads. */
	handle_oem_payload(ipmi, lan, oem_iana, oem_payload_id,
			   tmsg, payload_len);
#else
	goto out;
#endif
    } else if (! payloads[payload_type]) {
	add_stat(ipmi, STAT_INVALID_PAYLOAD, 1);
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "%sUnhandled payload: 0x%x",
		     IPMI_CONN_NAME(ipmi), payload_type);
	goto out;
    } else {
	rv = payloads[payload_type]->get_recv_seq(ipmi, tmsg,
						  payload_len, &seq);
	if (rv == ENOSYS) {
	    payloads[payload_type]->handle_recv_async(ipmi, tmsg, payload_len);
	    goto out;
	} else if (rv) {
	    add_stat(ipmi, STAT_SEQ_ERR, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "%sError getting sequence: 0x%x",
			 IPMI_CONN_NAME(ipmi), rv);
	    goto out;
	}
    }

    ipmi_lock(lan->seq_num_lock);
    if (! lan->seq_table[seq].inuse) {
	add_stat(ipmi, STAT_RSP_NO_CMD, 1);
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "%sDropped message seq not in use: 0x%x",
		     IPMI_CONN_NAME(ipmi), seq);
	goto out_unlock;
    }

    rv = payloads[payload_type]->handle_recv_rsp
	(ipmi,
	 lan->seq_table[seq].rsp_item,
	 &lan->seq_table[seq].addr,
	 lan->seq_table[seq].addr_len,
	 &lan->seq_table[seq].msg,
	 tmsg,
	 payload_len);
    if (rv) {
	if (rv == -1)
	    handle_send_rsp = ipmi->handle_send_rsp_err;
	else
	    goto out_unlock;
    }

    /* We got a response from the connection, so reset the failure
       count. */
    lan->ip[addr_num].consecutive_failures = 0;

    /* The command matches up, cancel the timer and deliver it */
    rv = ipmi->os_hnd->stop_timer(ipmi->os_hnd,
				  lan->seq_table[seq].timer);
    if (rv)
	/* Couldn't cancel the timer, make sure the timer
	   doesn't do the callback. */
	lan->seq_table[seq].timer_info->cancelled = 1;
    else {
	/* Timer is cancelled, free its data. */
	ipmi->os_hnd->free_timer(ipmi->os_hnd,
				 lan->seq_table[seq].timer);
	ipmi_mem_free(lan->seq_table[seq].timer_info);
    }

    handler = lan->seq_table[seq].rsp_handler;
    rspi = lan->seq_table[seq].rsp_item;
    lan->seq_table[seq].inuse = 0;

    if (lan->seq_table[seq].use_orig_addr) {
	/* We did an address translation, so translate back. */
	memcpy(&rspi->addr, &lan->seq_table[seq].orig_addr,
	       lan->seq_table[seq].orig_addr_len);
	rspi->addr_len = lan->seq_table[seq].orig_addr_len;
    }

    check_command_queue(ipmi, lan);
    ipmi_unlock(lan->seq_num_lock);
    
    if (handle_send_rsp)
	handle_send_rsp(ipmi, &rspi->msg);

    ipmi_handle_rsp_item(ipmi, rspi, handler);

 out:
    return;

 out_unlock:
    ipmi_unlock(lan->seq_num_lock);
}

static void
handle_rmcpp_recv(ipmi_con_t    *ipmi,
		  lan_data_t    *lan,
		  int           addr_num,
		  unsigned char *data,
		  unsigned int  len)
{
    unsigned char oem_iana[3] = { 0, 0, 0 };
#if 0
    /* FIXME - add handling of OEM payloads. */
    unsigned int  oem_payload_id = 0;
#endif
    unsigned char *tmsg;
    int           encrypted;
    int           authenticated;
    unsigned int  payload_type;
    uint32_t      session_id;
    uint32_t      session_seq;
    int           rv;
    unsigned int  payload_len;
    unsigned int  header_len;

    if (len < 16) { /* Minimum size of an RMCP+ msg. */
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "%sDropped message because too small(5)",
		     IPMI_CONN_NAME(ipmi));
	goto out;
    }

    encrypted = data[5] & 0x80;
    authenticated = data[5] & 0x40;
    payload_type = data[5] & 0x3f;

    tmsg = data+6;
    if (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OEM_EXPLICIT) {
	if (len < 22) { /* Minimum size of an RMCP+ type 2 msg. */
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "%sDropped message because too small(6)",
			 IPMI_CONN_NAME(ipmi));
	    goto out;
	}
	memcpy(oem_iana, tmsg, 3);
	tmsg += 4;
#if 0
	/* FIXME - add handling of OEM payloads. */
	oem_payload_id = ipmi_get_uint16(tmsg);
#endif
	tmsg += 2;
    }

    session_id = ipmi_get_uint32(tmsg);
    tmsg += 4;
    if (session_id != lan->ip[addr_num].session_id) {
	add_stat(ipmi, STAT_BAD_SESSION_ID, 1);
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "%sDropped message not valid session id (2)",
		     IPMI_CONN_NAME(ipmi));
	goto out;
    }

    session_seq = ipmi_get_uint32(tmsg);
    tmsg += 4;

    payload_len = ipmi_get_uint16(tmsg);
    tmsg += 2;

    header_len = tmsg - data;
    if ((header_len + payload_len) > len) {
	add_stat(ipmi, STAT_BAD_SIZE, 1);
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "%sDropped message payload length doesn't match up",
		     IPMI_CONN_NAME(ipmi));
	goto out;
    }

    /* Authenticate the message before we do anything else. */
    if (authenticated) {
	unsigned int  pad_len;
	unsigned int  integ_len;

	if (lan->ip[addr_num].working_integ
	    == IPMI_LANP_INTEGRITY_ALGORITHM_NONE)
	{
	    add_stat(ipmi, STAT_INVALID_AUTH, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "%sGot authenticated msg but authentication"
			 " not available", IPMI_CONN_NAME(ipmi));
	    goto out;
	}

	/* Increase the length to include the padding; this eases the
	   handling for the payload integrity check. */
	integ_len = header_len + payload_len;
	while ((integ_len < len) && (data[integ_len] == 0xff))
	    integ_len++;
	if (integ_len < len)
	    integ_len++;

	rv = lan->ip[addr_num].integ_info->integ_check
	    (ipmi,
	     lan->ip[addr_num].integ_data,
	     data,
	     integ_len,
	     len);
	if (rv) {
	    add_stat(ipmi, STAT_AUTH_FAIL, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "%sIntegrity failed",
			 IPMI_CONN_NAME(ipmi));
	    goto out;
	}

	/* Remove the integrity padding. */
	pad_len = data[integ_len-1] + 1;
	if ((integ_len - header_len - pad_len) != payload_len) {
	    add_stat(ipmi, STAT_BAD_SIZE, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "%sPadding size not valid: %d",
			 IPMI_CONN_NAME(ipmi), pad_len);
	    goto out;
	}
    }

    /* The packet is good, we can trust the data in it now. */

    /* If it's from a down connection, report it as up. */
    ipmi_lock(lan->ip_lock);
    if (! lan->ip[addr_num].working) {
	ipmi_unlock(lan->ip_lock);
	connection_up(lan, addr_num, 0);
	ipmi_lock(lan->ip_lock);
    }

    if (authenticated)
	rv = check_20_session_seq_num(lan, session_seq,
				      &(lan->ip[addr_num].inbound_seq_num),
				      &(lan->ip[addr_num].recv_msg_map));
    else if (session_id == 0)
	rv = 0; /* seq num not used for out-of-session messages. */
    else
	rv = check_20_session_seq_num(lan, session_seq,
				      &(lan->ip[addr_num].unauth_in_seq_num),
				      &(lan->ip[addr_num].unauth_recv_msg_map));
    ipmi_unlock(lan->ip_lock);
    if (rv) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "%sInvalid sequence number",
		     IPMI_CONN_NAME(ipmi));
	add_stat(ipmi, STAT_SEQ_OUT_OF_RANGE, 1);
	goto out;
    }

    /* Message is in sequence, so it's good to deliver after we
       decrypt it. */

    if (encrypted) {
	if (lan->ip[addr_num].working_conf
	    == IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE)
	{
	    add_stat(ipmi, STAT_INVALID_AUTH, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "%sGot encrypted msg but encryption not available",
			 IPMI_CONN_NAME(ipmi));
	    goto out;
	}

	rv = lan->ip[addr_num].conf_info->conf_decrypt
	    (ipmi, lan->ip[addr_num].conf_data, &tmsg, &payload_len);
	if (rv) {
	    add_stat(ipmi, STAT_DECRYPT_FAIL, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "%sDecryption failed",
			 IPMI_CONN_NAME(ipmi));
	    goto out;
	}
    }

    handle_payload(ipmi, lan, addr_num, payload_type, tmsg, payload_len);
    
 out:
    return;
}

static void
handle_lan15_recv(ipmi_con_t    *ipmi,
		  lan_data_t    *lan,
		  int           addr_num,
		  unsigned char *data,
		  unsigned int  len)
{
    uint32_t      seq, sess_id;
    unsigned char *tmsg = NULL;
    unsigned int  data_len;
    int           rv;

    if ((data[4] & 0x0f) == IPMI_AUTHTYPE_NONE) {
	if (len < 14) { /* Minimum size of an IPMI msg. */
	    add_stat(ipmi, STAT_TOO_SHORT, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "%sDropped message because too small(1)",
			 IPMI_CONN_NAME(ipmi));
	    goto out;
	}

	/* No authentication. */
	if (len < (unsigned int) (data[13] + 14)) {
	    /* Not enough data was supplied, reject the message. */
	    add_stat(ipmi, STAT_TOO_SHORT, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "%sDropped message because too small(2)",
			 IPMI_CONN_NAME(ipmi));
	    goto out;
	}
	data_len = data[13];
    } else {
	if (len < 30) { /* Minimum size of an authenticated IPMI msg. */
	    add_stat(ipmi, STAT_TOO_SHORT, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "%sDropped message because too small(3)",
			 IPMI_CONN_NAME(ipmi));
	    goto out;
	}
	/* authcode in message, add 16 to the above checks. */
	if (len < (unsigned int) (data[29] + 30)) {
	    add_stat(ipmi, STAT_TOO_SHORT, 1);
	    /* Not enough data was supplied, reject the message. */
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "%sDropped message because too small(4)",
			 IPMI_CONN_NAME(ipmi));
	    goto out;
	}
	data_len = data[29];
    }

    /* FIXME - need a lock on the session data. */

    /* Drop if the authtypes are incompatible. */
    if (lan->ip[addr_num].working_authtype != (data[4] & 0x0f)) {
	add_stat(ipmi, STAT_INVALID_AUTH, 1);
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "%sDropped message not valid authtype,"
		     " expected %d, got %d",
		     IPMI_CONN_NAME(ipmi),
		     lan->ip[addr_num].working_authtype,
		     data[4] & 0x0f);
	goto out;
    }

    /* Drop if sessions ID's don't match. */
    sess_id = ipmi_get_uint32(data+9);
    if (sess_id != lan->ip[addr_num].session_id) {
	add_stat(ipmi, STAT_BAD_SESSION_ID, 1);
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "%sDropped message not valid session id",
		     IPMI_CONN_NAME(ipmi));
	goto out;
    }

    seq = ipmi_get_uint32(data+5);

    if ((data[4] & 0x0f) != 0) {
	/* Validate the message's authcode.  Do this before checking
           the session seq num so we know the data is valid. */
	rv = auth_check(lan, data+9, data+5, data+30, data[29], data+13,
			addr_num);
	if (rv) {
	    add_stat(ipmi, STAT_AUTH_FAIL, 1);
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "%sDropped message auth fail",
			 IPMI_CONN_NAME(ipmi));
	    goto out;
	}
	tmsg = data + 30;
    } else {
	tmsg = data + 14;
    }

    /* If it's from a down connection, report it as up. */
    ipmi_lock(lan->ip_lock);
    if (! lan->ip[addr_num].working) {
	ipmi_unlock(lan->ip_lock);
	connection_up(lan, addr_num, 0);
	ipmi_lock(lan->ip_lock);
    }

    rv = check_15_session_seq_num(lan, seq,
				  &(lan->ip[addr_num].inbound_seq_num),
				  &(lan->ip[addr_num].recv_msg_map));
    ipmi_unlock(lan->ip_lock);
    if (rv)
	goto out;

    /*
     * Special case for Serial-over-LAN IPMI 1.5 packets, which use the
     * "reserved" nybble to identify the SoL payload.
     */
    if ((data[4] & 0xf0) == 0x80)
	    handle_payload(ipmi, lan, addr_num,
			   IPMI_RMCPP_PAYLOAD_TYPE_SOL, tmsg, data_len);
    else
	    handle_payload(ipmi, lan, addr_num,
			   IPMI_RMCPP_PAYLOAD_TYPE_IPMI, tmsg, data_len);

 out:
    return;
}

static int
addr_match_lan(lan_data_t *lan, uint32_t sid, sockaddr_ip_t *addr,
	       int *raddr_num)
{
    unsigned int addr_num;

    /* Make sure the source address matches one we expect from
       this system. */
    for (addr_num = 0; addr_num < lan->cparm.num_ip_addr; addr_num++) {
	if ((!sid || (lan->ip[addr_num].session_id == sid))
	    && lan_addr_same(&(lan->cparm.ip_addr[addr_num]), addr))
	{
	    *raddr_num = addr_num;
	    return 1;
	}
    }
    return 0;
}

static ipmi_con_t *
rmcpp_find_ipmi(lan_fd_t      *item,
		unsigned char *data,
		unsigned int  len,
		sockaddr_ip_t *addr,
		int           *addr_num)
{
    /* This is easy, the session id is our slot in the fd or is a
       message tag. */
    unsigned char payload;
    uint32_t      tag;
    uint32_t      sid;
    unsigned char ctag;
    unsigned int  mlen;
    unsigned char *d;
    ipmi_con_t    *ipmi = NULL;
    lan_data_t    *lan;

    /* We need to find the sessions id; it's position depends on
       the payload type. */
    if (len < 16) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Message too short(2): %d", len);
	return NULL;
    }
    payload = data[5] & 0x3f;
    if (payload == IPMI_RMCPP_PAYLOAD_TYPE_OEM_EXPLICIT) {
	if (len < 22) {
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "Message too short(3): %d", len);
	    return NULL;
	}
	d = data+12;
    } else {
	d = data+6;
    }

    mlen = ipmi_get_uint16(d+8);
    if ((mlen + 10 + (d-data)) > len) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "Dropped message payload length doesn't match up");
	return NULL;
    }

    sid = ipmi_get_uint32(d);
    if ((sid == 0) && payloads[payload]->get_msg_tag) {
	int rv = payloads[payload]->get_msg_tag(d+10, mlen, &ctag);
	if (rv) {
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "Error getting message tag: %d", rv);
	    return NULL;
	}
	tag = ctag;
    } else
	tag = sid - 1;

    if (tag >= MAX_CONS_PER_FD) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "tag is out of range: %d", tag);
	return NULL;
    }

    ipmi_lock(item->con_lock);
    lan = item->lan[tag];
    if (lan && addr_match_lan(lan, sid, addr, addr_num))
	ipmi = lan->ipmi;
    else if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	ipmi_log(IPMI_LOG_DEBUG, "tag doesn't match: %d", tag);
    ipmi_unlock(item->con_lock);

    return ipmi;
}

static ipmi_con_t *
rmcp_find_ipmi(lan_fd_t      *item,
	       unsigned char *data,
	       unsigned int  len,
	       sockaddr_ip_t *addr,
	       int           *addr_num)
{
    /* Old RMCP is harder, we have to hunt. */
    uint32_t   sid;
    lan_data_t *lan;
    int        i;
    ipmi_con_t *ipmi = NULL;

    if (len < 13) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Message too short(4): %d", len);
	return NULL;
    }

    sid = ipmi_get_uint32(data+9);
    ipmi_lock(item->con_lock);
    for (i=0; i<MAX_CONS_PER_FD; i++) {
	lan = item->lan[i];
	if (lan && addr_match_lan(lan, sid, addr, addr_num)) {
	    ipmi = lan->ipmi;
	    break;
	}
    }
    ipmi_unlock(item->con_lock);

    return ipmi;
}

static void
data_handler(int            fd,
	     void           *cb_data,
	     os_hnd_fd_id_t *id)
{
    lan_fd_t           *item = cb_data;
    ipmi_con_t         *ipmi;
    lan_data_t         *lan;
    unsigned char      data[IPMI_MAX_LAN_LEN];
    sockaddr_ip_t      ipaddrd;
    socklen_t          from_len;
    int                len;
    int                addr_num = 0; /* Keep gcc happy and initialize */

    from_len = sizeof(ipaddrd.s_ipsock);
    len = recvfrom(fd, data, sizeof(data), 0, (struct sockaddr *)&ipaddrd, 
		   &from_len);

    if (len < 0)
	/* Got an error, probably no data, just return. */
	return;

    ipaddrd.ip_addr_len = from_len;
    if (DEBUG_RAWMSG) {
	ipmi_log(IPMI_LOG_DEBUG_START, "incoming\n addr = ");
	dump_hex((unsigned char *) &ipaddrd, from_len);
	if (len) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =\n  ");
	    dump_hex(data, len);
	}
	ipmi_log(IPMI_LOG_DEBUG_END, " ");
    }

    if (len < 5) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Message too short(1): %d", len);
	return;
    }

    /* Validate the RMCP portion of the message. */
    if ((data[0] != 6)
	|| (data[2] != 0xff)
	|| (data[3] != 0x07))
    {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Dropped message not valid IPMI/RMCP");
	return;
    }

    if ((data[4] & 0x0f) == IPMI_AUTHTYPE_RMCP_PLUS) {
	ipmi = rmcpp_find_ipmi(item, data, len, &ipaddrd, &addr_num);
    } else {
	ipmi = rmcp_find_ipmi(item, data, len, &ipaddrd, &addr_num);
    }

    if (!lan_valid_ipmi(ipmi))
	/* This can fail due to a race condition, just return and
           everything should be fine. */
	return;

    lan = ipmi->con_data;

    add_stat(ipmi, STAT_RECV_PACKETS, 1);

    if ((data[4] & 0x0f) == IPMI_AUTHTYPE_RMCP_PLUS) {
	handle_rmcpp_recv(ipmi, lan, addr_num, data, len);
    } else {
	handle_lan15_recv(ipmi, lan, addr_num, data, len);
    }
    
    lan_put(ipmi);
    return;
}

/* Note that this puts the address number in data4 of the rspi. */
int
ipmi_lan_send_command_forceip(ipmi_con_t            *ipmi,
			      int                   addr_num,
			      ipmi_addr_t           *addr,
			      unsigned int          addr_len,
			      ipmi_msg_t            *msg,
			      ipmi_ll_rsp_handler_t rsp_handler,
			      ipmi_msgi_t           *rspi)
{
    lan_timer_info_t *info;
    lan_data_t       *lan;
    int              rv;
    /* We store the address number in data4. */

    if (addr_num >= MAX_IP_ADDR)
	return EINVAL;

    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    if (msg->data_len > IPMI_MAX_MSG_LENGTH)
	return EINVAL;

    lan = (lan_data_t *) ipmi->con_data;

    if (lan->in_cleanup)
	return ECANCELED;

    /* Odd netfns are responses or unacknowledged data.  Just send
       them. */
    if (msg->netfn & 1)
	return lan_send_addr(lan, addr, addr_len, msg, 0, addr_num, NULL);

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));

    /* Put it in the list first. */
    info->ipmi = ipmi;
    info->cancelled = 0;

    rv = ipmi->os_hnd->alloc_timer(ipmi->os_hnd, &(info->timer));
    if (rv) {
	ipmi_mem_free(info);
	return rv;
    }

    ipmi_lock(lan->seq_num_lock);

    if (lan->outstanding_msg_count >= 60) {
	rv = EAGAIN;
	goto out_unlock;
    }

    rspi->data4 = (void *) (long) addr_num;
    rv = handle_msg_send(info, addr_num, addr, addr_len, msg,
			 rsp_handler, rspi, 0);
    /* handle_msg_send handles freeing the timer and info on an error */
    info = NULL;
    if (! rv)
	lan->outstanding_msg_count++;
    ipmi_unlock(lan->seq_num_lock);
    return rv;

 out_unlock:
    ipmi_unlock(lan->seq_num_lock);
    if (rv) {
	if (info) {
	    if (info->timer)
		ipmi->os_hnd->free_timer(ipmi->os_hnd, info->timer);
	    ipmi_mem_free(info);
	}
    }
    return rv;
}

static int
lan_send_command_option(ipmi_con_t              *ipmi,
			const ipmi_addr_t       *addr,
			unsigned int            addr_len,
			const ipmi_msg_t        *msg,
			const ipmi_con_option_t *options,
			ipmi_ll_rsp_handler_t   rsp_handler,
			ipmi_msgi_t             *trspi)
{
    lan_timer_info_t *info;
    lan_data_t       *lan;
    int              rv;
    ipmi_msgi_t      *rspi = trspi;
    int              side_effects = 0;
    int              i;


    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    if (msg->data_len > IPMI_MAX_MSG_LENGTH)
	return EINVAL;

    lan = (lan_data_t *) ipmi->con_data;

    /* Odd netfns are responses or unacknowledged data.  Just send
       them. */
    if (msg->netfn & 1) {
	int dummy_send_ip;
	return lan_send(lan, addr, addr_len, msg, 0, &dummy_send_ip, options);
    }

    if (options) {
	for (i=0; options[i].option != IPMI_CON_OPTION_LIST_END; i++) {
	    if (options[i].option == IPMI_CON_MSG_OPTION_SIDE_EFFECTS)
		side_effects = options[i].ival;
	}
    }

    if (!rspi) {
	rspi = ipmi_mem_alloc(sizeof(*rspi));
	if (!rspi)
	    return ENOMEM;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	rv = ENOMEM;
	goto out_unlock2;
    }
    memset(info, 0, sizeof(*info));

    /* Put it in the list first. */
    info->ipmi = ipmi;
    info->cancelled = 0;

    rv = ipmi->os_hnd->alloc_timer(ipmi->os_hnd, &(info->timer));
    if (rv)
	goto out_unlock;

    ipmi_lock(lan->seq_num_lock);

    if (lan->outstanding_msg_count >= lan->max_outstanding_msg_count) {
	lan_wait_queue_t *q_item;

	q_item = ipmi_mem_alloc(sizeof(*q_item));
	if (!q_item) {
	    ipmi->os_hnd->free_timer(ipmi->os_hnd, info->timer);
	    rv = ENOMEM;
	    goto out_unlock;
	}

	q_item->info = info;
	memcpy(&(q_item->addr), addr, addr_len);
	q_item->addr_len = addr_len;
	memcpy(&q_item->msg, msg, sizeof(q_item->msg));
	q_item->msg.data = q_item->data;
	memcpy(q_item->data, msg->data, msg->data_len);
	q_item->rsp_handler = rsp_handler;
	q_item->rsp_item = rspi;
	q_item->side_effects = side_effects;

	/* Add it to the end of the queue. */
	q_item->next = NULL;
	if (lan->wait_q_tail == NULL) {
	    lan->wait_q_tail = q_item;
	    lan->wait_q = q_item;
	} else {
	    lan->wait_q_tail->next = q_item;
	    lan->wait_q_tail = q_item;
	}
	goto out_unlock;
    }

    rv = handle_msg_send(info, -1, addr, addr_len, msg,
			 rsp_handler, rspi, side_effects);
    /* handle_msg_send handles freeing the timer and info on an error */
    info = NULL;
    if (!rv)
	lan->outstanding_msg_count++;
    else if (!trspi && rspi)
	/* If we allocated an rspi, free it on error. */
	ipmi_mem_free(rspi);
    ipmi_unlock(lan->seq_num_lock);
    return rv;

 out_unlock:
    ipmi_unlock(lan->seq_num_lock);
    if (rv) {
	if (info) {
	    if (info->timer)
		ipmi->os_hnd->free_timer(ipmi->os_hnd, info->timer);
	    ipmi_mem_free(info);
	}
    }
 out_unlock2:
    if (rv) {
	/* If we allocated an rspi, free it. */
	if (!trspi && rspi)
	    ipmi_mem_free(rspi);
    }
    return rv;
}

static int
lan_send_command(ipmi_con_t            *ipmi,
		 const ipmi_addr_t     *addr,
		 unsigned int          addr_len,
		 const ipmi_msg_t      *msg,
		 ipmi_ll_rsp_handler_t rsp_handler,
		 ipmi_msgi_t           *trspi)
{
    return lan_send_command_option(ipmi, addr, addr_len, msg, NULL,
				   rsp_handler, trspi);
}

static int
lan_send_response(ipmi_con_t        *ipmi,
		  const ipmi_addr_t *addr,
		  unsigned int      addr_len,
		  const ipmi_msg_t  *msg,
		  long              sequence)
{
    return ENOSYS;
}

static int
lan_register_for_command(ipmi_con_t            *ipmi,
			 unsigned char         netfn,
			 unsigned char         cmd,
			 ipmi_ll_cmd_handler_t handler,
			 void                  *cmd_data,
			 void                  *data2,
			 void                  *data3)
{
    return ENOSYS;
}

static int
lan_deregister_for_command(ipmi_con_t    *ipmi,
			   unsigned char netfn,
			   unsigned char cmd)
{
    return ENOSYS;
}

static unsigned int
lan_get_num_ports(ipmi_con_t *ipmi)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    return lan->cparm.num_ip_addr;
}

static int
lan_get_port_info(ipmi_con_t *ipmi, unsigned int port,
		  char *info, int *info_len)
{
    lan_data_t    *lan = (lan_data_t *) ipmi->con_data;
    sockaddr_ip_t *a;
    int           count = 0;
    int           len = *info_len;

    if (port > lan->cparm.num_ip_addr)
	return EINVAL;

    a = &(lan->cparm.ip_addr[port]);

    if (lan->ip[port].working_authtype == IPMI_AUTHTYPE_RMCP_PLUS)
	count = snprintf(info, len, "rmcp+: ");
    else
	count = snprintf(info, len, "rmcp: ");
    
    switch (a->s_ipsock.s_addr.sa_family) {
    case PF_INET:
	{
	    struct sockaddr_in *ip = &a->s_ipsock.s_addr4;
	    char buf[INET_ADDRSTRLEN];

	    inet_ntop(AF_INET, &ip->sin_addr, buf, sizeof(buf));
	    count += snprintf(info+count, len-count, "inet:%s:%d",
			      buf, ntohs(ip->sin_port));
	}
	break;

#ifdef PF_INET6
    case PF_INET6:
	{
	    struct sockaddr_in6 *ip = &a->s_ipsock.s_addr6;
	    char buf[INET6_ADDRSTRLEN];

	    inet_ntop(AF_INET6, &ip->sin6_addr, buf, sizeof(buf));
	    count += snprintf(info+count, len-count, "inet6:%s:%d",
			      buf, ntohs(ip->sin6_port));
	}
	break;
#endif
    default:
	count += snprintf(info+count, len-count, "invalid");
	break;
    }

    *info_len = count;
    return 0;
}

static void *
auth_alloc(void *info, int size)
{
    return ipmi_mem_alloc(size);
}

static void
auth_free(void *info, void *data)
{
    ipmi_mem_free(data);
}

/* Send the final close session to shut the connection down. */
static void
send_close_session(ipmi_con_t *ipmi, lan_data_t *lan, int addr_num)
{
    ipmi_msg_t                   msg;
    unsigned char                data[4];
    ipmi_system_interface_addr_t si;

    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_CLOSE_SESSION_CMD;
    msg.data_len = 4;
    msg.data = data;
    if (lan->ip[addr_num].working_authtype == IPMI_AUTHTYPE_RMCP_PLUS)
	ipmi_set_uint32(data, lan->ip[addr_num].mgsys_session_id);
    else
	ipmi_set_uint32(data, lan->ip[addr_num].session_id);
    lan_send_addr(lan, (ipmi_addr_t *) &si, sizeof(si), &msg, 0, addr_num,
		  NULL);
}

typedef struct lan_unreg_stat_info_s
{
    lan_data_t          *lan;
    ipmi_ll_stat_info_t *cmpinfo;
    int                 found;
} lan_unreg_stat_info_t;

static int
lan_unreg_stat_info(void *cb_data, void *item1, void *item2)
{
    ipmi_ll_stat_info_t   *info = item2;
    lan_stat_info_t       *stat = item1;
    lan_unreg_stat_info_t *sinfo = cb_data;
    int                   i;

    if (!sinfo->cmpinfo || (sinfo->cmpinfo == info)) {
	locked_list_remove(sinfo->lan->lan_stat_list, stat, info);
	for (i=0; i<NUM_STATS; i++)
	    if (stat->stats[i]) {
		ipmi_ll_con_stat_call_unregister(info, stat->stats[i]);
		stat->stats[i] = NULL;
	    }
	ipmi_mem_free(stat);
	sinfo->found = 1;
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
cleanup_con(ipmi_con_t *ipmi)
{
    lan_data_t   *lan = NULL;
    unsigned int i;

    if (ipmi) {
	lan = (lan_data_t *) ipmi->con_data;
	ipmi_con_attr_cleanup(ipmi);
	if (ipmi->name) {
	    ipmi_mem_free(ipmi->name);
	    ipmi->name = NULL;
	}
	ipmi_mem_free(ipmi);
    }

    if (lan) {
	/* This is only called in the case of an error at startup, so
	   there is no need to remove it from the LAN lists (hashes),
	   because it won't be there yet. */

	for (i=0; i<lan->cparm.num_ip_addr; i++) {
	    if (lan->cparm.ip_addr_str[i])
		ipmi_mem_free(lan->cparm.ip_addr_str[i]);
	    if (lan->cparm.ip_port_str[i])
		ipmi_mem_free(lan->cparm.ip_port_str[i]);
	}

	if (lan->lan_stat_list) {
	    lan_unreg_stat_info_t sinfo;
	    sinfo.lan = lan;
	    sinfo.cmpinfo = NULL;
	    sinfo.found = 0;
	    locked_list_iterate(lan->lan_stat_list, lan_unreg_stat_info,
				&sinfo);
	    locked_list_destroy(lan->lan_stat_list);
	}
	if (lan->con_change_lock)
	    ipmi_destroy_lock(lan->con_change_lock);
	if (lan->ip_lock)
	    ipmi_destroy_lock(lan->ip_lock);
	if (lan->con_change_handlers)
	    locked_list_destroy(lan->con_change_handlers);
	if (lan->event_handlers)
	    locked_list_destroy(lan->event_handlers);
	if (lan->ipmb_change_handlers)
	    locked_list_destroy(lan->ipmb_change_handlers);
	if (lan->seq_num_lock)
	    ipmi_destroy_lock(lan->seq_num_lock);
	if (lan->fd)
	    release_lan_fd(lan->fd, lan->fd_slot);
	if (lan->authdata)
	    ipmi_auths[lan->chosen_authtype].authcode_cleanup(lan->authdata);
	for (i=0; i<MAX_IP_ADDR; i++) {
	    if (lan->ip[i].conf_data)
		lan->ip[i].conf_info->conf_free(ipmi, lan->ip[i].conf_data);
	    if (lan->ip[i].integ_data)
		lan->ip[i].integ_info->integ_free(ipmi, lan->ip[i].integ_data);
	}
	/* paranoia */
	memset(lan->cparm.password, 0, sizeof(lan->cparm.password));
	memset(lan->cparm.bmc_key, 0, sizeof(lan->cparm.bmc_key));
	ipmi_mem_free(lan);
    }
}

static void
lan_cleanup(ipmi_con_t *ipmi)
{
    lan_data_t   *lan = ipmi->con_data;
    int          rv;
    unsigned int i;

    /* After this point no other operations can occur on this ipmi
       interface, so it's safe. */

    for (i=0; i<lan->cparm.num_ip_addr; i++)
	send_close_session(ipmi, lan, i);

    lan->in_cleanup = 1;

    ipmi_lock(lan->seq_num_lock);
    for (i=0; i<64; i++) {
	if (lan->seq_table[i].inuse) {
	    ipmi_ll_rsp_handler_t handler;
	    ipmi_msgi_t           *rspi;
	    lan_timer_info_t      *info;

	    rv = ipmi->os_hnd->stop_timer(ipmi->os_hnd,
					  lan->seq_table[i].timer);

	    rspi = lan->seq_table[i].rsp_item;

	    if (lan->seq_table[i].use_orig_addr) {
		/* We did an address translation, so translate back. */
		memcpy(&rspi->addr, &lan->seq_table[i].orig_addr,
		       lan->seq_table[i].orig_addr_len);
		rspi->addr_len = lan->seq_table[i].orig_addr_len;
	    } else {
		memcpy(&rspi->addr, &(lan->seq_table[i].addr),
		       lan->seq_table[i].addr_len);
		rspi->addr_len = lan->seq_table[i].addr_len;
	    }
	    handler = lan->seq_table[i].rsp_handler;
	    info = lan->seq_table[i].timer_info;

	    rspi->msg.netfn = lan->seq_table[i].msg.netfn | 1;
	    rspi->msg.cmd = lan->seq_table[i].msg.cmd;
	    rspi->msg.data = rspi->data;
	    rspi->data[0] = IPMI_UNKNOWN_ERR_CC;
	    rspi->msg.data_len = 1;

	    lan->seq_table[i].inuse = 0;

	    /* Wait until here to free the info, as we use it above.
	       But we must be holding the lock while we do this. */
	    if (rv)
		info->cancelled = 1;
	    else {
		ipmi->os_hnd->free_timer(ipmi->os_hnd, info->timer);
		ipmi_mem_free(info);
	    }

	    ipmi_unlock(lan->seq_num_lock);

	    /* The unlock is safe here because the connection is no
               longer valid and thus nothing else can really happen on
               this connection.  Sends will fail and receives will not
               validate. */
	    
	    ipmi_handle_rsp_item(NULL, rspi, handler);

	    ipmi_lock(lan->seq_num_lock);
	}
    }
    while (lan->wait_q != NULL) {
	lan_wait_queue_t *q_item;

	q_item = lan->wait_q;
	lan->wait_q = q_item->next;

	ipmi->os_hnd->free_timer(ipmi->os_hnd, q_item->info->timer);

	ipmi_unlock(lan->seq_num_lock);

	q_item->msg.netfn |= 1; /* Convert it to a response. */
	q_item->msg.data[0] = IPMI_UNKNOWN_ERR_CC;
	q_item->msg.data_len = 1;
	ipmi_handle_rsp_item_copyall(ipmi, q_item->rsp_item,
				     &q_item->addr, q_item->addr_len,
				     &q_item->msg, q_item->rsp_handler);

	ipmi_lock(lan->seq_num_lock);

	ipmi_mem_free(q_item->info);
	ipmi_mem_free(q_item);
    }
    if (lan->audit_info) {
	rv = ipmi->os_hnd->stop_timer(ipmi->os_hnd, lan->audit_timer);
	if (rv)
	    lan->audit_info->cancelled = 1;
	else {
	    ipmi->os_hnd->free_timer(ipmi->os_hnd, lan->audit_timer);
	    ipmi_mem_free(lan->audit_info);
	}
    }
    ipmi_unlock(lan->seq_num_lock);

    if (lan->close_done)
	lan->close_done(ipmi, lan->close_cb_data);

    if (ipmi->oem_data_cleanup)
	ipmi->oem_data_cleanup(ipmi);

    cleanup_con(ipmi);
}

static int
lan_close_connection_done(ipmi_con_t            *ipmi,
			  ipmi_ll_con_closed_cb handler,
			  void                  *cb_data)
{
    lan_data_t *lan;

    if (! lan_valid_ipmi(ipmi))
	return EINVAL;

    lan = (lan_data_t *) ipmi->con_data;

    ipmi_lock(lan_list_lock);
    if (lan->users > 1) {
	/* The connection has been reused, just report it going
	   down. */
	lan->users--;
	ipmi_unlock(lan_list_lock);
	if (handler)
	    handler(ipmi, cb_data);
	lan_put(ipmi);
	return 0;
    }

    /* Once we begin the shutdown process, we don't want anyone else
       reusing the connection. */
    lan_remove_con_nolock(lan);
    ipmi_unlock(lan_list_lock);

    lan->close_done = handler;
    lan->close_cb_data = cb_data;

    /* Put it once for the lan_valid_ipmi() call, then once to
       actually destroy it. */
    lan_put(ipmi);
    lan_put(ipmi);
    return 0;
}

static int
lan_close_connection(ipmi_con_t *ipmi)
{
    return lan_close_connection_done(ipmi, NULL, NULL);
}

static void
handle_connected(ipmi_con_t *ipmi, int err, int addr_num)
{
    lan_data_t *lan;

    if (!ipmi)
	return;

    lan = (lan_data_t *) ipmi->con_data;

    /* This should be occurring single-threaded (the IP is down and is
       being brought back up or is initially coming up), so no need
       for a lock here. */

    /* Make sure session data is reset on an error. */
    if (err)
	reset_session_data(lan, addr_num);

    ipmi_lock(lan->ip_lock);
    ipmi_lock(lan->con_change_lock);
    ipmi_unlock(lan->ip_lock);
    call_con_change_handlers(lan, err, addr_num, lan->connected);
    ipmi_unlock(lan->con_change_lock);
}

static void
finish_connection(ipmi_con_t *ipmi, lan_data_t *lan, int addr_num)
{
    lan->connected = 1;
    connection_up(lan, addr_num, 1);
    if (! lan->initialized) {
	lan->initialized = 1;
	handle_connected(ipmi, 0, addr_num);
    }
}

static void
lan_set_ipmb_addr(ipmi_con_t    *ipmi,
		  const unsigned char ipmb_addr[],
		  unsigned int  num_ipmb_addr,
		  int           active,
		  unsigned int  hacks)
{
    lan_data_t   *lan = (lan_data_t *) ipmi->con_data;
    int          changed = 0;
    unsigned int i;

    for (i=0; i<num_ipmb_addr && i<MAX_IPMI_USED_CHANNELS; i++) {
	if (! ipmb_addr[i])
	    continue;
	if (lan->slave_addr[i] != ipmb_addr[i]) {
	    lan->slave_addr[i] = ipmb_addr[i];
	    ipmi->ipmb_addr[i] = ipmb_addr[i];
	    changed = 1;
	}
    }

    if (changed || (lan->is_active != active))  {
	lan->is_active = active;
	ipmi->hacks = hacks;
	call_ipmb_change_handlers(lan, 0, ipmb_addr, num_ipmb_addr,
				  active, hacks);
    }
}

static void
handle_ipmb_addr(ipmi_con_t   *ipmi,
		 int          err,
		 const unsigned char ipmb_addr[],
		 unsigned int  num_ipmb_addr,
		 int          active,
		 unsigned int hacks,
		 void         *cb_data)
{
    lan_data_t   *lan;
    unsigned int addr_num = (unsigned long) cb_data;
    unsigned int i;

    if (err) {
	handle_connected(ipmi, err, addr_num);
	return;
    }

    if (!ipmi) {
	handle_connected(ipmi, ECANCELED, addr_num);
	return;
    }

    lan = (lan_data_t *) ipmi->con_data;

    for (i=0; i<num_ipmb_addr && i<MAX_IPMI_USED_CHANNELS; i++) {
	if (! ipmb_addr[i])
	    continue;
	lan->slave_addr[i] = ipmb_addr[i];
	ipmi->ipmb_addr[i] = ipmb_addr[i];
    }

    lan->is_active = active;
    ipmi->hacks = hacks;
    finish_connection(ipmi, lan, addr_num);
    call_ipmb_change_handlers(lan, err, ipmb_addr, num_ipmb_addr,
			      active, hacks);
}

static int
handle_dev_id(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t   *msg = &rspi->msg;
    lan_data_t   *lan = NULL;
    int          err;
    unsigned int manufacturer_id;
    unsigned int product_id;
    int          addr_num = (long) rspi->data4;

    if (!ipmi) {
	err = ECANCELED;
	goto out_err;
    }

    lan = (lan_data_t *) ipmi->con_data;

    if (msg->data[0] != 0) {
	err = IPMI_IPMI_ERR_VAL(msg->data[0]);
	goto out_err;
    }

    if (msg->data_len < 12) {
	err = EINVAL;
	goto out_err;
    }

    manufacturer_id = (msg->data[7]
		       | (msg->data[8] << 8)
		       | (msg->data[9] << 16));
    product_id = msg->data[10] | (msg->data[11] << 8);

    if (!lan->oem_conn_handlers_called) {
	lan->oem_conn_handlers_called = 1;
	err = ipmi_check_oem_conn_handlers(ipmi, manufacturer_id, product_id);
	if (err)
	    goto out_err;

	if (ipmi->get_ipmb_addr) {
	    /* We have a way to fetch the IPMB address, do so. */
	    err = ipmi->get_ipmb_addr(ipmi, handle_ipmb_addr,
				      (void *) (long) addr_num);
	    if (err)
		goto out_err;
	} else
	    finish_connection(ipmi, lan, addr_num);
    } else {
	finish_connection(ipmi, lan, addr_num);
    }
    return IPMI_MSG_ITEM_NOT_USED;

 out_err:
    handle_connected(ipmi, err, addr_num);
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
send_get_dev_id(ipmi_con_t *ipmi, lan_data_t *lan, int addr_num,
		ipmi_msgi_t *rspi)
{
    ipmi_msg_t			 msg;
    int				 rv;
    ipmi_system_interface_addr_t addr;

    addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    addr.channel = 0xf;
    addr.lun = 0;

    msg.cmd = IPMI_GET_DEVICE_ID_CMD;
    msg.netfn = IPMI_APP_NETFN;
    msg.data = NULL;
    msg.data_len = 0;

    rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
				       (ipmi_addr_t *) &addr, sizeof(addr),
				       &msg, handle_dev_id, rspi);
    return rv;
}

static void
lan_oem_done(ipmi_con_t *ipmi, void *cb_data)
{
    lan_data_t  *lan;
    int         rv;
    ipmi_msgi_t *rspi = cb_data;
    int         addr_num = (long) rspi->data4;

    if (! ipmi) {
	ipmi_mem_free(rspi);
	return;
    }

    lan = (lan_data_t *) ipmi->con_data;
    rv = send_get_dev_id(ipmi, lan, addr_num, rspi);
    if (rv) {
        handle_connected(ipmi, rv, addr_num);
	ipmi_mem_free(rspi);
    }
}

static int
session_privilege_set(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t *msg = &rspi->msg;
    lan_data_t *lan;
    int        rv;
    int        addr_num = (long) rspi->data4;

    if (!ipmi) {
	handle_connected(ipmi, ECANCELED, addr_num);
	goto out;
    }

    lan = (lan_data_t *) ipmi->con_data;

    if (msg->data[0] != 0) {
        handle_connected(ipmi, IPMI_IPMI_ERR_VAL(msg->data[0]), addr_num);
	goto out;
    }

    if (msg->data_len < 2) {
        handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    if (lan->cparm.privilege != (unsigned int) (msg->data[1] & 0xf)) {
	/* Requested privilege level did not match. */
        handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    rv = ipmi_conn_check_oem_handlers(ipmi, lan_oem_done, rspi);
    if (rv) {
        handle_connected(ipmi, rv, addr_num);
	goto out;
    }

    return IPMI_MSG_ITEM_USED;

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
send_set_session_privilege(ipmi_con_t *ipmi, lan_data_t *lan, int addr_num,
			   ipmi_msgi_t *rspi)
{
    unsigned char		 data[1];
    ipmi_msg_t			 msg;
    int				 rv;
    ipmi_system_interface_addr_t addr;

    addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    addr.channel = 0xf;
    addr.lun = 0;

    data[0] = lan->cparm.privilege;

    msg.cmd = IPMI_SET_SESSION_PRIVILEGE_CMD;
    msg.netfn = IPMI_APP_NETFN;
    msg.data = data;
    msg.data_len = 1;

    rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
				       (ipmi_addr_t *) &addr, sizeof(addr),
				       &msg, session_privilege_set, rspi);
    return rv;
}

static int
check_rakp_rsp(ipmi_con_t   *ipmi,
	       ipmi_msg_t   *msg,
	       char         *caller,
	       unsigned int min_length,
	       int          addr_num)
{
    if (!ipmi) {
	handle_connected(ipmi, ECANCELED, addr_num);
	return ECANCELED;
    }

    if (msg->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(%s): Message data too short: %d",
		 IPMI_CONN_NAME(ipmi), caller, msg->data_len);
	handle_connected(ipmi, EINVAL, addr_num);
	return EINVAL;
    }

    if (msg->data[1]) {
	/* Got an RMCP+ error. */
	handle_connected(ipmi, IPMI_RMCPP_ERR_VAL(msg->data[1]), addr_num);
	return EINVAL;
    }

    if (msg->data_len < min_length) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(%s): Message data too short: %d",
		 IPMI_CONN_NAME(ipmi), caller, msg->data_len);
	handle_connected(ipmi, EINVAL, addr_num);
	return EINVAL;
    }

    return 0;
}

typedef struct auth_info_s
{
    ipmi_msgi_t *rspi;
    lan_data_t  *lan;
} auth_info_t;

static void
rmcpp_auth_finished(ipmi_con_t    *ipmi,
		    int           err,
		    int           addr_num,
		    void          *cb_data)
{
    auth_info_t *info = cb_data;
    lan_data_t  *lan = info->lan;
    int         rv = EINVAL;

    if (!ipmi) {
	handle_connected(lan->ipmi, ECANCELED, addr_num);
	goto out;
    }

    if (err) {
	handle_connected(lan->ipmi, err, addr_num);
	goto out;
    }

    lan->ip[addr_num].session_id = lan->ip[addr_num].precon_session_id;
    lan->ip[addr_num].mgsys_session_id
	= lan->ip[addr_num].precon_mgsys_session_id;
    lan->ip[addr_num].inbound_seq_num = 1;
    lan->ip[addr_num].outbound_seq_num = 1;
    lan->ip[addr_num].unauth_in_seq_num = 1;
    lan->ip[addr_num].unauth_out_seq_num = 1;

    /* We're up!.  Start the session stuff. */
    rv = send_set_session_privilege(ipmi, lan, addr_num, info->rspi);
    if (rv) {
        handle_connected(ipmi, rv, addr_num);
	goto out;
    }

 out:
    if (rv)
	ipmi_free_msg_item(info->rspi);
    ipmi_mem_free(info);
    return;
}

static int
rmcpp_set_info(ipmi_con_t        *ipmi,
	       int               addr_num,
	       ipmi_rmcpp_auth_t *ainfo,
	       void              *cb_data)
{
    auth_info_t *info = cb_data;
    lan_data_t  *lan = info->lan;
    int         rv;

    rv = lan->ip[addr_num].conf_info->conf_init
	(ipmi, ainfo, &(lan->ip[addr_num].conf_data));
    if (rv)
	goto out;

    rv = lan->ip[addr_num].integ_info->integ_init
	(ipmi, ainfo, &(lan->ip[addr_num].integ_data));
    if (rv)
	goto out;

 out:
    return rv;
}

static int
got_rmcpp_open_session_rsp(ipmi_con_t *ipmi, ipmi_msgi_t  *rspi)
{
    ipmi_msg_t   *msg = &rspi->msg;
    lan_data_t   *lan;
    int          addr_num = (long) rspi->data4;
    uint32_t     session_id;
    uint32_t     mgsys_session_id;
    unsigned int privilege;
    unsigned int auth, integ, conf;
    ipmi_rmcpp_authentication_t *authp = NULL;
    ipmi_rmcpp_confidentiality_t *confp = NULL;
    ipmi_rmcpp_integrity_t *integp = NULL;
    auth_info_t  *info;
    int          rv;

    if (check_rakp_rsp(ipmi, msg, "got_rmcpp_open_session_rsp", 36, addr_num))
	goto out;

    lan = (lan_data_t *) ipmi->con_data;

    privilege = msg->data[2] & 0xf;
    if (privilege != lan->cparm.privilege) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "Expected privilege %d, got %d",
		 IPMI_CONN_NAME(ipmi), lan->cparm.privilege, privilege);
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    session_id = ipmi_get_uint32(msg->data+4);
    if (session_id != lan->ip[addr_num].precon_session_id) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(got_rmcpp_open_session_rsp): "
		 " Got wrong session id: 0x%x",
		 IPMI_CONN_NAME(ipmi), session_id);
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    mgsys_session_id = ipmi_get_uint32(msg->data+8);
    if (mgsys_session_id == 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "Got NULL mgd system session id", IPMI_CONN_NAME(ipmi));
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }
    lan->ip[addr_num].precon_mgsys_session_id = mgsys_session_id;

    if ((msg->data[12] != 0) || (msg->data[15] != 8)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "Got NULL or invalid authentication payload",
		 IPMI_CONN_NAME(ipmi));
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }
    auth = msg->data[16] & 0x3f;

    if ((msg->data[20] != 1) || (msg->data[23] != 8)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "Got NULL or invalid integrity payload",
		 IPMI_CONN_NAME(ipmi));
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }
    integ = msg->data[24] & 0x3f;

    if ((msg->data[28] != 2) || (msg->data[31] != 8)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "Got NULL or invalid confidentiality payload",
		 IPMI_CONN_NAME(ipmi));
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }
    conf = msg->data[32] & 0x3f;

    if (auth >= 0x30) {
	auth_entry_t *e = oem_auth_list;
	while (e) {
	    if ((e->auth_num == auth)
		&& (memcmp(e->iana, lan->oem_iana, 3) == 0))
	    {
		authp = e->auth;
		break;
	    }
	    e = e->next;
	}
    } else
	authp = auths[auth];

    if (!authp) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "BMC returned an auth algorithm that wasn't supported: %d",
		 IPMI_CONN_NAME(ipmi), auth);
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    if (conf >= 0x30) {
	conf_entry_t *e = oem_conf_list;
	while (e) {
	    if ((e->conf_num == conf)
		&& (memcmp(e->iana, lan->oem_iana, 3) == 0))
	    {
		confp = e->conf;
		break;
	    }
	    e = e->next;
	}
    } else
	confp = confs[conf];

    if (!confp) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "BMC returned a conf algorithm that wasn't supported: %d",
		 IPMI_CONN_NAME(ipmi), conf);
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    if (integ >= 0x30) {
	integ_entry_t *e = oem_integ_list;
	while (e) {
	    if ((e->integ_num == integ)
		&& (memcmp(e->iana, lan->oem_iana, 3) == 0))
	    {
		integp = e->integ;
		break;
	    }
	    e = e->next;
	}
    } else
	integp = integs[integ];

    if (!integp) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "BMC returned an integ algorithm that wasn't supported: %d",
		 IPMI_CONN_NAME(ipmi), integ);
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	handle_connected(ipmi, ENOMEM, addr_num);
	goto out;
    }

    lan->ip[addr_num].working_conf = conf;
    lan->ip[addr_num].working_integ = integ;
    lan->ip[addr_num].conf_info = confp;
    lan->ip[addr_num].integ_info = integp;

    lan->ip[addr_num].ainfo.lan = lan;
    lan->ip[addr_num].ainfo.role = ((lan->cparm.name_lookup_only << 4)
				    | lan->cparm.privilege);

    info->lan = lan;
    info->rspi = rspi;

    rv = authp->start_auth(ipmi, addr_num, lan->fd_slot,
			   &(lan->ip[addr_num].ainfo),
			   rmcpp_set_info, rmcpp_auth_finished,
			   info);
    if (rv) {
	ipmi_mem_free(info);
	handle_connected(ipmi, rv, addr_num);
	goto out;
    }

    return IPMI_MSG_ITEM_USED;

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
send_rmcpp_open_session(ipmi_con_t *ipmi, lan_data_t *lan, ipmi_msgi_t *rspi,
			int addr_num)
{
    int               rv;
    unsigned char     data[32];
    ipmi_msg_t        msg;
    ipmi_rmcpp_addr_t addr;

    memset(data, 0, sizeof(data));
    data[0] = 0; /* Set to seq# by the formatting code. */
    data[1] = lan->cparm.privilege;
    ipmi_set_uint32(data+4, lan->ip[addr_num].precon_session_id);
    data[8] = 0; /* auth algorithm */
    if ((int) lan->cparm.auth == IPMI_LANP_AUTHENTICATION_ALGORITHM_BMCPICK)
	data[11] = 0; /* Let the BMC pick */
    else {
	data[11] = 8;
	data[12] = lan->cparm.auth;
    }
    data[16] = 1; /* integrity algorithm */
    if ((int) lan->cparm.integ == IPMI_LANP_INTEGRITY_ALGORITHM_BMCPICK)
	data[19] = 0; /* Let the BMC pick */
    else {
	data[19] = 8;
	data[20] = lan->cparm.integ;
    }
    data[24] = 2; /* confidentiality algorithm */
    if ((int) lan->cparm.conf == IPMI_LANP_CONFIDENTIALITY_ALGORITHM_BMCPICK)
	data[27] = 0; /* Let the BMC pick */
    else {
	data[27] = 8;
	data[28] = lan->cparm.conf;
    }

    msg.netfn = IPMI_RMCPP_DUMMY_NETFN;
    msg.cmd = IPMI_RMCPP_PAYLOAD_TYPE_OPEN_SESSION_REQUEST;
    msg.data = data;
    msg.data_len = 32;
    addr.addr_type = (IPMI_RMCPP_ADDR_START
		      + IPMI_RMCPP_PAYLOAD_TYPE_OPEN_SESSION_REQUEST);

    rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
				       (ipmi_addr_t *) &addr, sizeof(addr),
				       &msg, got_rmcpp_open_session_rsp, rspi);
    return rv;
}

static int
start_rmcpp(ipmi_con_t *ipmi, lan_data_t *lan, ipmi_msgi_t *rspi, int addr_num)
{
    int rv;

    /* We don't really need to get the cipher suites, the user
       requests them (or defaults them to the mandatory ones). */

    lan->ip[addr_num].working_authtype = IPMI_AUTHTYPE_RMCP_PLUS;
    lan->ip[addr_num].outbound_seq_num = 0;
    lan->ip[addr_num].unauth_out_seq_num = 0;
    lan->ip[addr_num].inbound_seq_num = 0;
    lan->ip[addr_num].unauth_in_seq_num = 0;
    /* Use our fd_slot in the fd for the session id, so we can look it
       up quickly. */
    lan->ip[addr_num].precon_session_id = lan->fd_slot + 1;
    lan->ip[addr_num].working_conf = IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE;
    lan->ip[addr_num].working_integ = IPMI_LANP_INTEGRITY_ALGORITHM_NONE;

    rv = send_rmcpp_open_session(ipmi, lan, rspi, addr_num);
    if (rv) {
	handle_connected(ipmi, rv, addr_num);
	goto out;
    }

    return IPMI_MSG_ITEM_USED;

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
session_activated(ipmi_con_t *ipmi, ipmi_msgi_t  *rspi)
{
    ipmi_msg_t *msg = &rspi->msg;
    lan_data_t *lan;
    int        rv;
    int        addr_num = (long) rspi->data4;


    if (!ipmi) {
	handle_connected(ipmi, ECANCELED, addr_num);
	goto out;
    }

    lan = (lan_data_t *) ipmi->con_data;

    if (msg->data[0] != 0) {
        handle_connected(ipmi, IPMI_IPMI_ERR_VAL(msg->data[0]), addr_num);
	goto out;
    }

    if (msg->data_len < 11) {
        handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    lan->ip[addr_num].working_authtype = msg->data[1] & 0xf;
    if ((lan->ip[addr_num].working_authtype != 0)
	&& (lan->ip[addr_num].working_authtype != lan->chosen_authtype))
    {
	/* Eh?  It didn't return a valid authtype. */
        handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    lan->ip[addr_num].session_id = ipmi_get_uint32(msg->data+2);
    lan->ip[addr_num].outbound_seq_num = ipmi_get_uint32(msg->data+6);

    rv = send_set_session_privilege(ipmi, lan, addr_num, rspi);
    if (rv) {
        handle_connected(ipmi, rv, addr_num);
	goto out;
    }

    return IPMI_MSG_ITEM_USED;

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
send_activate_session(ipmi_con_t *ipmi, lan_data_t *lan, int addr_num,
		      ipmi_msgi_t *rspi)
{
    unsigned char                data[IPMI_MAX_MSG_LENGTH];
    ipmi_msg_t                   msg;
    int                          rv;
    ipmi_system_interface_addr_t addr;

    addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    addr.channel = 0xf;
    addr.lun = 0;

    data[0] = lan->chosen_authtype;
    data[1] = lan->cparm.privilege;
    memcpy(data+2, lan->challenge_string, 16);
    ipmi_set_uint32(data+18, lan->ip[addr_num].inbound_seq_num);

    msg.cmd = IPMI_ACTIVATE_SESSION_CMD;
    msg.netfn = IPMI_APP_NETFN;
    msg.data = data;
    msg.data_len = 22;

    rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
				       (ipmi_addr_t *) &addr, sizeof(addr),
				       &msg, session_activated, rspi);
    return rv;
}

static int
challenge_done(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t *msg = &rspi->msg;
    lan_data_t *lan;
    int        rv;
    int        addr_num = (long) rspi->data4;


    if (!ipmi) {
	handle_connected(ipmi, ECANCELED, addr_num);
	goto out;
    }

    lan = (lan_data_t *) ipmi->con_data;

    if (msg->data[0] != 0) {
        handle_connected(ipmi, IPMI_IPMI_ERR_VAL(msg->data[0]), addr_num);
	goto out;
    }

    if (msg->data_len < 21) {
        handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    /* Get the temporary session id. */
    lan->ip[addr_num].session_id = ipmi_get_uint32(msg->data+1);

    lan->ip[addr_num].outbound_seq_num = 0;
    lan->ip[addr_num].working_authtype = lan->chosen_authtype;
    memcpy(lan->challenge_string, msg->data+5, 16);

    /* Get a random number of the other end to start sending me sequence
       numbers at, but don't let it be zero. */
    while (lan->ip[addr_num].inbound_seq_num == 0) {
	rv = ipmi->os_hnd->get_random(ipmi->os_hnd,
				      &(lan->ip[addr_num].inbound_seq_num), 4);
	if (rv) {
	    handle_connected(ipmi, rv, addr_num);
	    goto out;
	}
    }

    rv = send_activate_session(ipmi, lan, addr_num, rspi);
    if (rv) {
        handle_connected(ipmi, rv, addr_num);
	goto out;
    }

    return IPMI_MSG_ITEM_USED;

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
send_challenge(ipmi_con_t *ipmi, lan_data_t *lan, int addr_num,
	       ipmi_msgi_t *rspi)
{
    unsigned char                data[IPMI_MAX_MSG_LENGTH];
    ipmi_msg_t                   msg;
    ipmi_system_interface_addr_t addr;
    int                          rv;

    addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    addr.channel = 0xf;
    addr.lun = 0;

    data[0] = lan->chosen_authtype;
    msg.cmd = IPMI_GET_SESSION_CHALLENGE_CMD;
    msg.netfn = IPMI_APP_NETFN;
    msg.data = data;
    msg.data_len = 1;
    memcpy(data+1, lan->cparm.username, IPMI_USERNAME_MAX);
    msg.data_len += IPMI_USERNAME_MAX;

    rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
				       (ipmi_addr_t *) &addr, sizeof(addr),
				       &msg, challenge_done, rspi);
    return rv;
}

static int
auth_cap_done(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t *msg = &rspi->msg;
    lan_data_t *lan;
    int        rv;
    int        addr_num = (long) rspi->data4;
    int        supports_ipmi2;
    int        extended_capabilities_reported;

    if (!ipmi) {
	handle_connected(ipmi, ECANCELED, addr_num);
	goto out;
    }

    lan = (lan_data_t *) ipmi->con_data;

    if (msg->data[0] != 0) {
        handle_connected(ipmi, IPMI_IPMI_ERR_VAL(msg->data[0]), addr_num);
	goto out;
    }

    if (msg->data_len < 9) {
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    extended_capabilities_reported = (msg->data[2] & 0x80);
    supports_ipmi2 = (msg->data[4] & 0x02);
    if (extended_capabilities_reported && supports_ipmi2) {
	/* We have RMCP+ support!  Use it. */
	lan->use_two_keys = (msg->data[3] >> 5) & 1;
	memcpy(lan->oem_iana, msg->data+5, 3);
	lan->oem_aux = msg->data[8];
	return start_rmcpp(ipmi, lan, rspi, addr_num);
    }
    else if (supports_ipmi2)
    {
	/*
	 * The BMC has said that it supports RMCP+/IPMI 2.0 in the
	 * extended response fields, but has not indicated that we
	 * should USE the extended response fields!  The SuperMicro
	 * AOC-IPMI20-E currently does this (April 2005), and will do
	 * so until they provide BMC firmware that supports RMCP+.
	 */
	ipmi_log(IPMI_LOG_WARNING,
		"%sipmi_lan.c(auth_cap_done): "
		"BMC confused about RMCP+ support. Disabling RMCP+.",
		IPMI_CONN_NAME(lan->ipmi));
    } 
    if (lan->cparm.authtype == IPMI_AUTHTYPE_RMCP_PLUS) {
	/* The user specified RMCP+, but the system doesn't have it. */
	ipmi_log(IPMI_LOG_ERR_INFO,
		"%sipmi_lan.c(auth_cap_done): "
		"User requested RMCP+, but not supported",
		IPMI_CONN_NAME(lan->ipmi));
	handle_connected(ipmi, ENOENT, addr_num);
	goto out;
    }

    memcpy(lan->oem_iana, msg->data+5, 3);
    lan->oem_aux = msg->data[8];

    if (lan->authdata) {
	ipmi_auths[lan->chosen_authtype].authcode_cleanup(lan->authdata);
	lan->authdata = NULL;
    }

    if ((int) lan->cparm.authtype == IPMI_AUTHTYPE_DEFAULT) {
	/* Pick the most secure authentication type. */
	if (msg->data[2] & (1 << IPMI_AUTHTYPE_MD5)) {
	    lan->chosen_authtype = IPMI_AUTHTYPE_MD5;
	} else if (msg->data[2] & (1 << IPMI_AUTHTYPE_MD2)) {
	    lan->chosen_authtype = IPMI_AUTHTYPE_MD2;
	} else if (msg->data[2] & (1 << IPMI_AUTHTYPE_STRAIGHT)) {
	    lan->chosen_authtype = IPMI_AUTHTYPE_STRAIGHT;
	} else if (msg->data[2] & (1 << IPMI_AUTHTYPE_NONE)) {
	    lan->chosen_authtype = IPMI_AUTHTYPE_NONE;
	} else {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sipmi_lan.c(auth_cap_done): "
		     "No valid authentication supported",
		     IPMI_CONN_NAME(lan->ipmi));
	    handle_connected(ipmi, EINVAL, addr_num);
	    goto out;
	}
    } else {
	if (!(msg->data[2] & (1 << lan->cparm.authtype))) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sipmi_lan.c(auth_cap_done): "
		     "Requested authentication not supported",
		     IPMI_CONN_NAME(lan->ipmi));
	    handle_connected(ipmi, EINVAL, addr_num);
	    goto out;
	}
	lan->chosen_authtype = lan->cparm.authtype;
    }

    rv = ipmi_auths[lan->chosen_authtype].authcode_init(lan->cparm.password,
							&(lan->authdata),
							NULL, auth_alloc,
							auth_free);
    if (rv) {
        ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(auth_cap_done): "
		 "Unable to initialize authentication data: 0x%x",
		 IPMI_CONN_NAME(lan->ipmi), rv);
        handle_connected(ipmi, rv, addr_num);
	goto out;
    }

    rv = send_challenge(ipmi, lan, addr_num, rspi);
    if (rv) {
        ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sipmi_lan.c(auth_cap_done): "
		 "Unable to send challenge command: 0x%x",
		 IPMI_CONN_NAME(lan->ipmi), rv);
        handle_connected(ipmi, rv, addr_num);
	goto out;
    }

    return IPMI_MSG_ITEM_USED;

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
auth_cap_done_p(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t *msg = &rspi->msg;
    lan_data_t *lan;
    int        addr_num = (long) rspi->data4;
    int        rv;

    if (!ipmi) {
	handle_connected(ipmi, ECANCELED, addr_num);
	goto out;
    }

    lan = (lan_data_t *) ipmi->con_data;

    if ((msg->data[0] != 0) || (msg->data_len < 9)) {
	/* Got an error, try it without the RMCP+ bit set.  Some
	   systems incorrectly return errors when reserved data is
	   set. */

	if (lan->cparm.authtype == IPMI_AUTHTYPE_RMCP_PLUS) {
	    /* The user specified RMCP+, but the system doesn't have it. */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sipmi_lan.c(auth_cap_done_p): "
		     "Use requested RMCP+, but not supported",
		     IPMI_CONN_NAME(lan->ipmi));
	    handle_connected(ipmi, ENOENT, addr_num);
	    goto out;
	}

	rv = send_auth_cap(ipmi, lan, addr_num, 1);
	if (rv) {
	    handle_connected(ipmi, rv, addr_num);
	}
	goto out;
    }


    return auth_cap_done(ipmi, rspi);

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
send_auth_cap(ipmi_con_t *ipmi, lan_data_t *lan, int addr_num,
	      int force_ipmiv15)
{
    unsigned char                data[2];
    ipmi_msg_t                   msg;
    ipmi_system_interface_addr_t addr;
    int                          rv;
    ipmi_msgi_t                  *rspi;
    ipmi_ll_rsp_handler_t        rsp_handler;

    /* FIXME - a system may only support RMCP+ and not RMCP.  We need
       a way to detect and handle that.  */

    rspi = ipmi_mem_alloc(sizeof(*rspi));
    if (!rspi)
	return ENOMEM;

    addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    addr.channel = 0xf;
    addr.lun = 0;

    data[0] = 0xe;
    data[1] = lan->cparm.privilege;
    msg.cmd = IPMI_GET_CHANNEL_AUTH_CAPABILITIES_CMD;
    msg.netfn = IPMI_APP_NETFN;
    msg.data = data;
    msg.data_len = 2;
    if ((((int) lan->cparm.authtype == IPMI_AUTHTYPE_DEFAULT)
	 || ((int) lan->cparm.authtype == IPMI_AUTHTYPE_RMCP_PLUS))
	&& !force_ipmiv15)
    {
	rsp_handler = auth_cap_done_p;
	data[0] |= 0x80; /* Get RMCP data. */
    } else {
	rsp_handler = auth_cap_done;
    }

    rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
				       (ipmi_addr_t *) &addr, sizeof(addr),
				       &msg, rsp_handler, rspi);
    if (rv)
	ipmi_mem_free(rspi);
    return rv;
}

static int
lan_start_con(ipmi_con_t *ipmi)
{
    lan_data_t     *lan = (lan_data_t *) ipmi->con_data;
    int            rv;
    struct timeval timeout;
    unsigned int   i;

    ipmi_lock(lan->ip_lock);
    if (lan->started) {
	/* Only allow started to be called once, but make sure the
	   connected callback gets called if started is called again
	   (assuming the connection is up).  This lets multiple users
	   use the same connection.  If the LAN is not connected, this
	   doesn't matter, the callback will be called properly
	   later. */
	if (lan->connected) {
	    unsigned int i;
	    int          port_err[MAX_IP_ADDR];

	    for (i=0; i<lan->cparm.num_ip_addr; i++)
		port_err[i] = lan->ip[i].working ? 0 : EINVAL;

	    ipmi_lock(lan->con_change_lock);
	    ipmi_unlock(lan->ip_lock);

	    for (i=0; i<lan->cparm.num_ip_addr; i++)
		call_con_change_handlers(lan, port_err[i], i, 1);
	    ipmi_unlock(lan->con_change_lock);
	} else
	    ipmi_unlock(lan->ip_lock);
	return 0;
    }

    /* Start the timer to audit the connections. */
    lan->audit_info = ipmi_mem_alloc(sizeof(*(lan->audit_info)));
    if (!lan->audit_info) {
	rv = ENOMEM;
	goto out_err;
    }

    lan->audit_info->cancelled = 0;
    lan->audit_info->ipmi = ipmi;
    rv = ipmi->os_hnd->alloc_timer(ipmi->os_hnd, &(lan->audit_timer));
    if (rv)
	goto out_err;
    timeout.tv_sec = LAN_AUDIT_TIMEOUT / 1000000;
    timeout.tv_usec = LAN_AUDIT_TIMEOUT % 1000000;
    rv = ipmi->os_hnd->start_timer(ipmi->os_hnd,
				   lan->audit_timer,
				   &timeout,
				   audit_timeout_handler,
				   lan->audit_info);
    if (rv) {
	ipmi_mem_free(lan->audit_info);
	lan->audit_info = NULL;
	ipmi->os_hnd->free_timer(ipmi->os_hnd, lan->audit_timer);
	lan->audit_timer = NULL;
	goto out_err;
    }

    lan->started = 1;
    ipmi_unlock(lan->ip_lock);

    for (i=0; i<lan->cparm.num_ip_addr; i++)
	/* Ignore failures, this gets retried. */
	send_auth_cap(ipmi, lan, i, 0);

    return 0;

 out_err:
    ipmi_unlock(lan->ip_lock);
    return rv;
}

int
ipmi_lan_setup_con(struct in_addr            *ip_addrs,
		   int                       *ports,
		   unsigned int              num_ip_addrs,
		   unsigned int              authtype,
		   unsigned int              privilege,
		   void                      *username,
		   unsigned int              username_len,
		   void                      *password,
		   unsigned int              password_len,
		   os_handler_t              *handlers,
		   void                      *user_data,
		   ipmi_con_t                **new_con)
{
    char s_ip_addrs[MAX_IP_ADDR][20];
    char s_ports[MAX_IP_ADDR][10];
    char *paddrs[MAX_IP_ADDR], *pports[MAX_IP_ADDR];
    unsigned char *p;
    unsigned int  i;
    int           rv;

    if ((num_ip_addrs < 1) || (num_ip_addrs > MAX_IP_ADDR))
	return EINVAL;
    for (i=0; i<num_ip_addrs; i++) {
	p = (unsigned char *)&(ip_addrs[i]);
	sprintf(s_ip_addrs[i], "%u.%u.%u.%u", *p, *(p+1), *(p+2), *(p+3));
	sprintf(s_ports[i], "%u", ports[i]);
	paddrs[i] = s_ip_addrs[i];
	pports[i]= s_ports[i];
    }
    rv = ipmi_ip_setup_con(paddrs, 
			   pports, 
			   num_ip_addrs,
			   authtype,
			   privilege,
			   username,
			   username_len,
			   password,
			   password_len,
			   handlers,
			   user_data,
			   new_con);
    return rv;
}

int
ipmi_ip_setup_con(char         * const ip_addrs[],
		  char         * const ports[],
		  unsigned int num_ip_addrs,
		  unsigned int authtype,
		  unsigned int privilege,
		  void         *username,
		  unsigned int username_len,
		  void         *password,
		  unsigned int password_len,
		  os_handler_t *handlers,
		  void         *user_data,
		  ipmi_con_t   **new_con)
{
    ipmi_lanp_parm_t parms[6];

    parms[0].parm_id = IPMI_LANP_PARMID_ADDRS;
    parms[0].parm_data = (void *) ip_addrs;
    parms[0].parm_data_len = num_ip_addrs;
    parms[1].parm_id = IPMI_LANP_PARMID_PORTS;
    parms[1].parm_data = (void *) ports;
    parms[1].parm_data_len = num_ip_addrs;
    parms[2].parm_id = IPMI_LANP_PARMID_AUTHTYPE;
    parms[2].parm_val = authtype;
    parms[3].parm_id = IPMI_LANP_PARMID_PRIVILEGE;
    parms[3].parm_val = privilege;
    parms[4].parm_id = IPMI_LANP_PARMID_USERNAME;
    parms[4].parm_data = username;
    parms[4].parm_data_len = username_len;
    parms[5].parm_id = IPMI_LANP_PARMID_PASSWORD;
    parms[5].parm_data = password;
    parms[5].parm_data_len = password_len;
    return ipmi_lanp_setup_con(parms, 6, handlers, user_data, new_con);
}

static lan_data_t *
find_matching_lan(lan_conn_parms_t *cparm)
{
    lan_link_t   *l;
    lan_data_t   *lan;
    unsigned int idx;

    /* Look in the first IP addresses list. */
    idx = hash_lan_addr(&cparm->ip_addr[0].s_ipsock.s_addr);
    ipmi_lock(lan_list_lock);
    l = lan_ip_list[idx].next;
    while (l->lan) {
	lan = l->lan;
	if (memcmp(&lan->cparm, cparm, sizeof(*cparm)) == 0) {
	    /* Parms match up, use it */
	    lan->users++;
	    ipmi_unlock(lan_list_lock);
	    return lan;
	}
	l = l->next;
    }
    ipmi_unlock(lan_list_lock);
    return NULL;
}

static void
lan_use_connection(ipmi_con_t *ipmi)
{
    lan_data_t *lan = ipmi->con_data;

    ipmi_lock(lan_list_lock);
    lan->users++;
    ipmi_unlock(lan_list_lock);
}

static int
lan_register_stat_handler(ipmi_con_t          *ipmi,
			  ipmi_ll_stat_info_t *info)
{
    lan_stat_info_t *nstat;
    lan_data_t      *lan = ipmi->con_data;
    int             i;

    nstat = ipmi_mem_alloc(sizeof(*nstat));
    if (!nstat)
	return ENOMEM;
    memset(nstat, 0, sizeof(*nstat));

    for (i=0; i<NUM_STATS; i++)
	ipmi_ll_con_stat_call_register(info, lan_stat_names[i],
				       ipmi->name, &(nstat->stats[i]));

    if (!locked_list_add(lan->lan_stat_list, nstat, info)) {
	for (i=0; i<NUM_STATS; i++)
	    if (nstat->stats[i]) {
		ipmi_ll_con_stat_call_unregister(info, nstat->stats[i]);
		nstat->stats[i] = NULL;
	    }
	ipmi_mem_free(nstat);
	return ENOMEM;
    }

    return 0;
}

static int
lan_unregister_stat_handler(ipmi_con_t          *ipmi,
			    ipmi_ll_stat_info_t *info)
{
    lan_unreg_stat_info_t sinfo;
    lan_data_t            *lan = ipmi->con_data;

    sinfo.lan = lan;
    sinfo.cmpinfo = info;
    sinfo.found = 0;
    locked_list_iterate(lan->lan_stat_list, lan_unreg_stat_info,
			&sinfo);
    if (sinfo.found)
	return 0;
    else
	return EINVAL;
}

static ipmi_args_t *get_startup_args(ipmi_con_t *ipmi);

static unsigned int conf_order[] = {
    IPMI_LANP_CONFIDENTIALITY_ALGORITHM_AES_CBC_128
};

static unsigned int
most_secure_lanp_conf(void)
{
    unsigned int i, v;
    for (i=0; i<(sizeof(conf_order)/sizeof(unsigned int)); i++) {
	v = conf_order[i];
	if (confs[v])
	    return v;
    }

    return IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE;
}

static unsigned int integ_order[] = {
    IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_SHA1_96,
    IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_MD5_128,
    IPMI_LANP_INTEGRITY_ALGORITHM_MD5_128
};

static unsigned int
most_secure_lanp_integ(void)
{
    unsigned int i, v;
    for (i=0; i<(sizeof(integ_order)/sizeof(unsigned int)); i++) {
	v = integ_order[i];
	if (integs[v])
	    return v;
    }

    return IPMI_LANP_INTEGRITY_ALGORITHM_NONE;
}

static unsigned int auth_order[] = {
    IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_HMAC_SHA1,
    IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_HMAC_MD5
};

static unsigned int
most_secure_lanp_auth(void)
{
    unsigned int i, v;
    for (i=0; i<(sizeof(auth_order)/sizeof(unsigned int)); i++) {
	v = auth_order[i];
	if (auths[v])
	    return v;
    }

    return IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_NONE;
}


int
ipmi_lanp_setup_con(ipmi_lanp_parm_t *parms,
		    unsigned int     num_parms,
		    os_handler_t     *handlers,
		    void             *user_data,
		    ipmi_con_t       **new_con)
{
    ipmi_con_t         *ipmi = NULL;
    lan_data_t         *lan = NULL;
    int                rv;
    unsigned int       i;
    unsigned int       count;
    struct sockaddr_in *pa;
    char               **ip_addrs = NULL;
    char               *tports[MAX_IP_ADDR];
    char               **ports = NULL;
    lan_conn_parms_t   cparm;
    int max_outstanding_msg_count = DEFAULT_MAX_OUTSTANDING_MSG_COUNT;

    memset(&cparm, 0, sizeof(cparm));

    /* Pick some secure defaults. */
    cparm.authtype = IPMI_AUTHTYPE_DEFAULT;
    cparm.privilege = IPMI_PRIVILEGE_ADMIN;
    cparm.conf = most_secure_lanp_conf();
    cparm.integ = most_secure_lanp_integ();
    cparm.auth = most_secure_lanp_auth();
    cparm.name_lookup_only = 1;

    for (i=0; i<num_parms; i++) {
	switch (parms[i].parm_id) {
	case IPMI_LANP_PARMID_AUTHTYPE:
	    cparm.authtype = parms[i].parm_val;
	    break;

	case IPMI_LANP_PARMID_PRIVILEGE:
	    cparm.privilege = parms[i].parm_val;
	    break;

	case IPMI_LANP_PARMID_PASSWORD:
	    if (parms[i].parm_data_len > sizeof(cparm.password))
		return EINVAL;
	    memcpy(cparm.password, parms[i].parm_data, parms[i].parm_data_len);
	    cparm.password_len = parms[i].parm_data_len;
	    break;

	case IPMI_LANP_PARMID_USERNAME:
	    if (parms[i].parm_data_len > sizeof(cparm.username))
		return EINVAL;
	    memcpy(cparm.username, parms[i].parm_data, parms[i].parm_data_len);
	    cparm.username_len = parms[i].parm_data_len;
	    break;

	case IPMI_LANP_PARMID_ADDRS:
	    if (cparm.num_ip_addr
		&& (cparm.num_ip_addr != parms[i].parm_data_len))
		return EINVAL;
	    if (parms[i].parm_data_len > MAX_IP_ADDR)
		return EINVAL;
	    ip_addrs = parms[i].parm_data;
	    cparm.num_ip_addr = parms[i].parm_data_len;
	    break;

	case IPMI_LANP_PARMID_PORTS:
	    if (cparm.num_ip_addr
		&& (cparm.num_ip_addr != parms[i].parm_data_len))
		return EINVAL;
	    if (parms[i].parm_data_len > MAX_IP_ADDR)
		return EINVAL;
	    ports = parms[i].parm_data;
	    cparm.num_ip_addr = parms[i].parm_data_len;
	    break;

	case IPMI_LANP_AUTHENTICATION_ALGORITHM:
	    cparm.auth = parms[i].parm_val;
	    if ((int) cparm.auth != IPMI_LANP_AUTHENTICATION_ALGORITHM_BMCPICK)
	    {
		if (cparm.auth >= 64)
		    return EINVAL;
		if ((cparm.auth < 0x30) && (!auths[cparm.auth]))
		    return ENOSYS;
	    }
	    break;

	case IPMI_LANP_INTEGRITY_ALGORITHM:
	    cparm.integ = parms[i].parm_val;
	    if ((int) cparm.integ != IPMI_LANP_INTEGRITY_ALGORITHM_BMCPICK)
	    {
		if (cparm.integ >= 64)
		    return EINVAL;
		if (cparm.integ
		    && ((cparm.integ < 0x30) && (!integs[cparm.integ])))
		    return ENOSYS;
	    }
	    break;

	case IPMI_LANP_CONFIDENTIALITY_ALGORITHM:
	    cparm.conf = parms[i].parm_val;
	    if ((int)cparm.conf != IPMI_LANP_CONFIDENTIALITY_ALGORITHM_BMCPICK)
	    {
		if (cparm.conf >= 64)
		    return EINVAL;
		if (cparm.conf
		    && ((cparm.conf < 0x30) && (!confs[cparm.conf])))
		    return ENOSYS;
	    }
	    break;

	case IPMI_LANP_NAME_LOOKUP_ONLY:
	    cparm.name_lookup_only = parms[i].parm_val != 0;
	    break;

	case IPMI_LANP_BMC_KEY:
	    if (parms[i].parm_data_len > sizeof(cparm.bmc_key))
		return EINVAL;
	    memcpy(cparm.bmc_key, parms[i].parm_data, parms[i].parm_data_len);
	    cparm.bmc_key_len = parms[i].parm_data_len;
	    break;

	case IPMI_LANP_MAX_OUTSTANDING_MSG_COUNT:
	    if ((parms[i].parm_val < 1)
		|| (parms[i].parm_val > MAX_POSSIBLE_OUTSTANDING_MSG_COUNT))
		return EINVAL;
	    max_outstanding_msg_count = parms[i].parm_val;
	    break;
		
	default:
	    return EINVAL;
	}
    }

    if ((cparm.num_ip_addr == 0) || (ip_addrs == NULL))
	return EINVAL;
    if (((int) cparm.authtype != IPMI_AUTHTYPE_DEFAULT)
	&& (cparm.authtype != IPMI_AUTHTYPE_RMCP_PLUS)
	&& ((cparm.authtype >= MAX_IPMI_AUTHS)
	    || (ipmi_auths[cparm.authtype].authcode_init == NULL)))
	return EINVAL;
    if ((cparm.num_ip_addr < 1) || (cparm.num_ip_addr > MAX_IP_ADDR))
	return EINVAL;

    if (ports) {
	for (i=0; i<MAX_IP_ADDR; i++)
	    tports[i] = ports[i];
	ports = tports;
    } else {
	ports = tports;
	for (i=0; i<MAX_IP_ADDR; i++)
	    ports[i] = NULL;
    }
    for (i=0; i<MAX_IP_ADDR; i++) {
	if (!ports[i])
	    ports[i] = IPMI_LAN_STD_PORT_STR;
    }

    count = 0;
#ifdef HAVE_GETADDRINFO
    for (i=0; i<cparm.num_ip_addr; i++) {
        struct addrinfo hints, *res0;
 
        memset(&hints, 0, sizeof(hints));
        if (count == 0)
            hints.ai_family = AF_UNSPEC;
        else
	{
            /* Make sure all ip address are in the same protocol family*/
	    struct sockaddr_in *paddr;
	    paddr = (struct sockaddr_in *)&(cparm.ip_addr[0]);
            hints.ai_family = paddr->sin_family;
	}
        hints.ai_socktype = SOCK_DGRAM;
        rv = getaddrinfo(ip_addrs[i], ports[i], &hints, &res0);
	if (rv)
	    return EINVAL;

	if (res0->ai_addrlen > sizeof(cparm.ip_addr[count].s_ipsock)) {
	    freeaddrinfo(res0);
	    return EFBIG;
	}

	/* Only get the first choices */
	memcpy(&(cparm.ip_addr[count].s_ipsock), res0->ai_addr,
	       res0->ai_addrlen);
	cparm.ip_addr[count].ip_addr_len = res0->ai_addrlen;
	count++;
	freeaddrinfo(res0);
    }
#else
    /* System does not support getaddrinfo, just for IPv4*/
    for (i=0; i<cparm.num_ip_addr; i++) {
	struct hostent *ent;
	struct sockaddr_in *paddr;
	ent = gethostbyname(ip_addrs[i]);
	if (!ent)
	    return EINVAL;
	paddr = (struct sockaddr_in *)&(cparm.ip_addr[i]);
        paddr->sin_family = AF_INET;
        paddr->sin_port = htons(atoi(ports[i]));
	if (ent->h_length > sizeof(paddr->sin_addr))
	    return EFBIG;

	memcpy(&(paddr->sin_addr), ent->h_addr_list[0], ent->h_length);
	cparm.ip_addr[count].ip_addr_len = ent->h_length;
	count++;
    }
#endif
    if (count == 0)
	return EINVAL;
    cparm.num_ip_addr = count;

    /* At this point we have a validated set of parms in cparm.  See
       if we alreay have one that matches. */
    lan = find_matching_lan(&cparm);
    if (lan) {
	*new_con = lan->ipmi;
	return 0;
    }

    ipmi = ipmi_mem_alloc(sizeof(*ipmi));
    if (!ipmi)
	return ENOMEM;
    memset(ipmi, 0, sizeof(*ipmi));

    ipmi->user_data = user_data;
    ipmi->os_hnd = handlers;
    ipmi->con_type = "rmcp";
    ipmi->priv_level = cparm.privilege;
    for (i=0; i<MAX_IPMI_USED_CHANNELS; i++)
	ipmi->ipmb_addr[i] = 0x20; /* Assume this until told otherwise */

    rv = ipmi_con_attr_init(ipmi);
    if (rv)
	goto out_err;

    lan = ipmi_mem_alloc(sizeof(*lan));
    if (!lan) {
	rv = ENOMEM;
	goto out_err;
    }
    memset(lan, 0, sizeof(*lan));
    ipmi->con_data = lan;
    lan->cparm = cparm;
    for (i=0; i<cparm.num_ip_addr; i++) {
	lan->cparm.ip_addr_str[i] = ipmi_strdup(ip_addrs[i]);
	if (!lan->cparm.ip_addr_str[i]) {
	    rv = ENOMEM;
	    goto out_err;
	}
	lan->cparm.ip_port_str[i] = ipmi_strdup(ports[i]);
	if (!lan->cparm.ip_port_str[i]) {
	    rv = ENOMEM;
	    goto out_err;
	}
    }

    lan->refcount = 1;
    lan->users = 1;
    lan->ipmi = ipmi;
    for (i=0; i<MAX_IPMI_USED_CHANNELS; i++)
	lan->slave_addr[i] = 0x20; /* Assume this until told otherwise */
    lan->is_active = 1;
    lan->chosen_authtype = IPMI_AUTHTYPE_DEFAULT;
    lan->curr_ip_addr = 0;
    lan->num_sends = 0;
    lan->connected = 0;
    lan->initialized = 0;

    lan->outstanding_msg_count = 0;
    lan->max_outstanding_msg_count = max_outstanding_msg_count;
    lan->wait_q = NULL;
    lan->wait_q_tail = NULL;

    pa = (struct sockaddr_in *)&(lan->cparm.ip_addr[0]);
    lan->fd = find_free_lan_fd(pa->sin_family, lan, &lan->fd_slot);
    if (! lan->fd) {
	rv = errno;
	goto out_err;
    }

    /* Create the locks if they are available. */
    rv = ipmi_create_lock_os_hnd(handlers, &lan->seq_num_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock_os_hnd(handlers, &lan->ip_lock);
    if (rv)
	goto out_err;

    lan->con_change_handlers = locked_list_alloc(handlers);
    if (!lan->con_change_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    lan->event_handlers = locked_list_alloc(handlers);
    if (!lan->event_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    lan->ipmb_change_handlers = locked_list_alloc(handlers);
    if (!lan->ipmb_change_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    rv = ipmi_create_lock_os_hnd(handlers, &lan->con_change_lock);
    if (rv)
	goto out_err;

    lan->lan_stat_list = locked_list_alloc(handlers);
    if (!lan->lan_stat_list) {
	rv = ENOMEM;
	goto out_err;
    }

    ipmi->start_con = lan_start_con;
    ipmi->set_ipmb_addr = lan_set_ipmb_addr;
    ipmi->add_ipmb_addr_handler = lan_add_ipmb_addr_handler;
    ipmi->remove_ipmb_addr_handler = lan_remove_ipmb_addr_handler;
    ipmi->add_con_change_handler = lan_add_con_change_handler;
    ipmi->remove_con_change_handler = lan_remove_con_change_handler;
    ipmi->send_command = lan_send_command;
    ipmi->add_event_handler = lan_add_event_handler;
    ipmi->remove_event_handler = lan_remove_event_handler;
    ipmi->send_response = lan_send_response;
    ipmi->register_for_command = lan_register_for_command;
    ipmi->deregister_for_command = lan_deregister_for_command;
    ipmi->close_connection = lan_close_connection;
    ipmi->close_connection_done = lan_close_connection_done;
    ipmi->handle_async_event = handle_async_event;
    ipmi->get_startup_args = get_startup_args;
    ipmi->use_connection = lan_use_connection;
    ipmi->send_command_option = lan_send_command_option;
    ipmi->get_num_ports = lan_get_num_ports;
    ipmi->get_port_info = lan_get_port_info;
    ipmi->register_stat_handler = lan_register_stat_handler;
    ipmi->unregister_stat_handler = lan_unregister_stat_handler;

    /* Add it to the list of valid IPMIs so it will validate.  This
       must be done last, after a point where it cannot fail. */
    lan_add_con(lan);

    *new_con = ipmi;

    return 0;

 out_err:
    cleanup_con(ipmi);
    return rv;
}

static void
snmp_got_match(lan_data_t          *lan,
	       const ipmi_msg_t    *msg,
	       const unsigned char *pet_ack)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   ack;
    int                          dummy_send_ip;

    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    handle_async_event(lan->ipmi, (ipmi_addr_t *) &si, sizeof(si), msg);

    /* Send the ack directly. */
    ack.netfn = IPMI_SENSOR_EVENT_NETFN;
    ack.cmd = IPMI_PET_ACKNOWLEDGE_CMD;
    ack.data = (unsigned char *) pet_ack;
    ack.data_len = 12;
    lan_send(lan, (ipmi_addr_t *) &si, sizeof(si), &ack, 0, &dummy_send_ip,
	     NULL);
}

typedef struct lan_do_evt_s
{
    lan_data_t          *lan;
    struct lan_do_evt_s *next;
} lan_do_evt_t;

int
ipmi_lan_handle_external_event(const struct sockaddr *src_addr,
			       const ipmi_msg_t      *msg,
			       const unsigned char   *pet_ack)
{
    lan_link_t   *l;
    lan_data_t   *lan;
    unsigned int i;
    unsigned int idx;
    lan_do_evt_t *found = NULL;
    lan_do_evt_t *next = NULL;

    idx = hash_lan_addr(src_addr);
    ipmi_lock(lan_list_lock);
    l = lan_ip_list[idx].next;
    /* Note that we call all the connections with the given IP
       address, not just the first one we find.  There may be more
       than one. */
    while (l->lan) {
	lan = NULL;
	for (i=0; i<l->lan->cparm.num_ip_addr; i++) {
	    if (l->lan->cparm.ip_addr[i].s_ipsock.s_addr.sa_family
		!= src_addr->sa_family)
	    {
		continue;
	    }
	    switch (src_addr->sa_family)
	    {
	    case PF_INET:
	    {
		struct sockaddr_in *src, *dst;
		src = (struct sockaddr_in *) src_addr;
		dst = &(l->lan->cparm.ip_addr[i].s_ipsock.s_addr4);
		if (dst->sin_addr.s_addr == src->sin_addr.s_addr) {
		    /* We have a match, handle it */
		    lan = l->lan;
		    lan->refcount++;
		}
	    }
	    break;
#ifdef PF_INET6
	    case PF_INET6:
	    {
		struct sockaddr_in6 *src, *dst;
		src = (struct sockaddr_in6 *) src_addr;
		dst = &(l->lan->cparm.ip_addr[i].s_ipsock.s_addr6);
		if (memcmp(dst->sin6_addr.s6_addr,
			   src->sin6_addr.s6_addr,
			   sizeof(struct in6_addr))
		    == 0)
		{
		    /* We have a match, handle it */
		    lan = l->lan;
		    lan->refcount++;
		}
	    }
	    break;
#endif
	    }

	    if (lan) {
		next = ipmi_mem_alloc(sizeof(*next));
		if (!next)
		    /* Can't do anything, just go on.  It's not
		       fatal, it just delays things. */
		    continue;
		next->lan = lan;
		next->next = found;
		found = next;
	    }
	}
	l = l->next;
    }
    ipmi_unlock(lan_list_lock);

    while (found) {
	next = found;
	found = found->next;
	snmp_got_match(next->lan, msg, pet_ack);
	lan_put(next->lan->ipmi);
	ipmi_mem_free(next);
    }

    /* Next will be left non-NULL if something was delivered, it will
       be NULL if nothing was delivered. */
    return next != NULL;
}

typedef struct lan_args_s
{
    char            *str_addr[2];	/* parms 0, 1 */
    char            *str_port[2];	/* parms 2, 3 */
    int             num_addr;
    unsigned int    authtype;		/* parm 4 */
    unsigned int    privilege;		/* parm 5 */
    int             username_set;
    char            username[16];	/* parm 6 */
    unsigned int    username_len;
    int             password_set;
    char            password[20];	/* parm 7 */
    unsigned int    password_len;

    unsigned int    auth_alg;		/* parm 8 */
    unsigned int    integ_alg;		/* parm 9 */
    unsigned int    conf_alg;		/* parm 10 */
    unsigned int    name_lookup_only;	/* parm 11 */
    int             bmc_key_set;
    char            bmc_key[20];	/* parm 12 */
    unsigned int    bmc_key_len;

    unsigned int    hacks;		/* parms 13, 14 */
    unsigned int    max_outstanding_msgs;/* parm 15 */
} lan_args_t;

static const char *auth_range[] = { "default", "none", "md2", "md5",
				    "straight", "oem", "rmcp+", NULL };
static int auth_vals[] = { IPMI_AUTHTYPE_DEFAULT,
			   IPMI_AUTHTYPE_NONE,
			   IPMI_AUTHTYPE_MD2,
			   IPMI_AUTHTYPE_MD5,
			   IPMI_AUTHTYPE_STRAIGHT,
			   IPMI_AUTHTYPE_OEM,
			   IPMI_AUTHTYPE_RMCP_PLUS };

static const char *priv_range[] = { "callback", "user", "operator", "admin",
				    "oem", NULL };
static int priv_vals[] = { IPMI_PRIVILEGE_CALLBACK,
			   IPMI_PRIVILEGE_USER,
			   IPMI_PRIVILEGE_OPERATOR,
			   IPMI_PRIVILEGE_ADMIN,
			   IPMI_PRIVILEGE_OEM };

static const char *auth_alg_range[] = { "bmcpick", "rakp_none",
					"rakp_hmac_sha1", "rakp_hmac_md5",
					NULL };
static int auth_alg_vals[] = { IPMI_LANP_AUTHENTICATION_ALGORITHM_BMCPICK,
			       IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_NONE,
			       IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_HMAC_SHA1,
			       IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_HMAC_MD5 };
static const char *integ_alg_range[] = { "bmcpick", "none", "hmac_sha1",
					"hmac_md5", "md5", NULL };
static int integ_alg_vals[] = { IPMI_LANP_INTEGRITY_ALGORITHM_BMCPICK,
				IPMI_LANP_INTEGRITY_ALGORITHM_NONE,
				IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_SHA1_96,
				IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_MD5_128,
				IPMI_LANP_INTEGRITY_ALGORITHM_MD5_128 };

static const char *conf_alg_range[] = { "bmcpick", "none", "aes_cbc_128",
					"xrc4_128", "xrc4_40", NULL };
static int conf_alg_vals[] = { IPMI_LANP_CONFIDENTIALITY_ALGORITHM_BMCPICK,
			       IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE,
			       IPMI_LANP_CONFIDENTIALITY_ALGORITHM_AES_CBC_128,
			       IPMI_LANP_CONFIDENTIALITY_ALGORITHM_xRC4_128,
			       IPMI_LANP_CONFIDENTIALITY_ALGORITHM_xRC4_40 };

static struct lan_argnum_info_s
{
    const char *name;
    const char *type;
    const char *help;
    const char **range;
    const int  *values;
} lan_argnum_info[17] =
{
    { "Address",	"str",
      "*IP name or address of the MC",
      NULL, NULL },
    { "Port",		"str",
      "*IP port or port name for the MC",
      NULL, NULL },
    { "Address2",	"str",
      "IP name or address of a second connection to the same MC",
      NULL, NULL },
    { "Port2",		"str",
      "IP port or portname for a second connection to the same MC",
      NULL, NULL },
    { "Authtype",	"enum",
      "Authentication to use for the connection",
      auth_range, auth_vals },
    { "Privilege",	"enum",
      "Privilege level to use for the connection",
      priv_range, priv_vals },
    { "Username",	"str",
      "The user name to use for the connection",
      NULL, NULL },
    { "Password",	"str",
      "!The password to use for the connection",
      NULL, NULL },
    { "Authentication_Algorithm",	"enum",
      "Authentication algorithm to use for the connection, for RMCP+ only",
      auth_alg_range, auth_alg_vals },
    { "Integrity_Algorithm",	"enum",
      "Integrity algorithm to use for the connection, for RMCP+ only",
      integ_alg_range, integ_alg_vals },
    { "Confidentiality_Algorithm",	"enum",
      "Confidentiality algorithm to use for the connection, for RMCP+ only",
      conf_alg_range, conf_alg_vals },
    { "Name_Lookup_Only",	"bool",
      "Use only the name, not the privilege, for selecting the password",
      NULL, NULL },
    { "BMC_Key",		"str",
      "The key to use for connecting to the BMC, may or may not be required",
      NULL, NULL },
    { "RAKP3_Wrong_RoleM",	"bool",
      "Some systems use the wrong RoleM value for RAKP3, a common problem",
      NULL, NULL },
    { "RMCP_Integ_SIK",		"bool",
      "The IPMI 2.0 Spec was unclear which integrity key to use",
      NULL, NULL },
    { "Max_Outstanding_Msgs",	"int",
      "How many outstanding messages on the connection, range 1-63",
      NULL, NULL },

    { NULL },
};

static ipmi_args_t *lan_con_alloc_args(void);

static void
lan_free_args(ipmi_args_t *args)
{
    lan_args_t *largs = _ipmi_args_get_extra_data(args);

    if (largs->str_addr[0])
	ipmi_mem_free(largs->str_addr[0]);
    if (largs->str_addr[1])
	ipmi_mem_free(largs->str_addr[1]);
    if (largs->str_port[0])
	ipmi_mem_free(largs->str_port[0]);
    if (largs->str_port[1])
	ipmi_mem_free(largs->str_port[1]);
    /* paranoia */
    memset(largs->password, 0, sizeof(largs->password));
    memset(largs->bmc_key, 0, sizeof(largs->bmc_key));
}

static ipmi_args_t *
get_startup_args(ipmi_con_t *ipmi)
{
    ipmi_args_t      *args;
    lan_args_t       *largs;
    lan_data_t       *lan;
    lan_conn_parms_t *cparm;

    args = lan_con_alloc_args();
    if (! args)
	return NULL;
    largs = _ipmi_args_get_extra_data(args);
    lan = (lan_data_t *) ipmi->con_data;
    cparm = &lan->cparm;
    largs->str_addr[0] = ipmi_strdup(cparm->ip_addr_str[0]);
    if (!largs->str_addr[0])
	goto out_err;
    largs->str_port[0] = ipmi_strdup(cparm->ip_port_str[0]);
    if (!largs->str_port[0])
	goto out_err;
    if (cparm->num_ip_addr > 1) {
	largs->str_addr[1] = ipmi_strdup(cparm->ip_addr_str[1]);
	if (!largs->str_addr[1])
	    goto out_err;
	largs->str_port[1] = ipmi_strdup(cparm->ip_port_str[1]);
	if (!largs->str_port[1])
	    goto out_err;
    }
    largs->num_addr = cparm->num_ip_addr;
    largs->authtype = cparm->authtype;
    largs->privilege = cparm->privilege;
    if (cparm->username_len) {
	largs->username_len = cparm->username_len ;
	memcpy(largs->username, cparm->username, cparm->username_len);
	largs->username_set = 1;
    }
    if (cparm->password_len) {
	largs->password_len = cparm->password_len ;
	memcpy(largs->password, cparm->password, cparm->password_len);
	largs->password_set = 1;
    }
    largs->conf_alg = cparm->conf;
    largs->auth_alg = cparm->auth;
    largs->integ_alg = cparm->integ;
    largs->name_lookup_only = cparm->name_lookup_only;
    largs->hacks = ipmi->hacks;
    if (cparm->bmc_key_len) {
	largs->bmc_key_len = cparm->bmc_key_len ;
	memcpy(largs->bmc_key, cparm->bmc_key, cparm->bmc_key_len);
	largs->bmc_key_set = 1;
    }
    largs->max_outstanding_msgs = lan->max_outstanding_msg_count;
    return args;

 out_err:
    lan_free_args(args);
    return NULL;
}

static int
lan_connect_args(ipmi_args_t  *args,
		 os_handler_t *handlers,
		 void         *user_data,
		 ipmi_con_t   **con)
{
    lan_args_t       *largs = _ipmi_args_get_extra_data(args);
    int              i;
    ipmi_lanp_parm_t parms[12];
    int              rv;

    i = 0;
    parms[i].parm_id = IPMI_LANP_PARMID_ADDRS;
    parms[i].parm_data = largs->str_addr;
    parms[i].parm_data_len = largs->num_addr;
    i++;
    parms[i].parm_id = IPMI_LANP_PARMID_PORTS;
    parms[i].parm_data = largs->str_port;
    parms[i].parm_data_len = largs->num_addr;
    i++;
    parms[i].parm_id = IPMI_LANP_PARMID_AUTHTYPE;
    parms[i].parm_val = largs->authtype;
    i++;
    parms[i].parm_id = IPMI_LANP_PARMID_PRIVILEGE;
    parms[i].parm_val = largs->privilege;
    i++;
    if (largs->username_set) {
	parms[i].parm_id = IPMI_LANP_PARMID_USERNAME;
	parms[i].parm_data = largs->username;
	parms[i].parm_data_len = largs->username_len;
	i++;
    }
    if (largs->password_set) {
	parms[i].parm_id = IPMI_LANP_PARMID_PASSWORD;
	parms[i].parm_data = largs->password;
	parms[i].parm_data_len = largs->password_len;
	i++;
    }
    parms[i].parm_id = IPMI_LANP_AUTHENTICATION_ALGORITHM;
    parms[i].parm_val = largs->auth_alg;
    i++;
    parms[i].parm_id = IPMI_LANP_INTEGRITY_ALGORITHM;
    parms[i].parm_val = largs->integ_alg;
    i++;
    parms[i].parm_id = IPMI_LANP_CONFIDENTIALITY_ALGORITHM;
    parms[i].parm_val = largs->conf_alg;
    i++;
    parms[i].parm_id = IPMI_LANP_NAME_LOOKUP_ONLY;
    parms[i].parm_val = largs->name_lookup_only;
    i++;
    if (largs->bmc_key_set) {
	parms[i].parm_id = IPMI_LANP_BMC_KEY;
	parms[i].parm_data = largs->bmc_key;
	parms[i].parm_data_len = largs->bmc_key_len;
	i++;
    }
    parms[i].parm_id = IPMI_LANP_MAX_OUTSTANDING_MSG_COUNT;
    parms[i].parm_val = largs->max_outstanding_msgs;
    i++;
    rv = ipmi_lanp_setup_con(parms, i, handlers, user_data, con);
    if (!rv)
	(*con)->hacks = largs->hacks;
    return rv;
}

static int
get_str_val(char **dest, const char *data, int *is_set, unsigned int *len)
{
    char *rval = NULL;
    if (!dest)
	return 0;
    if (is_set && (! *is_set)) {
	*dest = NULL;
	return 0;
    }
    if (data) {
	if (len) {
	    rval = ipmi_mem_alloc(*len+1);
	    if (!rval)
		return ENOMEM;
	    memcpy(rval, data, *len);
	    rval[*len] = '\0';
	} else {
	    rval = ipmi_strdup(data);
	    if (!rval)
		return ENOMEM;
	}
	*dest = rval;
    } else {
	*dest = NULL;
    }
    return 0;
}

static int
get_enum_val(int argnum, char **dest, int data, const char ***rrange)
{
    char       *rval = NULL;
    const int  *values;
    const char **range;
    int        i;

    if (rrange)
	*rrange = lan_argnum_info[argnum].range;

    if (!dest)
	return 0;

    values = lan_argnum_info[argnum].values;
    range = lan_argnum_info[argnum].range;
    for (i=0; range[i]; i++) {
	if (values[i] == data) {
	    rval = ipmi_strdup(lan_argnum_info[argnum].range[i]);
	    if (!rval)
		return ENOMEM;
	    *dest = rval;
	    return 0;
	}
    }
    return EINVAL;
}

static int
get_bool_val(char **dest, int data, unsigned int bit)
{
    char *rval = NULL;

    if (!dest)
	return 0;
    if (data & bit)
	rval = ipmi_strdup("true");
    else
	rval = ipmi_strdup("false");
    if (!rval)
	return ENOMEM;
    *dest = rval;
    return 0;
}

static int
get_int_val(char **dest, int data)
{
    char *rval = NULL;
    int len;

    if (!dest)
	return 0;
    len = snprintf(NULL, 0, "%d", data);
    rval = malloc(len+1);
    if (!rval)
	return ENOMEM;
    snprintf(rval, len+1, "%d", data);
    *dest = rval;
    return 0;
}

static const char *
lan_args_get_type(ipmi_args_t *args)
{
    return "lan";
}

static int
lan_args_get_val(ipmi_args_t  *args,
		 unsigned int argnum,
		 const char   **name,
		 const char   **type,
		 const char   **help,
		 char         **value,
		 const char   ***range)
{
    lan_args_t *largs = _ipmi_args_get_extra_data(args);
    int        rv;

    switch(argnum) {
    case 0:
	rv = get_str_val(value, largs->str_addr[0], NULL, NULL);
	break;

    case 1:
	rv = get_str_val(value, largs->str_port[0], NULL, NULL);
	break;

    case 2:
	rv = get_str_val(value, largs->str_addr[1], NULL, NULL);
	break;

    case 3:
	rv = get_str_val(value, largs->str_port[1], NULL, NULL);
	break;

    case 4:
	rv = get_enum_val(argnum, value, largs->authtype, range);
	break;

    case 5:
	rv = get_enum_val(argnum, value, largs->privilege, range);
	break;

    case 6:
	rv = get_str_val(value, largs->username, &largs->username_set,
			 &largs->username_len);
	break;

    case 7:
	rv = get_str_val(value, largs->password, &largs->password_set,
			 &largs->password_len);
	break;

    case 8:
	rv = get_enum_val(argnum, value, largs->auth_alg, range);
	break;

    case 9:
	rv = get_enum_val(argnum, value, largs->integ_alg, range);
	break;

    case 10:
	rv = get_enum_val(argnum, value, largs->conf_alg, range);
	break;

    case 11:
	rv = get_bool_val(value, largs->name_lookup_only, 1);
	break;

    case 12:
	rv = get_str_val(value, largs->bmc_key, &largs->bmc_key_set,
			 &largs->bmc_key_len);
	break;

    case 13:
	rv = get_bool_val(value, largs->hacks,
			  IPMI_CONN_HACK_RAKP3_WRONG_ROLEM);
	break;

    case 14:
	rv = get_bool_val(value, largs->hacks,
			  IPMI_CONN_HACK_RMCPP_INTEG_SIK);
	break;

    case 15:
	rv = get_int_val(value, largs->max_outstanding_msgs);
	break;

    default:
	return E2BIG;
    }

    if (rv)
	return rv;

    if (name)
	*name = lan_argnum_info[argnum].name;
    if (type)
	*type = lan_argnum_info[argnum].type;
    if (help)
	*help = lan_argnum_info[argnum].help;

    return 0;
}

static int
set_str_val(char **dest, const char *value, int null_ok, int *is_set,
	    unsigned int *len, unsigned int max_len)
{
    char *rval;

    if (! value) {
	if (! null_ok)
	    return EINVAL;
	*dest = NULL;
	if (is_set)
	    *is_set = 0;
	return 0;
    }

    if (len) {
	unsigned int nlen = strlen(value);
	if (nlen > max_len)
	    return EINVAL;
	memcpy(*dest, value, nlen);
	*len = nlen;
    } else {
	rval = ipmi_strdup(value);
	if (!rval)
	    return ENOMEM;
	if (*dest)
	    ipmi_mem_free(*dest);
	*dest = rval;
    }
    if (is_set)
	*is_set = 1;
    return 0;
}

static int
set_enum_val(int argnum, unsigned int *dest, const char *value)
{
    const char **range;
    int        i;

    if (! value)
	return EINVAL;

    range = lan_argnum_info[argnum].range;
    for (i=0; range[i]; i++) {
	if (strcmp(range[i], value) == 0) {
	    *dest = lan_argnum_info[argnum].values[i];
	    return 0;
	}
    }
    return EINVAL;
}

static int
set_bool_val(unsigned int *dest, const char *value, unsigned int bit)
{
    if (! value)
	return EINVAL;

    if (strcmp(value, "true") == 0)
	*dest |= bit;
    else if (strcmp(value, "false") == 0)
	*dest &= ~bit;
    else
	return EINVAL;
    return 0;
}

static int
set_uint_val(unsigned int *dest, const char *value)
{
    int val;
    char *end;

    if (! value)
	return EINVAL;
    if (*value == '\0')
	return EINVAL;

    val = strtoul(value, &end, 0);
    if (*end != '\0')
	return EINVAL;
    *dest = val;
    return 0;
}

static int
lan_args_set_val(ipmi_args_t  *args,
		 unsigned int argnum,
		 const char   *name,
		 const char   *value)
{
    lan_args_t   *largs = _ipmi_args_get_extra_data(args);
    int          rv;
    char         *sval;

    if (name) {
	int i;
	for (i=0; lan_argnum_info[i].name; i++) {
	    if (strcmp(lan_argnum_info[i].name, name) == 0)
		break;
	}
	if (! lan_argnum_info[i].name)
	    return EINVAL;
	argnum = i;
    }

    switch (argnum) {
    case 0:
	rv = set_str_val(&(largs->str_addr[0]), value, 0, NULL, NULL, 0);
	if (!rv && (largs->num_addr == 0))
	    largs->num_addr = 1;
	break;

    case 1:
	rv = set_str_val(&(largs->str_port[0]), value, 1, NULL, NULL, 0);
	break;

    case 2:
	rv = set_str_val(&(largs->str_addr[1]), value, 1, NULL, NULL, 0);
	if (!rv) {
	    if (largs->str_addr[1]) {
		if (largs->num_addr < 2)
		    largs->num_addr = 2;
	    } else {
		if (largs->str_addr[0])
		    largs->num_addr = 1;
		else
		    largs->num_addr = 0;
	    }
	}
	break;

    case 3:
	rv = set_str_val(&(largs->str_port[1]), value, 1, NULL, NULL, 0);
	break;

    case 4:
	rv = set_enum_val(argnum, &largs->authtype, value);
	break;

    case 5:
	rv = set_enum_val(argnum, &largs->privilege, value);
	break;

    case 6:
	sval = largs->username;
	rv = set_str_val(&sval, value, 1, &largs->username_set,
			 &largs->username_len, 16);
	break;

    case 7:
	sval = largs->password;
	rv = set_str_val(&sval, value, 1, &largs->password_set,
			 &largs->password_len, 20);
	break;

    case 8:
	rv = set_enum_val(argnum, &largs->auth_alg, value);
	break;

    case 9:
	rv = set_enum_val(argnum, &largs->integ_alg, value);
	break;

    case 10:
	rv = set_enum_val(argnum, &largs->conf_alg, value);
	break;

    case 11:
	rv = set_bool_val(&largs->name_lookup_only, value, 1);
	break;

    case 12:
	sval = largs->bmc_key;
	rv = set_str_val(&sval, value, 1, &largs->bmc_key_set,
			 &largs->bmc_key_len, 20);
	break;

    case 13:
	rv = set_bool_val(&largs->hacks, value,
			  IPMI_CONN_HACK_RAKP3_WRONG_ROLEM);
	break;

    case 14:
	rv = set_bool_val(&largs->hacks, value,
			  IPMI_CONN_HACK_RMCPP_INTEG_SIK);
	break;

    case 15:
	rv = set_uint_val(&largs->max_outstanding_msgs, value);
	break;

    default:
	rv = E2BIG;
    }

    return rv;
}

static ipmi_args_t *
lan_args_copy(ipmi_args_t *args)
{
    ipmi_args_t *nargs;
    lan_args_t  *largs = _ipmi_args_get_extra_data(args);
    lan_args_t  *nlargs;

    nargs = lan_con_alloc_args();
    if (!nargs)
	return NULL;
    nlargs = _ipmi_args_get_extra_data(nargs);
    *nlargs = *largs;

    nlargs->str_addr[0] = NULL;
    nlargs->str_addr[1] = NULL;
    nlargs->str_port[0] = NULL;
    nlargs->str_port[1] = NULL;

    nlargs->str_addr[0] = ipmi_strdup(largs->str_addr[0]);
    if (! nlargs->str_addr[0])
	goto out_err;
    nlargs->str_addr[1] = ipmi_strdup(largs->str_addr[1]);
    if (! nlargs->str_addr[1])
	goto out_err;
    nlargs->str_port[0] = ipmi_strdup(largs->str_port[0]);
    if (! nlargs->str_port[0])
	goto out_err;
    nlargs->str_port[1] = ipmi_strdup(largs->str_port[1]);
    if (! nlargs->str_port[1])
	goto out_err;
    
    return nargs;

 out_err:
    lan_free_args(nargs);
    return NULL;
}

static int
lan_args_validate(ipmi_args_t *args, int *argnum)
{
    return 1; /* Can't be invalid */
}

static void
lan_args_free_val(ipmi_args_t *args, char *value)
{
    ipmi_mem_free(value);
}

#define CHECK_ARG \
    do { \
        if (*curr_arg >= arg_count) { \
	    rv = EINVAL; \
	    goto out_err; \
        } \
    } while(0)

static int
lan_parse_args(int         *curr_arg,
	       int         arg_count,
	       char        * const *args,
	       ipmi_args_t **iargs)
{
    int         rv;
    ipmi_args_t *p = NULL;
    lan_args_t  *largs;
    int         i;
    int         len;

    CHECK_ARG;

    p = lan_con_alloc_args();
    if (!p)
	return ENOMEM;

    largs = _ipmi_args_get_extra_data(p);
    largs->num_addr = 1;

    while (*curr_arg < arg_count) {
	if (args[*curr_arg][0] != '-') {
	    break;
	}

	if (strcmp(args[*curr_arg], "-U") == 0) {
	    (*curr_arg)++; CHECK_ARG;
	    len = strlen(args[*curr_arg]);
	    if (len > 16)
		len = 16;
	    memcpy(largs->username, args[*curr_arg], len);
	    largs->username_set = 1;
	    largs->username_len = len;
	} else if (strcmp(args[*curr_arg], "-P") == 0) {
	    (*curr_arg)++; CHECK_ARG;
	    len = strlen(args[*curr_arg]);
	    if (len > 20)
		len = 20;
	    memcpy(largs->password, args[*curr_arg], len);
	    largs->password_set = 1;
	    largs->password_len = len;
	} else if (strcmp(args[*curr_arg], "-H") == 0) {
	    (*curr_arg)++; CHECK_ARG;
	    if (strcmp(args[*curr_arg], "intelplus") == 0)
		largs->hacks |= IPMI_CONN_HACK_RAKP3_WRONG_ROLEM;
	    else if (strcmp(args[*curr_arg], "rakp3_wrong_rolem") == 0)
		largs->hacks |= IPMI_CONN_HACK_RAKP3_WRONG_ROLEM;
	    else if (strcmp(args[*curr_arg], "rmcpp_integ_sik") == 0)
		largs->hacks |= IPMI_CONN_HACK_RMCPP_INTEG_SIK;
	    /* Ignore unknown hacks. */
	} else if (strcmp(args[*curr_arg], "-s") == 0) {
	    largs->num_addr = 2;
	} else if (strcmp(args[*curr_arg], "-A") == 0) {
	    (*curr_arg)++; CHECK_ARG;
	    if (strcmp(args[*curr_arg], "none") == 0) {
		largs->authtype = IPMI_AUTHTYPE_NONE;
	    } else if (strcmp(args[*curr_arg], "md2") == 0) {
		largs->authtype = IPMI_AUTHTYPE_MD2;
	    } else if (strcmp(args[*curr_arg], "md5") == 0) {
		largs->authtype = IPMI_AUTHTYPE_MD5;
	    } else if (strcmp(args[*curr_arg], "straight") == 0) {
		largs->authtype = IPMI_AUTHTYPE_STRAIGHT;
	    } else if (strcmp(args[*curr_arg], "rmcp+") == 0) {
		largs->authtype = IPMI_AUTHTYPE_RMCP_PLUS;
	    } else {
		rv = EINVAL;
		goto out_err;
	    }
	} else if (strcmp(args[*curr_arg], "-L") == 0) {
	    (*curr_arg)++; CHECK_ARG;

	    if (strcmp(args[*curr_arg], "callback") == 0) {
		largs->privilege = IPMI_PRIVILEGE_CALLBACK;
	    } else if (strcmp(args[*curr_arg], "user") == 0) {
		largs->privilege = IPMI_PRIVILEGE_USER;
	    } else if (strcmp(args[*curr_arg], "operator") == 0) {
		largs->privilege = IPMI_PRIVILEGE_OPERATOR;
	    } else if (strcmp(args[*curr_arg], "admin") == 0) {
		largs->privilege = IPMI_PRIVILEGE_ADMIN;
	    } else if (strcmp(args[*curr_arg], "oem") == 0) {
		largs->privilege = IPMI_PRIVILEGE_OEM;
	    } else {
		rv = EINVAL;
		goto out_err;
	    }
	} else if (strcmp(args[*curr_arg], "-p") == 0) {
	    (*curr_arg)++; CHECK_ARG;
	    largs->str_port[0] = ipmi_strdup(args[*curr_arg]);
	    if (largs->str_port[0] == NULL) {
		rv = ENOMEM;
		goto out_err;
	    }
	} else if (strcmp(args[*curr_arg], "-p2") == 0) {
	    (*curr_arg)++; CHECK_ARG;
	    largs->str_port[1] = ipmi_strdup(args[*curr_arg]);
	    if (largs->str_port[1] == NULL) {
		rv = ENOMEM;
		goto out_err;
	    }
	} else if (strcmp(args[*curr_arg], "-Ra") == 0) {
	    (*curr_arg)++; CHECK_ARG;

	    if (strcmp(args[*curr_arg], "bmcpick") == 0) {
		largs->auth_alg = IPMI_LANP_AUTHENTICATION_ALGORITHM_BMCPICK;
	    } else if (strcmp(args[*curr_arg], "rakp_none") == 0) {
		largs->auth_alg = IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_NONE;
	    } else if (strcmp(args[*curr_arg], "rakp_hmac_sha1") == 0) {
		largs->auth_alg = IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_HMAC_SHA1;
	    } else if (strcmp(args[*curr_arg], "rakp_hmac_md5") == 0) {
		largs->auth_alg = IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_HMAC_MD5;
	    } else {
		rv = EINVAL;
		goto out_err;
	    }
	} else if (strcmp(args[*curr_arg], "-Ri") == 0) {
	    (*curr_arg)++; CHECK_ARG;

	    if (strcmp(args[*curr_arg], "bmcpick") == 0) {
		largs->integ_alg = IPMI_LANP_INTEGRITY_ALGORITHM_BMCPICK;
	    } else if (strcmp(args[*curr_arg], "none") == 0) {
		largs->integ_alg = IPMI_LANP_INTEGRITY_ALGORITHM_NONE;
	    } else if (strcmp(args[*curr_arg], "hmac_sha1") == 0) {
		largs->integ_alg = IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_SHA1_96;
	    } else if (strcmp(args[*curr_arg], "hmac_md5") == 0) {
		largs->integ_alg = IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_MD5_128;
	    } else if (strcmp(args[*curr_arg], "md5") == 0) {
		largs->integ_alg = IPMI_LANP_INTEGRITY_ALGORITHM_MD5_128;
	    } else {
		rv = EINVAL;
		goto out_err;
	    }
	} else if (strcmp(args[*curr_arg], "-Rc") == 0) {
	    (*curr_arg)++; CHECK_ARG;

	    if (strcmp(args[*curr_arg], "bmcpick") == 0) {
		largs->conf_alg = IPMI_LANP_CONFIDENTIALITY_ALGORITHM_BMCPICK;
	    } else if (strcmp(args[*curr_arg], "none") == 0) {
		largs->conf_alg = IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE;
	    } else if (strcmp(args[*curr_arg], "aes_cbc_128") == 0) {
		largs->conf_alg = IPMI_LANP_CONFIDENTIALITY_ALGORITHM_AES_CBC_128;
	    } else if (strcmp(args[*curr_arg], "xrc4_128") == 0) {
		largs->conf_alg = IPMI_LANP_CONFIDENTIALITY_ALGORITHM_xRC4_128;
	    } else if (strcmp(args[*curr_arg], "xrc4_40") == 0) {
		largs->conf_alg = IPMI_LANP_CONFIDENTIALITY_ALGORITHM_xRC4_40;
	    } else {
		rv = EINVAL;
		goto out_err;
	    }
	} else if (strcmp(args[*curr_arg], "-Rl") == 0) {
	    largs->name_lookup_only = 0;
	} else if (strcmp(args[*curr_arg], "-Rk") == 0) {
	    (*curr_arg)++; CHECK_ARG;
	    len = strlen(args[*curr_arg]);
	    if (len > 20)
		len = 20;
	    memcpy(largs->bmc_key, args[*curr_arg], len);
	    largs->bmc_key_set = 1;
	    largs->bmc_key_len = len;
	} else if (strcmp(args[*curr_arg], "-M") == 0) {
	    char *end;
	    int val;
	    (*curr_arg)++; CHECK_ARG;
	    if (args[*curr_arg][0] == '\0') {
		rv = EINVAL;
		goto out_err;
	    }
	    val = strtol(args[*curr_arg], &end, 0);
	    if (*end != '\0') {
		rv = EINVAL;
		goto out_err;
	    }
	    largs->max_outstanding_msgs = val;
	}
	(*curr_arg)++;
    }

    for (i=0; i<largs->num_addr; i++) {
	CHECK_ARG;
	largs->str_addr[i] = ipmi_strdup(args[*curr_arg]);
	if (largs->str_addr[i] == NULL) {
	    rv = ENOMEM;
	    goto out_err;
	}
	(*curr_arg)++;
	if (! largs->str_port[i]) {
	    largs->str_port[i] = ipmi_strdup("623");
	    if (largs->str_port[i] == NULL) {
		rv = ENOMEM;
		goto out_err;
	    }
	}
    }

    *iargs = p;
    return 0;

 out_err:
    if (p)
	ipmi_free_args(p);
    return rv;
}

static const char *
lan_parse_help(void)
{
    return
	"\n"
	" lan [-U <username>] [-P <password>] [-p[2] port] [-A <authtype>]\n"
	"     [-L <privilege>] [-s] [-Ra <auth alg>] [-Ri <integ alg>]\n"
	"     [-Rc <conf algo>] [-Rl] [-Rk <bmc key>] [-H <hackname>]\n"
	"     [-M <max outstanding msgs>] <host1> [<host2>]\n"
	"If -s is supplied, then two host names are taken (the second port\n"
	"may be specified with -p2).  Otherwise, only one hostname is\n"
	"taken.  The defaults are an empty username and password (anonymous),\n"
	"port 623, admin privilege, and authtype defaulting to the most\n"
	"secure one available.\n"
	"privilege is one of: callback, user, operator, admin, or oem.  These\n"
	"select the specific commands that are available to the connection.\n"
	"Higher privileges (ones further to the right in the above list) have\n"
	"more commands available to them.\n"
	"authtype is one of the following: rmcp+, md5, md2, straight, or none.\n"
	"Setting this to anything but rmcp+ forces normal rmcp\n"
	"authentication.  By default the most secure method available is\n"
	"chosen, in the order given above.\n"
	"For RMCP+ connections, the authentication algorithms supported (-Ra)\n"
	"are: bmcpick, rakp_none, rakp_hmac_sha1, and rakp_hmac_md5.  The\n"
	"integrity algorithms (-Ri) supported are: bmcpick, none, hmac_sha1,\n"
	"hmac_md5, and md5.  The confidentiality algorithms (-Rc) are: bmcpick,\n"
	"aes_cbc_128, xrc4_128, and xrc_40.  The defaults are\n"
	"rackp_hmac_sha1, hmac_sha1, and aes_cb_128.  -Rl turns on lookup up\n"
	"names by the name and the privilege level (allowing the same name with\n"
	"different privileges and different passwords), the default is straight\n"
	"name lookup.  -Rk sets the BMC key, needed if the system does two-key\n"
	"lookups.  The -M option sets the maximum outstanding messages.\n"
	"The default is 2, ranges 1-63.\n"
	"The -H option enables certain hacks for broken platforms.  This may\n"
	"be listed multiple times to enable multiple hacks.  The currently\n"
	"available hacks are:\n"
	"  intelplus - For Intel platforms that have broken RMCP+.\n"
	"  rakp3_wrong_rolem - For systems that truncate role(m) in the RAKP3"
	" msg.\n"
	"  rmcpp_integ_sik - For systems that use SIK instead of K(1) for"
	" integrity.";
}

static ipmi_args_t *
lan_con_alloc_args(void)
{
    ipmi_args_t *args;
    lan_args_t  *largs;
    args = _ipmi_args_alloc(lan_free_args, lan_connect_args,
			    lan_args_get_val, lan_args_set_val,
			    lan_args_copy, lan_args_validate,
			    lan_args_free_val, lan_args_get_type,
			    sizeof(lan_args_t));
    if (!args)
	return NULL;

    largs = _ipmi_args_get_extra_data(args);

    /* Set defaults */
    largs->authtype = IPMI_AUTHTYPE_DEFAULT;
    largs->privilege = IPMI_PRIVILEGE_ADMIN;
    largs->conf_alg = most_secure_lanp_conf();
    largs->integ_alg = most_secure_lanp_integ();
    largs->auth_alg = most_secure_lanp_auth();
    largs->name_lookup_only = 1;
    largs->max_outstanding_msgs = DEFAULT_MAX_OUTSTANDING_MSG_COUNT;
    /* largs->hacks = IPMI_CONN_HACK_RAKP3_WRONG_ROLEM; */
    return args;
}

static ipmi_con_setup_t *lan_setup;

int
_ipmi_lan_init(os_handler_t *os_hnd)
{
    int rv;
    int i;

    rv = ipmi_create_global_lock(&lan_list_lock);
    if (rv)
	return rv;

    rv = ipmi_create_global_lock(&fd_list_lock);
    if (rv)
	return rv;
    memset(&fd_list, 0, sizeof(fd_list));
    fd_list.next = &fd_list;
    fd_list.prev = &fd_list;
    fd_list.cons_in_use = MAX_CONS_PER_FD;

#ifdef PF_INET6
    rv = ipmi_create_global_lock(&fd6_list_lock);
    if (rv)
	return rv;
    memset(&fd6_list, 0, sizeof(fd6_list));
    fd6_list.next = &fd6_list;
    fd6_list.prev = &fd6_list;
    fd6_list.cons_in_use = MAX_CONS_PER_FD;
#endif

    for (i=0; i<LAN_HASH_SIZE; i++) {
	lan_list[i].next = &(lan_list[i]);
	lan_list[i].prev = &(lan_list[i]);
	lan_list[i].lan = NULL;
	lan_ip_list[i].next = &(lan_ip_list[i]);
	lan_ip_list[i].prev = &(lan_ip_list[i]);
	lan_ip_list[i].lan = NULL;
    }

    rv = ipmi_create_global_lock(&lan_payload_lock);
    if (rv)
	return rv;

    rv = ipmi_create_global_lock(&lan_auth_lock);
    if (rv)
	return rv;

    lan_setup = _ipmi_alloc_con_setup(lan_parse_args, lan_parse_help,
				      lan_con_alloc_args);
    if (! lan_setup)
	return ENOMEM;

    rv = _ipmi_register_con_type("lan", lan_setup);
    if (rv)
	return rv;

    lan_os_hnd = os_hnd;

    return 0;
}

void
_ipmi_lan_shutdown(void)
{
    _ipmi_unregister_con_type("lan", lan_setup);
    _ipmi_free_con_setup(lan_setup);
    lan_setup = NULL;

    if (lan_list_lock) {
	ipmi_destroy_lock(lan_list_lock);
	lan_list_lock = NULL;
    }
    if (lan_payload_lock) {
	ipmi_destroy_lock(lan_payload_lock);
	lan_payload_lock = NULL;
    }
    while (oem_payload_list) {
	payload_entry_t *e = oem_payload_list;
	oem_payload_list = e->next;
	ipmi_mem_free(e);
    }
    if (lan_auth_lock) {
	ipmi_destroy_lock(lan_auth_lock);
	lan_auth_lock = NULL;
    }
    while (oem_auth_list) {
	auth_entry_t *e = oem_auth_list;
	oem_auth_list = e->next;
	ipmi_mem_free(e);
    }
    while (oem_conf_list) {
	conf_entry_t *e = oem_conf_list;
	oem_conf_list = e->next;
	ipmi_mem_free(e);
    }
    while (oem_integ_list) {
	integ_entry_t *e = oem_integ_list;
	oem_integ_list = e->next;
	ipmi_mem_free(e);
    }
    if (fd_list_lock) {
	ipmi_destroy_lock(fd_list_lock);
	fd_list_lock = NULL;
    }
    while (fd_list.next != &fd_list) {
	lan_fd_t *e = fd_list.next;
	e->next->prev = e->prev;
	e->prev->next = e->next;
	lan_os_hnd->remove_fd_to_wait_for(lan_os_hnd, e->fd_wait_id);
	close(e->fd);
	ipmi_destroy_lock(e->con_lock);
	ipmi_mem_free(e);
    }
    while (fd_free_list) {
	lan_fd_t *e = fd_free_list;
	fd_free_list = e->next;
	ipmi_destroy_lock(e->con_lock);
	ipmi_mem_free(e);
    }
#ifdef PF_INET6
    if (fd6_list_lock) {
	ipmi_destroy_lock(fd6_list_lock);
	fd6_list_lock = NULL;
    }
    while (fd6_list.next != &fd6_list) {
	lan_fd_t *e = fd6_list.next;
	e->next->prev = e->prev;
	e->prev->next = e->next;
	lan_os_hnd->remove_fd_to_wait_for(lan_os_hnd, e->fd_wait_id);
	close(e->fd);
	ipmi_destroy_lock(e->con_lock);
	ipmi_mem_free(e);
    }
    while (fd6_free_list) {
	lan_fd_t *e = fd6_free_list;
	fd6_free_list = e->next;
	ipmi_destroy_lock(e->con_lock);
	ipmi_mem_free(e);
    }
#endif
    lan_os_hnd = NULL;
}
