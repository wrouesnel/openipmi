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

/* Timeout to wait for IPMI responses, in microseconds. */
#define LAN_RSP_TIMEOUT 1000000

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
    char                  data[IPMI_MAX_MSG_LENGTH];
    ipmi_ll_rsp_handler_t rsp_handler;
    ipmi_msgi_t           *rsp_item;

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
    int           name_lookup_only;
    unsigned char bmc_key[IPMI_PASSWORD_MAX];
    unsigned int  bmc_key_len;
} lan_conn_parms_t;

typedef struct lan_link_s lan_link_t;
struct lan_link_s
{
    lan_link_t *next, *prev;
    lan_data_t *lan;
};

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
    int                        fd;

    unsigned char              slave_addr;
    int                        is_active;

    /* Have we already been started? */
    int                        started;

    /* Protects modifiecations to ip_working, curr_ip_addr, RMCP
       sequence numbers, the con_change_handler, and other
       connection-related data.  Note that if the seq_num_lock must
       also be held, it must be locked before this lock.  */
    ipmi_lock_t                *ip_lock;

    /* IP address failure detection and handling. */
    int                        curr_ip_addr;
    int                        ip_working[MAX_IP_ADDR];
    unsigned int               consecutive_ip_failures[MAX_IP_ADDR];
    struct timeval             ip_failure_time[MAX_IP_ADDR];
    unsigned int               num_ip_addr;
    unsigned int               num_sends;

    /* If 0, we don't have a connection to the BMC right now. */
    int                        connected;

    /* If 0, we have not yet initialized */
    int                        initialized;

    /* If 0, the OEM handlers have not been called. */
    int                        oem_conn_handlers_called;

    /* We keep a session on each LAN connection.  I don't think all
       systems require that, but it's safer. */

    /* For both RMCP and RMCP+ */
    unsigned char              working_authtype[MAX_IP_ADDR];
    uint32_t                   session_id[MAX_IP_ADDR];
    uint32_t                   outbound_seq_num[MAX_IP_ADDR];
    uint32_t                   inbound_seq_num[MAX_IP_ADDR];
    uint16_t                   recv_msg_map[MAX_IP_ADDR];

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
    uint32_t                   unauth_out_seq_num[MAX_IP_ADDR];
    uint32_t                   unauth_in_seq_num[MAX_IP_ADDR];
    uint16_t                   unauth_recv_msg_map[MAX_IP_ADDR];
    unsigned char              working_integ[MAX_IP_ADDR];
    unsigned char              working_conf[MAX_IP_ADDR];
    uint32_t                   mgsys_session_id[MAX_IP_ADDR];
    ipmi_rmcpp_auth_t          ainfo[MAX_IP_ADDR];

    /* Used to hold the session id before the connection is up. */
    uint32_t                   precon_session_id[MAX_IP_ADDR];
    uint32_t                   precon_mgsys_session_id[MAX_IP_ADDR];

    ipmi_rmcpp_confidentiality_t *conf_info[MAX_IP_ADDR];
    void                         *conf_data[MAX_IP_ADDR];

    ipmi_rmcpp_integrity_t       *integ_info[MAX_IP_ADDR];
    void                         *integ_data[MAX_IP_ADDR];


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

    unsigned int               retries;
    os_hnd_timer_id_t          *timer;

    os_hnd_fd_id_t             *fd_wait_id;
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
    lan_link_t ip_link[MAX_IP_ADDR];
};


/************************************************************************
 *
 * Authentication and encryption information and functions.
 *
 ***********************************************************************/
extern ipmi_payload_t _ipmi_payload;

static int
open_format_msg(ipmi_con_t    *ipmi,
		ipmi_addr_t   *addr,
		unsigned int  addr_len,
		ipmi_msg_t    *msg,
		unsigned char *out_data,
		unsigned int  *out_data_len,
		int           *out_of_session,
		unsigned char seq)
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
		     "Dropped message because too small(7)");
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

static ipmi_payload_t open_payload =
{ open_format_msg, open_get_recv_seq, open_handle_recv,
  open_handle_recv_async };

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
    return ainfo->lan->precon_session_id[ainfo->addr_num];
}

uint32_t
ipmi_rmcpp_auth_get_mgsys_session_id(ipmi_rmcpp_auth_t *ainfo)
{
    return ainfo->lan->precon_mgsys_session_id[ainfo->addr_num];
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

/*
 * We keep two hash tables, one by IP address and one by connection
 * address.
 */
#define LAN_HASH_SIZE 256
#define LAN_HASH_SHIFT 6
static ipmi_lock_t *lan_list_lock = NULL;
static lan_link_t lan_list[LAN_HASH_SIZE];
static lan_link_t lan_ip_list[LAN_HASH_SIZE];

static int
hash_lan(ipmi_con_t *ipmi)
{
    int idx;

    idx = (((unsigned long) ipmi)
	   >> (sizeof(unsigned long) >> LAN_HASH_SHIFT));
    idx %= LAN_HASH_SIZE;
    return idx;
}

static int
hash_lan_addr(struct sockaddr *addr)
{
    int idx;
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
    int        idx;
    lan_link_t *head;
    int        i;

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
	lan->ip_link[i].lan = lan;
	lan->ip_link[i].next = head;
	lan->ip_link[i].prev = head->prev;
	head->prev->next = &lan->ip_link[i];
	head->prev = &lan->ip_link[i];
    }
    ipmi_unlock(lan_list_lock);
}

/* Must be called with the lan list lock held. */
static void
lan_remove_con_nolock(lan_data_t *lan)
{
    int i;
    if (!lan->link.lan)
	/* Hasn't been initialized. */
	return;
    lan->link.prev->next = lan->link.next;
    lan->link.next->prev = lan->link.prev;
    lan->link.lan = NULL;
    for (i=0; i<lan->cparm.num_ip_addr; i++) {
	lan->ip_link[i].prev->next = lan->link.next;
	lan->ip_link[i].next->prev = lan->link.prev;
	lan->ip_link[i].lan = NULL;
    }
}

static lan_data_t *
lan_find_con(ipmi_con_t *ipmi)
{
    int        idx;
    lan_link_t *l;

    ipmi_lock(lan_list_lock);
    idx = hash_lan(ipmi);
    l = lan_list[idx].next;
    while (l->lan) {
	if (l->lan->ipmi == ipmi)
	    break;
	l = l->next;
    }
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
open_lan_fd(int pf_family)
{
    int fd;

    fd = socket(pf_family, SOCK_DGRAM, IPPROTO_UDP);

    /* Bind is not necessary, we don't care what port we are. */

    return fd;
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

    rv = ipmi_auths[lan->working_authtype[addr_num]]
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

    rv = ipmi_auths[lan->working_authtype[addr_num]]
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
		 unsigned char *oem_iana, unsigned int oem_payload_id)
{
    unsigned char *tmsg;
    int           rv;
    unsigned int  header_used;
    unsigned char *data;
    unsigned int  payload_len;
    uint32_t      *seqp;

    if (in_session
	&& (lan->working_conf[addr_num]
	    != IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE))
    {
	/* Note: This may encrypt the data, the old data will be lost. */
	rv = lan->conf_info[addr_num]->conf_encrypt(lan->ipmi,
						    lan->conf_data[addr_num],
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
    data[4] = lan->working_authtype[addr_num];
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
	if (lan->working_conf[addr_num]
	    != IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE)
	{
	    data[5] |= 0x80;
	}
	if (lan->working_integ[addr_num] != IPMI_LANP_INTEGRITY_ALGORITHM_NONE)
	{
	    seqp = &(lan->outbound_seq_num[addr_num]);
	    data[5] |= 0x40;
	} else {
	    seqp = &(lan->unauth_out_seq_num[addr_num]);
	}
	ipmi_set_uint32(tmsg, lan->mgsys_session_id[addr_num]);
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

    if (in_session
	&& (lan->working_integ[addr_num]
	    != IPMI_LANP_INTEGRITY_ALGORITHM_NONE))
    {
	unsigned int orig_data_len = *data_len;
	rv = lan->integ_info[addr_num]->integ_pad(lan->ipmi,
						  lan->integ_data[addr_num],
						  data, data_len,
						  max_data_len);
	if (rv)
	    return rv;
	payload_len += *data_len - orig_data_len;
    }

    /* Now that we have all the padding in, we can add the length. */
    ipmi_set_uint16(tmsg, payload_len);

    if (in_session
	&& (lan->working_integ[addr_num]
	    != IPMI_LANP_INTEGRITY_ALGORITHM_NONE))
    {
	rv = lan->integ_info[addr_num]->integ_add(lan->ipmi,
						  lan->integ_data[addr_num],
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

    if (lan->working_authtype[addr_num] == IPMI_AUTHTYPE_NONE)
	data = *msgdata - 14;
    else
	data = *msgdata - 30;

    data[0] = 6; /* RMCP version 1.0. */
    data[1] = 0;
    data[2] = 0xff;
    data[3] = 0x07;
    data[4] = lan->working_authtype[addr_num];
    ipmi_set_uint32(data+5, lan->outbound_seq_num[addr_num]);
    ipmi_set_uint32(data+9, lan->session_id[addr_num]);

    /* FIXME - need locks for the sequence numbers. */

    /* Increment the outbound number, but make sure it's not zero.  If
       it's already zero, ignore it, we are in pre-setup. */
    if (lan->outbound_seq_num[addr_num] != 0) {
	(lan->outbound_seq_num[addr_num])++;
	if (lan->outbound_seq_num[addr_num] == 0)
	    (lan->outbound_seq_num[addr_num])++;
    }

    if (lan->working_authtype[addr_num] == IPMI_AUTHTYPE_NONE) {
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
lan_send_addr(lan_data_t  *lan,
	      ipmi_addr_t *addr,
	      int         addr_len,
	      ipmi_msg_t  *msg,
	      uint8_t     seq,
	      int         addr_num)
{
    unsigned char  data[IPMI_MAX_LAN_LEN+IPMI_LAN_MAX_HEADER];
    unsigned char  *tmsg;
    int            pos;
    int            rv;
    int            payload_type;
    int            out_of_session = 0;
    ipmi_payload_t *payload = NULL;
    unsigned char  oem_iana[3] = {0, 0, 0};
    unsigned int   oem_payload_id = 0;

    if ((addr->addr_type >= IPMI_RMCPP_ADDR_START)
	&& (addr->addr_type <= IPMI_RMCPP_ADDR_END))
    {
	if (lan->working_authtype[addr_num] != IPMI_AUTHTYPE_RMCP_PLUS)
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
	ipmi_rmcpp_addr_t *addr = (ipmi_rmcpp_addr_t *) addr;
	payload_entry_t *e;

	if (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OEM_EXPLICIT) {
	    memcpy(oem_iana, addr->oem_iana, 3);
	    oem_payload_id = addr->oem_payload_id;
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

    if (lan->working_authtype[addr_num] == IPMI_AUTHTYPE_RMCP_PLUS) {
	rv = rmcpp_format_msg(lan, addr_num,
			      payload_type, !out_of_session,
			      &tmsg, &pos,
			      IPMI_MAX_LAN_LEN, IPMI_LAN_MAX_HEADER,
			      oem_iana, oem_payload_id);
    } else {
	rv = lan15_format_msg(lan, addr_num, &tmsg, &pos);
    }
    if (rv)
	return rv;

    if (DEBUG_RAWMSG) {
	char buf1[32], buf2[32];
	ipmi_log(IPMI_LOG_DEBUG_START, "outgoing seq %d\n addr =",
		 seq);
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

    rv = sendto(lan->fd, tmsg, pos, 0,
		(struct sockaddr *) &(lan->cparm.ip_addr[addr_num]),
		sizeof(sockaddr_ip_t));
    if (rv == -1)
	rv = errno;
    else
	rv = 0;

    return rv;
}

static int
lan_send(lan_data_t  *lan,
	 ipmi_addr_t *addr,
	 int         addr_len,
	 ipmi_msg_t  *msg,
	 uint8_t     seq,
	 int         *send_ip_num)
{
    int curr_ip_addr;

    ipmi_lock(lan->ip_lock);
    if (lan->connected) {
	lan->num_sends++;

	/* We periodically switch between IP addresses, just to make sure
	   they are all operational. */
	if ((lan->num_sends % SENDS_BETWEEN_IP_SWITCHES) == 0) {
	    int addr_num = lan->curr_ip_addr + 1;
	    if (addr_num >= lan->cparm.num_ip_addr)
		addr_num = 0;
	    while (addr_num != lan->curr_ip_addr) {
		if (lan->ip_working[addr_num])
		    break;
		addr_num++;
		if (addr_num >= lan->cparm.num_ip_addr)
		    addr_num = 0;
	    }
	    lan->curr_ip_addr = addr_num;
	}
    } else {
	/* Just rotate between IP addresses if we are not yet connected */
	int addr_num = lan->curr_ip_addr + 1;
	if (addr_num >= lan->cparm.num_ip_addr)
	    addr_num = 0;
	lan->curr_ip_addr = addr_num;
    }
    curr_ip_addr = lan->curr_ip_addr;
    ipmi_unlock(lan->ip_lock);

    *send_ip_num = curr_ip_addr;

    return lan_send_addr(lan, addr, addr_len, msg, seq, curr_ip_addr);
}

typedef struct call_ipmb_change_handler_s
{
    lan_data_t  *lan;
    int          err;
    unsigned int ipmb_addr;
    int          active;
    unsigned int hacks;
} call_ipmb_change_handler_t;

static int
call_ipmb_change_handler(void *cb_data, void *item1, void *item2)
{
    call_ipmb_change_handler_t *info = cb_data;
    ipmi_ll_ipmb_addr_cb       handler = item1;

    handler(info->lan->ipmi, info->err, info->ipmb_addr, info->active,
	    info->hacks, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_ipmb_change_handlers(lan_data_t *lan, int err, unsigned int ipmb_addr,
			  int active, unsigned int hacks)
{
    call_ipmb_change_handler_t info;

    info.lan = lan;
    info.err = err;
    info.ipmb_addr = ipmb_addr;
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
	     unsigned int ipmb,
	     int          active,
	     unsigned int hacks,
	     void         *cb_data)
{
    lan_data_t *lan;

    if (err)
	return;

    lan = (lan_data_t *) ipmi->con_data;

    if ((lan->slave_addr != ipmb) || (lan->is_active != active))  {
	lan->slave_addr = ipmb;
	lan->is_active = active;
	ipmi->hacks = hacks;
	ipmi->ipmb_addr = ipmb;
	call_ipmb_change_handlers(lan, err, ipmb, active, hacks);
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
    int                          i;
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
	    start_up[i] = ! lan->ip_working[i];
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
    /* The IP is already operational, so ignore this. */
    ipmi_lock(lan->ip_lock);
    if ((! lan->ip_working[addr_num]) && new_con) {
	lan->ip_working[addr_num] = 1;

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
    lan->outbound_seq_num[addr_num] = 0;
    lan->inbound_seq_num[addr_num] = 0;
    lan->session_id[addr_num] = 0;
    lan->mgsys_session_id[addr_num] = 0;
    lan->precon_session_id[addr_num] = 0;
    lan->precon_mgsys_session_id[addr_num] = 0;
    lan->recv_msg_map[addr_num] = 0;
    lan->unauth_recv_msg_map[addr_num] = 0;
    lan->working_authtype[addr_num] = 0;
    lan->unauth_out_seq_num[addr_num] = 0;
    lan->unauth_in_seq_num[addr_num] = 0;
    if (lan->conf_data[addr_num]) {
	lan->conf_info[addr_num]->conf_free(lan->ipmi,
					    lan->conf_data[addr_num]);
	lan->conf_data[addr_num] = NULL;
    }
    lan->conf_info[addr_num] = NULL;
    if (lan->integ_data[addr_num]) {
	lan->integ_info[addr_num]->integ_free(lan->ipmi,
					      lan->integ_data[addr_num]);
	lan->integ_data[addr_num] = NULL;
    }
    lan->integ_info[addr_num] = NULL;
    lan->working_conf[addr_num] = IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE;
    lan->working_integ[addr_num] = IPMI_LANP_INTEGRITY_ALGORITHM_NONE;
}

static void
lost_connection(lan_data_t *lan, int addr_num)
{
    int i;

    ipmi_lock(lan->ip_lock);
    if (! lan->ip_working[addr_num]) {
	ipmi_unlock(lan->ip_lock);
	return;
    }

    lan->ip_working[addr_num] = 0;

    reset_session_data(lan, addr_num);

    ipmi_log(IPMI_LOG_WARNING,
	     "%sipmi_lan.c(lost_connection): "
	     "Connection %d to the BMC is down",
	     IPMI_CONN_NAME(lan->ipmi), addr_num);

    if (lan->curr_ip_addr == addr_num) {
	/* Scan to see if any address is operational. */
	for (i=0; i<lan->cparm.num_ip_addr; i++) {
	    if (lan->ip_working[i]) {
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
    int                   ip_num;

    if (!lan_valid_ipmi(ipmi))
	return;

    lan = ipmi->con_data;
    seq = info->seq;

    ipmi_lock(lan->seq_num_lock);

    /* If we were cancelled, just free the data and ignore it. */
    if (info->cancelled)
	goto out;

    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	ipmi_log(IPMI_LOG_DEBUG, "Timeout for seq #%d", seq);

    if (! lan->seq_table[seq].inuse)
	goto out;

    if (DEBUG_RAWMSG) {
	ip_num = lan->seq_table[seq].last_ip_num;
	ipmi_log(IPMI_LOG_DEBUG,
		 "Seq #%d\n"
		 "  addr_type=%d, ip_num=%d, fails=%d\n"
		 "  fail_start_time=%ld.%6.6ld",
		 seq, lan->seq_table[seq].addr.addr_type,
		 lan->seq_table[seq].last_ip_num,
		 lan->consecutive_ip_failures[ip_num],
		 lan->ip_failure_time[ip_num].tv_sec,
		 lan->ip_failure_time[ip_num].tv_usec);
    }

    if (lan->seq_table[seq].addr.addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE)
    {
	/* We only count timeouts on messages to the system interface.
           Otherwise, if we sent a bunch of messages to the IPMB that
           timed out, we might trigger this code accidentally. */
	ip_num = lan->seq_table[seq].last_ip_num;
	ipmi_lock(lan->ip_lock);
	if (lan->ip_working[ip_num]) {
	    if (lan->consecutive_ip_failures[ip_num] == 0) {
		/* Set the time when the connection will be considered
                   failed. */
		gettimeofday(&(lan->ip_failure_time[ip_num]), NULL);
		lan->ip_failure_time[ip_num].tv_sec += IP_FAIL_TIME / 1000000;
		lan->ip_failure_time[ip_num].tv_usec += IP_FAIL_TIME % 1000000;
		if (lan->ip_failure_time[ip_num].tv_usec > 1000000) {
		    lan->ip_failure_time[ip_num].tv_sec += 1;
		    lan->ip_failure_time[ip_num].tv_usec -= 1000000;
		}
		lan->consecutive_ip_failures[ip_num] = 1;
		ipmi_unlock(lan->ip_lock);
	    } else {
		lan->consecutive_ip_failures[ip_num]++;
		if (lan->consecutive_ip_failures[ip_num] >= IP_FAIL_COUNT) {
		    struct timeval now;
		    ipmi_unlock(lan->ip_lock);
		    gettimeofday(&now, NULL);
		    if (cmp_timeval(&now, &lan->ip_failure_time[ip_num]) > 0)
		    {
			lost_connection(lan, ip_num);
		    }
		} else {
		    ipmi_unlock(lan->ip_lock);
		}
	    }
	} else {
	    ipmi_unlock(lan->ip_lock);
	}
    }

    rspi = lan->seq_table[seq].rsp_item;

    if (lan->seq_table[seq].retries_left > 0)
    {
	struct timeval timeout;
	int            rv;

	lan->seq_table[seq].retries_left--;

	/* Note that we will need a new session seq # here, we can't reuse
	   the old one.  If the message got lost on the way back, the other
	   end would silently ignore resends of the seq #. */
	if (lan->seq_table[seq].addr_num >= 0)
	    rv = lan_send_addr(lan,
			       &(lan->seq_table[seq].addr),
			       lan->seq_table[seq].addr_len,
			       &(lan->seq_table[seq].msg),
			       seq,
			       lan->seq_table[seq].addr_num);
	else
	    rv = lan_send(lan,
			  &(lan->seq_table[seq].addr),
			  lan->seq_table[seq].addr_len,
			  &(lan->seq_table[seq].msg),
			  seq,
			  &(lan->seq_table[seq].last_ip_num));

	if (!rv) {
	    timeout.tv_sec = LAN_RSP_TIMEOUT / 1000000;
	    timeout.tv_usec = LAN_RSP_TIMEOUT % 1000000;
	    ipmi->os_hnd->start_timer(ipmi->os_hnd,
				      id,
				      &timeout,
				      rsp_timeout_handler,
				      cb_data);
	}
	if (rv) {
	    /* If we get an error resending the message, report an unknown
	       error. */
	    rspi->data[0] = IPMI_UNKNOWN_ERR_CC;
	} else {
	    ipmi_unlock(lan->seq_num_lock);
	    lan_put(ipmi);
	    return;
	}
    } else {
	rspi->data[0] = IPMI_TIMEOUT_CC;
    }

    rspi->msg.netfn = lan->seq_table[seq].msg.netfn | 1;
    rspi->msg.cmd = lan->seq_table[seq].msg.cmd;
    rspi->msg.data = rspi->data;
    rspi->msg.data_len = 1;

    memcpy(&rspi->addr,
	   &(lan->seq_table[seq].addr),
	   lan->seq_table[seq].addr_len);
    rspi->addr_len = lan->seq_table[seq].addr_len;

    handler = lan->seq_table[seq].rsp_handler;

    lan->seq_table[seq].inuse = 0;

    check_command_queue(ipmi, lan);
    ipmi_unlock(lan->seq_num_lock);

    ipmi->os_hnd->free_timer(ipmi->os_hnd, id);

    /* Convert broadcasts back into normal sends. */
    if (rspi->addr.addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE)
	rspi->addr.addr_type = IPMI_IPMB_ADDR_TYPE;

    ipmi_handle_rsp_item(ipmi, rspi, handler);

 out:
    lan_put(ipmi);
    ipmi_mem_free(info);
}

typedef struct call_event_handler_s
{
    lan_data_t   *lan;
    ipmi_addr_t  *addr;
    unsigned int addr_len;
    ipmi_event_t *event;
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
handle_async_event(ipmi_con_t   *ipmi,
		   ipmi_addr_t  *addr,
		   unsigned int addr_len,
		   ipmi_msg_t   *msg)
{
    lan_data_t           *lan = (lan_data_t *) ipmi->con_data;
    ipmi_event_t         *event = NULL;
    ipmi_time_t          timestamp;
    call_event_handler_t info;

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
		ipmi_addr_t           *addr,
		unsigned int          addr_len,
		ipmi_msg_t            *msg,
		ipmi_ll_rsp_handler_t rsp_handler,
		ipmi_msgi_t           *rspi)
{
    ipmi_con_t     *ipmi = info->ipmi;
    lan_data_t     *lan = ipmi->con_data;
    unsigned int   seq;
    struct timeval timeout;
    int            rv;
    ipmi_addr_t    tmp_addr;
    ipmi_addr_t    *orig_addr = NULL;
    unsigned int   orig_addr_len = 0;

    seq = (lan->last_seq + 1) % 64;
    if (seq == 0)
	seq++;
    while (lan->seq_table[seq].inuse) {
	if (seq == lan->last_seq) {
	    /* This cannot really happen if max_outstanding_msg_count <= 63. */
	    ipmi_log(IPMI_LOG_FATAL,
		     "%sipmi_lan.c(handle_msg_send): "
		     "ipmi_lan: Attempted to start too many messages",
		     IPMI_CONN_NAME(lan->ipmi));
	    abort();
	}

	seq = (seq + 1) % 64;
	if (seq == 0)
	    seq++;
    }

    if (DEBUG_MSG) {
	char buf1[32], buf2[32];
	ipmi_log(IPMI_LOG_DEBUG_START, "outgoing msg to IPMI addr =");
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

	if (ipmb->slave_addr == lan->slave_addr) {
	    ipmi_system_interface_addr_t *si = (void *) &tmp_addr;
	    /* Most systems don't handle sending to your own slave
               address, so we have to translate here. */

	    si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	    si->channel = IPMI_BMC_CHANNEL;
	    si->lun = ipmb->lun;
	    orig_addr = addr;
	    orig_addr_len = addr_len;
	    addr = &tmp_addr;
	    addr_len = sizeof(*si);
	}
    }

    info->seq = seq;
    lan->seq_table[seq].inuse = 1;
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

    timeout.tv_sec = LAN_RSP_TIMEOUT / 1000000;
    timeout.tv_usec = LAN_RSP_TIMEOUT % 1000000;
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
	rv = lan_send_addr(lan, addr, addr_len, msg, seq, addr_num);
	lan->seq_table[seq].last_ip_num = addr_num;
    } else {
	rv = lan_send(lan, addr, addr_len, msg, seq,
		      &(lan->seq_table[seq].last_ip_num));
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
			     q_item->rsp_item);
	if (rv) {
	    /* Send an error response to the user. */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sipmi_lan.c(check_command_queue): "
		     "Command was not able to be sent due to error 0x%x",
		     IPMI_CONN_NAME(lan->ipmi), rv);
	    
	    q_item->msg.netfn |= 1; /* Convert it to a response. */
	    q_item->msg.data[0] = IPMI_UNKNOWN_ERR_CC;
	    q_item->msg.data_len = 1;
	    q_item->info = NULL;
	    ipmi_handle_rsp_item_copyall(ipmi, q_item->rsp_item,
					 &q_item->addr, q_item->addr_len,
					 &q_item->msg, q_item->rsp_handler);
	} else {
	    /* We successfully sent a message, break out of the loop. */
	    started = 1;
	}
	ipmi_mem_free(q_item);
    }

    if (!started)
	lan->outstanding_msg_count--;
}

static int
check_session_seq_num(uint32_t seq, uint32_t *in_seq, uint16_t *map)
{
    /* Check the sequence number. */
    if ((seq - *in_seq) <= 8) {
	/* It's after the current sequence number, but within 8.  We
           move the sequence number forward. */
	*map <<= seq - *in_seq;
	*map |= 1;
	*in_seq = seq;
    } else if ((*in_seq - seq) <= 8) {
	/* It's before the current sequence number, but within 8. */
	uint8_t bit = 1 << (*in_seq - seq);
	if (*map & bit) {
	    /* We've already received the message, so discard it. */
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "Dropped message duplicate");
	    return EINVAL;
	}

	*map |= bit;
    } else {
	/* It's outside the current sequence number range, discard
	   the packet. */
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Dropped message out of seq range");
	return EINVAL;
    }

    return 0;
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

    if (payload_type == IPMI_RMCPP_PAYLOAD_TYPE_OPEN_SESSION_RESPONSE) {
	if (payload_len < 1) {
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "Payload length to short");
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
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Unhandled payload: 0x%x",
		     payload_type);
	goto out;
    } else {
	rv = payloads[payload_type]->get_recv_seq(ipmi, tmsg,
						  payload_len, &seq);
	if (rv == ENOSYS) {
	    payloads[payload_type]->handle_recv_async(ipmi, tmsg, payload_len);
	    goto out;
	} else if (rv) {
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "Error getting sequence: 0x%x",
			 rv);
	    goto out;
	}
    }

    ipmi_lock(lan->seq_num_lock);
    if (! lan->seq_table[seq].inuse) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "Dropped message seq not in use: 0x%x",
		     seq);
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
    if (rv)
	goto out_unlock;

    /* We got a response from the connection, so reset the failure
       count. */
    lan->consecutive_ip_failures[addr_num] = 0;

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
    unsigned int  oem_payload_id = 0;
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
		     "Dropped message because too small(5)");
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
			 "Dropped message because too small(6)");
	    goto out;
	}
	memcpy(oem_iana, tmsg, 3);
	tmsg += 4;
	oem_payload_id = ipmi_get_uint16(tmsg);
	tmsg += 2;
    }

    session_id = ipmi_get_uint32(tmsg);
    tmsg += 4;
    if (session_id != lan->session_id[addr_num]) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "Dropped message not valid session id (2)");
	goto out;
    }

    session_seq = ipmi_get_uint32(tmsg);
    tmsg += 4;

    payload_len = ipmi_get_uint16(tmsg);
    tmsg += 2;

    header_len = tmsg - data;
    if ((header_len + payload_len) > len) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "Dropped message payload length doesn't match up");
	goto out;
    }

    /* Authenticate the message before we do anything else. */
    if (authenticated) {
	unsigned int  pad_len;

	if (lan->working_integ[addr_num] == IPMI_LANP_INTEGRITY_ALGORITHM_NONE)
	{
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "Got authenticated msg but authentication not available");
	    goto out;
	}

	rv = lan->integ_info[addr_num]->integ_check(ipmi,
						    lan->integ_data[addr_num],
						    data,
						    header_len + payload_len,
						    len);
	if (rv) {
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "Integrity failed");
	    goto out;
	}

	/* Remove the integrity padding. */
	pad_len = tmsg[payload_len-1] + 1;
	if (pad_len > payload_len) {
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "Padding too large");
	    goto out;
	}

	payload_len -= pad_len;
    }

    /* The packet is good, we can trust the data in it now. */

    /* If it's from a down connection, report it as up. */
    ipmi_lock(lan->ip_lock);
    if (! lan->ip_working[addr_num]) {
	ipmi_unlock(lan->ip_lock);
	connection_up(lan, addr_num, 0);
	ipmi_lock(lan->ip_lock);
    }

    if (authenticated)
	rv = check_session_seq_num(session_seq,
				   &(lan->inbound_seq_num[addr_num]),
				   &(lan->recv_msg_map[addr_num]));
    else if (session_id == 0)
	rv = 0; /* seq num not used for out-of-session messages. */
    else
	rv = check_session_seq_num(session_seq,
				   &(lan->unauth_in_seq_num[addr_num]),
				   &(lan->unauth_recv_msg_map[addr_num]));
    ipmi_unlock(lan->ip_lock);
    if (rv)
	goto out;

    /* Message is in sequence, so it's good to deliver after we
       decrypt it. */

    if (encrypted) {
	if (lan->working_conf[addr_num]
	    == IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE)
	{
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "Got encrypted msg but encryption not available");
	    goto out;
	}

	rv = lan->conf_info[addr_num]->conf_decrypt(ipmi,
						    lan->conf_data[addr_num],
						    &tmsg, &payload_len);
	if (rv) {
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "Decryption failed");
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

    if (data[4] == IPMI_AUTHTYPE_NONE) {
	if (len < 14) { /* Minimum size of an IPMI msg. */
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "Dropped message because too small(1)");
	    goto out;
	}

	/* No authentication. */
	if (len < (data[13] + 14)) {
	    /* Not enough data was supplied, reject the message. */
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "Dropped message because too small(2)");
	    goto out;
	}
	data_len = data[13];
    } else {
	if (len < 30) { /* Minimum size of an authenticated IPMI msg. */
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "Dropped message because too small(3)");
	    goto out;
	}
	/* authcode in message, add 16 to the above checks. */
	if (len < (data[29] + 30)) {
	    /* Not enough data was supplied, reject the message. */
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG,
			 "Dropped message because too small(4)");
	    goto out;
	}
	data_len = data[29];
    }

    /* FIXME - need a lock on the session data. */

    /* Drop if the authtypes are incompatible. */
    if (lan->working_authtype[addr_num] != data[4]) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Dropped message not valid authtype");
	goto out;
    }

    /* Drop if sessions ID's don't match. */
    sess_id = ipmi_get_uint32(data+9);
    if (sess_id != lan->session_id[addr_num]) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Dropped message not valid session id");
	goto out;
    }

    seq = ipmi_get_uint32(data+5);

    if (data[4] != 0) {
	/* Validate the message's authcode.  Do this before checking
           the session seq num so we know the data is valid. */
	rv = auth_check(lan, data+9, data+5, data+30, data[29], data+13,
			addr_num);
	if (rv) {
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "Dropped message auth fail");
	    goto out;
	}
	tmsg = data + 30;
    } else {
	tmsg = data + 14;
    }

    /* If it's from a down connection, report it as up. */
    ipmi_lock(lan->ip_lock);
    if (! lan->ip_working[addr_num]) {
	ipmi_unlock(lan->ip_lock);
	connection_up(lan, addr_num, 0);
	ipmi_lock(lan->ip_lock);
    }

    rv = check_session_seq_num(seq, &(lan->inbound_seq_num[addr_num]),
			       &(lan->recv_msg_map[addr_num]));
    ipmi_unlock(lan->ip_lock);
    if (rv)
	goto out;

    handle_payload(ipmi, lan, addr_num,
		   IPMI_RMCPP_PAYLOAD_TYPE_IPMI, tmsg, data_len);

 out:
    return;
}

static void
data_handler(int            fd,
	     void           *cb_data,
	     os_hnd_fd_id_t *id)
{
    ipmi_con_t         *ipmi = (ipmi_con_t *) cb_data;
    lan_data_t         *lan;
    unsigned char      data[IPMI_MAX_LAN_LEN];
    sockaddr_ip_t      ipaddrd;
    struct sockaddr_in *paddr;
    socklen_t          from_len;
    int                addr_num;
    int                len;

    if (!lan_valid_ipmi(ipmi))
	/* We can have due to a race condition, just return and
           everything should be fine. */
	return;

    lan = ipmi->con_data;

    from_len = sizeof(ipaddrd);
    len = recvfrom(fd, data, sizeof(data), 0, (struct sockaddr *)&ipaddrd, 
		   &from_len);
    if (len < 5)
	goto out;

    if (DEBUG_RAWMSG) {
	ipmi_log(IPMI_LOG_DEBUG_START, "incoming\n addr = ");
	dump_hex((unsigned char *) &ipaddrd, from_len);
	if (len) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =\n  ");
	    dump_hex(data, len);
	}
	ipmi_log(IPMI_LOG_DEBUG_END, " ");
    }

    /* Make sure the source IP matches what we expect the other end to
       be. */
    paddr = (struct sockaddr_in *)&ipaddrd;
    switch (paddr->sin_family) {
    case PF_INET:
	{
	    struct sockaddr_in *ipaddr;
	    struct sockaddr_in *ipaddr4;
	    ipaddr = (struct sockaddr_in *)&(ipaddrd);
            for (addr_num = 0; addr_num < lan->cparm.num_ip_addr; addr_num++) {
		ipaddr4 = (struct sockaddr_in *)
		    &(lan->cparm.ip_addr[addr_num]);
		if ((ipaddr->sin_port == ipaddr4->sin_port)
		    && (ipaddr->sin_addr.s_addr
			== ipaddr4->sin_addr.s_addr))
		    break;
	    }
	}
            break;
#ifdef PF_INET6
    case PF_INET6:
	{
            struct sockaddr_in6 *ipa6;
            struct sockaddr_in6 *ipaddr6;
            ipa6 = (struct sockaddr_in6 *)&(ipaddrd);
            for (addr_num = 0; addr_num < lan->cparm.num_ip_addr; addr_num++) {
		ipaddr6 = (struct sockaddr_in6 *)
		    &(lan->cparm.ip_addr[addr_num]);
		if ((ipa6->sin6_port == ipaddr6->sin6_port)
		    && (bcmp(ipa6->sin6_addr.s6_addr,
			     ipaddr6->sin6_addr.s6_addr,
			     sizeof(struct in6_addr)) == 0))
		    break;
	    }
	}
	break;
#endif
    default:
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lan: Unknown protocol family: 0x%x",
		 paddr->sin_family);
	goto out;
	break;
    }

    if (addr_num >= lan->cparm.num_ip_addr) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "ipmi_lan: Dropped message due to invalid IP");
	goto out;
    }

    /* Validate the RMCP portion of the message. */
    if ((data[0] != 6)
	|| (data[2] != 0xff)
	|| (data[3] != 0x07))
    {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Dropped message not valid IPMI/RMCP");
	goto out;
    }

    if (data[4] == IPMI_AUTHTYPE_RMCP_PLUS) {
	handle_rmcpp_recv(ipmi, lan, addr_num, data, len);
    } else {
	handle_lan15_recv(ipmi, lan, addr_num, data, len);
    }
    
 out:
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


    lan = (lan_data_t *) ipmi->con_data;

    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    if (msg->data_len > IPMI_MAX_MSG_LENGTH)
	return EINVAL;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    /* Put it in the list first. */
    info->ipmi = ipmi;
    info->cancelled = 0;

    rv = ipmi->os_hnd->alloc_timer(ipmi->os_hnd, &(info->timer));
    if (rv) {
	ipmi_mem_free(info);
	ipmi_mem_free(rspi);
	return rv;
    }

    ipmi_lock(lan->seq_num_lock);

    if (lan->outstanding_msg_count >= 60) {
	rv = EAGAIN;
	goto out_unlock;
    }

    rspi->data4 = (void *) (long) addr_num;
    rv = handle_msg_send(info, addr_num, addr, addr_len, msg,
			 rsp_handler, rspi);
    /* handle_msg_send handles freeing the timer and info on an error */
    info = NULL;
    if (! rv)
	lan->outstanding_msg_count++;

 out_unlock:
    ipmi_unlock(lan->seq_num_lock);
    if (rv) {
	if (info) {
	    ipmi->os_hnd->free_timer(ipmi->os_hnd, info->timer);
	    ipmi_mem_free(info);
	}
    }
    return rv;
}

static int
lan_send_command(ipmi_con_t            *ipmi,
		 ipmi_addr_t           *addr,
		 unsigned int          addr_len,
		 ipmi_msg_t            *msg,
		 ipmi_ll_rsp_handler_t rsp_handler,
		 ipmi_msgi_t           *trspi)
{
    lan_timer_info_t *info;
    lan_data_t       *lan;
    int              rv;
    ipmi_msgi_t      *rspi = trspi;


    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    if (msg->data_len > IPMI_MAX_MSG_LENGTH)
	return EINVAL;

    lan = (lan_data_t *) ipmi->con_data;

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

    /* Put it in the list first. */
    info->ipmi = ipmi;
    info->cancelled = 0;

    rv = ipmi->os_hnd->alloc_timer(ipmi->os_hnd, &(info->timer));
    if (rv) {
	ipmi_mem_free(info);
	return rv;
    }

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
			 rsp_handler, rspi);
    /* handle_msg_send handles freeing the timer and info on an error */
    info = NULL;
    if (!rv)
	lan->outstanding_msg_count++;

 out_unlock:
    ipmi_unlock(lan->seq_num_lock);
    if (rv) {
	if (info) {
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
lan_send_response(ipmi_con_t   *ipmi,
		  ipmi_addr_t  *addr,
		  unsigned int addr_len,
		  ipmi_msg_t   *msg,
		  long         sequence)
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
    if (lan->working_authtype[addr_num] == IPMI_AUTHTYPE_RMCP_PLUS)
	ipmi_set_uint32(data, lan->mgsys_session_id[addr_num]);
    else
	ipmi_set_uint32(data, lan->session_id[addr_num]);
    lan_send_addr(lan, (ipmi_addr_t *) &si, sizeof(si), &msg, 0, addr_num);
}

static void
lan_cleanup(ipmi_con_t *ipmi)
{
    lan_data_t *lan = ipmi->con_data;
    int        rv;
    int        i;

    /* After this point no other operations can occur on this ipmi
       interface, so it's safe. */

    for (i=0; i<lan->cparm.num_ip_addr; i++)
	send_close_session(ipmi, lan, i);

    if (lan->close_done)
	lan->close_done(ipmi, lan->close_cb_data);

    ipmi_lock(lan->seq_num_lock);
    for (i=0; i<64; i++) {
	if (lan->seq_table[i].inuse) {
	    ipmi_ll_rsp_handler_t handler;
	    ipmi_msgi_t           *rspi;
	    lan_timer_info_t      *info;

	    rv = ipmi->os_hnd->stop_timer(ipmi->os_hnd,
					  lan->seq_table[i].timer);

	    rspi = lan->seq_table[i].rsp_item;

	    memcpy(&rspi->addr, &(lan->seq_table[i].addr),
		   lan->seq_table[i].addr_len);
	    rspi->addr_len = lan->seq_table[i].addr_len;
	    handler = lan->seq_table[i].rsp_handler;
	    info = lan->seq_table[i].timer_info;

	    rspi->msg.netfn = lan->seq_table[i].msg.netfn | 1;
	    rspi->msg.cmd = lan->seq_table[i].msg.cmd;
	    rspi->msg.data = rspi->data;
	    rspi->data[0] = IPMI_UNKNOWN_ERR_CC;
	    rspi->msg.data_len = 1;

	    lan->seq_table[i].inuse = 0;

	    ipmi_unlock(lan->seq_num_lock);

	    /* The unlock is safe here because the connection is no
               longer valid and thus nothing else can really happen on
               this connection.  Sends will fail and receives will not
               validate. */
	    
	    ipmi_handle_rsp_item(NULL, rspi, handler);

	    if (rv)
		info->cancelled = 1;
	    else {
		ipmi->os_hnd->free_timer(ipmi->os_hnd, info->timer);
		ipmi_mem_free(info);
	    }

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

    if (ipmi->oem_data_cleanup)
	ipmi->oem_data_cleanup(ipmi);
    ipmi_con_attr_cleanup(ipmi);
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
    if (lan->fd_wait_id)
	ipmi->os_hnd->remove_fd_to_wait_for(ipmi->os_hnd, lan->fd_wait_id);
    if (lan->authdata)
	ipmi_auths[lan->chosen_authtype].authcode_cleanup(lan->authdata);
    for (i=0; i<MAX_IP_ADDR; i++) {
	if (lan->conf_data[i])
	    lan->conf_info[i]->conf_free(ipmi, lan->conf_data[i]);
	if (lan->integ_data[i])
	    lan->integ_info[i]->integ_free(ipmi, lan->integ_data[i]);
    }
    /* paranoia */
    memset(lan->cparm.password, 0, sizeof(lan->cparm.password));
    memset(lan->cparm.bmc_key, 0, sizeof(lan->cparm.bmc_key));

    /* Close the fd after we have deregistered it. */
    close(lan->fd);

    ipmi_mem_free(lan);
    ipmi_mem_free(ipmi);
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
cleanup_con(ipmi_con_t *ipmi)
{
    lan_data_t   *lan = (lan_data_t *) ipmi->con_data;
    os_handler_t *handlers = ipmi->os_hnd;
    int          i;

    if (ipmi) {
	ipmi_con_attr_cleanup(ipmi);
	ipmi_mem_free(ipmi);
    }

    if (lan) {
	/* This is only called in the case of an error at startup, so
	   there is no need to remove it from the LAN lists (hashes),
	   because it won't be there yet. */

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
	if (lan->fd != -1)
	    close(lan->fd);
	if (lan->fd_wait_id)
	    handlers->remove_fd_to_wait_for(handlers, lan->fd_wait_id);
	if (lan->authdata)
	    ipmi_auths[lan->chosen_authtype].authcode_cleanup(lan->authdata);
	for (i=0; i<MAX_IP_ADDR; i++) {
	    if (lan->conf_data[i])
		lan->conf_info[i]->conf_free(ipmi, lan->conf_data[i]);
	    if (lan->integ_data[i])
		lan->integ_info[i]->integ_free(ipmi, lan->integ_data[i]);
	}
	ipmi_mem_free(lan);
    }
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
		  unsigned char ipmb,
		  int           active,
		  unsigned int  hacks)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    if ((lan->slave_addr != ipmb) || (lan->is_active != active))  {
	lan->slave_addr = ipmb;
	lan->is_active = active;
	ipmi->hacks = hacks;
	ipmi->ipmb_addr = ipmb;
	call_ipmb_change_handlers(lan, 0, ipmb, active, hacks);
    }
}

static void
handle_ipmb_addr(ipmi_con_t   *ipmi,
		 int          err,
		 unsigned int ipmb_addr,
		 int          active,
		 unsigned int hacks,
		 void         *cb_data)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;
    int        addr_num = (long) cb_data;

    if (err) {
	handle_connected(ipmi, err, addr_num);
	return;
    }

    lan->slave_addr = ipmb_addr;
    lan->is_active = active;
    ipmi->hacks = hacks;
    ipmi->ipmb_addr = ipmb_addr;
    finish_connection(ipmi, lan, addr_num);
    call_ipmb_change_handlers(lan, err, ipmb_addr, active, hacks);
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
    lan_data_t  *lan = (lan_data_t *) ipmi->con_data;
    int         rv;
    ipmi_msgi_t *rspi = cb_data;
    int         addr_num = (long) rspi->data4;

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

    if (lan->cparm.privilege != (msg->data[1] & 0xf)) {
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
		 "ipmi_lan.c(%s): Message data too short: %d",
		 caller, msg->data_len);
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
		 "ipmi_lan.c(%s): Message data too short: %d",
		 caller, msg->data_len);
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

    lan->session_id[addr_num] = lan->precon_session_id[addr_num];
    lan->mgsys_session_id[addr_num] = lan->precon_mgsys_session_id[addr_num];
    lan->inbound_seq_num[addr_num] = 1;
    lan->outbound_seq_num[addr_num] = 1;
    lan->unauth_in_seq_num[addr_num] = 1;
    lan->unauth_out_seq_num[addr_num] = 1;

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

    rv = lan->conf_info[addr_num]->conf_init(ipmi, ainfo,
					     &(lan->conf_data[addr_num]));
    if (rv)
	goto out;

    rv = lan->integ_info[addr_num]->integ_init(ipmi, ainfo,
					       &(lan->integ_data[addr_num]));
    if (rv)
	goto out;

 out:
    return rv;
}

static int
got_rmcpp_open_session_rsp(ipmi_con_t *ipmi, ipmi_msgi_t  *rspi)
{
    ipmi_msg_t  *msg = &rspi->msg;
    lan_data_t  *lan;
    int         addr_num = (long) rspi->data4;
    uint32_t    session_id;
    uint32_t    mgsys_session_id;
    int         privilege;
    int         auth, integ, conf;
    ipmi_rmcpp_authentication_t *authp = NULL;
    ipmi_rmcpp_confidentiality_t *confp = NULL;
    ipmi_rmcpp_integrity_t *integp = NULL;
    auth_info_t *info;
    int         rv;

    if (check_rakp_rsp(ipmi, msg, "got_rmcpp_open_session_rsp", 36, addr_num))
	goto out;

    lan = (lan_data_t *) ipmi->con_data;

    privilege = msg->data[2] & 0xf;
    if (privilege != lan->cparm.privilege) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "Expected privilege %d, got %d",
		 lan->cparm.privilege, privilege);
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    session_id = ipmi_get_uint32(msg->data+4);
    if (session_id != lan->precon_session_id[addr_num]) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lan.c(got_rmcpp_open_session_rsp): "
		 " Got wrong session id: 0x%x",
		 session_id);
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    mgsys_session_id = ipmi_get_uint32(msg->data+8);
    if (mgsys_session_id == 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "Got NULL mgd system session id");
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }
    lan->precon_mgsys_session_id[addr_num] = mgsys_session_id;

    if ((msg->data[12] != 0) || (msg->data[15] != 8)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "Got NULL or invalid authentication payload");
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }
    auth = msg->data[16] & 0x3f;

    if ((msg->data[20] != 0) || (msg->data[23] != 8)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "Got NULL or invalid integrity payload");
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }
    integ = msg->data[24] & 0x3f;

    if ((msg->data[28] != 0) || (msg->data[31] != 8)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "Got NULL or invalid confidentiality payload");
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
		 "ipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "BMC returned an auth algorithm that wasn't supported: %d",
		 auth);
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
		 "ipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "BMC returned a conf algorithm that wasn't supported: %d",
		 conf);
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
		 "ipmi_lan.c(got_rmcpp_open_session_rsp): "
		 "BMC returned an integ algorithm that wasn't supported: %d",
		 integ);
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	handle_connected(ipmi, ENOMEM, addr_num);
	goto out;
    }

    lan->working_conf[addr_num] = conf;
    lan->working_integ[addr_num] = integ;
    lan->conf_info[addr_num] = confp;
    lan->integ_info[addr_num] = integp;

    lan->ainfo[addr_num].lan = lan;
    lan->ainfo[addr_num].role = ((lan->cparm.name_lookup_only << 4)
				 | lan->cparm.privilege);

    info->lan = lan;
    info->rspi = rspi;

    rv = authp->start_auth(ipmi, addr_num, &(lan->ainfo[addr_num]),
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
    data[0] = 0;
    data[1] = lan->cparm.privilege;
    ipmi_set_uint32(data+4, lan->precon_session_id[addr_num]);
    data[8] = 0; /* auth algorithm */
    if (lan->cparm.auth == IPMI_LANP_AUTHENTICATION_ALGORITHM_BMCPICK)
	data[11] = 0; /* Let the BMC pick */
    else {
	data[11] = 8;
	data[12] = lan->cparm.auth;
    }
    data[16] = 1; /* integrity algorithm */
    if (lan->cparm.integ == IPMI_LANP_INTEGRITY_ALGORITHM_BMCPICK)
	data[19] = 0; /* Let the BMC pick */
    else {
	data[19] = 8;
	data[20] = lan->cparm.integ;
    }
    data[24] = 2; /* confidentiality algorithm */
    if (lan->cparm.conf == IPMI_LANP_CONFIDENTIALITY_ALGORITHM_BMCPICK)
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

    lan->working_authtype[addr_num] = IPMI_AUTHTYPE_RMCP_PLUS;
    lan->outbound_seq_num[addr_num] = 0;
    lan->unauth_out_seq_num[addr_num] = 0;
    lan->inbound_seq_num[addr_num] = 0;
    lan->unauth_in_seq_num[addr_num] = 0;
    lan->precon_session_id[addr_num] = 1; /* Use session 1, don't really care. */
    lan->working_conf[addr_num] = IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE;
    lan->working_integ[addr_num] = IPMI_LANP_INTEGRITY_ALGORITHM_NONE;

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

    lan->working_authtype[addr_num] = msg->data[1] & 0xf;
    if ((lan->working_authtype[addr_num] != 0)
	&& (lan->working_authtype[addr_num] != lan->chosen_authtype))
    {
	/* Eh?  It didn't return a valid authtype. */
        handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    lan->session_id[addr_num] = ipmi_get_uint32(msg->data+2);
    lan->outbound_seq_num[addr_num] = ipmi_get_uint32(msg->data+6);

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
    ipmi_set_uint32(data+18, lan->inbound_seq_num[addr_num]);

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
    lan->session_id[addr_num] = ipmi_get_uint32(msg->data+1);

    lan->outbound_seq_num[addr_num] = 0;
    lan->working_authtype[addr_num] = lan->chosen_authtype;
    memcpy(lan->challenge_string, msg->data+5, 16);

    /* Get a random number of the other end to start sending me sequence
       numbers at, but don't let it be zero. */
    while (lan->inbound_seq_num[addr_num] == 0) {
	rv = ipmi->os_hnd->get_random(ipmi->os_hnd,
				      &(lan->inbound_seq_num[addr_num]), 4);
	if (rv) {
	    handle_connected(ipmi, rv, addr_num);
	    goto out;
	}
    }

    lan->retries = 0;
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

    if (!ipmi) {
	handle_connected(ipmi, ECANCELED, addr_num);
	goto out;
    }

    lan = (lan_data_t *) ipmi->con_data;

    if ((msg->data[0] != 0) || (msg->data_len < 9)) {
	handle_connected(ipmi, EINVAL, addr_num);
	goto out;
    }

    memcpy(lan->oem_iana, msg->data+5, 3);
    lan->oem_aux = msg->data[8];

    if (lan->authdata) {
	ipmi_auths[lan->chosen_authtype].authcode_cleanup(lan->authdata);
	lan->authdata = NULL;
    }

    if (lan->cparm.authtype == IPMI_AUTHTYPE_DEFAULT) {
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

    if (msg->data[4] & 0x02) {
	/* We have RMCP+ support!  Use it. */
	lan->use_two_keys = (msg->data[3] >> 5) & 1;
	memcpy(lan->oem_iana, msg->data+5, 3);
	lan->oem_aux = msg->data[8];
	return start_rmcpp(ipmi, lan, rspi, addr_num);
    } else {
	if (lan->cparm.authtype == IPMI_AUTHTYPE_RMCP_PLUS) {
	    /* The user specified RMCP+, but the system doesn't have it. */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sipmi_lan.c(auth_cap_done_p): "
		     "Use requested RMCP+, but not supported",
		     IPMI_CONN_NAME(lan->ipmi));
	    handle_connected(ipmi, ENOENT, addr_num);
	    goto out;
	}

	return auth_cap_done(ipmi, rspi);
    }

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
    if (((lan->cparm.authtype == IPMI_AUTHTYPE_DEFAULT)
	 || (lan->cparm.authtype == IPMI_AUTHTYPE_RMCP_PLUS))
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
    int            i;

    ipmi_lock(lan->ip_lock);
    if (lan->started) {
	/* Only allow started to be called once, but make sure the
	   connected callback gets called if started is called again
	   (assuming the connection is up).  This lets multiple users
	   use the same connection.  If the LAN is not connected, this
	   doesn't matter, the callback will be called properly
	   later. */
	if (lan->connected) {
	    int i;
	    int port_err[MAX_IP_ADDR];

	    for (i=0; i<lan->cparm.num_ip_addr; i++)
		port_err[i] = lan->ip_working[i] ? 0 : EINVAL;

	    ipmi_lock(lan->con_change_lock);
	    ipmi_unlock(lan->ip_lock);

	    for (i=0; i<lan->cparm.num_ip_addr; i++)
		call_con_change_handlers(lan, port_err[i], i, 1);
	    ipmi_unlock(lan->con_change_lock);
	} else
	    ipmi_unlock(lan->ip_lock);
	return 0;
    }
    lan->started = 1;
    ipmi_unlock(lan->ip_lock);

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

    for (i=0; i<lan->cparm.num_ip_addr; i++) {
	rv = send_auth_cap(ipmi, lan, i, 0);
	if (rv)
	    goto out_err;
    }

 out_err:
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
    int i,rv;

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
    lan_link_t *l;
    lan_data_t *lan;
    int        idx;

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
    int                i;
    int		       count;
    struct sockaddr_in *pa;
    char               **ip_addrs = NULL;
    char               **ports = NULL;
    lan_conn_parms_t   cparm;

    memset(&cparm, 0, sizeof(cparm));

    /* Pick some secure defaults. */
    cparm.authtype = IPMI_AUTHTYPE_DEFAULT;
    cparm.privilege = IPMI_PRIVILEGE_ADMIN;
    cparm.conf = IPMI_LANP_CONFIDENTIALITY_ALGORITHM_AES_CBC_128;
    cparm.integ = IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_SHA1_96;
    cparm.auth = IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_HMAC_SHA1;
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
	    ip_addrs = parms[i].parm_data;
	    cparm.num_ip_addr = parms[i].parm_data_len;
	    break;

	case IPMI_LANP_PARMID_PORTS:
	    if (cparm.num_ip_addr
		&& (cparm.num_ip_addr != parms[i].parm_data_len))
		return EINVAL;
	    ports = parms[i].parm_data;
	    cparm.num_ip_addr = parms[i].parm_data_len;
	    break;

	case IPMI_LANP_AUTHENTICATION_ALGORITHM:
	    cparm.auth = parms[i].parm_val;
	    if (cparm.auth != IPMI_LANP_AUTHENTICATION_ALGORITHM_BMCPICK)
	    {
		if (cparm.auth >= 64)
		    return EINVAL;
		if ((cparm.auth < 0x30) && (!auths[cparm.auth]))
		    return ENOSYS;
	    }
	    break;

	case IPMI_LANP_INTEGRITY_ALGORITHM:
	    cparm.integ = parms[i].parm_val;
	    if (cparm.integ != IPMI_LANP_INTEGRITY_ALGORITHM_BMCPICK)
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
	    if (cparm.conf != IPMI_LANP_CONFIDENTIALITY_ALGORITHM_BMCPICK)
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

	default:
	    return EINVAL;
	}
    }

    if ((cparm.num_ip_addr == 0) || (ip_addrs == NULL))
	return EINVAL;
    if ((cparm.authtype != IPMI_AUTHTYPE_DEFAULT)
	&& ((cparm.authtype >= MAX_IPMI_AUTHS)
	    || (ipmi_auths[cparm.authtype].authcode_init == NULL)))
	return EINVAL;
    if ((cparm.num_ip_addr < 1) || (cparm.num_ip_addr > MAX_IP_ADDR))
	return EINVAL;

    count = 0;
#ifdef HAVE_GETADDRINFO
    for (i=0; i<cparm.num_ip_addr; i++) {
        struct addrinfo hints, *res0;
 
        memset(&hints, 0, sizeof(hints));
        if (count == 0)
            hints.ai_family = PF_UNSPEC;
        else
	{
            /* Make sure all ip address is in the same protocol family*/
	    struct sockaddr_in *paddr;
	    paddr = (struct sockaddr_in *)&(cparm.ip_addr[0]);
            hints.ai_family = paddr->sin_family;
	}
        hints.ai_socktype = SOCK_DGRAM;
        rv = getaddrinfo(ip_addrs[i], ports[i], &hints, &res0);
	if (rv)
	    return EINVAL;

	/* Only get the first choices */
	memcpy(&(cparm.ip_addr[count]), res0->ai_addr, res0->ai_addrlen);
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
	memcpy(&(paddr->sin_addr), ent->h_addr_list[0], ent->h_length);
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
    ipmi->ipmb_addr = 0x20; /* Assume this until told otherwise */

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

    lan->refcount = 1;
    lan->users = 1;
    lan->ipmi = ipmi;
    lan->slave_addr = 0x20; /* Assume this until told otherwise */
    lan->is_active = 1;
    lan->chosen_authtype = IPMI_AUTHTYPE_DEFAULT;
    lan->curr_ip_addr = 0;
    lan->num_sends = 0;
    lan->connected = 0;
    lan->initialized = 0;

    lan->outstanding_msg_count = 0;
    lan->max_outstanding_msg_count = DEFAULT_MAX_OUTSTANDING_MSG_COUNT;
    lan->wait_q = NULL;
    lan->wait_q_tail = NULL;

    pa = (struct sockaddr_in *)&(lan->cparm.ip_addr[0]);
    lan->fd = open_lan_fd(pa->sin_family);
    if (lan->fd == -1) {
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

    /* Add the waiter last. */
    rv = handlers->add_fd_to_wait_for(handlers,
				      lan->fd,
				      data_handler, 
				      ipmi,
				      NULL,
				      &(lan->fd_wait_id));
    if (rv)
	goto out_err;

    /* Add it to the list of valid IPMIs so it will validate.  This
       must be done last, after a point where it cannot fail. */
    lan_add_con(lan);

    lan->retries = 0;

    *new_con = ipmi;

    return 0;

 out_err:
    cleanup_con(ipmi);
    return rv;
}

/* This is a hack of a function so the MXP code can switch the
   connection over properly.  Must be called with the global read lock
   held. */
int
_ipmi_lan_set_ipmi(ipmi_con_t *old, ipmi_con_t *new)
{
    lan_data_t     *lan = (lan_data_t *) old->con_data;
    os_hnd_fd_id_t *fd_wait_id;
    int            rv;

    old->os_hnd->remove_fd_to_wait_for(old->os_hnd, lan->fd_wait_id);
    lan->fd_wait_id = NULL;
    rv = old->os_hnd->add_fd_to_wait_for(old->os_hnd,
					 lan->fd,
					 data_handler, 
					 new,
					 NULL,
					 &fd_wait_id);
    if (!rv) {
	lan->fd_wait_id = fd_wait_id;
	lan->ipmi = new;
    }

    return rv;
}

/* Another cheap hack so the MXP code can call this. */
void _ipmi_lan_handle_connected(ipmi_con_t *ipmi, int rv, int addr_num)
{
    handle_connected(ipmi, rv, addr_num);
}

static void
snmp_got_match(lan_data_t *lan, ipmi_msg_t *msg, unsigned char *pet_ack)
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
    ack.data = pet_ack;
    ack.data_len = 12;
    lan_send(lan, (ipmi_addr_t *) &si, sizeof(si), &ack, 0, &dummy_send_ip);
}

typedef struct lan_do_evt_s
{
    lan_data_t          *lan;
    struct lan_do_evt_s *next;
} lan_do_evt_t;

int
ipmi_lan_handle_external_event(struct sockaddr *src_addr,
			       ipmi_msg_t      *msg,
			       unsigned char   *pet_ack)
{
    lan_link_t   *l;
    lan_data_t   *lan;
    int          i;
    int          idx;
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
	for (i=0; i<lan->cparm.num_ip_addr; i++) {
	    if (lan->cparm.ip_addr[i].s_ipsock.s_addr.sa_family
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
		dst = &(lan->cparm.ip_addr[i].s_ipsock.s_addr4);
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
		dst = &(lan->cparm.ip_addr[i].s_ipsock.s_addr6);
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

int
_ipmi_lan_init(os_handler_t *os_hnd)
{
    int rv;
    int i;

    rv = ipmi_create_global_lock(&lan_list_lock);
    if (rv)
	return rv;

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

    return 0;
}

void
_ipmi_lan_shutdown(void)
{
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
}
