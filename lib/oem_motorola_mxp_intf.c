/*
 * oem_motorola_mxp_intf.c
 *
 * Code to handle the custom LAN interface for the MXP.
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/mxp.h>

#define MXP_NETFN_MXP1		0x30
#define MXP_OEM_SET_QUEUE_LOCK_CMD		0x3e

#ifdef DEBUG_MSG
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

/* This is the main timeout, it will go off every 50ms when messages
   are being sent.  The time is specified in microseconds. */
#define MXP_RESPONSE_TIMEOUT	50000

#define LAN_AUDIT_TIMEOUT 10000000

/* Timeout to wait for IPMI responses, in milliseconds. */
#define LAN_RSP_TIMEOUT 1000000

/* This is the number of timeout periods before most operations will
   be resent. */
#define MXP_STD_OP_TIMEOUT	20

/* This is the number of times a normal operation will be
   retransmitted before being deemed to have failed. */
#define MAX_SEND_RETRIES 5

/* The number of retries before we deem that a connection has failed
   and switch to another connection. */
#define CONN_FAILED_RETRIES 3

/* This is the timeout when waiting for an incoming message.  We try
   to fetch the message every tick. */
#define MXP_GET_MSG_TIMEOUT	1

/* The number of times a message fetch will be retried before being
   deemed to have failed.  In most retries, the get message is resent.
   Every GET_RETRY_RESEND_MOD retries, though, the actual message is
   resent. */
#define MAX_GET_RETRIES 40
#define GET_CONN_FAILED_RETRIES 20
#define GET_RETRY_RESEND_MOD 8

/* Broadcasts can be lossy, and they are just used for scanning, so we
   don't give them much time. */
#define MAX_GET_BC_RETRIES 4

struct ipmi_ll_event_handler_id_s
{
    ipmi_con_t            *ipmi;
    ipmi_ll_evt_handler_t handler;
    void                  *event_data;
    void                  *data2;

    ipmi_ll_event_handler_id_t *next, *prev;
};

typedef struct audit_timer_info_s
{
    int        cancelled;
    ipmi_con_t *ipmi;
} audit_timer_info_t;

typedef struct lan_timer_info_s
{
    int          cancelled;
    ipmi_con_t   *ipmi;
} lan_timer_info_t;

#define MAX_IP_ADDR 2

/* We must keep this number small, if it's too big and a failure
   occurs, we will be outside the sequence number before we switch. */
#define SENDS_BETWEEN_IP_SWITCHES 3

enum lan_state_e {
    LAN_IDLE,
    LAN_MSG_WAIT_NOLOCK,
    LAN_WAIT_LOCK,
    LAN_WAIT_SEL_LOCK,
    LAN_WAIT_SEL_SEND_RSP,
    LAN_WAIT_CLEAR,
    LAN_WAIT_SEND_RSP,
    LAN_WAIT_GET_RSP,
    LAN_WAIT_UNLOCK
};

typedef struct msg_del_s {
    ipmi_ll_rsp_handler_t handler;
    void                  *rsp_data;
    void                  *data2;
    void                  *data3;
    void                  *data4;
    ipmi_msg_t            msg;
    unsigned char         data[MAX_IPMI_DATA_SIZE];
    ipmi_addr_t           addr;
    unsigned int          addr_len;
} msg_del_t;

typedef struct lan_data_s
{
    ipmi_con_t                 *ipmi;
    unsigned int               swid;
    int                        fd;

    unsigned char              slave_addr;

    int                        curr_ip_addr;
    struct sockaddr_in         ip_addr[MAX_IP_ADDR];
    int                        ip_working[MAX_IP_ADDR];
    unsigned int               num_ip_addr;
    unsigned int               num_sends;

    /* If 0, we don't have a connection to the BMC right now. */
    int                        connected;

    /* If 0, we have not yet initialized */
    int                        initialized;

    unsigned int               authtype;
    unsigned int               privilege;
    unsigned char              username[IPMI_USERNAME_MAX];
    unsigned int               username_len;
    unsigned char              password[IPMI_PASSWORD_MAX];
    unsigned int               password_len;
    unsigned char              challenge_string[16];

    unsigned int               working_authtype;
    ipmi_authdata_t            authdata;
    uint32_t                   outbound_seq_num;
    uint32_t                   session_id;
    uint32_t                   inbound_seq_num;
    uint16_t                   recv_msg_map;

    struct {
	ipmi_addr_t           addr;
	unsigned int          addr_len;
	ipmi_msg_t            msg;
	ipmi_msg_t            cmp_msg;
	int                   lun;
	int                   is_ipmb_msg;
	int		      is_broadcast;

	/* If we get a message to the AMC as an IPMB message using the
           AMC's slave address, then we translate it to a direct
           message.  If this happens, use_orig_addr will be set, the
           original IPMB address will be in orig_addr, and addr will
           hold the direct address to the AMC. */
	int                   use_orig_addr;
	ipmi_addr_t           orig_addr;
	unsigned int          orig_addr_len;

	unsigned char         data[IPMI_MAX_MSG_LENGTH];
	ipmi_ll_rsp_handler_t rsp_handler;
	void                  *rsp_data;
	void                  *data2;
	void                  *data3;
	void                  *data4;
    } msg_queue[64];
    ipmi_lock_t               *msg_queue_lock;
    unsigned int              curr_msg;
    unsigned int              next_msg;
    enum lan_state_e          state;

    /* The number of retries before the operation is deemed to have
       failed. */
    unsigned int              retries;

    /* The number of retries before the connection is deemed to have
       failed. */
    unsigned int              conn_fail_retries;

    /* The following is used to count timer timeouts until the operation
       has deemed to time out.  The timer period is fixed, we use this
       to do the actual timing. */
    unsigned int              op_timeout_countdown;

    /* If true, force the operation until it succeeds. */
    int                       do_force;

    os_hnd_timer_id_t          *timer;
    lan_timer_info_t           *timer_info;

    os_hnd_fd_id_t             *fd_wait_id;

    os_hnd_timer_id_t          *audit_timer;
    audit_timer_info_t         *audit_info;

    ipmi_ll_con_changed_cb con_change_handler;
    void                   *con_change_cb_data;

    ipmi_ll_ipmb_addr_cb ipmb_addr_handler;
    void                 *ipmb_addr_cb_data;

    struct lan_data_s *next, *prev;
} lan_data_t;

#define QUEUE_NEXT(x) (((x) + 1) % 64)

static int send_auth_cap(ipmi_con_t *ipmi, lan_data_t *lan);

static lan_data_t *lan_list = NULL;

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
    lan_data_t *elem;

    elem = lan_list;
    while ((elem) && (elem->ipmi != ipmi)) {
	elem = elem->next;
    }

    return (elem != NULL);
}

static int
open_lan_fd(void)
{
    int                fd;
    struct sockaddr_in addr;
    int                curr_port;
    int                rv;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1)
	return fd;

    curr_port = 7000;
    do {
	curr_port++;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(curr_port);
	addr.sin_addr.s_addr = INADDR_ANY;

	rv = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
    } while ((curr_port < 7100) && (rv == -1));

    if (rv == -1)
    {
	int tmp_errno = errno;
	close(fd);
	errno = tmp_errno;
	return -1;
    }

    return fd;
}

static unsigned char
ipmb_checksum(unsigned char *data, int size)
{
	unsigned char csum = 0;
	
	for (; size > 0; size--, data++)
		csum += *data;

	return -csum;
}

static int
auth_gen(lan_data_t    *lan,
	 unsigned char *out,
	 uint8_t       *ses_id,
	 uint8_t       *seq,
	 unsigned char *data,
	 unsigned int  data_len)
{
    int rv;
    ipmi_auth_sg_t l[] =
    { { ses_id, 4 },
      { data,   data_len },
      { seq,    4 },
      { NULL,   0 }};

    rv = ipmi_auths[lan->working_authtype].authcode_gen(lan->authdata, l, out);
    return rv;
}

static int
auth_check(lan_data_t    *lan,
	   uint8_t       *ses_id,
	   uint8_t       *seq,
	   unsigned char *data,
	   unsigned int  data_len,
	   unsigned char *code)
{
    int rv;
    ipmi_auth_sg_t l[] =
    { { ses_id, 4  },
      { data,   data_len },
      { seq,    4 },
      { NULL,   0 }};

    rv = ipmi_auths[lan->working_authtype].authcode_check(lan->authdata,
							  l,
							  code);
    return rv;
}
	 
#define IPMI_MAX_LAN_LEN (IPMI_MAX_MSG_LENGTH + 42)
static int
lan_send_addr(lan_data_t  *lan,
	      int         lun,
	      ipmi_msg_t  *msg,
	      int         addr_num)
{
    unsigned char data[IPMI_MAX_LAN_LEN];
    unsigned char *tmsg;
    int           pos;
    int           rv;

    data[0] = 6; /* RMCP version 1.0. */
    data[1] = 0;
    data[2] = 0xff;
    data[3] = 0x07;
    data[4] = lan->working_authtype;
    ipmi_set_uint32(data+5, lan->outbound_seq_num);
    ipmi_set_uint32(data+9, lan->session_id);
    if (lan->working_authtype == 0)
	tmsg = data+14;
    else
	tmsg = data+30;

    tmsg[0] = 0x20; /* To the BMC. */
    tmsg[1] = (msg->netfn << 2) | lun;
    tmsg[2] = ipmb_checksum(tmsg, 2);
    tmsg[3] = 0x81; /* Remote console IPMI Software ID */
    tmsg[4] = 0x0;
    tmsg[5] = msg->cmd;
    memcpy(tmsg+6, msg->data, msg->data_len);
    pos = msg->data_len + 6;
    tmsg[pos] = ipmb_checksum(tmsg+3, pos-3);
    pos++;

    if (lan->working_authtype == 0) {
	/* No authentication, so no authcode. */
	data[13] = pos;
	pos += 14; /* Convert to pos in data */
    } else {
	data[29] = pos;
	rv = auth_gen(lan, data+13, data+9, data+5, tmsg, pos);
	if (rv)
	    return rv;
	pos += 30; /* Convert to pos in data */
    }

    /* FIXME - need locks for the sequence numbers. */

    /* Increment the outbound number, but make sure it's not zero.  If
       it's already zero, ignore it, we are in pre-setup. */
    if (lan->outbound_seq_num != 0) {
	(lan->outbound_seq_num)++;
	if (lan->outbound_seq_num == 0)
	    (lan->outbound_seq_num)++;
    }

    if (DEBUG_MSG) {
	dump_hex((unsigned char *) &(lan->ip_addr[lan->curr_ip_addr]),
		 sizeof(struct sockaddr_in));
	ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =\n  ");
	dump_hex(data, pos);
	ipmi_log(IPMI_LOG_DEBUG_END, "");
    }

    rv = sendto(lan->fd, data, pos, 0,
		(struct sockaddr *) &(lan->ip_addr[addr_num]),
		sizeof(struct sockaddr_in));
    if (rv == -1)
	rv = errno;
    else
	rv = 0;

    return rv;
}

static int
lan_send(lan_data_t  *lan,
	 int         lun,
	 ipmi_msg_t  *msg)
{
    if (lan->connected) {
	lan->num_sends++;

	/* We periodically switch between IP addresses, just to make sure
	   they are all operational. */
	if ((lan->num_sends % SENDS_BETWEEN_IP_SWITCHES) == 0) {
	    int addr_num = lan->curr_ip_addr + 1;
	    while (addr_num != lan->curr_ip_addr) {
		if (addr_num >= lan->num_ip_addr)
		    addr_num = 0;
		if (lan->ip_working[addr_num])
		    break;
		addr_num++;
	    }
	    lan->curr_ip_addr = addr_num;
	}
    } else {
	/* Just rotate between IP addresses if we are not yet connected */
	int addr_num = lan->curr_ip_addr + 1;
	if (addr_num >= lan->num_ip_addr)
	    addr_num = 0;
	lan->curr_ip_addr = addr_num;
    }

    return lan_send_addr(lan, lun, msg, lan->curr_ip_addr);
}

static void
send_lock_msg(lan_data_t *lan)
{
    ipmi_msg_t    msg;
    unsigned char data[5];

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_QUEUE_LOCK_CMD;
    msg.data = data;
    msg.data_len = 5;
    data[0] = 0xa1;
    data[1] = 0x00;
    data[2] = 0x00;
    data[3] = 0x01; /* lock */
    data[4] = lan->do_force;

    lan_send(lan, 0, &msg);
}

static void
send_unlock_msg(lan_data_t *lan)
{
    ipmi_msg_t    msg;
    unsigned char data[5];

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_QUEUE_LOCK_CMD;
    msg.data = data;
    msg.data_len = 5;
    data[0] = 0xa1;
    data[1] = 0x00;
    data[2] = 0x00;
    data[3] = 0x00; /* unlock */
    data[4] = 0x00; /* no force */

    lan_send(lan, 0, &msg);
}

static void
send_get_msg(lan_data_t *lan)
{
    ipmi_msg_t    msg;
    unsigned char data[1];

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_MSG_CMD;
    msg.data = data;
    msg.data_len = 1;
    data[0] = 0;

    lan_send(lan, 0, &msg);
}

static void
send_sel_lock_msg(lan_data_t *lan)
{
    ipmi_msg_t    msg;
    unsigned char data[4];

    msg.netfn = 0x30;  /* MXP OEM netfn. */
    msg.cmd = 0x4b; /* Set SEL Owner command. */
    msg.data = data;
    msg.data_len = 4;
    data[0] = 0xa1;
    data[1] = 0x00;
    data[2] = 0x00;
    data[3] = lan->swid;

    lan_send(lan, 0, &msg);
}

static void
start_next_msg(ipmi_con_t *ipmi,
	       lan_data_t *lan)
{
    int msg_num;

    if (lan->curr_msg == lan->next_msg)
	return;

    lan->num_sends++;

    /* We periodically switch between IP addresses, just to make sure
       they are all operational. */
    if ((lan->curr_ip_addr >= 0) &&
	((lan->num_sends % SENDS_BETWEEN_IP_SWITCHES) == 0))
    {
	int addr_num = lan->curr_ip_addr + 1;
	while (addr_num != lan->curr_ip_addr) {
	    if (addr_num >= lan->num_ip_addr)
		addr_num = 0;
	    if (lan->ip_working[addr_num])
		break;
	    addr_num++;
	}
	lan->curr_ip_addr = addr_num;
    }

    msg_num = lan->curr_msg;

    lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
    lan->retries = MAX_SEND_RETRIES;
    lan->conn_fail_retries = CONN_FAILED_RETRIES;
    lan->do_force = 0;

    if (DEBUG_MSG) {
	ipmi_log(IPMI_LOG_DEBUG_START, "outgoing\n addr =");
	dump_hex((unsigned char *) &lan->msg_queue[msg_num].addr,
		 lan->msg_queue[msg_num].addr_len);
	ipmi_log(IPMI_LOG_DEBUG_CONT,
		 "\n NetFN = %x", lan->msg_queue[msg_num].cmp_msg.netfn);
	ipmi_log(IPMI_LOG_DEBUG_CONT,
		 "\n Cmd = %x", lan->msg_queue[msg_num].cmp_msg.cmd);
	ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =");
	dump_hex(lan->msg_queue[msg_num].msg.data,
		 lan->msg_queue[msg_num].msg.data_len);
	ipmi_log(IPMI_LOG_DEBUG_END, "");
    }
    if ((lan->msg_queue[msg_num].is_ipmb_msg)
	|| ((lan->msg_queue[msg_num].msg.netfn == IPMI_STORAGE_NETFN)
	    && (lan->msg_queue[msg_num].msg.cmd >= 0x40)
	    && (lan->msg_queue[msg_num].msg.cmd <= 0x49)))
    {
	/* IPMB messages have to go through the locking mechanism.
	   Messages that affect the SEL also require locking, but they
	   have special handling because they lock the SEL lock,
	   too. */
	lan->state = LAN_WAIT_LOCK;
	send_lock_msg(lan);
    } else {
	/* Messages to the system interface can go right through. */
	lan->state = LAN_MSG_WAIT_NOLOCK;
	
	lan_send(lan,
		 lan->msg_queue[msg_num].lun,
		 &(lan->msg_queue[msg_num].msg));
    }
}

static void
del_init(msg_del_t *del)
{
    del->handler = NULL;
}

static void
handle_recv_err(ipmi_con_t    *ipmi,
		lan_data_t    *lan,
		unsigned char err,
		msg_del_t     *del)
{
    int msg_num = lan->curr_msg;

    del->data[0] = err;
    del->msg.netfn = lan->msg_queue[msg_num].cmp_msg.netfn | 1;
    del->msg.cmd = lan->msg_queue[msg_num].cmp_msg.cmd;
    del->msg.data = del->data;
    del->msg.data_len = 1;

    if (lan->msg_queue[msg_num].use_orig_addr) {
	memcpy(&del->addr,
	       &(lan->msg_queue[msg_num].orig_addr),
	       lan->msg_queue[msg_num].orig_addr_len);
	del->addr_len = lan->msg_queue[msg_num].orig_addr_len;
    } else {
	memcpy(&del->addr,
	       &(lan->msg_queue[msg_num].addr),
	       lan->msg_queue[msg_num].addr_len);
	del->addr_len = lan->msg_queue[msg_num].addr_len;
    }
    del->handler = lan->msg_queue[msg_num].rsp_handler;
    del->rsp_data = lan->msg_queue[msg_num].rsp_data;
    del->data2 = lan->msg_queue[msg_num].data2;
    del->data3 = lan->msg_queue[msg_num].data3;

    lan->curr_msg = QUEUE_NEXT(lan->curr_msg);
}

static void
deliver(ipmi_con_t *ipmi, msg_del_t *del)
{
    if (del->handler)
	del->handler(ipmi, &(del->addr), del->addr_len, &(del->msg),
		     del->rsp_data, del->data2, del->data3, del->data4);
}

static void
ipmb_handler(ipmi_con_t   *ipmi,
	     int          err,
	     unsigned int ipmb,
	     int          active,
	     void         *cb_data)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    if (err)
	return;

    if (ipmb != lan->slave_addr) {
	lan->slave_addr = ipmb;
	if (lan->ipmb_addr_handler)
	    lan->ipmb_addr_handler(ipmi, err, ipmb, active,
				   lan->ipmb_addr_cb_data);
    }
}

static void
lan_set_ipmb_addr_handler(ipmi_con_t           *ipmi,
			  ipmi_ll_ipmb_addr_cb handler,
			  void                 *cb_data)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    lan->ipmb_addr_handler = handler;
    lan->ipmb_addr_cb_data = cb_data;
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


    /* If we were cancelled, just free the data and ignore the call. */
    if (info->cancelled) {
	goto out_done;
    }

    ipmi_read_lock();

    if (!lan_valid_ipmi(ipmi)) {
	goto out_unlock_done;
    }

    lan = ipmi->con_data;

    if (! lan->connected) {
	send_auth_cap(ipmi, lan);
    } else {
	/* Send message to all addresses we think are down.  If the
           connection is down, this will bring it up, otherwise it
           will keep it alive. */
	for (i=0; i<lan->num_ip_addr; i++) {
	    if (! lan->ip_working[i]) {
		msg.netfn = IPMI_APP_NETFN;
		msg.cmd = IPMI_GET_DEVICE_ID_CMD;
		msg.data = NULL;
		msg.data_len = 0;
		
		lan_send_addr(lan, 0, &msg, i);
	    }
	}
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
	ipmi->send_command(ipmi,
			   (ipmi_addr_t *) &si, sizeof(si),
			   &msg, NULL, NULL, NULL, NULL, NULL);
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

 out_unlock_done:
    ipmi_read_unlock();
 out_done:
    if (info) {
	ipmi->os_hnd->free_timer(ipmi->os_hnd, id);
	ipmi_mem_free(info);
    }
    return;
}

static void
connection_up(lan_data_t *lan, int addr_num, int new_con)
{
    /* The IP is already operational, so ignore this. */
    if (! lan->ip_working[addr_num]) {
	lan->ip_working[addr_num] = 1;

	ipmi_log(IPMI_LOG_INFO, "Connection %d to the BMC is up", addr_num);
    }

    if (new_con) {
	ipmi_log(IPMI_LOG_INFO, "Connection to the BMC restored");
	lan->curr_ip_addr = addr_num;
    }

    if (lan->connected && lan->con_change_handler)
	lan->con_change_handler(lan->ipmi, 0, addr_num, 1,
				lan->con_change_cb_data);
}


static void
lost_connection(lan_data_t *lan, int addr_num)
{
    int i;

    if (! lan->ip_working[addr_num])
	return;

    lan->ip_working[addr_num] = 0;

    ipmi_log(IPMI_LOG_WARNING, "Connection %d to the BMC is down", addr_num);

    if (lan->curr_ip_addr == addr_num) {
	/* Scan to see if any address is operational. */
	for (i=0; i<lan->num_ip_addr; i++) {
	    if (lan->ip_working[i]) {
		lan->curr_ip_addr = i;
		break;
	    }
	}

	if (i >= lan->num_ip_addr) {
	    /* There were no operational connections, report that. */
	    ipmi_log(IPMI_LOG_SEVERE, "All connections to the BMC are down");

	    lan->connected = 0;

	    /* reset the session data. */
	    lan->outbound_seq_num = 0;
	    lan->inbound_seq_num = 0;
	    lan->session_id = 0;
	    lan->recv_msg_map = 0;
	    lan->working_authtype = 0;
	}
    }

    if (lan->con_change_handler)
	lan->con_change_handler(lan->ipmi, ETIMEDOUT, addr_num, lan->connected,
				lan->con_change_cb_data);
}

static void
rsp_timeout_handler(void              *cb_data,
		    os_hnd_timer_id_t *id)
{
    lan_timer_info_t      *info = cb_data;
    ipmi_con_t            *ipmi = info->ipmi;
    lan_data_t            *lan;
    msg_del_t             del;

    /* If we were cancelled, just free the data and ignore the call. */
    if (info->cancelled) {
	goto out_done;
    }

    del_init(&del);

    ipmi_read_lock();

    if (!lan_valid_ipmi(ipmi)) {
	goto out_unlock_done;
    }

    lan = ipmi->con_data;

    lan->op_timeout_countdown--;
    if (lan->op_timeout_countdown > 0) {
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = MXP_RESPONSE_TIMEOUT;
	ipmi->os_hnd->start_timer(ipmi->os_hnd,
				  id,
				  &timeout,
				  rsp_timeout_handler,
				  cb_data);
	ipmi_read_unlock();
	return;
    }

    ipmi_lock(lan->msg_queue_lock);

    lan->conn_fail_retries--;
    if (lan->conn_fail_retries == 0)
	lost_connection(lan, lan->curr_ip_addr);

    lan->retries--;
    if (lan->retries > 0) {
	struct timeval timeout;

	switch (lan->state) {
	    case LAN_IDLE:
		/* FIXME - this shouldn't happen, need a log. */
		goto out_unlock;

	    case LAN_MSG_WAIT_NOLOCK:
	    case LAN_WAIT_SEND_RSP:
	    case LAN_WAIT_SEL_SEND_RSP:
		lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		lan_send(lan,
			 lan->msg_queue[lan->curr_msg].lun,
			 &(lan->msg_queue[lan->curr_msg].msg));
		break;

	    case LAN_WAIT_LOCK:
		lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		send_lock_msg(lan);
		break;

	    case LAN_WAIT_SEL_LOCK:
		lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		send_sel_lock_msg(lan);
		break;

	    case LAN_WAIT_CLEAR:
		lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		send_get_msg(lan);
		break;

	    case LAN_WAIT_GET_RSP:
		lan->op_timeout_countdown = MXP_GET_MSG_TIMEOUT;
		if ((lan->retries % GET_RETRY_RESEND_MOD) == 0) {
		    /* Every once in a while, resend the actual message. */
		    lan_send(lan,
			     lan->msg_queue[lan->curr_msg].lun,
			     &(lan->msg_queue[lan->curr_msg].msg));
		} else {
		    send_get_msg(lan);
		}
		break;

	    case LAN_WAIT_UNLOCK:
		lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		send_unlock_msg(lan);
		break;
	}

	timeout.tv_sec = 0;
	timeout.tv_usec = MXP_RESPONSE_TIMEOUT;
	ipmi->os_hnd->start_timer(ipmi->os_hnd,
				  id,
				  &timeout,
				  rsp_timeout_handler,
				  cb_data);

	ipmi_unlock(lan->msg_queue_lock);
	ipmi_read_unlock();
	return;
    }

    if ((lan->state == LAN_WAIT_LOCK) && (!lan->do_force)) {
	/* If we fail getting the lock and we are not forcing it yet, then
	   try a force. */
	lan->do_force = 1;
	lan->retries = MAX_SEND_RETRIES;
	lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
	send_lock_msg(lan);
    } else if (lan->state == LAN_WAIT_UNLOCK) {
	/* If we fail doing the unlock, don't deliver the failure
           message, just go on. */
	lan->state = LAN_IDLE;
	start_next_msg(ipmi, lan);
    } else {
	handle_recv_err(ipmi, lan, IPMI_TIMEOUT_CC, &del);
	lan->op_timeout_countdown = MXP_GET_MSG_TIMEOUT;
	lan->retries = MAX_SEND_RETRIES;
	lan->state = LAN_WAIT_UNLOCK;
	send_unlock_msg(lan);
    }

    if (lan->state != LAN_IDLE) {
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = MXP_RESPONSE_TIMEOUT;
	ipmi->os_hnd->start_timer(ipmi->os_hnd,
				  id,
				  &timeout,
				  rsp_timeout_handler,
				  cb_data);
	info = NULL; /* Make sure this doesn't get deleted. */
    }

    ipmi_unlock(lan->msg_queue_lock);

    deliver(ipmi, &del);

 out_unlock_done:
    ipmi_read_unlock();
 out_done:
    if (info) {
	ipmi->os_hnd->free_timer(ipmi->os_hnd, id);
	ipmi_mem_free(info);
    }
    return;

 out_unlock:
    ipmi_unlock(lan->msg_queue_lock);
    goto out_unlock_done;
}

static int
handle_recv_msg(ipmi_con_t    *ipmi,
		lan_data_t    *lan,
		unsigned char *tmsg,
		unsigned int  data_len,
		msg_del_t     *del)
{
    int rv = 0;
    int msg_num = lan->curr_msg;

    if (tmsg[5] == IPMI_GET_MSG_CMD) {
	/* It's a response to a sent message. */
	ipmi_ipmb_addr_t *ipmb_addr = (ipmi_ipmb_addr_t *) &(del->addr);

	ipmb_addr->addr_type = IPMI_IPMB_ADDR_TYPE;
	ipmb_addr->channel = 0;
	ipmb_addr->slave_addr = tmsg[10];
	ipmb_addr->lun = tmsg[11] & 0x3;
	del->msg.netfn = tmsg[8] >> 2;
	del->msg.cmd = tmsg[12];
	del->addr_len = sizeof(ipmi_ipmb_addr_t);
	del->msg.data = tmsg+13;
	del->msg.data_len = data_len - 13;
	del->msg.data_len -= 2; /* Remove the checksums. */
    } else {
	/* It's a response directly from the BMC. */
	ipmi_system_interface_addr_t *si_addr
	    = (ipmi_system_interface_addr_t *) &(del->addr);

	si_addr->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si_addr->channel = 0xf;
	si_addr->lun = 0; /* FIXME - should be tmsg[1] & 3; */

	del->msg.netfn = tmsg[1] >> 2;
	del->msg.cmd = tmsg[5];
	del->addr_len = sizeof(ipmi_system_interface_addr_t);
	del->msg.data = tmsg+6;
	del->msg.data_len = data_len - 6;
	del->msg.data_len--; /* Remove the checksum */
    }

    /* Validate that this response if for this command. */
    if (((lan->msg_queue[msg_num].cmp_msg.netfn | 1) != del->msg.netfn)
	|| (lan->msg_queue[msg_num].cmp_msg.cmd != del->msg.cmd)
	|| (! ipmi_addr_equal(&(lan->msg_queue[msg_num].addr),
			      lan->msg_queue[msg_num].addr_len,
			      &(del->addr), del->addr_len)))
    {
	rv = EINVAL;
	goto out;
    }

    if (DEBUG_MSG) {
	ipmi_log(IPMI_LOG_DEBUG_START, "incoming\n addr =");
	dump_hex((unsigned char *) &del->addr, del->addr_len);
	ipmi_log(IPMI_LOG_DEBUG_CONT, "\n NetFN = %x", del->msg.netfn);
	ipmi_log(IPMI_LOG_DEBUG_CONT, "\n Cmd = %x", del->msg.cmd);
	ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =");
	dump_hex(del->msg.data, del->msg.data_len);
	ipmi_log(IPMI_LOG_DEBUG_END, "");
    }

    if (lan->msg_queue[msg_num].use_orig_addr)
    {
	/* If the address was translated, then fix it. */
	memcpy(&del->addr, &lan->msg_queue[msg_num].orig_addr,
	       lan->msg_queue[msg_num].orig_addr_len);
	del->addr_len = lan->msg_queue[msg_num].orig_addr_len;
    }

    /* The command matches up, cancel the timer and deliver it */

    del->handler = lan->msg_queue[msg_num].rsp_handler;
    del->rsp_data = lan->msg_queue[msg_num].rsp_data;
    del->data2 = lan->msg_queue[msg_num].data2;
    del->data3 = lan->msg_queue[msg_num].data3;

    lan->msg_queue[msg_num].rsp_handler = NULL;
    lan->curr_msg = QUEUE_NEXT(msg_num);
 out:
    return rv;
}

static void
data_handler(int            fd,
	     void           *cb_data,
	     os_hnd_fd_id_t *id)
{
    ipmi_con_t         *ipmi = (ipmi_con_t *) cb_data;
    lan_data_t         *lan;
    unsigned char      data[IPMI_MAX_LAN_LEN];
    struct sockaddr    ipaddrd;
    struct sockaddr_in *ipaddr;
    int                rv;
    int                len;
    socklen_t          from_len;
    uint32_t           seq, sess_id;
    unsigned char      *tmsg;
    unsigned int       data_len;
    int                recv_addr;
    msg_del_t          del;
    
    del_init(&del);

    ipmi_read_lock();

    if (!lan_valid_ipmi(ipmi))
	/* We can have due to a race condition, just return and
           everything should be fine. */
	goto out_unlock2;

    lan = ipmi->con_data;

    from_len = sizeof(ipaddrd);
    len = recvfrom(fd, data, sizeof(data), 0, &ipaddrd, &from_len);
    if (len < 0)
	goto out_unlock2;

    if (DEBUG_MSG) {
	ipmi_log(IPMI_LOG_DEBUG_START, "incoming\n addr = ");
	dump_hex((unsigned char *) &ipaddrd, from_len);
	ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =\n  ");
	dump_hex(data, len);
	ipmi_log(IPMI_LOG_DEBUG_END, "");
    }

    /* Make sure the source IP matches what we expect the other end to
       be. */
    ipaddr = (struct sockaddr_in *) &ipaddrd;
    for (recv_addr = 0; recv_addr < lan->num_ip_addr; recv_addr++) {
	if ((ipaddr->sin_port == lan->ip_addr[recv_addr].sin_port)
	    && (ipaddr->sin_addr.s_addr
		== lan->ip_addr[recv_addr].sin_addr.s_addr))
	{
	    break;
	}
    }
    if (recv_addr >= lan->num_ip_addr) {
	if (DEBUG_MSG)
	    ipmi_log(IPMI_LOG_DEBUG, "Dropped message due to invalid IP");
	goto out_unlock2;
    }

    /* Validate the length first, so we know that all the data in the
       buffer we will deal with is valid. */
    if (len < 21) { /* Minimum size of an IPMI msg. */
	if (DEBUG_MSG)
	    ipmi_log(IPMI_LOG_DEBUG, "Dropped message because too small(1)");
	goto out_unlock2;
    }

    if (data[4] == 0) {
	/* No authentication. */
	if (len < (data[13] + 14)) {
	    /* Not enough data was supplied, reject the message. */
	    if (DEBUG_MSG)
		ipmi_log(IPMI_LOG_DEBUG,
			 "Dropped message because too small(2)");
	    goto out_unlock2;
	}
	data_len = data[13];
    } else {
	if (len < 37) { /* Minimum size of an authenticated IPMI msg. */
	    if (DEBUG_MSG)
		ipmi_log(IPMI_LOG_DEBUG,
			 "Dropped message because too small(3)");
	    goto out_unlock2;
	}
	/* authcode in message, add 16 to the above checks. */
	if (len < (data[29] + 30)) {
	    /* Not enough data was supplied, reject the message. */
	    if (DEBUG_MSG)
		ipmi_log(IPMI_LOG_DEBUG,
			 "Dropped message because too small(4)");
	    goto out_unlock2;
	}
	data_len = data[29];
    }

    /* Validate the RMCP portion of the message. */
    if ((data[0] != 6)
	|| (data[2] != 0xff)
	|| (data[3] != 0x07))
    {
	if (DEBUG_MSG)
	    ipmi_log(IPMI_LOG_DEBUG, "Dropped message not valid IPMI/RMCP");
	goto out_unlock2;
    }

    /* FIXME - need a lock on the session data. */

    /* Drop if the authtypes are incompatible. */
    if (lan->working_authtype != data[4]) {
	if (DEBUG_MSG)
	    ipmi_log(IPMI_LOG_DEBUG, "Dropped message not valid authtype");
	goto out_unlock2;
    }

    /* Drop if sessions ID's don't match. */
    sess_id = ipmi_get_uint32(data+9);
    if (sess_id != lan->session_id) {
	if (DEBUG_MSG)
	    ipmi_log(IPMI_LOG_DEBUG, "Dropped message not valid session id");
	goto out_unlock2;
    }

    seq = ipmi_get_uint32(data+5);

    if (data[4] != 0) {
	/* Validate the message's authcode.  Do this before checking
           the session seq num so we know the data is valid. */
	rv = auth_check(lan, data+9, data+5, data+30, data[29], data+13);
	if (rv) {
	    if (DEBUG_MSG)
		ipmi_log(IPMI_LOG_DEBUG, "Dropped message auth fail");
	    goto out_unlock2;
	}
	tmsg = data + 30;
    } else {
	tmsg = data + 14;
    }

    /* If it's from a down connection, report it as up. */
    if (! lan->ip_working[recv_addr])
	connection_up(lan, recv_addr, 0);

    /* Check the sequence number. */
    if ((seq - lan->inbound_seq_num) <= 8) {
	/* It's after the current sequence number, but within 8.  We
           move the sequence number forward. */
	lan->recv_msg_map <<= seq - lan->inbound_seq_num;
	lan->recv_msg_map |= 1;
	lan->inbound_seq_num = seq;
    } else if ((lan->inbound_seq_num - seq) <= 8) {
	/* It's before the current sequence number, but within 8. */
	uint8_t bit = 1 << (lan->inbound_seq_num - seq);
	if (lan->recv_msg_map & bit) {
	    /* We've already received the message, so discard it. */
	    if (DEBUG_MSG)
		ipmi_log(IPMI_LOG_DEBUG, "Dropped message duplicate");
	    goto out_unlock2;
	}

	lan->recv_msg_map |= bit;
    } else {
	/* It's outside the current sequence number range, discard
	   the packet. */
	if (DEBUG_MSG)
	    ipmi_log(IPMI_LOG_DEBUG, "Dropped message out of seq range");
	goto out_unlock2;
    }

    /* Now we have an authentic in-sequence message. */

    /* We don't check the checksums, because the network layer should
       validate all this for us. */

    ipmi_lock(lan->msg_queue_lock);

    switch (lan->state)
    {
	case LAN_IDLE:
	    /* Got a message in a bogus state, ignore it. */
	    goto out_unlock;

	case LAN_MSG_WAIT_NOLOCK:
	    if (handle_recv_msg(ipmi, lan, tmsg, data_len, &del) == 0) {
	        lan->state = LAN_IDLE;
	        start_next_msg(ipmi, lan);
	    }
	    break;
	    
	case LAN_WAIT_LOCK:
	    if (tmsg[5] == MXP_OEM_SET_QUEUE_LOCK_CMD) {
		if (tmsg[6] != 0) {
		    /* We couldn't grab the lock, retry. */
		    send_lock_msg(lan);
		} else if (lan->msg_queue[lan->curr_msg].is_ipmb_msg) {
		    /* We got the lock, and it's going onto the IPMB,
                       next state */
		    lan->retries = MAX_SEND_RETRIES;
		    lan->conn_fail_retries = CONN_FAILED_RETRIES;
		    lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		    lan->state = LAN_WAIT_CLEAR;
		    send_get_msg(lan);
		} else {
		    /* We got a lock and it's an SEL command.  Lock
                       the SEL next. */
		    lan->retries = MAX_SEND_RETRIES;
		    lan->conn_fail_retries = CONN_FAILED_RETRIES;
		    lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		    lan->state = LAN_WAIT_SEL_LOCK;
		    send_sel_lock_msg(lan);
		}
	    }
	    break;

	case LAN_WAIT_SEL_LOCK:
	    if (tmsg[5] == 0x4b) {
		if (tmsg[6] != 0) {
		    /* Got an error, try again. */
		    send_sel_lock_msg(lan);
		} else {
		    lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		    lan->retries = MAX_SEND_RETRIES;
		    lan->conn_fail_retries = CONN_FAILED_RETRIES;
		    lan->state = LAN_WAIT_SEL_SEND_RSP;
		    lan_send(lan,
			     lan->msg_queue[lan->curr_msg].lun,
			     &(lan->msg_queue[lan->curr_msg].msg));
		}
	    }
	    break;

	case LAN_WAIT_SEL_SEND_RSP:
	    if (handle_recv_msg(ipmi, lan, tmsg, data_len, &del) == 0) {
		lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		lan->retries = MAX_SEND_RETRIES;
		lan->conn_fail_retries = CONN_FAILED_RETRIES;
	        lan->state = LAN_WAIT_UNLOCK;
		send_unlock_msg(lan);
	    }
	    break;

	case LAN_WAIT_CLEAR:
	    if (tmsg[5] == IPMI_GET_MSG_CMD) {
		if (tmsg[6] == 0) {
		    /* We grabbed a message from the queue.  Just
                       throw it away and request the next message,
                       since we are clearing the queue. */
		    send_get_msg(lan);
		} else {
		    /* The message queue is clear, so go to the next
                       state, send the actual message. */
		    lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		    lan->retries = MAX_SEND_RETRIES;
		    lan->conn_fail_retries = CONN_FAILED_RETRIES;
		    lan->state = LAN_WAIT_SEND_RSP;
		    lan_send(lan,
			     lan->msg_queue[lan->curr_msg].lun,
			     &(lan->msg_queue[lan->curr_msg].msg));
		}
	    }
	    break;

	case LAN_WAIT_SEND_RSP:
	    if (tmsg[5] == IPMI_SEND_MSG_CMD) {
		if (tmsg[6] == 0x82) {
		    ipmi_msg_t msg;
		    char data[3];
		    unsigned char *addr;

		    /* We got an IPMB problem, send an auto-isolate to
                       the AMC and let this operation timeout and be
                       resent. */
		    addr = (unsigned char *) &ipaddr->sin_addr.s_addr;
		    ipmi_log(IPMI_LOG_WARNING,
			     "Got an IPMB bus lockup on ip %d.%d.%d.%d,"
			     " isolating the bus."
			     "  If this happens often, you probably have"
			     " a hardware problem.",
			     addr[0], addr[1], addr[2], addr[3]);
		    
		    msg.netfn = MXP_NETFN_MXP1;
		    msg.cmd = 0x2a; /* MXP_OEM_SET_AUTO_IPMB_ISOLATE_CMD */
		    msg.data = data;
		    msg.data_len = 3;
		    data[0] = 0xa1;
		    data[1] = 0x00;
		    data[2] = 0x00;
		    lan_send(lan, 0, &msg);
		} else if (tmsg[6] != 0) {
		    /* An error from the send message, terminate the
		       operation. */
		    lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		    lan->retries = MAX_SEND_RETRIES;
		    lan->conn_fail_retries = CONN_FAILED_RETRIES;
		    handle_recv_err(ipmi, lan, tmsg[6], &del);
		    lan->state = LAN_WAIT_UNLOCK;
		    send_unlock_msg(lan);
		} else {
		    lan->op_timeout_countdown = MXP_GET_MSG_TIMEOUT;
		    lan->conn_fail_retries = GET_CONN_FAILED_RETRIES;
	            if (lan->msg_queue[lan->curr_msg].is_broadcast) {
		        lan->retries = MAX_GET_BC_RETRIES;
		    } else {
		        lan->retries = MAX_GET_RETRIES;
		    }
		    lan->state = LAN_WAIT_GET_RSP;
		}
	    }
	    break;

	case LAN_WAIT_GET_RSP:
	    if (tmsg[5] == IPMI_GET_MSG_CMD) {
	        if (tmsg[6] == 0x80) {
		    /* We got a response, so reset the fail retry
                       counter. */
		    lan->conn_fail_retries = GET_CONN_FAILED_RETRIES;
		    lan->op_timeout_countdown = MXP_GET_MSG_TIMEOUT;
		    break;
		} else if (tmsg[6] != 0) {
		    /* An error from the get message, terminate the
		       operation. */
		    handle_recv_err(ipmi, lan, tmsg[6], &del);
		} else {
		    if (handle_recv_msg(ipmi, lan, tmsg, data_len, &del))
			/* Message wasn't handled, so don't go on. */
			goto lan_wait_get_rsp_done;
		}
		lan->op_timeout_countdown = MXP_STD_OP_TIMEOUT;
		lan->conn_fail_retries = CONN_FAILED_RETRIES;
		lan->retries = MAX_SEND_RETRIES;
		lan->state = LAN_WAIT_UNLOCK;
		send_unlock_msg(lan);
	    }
            lan_wait_get_rsp_done:
	    break;

	case LAN_WAIT_UNLOCK:
	    if (tmsg[5] == MXP_OEM_SET_QUEUE_LOCK_CMD) {
		/* We don't care about errors, just go on. */
		lan->state = LAN_IDLE;
		start_next_msg(ipmi, lan);
	    }
	    break;
    }

    if ((lan->timer_info) && (lan->state == LAN_IDLE)) {
	/* We are not doing anything, cancel the timer. */
	rv = ipmi->os_hnd->stop_timer(ipmi->os_hnd, lan->timer);
	if (rv)
	    /* Couldn't cancel the timer, make sure the timer doesn't do the
	       callback. */
	    lan->timer_info->cancelled = 1;
	else {
	    /* Timer is cancelled, free its data. */
	    ipmi->os_hnd->free_timer(ipmi->os_hnd, lan->timer);
	    ipmi_mem_free(lan->timer_info);
	}
	lan->timer_info = NULL;
    }

    ipmi_unlock(lan->msg_queue_lock);

    deliver(ipmi, &del);

 out_unlock2:
    ipmi_read_unlock();
    return;
 out_unlock:
    ipmi_unlock(lan->msg_queue_lock);
    ipmi_read_unlock();
}

static int
lan_send_command(ipmi_con_t            *ipmi,
		 ipmi_addr_t           *addr,
		 unsigned int          addr_len,
		 ipmi_msg_t            *msg,
		 ipmi_ll_rsp_handler_t rsp_handler,
		 void                  *rsp_data,
		 void                  *data2,
		 void                  *data3,
		 void                  *data4)
{
    lan_data_t       *lan;
    int              rv = 0;
    int              msg_num;

    switch (addr->addr_type) {
	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
	case IPMI_IPMB_ADDR_TYPE:
	case IPMI_IPMB_BROADCAST_ADDR_TYPE:
	    break;
	default:
	    return EINVAL;
    }

    /* Don't let the user send send_msg commands. */
    if ((msg->netfn == IPMI_APP_NETFN) && (msg->cmd == IPMI_SEND_MSG_CMD))
	return EINVAL;

    lan = (lan_data_t *) ipmi->con_data;

    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    if (msg->data_len > IPMI_MAX_MSG_LENGTH)
	return EINVAL;

    ipmi_lock(lan->msg_queue_lock);
    if (QUEUE_NEXT(lan->next_msg) == lan->curr_msg) {
	rv = EAGAIN;
	goto out_unlock;
    }

    msg_num = lan->next_msg;

    lan->msg_queue[msg_num].rsp_handler = rsp_handler;
    lan->msg_queue[msg_num].rsp_data = rsp_data;
    lan->msg_queue[msg_num].data2 = data2;
    lan->msg_queue[msg_num].data3 = data3;
    lan->msg_queue[msg_num].data4 = data4;
    memcpy(&(lan->msg_queue[msg_num].addr), addr, addr_len);
    lan->msg_queue[msg_num].addr_len = addr_len;
    lan->msg_queue[msg_num].use_orig_addr = 0;

    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	/* It's a message straight to the BMC, no special formatting. */
	ipmi_system_interface_addr_t *si_addr
	    = (ipmi_system_interface_addr_t *) addr;

	lan->msg_queue[msg_num].lun = si_addr->lun;
	lan->msg_queue[msg_num].msg = *msg;
	lan->msg_queue[msg_num].cmp_msg = *msg;
	lan->msg_queue[msg_num].msg.data = lan->msg_queue[msg_num].data;
	memcpy(lan->msg_queue[msg_num].data, msg->data, msg->data_len);
	lan->msg_queue[msg_num].is_ipmb_msg = 0;
    } else if (((ipmi_ipmb_addr_t *) addr)->slave_addr == lan->slave_addr) {
	ipmi_system_interface_addr_t *si;
	/* Most systems don't handle sending to your own slave
	   address, so we have to translate here. */

	lan->msg_queue[msg_num].use_orig_addr = 1;
	memcpy(&(lan->msg_queue[msg_num].orig_addr), addr, addr_len);
	lan->msg_queue[msg_num].orig_addr_len = addr_len;

	si = (ipmi_system_interface_addr_t *) &lan->msg_queue[msg_num].addr;
	si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si->channel = IPMI_BMC_CHANNEL;
	si->lun = ((ipmi_ipmb_addr_t *) addr)->lun;
	lan->msg_queue[msg_num].addr_len = sizeof(*si);

	lan->msg_queue[msg_num].lun = si->lun;
	lan->msg_queue[msg_num].msg = *msg;
	lan->msg_queue[msg_num].cmp_msg = *msg;
	lan->msg_queue[msg_num].msg.data = lan->msg_queue[msg_num].data;
	memcpy(lan->msg_queue[msg_num].data, msg->data, msg->data_len);
	lan->msg_queue[msg_num].is_ipmb_msg = 0;
    } else {
	/* It's an IPMB message, encapsulate it. */
	ipmi_ipmb_addr_t *ipmb_addr = (ipmi_ipmb_addr_t *) addr;
	unsigned char    *tmsg;
	unsigned int     pos;
	unsigned int     msgstart;

	lan->msg_queue[msg_num].lun = 0;
	lan->msg_queue[msg_num].msg.netfn = IPMI_APP_NETFN;
	lan->msg_queue[msg_num].msg.cmd = IPMI_SEND_MSG_CMD;
	lan->msg_queue[msg_num].msg.data = lan->msg_queue[msg_num].data;
	lan->msg_queue[msg_num].is_ipmb_msg = 1;

	tmsg = lan->msg_queue[msg_num].data;

	lan->msg_queue[msg_num].cmp_msg = *msg;

	pos = 0;
	tmsg[pos++] = ipmb_addr->channel;
	if (addr->addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE){
	    /* The response will come back as a normal address. */
            lan->msg_queue[msg_num].addr.addr_type = IPMI_IPMB_ADDR_TYPE;
#if 0
	    /* We currently don't to the broadcast, it looks like it
               screws up some power supplies.  This technically
               violates the spec, but there's no I2C devices on the
               IPMB in the MXP chassis, so it shouldn't hurt
               anything. */
	    tmsg[pos++] = 0; /* Do a broadcast. */
#endif
	    lan->msg_queue[msg_num].is_broadcast = 1;
	} else {
	    lan->msg_queue[msg_num].is_broadcast = 0;
	}
	msgstart = pos;
	tmsg[pos++] = ipmb_addr->slave_addr;
	tmsg[pos++] = (msg->netfn << 2) | ipmb_addr->lun;
	tmsg[pos++] = ipmb_checksum(tmsg+msgstart, 2);
	msgstart = pos;
	tmsg[pos++] = 0x20;
	tmsg[pos++] = 0x2;
	tmsg[pos++] = msg->cmd;
	memcpy(tmsg+pos, msg->data, msg->data_len);
	pos += msg->data_len;
	tmsg[pos] = ipmb_checksum(tmsg+msgstart, pos-msgstart);
	pos++;
	lan->msg_queue[msg_num].msg.data_len = pos;
    }

    lan->retries = MAX_SEND_RETRIES;
    lan->conn_fail_retries = CONN_FAILED_RETRIES;

    if (lan->state == LAN_IDLE) {
	struct timeval   timeout;
	lan_timer_info_t *info;

	info = ipmi_mem_alloc(sizeof(*info));
	if (!info) {
	    rv = ENOMEM;
	    goto out_unlock;
	}
	info->cancelled = 0;
	info->ipmi = ipmi;

	/* The interface is idle, start the message now. */
	timeout.tv_sec = 0;
	timeout.tv_usec = MXP_RESPONSE_TIMEOUT;
	rv = ipmi->os_hnd->alloc_timer(ipmi->os_hnd, &(lan->timer));
	if (!rv) {
	    rv = ipmi->os_hnd->start_timer(ipmi->os_hnd,
					   lan->timer,
					   &timeout,
					   rsp_timeout_handler,
					   info);
	    if (rv)
		ipmi->os_hnd->free_timer(ipmi->os_hnd, lan->timer);
	}
	if (rv) {
	    ipmi_mem_free(info);
	    goto out_unlock;
	}

	lan->timer_info = info;
	lan->next_msg = QUEUE_NEXT(lan->next_msg);
	start_next_msg(ipmi, lan);
    } else {
	/* Something else is using the interface, just queue it. */
	lan->next_msg = QUEUE_NEXT(lan->next_msg);
    }

 out_unlock:
    ipmi_unlock(lan->msg_queue_lock);
    return rv;
}

static int
lan_register_for_events(ipmi_con_t                 *ipmi,
			ipmi_ll_evt_handler_t      handler,
			void                       *event_data,
			void                       *data2,
			ipmi_ll_event_handler_id_t **id)
{
    return ENOSYS;
}

static int
lan_deregister_for_events(ipmi_con_t                 *ipmi,
			  ipmi_ll_event_handler_id_t *id)
{
    return ENOSYS;
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
send_close_session(ipmi_con_t *ipmi, lan_data_t *lan)
{
    ipmi_msg_t                   msg;
    unsigned char                data[4];

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_CLOSE_SESSION_CMD;
    msg.data_len = 4;
    msg.data = data;
    ipmi_set_uint32(data, lan->session_id);
    lan_send_addr(lan, 0, &msg, lan->curr_ip_addr);
}

static int
lan_close_connection(ipmi_con_t *ipmi)
{
    lan_data_t *lan;
    int        rv;
    int        i;

    if (! lan_valid_ipmi(ipmi)) {
	return EINVAL;
    }

    /* First order of business is to remove it from the LAN list. */
    lan = (lan_data_t *) ipmi->con_data;

    ipmi_write_lock();
    if (lan->next)
	lan->next->prev = lan->prev;
    if (lan->prev)
	lan->prev->next = lan->next;
    else
	lan_list = lan->next;
    ipmi_write_unlock();

    /* After this point no other operations can occur on this ipmi
       interface, so it's safe. */

    send_close_session(ipmi, lan);

    ipmi_lock(lan->msg_queue_lock);
    for (i=lan->curr_msg; i!=lan->next_msg; i=lan->curr_msg) {
	msg_del_t del;

	lan->curr_msg = QUEUE_NEXT(i);
	ipmi_unlock(lan->msg_queue_lock);
	handle_recv_err(ipmi, lan, IPMI_UNKNOWN_ERR_CC, &del);
	deliver(ipmi, &del);
	ipmi_lock(lan->msg_queue_lock);
    }
    ipmi_unlock(lan->msg_queue_lock);
    if (lan->audit_info) {
	rv = ipmi->os_hnd->stop_timer(ipmi->os_hnd, lan->audit_timer);
	if (rv)
	    lan->audit_info->cancelled = 1;
	else {
	    ipmi->os_hnd->free_timer(ipmi->os_hnd, lan->audit_timer);
	    ipmi_mem_free(lan->audit_info);
	}
    }

    if (lan->msg_queue_lock)
	ipmi_destroy_lock(lan->msg_queue_lock);
    if (lan->fd_wait_id)
	ipmi->os_hnd->remove_fd_to_wait_for(ipmi->os_hnd, lan->fd_wait_id);
    if (lan->authdata)
	ipmi_auths[lan->authtype].authcode_cleanup(lan->authdata);

    /* Close the fd after we have deregistered it. */
    close(lan->fd);

    ipmi_mem_free(lan);
    ipmi_mem_free(ipmi);

    return 0;
}

static ll_ipmi_t lan_ll_ipmi =
{
    .valid_ipmi = lan_valid_ipmi,
    .registered = 0
};

static void
cleanup_con(ipmi_con_t *ipmi)
{
    lan_data_t   *lan = (lan_data_t *) ipmi->con_data;
    os_handler_t *handlers = ipmi->os_hnd;

    if (ipmi) {
	ipmi_mem_free(ipmi);
    }

    if (lan) {
	lan = (lan_data_t *) ipmi->con_data;

	ipmi_write_lock();
	if (lan->next)
	    lan->next->prev = lan->prev;
	if (lan->prev)
	    lan->prev->next = lan->next;
	else
	    lan_list = lan->next;
	ipmi_write_unlock();

	if (lan->msg_queue_lock)
	    ipmi_destroy_lock(lan->msg_queue_lock);
	if (lan->fd != -1)
	    close(lan->fd);
	if (lan->fd_wait_id)
	    handlers->remove_fd_to_wait_for(handlers, lan->fd_wait_id);
	if (lan->authdata)
	    ipmi_auths[lan->authtype].authcode_cleanup(lan->authdata);
	ipmi_mem_free(lan);
    }
}

static void
handle_connected(ipmi_con_t *ipmi, int err)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;
    int        i;

    if (lan->con_change_handler) {
	/* Report everything up. */
	for (i=0; i<lan->num_ip_addr; i++)
	{
	    if (lan->ip_working[i])
		lan->con_change_handler(ipmi, err, i, lan->connected,
					lan->con_change_cb_data);
	}
    }
}

static void
finish_start_con(void *cb_data, os_hnd_timer_id_t *id)
{
    ipmi_con_t *ipmi = cb_data;

    ipmi->os_hnd->free_timer(ipmi->os_hnd, id);

    handle_connected(ipmi, 0);
}

static void
finish_connection(ipmi_con_t *ipmi, lan_data_t *lan)
{
    lan->connected = 1;
    if (! lan->initialized) {
	struct timeval    timeout;
	os_hnd_timer_id_t *timer;
	int               rv;

	lan->initialized = 1;

	/* Schedule this to run in a timeout, so we are not holding
           the read lock. */
	rv = ipmi->os_hnd->alloc_timer(ipmi->os_hnd, &timer);
	if (rv) {
	    handle_connected(ipmi, rv);
	    return;
	}

	timeout.tv_sec = 0;
	timeout.tv_usec = 0;
	rv = ipmi->os_hnd->start_timer(ipmi->os_hnd,
				       timer,
				       &timeout,
				       finish_start_con,
				       ipmi);
	if (rv) {
	    ipmi->os_hnd->free_timer(ipmi->os_hnd, timer);
	    handle_connected(ipmi, rv);
	    return;
	}
    } else {
	connection_up(lan, lan->curr_ip_addr, 1);
    }
}

static void
lan_set_ipmb_addr(ipmi_con_t *ipmi, unsigned char ipmb, int active)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    if (lan->slave_addr != ipmb) {
	lan->slave_addr = ipmb;
	if (lan->ipmb_addr_handler)
	    lan->ipmb_addr_handler(ipmi, 0, ipmb, active,
				   lan->ipmb_addr_cb_data);
    }
}

static void
handle_ipmb_addr(ipmi_con_t   *ipmi,
		 int          err,
		 unsigned int ipmb_addr,
		 int          active,
		 void         *cb_data)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    if (err) {
	handle_connected(ipmi, err);
	return;
    }

    lan->slave_addr = ipmb_addr;
    finish_connection(ipmi, lan);
    if (lan->ipmb_addr_handler)
	lan->ipmb_addr_handler(ipmi, err, ipmb_addr, active,
			       lan->ipmb_addr_cb_data);
}

static void
handle_dev_id(ipmi_con_t   *ipmi,
	      ipmi_addr_t  *addr,
	      unsigned int addr_len,
	      ipmi_msg_t   *msg,
	      void         *rsp_data1,
	      void         *rsp_data2,
	      void         *rsp_data3,
	      void         *rsp_data4)
{
    lan_data_t        *lan = (lan_data_t *) ipmi->con_data;
    int               err;
    unsigned int      manufacturer_id;
    unsigned int      product_id;

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

    err = ipmi_check_oem_conn_handlers(ipmi, manufacturer_id, product_id);
    if (err)
	goto out_err;

    if (ipmi->get_ipmb_addr) {
	/* We have a way to fetch the IPMB address, do so. */
	err = ipmi->get_ipmb_addr(ipmi, handle_ipmb_addr, NULL);
	if (err)
	    goto out_err;
    } else
	finish_connection(ipmi, lan);
    return;

 out_err:
    handle_connected(ipmi, err);
}

static int
send_get_dev_id(ipmi_con_t *ipmi, lan_data_t *lan)
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

    rv = lan_send_command(ipmi, (ipmi_addr_t *) &addr, sizeof(addr),
			  &msg, handle_dev_id,
			  NULL, NULL, NULL, NULL);
    return rv;
}

static void session_privilege_set(ipmi_con_t   *ipmi,
				  ipmi_addr_t  *addr,
				  unsigned int addr_len,
				  ipmi_msg_t   *msg,
				  void         *rsp_data,
				  void         *data2,
				  void         *data3,
				  void         *data4)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;
    int        rv;

    if (msg->data[0] != 0) {
        handle_connected(ipmi, IPMI_IPMI_ERR_VAL(msg->data[0]));
	return;
    }

    if (msg->data_len < 2) {
        handle_connected(ipmi, EINVAL);
	return;
    }

    if (lan->privilege != (msg->data[1] & 0xf)) {
	/* Requested privilege level did not match. */
        handle_connected(ipmi, EINVAL);
	return;
    }

    rv = send_get_dev_id(ipmi, lan);
    if (rv)
        handle_connected(ipmi, rv);
}

static int
send_set_session_privilege(ipmi_con_t *ipmi, lan_data_t *lan)
{
    unsigned char		 data[IPMI_MAX_MSG_LENGTH];
    ipmi_msg_t			 msg;
    int				 rv;
    ipmi_system_interface_addr_t addr;

    addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    addr.channel = 0xf;
    addr.lun = 0;

    data[0] = lan->privilege;

    msg.cmd = IPMI_SET_SESSION_PRIVILEGE_CMD;
    msg.netfn = IPMI_APP_NETFN;
    msg.data = data;
    msg.data_len = 1;

    rv = lan_send_command(ipmi, (ipmi_addr_t *) &addr, sizeof(addr),
			  &msg, session_privilege_set,
			  NULL, NULL, NULL, NULL);
    return rv;
}

static void session_activated(ipmi_con_t   *ipmi,
			      ipmi_addr_t  *addr,
			      unsigned int addr_len,
			      ipmi_msg_t   *msg,
			      void         *rsp_data,
			      void         *data2,
			      void         *data3,
			      void         *data4)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;
    int        rv;


    if (msg->data[0] != 0) {
        handle_connected(ipmi, IPMI_IPMI_ERR_VAL(msg->data[0]));
	return;
    }

    if (msg->data_len < 11) {
        handle_connected(ipmi, EINVAL);
	return;
    }

    lan->working_authtype = msg->data[1] & 0xf;
    if ((lan->working_authtype != 0)
	&& (lan->working_authtype != lan->authtype))
    {
	/* Eh?  It didn't return a valid authtype. */
        handle_connected(ipmi, EINVAL);
	return;
    }

    lan->session_id = ipmi_get_uint32(msg->data+2);
    lan->outbound_seq_num = ipmi_get_uint32(msg->data+6);

    rv = send_set_session_privilege(ipmi, lan);
    if (rv)
        handle_connected(ipmi, rv);
}

static int
send_activate_session(ipmi_con_t *ipmi, lan_data_t *lan)
{
    unsigned char                data[IPMI_MAX_MSG_LENGTH];
    ipmi_msg_t                   msg;
    int                          rv;
    ipmi_system_interface_addr_t addr;

    addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    addr.channel = 0xf;
    addr.lun = 0;

    data[0] = lan->authtype;
    data[1] = lan->privilege;
    memcpy(data+2, lan->challenge_string, 16);
    ipmi_set_uint32(data+18, lan->inbound_seq_num);

    msg.cmd = IPMI_ACTIVATE_SESSION_CMD;
    msg.netfn = IPMI_APP_NETFN;
    msg.data = data;
    msg.data_len = 22;

    rv = lan_send_command(ipmi, (ipmi_addr_t *) &addr, sizeof(addr),
			  &msg, session_activated,
			  NULL, NULL, NULL, NULL);
    return rv;
}

static void challenge_done(ipmi_con_t   *ipmi,
			   ipmi_addr_t  *addr,
			   unsigned int addr_len,
			   ipmi_msg_t   *msg,
			   void         *rsp_data,
			   void         *data2,
			   void         *data3,
			   void         *data4)
{
    lan_data_t    *lan = (lan_data_t *) ipmi->con_data;
    int           rv;


    if (msg->data[0] != 0) {
        handle_connected(ipmi, IPMI_IPMI_ERR_VAL(msg->data[0]));
	return;
    }

    if (msg->data_len < 21) {
        handle_connected(ipmi, EINVAL);
	return;
    }

    /* Get the temporary session id. */
    lan->session_id = ipmi_get_uint32(msg->data+1);

    lan->outbound_seq_num = 0;
    lan->working_authtype = lan->authtype;
    memcpy(lan->challenge_string, msg->data+5, 16);

    /* Get a random number of the other end to start sending me sequence
       numbers at, but don't let it be zero. */
    while (lan->inbound_seq_num == 0) {
	rv = ipmi->os_hnd->get_random(ipmi->os_hnd,
				      &(lan->inbound_seq_num), 4);
	if (!rv) {
	    handle_connected(ipmi, rv);
	    return;
	}
    }

    rv = send_activate_session(ipmi, lan);
    if (rv) {
        handle_connected(ipmi, rv);
	return;
    }

}

static int
send_challenge(ipmi_con_t *ipmi, lan_data_t *lan)
{
    unsigned char                data[IPMI_MAX_MSG_LENGTH];
    ipmi_msg_t                   msg;
    ipmi_system_interface_addr_t addr;
    int                          rv;

    addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    addr.channel = 0xf;
    addr.lun = 0;

    data[0] = lan->authtype;
    msg.cmd = IPMI_GET_SESSION_CHALLENGE_CMD;
    msg.netfn = IPMI_APP_NETFN;
    msg.data = data;
    msg.data_len = 1;
    memcpy(data+1, lan->username, IPMI_USERNAME_MAX);
    msg.data_len += IPMI_USERNAME_MAX;

    rv = lan_send_command(ipmi, (ipmi_addr_t *) &addr, sizeof(addr),
			  &msg, challenge_done, NULL, NULL, NULL, NULL);
    return rv;
}

static void
auth_cap_done(ipmi_con_t   *ipmi,
	      ipmi_addr_t  *addr,
	      unsigned int addr_len,
	      ipmi_msg_t   *msg,
	      void         *rsp_data,
	      void         *data2,
	      void         *data3,
	      void         *data4)
{
    lan_data_t    *lan = (lan_data_t *) ipmi->con_data;
    int           rv;


    if ((msg->data[0] != 0) || (msg->data_len < 9)) {
	handle_connected(ipmi, EINVAL);
	return;
    }

    if (!(msg->data[2] & (1 << lan->authtype))) {
        ipmi_log(IPMI_LOG_ERR_INFO, "Requested authentication not supported");
        handle_connected(ipmi, EINVAL);
	return;
    }

    rv = send_challenge(ipmi, lan);
    if (rv) {
        ipmi_log(IPMI_LOG_ERR_INFO,
		 "Unable to send challenge command: 0x%x", rv);
        handle_connected(ipmi, rv);
    }
}

static int
send_auth_cap(ipmi_con_t *ipmi, lan_data_t *lan)
{
    unsigned char                data[IPMI_MAX_MSG_LENGTH];
    ipmi_msg_t                   msg;
    ipmi_system_interface_addr_t addr;
    int                          rv;

    addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    addr.channel = 0xf;
    addr.lun = 0;

    data[0] = 0xe;
    data[1] = lan->privilege;
    msg.cmd = IPMI_GET_CHANNEL_AUTH_CAPABILITIES_CMD;
    msg.netfn = IPMI_APP_NETFN;
    msg.data = data;
    msg.data_len = 2;

    rv = lan_send_command(ipmi, (ipmi_addr_t *) &addr, sizeof(addr),
			  &msg, auth_cap_done, NULL, NULL, NULL, NULL);
    return rv;
}

static void
lan_set_con_change_handler(ipmi_con_t             *ipmi,
			   ipmi_ll_con_changed_cb handler,
			   void                   *cb_data)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;

    lan->con_change_handler = handler;
    lan->con_change_cb_data = cb_data;
}

static int
lan_start_con(ipmi_con_t *ipmi)
{
    lan_data_t     *lan = (lan_data_t *) ipmi->con_data;
    int            rv;
    struct timeval timeout;

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

    rv = send_auth_cap(ipmi, lan);
    if (rv)
	goto out_err;

 out_err:
    return rv;
}

int
mxp_lan_setup_con(struct in_addr            *ip_addrs,
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
		  unsigned char             swid,
		  ipmi_con_t                **new_con)
{
    ipmi_con_t     *ipmi = NULL;
    lan_data_t     *lan = NULL;
    int            rv;
    int            i;

    if (username_len > IPMI_USERNAME_MAX)
	return EINVAL;
    if (password_len > IPMI_PASSWORD_MAX)
	return EINVAL;
    if ((authtype >= MAX_IPMI_AUTHS)
	|| (ipmi_auths[authtype].authcode_init == NULL))
	return EINVAL;
    if ((num_ip_addrs < 1) || (num_ip_addrs > MAX_IP_ADDR))
	return EINVAL;

    /* Make sure we register before anything else. */
    ipmi_register_ll(&lan_ll_ipmi);

    ipmi = ipmi_mem_alloc(sizeof(*ipmi));
    if (!ipmi)
	return ENOMEM;
    memset(ipmi, 0, sizeof(*ipmi));

    ipmi->user_data = user_data;
    ipmi->os_hnd = handlers;

    lan = ipmi_mem_alloc(sizeof(*lan));
    if (!lan) {
	rv = ENOMEM;
	goto out_err;
    }
    memset(lan, 0, sizeof(*lan));
    ipmi->con_data = lan;

    lan->ipmi = ipmi;
    lan->slave_addr = 0x20; /* Assume this until told otherwise */
    lan->authtype = authtype;
    lan->privilege = privilege;

    for (i=0; i<num_ip_addrs; i++) {
	lan->ip_addr[i].sin_family = AF_INET;
	lan->ip_addr[i].sin_port = htons(ports[i]);
	lan->ip_addr[i].sin_addr = ip_addrs[i];
	lan->ip_working[i] = 0;
    }
    lan->num_ip_addr = num_ip_addrs;
    lan->curr_ip_addr = 0;
    lan->num_sends = 0;
    lan->connected = 0;
    lan->initialized = 0;

    lan->curr_msg = 0;
    lan->next_msg = 0;
    lan->state = LAN_IDLE;
    lan->swid = swid;

    lan->fd = open_lan_fd();
    if (lan->fd == -1) {
	rv = errno;
	goto out_err;
    }

    /* Create the locks if they are available. */
    rv = ipmi_create_lock_os_hnd(handlers, &lan->msg_queue_lock);
    if (rv)
	goto out_err;

    memcpy(lan->username, username, username_len);
    lan->username_len = username_len;
    memcpy(lan->password, password, password_len);
    lan->password_len = password_len;

    ipmi->start_con = lan_start_con;
    ipmi->set_ipmb_addr = lan_set_ipmb_addr;
    ipmi->set_ipmb_addr_handler = lan_set_ipmb_addr_handler;
    ipmi->set_con_change_handler = lan_set_con_change_handler;
    ipmi->send_command = lan_send_command;
    ipmi->register_for_events = lan_register_for_events;
    ipmi->deregister_for_events = lan_deregister_for_events;
    ipmi->send_response = lan_send_response;
    ipmi->register_for_command = lan_register_for_command;
    ipmi->deregister_for_command = lan_deregister_for_command;
    ipmi->close_connection = lan_close_connection;

    /* Add the waiter last. */
    rv = handlers->add_fd_to_wait_for(handlers,
				      lan->fd,
				      data_handler, 
				      ipmi,
				      &(lan->fd_wait_id));
    if (rv)
	goto out_err;

    rv = ipmi_auths[authtype].authcode_init(lan->password, &(lan->authdata),
					    NULL, auth_alloc, auth_free);
    if (rv)
	goto out_err;

    /* Add it to the list of valid IPMIs so it will validate. */
    ipmi_write_lock();
    if (lan_list)
	lan_list->prev = lan;
    lan->next = lan_list;
    lan->prev = NULL;
    lan_list = lan;
    ipmi_write_unlock();

    *new_con = ipmi;

    return 0;

 out_err:
    cleanup_con(ipmi);
    return rv;
}
