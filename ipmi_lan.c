/*
 * ipmi_lan.c
 *
 * MontaVista IPMI code for handling IPMI LAN connections
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
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

#include <malloc.h>
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

#include <ipmi/ipmi_conn.h>
#include <ipmi/ipmi_msgbits.h>
#include <ipmi/ipmi_int.h>
#include <ipmi/ipmi_auth.h>
#include <ipmi/ipmi_err.h>
#include <ipmi/ipmi_lan.h>

#define DEBUG_MSG

#ifdef DEBUG_MSG
static void
dump_hex(unsigned char *data, int len)
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

#define MAX_SEND_RETRIES 3

struct ipmi_ll_event_handler_id_s
{
    ipmi_con_t            *ipmi;
    ipmi_ll_evt_handler_t handler;
    void                  *event_data;
    void                  *data2;

    ipmi_ll_event_handler_id_t *next, *prev;
};

typedef struct lan_timer_info_s
{
    int          cancelled;
    ipmi_con_t   *ipmi;
    unsigned int seq;
} lan_timer_info_t;

typedef struct lan_data_s
{
    ipmi_con_t                 *ipmi;
    int                        fd;

    struct sockaddr_in         addr;

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
	unsigned char         data[IPMI_MAX_MSG_LENGTH];
	ipmi_ll_rsp_handler_t rsp_handler;
	void                  *rsp_data;
	void                  *data2;
	void                  *data3;
	os_hnd_timer_id_t     *timer;
	lan_timer_info_t      *timer_info;
	unsigned int          retries;
    } seq_table[64];
    ipmi_lock_t               *seq_num_lock;
    unsigned int              last_seq;


    unsigned int               retries;
    os_hnd_timer_id_t          *timer;

    os_hnd_fd_id_t             *fd_wait_id;
    ipmi_ll_event_handler_id_t *event_handlers;
    ipmi_lock_t                *event_handlers_lock;

    struct lan_data_s *next, *prev;
} lan_data_t;

static lan_data_t *lan_list = NULL;

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

/* Must be called with event_lock held. */
static void
add_event_handler(ipmi_con_t                 *ipmi,
		  lan_data_t                 *lan,
		  ipmi_ll_event_handler_id_t *event)
{
    event->ipmi = ipmi;

    event->next = lan->event_handlers;
    event->prev = NULL;
    if (lan->event_handlers)
	lan->event_handlers->prev = event;
    lan->event_handlers = event;
}

static void
remove_event_handler(lan_data_t                 *lan,
		     ipmi_ll_event_handler_id_t *event)
{
    if (event->next)
	event->next->prev = event->prev;
    if (event->prev)
	event->prev->next = event->next;
    else
	lan->event_handlers = event->next;
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
	 unsigned char *data,
	 unsigned int  data_len)
{
    int rv;
    ipmi_auth_sg_t l[] =
    { { &lan->session_id,       4  },
      { data,                   data_len },
      { &lan->outbound_seq_num, 4 },
      { NULL,                   0 }};

    rv = ipmi_auths[lan->working_authtype].authcode_gen(lan->authdata, l, out);
    return rv;
}

static int
auth_check(lan_data_t    *lan,
	   uint32_t      ses_id,
	   uint32_t      seq,
	   unsigned char *data,
	   unsigned int  data_len,
	   unsigned char *code)
{
    int rv;
    ipmi_auth_sg_t l[] =
    { { &ses_id, 4  },
      { data,    data_len },
      { &seq,    4 },
      { NULL,    0 }};

    rv = ipmi_auths[lan->working_authtype].authcode_check(lan->authdata,
							  l,
							  code);
    return rv;
}
	 
#define IPMI_MAX_LAN_LEN (IPMI_MAX_MSG_LENGTH + 42)
static int
lan_send(lan_data_t  *lan,
	 ipmi_addr_t *addr,
	 int         addr_len,
	 ipmi_msg_t  *msg,
	 uint8_t     seq)
{
    unsigned char data[IPMI_MAX_LAN_LEN];
    unsigned char *tmsg;
    int           pos;
    int           msgstart;
    int           rv;

    switch (addr->addr_type) {
	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
	case IPMI_IPMB_ADDR_TYPE:
	case IPMI_IPMB_BROADCAST_ADDR_TYPE:
	    break;
	default:
	    return EINVAL;
    }

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

    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	/* It's a message straight to the BMC. */
	ipmi_system_interface_addr_t *si_addr
	    = (ipmi_system_interface_addr_t *) &addr;

	tmsg[0] = 0x20; /* To the BMC. */
	tmsg[1] = (msg->netfn << 2) | si_addr->lun;
	tmsg[2] = ipmb_checksum(tmsg, 2);
	tmsg[3] = 0x81; /* Remote console IPMI Software ID */
	tmsg[4] = (seq << 2) | 0x2;
	tmsg[5] = msg->cmd;
	memcpy(tmsg+6, msg->data, msg->data_len);
	pos = msg->data_len + 6;
	tmsg[pos] = ipmb_checksum(tmsg+3, pos-3);
	pos++;
    } else {
	/* It's an IPMB address, route it using a send message
           command. */
	ipmi_ipmb_addr_t *ipmb_addr = (ipmi_ipmb_addr_t *) &addr;

	pos = 0;
	tmsg[pos++] = 0x20; /* BMC is the bridge. */
	tmsg[pos++] = (IPMI_APP_NETFN << 2) | 0;
	tmsg[pos++] = ipmb_checksum(tmsg, 2);
	tmsg[pos++] = 0x81; /* Remote console IPMI Software ID */
	tmsg[pos++] = (seq << 2) | 0x2;
	tmsg[pos++] = IPMI_SEND_MSG_CMD;
	tmsg[pos++] = ipmb_addr->channel;
	if (addr->addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE)
	    tmsg[pos++] = 0; /* Do a broadcast. */
	msgstart = pos;
	tmsg[pos++] = ipmb_addr->slave_addr;
	tmsg[pos++] = (msg->netfn << 2) | ipmb_addr->lun;
	tmsg[pos++] = ipmb_checksum(tmsg+msgstart, 2);
	msgstart = pos;
	tmsg[pos++] = 0x81;
	tmsg[pos++] = (seq << 2) | 0x2;
	tmsg[pos++] = msg->cmd;
	memcpy(tmsg+pos, msg->data, msg->data_len);
	pos += msg->data_len;
	tmsg[pos] = ipmb_checksum(tmsg+msgstart, pos-msgstart);
	pos++;
	tmsg[pos] = ipmb_checksum(tmsg+3, pos-3);
	pos++;
    }

    if (lan->working_authtype == 0) {
	/* No authentication, so no authcode. */
	data[13] = pos;
	pos += 14; /* Convert to pos in data */
    } else {
	data[29] = pos;
	rv = auth_gen(lan, data+13, tmsg, pos);
	if (!rv)
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

#ifdef DEBUG_MSG
    printf("outgoing\n addr =");
    dump_hex((unsigned char *) &(lan->addr), sizeof(lan->addr));
    printf("\n data =\n  ");
    dump_hex(data, pos);
    printf("\n");
#endif    

    rv = sendto(lan->fd, data, pos, 0,
		(struct sockaddr *) &(lan->addr), sizeof(lan->addr));
    if (rv == -1)
	rv = errno;
    else
	rv = 0;

    return rv;
}

static void
rsp_timeout_handler(void              *cb_data,
		    os_hnd_timer_id_t *id)
{
    lan_timer_info_t      *info = cb_data;
    ipmi_con_t            *ipmi = info->ipmi;
    lan_data_t            *lan;
    ipmi_msg_t            msg;
    unsigned char         data[1];
    int                   seq;
    ipmi_addr_t           addr;
    unsigned int          addr_len;
    ipmi_ll_rsp_handler_t handler;
    void                  *rsp_data;
    void                  *data2;
    void                  *data3;

    ipmi_read_lock();

    if (!lan_valid_ipmi(ipmi)) {
	goto out_unlock2;
    }

    lan = ipmi->con_data;
    seq = info->seq;

    ipmi_lock(lan->seq_num_lock);

    /* If we were cancelled, just free the data and ignore it. */
    if (info->cancelled) {
	goto out_unlock;
    }

    if (lan->seq_table[seq].rsp_handler == NULL)
	goto out_unlock;

    lan->seq_table[seq].retries++;
    if (lan->seq_table[seq].retries <= MAX_SEND_RETRIES)
    {
	struct timeval timeout;
	int            rv;

	/* Note that we will need a new session seq # here, we can't reuse
	   the old one.  If the message got lost on the way back, the other
	   end would silently ignore resends of the seq #. */
	rv = lan_send(lan,
		      &(lan->seq_table[seq].addr),
		      lan->seq_table[seq].addr_len,
		      &(lan->seq_table[seq].msg),
		      seq);

	if (!rv) {
	    timeout.tv_sec = IPMI_RSP_TIMEOUT / 1000;
	    timeout.tv_usec = (IPMI_RSP_TIMEOUT % 1000) * 1000;
	    ipmi->os_hnd->restart_timer(id, &timeout);
	}
	if (rv) {
	    /* If we get an error resending the message, report an unknown
	       error. */
	    data[0] = IPMI_UNKNOWN_ERR_CC;
	} else {
	    ipmi_unlock(lan->seq_num_lock);
	    ipmi_read_unlock();
	    return;
	}
    } else {
	data[0] = IPMI_TIMEOUT_CC;
    }

    msg.netfn = lan->seq_table[seq].msg.netfn | 1;
    msg.cmd = lan->seq_table[seq].msg.cmd;
    msg.data = data;
    msg.data_len = 1;

    memcpy(&addr, &(lan->seq_table[seq].addr), lan->seq_table[seq].addr_len);
    addr_len = lan->seq_table[seq].addr_len;
    handler = lan->seq_table[seq].rsp_handler;
    rsp_data = lan->seq_table[seq].rsp_data;
    data2 = lan->seq_table[seq].data2;
    data3 = lan->seq_table[seq].data3;

    lan->seq_table[seq].rsp_handler = NULL;
    ipmi_unlock(lan->seq_num_lock);

    handler(ipmi, &addr, addr_len, &msg, rsp_data, data2, data3);

 out_unlock:
    ipmi_unlock(lan->seq_num_lock);
 out_unlock2:
    ipmi_read_unlock();
    free(info);
}

static void
handle_async_event(ipmi_con_t   *ipmi,
		   ipmi_addr_t  *addr,
		   unsigned int addr_len,
		   ipmi_msg_t   *msg)
{
    lan_data_t                 *lan = (lan_data_t *) ipmi->con_data;
    ipmi_ll_event_handler_id_t *elem, *next;

    ipmi_lock(lan->event_handlers_lock);
    elem = lan->event_handlers;
    while (elem != NULL) {
	/* Fetch the next element now, so the user can delete the
           current one. */
	next = elem->next;

	/* call the user handler. */
	elem->handler(ipmi, addr, addr_len, msg, elem->event_data, elem->data2);

	elem = next;
    }
    ipmi_unlock(lan->event_handlers_lock);
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
    ipmi_msg_t         msg;
    int                rv;
    int                len;
    socklen_t          from_len;
    uint32_t           seq, sess_id;
    unsigned char      *tmsg;
    ipmi_addr_t        addr;
    unsigned int       addr_len;
    unsigned int       data_len;
    
    ipmi_ll_rsp_handler_t handler;
    void                  *rsp_data;
    void                  *data2;
    void                  *data3;

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

#ifdef DEBUG_MSG
    printf("incoming\n addr = ");
    dump_hex((unsigned char *) &ipaddrd, from_len);
    printf("\n data =\n  ");
    dump_hex(data, len);
    printf("\n");
#endif

    /* Make sure the source IP matches what we expect the other end to
       be. */
    ipaddr = (struct sockaddr_in *) &ipaddrd;
    if ((ipaddr->sin_port != lan->addr.sin_port)
	|| (ipaddr->sin_addr.s_addr != lan->addr.sin_addr.s_addr))
	goto out_unlock2;

    /* Validate the length first, so we know that all the data in the
       buffer we will deal with is valid. */
    if (len < 21) /* Minimum size of an IPMI msg. */
	goto out_unlock2;
    if (data[4] == 0) {
	/* No authentication. */
	if (len < (data[13] + 14))
	    /* Not enough data was supplied, reject the message. */
	    goto out_unlock2;
	data_len = data[13];
    } else {
	if (len < 37) /* Minimum size of an authenticated IPMI msg. */
	    goto out_unlock2;
	/* authcode in message, add 16 to the above checks. */
	if (len < (data[29] + 30))
	    /* Not enough data was supplied, reject the message. */
	    goto out_unlock2;
	data_len = data[29];
    }

    /* Validate the RMCP portion of the message. */
    if ((data[0] != 6)
	|| (data[2] != 0xff)
	|| (data[3] != 0x07))
	goto out_unlock2;

    /* FIXME - need a lock on the session data. */

    /* Drop if the authtypes are incompatible. */
    if (lan->working_authtype != data[4])
	goto out_unlock2;

    /* Drop if sessions ID's don't match. */
    sess_id = ipmi_get_uint32(data+9);
    if (sess_id != lan->session_id)
	goto out_unlock2;

    seq = ipmi_get_uint32(data+5);
    if (data[4] != 0) {
	/* Validate the message's authcode.  Do this before checking
           the session seq num so we know the data is valid. */
	rv = auth_check(lan, sess_id, seq, data+30, data[29], data+13);
	if (rv)
	    goto out_unlock2;
	tmsg = data + 30;
    } else {
	tmsg = data + 14;
    }

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
	if (lan->recv_msg_map & bit)
	    /* We've already received the message, so discard it. */
	    goto out_unlock2;

	lan->recv_msg_map |= bit;
    } else {
	/* It's outside the current sequence number range, discard
	   the packet. */
	goto out_unlock2;
    }

    /* Now we have an authentic in-sequence message. */

    /* We don't check the checksums, because the network layer should
       validate all this for us. */

    if (tmsg[5] == IPMI_SEND_MSG_CMD) {
	/* It's a response to a sent message. */
	ipmi_ipmb_addr_t *ipmb_addr = (ipmi_ipmb_addr_t *) &addr;

	seq = tmsg[11] >> 2;
	ipmb_addr->addr_type = IPMI_IPMB_ADDR_TYPE;
	ipmb_addr->slave_addr = tmsg[10];
	ipmb_addr->lun = tmsg[11] & 0x3;
	msg.netfn = tmsg[8] >> 2;
	msg.cmd = tmsg[12];
	addr_len = sizeof(ipmi_ipmb_addr_t);
	msg.data = tmsg+13;
	msg.data_len = data_len - 13;
    } else if (tmsg[5] == IPMI_READ_EVENT_MSG_BUFFER_CMD) {
	/* It an event from the event buffer. */
	ipmi_system_interface_addr_t *si_addr
	    = (ipmi_system_interface_addr_t *) &addr;

	if (tmsg[6] != 0)
	    /* An error getting the events, just ignore it. */
	    goto out_unlock2;

	si_addr->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si_addr->channel = 0xf;

	msg.netfn = tmsg[1] >> 2;
	msg.cmd = tmsg[5];
	addr_len = sizeof(ipmi_system_interface_addr_t);
	msg.data = tmsg+6;
	msg.data_len = data_len - 6;
	handle_async_event(ipmi, &addr, addr_len, &msg);
	goto out_unlock2;
    } else {
	/* It's a response directly from the BMC. */
	ipmi_system_interface_addr_t *si_addr
	    = (ipmi_system_interface_addr_t *) &addr;

	si_addr->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si_addr->channel = 0xf;

	seq = tmsg[4] >> 2;
	msg.netfn = tmsg[1] >> 2;
	msg.cmd = tmsg[5];
	addr_len = sizeof(ipmi_system_interface_addr_t);
	msg.data = tmsg+6;
	msg.data_len = data_len - 6;
    }
    
    ipmi_lock(lan->seq_num_lock);
    if (lan->seq_table[seq].rsp_handler == NULL)
	goto out_unlock2;

    /* Validate that this response if for this command. */
    if (((lan->seq_table[seq].msg.netfn | 1) != msg.netfn)
	|| (lan->seq_table[seq].msg.cmd != msg.cmd)
	|| (! ipmi_addr_equal(&(lan->seq_table[seq].addr),
			      lan->seq_table[seq].addr_len,
			      &addr, addr_len)))
	goto out_unlock2;

    /* The command matches up, cancel the timer and deliver it */
    rv = ipmi->os_hnd->remove_timer(lan->seq_table[seq].timer);
    if (rv)
	/* Couldn't cancel the timer, make sure the timer doesn't do the
	   callback. */
	lan->seq_table[seq].timer_info->cancelled = 1;
    else
	/* Time is cancelled, free its data. */
	free(lan->seq_table[seq].timer_info);

    handler = lan->seq_table[seq].rsp_handler;
    rsp_data = lan->seq_table[seq].rsp_data;
    data2 = lan->seq_table[seq].data2;
    data3 = lan->seq_table[seq].data3;
    lan->seq_table[seq].rsp_handler = NULL;
    ipmi_unlock(lan->seq_num_lock);

    handler(ipmi, &addr, addr_len, &msg, rsp_data, data2, data3);
    
 out_unlock2:
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
		 void                  *data3)
{
    lan_timer_info_t *info;
    lan_data_t       *lan;
    struct timeval   timeout;
    int              rv;
    unsigned int     seq;


    lan = (lan_data_t *) ipmi->con_data;

    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    if (msg->data_len > IPMI_MAX_MSG_LENGTH)
	return EINVAL;

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    /* Put it in the list first. */
    info->ipmi = ipmi;
    info->cancelled = 0;

    ipmi_lock(lan->seq_num_lock);
    seq = (lan->last_seq + 1) % 64;
    while (lan->seq_table[seq].rsp_handler != NULL) {
	if (seq == lan->last_seq) {
	    rv = EAGAIN;
	    goto out_unlock;
	}

	seq = (seq + 1) % 64;
    }

    info->seq = seq;
    lan->seq_table[seq].rsp_handler = rsp_handler;
    lan->seq_table[seq].rsp_data = rsp_data;
    lan->seq_table[seq].data2 = data2;
    lan->seq_table[seq].data3 = data3;
    memcpy(&(lan->seq_table[seq].addr), addr, addr_len);
    lan->seq_table[seq].addr_len = addr_len;
    lan->seq_table[seq].msg = *msg;
    lan->seq_table[seq].msg.data = lan->seq_table[seq].data;
    memcpy(lan->seq_table[seq].data, msg->data, msg->data_len);
    lan->seq_table[seq].timer_info = info;
    lan->seq_table[seq].retries = 0;

    timeout.tv_sec = IPMI_RSP_TIMEOUT / 1000;
    timeout.tv_usec = (IPMI_RSP_TIMEOUT % 1000) * 1000;
    rv = ipmi->os_hnd->add_timer(&timeout,
				 rsp_timeout_handler,
				 info,
				 &(lan->seq_table[seq].timer));
    if (rv) {
	lan->seq_table[seq].rsp_handler = NULL;
	goto out_unlock;
    }

    rv = lan_send(lan, addr, addr_len, msg, seq);
    if (rv) {
	int err;

	lan->seq_table[seq].rsp_handler = NULL;
	err = ipmi->os_hnd->remove_timer(lan->seq_table[seq].timer);
	/* Special handling, if we can't remove the timer, then it
           will time out on us, so we need to not free the command and
           instead let the timeout handle freeing it. */
	if (err) {
	    info->cancelled = 1;
	    info = NULL;
	}
	goto out_unlock;
    }

 out_unlock:
    ipmi_unlock(lan->seq_num_lock);
    if ((rv) && (info))
	free(info);
    return rv;
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

static int
lan_register_for_events(ipmi_con_t                 *ipmi,
			ipmi_ll_evt_handler_t      handler,
			void                       *event_data,
			void                       *data2,
			ipmi_ll_event_handler_id_t **id)
{
    lan_data_t                 *lan;
    int                        rv = 0;
    ipmi_ll_event_handler_id_t *entry;

    lan = (lan_data_t *) ipmi->con_data;

    entry = malloc(sizeof(*entry));
    if (!entry) {
	rv = ENOMEM;
	goto out_unlock2;
    }

    entry->handler = handler;
    entry->event_data = event_data;
    entry->data2 = data2;

    ipmi_lock(lan->event_handlers_lock);
    add_event_handler(ipmi, lan, entry);
    ipmi_unlock(lan->event_handlers_lock);
 out_unlock2:
    return rv;
}

static int
lan_deregister_for_events(ipmi_con_t                 *ipmi,
			  ipmi_ll_event_handler_id_t *id)
{
    lan_data_t *lan;
    int        rv = 0;

    lan = (lan_data_t *) ipmi->con_data;

    if (id->ipmi != ipmi) {
	rv = EINVAL;
	goto out_unlock2;
    }

    ipmi_lock(lan->event_handlers_lock);
    remove_event_handler(lan, id);
    id->ipmi = NULL;
    free(id);
    ipmi_unlock(lan->event_handlers_lock);
 out_unlock2:

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

static int
lan_close_connection(ipmi_con_t *ipmi)
{
    lan_data_t                 *lan;
    ipmi_ll_event_handler_id_t *evt_to_free, *next_evt;
    int                        rv;
    int                        i;

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

    ipmi_lock(lan->seq_num_lock);
    for (i=0; i<64; i++) {
	if (lan->seq_table[i].rsp_handler) {
	    rv = ipmi->os_hnd->remove_timer(lan->seq_table[i].timer);
	    if (rv)
		lan->seq_table[i].timer_info->cancelled = 1;
	    else
		free(lan->seq_table[i].timer_info);

	    lan->seq_table[i].rsp_handler = NULL;
	}
    }
    ipmi_unlock(lan->seq_num_lock);

    evt_to_free = lan->event_handlers;
    lan->event_handlers = NULL;
    while (evt_to_free) {
	evt_to_free->ipmi = NULL;
	next_evt = evt_to_free->next;
	free(evt_to_free);
	evt_to_free = next_evt;
    }

    if (lan->event_handlers_lock)
	ipmi_destroy_lock(lan->event_handlers_lock);
    if (lan->seq_num_lock)
	ipmi_destroy_lock(lan->seq_num_lock);
    if (lan->fd_wait_id)
	ipmi->os_hnd->remove_fd_to_wait_for(lan->fd_wait_id);
    if (lan->authdata)
	ipmi_auths[lan->authtype].authcode_cleanup(lan->authdata);

    /* Close the fd after we have deregistered it. */
    close(lan->fd);

    free(lan);
    free(ipmi);

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
	free(ipmi);
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

	if (lan->event_handlers_lock)
	    ipmi_destroy_lock(lan->event_handlers_lock);
	if (lan->seq_num_lock)
	    ipmi_destroy_lock(lan->seq_num_lock);
	if (lan->fd != -1)
	    close(lan->fd);
	if (lan->fd_wait_id)
	    handlers->remove_fd_to_wait_for(lan->fd_wait_id);
	if (lan->authdata)
	    ipmi_auths[lan->authtype].authcode_cleanup(lan->authdata);
	free(lan);
    }
}

static void session_activated(ipmi_con_t   *ipmi,
			      ipmi_addr_t  *addr,
			      unsigned int addr_len,
			      ipmi_msg_t   *msg,
			      void         *rsp_data,
			      void         *data2,
			      void         *data3)
{
    lan_data_t *lan = (lan_data_t *) ipmi->con_data;
    int        rv;


    if (msg->data[0] != 0) {
	if (ipmi->setup_cb)
	    ipmi->setup_cb(NULL,
			   ipmi->setup_cb_data,
			   IPMI_IPMI_ERR_VAL(msg->data[0]));
	cleanup_con(ipmi);
	return;
    }

    if (msg->data_len < 11) {
	if (ipmi->setup_cb)
	    ipmi->setup_cb(NULL, ipmi->setup_cb_data, EINVAL);
	cleanup_con(ipmi);
	return;
    }

    lan->working_authtype = msg->data[1] & 0xf;
    if ((lan->working_authtype != 0)
	&& (lan->working_authtype != lan->authtype))
    {
	/* Eh?  It didn't return a valid authtype. */
	if (ipmi->setup_cb)
	    ipmi->setup_cb(NULL, ipmi->setup_cb_data, EINVAL);
	cleanup_con(ipmi);
	return;
    }

    lan->session_id = ipmi_get_uint32(msg->data+2);
    lan->outbound_seq_num = ipmi_get_uint32(msg->data+6);

    rv = ipmi_init_con(ipmi, addr, addr_len);
    if (rv) {
	if (ipmi->setup_cb)
	    ipmi->setup_cb(NULL, ipmi->setup_cb_data, EINVAL);
	cleanup_con(ipmi);
    }
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
    ipmi_set_uint32(msg.data+18, lan->inbound_seq_num);

    msg.cmd = IPMI_GET_SESSION_CHALLENGE_CMD;
    msg.netfn = IPMI_APP_NETFN;
    msg.data = data;
    msg.data_len = 22;

    rv = lan_send_command(ipmi, (ipmi_addr_t *) &addr, sizeof(addr),
			  &msg, session_activated,
			  NULL, NULL, NULL);
    return rv;
}

static void challenge_done(ipmi_con_t   *ipmi,
			   ipmi_addr_t  *addr,
			   unsigned int addr_len,
			   ipmi_msg_t   *msg,
			   void         *rsp_data,
			   void         *data2,
			   void         *data3)
{
    lan_data_t    *lan = (lan_data_t *) ipmi->con_data;
    int           rv;


    if (msg->data[0] != 0) {
	if (ipmi->setup_cb)
	    ipmi->setup_cb(NULL,
			   ipmi->setup_cb_data,
			   IPMI_IPMI_ERR_VAL(msg->data[0]));
	cleanup_con(ipmi);
	return;
    }

    if (msg->data_len < 21) {
	if (ipmi->setup_cb)
	    ipmi->setup_cb(NULL, ipmi->setup_cb_data, EINVAL);
	cleanup_con(ipmi);
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
	rv = ipmi->os_hnd->get_random(&(lan->inbound_seq_num), 4);
	if (rv) {
	    if (ipmi->setup_cb)
		ipmi->setup_cb(NULL, ipmi->setup_cb_data, rv);
	    cleanup_con(ipmi);
	    return;
	}
    }

    lan->retries = 0;
    rv = send_activate_session(ipmi, lan);
    if (rv) {
	if (ipmi->setup_cb)
	    ipmi->setup_cb(NULL, ipmi->setup_cb_data, rv);
	cleanup_con(ipmi);
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
			  &msg, challenge_done, NULL, NULL, NULL);
    return rv;
}

int
ipmi_lan_setup_con(struct in_addr    addr,
		   int               port,
		   unsigned int      authtype,
		   unsigned int      privilege,
		   void              *username,
		   unsigned int      username_len,
		   void              *password,
		   unsigned int      password_len,
		   os_handler_t      *handlers,
		   void              *user_data,
		   ipmi_setup_done_t setup_cb,
		   void              *cb_data)
{
    ipmi_con_t    *ipmi = NULL;
    lan_data_t    *lan = NULL;
    int           rv;


    if (username_len > IPMI_USERNAME_MAX)
	return EINVAL;
    if (password_len > IPMI_PASSWORD_MAX)
	return EINVAL;
    if ((authtype >= MAX_IPMI_AUTHS)
	|| (ipmi_auths[authtype].authcode_init == NULL))
	return EINVAL;

    /* Make sure we register before anything else. */
    ipmi_register_ll(&lan_ll_ipmi);

    ipmi = malloc(sizeof(*ipmi));
    if (!ipmi)
	return ENOMEM;

    ipmi->user_data = user_data;
    ipmi->os_hnd = handlers;

    lan = malloc(sizeof(*lan));
    if (!lan) {
	rv = ENOMEM;
	goto out_err;
    }
    memset(lan, 0, sizeof(*lan));
    ipmi->con_data = lan;

    lan->ipmi = ipmi;
    lan->authtype = authtype;
    lan->privilege = privilege;

    lan->addr.sin_family = AF_INET;
    lan->addr.sin_port = htons(port);
    lan->addr.sin_addr = addr;

    lan->fd = open_lan_fd();
    if (lan->fd == -1) {
	rv = errno;
	goto out_err;
    }

    /* Create the locks if they are available. */
    rv = ipmi_create_lock_os_hnd(handlers, &lan->seq_num_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock_os_hnd(handlers, &lan->event_handlers_lock);
    if (rv)
	goto out_err;

    memcpy(lan->username, username, username_len);
    lan->username_len = username_len;
    memcpy(lan->password, password, password_len);
    lan->password_len = password_len;

    ipmi->send_command = lan_send_command;
    ipmi->register_for_events = lan_register_for_events;
    ipmi->deregister_for_events = lan_deregister_for_events;
    ipmi->send_response = lan_send_response;
    ipmi->register_for_command = lan_register_for_command;
    ipmi->deregister_for_command = lan_deregister_for_command;
    ipmi->close_connection = lan_close_connection;

    /* Add the waiter last. */
    rv = handlers->add_fd_to_wait_for(lan->fd,
				      data_handler, 
				      ipmi,
				      &(lan->fd_wait_id));
    if (rv)
	goto out_err;

    rv = ipmi_auths[authtype].authcode_init(lan->password, &(lan->authdata));
    if (rv)
	goto out_err;

    ipmi->setup_cb = setup_cb;
    ipmi->setup_cb_data = cb_data;

    /* Add it to the list of valid IPMIs so it will validate. */
    ipmi_write_lock();
    if (lan_list)
	lan_list->prev = lan;
    lan->next = lan_list;
    lan->prev = NULL;
    lan_list = lan;
    ipmi_write_unlock();

    lan->retries = 0;
    rv = send_challenge(ipmi, lan);
    if (rv)
	goto out_err;

    return rv;

 out_err:
    cleanup_con(ipmi);
    return rv;
}
