/*
 * ipmi_smi.h
 *
 * MontaVista IPMI code for handling system management connections
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

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <linux/ipmi.h>
#include <net/af_ipmi.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_event.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_err.h>

/* We time the SMI messages, but we have a long timer. */
#define SMI_TIMEOUT 60000

#define SMI_AUDIT_TIMEOUT 10000000
#if !defined(MIN)
#define MIN(x,y) ((x)<(y)?(x):(y))
#endif

#ifdef DEBUG_MSG
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

typedef struct audit_timer_info_s
{
    int        cancelled;
    ipmi_con_t *ipmi;
} audit_timer_info_t;

typedef struct pending_cmd_s
{
    ipmi_con_t            *ipmi;
    ipmi_msg_t            msg;
    ipmi_addr_t           addr;
    unsigned int          addr_len;
    ipmi_ll_rsp_handler_t rsp_handler;
    ipmi_msgi_t           *rsp_item;
    int                   use_orig_addr;
    ipmi_addr_t           orig_addr;
    unsigned int          orig_addr_len;
    struct pending_cmd_s  *next, *prev;
} pending_cmd_t;

typedef struct cmd_handler_s
{
    unsigned char         netfn;
    unsigned char         cmd;
    ipmi_ll_cmd_handler_t handler;
    void                  *cmd_data;
    void                  *data2, *data3;

    struct cmd_handler_s *next, *prev;
} cmd_handler_t;

struct ipmi_ll_event_handler_id_s
{
    ipmi_con_t            *ipmi;
    ipmi_ll_evt_handler_t handler;
    void                  *event_data;
    void                  *data2;

    ipmi_ll_event_handler_id_t *next, *prev;
};

typedef struct smi_data_s
{
    ipmi_con_t                 *ipmi;
    int                        using_socket;
    int                        fd;
    int                        if_num;
    pending_cmd_t              *pending_cmds;
    ipmi_lock_t                *cmd_lock;
    cmd_handler_t              *cmd_handlers;
    ipmi_lock_t                *cmd_handlers_lock;
    os_hnd_fd_id_t             *fd_wait_id;
    ipmi_ll_event_handler_id_t *event_handlers;
    ipmi_lock_t                *event_handlers_lock;

    unsigned char              slave_addr;

    os_hnd_timer_id_t          *audit_timer;
    audit_timer_info_t         *audit_info;

    ipmi_ll_con_changed_cb     con_change_handler;
    void                       *con_change_cb_data;

    ipmi_ll_ipmb_addr_cb ipmb_addr_handler;
    void                 *ipmb_addr_cb_data;

    struct smi_data_s *next, *prev;
} smi_data_t;

static smi_data_t *smi_list = NULL;

/* Must be called with the ipmi read or write lock. */
static int smi_valid_ipmi(ipmi_con_t *ipmi)
{
    smi_data_t *elem;

    elem = smi_list;
    while ((elem) && (elem->ipmi != ipmi)) {
	elem = elem->next;
    }

    return (elem != NULL);
}

/* Must be called with cmd_lock held. */
static void
add_cmd(ipmi_con_t    *ipmi,
	ipmi_addr_t   *addr,
	unsigned int  addr_len,
	ipmi_msg_t    *msg,
	smi_data_t    *smi,
	pending_cmd_t *cmd)
{
    cmd->ipmi = ipmi;
    memcpy(&(cmd->addr), addr, addr_len);
    cmd->addr_len = addr_len;
    cmd->msg = *msg;
    cmd->msg.data = NULL;

    cmd->next = smi->pending_cmds;
    cmd->prev = NULL;
    if (smi->pending_cmds)
	smi->pending_cmds->prev = cmd;
    smi->pending_cmds = cmd;
}

static void
remove_cmd(ipmi_con_t    *ipmi,
	   smi_data_t    *smi,
	   pending_cmd_t *cmd)
{
    if (cmd->next)
	cmd->next->prev = cmd->prev;
    if (cmd->prev)
	cmd->prev->next = cmd->next;
    else
	smi->pending_cmds = cmd->next;
}

/* Must be called with event_lock held. */
static void
add_event_handler(ipmi_con_t                 *ipmi,
		  smi_data_t                 *smi,
		  ipmi_ll_event_handler_id_t *event)
{
    event->ipmi = ipmi;

    event->next = smi->event_handlers;
    event->prev = NULL;
    if (smi->event_handlers)
	smi->event_handlers->prev = event;
    smi->event_handlers = event;
}

static void
remove_event_handler(smi_data_t                 *smi,
		     ipmi_ll_event_handler_id_t *event)
{
    if (event->next)
	event->next->prev = event->prev;
    if (event->prev)
	event->prev->next = event->next;
    else
	smi->event_handlers = event->next;
}

static int
add_cmd_registration(ipmi_con_t            *ipmi,
		     unsigned char         netfn,
		     unsigned char         cmd,
		     ipmi_ll_cmd_handler_t handler,
		     void                  *cmd_data,
		     void                  *data2,
		     void                  *data3)
{
    cmd_handler_t *elem, *finder;
    smi_data_t    *smi = (smi_data_t *) ipmi->con_data;

    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem)
	return ENOMEM;

    elem->netfn = netfn;
    elem->cmd = cmd;
    elem->handler = handler;
    elem->cmd_data = cmd_data;
    elem->data2 = data2;
    elem->data3 = data3;

    ipmi_lock(smi->cmd_handlers_lock);
    finder = smi->cmd_handlers;
    while (finder != NULL) {
	if ((finder->netfn == netfn) && (finder->cmd == cmd)) {
	    ipmi_unlock(smi->cmd_handlers_lock);
	    ipmi_mem_free(elem);
	    return EEXIST;
	}
	finder = finder->next;
    }

    elem->next = smi->cmd_handlers;
    elem->prev = NULL;
    if (smi->cmd_handlers)
	smi->cmd_handlers->prev = elem;
    smi->cmd_handlers = elem;
    ipmi_unlock(smi->cmd_handlers_lock);

    return 0;
}

int
remove_cmd_registration(ipmi_con_t    *ipmi,
			unsigned char netfn,
			unsigned char cmd)
{
    smi_data_t    *smi = (smi_data_t *) ipmi->con_data;
    cmd_handler_t *elem;

    ipmi_lock(smi->cmd_handlers_lock);
    elem = smi->cmd_handlers;
    while (elem != NULL) {
	if ((elem->netfn == netfn) && (elem->cmd == cmd))
	    break;

	elem = elem->next;
    }
    if (!elem) {
	ipmi_unlock(smi->cmd_handlers_lock);
	return ENOENT;
    }

    if (elem->next)
	elem->next->prev = elem->prev;
    if (elem->prev)
	elem->prev->next = elem->next;
    else
	smi->cmd_handlers = elem->next;
    ipmi_unlock(smi->cmd_handlers_lock);

    return 0;
}

static int
open_smi_fd(int if_num, int *using_socket)
{
    char                 devname[30];
    int                  fd;
    struct sockaddr_ipmi addr;
    int                  rv;

    fd = socket(PF_IPMI, SOCK_DGRAM, 0);
    if (fd == -1)
	goto try_dev;
    addr.sipmi_family = AF_IPMI;
    addr.if_num = if_num;
    rv = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
    if (rv != -1) {
	*using_socket = 1;
	goto out;
    }

    *using_socket = 0;
 try_dev:
    sprintf(devname, "/dev/ipmidev/%d", if_num);
    fd = open(devname, O_RDWR);
    if (fd == -1) {
	sprintf(devname, "/dev/ipmi/%d", if_num);
	fd = open(devname, O_RDWR);
	if (fd == -1) {
	    sprintf(devname, "/dev/ipmi%d", if_num);
	    fd = open(devname, O_RDWR);
	}
    }

 out:
    return fd;
}

static int
smi_send(smi_data_t   *smi,
	 int          fd,
	 ipmi_addr_t  *addr,
	 unsigned int addr_len,
	 ipmi_msg_t   *msg,
	 long         msgid)
{
    int rv;
    ipmi_addr_t myaddr;

    if (DEBUG_MSG) {
	ipmi_log(IPMI_LOG_DEBUG_START, "outgoing msgid=%08lx\n addr =", msgid);
	dump_hex((unsigned char *) addr, addr_len);
        ipmi_log(IPMI_LOG_DEBUG_CONT,
                 "\n msg  = netfn=%s cmd=%s data_len=%d.",
		 ipmi_get_netfn_string(msg->netfn),
                 ipmi_get_command_string(msg->netfn, msg->cmd), msg->data_len);
	if ( msg->data_len ) {
	        ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =\n  ");
	        dump_hex((unsigned char *)msg->data, msg->data_len);
	}
	ipmi_log(IPMI_LOG_DEBUG_END, "\n");
    }

    if ((addr->addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE)
	&& (smi->ipmi->broadcast_broken))
    {
	memcpy(&myaddr, addr, addr_len);
	myaddr.addr_type = IPMI_IPMB_ADDR_TYPE;
	addr = &myaddr;
	/* FIXME - this will still be a 5 second timeout, need to fix
	   that. */
    }

    if (msg->data_len > IPMI_MAX_MSG_LENGTH)
	return EMSGSIZE;

    if (smi->using_socket) {
	struct sockaddr_ipmi     saddr;
        char                     smsg_data[sizeof(struct ipmi_sock_msg)
                                           + IPMI_MAX_MSG_LENGTH];
        struct ipmi_sock_msg     *smsg = (void *) smsg_data;

	saddr.sipmi_family = AF_IPMI;
	memcpy(&saddr.ipmi_addr, addr, addr_len);

	smsg->netfn = msg->netfn;
	smsg->cmd = msg->cmd;
	smsg->data_len = msg->data_len;
	smsg->msgid = msgid;
	memcpy(smsg->data, msg->data, smsg->data_len);

	rv = sendto(fd, smsg, sizeof(*smsg) + msg->data_len, 0,
		    (struct sockaddr *) &saddr,
		    addr_len + SOCKADDR_IPMI_OVERHEAD);
    } else {
	struct ipmi_req req;
	req.addr = (unsigned char *) addr;
	req.addr_len = addr_len;
	req.msgid = (long) smi;
	req.msg = *msg;
	req.msgid = msgid;
	rv = ioctl(fd, IPMICTL_SEND_COMMAND, &req);
    }

    if (rv == -1)
	return errno;

    return 0;
}

static void
set_ipmb_in_dev(smi_data_t *smi)
{
    unsigned int slave_addr = smi->slave_addr;
    int          rv;

    if (smi->using_socket)
	rv = ioctl(smi->fd, SIOCIPMISETADDR, &slave_addr);
    else
	rv = ioctl(smi->fd, IPMICTL_SET_MY_ADDRESS_CMD, &slave_addr);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sipmi_smi.c(set_ipmb_in_dev): "
		 "Error setting IPMB address: 0x%x",
		 IPMI_CONN_NAME(smi->ipmi), errno);
    }
}

static void
ipmb_handler(ipmi_con_t   *ipmi,
	     int          err,
	     unsigned int ipmb,
	     int          active,
	     unsigned int hacks,
	     void         *cb_data)
{
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;

    if (err)
	return;

    if (ipmb != smi->slave_addr) {
	smi->slave_addr = ipmb;
	if (smi->ipmb_addr_handler)
	    smi->ipmb_addr_handler(ipmi, err, ipmb, active, 0,
				   smi->ipmb_addr_cb_data);

	set_ipmb_in_dev(smi);
    }
}

static void
smi_set_ipmb_addr_handler(ipmi_con_t           *ipmi,
			  ipmi_ll_ipmb_addr_cb handler,
			  void                 *cb_data)
{
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;

    smi->ipmb_addr_handler = handler;
    smi->ipmb_addr_cb_data = cb_data;
}

static void
audit_timeout_handler(void              *cb_data,
		      os_hnd_timer_id_t *id)
{
    audit_timer_info_t           *info = cb_data;
    ipmi_con_t                   *ipmi = info->ipmi;
    smi_data_t                   *smi;
    struct timeval               timeout;
    ipmi_msg_t                   msg;
    ipmi_system_interface_addr_t si;


    /* If we were cancelled, just free the data and ignore the call. */
    if (info->cancelled) {
	goto out_done;
    }

    ipmi_read_lock();

    if (!smi_valid_ipmi(ipmi)) {
	goto out_unlock_done;
    }

    smi = ipmi->con_data;

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
			   &msg, NULL, NULL);
    }

    timeout.tv_sec = SMI_AUDIT_TIMEOUT / 1000000;
    timeout.tv_usec = SMI_AUDIT_TIMEOUT % 1000000;
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
handle_response(ipmi_con_t *ipmi, struct ipmi_recv *recv)
{
    smi_data_t            *smi = (smi_data_t *) ipmi->con_data;
    pending_cmd_t         *cmd, *finder;
    ipmi_ll_rsp_handler_t rsp_handler;
    ipmi_msgi_t           *rspi;

    cmd = (pending_cmd_t *) recv->msgid;
    
    ipmi_lock(smi->cmd_lock);

    finder = smi->pending_cmds;
    while (finder) {
	if (finder == cmd)
	    break;
	finder = finder->next;
    }
    if (!finder)
	/* The command was not found. */
	goto out_unlock;

    /* We have found the command, handle it. */

    /* Extract everything we need from the command here. */
    rsp_handler = cmd->rsp_handler;
    rspi = cmd->rsp_item;

    remove_cmd(ipmi, smi, cmd);

    ipmi_unlock(smi->cmd_lock);

    if (cmd->use_orig_addr) {
	/* We did an address translation, make sure the address is the one
	   that was previously provided. */
	memcpy(&rspi->addr, &cmd->orig_addr, cmd->orig_addr_len);
	rspi->addr_len = cmd->orig_addr_len;
    } else {
	memcpy(&rspi->addr, (ipmi_addr_t *) recv->addr, recv->addr_len);
	rspi->addr_len = recv->addr_len;
    }

    ipmi_mem_free(cmd);
    cmd = NULL; /* It's gone after this point. */

    ipmi_handle_rsp_item_copymsg(ipmi, rspi, &recv->msg, rsp_handler);

    return;

 out_unlock:
    ipmi_unlock(smi->cmd_lock);
}

static ipmi_mcid_t invalid_mcid = IPMI_MCID_INVALID;

static void
handle_async_event(ipmi_con_t *ipmi, struct ipmi_recv *recv)
{
    smi_data_t                 *smi = (smi_data_t *) ipmi->con_data;
    ipmi_ll_event_handler_id_t *elem, *next;
    ipmi_event_t               *event;
    ipmi_time_t                timestamp;
    unsigned int               type = recv->msg.data[2];
    unsigned int               record_id = ipmi_get_uint16(recv->msg.data);

    if (type < 0xe0)
	timestamp = ipmi_seconds_to_time(ipmi_get_uint32(recv->msg.data+3));
    else
	timestamp = -1;
    event = ipmi_event_alloc(invalid_mcid,
			     record_id,
			     type,
			     timestamp,
			     recv->msg.data+3, 13);
    if (!event)
	/* We missed it here, but the SEL fetch should catch it later. */
	return;

    ipmi_lock(smi->event_handlers_lock);
    elem = smi->event_handlers;
    while (elem != NULL) {
	/* Fetch the next element now, so the user can delete the
           current one. */
	next = elem->next;

	/* call the user handler. */
	elem->handler(ipmi,
		      (ipmi_addr_t *) &(recv->addr), recv->addr_len,
		      event, elem->event_data, elem->data2);

	elem = next;
    }
    ipmi_unlock(smi->event_handlers_lock);
    ipmi_event_free(event);
}

static void
handle_incoming_command(ipmi_con_t *ipmi, struct ipmi_recv *recv)
{
    smi_data_t    *smi = (smi_data_t *) ipmi->con_data;
    cmd_handler_t *elem;
    unsigned char netfn = recv->msg.netfn;
    unsigned char cmd_num = recv->msg.cmd;


    ipmi_lock(smi->cmd_handlers_lock);
    elem = smi->cmd_handlers;
    while (elem != NULL) {
	if ((elem->netfn == netfn) && (elem->cmd == cmd_num))
	    break;

	elem = elem->next;
    }
    if (!elem) {
	/* No handler, send an unhandled response and quit. */
	unsigned char data[1];
	ipmi_msg_t    msg;

	msg = recv->msg;
	msg.netfn |= 1; /* Make it into a response. */
	data[0] = IPMI_INVALID_CMD_CC;
	msg.data = data;
	msg.data_len = 1;
	smi_send(smi, smi->fd,
		 (ipmi_addr_t *) &(recv->addr), recv->addr_len,
		 &msg, recv->msgid);
	goto out_unlock;
    }

    elem->handler(ipmi,
		  (ipmi_addr_t *) &(recv->addr), recv->addr_len,
		  &(recv->msg), recv->msgid,
		  elem->cmd_data, elem->data2, elem->data3);

 out_unlock:
    ipmi_unlock(smi->cmd_handlers_lock);
}

static void
gen_recv_msg(ipmi_con_t *ipmi, struct ipmi_recv *recv)
{
    if (DEBUG_MSG) {
	ipmi_log(IPMI_LOG_DEBUG_START, "incoming msgid=%08lx\n addr =",
		 recv->msgid);
	dump_hex((unsigned char *) recv->addr, recv->addr_len);
        ipmi_log(IPMI_LOG_DEBUG_CONT,
                 "\n msg  = netfn=%s cmd=%s data_len=%d. cc=%s",
		 ipmi_get_netfn_string(recv->msg.netfn),
                 ipmi_get_command_string(recv->msg.netfn, recv->msg.cmd), recv->msg.data_len,
		 ipmi_get_cc_string(recv->msg.data[0]));
	ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =\n  ");
	dump_hex(recv->msg.data, recv->msg.data_len);
	ipmi_log(IPMI_LOG_DEBUG_END, "\n");
    }

    switch (recv->recv_type) {
	case IPMI_RESPONSE_RECV_TYPE:
	    handle_response(ipmi, recv);
	    break;

	case IPMI_ASYNC_EVENT_RECV_TYPE:
	    handle_async_event(ipmi, recv);
	    break;

	case IPMI_CMD_RECV_TYPE:
	    handle_incoming_command(ipmi, recv);
	    break;

	default:
	    break;
    }
}

static void
ipmi_dev_data_handler(int            fd,
		      void           *cb_data,
		      os_hnd_fd_id_t *id)
{
    ipmi_con_t       *ipmi = (ipmi_con_t *) cb_data;
    unsigned char    data[MAX_IPMI_DATA_SIZE];
    ipmi_addr_t      addr;
    struct ipmi_recv recv;
    int              rv;

    ipmi_read_lock();

    if (!smi_valid_ipmi(ipmi)) {
	/* We can have due to a race condition, just return and
           everything should be fine. */
	goto out_unlock2;
    }

    recv.msg.data = data;
    recv.msg.data_len = sizeof(data);
    recv.addr = (unsigned char *) &addr;
    recv.addr_len = sizeof(addr);
    rv = ioctl(fd, IPMICTL_RECEIVE_MSG_TRUNC, &recv);
    if (rv == -1) {
	if (errno == EMSGSIZE) {
	    /* The message was truncated, handle it as such. */
	    data[0] = IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC;
	    rv = 0;
	} else
	    goto out_unlock2;
    }

    gen_recv_msg(ipmi, &recv);

 out_unlock2:
    ipmi_read_unlock();
}

static void
ipmi_sock_data_handler(int            fd,
		       void           *cb_data,
		       os_hnd_fd_id_t *id)
{
    ipmi_con_t           *ipmi = (ipmi_con_t *) cb_data;
    struct sockaddr_ipmi addr;
    socklen_t            addr_len;
    struct ipmi_sock_msg *smsg;
    unsigned char        data[MAX_IPMI_DATA_SIZE + sizeof(*smsg)];
    int                  rv;
    struct ipmi_recv     recv;

    ipmi_read_lock();

    if (!smi_valid_ipmi(ipmi)) {
	/* We can have due to a race condition, just return and
           everything should be fine. */
	goto out_unlock2;
    }

    addr_len = sizeof(addr);
    rv = recvfrom(fd, data, sizeof(data), 0,
		  (struct sockaddr *) &addr, &addr_len);
    if (rv == -1) {
	/* FIXME - no handling for EMSGSIZE. */
	if (errno == EINTR) {
	    goto out_unlock2; /* Try again later. */
	} else {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%sipmi_smi.c(ipmi_sock_data_handler): "
		     "Error receiving message: %s\n",
		     IPMI_CONN_NAME(ipmi), strerror(errno));
	    goto out_unlock2;
	}
    }
    if (DEBUG_MSG) {
	ipmi_log(IPMI_LOG_DEBUG_START, "incoming\n addr(%d.) = ", addr_len);
	dump_hex((unsigned char *) &addr, MIN(addr_len,sizeof(addr)));
	ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data(%d.) =\n  ", rv);
	dump_hex(data, rv);
	ipmi_log(IPMI_LOG_DEBUG_END, "\n");
    }

    if (rv < sizeof(*smsg)) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sipmi_smi.c(ipmi_sock_data_handler): "
		 "Undersized socket message: %d bytes\n",
		 IPMI_CONN_NAME(ipmi), rv);
	goto out_unlock2;
    }

    smsg = (struct ipmi_sock_msg *) data;
    if (rv < (sizeof(*smsg) + smsg->data_len)) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sipmi_smi.c(ipmi_sock_data_handler): "
		 "Got subsized msg, size was %d, data_len was %d\n",
		 IPMI_CONN_NAME(ipmi), rv, smsg->data_len);
	return;
    }

    recv.recv_type = smsg->recv_type;
    recv.addr = (unsigned char *) &addr.ipmi_addr;
    recv.addr_len = addr_len - SOCKADDR_IPMI_OVERHEAD;
    recv.msgid = smsg->msgid;
    recv.msg.netfn = smsg->netfn;
    recv.msg.cmd = smsg->cmd;
    recv.msg.data = smsg->data;
    recv.msg.data_len = smsg->data_len;

    gen_recv_msg(ipmi, &recv);

 out_unlock2:
    ipmi_read_unlock();
}

static int
smi_send_command(ipmi_con_t            *ipmi,
		 ipmi_addr_t           *addr,
		 unsigned int          addr_len,
		 ipmi_msg_t            *msg,
		 ipmi_ll_rsp_handler_t rsp_handler,
		 ipmi_msgi_t           *trspi)
{
    pending_cmd_t *cmd;
    smi_data_t    *smi;
    int           rv;
    ipmi_addr_t   tmp_addr;
    ipmi_msgi_t   *rspi = trspi;


    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    if (msg->data_len > IPMI_MAX_MSG_LENGTH)
	return EINVAL;

    smi = (smi_data_t *) ipmi->con_data;

    if (!rspi) {
	rspi = ipmi_mem_alloc(sizeof(*rspi));
	if (!rspi)
	    return ENOMEM;
    }

    cmd = ipmi_mem_alloc(sizeof(*cmd));
    if (!cmd) {
	rv = ENOMEM;
	goto out_unlock2;
    }

    cmd->use_orig_addr = 0;

    if ((addr->addr_type == IPMI_IPMB_ADDR_TYPE)
	|| (addr->addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE))
    {
	ipmi_ipmb_addr_t *ipmb = (ipmi_ipmb_addr_t *) addr;

	if (ipmb->slave_addr == smi->slave_addr) {
	    ipmi_system_interface_addr_t *si = (void *) &tmp_addr;
	    /* Most systems don't handle sending to your own slave
               address, so we have to translate here. */

	    si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	    si->channel = IPMI_BMC_CHANNEL;
	    si->lun = ipmb->lun;
	    memcpy(&cmd->orig_addr, addr, addr_len);
	    cmd->orig_addr_len = addr_len;
	    addr = &tmp_addr;
	    addr_len = sizeof(*si);
	    cmd->use_orig_addr = 1;

	    /* In case it's a broadcast. */
	    cmd->orig_addr.addr_type = IPMI_IPMB_ADDR_TYPE;
	}
    }

    /* Put it in the list first. */
    cmd->msg = *msg;
    cmd->rsp_handler = rsp_handler;
    cmd->rsp_item = rspi;

    ipmi_lock(smi->cmd_lock);
    add_cmd(ipmi, addr, addr_len, msg, smi, cmd);

    rv = smi_send(smi, smi->fd, addr, addr_len, msg, (long) cmd);
    if (rv) {
	remove_cmd(ipmi, smi, cmd);
	ipmi_mem_free(cmd);
	goto out_unlock;
    }

 out_unlock:
    ipmi_unlock(smi->cmd_lock);
 out_unlock2:
    if (rv) {
	/* If we allocated an rspi, free it. */
	if (!trspi && rspi)
	    ipmi_mem_free(rspi);
    }
    return rv;
}

static int
smi_register_for_events(ipmi_con_t                 *ipmi,
			ipmi_ll_evt_handler_t      handler,
			void                       *event_data,
			void                       *data2,
			ipmi_ll_event_handler_id_t **id)
{
    smi_data_t                 *smi;
    int                        rv = 0;
    int                        was_empty;
    ipmi_ll_event_handler_id_t *entry;

    smi = (smi_data_t *) ipmi->con_data;

    entry = ipmi_mem_alloc(sizeof(*entry));
    if (!entry) {
	rv = ENOMEM;
	goto out_unlock2;
    }

    entry->handler = handler;
    entry->event_data = event_data;
    entry->data2 = data2;

    ipmi_lock(smi->event_handlers_lock);
    was_empty = smi->event_handlers == NULL;

    add_event_handler(ipmi, smi, entry);

    if (was_empty) {
	int val = 1;
	if (smi->using_socket)
	    rv = ioctl(smi->fd, SIOCIPMIGETEVENT, &val);
	else
	    rv = ioctl(smi->fd, IPMICTL_SET_GETS_EVENTS_CMD, &val);
	if (rv == -1) {
	    remove_event_handler(smi, entry);
	    rv = errno;
	    goto out_unlock;
	}
    }

 out_unlock:
    ipmi_unlock(smi->event_handlers_lock);
 out_unlock2:
    return rv;
}

static int
smi_deregister_for_events(ipmi_con_t                 *ipmi,
			  ipmi_ll_event_handler_id_t *id)
{
    smi_data_t *smi;
    int        rv = 0;

    smi = (smi_data_t *) ipmi->con_data;

    if (id->ipmi != ipmi) {
	rv = EINVAL;
	goto out_unlock2;
    }

    ipmi_lock(smi->event_handlers_lock);

    remove_event_handler(smi, id);
    id->ipmi = NULL;

    if (smi->event_handlers == NULL) {
	int val = 0;
	if (smi->using_socket)
	    rv = ioctl(smi->fd, SIOCIPMIGETEVENT, &val);
	else
	    rv = ioctl(smi->fd, IPMICTL_SET_GETS_EVENTS_CMD, &val);
	if (rv == -1) {
	    rv = errno;
	    goto out_unlock;
	}
    }

 out_unlock:
    ipmi_unlock(smi->event_handlers_lock);
 out_unlock2:

    return rv;
}

static int
smi_send_response(ipmi_con_t   *ipmi,
		  ipmi_addr_t  *addr,
		  unsigned int addr_len,
		  ipmi_msg_t   *msg,
		  long         sequence)
{
    smi_data_t *smi;
    int        rv;

    smi = (smi_data_t *) ipmi->con_data;

    rv = smi_send(smi, smi->fd, addr, addr_len, msg, sequence);

    return rv;
}

static int
smi_register_for_command(ipmi_con_t            *ipmi,
			 unsigned char         netfn,
			 unsigned char         cmd,
			 ipmi_ll_cmd_handler_t handler,
			 void                  *cmd_data,
			 void                  *data2,
			 void                  *data3)
{
    smi_data_t          *smi;
    struct ipmi_cmdspec reg;
    int                 rv;

    smi = (smi_data_t *) ipmi->con_data;

    rv = add_cmd_registration(ipmi, netfn, cmd, handler, cmd_data, data2, data3);
    if (rv)
	goto out_unlock;

    reg.netfn = netfn;
    reg.cmd = cmd;
    if (smi->using_socket)
	rv = ioctl(smi->fd, SIOCIPMIREGCMD, &reg);
    else
	rv = ioctl(smi->fd, IPMICTL_REGISTER_FOR_CMD, &reg);
    if (rv == -1) {
	remove_cmd_registration(ipmi, netfn, cmd);
	return errno;
    }

 out_unlock:
    return rv;
}

static int
smi_deregister_for_command(ipmi_con_t    *ipmi,
			   unsigned char netfn,
			   unsigned char cmd)
{
    smi_data_t          *smi;
    struct ipmi_cmdspec reg;
    int                 rv;

    smi = (smi_data_t *) ipmi->con_data;

    reg.netfn = netfn;
    reg.cmd = cmd;
    if (smi->using_socket)
	rv = ioctl(smi->fd, SIOCIPMIREGCMD, &reg);
    else
	rv = ioctl(smi->fd, IPMICTL_UNREGISTER_FOR_CMD, &reg);
    if (rv == -1) {
	rv = errno;
	goto out_unlock;
    }

    remove_cmd_registration(ipmi, netfn, cmd);

 out_unlock:

    return 0;
}

static int
smi_close_connection(ipmi_con_t *ipmi)
{
    smi_data_t                 *smi;
    pending_cmd_t              *cmd, *next_cmd;
    cmd_handler_t              *hnd_to_free, *next_hnd;
    ipmi_ll_event_handler_id_t *evt_to_free, *next_evt;
    int                        rv;

    if (! smi_valid_ipmi(ipmi)) {
	return EINVAL;
    }

    /* First order of business is to remove it from the SMI list. */
    smi = (smi_data_t *) ipmi->con_data;

    if (smi->next)
	smi->next->prev = smi->prev;
    if (smi->prev)
	smi->prev->next = smi->next;
    else
	smi_list = smi->next;

    /* After this point no other operations can occur on this ipmi
       interface, so it's safe. */

    cmd = smi->pending_cmds;
    smi->pending_cmds = NULL;
    while (cmd) {
	ipmi_addr_t   *addr;
	unsigned int  addr_len;
	unsigned char data[1];
	next_cmd = cmd->next;
	if (cmd->rsp_handler) {
	    if (cmd->use_orig_addr) {
		addr = &cmd->orig_addr;
		addr_len = cmd->orig_addr_len;
	    } else {
		addr = &cmd->addr;
		addr_len = cmd->addr_len;
	    }
	    data[0] = IPMI_UNKNOWN_ERR_CC;
	    
	    cmd->msg.netfn |= 1;
	    cmd->msg.data = data;
	    cmd->msg.data_len = 1;
	    ipmi_handle_rsp_item_copyall(ipmi, cmd->rsp_item,
					 addr, addr_len, &cmd->msg,
					 cmd->rsp_handler);
	}
	ipmi_mem_free(cmd);
	cmd = next_cmd;
    }

    hnd_to_free = smi->cmd_handlers;
    smi->cmd_handlers = NULL;
    while (hnd_to_free) {
	next_hnd = hnd_to_free->next;
	ipmi_mem_free(hnd_to_free);
	hnd_to_free = next_hnd;
    }

    evt_to_free = smi->event_handlers;
    smi->event_handlers = NULL;
    while (evt_to_free) {
	evt_to_free->ipmi = NULL;
	next_evt = evt_to_free->next;
	ipmi_mem_free(evt_to_free);
	evt_to_free = next_evt;
    }

    if (smi->audit_info) {
	rv = ipmi->os_hnd->stop_timer(ipmi->os_hnd, smi->audit_timer);
	if (rv)
	    smi->audit_info->cancelled = 1;
	else {
	    ipmi->os_hnd->free_timer(ipmi->os_hnd, smi->audit_timer);
	    ipmi_mem_free(smi->audit_info);
	}
    }

    if (ipmi->oem_data_cleanup)
	ipmi->oem_data_cleanup(ipmi);
    if (smi->event_handlers_lock)
	ipmi_destroy_lock(smi->event_handlers_lock);
    if (smi->cmd_handlers_lock)
	ipmi_destroy_lock(smi->cmd_handlers_lock);
    if (smi->cmd_lock)
	ipmi_destroy_lock(smi->cmd_lock);
    if (smi->fd_wait_id)
	ipmi->os_hnd->remove_fd_to_wait_for(ipmi->os_hnd, smi->fd_wait_id);

    /* Close the fd after we have deregistered it. */
    close(smi->fd);

    ipmi_mem_free(smi);
    ipmi_mem_free(ipmi);

    return 0;
}

static ll_ipmi_t smi_ll_ipmi =
{
    .valid_ipmi = smi_valid_ipmi,
    .registered = 0
};

static void
cleanup_con(ipmi_con_t *ipmi)
{
    smi_data_t   *smi = (smi_data_t *) ipmi->con_data;
    os_handler_t *handlers = ipmi->os_hnd;

    if (ipmi) {
	ipmi_mem_free(ipmi);
    }

    if (smi) {
	if (smi->event_handlers_lock)
	    ipmi_destroy_lock(smi->event_handlers_lock);
	if (smi->cmd_handlers_lock)
	    ipmi_destroy_lock(smi->cmd_handlers_lock);
	if (smi->cmd_lock)
	    ipmi_destroy_lock(smi->cmd_lock);
	if (smi->fd != -1)
	    close(smi->fd);
	if (smi->fd_wait_id)
	    handlers->remove_fd_to_wait_for(ipmi->os_hnd, smi->fd_wait_id);
	ipmi_mem_free(smi);
    }
}

static void
smi_set_con_change_handler(ipmi_con_t             *ipmi,
			   ipmi_ll_con_changed_cb handler,
			   void                   *cb_data)
{
    smi_data_t *smi = ipmi->con_data;

    smi->con_change_handler = handler;
    smi->con_change_cb_data = cb_data;
    return;
}

static void
finish_start_con(void *cb_data, os_hnd_timer_id_t *id)
{
    ipmi_con_t *ipmi = cb_data;
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;

    ipmi->os_hnd->free_timer(ipmi->os_hnd, id);

    if (smi->con_change_handler)
	smi->con_change_handler(ipmi, 0, 1, 1, smi->con_change_cb_data);
}

static void
smi_set_ipmb_addr(ipmi_con_t    *ipmi,
		  unsigned char ipmb,
		  int           active,
		  unsigned int  hacks)
{
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;

    if (smi->slave_addr != ipmb) {
	smi->slave_addr = ipmb;
	if (smi->ipmb_addr_handler)
	    smi->ipmb_addr_handler(ipmi, 0, ipmb, active, 0,
				   smi->ipmb_addr_cb_data);

	set_ipmb_in_dev(smi);
    }
}

static void
finish_connection(ipmi_con_t *ipmi, smi_data_t *smi)
{
    struct timeval    timeout;
    os_hnd_timer_id_t *timer;
    int               err;

    /* Schedule this to run in a timeout, so we are not holding
       the read lock. */
    err = ipmi->os_hnd->alloc_timer(ipmi->os_hnd, &timer);
    if (err)
	goto out_err;

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    err = ipmi->os_hnd->start_timer(ipmi->os_hnd,
				    timer,
				    &timeout,
				    finish_start_con,
				    ipmi);
    if (err) {
	ipmi->os_hnd->free_timer(ipmi->os_hnd, timer);
	goto out_err;
    }

    return;

 out_err:
    if (smi->con_change_handler)
	smi->con_change_handler(ipmi, err, 0, 0, smi->con_change_cb_data);
}

static void
handle_ipmb_addr(ipmi_con_t   *ipmi,
		 int          err,
		 unsigned int ipmb_addr,
		 int          active,
		 unsigned int hacks,
		 void         *cb_data)
{
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;

    if (err) {
	if (smi->con_change_handler)
	    smi->con_change_handler(ipmi, err, 0, 0, smi->con_change_cb_data);
	return;
    }

    smi->slave_addr = ipmb_addr;
    finish_connection(ipmi, smi);
    if (smi->ipmb_addr_handler)
	smi->ipmb_addr_handler(ipmi, err, ipmb_addr, active, 0,
			       smi->ipmb_addr_cb_data);

    set_ipmb_in_dev(smi);
}

static int
handle_dev_id(ipmi_con_t *ipmi, ipmi_msgi_t *msgi)
{
    ipmi_msg_t        *msg = &msgi->msg;
    smi_data_t        *smi = (smi_data_t *) ipmi->con_data;
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
	finish_connection(ipmi, smi);
    return IPMI_MSG_ITEM_NOT_USED;

 out_err:
    if (smi->con_change_handler)
	smi->con_change_handler(ipmi, err, 0, 0, smi->con_change_cb_data);
    return IPMI_MSG_ITEM_NOT_USED;
}

static void
smi_oem_done(ipmi_con_t *ipmi, void *cb_data)
{
    smi_data_t                   *smi = (smi_data_t *) ipmi->con_data;
    ipmi_msg_t                   msg;
    ipmi_system_interface_addr_t si;
    int                          rv;

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_DEVICE_ID_CMD;
    msg.data = NULL;
    msg.data_len = 0;
		
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    rv = smi_send_command(ipmi, (ipmi_addr_t *) &si, sizeof(si), &msg,
			  handle_dev_id, NULL);
    if (rv) {
	if (smi->con_change_handler)
	    smi->con_change_handler(ipmi, rv, 0, 0, smi->con_change_cb_data);
    }
}

static int
smi_start_con(ipmi_con_t *ipmi)
{
    smi_data_t                   *smi = (smi_data_t *) ipmi->con_data;
    int                          rv;
    struct timeval               timeout;

    /* Start the timer to audit the connections. */
    smi->audit_info = ipmi_mem_alloc(sizeof(*(smi->audit_info)));
    if (!smi->audit_info) {
	rv = ENOMEM;
	goto out_err;
    }

    smi->audit_info->cancelled = 0;
    smi->audit_info->ipmi = ipmi;
    rv = ipmi->os_hnd->alloc_timer(ipmi->os_hnd, &(smi->audit_timer));
    if (rv)
	goto out_err;
    timeout.tv_sec = SMI_AUDIT_TIMEOUT / 1000000;
    timeout.tv_usec = SMI_AUDIT_TIMEOUT % 1000000;
    rv = ipmi->os_hnd->start_timer(ipmi->os_hnd,
				   smi->audit_timer,
				   &timeout,
				   audit_timeout_handler,
				   smi->audit_info);
    if (rv) {
	ipmi_mem_free(smi->audit_info);
	smi->audit_info = NULL;
	ipmi->os_hnd->free_timer(ipmi->os_hnd, smi->audit_timer);
	smi->audit_timer = NULL;
	goto out_err;
    }

    rv = ipmi_conn_check_oem_handlers(ipmi, smi_oem_done, NULL);

 out_err:
    return rv;
}

static int
setup(int          if_num,
      os_handler_t *handlers,
      void         *user_data,
      ipmi_con_t   **new_con)
{
    ipmi_con_t *ipmi = NULL;
    smi_data_t *smi = NULL;
    int        rv;

    /* Make sure we register before anything else. */
    ipmi_register_ll(&smi_ll_ipmi);

    /* Keep things sane. */
    if (if_num >= 100)
	return EINVAL;

    ipmi = ipmi_mem_alloc(sizeof(*ipmi));
    if (!ipmi)
	return ENOMEM;
    memset(ipmi, 0, sizeof(*ipmi));

    ipmi->user_data = user_data;
    ipmi->os_hnd = handlers;

    smi = ipmi_mem_alloc(sizeof(*smi));
    if (!smi) {
	rv = ENOMEM;
	goto out_err;
    }
    memset(smi, 0, sizeof(*smi));

    ipmi->con_data = smi;

    smi->ipmi = ipmi;
    smi->slave_addr = 0x20; /* Assume this until told otherwise. */
    smi->pending_cmds = NULL;
    smi->cmd_lock = NULL;
    smi->cmd_handlers = NULL;
    smi->cmd_handlers_lock = NULL;
    smi->event_handlers = NULL;
    smi->event_handlers_lock = NULL;
    smi->fd_wait_id = NULL;

    smi->fd = open_smi_fd(if_num, &smi->using_socket);
    if (smi->fd == -1) {
	rv = errno;
	goto out_err;
    }

    /* Create the locks if they are available. */
    rv = ipmi_create_lock_os_hnd(handlers, &smi->cmd_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock_os_hnd(handlers, &smi->cmd_handlers_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock_os_hnd(handlers, &smi->event_handlers_lock);
    if (rv)
	goto out_err;

    smi->if_num = if_num;

    ipmi->start_con = smi_start_con;
    ipmi->set_ipmb_addr = smi_set_ipmb_addr;
    ipmi->set_ipmb_addr_handler = smi_set_ipmb_addr_handler;
    ipmi->set_con_change_handler = smi_set_con_change_handler;
    ipmi->send_command = smi_send_command;
    ipmi->register_for_events = smi_register_for_events;
    ipmi->deregister_for_events = smi_deregister_for_events;
    ipmi->send_response = smi_send_response;
    ipmi->register_for_command = smi_register_for_command;
    ipmi->deregister_for_command = smi_deregister_for_command;
    ipmi->close_connection = smi_close_connection;

    if (smi->using_socket) {
	rv = handlers->add_fd_to_wait_for(ipmi->os_hnd,
					  smi->fd,
					  ipmi_sock_data_handler, 
					  ipmi,
					  NULL,
					  &(smi->fd_wait_id));
    } else {
	rv = handlers->add_fd_to_wait_for(ipmi->os_hnd,
					  smi->fd,
					  ipmi_dev_data_handler,
					  ipmi,
					  NULL,
					  &(smi->fd_wait_id));
    }
    if (rv) {
	goto out_err;
    }

    /* Now it's valid, add it to the smi list. */
    ipmi_write_lock();
    if (smi_list)
	smi_list->prev = smi;
    smi->next = smi_list;
    smi->prev = NULL;
    smi_list = smi;
    ipmi_write_unlock();

    *new_con = ipmi;

    return 0;

 out_err:
    cleanup_con(ipmi);
    return rv;
}

int
ipmi_smi_setup_con(int               if_num,
		   os_handler_t      *handlers,
		   void              *user_data,
		   ipmi_con_t        **new_con)
{
    int                          err;

    if (!handlers->add_fd_to_wait_for
	|| !handlers->remove_fd_to_wait_for
	|| !handlers->alloc_timer
	|| !handlers->free_timer)
	return ENOSYS;

    err = setup(if_num, handlers, user_data, new_con);
    return err;
}
