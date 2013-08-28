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

#include <config.h>

#ifdef HAVE_OPENIPMI_SMI

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
#include <stdlib.h>
#include <ctype.h>

#include <linux/ipmi.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_auth.h>

#include <OpenIPMI/internal/ipmi_event.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/locked_list.h>

static ipmi_args_t *smi_con_alloc_args(void);

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

typedef struct smi_data_s
{
    int                        refcount;

    ipmi_con_t                 *ipmi;
    int                        fd;
    int                        if_num;
    pending_cmd_t              *pending_cmds;
    ipmi_lock_t                *cmd_lock;
    cmd_handler_t              *cmd_handlers;
    ipmi_lock_t                *cmd_handlers_lock;
    os_hnd_fd_id_t             *fd_wait_id;
    ipmi_lock_t                *smi_lock;
    locked_list_t              *event_handlers;

    unsigned char              slave_addr[MAX_IPMI_USED_CHANNELS];

    os_hnd_timer_id_t          *audit_timer;
    audit_timer_info_t         *audit_info;

    /* Handles connection shutdown reporting. */
    ipmi_ll_con_closed_cb close_done;
    void                  *close_cb_data;

    locked_list_t          *con_change_handlers;
    locked_list_t          *ipmb_change_handlers;

    struct smi_data_s *next, *prev;
} smi_data_t;

static ipmi_lock_t *smi_list_lock = NULL;
static smi_data_t *smi_list = NULL;

/* Must be called with the ipmi read or write lock. */
static int smi_valid_ipmi(ipmi_con_t *ipmi)
{
    smi_data_t *elem;

    ipmi_lock(smi_list_lock);
    elem = smi_list;
    while ((elem) && (elem->ipmi != ipmi)) {
	elem = elem->next;
    }
    if (elem)
	elem->refcount++;
    ipmi_unlock(smi_list_lock);

    return (elem != NULL);
}

static void
smi_cleanup(ipmi_con_t *ipmi)
{
    smi_data_t    *smi;
    pending_cmd_t *cmd, *next_cmd;
    cmd_handler_t *hnd_to_free, *next_hnd;
    int           rv;

    /* First order of business is to remove it from the SMI list. */
    smi = (smi_data_t *) ipmi->con_data;

    ipmi_lock(smi_list_lock);
    if (smi->next)
	smi->next->prev = smi->prev;
    if (smi->prev)
	smi->prev->next = smi->next;
    else
	smi_list = smi->next;
    ipmi_unlock(smi_list_lock);

    if (smi->close_done)
	smi->close_done(ipmi, smi->close_cb_data);

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
    ipmi_con_attr_cleanup(ipmi);
    if (smi->smi_lock)
	ipmi_destroy_lock(smi->smi_lock);
    if (smi->cmd_handlers_lock)
	ipmi_destroy_lock(smi->cmd_handlers_lock);
    if (smi->cmd_lock)
	ipmi_destroy_lock(smi->cmd_lock);
    if (smi->fd_wait_id)
	ipmi->os_hnd->remove_fd_to_wait_for(ipmi->os_hnd, smi->fd_wait_id);
    if (smi->con_change_handlers)
	locked_list_destroy(smi->con_change_handlers);
    if (smi->event_handlers)
	locked_list_destroy(smi->event_handlers);
    if (smi->ipmb_change_handlers)
	locked_list_destroy(smi->ipmb_change_handlers);

    /* Close the fd after we have deregistered it. */
    close(smi->fd);

    ipmi_mem_free(smi);
    if (ipmi->name)
	ipmi_mem_free(ipmi->name);
    ipmi_mem_free(ipmi);
}

static void
smi_put(ipmi_con_t *ipmi)
{
    smi_data_t *elem = ipmi->con_data;
    int        done;

    ipmi_lock(smi_list_lock);
    elem->refcount--;
    done = elem->refcount == 0;
    ipmi_unlock(smi_list_lock);

    if (done)
	smi_cleanup(ipmi);
}

/* Must be called with cmd_lock held. */
static void
add_cmd(ipmi_con_t        *ipmi,
	const ipmi_addr_t *addr,
	unsigned int      addr_len,
	const ipmi_msg_t  *msg,
	smi_data_t        *smi,
	pending_cmd_t     *cmd)
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
open_smi_fd(int if_num, int *reterr)
{
    char devname[30];
    int  fd;
    int  err;

    sprintf(devname, "/dev/ipmidev/%d", if_num);
    fd = open(devname, O_RDWR);
    if (fd == -1) {
	err = errno;
	sprintf(devname, "/dev/ipmi/%d", if_num);
	fd = open(devname, O_RDWR);
	if (fd == -1) {
	    if (errno != ENOENT)
		err = errno;
	    sprintf(devname, "/dev/ipmi%d", if_num);
	    fd = open(devname, O_RDWR);
	    if (fd == -1) {
		if (errno != ENOENT)
		    err = errno;
	    }
	}
    }

    *reterr = err;
    return fd;
}

static int
smi_send(smi_data_t        *smi,
	 int               fd,
	 const ipmi_addr_t *addr,
	 unsigned int      addr_len,
	 const ipmi_msg_t  *msg,
	 long              msgid)
{
    int             rv;
    ipmi_addr_t     myaddr;
    struct ipmi_req req;

    if (DEBUG_MSG) {
	char buf1[32], buf2[32];
	ipmi_log(IPMI_LOG_DEBUG_START, "%soutgoing msgid=%08lx\n addr =",
		 IPMI_CONN_NAME(smi->ipmi), msgid);
	dump_hex((unsigned char *) addr, addr_len);
        ipmi_log(IPMI_LOG_DEBUG_CONT,
                 "\n msg  = netfn=%s cmd=%s data_len=%d.",
		 ipmi_get_netfn_string(msg->netfn, buf1, 32),
                 ipmi_get_command_string(msg->netfn, msg->cmd, buf2, 32),
		 msg->data_len);
	if ( msg->data_len ) {
	        ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =\n  ");
	        dump_hex((unsigned char *)msg->data, msg->data_len);
	}
	ipmi_log(IPMI_LOG_DEBUG_END, " ");
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
	return EBADF;

    req.addr = (unsigned char *) addr;
    req.addr_len = addr_len;
    req.msgid = (long) smi;
    req.msg = *msg;
    req.msgid = msgid;
    rv = ioctl(fd, IPMICTL_SEND_COMMAND, &req);

    if (rv == -1)
	return errno;

    return 0;
}

static void
set_ipmb_in_dev(smi_data_t          *smi,
		const unsigned char ipmb_addr[],
		unsigned int        num_ipmb_addr)
{
    struct ipmi_channel_lun_address_set channel_addr;
    int                                 rv;
    unsigned int                        i;

    for (i=0; i<num_ipmb_addr; i++) {
	if (!ipmb_addr[i])
	    continue;
	channel_addr.channel = i;
	channel_addr.value = ipmb_addr[i];
	rv = ioctl(smi->fd, IPMICTL_SET_MY_CHANNEL_ADDRESS_CMD, &channel_addr);
	if (rv == -1)
	    goto try_old_version;
    }
    return;

 try_old_version:
    /* We can only set one address. */
    rv = ioctl(smi->fd, IPMICTL_SET_MY_ADDRESS_CMD, &ipmb_addr[0]);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sipmi_smi.c(set_ipmb_in_dev): "
		 "Error setting IPMB address: 0x%x",
		 IPMI_CONN_NAME(smi->ipmi), errno);
    }
}

typedef struct call_ipmb_change_handler_s
{
    smi_data_t   *smi;
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

    handler(info->smi->ipmi, info->err, info->ipmb_addr, info->num_ipmb_addr,
	    info->active, info->hacks, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_ipmb_change_handlers(smi_data_t *smi, int err,
			  const unsigned char ipmb_addr[],
			  unsigned int  num_ipmb_addr,
			  int active, unsigned int hacks)
{
    call_ipmb_change_handler_t info;

    info.smi = smi;
    info.err = err;
    info.ipmb_addr = ipmb_addr;
    info.num_ipmb_addr = num_ipmb_addr;
    info.active = active;
    info.hacks = hacks;
    locked_list_iterate(smi->ipmb_change_handlers, call_ipmb_change_handler,
			&info);
}

static int
smi_add_ipmb_addr_handler(ipmi_con_t           *ipmi,
			  ipmi_ll_ipmb_addr_cb handler,
			  void                 *cb_data)
{
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;

    if (locked_list_add(smi->ipmb_change_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

static int
smi_remove_ipmb_addr_handler(ipmi_con_t           *ipmi,
			     ipmi_ll_ipmb_addr_cb handler,
			     void                 *cb_data)
{
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;

    if (locked_list_remove(smi->ipmb_change_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

static void
ipmb_handler(ipmi_con_t    *ipmi,
	     int           err,
	     const unsigned char ipmb_addr[],
	     unsigned int  num_ipmb_addr,
	     int           active,
	     unsigned int  hacks,
	     void          *cb_data)
{
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;
    int        changed = 0;
    int        i;

    if (err)
	return;

    for (i=0; i<MAX_IPMI_USED_CHANNELS; i++) {
	if (! ipmb_addr[i])
	    continue;
	if (ipmb_addr[i] != smi->slave_addr[i]) {
	    smi->slave_addr[i] = ipmb_addr[i];
	    ipmi->ipmb_addr[i] = ipmb_addr[i];
	    changed = 1;
	}
    }
    if (changed) {
	call_ipmb_change_handlers(smi, err, ipmb_addr, num_ipmb_addr,
				  active, 0);
	set_ipmb_in_dev(smi, ipmb_addr, num_ipmb_addr);
    }
}

static void
audit_timeout_handler(void              *cb_data,
		      os_hnd_timer_id_t *id)
{
    audit_timer_info_t           *info = cb_data;
    ipmi_con_t                   *ipmi = info->ipmi;
    struct timeval               timeout;
    ipmi_msg_t                   msg;
    ipmi_system_interface_addr_t si;


    /* If we were cancelled, just free the data and ignore the call. */
    if (info->cancelled) {
	goto out_done;
    }

    if (!smi_valid_ipmi(ipmi)) {
	goto out_done;
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

    smi_put(ipmi);

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

typedef struct call_event_handler_s
{
    smi_data_t        *smi;
    const ipmi_addr_t *addr;
    unsigned int      addr_len;
    ipmi_event_t      *event;
} call_event_handler_t;

static int
call_event_handler(void *cb_data, void *item1, void *item2)
{
    call_event_handler_t  *info = cb_data;
    ipmi_ll_evt_handler_t handler = item1;

    handler(info->smi->ipmi, info->addr, info->addr_len, info->event, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
smi_add_event_handler(ipmi_con_t            *ipmi,
		      ipmi_ll_evt_handler_t handler,
		      void                  *cb_data)
{
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;
    int        rv = 0;

    ipmi_lock(smi->smi_lock);
    if (! locked_list_add(smi->event_handlers, handler, cb_data))
	rv = ENOMEM;
    if (!rv) {
	if (locked_list_num_entries(smi->event_handlers) == 1) {
	    int val = 1;
	    rv = ioctl(smi->fd, IPMICTL_SET_GETS_EVENTS_CMD, &val);
	    if (rv == -1) {
		locked_list_remove(smi->event_handlers, handler, cb_data);
		rv = errno;
	    }
	}
    }
    ipmi_unlock(smi->smi_lock);
    return rv;
}

static int
smi_remove_event_handler(ipmi_con_t            *ipmi,
			 ipmi_ll_evt_handler_t handler,
			 void                  *cb_data)
{
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;
    int        rv = 0;

    ipmi_lock(smi->smi_lock);
    if (! locked_list_remove(smi->event_handlers, handler, cb_data))
	rv = EINVAL;
    if (locked_list_num_entries(smi->event_handlers) == 0) {
	int val = 0;
	ioctl(smi->fd, IPMICTL_SET_GETS_EVENTS_CMD, &val);
    }
    ipmi_unlock(smi->smi_lock);
    return rv;
}

static ipmi_mcid_t invalid_mcid = IPMI_MCID_INVALID;

static void
handle_async_event(ipmi_con_t        *ipmi,
		   const ipmi_addr_t *addr,
		   unsigned int      addr_len,
		   const ipmi_msg_t  *msg)
{
    smi_data_t           *smi = (smi_data_t *) ipmi->con_data;
    ipmi_event_t         *event;
    ipmi_time_t          timestamp;
    unsigned int         type = msg->data[2];
    unsigned int         record_id = ipmi_get_uint16(msg->data);
    call_event_handler_t info;

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

    info.smi = smi;
    info.addr = addr;
    info.addr_len = addr_len;
    info.event = event;
    locked_list_iterate(smi->event_handlers, call_event_handler, &info);

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
		 (ipmi_addr_t *) recv->addr, recv->addr_len,
		 &msg, recv->msgid);
	goto out_unlock;
    }

    elem->handler(ipmi,
		  (ipmi_addr_t *) recv->addr, recv->addr_len,
		  &(recv->msg), recv->msgid,
		  elem->cmd_data, elem->data2, elem->data3);

 out_unlock:
    ipmi_unlock(smi->cmd_handlers_lock);
}

static void
gen_recv_msg(ipmi_con_t *ipmi, struct ipmi_recv *recv)
{
    if (DEBUG_MSG) {
	char buf1[32], buf2[32], buf3[32];
	ipmi_log(IPMI_LOG_DEBUG_START, "%sincoming msgid=%08lx\n addr =",
		 IPMI_CONN_NAME(ipmi), recv->msgid);
	dump_hex((unsigned char *) recv->addr, recv->addr_len);
        ipmi_log(IPMI_LOG_DEBUG_CONT,
                 "\n msg  = netfn=%s cmd=%s data_len=%d. cc=%s",
		 ipmi_get_netfn_string(recv->msg.netfn, buf1, 32),
                 ipmi_get_command_string(recv->msg.netfn, recv->msg.cmd,
					 buf2, 32),
		 recv->msg.data_len,
		 ipmi_get_cc_string(recv->msg.data[0], buf3, 32));
	if (recv->msg.data_len) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =\n  ");
	    dump_hex(recv->msg.data, recv->msg.data_len);
	}
	ipmi_log(IPMI_LOG_DEBUG_END, " ");
    }

    switch (recv->recv_type) {
	case IPMI_RESPONSE_RECV_TYPE:
	    handle_response(ipmi, recv);
	    break;

	case IPMI_ASYNC_EVENT_RECV_TYPE:
	    handle_async_event(ipmi, (ipmi_addr_t *) recv->addr,
			       recv->addr_len, &recv->msg);
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

    if (!smi_valid_ipmi(ipmi)) {
	/* We can have due to a race condition, just return and
           everything should be fine. */
	return;
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
	    goto out;
    }

    gen_recv_msg(ipmi, &recv);

 out:
    smi_put(ipmi);
}

static int
smi_send_command(ipmi_con_t            *ipmi,
		 const ipmi_addr_t     *iaddr,
		 unsigned int          addr_len,
		 const ipmi_msg_t      *msg,
		 ipmi_ll_rsp_handler_t rsp_handler,
		 ipmi_msgi_t           *trspi)
{
    pending_cmd_t *cmd;
    smi_data_t    *smi;
    int           rv;
    char          addr_data[sizeof(ipmi_addr_t)];
    char          addr_data2[sizeof(ipmi_addr_t)];
    ipmi_addr_t   *addr = (ipmi_addr_t *) addr_data;
    ipmi_msgi_t   *rspi = trspi;

    *addr = *iaddr;
    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    if (msg->data_len > IPMI_MAX_MSG_LENGTH)
	return EINVAL;

    smi = (smi_data_t *) ipmi->con_data;

    if (!rspi) {
	rspi = ipmi_alloc_msg_item();
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

	if (ipmb->channel >= MAX_IPMI_USED_CHANNELS)
	    return EINVAL;

	if (ipmb->slave_addr == smi->slave_addr[ipmb->channel]) {
	    ipmi_system_interface_addr_t *si = (void *) addr_data2;
	    /* Most systems don't handle sending to your own slave
               address, so we have to translate here. */

	    si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	    si->channel = IPMI_BMC_CHANNEL;
	    si->lun = ipmb->lun;
	    memcpy(&cmd->orig_addr, addr, addr_len);
	    cmd->orig_addr_len = addr_len;
	    addr = (ipmi_addr_t *) si;
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
	    ipmi_free_msg_item(rspi);
    }
    return rv;
}

static int
smi_send_response(ipmi_con_t        *ipmi,
		  const ipmi_addr_t *addr,
		  unsigned int      addr_len,
		  const ipmi_msg_t  *msg,
		  long              sequence)
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
smi_close_connection_done(ipmi_con_t *ipmi,
			  ipmi_ll_con_closed_cb handler,
			  void                  *cb_data)
{
    smi_data_t *smi;

    if (! smi_valid_ipmi(ipmi)) {
	return EINVAL;
    }

    smi = (smi_data_t *) ipmi->con_data;
    smi->close_done = handler;
    smi->close_cb_data = cb_data;

    smi_put(ipmi);
    smi_put(ipmi);
    return 0;
}

static int
smi_close_connection(ipmi_con_t *ipmi)
{
    return smi_close_connection_done(ipmi, NULL, NULL);
}

static void
cleanup_con(ipmi_con_t *ipmi)
{
    smi_data_t   *smi;
    os_handler_t *handlers;

    if (!ipmi)
	return;

    smi = (smi_data_t *) ipmi->con_data;
    handlers = ipmi->os_hnd;

    ipmi_con_attr_cleanup(ipmi);
    if (ipmi->name) {
	ipmi_mem_free(ipmi->name);
	ipmi->name = NULL;
    }
    ipmi_mem_free(ipmi);

    if (smi) {
	if (smi->smi_lock)
	    ipmi_destroy_lock(smi->smi_lock);
	if (smi->cmd_handlers_lock)
	    ipmi_destroy_lock(smi->cmd_handlers_lock);
	if (smi->cmd_lock)
	    ipmi_destroy_lock(smi->cmd_lock);
	if (smi->fd != -1)
	    close(smi->fd);
	if (smi->fd_wait_id)
	    handlers->remove_fd_to_wait_for(handlers, smi->fd_wait_id);
	if (smi->con_change_handlers)
	    locked_list_destroy(smi->con_change_handlers);
	if (smi->event_handlers)
	    locked_list_destroy(smi->event_handlers);
	if (smi->ipmb_change_handlers)
	    locked_list_destroy(smi->ipmb_change_handlers);
	ipmi_mem_free(smi);
    }
}

typedef struct call_con_change_handler_s
{
    smi_data_t  *smi;
    int          err;
    unsigned int port;
    int          any_port_up;
} call_con_change_handler_t;

static int
call_con_change_handler(void *cb_data, void *item1, void *item2)
{
    call_con_change_handler_t  *info = cb_data;
    ipmi_ll_con_changed_cb     handler = item1;

    handler(info->smi->ipmi, info->err, info->port, info->any_port_up, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_con_change_handlers(smi_data_t *smi, int err, unsigned int port,
			 int any_port_up)
{
    call_con_change_handler_t info;

    info.smi = smi;
    info.err = err;
    info.port = port;
    info.any_port_up = any_port_up;
    locked_list_iterate(smi->con_change_handlers, call_con_change_handler,
			&info);
}

static int
smi_add_con_change_handler(ipmi_con_t             *ipmi,
			   ipmi_ll_con_changed_cb handler,
			   void                   *cb_data)
{
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;

    if (locked_list_add(smi->con_change_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

static int
smi_remove_con_change_handler(ipmi_con_t             *ipmi,
			      ipmi_ll_con_changed_cb handler,
			      void                   *cb_data)
{
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;

    if (locked_list_remove(smi->con_change_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

static void
finish_start_con(void *cb_data, os_hnd_timer_id_t *id)
{
    ipmi_con_t *ipmi = cb_data;
    smi_data_t *smi = (smi_data_t *) ipmi->con_data;

    ipmi->os_hnd->free_timer(ipmi->os_hnd, id);

    call_con_change_handlers(smi, 0, 0, 1);
}

static void
smi_set_ipmb_addr(ipmi_con_t    *ipmi,
		  const unsigned char ipmb_addr[],
		  unsigned int  num_ipmb_addr,
		  int           active,
		  unsigned int  hacks)
{
    smi_data_t   *smi = (smi_data_t *) ipmi->con_data;
    int          changed = 0;
    unsigned int i;

    for (i=0; i<num_ipmb_addr && i<MAX_IPMI_USED_CHANNELS; i++) {
	if (! ipmb_addr[i])
	    continue;
	if (smi->slave_addr[i] != ipmb_addr[i]) {
	    smi->slave_addr[i] = ipmb_addr[i];
	    ipmi->ipmb_addr[i] = ipmb_addr[i];
	    changed = 1;
	}
    }
    if (changed) {
	call_ipmb_change_handlers(smi, 0, ipmb_addr, num_ipmb_addr, active, 0);
	set_ipmb_in_dev(smi, ipmb_addr, num_ipmb_addr);
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
    call_con_change_handlers(smi, err, 0, 0);
}

static void
handle_ipmb_addr(ipmi_con_t    *ipmi,
		 int           err,
		 const unsigned char ipmb_addr[],
		 unsigned int  num_ipmb_addr,
		 int           active,
		 unsigned int  hacks,
		 void          *cb_data)
{
    smi_data_t   *smi = (smi_data_t *) ipmi->con_data;
    unsigned int i;

    if (err) {
	call_con_change_handlers(smi, err, 0, 0);
	return;
    }

    for (i=0; i<num_ipmb_addr && i<MAX_IPMI_USED_CHANNELS; i++) {
	if (! ipmb_addr[i])
	    continue;
	smi->slave_addr[i] = ipmb_addr[i];
	ipmi->ipmb_addr[i] = ipmb_addr[i];
    }
    finish_connection(ipmi, smi);
    call_ipmb_change_handlers(smi, err, ipmb_addr, num_ipmb_addr, active, 0);
    set_ipmb_in_dev(smi, ipmb_addr, num_ipmb_addr);
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
    call_con_change_handlers(smi, err, 0, 0);
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
	call_con_change_handlers(smi, rv, 0, 0);
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

static ipmi_args_t *get_startup_args(ipmi_con_t *ipmi);

static int
setup(int          if_num,
      os_handler_t *handlers,
      void         *user_data,
      ipmi_con_t   **new_con)
{
    ipmi_con_t *ipmi = NULL;
    smi_data_t *smi = NULL;
    int        rv;
    int        i;

    /* Keep things sane. */
    if (if_num >= 100)
	return EINVAL;

    ipmi = ipmi_mem_alloc(sizeof(*ipmi));
    if (!ipmi)
	return ENOMEM;
    memset(ipmi, 0, sizeof(*ipmi));

    ipmi->user_data = user_data;
    ipmi->os_hnd = handlers;
    ipmi->con_type = "smi";
    ipmi->priv_level = IPMI_PRIVILEGE_ADMIN; /* Always admin privilege. */

    rv = ipmi_con_attr_init(ipmi);
    if (rv)
	goto out_err;

    smi = ipmi_mem_alloc(sizeof(*smi));
    if (!smi) {
	rv = ENOMEM;
	goto out_err;
    }
    memset(smi, 0, sizeof(*smi));

    ipmi->con_data = smi;

    smi->refcount = 1;
    smi->ipmi = ipmi;
    for (i=0; i<MAX_IPMI_USED_CHANNELS; i++)
	smi->slave_addr[i] = 0x20; /* Assume this until told otherwise. */

    smi->fd = open_smi_fd(if_num, &rv);
    if (smi->fd == -1) {
	goto out_err;
    }

    smi->con_change_handlers = locked_list_alloc(handlers);
    if (!smi->con_change_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    smi->event_handlers = locked_list_alloc(handlers);
    if (!smi->event_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    smi->ipmb_change_handlers = locked_list_alloc(handlers);
    if (!smi->ipmb_change_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    /* Create the locks if they are available. */
    rv = ipmi_create_lock_os_hnd(handlers, &smi->cmd_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock_os_hnd(handlers, &smi->cmd_handlers_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock_os_hnd(handlers, &smi->smi_lock);
    if (rv)
	goto out_err;

    smi->if_num = if_num;

    ipmi->start_con = smi_start_con;
    ipmi->set_ipmb_addr = smi_set_ipmb_addr;
    ipmi->add_ipmb_addr_handler = smi_add_ipmb_addr_handler;
    ipmi->remove_ipmb_addr_handler = smi_remove_ipmb_addr_handler;
    ipmi->add_con_change_handler = smi_add_con_change_handler;
    ipmi->remove_con_change_handler = smi_remove_con_change_handler;
    ipmi->send_command = smi_send_command;
    ipmi->add_event_handler = smi_add_event_handler;
    ipmi->remove_event_handler = smi_remove_event_handler;
    ipmi->send_response = smi_send_response;
    ipmi->register_for_command = smi_register_for_command;
    ipmi->deregister_for_command = smi_deregister_for_command;
    ipmi->close_connection = smi_close_connection;
    ipmi->close_connection_done = smi_close_connection_done;
    ipmi->handle_async_event = handle_async_event;
    ipmi->get_startup_args = get_startup_args;

    rv = handlers->add_fd_to_wait_for(ipmi->os_hnd,
				      smi->fd,
				      ipmi_dev_data_handler,
				      ipmi,
				      NULL,
				      &(smi->fd_wait_id));
    if (rv) {
	goto out_err;
    }

    /* Now it's valid, add it to the smi list. */
    ipmi_lock(smi_list_lock);
    if (smi_list)
	smi_list->prev = smi;
    smi->next = smi_list;
    smi->prev = NULL;
    smi_list = smi;
    ipmi_unlock(smi_list_lock);

    *new_con = ipmi;

    return 0;

 out_err:
    cleanup_con(ipmi);
    return rv;
}

int
ipmi_smi_setup_con(int          if_num,
		   os_handler_t *handlers,
		   void         *user_data,
		   ipmi_con_t   **new_con)
{
    int err;

    if (!handlers->add_fd_to_wait_for
	|| !handlers->remove_fd_to_wait_for
	|| !handlers->alloc_timer
	|| !handlers->free_timer)
	return ENOSYS;

    err = setup(if_num, handlers, user_data, new_con);
    return err;
}

typedef struct smi_args_s
{
    int ifnum;
} smi_args_t;

static ipmi_args_t *
get_startup_args(ipmi_con_t *ipmi)
{
    ipmi_args_t *args;
    smi_args_t  *sargs;
    smi_data_t  *smi;

    args = smi_con_alloc_args();
    if (! args)
	return NULL;
    sargs = _ipmi_args_get_extra_data(args);
    smi = (smi_data_t *) ipmi->con_data;
    sargs->ifnum = smi->if_num;
    return args;
}

static int
smi_connect_args(ipmi_args_t  *args,
		 os_handler_t *handler,
		 void         *user_data,
		 ipmi_con_t   **new_con)
{
    smi_args_t *sargs = _ipmi_args_get_extra_data(args);

    return ipmi_smi_setup_con(sargs->ifnum, handler, user_data, new_con);
}

static const char *
smi_args_get_type(ipmi_args_t  *args)
{
    return "smi";
}

static int
smi_args_get_val(ipmi_args_t  *args,
		 unsigned int argnum,
		 const char   **name,
		 const char   **type,
		 const char   **help,
		 char         **value,
		 const char   ***range)
{
    smi_args_t *sargs = _ipmi_args_get_extra_data(args);
    char       dummy[1];
    char       *sval;

    if (argnum > 0)
	return E2BIG;

    if (name)
	*name = "Interface_Number";
    if (type)
	*type = "str";
    if (help)
	*help = "*The interface number to open.  For instance, /dev/ipmi0"
	    " would be 0.  This is an integer value.";
    if (*value) {
	int len;
	len = snprintf(dummy, 1, "%d", sargs->ifnum);
	sval = ipmi_mem_alloc(len+1);
	if (! sval)
	    return ENOMEM;
	len = snprintf(sval, len+1, "%d", sargs->ifnum);
	*value = sval;
    }
    return 0;
}

static int
smi_args_set_val(ipmi_args_t  *args,
		 unsigned int argnum,
		 const char   *name,
		 const char   *value)
{
    smi_args_t   *sargs = _ipmi_args_get_extra_data(args);
    const char   *should_be_end;
    char         *end;
    unsigned int val;

    if (name) {
	if (strcmp(name, "Interface_Number") != 0)
	    return EINVAL;
    } else if (argnum > 0) {
	return E2BIG;
    }

    if (!value)
	return EINVAL;

    should_be_end = value + strlen(value) - 1;
    while ((should_be_end >= value) && isspace(*should_be_end))
	should_be_end--;
    should_be_end++;
    if (should_be_end <= value)
	return EINVAL;

    val = strtoul(value, &end, 0);
    if (end != should_be_end)
	return EINVAL;
    sargs->ifnum = val;
    return 0;
}

static ipmi_args_t *
smi_args_copy(ipmi_args_t *args)
{
    ipmi_args_t *nargs;
    smi_args_t  *sargs = _ipmi_args_get_extra_data(args);
    smi_args_t  *nsargs;

    nargs = smi_con_alloc_args();
    if (!nargs)
	return NULL;
    nsargs = _ipmi_args_get_extra_data(nargs);
    *nsargs = *sargs;
    return nargs;
}

static int
smi_args_validate(ipmi_args_t *args, int *argnum)
{
    return 1; /* Can't be invalid */
}

#define CHECK_ARG \
    do { \
        if (*curr_arg >= arg_count) { \
	    rv = EINVAL; \
	    goto out_err; \
        } \
    } while(0)

static int
smi_parse_args(int         *curr_arg,
	       int         arg_count,
	       char        * const *args,
	       ipmi_args_t **iargs)
{
    int         rv;
    ipmi_args_t *p = NULL;
    smi_args_t  *sargs;

    CHECK_ARG;

    p = smi_con_alloc_args();
    if (!p)
	return ENOMEM;

    sargs = _ipmi_args_get_extra_data(p);
    sargs->ifnum = atoi(args[*curr_arg]);
    *iargs = p;
    (*curr_arg)++;
    return 0;

 out_err:
    if (p)
	ipmi_free_args(p);
    return rv;
}

static void
smi_args_free_val(ipmi_args_t *args, char *value)
{
    ipmi_mem_free(value);
}

static const char *
smi_parse_help(void)
{
    return
	"\n"
	" smi <num>\n"
	"where the <num> is the IPMI device number to connect to.";
}

static ipmi_args_t *
smi_con_alloc_args(void)
{
    return _ipmi_args_alloc(NULL, smi_connect_args,
			    smi_args_get_val, smi_args_set_val,
			    smi_args_copy, smi_args_validate,
			    smi_args_free_val, smi_args_get_type,
			    sizeof(smi_args_t));
}

static ipmi_con_setup_t *smi_setup;

int
_ipmi_smi_init(os_handler_t *os_hnd)
{
    int rv;

    rv = ipmi_create_global_lock(&smi_list_lock);
    if (rv)
	return rv;

    smi_setup = _ipmi_alloc_con_setup(smi_parse_args, smi_parse_help,
				      smi_con_alloc_args);
    if (! smi_setup) {
	ipmi_destroy_lock(smi_list_lock);
	return ENOMEM;
    }
    rv = _ipmi_register_con_type("smi", smi_setup);
    if (rv) {
	_ipmi_free_con_setup(smi_setup);
	smi_setup = NULL;
	ipmi_destroy_lock(smi_list_lock);
	return rv;
    }

    return 0;
}

void
_ipmi_smi_shutdown(void)
{
    _ipmi_unregister_con_type("smi", smi_setup);
    _ipmi_free_con_setup(smi_setup);
    smi_setup = NULL;

    if (smi_list_lock) {
	ipmi_destroy_lock(smi_list_lock);
	smi_list_lock = NULL;
    }
}

#endif /* HAVE_OPENIPMI_SMI */
