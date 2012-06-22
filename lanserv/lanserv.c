/*
 * lanserv.c
 *
 * MontaVista IPMI code for creating a LAN interface to an SMI interface.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004,2005 MontaVista Software Inc.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdarg.h>
#include <popt.h> /* Option parsing made easy */
#include <sys/ioctl.h>
#if HAVE_SYSLOG
#include <syslog.h>
#endif

#include <OpenIPMI/ipmi_log.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/lanserv.h>

/* Stolen from ipmi_mc.h can't include that and linux/ipmi.h */
#define IPMI_CHANNEL_MEDIUM_8023_LAN	4

#include <linux/ipmi.h>


static int daemonize = 1;

#define MAX_ADDR 4

static void lanserv_log(bmc_data_t *bmc, int logtype, msg_t *msg,
			char *format, ...);

typedef struct misc_data
{
    int smi_fd;
    bmc_data_t *bmc;
    os_handler_t *os_hnd;
    os_handler_waiter_factory_t *waiter_factory;
    os_hnd_timer_id_t *timer;

    unsigned char bmc_ipmb;
} misc_data_t;

static void *
balloc(bmc_data_t *bmc, int size)
{
    return malloc(size);
}

static void
bfree(bmc_data_t *bmc, void *data)
{
    return free(data);
}

typedef struct lanserv_addr_s
{
    sockaddr_ip_t   addr;
    socklen_t       addr_len;
    int             xmit_fd;
} lanserv_addr_t;

static void
lan_send(lanserv_data_t *lan,
	 struct iovec *data, int vecs,
	 void *addr, int addr_len)
{
    struct msghdr msg;
    lanserv_addr_t *l = addr;
    int           rv;

    msg.msg_name = &(l->addr);
    msg.msg_namelen = l->addr_len;
    msg.msg_iov = data;
    msg.msg_iovlen = vecs;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    rv = sendmsg(l->xmit_fd, &msg, 0);
    if (rv) {
	/* FIXME - log an error. */
    }
}

static void
ipmb_addr_change_dev(channel_t     *chan,
		     unsigned char addr)
{
    unsigned int slave_addr = addr;
    int          rv;
    misc_data_t  *info = chan->oem.user_data;

    info->bmc_ipmb = addr;
    rv = ioctl(info->smi_fd, IPMICTL_SET_MY_ADDRESS_CMD, &slave_addr);
    if (rv) {
	chan->log(chan, OS_ERROR, NULL,
		  "Error setting IPMB address: 0x%x", errno);
    }    
}

static int
smi_send_dev(channel_t *chan, msg_t *msg)
{
    struct ipmi_req  req;
    char             addr_data[sizeof(struct ipmi_addr)];
    struct ipmi_addr *addr = (struct ipmi_addr *) addr_data;
    misc_data_t      *info = chan->oem.user_data;
    int              rv;

    req.addr = (unsigned char *) addr;
    
    if (msg->cmd == IPMI_SEND_MSG_CMD) {
	struct ipmi_ipmb_addr *ipmb = (void *) addr;
	int                   pos;
	/* Send message has special handling */
	
	if (msg->len < 8)
	    return EMSGSIZE;

	ipmb->addr_type = IPMI_IPMB_ADDR_TYPE;
	ipmb->channel = msg->data[0] & 0xf;
	pos = 1;
	if (msg->data[pos] == 0) {
	    ipmb->addr_type = IPMI_IPMB_BROADCAST_ADDR_TYPE;
	    pos++;
	    if (msg->len < 9)
	        return EMSGSIZE;
	}
	ipmb->slave_addr = msg->data[pos];
	ipmb->lun = msg->data[pos+1] & 0x3;
	req.addr_len = sizeof(*ipmb);
	req.msg.netfn = msg->data[pos+1] >> 2;
	req.msg.cmd = msg->data[pos+5];
	req.msg.data = msg->data+pos+6;
	req.msg.data_len = msg->len-(pos + 7); /* Subtract last checksum, too */
    } else {
	/* Normal message to the BMC. */
	struct ipmi_system_interface_addr *si = (void *) addr;

	si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si->channel = 0xf;
	si->lun = msg->rs_lun;
	req.addr_len = sizeof(*si);
	req.msg.netfn = msg->netfn;
	req.msg.cmd = msg->cmd;
	req.msg.data = msg->data;
	req.msg.data_len = msg->len;
    }

    req.msgid = (long) msg;

    rv = ioctl(info->smi_fd, IPMICTL_SEND_COMMAND, &req);
    if (rv == -1) {
	free(msg);
	return errno;
    } else
	return 0;
}

static int
gen_rand(lanserv_data_t *lan, void *data, int len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    int rv;

    if (fd == -1)
	return errno;

    while (len > 0) {
	rv = read(fd, data, len);
	if (rv < 0) {
	    rv = errno;
	    goto out;
	}
	len -= rv;
    }

    rv = 0;

 out:
    close(fd);
    return rv;
}

static uint8_t
ipmb_checksum(uint8_t *data, int size, uint8_t start)
{
	uint8_t csum = start;
	
	for (; size > 0; size--, data++)
		csum += *data;

	return -csum;
}

static void
handle_msg_ipmi_dev(int smi_fd, void *cb_data, os_hnd_fd_id_t *id)
{
    misc_data_t      *info = cb_data;
    struct ipmi_recv rsp;
    char             addr_data[sizeof(struct ipmi_addr)];
    struct ipmi_addr *addr = (struct ipmi_addr *) addr_data;
    unsigned char    data[IPMI_MAX_MSG_LENGTH+8];
    unsigned char    rdata[IPMI_MAX_MSG_LENGTH];
    int              rv;
    msg_t            *msg;

    rsp.addr = (unsigned char *) addr;
    rsp.addr_len = sizeof(struct ipmi_addr);
    rsp.msg.data = rdata;
    rsp.msg.data_len = sizeof(rdata);

    rv = ioctl(smi_fd, IPMICTL_RECEIVE_MSG_TRUNC, &rsp);
    if (rv == -1) {
	if (errno == EINTR)
	    return; /* Try again later. */
	if (errno == EMSGSIZE) {
	    rdata[0] = IPMI_REQUEST_DATA_TRUNCATED_CC;
	    rsp.msg.data_len = sizeof(rdata);
	} else {
	    lanserv_log(NULL, DEBUG, NULL, "Error receiving message: %s\n", strerror(errno));
	    return;
	}
    }

    msg = (msg_t *) rsp.msgid;

    if (rdata[0] == IPMI_TIMEOUT_CC) {
	/* Ignore timeouts, we let the LAN code do the timeouts. */
	free(msg);
	return;
    }

    /* We only handle responses. */
    if (rsp.recv_type != IPMI_RESPONSE_RECV_TYPE) {
	free(msg);
	return;
    }

    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	/* Nothing to do. */
    } else if (addr->addr_type == IPMI_IPMB_ADDR_TYPE) {
	struct ipmi_ipmb_addr *ipmb = (void *) addr; 

	data[0] = 0; /* return code. */
	data[1] = info->bmc_ipmb;
	data[2] = (rsp.msg.netfn << 2) | 2;
	data[3] = ipmb_checksum(data+1, 2, 0);
	data[4] = ipmb->slave_addr;
	data[5] = (msg->data[4] & 0xfc) | ipmb->lun;
	data[6] = rsp.msg.cmd;
	memcpy(data+7, rsp.msg.data, rsp.msg.data_len);
	rsp.msg.data = data;
	rsp.msg.data_len += 8;
	data[rsp.msg.data_len-1] = ipmb_checksum(data+1, rsp.msg.data_len-2, 0);
    } else {
	lanserv_log(NULL, DEBUG, NULL, "Error!\n");
	return;
    }

    ipmi_handle_smi_rsp(info->bmc->channels[msg->channel], msg,
			rsp.msg.data, rsp.msg.data_len);
}

static void
lan_data_ready(int lan_fd, void *cb_data, os_hnd_fd_id_t *id)
{
    lanserv_data_t *lan = cb_data;
    int                len;
    lanserv_addr_t     l;
    unsigned char      data[256];

    l.addr_len = sizeof(l.addr);
    len = recvfrom(lan_fd, data, sizeof(data), 0, 
		    (struct sockaddr *)&(l.addr), &(l.addr_len));
    if (len < 0) {
	if (errno != EINTR) {
	    perror("Error receiving message");
	    exit(1);
	}
	return;
    }
    l.xmit_fd = lan_fd;

    if (lan->bmcinfo->debug & DEBUG_RAW_MSG) {
	debug_log_raw_msg(lan->bmcinfo, (void *) &l.addr, l.addr_len,
			  "Raw LAN receive from:");
	debug_log_raw_msg(lan->bmcinfo, data, len,
			  " Receive message:");
    }

    if (len < 4)
	return;

    if (data[0] != 6)
	return; /* Invalid version */

    /* Check the message class. */
    switch (data[3]) {
	case 6:
	    handle_asf(lan, data, len, &l, sizeof(l));
	    break;

	case 7:
	    ipmi_handle_lan_msg(lan, data, len, &l, sizeof(l));
	    break;
    }
}

static int
ipmi_open(char *ipmi_dev)
{
    int ipmi_fd;

    if (ipmi_dev) {
	ipmi_fd = open(ipmi_dev, O_RDWR);
    } else {
	ipmi_fd = open("/dev/ipmidev/0", O_RDWR);
	if (ipmi_fd == -1) {
	    ipmi_fd = open("/dev/ipmi0", O_RDWR);
	}
    }

    if (ipmi_fd == -1) {
	perror("Could not open ipmi device /dev/ipmidev/0 or /dev/ipmi0");
    } else {
	/* Set the timing parameters for the connection to no retries
	   and 1 second timeout.  The LAN connection will retry, there
	   is no reason for us to.  If this fails, oh well, the kernel
	   doesn't support it.  It's not the end of the world. */
	struct ipmi_timing_parms parms;
	int                      rv;
	    
	parms.retries = 0;
	parms.retry_time_ms = 1000;
	    
	rv = ioctl(ipmi_fd, IPMICTL_SET_TIMING_PARMS_CMD, &parms);
	if (rv == -1)
	    perror("Could not set timing parms");
    }

    return ipmi_fd;
}

static int
open_lan_fd(struct sockaddr *addr, socklen_t addr_len)
{
    int                fd;
    int                rv;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
	perror("Unable to create socket");
	exit(1);
    }

    rv = bind(fd, addr, addr_len);
    if (rv == -1)
    {
	fprintf(stderr, "Unable to bind to LAN port: %s\n",
		strerror(errno));
	exit(1);
    }

    return fd;
}

static void
ilanserv_log(bmc_data_t *bmc, int logtype, msg_t *msg, char *format, va_list ap,
	     int len)
{
    if (msg) {
	char *str, dummy;
	int pos;
	unsigned int i;

#define mformat " channel=%d netfn=0x%x cmd=0x%x rs_addr=0x%x rs_lun=0x%x" \
	    " rq_addr=0x%x\n rq_lun=0x%x rq_seq=0x%x\n"

	len += snprintf(&dummy, 1, mformat, msg->channel, msg->netfn,
			msg->cmd, msg->rs_addr, msg->rs_lun, msg->rq_addr,
			msg->rq_lun, msg->rq_seq);
	len += 3 * msg->len + 3;
	str = malloc(len);
	if (!str)
	    goto print_no_msg;
	pos = vsprintf(str, format, ap);
	str[pos++] = '\n';
	pos += sprintf(str + pos, mformat, msg->channel, msg->netfn, msg->cmd,
		       msg->rs_addr, msg->rs_lun, msg->rq_addr, msg->rq_lun,
		       msg->rq_seq);
#undef mformat
	for (i = 0; i < msg->len; i++)
	    pos += sprintf(str + pos, " %2.2x", msg->data[i]);
	
	if (!daemonize || (logtype == DEBUG))
	    printf("%s\n", str);
#if HAVE_SYSLOG
	if (logtype != DEBUG)
	    syslog(LOG_NOTICE, "%s", str);
#endif
	free(str);
	return;
    }

 print_no_msg:
    if (!daemonize || (logtype == DEBUG)) {
	vprintf(format, ap);
	printf("\n");
    }
#if HAVE_SYSLOG
    if (logtype != DEBUG)
	vsyslog(LOG_NOTICE, format, ap);
#endif
}

static void
lanserv_log(bmc_data_t *bmc, int logtype, msg_t *msg, char *format, ...)
{
    va_list ap;
    char dummy;
    int len;

    va_start(ap, format);
    len = vsnprintf(&dummy, 1, format, ap);
    va_end(ap);
    va_start(ap, format);
    ilanserv_log(bmc, logtype, msg, format, ap, len);
    va_end(ap);
}

static void
lanserv_chan_log(channel_t *bmc, int logtype, msg_t *msg, char *format, ...)
{
    va_list ap;
    char dummy;
    int len;

    va_start(ap, format);
    len = vsnprintf(&dummy, 1, format, ap);
    va_end(ap);
    va_start(ap, format);
    ilanserv_log(NULL, logtype, msg, format, ap, len);
    va_end(ap);
}

static char *config_file = "/etc/ipmi_lan.conf";
static char *ipmi_dev = NULL;

static struct poptOption poptOpts[]=
{
    {
	"config-file",
	'c',
	POPT_ARG_STRING,
	&config_file,
	'c',
	"configuration file",
	""
    },
    {
	"ipmi-dev",
	'i',
	POPT_ARG_STRING,
	&ipmi_dev,
	'i',
	"IPMI device",
	""
    },
    {
	"debug",
	'd',
	POPT_ARG_NONE,
	NULL,
	'd',
	"debug",
	""
    },
    {
	"daemonize",
	'n',
	POPT_ARG_NONE,
	NULL,
	'n',
	"daemonize",
	""
    },
    POPT_AUTOHELP
    {
	NULL,
	0,
	0,
	NULL,
	0		 
    }	
};

static void
write_config(bmc_data_t *chan)
{
//    misc_data_t *info = lan->user_info;
}

void init_oem_force(void);

static void
tick(void *cb_data, os_hnd_timer_id_t *id)
{
    misc_data_t *data = cb_data;
    struct timeval tv;
    int err;
    unsigned int i;

    for (i = 0; i < IPMI_MAX_CHANNELS; i++) {
	channel_t *chan = data->bmc->channels[i];

	if (chan && (chan->medium_type == IPMI_CHANNEL_MEDIUM_8023_LAN)) {
	    ipmi_lan_tick(chan->chan_info, 1);
	}
    }

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    err = data->os_hnd->start_timer(data->os_hnd, data->timer, &tv, tick, data);
    if (err) {
	fprintf(stderr, "Unable to start timer: 0x%x\n", err);
	exit(1);
    }
}

static void *
ialloc(channel_t *chan, int size)
{
    return malloc(size);
}

static void
ifree(channel_t *chan, void *data)
{
    return free(data);
}

int
main(int argc, const char *argv[])
{
    bmc_data_t  bmcinfo;
    misc_data_t data;
    int o;
    unsigned int i;
    int err;
    poptContext poptCtx;
    struct timeval tv;
    int lan_fd;
    os_hnd_fd_id_t *fd_id;
    unsigned int debug = 0;

#if HAVE_SYSLOG
    openlog(argv[0], LOG_CONS, LOG_DAEMON);
#endif

    poptCtx = poptGetContext(argv[0], argc, argv, poptOpts, 0);
    while ((o = poptGetNextOpt(poptCtx)) >= 0) {
	switch (o) {
	    case 'd':
		debug++;
		break;
	    case 'n':
		daemonize = 0;
		break;
	}
    }
    poptFreeContext(poptCtx);

    data.bmc_ipmb = 0x20;
    data.bmc = &bmcinfo;
    data.os_hnd = ipmi_posix_setup_os_handler();
    if (!data.os_hnd) {
	fprintf(stderr, "Unable to allocate OS handler\n");
	exit(1);
    }

    err = os_handler_alloc_waiter_factory(data.os_hnd, 0, 0,
					  &data.waiter_factory);
    if (err) {
	fprintf(stderr, "Unable to allocate waiter factory: 0x%x\n", err);
	exit(1);
    }

    err = data.os_hnd->alloc_timer(data.os_hnd, &data.timer);
    if (err) {
	fprintf(stderr, "Unable to allocate timer: 0x%x\n", err);
	exit(1);
    }

    /* Call the OEM init code. */
    init_oem_force();

    bmcinfo_init(&bmcinfo);
    bmcinfo.alloc = balloc;
    bmcinfo.free = bfree;
    bmcinfo.write_config = write_config;
    bmcinfo.log = lanserv_log;
    bmcinfo.debug = debug;


    if (read_config(&bmcinfo, config_file))
	exit(1);

    data.smi_fd = ipmi_open(ipmi_dev);
    if (data.smi_fd == -1)
	exit(1);
    err = data.os_hnd->add_fd_to_wait_for(data.os_hnd, data.smi_fd,
					  handle_msg_ipmi_dev, &data,
					  NULL, &fd_id);
    if (err) {
	fprintf(stderr, "Unable to add input wait: 0x%x\n", err);
	exit(1);
    }

    for (i = 0; i < IPMI_MAX_CHANNELS; i++) {
	channel_t *chan = bmcinfo.channels[i];

	if (!chan)
	    continue;

	chan->smi_send = smi_send_dev;
	chan->oem.user_data = &data;
	chan->oem.ipmb_addr_change = ipmb_addr_change_dev;
	chan->alloc = ialloc;
	chan->free = ifree;
	chan->log = lanserv_chan_log;

	if (chan->medium_type == IPMI_CHANNEL_MEDIUM_8023_LAN) {
	    lanserv_data_t *lan = chan->chan_info;

	    lan->user_info = &data;
	    lan->send_out = lan_send;
	    lan->gen_rand = gen_rand;

	    err = ipmi_lan_init(lan);
	    if (err) {
		fprintf(stderr, "Unable to init lan: 0x%x\n", err);
		exit(1);
	    }

	    if (lan->num_lan_addrs == 0) {
		struct sockaddr_in *ipaddr = (void *) &lan->lan_addrs[0].addr;
		ipaddr->sin_family = AF_INET;
		ipaddr->sin_port = htons(623);
		ipaddr->sin_addr.s_addr = INADDR_ANY;
		lan->lan_addrs[0].addr_len = sizeof(*ipaddr);
		lan->num_lan_addrs++;
	    }

	    for (i=0; i<lan->num_lan_addrs; i++) {
		if (lan->lan_addrs[i].addr_len == 0)
		    break;

		lan_fd = open_lan_fd(&lan->lan_addrs[i].addr.s_ipsock.s_addr,
				     lan->lan_addrs[i].addr_len);
		if (lan_fd == -1) {
		    fprintf(stderr, "Unable to open LAN address %d\n", i+1);
		    exit(1);
		}

		err = data.os_hnd->add_fd_to_wait_for(data.os_hnd, lan_fd,
						      lan_data_ready, lan,
						      NULL, &fd_id);
		if (err) {
		    fprintf(stderr, "Unable to add socket wait: 0x%x\n", err);
		    exit(1);
		}
	    }
	} else 
	    chan_init(chan);
    }

    if (daemonize) {
	int pid;

	if ((pid = fork()) > 0) {
	    exit(0);
	} else if (pid < 0) {
	    lanserv_log(NULL, LAN_ERR, NULL, "Error forking first fork");
	    exit(1);
	} else {
	    /* setsid() is necessary if we really want to demonize */
	    setsid();
	    /* Second fork to really deamonize me. */
	    if ((pid = fork()) > 0) {
		exit(0);
	    } else if (pid < 0) {
		lanserv_log(NULL, LAN_ERR, NULL, "Error forking second fork");
		exit(1);
	    }
	}
    }

    lanserv_log(NULL, LAN_ERR, NULL, "%s startup", argv[0]);

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    err = data.os_hnd->start_timer(data.os_hnd, data.timer, &tv, tick, &data);
    if (err) {
	fprintf(stderr, "Unable to start timer: 0x%x\n", err);
	exit(1);
    }

    data.os_hnd->operation_loop(data.os_hnd);
    return 0;
}
