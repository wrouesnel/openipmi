/*
 * lanserv_emu.c
 *
 * MontaVista IPMI code for creating a LAN interface to an emulated
 * SMI interface.
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
#include <termios.h>

#include <OpenIPMI/ipmi_log.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/serv.h>
#include <OpenIPMI/lanserv.h>

#include "emu.h"

#define MAX_ADDR 4

static char *config_file = "/etc/ipmi_lan.conf";
static char *command_string = NULL;
static char *command_file = NULL;
static int debug = 0;
static int port = -1;

typedef struct misc_data
{
    bmc_data_t *bmc;
    emu_data_t *emu;
    os_handler_t *os_hnd;
    os_handler_waiter_factory_t *waiter_factory;
    os_hnd_timer_id_t *timer;
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

typedef struct sim_addr_s
{
    struct sockaddr addr;
    socklen_t       addr_len;
    int             xmit_fd;
} sim_addr_t;

static void
lan_send(lanserv_data_t *lan,
	 struct iovec *data, int vecs,
	 void *addr, int addr_len)
{
    struct msghdr msg;
    sim_addr_t    *l = addr;
    int           rv;

    /* When we send messages to ourself, we set the address to NULL so
       it won't be used. */
    if (!l)
	return;

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

static int
smi_send(channel_t *chan, msg_t *msg)
{
    misc_data_t      *data = chan->oem.user_data;
    unsigned char    msgd[36];
    unsigned int     msgd_len = sizeof(msgd);

    ipmi_emu_handle_msg(data->emu, msg, msgd, &msgd_len);

    ipmi_handle_smi_rsp(chan, msg, msgd, msgd_len);
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

static void
lan_data_ready(int lan_fd, void *cb_data, os_hnd_fd_id_t *id)
{
    lanserv_data_t    *lan = cb_data;
    int           len;
    sim_addr_t    l;
    unsigned char msgd[256];

    l.addr_len = sizeof(l.addr);
    len = recvfrom(lan_fd, msgd, sizeof(msgd), 0, &(l.addr), &(l.addr_len));
    if (len < 0) {
	if (errno != EINTR) {
	    perror("Error receiving message");
	    exit(1);
	}
	goto out;
    }
    l.xmit_fd = lan_fd;

    if (len < 4)
	goto out;

    if (msgd[0] != 6)
	goto out; /* Invalid version */

    /* Check the message class. */
    switch (msgd[3]) {
	case 6:
	    handle_asf(lan, msgd, len, &l, sizeof(l));
	    break;

	case 7:
	    ipmi_handle_lan_msg(lan, msgd, len, &l, sizeof(l));
	    break;
    }
 out:
    return;
}

static int
open_lan_fd(struct sockaddr *addr, socklen_t addr_len)
{
    int                fd;
    int                rv;
    struct sockaddr_in *ipaddr = (struct sockaddr_in *) addr;

    if (port > 0)
	ipaddr->sin_port = htons(port);

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
lanserv_log(int logtype, msg_t *msg, char *format, ...)
{
    va_list ap;
    struct timeval tod;
    struct tm ltime;
    char timebuf[30];
    int timelen;
    char fullformat[256];

    va_start(ap, format);
    gettimeofday(&tod, NULL);
    localtime_r(&tod.tv_sec, &ltime);
    asctime_r(&ltime, timebuf);
    timelen = strlen(timebuf);
    timebuf[timelen-1] = '\0'; /* Nuke the '\n'. */
    timelen--;
    if ((timelen + strlen(format) + 2) >= sizeof(fullformat)) {
	vprintf(format, ap);
    } else {
	strcpy(fullformat, timebuf);
	strcat(fullformat, ": ");
	strcat(fullformat, format);
	vprintf(fullformat, ap);
    }
    printf("\n");
    va_end(ap);
}

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
	"command-string",
	'x',
	POPT_ARG_STRING,
	&command_string,
	'x',
	"command string",
	""
    },
    {
	"command-file",
	'f',
	POPT_ARG_STRING,
	&command_file,
	'f',
	"command file",
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
	"port",
	'p',
	POPT_ARG_INT,
	&port,
	'p',
	"port",
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
write_config(bmc_data_t *bmc)
{
//    misc_data_t *info = lan->user_info;
}

static char buffer[1024];
static unsigned int pos = 0;
static int echo = 1;

static void
handle_user_char(misc_data_t *data, char c)
{
    switch(c) {
    case 8:
    case 0x7f:
	if (pos > 0) {
	    pos--;
	    if (echo)
		printf("\b \b");
	}
	break;

    case 4:
	if (pos == 0) {
	    if (echo)
		printf("\n");
	    ipmi_emu_shutdown();
	}
	break;

    case 10:
    case 13:
	printf("\n");
	buffer[pos] = '\0';
	if (strcmp(buffer, "noecho") == 0)
	    echo = 0;
	else
	    ipmi_emu_cmd(data->emu, buffer);
	printf("> ");
	pos = 0;
	break;

    default:
	if (pos >= sizeof(buffer)-1) {
	    printf("\nCommand is too long, max of %d characters\n",
		   (int) sizeof(buffer)-1);
	} else {
	    buffer[pos] = c;
	    pos++;
	    if (echo)
		printf("%c", c);
	}
    }
    fflush(stdout);
}

static void
user_data_ready(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
    misc_data_t *data = cb_data;
    char        rc;
    int         count;

    count = read(fd, &rc, 1);
    if (count > 0)
	handle_user_char(data, rc);
}

struct termios old_termios;
int old_flags;

static void
init_term(void)
{
    struct termios new_termios;

    tcgetattr(0, &old_termios);
    new_termios = old_termios;
    new_termios.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
			     |INLCR|IGNCR|ICRNL|IXON);
    new_termios.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    tcsetattr(0, TCSADRAIN, &new_termios);
}

void
ipmi_emu_shutdown(void)
{
    tcsetattr(0, TCSADRAIN, &old_termios);
    fcntl(0, F_SETFL, old_flags);
    tcdrain(0);
    exit(0);
}

/* Sleep and don't take any user input. */
static void
sleeper(emu_data_t *emu, struct timeval *time)
{
    misc_data_t    *data = ipmi_emu_get_user_data(emu);
    os_handler_waiter_t *waiter;

    waiter = os_handler_alloc_waiter(data->waiter_factory);
    if (!waiter) {
	fprintf(stderr, "Unable to allocate waiter\n");
	exit(1);
    }

    os_handler_waiter_wait(waiter, time);
    os_handler_waiter_release(waiter);
}

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
    ipmi_emu_tick(data->emu, 1);

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
    int err;
    int i;
    poptContext poptCtx;
    struct timeval tv;
    int lan_fd;
    os_hnd_fd_id_t *fd_id;

    poptCtx = poptGetContext(argv[0], argc, argv, poptOpts, 0);
    while ((i = poptGetNextOpt(poptCtx)) >= 0) {
	switch (i) {
	    case 'd':
		debug++;
		break;
	}
    }
    poptFreeContext(poptCtx);

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

    bmcinfo_init(&bmcinfo);
    bmcinfo.alloc = balloc;
    bmcinfo.free = bfree;
    bmcinfo.write_config = write_config;
    data.bmc = &bmcinfo;

    data.emu = ipmi_emu_alloc(&data, sleeper, &bmcinfo);

    if (read_config(&bmcinfo, config_file))
	exit(1);

    if (command_string)
	ipmi_emu_cmd(data.emu, command_string);

    if (command_file)
	read_command_file(data.emu, command_file);

    for (i = 0; i < IPMI_MAX_CHANNELS; i++) {
	channel_t *chan = bmcinfo.channels[i];

	if (!chan)
	    continue;

	chan->smi_send = smi_send;
	chan->oem.user_data = &data;
	chan->log = lanserv_log;
	chan->alloc = ialloc;
	chan->free = ifree;

	if (chan->medium_type == IPMI_CHANNEL_MEDIUM_8023_LAN) {
	    lanserv_data_t *lan = chan->chan_info;

	    lan->user_info = &data;
	    lan->send_out = lan_send;
	    lan->gen_rand = gen_rand;
	    lan->debug = debug;

	    err = ipmi_lan_init(lan);
	    if (err) {
		fprintf(stderr, "Unable to init lan: 0x%x\n", err);
		exit(1);
	    }

	    if (lan->guid) {
		lmc_data_t *bmc = ipmi_emu_get_bmc_mc(data.emu);
		if (bmc)
		    ipmi_emu_set_mc_guid(bmc, lan->guid, 0);
	    }

	    if (lan->num_lan_addrs == 0) {
		struct sockaddr_in *ipaddr = (void *) &lan->lan_addrs[0].addr;
		ipaddr->sin_family = AF_INET;
		if (port > 0)
		    ipaddr->sin_port = htons(port);
		else
		    ipaddr->sin_port = htons(623);
		ipaddr->sin_addr.s_addr = INADDR_ANY;
		lan->lan_addrs[0].addr_len = sizeof(*ipaddr);
		lan->num_lan_addrs++;
	    }

	    for (i=0; i<lan->num_lan_addrs; i++) {
		unsigned char addr_data[6];

		if (lan->lan_addrs[i].addr_len == 0)
		    break;

		lan_fd = open_lan_fd(&lan->lan_addrs[i].addr.s_ipsock.s_addr,
				     lan->lan_addrs[i].addr_len);
		if (lan_fd == -1) {
		    fprintf(stderr, "Unable to open LAN address %d\n", i+1);
		    exit(1);
		}

		memcpy(addr_data,
		       &lan->lan_addrs[i].addr.s_ipsock.s_addr4.sin_addr.s_addr,
		       4);
		memcpy(addr_data+4,
		       &lan->lan_addrs[i].addr.s_ipsock.s_addr4.sin_port, 2);
		ipmi_emu_set_addr(data.emu, i, 0, addr_data, 6);

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

    init_term();
    printf("> ");
    fflush(stdout);
    err = data.os_hnd->add_fd_to_wait_for(data.os_hnd, 0,
					  user_data_ready, &data,
					  NULL, &fd_id);
    if (err) {
	fprintf(stderr, "Unable to add input wait: 0x%x\n", err);
	exit(1);
    }

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
