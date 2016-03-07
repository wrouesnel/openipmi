/*
 * ipmi_sim.c
 *
 * MontaVista IPMI code for creating a LAN interface, emulated system
 * interfaces, and a full BMC emulator.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2003,2004,2005,2012 MontaVista Software Inc.
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
#include <netinet/tcp.h>
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
#include <signal.h>
#include <sys/wait.h>

#include <config.h>

#if HAVE_SYSLOG
#include <syslog.h>
#endif

#include <OpenIPMI/ipmi_log.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/serv.h>
#include <OpenIPMI/lanserv.h>
#include <OpenIPMI/serserv.h>

#include "emu.h"
#include <OpenIPMI/persist.h>

#define MAX_ADDR 4

#define BASE_CONF_STR SYSCONFDIR "/ipmi"
static char *config_file = BASE_CONF_STR "/lan.conf";
static const char *statedir = STATEDIR;
static char *command_string = NULL;
static char *command_file = NULL;
static int debug = 0;
static int nostdio = 0;

/*
 * Keep track of open sockets so we can close them on exec().
 */
typedef struct isim_fd {
    int fd;
    struct isim_fd *next;
} isim_fd_t;

static isim_fd_t *isim_fds = NULL;

static void isim_add_fd(int fd)
{
    isim_fd_t *n = malloc(sizeof(*n));

    if (!n) {
	fprintf(stderr, "Unable to add fd to list, out of memory\n");
	exit(1);
    }

    n->fd = fd;
    n->next = isim_fds;
    isim_fds = n;
}

static void isim_close_fds(void)
{
    isim_fd_t *n = isim_fds;

    while(n) {
	close(n->fd);
	n = n->next;
    }
}

static void shutdown_handler(int sig);

typedef struct misc_data misc_data_t;

typedef struct console_info_s
{
    char buffer[1024];
    unsigned int pos;
    int telnet;
    int echo;
    int shutdown_on_close;
    misc_data_t *data;
    int outfd;
    os_hnd_fd_id_t *conid;
    unsigned int tn_pos;
    unsigned char tn_buf[4];
    emu_out_t out;
    struct console_info_s *prev;
    struct console_info_s *next;
} console_info_t;

struct misc_data
{
    sys_data_t *sys;
    emu_data_t *emu;
    os_handler_t *os_hnd;
    os_handler_waiter_factory_t *waiter_factory;
    os_hnd_timer_id_t *timer;
    console_info_t *consoles;
};

static misc_data_t *global_misc_data;

static void *
balloc(sys_data_t *sys, int size)
{
    return malloc(size);
}

static void
bfree(sys_data_t *sys, void *data)
{
    return free(data);
}

typedef struct sim_addr_s
{
    struct sockaddr_storage addr;
    socklen_t       addr_len;
    int             xmit_fd;
} sim_addr_t;

static int
smi_send(channel_t *chan, msg_t *msg)
{
    misc_data_t      *data = chan->oem.user_data;
    unsigned char    msgd[36];
    unsigned int     msgd_len = sizeof(msgd);

    ipmi_emu_handle_msg(data->emu, chan->mc, msg, msgd, &msgd_len);

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

static int
sys_gen_rand(sys_data_t *lan, void *data, int len)
{
    gen_rand(NULL, data, len);
    return 0;
}

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

static void
lan_data_ready(int lan_fd, void *cb_data, os_hnd_fd_id_t *id)
{
    lanserv_data_t    *lan = cb_data;
    int           len;
    sim_addr_t    l;
    unsigned char msgd[256];

    l.addr_len = sizeof(l.addr);
    len = recvfrom(lan_fd, msgd, sizeof(msgd), 0,
		   (struct sockaddr *) &(l.addr), &(l.addr_len));
    if (len < 0) {
	if (errno != EINTR) {
	    perror("Error receiving message");
	    exit(1);
	}
	goto out;
    }
    l.xmit_fd = lan_fd;

    if (lan->sysinfo->debug & DEBUG_RAW_MSG) {
	debug_log_raw_msg(lan->sysinfo, (void *) &l.addr, l.addr_len,
			  "Raw LAN receive from:");
	debug_log_raw_msg(lan->sysinfo, msgd, len,
			  " Receive message:");
    }

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
    int fd;
    int rv;
    int opt;

    fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
	perror("Unable to create socket");
	exit(1);
    }

    opt = 1;
    rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (rv == -1) {
	fprintf(stderr, "Unable to set SO_REUSEADDR: %s\n",
		strerror(errno));
	exit(1);
    }

    rv = bind(fd, addr, addr_len);
    if (rv == -1) {
	fprintf(stderr, "Unable to bind to LAN port: %s\n",
		strerror(errno));
	exit(1);
    }

    isim_add_fd(fd);

    return fd;
}

static int
lan_channel_init(void *info, channel_t *chan)
{
    misc_data_t *data = info;
    lanserv_data_t *lan = chan->chan_info;
    int err;
    int lan_fd;
    os_hnd_fd_id_t *fd_id;
    unsigned char addr_data[6];

    lan->user_info = data;
    lan->send_out = lan_send;
    lan->gen_rand = gen_rand;

    err = ipmi_lan_init(lan);
    if (err) {
	fprintf(stderr, "Unable to init lan: 0x%x\n", err);
	exit(1);
    }

    if (lan->guid) {
	lmc_data_t *sys = ipmi_emu_get_bmc_mc(data->emu);
	if (sys)
	    ipmi_emu_set_mc_guid(sys, lan->guid, 0);
    }

    if (lan->lan_addr_set) {
	lan_fd = open_lan_fd(&lan->lan_addr.addr.s_ipsock.s_addr,
			     lan->lan_addr.addr_len);
	if (lan_fd == -1) {
	    fprintf(stderr, "Unable to open LAN address\n");
	    exit(1);
	}

	memcpy(addr_data,
	       &lan->lan_addr.addr.s_ipsock.s_addr4.sin_addr.s_addr,
	       4);
	memcpy(addr_data + 4,
	       &lan->lan_addr.addr.s_ipsock.s_addr4.sin_port, 2);
	ipmi_emu_set_addr(data->emu, 0, 0, addr_data, 6);

	err = data->os_hnd->add_fd_to_wait_for(data->os_hnd, lan_fd,
					       lan_data_ready, lan,
					       NULL, &fd_id);
	if (err) {
	    fprintf(stderr, "Unable to add socket wait: 0x%x\n", err);
	    exit(1);
	}
    }

    return err;
}

static void
ser_send(serserv_data_t *ser, unsigned char *data, unsigned int data_len)
{
    int rv;

    if (ser->con_fd == -1)
	/* Not connected */
	return;

    rv = write(ser->con_fd, data, data_len);
    if (rv) {
	/* FIXME - log an error. */
    }
}

static void
ser_data_ready(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
    serserv_data_t *ser = cb_data;
    int           len;
    unsigned char msgd[256];

    len = read(fd, msgd, sizeof(msgd));
    if (len <= 0) {
	if ((len < 0) && (errno == EINTR))
	    return;

	if (ser->codec->disconnected)
	    ser->codec->disconnected(ser);
	ser->os_hnd->remove_fd_to_wait_for(ser->os_hnd, id);
	close(fd);
	ser->con_fd = -1;
	return;
    }

    serserv_handle_data(ser, msgd, len);
}

static void
ser_bind_ready(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
    serserv_data_t *ser = cb_data;
    int rv;
    int err;
    os_hnd_fd_id_t *fd_id;
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    int val = 1;

    rv = accept(fd, (struct sockaddr *) &addr, &addr_len);
    if (rv < 0) {
	perror("Error from accept");
	exit(1);
    }

    if (ser->con_fd >= 0) {
	close(rv);
	return;
    }

    setsockopt(rv, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
    setsockopt(rv, SOL_SOCKET, SO_KEEPALIVE, (char *)&val, sizeof(val));

    ser->con_fd = rv;

    err = ser->os_hnd->add_fd_to_wait_for(ser->os_hnd, ser->con_fd,
					  ser_data_ready, ser,
					  NULL, &fd_id);
    if (err) {
	fprintf(stderr, "Unable to add serial socket wait: 0x%x\n", err);
	ser->con_fd = -1;
	close(rv);
    } else {
	if (ser->codec->connected)
	    ser->codec->connected(ser);
    }
}

static int
ser_channel_init(void *info, channel_t *chan)
{
    misc_data_t *data = info;
    serserv_data_t *ser = chan->chan_info;
    int err;
    int fd;
    struct sockaddr *addr = &ser->addr.addr.s_ipsock.s_addr;
    os_hnd_fd_id_t *fd_id;
    int val;

    ser->os_hnd = data->os_hnd;
    ser->user_info = data;
    ser->send_out = ser_send;

    err = serserv_init(ser);
    if (err) {
	fprintf(stderr, "Unable to init serial: 0x%x\n", err);
	exit(1);
    }

    fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
	perror("Unable to create socket");
	exit(1);
    }

    if (ser->do_connect) {
	err = connect(fd, addr, ser->addr.addr_len);
	if (err == -1) {
	    fprintf(stderr, "Unable to connect to serial TCP port: %s\n",
		    strerror(errno));
	    exit(1);
	}
	ser->con_fd = fd;
	ser->bind_fd = -1;

	err = data->os_hnd->add_fd_to_wait_for(data->os_hnd, ser->con_fd,
					       ser_data_ready, ser,
					       NULL, &fd_id);
	if (err) {
	    fprintf(stderr, "Unable to add serial socket wait: 0x%x\n", err);
	    exit(1);
	}
    } else {
        int opt = 1;

	err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (err == -1) {
	    fprintf(stderr, "Unable to set SO_REUSEADDR on serial TCP: %s\n",
		    strerror(errno));
	    exit(1);
	}

	err = bind(fd, addr, ser->addr.addr_len);
	if (err == -1) {
	    fprintf(stderr, "Unable to bind to serial TCP port: %s\n",
		    strerror(errno));
	    exit(1);
	}
	ser->bind_fd = fd;
	ser->con_fd = -1;

	err = listen(fd, 1);
	if (err == -1) {
	    fprintf(stderr, "Unable to listen to serial TCP port: %s\n",
		    strerror(errno));
	    exit(1);
	}

	val = 1;
	err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&val,
			 sizeof(val));
	if (err == -1) {
	    fprintf(stderr, "Unable to set SO_REUSEADDR on socket: %s\n",
		    strerror(errno));
	    exit(1);
	}
	

	err = data->os_hnd->add_fd_to_wait_for(data->os_hnd, ser->bind_fd,
					       ser_bind_ready, ser,
					       NULL, &fd_id);
	if (err) {
	    fprintf(stderr, "Unable to add serial socket wait: 0x%x\n", err);
	    exit(1);
	}
    }

    if (!err)
	isim_add_fd(fd);

    return err;
}

static void
isim_log(sys_data_t *sys, int logtype, msg_t *msg, const char *format,
	 va_list ap, int len)
{
    misc_data_t *data = sys->info;
    char *str;
    console_info_t *con;

    if (msg) {
	char dummy;
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
	    return;
	pos = vsprintf(str, format, ap);
	str[pos++] = '\n';
	pos += sprintf(str + pos, mformat, msg->channel, msg->netfn, msg->cmd,
		       msg->rs_addr, msg->rs_lun, msg->rq_addr, msg->rq_lun,
		       msg->rq_seq);
#undef mformat
	for (i = 0; i < msg->len; i++)
	    pos += sprintf(str + pos, " %2.2x", msg->data[i]);
    } else {
	str = malloc(len + 1);
	if (!str)
	    return;
	vsprintf(str, format, ap);
    }

    con = data->consoles;
    while (con) {
	con->out.printf(&con->out, "%s", str);
	con->out.printf(&con->out, "\n");
	con = con->next;
    }
#if HAVE_SYSLOG
    if (logtype == DEBUG)
	syslog(LOG_DEBUG, "%s", str);
    else
	syslog(LOG_NOTICE, "%s", str);
#endif
    free(str);
}

static void
sim_log(sys_data_t *sys, int logtype, msg_t *msg, const char *format, ...)
{
    va_list ap;
    char dummy;
    int len;

    va_start(ap, format);
    len = vsnprintf(&dummy, 1, format, ap);
    va_end(ap);
    va_start(ap, format);
    isim_log(sys, logtype, msg, format, ap, len);
    va_end(ap);
}

static void
sim_chan_log(channel_t *chan, int logtype, msg_t *msg, const char *format, ...)
{
    va_list ap;
    char dummy;
    int len;

    va_start(ap, format);
    len = vsnprintf(&dummy, 1, format, ap);
    va_end(ap);
    va_start(ap, format);
    isim_log(global_misc_data->sys, logtype, msg, format, ap, len);
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
	"state-dir",
	's',
	POPT_ARG_STRING,
	&statedir,
	's',
	"state directory",
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
	"version",
	'v',
	POPT_ARG_NONE,
	NULL,
	'v',
	"version",
	""
    },
    {
	"nostdio",
	'n',
	POPT_ARG_NONE,
	NULL,
	'n',
	"nostdio",
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
emu_printf(emu_out_t *out, char *format, ...)
{
    console_info_t *info = out->data;
    va_list ap;
    char buffer[500];
    int start = 0;
    int pos;

    va_start(ap, format);
    vsnprintf(buffer, sizeof(buffer), format, ap);
    va_end(ap);
    for (pos = 0; buffer[pos]; pos++) {
	if (buffer[pos] == '\n') {
	    (void) write(info->outfd, buffer + start, pos - start + 1);
	    (void) write(info->outfd, "\r", 1);
	    start = pos + 1;
	}
    }
    if (pos != start)
	(void) write(info->outfd, buffer + start, pos - start);
}

static void
dummy_printf(emu_out_t *out, char *format, ...)
{
}

#define TN_IAC  255
#define TN_WILL	251
#define TN_WONT	252
#define TN_DO	253
#define TN_DONT	254
#define TN_OPT_SUPPRESS_GO_AHEAD	3
#define TN_OPT_ECHO			1

static unsigned char
handle_telnet(console_info_t *info, unsigned char c)
{
    info->tn_buf[info->tn_pos++] = c;
    if ((info->tn_pos == 2) && (info->tn_buf[1] == TN_IAC))
	/* Double IAC, just send it on. */
	return TN_IAC;
    if ((info->tn_pos == 2) && (info->tn_buf[1] < 250))
	/* Ignore 1-byte commands */
	goto cmd_done;
    if ((info->tn_pos == 3) && (info->tn_buf[1] != 250)) {
	/* Two byte commands */
	switch (info->tn_buf[1]) {
	case TN_WILL:
	    goto send_dont;
	case TN_WONT:
	    break;
	case TN_DO:
	    if ((info->tn_buf[2] == TN_OPT_ECHO)
		|| (info->tn_buf[2] == TN_OPT_SUPPRESS_GO_AHEAD))
		break;
	    goto send_wont;
	}
	goto cmd_done;
    }

    if (info->tn_pos < 4)
	return 0;

    /*
     * We are in a suboption, which we ignore.  Just look for
     * IAC 240 for the end.  Use tn_buf[2] to track the last
     * character we got.
     */
    if ((info->tn_buf[2] == TN_IAC) && (info->tn_buf[3] == 240))
	goto cmd_done;
    info->tn_buf[2] = info->tn_buf[3];
    info->tn_pos--;

 send_wont:
    info->tn_buf[1] = TN_WONT;
    (void) write(info->outfd, info->tn_buf, 3);
    goto cmd_done;

 send_dont:
    info->tn_buf[1] = TN_DONT;
    (void) write(info->outfd, info->tn_buf, 3);
    goto cmd_done;

 cmd_done:
    info->tn_pos = 0;
    return 0;
}

static int
handle_user_char(console_info_t *info, unsigned char c)
{
    if (info->tn_pos)
	c = handle_telnet(info, c);

    if (!c)
	return 0;

    switch(c) {
    case TN_IAC:
	if (info->telnet) {
	    info->tn_buf[0] = c;
	    info->tn_pos = 1;
	} else
	    goto handle_char;
	break;

    case 8:
    case 0x7f:
	if (info->pos > 0) {
	    info->pos--;
	    if (info->echo)
		(void) write(info->outfd, "\b \b", 3);
	}
	break;

    case 4:
	if (info->pos == 0) {
	    if (info->echo)
		(void) write(info->outfd, "\n", 1);
	    return 1;
	}
	break;

    case 10:
    case 13:
	if (info->echo) {
	    (void) write(info->outfd, "\n", 1);
	    if (info->telnet)
		(void) write(info->outfd, "\r", 1);
	}
	info->buffer[info->pos] = '\0';
	if (strcmp(info->buffer, "noecho") == 0) {
	    info->echo = 0;
	} else {
	    ipmi_emu_cmd(&info->out, info->data->emu, info->buffer);
	}
	(void) write(info->outfd, "> ", 2);
	info->pos = 0;
	break;

    handle_char:
    default:
	if (info->pos >= sizeof(info->buffer)-1) {
	    char *msg = "\nCommand is too long, max of %d characters\n";
	    (void) write(info->outfd, msg, strlen(msg));
	} else {
	    info->buffer[info->pos] = c;
	    info->pos++;
	    if (info->echo)
		(void) write(info->outfd, &c, 1);
	}
    }

    return 0;
}

static void
user_data_ready(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
    console_info_t *info = cb_data;
    unsigned char  rc[50];
    unsigned char  *c = rc;
    int         count;

    count = read(fd, rc, sizeof(rc));
    if (count == 0)
	goto closeit;
    while (count > 0) {
	if (handle_user_char(info, *c))
	    goto closeit;
	c++;
	count--;
    }
    return;

 closeit:
    if (info->shutdown_on_close) {
	ipmi_emu_shutdown(info->data->emu);
	return;
    }

    info->data->os_hnd->remove_fd_to_wait_for(info->data->os_hnd, info->conid);
    close(fd);
    if (info->prev)
	info->prev->next = info->next;
    else
	info->data->consoles = info->next;
    if (info->next)
	info->next->prev = info->prev;
    free(info);
}

static void
console_bind_ready(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
    misc_data_t *misc = cb_data;
    console_info_t *newcon;
    int rv;
    int err;
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    int val = 1;
    static unsigned char telnet_init_seq[] = {
	TN_IAC, TN_WILL, TN_OPT_SUPPRESS_GO_AHEAD,
	TN_IAC, TN_WILL, TN_OPT_ECHO,
	TN_IAC, TN_DONT, TN_OPT_ECHO,
    };

    rv = accept(fd, (struct sockaddr *) &addr, &addr_len);
    if (rv < 0) {
	perror("Error from accept");
	exit(1);
    }

    newcon = malloc(sizeof(*newcon));
    if (!newcon) {
	char *msg = "Out of memory\n";
	err = write(rv, msg, strlen(msg));
	close(rv);
	return;
    }

    newcon->data = misc;
    newcon->outfd = rv;
    newcon->pos = 0;
    newcon->echo = 1;
    newcon->shutdown_on_close = 0;
    newcon->telnet = 1;
    newcon->tn_pos = 0;
    newcon->out.printf = emu_printf;
    newcon->out.data = newcon;

    setsockopt(rv, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
    setsockopt(rv, SOL_SOCKET, SO_KEEPALIVE, (char *)&val, sizeof(val));

    err = misc->os_hnd->add_fd_to_wait_for(misc->os_hnd, rv,
					   user_data_ready, newcon,
					   NULL, &newcon->conid);
    if (err) {
	char *msg = "Unable to add socket wait\n";
	err = write(rv, msg, strlen(msg));
	close(rv);
	free(newcon);
    }

    newcon->next = misc->consoles;
    if (newcon->next)
	newcon->next->prev = newcon;
    newcon->prev = NULL;
    misc->consoles = newcon;

    err = write(rv, telnet_init_seq, sizeof(telnet_init_seq));
    err = write(rv, "> ", 2);
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
ipmi_emu_shutdown(emu_data_t *emu)
{
    misc_data_t *data = ipmi_emu_get_user_data(emu);
    console_info_t *con;
    
    if (data->sys->console_fd != -1)
	close(data->sys->console_fd);
    con = data->consoles;
    while (con) {
	data->os_hnd->remove_fd_to_wait_for(data->os_hnd, con->conid);
	close(con->outfd);
	con = con->next;
    }
	
    if (!nostdio)
	tcsetattr(0, TCSADRAIN, &old_termios);
    fcntl(0, F_SETFL, old_flags);
    tcdrain(0);

    shutdown_handler(0);
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

struct ipmi_io_s
{
    os_hnd_fd_id_t *id;
    misc_data_t *data;
    void (*read_cb)(int fd, void *cb_data);
    void (*write_cb)(int fd, void *cb_data);
    void (*except_cb)(int fd, void *cb_data);
    void *cb_data;
};

static void
io_read_ready(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
    ipmi_io_t *io = cb_data;
    io->read_cb(fd, io->cb_data);
}

static void
io_write_ready(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
    ipmi_io_t *io = cb_data;
    io->write_cb(fd, io->cb_data);
}

static void
io_except_ready(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
    ipmi_io_t *io = cb_data;
    io->except_cb(fd, io->cb_data);
}

static void
ipmi_io_set_hnds(ipmi_io_t *io,
		 void (*write_hnd)(int fd, void *cb_data),
		 void (*except_hnd)(int fd, void *cb_data))
{
    io->write_cb = write_hnd;
    io->except_cb = except_hnd;
}

static void
ipmi_io_set_enables(ipmi_io_t *io, int read, int write, int except)
{
    io->data->os_hnd->set_fd_enables(io->data->os_hnd,
				     io->id, read, write, except);
}

static int
ipmi_add_io_hnd(sys_data_t *sys, int fd,
		void (*read_hnd)(int fd, void *cb_data),
		void *cb_data, ipmi_io_t **rio)
{
    ipmi_io_t *io;
    misc_data_t *data = sys->info;
    int err;

    io = malloc(sizeof(*io));
    if (!io)
	return ENOMEM;

    io->data = data;
    io->read_cb = read_hnd;
    io->cb_data = cb_data;
    
    err = data->os_hnd->add_fd_to_wait_for(data->os_hnd, fd, io_read_ready, io,
					   NULL,  &io->id);
    if (err) {
	free(io);
	return err;
    }
    data->os_hnd->set_fd_handlers(data->os_hnd, io->id, io_write_ready,
				  io_except_ready);

    *rio = io;
    return 0;
}

static void
ipmi_remove_io_hnd(ipmi_io_t *io)
{
    io->data->os_hnd->remove_fd_to_wait_for(io->data->os_hnd, io->id);
}

struct ipmi_timer_s
{
    os_hnd_timer_id_t *id;
    misc_data_t *data;
    void (*cb)(void *cb_data);
    void *cb_data;
};

static int
ipmi_alloc_timer(sys_data_t *sys, void (*cb)(void *cb_data),
		 void *cb_data, ipmi_timer_t **rtimer)
{
    misc_data_t *data = sys->info;
    ipmi_timer_t *timer;
    int err;

    timer = malloc(sizeof(ipmi_timer_t));
    if (!timer)
	return ENOMEM;

    timer->cb = cb;
    timer->cb_data = cb_data;
    timer->data = data;
    err = data->os_hnd->alloc_timer(data->os_hnd, &timer->id);
    if (err) {
	free(timer);
	return err;
    }

    *rtimer = timer;
    return 0;
}

static void
timer_cb(void *cb_data, os_hnd_timer_id_t *id)
{
    ipmi_timer_t *timer = cb_data;

    timer->cb(timer->cb_data);
}

static int
ipmi_start_timer(ipmi_timer_t *timer, struct timeval *timeout)
{
    return timer->data->os_hnd->start_timer(timer->data->os_hnd, timer->id,
					    timeout, timer_cb, timer);
}

static int
ipmi_stop_timer(ipmi_timer_t *timer)
{
    return timer->data->os_hnd->stop_timer(timer->data->os_hnd, timer->id);
}

static void
ipmi_free_timer(ipmi_timer_t *timer)
{
    timer->data->os_hnd->free_timer(timer->data->os_hnd, timer->id);
}

static ipmi_tick_handler_t *tick_handlers;

void
ipmi_register_tick_handler(ipmi_tick_handler_t *handler)
{
    handler->next = tick_handlers;
    tick_handlers = handler;
}

static void
tick(void *cb_data, os_hnd_timer_id_t *id)
{
    misc_data_t *data = cb_data;
    struct timeval tv;
    int err;
    ipmi_tick_handler_t *h;

    h = tick_handlers;
    while(h) {
	h->handler(h->info, 1);
	h = h->next;
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

static int sigpipeh[2] = {-1, -1};

static void
handle_sigchld(int sig)
{
    unsigned char c = 1;

    (void) write(sigpipeh[1], &c, 1);
}

static ipmi_child_quit_t *child_quit_handlers;

void
ipmi_register_child_quit_handler(ipmi_child_quit_t *handler)
{
    handler->next = child_quit_handlers;
    child_quit_handlers = handler;
}

static void
sigchld_ready(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
    char buf;
    int rv;
    int status;
    ipmi_child_quit_t *h;

    rv = read(sigpipeh[0], &buf, 1);
    rv = waitpid(-1, &status, WNOHANG);
    if (rv == -1)
	return;

    h = child_quit_handlers;
    while (h) {
	h->handler(h->info, rv);
	h = h->next;
    }
}

static ipmi_shutdown_t *shutdown_handlers;

void
ipmi_register_shutdown_handler(ipmi_shutdown_t *handler)
{
    handler->next = shutdown_handlers;
    shutdown_handlers = handler;
}

static int shutdown_sigs[] = {
    SIGINT, SIGQUIT, SIGILL, SIGABRT, SIGFPE, SIGSEGV, SIGTERM, SIGBUS,
    0
};

static void
shutdown_handler(int sig)
{
    ipmi_shutdown_t *h = shutdown_handlers;

    while (h) {
	h->handler(h->info, sig);
	h = h->next;
    }
    if (sig)
	raise(sig);
}

void
ipmi_do_start_cmd(startcmd_t *startcmd)
{
    pid_t pid;
    char *cmd;

    cmd = malloc(strlen(startcmd->startcmd) + 6);
    if (!cmd)
	return;
    strcpy(cmd, "exec ");
    strcpy(cmd + 5, startcmd->startcmd);

    pid = fork();
    if (pid == -1) {
	free(cmd);
	return;
    }

    if (pid == 0) {
	char *args[4] = { "/bin/sh", "-c", cmd, NULL };

	isim_close_fds();
	execvp(args[0], args);
	exit(1);
    }
    startcmd->vmpid = pid;
    free(cmd);
}

void
ipmi_do_kill(startcmd_t *startcmd, int noblock)
{
    if (noblock)
	kill(startcmd->vmpid, SIGKILL);
    else
	kill(startcmd->vmpid, SIGTERM);
}

static int ipmi_get_monotonic_time(sys_data_t *sys, struct timeval *tv)
{
    misc_data_t *data = sys->info;
    os_handler_t *os_hnd = data->os_hnd;
    return os_hnd->get_monotonic_time(os_hnd, tv);
}

static int ipmi_get_real_time(sys_data_t *sys, struct timeval *tv)
{
    misc_data_t *data = sys->info;
    os_handler_t *os_hnd = data->os_hnd;
    return os_hnd->get_real_time(os_hnd, tv);
}

int
main(int argc, const char *argv[])
{
    sys_data_t  sysinfo;
    misc_data_t data;
    int err, rv = 1;
    int i;
    poptContext poptCtx;
    struct timeval tv;
    console_info_t stdio_console;
    struct sigaction act;
    os_hnd_fd_id_t *conid;
    lmc_data_t *mc;
    int print_version = 0;

    poptCtx = poptGetContext(argv[0], argc, argv, poptOpts, 0);
    while ((i = poptGetNextOpt(poptCtx)) >= 0) {
	switch (i) {
	    case 'd':
		debug++;
		break;
	    case 'n':
		nostdio = 1;
		break;
	    case 'v':
		print_version = 1;
		break;
	}
    }
    poptFreeContext(poptCtx);

    printf("IPMI Simulator version %s\n", PVERSION);

    global_misc_data = &data;

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

    sysinfo_init(&sysinfo);
    sysinfo.info = &data;
    sysinfo.alloc = balloc;
    sysinfo.free = bfree;
    sysinfo.get_monotonic_time = ipmi_get_monotonic_time;
    sysinfo.get_real_time = ipmi_get_real_time;
    sysinfo.alloc_timer = ipmi_alloc_timer;
    sysinfo.start_timer = ipmi_start_timer;
    sysinfo.stop_timer = ipmi_stop_timer;
    sysinfo.free_timer = ipmi_free_timer;
    sysinfo.add_io_hnd = ipmi_add_io_hnd;
    sysinfo.io_set_hnds = ipmi_io_set_hnds;
    sysinfo.io_set_enables = ipmi_io_set_enables;
    sysinfo.remove_io_hnd = ipmi_remove_io_hnd;
    sysinfo.gen_rand = sys_gen_rand;
    sysinfo.debug = debug;
    sysinfo.log = sim_log;
    sysinfo.csmi_send = smi_send;
    sysinfo.clog = sim_chan_log;
    sysinfo.calloc = ialloc;
    sysinfo.cfree = ifree;
    sysinfo.lan_channel_init = lan_channel_init;
    sysinfo.ser_channel_init = ser_channel_init;
    data.sys = &sysinfo;

    err = pipe(sigpipeh);
    if (err) {
	perror("Creating signal handling pipe");
	exit(1);
    }

    act.sa_handler = handle_sigchld;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    
    err = sigaction(SIGCHLD, &act, NULL);
    if (err) {
	perror("setting up sigchld sigaction");
	exit(1);
    }

    err = data.os_hnd->add_fd_to_wait_for(data.os_hnd, sigpipeh[0],
					  sigchld_ready, &data,
					  NULL, &conid);
    if (err) {
	fprintf(stderr, "Unable to sigchld pipe wait: 0x%x\n", err);
	exit(1);
    }

    data.emu = ipmi_emu_alloc(&data, sleeper, &sysinfo);

    /* Set this up for console I/O, even if we don't use it. */
    stdio_console.data = &data;
    stdio_console.outfd = 1;
    stdio_console.pos = 0;
    stdio_console.echo = 1;
    stdio_console.shutdown_on_close = 1;
    stdio_console.telnet = 0;
    stdio_console.tn_pos = 0;
    if (nostdio) {
	stdio_console.out.printf = dummy_printf;
	stdio_console.out.data = &stdio_console;
    } else {
	stdio_console.out.printf = emu_printf;
	stdio_console.out.data = &stdio_console;
    }
    stdio_console.next = NULL;
    stdio_console.prev = NULL;
    data.consoles = &stdio_console;

    err = ipmi_mc_alloc_unconfigured(&sysinfo, 0x20, &mc);
    if (err) {
	if (err == ENOMEM)
	    fprintf(stderr, "Out of memory allocation BMC MC\n");
	exit(1);
    }
    sysinfo.mc = mc;
    sysinfo.chan_set = ipmi_mc_get_channelset(mc);
    sysinfo.startcmd = ipmi_mc_get_startcmdinfo(mc);
    sysinfo.cpef = ipmi_mc_get_pef(mc);
    sysinfo.cusers = ipmi_mc_get_users(mc);
    sysinfo.sol = ipmi_mc_get_sol(mc);

    if (read_config(&sysinfo, config_file, print_version))
	exit(1);

    if (print_version)
	exit(0);

    if (!sysinfo.name) {
	fprintf(stderr, "name not set in config file\n");
	exit(1);
    }

    err = persist_init("ipmi_sim", sysinfo.name, statedir);
    if (err) {
	fprintf(stderr, "Unable to initialize persistence: %s\n",
		strerror(err));
	exit(1);
    }

    read_persist_users(&sysinfo);

    err = sol_init(&sysinfo);
    if (err) {
	fprintf(stderr, "Unable to initialize SOL: %s\n",
		strerror(err));
	goto out;
    }

    err = read_sol_config(&sysinfo);
    if (err) {
	fprintf(stderr, "Unable to read SOL configs: %s\n",
		strerror(err));
	goto out;
    }

    err = load_dynamic_libs(&sysinfo, 0);
    if (err)
	goto out;

    if (!command_file) {
	FILE *tf;
	command_file = malloc(strlen(BASE_CONF_STR) + 6 + strlen(sysinfo.name));
	if (!command_file) {
	    fprintf(stderr, "Out of memory\n");
	    goto out;
	}
	strcpy(command_file, BASE_CONF_STR);
	strcat(command_file, "/");
	strcat(command_file, sysinfo.name);
	strcat(command_file, ".emu");
	tf = fopen(command_file, "r");
	if (!tf) {
	    free(command_file);
	    command_file = NULL;
	} else {
	    fclose(tf);
	}
    }

    if (command_file)
	read_command_file(&stdio_console.out, data.emu, command_file);

    if (command_string)
	ipmi_emu_cmd(&stdio_console.out, data.emu, command_string);

    if (!sysinfo.bmc_ipmb || !sysinfo.ipmb_addrs[sysinfo.bmc_ipmb]) {
	sysinfo.log(&sysinfo, SETUP_ERROR, NULL,
		    "No bmc_ipmb specified or configured.");
	goto out;
    }

    sysinfo.console_fd = -1;
    if (sysinfo.console_addr_len) {
	int nfd;
	int val;

	nfd = socket(sysinfo.console_addr.s_ipsock.s_addr.sa_family,
		     SOCK_STREAM, IPPROTO_TCP);
	if (nfd == -1) {
	    perror("Console socket open");
	    goto out;
	}
	err = bind(nfd, (struct sockaddr *) &sysinfo.console_addr,
		   sysinfo.console_addr_len);
	if (err) {
	    perror("bind to console socket");
	    goto out;
	}
	err = listen(nfd, 1);
	if (err == -1) {
	    perror("listen to console socket");
	    goto out;
	}
	val = 1;
	err = setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR,
			 (char *)&val, sizeof(val));
	if (err) {
	    perror("console setsockopt reuseaddr");
	    goto out;
	}
	sysinfo.console_fd = nfd;

	err = data.os_hnd->add_fd_to_wait_for(data.os_hnd, nfd,
					      console_bind_ready, &data,
					      NULL, &conid);
	if (err) {
	    fprintf(stderr, "Unable to add console wait: 0x%x\n", err);
	    goto out;
	} else {
	    isim_add_fd(nfd);
	}
    }

    if (!nostdio) {
	init_term();

	err = write(1, "> ", 2);
	err = data.os_hnd->add_fd_to_wait_for(data.os_hnd, 0,
					      user_data_ready, &stdio_console,
					      NULL, &stdio_console.conid);
	if (err) {
	    fprintf(stderr, "Unable to add input wait: 0x%x\n", err);
	    goto out;
	}
    }

    post_init_dynamic_libs(&sysinfo);

    act.sa_handler = shutdown_handler;
    act.sa_flags = SA_RESETHAND;
    for (i = 0; shutdown_sigs[i]; i++) {
	err = sigaction(shutdown_sigs[i], &act, NULL);
	if (err) {
	    fprintf(stderr, "Unable to register shutdown signal %d: %s\n",
		    shutdown_sigs[i], strerror(errno));
	}
    }

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    err = data.os_hnd->start_timer(data.os_hnd, data.timer, &tv, tick, &data);
    if (err) {
	fprintf(stderr, "Unable to start timer: 0x%x\n", err);
	goto out;
    }

    data.os_hnd->operation_loop(data.os_hnd);
    rv = 0;
  out:
    shutdown_handler(0);
    exit(rv);
}
