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
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

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
#include <malloc.h>
#include <sys/ioctl.h>

#include <OpenIPMI/log.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>

#include "lanserv.h"

typedef struct misc_data
{
    int lan1_fd, lan2_fd;
    char *config_file;
} misc_data_t;

static void *
ialloc(lan_data_t *lan, int size)
{
    return malloc(size);
}

static void
ifree(lan_data_t *lan, void *data)
{
    return free(data);
}

typedef struct lan_addr_s
{
    struct sockaddr addr;
    socklen_t       addr_len;
    int             xmit_fd;
} lan_addr_t;

static void
lan_send(lan_data_t *lan,
	 struct iovec *data, int vecs,
	 void *addr, int addr_len)
{
    struct msghdr msg;
    lan_addr_t    *l = addr;
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
handle_invalid_cmd(lan_data_t    *lan,
		   unsigned char *rdata,
		   unsigned int  *rdata_len)
{
    rdata[0] = IPMI_INVALID_CMD_CC;
    *rdata_len = 1;
}

static void
handle_get_device_id(lan_data_t    *lan,
		     unsigned char *data,
		     unsigned int  data_len,
		     unsigned char *rdata,
		     unsigned int  *rdata_len)
{
    memset(rdata, 0, 12);
    rdata[5] = 0x51;
    *rdata_len = 12;
}

static void
handle_app_netfn(lan_data_t    *lan,
		 unsigned int  cmd,
		 unsigned char *data,
		 unsigned int  data_len,
		 unsigned char *rdata,
		 unsigned int  *rdata_len)
{
    switch(cmd) {
	case IPMI_GET_DEVICE_ID_CMD:
	    handle_get_device_id(lan, data, data_len, rdata, rdata_len);
	    break;

	default:
	    handle_invalid_cmd(lan, rdata, rdata_len);
	    break;
    }
}

static int
smi_send(lan_data_t *lan, msg_t *msg)
{
    unsigned char    data[36];
    unsigned int     data_len;

    if (msg->cmd == IPMI_SEND_MSG_CMD) {
	data[0] = IPMI_TIMEOUT_CC;
	data_len = 1;
    } else {
	switch (msg->netfn) {
	    case IPMI_APP_NETFN:
		handle_app_netfn(lan, msg->cmd, msg->data, msg->len,
				 data, &data_len);
		break;

	    default:
		handle_invalid_cmd(lan, data, &data_len);
		break;
	}
    }

    ipmi_handle_smi_rsp(lan, msg, data, data_len);
    return 0;
}

static int
gen_rand(lan_data_t *lan, void *data, int size)
{
    int fd = open("/dev/urandom", O_RDONLY);
    int rv;

    if (fd == -1)
	return errno;

    rv = read(fd, data, size);

    close(fd);
    return rv;
}

static void
handle_msg_lan(int lan_fd, lan_data_t *lan)
{
    int                len;
    lan_addr_t         l;
    unsigned char      data[256];

    len = recvfrom(lan_fd, data, sizeof(data), 0, &(l.addr), &(l.addr_len));
    if (len < 0) {
	if (errno != EINTR) {
	    perror("Error receiving message");
	    exit(1);
	}
	return;
    }
    l.xmit_fd = lan_fd;

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

static void
write_config(lan_data_t *lan)
{
//    misc_data_t *info = lan->user_info;
}

static int
get_bool(char **tokptr, unsigned int *rval)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);

    if (!tok)
	return -1;
    if (strcmp(tok, "true") == 0)
	*rval = 1;
    else if (strcmp(tok, "false") == 0)
	*rval = 0;
    else
	return -1;

    return 0;
}

static int
get_priv(char **tokptr, unsigned int *rval)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);

    if (!tok)
	return -1;
    if (strcmp(tok, "callback") == 0)
	*rval = IPMI_PRIVILEGE_CALLBACK;
    else if (strcmp(tok, "user") == 0)
	*rval = IPMI_PRIVILEGE_USER;
    else if (strcmp(tok, "operator") == 0)
	*rval = IPMI_PRIVILEGE_OPERATOR;
    else if (strcmp(tok, "admin") == 0)
	*rval = IPMI_PRIVILEGE_ADMIN;
    else
	return -1;

    return 0;
}

static int
get_auths(char **tokptr, unsigned int *rval)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);
    int  val = 0;

    while (tok) {
	if (strcmp(tok, "none") == 0)
	    val |= (1 << IPMI_AUTHTYPE_NONE);
	else if (strcmp(tok, "md2") == 0)
	    val |= (1 << IPMI_AUTHTYPE_MD2);
	else if (strcmp(tok, "md5") == 0)
	    val |= (1 << IPMI_AUTHTYPE_MD5);
	else if (strcmp(tok, "straight") == 0)
	    val |= (1 << IPMI_AUTHTYPE_STRAIGHT);
	else
	    return -1;

	tok = strtok_r(NULL, " \t\n", tokptr);
    }

    *rval = val;

    return 0;
}

static int
get_uint(char **tokptr, unsigned int *rval)
{
    char *end;
    char *tok = strtok_r(NULL, " \t\n", tokptr);

    *rval = strtoul(tok, &end, 0);
    if (*end != '\0')
	return -1;
    return 0;
}

static void
cleanup_ascii_16(uint8_t *c)
{
    int i;

    i = 0;
    while ((i < 16) && (*c != 0)) {
	c++;
	i++;
    }
    while (i < 16) {
	*c = 0;
	c++;
	i++;
    }
}

static int
read_16(char **tokptr, unsigned char *data)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);
    char *end;

    if (!tok)
	return -1;
    if (*tok == '"') {
	int end;
	/* Ascii PW */
	tok++;
	end = strlen(tok) - 1;
	if (tok[end] != '"')
	    return -1;
	tok[end] = '\0';
	strncpy(data, tok, 16);
	cleanup_ascii_16(data);
    } else {
	int  i;
	char c[3];
	/* HEX pw */
	if (strlen(tok) != 32)
	    return -1;
	c[2] = '\0';
	for (i=0; i<16; i++) {
	    c[0] = *tok;
	    tok++;
	    c[1] = *tok;
	    tok++;
	    data[i] = strtoul(c, &end, 16);
	    if (*end != '\0')
		return -1;
	}
    }

    return 0;
}

static int
get_user(char **tokptr, lan_data_t *lan)
{
    unsigned int num;
    unsigned int val;
    int          err;

    err = get_uint(tokptr, &num);
    if (err)
	return err;

    if (num > MAX_USERS)
	return -1;

    err = get_bool(tokptr, &val);
    if (err)
	return err;
    lan->users[num].valid = val;

    err = read_16(tokptr, lan->users[num].username);
    if (err)
	return err;

    err = read_16(tokptr, lan->users[num].pw);
    if (err)
	return err;

    err = get_priv(tokptr, &val);
    if (err)
	return err;
    lan->users[num].privilege = val;

    err = get_uint(tokptr, &val);
    if (err)
	return err;
    lan->users[num].max_sessions = val;

    err = get_auths(tokptr, &val);
    if (err)
	return err;
    lan->users[num].allowed_auths = val;

    return 0;
}

static int
get_sock_addr(char **tokptr, struct sockaddr *addr, socklen_t *len)
{
    struct sockaddr_in *a = (void *) addr;
    struct hostent     *ent;
    char               *s;
    char               *end;

    s = strtok_r(NULL, " \t\n", tokptr);
    if (!s)
	return -1;

    ent = gethostbyname(s);
    if (!ent)
	return -1;

    a->sin_family = AF_INET;
    memcpy(&(a->sin_addr), ent->h_addr_list[0], ent->h_length);

    s = strtok_r(NULL, " \t\n", tokptr);
    if (s) {
	a->sin_port = strtoul(s, &end, 0);
	if (*end != '\0')
	    return -1;
    } else {
	a->sin_port = 623;
    }

    *len = sizeof(*a);
    return 0;
}

struct sockaddr addr1;
socklen_t addr1_len = 0;
struct sockaddr addr2;
socklen_t addr2_len = 0;

#define MAX_CONFIG_LINE 256
static int
read_config(lan_data_t *lan)
{
    misc_data_t  *info = lan->user_info;
    FILE         *f = fopen(info->config_file, "r");
    char         buf[MAX_CONFIG_LINE];
    char         *tok;
    char         *tokptr;
    unsigned int val;
    int          err = 0;
    int          line;

    if (!f)
	return -1;

    line = 0;
    while (fgets(buf, sizeof(buf), f) != NULL) {
	line++;

	if (buf[0] == '#')
	    continue;
	tok = strtok_r(buf, " \t\n", &tokptr);
	if (!tok)
	    continue;

	if (strcmp(tok, "PEF_alerting") == 0) {
	    err = get_bool(&tokptr, &val);
	    lan->channel.PEF_alerting = val;
	} else if (strcmp(tok, "per_msg_auth") == 0) {
	    err = get_bool(&tokptr, &val);
	    lan->channel.per_msg_auth = val;
	} else if (strcmp(tok, "priv_limit") == 0) {
	    err = get_priv(&tokptr, &val);
	    lan->channel.privilege_limit = val;
	} else if (strcmp(tok, "allowed_auths_callback") == 0) {
	    err = get_auths(&tokptr, &val);
	    lan->channel.priv_info[0].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_user") == 0) {
	    err = get_auths(&tokptr, &val);
	    lan->channel.priv_info[1].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_operator") == 0) {
	    err = get_auths(&tokptr, &val);
	    lan->channel.priv_info[2].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_admin") == 0) {
	    err = get_auths(&tokptr, &val);
	    lan->channel.priv_info[3].allowed_auths = val;
	} else if (strcmp(tok, "addr1") == 0) {
	    err = get_sock_addr(&tokptr, &addr1, &addr1_len);
	} else if (strcmp(tok, "addr2") == 0) {
	    err = get_sock_addr(&tokptr, &addr2, &addr2_len);
	} else if (strcmp(tok, "user") == 0) {
	    err = get_user(&tokptr, lan);
	} else if (strcmp(tok, "guid") == 0) {
	    if (!lan->guid)
		lan->guid = malloc(16);
	    if (!lan->guid)
		return -1;
	    err = read_16(&tokptr, lan->guid);
	    if (err)
		return err;
	} else {
	    /* error */
	}

	if (err)
	    return err;
    }

    return 0;
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

static void
log(int logtype, msg_t *msg, char *format, ...)
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

static char *config_file = "/etc/ipmi_lan.conf";
static int debug = 0;

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
	"debug",
	'd',
	POPT_ARG_NONE,
	NULL,
	'd',
	"debug",
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

int
main(int argc, const char *argv[])
{
    lan_data_t  lan;
    misc_data_t data;
    int max_fd;
    int rv;
    int o;
    poptContext poptCtx;
    struct timeval timeout;
    struct timeval time_next;
    struct timeval time_now;

    poptCtx = poptGetContext(argv[0], argc, argv, poptOpts, 0);
    while ((o = poptGetNextOpt(poptCtx)) >= 0) {
	switch (o) {
	    case 'd':
		debug++;
		break;
	}
    }

    data.config_file = config_file;

    memset(&lan, 0, sizeof(lan));
    lan.user_info = &data;
    lan.alloc = ialloc;
    lan.free = ifree;
    lan.lan_send = lan_send;
    lan.smi_send = smi_send;
    lan.gen_rand = gen_rand;
    lan.write_config = write_config;
    lan.log = log;
    lan.debug = debug;

    read_config(&lan);

    if (addr1_len == 0) {
	struct sockaddr_in *addr = (void *) &addr1;
	addr->sin_family = AF_INET;
	addr->sin_port = htons(623);
	addr->sin_addr.s_addr = INADDR_ANY;
	addr1_len = sizeof(*addr);
    }
    data.lan1_fd = open_lan_fd(&addr1, addr1_len);
    if (addr2_len != 0) {
	data.lan2_fd = open_lan_fd(&addr2, addr2_len);
    } else {
	data.lan2_fd = -1;
    }

    rv = ipmi_lan_init(&lan);
    if (rv)
	return 1;

    log(0, NULL, "%s startup", argv[0]);

    if (data.lan1_fd > data.lan2_fd)
	max_fd = data.lan1_fd + 1;
    else
	max_fd = data.lan2_fd + 1;

    gettimeofday(&time_next, NULL);
    time_next.tv_sec += 10;
    for (;;) {
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(data.lan1_fd, &readfds);
	if (data.lan2_fd != -1)
	    FD_SET(data.lan2_fd, &readfds);

	gettimeofday(&time_now, NULL);
	diff_timeval(&timeout, &time_next, &time_now);
	rv = select(max_fd, &readfds, NULL, NULL, &timeout);
	if ((rv == -1) && (errno == EINTR))
	    continue;

	if (rv == 0) {
	    ipmi_lan_tick(&lan, 10);
	    time_next.tv_sec += 10;
	} else {
	    if (FD_ISSET(data.lan1_fd, &readfds)) {
		handle_msg_lan(data.lan1_fd, &lan);
	    }

	    if ((data.lan2_fd != -1) && FD_ISSET(data.lan2_fd, &readfds)) {
		handle_msg_lan(data.lan2_fd, &lan);
	    }
	}
    }
}
