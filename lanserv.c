/*
 * lanserv.c
 *
 * MontaVista IPMI code for creating a LAN interface to an SMI interface.
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
#include <syslog.h>

#include <OpenIPMI/log.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/lanserv.h>

#include <linux/ipmi.h>


static int debug = 0;

#define MAX_ADDR 4

static void log(int logtype, msg_t *msg, char *format, ...);

typedef struct misc_data
{
    int lan_fd[MAX_ADDR];
    int smi_fd;
    char *config_file;
} misc_data_t;

static int
dump_hex(void *vdata, int len, int left)
{
    unsigned char *data = vdata;

    int i;
    for (i=0; i<len; i++) {
	if (left == 0) {
	    log(DEBUG,  NULL, "\n  ");
	    left = 15;
	} else {
	    left--;
	}
	log(DEBUG, NULL, " %2.2x", data[i]);
    }

    return left;
}

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

    if (debug) {
	int left, i;
	log(DEBUG, NULL, "Sending message to:\n  ");
	dump_hex(&l->addr, l->addr_len, 16);
	log(DEBUG, NULL, "\nMsg:\n  ");
	left = 16;
	for (i=0; i<vecs; i++) {
	    left = dump_hex(data[i].iov_base, data[i].iov_len, left);
	}
	log(DEBUG, NULL, "\n");
    }

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
ipmb_addr_change(lan_data_t    *lan,
		 unsigned char addr)
{
    unsigned int slave_addr = addr;
    int          rv;
    misc_data_t  *info = lan->user_info;

    rv = ioctl(info->smi_fd, IPMICTL_SET_MY_ADDRESS_CMD, &slave_addr);
    if (rv) {
	lan->log(OS_ERROR, NULL,
		 "Error setting IPMB address: 0x%x", errno);
    }    
}

static int
smi_send(lan_data_t *lan, msg_t *msg)
{
    struct ipmi_req  req;
    struct ipmi_addr addr;
    misc_data_t      *info = lan->user_info;
    int              rv;

    req.addr = (unsigned char *) &addr;
    
    if (msg->cmd == IPMI_SEND_MSG_CMD) {
	struct ipmi_ipmb_addr *ipmb = (void *) &addr;
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
	struct ipmi_system_interface_addr *si = (void *) &addr;

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
    if (rv == -1)
	return errno;
    else
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

static uint8_t
ipmb_checksum(uint8_t *data, int size, uint8_t start)
{
	uint8_t csum = start;
	
	for (; size > 0; size--, data++)
		csum += *data;

	return -csum;
}

static void
handle_msg_ipmi(int smi_fd, lan_data_t *lan)
{
    struct ipmi_recv rsp;
    struct ipmi_addr addr;
    unsigned char    data[IPMI_MAX_MSG_LENGTH+7];
    unsigned char    rdata[IPMI_MAX_MSG_LENGTH];
    int              rv;
    msg_t            *msg;

    rsp.addr = (char *) &addr;
    rsp.addr_len = sizeof(addr);
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
	    log(DEBUG, NULL, "Error receiving message: %s\n", strerror(errno));
	    return;
	}
    }

    if (rdata[0] == IPMI_TIMEOUT_CC)
	/* Ignore timeouts, we let the LAN code do the timeouts. */
	return;

    /* We only handle responses. */
    if (rsp.recv_type != IPMI_RESPONSE_RECV_TYPE)
	return;

    msg = (msg_t *) rsp.msgid;

    if (addr.addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	/* Nothing to do. */
    } else if (addr.addr_type == IPMI_IPMB_ADDR_TYPE) {
	struct ipmi_ipmb_addr *ipmb = (void *) &addr; 

	data[0] = 0; /* return code. */
	data[1] = (rsp.msg.netfn << 2) | 2;
	data[2] = ipmb_checksum(data+1, 1, 0);
	data[3] = ipmb->slave_addr;
	data[4] = (msg->data[4] & 0xfc) | ipmb->lun;
	data[5] = rsp.msg.cmd;
	memcpy(data+6, rsp.msg.data, rsp.msg.data_len);
	rsp.msg.data = data;
	rsp.msg.data_len += 7;
	data[rsp.msg.data_len-1] = ipmb_checksum(data+1, rsp.msg.data_len-2, 0);
    } else {
	log(DEBUG, NULL, "Error!\n");
	return;
    }

    ipmi_handle_smi_rsp(lan, msg, rsp.msg.data, rsp.msg.data_len);
}

static void
handle_msg_lan(int lan_fd, lan_data_t *lan)
{
    int                len;
    lan_addr_t         l;
    unsigned char      data[256];

    l.addr_len = sizeof(l.addr);
    len = recvfrom(lan_fd, data, sizeof(data), 0, &(l.addr), &(l.addr_len));
    if (len < 0) {
	if (errno != EINTR) {
	    perror("Error receiving message");
	    exit(1);
	}
	return;
    }
    l.xmit_fd = lan_fd;

    if (debug) {
	log(DEBUG, NULL, "Got message from:\n  ");
	dump_hex(&l.addr, l.addr_len, 16);
	log(DEBUG, NULL, "\nMsg:\n  ");
	dump_hex(data, len, 16);
	log(DEBUG, NULL, "\n");
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

static void
write_config(lan_data_t *lan)
{
//    misc_data_t *info = lan->user_info;
}

static int
get_bool(char **tokptr, unsigned int *rval, char **err)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);

    if (!tok)
	return -1;
    if (strcasecmp(tok, "true") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "false") == 0)
	*rval = 0;
    else if (strcasecmp(tok, "on") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "off") == 0)
	*rval = 0;
    else {
	*err = "Invalid boolean value, must be 'true', 'on', 'false', or 'off'";
	return -1;
    }

    return 0;
}

static int
get_priv(char **tokptr, unsigned int *rval, char **err)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No privilege specified, must be 'callback', 'user',"
	    " 'operator', or 'admin'";
	return -1;
    }
    if (strcmp(tok, "callback") == 0)
	*rval = IPMI_PRIVILEGE_CALLBACK;
    else if (strcmp(tok, "user") == 0)
	*rval = IPMI_PRIVILEGE_USER;
    else if (strcmp(tok, "operator") == 0)
	*rval = IPMI_PRIVILEGE_OPERATOR;
    else if (strcmp(tok, "admin") == 0)
	*rval = IPMI_PRIVILEGE_ADMIN;
    else {
	*err = "Invalid privilege specified, must be 'callback', 'user',"
	    " 'operator', or 'admin'";
	return -1;
    }

    return 0;
}

static int
get_auths(char **tokptr, unsigned int *rval, char **err)
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
	else {
	    *err = "Invalid authorization type, must be 'none', 'md2',"
		" 'md5', or 'straight'";
	    return -1;
	}

	tok = strtok_r(NULL, " \t\n", tokptr);
    }

    *rval = val;

    return 0;
}

static int
get_uint(char **tokptr, unsigned int *rval, char **err)
{
    char *end;
    char *tok = strtok_r(NULL, " \t\n", tokptr);

    *rval = strtoul(tok, &end, 0);
    if (*end != '\0') {
	*err = "Invalid integer value";
	return -1;
    }
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
read_16(char **tokptr, unsigned char *data, char **err)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);
    char *end;

    if (!tok) {
	*err = "Missing password or username";
	return -1;
    }
    if (*tok == '"') {
	int end;
	/* Ascii PW */
	tok++;
	end = strlen(tok) - 1;
	if (tok[end] != '"') {
	    *err = "ASCII password or username doesn't end in '\"'";
	    return -1;
	}
	tok[end] = '\0';
	strncpy(data, tok, 16);
	cleanup_ascii_16(data);
    } else {
	int  i;
	char c[3];
	/* HEX pw */
	if (strlen(tok) != 32) {
	    *err = "HEX password or username not 32 HEX characters long";
	    return -1;
	}
	c[2] = '\0';
	for (i=0; i<16; i++) {
	    c[0] = *tok;
	    tok++;
	    c[1] = *tok;
	    tok++;
	    data[i] = strtoul(c, &end, 16);
	    if (*end != '\0') {
		*err = "Invalid HEX character in password or username";
		return -1;
	    }
	}
    }

    return 0;
}

static int
get_user(char **tokptr, lan_data_t *lan, char **err)
{
    unsigned int num;
    unsigned int val;
    int          rv;

    rv = get_uint(tokptr, &num, err);
    if (rv)
	return rv;

    if (num > MAX_USERS) {
	*err = "User number larger than the allowed number of users";
	return -1;
    }

    rv = get_bool(tokptr, &val, err);
    if (rv)
	return rv;
    lan->users[num].valid = val;

    rv = read_16(tokptr, lan->users[num].username, err);
    if (rv)
	return rv;

    rv = read_16(tokptr, lan->users[num].pw, err);
    if (rv)
	return rv;

    rv = get_priv(tokptr, &val, err);
    if (rv)
	return rv;
    lan->users[num].privilege = val;

    rv = get_uint(tokptr, &val, err);
    if (rv)
	return rv;
    lan->users[num].max_sessions = val;

    rv = get_auths(tokptr, &val, err);
    if (rv)
	return rv;
    lan->users[num].allowed_auths = val;

    return 0;
}

static int
get_sock_addr(char **tokptr, struct sockaddr *addr, socklen_t *len, char **err)
{
    struct sockaddr_in *a = (void *) addr;
    struct hostent     *ent;
    char               *s;
    char               *end;

    s = strtok_r(NULL, " \t\n", tokptr);
    if (!s) {
	*err = "No IP address specified";
	return -1;
    }

    ent = gethostbyname(s);
    if (!ent) {
	*err = "Invalid IP address specified";
	return -1;
    }

    a->sin_family = AF_INET;
    memcpy(&(a->sin_addr), ent->h_addr_list[0], ent->h_length);

    s = strtok_r(NULL, " \t\n", tokptr);
    if (s) {
	a->sin_port = htons(strtoul(s, &end, 0));
	if (*end != '\0') {
	    *err = "Invalid IP port specified";
	    return -1;
	}
    } else {
	a->sin_port = htons(623);
    }

    *len = sizeof(*a);
    return 0;
}

struct sockaddr addr[MAX_ADDR];
socklen_t addr_len[MAX_ADDR];
int num_addr = 0;

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
    char         *errstr;

    if (!f) {
	fprintf(stderr, "Unable to open configuration file '%s'\n",
		info->config_file);
	return -1;
    }

    line = 0;
    while (fgets(buf, sizeof(buf), f) != NULL) {
	line++;

	if (buf[0] == '#')
	    continue;
	tok = strtok_r(buf, " \t\n", &tokptr);
	if (!tok)
	    continue;

	if (strcmp(tok, "PEF_alerting") == 0) {
	    err = get_bool(&tokptr, &val, &errstr);
	    lan->channel.PEF_alerting = val;
	} else if (strcmp(tok, "per_msg_auth") == 0) {
	    err = get_bool(&tokptr, &val, &errstr);
	    lan->channel.per_msg_auth = val;
	} else if (strcmp(tok, "priv_limit") == 0) {
	    err = get_priv(&tokptr, &val, &errstr);
	    lan->channel.privilege_limit = val;
	} else if (strcmp(tok, "allowed_auths_callback") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[0].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_user") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[1].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_operator") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[2].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_admin") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[3].allowed_auths = val;
	} else if (strcmp(tok, "addr") == 0) {
	    if (num_addr >= MAX_ADDR) {
		fprintf(stderr, "Too many addresses specified\n");
		err = EINVAL;
	    }
	    err = get_sock_addr(&tokptr, &addr[num_addr], &addr_len[num_addr],
				&errstr);
	    num_addr++;
	} else if (strcmp(tok, "user") == 0) {
	    err = get_user(&tokptr, lan, &errstr);
	} else if (strcmp(tok, "guid") == 0) {
	    if (!lan->guid)
		lan->guid = malloc(16);
	    if (!lan->guid)
		return -1;
	    err = read_16(&tokptr, lan->guid, &errstr);
	    if (err)
		return err;
	} else {
	    errstr = "Invalid configuration option";
	    err = -1;
	}

	if (err) {
	    fprintf(stderr, "Error on line %d: %s\n", line, errstr);
	    return err;
	}
    }

    return 0;
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
	return fd;
    }

    rv = bind(fd, addr, addr_len);
    if (rv == -1)
    {
	fprintf(stderr, "Unable to bind to LAN port: %s\n",
		strerror(errno));
	return -1;
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
    if (timelen > 0) {
	timebuf[timelen-1] = '\0'; /* Nuke the '\n'. */
	timelen--;
    }
    if ((timelen + strlen(format) + 2) >= sizeof(fullformat)) {
	vsyslog(LOG_NOTICE, format, ap);
    } else {
	strcpy(fullformat, timebuf);
	strcat(fullformat, ": ");
	strcat(fullformat, format);
	if (debug || (logtype == DEBUG)) {
	    vprintf(fullformat, ap);
	    printf("\n");
	}
	if (logtype != DEBUG)
	    vsyslog(LOG_NOTICE, fullformat, ap);
    }
    va_end(ap);
}

static char *config_file = "/etc/ipmi_lan.conf";
static char *ipmi_dev = NULL;
static int daemonize = 1;

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

void init_oem_force(void);

int
main(int argc, const char *argv[])
{
    lan_data_t  lan;
    misc_data_t data;
    int max_fd;
    int rv;
    int o;
    int i;
    poptContext poptCtx;
    struct timeval timeout;
    struct timeval time_next;
    struct timeval time_now;

    openlog(argv[0], LOG_CONS, LOG_DAEMON);

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

    data.config_file = config_file;

    /* Call the OEM init code. */
    init_oem_force();

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
    lan.ipmb_addr_change = ipmb_addr_change;

    if (read_config(&lan))
	exit(1);

    data.smi_fd = ipmi_open(ipmi_dev);
    if (data.smi_fd == -1)
	exit(1);

    if (num_addr == 0) {
	struct sockaddr_in *ipaddr = (void *) &addr[0];
	ipaddr->sin_family = AF_INET;
	ipaddr->sin_port = htons(623);
	ipaddr->sin_addr.s_addr = INADDR_ANY;
	addr_len[0] = sizeof(*ipaddr);
	num_addr++;
    }

    for (i=0; i<num_addr; i++) {
	if (addr_len[i] == 0)
	    break;

	data.lan_fd[i] = open_lan_fd(&addr[i], addr_len[i]);
	if (data.lan_fd[i] == -1) {
	    fprintf(stderr, "Unable to open LAN address %d\n", i+1);
	    exit(1);
	}
    }

    rv = ipmi_lan_init(&lan);
    if (rv)
	return 1;

    openlog("ipmilan", LOG_PID | LOG_CONS, LOG_DAEMON);

    if (daemonize) {
	int pid;

	if ((pid = fork()) > 0) {
	    exit(0);
	} else if (pid < 0) {
	    syslog(LOG_ERR, "Error forking first fork");
	    exit(1);
	} else {
	    /* setsid() is necessary if we really want to demonize */
	    setsid();
	    /* Second fork to really deamonize me. */
	    if ((pid = fork()) > 0) {
		exit(0);
	    } else if (pid < 0) {
		syslog(LOG_ERR, "Error forking second fork");
		exit(1);
	    }
	}
    }

    syslog(LOG_INFO, "%s startup", argv[0]);

    max_fd = data.smi_fd;
    for (i=0; i<num_addr; i++) {
	if (data.lan_fd[i] > max_fd)
	    max_fd = data.lan_fd[i];
    }
    max_fd++;

    gettimeofday(&time_next, NULL);
    time_next.tv_sec += 10;
    for (;;) {
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(data.smi_fd, &readfds);
	for (i=0; i<num_addr; i++)
	    FD_SET(data.lan_fd[i], &readfds);

	gettimeofday(&time_now, NULL);
	diff_timeval(&timeout, &time_next, &time_now);
	rv = select(max_fd, &readfds, NULL, NULL, &timeout);
	if ((rv == -1) && (errno == EINTR))
	    continue;

	if (rv == 0) {
	    ipmi_lan_tick(&lan, 10);
	    time_next.tv_sec += 10;
	} else {
	    if (FD_ISSET(data.smi_fd, &readfds)) {
		handle_msg_ipmi(data.smi_fd, &lan);
	    }

	    for (i=0; i<num_addr; i++) {
		if (FD_ISSET(data.lan_fd[i], &readfds))
		    handle_msg_lan(data.lan_fd[i], &lan);
	    }
	}
    }
}
