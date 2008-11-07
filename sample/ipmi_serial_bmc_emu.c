/*
 * ipmi_serial_bmc_emu.c
 *
 * An emulator for various IPMI BMCs that sit on a serial port
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2006 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at your
 *  option) any later version.
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  675 Mass Ave, Cambridge, MA 02139, USA.  */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <editline/readline.h>

#define _GNU_SOURCE
#include <getopt.h>

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


#define IPMB_MAX_MSG_LENGTH 32
#define IPMI_MAX_MSG_LENGTH 36

struct msg {
    unsigned char data[IPMB_MAX_MSG_LENGTH];
    unsigned int data_len;
    struct msg *next;
};

struct msg_info;

struct codec {
    char *name;
    void (*handle_char)(unsigned char ch, struct msg_info *mi);
    void (*send)(unsigned char *msg, unsigned int msg_len,
		 struct msg_info *mi);
    void *(*setup)(void);
    void (*handle_event)(struct msg *emsg, struct msg_info *mi);
    void (*handle_ipmb)(struct msg *emsg, struct msg_info *mi);
};

struct oem_handler {
    char *name;
    int (*handler)(const unsigned char *msg, unsigned int len,
		   struct msg_info *mi,
		   unsigned char *rsp, unsigned int *rsp_len);
    void (*init)(struct msg_info *mi);
};

#define EVENT_BUFFER_GLOBAL_ENABLE	(1 << 2)
#define EVENT_LOG_GLOBAL_ENABLE		(1 << 3)
#define SUPPORTED_GLOBAL_ENABLES	(EVENT_BUFFER_GLOBAL_ENABLE | \
					 EVENT_LOG_GLOBAL_ENABLE)

struct msg_info {
    /* General info, set by main code, not formatters. */
    void          *info;
    int           sock;
    struct codec  *codec;
    struct oem_handler *oem;

    /* Queues for events and IPMB messages. */
    struct msg *ipmb_q, *ipmb_q_tail;
    struct msg *event_q, *event_q_tail;

    void *oem_info;

    /* Settings */
    int           echo;
    unsigned char my_ipmb;
    int           debug;
    int           do_attn;
    unsigned char attn_chars[8];
    int           attn_chars_len;
    char          global_enables;

    /* Info from the recv message. */
    unsigned char netfn;
    unsigned char dest;
    unsigned char seq;
    unsigned char rsAddr;
    unsigned char rqAddr;
    unsigned char rqLUN;
    unsigned char rsLUN;
    unsigned char cmd;
};

static void socket_send(const unsigned char *data, unsigned int len,
			struct msg_info *mi);
static void handle_msg(const unsigned char *msg, unsigned int len,
		       struct msg_info *mi);
static void handle_ipmb_msg(const unsigned char *msg, unsigned int len,
			    struct msg_info *mi, struct msg_info *top_mi);

static unsigned char hex2char[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

static int fromhex(unsigned char c)
{
    if (isdigit(c))
	return c - '0';
    else if (isxdigit(c))
	return tolower(c) - 'a' + 10;
    else
	return -EINVAL;
}

static unsigned char
ipmb_checksum(const unsigned char *data, int size)
{
	unsigned char csum = 0;

	for (; size > 0; size--, data++)
		csum += *data;

	return -csum;
}

static int
unformat_ipmb_msg(const unsigned char *msg, unsigned int *pos,
		  unsigned int *len, struct msg_info *mi)
{
    msg += *pos;

    if (*len < 7) {
	fprintf(stderr, "Message too short\n");
	return -EINVAL;
    }

    if (ipmb_checksum(msg, *len) != 0) {
	fprintf(stderr, "Message checksum failure\n");
	return -EINVAL;
    }
    (*len)--;

    mi->rsAddr = msg[0];
    mi->netfn = msg[1] >> 2;
    mi->rsLUN = msg[1] & 3;
    mi->rqAddr = msg[3];
    mi->seq = msg[4] >> 2;
    mi->rqLUN = msg[4] & 3;
    mi->cmd = msg[5];
    *pos += 6;
    *len -= 6;

    return 0;
}

static unsigned int
format_ipmb_rsp(unsigned char *msg, const unsigned char *omsg,
		unsigned int omsg_len, struct msg_info *mi)
{
    unsigned int msg_len;

    msg[0] = mi->rqAddr;
    msg[1] = (mi->netfn << 2) | mi->rqLUN;
    msg[2] = ipmb_checksum(msg, 2);
    msg[3] = mi->rsAddr;
    msg[4] = (mi->seq << 2) | mi->rsLUN;
    msg[5] = mi->cmd;
    memcpy(msg+6, omsg, omsg_len);
    msg_len = omsg_len + 6;
    msg[msg_len] = ipmb_checksum(msg + 3, msg_len - 3);
    msg_len++;

    return msg_len;
}

static void
queue_ipmb(struct msg *imsg, struct msg_info *mi)
{
    imsg->next = NULL;
    if (mi->ipmb_q_tail)
	mi->ipmb_q_tail->next = imsg;
    else
	mi->ipmb_q = imsg;
    mi->ipmb_q_tail = imsg;
    if (mi->do_attn)
	socket_send(mi->attn_chars, mi->attn_chars_len, mi);
}

static void
queue_event(struct msg *emsg, struct msg_info *mi)
{
    emsg->next = NULL;
    if (mi->event_q_tail)
	mi->event_q_tail->next = emsg;
    else
	mi->event_q = emsg;
    mi->event_q_tail = emsg;
    if (mi->do_attn)
	socket_send(mi->attn_chars, mi->attn_chars_len, mi);
}

/***********************************************************************
 *
 * Radisys ASCII codec.
 *
 ***********************************************************************/

#define RA_MAX_CHARS_SIZE (((IPMI_MAX_MSG_LENGTH + 1) * 3) + 4)

struct ra_data {
    unsigned char recv_chars[RA_MAX_CHARS_SIZE];
    unsigned int  recv_chars_len;
    int           recv_chars_too_many;
};

static void ra_format_msg(const unsigned char *msg, unsigned int msg_len,
			  struct msg_info *mi)
{
    int i;
    int len;
    unsigned char c[RA_MAX_CHARS_SIZE];

    len = 0;
    for (i = 0; i < msg_len; i++) {
	c[len] = hex2char[msg[i] >> 4];
	len++;
	c[len] = hex2char[msg[i] & 0xf];
	len++;
    }
    c[len] = 0x0d;
    len++;

    socket_send(c, len, mi);
}

static void
ra_ipmb_handler(struct msg *imsg, struct msg_info *mi)
{
    ra_format_msg(imsg->data, imsg->data_len, mi);
    free(imsg);
}

/*
 * Called when the '0x0d' is seen.
 */
static int ra_unformat_msg(unsigned char *r, unsigned int len,
			   struct msg_info *mi)
{
    unsigned char o[IPMI_MAX_MSG_LENGTH];
    unsigned int p = 0;
    unsigned int i = 0;
    int          rv;

    while (p < len) {
	rv = fromhex(r[p]);
	if (rv < 0)
	    return rv;
	o[i] = rv << 4;
	p++;
	if (p >= len)
	    return -EINVAL;
	rv = fromhex(r[p]);
	if (rv < 0)
	    return rv;
	o[i] |= rv;
	p++;
	i++;
    }

    p = 0;
    rv = unformat_ipmb_msg(o, &p, &i, mi);
    if (rv)
	return rv;
    if ((mi->rsAddr == mi->my_ipmb) || (mi->rsAddr == 1))
	handle_msg(o + p, i, mi);
    else
	handle_ipmb_msg(o + p, i, mi, mi);
    return 0;
}

static void
ra_handle_char(unsigned char ch, struct msg_info *mi)
{
    struct ra_data *info = mi->info;
    unsigned int len = info->recv_chars_len;
    unsigned char *r;
    int           rv;

    if (ch == 0x0d) {
	/* End of command, handle it. */
	if (info->recv_chars_too_many) {
	    /* Input data overrun. */
	    fprintf(stderr, "Data overrun\n");
	    info->recv_chars_too_many = 0;
	    info->recv_chars_len = 0;
	    return;
	}
	rv = ra_unformat_msg(info->recv_chars, info->recv_chars_len, mi);
	info->recv_chars_too_many = 0;
	info->recv_chars_len = 0;
	if (rv) {
	    /* Bad input data. */
	    fprintf(stderr, "Bad input data\n");
	    return;
	}
	return;
    }

    if (info->recv_chars_too_many)
	return;

    r = info->recv_chars;

    if (len >= sizeof(info->recv_chars)) {
	info->recv_chars_too_many = 1;
    } else if ((len > 0) && isspace(r[len-1]) && isspace(ch)) {
	/* Ignore multiple spaces together. */
    } else {
	r[len] = ch;
	info->recv_chars_len++;
    }
}

static void
ra_send(unsigned char *omsg, unsigned int omsg_len, struct msg_info *mi)
{
    unsigned char msg[IPMI_MAX_MSG_LENGTH + 7];
    unsigned int msg_len;

    msg_len = format_ipmb_rsp(msg, omsg, omsg_len, mi);

    ra_format_msg(msg, msg_len, mi);
}

static void *
ra_setup(void)
{
    struct ra_data *info;

    info = malloc(sizeof(*info));
    if (!info)
	return NULL;

    info->recv_chars_len = 0;
    info->recv_chars_too_many = 0;
    return info;
}

/***********************************************************************
 *
 * Direct Mode codec.
 *
 ***********************************************************************/

#define DM_START_CHAR		0xA0
#define DM_STOP_CHAR		0xA5
#define DM_PACKET_HANDSHAKE	0xA6
#define DM_DATA_ESCAPE_CHAR	0xAA

struct dm_data {
    unsigned char recv_msg[IPMI_MAX_MSG_LENGTH + 4];
    unsigned int  recv_msg_len;
    int           recv_msg_too_many;
    int           in_recv_msg;
    int           in_escape;
};

static void
dm_handle_msg(unsigned char *msg, unsigned int len, struct msg_info *mi)
{
    int rv;
    unsigned int pos;

    pos = 0;
    rv = unformat_ipmb_msg(msg, &pos, &len, mi);
    if (rv)
	return;
    handle_msg(msg + pos, len, mi);
}

static void
dm_handle_char(unsigned char ch, struct msg_info *mi)
{
    struct dm_data *info = mi->info;
    unsigned int len = info->recv_msg_len;
    unsigned char c;

    switch (ch) {
    case DM_START_CHAR:
	if (info->in_recv_msg)
	    fprintf(stderr, "Msg started in the middle of another\n");
	info->in_recv_msg = 1;
	info->recv_msg_len = 0;
	info->recv_msg_too_many = 0;
	info->in_escape = 0;
	break;

    case DM_STOP_CHAR:
	if (!info->in_recv_msg)
	    fprintf(stderr, "Empty message\n");
	else if (info->in_escape) {
	    info->in_recv_msg = 0;
	    fprintf(stderr, "Message ended in escape\n");
	} else if (info->recv_msg_too_many) {
	    fprintf(stderr, "Message too long\n");
	    info->in_recv_msg = 0;
	} else {
	    dm_handle_msg(info->recv_msg, info->recv_msg_len, mi);
	    info->in_recv_msg = 0;
	}
	info->in_escape = 0;

	c = DM_PACKET_HANDSHAKE;
	socket_send(&c, 1, mi);
	break;

    case DM_PACKET_HANDSHAKE:
	info->in_escape = 0;
	break;

    case DM_DATA_ESCAPE_CHAR:
	if (!info->recv_msg_too_many)
	    info->in_escape = 1;
	break;

    default:
	if (!info->in_recv_msg)
	    /* Ignore characters outside of messages. */
	    break;

	if (info->in_escape) {
	    info->in_escape = 0;
	    switch (ch) {
	    case 0xB0: ch = DM_START_CHAR; break;
	    case 0xB5: ch = DM_STOP_CHAR; break;
	    case 0xB6: ch = DM_PACKET_HANDSHAKE; break;
	    case 0xBA: ch = DM_DATA_ESCAPE_CHAR; break;
	    case 0x3B: ch = 0x1b; break;
	    default:
		fprintf(stderr, "Invalid escape char: 0x%x\n", ch);
		info->recv_msg_too_many = 1;
		return;
	    }
	}

	if (!info->recv_msg_too_many) {
	    if (len >= sizeof(info->recv_msg)) {
		info->recv_msg_too_many = 1;
		break;
	    }
	    
	    info->recv_msg[len] = ch;
	    info->recv_msg_len++;
	}
	break;
    }
}

static void
dm_send(unsigned char *omsg, unsigned int omsg_len, struct msg_info *mi)
{
    unsigned int i;
    unsigned int len = 0;
    unsigned char c[(IPMI_MAX_MSG_LENGTH + 7) * 2];
    unsigned char msg[IPMI_MAX_MSG_LENGTH + 7];
    unsigned int msg_len;

    msg_len = format_ipmb_rsp(msg, omsg, omsg_len, mi);

    c[len++] = 0xA0;
    for (i = 0; i < msg_len; i++) {
	switch (msg[i]) {
	case 0xA0:
	    c[len++] = 0xAA;
	    c[len++] = 0xB0;
	    break;

	case 0xA5:
	    c[len++] = 0xAA;
	    c[len++] = 0xB5;
	    break;

	case 0xA6:
	    c[len++] = 0xAA;
	    c[len++] = 0xB6;
	    break;

	case 0xAA:
	    c[len++] = 0xAA;
	    c[len++] = 0xBA;
	    break;

	case 0x1B:
	    c[len++] = 0xAA;
	    c[len++] = 0x3B;
	    break;

	default:
	    c[len++] = msg[i];
	}

    }
    c[len++] = 0xA5;

    socket_send(c, len, mi);
}

static void *
dm_setup(void)
{
    struct dm_data *info;

    info = malloc(sizeof(*info));
    if (!info)
	return NULL;
    memset(info, 0, sizeof(*info));
    return info;
}


/***********************************************************************
 *
 * Terminal Mode codec.
 *
 ***********************************************************************/

#define TM_MAX_CHARS_SIZE (((IPMI_MAX_MSG_LENGTH + 1) * 3) + 4)

struct tm_data {
    unsigned char recv_chars[TM_MAX_CHARS_SIZE];
    unsigned int  recv_chars_len;
    int           recv_chars_too_many;
};

static void tm_format_msg(const unsigned char *msg, unsigned int msg_len,
			  struct msg_info *mi)
{
    int i;
    int len;
    unsigned char c[TM_MAX_CHARS_SIZE];
    unsigned char t;

    len = 0;
    c[len] = '[';
    len++;

    t = mi->netfn << 2 | mi->rqLUN;
    c[len] = hex2char[t >> 4];
    len++;
    c[len] = hex2char[t & 0xf];
    len++;

    /*
     * Insert the sequence number and bridge bits.  Bridge bits
     * are always zero.
     */
    t = mi->seq << 2;
    c[len] = hex2char[t >> 4];
    len++;
    c[len] = hex2char[t & 0xf];
    len++;

    c[len] = hex2char[mi->cmd >> 4];
    len++;
    c[len] = hex2char[mi->cmd & 0xf];
    len++;

    /* Now the rest of the message. */
    for (i = 0; ; ) {
	c[len] = hex2char[msg[i] >> 4];
	len++;
	c[len] = hex2char[msg[i] & 0xf];
	len++;
	i++;
	if (i == msg_len)
	    break;
	c[len] = ' ';
	len++;
    }
    c[len] = ']';
    len++;
    c[len] = 0x0a;
    len++;

    socket_send(c, len, mi);
}

/*
 * Called when the ']' is seen, the leading '[' is removed, too.  We
 * get this with a leading space and no more than one space between
 * items.
 */
static int tm_unformat_msg(unsigned char *r, unsigned int len,
			   struct msg_info *mi)
{
    unsigned char o[IPMI_MAX_MSG_LENGTH];
    unsigned int p = 0;
    unsigned int i = 0;
    int          rv;

#define SKIP_SPACE if (isspace(r[p])) p++
#define ENSURE_MORE if (p >= len) return -EINVAL

	SKIP_SPACE;
	while (p < len) {
		if (i >= sizeof(o))
			return -EFBIG;
		ENSURE_MORE;
		rv = fromhex(r[p]);
		if (rv < 0)
			return rv;
		o[i] = rv << 4;
		p++;
		ENSURE_MORE;
		rv = fromhex(r[p]);
		if (rv < 0)
			return rv;
		o[i] |= rv;
		p++;
		i++;
		SKIP_SPACE;
	}

	if (i < 3)
	    return -EINVAL;

	mi->netfn = o[0] >> 2;
	mi->rqLUN = o[0] & 3;
	mi->seq = o[1] >> 2;
	mi->cmd = o[2];
	handle_msg(o+3, i-3, mi);
	return 0;
#undef SKIP_SPACE
#undef ENSURE_MORE
}

static void
tm_handle_char(unsigned char ch, struct msg_info *mi)
{
    struct tm_data *info = mi->info;
    unsigned int len = info->recv_chars_len;
    unsigned char *r;
    int           rv;

    if (ch == '[') {
	/*
	 * Start of a command.  Note that if a command is
	 * already in progress (len != 0) we abort it.
	 */
	if (len != 0)
	    fprintf(stderr, "Msg started in the middle of another\n");
	
	/* Convert the leading '[' to a space, that's innocuous. */
	info->recv_chars[0] = ' ';
	info->recv_chars_len = 1;
	info->recv_chars_too_many = 0;
	return;
    }

    if (len == 0)
	/* Ignore everything outside [ ]. */
	return;

    if (ch == ']') {
	/* End of command, handle it. */
	if (info->recv_chars_too_many) {
	    /* Input data overrun. */
	    fprintf(stderr, "Data overrun\n");
	    info->recv_chars_too_many = 0;
	    info->recv_chars_len = 0;
	    return;
	}
	rv = tm_unformat_msg(info->recv_chars, info->recv_chars_len, mi);
	info->recv_chars_too_many = 0;
	info->recv_chars_len = 0;
	if (rv) {
	    /* Bad input data. */
	    fprintf(stderr, "Bad input data\n");
	    return;
	}
	return;
    }

    if (info->recv_chars_too_many)
	return;

    r = info->recv_chars;

    if (len >= sizeof(info->recv_chars)) {
	info->recv_chars_too_many = 1;
    } else if ((len > 0) && isspace(r[len-1]) && isspace(ch)) {
	/* Ignore multiple spaces together. */
    } else {
	r[len] = ch;
	info->recv_chars_len++;
    }
}

static void
tm_send(unsigned char *msg, unsigned int msg_len, struct msg_info *mi)
{
    tm_format_msg(msg, msg_len, mi);
}

static void *
tm_setup(void)
{
    struct tm_data *info;

    info = malloc(sizeof(*info));
    if (!info)
	return NULL;

    info->recv_chars_len = 0;
    info->recv_chars_too_many = 0;
    return info;
}


/***********************************************************************
 *
 * codec structure
 *
 ***********************************************************************/
struct codec codecs[] = {
    { "TerminalMode",
      tm_handle_char, tm_send, tm_setup, queue_event, queue_ipmb },
    { "Direct",
      dm_handle_char, dm_send, dm_setup, queue_event, queue_ipmb },
    { "RadisysAscii",
      ra_handle_char, ra_send, ra_setup, NULL, ra_ipmb_handler },
    { NULL }
};


static void
socket_send(const unsigned char *data, unsigned int len, struct msg_info *mi)
{
    int rv;
    int i;

    if (mi->debug > 0) {
	printf("Sock send:");
	for (i=0; i<len; i++) {
	    if ((i % 16) == 0)
		printf("\n  ");
	    printf(" %2.2x(%c)", data[i], isprint(data[i]) ? data[i] : ' ');
	}
	printf("\n");
    }

 restart:
    rv = write(mi->sock, data, len);
    if (rv < 0) {
	perror("write");
	return;
    } else if (rv < len) {
	len -= rv;
	data += rv;
	goto restart;
    }
}

#define IPMI_APP_NETFN	6
#define IPMI_GET_DEV_ID_CMD	0x01
#define IPMI_GET_DEVICE_GUID_CMD 0x08
#define IPMI_SET_BMC_GLOBAL_ENABLES_CMD	0x2e
#define IPMI_GET_BMC_GLOBAL_ENABLES_CMD	0x2f
#define IPMI_GET_MSG_FLAGS_CMD	0x31
#define IPMI_GET_MSG_CMD	0x33
#define IPMI_SEND_MSG_CMD	0x34
#define IPMI_READ_EVENT_MSG_CMD	0x35
#define IPMI_OEM_NETFN	0x2e

static unsigned char ipmb_devid_data[] = {
    0x00, 0x01, 0x00, 0x48, 0x02, 0x9f, 0xaa, 0x01, 0x00, 0x23, 0x00,
    0x00, 0x11, 0x00, 0x04
};

static void
handle_ipmb_msg(const unsigned char *msg, unsigned int len,
		struct msg_info *mi, struct msg_info *top_mi)
{
    struct msg *imsg;
    unsigned char rsp[IPMI_MAX_MSG_LENGTH];
    unsigned int rsp_len;
    int          i;

    imsg = malloc(sizeof(*imsg));
    if (!imsg)
	return;

    if (top_mi->debug > 0) {
	printf("Recv IPMB Msg (%x:%x):", mi->netfn, mi->cmd);
	for (i=0; i<len; i++) {
	    if ((i % 16) == 0)
		printf("\n  ");
	    printf(" %2.2x(%c)", msg[i], isprint(msg[i]) ? msg[i] : ' ');
	}
	printf("\n");
    }

    if (mi->netfn == IPMI_APP_NETFN) {
	switch (mi->cmd) {
	case IPMI_GET_DEV_ID_CMD:
	    rsp[0] = 0;
	    memcpy(rsp+1, ipmb_devid_data, sizeof(ipmb_devid_data));
	    rsp_len = sizeof(ipmb_devid_data) + 1;
	    break;
	default:
	    goto invalid_msg;
	}
    } else
	goto invalid_msg;

 send_rsp:
    /* Convert to response. */
    mi->netfn |= 1;
    imsg->data_len = format_ipmb_rsp(imsg->data, rsp, rsp_len, mi);
    top_mi->codec->handle_ipmb(imsg, top_mi);
    return;

 invalid_msg:
    rsp[0] = 0xc1;
    rsp_len = 1;
    goto send_rsp;
}

static unsigned char devid_data[] = {
    0x20, 0x01, 0x00, 0x48, 0x02, 0x9f, 0x22, 0x03, 0x00, 0x11, 0x43,
    0x00, 0x11, 0x00, 0x04
};

static unsigned char guid_data[] = {
    0x00, 0x01, 0x00, 0x48, 0x02, 0x9f, 0xaa, 0x01,
    0x00, 0x23, 0x00, 0x00, 0x11, 0x00, 0x04, 0x99
};

static void
handle_msg(const unsigned char *msg, unsigned int len, struct msg_info *mi)
{
    int i;
    unsigned char rsp[IPMI_MAX_MSG_LENGTH];
    unsigned int rsp_len;
    struct msg *m;
    int rv;
    struct msg_info nmi;
    unsigned int p;

    if (mi->debug > 0) {
	printf("Recv Msg (%x:%x):", mi->netfn, mi->cmd);
	for (i=0; i<len; i++) {
	    if ((i % 16) == 0)
		printf("\n  ");
	    printf(" %2.2x(%c)", msg[i], isprint(msg[i]) ? msg[i] : ' ');
	}
	printf("\n");
    }

    if (mi->oem) {
	rv = mi->oem->handler(msg, len, mi, rsp, &rsp_len);
	if (!rv)
	    goto send_rsp;
    }

    if (mi->netfn == IPMI_APP_NETFN) {
	switch (mi->cmd) {
	case IPMI_GET_DEV_ID_CMD:
	    rsp[0] = 0;
	    memcpy(rsp+1, devid_data, sizeof(devid_data));
	    rsp_len = sizeof(devid_data) + 1;
	    break;

	case IPMI_GET_DEVICE_GUID_CMD:
	    rsp[0] = 0;
	    memcpy(rsp+1, guid_data, sizeof(guid_data));
	    rsp_len = sizeof(guid_data) + 1;
	    break;

	case IPMI_GET_MSG_FLAGS_CMD:
	    rsp[0] = 0;
	    rsp[1] = 0;
	    if (mi->event_q)
		rsp[1] |= 2;
	    if (mi->ipmb_q)
		rsp[1] |= 1;
	    rsp_len = 2;
	    break;

	case IPMI_GET_MSG_CMD:
	    if (!mi->ipmb_q) {
		rsp[0] = 0x80;
		rsp_len = 1;
		break;
	    }
	    m = mi->ipmb_q;
	    mi->ipmb_q = m->next;
	    if (!mi->ipmb_q)
		mi->ipmb_q_tail = NULL;

	    rsp[0] = 0;
	    rsp[1] = 0; /* Channel # */
	    /* Note we don't put our slave address in the response, as
	       that is what get smg expects. */
	    memcpy(rsp + 2, m->data + 1, m->data_len - 1);
	    rsp_len = 2 + m->data_len - 1;
	    free(m);
	    break;

	case IPMI_SEND_MSG_CMD:
	    if (msg[0] != 0) {
		rsp[0] = 0xcc;
		rsp_len = 1;
		break;
	    }
	    p = 1;
	    len -= 1;
	    rv = unformat_ipmb_msg(msg, &p, &len, &nmi);
	    if (rv) {
		rsp[0] = 0xcc;
		rsp_len = 1;
		break;
	    }
	    if (nmi.netfn & 1) {
		/* Ignore responses */
		rsp[0] = 0;
		rsp_len = 1;
		break;
	    }
	    handle_ipmb_msg(msg+p, len, &nmi, mi);
	    rsp[0] = 0;
	    rsp_len = 1;
	    break;

	case IPMI_SET_BMC_GLOBAL_ENABLES_CMD:
	    if (len < 1) {
		rsp[0] = 0xcc;
		rsp_len = 1;
		break;
	    }

	    if ((msg[0] & ~SUPPORTED_GLOBAL_ENABLES) != 0) {
		rsp[0] = 0xcc;
		rsp_len = 1;
		break;
	    }

	    mi->global_enables = msg[0];

	    rsp[0] = 0;
	    rsp_len = 1;
	    break;

	case IPMI_GET_BMC_GLOBAL_ENABLES_CMD:
	    rsp[0] = 0;
	    rsp[1] = mi->global_enables;
	    rsp_len = 2;
	    break;

	case IPMI_READ_EVENT_MSG_CMD:
	    if (!mi->event_q) {
		rsp[0] = 0x80;
		rsp_len = 1;
		break;
	    }
	    m = mi->event_q;
	    mi->event_q = m->next;
	    if (!mi->event_q)
		mi->event_q_tail = NULL;

	    rsp[0] = 0;
	    memcpy(rsp + 1, m->data, m->data_len);
	    rsp_len = 1 + m->data_len;
	    free(m);
	    break;

	default:
	    goto invalid_msg;
	}
    } else
	goto invalid_msg;

 send_rsp:
    /* Convert to response. */
    mi->netfn |= 1;
    mi->codec->send(rsp, rsp_len, mi);
    return;

 invalid_msg:
    rsp[0] = 0xc1;
    rsp_len = 1;
    goto send_rsp;
}

#define PP_GET_SERIAL_INTF_CMD	0x01
#define PP_SET_SERIAL_INTF_CMD	0x02
static unsigned char pp_oem_chars[] = { 0x00, 0x40, 0x0a };
static int
pp_oem_handler(const unsigned char *msg, unsigned int len,
	       struct msg_info *mi,
	       unsigned char *rsp, unsigned int *rsp_len)
{
    if ((len < 3) || (memcmp(msg, pp_oem_chars, 3) != 0))
	return -ENOSYS;
    msg += 3;
    len -= 3;
		     
    if (mi->netfn == IPMI_OEM_NETFN) {
	switch (mi->cmd) {
	case PP_GET_SERIAL_INTF_CMD:
	    rsp[0] = 0;
	    memcpy(rsp+1, pp_oem_chars, 3);
	    rsp[4] = 0;
	    if (msg[0] == 1)
		rsp[4] |= mi->echo;
	    *rsp_len = 5;
	    break;

	case PP_SET_SERIAL_INTF_CMD:
	    if (len < 2)
		rsp[0] = 0xcc;
	    else if (msg[0] == 1) {
		mi->echo = msg[1] & 1;
		rsp[0] = 0;
	    }
	    memcpy(rsp+1, pp_oem_chars, 3);
	    *rsp_len = 4;
	    break;

	default:
	    return -ENOSYS;
	}
    } else
	return -ENOSYS;

    return 0;
}

static void
pp_oem_init(struct msg_info *mi)
{
    mi->echo = 1;
}

#define RA_CONTROLLER_OEM_NETFN	0x3e
#define RA_GET_IPMB_ADDR_CMD	0x12
static int
ra_oem_handler(const unsigned char *msg, unsigned int len,
	       struct msg_info *mi,
	       unsigned char *rsp, unsigned int *rsp_len)
{
    if (mi->netfn == RA_CONTROLLER_OEM_NETFN) {
	switch (mi->cmd) {
	case RA_GET_IPMB_ADDR_CMD:
	    rsp[0] = 0;
	    rsp[1] = mi->my_ipmb;
	    *rsp_len = 2;
	    break;

	default:
	    return -ENOSYS;
	}
    } else if (mi->netfn == IPMI_APP_NETFN) {
	switch (mi->cmd) {
	case IPMI_GET_MSG_FLAGS_CMD:
	    /* No message flag support. */
	    rsp[0] = 0xc1;
	    *rsp_len = 1;
	    break;

	default:
	    return -ENOSYS;
	}
    } else
	return -ENOSYS;

    return 0;
}

static void
ra_oem_init(struct msg_info *mi)
{
}

static struct oem_handler oem_handlers[] = {
    { "PigeonPoint",		pp_oem_handler,		pp_oem_init },
    { "Radisys",		ra_oem_handler,		ra_oem_init },
    { NULL }
};

static char *
next_tok(char **str)
{
    char *rv;
    char *s = *str;

    while (isspace(*s))
	s++;
    rv = s;
    while (*s && (!isspace(*s)))
	s++;
    if (*s) {
	*s = '\0';
	s++;
    }
    *str = s;
    if (*rv)
	return rv;
    else
	return NULL;
}

static void
exit_handler(char *line, struct msg_info *mi)
{
    close(mi->sock);
    exit(0);
}

static void
inc_debug_handler(char *line, struct msg_info *mi)
{
    mi->debug++;
}

static void
dec_debug_handler(char *line, struct msg_info *mi)
{
    if (mi->debug > 0)
	mi->debug--;
}

static void
event_handler(char *line, struct msg_info *mi)
{
    struct msg *emsg;
    int i, p;
    unsigned char *m;

    if (!mi->codec->handle_event) {
	printf("This codec does not support event messages\n");
	return;
    }

    emsg = malloc(sizeof(*emsg));
    if (!emsg) {
	printf("Could not allocate event message\n");
	return;
    }

    p = 0;
    m = emsg->data;
    for (i=0; i<16; i++) {
	char *s, *e;
	s = next_tok(&line);
	if (!s) {
	    printf("Events need 16 bytes of data\n");
	    free(emsg);
	    return;
	}
	m[p++] = strtoul(s, &e, 16);
	if (*e != '\0') {
	    printf("Byte %d was invalid\n", i+1);
	    free(emsg);
	    return;
	}
    }
    emsg->data_len = 16;

    mi->codec->handle_event(emsg, mi);
}

static void help_handler(char *line, struct msg_info *mi);

static const char help_help[] = "This command.";
static const char exit_help[] = "Quit the program.";
static const char quit_help[] = "Quit the program.";
static const char event_help[] =
"Put an event into the event queue. Takes 16 bytes of data like:\n"
"      event 10 20 30 40 50 60 70 80 90 a0 b0 c0 d0 e0 f0 f1";
static const char inc_debug_help[] = "Increment the debugging flag.";
static const char dec_debug_help[] = "Decrement the debugging flag.";

static struct {
    const char *cmd;
    void (*handler)(char *line, struct msg_info *mi);
    const char *help;
} cmds[] = {
    { "help",			help_handler,		help_help },
    { "exit",			exit_handler,		exit_help },
    { "quit",			exit_handler,		quit_help },
    { "event",			event_handler,		event_help },
    { "debug+",			inc_debug_handler,	inc_debug_help },
    { "debug-",			dec_debug_handler,	dec_debug_help },
    { NULL }
};

static void
help_handler(char *line, struct msg_info *mi)
{
    int i;
    printf("Valid commands:");
    for (i=0; cmds[i].cmd; i++)
	printf("  %s - %s\n", cmds[i].cmd, cmds[i].help);
}

static struct msg_info main_mi;

static void
command_string_handler(char *cmdline)
{
    char *expansion = NULL;
    int result;
    int i;
    char *s, *cmd;

    if (cmdline == NULL) {
	printf("\n");
	exit_handler(NULL, &main_mi);
    }

    result = history_expand(cmdline, &expansion);
    if (result < 0 || result == 2) {
	fprintf(stderr, "%s\n", expansion);
    } else if (expansion && strlen(expansion)){
	add_history(expansion);

	s = expansion;
	cmd = next_tok(&s);
	if (cmd) {
	    /* Extract the command. */
	    for (i=0; cmds[i].cmd != NULL; i++) {
		if (strcmp(cmd, cmds[i].cmd) == 0)
		    break;
	    }
	    if (cmds[i].cmd) {
		cmds[i].handler(s, &main_mi);
	    } else {
		printf("Unknown command: '%s'\n", cmd);
	    }
	}
    }
    if (expansion)
	free(expansion);
}

struct option options[] = {
    { "codec",		 1, NULL, 'c' },
    { "ipmb_addr",	 1, NULL, 'a' },
    { "oem_setup",	 1, NULL, 'o' },
    { "debug",		 0, NULL, 'd' },
    { "attn",		 2, NULL, 't' },
    { 0 }
};

static char *usage_str =
"%s [options] <server> <port>\n"
"  Emulate various IPMI serial port BMCs, primarily for testing the\n"
"  IPMI driver.\n"
"  Options are:\n"
"   -c <codec>, --codec <codec> - Set the codec to use.  Valid codecs\n"
"     are:\n"
"        TerminalMode - Standard terminal mode\n"
"        Direct - standard serial direct mode\n"
"        RadisysAscii - Radisys defined ASCII\n"
"   -a <addr>, --ipmb_addr <addr> - Set the IPMB address for the emulated\n"
"     BMC.\n"
"   -o <oem>, --oem_setup <oem> - Emulate certain OEM commands:\n"
"     PigeonPoint - Emulate echo handling per the PigeonPoint IPMCs,\n"
"         primarily for terminal mode.\n"
"     Radisys - Emulate the Radisys method for fetching the IPMB address.\n"
"   --attn[=<char>[,<char>[,...]]] - Set the attention characters to\n"
"     the given value.  This is sent whenever something is added to the\n"
"     event or receive message queue.  It defaults to one BELL character,\n"
"     which is 0x07.  The specified values are numbers, like 0x07.\n"
"     For direct mode using the ASCII escape, this would be 0x1b.  For\n"
"     direct mode on the Sun CPxxxx, this would be 0xAA,0x47.\n"
"   -d, --debug - Increment the debug setting\n"
"  This program connects to a remote TCP port, so you need to have a\n"
"  terminal server (in raw mode, not telnet mode) to use this program.\n"
"  I use ser2net, get that if you need it.\n";
char *cmdname;
static void
usage(void)
{
    printf(usage_str, cmdname);
    exit(1);
}

int
main(int argc, char *argv[])
{
    int i;
    struct addrinfo hints, *res0;
    sockaddr_ip_t addr;
    struct msg_info *mi = &main_mi;
    int rv;
    char *s, *e;

    cmdname = argv[0];

    memset(mi, 0, sizeof(*mi));
    mi->my_ipmb = 0x20;
    mi->codec = &(codecs[0]);

    for (;;) {
	int f;
	f = getopt_long(argc, argv, "c:o:a:d", options, NULL);
	if (f == -1)
	    break;

	switch (f) {
	case 'c':
	    for (i=0; codecs[i].name; i++) {
		if (strcmp(codecs[i].name, optarg) == 0)
		    break;
	    }
	    if (codecs[i].name)
		mi->codec = &(codecs[i]);
	    else {
		fprintf(stderr, "Invalid codec: %s\n", optarg);
		usage();
	    }
	    break;

	case 'd':
	    mi->debug++;
	    break;

	case 'a':
	    mi->my_ipmb = strtoul(optarg, NULL, 0);
	    break;

	case 't':
	    mi->do_attn = 1;
	    if (optarg) {
		s = optarg;
		for (i=0; ; i++) {
		    if (i >= sizeof(mi->attn_chars)) {
			fprintf(stderr, "Too many attention characters\n");
			usage();
		    }
		    mi->attn_chars[i] = strtoul(s, &e, 0);
		    mi->attn_chars_len++;
		    if (*e == '\0')
			break;
		    else if (*e == ',')
			s = e + 1;
		    else {
			fprintf(stderr, "Invalid attention characters\n");
			usage();
		    }
		}
	    } else {
		mi->attn_chars[0] = 0x07;
		mi->attn_chars_len = 1;
	    }
	    break;

	case 'o':
	    for (i=0; oem_handlers[i].name != NULL; i++) {
		if (strcmp(optarg, oem_handlers[i].name) == 0)
		    break;
	    }
	    if (oem_handlers[i].name) {
		mi->oem = &(oem_handlers[i]);
		mi->oem->init(mi);
	    } else {
		fprintf(stderr, "Invalid OEM handler '%s'\n", optarg);
		usage();
	    }
	    break;

	default:
	    fprintf(stderr, "Invalid flag: '%c'\n", optopt);
	    usage();
	}
    }

    i = optind;
    if (i+2 < argc) {
	fprintf(stderr, "Host and/or port not supplied\n");
	usage();
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    rv = getaddrinfo(argv[i], argv[i+1], &hints, &res0);
    if (rv) {
	perror("getaddrinfo");
	usage();
    }
    /* Only get the first choices */
    memcpy(&addr, res0->ai_addr, res0->ai_addrlen);
    freeaddrinfo(res0);

    mi->sock = socket(PF_INET, SOCK_STREAM, 0);
    if (mi->sock < 0) {
	perror("socket");
	usage();
    }

    rv = connect(mi->sock, (struct sockaddr *) &addr, sizeof(addr));
    if (rv < 0) {
	perror("connect");
	usage();
    }

    i = 1;
    if (setsockopt(mi->sock, IPPROTO_TCP, TCP_NODELAY,
		   (char *) &i, sizeof(i)) == -1) {
	perror("setsockopt TCP_NODELAY");
	usage();
    }

    mi->info = mi->codec->setup();
    if (!mi->info) {
	fprintf(stderr, "Out of memory\n");
	usage();
    }

    printf("Starting IPMI serial BMC emulator with:\n  %s codec"
	   "\n  %s OEM emulation\n",
	   mi->codec->name, mi->oem ? mi->oem->name : "no");
    if (mi->do_attn) {
	printf("  attention chars:");
	for (i=0; i<mi->attn_chars_len; i++)
	    printf(" %2.2x", mi->attn_chars[i]);
	printf("\n");
    }
    stifle_history(500);
    rl_callback_handler_install("> ", command_string_handler);

    for (;;) {
	unsigned char buf[128];
	int i;
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(0, &readfds);
	FD_SET(mi->sock, &readfds);
	rv = select(mi->sock+1, &readfds, NULL, NULL, NULL);
	if (rv < 0) {
	    if (errno != EINTR) {
		perror("select");
		usage();
	    }
	    continue;
	}

	if (FD_ISSET(mi->sock, &readfds)) {
	    rv = read(mi->sock, buf, sizeof(buf));
	    if (rv < 0) {
		perror("read");
		usage();
	    }

	    if (mi->debug > 1) {
		printf("recv:");
		for (i=0; i<rv; i++) {
		    if ((i % 16) == 0)
			printf("\n  ");
		    printf(" %2.2x(%c)", buf[i],
			   isprint(buf[i]) ? buf[i] : ' ');
		}
		printf("\n");
	    }

	    for (i=0; i<rv; i++) {
		/*
		 * Echo one at a time in case the echo gets turned off
		 * in the middle of this data.
		 */
		if (mi->echo)
		    write(mi->sock, buf+i, 1);
		mi->codec->handle_char(buf[i], mi);
	    }
	}

	if (FD_ISSET(0, &readfds))
	    rl_callback_read_char();
    }
}
