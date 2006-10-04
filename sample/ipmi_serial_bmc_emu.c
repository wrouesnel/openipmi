
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

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

enum emu_type {
    TERMINAL_MODE,
    DIRECT_MODE,
    RADISYS_ASCII
};


#define IPMI_MAX_MSG_LENGTH 36

struct msg_info {
    void          *info;
    int           sock;
    enum emu_type emu;
    unsigned char netfn;
    unsigned char dest;
    unsigned char src;
    unsigned char seq;
    unsigned char rqLUN;
    unsigned char rsLUN;
    unsigned char cmd;
};

static void socket_send(unsigned char *data, unsigned int len,
			struct msg_info *mi);
static void handle_msg(unsigned char *msg, unsigned int len,
		       struct msg_info *mi);


#define TM_MAX_CHARS_SIZE (((IPMI_MAX_MSG_LENGTH + 1) * 3) + 4)

struct tm_data {
    unsigned char recv_chars[TM_MAX_CHARS_SIZE];
    unsigned int  recv_chars_len;
    int           recv_chars_too_many;
};

static unsigned char hex2char[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
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

static int fromhex(unsigned char c)
{
    if (isdigit(c))
	return c - '0';
    else if (isxdigit(c))
	return tolower(c) - 'a' + 10;
    else
	return -EINVAL;
}

/*
 * Called when the ']' is seen, the leading '[' is removed, too.  We
 * get this with a leading space and no more than one space between
 * items.
 */
static int unformat_msg(unsigned char *r, unsigned int len,
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
	if (len != 0) {
	    fprintf(stderr, "Msg started in the middle of another\n");
	}
	
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
	rv = unformat_msg(info->recv_chars, info->recv_chars_len, mi);
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
    } else if (isspace(r[len-1]) && isspace(ch)) {
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

struct codecs {
    void (*handle_char)(unsigned char ch, struct msg_info *mi);
    void (*send)(unsigned char *msg, unsigned int msg_len,
		 struct msg_info *mi);
    void *(*setup)(void);
} codecs[] = {
    { tm_handle_char, tm_send, tm_setup }
};

static void
socket_send(unsigned char *data, unsigned int len, struct msg_info *mi)
{
    int rv;
    int i;

    printf("Sock send:");
    for (i=0; i<len; i++) {
	if ((i % 16) == 0)
	    printf("\n  ");
	printf(" %2.2x(%c)", data[i], isprint(data[i]) ? data[i] : ' ');
    }
    printf("\n");

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
#define IPMI_GET_MSG_FLAGS_CMD	0x31

static unsigned char devid_data[] = {
    0x20, 0x01, 0x00, 0x48, 0x02, 0x9f, 0x57, 0x01, 0x00, 0x23, 0x00,
    0x00, 0x11, 0x00, 0x04
};

static void
handle_msg(unsigned char *msg, unsigned int len, struct msg_info *mi)
{
    int i;
    unsigned char rsp[IPMI_MAX_MSG_LENGTH];
    unsigned int rsp_len;

    printf("Recv Msg (%x:%x):", mi->netfn, mi->cmd);
    for (i=0; i<len; i++) {
	if ((i % 16) == 0)
	    printf("\n  ");
	printf(" %2.2x(%c)", msg[i], isprint(msg[i]) ? msg[i] : ' ');
    }
    printf("\n");
    if (mi->netfn == IPMI_APP_NETFN) {
	switch (mi->cmd) {
	case IPMI_GET_DEV_ID_CMD:
	    rsp[0] = 0;
	    memcpy(rsp+1, devid_data, sizeof(devid_data));
	    rsp_len = sizeof(devid_data) + 1;
	    break;

	case IPMI_GET_MSG_FLAGS_CMD:
	    rsp[0] = 0;
	    rsp[1] = 0;
	    rsp_len = 2;
	    break;

	default:
	    goto invalid_msg;
	}
    } else
	goto invalid_msg;

 send_rsp:
    /* Convert to response. */
    mi->netfn |= 1;
    codecs[mi->emu].send(rsp, rsp_len, mi);
    return;

 invalid_msg:
    rsp[0] = 0xc1;
    rsp_len = 1;
    goto send_rsp;
}

int
main(int argc, char *argv[])
{
    int s;
    int i;
    enum emu_type emu = TERMINAL_MODE;
    struct addrinfo hints, *res0;
    sockaddr_ip_t addr;
    struct msg_info mi;
    int rv;

    for (i=1; i<argc; i++) {
	if (argv[i][0] != '-')
	    break;
	if (argv[i][1] == '-')
	    break;
	switch (argv[i][1]) {
	case 't':
	    emu = TERMINAL_MODE;
	    break;
	case 'd':
	    emu = DIRECT_MODE;
	    break;
	case 'r':
	    emu = RADISYS_ASCII;
	    break;
	default:
	    fprintf(stderr, "Invalid flag: '%c'\n", argv[i][1]);
	    return 1;
	}
    }

    if (i+2 < argc) {
	fprintf(stderr, "Host and/or port not supplied\n");
	return 1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    rv = getaddrinfo(argv[i], argv[i+1], &hints, &res0);
    if (rv) {
	perror("getaddrinfo");
	return 1;
    }
    /* Only get the first choices */
    memcpy(&addr, res0->ai_addr, res0->ai_addrlen);
    freeaddrinfo(res0);

    s = socket(PF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("socket");
	return 1;
    }

    rv = connect(s, (struct sockaddr *) &addr, sizeof(addr));
    if (rv < 0) {
	perror("connect");
	return 1;
    }

    mi.sock = s;
    mi.emu = emu;
    mi.info = codecs[emu].setup();
    if (!mi.info) {
	fprintf(stderr, "Out of memory\n");
	return 1;
    }
    for (;;) {
	unsigned char buf[128];
	int i;

	rv = read(s, buf, sizeof(buf));
	if (rv < 0) {
	    perror("read");
	    return 1;
	}
	for (i=0; i<rv; i++)
	    codecs[emu].handle_char(buf[i], &mi);
    }
}
