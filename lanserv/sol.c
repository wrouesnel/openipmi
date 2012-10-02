/*
 * sol.c
 *
 * MontaVista IPMI code for running the SOL protocol.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2012 MontaVista Software Inc.
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <OpenIPMI/serv.h>
#include <OpenIPMI/mcserv.h>
#include <OpenIPMI/lanserv.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_err.h>

/* FIXME - move to configure handling */
#define USE_UUCP_LOCKING

#define SOL_INBUF_SIZE 32
#define SOL_OUTBUF_SIZE 32

struct soldata_s {
    int fd;
    sys_data_t *sys;
    ipmi_io_t *fd_id;
    struct termios termctl;
    int modemstate;

    channel_t *channel;
    msg_t dummy_send_msg;

    /* Data from the remote to the serial port */
    unsigned char inbuf[SOL_INBUF_SIZE];
    unsigned int inlen;

    /* Data from the serial port to the remote */
    unsigned char outbuf[SOL_OUTBUF_SIZE];
    unsigned int outlen;

    /*
     * A circular history buffer.  Note that history_end points to the
     * last byte (not one past the last byte) and history_start points
     * to the first byte.
     */
    unsigned char *history;
    int history_start;
    int history_end;

    /* A copy of the history, used for reliable streaming. */
    unsigned char *history_copy;
    unsigned int history_copy_size;
    unsigned int history_pos;
    msg_t history_dummy_send_msg;
    channel_t *history_channel;
    int history_last_acked_packet;
    int history_last_acked_packet_len;
    int history_curr_packet_seq;
    char history_in_nack;
    ipmi_timer_t *history_timer;
    unsigned int history_num_sends;

    char in_nack;
    char read_enabled;
    char write_enabled;
    char waiting_ack;

    int last_acked_packet;
    int last_acked_packet_len;
    int curr_packet_seq;
    ipmi_timer_t *timer;
    unsigned int num_sends;
};

static char *end_history_msg = "\r\n<End Of History>\r\n";

#define MAX_HISTORY_SEND 64
#define MAX_SOL_RESENDS 4
static void sol_timeout(void *cb_data);
static void sol_history_timeout(void *cb_data);

static void
reset_modem_state(ipmi_sol_t *sol)
{
    int modemstate;

    /* Turn on CTS and DCD if we have history, off if not */
    /* Assuming standard NULL modem, RTS->CTS, DTR->DSR/DCD */
    ioctl(sol->soldata->fd, TIOCMGET, &modemstate);
    if (sol->history_size)
	modemstate |= TIOCM_DTR | TIOCM_RTS;
    else
	modemstate &= ~(TIOCM_DTR | TIOCM_RTS);
    sol->soldata->modemstate = modemstate & (TIOCM_DTR | TIOCM_RTS);
    ioctl(sol->soldata->fd, TIOCMSET, &modemstate);
}

static void
sol_session_closed(lmc_data_t *mc, uint32_t session_id, void *cb_data)
{
    ipmi_sol_t *sol = cb_data;
    soldata_t *sd = sol->soldata;

    if (session_id == sol->session_id) {
	if (sol->soldata->dummy_send_msg.src_addr) {
	    sd->sys->free(sd->sys, sol->soldata->dummy_send_msg.src_addr);
	    sol->soldata->dummy_send_msg.src_addr = NULL;
	}
	sol->active = 0;
	sol->session_id = 0;
	reset_modem_state(sol);
    } else if (session_id == sol->history_session_id) {
	if (sol->soldata->history_dummy_send_msg.src_addr) {
	    sd->sys->free(sd->sys,
			   sol->soldata->history_dummy_send_msg.src_addr);
	    sol->soldata->history_dummy_send_msg.src_addr = NULL;
	}
	if (sol->soldata->history_copy) {
	    sd->sys->free(sd->sys, sol->soldata->history_copy);
	    sol->soldata->history_copy = NULL;
	}
	sol->history_active = 0;
	sol->history_session_id = 0;
    }
}

static unsigned char *
copy_history_buffer(ipmi_sol_t *sol, unsigned int *rsize)
{
    soldata_t *sd = sol->soldata;
    unsigned int to_copy;
    unsigned int endmsg_size = strlen(end_history_msg);
    unsigned char *dest = sd->sys->alloc(sd->sys,
					  sol->history_size + endmsg_size);
    unsigned int size;

    if (!dest)
	return NULL;
    if (sd->history_start > sd->history_end) {
	/* Buffer is filled, copy in two chunks. */
	to_copy = sol->history_size - sd->history_start;
	memcpy(dest + to_copy, sd->history, sd->history_end + 1);
	size = sol->history_size;
    } else {
	/* Buffer is not yet filled, just runs from start to end */
	to_copy = sd->history_end - sd->history_start + 1;
	size = to_copy;
    }
    memcpy(dest, sd->history + sd->history_start, to_copy);
    memcpy(dest + size, end_history_msg, endmsg_size);
    size += endmsg_size;
    *rsize = size;
    return dest;
}

unsigned char *
sol_set_frudata(lmc_data_t *mc, unsigned int *size)
{
    ipmi_sol_t *sol = ipmi_mc_get_sol(mc);

    return copy_history_buffer(sol, size);
}

void sol_free_frudata(lmc_data_t *mc, unsigned char *data)
{
    ipmi_sol_t *sol = ipmi_mc_get_sol(mc);
    soldata_t *sd = sol->soldata;

    if (data)
	sd->sys->free(sd->sys, data);
}

void
ipmi_sol_activate(lmc_data_t    *mc,
		  channel_t     *channel,
		  msg_t         *msg,
		  unsigned char *rdata,
		  unsigned int  *rdata_len)
{
    ipmi_sol_t *sol = ipmi_mc_get_sol(mc);
    soldata_t *sd = sol->soldata;
    uint16_t port;
    int rv;
    msg_t *dmsg;
    unsigned int instance;

    /*
     * FIXME - we are currently ignoring all the payload encryption and
     * authentication bits in the message.
     */

    instance = msg->data[1] & 0xf;
    if (instance == 1) {
	if (sol->active) {
	    *rdata = 0x80; /* Payload already active */
	    *rdata_len = 1;
	    return;
	}
	dmsg = &sd->dummy_send_msg;
    } else if (instance == 2 && sol->history_size) {
	if (sol->history_active) {
	    *rdata = 0x80; /* Payload already active */
	    *rdata_len = 1;
	    return;
	}
	dmsg = &sd->history_dummy_send_msg;
    } else {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    dmsg->src_addr = sd->sys->alloc(sd->sys, msg->src_len);
    if (!dmsg->src_addr) {
	rdata[0] = IPMI_OUT_OF_SPACE_CC;
	*rdata_len = 1;
	return;
    }
    memcpy(dmsg->src_addr, msg->src_addr, msg->src_len);
    dmsg->src_len = msg->src_len;
    dmsg->rmcpp.payload = IPMI_RMCPP_PAYLOAD_TYPE_SOL;

    rv = channel->set_associated_mc(channel, msg->sid, msg->data[0] & 0xf, mc,
				    &port, sol_session_closed, sol);
    if (rv == EBUSY) {
	sd->sys->free(sd->sys, dmsg->src_addr);
	dmsg->src_addr = NULL;
	rdata[0] = IPMI_NODE_BUSY_CC;
	*rdata_len = 1;
	return;
    } else if (rv) {
	sd->sys->free(sd->sys, dmsg->src_addr);
	dmsg->src_addr = NULL;
	rdata[0] = IPMI_UNKNOWN_ERR_CC;
	*rdata_len = 1;
	return;
    }

    dmsg->sid = msg->sid;

    if (instance == 1) {
	/*
	 * Note that we enable CTS and DCD if history is set, because we
	 * always monitor the history.
	 */
	if (!sol->history_size) {
	    if ((msg->data[2] & 1) == 0) {
		/* Assuming standard NULL modem, RTS->CTS, DTR->DSR/DCD */
		int modemstate;
		ioctl(sd->fd, TIOCMGET, &modemstate);
		modemstate |= TIOCM_DTR | TIOCM_RTS;
		sd->modemstate = TIOCM_DTR | TIOCM_RTS;
		ioctl(sd->fd, TIOCMSET, &modemstate);
	    }
	}

	sol->active = 1;
	sol->session_id = msg->sid;
	sd->channel = channel;
	ipmi_set_uint16(rdata + 5, sizeof(sd->inbuf));
	ipmi_set_uint16(rdata + 7, sizeof(sd->outbuf));
    } else if (instance == 2 && sol->history_size) {
	struct timeval tv;

	sd->history_copy = copy_history_buffer(sol, &sd->history_copy_size);
	if (!sd->history_copy) {
	    rdata[0] = IPMI_OUT_OF_SPACE_CC;
	    *rdata_len = 1;
	    return;
	}
	sd->history_pos = 0;
	sol->history_active = 1;
	sol->history_session_id = msg->sid;
	sd->history_channel = channel;
	ipmi_set_uint16(rdata + 5, MAX_HISTORY_SEND);
	ipmi_set_uint16(rdata + 7, MAX_HISTORY_SEND);
	tv.tv_sec = 0;
	tv.tv_usec = 0; /* Send immediately */
	sd->history_num_sends = 0;
	sd->sys->start_timer(sd->history_timer, &tv);
    }

    rdata[0] = 0;
    ipmi_set_uint32(rdata + 1, 0);
    ipmi_set_uint16(rdata + 9, port);
    ipmi_set_uint16(rdata + 11, 0xffff);
    *rdata_len = 13;
}

void
ipmi_sol_deactivate(lmc_data_t    *mc,
		    channel_t     *channel,
		    msg_t         *msg,
		    unsigned char *rdata,
		    unsigned int  *rdata_len)
{
    ipmi_sol_t *sol = ipmi_mc_get_sol(mc);
    unsigned int instance;
    uint32_t session_id;

    instance = msg->data[1] & 0xf;
    if (instance == 1) {
	if (!sol->active) {
	    *rdata = 0x80; /* Payload already deactivated */
	    *rdata_len = 1;
	    return;
	}
	session_id = sol->session_id;
    } else if (instance == 2) {
	if (!sol->history_active) {
	    *rdata = 0x80; /* Payload already deactivated */
	    *rdata_len = 1;
	    return;
	}
	session_id = sol->history_session_id;
    } else {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sol_session_closed(mc, session_id, sol);
    channel->set_associated_mc(channel, session_id, msg->data[0] & 0xf, NULL,
			       NULL, NULL, NULL);

    rdata[0] = 0;
    *rdata_len = 1;
}

#ifdef USE_UUCP_LOCKING
static char *uucp_lck_dir = "/var/lock";
static char *progname = "ipmisim";

static int
uucp_fname_lock_size(char *devname)
{
    char *ptr;

    (ptr = strrchr(devname, '/'));
    if (ptr == NULL) {
	ptr = devname;
    } else {
	ptr = ptr + 1;
    }

    return 7 + strlen(uucp_lck_dir) + strlen(ptr);
}

static void
uucp_fname_lock(char *buf, char *devname)
{
    char *ptr;

    (ptr = strrchr(devname, '/'));
    if (ptr == NULL) {
	ptr = devname;
    } else {
	ptr = ptr + 1;
    }
    sprintf(buf, "%s/LCK..%s", uucp_lck_dir, ptr);
}

static int
write_full(int fd, char *data, size_t count)
{
    size_t written;

 restart:
    while ((written = write(fd, data, count)) > 0) {
	data += written;
	count -= written;
    }
    if (written < 0) {
	if (errno == EAGAIN)
	    goto restart;
	return -1;
    }
    return 0;
}

static void
uucp_rm_lock(sys_data_t *sys, char *devname)
{
    char *lck_file;

    lck_file = sys->alloc(sys, uucp_fname_lock_size(devname));
    if (lck_file == NULL) {
	return;
    }
    uucp_fname_lock(lck_file, devname);
    unlink(lck_file);
    sys->free(sys, lck_file);
}

/* return 0=OK, -1=error, 1=locked by other proces */
static int
uucp_mk_lock(sys_data_t *sys, char *devname)
{
    struct stat stt;
    int pid = -1;

    if (stat(uucp_lck_dir, &stt) == 0) { /* is lock file directory present? */
	char *lck_file;
	union {
	    uint32_t ival;
	    char     str[64];
	} buf;
	int fd;

	lck_file = sys->alloc(sys, uucp_fname_lock_size(devname));
	if (lck_file == NULL)
	    return -1;

	uucp_fname_lock(lck_file, devname);

	pid = 0;
	if ((fd = open(lck_file, O_RDONLY)) >= 0) {
	    int n;

    	    n = read(fd, &buf, sizeof(buf));
	    close(fd);
	    if( n == 4 ) 		/* Kermit-style lockfile. */
		pid = buf.ival;
	    else if (n > 0) {		/* Ascii lockfile. */
		buf.str[n] = 0;
		sscanf(buf.str, "%d", &pid);
	    }

	    if (pid > 0 && kill((pid_t)pid, 0) < 0 && errno == ESRCH) {
		/* death lockfile - remove it */
		unlink(lck_file);
		sleep(1);
		pid = 0;
	    }
	}

	if (pid == 0) {
	    int mask;
	    size_t rv;

	    mask = umask(022);
	    fd = open(lck_file, O_WRONLY | O_CREAT | O_EXCL, 0666);
	    umask(mask);
	    if (fd >= 0) {
		snprintf(buf.str, sizeof(buf), "%10ld\t%s\n",
			 (long)getpid(), progname );
		rv = write_full(fd, buf.str, strlen(buf.str));
		close(fd);
		if (rv < 0) {
		    pid = -errno;
		    unlink(lck_file);
		}
	    } else {
		pid = -errno;
	    }
	}

	sys->free(sys, lck_file);
    }

    return pid;
}
#endif /* USE_UUCP_LOCKING */

static int
sol_to_termios_bitrate(ipmi_sol_t *sol, int solbps)
{
    int retried = 0;

  retry:
    switch(solbps) {
    case 6: return B9600;
    case 7: return B19200;
    case 8: return B38400;
    case 9: return B57600;
    case 10: return B115200;

    case 0:
    default:
	if (retried)
	    return B9600;
	solbps = sol->solparm.default_bitrate;
	goto retry;
    }
}

/* Initialize a serial port control structure for the first time. */
static void
devinit(ipmi_sol_t *sol, struct termios *termctl)
{
    int bitrate = sol_to_termios_bitrate(sol, sol->solparm.bitrate);

    cfmakeraw(termctl);
    cfsetospeed(termctl, bitrate);
    cfsetispeed(termctl, bitrate);
    termctl->c_cflag &= ~(CSTOPB);
    termctl->c_cflag &= ~(CSIZE);
    termctl->c_cflag |= CS8;
    termctl->c_cflag &= ~(PARENB);
    termctl->c_cflag |= CLOCAL;
    termctl->c_cflag &= ~(HUPCL);
    termctl->c_cflag |= CREAD;
    if (sol->use_rtscts)
	termctl->c_cflag |= CRTSCTS;
    else
	termctl->c_cflag &= ~(CRTSCTS);
    termctl->c_iflag &= ~(IXON | IXOFF | IXANY);
    termctl->c_iflag |= IGNBRK;

    reset_modem_state(sol);
}

static void
sol_update_bitrate(lmc_data_t *mc)
{
    ipmi_sol_t *sol = ipmi_mc_get_sol(mc);
    int bitrate = sol_to_termios_bitrate(sol, sol->solparm.bitrate);

    cfsetospeed(&sol->soldata->termctl, bitrate);
    cfsetispeed(&sol->soldata->termctl, bitrate);
    tcsetattr(sol->soldata->fd, TCSANOW, &sol->soldata->termctl);
}

static void
set_read_enable(soldata_t *sd)
{
    int val;

    if (sizeof(sd->outbuf) == sd->outlen)
	/* Read is always disabled if we have nothing to read into. */
	val = 0;
    else
	val = !sd->in_nack;
    if (sd->read_enabled == val)
	return;

    sd->read_enabled = val;
    sd->sys->io_set_enables(sd->fd_id, sd->read_enabled, sd->write_enabled, 0);
}

static void
set_write_enable(soldata_t *sd)
{
    int val = sd->inlen > 0;

    if (sd->write_enabled == val)
	return;

    sd->write_enabled = val;
    sd->sys->io_set_enables(sd->fd_id, sd->read_enabled, sd->write_enabled, 0);
}

static void
send_data(ipmi_sol_t *sol, int need_send_ack)
{
    soldata_t *sd = sol->soldata;
    rsp_msg_t msg;
    unsigned char data[SOL_OUTBUF_SIZE + 4];

    data[0] = sd->curr_packet_seq;
    if (need_send_ack) {
	data[1] = sd->last_acked_packet;
	data[2] = sd->last_acked_packet_len;
    } else {
	data[1] = 0;
	data[2] = 0;
    }
    data[3] = (sd->inlen == sizeof(sd->inbuf)) << 6;
    memcpy(data + 4, sd->outbuf, sd->outlen);
    msg.data = data;
    msg.data_len = sd->outlen + 4;
    sd->waiting_ack = 1;

    sd->channel->return_rsp(sd->channel, &sd->dummy_send_msg, &msg);
}

static void
send_ack(ipmi_sol_t *sol)
{
    soldata_t *sd = sol->soldata;
    rsp_msg_t msg;
    unsigned char data[SOL_OUTBUF_SIZE + 4];

    data[0] = 0;
    data[1] = sd->last_acked_packet;
    data[2] = sd->last_acked_packet_len;
    data[3] = (sd->inlen == sizeof(sd->inbuf)) << 6;
    msg.data = data;
    msg.data_len = 4;

    sd->channel->return_rsp(sd->channel, &sd->dummy_send_msg, &msg);
}

static void
next_seq(soldata_t *sd)
{
    sd->curr_packet_seq++;
    if (sd->curr_packet_seq >= 16)
	sd->curr_packet_seq = 1;
}

static void
sol_timeout(void *cb_data)
{
    ipmi_sol_t *sol = cb_data;
    soldata_t *sd = sol->soldata;
    struct timeval tv;

    if (sd->num_sends > MAX_SOL_RESENDS) {
	sd->waiting_ack = 0;
	next_seq(sd);
	sd->outlen = 0;
	return;
    }

    sd->num_sends++;
    send_data(sol, 0);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    sd->sys->start_timer(sd->history_timer, &tv);
}

static void
handle_sol_port_payload(lanserv_data_t *lan, ipmi_sol_t *sol, msg_t *msg)
{
    soldata_t *sd = sol->soldata;
    unsigned char seq, ack, count;
    char isnack, isbreak, ctspause, deassert_dcd, flush_in, flush_out;
    unsigned char *data;
    unsigned int len;
    int need_send_ack = 0;
    struct timeval tv;

    if (!sol->active || msg->len < 4)
	return;

    seq = msg->data[0] & 0xf;
    ack = msg->data[1] & 0xf;
    count = msg->data[2];
    isnack = msg->data[3] & (1 << 6);
    /* Ring Indicator is ignored for now */
    isbreak = msg->data[3] & (1 << 4);
    ctspause = msg->data[3] & (1 << 3);
    deassert_dcd = msg->data[3] & (1 << 2);
    flush_in = msg->data[3] & (1 << 1);
    flush_out = msg->data[3] & (1 << 0);

    data = msg->data + 4;
    len = msg->len - 4;

    if (seq != 0) {
	if (seq == sd->last_acked_packet) {
	    need_send_ack = 1;
	} else if (len) {
	    sd->last_acked_packet = seq;
	    if (len > (sizeof(sd->inbuf) - sd->inlen))
		len = sizeof(sd->inbuf) - sd->inlen;
	    sd->last_acked_packet_len = len;
	    memcpy(sd->inbuf + sd->inlen, data, len);
	    sd->inlen += len;

	    need_send_ack = 1;
	    set_write_enable(sol->soldata);
	}
    }

    if (ack == sd->curr_packet_seq) {
	next_seq(sd);
	sd->sys->stop_timer(sd->timer);
	if (isnack) {
	    sd->in_nack = 1;
	    set_read_enable(sd);
	} else {
	    sd->in_nack = 0;
	    if (count < sd->outlen) {
		unsigned int i;
		len = sd->outlen - count;
		for (i = 0; i < len; i++)
		    sd->outbuf[i] = sd->outbuf[i + count];
		sd->outlen = len;
		
		send_data(sol, need_send_ack);
		need_send_ack = 0;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		sd->sys->start_timer(sd->timer, &tv);
	    } else {
		sd->waiting_ack = 0;
		sd->outlen = 0;
	    }
	    set_read_enable(sd);
	}
    }

    if (need_send_ack)
	send_ack(sol);

    if (flush_out) {
	sd->waiting_ack = 0;
	next_seq(sd);
	sd->outlen = 0;
    }

    if (flush_in)
	sd->inlen = 0;

    if (isbreak)
	tcsendbreak(sd->fd, 0);

    /*
     * If history is enabled, we don't allow DCD/CTS fiddling, just leave
     * them on all the time.
     */
    if (!sol->history_size) {
	int modemstate = 0;
	if (!ctspause)
	    modemstate |= TIOCM_RTS;
	if (!deassert_dcd)
	    modemstate |= TIOCM_DTR;

	if (modemstate != sd->modemstate) {
	    int val;
	    ioctl(sol->soldata->fd, TIOCMGET, &val);
	    val &= ~(TIOCM_DTR | TIOCM_RTS);
	    val |= modemstate;
	    ioctl(sol->soldata->fd, TIOCMSET, &val);
	}
    }
}

static int
send_history_data(ipmi_sol_t *sol, int need_send_ack)
{
    soldata_t *sd = sol->soldata;
    rsp_msg_t msg;
    unsigned char data[MAX_HISTORY_SEND + 4];
    int to_send;

    to_send = sd->history_copy_size - sd->history_pos;
    if (to_send <= 0)
	return need_send_ack;
    if (to_send > MAX_HISTORY_SEND)
	to_send = MAX_HISTORY_SEND;

    data[0] = sd->history_curr_packet_seq;
    if (need_send_ack) {
	data[1] = sd->history_last_acked_packet;
	data[2] = sd->history_last_acked_packet_len;
    } else {
	data[1] = 0;
	data[2] = 0;
    }
    data[3] = 1 << 6; /* Always ready to get data, we just throw it away */

    memcpy(data + 4, sd->history_copy + sd->history_pos, to_send);
    msg.data = data;
    msg.data_len = to_send + 4;

    sd->history_channel->return_rsp(sd->history_channel,
				    &sd->history_dummy_send_msg, &msg);
    return 0;
}

static void
send_history_ack(ipmi_sol_t *sol)
{
    soldata_t *sd = sol->soldata;
    rsp_msg_t msg;
    unsigned char data[SOL_OUTBUF_SIZE + 4];

    data[0] = 0;
    data[1] = sd->history_last_acked_packet;
    data[2] = sd->history_last_acked_packet_len;
    data[3] = 1 << 6;
    msg.data = data;
    msg.data_len = 4;

    sd->history_channel->return_rsp(sd->history_channel,
				    &sd->history_dummy_send_msg, &msg);
}

static void
sol_history_next_packet(soldata_t *sd)
{
    /* Only send one size for history, no need to check msg's count */
    sd->history_pos += MAX_HISTORY_SEND;
    sd->history_curr_packet_seq++;
    if (sd->history_curr_packet_seq >= 16)
	sd->history_curr_packet_seq = 1;
    sd->history_num_sends = 0;
}

static void
sol_history_timeout(void *cb_data)
{
    ipmi_sol_t *sol = cb_data;
    soldata_t *sd = sol->soldata;
    struct timeval tv;

    if (sd->history_num_sends > MAX_SOL_RESENDS)
	sol_history_next_packet(sd);

    if (sd->history_pos >= sd->history_copy_size)
	return;

    sd->history_num_sends++;
    send_history_data(sol, 0);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    sd->sys->start_timer(sd->history_timer, &tv);
}

static void
handle_sol_history_payload(lanserv_data_t *lan, ipmi_sol_t *sol, msg_t *msg)
{
    soldata_t *sd = sol->soldata;
    unsigned char seq, ack;
    char isnack;
    unsigned char *data;
    unsigned int len;
    int need_send_ack = 0;

    if (!sol->history_active || msg->len < 4)
	return;

    seq = msg->data[0] & 0xf;
    ack = msg->data[1] & 0xf;
    isnack = msg->data[3] & (1 << 6);

    data = msg->data + 4;
    len = msg->len - 4;

    if (seq != 0) {
	if (seq == sd->history_last_acked_packet) {
	    need_send_ack = 1;
	} else if (len) {
	    sd->history_last_acked_packet = seq;
	    sd->history_last_acked_packet_len = len;
	    need_send_ack = 1;
	}
    }

    if (ack == sd->history_curr_packet_seq) {
	if (isnack) {
	    sd->history_in_nack = 1;
	} else {
	    sd->history_in_nack = 0;
	    sol_history_next_packet(sd);
	    need_send_ack = send_history_data(sol, need_send_ack);
	}
	sd->sys->stop_timer(sd->timer);
    }

    if (need_send_ack)
	send_history_ack(sol);
}

static void
handle_sol_payload(lanserv_data_t *lan, msg_t *msg)
{
    ipmi_sol_t *sol;
    channel_t *channel = &lan->channel;
    lmc_data_t *mc;

    mc = channel->get_associated_mc(channel, msg->sid,
				    IPMI_RMCPP_PAYLOAD_TYPE_SOL);
    if (!mc)
	return;

    sol = ipmi_mc_get_sol(mc);
    if (msg->sid == sol->session_id)
	handle_sol_port_payload(lan, sol, msg);
    else if (msg->sid == sol->history_session_id)
	handle_sol_history_payload(lan, sol, msg);
}

static void
sol_write_ready(int fd, void *cb_data)
{
    ipmi_sol_t *sol = cb_data;
    soldata_t *sd = sol->soldata;
    int rv;

    rv = write(fd, sd->inbuf, sd->inlen);
    if (rv < 0) {
	sd->channel->log(sd->channel, OS_ERROR, NULL,
			 "Error reading from serial port: %d, disabling\n",
			 errno);
	sd->sys->remove_io_hnd(sd->fd_id);
	close(sd->fd);
	sd->fd = -1;
	return;
    }

    if (((unsigned int) rv) < sd->inlen)
	memcpy(sd->inbuf, sd->inbuf + rv, sd->inlen - rv);
    sd->inlen -= rv;

    set_write_enable(sd);
}

static void
add_to_history(ipmi_sol_t *sol, unsigned char *buf, unsigned int len)
{
    soldata_t *sd = sol->soldata;
    int to_copy;

    if (!sd->history || len == 0)
	return;

    /*
     * No point in handling more data than we can take, only take the
     * last history size section.
     */
    if (len > sol->history_size) {
	buf += len - sol->history_size;
	len = sol->history_size;
    }

    if (sd->history_end + len + 1 > sol->history_size) {
	/* Wrap case, copy to the end and wrap history_end. */
	to_copy = sol->history_size - sd->history_end - 1;
	memcpy(sd->history + sd->history_end + 1, buf, to_copy);
	sd->history_end = -1;
	len -= to_copy;
	buf += to_copy;
    }

    /*
     * At this point all the data should fit between history_end
     * and the end of the buffer.
     */
    memcpy(sd->history + sd->history_end + 1, buf, len);
    if (sd->history_start > sd->history_end) {
	/*
	 * Before we completely fill the buffer, history_start will
	 * always be <= history_end.  After we fill the buffer,
	 * history_end will always be < history_start.
	 */
	sd->history_start += len;
	if (sd->history_start >= (int) sol->history_size)
	    sd->history_start -= sol->history_size;
    }
    sd->history_end += len;
}

static void
sol_data_ready(int fd, void *cb_data)
{
    ipmi_sol_t *sol = cb_data;
    soldata_t *sd = sol->soldata;
    int rv;
    struct timeval tv;

    rv = read(fd, sd->outbuf + sd->outlen, sizeof(sd->outbuf) - sd->outlen);
    if (rv < 0) {
	sd->channel->log(sd->channel, OS_ERROR, NULL,
			 "Error reading from serial port: %d, disabling\n",
			 errno);
	sd->sys->remove_io_hnd(sd->fd_id);
	close(sd->fd);
	sd->fd = -1;
	return;
    }

    add_to_history(sol, sd->outbuf + sd->outlen, rv);

    sd->outlen += rv;

    if (!sol->active) {
	sd->outlen = 0;
	return;
    }

    /* Looks strange, but will turn off read if the buffer is full */
    set_read_enable(sd);

    if (!sd->waiting_ack) {
	send_data(sol, 0);
	sd->num_sends = 0;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	sd->sys->start_timer(sd->timer, &tv);
    }
}

int
sol_init(sys_data_t *sys)
{
    return ipmi_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_SOL,
				 handle_sol_payload);
}

int
sol_init_mc(sys_data_t *sys, lmc_data_t *mc)
{
    ipmi_sol_t *sol = ipmi_mc_get_sol(mc);
    soldata_t *sd;
    int err;

    sd = sys->alloc(sys, sizeof(*sd));
    if (!sd)
	return ENOMEM;
    memset(sd, 0, sizeof(*sd));

    if (sys->alloc_timer(sys, sol_timeout, sol, &sd->timer)) {
	sys->free(sys, sd);
	return ENOMEM;
    }

    if (sol->history_size) {
	if (sys->alloc_timer(sys, sol_history_timeout, sol,
			     &sd->history_timer)) {
	    sys->free_timer(sd->timer);
	    sys->free(sys, sd);
	    return ENOMEM;
	}

	sd->history = sys->alloc(sys, sol->history_size);
	if (!sd->history) {
	    sys->free_timer(sd->history_timer);
	    sys->free_timer(sd->timer);
	    sys->free(sys, sd);
	    return ENOMEM;
	}
    }

    sd->sys = sys;
    sol->soldata = sd;
    sd->fd = -1;
    sd->curr_packet_seq = 1;
    sd->history_curr_packet_seq = 1;

#ifdef USE_UUCP_LOCKING
    err = uucp_mk_lock(sys, sol->device);
    if (err > 0) {
	fprintf(stderr, "SOL device %s is already owned by process %d\n",
		sol->device, err);
	err = EBUSY;
	goto out;
    }
    if (err < 0) {
	fprintf(stderr, "Error locking SOL device %s\n", sol->device);
	err = -err;
	goto out;
    }
#endif /* USE_UUCP_LOCKING */
    sol->configured++; /* Marked that we locked the device. */

    devinit(sol, &sd->termctl);

    sd->fd = open(sol->device, O_NONBLOCK | O_NOCTTY | O_RDWR);
    if (sd->fd == -1) {
	err = errno;
	fprintf(stderr, "Error opening SOL device %s\n", sol->device);
	goto out;
    }

    err = tcsetattr(sd->fd, TCSANOW, &sd->termctl);
    if (err == -1) {
	err = errno;
	fprintf(stderr, "Error configuring SOL device %s\n", sol->device);
	goto out;
    }
   
    sol->update_bitrate = sol_update_bitrate;

    /* Turn off BREAK. */
    ioctl(sd->fd, TIOCCBRK);

    sd->read_enabled = 1;
    sd->write_enabled = 0;
    err = sys->add_io_hnd(sys, sd->fd, sol_data_ready, sol, &sd->fd_id);
    if (err)
	goto out;

    sd->sys->io_set_hnds(sd->fd_id, sol_write_ready, NULL);

  out:
    if (err) {
	if (sd->timer)
	    sys->free_timer(sd->timer);
	if (sd->history_timer)
	    sys->free_timer(sd->history_timer);
	if (sd->fd >= 0)
	    close(sd->fd);
	if (sd->history)
	    sys->free(sys, sd->history);
	sys->free(sys, sd);
	sol->soldata = NULL;
    }

    return err;
}

void
sol_shutdown(sys_data_t *sys)
{
    unsigned int i;

    for (i = 0; i < IPMI_MAX_MCS; i++) {
	lmc_data_t *mc = sys->ipmb[i];
	ipmi_sol_t *sol;

	if (!mc)
	    continue;
	sol = ipmi_mc_get_sol(mc);
	if (sol->configured < 2)
	    continue;

#ifdef USE_UUCP_LOCKING
	uucp_rm_lock(sys, sol->device);
#endif /* USE_UUCP_LOCKING */
    }
}
