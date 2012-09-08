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
#include <malloc.h>
#include <signal.h>
#include <sys/ioctl.h>

#include <OpenIPMI/serv.h>
#include <OpenIPMI/mcserv.h>
#include <OpenIPMI/lanserv.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_err.h>

/* FIXME - move to configure handling */
#define USE_UUCP_LOCKING

static os_handler_t *sol_os_hnd;

static void ipmi_set_uint16(uint8_t *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
}

static void ipmi_set_uint32(uint8_t *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
    data[2] = (val >> 16) & 0xff;
    data[3] = (val >> 24) & 0xff;
}

void
ipmi_sol_activate(lmc_data_t    *mc,
		  channel_t     *channel,
		  msg_t         *msg,
		  unsigned char *rdata,
		  unsigned int  *rdata_len)
{
    ipmi_sol_t *sol = ipmi_mc_get_sol(mc);
    uint16_t port;
    int rv;

    if (sol->active) {
	*rdata = 0x80; /* Payload already active */
	*rdata_len = 1;
	return;
    }

    rv = channel->set_associated_mc(channel, msg->sid, msg->data[0] & 0xf, mc,
				    &port);
    if (rv == EBUSY) {
	rdata[0] = IPMI_NODE_BUSY_CC;
	*rdata_len = 1;
	return;
    } else if (rv) {
	rdata[0] = IPMI_UNKNOWN_ERR_CC;
	*rdata_len = 1;
	return;
    }

    sol->active = 1;
    sol->session_id = msg->sid;

    rdata[0] = 0;
    ipmi_set_uint32(rdata + 1, 0);
    ipmi_set_uint16(rdata + 5, sizeof(sol->inbuf));
    ipmi_set_uint16(rdata + 7, sizeof(sol->outbuf));
    ipmi_set_uint16(rdata + 9, port);
    ipmi_set_uint16(rdata + 11, 0xffff);
}

void
ipmi_sol_deactivate(lmc_data_t    *mc,
		    channel_t     *channel,
		    msg_t         *msg,
		    unsigned char *rdata,
		    unsigned int  *rdata_len)
{
    ipmi_sol_t *sol = ipmi_mc_get_sol(mc);

    if (!sol->active) {
	*rdata = 0x80; /* Payload already deactivated */
	*rdata_len = 1;
	return;
    }

    sol->active = 0;
    sol->session_id = 0;
    channel->set_associated_mc(channel, msg->sid, msg->data[0] & 0xf, NULL,
			       NULL);
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
uucp_rm_lock(char *devname)
{
    char *lck_file;

    lck_file = malloc(uucp_fname_lock_size(devname));
    if (lck_file == NULL) {
	return;
    }
    uucp_fname_lock(lck_file, devname);
    unlink(lck_file);
    free(lck_file);
}

/* return 0=OK, -1=error, 1=locked by other proces */
static int
uucp_mk_lock(char *devname)
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

	lck_file = malloc(uucp_fname_lock_size(devname));
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
	    } else
		pid = 1;

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

	free(lck_file);
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
    termctl->c_cflag &= ~(CLOCAL);
    termctl->c_cflag &= ~(HUPCL);
    termctl->c_cflag |= CREAD;
    termctl->c_cflag &= ~(CRTSCTS);
    termctl->c_iflag &= ~(IXON | IXOFF | IXANY);
    termctl->c_iflag |= IGNBRK;
}

static void
sol_update_bitrate(lmc_data_t *mc)
{
    ipmi_sol_t *sol = ipmi_mc_get_sol(mc);
    int bitrate = sol_to_termios_bitrate(sol, sol->solparm.bitrate);

    cfsetospeed(&sol->termctl, bitrate);
    cfsetispeed(&sol->termctl, bitrate);
    tcsetattr(sol->fd, TCSANOW, &sol->termctl);
}

static void
handle_sol_payload(lanserv_data_t *lan, lmc_data_t *mc, msg_t *msg)
{
    ipmi_sol_t *sol = ipmi_mc_get_sol(mc);

    if (!sol->active)
	return;
}

static void
sol_data_ready(int lan_fd, void *cb_data, os_hnd_fd_id_t *id)
{
}

int
sol_init(sys_data_t *sys, os_handler_t *os_hnd)
{
    if (!sys->sol_present)
	return 0;

    sol_os_hnd = os_hnd;

    return ipmi_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_SOL,
				 handle_sol_payload);
}

int
sol_init_mc(lmc_data_t *mc)
{
    ipmi_sol_t *sol = ipmi_mc_get_sol(mc);
    int err;

#ifdef USE_UUCP_LOCKING
    err = uucp_mk_lock(sol->device);
    if (err > 0) {
	fprintf(stderr, "SOL device %s is already owned by process %d\n",
		sol->device, err);
	return EBUSY;
    }
    if (err < 0) {
	fprintf(stderr, "Error locking SOL device %s\n", sol->device);
	return -err;
    }
#endif /* USE_UUCP_LOCKING */
    sol->configured++; /* Marked that we locked the device. */

    devinit(sol, &sol->termctl);

    sol->fd = open(sol->device, O_NONBLOCK | O_NOCTTY | O_RDWR);
    if (sol->fd == -1) {
	err = errno;
	fprintf(stderr, "Error opening SOL device %s\n", sol->device);
	return err;
    }

    err = tcsetattr(sol->fd, TCSANOW, &sol->termctl);
    if (err == -1) {
	err = errno;
	fprintf(stderr, "Error configuring SOL device %s\n", sol->device);
	return err;
    }
   
    sol->update_bitrate = sol_update_bitrate;

    /* Turn off BREAK. */
    ioctl(sol->fd, TIOCCBRK);

    err = sol_os_hnd->add_fd_to_wait_for(sol_os_hnd, sol->fd,
					 sol_data_ready, sol,
					 NULL, &sol->fd_id);
 
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
	uucp_rm_lock(sol->device);
#endif /* USE_UUCP_LOCKING */
    }
}
