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
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include <malloc.h>

#include <OpenIPMI/log.h>
#include <OpenIPMI/ipmi_err.h>

#include "lanserv.h"

typedef struct misc_data
{
    int lan_fd;
    int smi_fd;
} misc_data_t;

static void
handle_msg_ipmi(int smi_fd, lan_data_t *lan)
{
    
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

static void
lan_send(lan_data_t *lan,
	 struct iovec *data, int vecs,
	 void *addr, int addr_len)
{
}

static int
smi_send(lan_data_t *lan, msg_t *msg)
{
    return 0;
}

static void
gen_rand(lan_data_t *lan, void *data, int size)
{
}

static void
handle_msg_lan(int lan_fd, lan_data_t *lan)
{
    int                len;
    struct sockaddr    from_addr;
    socklen_t          from_len;
    unsigned char      data[256];

    from_len = sizeof(from_addr);
    len = recvfrom(lan_fd, data, sizeof(data), 0, &from_addr, &from_len);
    if (len < 0) {
	if (errno != EINTR) {
	    perror("Error receiving message");
	    exit(1);
	}
	return;
    }

    if (len < 4)
	return;

    if (data[0] != 6)
	return; /* Invalid version */

    /* Check the message class. */
    switch (data[3]) {
	case 6:
	    handle_asf(lan, data, len, &from_addr, from_len);
	    break;

	case 7:
	    ipmi_handle_lan_msg(lan, data, len, &from_addr, from_len);
	    break;
    }
}

static void
write_config(lan_data_t *lan)
{
}

static int
ipmi_open(void)
{
    int ipmi_fd;

    ipmi_fd = open("/dev/ipmidev/0", O_RDWR);
    if (ipmi_fd == -1) {
	ipmi_fd = open("/dev/ipmi0", O_RDWR);
	if (ipmi_fd == -1) {
	    perror("Could not open ipmi device /dev/ipmidev/0 or /dev/ipmi0");
	    exit(1);
	}
    }

    return ipmi_fd;
}

int lan_port = 623;

static int
open_lan_fd(void)
{
    int                fd;
    struct sockaddr_in addr;
    int                rv;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
	perror("Unable to create socket");
	exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(lan_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    rv = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
    if (rv == -1)
    {
	fprintf(stderr, "Unable to bind to LAN port (%d): %s\n",
		lan_port, strerror(errno));
	exit(1);
    }

    return fd;
}

int
main(int argc, char *argv[])
{
    lan_data_t  lan;
    misc_data_t data;
    int max_fd;
    int rv;


    data.smi_fd = ipmi_open();
    data.lan_fd = open_lan_fd();

    memset(&lan, 0, sizeof(lan));
    lan.user_info = &data;
    lan.alloc = ialloc;
    lan.free = ifree;
    lan.lan_send = lan_send;
    lan.smi_send = smi_send;
    lan.gen_rand = gen_rand;
    lan.write_config = write_config;

    if (data.lan_fd > data.smi_fd)
	max_fd = data.lan_fd + 1;
    else
	max_fd = data.smi_fd + 1;

    for (;;) {
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(data.smi_fd, &readfds);
	FD_SET(data.lan_fd, &readfds);

	rv = select(max_fd, &readfds, NULL, NULL, NULL);
	if ((rv == -1) && (errno == EINTR))
	    continue;

	if (FD_ISSET(data.smi_fd, &readfds))
	    handle_msg_ipmi(data.smi_fd, &lan);

	if (FD_ISSET(data.lan_fd, &readfds))
	    handle_msg_lan(data.lan_fd, &lan);
    }
}

#if 0
    ipmi_addr_t   addr;
    ipmi_msg_t    imsg;
    if (msg->cmd == IPMI_SEND_MSG_CMD) {
	ipmi_ipmb_addr_t *ipmb = (void *) &addr;
	int              pos;
	/* Send message has special handling */
	
	if (msg->len < 8) {
	    return_err(lan, msg, session, IPMI_REQUEST_DATA_LENGTH_INVALID_CC);
	    return;
	}

	ipmb->addr_type = IPMI_IPMB_ADDR_TYPE;
	ipmb->channel = msg->data[0] & 0xf;
	pos = 1;
	if (msg->data[pos] == 0) {
	    ipmb->addr_type = IPMI_IPMB_BROADCAST_ADDR_TYPE;
	    pos++;
	}
	ipmb->slave_addr = msg->data[pos];
	ipmb->lun = msg->data[pos+1] & 0x3;
	addr_len = sizeof(*ipmb);
	imsg.netfn = msg->data[pos+1] >> 2;
	imsg.cmd = msg->data[pos+5];
	imsg.data = msg->data+pos+6;
	imsg.data_len = msg->len-(pos + 7); /* Subtract last checksum, too */
    } else {
	/* Normal message to the BMC. */
	ipmi_system_interface_addr_t *si = (void *) &addr;

	si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si->channel = 0xf;
	si->lun = msg->rs_lun;
	addr_len = sizeof(*si);
	imsg.netfn = msg->netfn;
	imsg.cmd = msg->cmd;
	imsg.data = msg->data;
	imsg.data_len = msg->len;
    }

    if (addr->addr_type == IPMI_IPMB_ADDR_TYPE) {
	ipmi_ipmb_addr_t *ipmb = (void *) addr; 

	if (imsg->data_len > IPMI_MAX_MSG_LENGTH) {
	    imsg->data[0] = IPMI_REQUEST_DATA_TRUNCATED_CC;
	    imsg->data_len = IPMI_MAX_MSG_LENGTH;
	}

	data[0] = 0;
	data[1] = (imsg->netfn << 2) | 2;
	data[2] = ipmb_checksum(data+1, 1);
	data[3] = ipmb->slave_addr;
//	data[4] = 
    }

#endif
