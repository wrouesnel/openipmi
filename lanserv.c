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

#include <OpenIPMI/log.h>
#include <OpenIPMI/ipmi_err.h>

#include "lanserv.h"

int smi_fd;
int lan_fd;

unsigned int __ipmi_log_mask = 0;

void
ipmi_log(enum ipmi_log_type_e log_type, char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

void
handle_msg(lan_data_t *lan)
{
    int                len;
    struct sockaddr    from_addr;
    socklen_t          from_len;
    unsigned char      data[IPMI_MAX_LAN_LEN];

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
    lan_data_t lan;

    smi_fd = ipmi_open();
    lan_fd = open_lan_fd();

    for (;;) {
	handle_msg(&lan);
    }
}
