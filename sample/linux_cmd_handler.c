/*
 * linux-cmd-handler.c
 *
 * A test/example program that receives a command sent to LUN 2,
 * prints it out, and sends a response.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2017 MontaVista Software Inc.
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
 *  675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * This program provides an example of how to receive a command from
 * the BMC and send a response.  This can be used to extend IPMI in the
 * host system, if you want to do that.
 *
 * This works by sending a sending a command to the BMC on LUN 2.  The
 * BMC should route this to the receive queue, the driver will pick it
 * up and if something is registered to that particular netfn/cmd, it
 * will route it to that.
 *
 * Generally you are sending these commands over a lan interface.  Here is
 * an example ipmitool command to do this:
 *
 *  ipmitool -I lan -A MD5 -U <user> -P <pw) -l 2 -H t-langley-1 raw 2 3 1 2 3 4
 * You should get the response:
 *  01 02 03 04
 * Note that older versions on ipmitool may have a broken -l option.
 *
 * In openipmicmd, you would do the following:
 *  => f 2 2 3 1 2 3 4
 *  => Got message:
 *    type      = response
 *    addr_type = SI
 *    channel   = 0xf
 *    lun       = 0x2
 *    netfn     = 0x3
 *    cmd       = 0x3
 *    data      =00 01 02 03 04 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <linux/ipmi.h>

static char *progname;
static char *devname = "/dev/ipmi0";
static int netfn = 2;
static int cmd = 3;

static void
usage(int exitcode)
{
    printf("Wait for incoming commands on an IPMI interface, print then,\n");
    printf("and send a response back\n\n");
    printf("%s [-d|--device <device file>] [-n|--netfn <netfn>]\n", progname);
    printf("        [-c|--command] <command>\n\n");
    printf(" -d|--device - Set the IPMI device to use."
	   "  Default is /dev/ipmi0\n");
    printf(" -n|--netfn - Set the netfn to listen for.  Default is 2\n");
    printf(" -c|--command - Set the command to listen for.  Default is 3\n");
    
    exit(exitcode);
}

static int
parse_num(const char *str, const char *optname)
{
    char *end;
    int num;

    if (*str == '\0') {
	fprintf(stderr, "Empty value given for %s, must be an integer\n",
		optname);
	exit(1);
    }
    num = strtoul(str, &end, 0);
    if (*end != '\0') {
	fprintf(stderr, "Invalid value given for %s, must be an integer\n",
		optname);
	exit(1);
    }

    return num;
}

static void
parse_args(int argc, char *argv[])
{
    int argn;

    progname = argv[0];

    for (argn = 1; argn < argc; argn++) {
	int p = argn;

	if (argv[p][0] != '-')
	    break;

	if (strcmp(argv[p], "-h") == 0 || strcmp(argv[p], "--help") == 0)
	    usage(0);

	/* All options here down take a value. */
	argn++;
	if (strcmp(argv[p], "-d") == 0 || strcmp(argv[p], "--device") == 0) {
	    if (argn >= argc)
		goto no_parm;
	    devname = argv[argn];
	    continue;
	}
	if (strcmp(argv[p], "-n") == 0 || strcmp(argv[p], "--netfn") == 0) {
	    if (argn >= argc)
		goto no_parm;
	    netfn = parse_num(argv[argn], argv[p]);
	    continue;
	}
	if (strcmp(argv[p], "-c") == 0 || strcmp(argv[p], "--command") == 0) {
	    if (argn >= argc)
		goto no_parm;
	    cmd = parse_num(argv[argn], argv[p]);
	    continue;
	}

	fprintf(stderr, "Unknown option given: %s\n", argv[p]);
	usage(1);
    no_parm:
	fprintf(stderr, "Option %s must have a value\n", argv[p]);
	exit(1);
    }

    if (argn < argc) {
	fprintf(stderr, "This program takes only options, no parameters\n");
	exit(1);
    }

    if (netfn & 1) {
	fprintf(stderr, "The netfn must be an even number\n");
	exit(1);
    }
}

int
main(int argc, char *argv[])
{
    int fd, rv;
    struct ipmi_cmdspec cmdspec;

    parse_args(argc, argv);

    fd = open(devname, O_RDWR);
    if (fd == -1) {
	fprintf(stderr, "Error opening %s: %s\n", devname, strerror(errno));
	exit(1);
    }

    cmdspec.netfn = netfn;
    cmdspec.cmd = cmd;
    rv = ioctl(fd, IPMICTL_REGISTER_FOR_CMD, &cmdspec);
    if (rv == -1) {
	fprintf(stderr, "Error registering for command %2.2x:%2.2x: %s\n",
		netfn, cmd, strerror(errno));
	exit(1);
    }

    while (true) {
	fd_set readfds;
	struct ipmi_recv recv;
	struct ipmi_addr addr;
	struct ipmi_req resp;
	unsigned char data[IPMI_MAX_MSG_LENGTH];
	unsigned char rspdata[IPMI_MAX_MSG_LENGTH];
	unsigned int i;

	/* Wait for something. */
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	rv = select(fd + 1, &readfds, NULL, NULL, NULL);
	if (rv == -1) {
	    fprintf(stderr, "Error from select: %s\n", strerror(errno));
	    exit(1);
	}

	/* Receive the message. */
	recv.addr = (unsigned char *) &addr;
	recv.addr_len = sizeof(addr);
	recv.msg.data = data;
	recv.msg.data_len = sizeof(data);
	rv = ioctl(fd, IPMICTL_RECEIVE_MSG, &recv);
	if (rv == -1) {
	    fprintf(stderr, "Error receiving message: %s\n", strerror(errno));
	    continue;
	}

	if (recv.recv_type == IPMI_RESPONSE_RESPONSE_TYPE) {
	    /*
	     * This is a response to the response we sent.  Kind of
	     * weird sounding, but this lets the driver report errors
	     * in sending the response.
	     */
	    if (recv.msg.data_len < 1)
		fprintf(stderr,
			"Response response didn't contain a return code\n");
	    else if (recv.msg.data[0] != 0)
		fprintf(stderr,
			"Response response had an error: %2.2x\n",
			recv.msg.data[0]);
	    continue;
	}

	if (recv.recv_type != IPMI_CMD_RECV_TYPE) {
	    /*
	     * This should never happen, we haven't registered for events or 
	     * sent any commands to get responses for.
	     */
	    fprintf(stderr, "Got invalid message type: %d\n", recv.recv_type);
	    continue;
	}

	/* Got a valid message.  Print it. */
	printf("Got command %2.2x:%2.2x, data:", recv.msg.netfn, recv.msg.cmd);
	for (i = 0; i < recv.msg.data_len; i++) {
	    if ((i % 16) == 0)
		printf("\n ");
	    printf(" %2.2x", recv.msg.data[i]);
	}
	printf("\n");

	/* Send echo response back to the address we got it from. */
	resp.addr = recv.addr;
	resp.addr_len = recv.addr_len;
	resp.msgid = recv.msgid;
	resp.msg.netfn = recv.msg.netfn | 1; /* Set to a response. */
	resp.msg.cmd = recv.msg.cmd;
	/*
	 * All the strange finagling is is adding the error byte at
	 * the beginning of the response.
	 */
	if (recv.msg.data_len > sizeof(rspdata) - 1)
	    recv.msg.data_len = sizeof(rspdata) - 1;
	memcpy(rspdata + 1, recv.msg.data, recv.msg.data_len);
	rspdata[0] = 0;
	resp.msg.data = rspdata;
	resp.msg.data_len = recv.msg.data_len + 1;
	rv = ioctl(fd, IPMICTL_SEND_COMMAND, &resp);
	if (rv == -1)
	    fprintf(stderr, "Error sending response: %s\n", strerror(errno));
    }

    exit(0);
}
