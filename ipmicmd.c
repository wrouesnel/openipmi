/*
 * ipmicmd.c
 *
 * A test program that allows you to send messages on IPMI.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
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


/* To use the program, run it, and you will receive a prompt.  Then enter
   ipmi commands.

   Commands are entered in two formats:

   0x0f <netfn> <lun> <cmd> <data....>
     - This will send messages to the BMC directly.

   <channel> <slave addr> <slave lun> <netfn> <lun> <cmd> <data....>
     - This will send messages on an IPMB channel.

   <channel> 00 <slave addr> <slave lun> <netfn> <lun> <cmd> <data....>
     - This will send broadcast messages on an IPMB channel.

   There's no support for anything but IPMB channels and the direct BMC
   interface right now.
*/



/*** DESCRIPTION SECTION *****************************************************
*
*  File Name:     ipmicmd.c
*  Creation Date: 2002-10-10 10:00
*  Programmer:    F.Isabelle
*  Description:   ipmicmd , user space command line tool for ipmi commands
*
*
*  This file as been renamed to ipmicmd.c in order to implement a command similar
*   to ipmitool or ipmi_ctl, able to run non-interactively.
*
*   ipmicmd is going to be use in that way:
*
*   ipmicmd -k "0x0f <netfn> <lun> <cmd> <data...>" or
*  or 
*   ipmicmd -k "<channel> <slave addr> <slave lun> <netfn> <lun> <cmd> <data...> or"
*   
*
*
*****************************************************************************/
/*** PVCS LOG SECTION ********************************************************
*
* $Log: not supported by cvs2svn $
* Revision 1.1  2003/02/21 16:11:20  cminyard
* Added ipmicmd to this code.
* Moved to the newest kernel headers.
**
 * 
 *    Rev 1.5   16 Oct 2002 09:20:36   Isabellf
 *  - make it work with patch v7 of the driver
 * 
 *    Rev 1.4   10 Oct 2002 16:44:08   Isabellf
 *   - added exit status for process_input_line to avoid stalls
 * 
 *    Rev 1.2   10 Oct 2002 10:30:52   Isabellf
 *  - added command line parsing initial support
 * 
 *    Rev 1.1   10 Oct 2002 10:10:46   Isabellf
 *   - started modification to non - interactive tool
*
*****************************************************************************/


#include <linux/ipmi.h>


#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <popt.h> /* Option parsing made easy */

static char* sOp		= NULL;
static int   interactive        = 1;

struct poptOption poptOpts[]=
{
    {
	"kcs",
	'k',
	POPT_ARG_STRING,
	&sOp,
	'k',
	"Command string to be send",
	""
    },
    {
	"interactive",
	'I',
	POPT_ARG_NONE,
	NULL,
	'I',
	"Set in interactive mode",
	""
    },
    {
	"slaveaddr",
	's',
	POPT_ARG_STRING,
	NULL,
	's',
	"Set the slave address for this KCS",
	""
    },
    {
	"version",
	'v',
	POPT_ARG_NONE,
	NULL,
	'v',
	"Display version info about the program",
	NULL
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

int ipmi_fd;
int curr_seq = 0;


void printInfo( )
{
    printf( "ipmicmd\t$,$Date: 2003-03-05 15:42:34 $,$Author: cminyard $\n");
    printf( "Kontron Canada Inc.\n");
    printf( "-\n");
    printf( "This little utility is an ipmi command tool ;-)\n");
    printf( "It can be used to send commands to an IPMI interface\n");
    printf( "It uses popt for command line parsing, type -? for usage info.\n");
    printf("Enjoy!\n");
}

char *
get_addr_type(int type)
{
    switch (type)
    {
	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
	    return "SI";
	case IPMI_IPMB_ADDR_TYPE:
	    return "ipmb";
	case IPMI_IPMB_BROADCAST_ADDR_TYPE:
	    return "ipmb broadcast";
	default:
	    return "UNKNOWN";
    }
}

void
got_data(int fd)
{
    struct ipmi_recv      rsp;
    struct ipmi_addr      addr;
    unsigned char         data[40];
    int                   rv;
    int                   i;
    struct ipmi_system_interface_addr *smi_addr = NULL;
    struct ipmi_ipmb_addr *ipmb_addr = NULL;

    rsp.addr = (char *) &addr;
    rsp.addr_len = sizeof(addr);
    rsp.msg.data = data;
    rsp.msg.data_len = sizeof(data);

    rv = ioctl(fd, IPMICTL_RECEIVE_MSG_TRUNC, &rsp);
    if (rv == -1) {
	printf("Error receiving message: %s\n", strerror(errno));
	if (errno != EMSGSIZE)
	    return;
    }

    if (addr.addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	smi_addr = (struct ipmi_system_interface_addr *) &addr;
    } else if ((addr.addr_type == IPMI_IPMB_ADDR_TYPE)
	       || (addr.addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE))
    {
	ipmb_addr = (struct ipmi_ipmb_addr *) &addr;
    }

    if (interactive)
    {
	printf("Got message:\n");
	printf("  type      = %d\n", rsp.recv_type);
	printf("  addr_type = %s\n", get_addr_type(addr.addr_type));
	printf("  channel   = 0x%x\n", addr.channel);
	if (smi_addr)
	    printf("  lun       = 0x%x\n", smi_addr->lun);
	else if (ipmb_addr)
	    printf("    slave addr = %x,%x\n",
		   ipmb_addr->slave_addr,
		   ipmb_addr->lun);
	printf("  msgid     = %ld\n", rsp.msgid);
	printf("  netfn     = 0x%x\n", rsp.msg.netfn);
	printf("  cmd       = 0x%x\n", rsp.msg.cmd);
	printf("  data      =");
    }
    else 
    {
	if (smi_addr)
	{
	    printf("%2.2x %2.2x %2.2x %2.2x ",
		   addr.channel,
		   rsp.msg.netfn,
		   smi_addr->lun,
		   rsp.msg.cmd);
	}
	else
	{
	    printf("%2.2x %2.2x %2.2x %2.2x ",
		   addr.channel,
		   rsp.msg.netfn,
		   ipmb_addr->lun,
		   rsp.msg.cmd);
	}
    }

    for (i=0; i<rsp.msg.data_len; i++) {
	if (((i%16) == 0) && (i != 0)) {
	    printf("\n             ");
	}
	printf("%2.2x ", data[i]);
    }
    printf("\n");
}

void
time_msgs(struct ipmi_req *req, unsigned long count)
{
    struct timeval   start_time, end_time;
    int              i;
    fd_set           rset;
    struct ipmi_recv rsp;
    unsigned long    diff;
    int              rv;
    struct ipmi_addr addr;
    char             data[30];

    gettimeofday(&start_time, NULL);
    for (i=0; i<count; i++) {
	rv = ioctl(ipmi_fd, IPMICTL_SEND_COMMAND, req);
	if (rv == -1) {
	    printf("Error sending command: %s\n", strerror(errno));
	    return;
	}

	FD_ZERO(&rset);
	FD_SET(ipmi_fd, &rset);
	rv = select(ipmi_fd+1, &rset, NULL, NULL, NULL);
	if (rv == -1) {
	    printf("Error from select: %s\n", strerror(errno));
	    return;
	}

	rsp.addr = (unsigned char *) &addr;
	rsp.addr_len = sizeof(addr);
	rsp.msg.data = data;
	rsp.msg.data_len = sizeof(data);
	rv = ioctl(ipmi_fd, IPMICTL_RECEIVE_MSG, &rsp);
	if (rv == -1) {
	    printf("Error receiving response: %s\n", strerror(errno));
	    return;
	}
    }
    gettimeofday(&end_time, NULL);
    diff = (((end_time.tv_sec - start_time.tv_sec) * 1000000)
	    + (end_time.tv_usec - start_time.tv_usec));
    printf("Time was %fus per msg, %ldus total\n",
	   ((float) diff) / ((float)(count)),
	   diff);
}


int
process_input_line(char *buf)
{
    char               *strtok_data;
    char               *endptr;
    char               *v = strtok_r(buf, " \t\r\n,.\"", &strtok_data);
    int                               pos = 0;
    int                               start;
    struct ipmi_req                   req;
    struct ipmi_ipmb_addr             ipmb_addr;
    struct ipmi_system_interface_addr bmc_addr;
    char                              outbuf[40];
    int                               rv = 0;
    short                             channel;
    unsigned long                     time_count = 0;

    if (v == NULL)
	return -1;

    if (strcmp(v, "help") == 0) {
	printf("Commands are:\n");
	printf("  regcmd <netfn> <cmd> - Register to receive this cmd\n");
	printf("  unregcmd <netfn> <cmd> - Unregister to receive this cmd\n");
	printf("  help - This help\n");
	printf("  0f <netfn> <lun> <cmd> <data.....> - send a command\n");
	printf("      to the local BMC\n");
	printf("  <channel> <dest addr> <dest lun> <netfn> <cmd> <data...> -\n");
	printf("      send a command on the channel.\n");
	printf("  <channel> 00 <dest addr> <dest lun> <netfn> <cmd> <data...> -\n");
	printf("      broadcast a command on the channel.\n");
	printf("  test_lat <count> <command> - Send the command and wait for\n"
	       "      the response <count> times and measure the average\n"
	       "      time.\n");
	return 0;
    }

    if (strcmp(v, "regcmd") == 0) {
	struct ipmi_cmdspec spec;
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
	if (!v) {
	    printf("No netfn for regcmd\n");
	    return -1;
	}
	spec.netfn = strtoul(v, &endptr, 16);
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
	if (!v) {
	    printf("No cmd for regcmd\n");
	    return -1;
	}
	spec.cmd = strtoul(v, &endptr, 16);
	
	rv = ioctl(ipmi_fd, IPMICTL_REGISTER_FOR_CMD, &spec);
	if (rv) {
	    perror("Could not set to get receive command:");
	    return -1;
	}
	return 0;
    }

    if (strcmp(v, "unregcmd") == 0) {
	struct ipmi_cmdspec spec;
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
	if (!v) {
	    printf("No netfn for regcmd\n");
	    return -1;
	}
	spec.netfn = strtoul(v, &endptr, 16);
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
	if (!v) {
	    printf("No cmd for regcmd\n");
	    return -1;
	}
	spec.cmd = strtoul(v, &endptr, 16);
	
	rv = ioctl(ipmi_fd, IPMICTL_UNREGISTER_FOR_CMD, &spec);
	if (rv) {
	    perror("Could not set to get receive command:");
	    return -1;
	}
	return 0;
    }

    if (strcmp(v, "test_lat") == 0) {
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
	if (!v) {
	    printf("No netfn for regcmd\n");
	    return -1;
	}
	time_count = strtoul(v, &endptr, 16);

	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
    }

    while (v != NULL) {
	if (pos >= sizeof(outbuf)) {
	    printf("Message too long");
	    return -1;
	}

	outbuf[pos] = strtoul(v, &endptr, 16);
	if (*endptr != '\0') {
	    printf("Value %d was invalid\n", pos+1);
	    return -1;
	}
	pos++;
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
    }

    start = 0;
    channel = outbuf[start]; start++;

    if (channel == IPMI_BMC_CHANNEL) {
	if ((pos-start) < 1) {
	    printf("No IPMB address specified\n");
	    return -1;
	}
	req.msg.netfn = outbuf[start]; start++;
	bmc_addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	bmc_addr.channel = IPMI_BMC_CHANNEL;
	bmc_addr.lun = outbuf[start]; start++;
	req.addr = (char *) &bmc_addr;
	req.addr_len = sizeof(bmc_addr);
    } else {
	if ((pos-start) < 2) {
	    printf("No IPMB address specified\n");
	    return -1;
	}

	if (outbuf[start] == 0) {
	    ipmb_addr.addr_type = IPMI_IPMB_BROADCAST_ADDR_TYPE;
	    start++;
	} else {
	    ipmb_addr.addr_type = IPMI_IPMB_ADDR_TYPE;
	}
	ipmb_addr.slave_addr = outbuf[start]; start++;
	ipmb_addr.lun = outbuf[start]; start++;
	req.msg.netfn = outbuf[start]; start++;
	ipmb_addr.channel = channel;
	req.addr = (char *) &ipmb_addr;
	req.addr_len = sizeof(ipmb_addr);
    }

    if ((pos-start) < 1) {
	printf("Message too short\n");
	return -1;
    }

    req.msgid = curr_seq;
    req.msg.cmd = outbuf[start]; start++;
    req.msg.data = &(outbuf[start]);
    req.msg.data_len = pos-start;
    if (time_count) {
	time_msgs(&req, time_count);
    } else {
	rv = ioctl(ipmi_fd, IPMICTL_SEND_COMMAND, &req);
	if (rv == -1) {
	    printf("Error sending command: %s\n", strerror(errno));
	}
    }
    curr_seq++;

    return(rv);
   
}

static int
ipmi_open(void)
{
    int ipmi_fd;

    ipmi_fd = open("/dev/ipmidev/0", O_RDWR);
    if (ipmi_fd == -1) {
	ipmi_fd = open("/dev/ipmi/0", O_RDWR);
	if (ipmi_fd == -1) {
	    ipmi_fd = open("/dev/ipmi0", O_RDWR);
	    if (ipmi_fd == -1) {
		perror("Could not open ipmi device /dev/ipmidev/0 or /dev/ipmi0");
		exit(1);
	    }
	}
    }

    return ipmi_fd;
}

int
main(int argc, const char *argv[])
{
    int    i, j;
    fd_set readfds;
    int    err;
    char   input_line[256];
    int    pos;
    int    o;
    char   *bufline = NULL;
    char   buf[256];
    unsigned int slave_addr = 0;


    poptContext poptCtx = poptGetContext("ipmicmd", argc, argv,poptOpts,0);

    while (( o = poptGetNextOpt(poptCtx)) >= 0)
    {   
	switch( o )
	{
	    case 'I':
		interactive = 1;
		break;

	    case 'k':
		strcpy( buf, poptGetOptArg(poptCtx) );
		bufline = buf;
		interactive = 0;
		break;

	    case 's':
		slave_addr = strtoul(poptGetOptArg(poptCtx), NULL, 0);
		break;

	    case 'v':
		printInfo();
		exit(0);
		break;

	    default:
		poptPrintUsage(poptCtx, stderr, 0);
		exit(1);
		break;
	}
    }

    ipmi_fd = ipmi_open();

    if (slave_addr) {
	err = ioctl(ipmi_fd, IPMICTL_SET_MY_ADDRESS_CMD, &slave_addr);
	if (err) {
	    perror("Could not set slave address");
	    exit(1);
	}
    }

    if (interactive) {
	err = ioctl(ipmi_fd, IPMICTL_GET_MY_ADDRESS_CMD, &slave_addr);
	if (err) {
	    perror("Could not get slave address");
	    exit(1);
	}

	printf("My slave address is: 0x%2.2x\n", slave_addr);

	i = 1;
	err = ioctl(ipmi_fd, IPMICTL_SET_GETS_EVENTS_CMD, &i);
	if (err) {
	    perror("Could not set to get events");
	    exit(1);
	}
    } else {
	if (process_input_line(buf))
	    exit(1);
    }

    pos = 0;
    if (interactive)
	printf("=> ");
    fflush(stdout);
    for (;;)
    {
	FD_ZERO(&readfds);
	if (interactive)
	    FD_SET(0, &readfds);
	FD_SET(ipmi_fd, &readfds);
	err = select(ipmi_fd+1, &readfds, NULL, NULL, NULL);
	if (err == -1) {
	    perror("select");
	    continue;
	}

	if (FD_ISSET(ipmi_fd, &readfds)) {
	    got_data(ipmi_fd);
	    
	    if (interactive)
		continue; 
	    else
		break;
	}
	    
	if (FD_ISSET(0, &readfds)) {
	    int count = read(0, input_line+pos, 255-pos);

	    if (count < 0) {
		perror("input read");
		continue;
	    }
	    if (count == 0) {
		break;
	    }

	    for (i=0; count > 0; i++, count--) {
		if ((input_line[pos] == '\n') || (input_line[pos] == '\r'))
		{
		    input_line[pos] = '\0';
		    process_input_line(input_line);
		    for (j=0; j<count; j++)
			input_line[j] = input_line[j+pos];
		    pos = 0;
		    if( interactive )
			printf("=> "); 
		    fflush(stdout);
		} else {
		    pos++;
		}
	    }

	    if (pos >= 255) {
		printf("Input line too long\n");
		pos = 0;
		if ( interactive )
		    printf("=> ");
		fflush(stdout);
	    }
	}
    }

    if( interactive)
	printf("\n"); 
    return 0;
}
