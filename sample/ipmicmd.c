/*
 * ipmicmd.c
 *
 * A test program that allows you to send messages on IPMI.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Note that F.Isabelle of Kontron did a significant amount of work on
 * this in the beginning, but not much is left of that work since it
 * has been redone to sit on top of the IPMI connections.
 *
 * Copyright 2002,2003 MontaVista Software Inc.
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


/* To use the program, run it, and you will receive a prompt.  Then enter
   ipmi commands.  Type "help" for more details. */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <popt.h> /* Option parsing made easy */

#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/mxp.h>

#include <OpenIPMI/ipmi_int.h>

void ipmi_oem_force_conn_init(void);
int ipmi_oem_motorola_mxp_init(void);

extern os_handler_t ipmi_ui_cb_handlers;

static char* sOp		= NULL;
static int   interactive        = 1;

struct poptOption poptOpts[]=
{
    {
	"command",
	'k',
	POPT_ARG_STRING,
	&sOp,
	'k',
	"Command string to be send",
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

selector_t *ui_sel;
static ipmi_con_t *con;

/* We cobbled everything in the next section together to provide the
   things that the low-level handlers need. */
void
ipmi_write_lock()
{
}

void
ipmi_write_unlock()
{
}

void
ipmi_read_lock()
{
}

void
ipmi_read_unlock()
{
}

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
ui_vlog(char *format, enum ipmi_log_type_e log_type, va_list ap)
{
    vfprintf(stderr, format, ap);
}

void
ipmi_report_lock_error(os_handler_t *handler, char *str)
{
}

void
ipmi_check_lock(ipmi_lock_t *lock, char *str)
{
}

void
ipmi_register_ll(ll_ipmi_t *ll)
{
}

struct ipmi_lock_s
{
    os_hnd_lock_t *ll_lock;
    os_handler_t  *os_hnd;
};
int
ipmi_create_lock_os_hnd(os_handler_t *os_hnd, ipmi_lock_t **new_lock)
{
    ipmi_lock_t *lock;
    int         rv;

    lock = ipmi_mem_alloc(sizeof(*lock));
    if (!lock)
	return ENOMEM;

    lock->os_hnd = os_hnd;
    if (lock->os_hnd && lock->os_hnd->create_lock) {
	rv = lock->os_hnd->create_lock(lock->os_hnd, &(lock->ll_lock));
	if (rv) {
	    ipmi_mem_free(lock);
	    return rv;
	}
    } else {
	lock->ll_lock = NULL;
    }

    *new_lock = lock;

    return 0;
}

int
ipmi_create_global_lock(ipmi_lock_t **new_lock)
{
    ipmi_lock_t *lock;
    int         rv;

    lock = ipmi_mem_alloc(sizeof(*lock));
    if (!lock)
	return ENOMEM;

    lock->os_hnd = &ipmi_ui_cb_handlers;
    if (lock->os_hnd && lock->os_hnd->create_lock) {
	rv = lock->os_hnd->create_lock(lock->os_hnd, &(lock->ll_lock));
	if (rv) {
	    ipmi_mem_free(lock);
	    return rv;
	}
    } else {
	lock->ll_lock = NULL;
    }

    *new_lock = lock;

    return 0;
}

void ipmi_lock(ipmi_lock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->lock(lock->os_hnd, lock->ll_lock);
}

void ipmi_unlock(ipmi_lock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->unlock(lock->os_hnd, lock->ll_lock);
}

void ipmi_destroy_lock(ipmi_lock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->destroy_lock(lock->os_hnd, lock->ll_lock);
    ipmi_mem_free(lock);
}

static void
real_quit(selector_t *sel, sel_timer_t *timer, void *data)
{
    int rv = (int)(*(int *)data);
    sel_free_timer(timer);
    if (con && con->close_connection) 
	con->close_connection(con);
    if (ui_sel)
	sel_free_selector(ui_sel);
    exit(rv);
}

void
leave(int ret)
{
    int               rv;
    sel_timer_t *timer = NULL;
    struct timeval    timeout;
    static int ret_code;

    ret_code = ret;
    rv = sel_alloc_timer(ui_sel, real_quit, &ret_code, &timer);
    if (rv) {
	/* Cannot allocate timer, exit anyway */
        if (ui_sel)
	    sel_free_selector(ui_sel);
	exit(1);
    }

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    rv = sel_start_timer(timer, &timeout);
    if (rv) {
	sel_free_timer(timer);
        if (ui_sel)
	    sel_free_selector(ui_sel);
	exit(1);
    }
}

void printInfo( )
{
    printf("ipmicmd\n");
    printf("This little utility is an ipmi command tool ;-)\n");
    printf("It can be used to send commands to an IPMI interface\n");
    printf("It uses popt for command line parsing, type -? for usage info.\n");
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
	case IPMI_LAN_ADDR_TYPE:
	    return "lan";
	default:
	    return "UNKNOWN";
    }
}

void
dump_msg_data(ipmi_msg_t *msg, ipmi_addr_t *addr, char *type)
{
    ipmi_system_interface_addr_t *smi_addr = NULL;
    int                          i;
    ipmi_ipmb_addr_t             *ipmb_addr = NULL;
    ipmi_lan_addr_t              *lan_addr = NULL;

    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	smi_addr = (struct ipmi_system_interface_addr *) addr;
    } else if ((addr->addr_type == IPMI_IPMB_ADDR_TYPE)
	       || (addr->addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE))
    {
	ipmb_addr = (struct ipmi_ipmb_addr *) addr;
    } else if (addr->addr_type == IPMI_LAN_ADDR_TYPE) {
	lan_addr = (struct ipmi_lan_addr *) addr;
    }

    if (interactive)
    {
	printf("Got message:\n");
	printf("  type      = %s\n", type);
	printf("  addr_type = %s\n", get_addr_type(addr->addr_type));
	printf("  channel   = 0x%x\n", addr->channel);
	if (smi_addr)
	    printf("  lun       = 0x%x\n", smi_addr->lun);
	else if (ipmb_addr)
	    printf("    slave addr = %x,%x\n",
		   ipmb_addr->slave_addr,
		   ipmb_addr->lun);
	else if (lan_addr)
	    printf("    lan addr = %x,%x,%x,%x\n",
		   lan_addr->session_handle,
		   lan_addr->remote_SWID,
		   lan_addr->local_SWID,
		   lan_addr->lun);
	printf("  netfn     = 0x%x\n", msg->netfn);
	printf("  cmd       = 0x%x\n", msg->cmd);
	printf("  data      =");
    }
    else 
    {
	if (smi_addr)
	{
	    printf("%2.2x %2.2x %2.2x %2.2x ",
		   addr->channel,
		   msg->netfn,
		   smi_addr->lun,
		   msg->cmd);
	}
	else
	{
	    printf("%2.2x %2.2x %2.2x %2.2x ",
		   addr->channel,
		   msg->netfn,
		   ipmb_addr->lun,
		   msg->cmd);
	}
    }

    for (i=0; i<msg->data_len; i++) {
	if (((i%16) == 0) && (i != 0)) {
	    printf("\n             ");
	}
	printf("%2.2x ", msg->data[i]);
    }
    printf("\n");
}

void
cmd_handler(ipmi_con_t   *ipmi,
	    ipmi_addr_t  *addr,
	    unsigned int addr_len,
	    ipmi_msg_t   *cmd,
	    long         sequence,
	    void         *data1,
	    void         *data2,
	    void         *data3)
{
    dump_msg_data(cmd, addr, "command");
    printf("Command sequence = 0x%lx\n", sequence);
}

void
rsp_handler(ipmi_con_t   *ipmi,
	    ipmi_addr_t  *addr,
	    unsigned int addr_len,
	    ipmi_msg_t   *rsp,
	    void         *data1,
	    void         *data2,
	    void         *data3,
	    void         *data4)
{
    dump_msg_data(rsp, addr, "response");
    if (!interactive) {
    	ipmi->close_connection(ipmi);
	leave(0);
    }
}

void
event_handler(ipmi_con_t   *ipmi,
	      ipmi_addr_t  *addr,
	      unsigned int addr_len,
	      ipmi_msg_t   *event,
	      void         *data1,
	      void         *data2)
{
    dump_msg_data(event, addr, "event");
}

typedef struct timed_data_s
{
    ipmi_con_t     *con;
    struct timeval start_time;
    ipmi_msg_t     msg;
    unsigned char  data[MAX_IPMI_DATA_SIZE];
    ipmi_addr_t    addr;
    unsigned int   addr_len;
    unsigned int   count;
    unsigned int   total_count;
} timed_data_t;

void
timed_rsp_handler(ipmi_con_t   *con,
		  ipmi_addr_t  *addr,
		  unsigned int addr_len,
		  ipmi_msg_t   *rsp,
		  void         *data1,
		  void         *data2,
		  void         *data3,
		  void         *data4)
{
    timed_data_t *data = data1;

    if (data->count == 0) {
	unsigned long  diff;
	struct timeval end_time;

	gettimeofday(&end_time, NULL);
	diff = (((end_time.tv_sec - data->start_time.tv_sec) * 1000000)
		+ (end_time.tv_usec - data->start_time.tv_usec));
	printf("Time was %fus per msg, %ldus total\n",
	       ((float) diff) / ((float)(data->total_count)),
	       diff);
	free(data);
    } else {
	int rv;

	rv = con->send_command(data->con,
			       &data->addr,
			       data->addr_len,
			       &data->msg,
			       timed_rsp_handler,
			       data, NULL, NULL, NULL);
	data->count--;
	if (rv) {
	    printf("Error sending command: %x\n", rv);
	    free(data);
	}
    }
}

void
time_msgs(ipmi_con_t    *con,
	  ipmi_msg_t    *msg,
	  ipmi_addr_t   *addr,
	  unsigned int  addr_len,
	  unsigned long count)
{
    timed_data_t *data;
    int          rv;

    data = malloc(sizeof(*data));
    if (!data) {
	printf("No memory to perform command\n");
	return;
    }

    data->con = con;
    gettimeofday(&data->start_time, NULL);
    data->count = 0;
    memcpy(&data->msg, msg, sizeof(data->msg));
    memcpy(data->data, msg->data, msg->data_len);
    data->msg.data = data->data;
    memcpy(&data->addr, addr, addr_len);
    data->addr_len = addr_len;
    data->count = count;
    data->total_count = count;

    rv = con->send_command(data->con,
			   &data->addr,
			   data->addr_len,
			   &data->msg,
			   timed_rsp_handler,
			   data, NULL, NULL, NULL);
    data->count--;
    if (rv) {
	printf("Error sending command: %x\n", rv);
	free(data);
    }
}

int
process_input_line(char *buf)
{
    char               *strtok_data;
    char               *endptr;
    char               *v = strtok_r(buf, " \t\r\n,.\"", &strtok_data);
    int                pos = 0;
    int                start;
    ipmi_addr_t        addr;
    unsigned int       addr_len;
    ipmi_msg_t         msg;
    char               outbuf[MAX_IPMI_DATA_SIZE];
    int                rv = 0;
    short              channel;
    unsigned char      seq = 0;
    unsigned int       time_count = 0;
    int                lan_addr = 0;

    if (v == NULL)
	return -1;

    if (strcmp(v, "help") == 0) {
	printf("Commands are:\n");
	printf("  regcmd <netfn> <cmd> - Register to receive this cmd\n");
	printf("  unregcmd <netfn> <cmd> - Unregister to receive this cmd\n");
	printf("  help - This help\n");
	printf("  0f <lun> <netfn> <cmd> <data.....> - send a command\n");
	printf("      to the local BMC\n");
	printf("  <channel> [ipmb] <dest addr> <lun> <netfn> <cmd> <data...> -\n");
	printf("      send an IPMB command on the channel.\n");
	printf("  <channel> lan <handle> <remote swid> <local swid> <lun> <netfn> <cmd> <data...> -\n");
	printf("      send a command on a LAN channel.\n");
	printf("  <channel> 00 <dest addr> <lun> <netfn> <cmd> <data...> -\n");
	printf("      broadcast a command on the channel.\n");
	printf("  test_lat <count> <command> - Send the command and wait for\n"
	       "      the response <count> times and measure the average\n"
	       "      time.\n");
	return 0;
    }

    if (strcmp(v, "quit") == 0) {
	leave(0);
	return 0;
    }

    if (strcmp(v, "regcmd") == 0) {
	unsigned char netfn, cmd;
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
	if (!v) {
	    printf("No netfn for regcmd\n");
	    return -1;
	}
	netfn = strtoul(v, &endptr, 16);
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
	if (!v) {
	    printf("No cmd for regcmd\n");
	    return -1;
	}
	cmd = strtoul(v, &endptr, 16);

	rv = con->register_for_command(con, netfn, cmd,
				       cmd_handler, NULL, NULL, NULL);
	if (rv) {
	    fprintf(stderr, "Could not set to get receive command: %x\n", rv);
	    return -1;
	}
	return 0;
    }

    if (strcmp(v, "unregcmd") == 0) {
	unsigned char netfn, cmd;
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
	if (!v) {
	    printf("No netfn for regcmd\n");
	    return -1;
	}
	netfn = strtoul(v, &endptr, 16);
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
	if (!v) {
	    printf("No cmd for regcmd\n");
	    return -1;
	}
	cmd = strtoul(v, &endptr, 16);
	
	rv = con->deregister_for_command(con, netfn, cmd);
	if (rv) {
	    printf("Could not set to get receive command: %x", rv);
	    return -1;
	}
	return 0;
    }

    if (strcmp(v, "test_lat") == 0) {
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
	if (!v) {
	    printf("No count for test_lat\n");
	    return -1;
	}
	time_count = strtoul(v, &endptr, 16);

	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
    }

    if (strcmp(v, "lan") == 0) {
	lan_addr = 1;
	v = strtok_r(NULL, " \t\r\n,.", &strtok_data);
    } else if (strcmp(v, "ipmb") == 0) {
	lan_addr = 0;
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
	struct ipmi_system_interface_addr *si = (void *) &addr;
	if ((pos-start) < 1) {
	    printf("No IPMB address specified\n");
	    return -1;
	}
	si->lun = outbuf[start]; start++;
	msg.netfn = outbuf[start]; start++;
	si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si->channel = IPMI_BMC_CHANNEL;
	addr_len = sizeof(*si);
    } else if (lan_addr) {
	struct ipmi_lan_addr *lan = (void *) &addr;

	if ((pos-start) < 3) {
	    printf("No LAN address specified\n");
	    return -1;
	}

	lan->addr_type = IPMI_LAN_ADDR_TYPE;
	lan->channel = channel;
	lan->session_handle = outbuf[start]; start++;
	lan->remote_SWID = outbuf[start]; start++;
	lan->local_SWID = outbuf[start]; start++;
	lan->lun = outbuf[start]; start++;
	msg.netfn = outbuf[start]; start++;
	addr_len = sizeof(*lan);
    } else {
	struct ipmi_ipmb_addr *ipmb = (void *) &addr;

	if ((pos-start) < 2) {
	    printf("No IPMB address specified\n");
	    return -1;
	}

	if (outbuf[start] == 0) {
	    ipmb->addr_type = IPMI_IPMB_BROADCAST_ADDR_TYPE;
	    start++;
	} else {
	    ipmb->addr_type = IPMI_IPMB_ADDR_TYPE;
	}
	ipmb->slave_addr = outbuf[start]; start++;
	ipmb->channel = channel;
	ipmb->lun = outbuf[start]; start++;
	msg.netfn = outbuf[start]; start++;
	addr_len = sizeof(*ipmb);
    }

    if (msg.netfn & 1) {
	if ((pos-start) < 1) {
	    printf("No sequence for response\n");
	    return -1;
	}

	seq = outbuf[start]; start++;
    }

    if ((pos-start) < 1) {
	printf("Message too short\n");
	return -1;
    }

    msg.cmd = outbuf[start]; start++;
    msg.data = &(outbuf[start]);
    msg.data_len = pos-start;
    if (time_count) {
	time_msgs(con, &msg, &addr, addr_len, time_count);
	rv = 0;
    } else {
	if (msg.netfn & 1)
	    rv = con->send_response(con, &addr, addr_len, &msg, seq);
	else
	    rv = con->send_command(con, &addr, addr_len, &msg, rsp_handler,
				   NULL, NULL, NULL, NULL);
	if (rv) {
	    printf("Error sending command: %x\n", rv);
	}
    }

    return(rv);
}

static char input_line[256];
static int pos = 0;

static void
user_input_ready(int fd, void *data)
{
    int count = read(0, input_line+pos, 255-pos);
    int i, j;

    if (count < 0) {
	perror("input read");
    	con->close_connection(con);
	leave(1);
    }
    if (count == 0) {
	if( interactive)
	    printf("\n"); 
    	con->close_connection(con);
	leave(0);
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
	if (interactive)
	    printf("=> ");
	fflush(stdout);
    }
}

char buf[256];

static void
con_changed_handler(ipmi_con_t   *ipmi,
		    int          err,
		    unsigned int port_num,
		    int          still_connected,
		    void         *cb_data)
{
    if (!interactive) {
	if (err) {
	    fprintf(stderr, "Unable to setup connection: %x\n", err);
	    leave(1);
	}
	process_input_line(buf);
    } else {
	if (err)
	    fprintf(stderr, "Connection failed to port %d: %x\n", port_num,
		    err);
	else
	    fprintf(stderr, "Connection up to port %d\n", port_num);
	if (!still_connected)
	    fprintf(stderr, "All connection to the BMC are down\n");
    }
}

int
main(int argc, const char *oargv[])
{
    int         rv;
    int         pos;
    int         o;
    char        *bufline = NULL;
    int         curr_arg;
    ipmi_args_t *args;
    const char  **argv;


    poptContext poptCtx = poptGetContext("ipmicmd", argc, oargv,poptOpts,0);

    while (( o = poptGetNextOpt(poptCtx)) >= 0)
    {   
	switch( o )
	{
	    case 'k':
		strcpy( buf, poptGetOptArg(poptCtx) );
		bufline = buf;
		interactive = 0;
		break;

	    case 'v':
		printInfo();
		leave(0);
		break;

	    default:
		poptPrintUsage(poptCtx, stderr, 0);
		leave(1);
		break;
	}
    }

    argv = poptGetArgs(poptCtx);

    if (!argv) {
	fprintf(stderr, "Not enough arguments\n");
	leave(1);
    }

    for (argc=0; argv[argc]!= NULL; argc++)
	;

    if (argc < 1) {
	fprintf(stderr, "Not enough arguments\n");
	leave(1);
    }

    /* Initialize the OEM handlers. */
    rv = _ipmi_conn_init();
    if (rv) {
	fprintf(stderr, "Error initializing connections: 0x%x\n", rv);
	leave(1);
    }
    ipmi_oem_force_conn_init();
    ipmi_oem_motorola_mxp_init();


    curr_arg = 0;

    rv = sel_alloc_selector(&ui_sel);
    if (rv) {
	fprintf(stderr, "Could not allocate selector\n");
	leave(1);
    }

    rv = ipmi_parse_args(&curr_arg, argc, argv, &args);
    if (rv) {
	fprintf(stderr, "Error parsing command arguments, argument %d: %s\n",
		curr_arg, strerror(rv));
	leave(1);
    }

    rv = ipmi_args_setup_con(args,
			     &ipmi_ui_cb_handlers,
			     ui_sel,
			     &con);
    if (rv) {
        fprintf(stderr, "ipmi_ip_setup_con: %s", strerror(rv));
	leave(1);
    }

    if (interactive) {
	rv = con->register_for_events(con, event_handler, NULL, NULL, NULL);
	if (rv) {
	    fprintf(stderr, "Could not set to get events: %x\n", rv);
	}

	sel_set_fd_handlers(ui_sel, 0, NULL, user_input_ready, NULL, NULL);
	sel_set_fd_read_handler(ui_sel, 0, SEL_FD_HANDLER_ENABLED);
    }

    con->set_con_change_handler(con, con_changed_handler, NULL);

    rv = con->start_con(con);
    if (rv) {
	fprintf(stderr, "Could not start connection: %x\n", rv);
	leave(1);
    }

    pos = 0;
    if (interactive)
	printf("=> ");
    fflush(stdout);

    sel_select_loop(ui_sel, NULL, 0, NULL);

    return rv;
}
