/*
 * ipmish.c
 *
 * MontaVista IPMI basic UI to use the main UI code.
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/ipmi_cmdlang.h>

#ifdef HAVE_UCDSNMP
# ifdef HAVE_NETSNMP
#  include <net-snmp/net-snmp-config.h>
#  include <net-snmp/net-snmp-includes.h>
# elif defined(HAVE_ALT_UCDSNMP_DIR)
#  include <ucd-snmp/asn1.h>
#  include <ucd-snmp/snmp_api.h>
#  include <ucd-snmp/snmp.h>
# else
#  include <asn1.h>
#  include <snmp_api.h>
#  include <snmp.h>
# endif
#endif

void
posix_vlog(char *format,
	   enum ipmi_log_type_e log_type,
	   va_list ap)
{
    int do_nl = 1;

    switch(log_type) {
    case IPMI_LOG_INFO:
	printf("INFO: ");
	break;

    case IPMI_LOG_WARNING:
	printf("WARN: ");
	break;

    case IPMI_LOG_SEVERE:
	printf("SEVR: ");
	break;

    case IPMI_LOG_FATAL:
	printf("FATL: ");
	break;

    case IPMI_LOG_ERR_INFO:
	printf("EINF: ");
	break;

    case IPMI_LOG_DEBUG_START:
	do_nl = 0;
	/* FALLTHROUGH */
    case IPMI_LOG_DEBUG:
	printf("DEBG: ");
	break;

    case IPMI_LOG_DEBUG_CONT:
	do_nl = 0;
	/* FALLTHROUGH */
    case IPMI_LOG_DEBUG_END:
	break;
    }

    vprintf(format, ap);
    if (do_nl)
	printf("\n");
}

#ifdef HAVE_UCDSNMP
#define IPMI_OID_SIZE 9
static oid ipmi_oid[IPMI_OID_SIZE] = {1,3,6,1,4,1,3183,1,1};
int snmp_input(int op,
	       struct snmp_session *session,
	       int reqid,
	       struct snmp_pdu *pdu,
	       void *magic)
{
    struct sockaddr_in   *src_ip;
    uint32_t             specific;
    struct variable_list *var;

#ifdef HAVE_NETSNMP
    if (op != NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE)
	goto out;
#else
    if (op != RECEIVED_MESSAGE)
	goto out;
#endif
    if (pdu->command != SNMP_MSG_TRAP)
	goto out;
    if (snmp_oid_compare(ipmi_oid, IPMI_OID_SIZE,
			 pdu->enterprise, pdu->enterprise_length)
	!= 0)
    {
	goto out;
    }
    if (pdu->trap_type != SNMP_TRAP_ENTERPRISESPECIFIC)
	goto out;

    src_ip = (struct sockaddr_in *) &pdu->agent_addr;
    specific = pdu->specific_type;

    var = pdu->variables;
    if (var == NULL)
	goto out;
    if (var->type != ASN_OCTET_STR)
	goto out;
    if (snmp_oid_compare(ipmi_oid, IPMI_OID_SIZE, var->name, var->name_length)
	!= 0)
    {
	goto out;
    }
    if (var->val_len < 46)
	goto out;
    
    ipmi_handle_snmp_trap_data(src_ip,
		    	       sizeof(*src_ip),
			       IPMI_EXTERN_ADDR_IP,
			       specific,
			       var->val.string,
			       var->val_len);

 out:
    return 1;
}

#ifdef HAVE_NETSNMP
static int
snmp_pre_parse(netsnmp_session * session, netsnmp_transport *transport,
	       void *transport_data, int transport_data_length)
{
    return 1;
}
#else
static int
snmp_pre_parse(struct snmp_session *session, snmp_ipaddr from)
{
    return 1;
}
#endif

struct snmp_session *snmp_session;

void snmp_add_read_fds(selector_t     *sel,
		       int            *num_fds,
		       fd_set         *fdset,
		       struct timeval *timeout,
		       int            *timeout_invalid,
		       void           *cb_data)
{
    snmp_select_info(num_fds, fdset, timeout, timeout_invalid);
}

void snmp_check_read_fds(selector_t *sel,
			 fd_set     *fds,
			 void       *cb_data)
{
    snmp_read(fds);
}

void snmp_check_timeout(selector_t *sel,
			void       *cb_data)
{
    snmp_timeout();
}

int
snmp_init(selector_t *sel)
{
    struct snmp_session session;
#ifdef HAVE_NETSNMP
    netsnmp_transport *transport = NULL;
    static char *snmp_default_port = "udp:162";

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
			   NETSNMP_DS_LIB_MIB_ERRORS,
			   0);

    init_snmp("ipmish");

    transport = netsnmp_tdomain_transport(snmp_default_port, 1, "udp");
    if (!transport) {
        snmp_sess_perror("ipmish", &session);
	return -1;
    }
#else
    void *transport = NULL;
#endif
    snmp_sess_init(&session);
    session.peername = SNMP_DEFAULT_PEERNAME;
    session.version = SNMP_DEFAULT_VERSION;
    session.community_len = SNMP_DEFAULT_COMMUNITY_LEN;
    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;
    session.local_port = SNMP_TRAP_PORT;
    session.callback = snmp_input;
    session.callback_magic = transport;
    session.authenticator = NULL;
    session.isAuthoritative = SNMP_SESS_UNKNOWNAUTH;

#ifdef HAVE_NETSNMP
    snmp_session = snmp_add(&session, transport, snmp_pre_parse, NULL);
#else
    snmp_session = snmp_open_ex(&session, snmp_pre_parse,
				NULL, NULL, NULL, NULL);
#endif
    if (snmp_session == NULL) {
        snmp_sess_perror("ipmish", &session);
	return -1;
    }

    ipmi_sel_set_read_fds_handler(sel,
				  snmp_add_read_fds,
				  snmp_check_read_fds,
				  snmp_check_timeout,
				  NULL);

    return 0;
}
#endif /* HAVE_UCDSNMP */

static int done = 0;
typedef struct out_data_s
{
    FILE *stream;
    int  indent;
} out_data_t;

static void
out_value(ipmi_cmdlang_t *info, char *name, char *value)
{
    out_data_t *out_data = info->user_data;

    if (value)
	fprintf(out_data->stream, "%*s%s: %s\n", out_data->indent*2, "",
		name, value);
    else
	fprintf(out_data->stream, "%*s%s\n", out_data->indent*2, "", name);
    fflush(out_data->stream);
}

static void
out_binary(ipmi_cmdlang_t *info, char *name, char *value, unsigned int len)
{
    out_data_t *out_data = info->user_data;
    unsigned char *data = (unsigned char *) value;
    int indent2 = (out_data->indent * 2) + strlen(name) + 1;
    int i;

    fprintf(out_data->stream, "%*s%s:", out_data->indent*2, "", name);
    for (i=0; i<len; i++) {
	if ((i != 0) && ((i % 8) == 0))
	    fprintf(out_data->stream, "\n%*s", indent2, "");
	fprintf(out_data->stream, " 0x%2.2x", data[i]);
    }
    fprintf(out_data->stream, "\n");
    
    fflush(out_data->stream);
}

static void
out_unicode(ipmi_cmdlang_t *info, char *name, char *value, unsigned int len)
{
    out_data_t *out_data = info->user_data;

    fprintf(out_data->stream, "%*s%s: %s\n", out_data->indent*2, "",
	    name, "Unicode!");
    fflush(out_data->stream);
}

void
down_level(ipmi_cmdlang_t *info)
{
    out_data_t *out_data = info->user_data;

    out_data->indent++;
}

void
up_level(ipmi_cmdlang_t *info)
{
    out_data_t *out_data = info->user_data;

    out_data->indent--;
}

void cmd_done(ipmi_cmdlang_t *info);

static out_data_t lout_data =
{
    .stream = NULL,
    .indent = 0,
};
static char cmdlang_objstr[IPMI_MAX_NAME_LEN];
static ipmi_cmdlang_t cmdlang =
{
    .out = out_value,
    .out_binary = out_binary,
    .out_unicode = out_unicode,
    .down = down_level,
    .up = up_level,
    .done = cmd_done,

    .os_hnd = NULL,
    .selector = NULL,

    .user_data = &lout_data,

    .objstr = cmdlang_objstr,
    .objstr_len = sizeof(cmdlang_objstr),
};

void
cmd_done(ipmi_cmdlang_t *info)
{
    out_data_t *out_data = info->user_data;

    if (info->err) {
	if (!info->location)
	    info->location = "";
	if (strlen(info->objstr) == 0) {
	    fprintf(out_data->stream, "error: %s: %s (0x%x)\n",
		    info->location, info->errstr,
		    info->err);
	} else {
	    fprintf(out_data->stream, "error: %s %s: %s (0x%x)\n",
		    info->location, info->objstr, info->errstr,
		    info->err);
	}
	if (info->errstr_dynalloc)
	    ipmi_mem_free(info->errstr);
	info->errstr_dynalloc = 0;
	info->errstr = NULL;
	info->location = NULL;
	info->objstr[0] = '\0';
	info->err = 0;
    }

    fputs("> ", out_data->stream);
    sel_set_fd_read_handler(info->selector, 0, SEL_FD_HANDLER_ENABLED);
    out_data->indent = 0;
    fflush(out_data->stream);
}


void
ipmi_cmdlang_global_err(char *objstr,
			char *location,
			char *errstr,
			int  errval)
{
    if (objstr)
	fprintf(stderr, "global error: %s %s: %s (0x%x)", location, objstr,
		errstr, errval);
    else
	fprintf(stderr, "global error: %s: %s (0x%x)", location,
		errstr, errval);
}

void
ipmi_cmdlang_report_event(ipmi_cmdlang_event_t *event)
{
    unsigned int level;
    char         *name, *value;

    ipmi_cmdlang_event_restart(event);
    printf("Event\n");
    while (ipmi_cmdlang_event_next_field(event, &level, &name, &value)) {
	if (value)
	    printf("  %*s%s: %s\n", level*2, "", name, value);
	else
	    printf("  %*s%s\n", level*2, "", name);
    }
}

static char *line_buffer;
static int  line_buffer_max = 0;
static int  line_buffer_pos = 0;

void
user_input_ready(int fd, void *data)
{
    ipmi_cmdlang_t *info = data;
    out_data_t *out_data = info->user_data;
    char rc;
    int  count;
    int  i;

    count = read(fd, &rc, 1);
    if (count <= 0) {
	done = 1;
	return;
    }

    switch(rc) {
    case 0x04: /* ^d */
	fputs("\n", out_data->stream);
	done = 1;
	break;

    case '\r': case '\n':
	if (line_buffer) {
	    fputs("\n", out_data->stream);
	    line_buffer[line_buffer_pos] = '\0';
	    for (i=0; isspace(line_buffer[i]); i++)
		;
	    /* Ignore blank lines. */
	    if (line_buffer[i] != '\0') {
		/* Turn off input processing. */
		sel_set_fd_read_handler(info->selector, 0,
					SEL_FD_HANDLER_DISABLED);

		cmdlang.err = 0;
		cmdlang.errstr = NULL;
		cmdlang.errstr_dynalloc = 0;
		cmdlang.location = NULL;
		ipmi_cmdlang_handle(&cmdlang, line_buffer);
		line_buffer_pos = 0;
	    } else {
		fputs("> ", out_data->stream);
	    }
	} else {
	    fputs("\n> ", out_data->stream);
	}
	break;

    case '\b': case 0x7f: /* backspace */
	if (line_buffer_pos > 0) {
	    line_buffer_pos--;
	    fputs("\b \b", out_data->stream);
	}
	break;

    default:
	if (line_buffer_pos >= line_buffer_max) {
	    char *new_line = ipmi_mem_alloc(line_buffer_max+10+1);
	    if (!new_line)
		break;
	    line_buffer_max += 10;
	    if (line_buffer) {
		memcpy(new_line, line_buffer, line_buffer_pos);
		ipmi_mem_free(line_buffer);
	    }
	    line_buffer = new_line;
	}
	line_buffer[line_buffer_pos] = rc;
	line_buffer_pos++;
	putc(rc, out_data->stream);
	break;
    }

    fflush(out_data->stream);
}

static int term_setup;
//static int old_flags;
struct termios old_termios;

static void
setup_term(os_handler_t *os_hnd, selector_t *sel)
{
    struct termios new_termios;

    tcgetattr(0, &old_termios);
    new_termios = old_termios;
    new_termios.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
			     |INLCR|IGNCR|ICRNL|IXON);
    new_termios.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    tcsetattr(0, TCSADRAIN, &new_termios);
    //old_flags = fcntl(0, F_GETFL) & O_ACCMODE;
    //	fcntl(0, F_SETFL, old_flags | O_NONBLOCK);
    term_setup = 1;

    lout_data.stream = stdout;

    cmdlang.os_hnd = os_hnd;
    cmdlang.selector = sel;

    sel_set_fd_handlers(sel, 0, &cmdlang, user_input_ready, NULL, NULL, NULL);
    sel_set_fd_read_handler(sel, 0, SEL_FD_HANDLER_ENABLED);
}

static void
cleanup_term(os_handler_t *os_hnd, selector_t *sel)
{
    if (!term_setup)
	return;

    tcsetattr(0, TCSADRAIN, &old_termios);
    //fcntl(0, F_SETFL, old_flags);
    tcdrain(0);
    term_setup = 0;
    if (line_buffer) {
	ipmi_mem_free(line_buffer);
	line_buffer = NULL;
    }
    sel_clear_fd_handlers(sel, 0);
}

static void
exit_cmd(ipmi_cmd_info_t *cmd_info)
{
    done = 1;
}

static void
setup_cmds(void)
{
    int rv;

    rv = ipmi_cmdlang_reg_cmd(NULL,
			      "exit",
			      "leave the program",
			      exit_cmd, NULL, NULL);
    if (rv) {
	fprintf(stderr, "Error adding exit command: 0x%x\n", rv);
	exit(1);
    }
}

static void
domain_down(void *cb_data)
{
    int *count = cb_data;
    (*count)--;
}

static void
shutdown_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    int *count = cb_data;
    int rv;

    rv = ipmi_close_connection(domain, domain_down, cb_data);
    if (!rv)
	(*count)++;
}


int
main(int argc, const char *argv[])
{
    int              rv;
    int              curr_arg = 1;
    const char       *arg;
    int              full_screen = 1;
#ifdef HAVE_UCDSNMP
    int              init_snmp = 0;
#endif
    os_handler_t     *os_hnd;
    selector_t       *sel;


    while ((curr_arg < argc) && (argv[curr_arg][0] == '-')) {
	arg = argv[curr_arg];
	curr_arg++;
	if (strcmp(arg, "--") == 0) {
	    break;
	} else if (strcmp(arg, "-c") == 0) {
	    full_screen = 0;
	} else if (strcmp(arg, "-dlock") == 0) {
	    DEBUG_LOCKS_ENABLE();
	} else if (strcmp(arg, "-dmem") == 0) {
	    DEBUG_MALLOC_ENABLE();
	} else if (strcmp(arg, "-drawmsg") == 0) {
	    DEBUG_RAWMSG_ENABLE();
	} else if (strcmp(arg, "-dmsg") == 0) {
	    DEBUG_MSG_ENABLE();
#ifdef HAVE_UCDSNMP
	} else if (strcmp(arg, "-snmp") == 0) {
	    init_snmp = 1;
#endif
	} else {
	    fprintf(stderr, "Unknown option: %s\n", arg);
	    return 1;
	}
    }

    os_hnd = ipmi_posix_setup_os_handler();
    if (!os_hnd) {
	fprintf(stderr, "ipmi_smi_setup_con: Unable to allocate os handler\n");
	return 1;
    }

    sel = ipmi_posix_os_handler_get_sel(os_hnd);

    /* Initialize the OpenIPMI library. */
    ipmi_init(os_hnd);

#ifdef HAVE_UCDSNMP
    if (init_snmp) {
	if (snmp_init(sel) < 0)
	    return 1;
    }
#endif

    rv = ipmi_cmdlang_init();
    if (rv) {
	fprintf(stderr, "Unable to initialize command processor: 0x%x\n", rv);
	return 1;
    }

    setup_cmds();

    setup_term(os_hnd, sel);

    printf("> ");
    fflush(stdout);

    while (!done)
	os_hnd->perform_one_op(os_hnd, NULL);

    cleanup_term(os_hnd, sel);

    /* Shut down all existing domains. */
    
    done = 0;
    ipmi_domain_iterate_domains(shutdown_domain_handler, &done);
    while (done)
	os_hnd->perform_one_op(os_hnd, NULL);

    ipmi_cmdlang_cleanup();
    ipmi_shutdown();

    os_hnd->free_os_handler(os_hnd);

    /* Make sure a mem log always comes out, if we have that enabled. */
    ipmi_mem_alloc(10);

    ipmi_debug_malloc_cleanup();

    if (rv)
	return 1;
    return 0;
}
