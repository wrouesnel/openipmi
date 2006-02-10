/*
 * basic_ui.c
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


#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_ui.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_debug.h>

#include <OpenIPMI/internal/ipmi_malloc.h>

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

/* This is here because the POSIX library requires it, but we only
   pull the posix library to get the selector code, so this is not
   used. */
void
posix_vlog(char *format,
	   enum ipmi_log_type_e log_type,
	   va_list ap)
{
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

    init_snmp("ipmi_ui");

    transport = netsnmp_tdomain_transport(snmp_default_port, 1, "udp");
    if (!transport) {
        snmp_sess_perror("ipmi_ui", &session);
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
        snmp_sess_perror("ipmi_ui", &session);
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
    
int
main(int argc, char *argv[])
{
    int              rv;
    int              curr_arg = 1;
    const char       *arg;
    int              full_screen = 1;
    ipmi_domain_id_t domain_id;
    int              i;
#ifdef HAVE_UCDSNMP
    int              init_snmp = 0;
#endif
    ipmi_args_t      *con_parms[2];
    ipmi_con_t       *con[2];
    int              last_con = 0;
    selector_t       *selector;



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

    rv = ipmi_ui_init(&selector, full_screen);

#ifdef HAVE_UCDSNMP
    if (init_snmp) {
	if (snmp_init(selector) < 0)
	    goto out;
    }
#endif

 next_con:
    rv = ipmi_parse_args(&curr_arg, argc, argv, &con_parms[last_con]);
    if (rv) {
	fprintf(stderr, "Error parsing command arguments, argument %d: %s\n",
		curr_arg, strerror(rv));
	exit(1);
    }
    last_con++;

    if (curr_arg < argc) {
	if (last_con == 2) {
	    fprintf(stderr, "Too many connections\n");
	    rv = EINVAL;
	    goto out;
	}
	goto next_con;
    }

    for (i=0; i<last_con; i++) {
	rv = ipmi_args_setup_con(con_parms[i],
				 &ipmi_ui_cb_handlers,
				 selector,
				 &con[i]);
	if (rv) {
	    fprintf(stderr, "ipmi_ip_setup_con: %s", strerror(rv));
	    exit(1);
	}
    }

    for (i=0; i<last_con; i++)
	ipmi_free_args(con_parms[i]);

    rv = ipmi_open_domain("first", con, last_con, ipmi_ui_setup_done,
			  NULL, NULL, NULL, NULL, 0, &domain_id);
    if (rv) {
	fprintf(stderr, "ipmi_init_domain: %s\n", strerror(rv));
	goto out;
    }

    sel_select_loop(selector, NULL, 0, NULL);

 out:
    ipmi_ui_shutdown();

    if (rv)
	return 1;
    return 0;
}
