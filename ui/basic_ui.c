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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_ui.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_conn.h>

#include <ucd-snmp/asn1.h>
#include <ucd-snmp/snmp_api.h>
#include <ucd-snmp/snmp.h>

static selector_t *selector;

ipmi_args_t *con_parms[2];
ipmi_con_t  *con[2];
int         last_con = 0;

void
ui_shutdown_main(void)
{
    int i;
    for (i=0; i<2; i++) {
	if (con_parms[i])
	    ipmi_free_args(con_parms[i]);
    }
}

/* This is used by the UI to reconnect after a connection has been
   disconnected. */
void
ui_reconnect(void)
{
    int        rv;
    int        i;

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
	
    rv = ipmi_init_domain(con, last_con, ipmi_ui_setup_done,
			  NULL, NULL, NULL);
    if (rv) {
	fprintf(stderr, "ipmi_init_domain: %s\n", strerror(rv));
	exit(1);
    }
}

#define IPMI_OID_SIZE 9
static oid ipmi_oid[IPMI_OID_SIZE] = {1,3,6,1,4,1,3183,1,1};
int snmp_input(int op,
	       struct snmp_session *session,
	       int reqid,
	       struct snmp_pdu *pdu,
	       void *magic)
{
    struct sockaddr_in *src_ip;
    uint32_t           specific;

    if (op != RECEIVED_MESSAGE)
	goto out;
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

    

 out:
    return 1;
}

static
int snmp_pre_parse(struct snmp_session *session, snmp_ipaddr from)
{
    return 1;
}

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

    snmp_sess_init(&session);
    session.peername = SNMP_DEFAULT_PEERNAME;
    session.version = SNMP_DEFAULT_VERSION;
    session.community_len = SNMP_DEFAULT_COMMUNITY_LEN;
    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;
    session.local_port = SNMP_TRAP_PORT;
    session.callback = snmp_input;
    session.callback_magic = NULL;
    session.authenticator = NULL;
    session.isAuthoritative = SNMP_SESS_UNKNOWNAUTH;

    snmp_session = snmp_open_ex(&session, snmp_pre_parse,
				NULL, NULL, NULL, NULL);
    if (snmp_session == NULL) {
        snmp_sess_perror("snmptrapd", &session);
	return -1;
    }

    ipmi_sel_set_read_fds_handler(sel,
				  snmp_add_read_fds,
				  snmp_check_read_fds,
				  snmp_check_timeout,
				  NULL);

    return 0;
}
    
int
main(int argc, const char *argv[])
{
    int              rv;
    int              curr_arg = 1;
    const char       *arg;
    int              full_screen = 1;
    ipmi_domain_id_t domain_id;
    int              i;
    int              init_snmp = 0;

    while ((curr_arg < argc) && (argv[curr_arg][0] == '-')) {
	arg = argv[curr_arg];
	curr_arg++;
	if (strcmp(arg, "--") == 0) {
	    break;
	} else if (strcmp(arg, "-c") == 0) {
	    full_screen = 0;
	} else if (strcmp(arg, "-dmem") == 0) {
	    DEBUG_MALLOC_ENABLE();
	} else if (strcmp(arg, "-dmsg") == 0) {
	    DEBUG_MSG_ENABLE();
	} else if (strcmp(arg, "-snmp") == 0) {
	    init_snmp = 1;
	} else {
	    fprintf(stderr, "Unknown option: %s\n", arg);
	    return 1;
	}
    }

    rv = ipmi_ui_init(&selector, full_screen);

    if (init_snmp) {
	if (snmp_init(selector) < 0)
	    return 1;
    }

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

    rv = ipmi_init_domain(con, last_con,
			  ipmi_ui_setup_done, NULL, NULL, &domain_id);
    if (rv) {
	fprintf(stderr, "ipmi_init_domain: %s\n", strerror(rv));
	goto out;
    }

    ipmi_ui_set_domain_id(domain_id);

    sel_select_loop(selector, NULL, 0, NULL);

 out:
    ipmi_ui_shutdown();

    if (rv)
	return 1;
    return 0;
}
