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
#include <netdb.h>
#include <errno.h>
#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_ui.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_int.h>

static selector_t *selector;

enum con_type_e { SMI, LAN, LAN2 };

/* SMI parms. */

/* LAN parms. */
typedef struct con_parms_s
{
    enum con_type_e con_type;

    int             smi_intf;

    struct in_addr  lan_addr[2];
    int             lan_port[2];
    int             num_addr;
    int             authtype;
    int             privilege;
    char            username[17];
    char            password[17];
} con_parms_t;

con_parms_t con_parms[2];
int         last_con = 0;

/* This is used by the UI to reconnect after a connection has been
   disconnected. */
void ui_reconnect(void)
{
    int        rv;
    ipmi_con_t *con[2];
    int        i;

    for (i=0; i<=last_con; i++) {
	if (con_parms[i].con_type == SMI) {
	    rv = ipmi_smi_setup_con(con_parms[i].smi_intf,
				    &ipmi_ui_cb_handlers, selector,
				    &con[i]);
	    if (rv) {
		fprintf(stderr, "ipmi_smi_setup_con: %s\n", strerror(rv));
		exit(1);
	    }
	} else if (con_parms[last_con].con_type == LAN) {
	    rv = ipmi_lan_setup_con(con_parms[i].lan_addr,
				    con_parms[i].lan_port,
				    con_parms[i].num_addr,
				    con_parms[i].authtype,
				    con_parms[i].privilege,
				    con_parms[i].username,
				    strlen(con_parms[i].username),
				    con_parms[i].password,
				    strlen(con_parms[i].password),
				    &ipmi_ui_cb_handlers, selector,
				    &con[i]);
	    if (rv) {
		fprintf(stderr, "ipmi_lan_setup_con: %s", strerror(rv));
		exit(1);
	    }
	}
    }
	
    rv = ipmi_init_domain(con, last_con+1, ipmi_ui_setup_done,
			  NULL, NULL, NULL);
    if (rv) {
	fprintf(stderr, "ipmi_init_domain: %s\n", strerror(rv));
	exit(1);
    }
}
    
int
main(int argc, char *argv[])
{
    int        rv;
    int        curr_arg = 1;
    char       *arg;
    int        full_screen = 1;
    ipmi_con_t *con[2];

    while ((argc > 1) && (argv[curr_arg][0] == '-')) {
	arg = argv[curr_arg];
	curr_arg++;
	argc--;
	if (strcmp(arg, "--") == 0) {
	    break;
	} else if (strcmp(arg, "-c") == 0) {
	    full_screen = 0;
	} else if (strcmp(arg, "-dmem") == 0) {
	    DEBUG_MALLOC_ENABLE();
	} else if (strcmp(arg, "-dmsg") == 0) {
	    DEBUG_MSG_ENABLE();
	} else {
	    fprintf(stderr, "Unknown option: %s\n", arg);
	    return 1;
	}
    }

    argc--;

    if (argc < 1) {
	fprintf(stderr, "Not enough arguments\n");
	exit(1);
    }

    rv = ipmi_ui_init(&selector, full_screen);

 next_con:
    if (strcmp(argv[curr_arg], "smi") == 0) {
	con_parms[last_con].con_type = SMI;

	argc--;
	curr_arg++;
	if (argc < 1) {
	    fprintf(stderr, "Not enough arguments\n");
	    exit(1);
	}

	con_parms[last_con].smi_intf = atoi(argv[curr_arg]);
	rv = ipmi_smi_setup_con(con_parms[last_con].smi_intf,
				&ipmi_ui_cb_handlers, selector,
				&con[last_con]);
	if (rv) {
	    fprintf(stderr, "ipmi_smi_setup_con: %s\n", strerror(rv));
	    exit(1);
	}

    } else if (strcmp(argv[curr_arg], "lan") == 0) {
	struct hostent *ent;

	argc--;
	curr_arg++;

	con_parms[last_con].con_type = LAN;
	con_parms[last_con].num_addr = 1;

	if (argc < 6) {
	    fprintf(stderr, "Not enough arguments\n");
	    exit(1);
	}

	ent = gethostbyname(argv[curr_arg]);
	if (!ent) {
	    fprintf(stderr, "gethostbyname failed: %s\n", strerror(h_errno));
	    exit(1);
	}
	curr_arg++;
	argc--;
	memcpy(&con_parms[last_con].lan_addr[0],
	       ent->h_addr_list[0],
	       ent->h_length);
	con_parms[last_con].lan_port[0] = atoi(argv[curr_arg]);
	curr_arg++;
	argc--;

    doauth:
	if (strcmp(argv[curr_arg], "none") == 0) {
	    con_parms[last_con].authtype = IPMI_AUTHTYPE_NONE;
	} else if (strcmp(argv[curr_arg], "md2") == 0) {
	    con_parms[last_con].authtype = IPMI_AUTHTYPE_MD2;
	} else if (strcmp(argv[curr_arg], "md5") == 0) {
	    con_parms[last_con].authtype = IPMI_AUTHTYPE_MD5;
	} else if (strcmp(argv[curr_arg], "straight") == 0) {
	    con_parms[last_con].authtype = IPMI_AUTHTYPE_STRAIGHT;
	} else if (con_parms[last_con].num_addr == 1) {
	    if (argc < 8) {
		fprintf(stderr, "Not enough arguments\n");
		exit(1);
	    }

	    con_parms[last_con].num_addr++;
	    ent = gethostbyname(argv[curr_arg]);
	    if (!ent) {
		fprintf(stderr, "gethostbyname failed: %s\n",
			strerror(h_errno));
		rv = EINVAL;
		goto out;
	    }
	    curr_arg++;
	    argc--;
	    memcpy(&con_parms[last_con].lan_addr[1],
		   ent->h_addr_list[0],
		   ent->h_length);
	    con_parms[last_con].lan_port[1] = atoi(argv[curr_arg]);
	    curr_arg++;
	    argc--;
	    goto doauth;
	} else {
	    fprintf(stderr, "Invalid authtype: %s\n", argv[curr_arg]);
	    rv = EINVAL;
	    goto out;
	}
	curr_arg++;
	argc--;

	if (strcmp(argv[curr_arg], "callback") == 0) {
	    con_parms[last_con].privilege = IPMI_PRIVILEGE_CALLBACK;
	} else if (strcmp(argv[curr_arg], "user") == 0) {
	    con_parms[last_con].privilege = IPMI_PRIVILEGE_USER;
	} else if (strcmp(argv[curr_arg], "operator") == 0) {
	    con_parms[last_con].privilege = IPMI_PRIVILEGE_OPERATOR;
	} else if (strcmp(argv[curr_arg], "admin") == 0) {
	    con_parms[last_con].privilege = IPMI_PRIVILEGE_ADMIN;
	} else {
	    fprintf(stderr, "Invalid privilege: %s\n", argv[curr_arg]);
	    rv = EINVAL;
	    goto out;
	}
	curr_arg++;
	argc--;

	memset(con_parms[last_con].username, 0,
	       sizeof(con_parms[last_con].username));
	memset(con_parms[last_con].password, 0,
	       sizeof(con_parms[last_con].password));
	strncpy(con_parms[last_con].username, argv[curr_arg], 16);
	con_parms[last_con].username[16] = '\0';
	curr_arg++;
	argc--;
	strncpy(con_parms[last_con].password, argv[curr_arg], 16);
	con_parms[last_con].password[16] = '\0';
	curr_arg++;
	argc--;

	rv = ipmi_lan_setup_con(con_parms[last_con].lan_addr,
				con_parms[last_con].lan_port,
				con_parms[last_con].num_addr,
				con_parms[last_con].authtype,
				con_parms[last_con].privilege,
				con_parms[last_con].username,
				strlen(con_parms[last_con].username),
				con_parms[last_con].password,
				strlen(con_parms[last_con].password),
				&ipmi_ui_cb_handlers, selector,
				&con[last_con]);
	if (rv) {
	    fprintf(stderr, "ipmi_lan_setup_con: %s\n", strerror(rv));
	    rv = EINVAL;
	    goto out;
	}
    } else {
	fprintf(stderr, "Invalid mode\n");
	rv = EINVAL;
	goto out;
    }

printf("****%d, %d\n", argc, curr_arg);

    if (argc > 0) {
	if (last_con == 1) {
	    fprintf(stderr, "Too many connections\n");
	    rv = EINVAL;
	    goto out;
	}
	    
	last_con++;
	goto next_con;
    }

    rv = ipmi_init_domain(con, last_con+1,
			  ipmi_ui_setup_done, NULL, NULL, NULL);
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
