/*
 * test1.c
 *
 * OpenIPMI test code
 *
 * Author: Intel Corporation
 *         Jeff Zheng <Jeff.Zheng@Intel.com>
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
#include <malloc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_sel.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_int.h>

/* This sample application demostrates a very simple method to use
   OpenIPMI. It just search all sensors in the system.  From this
   application, you can find that there is only 4 lines code in main()
   function if you use the SMI-only interface, and several simple
   callback functions in all cases. */

extern os_handler_t ipmi_ui_cb_handlers;
selector_t *ui_sel;

/* This is connection information.  This is for flexibility in dealing
   with the different types of conenction and parameters.  In
   particular, LAN connections are very complex.  If you only need SMI
   connections, things are much simpler. */
enum con_type_e { SMI, LAN };
static enum con_type_e con_type;

/* SMI parms. */
static int smi_intf;

/* LAN parms. */
static struct in_addr lan_addr;
static int            lan_port;
static int            authtype = 0;
static int            privilege = 0;
static char           username[17];
static char           password[17];

static char *progname;

static void
usage(void)
{
    printf("Usage:\n"
	   "  %s [options] smi <smi #>\n"
	   "     Make a connection to a local system management interface.\n"
	   "     smi # is generally 0.\n"
	   "  %s [options] lan <host> <port> <authtype> <privilege> <username> <password>\n"
	   "     Make a connection to a IPMI 1.5 LAN interface.\n"
	   "     Host and port specify where to connect to (port is\n"
	   "     generally 623).  authtype is none, md2, md5, or straight.\n"
	   "     privilege is callback, user, operator, or admin.  The\n"
	   "     username and password must be provided if the authtype is\n"
	   "     not none.\n", progname, progname);
}

/* Whenever the status of a sensor changes, the function is called
   We display the information of the sensor if we find a new sensor
*/
static void
sensor_change(enum ipmi_update_e op,
	      ipmi_entity_t      *ent,
	      ipmi_sensor_t      *sensor,
	      void               *cb_data)
{
    int id, instance;
    char name[33];

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_id(sensor, name, 32);
    if ( op == IPMI_ADDED ) 
	printf("Sensor added: %d.%d.%s\n", id, instance, name);
}

/* Whenever the status of an entity changes, the function is called
   When a new entity is created, we search all sensors that belong 
   to the entity */
static void
entity_change(enum ipmi_update_e op,
	      ipmi_domain_t      *domain,
	      ipmi_entity_t      *entity,
	      void               *cb_data)
{
    int rv;
    int id, instance;

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    if (op == IPMI_ADDED) {
	    printf("Entity added: %d.%d\n", id, instance);
	    /* Register callback so that when the status of a
	       sensor changes, sensor_change is called */
	    rv = ipmi_entity_set_sensor_update_handler(entity,
						       sensor_change,
						       entity);
	    if (rv) {
		printf("ipmi_entity_set_sensor_update_handler: 0x%x", rv);
		exit(1);
	    }
    }
}

/* After we have established connection to domain, this function get called
   At this time, we can do whatever things we want to do. Herr we want to
   search all entities in the system */ 
void
setup_done(ipmi_domain_t *domain,
	   int           err,
	   unsigned int  conn_num,
	   unsigned int  port_num,
	   int           still_connected,
	   void          *user_data)
{
    int rv;

    /* Register a callback functin entity_change. When a new entities 
       is created, entity_change is called */
    rv = ipmi_domain_set_entity_update_handler(domain, entity_change, domain);
    if (rv) 
	printf("ipmi_domain_iterate_entities return error\n");
}

int
main(int argc, char *argv[])
{
    int        rv;
    int        curr_arg = 1;
    ipmi_con_t *con;

    progname = argv[0];

    /* Create selector first. */
    sel_alloc_selector(&ui_sel);

    /* Initialize the OpenIPMI library. ipmi_ui_cb_handler is an OS
       OS handler */
    ipmi_init(&ipmi_ui_cb_handlers);

#if 0
    /* If all you need is an SMI connection, this is all the code you
       need. */
    /* Establish connections to domain through system interface.  This
       function connect domain, selector and OS handler together.
       When there is response message from domain, the status of file
       descriptor in selector is changed and predefined callback is
       called. After the connection is established, setup_done will be
       called. */
    rv = ipmi_smi_setup_con(0, &ipmi_ui_cb_handlers, ui_sel, &con);
    if (rv) {
	printf("ipmi_smi_setup_con", rv);
	exit(1);
    }
#endif

#if 1
    /* The following code does complex argument parsing to allow LAN
       and SMI connections, and to allow specifying passwords,
       etc. for LAN connections. */
    while ((argc > 1) && (argv[curr_arg][0] == '-')) {
	char *arg = argv[curr_arg];
	curr_arg++;
	argc--;
	if (strcmp(arg, "--") == 0) {
	    break;
	} else if (strcmp(arg, "-dmem") == 0) {
	    DEBUG_MALLOC_ENABLE();
	} else if (strcmp(arg, "-dmsg") == 0) {
	    DEBUG_MSG_ENABLE();
	} else {
	    fprintf(stderr, "Unknown option: %s\n", arg);
	    usage();
	    return 1;
	}
    }

    if (argc < 2) {
	fprintf(stderr, "Not enough arguments\n");
	usage();
	exit(1);
    }

    if (strcmp(argv[curr_arg], "smi") == 0) {
	con_type = SMI;

	if (argc < 3) {
	    fprintf(stderr, "Not enough arguments\n");
	    usage();
	    exit(1);
	}

	smi_intf = atoi(argv[curr_arg+1]);
	rv = ipmi_smi_setup_con(smi_intf,
				&ipmi_ui_cb_handlers, ui_sel,
				&con);
	if (rv) {
	    fprintf(stderr, "ipmi_smi_setup_con: %s\n", strerror(rv));
	    exit(1);
	}

    } else if (strcmp(argv[curr_arg], "lan") == 0) {
	struct hostent *ent;

	con_type = LAN;

	if (argc < 6) {
	    fprintf(stderr, "Not enough arguments\n");
	    usage();
	    exit(1);
	}

	ent = gethostbyname(argv[curr_arg+1]);
	if (!ent)
	    fprintf(stderr, "gethostbyname failed: %s\n", strerror(h_errno));

	memcpy(&lan_addr, ent->h_addr_list[0], ent->h_length);
	lan_port = atoi(argv[curr_arg+2]);

	if (strcmp(argv[curr_arg+3], "none") == 0) {
	    authtype = IPMI_AUTHTYPE_NONE;
	} else if (strcmp(argv[curr_arg+3], "md2") == 0) {
	    authtype = IPMI_AUTHTYPE_MD2;
	} else if (strcmp(argv[curr_arg+3], "md5") == 0) {
	    authtype = IPMI_AUTHTYPE_MD5;
	} else if (strcmp(argv[curr_arg+3], "straight") == 0) {
	    authtype = IPMI_AUTHTYPE_STRAIGHT;
	} else {
	    fprintf(stderr, "Invalid authtype: %s\n", argv[curr_arg+3]);
	    usage();
	    exit(1);
	}

	if (strcmp(argv[curr_arg+4], "callback") == 0) {
	    privilege = IPMI_PRIVILEGE_CALLBACK;
	} else if (strcmp(argv[curr_arg+4], "user") == 0) {
	    privilege = IPMI_PRIVILEGE_USER;
	} else if (strcmp(argv[curr_arg+4], "operator") == 0) {
	    privilege = IPMI_PRIVILEGE_OPERATOR;
	} else if (strcmp(argv[curr_arg+4], "admin") == 0) {
	    privilege = IPMI_PRIVILEGE_ADMIN;
	} else {
	    fprintf(stderr, "Invalid privilege: %s\n", argv[curr_arg+4]);
	    usage();
	    exit(1);
	}

	if (authtype == IPMI_AUTHTYPE_NONE) {
	    username[0] = '\0';
	    password[0] = '\0';
	} else {
	    if (argc < 8) {
		fprintf(stderr, "Username and password not provided\n");
		usage();
		exit(1);
	    }

	    memset(username, 0, sizeof(username));
	    memset(password, 0, sizeof(password));
	    strncpy(username, argv[curr_arg+5], 16);
	    username[16] = '\0';
	    strncpy(password, argv[curr_arg+6], 16);
	    password[16] = '\0';
	}

	rv = ipmi_lan_setup_con(&lan_addr, &lan_port, 1,
				authtype, privilege,
				username, strlen(username),
				password, strlen(password),
				&ipmi_ui_cb_handlers, ui_sel,
				&con);
	if (rv) {
	    fprintf(stderr, "ipmi_lan_setup_con: %s", strerror(rv));
	    exit(1);
	}
    } else {
	fprintf(stderr, "Invalid mode\n");
	usage();
	exit(1);
    }
#endif

    rv = ipmi_init_domain(&con, 1, setup_done, NULL, NULL, NULL);
    if (rv) {
	fprintf(stderr, "ipmi_init_domain: %s\n", strerror(rv));
	exit(1);
    }

    /* This is the main loop of the event-driven program. 
       Try <CTRL-C> to exit the program */ 
#if 1
    /* We run the select loop here, this shows how you can use
       sel_select.  You could add your own processing in this loop. */
    while (1) {
	sel_select(ui_sel, NULL, 0, NULL, NULL);
    }
#else
    /* Let the selector code run the select loop. */
    sel_select_loop(ui_sel, NULL, 0, NULL);
#endif
}

void
ui_vlog(char *format, enum ipmi_log_type_e log_type, va_list ap)
{
    int do_nl = 1;

    switch(log_type)
    {
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
