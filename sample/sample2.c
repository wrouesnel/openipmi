/*
 * sample.c
 *
 * OpenIPMI sample code
 *
 * Author: MontaVista Software
 *         Corey Minyard <cminyard@mvista.com>
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

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/selector.h>

/* This sample application demostrates a very simple method to use
   OpenIPMI. It just searchs all controlss in the system.  From this
   application, you can find that there is only 4 lines code in main()
   function if you use the SMI-only interface, and several simple
   callback functions in all cases. */

extern os_handler_t ipmi_ui_cb_handlers;
selector_t *ui_sel;

static const char *progname;

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

int entity_id;
int entity_instance;
const char *control_name;

ipmi_domain_id_t domain_id;
int leaving = 0;

void
leave_done(void *cb_data)
{
    exit(0);
}

void
leave2(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_close_connection(domain, leave_done, NULL);
}

void
leave(void)
{
    leaving = 1;
    ipmi_domain_pointer_cb(domain_id, leave2, NULL);
}

void got_val(ipmi_control_t *control,
	     int            err,
	     int            *val,
	     void           *cb_data)
{
    int i;
    int count;

    if (err) {
	printf("Error reading values\n");
	exit(1);
    }

    count = ipmi_control_get_num_vals(control);
    printf("Value:");
    for (i=0; i<count; i++) {
	printf(" %d", val[i]);
    }
    printf("\n");

    leave();
}

void got_id(ipmi_control_t *control,
	    int            err,
	    unsigned char  *val,
	    int            length,
	    void           *cb_data)
{
    int i;

    if (err) {
	printf("Error reading values\n");
	leave();
    }

    printf("Value:");
    for (i=0; i<length; i++) {
	printf(" %2.2x", val[i]);
    }
    printf("\n");
    leave();
}


/* Whenever the status of a control changes, the function is called
   We display the information of the control if we find a new control
*/
static void
control_change(enum ipmi_update_e op,
	       ipmi_entity_t      *ent,
	       ipmi_control_t     *control,
	       void               *cb_data)
{
    int id, instance;
    char name[33];
    int rv = 0;

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_control_get_id(control, name, 32);
    if (op == IPMI_ADDED) {
	if ((id == entity_id)
	    && (instance == entity_instance)
	    && (strcmp(control_name, name) == 0))
	{
	    switch(ipmi_control_get_type(control))
	    {
	    case IPMI_CONTROL_RELAY:
	    case IPMI_CONTROL_ALARM:
	    case IPMI_CONTROL_RESET:
	    case IPMI_CONTROL_POWER:
	    case IPMI_CONTROL_FAN_SPEED:
	    case IPMI_CONTROL_OUTPUT:
	    case IPMI_CONTROL_LIGHT:
		rv = ipmi_control_get_val(control, got_val, NULL);
		break;

	    case IPMI_CONTROL_IDENTIFIER:
		rv = ipmi_control_identifier_get_val(control, got_id, NULL);
		break;

	    default:
		printf("Invalid control type\n");
		leave();
	    }
	    if (rv) {
		printf("Unable to get control val: %x\n", rv);
		leave();
	    }
	}
    }
}

/* Whenever the status of an entity changes, the function is called
   When a new entity is created, we search all controls that belong 
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
	    /* Register callback so that when the status of a
	       control changes, control_change is called */
	    rv = ipmi_entity_set_control_update_handler(entity,
							control_change,
							entity);
	    if (rv) {
		printf("ipmi_entity_set_control_update_handler: 0x%x", rv);
		leave();
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

    domain_id = ipmi_domain_convert_to_id(domain);

    /* Register a callback functin entity_change. When a new entity
       is created, entity_change is called */
    rv = ipmi_domain_set_entity_update_handler(domain, entity_change, domain);
    if (rv) {      
	printf("ipmi_domain_set_entity_update_handler return error: %d\n", rv);
	return;
    }
}

int
main(int argc, const char *argv[])
{
    int         rv;
    int         curr_arg = 4;
    ipmi_args_t *args;
    ipmi_con_t  *con;

    progname = argv[0];

    if (argc < 4) {
	usage();
	exit(1);
    }

    entity_id = strtoul(argv[1], NULL, 10);
    entity_instance = strtoul(argv[2], NULL, 10);
    control_name = argv[3];

    /* Create selector first. */
    sel_alloc_selector(&ui_sel);

    /* Initialize the OpenIPMI library. ipmi_ui_cb_handler is an OS
       handler */
    ipmi_init(&ipmi_ui_cb_handlers);

    rv = ipmi_parse_args(&curr_arg, argc, argv, &args);
    if (rv) {
	fprintf(stderr, "Error parsing command arguments, argument %d: %s\n",
		curr_arg, strerror(rv));
	usage();
	exit(1);
    }

    rv = ipmi_args_setup_con(args,
			     &ipmi_ui_cb_handlers,
			     ui_sel,
			     &con);
    if (rv) {
        fprintf(stderr, "ipmi_ip_setup_con: %s", strerror(rv));
	exit(1);
    }

    rv = ipmi_init_domain(&con, 1, setup_done, NULL, NULL, NULL);
    if (rv) {
	fprintf(stderr, "ipmi_init_domain: %s\n", strerror(rv));
	exit(1);
    }

    /* This is the main loop of the event-driven program. 
       Try <CTRL-C> to exit the program */ 
    /* We run the select loop here, this shows how you can use
       sel_select.  You could add your own processing in this loop. */
    while (1) {
	sel_select(ui_sel, NULL, 0, NULL, NULL);
    }
}

void
ui_vlog(char *format, enum ipmi_log_type_e log_type, va_list ap)
{
    int do_nl = 1;

    if (leaving)
	return;

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
