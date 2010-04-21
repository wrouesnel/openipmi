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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>
#include <time.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/ipmi_fru.h>

/* This sample application demostrates a very simple method to use
   OpenIPMI. It just search all sensors in the system.  From this
   application, you can find that there is only 4 lines code in main()
   function if you use the SMI-only interface, and several simple
   callback functions in all cases. */

static const char *progname;

static void con_usage(const char *name, const char *help, void *cb_data)
{
    printf("\n%s%s", name, help);
}

static void
usage(void)
{
    printf("Usage:\n");
    printf(" %s <con_parms>\n", progname);
    printf(" Where <con_parms> is one of:");
    ipmi_parse_args_iter_help(con_usage, NULL);
}

static int
sensor_threshold_event_handler(ipmi_sensor_t               *sensor,
			       enum ipmi_event_dir_e       dir,
			       enum ipmi_thresh_e          threshold,
			       enum ipmi_event_value_dir_e high_low,
			       enum ipmi_value_present_e   value_present,
			       unsigned int                raw_value,
			       double                      value,
			       void                        *cb_data,
			       ipmi_event_t                *event)
{
    ipmi_entity_t *ent = ipmi_sensor_get_entity(sensor);
    int id, instance;
    char name[33];

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_id(sensor, name, 32);

    printf("Event from sensor %d.%d.%s: %s %s %s\n",
	   id, instance, name,
	   ipmi_get_threshold_string(threshold),
	   ipmi_get_value_dir_string(high_low),
	   ipmi_get_event_dir_string(dir));
    if (value_present == IPMI_BOTH_VALUES_PRESENT) {
	printf("  value is %f (%2.2x)\n", value, raw_value);
    } else if (value_present == IPMI_RAW_VALUE_PRESENT) {
	printf("  raw value is 0x%x\n", raw_value);
    }
    if (event)
	printf("Due to event 0x%4.4x\n", ipmi_event_get_record_id(event));

    /* This passes the event on to the main event handler, which does
       not exist in this program. */
    return IPMI_EVENT_NOT_HANDLED;
}

static int
sensor_discrete_event_handler(ipmi_sensor_t         *sensor,
			      enum ipmi_event_dir_e dir,
			      int                   offset,
			      int                   severity,
			      int                   prev_severity,
			      void                  *cb_data,
			      ipmi_event_t          *event)
{
    ipmi_entity_t *ent = ipmi_sensor_get_entity(sensor);
    int id, instance;
    char name[33];

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_id(sensor, name, 32);

    printf("Event from sensor %d.%d.%s: %d %s\n",
	   id, instance, name,
	   offset,
	   ipmi_get_event_dir_string(dir));
    if (severity != -1)
	printf("  severity is %d\n", severity);
    if (prev_severity != -1)
	printf("  prev severity is %d\n", prev_severity);
    if (event)
	printf("Due to event 0x%4.4x\n", ipmi_event_get_record_id(event));

    /* This passes the event on to the main event handler, which does
       not exist in this program. */
    return IPMI_EVENT_NOT_HANDLED;
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
    int rv;

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_id(sensor, name, 32);
    if (op == IPMI_ADDED) {
	printf("Sensor added: %d.%d.%s\n", id, instance, name);

	if (ipmi_sensor_get_event_reading_type(sensor)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	    rv = ipmi_sensor_add_threshold_event_handler
		(sensor,
		 sensor_threshold_event_handler,
		 NULL);
	else
	    rv = ipmi_sensor_add_discrete_event_handler
		(sensor,
		 sensor_discrete_event_handler,
		 NULL);
	if (rv)
	    printf("Unable to add the sensor event handler: %x\n", rv);
    }
}

static int
traverse_fru_node_tree(int indent, ipmi_fru_node_t *node)
{
    const char                *name;
    unsigned int              i, j;
    enum ipmi_fru_data_type_e dtype;
    int                       intval, rv;
    time_t                    time;
    double                    floatval;
    char                      *data;
    unsigned int              data_len;
    ipmi_fru_node_t           *sub_node;
    
    for (i=0; ; i++) {
	data = NULL;
        rv = ipmi_fru_node_get_field(node, i, &name, &dtype, &intval, &time,
				     &floatval, &data, &data_len, &sub_node);
        if (rv == EINVAL)
            break;
        else if (rv)
            continue;

	if (name)
	    printf("%*s%s: ", indent, "", name);
	else
	    printf("%*s[%d]: ", indent, "", i);

        switch (dtype) {
	case IPMI_FRU_DATA_INT:
	    printf("(integer) %d\n", intval);
	    break;

	case IPMI_FRU_DATA_TIME:
	    printf("(integer) %ld\n", (long) time);
	    break;

	case IPMI_FRU_DATA_BINARY:
	    printf("(binary)");
	    for (j=0; j<data_len; j++)
		printf(" %2.2x", data[j]);
	    printf("\n");
	    break;

	case IPMI_FRU_DATA_UNICODE:
	    printf("(unicode)");
	    for (j=0; j<data_len; j++)
		printf(" %2.2x", data[j]);
	    printf("\n");
	    break;

	case IPMI_FRU_DATA_ASCII:
	    printf("(ascii) \"%s\"\n", data);
	    break;

	case IPMI_FRU_DATA_BOOLEAN:
	    printf("(boolean) \"%s\"\n", intval ? "true" : "false");
	    break;

	case IPMI_FRU_DATA_FLOAT:
	    printf("(float) %f\n", floatval);
	    break;

	case IPMI_FRU_DATA_SUB_NODE:
	    if (intval == -1)
		printf("(record)\n");
	    else
		printf("(array) %d\n", intval);
	    traverse_fru_node_tree(indent+2, sub_node);
	    break;
	    
	default:
	    printf("(unknown)");
	    break;
	}

	if (data)
	    ipmi_fru_data_free(data);
    }
    
    ipmi_fru_put_node(node);

    return 0;
}

static void
fru_change(enum ipmi_update_e op,
           ipmi_entity_t     *entity,
           void              *cb_data)
{
    int           id, instance;
    int           rv;
    ipmi_fru_t    *fru = ipmi_entity_get_fru(entity);
    const char    *type;
    ipmi_fru_node_t *node;

    if (op == IPMI_ADDED) {
	id = ipmi_entity_get_entity_id(entity);
	instance = ipmi_entity_get_entity_instance(entity);

	printf("FRU added for: %d.%d\n", id, instance);

	if (!fru)
	    return;

	rv = ipmi_fru_get_root_node(fru, &type, &node);
	if (rv)
	    return;
	printf("FRU type: %s", type);
	traverse_fru_node_tree(2, node);
    }
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
	    rv = ipmi_entity_add_sensor_update_handler(entity,
						       sensor_change,
						       entity);
	    if (rv) {
		printf("ipmi_entity_set_sensor_update_handler: 0x%x", rv);
		exit(1);
	    }

            rv = ipmi_entity_add_fru_update_handler(entity,
                                                    fru_change,
                                                    NULL);
	    if (rv) {
		printf("ipmi_entity_set_fru_update_handler: 0x%x", rv);
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
    rv = ipmi_domain_add_entity_update_handler(domain, entity_change, domain);
    if (rv) {      
	printf("ipmi_domain_add_entity_update_handler return error: %d\n", rv);
	return;
    }

}

static os_handler_t *os_hnd;

static void
my_vlog(os_handler_t         *handler,
	const char           *format,
	enum ipmi_log_type_e log_type,
	va_list              ap)
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

int
main(int argc, char *argv[])
{
    int         rv;
    int         curr_arg = 1;
    ipmi_args_t *args;
    ipmi_con_t  *con;

    progname = argv[0];

    /* OS handler allocated first. */
    os_hnd = ipmi_posix_setup_os_handler();
    if (!os_hnd) {
	printf("ipmi_smi_setup_con: Unable to allocate os handler\n");
	exit(1);
    }

    /* Override the default log handler (just to show how). */
    os_hnd->set_log_handler(os_hnd, my_vlog);

    /* Initialize the OpenIPMI library.  Do a double one to look for
       init/shutdown bugs. */
    rv = ipmi_init(os_hnd);
    if (rv) {
	fprintf(stderr, "Error in ipmi initialization %d: %s\n",
		curr_arg, strerror(rv));
	exit(1);
    }
    ipmi_shutdown();
    rv = ipmi_init(os_hnd);
    if (rv) {
	fprintf(stderr, "Error in ipmi initialization(2) %d: %s\n",
		curr_arg, strerror(rv));
	exit(1);
    }

#if 0
    /* If all you need is an SMI connection, this is all the code you
       need. */
    /* Establish connections to domain through system interface.  This
       function connect domain, selector and OS handler together.
       When there is response message from domain, the status of file
       descriptor in selector is changed and predefined callback is
       called. After the connection is established, setup_done will be
       called. */
    rv = ipmi_smi_setup_con(0, os_hnd, NULL, &con);
    if (rv) {
	printf("ipmi_smi_setup_con: %s", strerror(rv));
	exit(1);
    }
#endif

#if 1
    rv = ipmi_parse_args2(&curr_arg, argc, argv, &args);
    if (rv) {
	fprintf(stderr, "Error parsing command arguments, argument %d: %s\n",
		curr_arg, strerror(rv));
	usage();
	exit(1);
    }

    rv = ipmi_args_setup_con(args, os_hnd, NULL, &con);
    if (rv) {
        fprintf(stderr, "ipmi_ip_setup_con: %s", strerror(rv));
	exit(1);
    }
#endif

    rv = ipmi_open_domain("", &con, 1, setup_done, NULL, NULL, NULL,
			  NULL, 0, NULL);
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
	os_hnd->perform_one_op(os_hnd, NULL);
    }
#else
    /* Let the selector code run the select loop. */
    os_hnd->operation_loop(os_hnd);
#endif

    /* Technically, we can't get here, but this is an example. */
    os_hnd->free_os_handler(os_hnd);
}
