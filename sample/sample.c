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
#include <ctype.h>
#include <time.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/ipmi_event.h>

/* This file should not normally be included by the user, but is here
   to demonstrate an internal domain function. */
#include <OpenIPMI/ipmi_domain.h>

/* This sample application demostrates a very simple method to use
   OpenIPMI. It just search all sensors in the system.  From this
   application, you can find that there is only 4 lines code in main()
   function if you use the SMI-only interface, and several simple
   callback functions in all cases. */

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
dump_fru_str(ipmi_entity_t *entity,
	     char          *str,
	     int (*glen)(ipmi_entity_t *fru,
			 unsigned int  *length),
	     int (*gtype)(ipmi_entity_t        *fru,
			  enum ipmi_str_type_e *type),
	     int (*gstr)(ipmi_entity_t *fru,
			 char          *str,
			 unsigned int  *strlen))
{
    enum ipmi_str_type_e type;
    int rv;
    char buf[128];
    unsigned int len;

    rv = gtype(entity, &type);
    if (rv) {
	if (rv != ENOSYS)
	    printf("  Error fetching type for %s: %x\n", str, rv);
	return rv;
    }

    if (type == IPMI_BINARY_STR) {
	printf("    %s is in binary\n", str);
	return 0;
    } else if (type == IPMI_UNICODE_STR) {
	printf("    %s is in unicode\n", str);
	return 0;
    } else if (type != IPMI_ASCII_STR) {
	printf("    %s is in unknown format\n", str);
	return 0;
    }

    len = sizeof(buf);
    rv = gstr(entity, buf, &len);
    if (rv) {
	printf("    Error fetching string for %s: %x\n", str, rv);
	return rv;
    }

    printf("    %s: %s\n", str, buf);
    return 0;
}

static int
dump_fru_custom_str(ipmi_entity_t *entity,
		    char       *str,
		    int        num,
		    int (*glen)(ipmi_entity_t   *entity,
				unsigned int num,
				unsigned int *length),
		    int (*gtype)(ipmi_entity_t           *entity,
				 unsigned int         num,
				 enum ipmi_str_type_e *type),
		    int (*gstr)(ipmi_entity_t   *entity,
				unsigned int num,
				char         *str,
				unsigned int *strlen))
{
    enum ipmi_str_type_e type;
    int rv;
    char buf[128];
    unsigned int len;

    rv = gtype(entity, num, &type);
    if (rv)
	return rv;

    if (type == IPMI_BINARY_STR) {
	printf("    %s custom %d is in binary\n", str, num);
	return 0;
    } else if (type == IPMI_UNICODE_STR) {
	printf("    %s custom %d is in unicode\n", str, num);
	return 0;
    } else if (type != IPMI_ASCII_STR) {
	printf("    %s custom %d is in unknown format\n", str, num);
	return 0;
    }

    len = sizeof(buf);
    rv = gstr(entity, num, buf, &len);
    if (rv) {
	printf("  Error fetching string for %s custom %d: %x\n",
			str, num, rv);
	return rv;
    }

    printf("    %s custom %d: %s\n", str, num, buf);
    return 0;
}

#define DUMP_FRU_STR(name, str) \
dump_fru_str(entity, str, ipmi_entity_get_ ## name ## _len, \
             ipmi_entity_get_ ## name ## _type, \
             ipmi_entity_get_ ## name)

#define DUMP_FRU_CUSTOM_STR(name, str) \
do {									\
    int i, _rv;								\
    for (i=0; ; i++) {							\
        _rv = dump_fru_custom_str(entity, str, i,			\
				  ipmi_entity_get_ ## name ## _custom_len, \
				  ipmi_entity_get_ ## name ## _custom_type, \
				  ipmi_entity_get_ ## name ## _custom);	\
	if (_rv)							\
	    break;							\
    }									\
} while (0)


static void
fru_change(enum ipmi_update_e op,
           ipmi_entity_t     *entity,
           void              *cb_data)
{
    int id, instance;
    int rv;
    unsigned char ucval;
    unsigned int  uival;
    time_t        tval;
    

    if (op == IPMI_ADDED) {
	id = ipmi_entity_get_entity_id(entity);
	instance = ipmi_entity_get_entity_instance(entity);

	printf("FRU added for: %d.%d\n", id, instance);

	printf("  internal area info:\n");
	rv = ipmi_entity_get_internal_use_version(entity, &ucval);
	if (!rv)
	    printf("    version: 0x%2.2x\n", ucval);
	rv = ipmi_entity_get_internal_use_length(entity, &uival);
	if (!rv)
	    printf("    length: %d\n", uival);

	printf("  chassis area info:\n");
	rv = ipmi_entity_get_chassis_info_version(entity, &ucval);
	if (!rv)
	    printf("    version: 0x%2.2x\n", ucval);
	rv = ipmi_entity_get_chassis_info_type(entity, &ucval);
	if (!rv)
	    printf("    chassis type: %d\n", uival);
	DUMP_FRU_STR(chassis_info_part_number, "part number");
	DUMP_FRU_STR(chassis_info_serial_number, "serial number");
	DUMP_FRU_CUSTOM_STR(chassis_info, "chassis");

	printf("  board area info:\n");
	rv = ipmi_entity_get_board_info_version(entity, &ucval);
	if (!rv)
	    printf("    version: 0x%2.2x\n", ucval);
	rv = ipmi_entity_get_board_info_lang_code(entity, &ucval);
	if (!rv)
	    printf("    language: %d\n", uival);
	rv = ipmi_entity_get_board_info_mfg_time(entity, &tval);
	if (!rv)
	    printf("    mfg time: %s\n", ctime(&tval));
	DUMP_FRU_STR(board_info_board_manufacturer, "manufacturer");
	DUMP_FRU_STR(board_info_board_product_name, "name");
	DUMP_FRU_STR(board_info_board_serial_number, "serial number");
	DUMP_FRU_STR(board_info_board_part_number, "part number");
	DUMP_FRU_STR(board_info_fru_file_id, "fru file id");
	DUMP_FRU_CUSTOM_STR(board_info, "board");

	printf("product area info:\n");
	rv = ipmi_entity_get_product_info_version(entity, &ucval);
	if (!rv)
	    printf("    version: 0x%2.2x\n", ucval);
	rv = ipmi_entity_get_product_info_lang_code(entity, &ucval);
	if (!rv)
	    printf("    language: %d\n", uival);
	DUMP_FRU_STR(product_info_manufacturer_name,
		     "manufacturer");
	DUMP_FRU_STR(product_info_product_name, "product name");
	DUMP_FRU_STR(product_info_product_part_model_number,
		     "part model number");
	DUMP_FRU_STR(product_info_product_version, "product version");
	DUMP_FRU_STR(product_info_product_serial_number,
		     "serial number");
	DUMP_FRU_STR(product_info_asset_tag, "asset tag");
	DUMP_FRU_STR(product_info_fru_file_id, "fru file id");
	DUMP_FRU_CUSTOM_STR(product_info, "product info");

	/* multi record */
	/* FIXME - not implemented */
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

static void reread_sels_done(ipmi_domain_t *domain, int err, void *cb_data)
{
    int count;
    ipmi_domain_sel_entries_used(domain, &count);
    printf("reread sel done. entries = %d\n", count);
}

static void bus_scan_done(ipmi_domain_t *domain, int err, void *cb_data)
{
    int count;
    ipmi_domain_reread_sels(domain, reread_sels_done, &count);
    printf("bus scan done.\n");
    return;
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

    rv = ipmi_domain_set_bus_scan_handler(domain, bus_scan_done, NULL);
    if (rv) {
	printf("ipmi_domain_set_bus_scan_handler return error: %d\n", rv);
	return;
    }
    
}

static os_handler_t *os_hnd;

int
main(int argc, const char *argv[])
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

    /* Initialize the OpenIPMI library. */
    ipmi_init(os_hnd);

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
    rv = ipmi_parse_args(&curr_arg, argc, argv, &args);
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

    rv = ipmi_open_domain("", &con, 1, setup_done, NULL, NULL, 0, NULL);
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

void
posix_vlog(char *format, enum ipmi_log_type_e log_type, va_list ap)
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
