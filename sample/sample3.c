/*
 * test1.c
 *
 * OpenIPMI test code showing event setup
 *
 * Author: Corey Minyard <minyard@acm.org>
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

static void
got_thresh_reading(ipmi_sensor_t             *sensor,
		   int                       err,
		   enum ipmi_value_present_e value_present,
		   unsigned int              raw_value,
		   double                    val,
		   ipmi_states_t             *states,
		   void                      *cb_data)
{
}

static void
got_discrete_states()
{
}

static void
event_set_done(ipmi_sensor_t *sensor,
	       int           err,
	       void          *cb_data)
{
    char *sname = cb_data;

    if (!sensor) {
	printf("sensor %s went away while setting events due to error 0x%x\n",
	       sname, err);
	goto out;
    }

    if (err) {
	printf("Error 0x%x setting events for sensor %s\n", err, sname);
	goto out;
    }

    printf("Events set for sensor %s\n", sname);

 out:
    free(sname);
}

static void
got_events(ipmi_sensor_t      *sensor,
	   int                err,
	   ipmi_event_state_t *states,
	   void               *cb_data)
{
    char               *sname = cb_data;
    ipmi_event_state_t *es;
    int                state_sup;
    int                rv;

    if (!sensor) {
	printf("sensor %s went away while setting events due to error 0x%x\n",
	       sname, err);
	goto out_err;
    }

    if (err) {
	printf("Error 0x%x getting events for sensor %s\n", err, sname);
	goto out_err;
    }

    state_sup = ipmi_sensor_get_event_support(sensor);

    es = malloc(ipmi_event_state_size());
    if (!es) {
	printf("Unable to allocate event state memory\n");
	goto out_err;
    }
    ipmi_event_state_init(es);

    /* Turn on the general events for a sensor, since this at
       least supports per-sensor enables. */
    ipmi_event_state_set_events_enabled(es, 1);
    ipmi_event_state_set_scanning_enabled(es, 1);

    printf("Sensor %s event settings:\n", sname);
    if (state_sup != IPMI_EVENT_SUPPORT_PER_STATE) {
	/* No per-state sensors, just do the global enable. */
    } else if (ipmi_sensor_get_event_reading_type(sensor)
	       == IPMI_EVENT_READING_TYPE_THRESHOLD)
    {
	/* Check each event, print out the current state, and turn it
	   on in the events to set if it is available. */
	enum ipmi_event_value_dir_e value_dir;
	enum ipmi_event_dir_e       dir;
	enum ipmi_thresh_e          thresh;
	int                         val;
	for (value_dir=IPMI_GOING_LOW; value_dir<=IPMI_GOING_HIGH; value_dir++)
	{
	    for (dir=IPMI_ASSERTION; dir<=IPMI_DEASSERTION; dir++) {
		for (thresh=IPMI_LOWER_NON_CRITICAL;
		     thresh<=IPMI_UPPER_NON_RECOVERABLE;
		     thresh++)
		{
		    char *v;
			    
		    rv = ipmi_sensor_threshold_event_supported
			(sensor, thresh, value_dir, dir, &val);
		    if (rv || !val)
			continue;
		    
		    if (ipmi_is_threshold_event_set(states, thresh,
						    value_dir, dir))
			v = " not";
		    else
			v = "";
		    
		    printf("  %s %s %s was%s enabled\n",
			   ipmi_get_threshold_string(thresh),
			   ipmi_get_value_dir_string(value_dir),
			   ipmi_get_event_dir_string(dir),
			   v);
		    
		    ipmi_threshold_event_set(es, thresh, value_dir, dir);
		}
	    }
	}
    } else {
	/* Check each event, print out the current state, and turn it
	   on in the events to set if it is available. */
	enum ipmi_event_dir_e dir;
	int                   i;

	for (dir=IPMI_ASSERTION; dir<=IPMI_DEASSERTION; dir++) {
	    for (i=0; i<15; i++) {
		char *v;
		int  val;
			    
		rv = ipmi_sensor_discrete_event_supported
		    (sensor, i, dir, &val);
		if (rv || !val)
		    continue;
		    
		if (ipmi_is_discrete_event_set(states, i, dir))
		    v = " not";
		else
		    v = "";
		    
		printf("  bit %d %s was%s enabled\n",
		       i,
		       ipmi_get_event_dir_string(dir),
		       v);
		    
		ipmi_discrete_event_set(es, i, dir);
	    }
	}
    }

    rv = ipmi_sensor_events_enable_set(sensor, es, event_set_done, sname);
    free(es);
    if (rv) {
	printf("Error 0x%x enabling events for sensor %s\n", err, sname);
	goto out_err;
    }

    return;

 out_err:
    free(sname);
}

static void
thresholds_set(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    char *sname = cb_data;

    if (!sensor) {
	printf("sensor %s went away while setting thresholds"
	       " due to error 0x%x\n",
	       sname, err);
	goto out;
    }

    if (err) {
	printf("Error 0x%x setting thresholds for sensor %s\n", err, sname);
	goto out;
    }

    printf("Thresholds set for sensor %s\n", sname);

 out:
    free(sname);
}

static void
got_thresholds(ipmi_sensor_t     *sensor,
	       int               err,
	       ipmi_thresholds_t *th,
	       void              *cb_data)
{
    char               *sname = cb_data;
    ipmi_thresholds_t  *nth;
    enum ipmi_thresh_e thresh;
    int                rv;

    if (!sensor) {
	printf("sensor %s went away while getting thresholds"
	       " due to error 0x%x\n",
	       sname, err);
	goto out_err;
    }

    if (err) {
	printf("Error 0x%x getting events for sensor %s\n", err, sname);
	goto out_err;
    }

    nth = malloc(ipmi_thresholds_size());
    if (!nth) {
	printf("Unable to allocate threshold memory\n");
	goto out_err;
    }
    ipmi_thresholds_init(nth);

    printf("Sensor %s threshold settings:\n", sname);
    for (thresh=IPMI_LOWER_NON_CRITICAL;
	 thresh<=IPMI_UPPER_NON_RECOVERABLE;
	 thresh++)
    {
	int    val;
	double dval;

	rv = ipmi_sensor_threshold_readable(sensor, thresh, &val);
	if (rv || !val)
	    /* Threshold not available. */
	    continue;

	rv = ipmi_threshold_get(th, thresh, &dval);
	if (rv) {
	    printf("  threshold %s could not be fetched due to error 0x%x\n",
		   ipmi_get_threshold_string(thresh), rv);
	} else {
	    printf("  threshold %s is %lf\n",
		   ipmi_get_threshold_string(thresh), dval);
	}
    }

    rv = ipmi_get_default_sensor_thresholds(sensor, nth);
    if (rv) {
	printf("Error 0x%x getting def thresholds for sensor %s\n", rv, sname);
	free(nth);
	goto out_err;
    }

    rv = ipmi_thresholds_set(sensor, nth, thresholds_set, sname);
    free(nth);
    if (rv) {
	printf("Error 0x%x setting thresholds for sensor %s\n", rv, sname);
	goto out_err;
    }
    return;

 out_err:
    free(sname);
}


/* Whenever the status of a sensor changes, the function is called
   We display the information of the sensor if we find a new sensor */
static void
sensor_change(enum ipmi_update_e op,
	      ipmi_entity_t      *ent,
	      ipmi_sensor_t      *sensor,
	      void               *cb_data)
{
    int id, instance;
    char name[33];
    char *sname, *sname2, *sname3;
    int rv;

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_id(sensor, name, 32);
    if (op == IPMI_ADDED) {
	int state_sup, thresh_sup;

	sname = malloc(strlen(name)+32);
	if (!sname) {
	    printf("Unable to allocate sensor name memory\n");
	    return;
	}
	sprintf(sname, "%d.%d.%s", id, instance, name);
	sname2 = strdup(sname);
	sname3 = strdup(sname);

	printf("Sensor added: %s\n", sname);

	/* Get the current reading. */
	if (ipmi_sensor_get_event_reading_type(sensor)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    rv = ipmi_reading_get(sensor, got_thresh_reading, sname);
	    if (rv) {
		printf("ipmi_reading_get return error: %d\n", rv);
		free(sname);
	    }
	} else {
	    rv = ipmi_states_get(sensor, got_discrete_states, sname);
	    if (rv) {
		printf("ipmi_reading_get return error: %d\n", rv);
		free(sname);
	    }
	}

	if (!sname2) {
	    printf("Unable to allocate sensor name memory 2\n");
	    return;
	}
	if (!sname3) {
	    printf("Unable to allocate sensor name memory 3\n");
	    free(sname2);
	    return;
	}

	/* Set up events. */
	state_sup = ipmi_sensor_get_event_support(sensor);
	switch (state_sup)
	{
	    case IPMI_EVENT_SUPPORT_NONE:
	    case IPMI_EVENT_SUPPORT_GLOBAL_ENABLE:
		/* No events to set up. */
		printf("Sensor %s has no event support\n", sname2);
		free(sname2);
		goto get_thresh;
	}

	rv = ipmi_sensor_events_enable_get(sensor, got_events, sname2);
	if (rv) {
	    printf("ipmi_sensor_events_enable_get return error: %d\n", rv);
	    free(sname2);
	}

    get_thresh:
	/* Handle the threshold settings. */

	if (ipmi_sensor_get_event_reading_type(sensor)
	    != IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    /* Thresholds only for threshold sensors (duh) */
	    free(sname3);
	    goto out;
	}

	thresh_sup = ipmi_sensor_get_threshold_access(sensor);

	switch (thresh_sup)
	{
	case IPMI_THRESHOLD_ACCESS_SUPPORT_NONE:
	    printf("Sensor %s has no threshold support\n", sname3);
	    free(sname3);
	    goto out;

	case IPMI_THRESHOLD_ACCESS_SUPPORT_FIXED:
	    printf("Sensor %s has fixed threshold support\n", sname3);
	    free(sname3);
	    goto out;
	}

	rv = ipmi_thresholds_get(sensor, got_thresholds, sname3);
	if (rv) {
	    printf("ipmi_thresholds_get return error: %d\n", rv);
	    free(sname3);
	}

    }
 out:
    return;
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

    rv = ipmi_open_domain(&con, 1, setup_done, NULL, NULL);
    if (rv) {
	fprintf(stderr, "ipmi_init_domain: %s\n", strerror(rv));
	exit(1);
    }

    /* This is the main loop of the event-driven program. 
       Try <CTRL-C> to exit the program */ 
    /* Let the selector code run the select loop. */
    os_hnd->operation_loop(os_hnd);

    /* Technically, we can't get here, but this is an example. */
    os_hnd->free_os_handler(os_hnd);
    return 0;
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
