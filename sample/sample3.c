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

/* This sample application demostrates some general handling of sensors,
   like reading values, setting up events, and things of that nature.
   It also demonstrates some good coding practices like refcounting
   structures. */

static const char *progname;

#define MAX_SENSOR_NAME_SIZE 128

typedef struct sdata_s
{
    unsigned int       refcount;
    ipmi_sensor_id_t   sensor_id;
    char               name[MAX_SENSOR_NAME_SIZE];
    ipmi_event_state_t *es;
    ipmi_thresholds_t  *th;
    int                state_sup;
    int                thresh_sup;

    struct sdata_s     *next, *prev;
} sdata_t;

static sdata_t *sdata_list = NULL;

static sdata_t *
alloc_sdata(ipmi_sensor_t *sensor)
{
    sdata_t *sdata;

    sdata = malloc(sizeof(*sdata));
    if (!sdata)
	return NULL;

    sdata->es = malloc(ipmi_event_state_size());
    if (!sdata->es) {
	free(sdata);
	return NULL;
    }
    ipmi_event_state_init(sdata->es);

    sdata->th = malloc(ipmi_thresholds_size());
    if (!sdata->th) {
	free(sdata->es);
	free(sdata);
	return NULL;
    }
    ipmi_thresholds_init(sdata->th);

    sdata->refcount = 1;

    sdata->sensor_id = ipmi_sensor_convert_to_id(sensor);
    ipmi_sensor_get_name(sensor, sdata->name, sizeof(sdata->name));

    sdata->next = sdata_list;
    sdata->prev = NULL;
    sdata_list = sdata;

    return sdata;
}

static sdata_t *
find_sdata(ipmi_sensor_t *sensor)
{
    ipmi_sensor_id_t id = ipmi_sensor_convert_to_id(sensor);
    sdata_t          *link;

    link = sdata_list;
    while (link) {
	if (ipmi_cmp_sensor_id(id, link->sensor_id) == 0)
	    return link;
	link = link->next;
    }
    return NULL;
}

static void
use_sdata(sdata_t *sdata)
{
    sdata->refcount++;
}

static void
release_sdata(sdata_t *sdata)
{
    sdata->refcount--;
    if (sdata->refcount == 0) {
	/* Remove it from the list. */
	if (sdata->next)
	    sdata->next->prev = sdata->prev;

	if (sdata->prev)
	    sdata->prev->next = sdata->next;
	else
	    sdata_list = sdata->next;

	free(sdata->es);
	free(sdata->th);
	free(sdata);
    }
}

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

static void
got_thresh_reading(ipmi_sensor_t             *sensor,
		   int                       err,
		   enum ipmi_value_present_e value_present,
		   unsigned int              raw_value,
		   double                    val,
		   ipmi_states_t             *states,
		   void                      *cb_data)
{
    sdata_t            *sdata = cb_data;
    enum ipmi_thresh_e thresh;

    if (err) {
	printf("Error 0x%x getting discrete states for sensor %s\n",
	       err, sdata->name);
	goto out;
    }

    printf("Got threshold reading for sensor %s\n", sdata->name);
    if (ipmi_is_event_messages_enabled(states))
	printf("  event messages enabled\n");
    if (ipmi_is_sensor_scanning_enabled(states))
	printf("  sensor scanning enabled\n");
    if (ipmi_is_initial_update_in_progress(states))
	printf("  initial update in progress\n");

    switch (value_present)
    {
    case IPMI_NO_VALUES_PRESENT:
	printf("  no value present\n");
	break;
    case IPMI_BOTH_VALUES_PRESENT:
	{
	    const char *percent = "";
	    const char *base;
	    const char *mod_use = "";
	    const char *modifier = "";
	    const char *rate;

	    base = ipmi_sensor_get_base_unit_string(sensor);
	    if (ipmi_sensor_get_percentage(sensor))
		percent = "%";
	    switch (ipmi_sensor_get_modifier_unit_use(sensor)) {
	    case IPMI_MODIFIER_UNIT_NONE:
		break;
	    case IPMI_MODIFIER_UNIT_BASE_DIV_MOD:
		mod_use = "/";
		modifier = ipmi_sensor_get_modifier_unit_string(sensor);
		break;
	    case IPMI_MODIFIER_UNIT_BASE_MULT_MOD:
		mod_use = "*";
		modifier = ipmi_sensor_get_modifier_unit_string(sensor);
		break;
	    }
	    rate = ipmi_sensor_get_rate_unit_string(sensor);
	    
	    printf("  value: %lf%s %s%s%s%s\n", val, percent,
		   base, mod_use, modifier, rate);
	}
	/* FALLTHROUGH */
    case IPMI_RAW_VALUE_PRESENT:
	printf("  raw value: 0x%2.2x\n", raw_value);
    }

    if (sdata->thresh_sup == IPMI_THRESHOLD_ACCESS_SUPPORT_NONE)
	goto out;

    for (thresh=IPMI_LOWER_NON_CRITICAL;
	 thresh<=IPMI_UPPER_NON_RECOVERABLE;
	 thresh++)
    {
	int val, rv;

	rv = ipmi_sensor_threshold_reading_supported(sensor, thresh, &val);
	if (rv || !val)
	    continue;

	if (ipmi_is_threshold_out_of_range(states, thresh))
	    printf("  Threshold %s is out of range\n",
		   ipmi_get_threshold_string(thresh));
	else
	    printf("  Threshold %s is in range\n",
		   ipmi_get_threshold_string(thresh));
    }

 out:
    release_sdata(sdata);
}

static void
got_discrete_states(ipmi_sensor_t *sensor,
		    int           err,
		    ipmi_states_t *states,
		    void          *cb_data)
{
    sdata_t *sdata = cb_data;
    int     i;

    if (err) {
	printf("Error 0x%x getting discrete states for sensor %s\n",
	       err, sdata->name);
	goto out;
    }

    if (err) {
	printf("Error 0x%x getting discrete states for sensor %s\n",
	       err, sdata->name);
	goto out;
    }

    printf("Got state reading for sensor %s\n", sdata->name);
    if (ipmi_is_event_messages_enabled(states))
	printf("  event messages enabled\n");
    if (ipmi_is_sensor_scanning_enabled(states))
	printf("  sensor scanning enabled\n");
    if (ipmi_is_initial_update_in_progress(states))
	printf("  initial update in progress\n");

    for (i=0; i<15; i++) {
	int val, rv;

	rv = ipmi_sensor_discrete_event_readable(sensor, i, &val);
	if (rv || !val)
	    continue;

	printf("  state %d value is %d\n", i, ipmi_is_state_set(states, i));
    }

 out:
    release_sdata(sdata);
}

static void
event_set_done(ipmi_sensor_t *sensor,
	       int           err,
	       void          *cb_data)
{
    sdata_t *sdata = cb_data;

    if (err) {
	printf("Error 0x%x setting events for sensor %s\n", err, sdata->name);
	goto out;
    }

    printf("Events set for sensor %s\n", sdata->name);

 out:
    release_sdata(sdata);
}

static void
got_events(ipmi_sensor_t      *sensor,
	   int                err,
	   ipmi_event_state_t *states,
	   void               *cb_data)
{
    sdata_t *sdata = cb_data;
    int     rv;

    if (err) {
	printf("Error 0x%x getting events for sensor %s\n", err, sdata->name);
	goto out_err;
    }

    /* Turn on the general events for a sensor, since this at
       least supports per-sensor enables. */
    ipmi_event_state_set_events_enabled(sdata->es, 1);
    ipmi_event_state_set_scanning_enabled(sdata->es, 1);

    printf("Sensor %s event settings:\n", sdata->name);
    if (sdata->state_sup != IPMI_EVENT_SUPPORT_PER_STATE) {
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
			v = "";
		    else
			v = " not";
		    
		    printf("  %s %s %s was%s enabled\n",
			   ipmi_get_threshold_string(thresh),
			   ipmi_get_value_dir_string(value_dir),
			   ipmi_get_event_dir_string(dir),
			   v);
		    
		    ipmi_threshold_event_set(sdata->es, thresh,
					     value_dir, dir);
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
		    v = "";
		else
		    v = " not";
		    
		printf("  bit %d %s was%s enabled\n",
		       i,
		       ipmi_get_event_dir_string(dir),
		       v);
		    
		ipmi_discrete_event_set(sdata->es, i, dir);
	    }
	}
    }

    rv = ipmi_sensor_set_event_enables(sensor, sdata->es,
				       event_set_done, sdata);
    if (rv) {
	printf("Error 0x%x enabling events for sensor %s\n", err, sdata->name);
	goto out_err;
    }

    return;

 out_err:
    release_sdata(sdata);
}

static void
thresholds_set(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    sdata_t *sdata = cb_data;

    if (err) {
	printf("Error 0x%x setting thresholds for sensor %s\n",
	       err, sdata->name);
	goto out;
    }

    printf("Thresholds set for sensor %s\n", sdata->name);

 out:
    release_sdata(sdata);
}

static void
got_thresholds(ipmi_sensor_t     *sensor,
	       int               err,
	       ipmi_thresholds_t *th,
	       void              *cb_data)
{
    sdata_t            *sdata = cb_data;
    enum ipmi_thresh_e thresh;
    int                rv;

    if (err) {
	printf("Error 0x%x getting events for sensor %s\n", err, sdata->name);
	goto out_err;
    }

    printf("Sensor %s threshold settings:\n", sdata->name);
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

    rv = ipmi_get_default_sensor_thresholds(sensor, sdata->th);
    if (rv) {
	printf("Error 0x%x getting def thresholds for sensor %s\n",
	       rv, sdata->name);
	goto out_err;
    }

    rv = ipmi_sensor_set_thresholds(sensor, sdata->th, thresholds_set, sdata);
    if (rv) {
	printf("Error 0x%x setting thresholds for sensor %s\n",
	       rv, sdata->name);
	goto out_err;
    }
    return;

 out_err:
    release_sdata(sdata);
}


/* Whenever the status of a sensor changes, the function is called
   We display the information of the sensor if we find a new sensor */
static void
sensor_change(enum ipmi_update_e op,
	      ipmi_entity_t      *ent,
	      ipmi_sensor_t      *sensor,
	      void               *cb_data)
{
    sdata_t *sdata;
    int     rv;

    if (op == IPMI_ADDED) {
	sdata = alloc_sdata(sensor);
	if (!sdata) {
	    printf("Unable to allocate sensor name memory\n");
	    return;
	}

	printf("Sensor added: %s\n", sdata->name);

	/* Get the current reading. */
	if (ipmi_sensor_get_event_reading_type(sensor)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    use_sdata(sdata);
	    rv = ipmi_sensor_get_reading(sensor, got_thresh_reading, sdata);
	    if (rv) {
		printf("ipmi_reading_get returned error 0x%x for sensor %s\n",
		       rv, sdata->name);
		release_sdata(sdata);
	    }
	} else {
	    use_sdata(sdata);
	    rv = ipmi_sensor_get_states(sensor, got_discrete_states, sdata);
	    if (rv) {
		printf("ipmi_states_get returned error 0x%x for sensor %s\n",
		       rv, sdata->name);
		release_sdata(sdata);
	    }
	}

	/* Set up events. */
	sdata->state_sup = ipmi_sensor_get_event_support(sensor);
	switch (sdata->state_sup)
	{
	    case IPMI_EVENT_SUPPORT_NONE:
	    case IPMI_EVENT_SUPPORT_GLOBAL_ENABLE:
		/* No events to set up. */
		printf("Sensor %s has no event support\n", sdata->name);
		goto get_thresh;
	}

	use_sdata(sdata);
	rv = ipmi_sensor_get_event_enables(sensor, got_events, sdata);
	if (rv) {
	    printf("ipmi_sensor_events_enable_get returned error 0x%x"
		   " for sensor %s\n",
		   rv, sdata->name);
	    release_sdata(sdata);
	}

    get_thresh:
	/* Handle the threshold settings. */

	if (ipmi_sensor_get_event_reading_type(sensor)
	    != IPMI_EVENT_READING_TYPE_THRESHOLD)
	    /* Thresholds only for threshold sensors (duh) */
	    goto out;

	sdata->thresh_sup = ipmi_sensor_get_threshold_access(sensor);

	switch (sdata->thresh_sup)
	{
	case IPMI_THRESHOLD_ACCESS_SUPPORT_NONE:
	    printf("Sensor %s has no threshold support\n", sdata->name);
	    goto out;

	case IPMI_THRESHOLD_ACCESS_SUPPORT_FIXED:
	    printf("Sensor %s has fixed threshold support\n", sdata->name);
	    goto out;
	}

	use_sdata(sdata);
	rv = ipmi_sensor_get_thresholds(sensor, got_thresholds, sdata);
	if (rv) {
	    printf("ipmi_thresholds_get returned error 0x%x"
		   " for sensor %s\n",
		   rv, sdata->name);
	    release_sdata(sdata);
	}
    } else if (op == IPMI_DELETED) {
	sdata = find_sdata(sensor);
	if (!sdata) {
	    char name[120];
	    ipmi_sensor_get_name(sensor, name, sizeof(name));

	    printf("sensor %s was deleted but not found in the sensor db\n",
		   name);
	    goto out;
	}

	printf("sensor %s was deleted\n", sdata->name);
	release_sdata(sdata);
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
    int  rv;
    char name[50];

    ipmi_entity_get_name(entity, name, sizeof(name));
    if (op == IPMI_ADDED) {
	    printf("Entity added: %s\n", name);
	    /* Register callback so that when the status of a
	       sensor changes, sensor_change is called */
	    rv = ipmi_entity_add_sensor_update_handler(entity,
						       sensor_change,
						       NULL);
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

    /* Use the default log handler. */

    /* Initialize the OpenIPMI library. */
    ipmi_init(os_hnd);

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

    rv = ipmi_open_domain("", &con, 1, setup_done, NULL, NULL, NULL,
			  NULL, 0, NULL);
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
