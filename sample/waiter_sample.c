/*
 * waiter_sample.c
 *
 * OpenIPMI test code how to use OS handler waiters for blocking code.
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

#define MAX_SENSORS 128

struct waiter_data
{
    os_handler_waiter_t *waiter;
    int err;
    ipmi_sensor_id_t sensors[MAX_SENSORS];
    int sensors_type[MAX_SENSORS];
    unsigned int num_sensors;
    unsigned int curr;

    /* values from a threshold sensor. */
    enum ipmi_value_present_e value_present;
    unsigned int              raw_value;
    double                    val;

    /* values from a discrete and a threshold sensor */
    ipmi_states_t *states;
};

void
setup_done(ipmi_domain_t *domain,
	   int           err,
	   unsigned int  conn_num,
	   unsigned int  port_num,
	   int           still_connected,
	   void          *cb_data)
{
    struct waiter_data *wd = cb_data;

    if (err) {
	wd->err = err;
	os_handler_waiter_release(wd->waiter);
    }
}

void
fully_up(ipmi_domain_t *domain, void *cb_data)
{
    struct waiter_data *wd = cb_data;

    wd->err = 0;
    os_handler_waiter_release(wd->waiter);
}

void
sensor_handler(ipmi_entity_t *entity, ipmi_sensor_t *sensor, void *cb_data)
{
    struct waiter_data *wd = cb_data;

    if (wd->num_sensors >= MAX_SENSORS)
	return;

    wd->sensors[wd->num_sensors] = ipmi_sensor_convert_to_id(sensor);
    wd->sensors_type[wd->num_sensors]
	= ipmi_sensor_get_event_reading_type(sensor);

    wd->num_sensors++;
}

void
entity_iterate_sensors(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_entity_iterate_sensors(entity, sensor_handler, cb_data);
}

void
domain_iterate_entities(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_domain_iterate_entities(domain, entity_iterate_sensors, cb_data);
}

void
close_done(void *cb_data)
{
    struct waiter_data *wd = cb_data;

    os_handler_waiter_release(wd->waiter);
}

void
domain_close(ipmi_domain_t *domain, void *cb_data)
{
    struct waiter_data *wd = cb_data;

    wd->err = ipmi_domain_close(domain, close_done, cb_data);
    if (wd->err)
	os_handler_waiter_release(wd->waiter);
}

static void
handle_sensor_reading(ipmi_sensor_t             *sensor,
		      int                       err,
		      enum ipmi_value_present_e value_present,
		      unsigned int              raw_value,
		      double                    val,
		      ipmi_states_t             *states,
		      void                      *cb_data)
{
    struct waiter_data *wd = cb_data;
    enum ipmi_thresh_e thresh;
    char name[IPMI_SENSOR_NAME_LEN];

    ipmi_sensor_get_name(sensor, name, sizeof(name));
    if (err) {
	printf("Error 0x%x getting discrete states for sensor %s\n",
	       err, name);
	goto out;
    }

    printf("Got threshold reading for sensor %s\n", name);
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

    if (ipmi_sensor_get_threshold_access(sensor)
	== IPMI_THRESHOLD_ACCESS_SUPPORT_NONE)
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
    os_handler_waiter_release(wd->waiter);
}

static void
handle_sensor_states(ipmi_sensor_t *sensor,
		     int           err,
		     ipmi_states_t *states,
		     void          *cb_data)
{
    struct waiter_data *wd = cb_data;
    int  i;
    char name[IPMI_SENSOR_NAME_LEN];

    ipmi_sensor_get_name(sensor, name, sizeof(name));
    if (err) {
	printf("Error 0x%x getting discrete states for sensor %s\n",
	       err, name);
	goto out;
    }

    printf("Got state reading for sensor %s\n", name);
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
    os_handler_waiter_release(wd->waiter);
}

int
main(int argc, char *argv[])
{
    int         rv;
    int         curr_arg = 1;
    ipmi_args_t *args;
    ipmi_con_t  *con;
    os_handler_waiter_factory_t *waiterf;
    os_handler_t *os_hnd;
    char	ebuf[128];
    ipmi_domain_id_t domain_id;
 

    /*
     * We can do this without dynamic allocation because this function will
     * never be exited until the progran is done.
     */
    struct waiter_data waiter_space;
    struct waiter_data *wd = &waiter_space;

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
		curr_arg, ipmi_get_error_string(rv, ebuf, sizeof(ebuf)));
	exit(1);
    }

    rv = ipmi_args_setup_con(args, os_hnd, NULL, &con);
    if (rv) {
        fprintf(stderr, "ipmi_ip_setup_con: %s",
		ipmi_get_error_string(rv, ebuf, sizeof(ebuf)));
	exit(1);
    }

    rv = os_handler_alloc_waiter_factory(os_hnd, 0, 0, &waiterf);
    if (rv) {
        fprintf(stderr, "os_handler_alloc_waiter_factory: %s",
		ipmi_get_error_string(rv, ebuf, sizeof(ebuf)));
	exit(1);
    }

    wd->num_sensors = 0;
    wd->waiter = os_handler_alloc_waiter(waiterf);
    if (!wd->waiter) {
        fprintf(stderr, "os_handler_alloc_waiter: Out of memory");
	exit(1);
    }

    rv = ipmi_open_domain("", &con, 1, setup_done, wd, fully_up, wd,
			  NULL, 0, &domain_id);
    if (rv) {
	fprintf(stderr, "ipmi_init_domain: %s\n",
		ipmi_get_error_string(rv, ebuf, sizeof(ebuf)));
	exit(1);
    }

    os_handler_waiter_wait(wd->waiter, NULL);
    if (wd->err) {
	fprintf(stderr, "Error starting connection: %s\n", 
		ipmi_get_error_string(wd->err, ebuf, sizeof(ebuf)));
    }

    /*
     * At this point the domain is fully up.  We can iterate the
     * sensors now.  First get a list of all sensor ids.
     */
    ipmi_domain_pointer_cb(domain_id, domain_iterate_entities, wd);

    /*
     * Now scan the sensors
     */
    for (wd->curr = 0; wd->curr < wd->num_sensors; wd->curr++) {
	os_handler_waiter_use(wd->waiter);
	if (wd->sensors_type[wd->curr] == IPMI_EVENT_READING_TYPE_THRESHOLD)
	    rv = ipmi_sensor_id_get_reading(wd->sensors[wd->curr],
					    handle_sensor_reading, wd);
	else
	    rv = ipmi_sensor_id_get_states(wd->sensors[wd->curr],
					   handle_sensor_states, wd);
	if (rv) {
	    fprintf(stderr, "Error reading sensor: %s\n",
		    ipmi_get_error_string(rv, ebuf, sizeof(ebuf)));
	    continue;
	}
	os_handler_waiter_wait(wd->waiter, NULL);
    }

    wd->err = 0;
    os_handler_waiter_use(wd->waiter);
    rv = ipmi_domain_pointer_cb(domain_id, domain_close, wd);
    if (rv) {
	fprintf(stderr, "close ptr cb: %s\n",
		ipmi_get_error_string(rv, ebuf, sizeof(ebuf)));
	exit(1);
    }
    os_handler_waiter_wait(wd->waiter, NULL);
    if (wd->err) {
	fprintf(stderr, "ipmi_domain_close: %s\n", 
		ipmi_get_error_string(wd->err, ebuf, sizeof(ebuf)));
    }

    /* Technically, we can't get here, but this is an example. */
    os_hnd->free_os_handler(os_hnd);
    return 0;
}
