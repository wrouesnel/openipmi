/*
 * cmd_sensor.c
 *
 * A command interpreter for OpenIPMI
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2004 MontaVista Software Inc.
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

#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_cmdlang.h>

/* Internal includes, do not use in your programs */
#include <OpenIPMI/internal/ipmi_malloc.h>

static void
sensor_list_handler(ipmi_entity_t *entity, ipmi_sensor_t *sensor,
		    void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            sensor_name[IPMI_SENSOR_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));

    ipmi_cmdlang_out(cmd_info, "Name", sensor_name);
}

static void
sensor_list(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            entity_name[IPMI_ENTITY_NAME_LEN];

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));
    ipmi_cmdlang_out(cmd_info, "Entity", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", entity_name);
    ipmi_cmdlang_out(cmd_info, "Sensors", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_entity_iterate_sensors(entity, sensor_list_handler, cmd_info);
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static void
sensor_dump(ipmi_sensor_t *sensor, ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             num, lun;
    char            *str;
    const char      *cstr;
    int             event_support;
    int             event_reading_type;
    int             len;
    int             rv;
    int             val;

    event_reading_type = ipmi_sensor_get_event_reading_type(sensor);

    ipmi_sensor_get_num(sensor, &lun, &num);
    ipmi_cmdlang_out_int(cmd_info, "LUN", lun);
    ipmi_cmdlang_out_int(cmd_info, "Number", num);
    ipmi_cmdlang_out_int(cmd_info, "Event Reading Type",
		     ipmi_sensor_get_event_reading_type(sensor));
    ipmi_cmdlang_out(cmd_info, "Event Reading Type Name",
		     ipmi_sensor_get_event_reading_type_string(sensor));
    ipmi_cmdlang_out_int(cmd_info, "Type",
			 ipmi_sensor_get_sensor_type(sensor));
    ipmi_cmdlang_out(cmd_info, "Type Name",
		     ipmi_sensor_get_sensor_type_string(sensor));
    val = ipmi_sensor_get_sensor_direction(sensor);
    if (val != IPMI_SENSOR_DIRECTION_UNSPECIFIED)
	ipmi_cmdlang_out(cmd_info, "Direction",
			 ipmi_get_sensor_direction_string(val));
    
    event_support = ipmi_sensor_get_event_support(sensor);
    switch (event_support) {
    case IPMI_EVENT_SUPPORT_PER_STATE:
	ipmi_cmdlang_out(cmd_info, "Event Support", "per state");
	break;
    case IPMI_EVENT_SUPPORT_ENTIRE_SENSOR:
	ipmi_cmdlang_out(cmd_info, "Event Support", "entire sensor");
	break;
    case IPMI_EVENT_SUPPORT_GLOBAL_ENABLE:
	ipmi_cmdlang_out(cmd_info, "Event Support", "global");
	break;
    default:
	break;
    }

    ipmi_cmdlang_out_bool(cmd_info, "Init Scanning",
			 ipmi_sensor_get_sensor_init_scanning(sensor));
    ipmi_cmdlang_out_bool(cmd_info, "Init Events",
			 ipmi_sensor_get_sensor_init_events(sensor));
    ipmi_cmdlang_out_bool(cmd_info, "Init Thresholds",
			 ipmi_sensor_get_sensor_init_thresholds(sensor));
    ipmi_cmdlang_out_bool(cmd_info, "Init Hysteresis",
			 ipmi_sensor_get_sensor_init_hysteresis(sensor));
    ipmi_cmdlang_out_bool(cmd_info, "Init Type",
			 ipmi_sensor_get_sensor_init_type(sensor));
    ipmi_cmdlang_out_bool(cmd_info, "Init Power Up Events",
			 ipmi_sensor_get_sensor_init_pu_events(sensor));
    ipmi_cmdlang_out_bool(cmd_info, "Init Power Up Scanning",
			 ipmi_sensor_get_sensor_init_pu_scanning(sensor));

    ipmi_cmdlang_out_bool(cmd_info, "Ignore If No Entity",
			 ipmi_sensor_get_ignore_if_no_entity(sensor));
    ipmi_cmdlang_out_bool(cmd_info, "Auto Rearm",
			 ipmi_sensor_get_supports_auto_rearm(sensor));
    ipmi_cmdlang_out_int(cmd_info, "OEM1",
			 ipmi_sensor_get_oem1(sensor));

    len = ipmi_sensor_get_id_length(sensor);
    if (len) {
	str = ipmi_mem_alloc(len);
	if (!str) {
	    cmdlang->err = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	    goto out_err;
	}
	len = ipmi_sensor_get_id(sensor, str, len);
	ipmi_cmdlang_out_type(cmd_info, "Id",
			      ipmi_sensor_get_id_type(sensor),
			      str, len);
	ipmi_mem_free(str);
    }

    if (event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD) {
	int access = ipmi_sensor_get_threshold_access(sensor);
	enum ipmi_thresh_e          thresh;
	enum ipmi_event_value_dir_e value_dir;
	enum ipmi_event_dir_e       dir;
	int                         rv;
	char                        th_name[50];
	double                      dval;

	ipmi_cmdlang_out(cmd_info, "Threshold Access",
			 ipmi_get_threshold_access_support_string(access));

	for (thresh = IPMI_LOWER_NON_CRITICAL;
	     thresh <= IPMI_UPPER_NON_RECOVERABLE; 
	     thresh++)
	{
	    rv = ipmi_sensor_threshold_reading_supported(sensor, thresh, &val);
	    if ((rv) || !val)
		continue;

	    ipmi_cmdlang_out(cmd_info, "Threshold", NULL);
	    ipmi_cmdlang_down(cmd_info);
	    ipmi_cmdlang_out(cmd_info, "Name",
			     ipmi_get_threshold_string(thresh));
	    rv = ipmi_sensor_threshold_readable(sensor, thresh, &val);
	    if (rv)
		val = 0;
	    ipmi_cmdlang_out_bool(cmd_info, "Readable", val);
	    rv = ipmi_sensor_threshold_settable(sensor, thresh, &val);
	    if (rv)
		val = 0;
	    ipmi_cmdlang_out_bool(cmd_info, "Settable", val);

	    for (value_dir = IPMI_GOING_LOW;
		 value_dir <= IPMI_GOING_HIGH;
		 value_dir++)
	    {
		for (dir = IPMI_ASSERTION;
		     dir <= IPMI_DEASSERTION;
		     dir++)
		{
		    rv = ipmi_sensor_threshold_event_supported(sensor,
							       thresh,
							       value_dir,
							       dir,
							       &val);
		    if (rv || !val) continue;

		    snprintf(th_name, sizeof(th_name), "%s %s",
			     ipmi_get_value_dir_string(value_dir),
			     ipmi_get_event_dir_string(dir));
		    ipmi_cmdlang_out(cmd_info, "Supports", th_name);
		}
	    }
	    ipmi_cmdlang_up(cmd_info);
	}

	val = ipmi_sensor_get_hysteresis_support(sensor);
	ipmi_cmdlang_out(cmd_info, "Hysteresis Support",
			 ipmi_get_hysteresis_support_string(val));

#if 0
	/* FIXME - no accuracy handling */
	int ipmi_sensor_get_accuracy(ipmi_sensor_t *sensor, int val,
				     double *accuracy);
#endif

	rv = ipmi_sensor_get_nominal_reading(sensor, &dval);
	if (!rv)
	    ipmi_cmdlang_out_double(cmd_info, "Nominal Reading", dval);
	rv = ipmi_sensor_get_normal_max(sensor, &dval);
	if (!rv)
	    ipmi_cmdlang_out_double(cmd_info, "Normal Max", dval);
	rv = ipmi_sensor_get_normal_min(sensor, &dval);
	if (!rv)
	    ipmi_cmdlang_out_double(cmd_info, "Normal Min", dval);
	rv = ipmi_sensor_get_sensor_max(sensor, &dval);
	if (!rv)
	    ipmi_cmdlang_out_double(cmd_info, "Sensor Max", dval);
	rv = ipmi_sensor_get_sensor_min(sensor, &dval);
	if (!rv)
	    ipmi_cmdlang_out_double(cmd_info, "Sensor Min", dval);

	ipmi_cmdlang_out_int(cmd_info, "Base Unit",
			     ipmi_sensor_get_base_unit(sensor));
	ipmi_cmdlang_out(cmd_info, "Base Unit Name",
			 ipmi_sensor_get_base_unit_string(sensor));
	cstr = ipmi_sensor_get_rate_unit_string(sensor);
	if (strlen(cstr)) {
	    ipmi_cmdlang_out_int(cmd_info, "Rate Unit",
				 ipmi_sensor_get_rate_unit(sensor));
	    ipmi_cmdlang_out(cmd_info, "Rate Unit Name", cstr);
	}
	switch (ipmi_sensor_get_modifier_unit_use(sensor)) {
	case IPMI_MODIFIER_UNIT_BASE_DIV_MOD:
	    ipmi_cmdlang_out(cmd_info, "Modifier Use", "/");
	    ipmi_cmdlang_out_int(cmd_info, "Modifier Unit",
				 ipmi_sensor_get_modifier_unit(sensor));
	    ipmi_cmdlang_out(cmd_info, "Modifier Unit Name",
			     ipmi_sensor_get_modifier_unit_string(sensor));
	    break;
		
	case IPMI_MODIFIER_UNIT_BASE_MULT_MOD:
	    ipmi_cmdlang_out(cmd_info, "Modifier Use", "*");
	    ipmi_cmdlang_out_int(cmd_info, "Modifier Unit",
				 ipmi_sensor_get_modifier_unit(sensor));
	    ipmi_cmdlang_out(cmd_info, "Modifier Unit Name",
			     ipmi_sensor_get_modifier_unit_string(sensor));
	    break;

	default:
	    break;
	}
	if (ipmi_sensor_get_percentage(sensor))
	    ipmi_cmdlang_out(cmd_info, "Percentage", "%");
    } else {
	int                   event;
	enum ipmi_event_dir_e dir;

	for (event=0; event<15; event++) {
	    ipmi_cmdlang_out(cmd_info, "Event", NULL);
	    ipmi_cmdlang_down(cmd_info);
	    ipmi_cmdlang_out_int(cmd_info, "Offset", event);
	    cstr = ipmi_sensor_reading_name_string(sensor, event);
	    if (strcmp(cstr, "unknown") != 0)
		ipmi_cmdlang_out(cmd_info, "Name", cstr);
	    
	    for (dir = IPMI_ASSERTION;
		 dir <= IPMI_DEASSERTION;
		 dir++)
	    {
		rv = ipmi_sensor_discrete_event_supported(sensor,
							  event,
							  dir,
							  &val);
		if (rv || !val) continue;

		ipmi_cmdlang_out(cmd_info, "Supports",
				 ipmi_get_event_dir_string(dir));
	    }
	    ipmi_cmdlang_up(cmd_info);
	}
    }
    return;

 out_err:
    ipmi_sensor_get_name(sensor, cmdlang->objstr,
			 cmdlang->objstr_len);
    cmdlang->location = "cmd_sensor.c(sensor_dump)";
}

static void
sensor_info(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            sensor_name[IPMI_SENSOR_NAME_LEN];

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));

    ipmi_cmdlang_out(cmd_info, "Sensor", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", sensor_name);
    sensor_dump(sensor, cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static void
read_sensor(ipmi_sensor_t             *sensor,
	    int                       err,
	    enum ipmi_value_present_e value_present,
	    unsigned int              raw_val,
	    double                    val,
	    ipmi_states_t             *states,
	    void                      *cb_data)
{
    ipmi_cmd_info_t    *cmd_info = cb_data;
    ipmi_cmdlang_t     *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    enum ipmi_thresh_e thresh;
    char               sensor_name[IPMI_SENSOR_NAME_LEN];
    int                rv;

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error reading sensor";
	cmdlang->err = err;
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(read_sensor)";
	goto out;
    }

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));

    ipmi_cmdlang_out(cmd_info, "Sensor", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", sensor_name);

    ipmi_cmdlang_out_bool(cmd_info, "Event Messages Enabled",
			  ipmi_is_event_messages_enabled(states));
    ipmi_cmdlang_out_bool(cmd_info, "Sensor Scanning Enabled",
			  ipmi_is_sensor_scanning_enabled(states));
    ipmi_cmdlang_out_bool(cmd_info, "Initial Update In Progress",
			  ipmi_is_initial_update_in_progress(states));

    switch (value_present) {
    case IPMI_BOTH_VALUES_PRESENT:
	ipmi_cmdlang_out_double(cmd_info, "Value", val);
	/* FALLTHRU */
    case IPMI_RAW_VALUE_PRESENT:
	ipmi_cmdlang_out_hex(cmd_info, "Raw Value", raw_val);
    default:
	break;
    }	

    for (thresh = IPMI_LOWER_NON_CRITICAL;
	 thresh <= IPMI_UPPER_NON_RECOVERABLE; 
	 thresh++)
    {
	int ival;

	rv = ipmi_sensor_threshold_reading_supported(sensor, thresh, &ival);
	if ((rv) || !ival)
	    continue;

	ipmi_cmdlang_out(cmd_info, "Threshold", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Name",
			 ipmi_get_threshold_string(thresh));
	ipmi_cmdlang_out_bool(cmd_info, "Out Of Range",
			      ipmi_is_threshold_out_of_range(states, thresh));
	ipmi_cmdlang_up(cmd_info);
    }
    ipmi_cmdlang_up(cmd_info);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
read_sensor_states(ipmi_sensor_t *sensor,
		   int           err,
		   ipmi_states_t *states,
		   void          *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             i;
    char            sensor_name[IPMI_SENSOR_NAME_LEN];
    int             rv;

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error reading sensor";
	cmdlang->err = err;
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(read_sensor_states)";
	goto out;
    }

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));

    ipmi_cmdlang_out(cmd_info, "Sensor", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", sensor_name);

    ipmi_cmdlang_out_bool(cmd_info, "Event Messages Enabled",
			  ipmi_is_event_messages_enabled(states));
    ipmi_cmdlang_out_bool(cmd_info, "Sensor Scanning Enabled",
			  ipmi_is_sensor_scanning_enabled(states));
    ipmi_cmdlang_out_bool(cmd_info, "Initial Update In Progress",
			  ipmi_is_initial_update_in_progress(states));
    for (i=0; i<15; i++) {
	int        ival;
	const char *str;

	rv = ipmi_sensor_discrete_event_readable(sensor, i, &ival);
	if ((rv) || !ival)
	    continue;

	ipmi_cmdlang_out(cmd_info, "Event", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out_int(cmd_info, "Offset", i);
	str = ipmi_sensor_reading_name_string(sensor, i);
	if (strcmp(str, "unknown") != 0)
	    ipmi_cmdlang_out(cmd_info, "Name", str);
	ipmi_cmdlang_out_bool(cmd_info, "Set", ipmi_is_state_set(states, i));
	ipmi_cmdlang_up(cmd_info);
    }
    ipmi_cmdlang_up(cmd_info);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
sensor_get(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    if (ipmi_sensor_get_event_reading_type(sensor)
	== IPMI_EVENT_READING_TYPE_THRESHOLD)
    {
	rv = ipmi_sensor_get_reading(sensor, read_sensor, cmd_info);
    } else {
	rv = ipmi_sensor_get_states(sensor, read_sensor_states, cmd_info);
    }
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Error reading sensor";
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(sensor_get)";
    }
}

static void
sensor_rearm_done(ipmi_sensor_t *sensor,
		  int           err,
		  void          *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            sensor_name[IPMI_SENSOR_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error rearming sensor";
	cmdlang->err = err;
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(sensor_rearm_done)";
	goto out;
    }

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));
    ipmi_cmdlang_out(cmd_info, "Rearm done", sensor_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
sensor_rearm(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_cmd_info_t    *cmd_info = cb_data;
    ipmi_cmdlang_t     *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int                rv;
    int                curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int                argc = ipmi_cmdlang_get_argc(cmd_info);
    char               **argv = ipmi_cmdlang_get_argv(cmd_info);
    int                global;
    ipmi_event_state_t *s = NULL;

    if ((argc - curr_arg) < 1) {
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    if (strcmp(argv[curr_arg], "global") == 0) {
	global = 1;
    } else {
	global = 0;
	s = ipmi_mem_alloc(ipmi_event_state_size());
	if (!s) {
	    cmdlang->errstr = "Out of memory";
	    cmdlang->err = ENOMEM;
	    goto out_err;
	}
	ipmi_event_state_init(s);

	if (ipmi_sensor_get_event_reading_type(sensor)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    enum ipmi_thresh_e          thresh;
	    enum ipmi_event_value_dir_e value_dir;
	    enum ipmi_event_dir_e       dir;

	    while (curr_arg < argc) {
		ipmi_cmdlang_get_threshold_ev(argv[curr_arg], &thresh,
					      &value_dir, &dir, cmd_info);
		if (cmdlang->err) {
		    goto out_err;
		}
		ipmi_threshold_event_set(s, thresh, value_dir, dir);
		curr_arg++;
	    }
	} else {
	    int                   offset;
	    enum ipmi_event_dir_e dir;
	    
	    while (curr_arg < argc) {
		ipmi_cmdlang_get_discrete_ev(argv[curr_arg], &offset,
					     &dir, cmd_info);
		if (cmdlang->err) {
		    goto out_err;
		}
		ipmi_discrete_event_set(s, offset, dir);
		curr_arg++;
	    }
	}
    }

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_sensor_rearm(sensor, global, s, sensor_rearm_done, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Error rearming sensor";
	goto out_err;
    }

    if (s)
	ipmi_mem_free(s);
    return;

 out_err:
    ipmi_sensor_get_name(sensor, cmdlang->objstr,
			 cmdlang->objstr_len);
    cmdlang->location = "cmd_sensor.c(sensor_rearm)";
    if (s)
	ipmi_mem_free(s);
}

static void
sensor_get_thresholds_done(ipmi_sensor_t     *sensor,
			   int               err,
			   ipmi_thresholds_t *th,
			   void              *cb_data)
{
    ipmi_cmd_info_t    *cmd_info = cb_data;
    ipmi_cmdlang_t     *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char               sensor_name[IPMI_SENSOR_NAME_LEN];
    enum ipmi_thresh_e thresh;
    int                rv;

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error reading sensor thresholds";
	cmdlang->err = err;
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(sensor_get_thresholds_done)";
	goto out;
    }

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));
    ipmi_cmdlang_out(cmd_info, "Sensor", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", sensor_name);

    for (thresh = IPMI_LOWER_NON_CRITICAL;
	 thresh <= IPMI_UPPER_NON_RECOVERABLE; 
	 thresh++)
    {
	int ival;
	double dval;

	rv = ipmi_sensor_threshold_reading_supported(sensor, thresh, &ival);
	if ((rv) || !ival)
	    continue;

	ipmi_cmdlang_out(cmd_info, "Threshold", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Name",
			 ipmi_get_threshold_string(thresh));
	rv = ipmi_threshold_get(th, thresh, &dval);
	if (rv)
	    continue;
	ipmi_cmdlang_out_double(cmd_info, "Value", dval);
	ipmi_cmdlang_up(cmd_info);
    }
    ipmi_cmdlang_up(cmd_info);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
sensor_get_thresholds(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_cmd_info_t    *cmd_info = cb_data;
    ipmi_cmdlang_t     *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int                rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_sensor_get_thresholds(sensor, sensor_get_thresholds_done,
				    cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Error getting thresholds";
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(sensor_get_thresholds)";
    }
}

static void
sensor_set_thresholds_done(ipmi_sensor_t *sensor,
			   int           err,
			   void          *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            sensor_name[IPMI_SENSOR_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error setting sensor thresholds";
	cmdlang->err = err;
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(sensor_set_thresholds_done)";
	goto out;
    }

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));
    ipmi_cmdlang_out(cmd_info, "Thresholds set", sensor_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
sensor_set_thresholds(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_cmd_info_t    *cmd_info = cb_data;
    ipmi_cmdlang_t     *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int                rv;
    int                curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int                argc = ipmi_cmdlang_get_argc(cmd_info);
    char               **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_thresholds_t  *th = NULL;
    enum ipmi_thresh_e thresh;
    double             val;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    th = ipmi_mem_alloc(ipmi_thresholds_size());
    if (!th) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	goto out_err;
    }
    ipmi_thresholds_init(th);
    while (curr_arg < argc) {
	ipmi_cmdlang_get_threshold(argv[curr_arg], &thresh, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "Invalid threshold";
	    goto out_err;
	}
	curr_arg++;

	ipmi_cmdlang_get_double(argv[curr_arg], &val, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "Invalid threshold value";
	    goto out_err;
	}
	curr_arg++;

	rv = ipmi_threshold_set(th, sensor, thresh, val);
	if (rv) {
	    cmdlang->errstr = "Error setting value";
	    cmdlang->err = rv;
	    goto out_err;
	}
    }

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_sensor_set_thresholds(sensor, th, sensor_set_thresholds_done,
				    cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Error setting thresholds";
	goto out_err;
    }
    ipmi_mem_free(th);
    return;

 out_err:
    ipmi_sensor_get_name(sensor, cmdlang->objstr,
			 cmdlang->objstr_len);
    cmdlang->location = "cmd_sensor.c(sensor_set_thresholds)";
    if (th)
	ipmi_mem_free(th);
}

static void
sensor_get_hysteresis_done(ipmi_sensor_t *sensor,
			   int           err,
			   unsigned int  positive_hysteresis,
			   unsigned int  negative_hysteresis,
			   void          *cb_data)
{
    ipmi_cmd_info_t    *cmd_info = cb_data;
    ipmi_cmdlang_t     *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char               sensor_name[IPMI_SENSOR_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error reading sensor hysteresis";
	cmdlang->err = err;
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(sensor_get_hysteresis_done)";
	goto out;
    }

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));
    ipmi_cmdlang_out(cmd_info, "Sensor", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", sensor_name);

    ipmi_cmdlang_out_int(cmd_info, "Positive Hysteresis",
			 positive_hysteresis);
    ipmi_cmdlang_out_int(cmd_info, "Negative Hysteresis",
			 negative_hysteresis);

    ipmi_cmdlang_up(cmd_info);
    

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
sensor_get_hysteresis(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_cmd_info_t    *cmd_info = cb_data;
    ipmi_cmdlang_t     *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int                rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_sensor_get_hysteresis(sensor, sensor_get_hysteresis_done,
				    cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Error getting hysteresis";
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(sensor_get_hysteresis)";
    }
}

static void
sensor_set_hysteresis_done(ipmi_sensor_t *sensor,
			   int           err,
			   void          *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            sensor_name[IPMI_SENSOR_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error setting sensor hysteresis";
	cmdlang->err = err;
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(sensor_set_hysteresis_done)";
	goto out;
    }

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));
    ipmi_cmdlang_out(cmd_info, "Hysteresis set", sensor_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
sensor_set_hysteresis(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_cmd_info_t    *cmd_info = cb_data;
    ipmi_cmdlang_t     *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int                rv;
    int                curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int                argc = ipmi_cmdlang_get_argc(cmd_info);
    char               **argv = ipmi_cmdlang_get_argv(cmd_info);
    int                pos, neg;

    if ((argc - curr_arg) < 2) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &pos, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "Invalid positive hysteresis";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &neg, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "Invalid negative hysteresis";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_sensor_set_hysteresis(sensor, pos, neg,
				    sensor_set_hysteresis_done, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Error setting hysteresis";
	goto out_err;
    }

 out_err:
    ipmi_sensor_get_name(sensor, cmdlang->objstr,
			 cmdlang->objstr_len);
    cmdlang->location = "cmd_sensor.c(sensor_set_hysteresis)";
}

static void
sensor_get_event_enables_done(ipmi_sensor_t      *sensor,
			      int                err,
			      ipmi_event_state_t *states,
			      void               *cb_data)
{
    ipmi_cmd_info_t    *cmd_info = cb_data;
    ipmi_cmdlang_t     *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char               sensor_name[IPMI_SENSOR_NAME_LEN];
    int                rv;
    int                val;

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error reading sensor event enables";
	cmdlang->err = err;
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(sensor_get_event_enables_done)";
	goto out;
    }

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));
    ipmi_cmdlang_out(cmd_info, "Sensor", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", sensor_name);

    ipmi_cmdlang_out_bool(cmd_info, "Event Messages Enabled",
			  ipmi_event_state_get_events_enabled(states));
    ipmi_cmdlang_out_bool(cmd_info, "Sensor Scanning Enabled",
			  ipmi_event_state_get_scanning_enabled(states));
    ipmi_cmdlang_out_bool(cmd_info, "Busy",
			  ipmi_event_state_get_busy(states));

    if (ipmi_sensor_get_event_reading_type(sensor)
	== IPMI_EVENT_READING_TYPE_THRESHOLD)
    {
	enum ipmi_thresh_e          thresh;
	enum ipmi_event_value_dir_e value_dir;
	enum ipmi_event_dir_e       dir;

	for (thresh = IPMI_LOWER_NON_CRITICAL;
	     thresh <= IPMI_UPPER_NON_RECOVERABLE; 
	     thresh++)
	{
	    for (value_dir = IPMI_GOING_LOW;
		 value_dir <= IPMI_GOING_HIGH;
		 value_dir++)
	    {
		for (dir = IPMI_ASSERTION;
		     dir <= IPMI_DEASSERTION;
		     dir++)
		{
		    char th_name[50];

		    rv = ipmi_sensor_threshold_event_supported(sensor,
							       thresh,
							       value_dir,
							       dir,
							       &val);
		    if (rv || !val) continue;

		    ipmi_cmdlang_out(cmd_info, "Threshold", NULL);
		    ipmi_cmdlang_down(cmd_info);
		    snprintf(th_name, sizeof(th_name), "%s %s %s",
			     ipmi_get_threshold_string(thresh),
			     ipmi_get_value_dir_string(value_dir),
			     ipmi_get_event_dir_string(dir));
		    ipmi_cmdlang_out(cmd_info, "Name", th_name);
		    ipmi_cmdlang_out_bool(cmd_info, "Enabled",
					  ipmi_is_threshold_event_set
					  (states, thresh, value_dir, dir));
		    ipmi_cmdlang_up(cmd_info);
		}
	    }
	}
    } else {
	int        offset;
	const char *str;

	for (offset=0; offset<15; offset++) {
	    ipmi_cmdlang_out(cmd_info, "Event", NULL);
	    ipmi_cmdlang_down(cmd_info);
	    ipmi_cmdlang_out_int(cmd_info, "Offset", offset);
	    str = ipmi_sensor_reading_name_string(sensor, offset);
	    if (strcmp(str, "unknown") != 0)
		ipmi_cmdlang_out(cmd_info, "Name", str);
	    
	    rv = ipmi_sensor_discrete_event_supported(sensor,
						      offset,
						      IPMI_ASSERTION,
						      &val);
	    if (!rv && val) {
		ipmi_cmdlang_out_bool(cmd_info, "Assertion Enabled",
				      ipmi_is_discrete_event_set
				      (states, offset, IPMI_ASSERTION));
	    }
	    rv = ipmi_sensor_discrete_event_supported(sensor,
						      offset,
						      IPMI_DEASSERTION,
						      &val);
	    if (!rv && val) {
		ipmi_cmdlang_out_bool(cmd_info, "Deassertion Enabled",
				      ipmi_is_discrete_event_set
				      (states, offset, IPMI_DEASSERTION));
	    }
	    ipmi_cmdlang_up(cmd_info);
	}
    }

    ipmi_cmdlang_up(cmd_info);
    

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
sensor_get_event_enables(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_cmd_info_t    *cmd_info = cb_data;
    ipmi_cmdlang_t     *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int                rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_sensor_get_event_enables(sensor, sensor_get_event_enables_done,
				       cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Error getting event enables";
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(sensor_get_event_enables)";
    }
}

static void
sensor_set_event_enables_done(ipmi_sensor_t *sensor,
			      int           err,
			      void          *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            sensor_name[IPMI_SENSOR_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error setting event enables";
	cmdlang->err = err;
	ipmi_sensor_get_name(sensor, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_sensor.c(sensor_set_event_enables_done)";
	goto out;
    }

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));
    ipmi_cmdlang_out(cmd_info, "Event enables set", sensor_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

enum ev_en_kind { ev_en_set, ev_en_enable, ev_en_disable };

static void
mod_event_enables(ipmi_sensor_t *sensor, void *cb_data, enum ev_en_kind kind)
{
    ipmi_cmd_info_t    *cmd_info = cb_data;
    ipmi_cmdlang_t     *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int                rv;
    int                curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int                argc = ipmi_cmdlang_get_argc(cmd_info);
    char               **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_event_state_t *s = NULL;

    if ((argc - curr_arg) < 2) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    s = ipmi_mem_alloc(ipmi_states_size());
    if (!s) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	goto out_err;
    }
    ipmi_event_state_init(s);

    if (strcmp(argv[curr_arg], "msg") == 0)
	ipmi_event_state_set_events_enabled(s, 1);
    else if (strcmp(argv[curr_arg], "nomsg") == 0)
	ipmi_event_state_set_events_enabled(s, 0);
    else {
	cmdlang->errstr = "Invalid message enable setting";
	cmdlang->err = EINVAL;
	goto out_err;
    }
    curr_arg++;

    if (strcmp(argv[curr_arg], "scan") == 0)
	ipmi_event_state_set_scanning_enabled(s, 1);
    else if (strcmp(argv[curr_arg], "noscan") == 0)
	ipmi_event_state_set_scanning_enabled(s, 0);
    else {
	cmdlang->errstr = "Invalid scanning enable setting";
	cmdlang->err = EINVAL;
	goto out_err;
    }
    curr_arg++;

    if (ipmi_sensor_get_event_reading_type(sensor)
	== IPMI_EVENT_READING_TYPE_THRESHOLD)
    {
	while (curr_arg < argc) {
	    enum ipmi_thresh_e          thresh;
	    enum ipmi_event_value_dir_e value_dir;
	    enum ipmi_event_dir_e       dir;

	    ipmi_cmdlang_get_threshold_ev(argv[curr_arg], &thresh,
					  &value_dir, &dir, cmd_info);
	    if (cmdlang->err) {
		goto out_err;
	    }
	    ipmi_threshold_event_set(s, thresh, value_dir, dir);
	    curr_arg++;
	}
    } else {
	while (curr_arg < argc) {
	    int                   offset;
	    enum ipmi_event_dir_e dir;

	    ipmi_cmdlang_get_discrete_ev(argv[curr_arg], &offset,
					 &dir, cmd_info);
	    if (cmdlang->err) {
		goto out_err;
	    }
	    ipmi_discrete_event_set(s, offset, dir);
	    curr_arg++;
	}
    }

    ipmi_cmdlang_cmd_info_get(cmd_info);
    switch (kind) {
    case ev_en_set:
	rv = ipmi_sensor_set_event_enables(sensor, s,
					   sensor_set_event_enables_done,
					   cmd_info);
	break;
    case ev_en_enable:
	rv = ipmi_sensor_enable_events(sensor, s,
				       sensor_set_event_enables_done,
				       cmd_info);
	break;
    case ev_en_disable:
	rv = ipmi_sensor_disable_events(sensor, s,
					sensor_set_event_enables_done,
					cmd_info);
	break;
    default:
	rv = EINVAL;
    }

    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Error setting event enables";
	goto out_err;
    }
    ipmi_mem_free(s);
    return;

 out_err:
    ipmi_sensor_get_name(sensor, cmdlang->objstr,
			 cmdlang->objstr_len);
    cmdlang->location = "cmd_sensor.c(sensor_set_event_enables)";
    if (s)
	ipmi_mem_free(s);
}

static void
sensor_set_event_enables(ipmi_sensor_t *sensor, void *cb_data)
{
    mod_event_enables(sensor, cb_data, ev_en_set);
}

static void
sensor_enable_events(ipmi_sensor_t *sensor, void *cb_data)
{
    mod_event_enables(sensor, cb_data, ev_en_enable);
}

static void
sensor_disable_events(ipmi_sensor_t *sensor, void *cb_data)
{
    mod_event_enables(sensor, cb_data, ev_en_disable);
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
    ipmi_cmd_info_t *evi;
    char            sensor_name[IPMI_SENSOR_NAME_LEN];
    int             rv;
    char            *errstr;

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Sensor");
    ipmi_cmdlang_out(evi, "Name", sensor_name);
    ipmi_cmdlang_out(evi, "Operation", "Event");
    ipmi_cmdlang_out_int(evi, "Offset", offset);
    ipmi_cmdlang_out(evi, "Direction", ipmi_get_event_dir_string(dir));
    ipmi_cmdlang_out_int(evi, "Severity", severity);
    ipmi_cmdlang_out_int(evi, "Previous Severity", prev_severity);
    if (event) {
	ipmi_cmdlang_out(evi, "Event", NULL);
	ipmi_cmdlang_down(evi);
	ipmi_cmdlang_event_out(event, evi);
	ipmi_cmdlang_up(evi);
    }
    ipmi_cmdlang_cmd_info_put(evi);
    return IPMI_EVENT_NOT_HANDLED;

 out_err:
    ipmi_cmdlang_global_err(sensor_name,
			    "cmd_sensor.c(sensor_discrete_event_handler)",
			    errstr, rv);
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
    return IPMI_EVENT_NOT_HANDLED;
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
    ipmi_cmd_info_t *evi;
    char            sensor_name[IPMI_SENSOR_NAME_LEN];
    int             rv;
    char            *errstr;

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Sensor");
    ipmi_cmdlang_out(evi, "Name", sensor_name);
    ipmi_cmdlang_out(evi, "Operation", "Event");
    ipmi_cmdlang_out(evi, "Threshold", ipmi_get_threshold_string(threshold));
    ipmi_cmdlang_out(evi, "High/Low", ipmi_get_value_dir_string(high_low));
    ipmi_cmdlang_out(evi, "Direction", ipmi_get_event_dir_string(dir));
    switch (value_present) {
    case IPMI_BOTH_VALUES_PRESENT:
	ipmi_cmdlang_out_double(evi, "Value", value);
	/* FALLTHRU */
    case IPMI_RAW_VALUE_PRESENT:
	ipmi_cmdlang_out_int(evi, "Raw Value", raw_value);
	break;

    default:
	break;
    }
    if (event) {
	ipmi_cmdlang_out(evi, "Event", NULL);
	ipmi_cmdlang_down(evi);
	ipmi_cmdlang_event_out(event, evi);
	ipmi_cmdlang_up(evi);
    }
    ipmi_cmdlang_cmd_info_put(evi);
    return IPMI_EVENT_NOT_HANDLED;

 out_err:
    ipmi_cmdlang_global_err(sensor_name,
			    "cmd_sensor.c(sensor_threshold_event_handler)",
			    errstr, rv);
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
    return IPMI_EVENT_NOT_HANDLED;
}

void
ipmi_cmdlang_sensor_change(enum ipmi_update_e op,
			   ipmi_entity_t      *entity,
			   ipmi_sensor_t      *sensor,
			   void               *cb_data)
{
    char            *errstr;
    int             rv;
    ipmi_cmd_info_t *evi;
    char            sensor_name[IPMI_SENSOR_NAME_LEN];

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Sensor");
    ipmi_cmdlang_out(evi, "Name", sensor_name);

    switch (op) {
    case IPMI_ADDED:
	ipmi_cmdlang_out(evi, "Operation", "Add");
	if (ipmi_cmdlang_get_evinfo())
	    sensor_dump(sensor, evi);

	if (ipmi_sensor_get_event_reading_type(sensor)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    rv = ipmi_sensor_add_threshold_event_handler
		(sensor,
		 sensor_threshold_event_handler,
		 NULL);
	} else {
	    rv = ipmi_sensor_add_discrete_event_handler
		(sensor,
		 sensor_discrete_event_handler,
		 NULL);
	}
	if (rv) {
	    ipmi_cmdlang_global_err(sensor_name,
				    "cmd_sensor.c(ipmi_cmdlang_sensor_change)",
				    "Unable to set event handler for sensor",
				    rv);
	}
	break;

	case IPMI_DELETED:
	    ipmi_cmdlang_out(evi, "Operation", "Delete");
	    break;

	case IPMI_CHANGED:
	    ipmi_cmdlang_out(evi, "Operation", "Change");
	    if (ipmi_cmdlang_get_evinfo())
		sensor_dump(sensor, evi);
	    break;
    }

    ipmi_cmdlang_cmd_info_put(evi);
    return;

 out_err:
    ipmi_cmdlang_global_err(sensor_name,
			    "cmd_sensor.c(ipmi_cmdlang_sensor_change)",
			    errstr, rv);
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
}

static ipmi_cmdlang_cmd_t *sensor_cmds;

static ipmi_cmdlang_init_t cmds_sensor[] =
{
    { "sensor", NULL,
      "- Commands dealing with sensors",
      NULL, NULL, &sensor_cmds },
    { "list", &sensor_cmds,
      "- List all the entities in the system",
      ipmi_cmdlang_entity_handler, sensor_list, NULL },
    { "info", &sensor_cmds,
      "<sensor> - Dump information about an sensor",
      ipmi_cmdlang_sensor_handler, sensor_info, NULL },
    { "get", &sensor_cmds,
      "<sensor> - Get the sensor's current reading",
      ipmi_cmdlang_sensor_handler, sensor_get, NULL },
    { "rearm", &sensor_cmds,
      "<sensor> global | <thresholds> | <discrete states> - "
      " Rearm the sensor.  If global is specified, then rearm"
      " all events in the sensor.  If it is a threshold sensor, then"
      " put in a list of thresholds of the form '[ul][ncr][hl][ad]"
      " where [ul] means upper or lower, [ncr] means non-critical,"
      " critical, or non-recoverable, [hl] means going high or going"
      " low, and [ad] means assertion or deassertion.  If it is a"
      " discrete sensor, then the form is <num>[ad] where the number"
      " is the offset and [ad] means assertion or deassertion",
      ipmi_cmdlang_sensor_handler, sensor_rearm, NULL },
    { "get_thresholds", &sensor_cmds,
      "<sensor> - Get the sensor's thresholds",
      ipmi_cmdlang_sensor_handler, sensor_get_thresholds, NULL },
    { "set_thresholds", &sensor_cmds,
      "<sensor> <threshold> <value> ... - Set the sensor's thresholds to"
      " the given values.  If a threshold is not specified, it will not"
      " be modified.  Thresholds are un, uc, ur, lr, lc, ln.  The u stands"
      " for upper, l for lower, n for non-critical, c for critical, and"
      " r for non-recoverable.  The value is floating point.",
      ipmi_cmdlang_sensor_handler, sensor_set_thresholds, NULL },
    { "get_hysteresis", &sensor_cmds,
      "<sensor> - Get the sensor's hysteresis values",
      ipmi_cmdlang_sensor_handler, sensor_get_hysteresis, NULL },
    { "set_hysteresis", &sensor_cmds,
      "<sensor> <pos hyst> <neg hyst> - Set the sensor's"
      " hysteresis to the given values.  These are raw integer"
      " value; hystersis is specified as a raw value and it cannot be"
      " converted to floating point because the function may be"
      " non-linear.",
      ipmi_cmdlang_sensor_handler, sensor_set_hysteresis, NULL },
    { "get_event_enables", &sensor_cmds,
      "<sensor> - Get the sensor's event enable values",
      ipmi_cmdlang_sensor_handler, sensor_get_event_enables, NULL },
    { "set_event_enables", &sensor_cmds,
      "<sensor> msg|nomsg scan|noscan [<event> [<event> ...]]- Set the"
      " sensor's event enable values.  This turns sensor messages and"
      " scanning on and off and will enable all the listed events and"
      " disable all over events.  The"
      " events are in the same format as the rearm subcommand and depend"
      " on the sensor type.  See the rearm command for details.",
      ipmi_cmdlang_sensor_handler, sensor_set_event_enables, NULL },
    { "enable_events", &sensor_cmds,
      "<sensor> msg|nomsg scan|noscan [<event> [<event> ...]]- Enable"
      " event enable values.  This turns sensor messages and"
      " scanning on and off and will enable all the listed events.  The"
      " events are in the same format as the rearm subcommand and depend"
      " on the sensor type.  See the rearm command for details.  This will"
      " only enable the given events, the other events will be left alone.",
      ipmi_cmdlang_sensor_handler, sensor_enable_events, NULL },
    { "disable_events", &sensor_cmds,
      "<sensor> msg|nomsg scan|noscan [<event> [<event> ...]]- Disable"
      " event enable values.  This turns sensor messages and"
      " scanning on and off and will disable all the listed events.  The"
      " events are in the same format as the rearm subcommand and depend"
      " on the sensor type.  See the rearm command for details.  This will"
      " only disable the given events, the other events will be left alone.",
      ipmi_cmdlang_sensor_handler, sensor_disable_events, NULL },
};
#define CMDS_SENSOR_LEN (sizeof(cmds_sensor)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_sensor_init(os_handler_t *os_hnd)
{
    return ipmi_cmdlang_reg_table(cmds_sensor, CMDS_SENSOR_LEN);
}
