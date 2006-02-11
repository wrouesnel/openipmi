/*
 * cmd_control.c
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
control_list_handler(ipmi_entity_t *entity, ipmi_control_t *control,
		     void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            control_name[IPMI_CONTROL_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_control_get_name(control, control_name, sizeof(control_name));

    ipmi_cmdlang_out(cmd_info, "Name", control_name);
}

static void
control_list(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            entity_name[IPMI_ENTITY_NAME_LEN];

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));
    ipmi_cmdlang_out(cmd_info, "Entity", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", entity_name);
    ipmi_cmdlang_out(cmd_info, "Controls", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_entity_iterate_controls(entity, control_list_handler, cmd_info);
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static void
control_dump(ipmi_control_t *control, ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             num;
    char            *str;
    int             len;
    int             val, val2, val3;
    int             i, j, k;

    ipmi_cmdlang_out(cmd_info, "Type", ipmi_control_get_type_string(control));
    ipmi_cmdlang_out_bool(cmd_info, "Generates events",
			  ipmi_control_has_events(control));
    ipmi_cmdlang_out_bool(cmd_info, "Settable",
			  ipmi_control_is_settable(control));
    ipmi_cmdlang_out_bool(cmd_info, "Readable",
			  ipmi_control_is_readable(control));
    num = ipmi_control_get_num_vals(control);
    ipmi_cmdlang_out_int(cmd_info, "Num Values", num);
    len = ipmi_control_get_id_length(control);
    if (len) {
	str = ipmi_mem_alloc(len);
	if (!str) {
	    cmdlang->err = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	    goto out_err;
	}
	len = ipmi_control_get_id(control, str, len);
	ipmi_cmdlang_out_type(cmd_info, "Id",
			      ipmi_control_get_id_type(control),
			      str, len);
	ipmi_mem_free(str);
    }

    switch (ipmi_control_get_type(control)) {
    case IPMI_CONTROL_LIGHT:
	val = ipmi_control_light_set_with_setting(control);
	if (val) {
	    ipmi_cmdlang_out(cmd_info, "Set with", "settings");
	    for (j=0; j<num; j++) {
		ipmi_cmdlang_out(cmd_info, "Light", NULL);
		ipmi_cmdlang_down(cmd_info);
		ipmi_cmdlang_out_int(cmd_info, "Number", j);
		val = ipmi_control_light_has_loc_ctrl(control, j);
		ipmi_cmdlang_out_bool(cmd_info, "Local Control", val);
		for (i=IPMI_CONTROL_COLOR_BLACK;
		     i<IPMI_CONTROL_COLOR_ORANGE;
		     i++)
		{
		    val = ipmi_control_light_is_color_sup(control, j, i);
		    if (val)
			ipmi_cmdlang_out(cmd_info, "Color",
					 ipmi_get_color_string(i));
		}
		ipmi_cmdlang_up(cmd_info);
	    }
	} else {
	    ipmi_cmdlang_out(cmd_info, "Set with", "transitions");
	    for (i=0; i<num; i++) {
		ipmi_cmdlang_out(cmd_info, "Light", NULL);
		ipmi_cmdlang_down(cmd_info);
		ipmi_cmdlang_out_int(cmd_info, "Number", i);
		val = ipmi_control_get_num_light_values(control, i);
		ipmi_cmdlang_out_int(cmd_info, "Num Values", val);
		for (j=0; j<val; j++) {
		    ipmi_cmdlang_out(cmd_info, "Value", NULL);
		    ipmi_cmdlang_down(cmd_info);
		    ipmi_cmdlang_out_int(cmd_info, "Number", j);
		    val2 = ipmi_control_get_num_light_transitions(control,
								  i, j);
		    ipmi_cmdlang_out_int(cmd_info, "Num Transitions", val2);
		    for (k=0; k<val2; k++) {
			ipmi_cmdlang_out(cmd_info, "Transition", NULL);
			ipmi_cmdlang_down(cmd_info);
			ipmi_cmdlang_out_int(cmd_info, "Number", k);
			val3 = ipmi_control_get_light_color(control, i, j, k);
			ipmi_cmdlang_out(cmd_info, "Color",
					 ipmi_get_color_string(val3));
			ipmi_cmdlang_out_int(cmd_info, "Time",
					     ipmi_control_get_light_color_time
					     (control, i, j, k));
			ipmi_cmdlang_up(cmd_info);
		    }
		    ipmi_cmdlang_up(cmd_info);
		}
		ipmi_cmdlang_up(cmd_info);
	    }
	}
	break;

    case IPMI_CONTROL_IDENTIFIER:
	ipmi_cmdlang_out_int(cmd_info, "Max Length",
			     ipmi_control_identifier_get_max_length(control));
	break;

    case IPMI_CONTROL_DISPLAY:
	break;

    case IPMI_CONTROL_RELAY:
    case IPMI_CONTROL_ALARM:
    case IPMI_CONTROL_RESET:
    case IPMI_CONTROL_POWER:
    case IPMI_CONTROL_FAN_SPEED:
    case IPMI_CONTROL_ONE_SHOT_RESET:
    case IPMI_CONTROL_OUTPUT:
    case IPMI_CONTROL_ONE_SHOT_OUTPUT:
	break;
    }
    return;

 out_err:
    ipmi_control_get_name(control, cmdlang->objstr,
			 cmdlang->objstr_len);
    cmdlang->location = "cmd_control.c(control_dump)";
}

static void
control_info(ipmi_control_t *control, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            control_name[IPMI_CONTROL_NAME_LEN];

    ipmi_control_get_name(control, control_name, sizeof(control_name));

    ipmi_cmdlang_out(cmd_info, "Control", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", control_name);
    control_dump(control, cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static void
control_set_done(ipmi_control_t *control,
		 int            err,
		 void           *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            control_name[IPMI_CONTROL_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error setting control";
	cmdlang->err = err;
	ipmi_control_get_name(control, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->location = "cmd_control.c(control_set_done)";
	goto out;
    }

    ipmi_control_get_name(control, control_name, sizeof(control_name));
    ipmi_cmdlang_out(cmd_info, "Set done", control_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
control_set(ipmi_control_t *control, void *cb_data)
{
    ipmi_cmd_info_t      *cmd_info = cb_data;
    ipmi_cmdlang_t       *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int                  *data = NULL;
    unsigned char        *ucdata = NULL;
    int                  num;
    int                  i;
    int                  rv;
    int                  curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int                  argc = ipmi_cmdlang_get_argc(cmd_info);
    char                 **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_light_setting_t *s = NULL;


    num = ipmi_control_get_num_vals(control);
    if ((argc - curr_arg) < num) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    switch (ipmi_control_get_type(control)) {
    case IPMI_CONTROL_LIGHT:
	if (!ipmi_control_light_set_with_setting(control))
	    goto normal_val_set;

	s = ipmi_alloc_light_settings(num);
	if (!s) {
	    cmdlang->errstr = "Out of memory";
	    cmdlang->err = ENOMEM;
	    goto out_err;
	}

	for (i=0; i<num; i++) {
	    int val;

	    if (strcmp(argv[curr_arg], "lc") == 0) {
		ipmi_light_setting_set_local_control(s, i, 1);
		continue;
	    } else if (strcmp(argv[curr_arg], "nolc") == 0) {
		ipmi_light_setting_set_local_control(s, i, 0);
	    } else {
		cmdlang->errstr = "Invalid local control setting";
		cmdlang->err = EINVAL;
		goto out_err;
	    }
	    curr_arg++;

	    ipmi_cmdlang_get_color(argv[curr_arg], &val, cmd_info);
	    if (cmdlang->err)
		goto out_err;
	    rv = ipmi_light_setting_set_color(s, i, val);
	    if (rv) {
		cmdlang->errstr = "Error setting color";
		cmdlang->err = rv;
		goto out_err;
	    }
	    curr_arg++;

	    ipmi_cmdlang_get_int(argv[curr_arg], &val, cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "Invalid on time";
		goto out_err;
	    }
	    rv = ipmi_light_setting_set_on_time(s, i, val);
	    if (rv) {
		cmdlang->errstr = "Error setting on time";
		cmdlang->err = rv;
		goto out_err;
	    }
	    curr_arg++;

	    ipmi_cmdlang_get_int(argv[curr_arg], &val, cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "Invalid off time";
		goto out_err;
	    }
	    rv = ipmi_light_setting_set_off_time(s, i, val);
	    if (rv) {
		cmdlang->errstr = "Error setting off time";
		cmdlang->err = rv;
		goto out_err;
	    }
	    curr_arg++;
	}

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_control_set_light(control, s, control_set_done,
				    cmd_info);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->errstr = "Error setting light control";
	    cmdlang->err = rv;
	    goto out_err;
	}
	ipmi_free_light_settings(s);
	break;

    case IPMI_CONTROL_IDENTIFIER:
	num = ipmi_control_identifier_get_max_length(control);
	ucdata = ipmi_mem_alloc(num);
	if (!ucdata) {
	    cmdlang->errstr = "Out of memory";
	    cmdlang->err = ENOMEM;
	    goto out_err;
	}
	for (i=0; i<num; i++) {
	    ipmi_cmdlang_get_uchar(argv[curr_arg], &ucdata[i], cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "value invalid";
		goto out_err;
	    }
	    curr_arg++;
	}
	
	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_control_identifier_set_val(control, ucdata, i,
					     control_set_done, cmd_info);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->errstr = "Error setting id control";
	    cmdlang->err = rv;
	    goto out_err;
	}
	ipmi_mem_free(ucdata);
	break;

    case IPMI_CONTROL_DISPLAY:
	cmdlang->errstr = "Setting displays not currently supported";
	cmdlang->err = ENOSYS;
	goto out_err;
	break;

    case IPMI_CONTROL_RELAY:
    case IPMI_CONTROL_ALARM:
    case IPMI_CONTROL_RESET:
    case IPMI_CONTROL_POWER:
    case IPMI_CONTROL_FAN_SPEED:
    case IPMI_CONTROL_ONE_SHOT_RESET:
    case IPMI_CONTROL_OUTPUT:
    case IPMI_CONTROL_ONE_SHOT_OUTPUT:
    normal_val_set:
	data = ipmi_mem_alloc(num * sizeof(int));
	if (!data) {
	    cmdlang->errstr = "Out of memory";
	    cmdlang->err = ENOMEM;
	    goto out_err;
	}
	for (i=0; i<num; i++) {
	    ipmi_cmdlang_get_int(argv[curr_arg], &data[i], cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "value invalid";
		goto out_err;
	    }
	    curr_arg++;
	}

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_control_set_val(control, data, control_set_done, cmd_info);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->errstr = "Error setting control";
	    cmdlang->err = rv;
	    goto out_err;
	}
	ipmi_mem_free(data);
	break;
    }
    return;

 out_err:
    ipmi_control_get_name(control, cmdlang->objstr,
			 cmdlang->objstr_len);
    cmdlang->location = "cmd_control.c(control_set)";
    if (s)
	ipmi_free_light_settings(s);
    if (ucdata)
	ipmi_mem_free(ucdata);
    if (data)
	ipmi_mem_free(data);
}

static void
control_get_light_done(ipmi_control_t       *control,
		       int                  err,
		       ipmi_light_setting_t *s,
		       void                 *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             i, num;
    int             rv;

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error setting control";
	cmdlang->err = err;
	goto out;
    }

    num = ipmi_light_setting_get_count(s);
    for (i=0; i<num; i++) {
	int val;

	ipmi_cmdlang_out(cmd_info, "Light", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out_int(cmd_info, "Num", i);
	rv = ipmi_light_setting_in_local_control(s, i, &val);
	if (rv) {
	    cmdlang->errstr = "Error getting if in local control";
	    cmdlang->err = rv;
	    goto out;
	}
	ipmi_cmdlang_out_bool(cmd_info, "Local Control", val);
	if (!val) {
	    rv = ipmi_light_setting_get_color(s, i, &val);
	    if (rv) {
		cmdlang->errstr = "Error getting color";
		cmdlang->err = rv;
		goto out;
	    }
	    ipmi_cmdlang_out(cmd_info, "Color", ipmi_get_color_string(val));

	    rv = ipmi_light_setting_get_on_time(s, i, &val);
	    if (rv) {
		cmdlang->errstr = "Error getting on time";
		cmdlang->err = rv;
		goto out;
	    }
	    ipmi_cmdlang_out_int(cmd_info, "On Time", val);

	    rv = ipmi_light_setting_get_off_time(s, i, &val);
	    if (rv) {
		cmdlang->errstr = "Error getting off time";
		cmdlang->err = rv;
		goto out;
	    }
	    ipmi_cmdlang_out_int(cmd_info, "Off Time", val);
	}
	ipmi_cmdlang_up(cmd_info);
    }

 out:
    if (cmdlang->err) {
	ipmi_control_get_name(control, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->location = "cmd_control.c(control_get_light_done)";
    }
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
control_get_id_done(ipmi_control_t *control,
		    int            err,
		    unsigned char  *val,
		    int            length,
		    void           *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error setting control";
	cmdlang->err = err;
	goto out;
    }

    ipmi_cmdlang_out_binary(cmd_info, "Data", (char *) val, length);

 out:
    if (cmdlang->err) {
	ipmi_control_get_name(control, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->location = "cmd_control.c(control_get_light_done)";
    }
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
control_get_done(ipmi_control_t *control,
		 int            err,
		 int            *val,
		 void           *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             i, num;
    char            control_name[IPMI_CONTROL_NAME_LEN];

    ipmi_control_get_name(control, control_name, sizeof(control_name));

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error setting control";
	cmdlang->err = err;
	goto out;
    }

    ipmi_cmdlang_out(cmd_info, "Control", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", control_name);
    num = ipmi_control_get_num_vals(control);
    for (i=0; i<num; i++) {
	ipmi_cmdlang_out(cmd_info, "Value", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out_int(cmd_info, "Num", i);
	ipmi_cmdlang_out_int(cmd_info, "Value", val[i]);
	ipmi_cmdlang_up(cmd_info);
    }
    ipmi_cmdlang_up(cmd_info);

 out:
    if (cmdlang->err) {
	ipmi_control_get_name(control, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->location = "cmd_control.c(control_get_light_done)";
    }
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
control_get(ipmi_control_t *control, void *cb_data)
{
    ipmi_cmd_info_t      *cmd_info = cb_data;
    ipmi_cmdlang_t       *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int                  rv;


    switch (ipmi_control_get_type(control)) {
    case IPMI_CONTROL_LIGHT:
	if (!ipmi_control_light_set_with_setting(control))
	    goto normal_val_get;

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_control_get_light(control, control_get_light_done, cmd_info);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->errstr = "Error getting light control";
	    cmdlang->err = rv;
	    goto out_err;
	}
	break;

    case IPMI_CONTROL_IDENTIFIER:
	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_control_identifier_get_val(control, 
					     control_get_id_done, cmd_info);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->errstr = "Error getting id control";
	    cmdlang->err = rv;
	    goto out_err;
	}
	break;

    case IPMI_CONTROL_DISPLAY:
	cmdlang->errstr = "Getting displays not currently supported";
	cmdlang->err = ENOSYS;
	goto out_err;
	break;

    case IPMI_CONTROL_RELAY:
    case IPMI_CONTROL_ALARM:
    case IPMI_CONTROL_RESET:
    case IPMI_CONTROL_POWER:
    case IPMI_CONTROL_FAN_SPEED:
    case IPMI_CONTROL_ONE_SHOT_RESET:
    case IPMI_CONTROL_OUTPUT:
    case IPMI_CONTROL_ONE_SHOT_OUTPUT:
    normal_val_get:
	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_control_get_val(control, control_get_done, cmd_info);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->errstr = "Error getting control";
	    cmdlang->err = rv;
	    goto out_err;
	}
	break;
    }
    return;

 out_err:
    ipmi_control_get_name(control, cmdlang->objstr,
			 cmdlang->objstr_len);
    cmdlang->location = "cmd_control.c(control_get)";
}

static int
control_event_handler(ipmi_control_t *control,
		      int            *valid_vals,
		      int            *vals,
		      void           *cb_data,
		      ipmi_event_t   *event)
{
    ipmi_cmd_info_t *evi;
    char            control_name[IPMI_CONTROL_NAME_LEN];
    int             rv;
    char            *errstr;
    int             i;
    int             num;

    ipmi_control_get_name(control, control_name, sizeof(control_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Control");
    ipmi_cmdlang_out(evi, "Name", control_name);
    ipmi_cmdlang_out(evi, "Operation", "Event");
    num = ipmi_control_get_num_vals(control);
    for (i=0; i<num; i++) {
	if (!valid_vals[i])
	    continue;
	ipmi_cmdlang_out(evi, "Value", NULL);
	ipmi_cmdlang_down(evi);
	ipmi_cmdlang_out_int(evi, "Number", i);
	ipmi_cmdlang_out_int(evi, "Value", vals[i]);
	ipmi_cmdlang_up(evi);
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
    ipmi_cmdlang_global_err(control_name,
			    "cmd_control.c(ipmi_cmdlang_control_change)",
			    errstr, rv);
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
    return IPMI_EVENT_NOT_HANDLED;
}

void
ipmi_cmdlang_control_change(enum ipmi_update_e op,
			    ipmi_entity_t      *entity,
			    ipmi_control_t      *control,
			    void               *cb_data)
{
    char            *errstr;
    int             rv;
    ipmi_cmd_info_t *evi;
    char            control_name[IPMI_CONTROL_NAME_LEN];

    ipmi_control_get_name(control, control_name, sizeof(control_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Control");
    ipmi_cmdlang_out(evi, "Name", control_name);

    switch (op) {
    case IPMI_ADDED:
	ipmi_cmdlang_out(evi, "Operation", "Add");
	if (ipmi_cmdlang_get_evinfo())
	    control_dump(control, evi);

	if (ipmi_control_has_events(control)) {
	    rv = ipmi_control_add_val_event_handler(control,
						    control_event_handler,
						    NULL);
	    if (rv) {
		ipmi_cmdlang_global_err
		    (control_name,
		     "cmd_control.c(ipmi_cmdlang_control_change)",
		     "Unable to set event handler for control",
		     rv);
	    }
	}
	break;

	case IPMI_DELETED:
	    ipmi_cmdlang_out(evi, "Operation", "Delete");
	    break;

	case IPMI_CHANGED:
	    ipmi_cmdlang_out(evi, "Operation", "Change");
	    if (ipmi_cmdlang_get_evinfo())
		control_dump(control, evi);
	    break;
    }

    ipmi_cmdlang_cmd_info_put(evi);
    return;

 out_err:
    ipmi_cmdlang_global_err(control_name,
			    "cmd_control.c(ipmi_cmdlang_control_change)",
			    errstr, rv);
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
}

static ipmi_cmdlang_cmd_t *control_cmds;

static ipmi_cmdlang_init_t cmds_control[] =
{
    { "control", NULL,
      "- Commands dealing with controls",
      NULL, NULL, &control_cmds },
    { "list", &control_cmds,
      "- List all the entities in the system",
      ipmi_cmdlang_entity_handler, control_list, NULL },
    { "info", &control_cmds,
      "<control> - Dump information about an control",
      ipmi_cmdlang_control_handler, control_info, NULL },
    { "set", &control_cmds,
      "<control> <values> - Set the value of a control.  The settings"
      " depend on control type, most take one or more integer values. "
      " An identifier type takes one or more unsigned characters.  A"
      " light set with settings take the form 'lc|nolc <color> <on time>"
      " <off time>.  lc and nolc turn on or of local control, the over"
      " values should be obvious.",
      ipmi_cmdlang_control_handler, control_set, NULL },
    { "get", &control_cmds,
      "<control> - Get the value of a control",
      ipmi_cmdlang_control_handler, control_get, NULL },
};
#define CMDS_CONTROL_LEN (sizeof(cmds_control)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_control_init(os_handler_t *os_hnd)
{
    return ipmi_cmdlang_reg_table(cmds_control, CMDS_CONTROL_LEN);
}
