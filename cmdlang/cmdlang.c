/*
 * cmdlang.c
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
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_int.h>


struct ipmi_cmdlang_cmd_s
{
    char               *name;
    char               *help;

    /* Only one of handler or subcmds may be non-NULL. */
    ipmi_cmdlang_handler_cb handler;
    ipmi_cmdlang_cmd_t      *subcmds;

    void                    *handler_data;

    /* Used for a linked list. */
    ipmi_cmdlang_cmd_t *next;
};

/* Parse a string of the form [domain][(class)][.obj] and return each
   of the strings in the given string pointers. */
static int
parse_ipmi_objstr(char *str,
		  char **domain,
		  char **class,
		  char **obj)
{
    int  i;
    char *class_start = NULL, *class_end = NULL;

    for (i=0; str[i]; i++) {
	if (str[i] == '(') {
	    if (class_start)
		/* Only one '(' allowed. */
		return EINVAL;
	    class_start = str + i;
	} else if (str[i] == ')') {
	    if (class_start) {
		/* a ')' only means something after a '('. */
		class_end = str + i;
		break;
	    }
	}
    }

    if (str[i]) {
	if (str[i] != '.')
	    return EINVAL;
    }

    if (class_start) {
	if (!class_end)
	    /* If class starts, must see the end paren. */
	    return EINVAL;
	*class_start = '\0';
	*class_end = '\0';
	*class = class_start + 1;
    } else {
	*class = NULL;
    }

    if (strlen(str) == 0)
	*domain = NULL;
    else
	*domain = str;

    if (str[i])
	*obj = str + i + 1;

    return 0;
}


/*
 * Handling for iterating domains.
 */

typedef struct domain_iter_info_s
{
    char               *cmpstr;
    int                found;
    ipmi_domain_ptr_cb handler;
    void               *cb_data;
} domain_iter_info_t;

static void
for_each_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    domain_iter_info_t *info = cb_data;
    char               domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    if ((!info->cmpstr) || (strcmp(info->cmpstr, domain_name) == 0)) {
	info->found = 1;
	info->handler(domain, info->cb_data);
    }
}

static int
for_each_domain(ipmi_cmd_info_t    *cmd_info,
		char               *domain,
		char               *class,
		char               *obj,
		ipmi_domain_ptr_cb handler,
		void               *cb_data)
{
    domain_iter_info_t info;

    if (class || obj) {
	cmd_info->cmdlang->err = "Invalid domain";
	return EINVAL;
    }

    info.cmpstr = domain;
    info.found = 0;
    info.handler = handler;
    info.cb_data = cb_data;
    ipmi_domain_iterate_domains(for_each_domain_handler, &info);
    if (!info.found) {
	cmd_info->cmdlang->err = "domain not found";
	return ENOENT;
    }
    return 0;
}

int
ipmi_cmdlang_domain_handler(ipmi_cmd_info_t *cmd_info)
{
    char *domain, *class, *obj;
    int  rv;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	rv = parse_ipmi_objstr(cmd_info->argv[cmd_info->curr_arg],
			       &domain, &class, &obj);
	if (rv) {
	    cmd_info->cmdlang->err = "Invalid domain";
	    return rv;
	}
	cmd_info->curr_arg++;
    }

    return for_each_domain(cmd_info, domain, class, obj,
			   cmd_info->handler_data, cmd_info);
}


/*
 * Handling for iterating entities.
 */
typedef struct entity_iter_info_s
{
    char               *cmpstr;
    int                found;
    ipmi_entity_ptr_cb handler;
    void               *cb_data;
} entity_iter_info_t;

static void
for_each_entity_handler(ipmi_entity_t *entity, void *cb_data)
{
    entity_iter_info_t *info = cb_data;
    char               entity_name[IPMI_ENTITY_NAME_LEN];

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));
    if ((!info->cmpstr) || (strcmp(info->cmpstr, entity_name) == 0)) {
	info->found = 1;
	info->handler(entity, info->cb_data);
    }
}

static void
for_each_entity_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_domain_iterate_entities(domain, for_each_entity_handler, cb_data);
}

static int
for_each_entity(ipmi_cmd_info_t    *cmd_info,
		char               *domain,
		char               *class,
		char               *obj,
		ipmi_entity_ptr_cb handler,
		void               *cb_data)
{
    entity_iter_info_t info;
    int                rv;

    if (obj) {
	cmd_info->cmdlang->err = "Invalid entity";
	return EINVAL;
    }

    info.cmpstr = class;
    info.found = 0;
    info.handler = handler;
    info.cb_data = cb_data;
    rv = for_each_domain(cmd_info, domain, NULL, NULL,
			 for_each_entity_domain_handler, &info);
    if (rv)
	return rv;
    if (!info.found) {
	cmd_info->cmdlang->err = "entity not found";
	return ENOENT;
    }
    return 0;
}

int
ipmi_cmdlang_entity_handler(ipmi_cmd_info_t *cmd_info)
{
    char *domain, *class, *obj;
    int  rv;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	rv = parse_ipmi_objstr(cmd_info->argv[cmd_info->curr_arg],
			       &domain, &class, &obj);
	if (rv) {
	    cmd_info->cmdlang->err = "Invalid entity";
	    return rv;
	}
	cmd_info->curr_arg++;
    }

    return for_each_entity(cmd_info, domain, class, obj,
			   cmd_info->handler_data, cmd_info);
}


/*
 * Handling for iterating sensors.
 */
typedef struct sensor_iter_info_s
{
    char               *cmpstr;
    int                found;
    ipmi_sensor_ptr_cb handler;
    void               *cb_data;
} sensor_iter_info_t;

static void
for_each_sensor_handler(ipmi_entity_t *entity,
			ipmi_sensor_t *sensor,
			void          *cb_data)
{
    sensor_iter_info_t *info = cb_data;
    char               sensor_name[IPMI_SENSOR_NAME_LEN];

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));
    if ((!info->cmpstr) || (strcmp(info->cmpstr, sensor_name) == 0)) {
	info->found = 1;
	info->handler(sensor, info->cb_data);
    }
}

static void
for_each_sensor_entity_handler(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_entity_iterate_sensors(entity, for_each_sensor_handler, cb_data);
}

static int
for_each_sensor(ipmi_cmd_info_t    *cmd_info,
		char               *domain,
		char               *class,
		char               *obj,
		ipmi_sensor_ptr_cb handler,
		void               *cb_data)
{
    sensor_iter_info_t info;
    int                rv;

    info.cmpstr = class;
    info.found = 0;
    info.handler = handler;
    info.cb_data = cb_data;
    rv = for_each_entity(cmd_info, domain, class, NULL,
			 for_each_sensor_entity_handler, &info);
    if (rv)
	return rv;
    if (!info.found) {
	cmd_info->cmdlang->err = "sensor not found";
	return ENOENT;
    }
    return 0;
}

int
ipmi_cmdlang_sensor_handler(ipmi_cmd_info_t *cmd_info)
{
    char *domain, *class, *obj;
    int  rv;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	rv = parse_ipmi_objstr(cmd_info->argv[cmd_info->curr_arg],
			       &domain, &class, &obj);
	if (rv) {
	    cmd_info->cmdlang->err = "Invalid sensor";
	    return rv;
	}
	cmd_info->curr_arg++;
    }

    return for_each_sensor(cmd_info, domain, class, obj,
			   cmd_info->handler_data, cmd_info);
}


/*
 * Handling for iterating controls.
 */
typedef struct control_iter_info_s
{
    char                *cmpstr;
    int                 found;
    ipmi_control_ptr_cb handler;
    void                *cb_data;
} control_iter_info_t;

static void
for_each_control_handler(ipmi_entity_t  *entity,
			 ipmi_control_t *control,
			 void           *cb_data)
{
    control_iter_info_t *info = cb_data;
    char                control_name[IPMI_CONTROL_NAME_LEN];

    ipmi_control_get_name(control, control_name, sizeof(control_name));
    if ((!info->cmpstr) || (strcmp(info->cmpstr, control_name) == 0)) {
	info->found = 1;
	info->handler(control, info->cb_data);
    }
}

static void
for_each_control_entity_handler(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_entity_iterate_controls(entity, for_each_control_handler, cb_data);
}

static int
for_each_control(ipmi_cmd_info_t     *cmd_info,
		 char                *domain,
		 char                *class,
		 char                *obj,
		 ipmi_control_ptr_cb handler,
		 void                *cb_data)
{
    control_iter_info_t info;
    int                 rv;

    info.cmpstr = class;
    info.found = 0;
    info.handler = handler;
    info.cb_data = cb_data;
    rv = for_each_entity(cmd_info, domain, class, NULL,
			 for_each_control_entity_handler, &info);
    if (rv)
	return rv;
    if (!info.found) {
	cmd_info->cmdlang->err = "control not found";
	return ENOENT;
    }
    return 0;
}

int
ipmi_cmdlang_control_handler(ipmi_cmd_info_t *cmd_info)
{
    char *domain, *class, *obj;
    int  rv;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	rv = parse_ipmi_objstr(cmd_info->argv[cmd_info->curr_arg],
			       &domain, &class, &obj);
	if (rv) {
	    cmd_info->cmdlang->err = "Invalid control";
	    return rv;
	}
	cmd_info->curr_arg++;
    }

    return for_each_control(cmd_info, domain, class, obj,
			    cmd_info->handler_data, cmd_info);
}


/*
 * Handling for iterating mcs.
 */
typedef struct mc_iter_info_s
{
    char           *cmpstr;
    int            found;
    ipmi_mc_ptr_cb handler;
    void           *cb_data;
} mc_iter_info_t;

static void
for_each_mc_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    mc_iter_info_t *info = cb_data;
    char           mc_name[IPMI_MC_NAME_LEN];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    if ((!info->cmpstr) || (strcmp(info->cmpstr, mc_name) == 0)) {
	info->found = 1;
	info->handler(mc, info->cb_data);
    }
}

static void
for_each_mc_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_domain_iterate_mcs(domain, for_each_mc_handler, cb_data);
}

static int
for_each_mc(ipmi_cmd_info_t *cmd_info,
	    char            *domain,
	    char            *class,
	    char            *obj,
	    ipmi_mc_ptr_cb  handler,
	    void            *cb_data)
{
    mc_iter_info_t info;
    int            rv;

    if (obj) {
	cmd_info->cmdlang->err = "Invalid MC";
	return EINVAL;
    }

    info.cmpstr = class;
    info.found = 0;
    info.handler = handler;
    info.cb_data = cb_data;
    rv = for_each_domain(cmd_info, domain, NULL, NULL,
			 for_each_mc_domain_handler, &info);
    if (rv)
	return rv;
    if (!info.found) {
	cmd_info->cmdlang->err = "MC not found";
	return ENOENT;
    }
    return 0;
}

int
ipmi_cmdlang_mc_handler(ipmi_cmd_info_t *cmd_info)
{
    char *domain, *class, *obj;
    int  rv;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	rv = parse_ipmi_objstr(cmd_info->argv[cmd_info->curr_arg],
			       &domain, &class, &obj);
	if (rv) {
	    cmd_info->cmdlang->err = "Invalid MC";
	    return rv;
	}
	cmd_info->curr_arg++;
    }

    return for_each_mc(cmd_info, domain, class, obj, cmd_info->handler_data,
		       cmd_info);
}


/*
 * Handling for iterating connections.
 */
typedef struct conn_iter_info_s
{
    int                    conn;
    int                    found;
    ipmi_connection_ptr_cb handler;
    void                   *cb_data;
} conn_iter_info_t;

static void
for_each_conn_handler(ipmi_domain_t *domain, int conn, void *cb_data)
{
    conn_iter_info_t       *info = cb_data;

    if ((info->conn == -1) || (info->conn == conn)) {
	info->found = 1;
	info->handler(domain, conn, info->cb_data);
    }
}

static void
for_each_conn_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_domain_iterate_connections(domain, for_each_conn_handler, cb_data);
}

static int
for_each_connection(ipmi_cmd_info_t        *cmd_info,
		    char                   *domain,
		    char                   *class,
		    char                   *obj,
		    ipmi_connection_ptr_cb handler,
		    void                   *cb_data)
{
    conn_iter_info_t info;
    char             *endptr;
    int              rv;

    if (class) {
	cmd_info->cmdlang->err = "Invalid domain";
	return EINVAL;
    }

    if (obj) {
	if (!isdigit(obj[0]))
	    return EINVAL;
	info.conn = strtoul(class, &endptr, 0);
	if (*endptr != '\0')
	    return EINVAL;
    } else {
	info.conn = -1;
    }
    info.found = 0;
    info.handler = handler;
    info.cb_data = cb_data;
    rv = for_each_domain(cmd_info, domain, NULL, NULL,
			 for_each_conn_domain_handler, &info);
    if (rv)
	return rv;
    if (!info.found) {
	cmd_info->cmdlang->err = "Connection not found";
	return ENOENT;
    }
    return 0;
}

int
ipmi_cmdlang_connection_handler(ipmi_cmd_info_t *cmd_info)
{
    char *domain, *class, *obj;
    int  rv;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	rv = parse_ipmi_objstr(cmd_info->argv[cmd_info->curr_arg],
			       &domain, &class, &obj);
	if (rv) {
	    cmd_info->cmdlang->err = "Invalid connection";
	    return rv;
	}
	cmd_info->curr_arg++;
    }

    return for_each_connection(cmd_info,
			       domain, class, obj, cmd_info->handler_data,
			       cmd_info);
}


static int
parse_next_str(char **tok, char **istr)
{
    char *str = *istr;
    char *tstr;
    char quote = 0;

    while (isspace(*str))
	str++;
    if (!*str)
	return ENOENT;

    if ((*str == '"') || (*str == '\'')) {
	quote = *str;
	str++;
    }

    while (*str) {
	if (quote) {
	    if (*str == quote)
		break;
	} else {
	    if (isspace(*str))
		break;
	}

	if (*str == '\\') {
	    tstr = str;
	    if (! *(tstr+1))
		/* Nothing after a '\' */
		return EINVAL;
	    while (*(tstr+1)) {
		*tstr = *(tstr+1);
		tstr++;
	    }
	    *str++;
	}
    }

    if (*str) {
	*str = '\0';
	*istr = str+1;
    } else {
	*istr = str;
    }

    return 0;
}

static ipmi_cmdlang_cmd_t *cmd_list;

#define MAXARGS 100
int
ipmi_cmdlang_handle(ipmi_cmdlang_t *cmdlang, char *str)
{
    int                argc;
    char               *argv[MAXARGS];
    int                curr_arg;
    ipmi_cmdlang_cmd_t *cmd;
    ipmi_cmd_info_t    info;
    int                rv;

    for (argc=0; argc<MAXARGS; argc++) {
	rv = parse_next_str(&argv[argc], &str);
	if (rv) {
	    if (rv == ENOENT)
		break;
	    cmdlang->err = "Invalid string";
	    goto done;
	}
    }

    if (*str) {
	/* Too many arguments */
	cmdlang->err = "Too many arguments";
	rv = E2BIG;
	goto done;
    }

    curr_arg = 0;
    rv = 0;
    cmd = cmd_list;

    if (argc == curr_arg) {
	cmdlang->err = "No command";
	rv = ENOMSG;
	goto done;
    }
    if (strcmp(argv[curr_arg], "help") == 0) {
	ipmi_cmdlang_cmd_t *parent = NULL;
	/* Help has special handling. */

	curr_arg++;
	for (;;) {
	next_help:
	    if (argc == curr_arg) {
		rv = 0;
		if (parent)
		    rv = cmdlang->out(cmdlang, parent->name, parent->help);
		else
		    rv = cmdlang->out(cmdlang, "help", NULL);
		if (rv)
		    goto done;
		while (cmd) {
		    rv = cmdlang->out(cmdlang, cmd->name, cmd->help);
		    if (rv)
			goto done;
		    cmd = cmd->next;
		}
		break;
	    }
	    if (!cmd) {
		cmdlang->err = "Command not found";
		rv = ENOSYS;
		goto done;
	    }

	    while (cmd) {
		if (strcmp(cmd->name, argv[curr_arg]) == 0) {
		    if (cmd->subcmds) {
			parent = cmd;
			cmd = cmd->subcmds;
			curr_arg++;
			goto next_help;
		    } else {
			parent = cmd;
			cmd = NULL;
			goto next_help;
		    }
		}
	    }

	    rv = ENOSYS;
	    goto done;
	}

	goto done;
    }	

    for (;;) {
	if (argc == curr_arg) {
	    cmdlang->err = "Missing commands";
	    rv = ENOMSG;
	    goto done;
	}

	while (cmd) {
	    if (strcmp(cmd->name, argv[curr_arg]) == 0) {
		if (cmd->subcmds) {
		    cmd = cmd->subcmds;
		    curr_arg++;
		    /* Continue processing this subcommand list */
		    break;
		} else {
		    curr_arg++;
		    info.handler_data = cmd->handler_data;
		    info.curr_arg = curr_arg;
		    info.argc = argc;
		    info.argv = argv;
		    info.cmdlang = cmdlang;
		    info.cmd = cmd;
		    rv = cmd->handler(&info);
		    goto done;
		}
	    }
	}

	if (!cmd) {
	    cmdlang->err = "Command not found";
	    rv = ENOSYS;
	    goto done;
	}
    }

 done:

    if (rv)
	cmdlang->done(cmdlang);

    return rv;
}

int
ipmi_cmdlang_reg_cmd(ipmi_cmdlang_cmd_t      *parent,
		     char                    *name,
		     char                    *help,
		     ipmi_cmdlang_handler_cb handler,
		     void                    *cb_data,
		     ipmi_cmdlang_cmd_t      **new_val)
{
    ipmi_cmdlang_cmd_t *rv;
    ipmi_cmdlang_cmd_t *cmd;

    /* Check for dups. */
    if (!parent)
	cmd = cmd_list;
    else
	cmd = parent;
    while (cmd) {
	if (strcmp(cmd->name, name) == 0)
	    return EEXIST;
    }

    rv = ipmi_mem_alloc(sizeof(*rv));
    if (!rv)
	return ENOMEM;

    rv->name = name;
    rv->help = help;
    rv->handler = handler;
    rv->subcmds = NULL;
    rv->handler_data = cb_data;
    rv->next = NULL;

    if (parent) {
	if (!parent->subcmds) {
	    parent->subcmds = rv;
	    goto done;
	}
	cmd = parent->subcmds;
    } else {
	if (!cmd_list) {
	    cmd_list = rv;
	    goto done;
	}
	cmd = cmd_list;
    }
    while (cmd->next) {
	cmd = cmd->next;
    }
    cmd->next = rv;

 done:
    if (new_val)
	*new_val = rv;
    return 0;
}

int
ipmi_cmdlang_out(ipmi_cmd_info_t *info,
		 char            *name,
		 char            *value)
{
    return info->cmdlang->out(info->cmdlang, name, value);
}

int
ipmi_cmdlang_out_int(ipmi_cmd_info_t *info,
		     char            *name,
		     int             value)
{
    char sval[20];

    sprintf(sval, "%d", value);
    return ipmi_cmdlang_out(info, name, sval);
}

int
ipmi_cmdlang_down(ipmi_cmd_info_t *info)
{
    return info->cmdlang->down(info->cmdlang);
}

int
ipmi_cmdlang_up(ipmi_cmd_info_t *info)
{
    return info->cmdlang->up(info->cmdlang);
}

int
ipmi_cmdlang_done(ipmi_cmd_info_t *info)
{
    return info->cmdlang->done(info->cmdlang);
}

int ipmi_cmdlang_domain_init(void);

int
ipmi_cmdlang_init(void)
{
    int rv;

    rv = ipmi_cmdlang_domain_init();
    if (rv)
	return rv;

    return 0;
}

/*
The command hierarchy is:

* help - get general help.
* domain
  * help
  * list - List all domains
  * info <domain> - List information about the given domain
  * fru <domain> <is_logical> <device_address> <device_id> <lun> <private_bus>
    <channel> - dump a fru given all it's insundry information.
  * msg <domain> <channel> <ipmb> <LUN> <NetFN> <Cmd> [data...] - Send a
    command to the given IPMB address on the given channel and display the
    response.  Note that this does not require the existance of an
    MC.
  * pet <domain> <connection> <channel> <ip addr> <mac_addr> <eft selector>
    <policy num> <apt selector> <lan dest selector> - 
    Set up the domain to send PET traps from the given connection
    to the given IP/MAC address over the given channel
  * scan <domain> <ipmb addr> [ipmb addr] - scan an IPMB to add or remove it.
    If a range is given, then scan all IPMBs in the range
  * presence - Check the presence of entities
  new <domain> <parms...> - Open a connection to a new domain
  close <domain> - close the given domain
* entity
  * help
  * list <domain> - List all entities.
  * info <entity> - List information about the given entity
  * hs - hot-swap control
    * get_act_time <entity> - Get the host-swap auto-activate time
    * set_act_time <entity> - Set the host-swap auto-activate time
    * get_deact_time <entity> - Get the host-swap auto-deactivate time
    * set_deact_time <entity> - Set the host-swap auto-deactivate time
    * activation_request <entity> Act like a user requested an
      activation of the entity.  This is generally equivalent to
      closing the handle latch or something like that.
    * activate <entity> - activate the given entity
    * deactivate <entity> - deactivate the given entity
    * state <entity> - Return the current hot-swap state of the given entity
    * check <domain> - Audit all the entity hot-swap states
  * fru <entity> - Dump the FRU information about the given entity.
* sensor
  * help
  * list <entity> - List all sensors
  * info <sensor> 
  * rearm <sensor> - rearm the current sensor
  * set_hysteresis - Sets the hysteresis for the current sensor
  * get_hysteresis - Gets the hysteresis for the current sensor
  * events_enable <events> <scanning> <assertion bitmask> <deassertion bitmask>
    - set the events enable data for the sensor
* control
  * help
  * list <entity> - List all controls
  * info <control> 
  * set <control> <val1> [<val2> ...] - set the value(s) for the control
* mc
  * help
  * list <domain> - List all MCs
  * info <mc> 
  * reset <warm | cold> <mc> - Do a warm or cold reset on the given MC
  * cmd <mc> <LUN> <NetFN> <Cmd> [data...] - Send the given command"
    to the management controller and display the response.
  * set_events_enable <enable | disable> <mc> - enables or disables
    events on the MC.
  * get_events_enabled <mc> - Prints out if the events are enabled for
    the given MC.
  * sdrs <mc> <main | sensor> - list the SDRs for the mc.  Either gets
    the main SDR repository or the sensor SDR repository.
  * get_sel_time <mc> - Get the time in the SEL for the given MC
* pef
  * read <mc> - read pef information from an MC.  Note the lock is not
    released.
  * clearlock <mc> - Clear a PEF lock.
  * write <mc> <pefval> <value> [pefval <value> [...]]
    - write the PEF information to the MC.  Every value given will be
     written atomically and the lock will be released.  Note that
     you must do a read before doing this command.
* lan
    * read <mc> <channel> - read lanparm information from an MC for
      the given channel on the MC.  Note the lock will not be released
      after this command.
    * clearlock <mc> <channel> - Clear the LAN parm lock on the given
      MC and channel.
    * writelanparm <mc> <channel> <lanval> <value> [lanval <value> [...]]
      - write the LANPARM information to an MC.  Every value given will be
      written atomically and the lock will be released.  Note that
      you must do a read before doing this command.
* con
  * list <domain> - List the connections
  * active <connection> - print out if the given connection is active or not
  * activate <connection> - Activate the given connection
* sel
    * delevent <mc> <log #> - Delete the given event number from the SEL
      FIXME - is the "mc" right?
    * addevent <mc> <record id> <type> <13 bytes of data> - Add the
      event data to the SEL.
    * clear <domain> - clear the system event log
    * list <domain> - list the local copy of the system event log
* general
  * debug <type> on|off - Turn the given debugging type on or off
  * xml on|off - enable or disable XML-style output
*/
