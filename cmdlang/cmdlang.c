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
    else
	*obj = NULL;

    return 0;
}


/*
 * Handling for iterating domains.
 */

typedef struct domain_iter_info_s
{
    char               *cmpstr;
    ipmi_domain_ptr_cb handler;
    void               *cb_data;
    ipmi_cmd_info_t    *cmd_info;
} domain_iter_info_t;

static void
for_each_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    domain_iter_info_t *info = cb_data;
    ipmi_cmd_info_t    *cmd_info = info->cmd_info;
    char               domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

    if (cmd_info->cmdlang->err)
	return;

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    if ((!info->cmpstr) || (strcmp(info->cmpstr, domain_name) == 0)) {
	ipmi_cmdlang_out(cmd_info, "Domain", domain_name);
	ipmi_cmdlang_down(cmd_info);
	info->handler(domain, info->cb_data);
	ipmi_cmdlang_up(cmd_info);
    }
}

static void
for_each_domain(ipmi_cmd_info_t    *cmd_info,
		char               *domain,
		char               *class,
		char               *obj,
		ipmi_domain_ptr_cb handler,
		void               *cb_data)
{
    domain_iter_info_t info;

    if (class || obj) {
	cmd_info->cmdlang->errstr = "Invalid domain";
	cmd_info->cmdlang->err = EINVAL;
	cmd_info->cmdlang->location = "cmdlang.c(for_each_domain)";
	return;
    }

    info.cmpstr = domain;
    info.handler = handler;
    info.cb_data = cb_data;
    info.cmd_info = cmd_info;
    ipmi_domain_iterate_domains(for_each_domain_handler, &info);
}

void
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
	    cmd_info->cmdlang->errstr = "Invalid domain";
	    cmd_info->cmdlang->err = rv;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_domain_handler)";
	    return;
	}
	cmd_info->curr_arg++;
    }

    for_each_domain(cmd_info, domain, class, obj,
		    cmd_info->handler_data, cmd_info);
}


/*
 * Handling for iterating entities.
 */
typedef struct entity_iter_info_s
{
    char               *cmpstr;
    ipmi_entity_ptr_cb handler;
    void               *cb_data;
    ipmi_cmd_info_t    *cmd_info;
} entity_iter_info_t;

static void
for_each_entity_handler(ipmi_entity_t *entity, void *cb_data)
{
    entity_iter_info_t *info = cb_data;
    ipmi_cmd_info_t    *cmd_info = info->cmd_info;
    char               entity_name[IPMI_ENTITY_NAME_LEN];

    if (cmd_info->cmdlang->err)
	return;

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));
    if ((!info->cmpstr) || (strcmp(info->cmpstr, entity_name) == 0)) {
	ipmi_cmdlang_out(cmd_info, "Entity", entity_name);
	ipmi_cmdlang_down(cmd_info);
	info->handler(entity, info->cb_data);
	ipmi_cmdlang_up(cmd_info);
    }
}

static void
for_each_entity_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_domain_iterate_entities(domain, for_each_entity_handler, cb_data);
}

static void
for_each_entity(ipmi_cmd_info_t    *cmd_info,
		char               *domain,
		char               *class,
		char               *obj,
		ipmi_entity_ptr_cb handler,
		void               *cb_data)
{
    entity_iter_info_t info;

    if (obj) {
	cmd_info->cmdlang->errstr = "Invalid entity";
	cmd_info->cmdlang->err = EINVAL;
	cmd_info->cmdlang->location = "cmdlang.c(for_each_entity)";
	return;
    }

    info.cmpstr = class;
    info.handler = handler;
    info.cb_data = cb_data;
    info.cmd_info = cmd_info;
    for_each_domain(cmd_info, domain, NULL, NULL,
		    for_each_entity_domain_handler, &info);
}

void
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
	    cmd_info->cmdlang->errstr = "Invalid entity";
	    cmd_info->cmdlang->err = rv;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_entity_handler)";
	    return;
	}
	cmd_info->curr_arg++;
    }

    for_each_entity(cmd_info, domain, class, obj,
		    cmd_info->handler_data, cmd_info);
}


/*
 * Handling for iterating sensors.
 */
typedef struct sensor_iter_info_s
{
    char               *cmpstr;
    ipmi_sensor_ptr_cb handler;
    void               *cb_data;
    ipmi_cmd_info_t    *cmd_info;
} sensor_iter_info_t;

static void
for_each_sensor_handler(ipmi_entity_t *entity,
			ipmi_sensor_t *sensor,
			void          *cb_data)
{
    sensor_iter_info_t *info = cb_data;
    ipmi_cmd_info_t    *cmd_info = info->cmd_info;
    char               sensor_name[IPMI_SENSOR_NAME_LEN];

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));
    if ((!info->cmpstr) || (strcmp(info->cmpstr, sensor_name) == 0)) {
	ipmi_cmdlang_out(cmd_info, "Sensor", sensor_name);
	ipmi_cmdlang_down(cmd_info);
	info->handler(sensor, info->cb_data);
	ipmi_cmdlang_up(cmd_info);
    }
}

static void
for_each_sensor_entity_handler(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_entity_iterate_sensors(entity, for_each_sensor_handler, cb_data);
}

static void
for_each_sensor(ipmi_cmd_info_t    *cmd_info,
		char               *domain,
		char               *class,
		char               *obj,
		ipmi_sensor_ptr_cb handler,
		void               *cb_data)
{
    sensor_iter_info_t info;

    info.cmpstr = class;
    info.handler = handler;
    info.cb_data = cb_data;
    info.cmd_info = cmd_info;
    for_each_entity(cmd_info, domain, class, NULL,
		    for_each_sensor_entity_handler, &info);
}

void
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
	    cmd_info->cmdlang->errstr = "Invalid sensor";
	    cmd_info->cmdlang->err = rv;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_sensor_handler)";
	    return;
	}
	cmd_info->curr_arg++;
    }

    for_each_sensor(cmd_info, domain, class, obj,
		    cmd_info->handler_data, cmd_info);
}


/*
 * Handling for iterating controls.
 */
typedef struct control_iter_info_s
{
    char                *cmpstr;
    ipmi_control_ptr_cb handler;
    void                *cb_data;
    ipmi_cmd_info_t     *cmd_info;
} control_iter_info_t;

static void
for_each_control_handler(ipmi_entity_t  *entity,
			 ipmi_control_t *control,
			 void           *cb_data)
{
    control_iter_info_t *info = cb_data;
    ipmi_cmd_info_t     *cmd_info = info->cmd_info;
    char                control_name[IPMI_CONTROL_NAME_LEN];

    ipmi_control_get_name(control, control_name, sizeof(control_name));
    if ((!info->cmpstr) || (strcmp(info->cmpstr, control_name) == 0)) {
	ipmi_cmdlang_out(cmd_info, "Control", control_name);
	ipmi_cmdlang_down(cmd_info);
	info->handler(control, info->cb_data);
	ipmi_cmdlang_up(cmd_info);
    }
}

static void
for_each_control_entity_handler(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_entity_iterate_controls(entity, for_each_control_handler, cb_data);
}

static void
for_each_control(ipmi_cmd_info_t     *cmd_info,
		 char                *domain,
		 char                *class,
		 char                *obj,
		 ipmi_control_ptr_cb handler,
		 void                *cb_data)
{
    control_iter_info_t info;

    info.cmpstr = class;
    info.handler = handler;
    info.cb_data = cb_data;
    info.cmd_info = cmd_info;
    for_each_entity(cmd_info, domain, class, NULL,
		    for_each_control_entity_handler, &info);
}

void
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
	    cmd_info->cmdlang->errstr = "Invalid control";
	    cmd_info->cmdlang->err = rv;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_control_handler)";
	    return;
	}
	cmd_info->curr_arg++;
    }

    for_each_control(cmd_info, domain, class, obj,
		     cmd_info->handler_data, cmd_info);
}


/*
 * Handling for iterating mcs.
 */
typedef struct mc_iter_info_s
{
    char            *cmpstr;
    ipmi_mc_ptr_cb  handler;
    void            *cb_data;
    ipmi_cmd_info_t *cmd_info;
} mc_iter_info_t;

static void
for_each_mc_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    mc_iter_info_t  *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    if ((!info->cmpstr) || (strcmp(info->cmpstr, mc_name) == 0)) {
	ipmi_cmdlang_out(cmd_info, "MC", mc_name);
	ipmi_cmdlang_down(cmd_info);
	info->handler(mc, info->cb_data);
	ipmi_cmdlang_up(cmd_info);
    }
}

static void
for_each_mc_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_domain_iterate_mcs(domain, for_each_mc_handler, cb_data);
}

static void
for_each_mc(ipmi_cmd_info_t *cmd_info,
	    char            *domain,
	    char            *class,
	    char            *obj,
	    ipmi_mc_ptr_cb  handler,
	    void            *cb_data)
{
    mc_iter_info_t info;

    if (obj) {
	cmd_info->cmdlang->errstr = "Invalid MC";
	cmd_info->cmdlang->err = EINVAL;
	cmd_info->cmdlang->location = "cmdlang.c(for_each_mc)";
	return;
    }

    info.cmpstr = class;
    info.handler = handler;
    info.cb_data = cb_data;
    info.cmd_info = cmd_info;
    for_each_domain(cmd_info, domain, NULL, NULL,
		    for_each_mc_domain_handler, &info);
}

void
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
	    cmd_info->cmdlang->errstr = "Invalid MC";
	    cmd_info->cmdlang->err = rv;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_mc_handler)";
	    return;
	}
	cmd_info->curr_arg++;
    }

    for_each_mc(cmd_info, domain, class, obj, cmd_info->handler_data,
		cmd_info);
}


/*
 * Handling for iterating connections.
 */
typedef struct conn_iter_info_s
{
    int                    conn;
    ipmi_connection_ptr_cb handler;
    void                   *cb_data;
    ipmi_cmd_info_t        *cmd_info;
} conn_iter_info_t;

static void
for_each_conn_handler(ipmi_domain_t *domain, int conn, void *cb_data)
{
    conn_iter_info_t *info = cb_data;
    ipmi_cmd_info_t  *cmd_info = info->cmd_info;

    if ((info->conn == -1) || (info->conn == conn)) {
	ipmi_cmdlang_out_int(cmd_info, "Connection", info->conn);
	ipmi_cmdlang_down(cmd_info);
	info->handler(domain, conn, info->cb_data);
	ipmi_cmdlang_up(cmd_info);
    }
}

static void
for_each_conn_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_domain_iterate_connections(domain, for_each_conn_handler, cb_data);
}

static void
for_each_connection(ipmi_cmd_info_t        *cmd_info,
		    char                   *domain,
		    char                   *class,
		    char                   *obj,
		    ipmi_connection_ptr_cb handler,
		    void                   *cb_data)
{
    conn_iter_info_t info;
    char             *endptr;

    if (class) {
	cmd_info->cmdlang->errstr = "Invalid connection";
	cmd_info->cmdlang->err = EINVAL;
	cmd_info->cmdlang->location = "cmdlang.c(for_each_connection)";
	return;
    }

    if (obj) {
	if (!isdigit(obj[0])) {
	    cmd_info->cmdlang->errstr = "Invalid connection number";
	    cmd_info->cmdlang->err = EINVAL;
	    cmd_info->cmdlang->location = "cmdlang.c(for_each_connection)";
	    return;
	}
	info.conn = strtoul(class, &endptr, 0);
	if (*endptr != '\0') {
	    cmd_info->cmdlang->errstr = "Invalid connection number";
	    cmd_info->cmdlang->err = EINVAL;
	    cmd_info->cmdlang->location = "cmdlang.c(for_each_connection)";
	    return;
	}
    } else {
	info.conn = -1;
    }
    info.handler = handler;
    info.cb_data = cb_data;
    info.cmd_info = cmd_info;
    for_each_domain(cmd_info, domain, NULL, NULL,
		    for_each_conn_domain_handler, &info);
}

void
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
	    cmd_info->cmdlang->errstr = "Invalid connection";
	    cmd_info->cmdlang->err = rv;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_connection_handler)";
	    return;
	}
	cmd_info->curr_arg++;
    }

    for_each_connection(cmd_info,
			domain, class, obj, cmd_info->handler_data,
			cmd_info);
}


static int
parse_next_str(char **tok, char **istr)
{
    char *str = *istr;
    char *tstr;
    char *start;
    char quote = 0;

    while (isspace(*str))
	str++;
    if (!*str)
	return ENOENT;

    if ((*str == '"') || (*str == '\'')) {
	quote = *str;
	str++;
    }

    start = str;

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
	}
	*str++;
    }

    if (*str) {
	*str = '\0';
	*istr = str+1;
    } else {
	*istr = str;
    }
    *tok = start;

    return 0;
}

static ipmi_cmdlang_cmd_t *cmd_list;

#define MAXARGS 100
void
ipmi_cmdlang_handle(ipmi_cmdlang_t *cmdlang, char *str)
{
    int                argc;
    char               *argv[MAXARGS];
    int                curr_arg;
    ipmi_cmdlang_cmd_t *cmd;
    ipmi_cmd_info_t    *info;
    int                rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	cmdlang->location = "cmdlang.c(ipmi_cmdlang_handle)";
	goto done;
    }
    memset(info, 0, sizeof(*info));
    info->usecount = 1;
    info->cmdlang = cmdlang;

    for (argc=0; argc<MAXARGS; argc++) {
	rv = parse_next_str(&argv[argc], &str);
	if (rv) {
	    if (rv == ENOENT)
		break;
	    cmdlang->errstr = "Invalid string";
	    cmdlang->err = rv;
	    cmdlang->location = "cmdlang.c(ipmi_cmdlang_handle)";
	    goto done;
	}
    }

    if (*str) {
	/* Too many arguments */
	cmdlang->errstr = "Too many arguments";
	cmdlang->err = E2BIG;
	cmdlang->location = "cmdlang.c(ipmi_cmdlang_handle)";
	goto done;
    }

    curr_arg = 0;
    rv = 0;
    cmd = cmd_list;

    if (argc == curr_arg) {
	cmdlang->errstr = "No command";
	cmdlang->err = ENOMSG;
	cmdlang->location = "cmdlang.c(ipmi_cmdlang_handle)";
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
		    cmdlang->out(cmdlang, parent->name, parent->help);
		else
		    cmdlang->out(cmdlang, "help", NULL);
		if (cmdlang->err)
		    goto done_help;
		cmdlang->down(cmdlang);
		while (cmd) {
		    cmdlang->out(cmdlang, cmd->name, cmd->help);
		    if (cmdlang->err) {
			cmdlang->up(cmdlang);
			goto done_help;
		    }
		    cmd = cmd->next;
		}
		cmdlang->up(cmdlang);
		break;
	    }
	    if (!cmd) {
		cmdlang->errstr = "Command not found";
		cmdlang->err = ENOSYS;
		cmdlang->location = "cmdlang.c(ipmi_cmdlang_handle)";
		goto done_help;
	    }

	    while (cmd) {
		if (strcmp(cmd->name, argv[curr_arg]) == 0) {
		    curr_arg++;
		    parent = cmd;
		    cmd = cmd->subcmds;
		    goto next_help;
		}
		cmd = cmd->next;
	    }

	    cmdlang->errstr = "Command not found";
	    cmdlang->err = ENOSYS;
	    cmdlang->location = "cmdlang.c(ipmi_cmdlang_handle)";
	    goto done_help;
	}

    done_help:
	goto done;
    }	

    for (;;) {
	if (argc == curr_arg) {
	    cmdlang->errstr = "Missing command";
	    cmdlang->err = ENOMSG;
	    cmdlang->location = "cmdlang.c(ipmi_cmdlang_handle)";
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
		    info->handler_data = cmd->handler_data;
		    info->curr_arg = curr_arg;
		    info->argc = argc;
		    info->argv = argv;
		    info->cmd = cmd;
		    cmd->handler(info);
		    goto done;
		}
	    }
	    cmd = cmd->next;
	}

	if (!cmd) {
	    cmdlang->errstr = "Command not found";
	    cmdlang->err = ENOSYS;
	    cmdlang->location = "cmdlang.c(ipmi_cmdlang_handle)";
	    goto done;
	}
    }

 done:

    if (info)
	ipmi_cmdlang_cmd_info_put(info);
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
	cmd = cmd->next;
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

void
ipmi_cmdlang_out(ipmi_cmd_info_t *info,
		 char            *name,
		 char            *value)
{
    info->cmdlang->out(info->cmdlang, name, value);
}

void
ipmi_cmdlang_out_int(ipmi_cmd_info_t *info,
		     char            *name,
		     int             value)
{
    char sval[20];

    sprintf(sval, "%d", value);
    ipmi_cmdlang_out(info, name, sval);
}

void
ipmi_cmdlang_out_hex(ipmi_cmd_info_t *info,
		     char            *name,
		     int             value)
{
    char sval[20];

    sprintf(sval, "0x%x", value);
    ipmi_cmdlang_out(info, name, sval);
}

void
ipmi_cmdlang_out_long(ipmi_cmd_info_t *info,
		      char            *name,
		      long            value)
{
    char sval[32];

    sprintf(sval, "%ld", value);
    ipmi_cmdlang_out(info, name, sval);
}

void
ipmi_cmdlang_out_binary(ipmi_cmd_info_t *info,
			char            *name,
			char            *value,
			unsigned int    len)
{
    info->cmdlang->out_binary(info->cmdlang, name, value, len);
}

void
ipmi_cmdlang_out_unicode(ipmi_cmd_info_t *info,
			 char            *name,
			 char            *value,
			 unsigned int    len)
{
    info->cmdlang->out_unicode(info->cmdlang, name, value, len);
}

void
ipmi_cmdlang_down(ipmi_cmd_info_t *info)
{
    info->cmdlang->down(info->cmdlang);
}

void
ipmi_cmdlang_up(ipmi_cmd_info_t *info)
{
    info->cmdlang->up(info->cmdlang);
}

void
ipmi_cmdlang_cmd_info_get(ipmi_cmd_info_t *cmd_info)
{
    cmd_info->usecount++;
}

void
ipmi_cmdlang_cmd_info_put(ipmi_cmd_info_t *cmd_info)
{
    cmd_info->usecount--;
    if (cmd_info->usecount == 0) {
	cmd_info->cmdlang->done(cmd_info->cmdlang);
	ipmi_mem_free(cmd_info);
    }
}

void
ipmi_cmdlang_get_int(char *str, int *val, ipmi_cmdlang_t *cmdlang)
{
    char *end;
    int  rv;

    if (cmdlang->err)
	return;

    rv = strtoul(str, &end, 0);
    if (*end != '\0') {
	cmdlang->errstr = "Invalid integer";
	cmdlang->err = EINVAL;
	cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_int)";
	return;
    }

    *val = rv;
}

void
ipmi_cmdlang_get_uchar(char *str, unsigned char *val, ipmi_cmdlang_t *cmdlang)
{
    char *end;
    int  rv;

    if (cmdlang->err)
	return;

    rv = strtoul(str, &end, 0);
    if (*end != '\0') {
	cmdlang->errstr = "Invalid integer";
	cmdlang->err = EINVAL;
	cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_int)";
	return;
    }

    *val = rv;
}

void
ipmi_cmdlang_get_bool(char *str, int *val, ipmi_cmdlang_t *cmdlang)
{
    int  rv;

    if (cmdlang->err)
	return;

    if ((strcasecmp(str, "true") == 0)
	|| (strcasecmp(str, "t") == 0)
	|| (strcmp(str, "1") == 0))
    {
	rv = 1;
    } else if ((strcasecmp(str, "false") == 0)
	       || (strcasecmp(str, "f") == 0)
	       || (strcmp(str, "0") == 0))
    {
	rv = 0;
    } else {
	cmdlang->errstr = "Invalid boolean";
	cmdlang->err = EINVAL;
	cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_bool)";
	return;
    }

    *val = rv;
}

typedef struct ipmi_cmdlang_event_entry_s ipmi_cmdlang_event_entry_t;
struct ipmi_cmdlang_event_entry_s
{
    char *name;
    char *value;
    int  level;
    ipmi_cmdlang_event_entry_t *next;
};

struct ipmi_cmdlang_event_s
{
    int curr_level;
    ipmi_cmd_info_t *info;
    ipmi_cmdlang_event_entry_t *head, *tail;
    ipmi_cmdlang_event_entry_t *curr;
};

void event_out(ipmi_cmdlang_t *cmdlang, char *name, char *value)
{
    ipmi_cmdlang_event_entry_t *entry;
    ipmi_cmdlang_event_t       *event = cmdlang->user_data;

    if (cmdlang->err)
	return;

    entry = ipmi_mem_alloc(sizeof(*entry));
    if (!entry)
	goto out_nomem;

    entry->name = ipmi_strdup(name);
    if (!entry->name) {
	ipmi_mem_free(entry);
	goto out_nomem;
    }

    if (value) {
	entry->value = ipmi_strdup(value);
	if (!entry->value) {
	    ipmi_mem_free(entry->name);
	    ipmi_mem_free(entry);
	    goto out_nomem;
	}
    } else
	entry->value = NULL;

    entry->level = event->curr_level;

    entry->next = NULL;
    if (event->head) {
	event->tail->next = entry;
	event->tail = entry;
    } else {
	event->head = entry;
	event->tail = entry;
    }

    return;

 out_nomem:
    cmdlang->err = ENOMEM;
    cmdlang->errstr = "Out of memory";
    cmdlang->location = "cmdlang.c(event_out)";
}

void event_up(ipmi_cmdlang_t *cmdlang)
{
    ipmi_cmdlang_event_t *event = cmdlang->user_data;

    if (cmdlang->err)
	return;

    event->curr_level++;
}

void event_down(ipmi_cmdlang_t *cmdlang)
{
    ipmi_cmdlang_event_t *event = cmdlang->user_data;

    if (cmdlang->err)
	return;

    event->curr_level--;
}

void event_done(ipmi_cmdlang_t *cmdlang)
{
    ipmi_cmdlang_event_entry_t *entry;
    ipmi_cmdlang_event_t       *event = cmdlang->user_data;
    ipmi_cmd_info_t            *info = event->info;

    if (strlen(info->cmdlang->objstr) == 0) {
	ipmi_mem_free(info->cmdlang->objstr);
	cmdlang->objstr = NULL;
    }

    if (info->cmdlang->err) {
	ipmi_cmdlang_global_err(cmdlang->objstr,
				cmdlang->location,
				cmdlang->errstr,
				cmdlang->err);
	if (cmdlang->errstr_dynalloc)
	    ipmi_mem_free(cmdlang->errstr);
    } else {
	ipmi_cmdlang_report_event(event);
    }

    if (cmdlang->objstr)
	ipmi_mem_free(cmdlang->objstr);
    ipmi_mem_free(cmdlang);

    entry = event->head;
    while (entry) {
	event->head = entry->next;
	ipmi_mem_free(entry->name);
	if (entry->value)
	    ipmi_mem_free(entry->value);
	ipmi_mem_free(entry);
	entry = event->head;
    }
    ipmi_mem_free(event);
}

ipmi_cmd_info_t *ipmi_cmdlang_alloc_event_info(void)
{
    ipmi_cmd_info_t      *cmdinfo = NULL;
    ipmi_cmdlang_event_t *event;

    cmdinfo = ipmi_mem_alloc(sizeof(*cmdinfo));
    if (!cmdinfo)
	return NULL;
    memset(cmdinfo, 0, sizeof(*cmdinfo));
    cmdinfo->usecount = 1;

    cmdinfo->cmdlang = ipmi_mem_alloc(sizeof(*cmdinfo->cmdlang));
    if (!cmdinfo->cmdlang) {
	ipmi_mem_free(cmdinfo);
	return NULL;
    }
    memset(cmdinfo->cmdlang, 0, sizeof(*cmdinfo->cmdlang));

    cmdinfo->cmdlang->objstr = ipmi_mem_alloc(IPMI_MAX_NAME_LEN);
    if (!cmdinfo->cmdlang->objstr) {
	ipmi_mem_free(cmdinfo->cmdlang);
	ipmi_mem_free(cmdinfo);
	return NULL;
    }
    cmdinfo->cmdlang->objstr[0] = '\0';
    cmdinfo->cmdlang->objstr_len = IPMI_MAX_NAME_LEN;

    cmdinfo->cmdlang->user_data	= ipmi_mem_alloc(sizeof(ipmi_cmdlang_event_t));
    if (!cmdinfo->cmdlang->user_data) {
	ipmi_mem_free(cmdinfo->cmdlang->objstr);
	ipmi_mem_free(cmdinfo->cmdlang);
	ipmi_mem_free(cmdinfo);
	return NULL;
    }

    event = cmdinfo->cmdlang->user_data;
    memset(event, 0, sizeof(*event));
    event->info = cmdinfo;

    cmdinfo->cmdlang->out = event_out;
    cmdinfo->cmdlang->down = event_down;
    cmdinfo->cmdlang->up = event_up;
    cmdinfo->cmdlang->done = event_done;

    return cmdinfo;
}

/* Move to the first field. */
void ipmi_cmdlang_event_restart(ipmi_cmdlang_event_t *event)
{
    event->curr = event->head;
}

/* Returns true if successful, false if no more fields left. */
int ipmi_cmdlang_event_next_field(ipmi_cmdlang_event_t *event,
				  unsigned int         *level,
				  char                 **name,
				  char                 **value)
{
    ipmi_cmdlang_event_entry_t *curr = event->curr;

    if (!curr)
	return 0;

    *level = curr->level;
    *name = curr->name;
    *value = curr->value;

    event->curr = curr->next;
    return 1;
}


int ipmi_cmdlang_domain_init(void);
int ipmi_cmdlang_entity_init(void);

int
ipmi_cmdlang_init(void)
{
    int rv;

    rv = ipmi_cmdlang_domain_init();
    if (rv)
	return rv;

    rv = ipmi_cmdlang_entity_init();
    if (rv)
	return rv;

    return 0;
}

static void
cleanup_level(ipmi_cmdlang_cmd_t *cmds)
{
    ipmi_cmdlang_cmd_t *cmd;

    while (cmds) {
	cmd = cmds;
	cmds = cmd->next;
	if (cmd->subcmds)
	    cleanup_level(cmd->subcmds);
	ipmi_mem_free(cmd);
    }
}

void
ipmi_cmdlang_cleanup(void)
{
    cleanup_level(cmd_list);
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
