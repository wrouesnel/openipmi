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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_pet.h>
#include <OpenIPMI/ipmi_lanparm.h>
#include <OpenIPMI/ipmi_solparm.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_pef.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_debug.h>
#include <OpenIPMI/ipmi_mc.h>

/* Internal includes, do not use in your programs */
#include <OpenIPMI/internal/ipmi_locks.h>
#include <OpenIPMI/internal/ipmi_malloc.h>

/*
 * This is the value passed to a command handler.
 */
struct ipmi_cmd_info_s
{
    void               *handler_data; /* From cb_data in the cmd reg */
    int                curr_arg;      /* Argument you should start at */
    int                argc;          /* Total number of arguments */
    char               **argv;        /* The arguments */

    /* Only allow one writer at a time */
    ipmi_lock_t        *lock;

    /* The cmdlang structure the user passed in.  Use this for output
       and error reporting. */
    ipmi_cmdlang_t     *cmdlang;

    /* The matching cmd structure for the command being executed.  May
       be NULL if no command is being processed. */
    ipmi_cmdlang_cmd_t *cmd;

    /* Refcount for the structure. */
    unsigned int       usecount;

    /* For use by the user commands */
    void *data;

    /* Used to know if the command generated output. */
    int did_output;
};


struct ipmi_cmdlang_cmd_s
{
    char                  *name;
    char                  *help;
    ipmi_help_finisher_cb help_finish;

    /* Only one of handler or subcmds may be non-NULL. */
    ipmi_cmdlang_handler_cb handler;
    ipmi_cmdlang_cmd_t      *subcmds;

    void                    *handler_data;

    /* Used for a linked list. */
    ipmi_cmdlang_cmd_t *next;
};

static os_handler_t *cmdlang_os_hnd;

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
		i++;
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
    char               domain_name[IPMI_DOMAIN_NAME_LEN];

    if (cmd_info->cmdlang->err)
	return;

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    if ((!info->cmpstr) || (strcmp(info->cmpstr, domain_name) == 0))
	info->handler(domain, info->cb_data);
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
 * Handling for iterating PETs.
 */
typedef struct pet_iter_info_s
{
    char            *cmdstr;
    ipmi_pet_ptr_cb handler;
    void            *cb_data;
    ipmi_cmd_info_t *cmd_info;
} pet_iter_info_t;

static void
for_each_pet_handler(ipmi_pet_t *pet, void *cb_data)
{
    pet_iter_info_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            name[IPMI_PET_NAME_LEN];
    char            *c;

    if (cmdlang->err)
	return;

    ipmi_pet_get_name(pet, name, sizeof(name));

    c = strrchr(name, '.');
    if (!c)
	goto out_err;
    c++;
    if ((! info->cmdstr) || (strcmp(info->cmdstr, c) == 0))
	info->handler(pet, info->cb_data);
    return;

 out_err:
    ipmi_cmdlang_global_err(name,
			    "cmdlang.c(for_each_pet_handler)",
			    "Bad PET name", EINVAL);
}

static void
for_each_pet_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_pet_iterate_pets(domain, for_each_pet_handler, cb_data);
}

static void
for_each_pet(ipmi_cmd_info_t *cmd_info,
	     char            *domain,
	     char            *class,
	     char            *obj,
	     ipmi_pet_ptr_cb handler,
	     void            *cb_data)
{
    pet_iter_info_t info;

    if (class) {
	cmd_info->cmdlang->errstr = "Invalid PET";
	cmd_info->cmdlang->err = EINVAL;
	cmd_info->cmdlang->location = "cmdlang.c(for_each_pet)";
	return;
    }

    info.handler = handler;
    info.cb_data = cb_data;
    info.cmd_info = cmd_info;
    info.cmdstr = obj;
    for_each_domain(cmd_info, domain, NULL, NULL,
		    for_each_pet_domain_handler, &info);
}

void
ipmi_cmdlang_pet_handler(ipmi_cmd_info_t *cmd_info)
{
    char *domain, *class, *obj;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	domain = cmd_info->argv[cmd_info->curr_arg];
	class = NULL;
	obj = strrchr(domain, '.');
	if (!obj) {
	    cmd_info->cmdlang->errstr = "Invalid PET";
	    cmd_info->cmdlang->err = EINVAL;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_pet_handler)";
	    return;
	}
	*obj = '\0';
	obj++;
	cmd_info->curr_arg++;
    }

    for_each_pet(cmd_info, domain, class, obj, cmd_info->handler_data,
		 cmd_info);
}

/*
 * Handling for iterating LANPARMs.
 */
typedef struct lanparm_iter_info_s
{
    char                *cmdstr;
    ipmi_lanparm_ptr_cb handler;
    void                *cb_data;
    ipmi_cmd_info_t     *cmd_info;
} lanparm_iter_info_t;

static void
for_each_lanparm_handler(ipmi_lanparm_t *lanparm, void *cb_data)
{
    lanparm_iter_info_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            name[IPMI_LANPARM_NAME_LEN];
    char            *c;

    if (cmdlang->err)
	return;

    ipmi_lanparm_get_name(lanparm, name, sizeof(name));

    c = strrchr(name, '.');
    if (!c)
	goto out_err;
    c++;
    if ((! info->cmdstr) || (strcmp(info->cmdstr, c) == 0))
	info->handler(lanparm, info->cb_data);
    return;

 out_err:
    ipmi_cmdlang_global_err(name,
			    "cmdlang.c(for_each_lanparm_handler)",
			    "Bad LANPARM name", EINVAL);
}

static void
for_each_lanparm_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_lanparm_iterate_lanparms(domain, for_each_lanparm_handler, cb_data);
}

static void
for_each_lanparm(ipmi_cmd_info_t *cmd_info,
	     char            *domain,
	     char            *class,
	     char            *obj,
	     ipmi_lanparm_ptr_cb handler,
	     void            *cb_data)
{
    lanparm_iter_info_t info;

    if (class) {
	cmd_info->cmdlang->errstr = "Invalid LANPARM";
	cmd_info->cmdlang->err = EINVAL;
	cmd_info->cmdlang->location = "cmdlang.c(for_each_lanparm)";
	return;
    }

    info.handler = handler;
    info.cb_data = cb_data;
    info.cmd_info = cmd_info;
    info.cmdstr = obj;
    for_each_domain(cmd_info, domain, NULL, NULL,
		    for_each_lanparm_domain_handler, &info);
}

void
ipmi_cmdlang_lanparm_handler(ipmi_cmd_info_t *cmd_info)
{
    char *domain, *class, *obj;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	domain = cmd_info->argv[cmd_info->curr_arg];
	class = NULL;
	obj = strrchr(domain, '.');
	if (!obj) {
	    cmd_info->cmdlang->errstr = "Invalid LANPARM";
	    cmd_info->cmdlang->err = EINVAL;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_lanparm_handler)";
	    return;
	}
	*obj = '\0';
	obj++;
	cmd_info->curr_arg++;
    }

    for_each_lanparm(cmd_info, domain, class, obj, cmd_info->handler_data,
		 cmd_info);
}

/*
 * Handling for iterating SOLPARMs.
 */
typedef struct solparm_iter_info_s
{
    char                *cmdstr;
    ipmi_solparm_ptr_cb handler;
    void                *cb_data;
    ipmi_cmd_info_t     *cmd_info;
} solparm_iter_info_t;

static void
for_each_solparm_handler(ipmi_solparm_t *solparm, void *cb_data)
{
    solparm_iter_info_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            name[IPMI_SOLPARM_NAME_LEN];
    char            *c;

    if (cmdlang->err)
	return;

    ipmi_solparm_get_name(solparm, name, sizeof(name));

    c = strrchr(name, '.');
    if (!c)
	goto out_err;
    c++;
    if ((! info->cmdstr) || (strcmp(info->cmdstr, c) == 0))
	info->handler(solparm, info->cb_data);
    return;

 out_err:
    ipmi_cmdlang_global_err(name,
			    "cmdlang.c(for_each_solparm_handler)",
			    "Bad SOLPARM name", EINVAL);
}

static void
for_each_solparm_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_solparm_iterate_solparms(domain, for_each_solparm_handler, cb_data);
}

static void
for_each_solparm(ipmi_cmd_info_t *cmd_info,
	     char            *domain,
	     char            *class,
	     char            *obj,
	     ipmi_solparm_ptr_cb handler,
	     void            *cb_data)
{
    solparm_iter_info_t info;

    if (class) {
	cmd_info->cmdlang->errstr = "Invalid SOLPARM";
	cmd_info->cmdlang->err = EINVAL;
	cmd_info->cmdlang->location = "cmdlang.c(for_each_solparm)";
	return;
    }

    info.handler = handler;
    info.cb_data = cb_data;
    info.cmd_info = cmd_info;
    info.cmdstr = obj;
    for_each_domain(cmd_info, domain, NULL, NULL,
		    for_each_solparm_domain_handler, &info);
}

void
ipmi_cmdlang_solparm_handler(ipmi_cmd_info_t *cmd_info)
{
    char *domain, *class, *obj;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	domain = cmd_info->argv[cmd_info->curr_arg];
	class = NULL;
	obj = strrchr(domain, '.');
	if (!obj) {
	    cmd_info->cmdlang->errstr = "Invalid SOLPARM";
	    cmd_info->cmdlang->err = EINVAL;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_solparm_handler)";
	    return;
	}
	*obj = '\0';
	obj++;
	cmd_info->curr_arg++;
    }

    for_each_solparm(cmd_info, domain, class, obj, cmd_info->handler_data,
		 cmd_info);
}

/*
 * Handling for iterating PEFs.
 */
typedef struct pef_iter_info_s
{
    char            *cmdstr;
    ipmi_pef_ptr_cb handler;
    void            *cb_data;
    ipmi_cmd_info_t *cmd_info;
} pef_iter_info_t;

static void
for_each_pef_handler(ipmi_pef_t *pef, void *cb_data)
{
    pef_iter_info_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            name[IPMI_PEF_NAME_LEN];
    char            *c;

    if (cmdlang->err)
	return;

    ipmi_pef_get_name(pef, name, sizeof(name));

    c = strrchr(name, '.');
    if (!c)
	goto out_err;
    c++;
    if ((! info->cmdstr) || (strcmp(info->cmdstr, c) == 0))
	info->handler(pef, info->cb_data);
    return;

 out_err:
    ipmi_cmdlang_global_err(name,
			    "cmdlang.c(for_each_pef_handler)",
			    "Bad PEF name", EINVAL);
}

static void
for_each_pef_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_pef_iterate_pefs(domain, for_each_pef_handler, cb_data);
}

static void
for_each_pef(ipmi_cmd_info_t *cmd_info,
	     char            *domain,
	     char            *class,
	     char            *obj,
	     ipmi_pef_ptr_cb handler,
	     void            *cb_data)
{
    pef_iter_info_t info;

    if (class) {
	cmd_info->cmdlang->errstr = "Invalid PEF";
	cmd_info->cmdlang->err = EINVAL;
	cmd_info->cmdlang->location = "cmdlang.c(for_each_pef)";
	return;
    }

    info.handler = handler;
    info.cb_data = cb_data;
    info.cmd_info = cmd_info;
    info.cmdstr = obj;
    for_each_domain(cmd_info, domain, NULL, NULL,
		    for_each_pef_domain_handler, &info);
}

void
ipmi_cmdlang_pef_handler(ipmi_cmd_info_t *cmd_info)
{
    char *domain, *class, *obj;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	domain = cmd_info->argv[cmd_info->curr_arg];
	class = NULL;
	obj = strrchr(domain, '.');
	if (!obj) {
	    cmd_info->cmdlang->errstr = "Invalid PEF";
	    cmd_info->cmdlang->err = EINVAL;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_pef_handler)";
	    return;
	}
	*obj = '\0';
	obj++;
	cmd_info->curr_arg++;
    }

    for_each_pef(cmd_info, domain, class, obj, cmd_info->handler_data,
		 cmd_info);
}


/*
 * Handling for iterating FRUs.
 */
typedef struct fru_iter_info_s
{
    char            *cmdstr;
    ipmi_fru_ptr_cb handler;
    void            *cb_data;
    ipmi_cmd_info_t *cmd_info;
} fru_iter_info_t;

static void
for_each_fru_handler(ipmi_fru_t *fru, void *cb_data)
{
    fru_iter_info_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            name[IPMI_FRU_NAME_LEN];
    char            *c;

    if (cmdlang->err)
	return;

    ipmi_fru_get_name(fru, name, sizeof(name));

    c = strrchr(name, '.');
    if (!c)
	goto out_err;
    c++;
    if ((! info->cmdstr) || (strcmp(info->cmdstr, c) == 0))
	info->handler(fru, info->cb_data);
    return;

 out_err:
    ipmi_cmdlang_global_err(name,
			    "cmdlang.c(for_each_fru_handler)",
			    "Bad FRU name", EINVAL);
}

static void
for_each_fru_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_fru_iterate_frus(domain, for_each_fru_handler, cb_data);
}

static void
for_each_fru(ipmi_cmd_info_t *cmd_info,
	     char            *domain,
	     char            *class,
	     char            *obj,
	     ipmi_fru_ptr_cb handler,
	     void            *cb_data)
{
    fru_iter_info_t info;

    if (class) {
	cmd_info->cmdlang->errstr = "Invalid FRU";
	cmd_info->cmdlang->err = EINVAL;
	cmd_info->cmdlang->location = "cmdlang.c(for_each_fru)";
	return;
    }

    info.handler = handler;
    info.cb_data = cb_data;
    info.cmd_info = cmd_info;
    info.cmdstr = obj;
    for_each_domain(cmd_info, domain, NULL, NULL,
		    for_each_fru_domain_handler, &info);
}

void
ipmi_cmdlang_fru_handler(ipmi_cmd_info_t *cmd_info)
{
    char *domain, *class, *obj;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	domain = cmd_info->argv[cmd_info->curr_arg];
	class = NULL;
	obj = strrchr(domain, '.');
	if (!obj) {
	    cmd_info->cmdlang->errstr = "Invalid FRU";
	    cmd_info->cmdlang->err = EINVAL;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_fru_handler)";
	    return;
	}
	*obj = '\0';
	obj++;
	cmd_info->curr_arg++;
    }

    for_each_fru(cmd_info, domain, class, obj, cmd_info->handler_data,
		 cmd_info);
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
    char               *c, *c2;

    if (cmd_info->cmdlang->err)
	return;

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));
    c = strchr(entity_name, '(');
    if (!c)
	goto out_err;
    c++;
    c2 = strchr(c, ')');
    if (!c2)
	goto out_err;
    *c2 = '\0';
    if ((!info->cmpstr) || (strcmp(info->cmpstr, c) == 0)) {
	*c2 = ')';
	info->handler(entity, info->cb_data);
    } else
	*c2 = ')';
    return;

 out_err:
    ipmi_cmdlang_global_err(entity_name,
			    "cmdlang.c(for_each_entity_handler)",
			    "Bad entity name", EINVAL);
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
    char               sensor_name[IPMI_SENSOR_NAME_LEN];
    char               *c;

    ipmi_sensor_get_name(sensor, sensor_name, sizeof(sensor_name));
    c = strchr(sensor_name, '(');
    if (!c)
	goto out_err;
    c = strchr(c, ')');
    if (!c)
	goto out_err;
    c = strchr(c, '.');
    if (!c)
	goto out_err;
    c++;
    if ((!info->cmpstr) || (strcmp(info->cmpstr, c) == 0))
	info->handler(sensor, info->cb_data);
    return;

 out_err:
    ipmi_cmdlang_global_err(sensor_name,
			    "cmdlang.c(for_each_sensor_handler)",
			    "Bad sensor name", EINVAL);
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

    info.cmpstr = obj;
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
    char                control_name[IPMI_CONTROL_NAME_LEN];
    char               *c;

    ipmi_control_get_name(control, control_name, sizeof(control_name));
    c = strchr(control_name, '(');
    if (!c)
	goto out_err;
    c = strchr(c, ')');
    if (!c)
	goto out_err;
    c = strchr(c, '.');
    if (!c)
	goto out_err;
    c++;
    if ((!info->cmpstr) || (strcmp(info->cmpstr, c) == 0))
	info->handler(control, info->cb_data);
    return;

 out_err:
    ipmi_cmdlang_global_err(control_name,
			    "cmdlang.c(for_each_control_handler)",
			    "Bad control name", EINVAL);
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

    info.cmpstr = obj;
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
    char            mc_name[IPMI_MC_NAME_LEN];
    char            *c, *c2;

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    c = strchr(mc_name, '(');
    if (!c)
	goto out_err;
    c++;
    c2 = strchr(c, ')');
    if (!c2)
	goto out_err;
    *c2 = '\0';
    if ((!info->cmpstr) || (strcmp(info->cmpstr, c) == 0)) {
	*c2 = ')';
	info->handler(mc, info->cb_data);
    } else
	*c2 = ')';
    return;

 out_err:
    ipmi_cmdlang_global_err(mc_name,
			    "cmdlang.c(for_each_entity_handler)",
			    "Bad mc name", EINVAL);
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

    if ((info->conn == -1) || (info->conn == conn))
	info->handler(domain, conn, info->cb_data);
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
	info.conn = strtoul(obj, &endptr, 0);
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

    if (cmd_info->curr_arg >= cmd_info->argc) {
	domain = class = obj = NULL;
    } else {
	domain = cmd_info->argv[cmd_info->curr_arg];
	class = NULL;
	obj = strrchr(domain, '.');
	if (!obj) {
	    cmd_info->cmdlang->errstr = "Invalid connection";
	    cmd_info->cmdlang->err = EINVAL;
	    cmd_info->cmdlang->location
		= "cmdlang.c(ipmi_cmdlang_connection_handler)";
	    return;
	}
	*obj = '\0';
	obj++;
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
	str++;
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

    if (*str == '#') {
	/* A comment */
	cmdlang->done(cmdlang);
	return;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	cmdlang->location = "cmdlang.c(ipmi_cmdlang_handle)";
	cmdlang->done(cmdlang);
	return;
    }
    memset(info, 0, sizeof(*info));
    info->usecount = 1;
    info->cmdlang = cmdlang;
    rv = ipmi_create_lock_os_hnd(cmdlang->os_hnd, &info->lock);
    if (rv) {
	cmdlang->errstr = "Could not allocate lock";
	cmdlang->err = rv;
	cmdlang->location = "cmdlang.c(ipmi_cmdlang_handle)";
	goto done;
    }

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
	int                old_help = cmdlang->help;
	/* Help has special handling. */

	cmdlang->help = 1;
	curr_arg++;
	for (;;) {
	next_help:
	    if (argc == curr_arg) {
		rv = 0;
		if (parent) {
		    cmdlang->out(cmdlang, parent->name, parent->help);
		    if (parent->help_finish)
			parent->help_finish(cmdlang);
		}else
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
		    if (cmd->help_finish)
			cmd->help_finish(cmdlang);
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
	info->did_output = 1;
	cmdlang->help = old_help;
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
    ipmi_cmdlang_cmd_info_put(info);
}

int
ipmi_cmdlang_reg_cmd(ipmi_cmdlang_cmd_t      *parent,
		     char                    *name,
		     char                    *help,
		     ipmi_cmdlang_handler_cb handler,
		     void                    *cb_data,
		     ipmi_help_finisher_cb   help_finish,
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
    rv->help_finish = help_finish;
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
ipmi_cmdlang_reg_table(ipmi_cmdlang_init_t *table, int len)
{
    int                i;
    int                rv;
    ipmi_cmdlang_cmd_t *parent = NULL;

    for (i=0; i<len; i++) {
	if (table[i].parent)
	    parent = *table[i].parent;
	rv = ipmi_cmdlang_reg_cmd(parent,
				  table[i].name,
				  table[i].help,
				  table[i].handler,
				  table[i].cb_data,
				  table[i].help_finish,
				  table[i].new_val);
	if (rv)
	    return rv;
    }

    return 0;
}

void
ipmi_cmdlang_lock(ipmi_cmd_info_t *info)
{
    ipmi_lock(info->lock);
}

void
ipmi_cmdlang_unlock(ipmi_cmd_info_t *info)
{
    ipmi_unlock(info->lock);
}

void
ipmi_cmdlang_out(ipmi_cmd_info_t *info,
		 const char      *name,
		 const char      *value)
{
    info->did_output = 1;
    info->cmdlang->out(info->cmdlang, name, value);
}

void
ipmi_cmdlang_out_int(ipmi_cmd_info_t *info,
		     const char      *name,
		     int             value)
{
    char sval[20];

    sprintf(sval, "%d", value);
    ipmi_cmdlang_out(info, name, sval);
}

void
ipmi_cmdlang_out_double(ipmi_cmd_info_t *info,
			const char      *name,
			double          value)
{
    char sval[80];

    sprintf(sval, "%e", value);
    ipmi_cmdlang_out(info, name, sval);
}

void
ipmi_cmdlang_out_hex(ipmi_cmd_info_t *info,
		     const char      *name,
		     int             value)
{
    char sval[20];

    sprintf(sval, "0x%x", value);
    ipmi_cmdlang_out(info, name, sval);
}

void
ipmi_cmdlang_out_long(ipmi_cmd_info_t *info,
		      const char      *name,
		      long            value)
{
    char sval[32];

    sprintf(sval, "%ld", value);
    ipmi_cmdlang_out(info, name, sval);
}

void
ipmi_cmdlang_out_binary(ipmi_cmd_info_t *info,
			const char      *name,
			const char      *value,
			unsigned int    len)
{
    info->did_output = 1;
    info->cmdlang->out_binary(info->cmdlang, name, value, len);
}

void
ipmi_cmdlang_out_unicode(ipmi_cmd_info_t *info,
			 const char      *name,
			 const char      *value,
			 unsigned int    len)
{
    info->did_output = 1;
    info->cmdlang->out_unicode(info->cmdlang, name, value, len);
}

void
ipmi_cmdlang_out_type(ipmi_cmd_info_t      *info,
		      char                 *name,
		      enum ipmi_str_type_e type,
		      const char           *value,
		      unsigned int         len)
{
    switch(type) {
    case IPMI_ASCII_STR:
	ipmi_cmdlang_out(info, name, value);
	break;
    case IPMI_UNICODE_STR:
	ipmi_cmdlang_out_unicode(info, name, value, len);
	break;
    case IPMI_BINARY_STR:
	ipmi_cmdlang_out_binary(info, name, value, len);
	break;
    }
}

void
ipmi_cmdlang_out_bool(ipmi_cmd_info_t *info,
		      const char      *name,
		      int             value)
{
    if (value)
	ipmi_cmdlang_out(info, name, "true");
    else
	ipmi_cmdlang_out(info, name, "false");
}

void
ipmi_cmdlang_out_time(ipmi_cmd_info_t *info,
		      const char      *name,
		      ipmi_time_t     value)
{
    char sval[40];

    sprintf(sval, "%lld", (long long) value);
    ipmi_cmdlang_out(info, name, sval);
}

void
ipmi_cmdlang_out_timeout(ipmi_cmd_info_t *info,
			 const char      *name,
			 ipmi_timeout_t  value)
{
    char sval[40];

    sprintf(sval, "%lld", (long long) value);
    ipmi_cmdlang_out(info, name, sval);
}

void
ipmi_cmdlang_out_ip(ipmi_cmd_info_t *info,
		    const char      *name,
		    struct in_addr  *ip_addr)
{
    char outstr[16];
    u_int32_t addr = ntohl(ip_addr->s_addr);

    /* Why isn't there an inet_ntoa_r? */
    sprintf(outstr, "%d.%d.%d.%d",
	    (addr >> 24) & 0xff,
	    (addr >> 16) & 0xff,
	    (addr >> 8) & 0xff,
	    (addr >> 0) & 0xff);
    ipmi_cmdlang_out(info, name, outstr);
}

void
ipmi_cmdlang_out_mac(ipmi_cmd_info_t *info,
		     const char      *name,
		     unsigned char   mac_addr[6])
{
    char outstr[18];

    /* Why isn't there a standard ether_ntoa_r? */
    sprintf(outstr, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
	    mac_addr[0],
	    mac_addr[1],
	    mac_addr[2],
	    mac_addr[3],
	    mac_addr[4],
	    mac_addr[5]);
    ipmi_cmdlang_out(info, name, outstr);
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
    ipmi_cmdlang_lock(cmd_info);
    cmd_info->usecount++;
    ipmi_cmdlang_unlock(cmd_info);
}

void
ipmi_cmdlang_cmd_info_put(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_lock(cmd_info);
    cmd_info->usecount--;
    if (cmd_info->usecount == 0) {
	if ((!cmd_info->cmdlang->err) && (!cmd_info->did_output)) {
	    cmd_info->cmdlang->errstr = "Specified object not found";
	    cmd_info->cmdlang->err = EINVAL;
	    cmd_info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_handle)";
	}

	cmd_info->cmdlang->done(cmd_info->cmdlang);
	ipmi_cmdlang_unlock(cmd_info);
	if (cmd_info->lock)
	    ipmi_destroy_lock(cmd_info->lock);
	ipmi_mem_free(cmd_info);
    } else
	ipmi_cmdlang_unlock(cmd_info);
}

void
ipmi_cmdlang_get_int(char *str, int *val, ipmi_cmd_info_t *info)
{
    char *end;
    int  rv;

    if (info->cmdlang->err)
	return;

    rv = strtoul(str, &end, 0);
    if (*end != '\0') {
	info->cmdlang->errstr = "Invalid integer";
	info->cmdlang->err = EINVAL;
	info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_int)";
	return;
    }

    *val = rv;
}

void
ipmi_cmdlang_get_time(char *str, ipmi_time_t *val, ipmi_cmd_info_t *info)
{
    char        *end;
    ipmi_time_t rv;

    if (info->cmdlang->err)
	return;

    rv = strtoull(str, &end, 0);
    if (*end != '\0') {
	info->cmdlang->errstr = "Invalid integer";
	info->cmdlang->err = EINVAL;
	info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_int)";
	return;
    }

    *val = rv;
}

void
ipmi_cmdlang_get_timeout(char *str, ipmi_timeout_t *val,
			 ipmi_cmd_info_t *info)
{
    char           *end;
    ipmi_timeout_t rv;

    if (info->cmdlang->err)
	return;

    rv = strtoull(str, &end, 0);
    if (*end != '\0') {
	info->cmdlang->errstr = "Invalid integer";
	info->cmdlang->err = EINVAL;
	info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_int)";
	return;
    }

    *val = rv;
}

void
ipmi_cmdlang_get_double(char *str, double *val, ipmi_cmd_info_t *info)
{
    char   *end;
    double rv;

    if (info->cmdlang->err)
	return;

    rv = strtod(str, &end);
    if (*end != '\0') {
	info->cmdlang->errstr = "Invalid double";
	info->cmdlang->err = EINVAL;
	info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_double)";
	return;
    }

    *val = rv;
}

void
ipmi_cmdlang_get_uchar(char *str, unsigned char *val, ipmi_cmd_info_t *info)
{
    char *end;
    int  rv;

    if (info->cmdlang->err)
	return;

    rv = strtoul(str, &end, 0);
    if (*end != '\0') {
	info->cmdlang->errstr = "Invalid integer";
	info->cmdlang->err = EINVAL;
	info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_uchar)";
	return;
    }

    *val = rv;
}

void
ipmi_cmdlang_get_bool(char *str, int *val, ipmi_cmd_info_t *info)
{
    int  rv;

    if (info->cmdlang->err)
	return;

    if ((strcasecmp(str, "true") == 0)
	|| (strcasecmp(str, "on") == 0)
	|| (strcasecmp(str, "t") == 0)
	|| (strcmp(str, "1") == 0))
    {
	rv = 1;
    } else if ((strcasecmp(str, "false") == 0)
	       || (strcasecmp(str, "off") == 0)
	       || (strcasecmp(str, "f") == 0)
	       || (strcmp(str, "0") == 0))
    {
	rv = 0;
    } else {
	info->cmdlang->errstr = "Invalid boolean";
	info->cmdlang->err = EINVAL;
	info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_bool)";
	return;
    }

    *val = rv;
}

void
ipmi_cmdlang_get_user(char *str, int *val, ipmi_cmd_info_t *info)
{
    char *end;
    int  rv;

    if (info->cmdlang->err)
	return;

    rv = strtoul(str, &end, 0);
    if (*end != '\0')
	goto not_int;

    *val = rv;
    return;

 not_int:
    if (strcmp(str, "callback") == 0)
	*val = IPMI_PRIVILEGE_CALLBACK;
    else if (strcmp(str, "user") == 0)
	*val = IPMI_PRIVILEGE_USER;
    else if (strcmp(str, "operator") == 0)
	*val = IPMI_PRIVILEGE_OPERATOR;
    else if (strcmp(str, "admin") == 0)
	*val = IPMI_PRIVILEGE_ADMIN;
    else if (strcmp(str, "oem") == 0)
	*val = IPMI_PRIVILEGE_OEM;
    else {
	info->cmdlang->errstr = "Invalid privilege level";
	info->cmdlang->err = EINVAL;
	info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_user)";
    }
}

void
ipmi_cmdlang_get_ip(char *str, struct in_addr *val, ipmi_cmd_info_t *info)
{
#ifdef HAVE_GETADDRINFO
    struct addrinfo    hints, *res0;
    int                rv;
    struct sockaddr_in *paddr;
 
    if (info->cmdlang->err)
	return;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    rv = getaddrinfo(str, 0, &hints, &res0);
    if (rv == 0) {
	/* Only get the first choice */
	paddr = (struct sockaddr_in *) res0->ai_addr;
	*val = paddr->sin_addr;
	freeaddrinfo(res0);
    } else
	info->cmdlang->err = rv;
#else
    /* System does not support getaddrinfo, just for IPv4*/
    struct hostent     *ent;
    struct sockaddr_in *paddr;

    if (info->cmdlang->err)
	return;

    ent = gethostbyname(str);
    if (!ent) {
	info->cmdlang->err = EINVAL;
    } else {
	paddr = (struct sockaddr_in *) &ent->h_addr_list[0];
	*val = paddr->sin_addr;
	memcpy(val, ent->h_addr_list[0], ent->h_length);
    }
#endif
}

void
ipmi_cmdlang_get_mac(char *str, unsigned char val[6], ipmi_cmd_info_t *info)
{
    char          tmp[3];
    char          *tv;
    int           len;
    unsigned char tmp_val[6];
    int           i;
    char          *end;

    if (info->cmdlang->err)
	return;

    for (i=0; i<6; i++) {
	if (i == 5)
	    tv = str + strlen(str);
	else
	    tv = strchr(str, ':');
	if (!tv) {
	    info->cmdlang->err = EINVAL;
	    goto out;
	}
	len = tv-str;
	if (len > 2) {
	    info->cmdlang->err = EINVAL;
	    goto out;
	}
	memset(tmp, 0, sizeof(tmp));
	memcpy(tmp, str, len);
	tmp_val[i] = strtoul(tmp, &end, 16);
	if (*end != '\0') {
	    info->cmdlang->err = EINVAL;
	    goto out;
	}
	str = tv+1;
    }

    memcpy(val, tmp_val, sizeof(tmp_val));
    return;

 out:
    return;
}

void
ipmi_cmdlang_get_color(char *str, int *val, ipmi_cmd_info_t *info)
{
    int i;

    for (i=IPMI_CONTROL_COLOR_BLACK; i<IPMI_CONTROL_COLOR_ORANGE; i++){
	if (strcmp(str, ipmi_get_color_string(i)) == 0) {
	    *val = i;
	    return;
	}
    }

    info->cmdlang->errstr = "Invalid color";
    info->cmdlang->err = EINVAL;
    info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_color)";
}

static int
issep(char val)
{
    return ((val == ' ')
	    || (val == '\t')
	    || (val == '\n')
	    || (val == '\r'));
}

void
ipmi_cmdlang_get_threshold_ev(char                        *str,
			      enum ipmi_thresh_e          *rthresh,
			      enum ipmi_event_value_dir_e *rvalue_dir,
			      enum ipmi_event_dir_e       *rdir,
			      ipmi_cmd_info_t             *info)
{
    enum ipmi_thresh_e          thresh;
    enum ipmi_event_value_dir_e value_dir;
    enum ipmi_event_dir_e       dir;
    char                        val[4][20];
    int                         len;
    int                         vc;


    vc = 0;
    for (;;) {
	char *start, *end;

	while (issep(*str))
	    str++;
	if (! *str)
	    break;

	if (vc == 4)
	    goto out_err;

	start = str;
	while (*str && (!issep(*str)))
	    str++;
	end = str;
	len = end - start;
	if (len >= 20)
	    goto out_err;

	memcpy(val[vc], start, len);
	val[vc][len] = '\0';
	vc++;
    }

    if (vc == 1) {
	/* One value, it is a compressed form. */
	if (strlen(val[0]) != 4)
	    goto out_err;

	if ((val[0][0] == 'u') || (val[0][0] == 'U')) {
	    if ((val[0][1] == 'n') || (val[0][1] == 'N'))
		thresh = IPMI_UPPER_NON_CRITICAL;
	    else if ((val[0][1] == 'c') || (val[0][1] == 'C'))
		thresh = IPMI_UPPER_CRITICAL;
	    else if ((val[0][1] == 'f') || (val[0][1] == 'F'))
		thresh = IPMI_UPPER_NON_RECOVERABLE;
	    else if ((val[0][1] == 'r') || (val[0][1] == 'R'))
		thresh = IPMI_UPPER_NON_RECOVERABLE;
	    else
		goto out_err;
	} else if ((val[0][0] == 'l') || (val[0][0] == 'L')) {
	    if ((val[0][1] == 'n') || (val[0][1] == 'N'))
		thresh = IPMI_LOWER_NON_CRITICAL;
	    else if ((val[0][1] == 'c') || (val[0][1] == 'C'))
		thresh = IPMI_LOWER_CRITICAL;
	    else if ((val[0][1] == 'f') || (val[0][1] == 'F'))
		thresh = IPMI_LOWER_NON_RECOVERABLE;
	    else if ((val[0][1] == 'r') || (val[0][1] == 'R'))
		thresh = IPMI_LOWER_NON_RECOVERABLE;
	    else
		goto out_err;
	} else
	    goto out_err;

	if ((val[0][2] == 'h') || (val[0][2] == 'H'))
	    value_dir = IPMI_GOING_HIGH;
	else if ((val[0][2] == 'l') || (val[0][2] == 'L'))
	    value_dir = IPMI_GOING_LOW;
	else
	    goto out_err;

	if ((val[0][3] == 'a') || (val[0][2] == 'A'))
	    dir = IPMI_ASSERTION;
	else if ((val[0][3] == 'd') || (val[0][3] == 'D'))
	    dir = IPMI_DEASSERTION;
	else
	    goto out_err;
    } else if (vc == 4) {
	/* Four values, uncompressed form */
	if (strcasecmp(val[0], "upper") == 0) {
	    if (strcasecmp(val[1], "non-critical") == 0)
		thresh = IPMI_UPPER_NON_CRITICAL;
	    else if (strcasecmp(val[1], "critical") == 0)
		thresh = IPMI_UPPER_CRITICAL;
	    else if (strcasecmp(val[1], "non-recoverable") == 0)
		thresh = IPMI_UPPER_NON_RECOVERABLE;
	    else
		goto out_err;
	} else if (strcasecmp(val[0], "lower") == 0) {
	    if (strcasecmp(val[1], "non-critical") == 0)
		thresh = IPMI_LOWER_NON_CRITICAL;
	    else if (strcasecmp(val[1], "critical") == 0)
		thresh = IPMI_LOWER_CRITICAL;
	    else if (strcasecmp(val[1], "non-recoverable") == 0)
		thresh = IPMI_LOWER_NON_RECOVERABLE;
	    else
		goto out_err;
	} else
	    goto out_err;

	if (strcasecmp(val[2], "going-high") == 0)
	    value_dir = IPMI_GOING_HIGH;
	else if (strcasecmp(val[2], "going-low") == 0)
	    value_dir = IPMI_GOING_LOW;
	else
	    goto out_err;

	if (strcasecmp(val[3], "assertion") == 0)
	    dir = IPMI_ASSERTION;
	else if (strcasecmp(val[3], "deassertion") == 0)
	    dir = IPMI_DEASSERTION;
	else
	    goto out_err;
    } else
	goto out_err;
    if (rdir)
	*rdir = dir;
    if (rvalue_dir)
	*rvalue_dir = value_dir;
    if (rthresh)
	*rthresh = thresh;
    return;

 out_err:
    info->cmdlang->errstr = "Invalid threshold event";
    info->cmdlang->err = EINVAL;
    info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_threshold_ev)";
}

void
ipmi_cmdlang_get_threshold(char               *str,
			   enum ipmi_thresh_e *rthresh,
			   ipmi_cmd_info_t    *info)
{
    enum ipmi_thresh_e thresh;

    for (thresh = IPMI_LOWER_NON_CRITICAL;
	 thresh <= IPMI_UPPER_NON_RECOVERABLE; 
	 thresh++)
    {
	if (strcmp(str, ipmi_get_threshold_string(thresh)) == 0) {
	    if (rthresh)
		*rthresh = thresh;
	    return;
	}
    }
    if (strcasecmp(str, "un") == 0)
	thresh = IPMI_UPPER_NON_CRITICAL;
    else if (strcasecmp(str, "uc") == 0)
	thresh = IPMI_UPPER_CRITICAL;
    else if (strcasecmp(str, "ur") == 0)
	thresh = IPMI_UPPER_NON_RECOVERABLE;
    else if (strcasecmp(str, "ln") == 0)
	thresh = IPMI_LOWER_NON_CRITICAL;
    else if (strcasecmp(str, "lc") == 0)
	thresh = IPMI_LOWER_CRITICAL;
    else if (strcasecmp(str, "lr") == 0)
	thresh = IPMI_LOWER_NON_RECOVERABLE;
    else
	goto out_err;

    if (rthresh)
	*rthresh = thresh;
    return;

 out_err:
    info->cmdlang->errstr = "Invalid threshold";
    info->cmdlang->err = EINVAL;
    info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_threshold)";
}

void
ipmi_cmdlang_get_discrete_ev(char                  *str,
			     int                   *roffset,
			     enum ipmi_event_dir_e *rdir,
			     ipmi_cmd_info_t       *info)
{
    int                   offset;
    enum ipmi_event_dir_e dir;
    char                  val[4][20];
    int                   len;
    int                   vc;
    char                  *end;


    vc = 0;
    for (;;) {
	char *start, *end;

	while (issep(*str))
	    str++;
	if (! *str)
	    break;

	if (vc == 4)
	    goto out_err;

	start = str;
	while (*str && (!issep(*str)))
	    str++;
	end = str;
	len = end - start;
	if (len >= 20)
	    goto out_err;

	memcpy(val[vc], start, len);
	val[vc][len] = '\0';
	vc++;
    }

    if (vc == 1) {
	/* One value, it is a compressed form. */

	offset = strtoul(val[0], &end, 0);
	if (end == val[0])
	    goto out_err;
	if ((*end == 'd') || (*end == 'D'))
	    dir = IPMI_DEASSERTION;
	else if ((*end == 'a') || (*end == 'A'))
	    dir = IPMI_ASSERTION;
	else
	    goto out_err;
	end++;
	if (*end != '\0')
	    goto out_err;
    } else if (vc == 2) {
	offset = strtoul(val[0], &end, 0);
	if ((end == val[0]) || (*end != '\0'))
	    goto out_err;
	if (strcasecmp(val[1], "deassertion")  == 0)
	    dir = IPMI_DEASSERTION;
	else if (strcasecmp(val[1], "assertion")  == 0)
	    dir = IPMI_ASSERTION;
	else
	    goto out_err;
    } else
	goto out_err;

    if (roffset)
	*roffset = offset;
    if (rdir)
	*rdir = dir;
    return;

 out_err:
    info->cmdlang->errstr = "Invalid discrete event";
    info->cmdlang->err = EINVAL;
    info->cmdlang->location = "cmdlang.c(ipmi_cmdlang_get_discrete_event)";
}

typedef struct ipmi_cmdlang_event_entry_s ipmi_cmdlang_event_entry_t;
struct ipmi_cmdlang_event_entry_s
{
    char *name;
    enum ipmi_cmdlang_out_types type;
    char *value;
    unsigned int len;
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

void
event_out(ipmi_cmdlang_t *cmdlang, const char *name, const char *value)
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

    entry->type = IPMI_CMDLANG_STRING;

    if (value) {
	entry->len = strlen(value);
	entry->value = ipmi_strdup(value);
	if (!entry->value) {
	    ipmi_mem_free(entry->name);
	    ipmi_mem_free(entry);
	    goto out_nomem;
	}
    } else {
	entry->len = 0;
	entry->value = NULL;
    }

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

static void
event_out_binary(ipmi_cmdlang_t *cmdlang, const char *name,
		 const char *value, unsigned int len)
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

    entry->type = IPMI_CMDLANG_BINARY;

    entry->len = len;
    if (len > 0) {
	entry->value = ipmi_mem_alloc(len);
	if (!entry->value) {
	    ipmi_mem_free(entry->name);
	    ipmi_mem_free(entry);
	    goto out_nomem;
	}
	memcpy(entry->value, value, len);
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
    cmdlang->location = "cmdlang.c(event_out_binary)";
}

static void
event_out_unicode(ipmi_cmdlang_t *cmdlang, const char *name,
		  const char *value, unsigned int len)
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

    entry->type = IPMI_CMDLANG_UNICODE;

    entry->len = len;
    if (len > 0) {
	entry->value = ipmi_mem_alloc(len);
	if (!entry->value) {
	    ipmi_mem_free(entry->name);
	    ipmi_mem_free(entry);
	    goto out_nomem;
	}
	memcpy(entry->value, value, len);
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
    cmdlang->location = "cmdlang.c(event_out_binary)";
}

void
event_up(ipmi_cmdlang_t *cmdlang)
{
    ipmi_cmdlang_event_t *event = cmdlang->user_data;

    if (cmdlang->err)
	return;

    event->curr_level--;
}

void
event_down(ipmi_cmdlang_t *cmdlang)
{
    ipmi_cmdlang_event_t *event = cmdlang->user_data;

    if (cmdlang->err)
	return;

    event->curr_level++;
}

void
event_done(ipmi_cmdlang_t *cmdlang)
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

ipmi_cmd_info_t *
ipmi_cmdlang_alloc_event_info(void)
{
    ipmi_cmd_info_t      *cmdinfo = NULL;
    ipmi_cmdlang_event_t *event;
    int                  rv;

    cmdinfo = ipmi_mem_alloc(sizeof(*cmdinfo));
    if (!cmdinfo)
	return NULL;
    memset(cmdinfo, 0, sizeof(*cmdinfo));
    cmdinfo->usecount = 1;

    rv = ipmi_create_lock_os_hnd(cmdlang_os_hnd, &cmdinfo->lock);
    if (rv) {
	ipmi_mem_free(cmdinfo);
	return NULL;
    }

    cmdinfo->cmdlang = ipmi_mem_alloc(sizeof(*cmdinfo->cmdlang));
    if (!cmdinfo->cmdlang) {
	ipmi_destroy_lock(cmdinfo->lock);
	ipmi_mem_free(cmdinfo);
	return NULL;
    }
    memset(cmdinfo->cmdlang, 0, sizeof(*cmdinfo->cmdlang));

    cmdinfo->cmdlang->objstr = ipmi_mem_alloc(IPMI_MAX_NAME_LEN);
    if (!cmdinfo->cmdlang->objstr) {
	ipmi_mem_free(cmdinfo->cmdlang);
	ipmi_destroy_lock(cmdinfo->lock);
	ipmi_mem_free(cmdinfo);
	return NULL;
    }
    cmdinfo->cmdlang->objstr[0] = '\0';
    cmdinfo->cmdlang->objstr_len = IPMI_MAX_NAME_LEN;

    cmdinfo->cmdlang->user_data	= ipmi_mem_alloc(sizeof(ipmi_cmdlang_event_t));
    if (!cmdinfo->cmdlang->user_data) {
	ipmi_mem_free(cmdinfo->cmdlang->objstr);
	ipmi_mem_free(cmdinfo->cmdlang);
	ipmi_destroy_lock(cmdinfo->lock);
	ipmi_mem_free(cmdinfo);
	return NULL;
    }

    event = cmdinfo->cmdlang->user_data;
    memset(event, 0, sizeof(*event));
    event->info = cmdinfo;

    cmdinfo->cmdlang->out = event_out;
    cmdinfo->cmdlang->down = event_down;
    cmdinfo->cmdlang->out_binary = event_out_binary;
    cmdinfo->cmdlang->out_unicode = event_out_unicode;
    cmdinfo->cmdlang->up = event_up;
    cmdinfo->cmdlang->done = event_done;

    return cmdinfo;
}

/* Move to the first field. */
void
ipmi_cmdlang_event_restart(ipmi_cmdlang_event_t *event)
{
    event->curr = event->head;
}

/* Returns true if successful, false if no more fields left. */
int
ipmi_cmdlang_event_next_field(ipmi_cmdlang_event_t        *event,
			      unsigned int                *level,
			      enum ipmi_cmdlang_out_types *type,
			      char                        **name,
			      unsigned int                *len,
			      char                        **value)
{
    ipmi_cmdlang_event_entry_t *curr = event->curr;

    if (!curr)
	return 0;

    if (level)
	*level = curr->level;
    if (name)
	*name = curr->name;
    if (value)
	*value = curr->value;
    if (type)
	*type = curr->type;
    if (len)
	*len = curr->len;

    event->curr = curr->next;
    return 1;
}

int
ipmi_cmdlang_get_argc(ipmi_cmd_info_t *info)
{
    return info->argc;
}

char **
ipmi_cmdlang_get_argv(ipmi_cmd_info_t *info)
{
    return info->argv;
}

int
ipmi_cmdlang_get_curr_arg(ipmi_cmd_info_t *info)
{
    return info->curr_arg;
}

ipmi_cmdlang_t *
ipmi_cmdinfo_get_cmdlang(ipmi_cmd_info_t *info)
{
    return info->cmdlang;
}

static void
evinfo(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int            argc = ipmi_cmdlang_get_argc(cmd_info);
    char           **argv = ipmi_cmdlang_get_argv(cmd_info);
    int            do_evinfo;

    if ((argc - curr_arg) < 1) {
	cmdlang->errstr = "True or False not entered";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_bool(argv[curr_arg], &do_evinfo, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "True or False not entered";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_set_evinfo(do_evinfo);
    ipmi_cmdlang_out(cmd_info, "event info set", NULL);
    return;

 out_err:
    cmdlang->location = "cmdlang.c(evinfo)";
}

static void
debug(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int            argc = ipmi_cmdlang_get_argc(cmd_info);
    char           **argv = ipmi_cmdlang_get_argv(cmd_info);
    char           *type;
    int            val;

    if ((argc - curr_arg) < 2) {
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    type = argv[curr_arg];
    curr_arg++;

    ipmi_cmdlang_get_bool(argv[curr_arg], &val, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "Invalid boolean setting";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    if (strcmp(type, "msg") == 0) {
	if (val) DEBUG_MSG_ENABLE(); else DEBUG_MSG_DISABLE();
    } else if (strcmp(type, "msgerr") == 0) {
	if (val) DEBUG_MSG_ERR_ENABLE(); else DEBUG_MSG_ERR_DISABLE();
    } else if (strcmp(type, "rawmsg") == 0) {
	if (val) DEBUG_RAWMSG_ENABLE(); else DEBUG_RAWMSG_DISABLE();
    } else if (strcmp(type, "locks") == 0) {
	if (val) DEBUG_LOCKS_ENABLE(); else DEBUG_LOCKS_DISABLE();
    } else if (strcmp(type, "events") == 0) {
	if (val) DEBUG_EVENTS_ENABLE(); else DEBUG_EVENTS_DISABLE();
    } else if (strcmp(type, "con0") == 0) {
	if (val) DEBUG_CON_FAIL_ENABLE(0); else DEBUG_CON_FAIL_DISABLE(0);
    } else if (strcmp(type, "con1") == 0) {
	if (val) DEBUG_CON_FAIL_ENABLE(1); else DEBUG_CON_FAIL_DISABLE(1);
    } else if (strcmp(type, "con2") == 0) {
	if (val) DEBUG_CON_FAIL_ENABLE(2); else DEBUG_CON_FAIL_DISABLE(2);
    } else if (strcmp(type, "con3") == 0) {
	if (val) DEBUG_CON_FAIL_ENABLE(3); else DEBUG_CON_FAIL_DISABLE(3);
    } else {
	cmdlang->errstr = "Invalid debug setting";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_out(cmd_info, "Debugging set", NULL);
    return;

 out_err:
    if (cmdlang->err)
	cmdlang->location = "cmdlang.c(debug)";
}

static ipmi_cmdlang_init_t cmds_global[] =
{
    { "evinfo", NULL,
      "true | false - Enable/disable printing info about the object"
      " when an event is reported on it (such as entity info, domain"
      " info, etc.)",
      evinfo, NULL, NULL },
    { "debug", NULL,
      "<type> true | false - "
      " Turn on/off the specific debugging.  The debugging types are:"
      " msg, rawmsg, events, con0, con1, con2, con3.  This is primarily"
      " for designers of OpenIPMI trying to debug problems.",
      debug, NULL, NULL },
};
#define CMDS_GLOBAL_LEN (sizeof(cmds_global)/sizeof(ipmi_cmdlang_init_t))

int ipmi_cmdlang_domain_init(os_handler_t *os_hnd);
int ipmi_cmdlang_con_init(os_handler_t *os_hnd);
int ipmi_cmdlang_entity_init(os_handler_t *os_hnd);
int ipmi_cmdlang_mc_init(os_handler_t *os_hnd);
int ipmi_cmdlang_pet_init(os_handler_t *os_hnd);
int ipmi_cmdlang_lanparm_init(os_handler_t *os_hnd);
int ipmi_cmdlang_solparm_init(os_handler_t *os_hnd);
int ipmi_cmdlang_fru_init(os_handler_t *os_hnd);
void ipmi_cmdlang_lanparm_shutdown();
void ipmi_cmdlang_solparm_shutdown();
int ipmi_cmdlang_pef_init(os_handler_t *os_hnd);
void ipmi_cmdlang_pef_shutdown();
int ipmi_cmdlang_sensor_init(os_handler_t *os_hnd);
int ipmi_cmdlang_control_init(os_handler_t *os_hnd);
int ipmi_cmdlang_sel_init(os_handler_t *os_hnd);

int
ipmi_cmdlang_init(os_handler_t *os_hnd)
{
    int rv;

    rv = ipmi_cmdlang_domain_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_con_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_entity_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_mc_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_pet_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_lanparm_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_solparm_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_fru_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_pef_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_sensor_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_control_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_sel_init(os_hnd);
    if (rv) return rv;

    rv = ipmi_cmdlang_reg_table(cmds_global, CMDS_GLOBAL_LEN);
    if (rv) return rv;

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
    ipmi_cmdlang_pef_shutdown();
    ipmi_cmdlang_lanparm_shutdown();
    ipmi_cmdlang_solparm_shutdown();
    cleanup_level(cmd_list);
}

static int do_evinfo = 0;

void
ipmi_cmdlang_set_evinfo(int evinfo)
{
    do_evinfo = evinfo;
}

int
ipmi_cmdlang_get_evinfo(void)
{
    return do_evinfo;
}
