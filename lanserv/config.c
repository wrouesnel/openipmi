/*
 * config.c
 *
 * MontaVista IPMI code for reading lanserv configuration files.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004,2005,2012 MontaVista Software Inc.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * Lesser General Public License (GPL) Version 2 or the modified BSD
 * license below.  The following disclamer applies to both licenses:
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
 * GNU Lesser General Public Licence
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Modified BSD Licence
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *   3. The name of the author may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 */

#include <config.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <dlfcn.h>

#include <OpenIPMI/serv.h>
#include <OpenIPMI/lanserv.h>
#include <OpenIPMI/serserv.h>
#include <OpenIPMI/persist.h>

void
read_persist_users(sys_data_t *sys)
{
    unsigned int i, j;

    for (i = 0; i < IPMI_MAX_MCS; i++) {
	lmc_data_t *mc = sys->ipmb_addrs[i];
	user_t *users;
	persist_t *p;
	long iv;

	if (!mc)
	    continue;

	p = read_persist("users.mc%2.2x", ipmi_mc_get_ipmb(mc));
	if (!p)
	    continue;

	users = ipmi_mc_get_users(mc);
	for (j = 0; j <= MAX_USERS; j++) {
	    void *data;
	    unsigned int len;

	    if (!read_persist_int(p, &iv, "%d.valid", j))
		users[j].valid = iv;
	    if (!read_persist_int(p, &iv, "%d.link_auth", j))
		users[j].link_auth = iv;
	    if (!read_persist_int(p, &iv, "%d.cb_only", j))
		users[j].cb_only = iv;
	    if (!read_persist_data(p, &data, &len, "%d.username", j)) {
		if (len == sizeof(users[j].username))
		    memcpy(users[j].username, data, len);
		free_persist_data(data);
	    }
	    if (!read_persist_data(p, &data, &len, "%d.passwd", j)) {
		if (len == sizeof(users[j].pw))
		    memcpy(users[j].pw, data, len);
		free_persist_data(data);
	    }
	    if (!read_persist_int(p, &iv, "%d.privilege", j))
		users[j].privilege = iv;
	    if (!read_persist_int(p, &iv, "%d.max_sessions", j))
		users[j].max_sessions = iv;
	    if (!read_persist_int(p, &iv, "%d.allowed_auths", j))
		users[j].allowed_auths = iv;
	}
	free_persist(p);
    }
}

int
write_persist_users(sys_data_t *sys)
{
    unsigned int i, j;

    for (i = 0; i < IPMI_MAX_MCS; i++) {
	lmc_data_t *mc = sys->ipmb_addrs[i];
	user_t *users;
	persist_t *p;

	if (!mc || !ipmi_mc_users_changed(mc))
	    continue;

	p = alloc_persist("users.mc%2.2x", ipmi_mc_get_ipmb(mc));
	if (!p)
	    return ENOMEM;

	users = ipmi_mc_get_users(mc);
	for (j = 0; j <= MAX_USERS; j++) {
	    add_persist_int(p, users[j].valid, "%d.valid", j);
	    add_persist_int(p, users[j].link_auth, "%d.link_auth", j);
	    add_persist_int(p, users[j].cb_only, "%d.cb_only", j);
	    add_persist_data(p, users[j].username, sizeof(users[j].username),
			     "%d.username", j);
	    add_persist_data(p, users[j].pw, sizeof(users[j].pw),
			     "%d.passwd", j);
	    add_persist_int(p, users[j].privilege, "%d.privilege", j);
	    add_persist_int(p, users[j].max_sessions, "%d.max_sessions", j);
	    add_persist_int(p, users[j].allowed_auths, "%d.allowed_auths", j);
	}
	write_persist(p);
	free_persist(p);
    }
    return 0;
}

struct variable {
    char *name;
    char *value;
    struct variable *next;
} *vars;

int
add_variable(const char *name, const char *value)
{
    struct variable *var = vars, *last = NULL;

    while (var) {
	if (strcmp(name, var->name) == 0)
	    break;
	last = var;
	var = var->next;
    }
    if (var) {
	free(var->value);
    } else {
	var = malloc(sizeof(*var));
	if (!var)
	    return ENOMEM;
	var->name = strdup(name);
	if (!var->name)
	    return ENOMEM;
	var->next = NULL;
	if (last)
	    last->next = var;
	else
	    vars = var;
    }
    
    var->value = strdup(value);
    if (!var->value)
	return ENOMEM;

    return 0;
}

const char
*find_variable(const char *name)
{
    struct variable *var = vars;
    while (var) {
	if (strcmp(name, var->name) == 0)
	    break;
	var = var->next;
    }
    if (!var)
	return NULL;
    return var->value;
}

/*
 * To parse more complex expressions, we really need to know what the
 * save state is.  So we, unfortunately, have to create our own
 * version of strtok so we know what it is.
 */
const char *
mystrtok(char *str, const char *delim, char **next)
{
    char *pos;
    char *curr;

    if (str)
	curr = str;
    else
	curr = *next;

    /* Skip initial delimiters. */
    for (;;) {
	const char *c = delim;
	if (*curr == '\0') {
	    *next = curr;
	    return NULL;
	}

	while (*c != '\0') {
	    if (*c == *curr)
		break;
	    c++;
	}
	if (*c == '\0')
	    break;
	curr++;
    }

    pos = curr;
    /* Now collect until there is a delimiter. */
    for (;;) {
	const char *c = delim;
	if (*curr == '\0') {
	    *next = curr;
	    goto out;
	}
	while (*c != '\0') {
	    if (*c == *curr) {
		*curr = '\0';
		*next = curr + 1;
		goto out;
	    }
	    c++;
	}
	curr++;
    }
 out:
    if (*pos == '$')
	return find_variable(pos + 1);
    else
	return pos;
}

int
isquote(char c)
{
    return c == '\'' || c == '"';
}

int
get_delim_str(char **rtokptr, const char **rval, const char **err)
{
    char *tokptr = *rtokptr;
    char endc;
    char *rv = NULL;

    while (isspace(*tokptr))
	tokptr++;
    if (*tokptr == '\0') {
	*err = "missing string value";
	return -1;
    }
    for (;;) {
	const char *val;

	if (*tokptr == '$') {
	    char oldc;

	    tokptr++;
	    val = tokptr;
	    while (*tokptr && *tokptr != '$' &&
		   !isspace(*tokptr) && !isquote(*tokptr)) {
		tokptr++;
	    }
	    oldc = *tokptr;
	    *tokptr = '\0';
	    val = find_variable(val);
	    if (!val)
		return -1;
	    *tokptr = oldc;
	} else if (isquote(*tokptr)) {
	    endc = *tokptr;
	    tokptr++;
	    val = tokptr;
	    while (*tokptr != endc) {
		if (*tokptr == '\0') {
		    *err = "End of line in string";
		    return -1;
		}
		tokptr++;
	    }
	    *tokptr = '\0';
	    tokptr++;
	} else {
	    *err = "string value must start with '\"' or '''";
	    return -1;
	}

	if (rv) {
	    char *newrv = malloc(strlen(rv) + strlen(val) + 1);
	    if (!newrv) {
		*err = "Out of memory copying string";
		return -1;
	    }
	    strcpy(newrv, rv);
	    strcat(newrv, val);
	    free(rv);
	    rv = newrv;
	} else {
	    rv = strdup(val);
	    if (!rv) {
		*err = "Out of memory copying string";
		return -1;
	    }
	}

	if (*tokptr == '\0' || isspace(*tokptr))
	    break;
    }
    *rtokptr = tokptr;
    *rval = rv;
    return 0;
}

int
get_bool(char **tokptr, unsigned int *rval, const char **err)
{
    const char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No boolean value given";
	return -1;
    }
    if (strcasecmp(tok, "true") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "false") == 0)
	*rval = 0;
    else if (strcasecmp(tok, "on") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "off") == 0)
	*rval = 0;
    else if (strcasecmp(tok, "yes") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "no") == 0)
	*rval = 0;
    else if (strcasecmp(tok, "1") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "0") == 0)
	*rval = 0;
    else {
	*err = "Invalid boolean value, must be 'true', 'on', 'false', or 'off'";
	return -1;
    }

    return 0;
}

int
get_uint(char **tokptr, unsigned int *rval, const char **err)
{
    char *end;
    const char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No integer value given";
	return -1;
    }

    *rval = strtoul(tok, &end, 0);
    if (*end != '\0') {
	*err = "Invalid integer value";
	return -1;
    }
    return 0;
}

int
get_int(char **tokptr, int *rval, const char **err)
{
    char *end;
    const char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No integer value given";
	return -1;
    }

    *rval = strtol(tok, &end, 0);
    if (*end != '\0') {
	*err = "Invalid integer value";
	return -1;
    }
    return 0;
}

int
get_uchar(char **tokptr, unsigned char *rval, const char **err)
{
    char *end;
    const char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No integer value given";
	return -1;
    }

    *rval = strtoul(tok, &end, 0);
    if (*end != '\0') {
	*err = "Invalid integer value";
	return -1;
    }
    return 0;
}

int
get_priv(char **tokptr, unsigned int *rval, const char **err)
{
    const char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No privilege specified, must be 'callback', 'user',"
	    " 'operator', or 'admin'";
	return -1;
    }
    if (strcmp(tok, "callback") == 0)
	*rval = IPMI_PRIVILEGE_CALLBACK;
    else if (strcmp(tok, "user") == 0)
	*rval = IPMI_PRIVILEGE_USER;
    else if (strcmp(tok, "operator") == 0)
	*rval = IPMI_PRIVILEGE_OPERATOR;
    else if (strcmp(tok, "admin") == 0)
	*rval = IPMI_PRIVILEGE_ADMIN;
    else {
	*err = "Invalid privilege specified, must be 'callback', 'user',"
	    " 'operator', or 'admin'";
	return -1;
    }

    return 0;
}

int
get_auths(char **tokptr, unsigned int *rval, const char **err)
{
    const char *tok = mystrtok(NULL, " \t\n", tokptr);
    int  val = 0;

    while (tok) {
	if (strcmp(tok, "none") == 0)
	    val |= (1 << IPMI_AUTHTYPE_NONE);
	else if (strcmp(tok, "md2") == 0)
	    val |= (1 << IPMI_AUTHTYPE_MD2);
	else if (strcmp(tok, "md5") == 0)
	    val |= (1 << IPMI_AUTHTYPE_MD5);
	else if (strcmp(tok, "straight") == 0)
	    val |= (1 << IPMI_AUTHTYPE_STRAIGHT);
	else {
	    *err = "Invalid authorization type, must be 'none', 'md2',"
		" 'md5', or 'straight'";
	    return -1;
	}

	tok = mystrtok(NULL, " \t\n", tokptr);
    }

    *rval = val;

    return 0;
}

int
read_bytes(char **tokptr, unsigned char *data, const char **err,
	   unsigned int len)
{
    const char *tok = mystrtok(NULL, " \t\n", tokptr);
    char *end;

    if (!tok) {
	*err = "Missing password or username";
	return -1;
    }
    if (*tok == '"') {
	unsigned int end;
	/* Ascii PW */
	tok++;
	end = strlen(tok) - 1;
	if (tok[end] != '"') {
	    *err = "ASCII password or username doesn't end in '\"'";
	    return -1;
	}
	if (end > (len - 1))
	    end = len - 1;
	memcpy(data, tok, end);
	data[end] = '\0';
	zero_extend_ascii(data, len);
    } else {
	unsigned int i;
	char         c[3];
	/* HEX pw */
	if (strlen(tok) != 32) {
	    *err = "HEX password or username not 32 HEX characters long";
	    return -1;
	}
	c[2] = '\0';
	for (i=0; i<len; i++) {
	    c[0] = *tok;
	    tok++;
	    c[1] = *tok;
	    tok++;
	    data[i] = strtoul(c, &end, 16);
	    if (*end != '\0') {
		*err = "Invalid HEX character in password or username";
		return -1;
	    }
	}
    }

    return 0;
}

int
get_sock_addr(char **tokptr, sockaddr_ip_t *addr, socklen_t *len,
	      char *def_port, int socktype, const char **err)
{
    const char *s, *p;

    s = mystrtok(NULL, " \t\n", tokptr);
    if (!s) {
	*err = "No IP address specified";
	return -1;
    }
    p = mystrtok(NULL, " \t\n", tokptr);

#ifdef HAVE_GETADDRINFO
    {
	struct addrinfo     hints, *res0;
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = socktype;
	hints.ai_flags = AI_PASSIVE;
	if (!p)
	    p = def_port;
	if (!p) {
	    *err = "No port specified";
	    return -1;
	}
	rv = getaddrinfo(s, p, &hints, &res0);
	if (rv) {
	    *err = "getaddrinfo err";
	    return -1;
	}
	memcpy(addr, res0->ai_addr, res0->ai_addrlen);
	*len = res0->ai_addrlen;
	freeaddrinfo(res0);
    }
#else
    /* System does not support getaddrinfo, just for IPv4*/
    {
	struct hostent     *ent;
	struct sockaddr_in *paddr;
        char               *end;

	ent = gethostbyname(s);
	if (!ent) {
	    *err = "Invalid IP address specified";
	    return -1;
	}

	paddr = (struct sockaddr_in *)addr;
	paddr->sin_family = AF_INET;
	if (p) {
	    paddr->sin_port = htons(strtoul(p, &end, 0));
	    if (*end != '\0') {
	        *err = "Invalid IP port specified";
	        return -1;
	    }
	} else {
	    paddr->sin_port = htons(623);
	}
	*len = sizeof(struct sockaddr_in);
    }
#endif
    return 0;
}

static int
get_user(char **tokptr, sys_data_t *sys, const char **err)
{
    unsigned int num;
    unsigned int val;
    int          rv;

    rv = get_uint(tokptr, &num, err);
    if (rv)
	return rv;

    if (num > MAX_USERS) {
	*err = "User number larger than the allowed number of users";
	return -1;
    }

    rv = get_bool(tokptr, &val, err);
    if (rv)
	return rv;
    sys->cusers[num].valid = val;

    rv = read_bytes(tokptr, sys->cusers[num].username, err, 16);
    if (rv)
	return rv;

    rv = read_bytes(tokptr, sys->cusers[num].pw, err, 20);
    if (rv)
	return rv;

    rv = get_priv(tokptr, &val, err);
    if (rv)
	return rv;
    sys->cusers[num].privilege = val;

    rv = get_uint(tokptr, &val, err);
    if (rv)
	return rv;
    sys->cusers[num].max_sessions = val;

    rv = get_auths(tokptr, &val, err);
    if (rv)
	return rv;
    sys->cusers[num].allowed_auths = val;

    return 0;
}

struct dliblist {
    const char *file;
    const char *init;
    void *handle;
    struct dliblist *next;
};

static struct dliblist *dlibs;

int
load_dynamic_libs(sys_data_t *sys, int print_version)
{
    struct dliblist *dlib = dlibs;
    int (*func)(sys_data_t *sys, const char *initstr);
    void *handle;
    int err;

    while (dlib) {
	handle = dlopen(dlib->file, RTLD_NOW | RTLD_GLOBAL);
	if (!handle) {
	    fprintf(stderr, "Unable to load dynamic library %s: %s\n",
		    dlib->file, dlerror());
	    return EINVAL;
	}

	if (print_version) {
	    func = dlsym(handle, "ipmi_sim_module_print_version");
	    if (func) {
		err = func(sys, dlib->init);
		if (err) {
		    fprintf(stderr, "Error from module %s version print: %s\n",
			    dlib->file, strerror(err));
		    return EINVAL;
		}
	    }
	    dlclose(handle);
	} else {
	    func = dlsym(handle, "ipmi_sim_module_init");
	    if (func) {
		err = func(sys, dlib->init);
		if (err) {
		    fprintf(stderr, "Error from module %s init: %s\n",
			    dlib->file, strerror(err));
		    return EINVAL;
		}
	    }
	    dlib->handle = handle;
	}
	dlib = dlib->next;
    }

    return 0;
}

void
post_init_dynamic_libs(sys_data_t *sys)
{
    struct dliblist *dlib = dlibs;
    void (*func)(sys_data_t *sys);

    while (dlib) {
	func = dlsym(dlib->handle, "ipmi_sim_module_post_init");
	if (func)
	    func(sys);
	dlib = dlib->next;
    }
}

int
read_config(sys_data_t *sys,
	    char       *config_file,
	    int        print_version)
{
    FILE         *f = fopen(config_file, "r");
    int          line;
    unsigned int val;
    char         buf[MAX_CONFIG_LINE];
    const char   *tok;
    char         *tokptr;
    int          err = 0;
    const char   *errstr;

    if (!f) {
	fprintf(stderr, "Unable to open configuration file '%s'\n",
		config_file);
	return -1;
    }

    line = 0;
    while (fgets(buf, sizeof(buf), f) != NULL) {
	line++;

	tok = mystrtok(buf, " \t\n", &tokptr);
	if (!tok || (tok[0] == '#'))
	    continue;

	if (strcmp(tok, "define") == 0) {
	    const char *varname, *value;

	    varname = mystrtok(NULL, " \t\n", &tokptr);
	    if (!varname) {
		err = EINVAL;
		errstr = "No variable supplied for define";
		goto next;
	    }
	    err = get_delim_str(&tokptr, &value, &errstr);
	    if (err)
		goto next;
	    err = add_variable(varname, value);
	    if (err) {
		err = ENOMEM;
		errstr = "Out of memory";
		goto next;
	    }
	} else if (strcmp(tok, "loadlib") == 0) {
	    const char *library = NULL, *initstr = NULL;
	    struct dliblist *dlib, *dlibp;

	    err = get_delim_str(&tokptr, &library, &errstr);
	    if (!err)
		err = get_delim_str(&tokptr, &initstr, &errstr);
	    if (!err) {
		dlib = malloc(sizeof(*dlib));
		if (!dlib) {
		    err = ENOMEM;
		    errstr = "Out of memory";
		} else {
		    dlib->file = library;
		    dlib->init = initstr;
		    dlib->next = NULL;
		    if (!dlibs) {
			dlibs = dlib;
		    } else {
			dlibp = dlibs;
			while (dlibp->next)
			    dlibp = dlibp->next;
			dlibp->next = dlib;
		    }
		}
	    }
	    if (err) {
		if (library)
		    free((char *) library);
		if (initstr)
		    free((char *) initstr);
	    }
	    goto next;
	}

	if (print_version)
	    goto next;

	if (strcmp(tok, "startlan") == 0) {
	    err = get_uint(&tokptr, &val, &errstr);
	    if (!err && (val >= IPMI_MAX_CHANNELS)) {
		err = -1;
		errstr = "Channel number out of range";
	    }
	    if (!err) {
		err = lanserv_read_config(sys, f, &line, val);
	    }
	} else if (strcmp(tok, "user") == 0) {
	    err = get_user(&tokptr, sys, &errstr);
	} else if (strcmp(tok, "serial") == 0) {
	    err = serserv_read_config(&tokptr, sys, &errstr);
	} else if (strcmp(tok, "sol") == 0) {
	    err = sol_read_config(&tokptr, sys, &errstr);
	} else if (strcmp(tok, "chassis_control") == 0) {
	    const char *prog;
	    err = get_delim_str(&tokptr, &prog, &errstr);
	    if (!err)
		ipmi_set_chassis_control_prog(sys->mc, prog);
	} else if (strcmp(tok, "name") == 0) {
	    err = get_delim_str(&tokptr, &sys->name, &errstr);
	} else if (strcmp(tok, "startcmd") == 0) {
	    if (sys->startcmd)
		err = get_delim_str(&tokptr, &sys->startcmd->startcmd, &errstr);
	} else if (strcmp(tok, "startnow") == 0) {
	    if (sys->startcmd)
		err = get_bool(&tokptr, &sys->startcmd->startnow, &errstr);
	} else if (strcmp(tok, "poweroff_wait") == 0) {
	    if (sys->startcmd)
		err = get_uint(&tokptr, &sys->startcmd->poweroff_wait_time,
			   &errstr);
	} else if (strcmp(tok, "kill_wait") == 0) {
	    if (sys->startcmd)
		err = get_uint(&tokptr, &sys->startcmd->kill_wait_time, &errstr);
	} else if (strcmp(tok, "set_working_mc") == 0) {
	    unsigned char ipmb;
	    err = get_uchar(&tokptr, &ipmb, &errstr);
	    if (!err) {
		lmc_data_t *mc;
		err = ipmi_mc_alloc_unconfigured(sys, ipmb, &mc);
		if (err == ENOMEM) {
		    errstr = "Out of memory";
		    err = -1;
		} else if (err) {
		    errstr = "Invalid IPMB specified";
		    err = -1;
		} else {
		    sys->mc = mc;
		    sys->cusers = ipmi_mc_get_users(mc);
		    sys->chan_set = ipmi_mc_get_channelset(mc);
		    sys->cpef = ipmi_mc_get_pef(mc);
		    sys->startcmd = ipmi_mc_get_startcmdinfo(mc);
		    sys->sol = ipmi_mc_get_sol(mc);
		}
	    }
	} else if (strcmp(tok, "console") == 0) {
	    err = get_sock_addr(&tokptr,
				&sys->console_addr, &sys->console_addr_len,
				NULL, SOCK_STREAM, &errstr);
	} else {
	    errstr = "Invalid configuration option";
	    err = -1;
	}

      next:
	if (err) {
	    fprintf(stderr, "Error on line %d: %s\n", line, errstr);
	    break;
	}
    }

    fclose(f);

    if (print_version)
	load_dynamic_libs(sys, print_version);

    return err;
}
