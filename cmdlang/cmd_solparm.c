/*
 * cmd_solparm.c
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
#include <OpenIPMI/ipmi_solparm.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_mc.h>

/* Internal includes, do not use in your programs */
#include <OpenIPMI/internal/ipmi_malloc.h>
#include <OpenIPMI/internal/locked_list.h>

static locked_list_t *solcs;

static void
solparm_list_handler(ipmi_solparm_t *solparm, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            solparm_name[IPMI_SOLPARM_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_solparm_get_name(solparm, solparm_name, sizeof(solparm_name));

    ipmi_cmdlang_out(cmd_info, "Name", solparm_name);
}

static void
solparm_list(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char             domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "Domain", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
    ipmi_cmdlang_out(cmd_info, "SOLPARMs", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_solparm_iterate_solparms(domain, solparm_list_handler, cmd_info);
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static void
get_mc_name(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
}

static void
solparm_info(ipmi_solparm_t *solparm, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    int             rv;
    char            solparm_name[IPMI_SOLPARM_NAME_LEN];

    ipmi_solparm_get_name(solparm, solparm_name, sizeof(solparm_name));

    ipmi_cmdlang_out(cmd_info, "SOLPARM", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", solparm_name);
    rv = ipmi_mc_pointer_cb(ipmi_solparm_get_mc_id(solparm), get_mc_name,
			    cmd_info);
    if (rv) {
	ipmi_cmdlang_out_int(cmd_info, "Error getting MC", rv);
    }
    ipmi_cmdlang_out_int(cmd_info, "Channel",
			 ipmi_solparm_get_channel(solparm));
    ipmi_cmdlang_up(cmd_info);
}

static void
solparm_new(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             channel;
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_solparm_t  *solparm;
    char            solparm_name[IPMI_SOLPARM_NAME_LEN];

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &channel, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "channel invalid";
	goto out_err;
    }
    curr_arg++;

    rv = ipmi_solparm_alloc(mc, channel, &solparm);
    if (rv) {
	cmdlang->errstr = "Error from ipmi_solparm_alloc";
	cmdlang->err = rv;
	goto out_err;
    }

    ipmi_solparm_get_name(solparm, solparm_name, sizeof(solparm_name));
    ipmi_cmdlang_out(cmd_info, "SOLPARM", solparm_name);

    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_solparm.c(solparm_new)";
}

typedef struct solparm_info_s
{
    char            name[IPMI_SOLPARM_NAME_LEN];
    ipmi_cmd_info_t *cmd_info;
} solparm_info_t;

static void
solparm_close_done(ipmi_solparm_t *solparm, int err, void *cb_data)
{
    solparm_info_t  *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	ipmi_solparm_get_name(solparm, cmdlang->objstr,
			  cmdlang->objstr_len);
	cmdlang->errstr = "Error closing SOLPARM";
	cmdlang->err = err;
	cmdlang->location = "cmd_solparm.c(solparm_close_done)";
	goto out;
    }

    ipmi_cmdlang_out(cmd_info, "SOLPARM destroyed", info->name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static void
solparm_close(ipmi_solparm_t *solparm, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;
    solparm_info_t  *info;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	goto out_err;
    }
    info->cmd_info = cmd_info;
    ipmi_solparm_get_name(solparm, info->name, sizeof(info->name));

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_solparm_destroy(solparm, solparm_close_done, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	ipmi_solparm_get_name(solparm, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->errstr = "Error closing SOLPARM";
	cmdlang->err = rv;
	ipmi_mem_free(info);
    }
    return;

 out_err:
    cmdlang->location = "cmd_solparm.c(solparm_close)";
}

#define SOL_CONFIG_NAME_LEN 80
typedef struct sol_config_info_s
{
    char              name[SOL_CONFIG_NAME_LEN];
    ipmi_sol_config_t *config;
} sol_config_info_t;

static unsigned int unique_num = 0;

typedef struct find_config_s
{
    char              *name;
    ipmi_sol_config_t *config;
    int               delete;
} find_config_t;

static int
find_config_handler(void *cb_data, void *item1, void *item2)
{
    sol_config_info_t *info = item1;
    find_config_t     *find = cb_data;

    if (strcmp(find->name, info->name) == 0) {
	find->config = info->config;
	if (find->delete) {
	    locked_list_remove(solcs, item1, item2);
	    ipmi_mem_free(info);
	}
	return LOCKED_LIST_ITER_STOP;
    }

    return LOCKED_LIST_ITER_CONTINUE;
}

static ipmi_sol_config_t *
find_config(char *name, int delete)
{
    find_config_t find;

    find.name = name;
    find.config = NULL;
    find.delete = delete;
    locked_list_iterate(solcs, find_config_handler, &find);
    return find.config;
}

typedef void (*lp_set)(ipmi_cmd_info_t *cmd_info, char *val,
		       ipmi_sol_config_t *solc, void *func);
typedef void (*lp_out)(ipmi_cmd_info_t *cmd_info, char *name,
		       ipmi_sol_config_t *solc, void *func);
typedef struct lp_item_s
{
    lp_set set;
    lp_out out;
} lp_item_t;

static void
set_retint(ipmi_cmd_info_t *cmd_info, char *val,
	   ipmi_sol_config_t *solc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_sol_config_t *l, unsigned int v) = func;
    int            v;

    ipmi_cmdlang_get_int(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(solc, v);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
static void
out_retint(ipmi_cmd_info_t *cmd_info, char *name,
	   ipmi_sol_config_t *solc, void *func)
{
    unsigned int   (*f)(ipmi_sol_config_t *l) = func;
    ipmi_cmdlang_out_int(cmd_info, name, f(solc));
}
static lp_item_t lp_retint = {set_retint, out_retint};

static void
set_retbool(ipmi_cmd_info_t *cmd_info, char *val,
	    ipmi_sol_config_t *solc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_sol_config_t *l, unsigned int v) = func;
    int            v;

    ipmi_cmdlang_get_bool(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(solc, v);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
static void
out_retbool(ipmi_cmd_info_t *cmd_info, char *name,
	    ipmi_sol_config_t *solc, void *func)
{
    unsigned int   (*f)(ipmi_sol_config_t *l) = func;
    ipmi_cmdlang_out_bool(cmd_info, name, f(solc));
}
static lp_item_t lp_retbool = {set_retbool, out_retbool};

static void
set_int(ipmi_cmd_info_t *cmd_info, char *val,
	ipmi_sol_config_t *solc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_sol_config_t *l, unsigned int v) = func;
    int            v;

    ipmi_cmdlang_get_int(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(solc, v);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
static void
out_int(ipmi_cmd_info_t *cmd_info, char *name,
	ipmi_sol_config_t *solc, void *func)
{
    unsigned int   v;
    int            rv;
    int            (*f)(ipmi_sol_config_t *l, unsigned int *v) = func;
    
    rv = f(solc, &v);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, name, v);
}
static lp_item_t lp_int = {set_int, out_int};

static struct lps_s
{
    char      *name;
    lp_item_t *lpi;
    void      *get_func;
    void      *set_func;
} lps[] =
/* read-only */
#define FR(name, type) { #name, &lp_ ## type, ipmi_solconfig_get_ ## name, \
		         NULL }
/* Writable */
#define F(name, type) { #name, &lp_ ## type, ipmi_solconfig_get_ ## name, \
		        ipmi_solconfig_set_ ## name }
{
    F(enable, retbool),
    F(force_payload_encryption, retbool),
    F(force_payload_authentication, retbool),
    F(privilege_level, retint),
    F(char_accumulation_interval, retint),
    F(char_send_threshold, retint),
    F(retry_count, retint),
    F(retry_interval, retint),
    F(port_number, retint),
    FR(payload_channel, int),
    { NULL }
};

static void
config_info(ipmi_cmd_info_t *cmd_info, ipmi_sol_config_t *config)
{
    int i;

    /* Basic items */
    for (i=0; lps[i].name; i++) {
	lp_item_t *lp = lps[i].lpi;
	lp->out(cmd_info, lps[i].name, config, lps[i].get_func);
    }
}

static void
solparm_config_get_done(ipmi_solparm_t    *solparm,
			int               err,
			ipmi_sol_config_t *config,
			void              *cb_data)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char              solparm_name[IPMI_SOLPARM_NAME_LEN];
    sol_config_info_t *info;

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error getting SOLPARM";
	cmdlang->err = err;
	goto out;
    }

    ipmi_solparm_get_name(solparm, solparm_name, sizeof(solparm_name));

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	ipmi_sol_free_config(config);
	goto out;
    }
    snprintf(info->name, sizeof(info->name), "%s.%u",
	     solparm_name, unique_num);
    info->config = config;
    if (!locked_list_add(solcs, info, NULL)) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	ipmi_sol_free_config(config);
	ipmi_mem_free(info);
	goto out;
    }
    unique_num++;

    ipmi_cmdlang_out(cmd_info, "SOLPARM Config", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", info->name);
    config_info(cmd_info, config);
    ipmi_cmdlang_up(cmd_info);

 out:
    if (cmdlang->err) {
	ipmi_solparm_get_name(solparm, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->location = "cmd_solparm.c(solparm_config_get_done)";
    }
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
solparm_config_get(ipmi_solparm_t *solparm, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_sol_get_config(solparm, solparm_config_get_done, cmd_info);
    if (rv) {
	ipmi_solparm_get_name(solparm, cmdlang->objstr,
			      cmdlang->objstr_len);
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error getting SOLPARM";
	cmdlang->err = rv;
	cmdlang->location = "cmd_solparm.c(solparm_config_get)";
    }
}

typedef struct lp_config_op_s
{
    char            name[SOL_CONFIG_NAME_LEN];
    ipmi_cmd_info_t *cmd_info;
} lp_config_op_t;

static void
solparm_config_set_done(ipmi_solparm_t    *solparm,
			int               err,
			void              *cb_data)
{
    lp_config_op_t  *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	ipmi_solparm_get_name(solparm, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->errstr = "Error setting SOLPARM";
	cmdlang->err = err;
	cmdlang->location = "cmd_solparm.c(solparm_config_set_done)";
	goto out;
    }

    ipmi_cmdlang_out(cmd_info, "SOLPARM config set", info->name);

 out:
    ipmi_mem_free(info);
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
solparm_config_set(ipmi_solparm_t *solparm, void *cb_data)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               rv;
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_sol_config_t *solc;
    lp_config_op_t    *info = cb_data;
    char              *name;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    name = argv[curr_arg];
    curr_arg++;
    
    solc = find_config(name, 0);
    if (!solc) {
	cmdlang->errstr = "Invalid SOL config";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	goto out_err;
    }
    info->cmd_info = cmd_info;
    strncpy(info->name, name, sizeof(info->name));

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_sol_set_config(solparm, solc, solparm_config_set_done, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error setting SOLPARM";
	cmdlang->err = rv;
	ipmi_mem_free(info);
	goto out_err;
    }

    return;

 out_err:
    ipmi_solparm_get_name(solparm, cmdlang->objstr,
			  cmdlang->objstr_len);
    cmdlang->location = "cmd_solparm.c(solparm_config_set)";
}

static void
solparm_config_unlock_done(ipmi_solparm_t    *solparm,
			   int               err,
			   void              *cb_data)
{
    lp_config_op_t  *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	ipmi_solparm_get_name(solparm, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->errstr = "Error unlocking SOLPARM";
	cmdlang->err = err;
	cmdlang->location = "cmd_solparm.c(solparm_config_unlock_done)";
	goto out;
    }

    ipmi_cmdlang_out(cmd_info, "SOLPARM config unlocked", info->name);

 out:
    ipmi_mem_free(info);
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
solparm_config_unlock(ipmi_solparm_t *solparm, void *cb_data)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               rv;
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_sol_config_t *solc;
    lp_config_op_t    *info = cb_data;
    char              *name;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    name = argv[curr_arg];
    curr_arg++;
    solc = find_config(name, 0);
    if (!solc) {
	cmdlang->errstr = "Invalid SOL config";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	goto out_err;
    }
    info->cmd_info = cmd_info;
    strncpy(info->name, name, sizeof(info->name));

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_sol_clear_lock(solparm, solc, solparm_config_unlock_done, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error getting SOLPARM";
	cmdlang->err = rv;
	ipmi_mem_free(info);
	goto out_err;
    }

    return;

 out_err:
    ipmi_solparm_get_name(solparm, cmdlang->objstr,
			  cmdlang->objstr_len);
    cmdlang->location = "cmd_solparm.c(solparm_config_unlock)";
}

static void
solparm_config_close(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_sol_config_t *solc;
    char              *solc_name;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	solc_name = "";
	goto out_err;
    }
    solc_name = argv[curr_arg];

    solc = find_config(solc_name, 1);
    if (!solc) {
	cmdlang->errstr = "Invalid SOL config";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_sol_free_config(solc);
    ipmi_cmdlang_out(cmd_info, "SOLPARM config destroyed", solc_name);
    return;

 out_err:
    strncpy(cmdlang->objstr, solc_name, cmdlang->objstr_len);
    cmdlang->location = "cmd_solparm.c(solparm_config_close)";
}

static int
solparm_config_list_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    sol_config_info_t *info = item1;

    ipmi_cmdlang_out(cmd_info, "Name", info->name);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
solparm_config_list(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_out(cmd_info, "SOLPARM Configs", NULL);
    ipmi_cmdlang_down(cmd_info);
    locked_list_iterate(solcs, solparm_config_list_handler, cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static int
solparm_config_info_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    sol_config_info_t *info = item1;

    ipmi_cmdlang_out(cmd_info, "SOLPARM Config", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", info->name);
    config_info(cmd_info, info->config);
    ipmi_cmdlang_up(cmd_info);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
solparm_config_info(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_sol_config_t *solc;

    if ((argc - curr_arg) < 1) {
	locked_list_iterate(solcs, solparm_config_info_handler, cmd_info);
    } else {
	solc = find_config(argv[curr_arg], 0);
	if (!solc) {
	    cmdlang->errstr = "Invalid SOL config";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
	ipmi_cmdlang_out(cmd_info, "SOLPARM Config", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Name", argv[curr_arg]);
	config_info(cmd_info, solc);
	ipmi_cmdlang_up(cmd_info);
    }
    return;

 out_err:
    strncpy(cmdlang->objstr, argv[curr_arg], cmdlang->objstr_len);
    cmdlang->location = "cmd_solparm.c(solparm_config_info)";
}

static void
solparm_config_update(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_sol_config_t *solc;
    int               i;
    char              *name;
    char              *val;
    char              *solc_name;

    if ((argc - curr_arg) < 3) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	solc_name = "";
	goto out_err;
    }
    solc_name = argv[curr_arg];
    curr_arg++;

    solc = find_config(solc_name, 0);
    if (!solc) {
	cmdlang->errstr = "Invalid SOL config";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    name = argv[curr_arg];
    curr_arg++;
    val = argv[curr_arg];
    curr_arg++;

    /* Basic items */
    for (i=0; lps[i].name; i++) {
	if (strcmp(lps[i].name, name) == 0) {
	    lp_item_t *lp = lps[i].lpi;
	    if (!lp->set) {
		cmdlang->errstr = "Parameter is read-only";
		cmdlang->err = EINVAL;
		goto out_err;
	    }
	    lp->set(cmd_info, val, solc, lps[i].set_func);
	    goto out;
	}
    }

    cmdlang->errstr = "Invalid parameter name";
    cmdlang->err = EINVAL;
    goto out_err;

 out:
    ipmi_cmdlang_out(cmd_info, "SOLPARM config updated", solc_name);
    return;

 out_err:
    strncpy(cmdlang->objstr, solc_name, cmdlang->objstr_len);
    cmdlang->location = "cmd_solparm.c(solparm_config_update)";
}

typedef struct solparm_mc_unlock_s
{
    char            name[IPMI_MC_NAME_LEN];
    ipmi_cmd_info_t *cmd_info;
} solparm_mc_unlock_t;

static void
solparm_unlock_mc_done(ipmi_solparm_t *solparm, int err, void *cb_data)
{
    solparm_mc_unlock_t *info = cb_data;
    ipmi_cmd_info_t     *cmd_info = info->cmd_info;
    ipmi_cmdlang_t      *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	ipmi_solparm_get_name(solparm, cmdlang->objstr,
			  cmdlang->objstr_len);
	cmdlang->errstr = "Error unlocking MC SOLPARM";
	cmdlang->err = err;
	cmdlang->location = "cmd_solparm.c(solparm_unlock_mc_done)";
	goto out;
    }

    ipmi_cmdlang_out(cmd_info, "SOLPARM unlocked", info->name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_solparm_destroy(solparm, NULL, NULL);
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static void
solparm_unlock_mc(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             channel;
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_solparm_t  *solparm = NULL;
    solparm_mc_unlock_t *info;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &channel, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "channel invalid";
	goto out_err;
    }
    curr_arg++;

    rv = ipmi_solparm_alloc(mc, channel, &solparm);
    if (rv) {
	cmdlang->errstr = "Error from ipmi_solparm_alloc";
	cmdlang->err = rv;
	goto out_err;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	goto out_err;
    }
    info->cmd_info = cmd_info;
    ipmi_mc_get_name(mc, info->name, sizeof(info->name));
    
    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_sol_clear_lock(solparm, NULL, solparm_unlock_mc_done, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error from ipmi_sol_clear_lock";
	cmdlang->err = rv;
	ipmi_solparm_destroy(solparm, NULL, NULL);
	ipmi_mem_free(info);
	goto out_err;
    }
    return;

 out_err:
    if (solparm)
	ipmi_solparm_destroy(solparm, NULL, NULL);
    ipmi_mc_get_name(mc, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_solparm.c(solparm_unlock_mc)";
}

static ipmi_cmdlang_cmd_t *solparm_cmds;
static ipmi_cmdlang_cmd_t *config_cmds;

static ipmi_cmdlang_init_t cmds_solparm[] =
{
    { "solparm", NULL,
      "- Commands dealing with SOL Parameters (solparms)",
      NULL, NULL, &solparm_cmds},
    { "list", &solparm_cmds,
      "- List all the solparms in the system",
      ipmi_cmdlang_domain_handler, solparm_list,  NULL },
    { "new", &solparm_cmds,
      "<mc> <channel>"
      " - Create a solparm for the given MC and channel.",
      ipmi_cmdlang_mc_handler, solparm_new, NULL },
    { "info", &solparm_cmds,
      "<solparm> - Dump information about a solparm",
      ipmi_cmdlang_solparm_handler, solparm_info, NULL },
    { "config", &solparm_cmds,
      "- Commands dealing with SOLPARM configs",
      NULL, NULL, &config_cmds },
    { "list", &config_cmds,
      "- List the sol configurations that currently exist",
      solparm_config_list, NULL, NULL },
    { "info", &config_cmds,
      "<config> - List info on sol configuration",
      solparm_config_info, NULL, NULL },
    { "get", &config_cmds,
      "<solparm> - Fetch the SOL information for the solparm",
      ipmi_cmdlang_solparm_handler, solparm_config_get, NULL },
    { "set", &config_cmds,
      "<solparm> <solparm config> - Set the SOL information for the solparm",
      ipmi_cmdlang_solparm_handler, solparm_config_set, NULL },
    { "unlock", &config_cmds,
      "<solparm> <solparm config> - Unlock, but do not set the config",
      ipmi_cmdlang_solparm_handler, solparm_config_unlock, NULL },
    { "update", &config_cmds,
      "<solparm config> <parm> [selector] <value> - Set the given parameter"
      " in the solparm config to the given value.  If the parameter has"
      " a selector of some type, the selector must be given, otherwise"
      " no selector should be given.",
      solparm_config_update, NULL, NULL },
    { "close", &config_cmds,
      "<solparm config> - free the config",
      solparm_config_close, NULL, NULL },
    { "unlock_mc", &solparm_cmds,
      "<mc> <channel> - Unlock the solparms for the given mc/channel",
      ipmi_cmdlang_mc_handler, solparm_unlock_mc, NULL },
    { "close", &solparm_cmds,
      "<solparm> - Close the solparm",
      ipmi_cmdlang_solparm_handler, solparm_close, NULL },
};
#define CMDS_SOLPARM_LEN (sizeof(cmds_solparm)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_solparm_init(os_handler_t *os_hnd)
{
    int rv;

    solcs = locked_list_alloc(os_hnd);
    if (!solcs)
	return ENOMEM;

    rv = ipmi_cmdlang_reg_table(cmds_solparm, CMDS_SOLPARM_LEN);
    if (rv) {
	locked_list_destroy(solcs);
	solcs = NULL;
    }

    return rv;
}

static int
config_destroy_handler(void *cb_data, void *item1, void *item2)
{
    sol_config_info_t *info = item1;

    ipmi_sol_free_config(info->config);
    ipmi_mem_free(info);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_cmdlang_solparm_shutdown(void)
{
    locked_list_iterate(solcs, config_destroy_handler, NULL);
    locked_list_destroy(solcs);
    solcs = NULL;
}
