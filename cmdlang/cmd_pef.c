/*
 * cmd_pef.c
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
#include <OpenIPMI/ipmi_pef.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_mc.h>

/* Internal includes, do not use in your programs */
#include <OpenIPMI/internal/ipmi_malloc.h>
#include <OpenIPMI/internal/locked_list.h>

static locked_list_t *pefs;

static void
pef_list_handler(ipmi_pef_t *pef, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            pef_name[IPMI_PEF_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_pef_get_name(pef, pef_name, sizeof(pef_name));

    ipmi_cmdlang_out(cmd_info, "Name", pef_name);
}

static void
pef_list(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char             domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "Domain", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
    ipmi_cmdlang_out(cmd_info, "PEFs", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_pef_iterate_pefs(domain, pef_list_handler, cmd_info);
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
pef_info(ipmi_pef_t *pef, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            pef_name[IPMI_PEF_NAME_LEN];

    ipmi_pef_get_name(pef, pef_name, sizeof(pef_name));

    ipmi_cmdlang_out(cmd_info, "PEF", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", pef_name);
    ipmi_mc_pointer_cb(ipmi_pef_get_mc(pef), get_mc_name, cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static void
pef_new_done(ipmi_pef_t *pef, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            pef_name[IPMI_PEF_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error allocating PEF";
	cmdlang->err = err;
	cmdlang->location = "cmd_pef.c(pef_new_done)";
	goto out;
    }

    ipmi_pef_get_name(pef, pef_name, sizeof(pef_name));
    ipmi_cmdlang_out(cmd_info, "PEF", pef_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
pef_new(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_pef_alloc(mc, pef_new_done, cmd_info, NULL);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error from ipmi_pef_alloc";
	cmdlang->err = rv;
	goto out_err;
    }
    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_pef.c(pef_new)";
}

static void
pef_close_done(ipmi_pef_t *pef, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            pef_name[IPMI_PEF_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	ipmi_pef_get_name(pef, cmdlang->objstr,
			  cmdlang->objstr_len);
	cmdlang->errstr = "Error closing PEF";
	cmdlang->err = err;
	cmdlang->location = "cmd_pef.c(pef_close_done)";
	goto out;
    }

    ipmi_pef_get_name(pef, pef_name, sizeof(pef_name));
    ipmi_cmdlang_out(cmd_info, "PEF destroyed", pef_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
pef_close(ipmi_pef_t *pef, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_pef_destroy(pef, pef_close_done, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	ipmi_pef_get_name(pef, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->errstr = "Error closing PEF";
	cmdlang->err = rv;
	cmdlang->location = "cmd_pef.c(pef_close)";
    }
}

#define PEF_CONFIG_NAME_LEN 80
typedef struct pef_config_info_s
{
    char              name[PEF_CONFIG_NAME_LEN];
    ipmi_pef_config_t *config;
} pef_config_info_t;

static unsigned int unique_num = 0;

typedef struct find_config_s
{
    char              *name;
    ipmi_pef_config_t *config;
    int               delete;
} find_config_t;

static int
find_config_handler(void *cb_data, void *item1, void *item2)
{
    pef_config_info_t *info = item1;
    find_config_t     *find = cb_data;

    if (strcmp(find->name, info->name) == 0) {
	find->config = info->config;
	if (find->delete) {
	    locked_list_remove(pefs, item1, item2);
	    ipmi_mem_free(info);
	}
	return LOCKED_LIST_ITER_STOP;
    }

    return LOCKED_LIST_ITER_CONTINUE;
}

static ipmi_pef_config_t *
find_config(char *name, int delete)
{
    find_config_t find;

    find.name = name;
    find.config = NULL;
    find.delete = delete;
    locked_list_iterate(pefs, find_config_handler, &find);
    return find.config;
}

typedef void (*lp_set)(ipmi_cmd_info_t *cmd_info, char *val,
		       ipmi_pef_config_t *lanc, void *func);
typedef void (*lp_out)(ipmi_cmd_info_t *cmd_info, char *name,
		       ipmi_pef_config_t *lanc, void *func);
typedef struct lp_item_s
{
    lp_set set;
    lp_out out;
} lp_item_t;

static void
set_retint(ipmi_cmd_info_t *cmd_info, char *val,
	   ipmi_pef_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_pef_config_t *l, unsigned int v) = func;
    int            v;

    ipmi_cmdlang_get_int(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, v);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
static void
out_retint(ipmi_cmd_info_t *cmd_info, char *name,
	   ipmi_pef_config_t *lanc, void *func)
{
    unsigned int   (*f)(ipmi_pef_config_t *l) = func;
    ipmi_cmdlang_out_int(cmd_info, name, f(lanc));
}
static lp_item_t lp_retint = {set_retint, out_retint};

static void
set_retbool(ipmi_cmd_info_t *cmd_info, char *val,
	    ipmi_pef_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_pef_config_t *l, unsigned int v) = func;
    int            v;

    ipmi_cmdlang_get_bool(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, v);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
static void
out_retbool(ipmi_cmd_info_t *cmd_info, char *name,
	    ipmi_pef_config_t *lanc, void *func)
{
    unsigned int   (*f)(ipmi_pef_config_t *l) = func;
    ipmi_cmdlang_out_bool(cmd_info, name, f(lanc));
}
static lp_item_t lp_retbool = {set_retbool, out_retbool};

static void
set_int(ipmi_cmd_info_t *cmd_info, char *val,
	ipmi_pef_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_pef_config_t *l, unsigned int v) = func;
    int            v;

    ipmi_cmdlang_get_int(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, v);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
static void
out_int(ipmi_cmd_info_t *cmd_info, char *name,
	ipmi_pef_config_t *lanc, void *func)
{
    unsigned int   v;
    int            rv;
    int            (*f)(ipmi_pef_config_t *l, unsigned int *v) = func;
    
    rv = f(lanc, &v);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, name, v);
}
static lp_item_t lp_int = {set_int, out_int};

static void
set_guid(ipmi_cmd_info_t *cmd_info, char *val,
	 ipmi_pef_config_t *lanc, void *func)
{
    unsigned char  v[16];
    char           tmp[3];
    char           *end;
    int            i;
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_pef_config_t *l, unsigned char *v,
			unsigned int dl) = func;

    if (strlen(val) != 32) {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "Invalid GUID";
	return;
    }

    for (i=0; i<16; i++) {
	memset(tmp, 0, sizeof(tmp));
	memcpy(tmp, val+(i*2), 2);
	v[i] = strtoul(tmp, &end, 16);
	if (*end != '\0') {
	    cmdlang->err = EINVAL;
	    cmdlang->errstr = "Invalid GUID";
	    return;
	}
    }
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, v, sizeof(v));
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
static void
out_guid(ipmi_cmd_info_t *cmd_info, char *name,
       ipmi_pef_config_t *lanc, void *func)
{
    int            rv;
    int            (*f)(ipmi_pef_config_t *l, unsigned char *v,
			unsigned int *dl) = func;
    unsigned char  v[16];
    unsigned int   len = sizeof(v);
    char           str[33];
    char           *s;
    int            i;
    
    rv = f(lanc, (unsigned char *) &v, &len);
    if (!rv) {
	s = str;
	for (i=0; i<16; i++)
	    s += sprintf(s, "%2.2x", v[i]);
	ipmi_cmdlang_out(cmd_info, name, str);
    }
}
static lp_item_t lp_guid = {set_guid, out_guid};

static struct lps_s
{
    char      *name;
    lp_item_t *lpi;
    void      *get_func;
    void      *set_func;
} lps[] =
/* read-only */
#define FR(name, type) { #name, &lp_ ## type, ipmi_pefconfig_get_ ## name, \
		         NULL }
/* Writable */
#define F(name, type) { #name, &lp_ ## type, ipmi_pefconfig_get_ ## name, \
		        ipmi_pefconfig_set_ ## name }
{
    F(alert_startup_delay_enabled, retbool),
    F(startup_delay_enabled, retbool),
    F(event_messages_enabled, retbool),
    F(pef_enabled, retbool),
    F(diagnostic_interrupt_enabled, retbool),
    F(oem_action_enabled, retbool),
    F(power_cycle_enabled, retbool),
    F(reset_enabled, retbool),
    F(power_down_enabled, retbool),
    F(alert_enabled, retbool),
    F(startup_delay, int),
    F(alert_startup_delay, int),
    F(guid_enabled, retbool),
    F(guid_val, guid),
    FR(num_event_filters, retint),
    FR(num_alert_policies, retint),
    FR(num_alert_strings, retint),
    { NULL }
};

/*
 * Selector-based get/out routines.
 */
typedef void (*ulp_set)(ipmi_cmd_info_t *cmd_info, int sel, char *val,
			ipmi_pef_config_t *lanc, void *func);
typedef void (*ulp_out)(ipmi_cmd_info_t *cmd_info, int sel, char *name,
			ipmi_pef_config_t *lanc, void *func);
typedef struct ulp_item_s
{
    ulp_set set;
    ulp_out out;
} ulp_item_t;

static void
uset_bool(ipmi_cmd_info_t *cmd_info, int sel, char *val,
	 ipmi_pef_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_pef_config_t *l, unsigned int sel,
			unsigned int v) = func;
    int            v;

    ipmi_cmdlang_get_bool(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, sel, v);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
static void
uout_bool(ipmi_cmd_info_t *cmd_info, int sel, char *name,
	 ipmi_pef_config_t *lanc, void *func)
{
    unsigned int   v;
    int            rv;
    int            (*f)(ipmi_pef_config_t *l, unsigned int sel,
			unsigned int *v) = func;
    
    rv = f(lanc, sel, &v);
    if (!rv)
	ipmi_cmdlang_out_bool(cmd_info, name, v);
}
static ulp_item_t lp_ubool = {uset_bool, uout_bool};

static void
uset_int(ipmi_cmd_info_t *cmd_info, int sel, char *val,
	 ipmi_pef_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_pef_config_t *l, unsigned int sel,
			unsigned int v) = func;
    int            v;

    ipmi_cmdlang_get_int(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, sel, v);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
static void
uout_int(ipmi_cmd_info_t *cmd_info, int sel, char *name,
	 ipmi_pef_config_t *lanc, void *func)
{
    unsigned int   v;
    int            rv;
    int            (*f)(ipmi_pef_config_t *l, unsigned int sel,
			unsigned int *v) = func;
    
    rv = f(lanc, sel, &v);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, name, v);
}
static ulp_item_t lp_uint = {uset_int, uout_int};

static void
uset_str(ipmi_cmd_info_t *cmd_info, int sel, char *val,
	 ipmi_pef_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_pef_config_t *l, unsigned int sel,
			char *v) = func;

    if (!cmdlang->err) {
	cmdlang->err = f(lanc, sel, val);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
static void
uout_str(ipmi_cmd_info_t *cmd_info, int sel, char *name,
	 ipmi_pef_config_t *lanc, void *func)
{
    char          v[100];
    int           rv;
    int           (*f)(ipmi_pef_config_t *l, unsigned int sel,
		       char *v, unsigned int *dl) = func;
    unsigned int  len = sizeof(v);
    
    rv = f(lanc, sel, v, &len);
    if (!rv)
	ipmi_cmdlang_out(cmd_info, name, v);
}
static ulp_item_t lp_ustr = {uset_str, uout_str};

/*
 * event-filter table items
 */
static struct ulps_s
{
    char       *name;
    ulp_item_t *lpi;
    void       *get_func;
    void       *set_func;
} elps[] =
{
    F(enable_filter, ubool),
    F(filter_type, uint),
    F(diagnostic_interrupt, ubool),
    F(oem_action, ubool),
    F(power_cycle, ubool),
    F(reset, ubool),
    F(power_down, ubool),
    F(alert, ubool),
    F(alert_policy_number, uint),
    F(event_severity, uint),
    F(generator_id_addr, uint),
    F(generator_id_channel_lun, uint),
    F(sensor_type, uint),
    F(sensor_number, uint),
    F(event_trigger, uint),
    F(data1_offset_mask, uint),
    F(data1_mask, uint),
    F(data1_compare1, uint),
    F(data1_compare2, uint),
    F(data2_mask, uint),
    F(data2_compare1, uint),
    F(data2_compare2, uint),
    F(data3_mask, uint),
    F(data3_compare1, uint),
    F(data3_compare2, uint),
    { NULL }
};

/*
 * Alert policy table items
 */
static struct ulps_s plps[] =
{
    F(policy_num, uint),
    F(enabled, ubool),
    F(policy, uint),
    F(channel, uint),
    F(destination_selector, uint),
    F(alert_string_event_specific, ubool),
    F(alert_string_selector, uint),
    { NULL }
};

/*
 * Alert string items
 */
static struct ulps_s slps[] =
{
    F(event_filter, uint),
    F(alert_string_set, uint),
    F(alert_string, ustr),
    { NULL }
};

static void
config_info(ipmi_cmd_info_t *cmd_info, ipmi_pef_config_t *config)
{
    int i;
    int j;
    int num;

    /* Basic items */
    for (i=0; lps[i].name; i++) {
	lp_item_t *lp = lps[i].lpi;
	lp->out(cmd_info, lps[i].name, config, lps[i].get_func);
    }

    /* per-event-filter table items */
    num = ipmi_pefconfig_get_num_event_filters(config);
    for (j=0; j<num; j++) {
	struct ulps_s *lps = elps;
	ipmi_cmdlang_out(cmd_info, "Event Filter", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out_int(cmd_info, "Number", j);
	for (i=0; lps[i].name; i++) {
	    ulp_item_t *lp = lps[i].lpi;
	    lp->out(cmd_info, j, lps[i].name, config, lps[i].get_func);
	}
	ipmi_cmdlang_up(cmd_info);
    }

    /* per-alert policy table items */
    num = ipmi_pefconfig_get_num_alert_policies(config);
    for (j=0; j<num; j++) {
	struct ulps_s *lps = plps;
	ipmi_cmdlang_out(cmd_info, "Alert Policy", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out_int(cmd_info, "Number", j);
	for (i=0; lps[i].name; i++) {
	    ulp_item_t *lp = lps[i].lpi;
	    lp->out(cmd_info, j, lps[i].name, config, lps[i].get_func);
	}
	ipmi_cmdlang_up(cmd_info);
    }

    /* per-alert string items */
    num = ipmi_pefconfig_get_num_alert_strings(config);
    for (j=0; j<num; j++) {
	struct ulps_s *lps = slps;
	ipmi_cmdlang_out(cmd_info, "Alert String", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out_int(cmd_info, "Number", j);
	for (i=0; lps[i].name; i++) {
	    ulp_item_t *lp = lps[i].lpi;
	    lp->out(cmd_info, j, lps[i].name, config, lps[i].get_func);
	}
	ipmi_cmdlang_up(cmd_info);
    }
}

static void
pef_config_get_done(ipmi_pef_t        *pef,
		    int               err,
		    ipmi_pef_config_t *config,
		    void              *cb_data)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char              pef_name[IPMI_PEF_NAME_LEN];
    pef_config_info_t *info;

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error getting PEF";
	cmdlang->err = err;
	goto out;
    }

    ipmi_pef_get_name(pef, pef_name, sizeof(pef_name));

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	ipmi_pef_free_config(config);
	goto out;
    }
    snprintf(info->name, sizeof(info->name), "%s.%u",
	     pef_name, unique_num);
    info->config = config;
    if (!locked_list_add(pefs, info, NULL)) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	ipmi_pef_free_config(config);
	ipmi_mem_free(info);
	goto out;
    }
    unique_num++;

    ipmi_cmdlang_out(cmd_info, "PEF Config", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", info->name);
    config_info(cmd_info, config);
    ipmi_cmdlang_up(cmd_info);

 out:
    if (cmdlang->err) {
	ipmi_pef_get_name(pef, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->location = "cmd_pef.c(pef_config_get_done)";
    }
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
pef_config_get(ipmi_pef_t *pef, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_pef_get_config(pef, pef_config_get_done, cmd_info);
    if (rv) {
	ipmi_pef_get_name(pef, cmdlang->objstr,
			      cmdlang->objstr_len);
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error getting PEF";
	cmdlang->err = rv;
	cmdlang->location = "cmd_pef.c(pef_config_get)";
    }
}

typedef struct pef_config_op_s
{
    char            name[PEF_CONFIG_NAME_LEN];
    ipmi_cmd_info_t *cmd_info;
} pef_config_op_t;

static void
pef_config_set_done(ipmi_pef_t *pef,
		    int        err,
		    void       *cb_data)
{
    pef_config_op_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	ipmi_pef_get_name(pef, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->errstr = "Error setting PEF";
	cmdlang->err = err;
	cmdlang->location = "cmd_pef.c(pef_config_set_done)";
	goto out;
    }

    ipmi_cmdlang_out(cmd_info, "PEF config set", info->name);

 out:
    ipmi_mem_free(info);
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
pef_config_set(ipmi_pef_t *pef, void *cb_data)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               rv;
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_pef_config_t *lanc;
    pef_config_op_t   *info;
    char              *name;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    name = argv[curr_arg];
    curr_arg++;
    lanc = find_config(name, 0);
    if (!lanc) {
	cmdlang->errstr = "Invalid PEF config";
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
    rv = ipmi_pef_set_config(pef, lanc, pef_config_set_done, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error setting PEF";
	cmdlang->err = rv;
	ipmi_mem_free(info);
	goto out_err;
    }

    return;

 out_err:
    ipmi_pef_get_name(pef, cmdlang->objstr,
			  cmdlang->objstr_len);
    cmdlang->location = "cmd_pef.c(pef_config_set)";
}

static void
pef_config_unlock_done(ipmi_pef_t *pef,
		       int        err,
		       void       *cb_data)
{
    pef_config_op_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	ipmi_pef_get_name(pef, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->errstr = "Error unlocking PEF";
	cmdlang->err = err;
	cmdlang->location = "cmd_pef.c(pef_config_unlock_done)";
	goto out;
    }

    ipmi_cmdlang_out(cmd_info, "PEF config unlocked", info->name);

 out:
    ipmi_mem_free(info);
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
pef_config_unlock(ipmi_pef_t *pef, void *cb_data)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               rv;
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_pef_config_t *lanc;
    pef_config_op_t   *info;
    char              *name;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    name = argv[curr_arg];
    curr_arg++;
    lanc = find_config(name, 0);
    if (!lanc) {
	cmdlang->errstr = "Invalid PEF config";
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
    rv = ipmi_pef_clear_lock(pef, lanc, pef_config_unlock_done, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error clearing PEF lock";
	cmdlang->err = rv;
	ipmi_mem_free(info);
	goto out_err;
    }

    return;

 out_err:
    ipmi_pef_get_name(pef, cmdlang->objstr,
			  cmdlang->objstr_len);
    cmdlang->location = "cmd_pef.c(pef_config_unlock)";
}

static void
pef_config_close(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_pef_config_t *lanc;
    char              *lanc_name;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	lanc_name = "";
	goto out_err;
    }
    lanc_name = argv[curr_arg];

    lanc = find_config(lanc_name, 1);
    if (!lanc) {
	cmdlang->errstr = "Invalid PEF config";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_pef_free_config(lanc);
    ipmi_cmdlang_out(cmd_info, "PEF config destroyed", lanc_name);
    return;

 out_err:
    strncpy(cmdlang->objstr, lanc_name, cmdlang->objstr_len);
    cmdlang->location = "cmd_pef.c(pef_config_close)";
}

static int
pef_config_list_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    pef_config_info_t *info = item1;

    ipmi_cmdlang_out(cmd_info, "Name", info->name);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
pef_config_list(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_out(cmd_info, "PEF Configs", NULL);
    ipmi_cmdlang_down(cmd_info);
    locked_list_iterate(pefs, pef_config_list_handler, cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static int
pef_config_info_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    pef_config_info_t *info = item1;

    ipmi_cmdlang_out(cmd_info, "PEF Config", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", info->name);
    config_info(cmd_info, info->config);
    ipmi_cmdlang_up(cmd_info);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
pef_config_info(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_pef_config_t *lanc;

    if ((argc - curr_arg) < 1) {
	locked_list_iterate(pefs, pef_config_info_handler, cmd_info);
    } else {
	lanc = find_config(argv[curr_arg], 0);
	if (!lanc) {
	    cmdlang->errstr = "Invalid PEF config";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
	ipmi_cmdlang_out(cmd_info, "PEF Config", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Name", argv[curr_arg]);
	config_info(cmd_info, lanc);
	ipmi_cmdlang_up(cmd_info);
    }
    return;

 out_err:
    strncpy(cmdlang->objstr, argv[curr_arg], cmdlang->objstr_len);
    cmdlang->location = "cmd_pef.c(pef_config_info)";
}

static void
pef_config_update(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_pef_config_t *lanc;
    int               i;
    char              *name;
    char              *val;
    char              *lanc_name;
    int               sel;

    if ((argc - curr_arg) < 3) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	lanc_name = "";
	goto out_err;
    }
    lanc_name = argv[curr_arg];
    curr_arg++;

    lanc = find_config(lanc_name, 0);
    if (!lanc) {
	cmdlang->errstr = "Invalid PEF config";
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
	    lp->set(cmd_info, val, lanc, lps[i].set_func);
	    goto out;
	}
    }

    /* per-event filter items */
    for (i=0; elps[i].name; i++) {
	struct ulps_s *lps = elps;
	if (strcmp(lps[i].name, name) == 0) {
	    ulp_item_t *lp = lps[i].lpi;

	    if ((argc - curr_arg) < 1) {
		/* Not enough parameters */
		cmdlang->errstr = "Not enough parameters";
		cmdlang->err = EINVAL;
		goto out_err;
	    }
	    if (!lp->set) {
		cmdlang->errstr = "Parameter is read-only";
		cmdlang->err = EINVAL;
		goto out_err;
	    }
	    ipmi_cmdlang_get_int(val, &sel, cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "selector invalid";
		goto out_err;
	    }
	    val = argv[curr_arg];
	    curr_arg++;
	    lp->set(cmd_info, sel, val, lanc, lps[i].set_func);
	    goto out;
	}
    }

    /* per-event filter items */
    for (i=0; plps[i].name; i++) {
	struct ulps_s *lps = plps;
	if (strcmp(lps[i].name, name) == 0) {
	    ulp_item_t *lp = lps[i].lpi;

	    if ((argc - curr_arg) < 1) {
		/* Not enough parameters */
		cmdlang->errstr = "Not enough parameters";
		cmdlang->err = EINVAL;
		goto out_err;
	    }
	    if (!lp->set) {
		cmdlang->errstr = "Parameter is read-only";
		cmdlang->err = EINVAL;
		goto out_err;
	    }
	    ipmi_cmdlang_get_int(val, &sel, cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "selector invalid";
		goto out_err;
	    }
	    val = argv[curr_arg];
	    curr_arg++;
	    lp->set(cmd_info, sel, val, lanc, lps[i].set_func);
	    goto out;
	}
    }

    /* per-event filter items */
    for (i=0; slps[i].name; i++) {
	struct ulps_s *lps = slps;
	if (strcmp(lps[i].name, name) == 0) {
	    ulp_item_t *lp = lps[i].lpi;

	    if ((argc - curr_arg) < 1) {
		/* Not enough parameters */
		cmdlang->errstr = "Not enough parameters";
		cmdlang->err = EINVAL;
		goto out_err;
	    }
	    if (!lp->set) {
		cmdlang->errstr = "Parameter is read-only";
		cmdlang->err = EINVAL;
		goto out_err;
	    }
	    ipmi_cmdlang_get_int(val, &sel, cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "selector invalid";
		goto out_err;
	    }
	    val = argv[curr_arg];
	    curr_arg++;
	    lp->set(cmd_info, sel, val, lanc, lps[i].set_func);
	    goto out;
	}
    }

    cmdlang->errstr = "Invalid parameter name";
    cmdlang->err = EINVAL;
    goto out_err;

 out:
    ipmi_cmdlang_out(cmd_info, "PEF config updated", lanc_name);
    return;

 out_err:
    strncpy(cmdlang->objstr, lanc_name, cmdlang->objstr_len);
    cmdlang->location = "cmd_pef.c(pef_config_update)";
}

typedef struct pet_mc_unlock_s
{
    char            name[IPMI_MC_NAME_LEN];
    ipmi_cmd_info_t *cmd_info;
} pef_mc_unlock_t;

static void
pef_unlock_mc_done2(ipmi_pef_t *pef, int err, void *cb_data)
{
    pef_mc_unlock_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	ipmi_pef_get_name(pef, cmdlang->objstr,
			  cmdlang->objstr_len);
	cmdlang->errstr = "Error unlocking MC PEF";
	cmdlang->err = err;
	cmdlang->location = "cmd_pef.c(pef_unlock_mc_done)";
	goto out;
    }

    ipmi_cmdlang_out(cmd_info, "PEF unlocked", info->name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_pef_destroy(pef, NULL, NULL);
    ipmi_mem_free(info);
}

static void
pef_unlock_mc_done1(ipmi_pef_t *pef, int err, void *cb_data)
{
    pef_mc_unlock_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    if (err) {
	ipmi_cmdlang_lock(cmd_info);
	cmdlang->errstr = "Error unlocking MC PEF";
	cmdlang->err = err;
	cmdlang->location = "cmd_pef.c(pef_unlock_mc_done)";
	ipmi_cmdlang_unlock(cmd_info);
	goto out_err;
    }

    rv = ipmi_pef_clear_lock(pef, NULL, pef_unlock_mc_done2, info);
    if (rv) {
	ipmi_cmdlang_lock(cmd_info);
	cmdlang->errstr = "Error from ipmi_pef_clear_lock";
	cmdlang->err = rv;
	ipmi_cmdlang_unlock(cmd_info);
	goto out_err;
    }
    return;

 out_err:
    ipmi_pef_destroy(pef, NULL, NULL);
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static void
pef_unlock_mc(ipmi_mc_t *mc, void *cb_data)
{
    pef_mc_unlock_t *info;
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	goto out_err;
    }
    info->cmd_info = cmd_info;
    ipmi_mc_get_name(mc, info->name, sizeof(info->name));
    
    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_pef_alloc(mc, pef_unlock_mc_done1, info, NULL);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error from ipmi_pef_alloc";
	cmdlang->err = rv;
	ipmi_mem_free(info);
	goto out_err;
    }
    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_pef.c(pef_unlock_mc)";
}

static ipmi_cmdlang_cmd_t *pef_cmds;
static ipmi_cmdlang_cmd_t *config_cmds;

static ipmi_cmdlang_init_t cmds_pef[] =
{
    { "pef", NULL,
      "- Commands dealing with PEF Parameters (pefs)",
      NULL, NULL, &pef_cmds},
    { "list", &pef_cmds,
      "- List all the pefs in the system",
      ipmi_cmdlang_domain_handler, pef_list,  NULL },
    { "new", &pef_cmds,
      "<mc> - Create a pef for the given MC.",
      ipmi_cmdlang_mc_handler, pef_new, NULL },
    { "info", &pef_cmds,
      "<pef> - Dump information about a pef",
      ipmi_cmdlang_pef_handler, pef_info, NULL },
    { "config", &pef_cmds,
      "- Commands dealing with PEF configs",
      NULL, NULL, &config_cmds },
    { "list", &config_cmds,
      "- List the lan configurations that currently exist",
      pef_config_list, NULL, NULL },
    { "info", &config_cmds,
      "<config> - List info on lan configuration",
      pef_config_info, NULL, NULL },
    { "get", &config_cmds,
      "<pef> - Fetch the PEF information for the pef",
      ipmi_cmdlang_pef_handler, pef_config_get, NULL },
    { "set", &config_cmds,
      "<pef> <pef config> - Set the PEF information for the pef",
      ipmi_cmdlang_pef_handler, pef_config_set, NULL },
    { "unlock", &config_cmds,
      "<pef> <pef config> - Unlock, but do not set the config",
      ipmi_cmdlang_pef_handler, pef_config_unlock, NULL },
    { "update", &config_cmds,
      "<pef config> <parm> [selector] <value> - Set the given parameter"
      " in the pef config to the given value.  If the parameter has"
      " a selector of some type, the selector must be given, otherwise"
      " no selector should be given.",
      pef_config_update, NULL, NULL },
    { "close", &config_cmds,
      "<pef config> - free the config",
      pef_config_close, NULL, NULL },
    { "unlock_mc", &pef_cmds,
      "<mc> - Unlock the pef for the given mc",
      ipmi_cmdlang_mc_handler, pef_unlock_mc, NULL },
    { "close", &pef_cmds,
      "<pef> - Close the pef",
      ipmi_cmdlang_pef_handler, pef_close, NULL },
};
#define CMDS_PEF_LEN (sizeof(cmds_pef)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_pef_init(os_handler_t *os_hnd)
{
    int rv;

    pefs = locked_list_alloc(os_hnd);
    if (!pefs)
	return ENOMEM;

    rv = ipmi_cmdlang_reg_table(cmds_pef, CMDS_PEF_LEN);
    if (rv) {
	locked_list_destroy(pefs);
	pefs = NULL;
    }

    return rv;
}

static int
config_destroy_handler(void *cb_data, void *item1, void *item2)
{
    pef_config_info_t *info = item1;

    ipmi_pef_free_config(info->config);
    ipmi_mem_free(info);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_cmdlang_pef_shutdown(void)
{
    locked_list_iterate(pefs, config_destroy_handler, NULL);
    locked_list_destroy(pefs);
    pefs = NULL;
}
