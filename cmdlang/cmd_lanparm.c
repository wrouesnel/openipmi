/*
 * cmd_lanparm.c
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
#include <OpenIPMI/ipmi_lanparm.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/locked_list.h>

locked_list_t *lancs;

static void
lanparm_list_handler(ipmi_lanparm_t *lanparm, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            lanparm_name[IPMI_LANPARM_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_lanparm_get_name(lanparm, lanparm_name, sizeof(lanparm_name));

    ipmi_cmdlang_out(cmd_info, "Name", lanparm_name);
}

static void
lanparm_list(ipmi_domain_t *domain, ipmi_cmd_info_t *cmd_info)
{
    ipmi_lanparm_iterate_lanparms(domain, lanparm_list_handler, cmd_info);
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
lanparm_info(ipmi_lanparm_t *lanparm, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    int             rv;

    ipmi_cmdlang_out(cmd_info, "LANPARM", NULL);
    ipmi_cmdlang_down(cmd_info);
    rv = ipmi_mc_pointer_cb(ipmi_lanparm_get_mc_id(lanparm), get_mc_name,
			    cmd_info);
    ipmi_cmdlang_out_int(cmd_info, "Channel",
			 ipmi_lanparm_get_channel(lanparm));
    ipmi_cmdlang_up(cmd_info);
}

static void
lanparm_new(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             channel;
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_lanparm_t  *lanparm;
    char            lanparm_name[IPMI_LANPARM_NAME_LEN];

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

    rv = ipmi_lanparm_alloc(mc, channel, &lanparm);
    if (rv) {
	cmdlang->errstr = "Error from ipmi_lanparm_alloc";
	cmdlang->err = rv;
	goto out_err;
    }

    ipmi_lanparm_get_name(lanparm, lanparm_name, sizeof(lanparm_name));
    ipmi_cmdlang_out(cmd_info, "LANPARM", lanparm_name);

    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_lanparm.c(lanparm_new)";
}

static void
lanparm_close_done(ipmi_lanparm_t *lanparm, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    if (err) {
	ipmi_cmdlang_lock(cmd_info);
	ipmi_lanparm_get_name(lanparm, cmdlang->objstr,
			  cmdlang->objstr_len);
	cmdlang->errstr = "Error closing LANPARM";
	cmdlang->err = err;
	cmdlang->location = "cmd_lanparm.c(lanparm_close_done)";
	ipmi_cmdlang_unlock(cmd_info);
    }

    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
lanparm_close(ipmi_lanparm_t *lanparm, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_lanparm_destroy(lanparm, lanparm_close_done, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	ipmi_lanparm_get_name(lanparm, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->errstr = "Error closing LANPARM";
	cmdlang->err = rv;
	cmdlang->location = "cmd_lanparm.c(lanparm_close)";
    }
}

#define LAN_CONFIG_NAME_LEN 80
typedef struct lan_config_info_s
{
    char              name[LAN_CONFIG_NAME_LEN];
    ipmi_lan_config_t *config;
} lan_config_info_t;

static unsigned int unique_num = 0;

typedef struct find_config_s
{
    char              *name;
    ipmi_lan_config_t *config;
    int               delete;
} find_config_t;

static int
find_config_handler(void *cb_data, void *item1, void *item2)
{
    lan_config_info_t *info = item1;
    find_config_t     *find = cb_data;

    if (strcmp(find->name, info->name) == 0) {
	find->config = info->config;
	if (find->delete) {
	    locked_list_remove(lancs, item1, item2);
	    ipmi_mem_free(info);
	}
	return LOCKED_LIST_ITER_STOP;
    }

    return LOCKED_LIST_ITER_CONTINUE;
}

static ipmi_lan_config_t *
find_config(char *name, int delete)
{
    find_config_t find;

    find.name = name;
    find.config = NULL;
    find.delete = delete;
    locked_list_iterate(lancs, find_config_handler, &find);
    return find.config;
}

typedef void (*lp_set)(ipmi_cmd_info_t *cmd_info, char *val,
		       ipmi_lan_config_t *lanc, void *func);
typedef void (*lp_out)(ipmi_cmd_info_t *cmd_info, char *name,
		       ipmi_lan_config_t *lanc, void *func);
typedef struct lp_item_s
{
    lp_set set;
    lp_out out;
} lp_item_t;

void
set_retint(ipmi_cmd_info_t *cmd_info, char *val,
	   ipmi_lan_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_lan_config_t *l, unsigned int v) = func;
    int            v;

    ipmi_cmdlang_get_int(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, v);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
void
out_retint(ipmi_cmd_info_t *cmd_info, char *name,
	   ipmi_lan_config_t *lanc, void *func)
{
    unsigned int   (*f)(ipmi_lan_config_t *l) = func;
    ipmi_cmdlang_out_int(cmd_info, name, f(lanc));
}
static lp_item_t lp_retint = {set_retint, out_retint};

void
set_retbool(ipmi_cmd_info_t *cmd_info, char *val,
	    ipmi_lan_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_lan_config_t *l, unsigned int v) = func;
    int            v;

    ipmi_cmdlang_get_bool(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, v);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
void
out_retbool(ipmi_cmd_info_t *cmd_info, char *name,
	    ipmi_lan_config_t *lanc, void *func)
{
    unsigned int   (*f)(ipmi_lan_config_t *l) = func;
    ipmi_cmdlang_out_bool(cmd_info, name, f(lanc));
}
static lp_item_t lp_retbool = {set_retbool, out_retbool};

void
set_int(ipmi_cmd_info_t *cmd_info, char *val,
	ipmi_lan_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_lan_config_t *l, unsigned int v) = func;
    int            v;

    ipmi_cmdlang_get_int(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, v);
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
void
out_int(ipmi_cmd_info_t *cmd_info, char *name,
	ipmi_lan_config_t *lanc, void *func)
{
    unsigned int   v;
    int            rv;
    int            (*f)(ipmi_lan_config_t *l, unsigned int *v) = func;
    
    rv = f(lanc, &v);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, name, v);
}
static lp_item_t lp_int = {set_int, out_int};

void
set_ip(ipmi_cmd_info_t *cmd_info, char *val,
       ipmi_lan_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_lan_config_t *l, unsigned char *v,
			unsigned int dl) = func;
    struct in_addr v;

    ipmi_cmdlang_get_ip(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, (unsigned char *) &v, sizeof(v));
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
void
out_ip(ipmi_cmd_info_t *cmd_info, char *name,
       ipmi_lan_config_t *lanc, void *func)
{
    struct in_addr v;
    int            rv;
    int            (*f)(ipmi_lan_config_t *l, unsigned char *v,
			unsigned int *dl) = func;
    unsigned int   len = sizeof(v);
    
    rv = f(lanc, (unsigned char *) &v, &len);
    if (!rv)
	ipmi_cmdlang_out_ip(cmd_info, name, &v);
}
static lp_item_t lp_ip = {set_ip, out_ip};

void
set_port(ipmi_cmd_info_t *cmd_info, char *val,
	 ipmi_lan_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_lan_config_t *l, unsigned char *v,
			unsigned int dl) = func;
    int            v;
    short          sv;

    ipmi_cmdlang_get_int(val, &v, cmd_info);
    sv = htons(v);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, (unsigned char *) &v, sizeof(v));
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
void
out_port(ipmi_cmd_info_t *cmd_info, char *name,
	 ipmi_lan_config_t *lanc, void *func)
{
    short          v;
    int            rv;
    int            (*f)(ipmi_lan_config_t *l, unsigned char *v,
			unsigned int *dl) = func;
    unsigned int   len = sizeof(v);
    
    rv = f(lanc, (unsigned char *) &v, &len);
    if (!rv) {
	v = ntohs(v);
	ipmi_cmdlang_out_int(cmd_info, name, v);
    }
}
static lp_item_t lp_port = {set_port, out_port};

void
set_mac(ipmi_cmd_info_t *cmd_info, char *val,
       ipmi_lan_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_lan_config_t *l, unsigned char *v,
			unsigned int dl) = func;
    unsigned char  v[6];

    ipmi_cmdlang_get_mac(val, v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, v, sizeof(v));
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
void
out_mac(ipmi_cmd_info_t *cmd_info, char *name,
       ipmi_lan_config_t *lanc, void *func)
{
    unsigned char v[6];
    int           rv;
    int           (*f)(ipmi_lan_config_t *l, unsigned char *v,
		       unsigned int *dl) = func;
    unsigned int  len = sizeof(v);
    
    rv = f(lanc, v, &len);
    if (!rv)
	ipmi_cmdlang_out_mac(cmd_info, name, v);
}
static lp_item_t lp_mac = {set_mac, out_mac};

static struct lps_s
{
    char      *name;
    lp_item_t *lpi;
    void      *get_func;
    void      *set_func;
} lps[] =
/* read-only */
#define FR(name, type) { #name, &lp_ ## type, ipmi_lanconfig_get_ ## name, \
		         NULL }
/* Writable */
#define F(name, type) { #name, &lp_ ## type, ipmi_lanconfig_get_ ## name, \
		        ipmi_lanconfig_set_ ## name }
{
    FR(support_auth_oem, retbool),
    FR(support_auth_straight, retbool),
    FR(support_auth_md5, retbool),
    FR(support_auth_md2, retbool),
    FR(support_auth_none, retbool),
    F(ip_addr_source, retint),
    FR(num_alert_destinations, retint),
    F(ipv4_ttl, int),
    F(ipv4_flags, int),
    F(ipv4_precedence, int),
    F(ipv4_tos, int),
    F(ip_addr, ip),
    F(mac_addr, mac),
    F(subnet_mask, ip),
    F(primary_rmcp_port, port),
    F(secondary_rmcp_port, port),
    F(bmc_generated_arps, int),
    F(bmc_generated_garps, int),
    F(garp_interval, int),
    F(default_gateway_ip_addr, ip),
    F(default_gateway_mac_addr, mac),
    F(backup_gateway_ip_addr, ip),
    F(backup_gateway_mac_addr, mac),
    { NULL }
};

/*
 * per-user items
 */
typedef void (*ulp_set)(ipmi_cmd_info_t *cmd_info, int sel, char *val,
			ipmi_lan_config_t *lanc, void *func);
typedef void (*ulp_out)(ipmi_cmd_info_t *cmd_info, int sel, char *name,
			ipmi_lan_config_t *lanc, void *func);
typedef struct ulp_item_s
{
    ulp_set set;
    ulp_out out;
} ulp_item_t;

void
uset_bool(ipmi_cmd_info_t *cmd_info, int sel, char *val,
	 ipmi_lan_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_lan_config_t *l, unsigned int sel,
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
void
uout_bool(ipmi_cmd_info_t *cmd_info, int sel, char *name,
	 ipmi_lan_config_t *lanc, void *func)
{
    unsigned int   v;
    int            rv;
    int            (*f)(ipmi_lan_config_t *l, unsigned int sel,
			unsigned int *v) = func;
    
    rv = f(lanc, sel, &v);
    if (!rv)
	ipmi_cmdlang_out_bool(cmd_info, name, v);
}
static ulp_item_t lp_ubool = {uset_bool, uout_bool};

static struct ulps_s
{
    char       *name;
    ulp_item_t *lpi;
    void       *get_func;
    void       *set_func;
} ulps[] =
{
    F(enable_auth_oem, ubool),
    F(enable_auth_straight, ubool),
    F(enable_auth_md5, ubool),
    F(enable_auth_md2, ubool),
    F(enable_auth_none, ubool),
    { NULL }
};

/*
 * per-alert-dest items
 */
void
uset_int(ipmi_cmd_info_t *cmd_info, int sel, char *val,
	 ipmi_lan_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_lan_config_t *l, unsigned int sel,
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
void
uout_int(ipmi_cmd_info_t *cmd_info, int sel, char *name,
	 ipmi_lan_config_t *lanc, void *func)
{
    unsigned int   v;
    int            rv;
    int            (*f)(ipmi_lan_config_t *l, unsigned int sel,
			unsigned int *v) = func;
    
    rv = f(lanc, sel, &v);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, name, v);
}
static ulp_item_t lp_uint = {uset_int, uout_int};

void
uset_ip(ipmi_cmd_info_t *cmd_info, int sel, char *val,
	ipmi_lan_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_lan_config_t *l, unsigned int sel,
			unsigned char *v, unsigned int dl) = func;
    struct in_addr v;

    ipmi_cmdlang_get_ip(val, &v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, sel, (unsigned char *) &v, sizeof(v));
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
void
uout_ip(ipmi_cmd_info_t *cmd_info, int sel, char *name,
	ipmi_lan_config_t *lanc, void *func)
{
    struct in_addr v;
    int            rv;
    int            (*f)(ipmi_lan_config_t *l, unsigned int sel,
			unsigned char *v, unsigned int *dl) = func;
    unsigned int   len = sizeof(v);
    
    rv = f(lanc, sel, (unsigned char *) &v, &len);
    if (!rv)
	ipmi_cmdlang_out_ip(cmd_info, name, &v);
}
static ulp_item_t lp_uip = {uset_ip, uout_ip};

void
uset_mac(ipmi_cmd_info_t *cmd_info, int sel, char *val,
	 ipmi_lan_config_t *lanc, void *func)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int            (*f)(ipmi_lan_config_t *l, unsigned int sel,
			unsigned char *v, unsigned int dl) = func;
    unsigned char  v[6];

    ipmi_cmdlang_get_mac(val, v, cmd_info);
    if (!cmdlang->err) {
	cmdlang->err = f(lanc, sel, v, sizeof(v));
	if (cmdlang->err) {
	    cmdlang->errstr = "Error setting parameter";
	}
    }
}
void
uout_mac(ipmi_cmd_info_t *cmd_info, int sel, char *name,
	 ipmi_lan_config_t *lanc, void *func)
{
    unsigned char v[6];
    int           rv;
    int           (*f)(ipmi_lan_config_t *l, unsigned int sel,
		       unsigned char *v, unsigned int *dl) = func;
    unsigned int  len = sizeof(v);
    
    rv = f(lanc, sel, v, &len);
    if (!rv)
	ipmi_cmdlang_out_mac(cmd_info, name, v);
}
static ulp_item_t lp_umac = {uset_mac, uout_mac};

static struct ulps_s alps[] =
{
    F(alert_ack, ubool),
    F(dest_type, uint),
    F(alert_retry_interval, uint),
    F(max_alert_retries, uint),
    F(dest_format, uint),
    F(gw_to_use, uint),
    F(dest_ip_addr, uip),
    F(dest_mac_addr, umac),
    { NULL }
};

static char *user_names[5] =
    { "callback", "user", "operator", "admin", "oem" };

static void
config_info(ipmi_cmd_info_t *cmd_info, ipmi_lan_config_t *config)
{
    int i;
    int user;
    int num;

    /* Basic items */
    for (i=0; lps[i].name; i++) {
	lp_item_t *lp = lps[i].lpi;
	lp->out(cmd_info, lps[i].name, config, lps[i].get_func);
    }

    /* per-user items */
    for (user=0; user<5; user++) {
	ipmi_cmdlang_out(cmd_info, "User", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Name", user_names[user]);
	for (i=0; ulps[i].name; i++) {
	    ulp_item_t *lp = ulps[i].lpi;
	    lp->out(cmd_info, user, ulps[i].name, config, ulps[i].get_func);
	}
	ipmi_cmdlang_up(cmd_info);
    }

    /* per-destination items */
    num = ipmi_lanconfig_get_num_alert_destinations(config);
    for (user=0; user<num; user++) {
	ipmi_cmdlang_out(cmd_info, "Alert Destination", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out_int(cmd_info, "Number", user);
	for (i=0; alps[i].name; i++) {
	    ulp_item_t *lp = alps[i].lpi;
	    lp->out(cmd_info, user, alps[i].name, config, alps[i].get_func);
	}
	ipmi_cmdlang_up(cmd_info);
    }
}

static void
lanparm_config_get_done(ipmi_lanparm_t    *lanparm,
			int               err,
			ipmi_lan_config_t *config,
			void              *cb_data)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char              lanparm_name[IPMI_LANPARM_NAME_LEN];
    lan_config_info_t *info;

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error getting LANPARM";
	cmdlang->err = err;
	goto out;
    }

    ipmi_lanparm_get_name(lanparm, lanparm_name, sizeof(lanparm_name));

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	ipmi_lan_free_config(config);
	goto out;
    }
    snprintf(info->name, sizeof(info->name), "%s.%u",
	     lanparm_name, unique_num);
    info->config = config;
    if (!locked_list_add(lancs, info, NULL)) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	ipmi_lan_free_config(config);
	ipmi_mem_free(info);
	goto out;
    }
    unique_num++;

    ipmi_cmdlang_out(cmd_info, "LANPARM Config", lanparm_name);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", info->name);
    config_info(cmd_info, config);
    ipmi_cmdlang_up(cmd_info);

 out:
    if (cmdlang->err) {
	ipmi_lanparm_get_name(lanparm, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->location = "cmd_lanparm.c(lanparm_config_get_done)";
    }
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
lanparm_config_get(ipmi_lanparm_t *lanparm, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_lan_get_config(lanparm, lanparm_config_get_done, cmd_info);
    if (rv) {
	ipmi_lanparm_get_name(lanparm, cmdlang->objstr,
			      cmdlang->objstr_len);
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error getting LANPARM";
	cmdlang->err = rv;
	cmdlang->location = "cmd_lanparm.c(lanparm_config_get)";
    }
}

static void
lanparm_config_set_done(ipmi_lanparm_t    *lanparm,
			int               err,
			void              *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    if (err) {
	ipmi_cmdlang_lock(cmd_info);
	ipmi_lanparm_get_name(lanparm, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->errstr = "Error setting LANPARM";
	cmdlang->err = err;
	cmdlang->location = "cmd_lanparm.c(lanparm_config_set_done)";
	ipmi_cmdlang_unlock(cmd_info);
    }
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
lanparm_config_set(ipmi_lanparm_t *lanparm, void *cb_data)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               rv;
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_lan_config_t *lanc;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    lanc = find_config(argv[curr_arg], 0);
    if (!lanc) {
	cmdlang->errstr = "Invalid LAN config";
	cmdlang->err = EINVAL;
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_lan_set_config(lanparm, lanc, lanparm_config_set_done, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error getting LANPARM";
	cmdlang->err = rv;
	goto out_err;
    }

    return;

 out_err:
    ipmi_lanparm_get_name(lanparm, cmdlang->objstr,
			  cmdlang->objstr_len);
    cmdlang->location = "cmd_lanparm.c(lanparm_config_set)";
}

static void
lanparm_config_unlock_done(ipmi_lanparm_t    *lanparm,
			   int               err,
			   void              *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    if (err) {
	ipmi_cmdlang_lock(cmd_info);
	ipmi_lanparm_get_name(lanparm, cmdlang->objstr,
			      cmdlang->objstr_len);
	cmdlang->errstr = "Error unlocking LANPARM";
	cmdlang->err = err;
	cmdlang->location = "cmd_lanparm.c(lanparm_config_unlock_done)";
	ipmi_cmdlang_unlock(cmd_info);
    }
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
lanparm_config_unlock(ipmi_lanparm_t *lanparm, void *cb_data)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               rv;
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_lan_config_t *lanc;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    lanc = find_config(argv[curr_arg], 0);
    if (!lanc) {
	cmdlang->errstr = "Invalid LAN config";
	cmdlang->err = EINVAL;
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_lan_clear_lock(lanparm, lanc, lanparm_config_unlock_done,
			     cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error getting LANPARM";
	cmdlang->err = rv;
	goto out_err;
    }

    return;

 out_err:
    ipmi_lanparm_get_name(lanparm, cmdlang->objstr,
			  cmdlang->objstr_len);
    cmdlang->location = "cmd_lanparm.c(lanparm_config_unlock)";
}

static void
lanparm_config_close(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_lan_config_t *lanc;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    lanc = find_config(argv[curr_arg], 1);
    if (!lanc) {
	cmdlang->errstr = "Invalid LAN config";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_lan_free_config(lanc);
    return;

 out_err:
    strncpy(cmdlang->objstr, argv[curr_arg], cmdlang->objstr_len);
    cmdlang->location = "cmd_lanparm.c(lanparm_config_close)";
}

static int
lanparm_config_list_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    lan_config_info_t *info = item1;

    ipmi_cmdlang_out(cmd_info, "Name", info->name);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
lanparm_config_list(ipmi_cmd_info_t *cmd_info)
{
    locked_list_iterate(lancs, lanparm_config_list_handler, cmd_info);
}

static int
lanparm_config_info_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_cmd_info_t   *cmd_info = cb_data;
    lan_config_info_t *info = item1;

    ipmi_cmdlang_out(cmd_info, "LANPARM Config", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", info->name);
    config_info(cmd_info, info->config);
    ipmi_cmdlang_up(cmd_info);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
lanparm_config_info(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t    *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int               curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int               argc = ipmi_cmdlang_get_argc(cmd_info);
    char              **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_lan_config_t *lanc;

    if ((argc - curr_arg) < 1) {
	locked_list_iterate(lancs, lanparm_config_info_handler, cmd_info);
    } else {
	lanc = find_config(argv[curr_arg], 1);
	if (!lanc) {
	    cmdlang->errstr = "Invalid LAN config";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
	ipmi_cmdlang_out(cmd_info, "LANPARM Config", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Name", argv[curr_arg]);
	config_info(cmd_info, lanc);
	ipmi_cmdlang_up(cmd_info);
    }
    return;

 out_err:
    strncpy(cmdlang->objstr, argv[curr_arg], cmdlang->objstr_len);
    cmdlang->location = "cmd_lanparm.c(lanparm_config_close)";
}

static void
lanparm_unlock_mc_done(ipmi_lanparm_t *lanparm, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    if (err) {
	ipmi_cmdlang_lock(cmd_info);
	ipmi_lanparm_get_name(lanparm, cmdlang->objstr,
			  cmdlang->objstr_len);
	cmdlang->errstr = "Error unlocking MC LANPARM";
	cmdlang->err = err;
	cmdlang->location = "cmd_lanparm.c(lanparm_unlock_mc_done)";
	ipmi_cmdlang_unlock(cmd_info);
    }

    ipmi_lanparm_destroy(lanparm, NULL, NULL);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
lanparm_unlock_mc(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             channel;
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_lanparm_t  *lanparm;

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

    rv = ipmi_lanparm_alloc(mc, channel, &lanparm);
    if (rv) {
	cmdlang->errstr = "Error from ipmi_lanparm_alloc";
	cmdlang->err = rv;
	goto out_err;
    }

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_lan_clear_lock(lanparm, NULL, lanparm_unlock_mc_done, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error from ipmi_lan_clear_lock";
	cmdlang->err = rv;
	ipmi_lanparm_destroy(lanparm, NULL, NULL);
	goto out_err;
    }
    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_lanparm.c(lanparm_unlock_mc)";
}

static ipmi_cmdlang_cmd_t *lanparm_cmds;
static ipmi_cmdlang_cmd_t *config_cmds;

static ipmi_cmdlang_init_t cmds_lanparm[] =
{
    { "lanparm", NULL,
      "- Commands dealing with LAN Parameters (lanparms)",
      NULL, NULL, &lanparm_cmds},
    { "list", &lanparm_cmds,
      "- List all the lanparms in the system",
      ipmi_cmdlang_domain_handler, lanparm_list,  NULL },
    { "new", &lanparm_cmds,
      "<mc> <channel>"
      " - Set up the MC to send LANPARM traps from the given connection"
      " to the given IP/MAC address over the given channel",
      ipmi_cmdlang_mc_handler, lanparm_new, NULL },
    { "info", &lanparm_cmds,
      "<lanparm> - Dump information about a lanparm",
      ipmi_cmdlang_lanparm_handler, lanparm_info, NULL },
    { "config", &lanparm_cmds,
      "- Commands dealing with LANPARM configs",
      NULL, NULL, &config_cmds },
    { "list", &config_cmds,
      "- List the lan configurations that currently exist",
      lanparm_config_list, NULL, NULL },
    { "info", &config_cmds,
      "<config> - List info on lan configuration",
      lanparm_config_info, NULL, NULL },
    { "get", &config_cmds,
      "<lanparm> - Fetch the LAN information for the lanparm",
      ipmi_cmdlang_lanparm_handler, lanparm_config_get, NULL },
    { "set", &config_cmds,
      "<lanparm> <config> - Set the LAN information for the lanparm",
      ipmi_cmdlang_lanparm_handler, lanparm_config_set, NULL },
    { "unlock", &config_cmds,
      "<lanparm> <config> - Unlock, but do not set the config",
      ipmi_cmdlang_lanparm_handler, lanparm_config_unlock, NULL },
    { "close", &config_cmds,
      "<config> - free the config",
      lanparm_config_close, NULL, NULL },
    { "unlock_mc", &lanparm_cmds,
      "<mc> <channel> - Unlock the lanparms for the given mc/channel",
      ipmi_cmdlang_mc_handler, lanparm_unlock_mc, NULL },
    { "close", &lanparm_cmds,
      "<lanparm> - Close the lanparm",
      ipmi_cmdlang_lanparm_handler, lanparm_close, NULL },
};
#define CMDS_LANPARM_LEN (sizeof(cmds_lanparm)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_lanparm_init(void)
{
    int rv;

    lancs = locked_list_alloc(ipmi_get_global_os_handler());
    if (!lancs)
	return ENOMEM;

    rv = ipmi_cmdlang_reg_table(cmds_lanparm, CMDS_LANPARM_LEN);
    if (rv) {
	locked_list_destroy(lancs);
	lancs = NULL;
    }

    return rv;
}

static int
config_destroy_handler(void *cb_data, void *item1, void *item2)
{
    lan_config_info_t *info = item1;

    ipmi_lan_free_config(info->config);
    ipmi_mem_free(info);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_cmdlang_lanparm_shutdown(void)
{
    locked_list_iterate(lancs, config_destroy_handler, NULL);
    locked_list_destroy(lancs);
    lancs = NULL;
}
