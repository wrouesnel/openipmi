/*
 * cmd_domain.c
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
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_sdr.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_auth.h>

/* Internal includes, do not use in your programs */
#include <OpenIPMI/internal/ipmi_malloc.h>

static void
mc_list_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    ipmi_cmdlang_out(cmd_info, "Name", mc_name);
}

static void
mc_list(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char             domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "Domain", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
    ipmi_cmdlang_out(cmd_info, "MCs", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_domain_iterate_mcs(domain, mc_list_handler, cmd_info);
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static void
mc_dump(ipmi_mc_t *mc, ipmi_cmd_info_t *cmd_info)
{
    unsigned char   vals[4];
    char            str[100];

    ipmi_cmdlang_out_bool(cmd_info, "Active", ipmi_mc_is_active(mc));
    ipmi_cmdlang_out_int(cmd_info, "SEL Rescan Time",
			 ipmi_mc_get_sel_rescan_time(mc));
    ipmi_cmdlang_out_bool(cmd_info, "provides_device_sdrs",
			  ipmi_mc_provides_device_sdrs(mc));
    ipmi_cmdlang_out_bool(cmd_info, "device_available",
			  ipmi_mc_device_available(mc));
    ipmi_cmdlang_out_bool(cmd_info, "chassis_support",
			  ipmi_mc_chassis_support(mc));
    ipmi_cmdlang_out_bool(cmd_info, "bridge_support",
			  ipmi_mc_bridge_support(mc));
    ipmi_cmdlang_out_bool(cmd_info, "ipmb_event_generator",
			  ipmi_mc_ipmb_event_generator_support(mc));
    ipmi_cmdlang_out_bool(cmd_info, "ipmb_event_receiver",
			  ipmi_mc_ipmb_event_receiver_support(mc));
    ipmi_cmdlang_out_bool(cmd_info, "fru_inventory_support",
			  ipmi_mc_fru_inventory_support(mc));
    ipmi_cmdlang_out_bool(cmd_info, "sel_device_support",
			  ipmi_mc_sel_device_support(mc));
    ipmi_cmdlang_out_bool(cmd_info, "sdr_repository_support",
			  ipmi_mc_sdr_repository_support(mc));
    ipmi_cmdlang_out_bool(cmd_info, "sensor_device_support",
			  ipmi_mc_sensor_device_support(mc));
    ipmi_cmdlang_out_hex(cmd_info, "device_id", ipmi_mc_device_id(mc));
    ipmi_cmdlang_out_int(cmd_info, "device_revision",
			 ipmi_mc_device_revision(mc));
    snprintf(str, sizeof(str), "%d.%d%d",
	     ipmi_mc_major_fw_revision(mc),
	     ipmi_mc_minor_fw_revision(mc)>>4,
	     ipmi_mc_minor_fw_revision(mc)&0xf);
    ipmi_cmdlang_out(cmd_info, "fw_revision", str);
    snprintf(str, sizeof(str), "%d.%d",
	     ipmi_mc_major_version(mc),
	     ipmi_mc_minor_version(mc));
    ipmi_cmdlang_out(cmd_info, "version", str);
    ipmi_cmdlang_out_hex(cmd_info, "manufacturer_id",
			 ipmi_mc_manufacturer_id(mc));
    ipmi_cmdlang_out_hex(cmd_info, "product_id", ipmi_mc_product_id(mc));
    ipmi_mc_aux_fw_revision(mc, vals);
    ipmi_cmdlang_out_binary(cmd_info, "aux_fw_revision", vals, sizeof(vals));
}

static void
mc_info(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    ipmi_cmdlang_out(cmd_info, "MC", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", mc_name);
    mc_dump(mc, cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static void
mc_reset_done(ipmi_mc_t *mc, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error resetting MC";
	cmdlang->err = err;
	ipmi_mc_get_name(mc, cmdlang->objstr,
			 cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(mc_reset_done)";
	goto out;
    }

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    ipmi_cmdlang_out(cmd_info, "Reset done", mc_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
mc_reset(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             cmd;
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    if (strcasecmp(argv[curr_arg], "warm") == 0)
	cmd = IPMI_MC_RESET_WARM;
    else if (strcasecmp(argv[curr_arg], "cold") == 0)
	cmd = IPMI_MC_RESET_COLD;
    else {
	cmdlang->errstr = "reset type not 'warm' or 'cold'";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_reset(mc, cmd, mc_reset_done, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error from ipmi_mc_reset";
	cmdlang->err = EINVAL;
	goto out_err;
    }

 out_err:
    if (cmdlang->err) {
	ipmi_mc_get_name(mc, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(mc_reset)";
    }
}

static void
set_events_enable_done(ipmi_mc_t *mc, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error setting events enable";
	cmdlang->err = err;
	ipmi_mc_get_name(mc, cmdlang->objstr,
			 cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(set_events_enable_done)";
	goto out;
    }

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    ipmi_cmdlang_out(cmd_info, "Events enable done", mc_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
mc_set_events_enable(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             enable;
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    if (strcasecmp(argv[curr_arg], "enable") == 0)
	enable = 1;
    else if (strcasecmp(argv[curr_arg], "disable") == 0)
	enable = 0;
    else {
	cmdlang->errstr = "enable type not 'enable' or 'disable'";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_set_events_enable(mc, enable, set_events_enable_done,
				   cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error from ipmi_mc_set_events_enable";
	cmdlang->err = EINVAL;
	goto out_err;
    }

 out_err:
    if (cmdlang->err) {
	ipmi_mc_get_name(mc, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(mc_set_events_enable)";
    }
}

static void
mc_get_events_enable(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    
    ipmi_cmdlang_out_bool(cmd_info, "Events Enable",
			  ipmi_mc_get_events_enable(mc));
}

static void
mc_sel_info(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            str[20];
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    ipmi_cmdlang_out(cmd_info, "MC", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", mc_name);
    snprintf(str, sizeof(str), "%d.%d", 
	     ipmi_mc_sel_get_major_version(mc),
	     ipmi_mc_sel_get_num_entries(mc));
    ipmi_cmdlang_out(cmd_info, "SEL Version", str);
    ipmi_cmdlang_out_int(cmd_info, "SEL Count", ipmi_mc_sel_count(mc));
    ipmi_cmdlang_out_int(cmd_info, "SEL Slots Used",
			 ipmi_mc_sel_entries_used(mc));
    ipmi_cmdlang_out_int(cmd_info, "SEL Free Bytes",
			 ipmi_mc_sel_get_free_bytes(mc));
    ipmi_cmdlang_out_int(cmd_info, "SEL Last Addition Timestamp",
			 ipmi_mc_sel_get_last_addition_timestamp(mc));
    ipmi_cmdlang_out_bool(cmd_info, "SEL overflow",
			  ipmi_mc_sel_get_overflow(mc));
    ipmi_cmdlang_out_bool(cmd_info, "SEL Supports Delete",
			  ipmi_mc_sel_get_supports_delete_sel(mc));
    ipmi_cmdlang_out_bool(cmd_info, "SEL Supports Partial Add",
			  ipmi_mc_sel_get_supports_partial_add_sel(mc));
    ipmi_cmdlang_out_bool(cmd_info, "SEL Supports Reserve",
			  ipmi_mc_sel_get_supports_reserve_sel(mc));
    ipmi_cmdlang_out_bool(cmd_info, "SEL Supports Get SEL Allocation",
			  ipmi_mc_sel_get_supports_get_sel_allocation(mc));
    ipmi_cmdlang_up(cmd_info);
}

static void
get_sel_time_handler(ipmi_mc_t *mc, int err, unsigned long time, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error getting SEL time";
	cmdlang->err = err;
	ipmi_mc_get_name(mc, cmdlang->objstr,
			 cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(get_sel_time_handler)";
    } else {
	ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
	ipmi_cmdlang_out(cmd_info, "MC", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Name", mc_name);
	ipmi_cmdlang_out_long(cmd_info, "SEL Time", time);
	ipmi_cmdlang_up(cmd_info);
    }
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
mc_get_sel_time(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_get_current_sel_time(mc, get_sel_time_handler, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error from ipmi_mc_get_current_sel_time";
	cmdlang->err = EINVAL;
	ipmi_mc_get_name(mc, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(mc_get_sel_time)";
    }
}

static void
set_sel_time_handler(ipmi_mc_t *mc, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	cmdlang->errstr = "Error Setting SEL time";
	cmdlang->err = err;
	ipmi_mc_get_name(mc, cmdlang->objstr,
			 cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(get_sel_time_handler)";
    } else {
	ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
	ipmi_cmdlang_out(cmd_info, "MC SEL time set", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Name", mc_name);
	ipmi_cmdlang_up(cmd_info);
    }
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
mc_set_sel_time(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;
    int             time;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    struct timeval  tv;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &time, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "time invalid";
	goto out_err;
    }
    curr_arg++;

    tv.tv_sec = time;
    tv.tv_usec = 0;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_set_current_sel_time(mc, &tv, set_sel_time_handler, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error from ipmi_mc_get_current_sel_time";
	cmdlang->err = EINVAL;
	ipmi_mc_get_name(mc, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(mc_get_sel_time)";
    }

 out_err:
    if (cmdlang->err) {
	ipmi_mc_get_name(mc, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(mc_set_sel_time)";
    }
}

static void
mc_rescan_sel_done(ipmi_mc_t *mc, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	if (! cmdlang->err) {
	    cmdlang->err = err;
	    cmdlang->errstr = "Error scanning SELs";
	    ipmi_mc_get_name(mc, cmdlang->objstr,
				 cmdlang->objstr_len);
	    cmdlang->location = "cmd_mc.c(sel_rescan_done)";
	}
	goto out;
    }

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    ipmi_cmdlang_out(cmd_info, "SEL Rescan done", mc_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
mc_rescan_sels(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_reread_sel(mc, mc_rescan_sel_done, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error requesting SEL rescan";
	cmdlang->err = rv;
	goto out_err;
    }
    
 out_err:
    if (cmdlang->err) {
	ipmi_mc_get_name(mc, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(mc_rescan_sels)";
    }
}

static void
mc_sel_rescan_time(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             time;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &time, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "time invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_mc_set_sel_rescan_time(mc, time);

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    ipmi_cmdlang_out(cmd_info, "MC SEL rescan time set", mc_name);

 out_err:
    if (cmdlang->err) {
	ipmi_mc_get_name(mc, cmdlang->objstr,
			 cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(mc_sel_rescan_time)";
    }
}


static void
mc_msg_handler(ipmi_mc_t *mc, ipmi_msg_t *msg, void *cb_data)
{
    ipmi_cmd_info_t  *cmd_info = cb_data;
    char             mc_name[IPMI_MC_NAME_LEN];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Response", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    ipmi_cmdlang_out_int(cmd_info, "NetFN", msg->netfn);
    ipmi_cmdlang_out_int(cmd_info, "command", msg->cmd);
    if (msg->data_len)
	ipmi_cmdlang_out_binary(cmd_info, "Data", msg->data, msg->data_len);
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_unlock(cmd_info);

    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
mc_msg(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             LUN;
    int             NetFN;
    int             command;
    unsigned char   data[100];
    int             rv;
    int             i;
    ipmi_msg_t      msg;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);


    if ((argc - curr_arg) < 3) {
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg],
			 &LUN, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "LUN invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg],
			 &NetFN, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "NetFN invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg],
			 &command, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "command invalid";
	goto out_err;
    }
    curr_arg++;

    i = 0;
    while (curr_arg < argc) {
	ipmi_cmdlang_get_uchar(argv[curr_arg],
			       &data[i], cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "data invalid";
	    goto out_err;
	}
	curr_arg++;
	i++;
    }

    msg.netfn = NetFN;
    msg.cmd = command;
    msg.data_len = i;
    msg.data = data;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_send_command(mc,
			      LUN,
			      &msg,
			      mc_msg_handler,
			      cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error sending message";
	cmdlang->err = rv;
	goto out_err;
    }

    return;

 out_err:
    if (cmdlang->err) {
	ipmi_mc_get_name(mc, cmdlang->objstr,
			 cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(mc_msg)";
    }
}

typedef struct sdr_info_s
{
    ipmi_cmd_info_t *cmd_info;
    char            mc_name[IPMI_MC_NAME_LEN];
} sdr_info_t;

void
sdrs_fetched(ipmi_sdr_info_t *sdrs,
	     int             err,
	     int             changed,
	     unsigned int    count,
	     void            *cb_data)
{
    sdr_info_t      *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             i;
    int             rv;
    int             total_size = 0;

    if (err) {
	cmdlang->err = err;
	cmdlang->errstr = "Error fetchding SDRs";
	goto out_err;
    }

    if (!sdrs) {
	cmdlang->err = ECANCELED;
	cmdlang->errstr = "MC went away during SDR fetch";
	goto out_err;
    }

    ipmi_cmdlang_out(cmd_info, "MC", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", info->mc_name);
    for (i=0; i<count; i++) {
	ipmi_sdr_t sdr;
	char       str[20];

	rv = ipmi_get_sdr_by_index(sdrs, i, &sdr);
	if (rv)
	    continue;

        ipmi_cmdlang_out(cmd_info, "SDR", NULL);
	ipmi_cmdlang_down(cmd_info);
        ipmi_cmdlang_out_int(cmd_info, "Record ID", sdr.record_id);
        ipmi_cmdlang_out_int(cmd_info, "Type", sdr.type);
	snprintf(str, sizeof(str), "%d.%d", sdr.major_version,
		 sdr.minor_version);
        ipmi_cmdlang_out(cmd_info, "Version", str);
	ipmi_cmdlang_out_binary(cmd_info, "Data", sdr.data, sdr.length);
	ipmi_cmdlang_up(cmd_info);
	total_size += sdr.length+5;
    }
    ipmi_cmdlang_out_int(cmd_info, "Total Size", total_size);
    ipmi_cmdlang_up(cmd_info);

 out_err:
    if (cmdlang->err) {
	cmdlang->location = "cmd_mc.c(sdrs_fetched)";
    }
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_sdr_info_destroy(sdrs, NULL, NULL);
    ipmi_mem_free(info);
}

static void
mc_sdrs(ipmi_mc_t *mc, void *cb_data)
{
    sdr_info_t      *info = NULL;
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             do_sensor;
    ipmi_sdr_info_t *sdrs;
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);


    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    if (strcmp(argv[curr_arg], "main") == 0) {
	do_sensor = 0;
    } else if (strcmp(argv[curr_arg], "sensor") == 0) {
	do_sensor = 1;
    } else {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "Fetch type was not sensor or main";
	goto out_err;
    }
    curr_arg++;

    rv = ipmi_sdr_info_alloc(ipmi_mc_get_domain(mc),
			     mc, 0, do_sensor, &sdrs);
    if (rv) {
	cmdlang->err = rv;
	cmdlang->errstr = "Could not allocate SDR info";
	goto out_err;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->err = ENOMEM;
	cmdlang->errstr = "Could not allocate SDR data";
	goto out_err;
    }
    info->cmd_info = cmd_info;
    ipmi_mc_get_name(mc, info->mc_name, sizeof(info->mc_name));

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_sdr_fetch(sdrs, sdrs_fetched, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Could not start SDR fetch";
	ipmi_sdr_info_destroy(sdrs, NULL, NULL);
	goto out_err;
    }

    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr, cmdlang->objstr_len);
    cmdlang->location = "cmd_mc.c(mc_sdrs)";
    if (info)
	ipmi_mem_free(info);
}

void
got_chan_info(ipmi_mc_t  *mc,
	      ipmi_msg_t *rsp,
	      void       *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];
    char            *str;

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    if (rsp->data[0] != 0) {
	cmdlang->err = IPMI_IPMI_ERR_VAL(rsp->data[0]);
	cmdlang->errstr = "Error getting channel info";
	goto out_err;
    }

    if (rsp->data_len < 10) {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "Channel info response too small";
	goto out_err;
    }

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Channel Info", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    ipmi_cmdlang_out_int(cmd_info, "Channel", rsp->data[1] & 0xf);
    ipmi_cmdlang_out_int(cmd_info, "Medium", rsp->data[2] & 0x7f);
    ipmi_cmdlang_out_int(cmd_info, "Protocol Type", rsp->data[3] & 0x1f);
    switch (rsp->data[4] >> 6) {
    case 0: str = "session-less"; break;
    case 1: str = "single-session"; break;
    case 2: str = "multi-session"; break;
    case 3: str = "session-based"; break;
    default: str = "unknown";
    }
    ipmi_cmdlang_out(cmd_info, "Session Support", str);
    ipmi_cmdlang_out_binary(cmd_info, "Vendor ID", rsp->data+5, 3);
    ipmi_cmdlang_out_binary(cmd_info, "Aux Info", rsp->data+8, 2);
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_unlock(cmd_info);

 out_err:
    if (cmdlang->err) {
	cmdlang->location = "cmd_mc.c(got_chan_info)";
    }

    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
mc_get_chan_info(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_msg_t      msg;
    unsigned char   data[1];
    int             channel;


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

    data[0] = channel & 0xf;
    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_CHANNEL_INFO_CMD;
    msg.data = data;
    msg.data_len = 1;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_send_command(mc, 0, &msg, got_chan_info, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Could not send command";
	goto out_err;
    }

    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr, cmdlang->objstr_len);
    cmdlang->location = "cmd_mc.c(mc_get_chan_info)";
}

typedef struct get_chan_info_s
{
    char            *type;
    ipmi_cmd_info_t *cmd_info;
    int             channel;
} get_chan_info_t;

void
got_chan_access(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *cb_data)
{
    get_chan_info_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];
    char            *str;

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    if (rsp->data[0] != 0) {
	cmdlang->err = IPMI_IPMI_ERR_VAL(rsp->data[0]);
	cmdlang->errstr = "Error getting channel access info";
	goto out_err;
    }

    if (rsp->data_len < 3) {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "Channel access response too small";
	goto out_err;
    }

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Channel Access", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    ipmi_cmdlang_out_int(cmd_info, "Channel", info->channel);
    ipmi_cmdlang_out(cmd_info, "Type", info->type);
    ipmi_cmdlang_out_bool(cmd_info, "Alerting Enabled", rsp->data[1] & 0x20);
    ipmi_cmdlang_out_bool(cmd_info, "Per-Message Auth", rsp->data[1] & 0x10);
    ipmi_cmdlang_out_bool(cmd_info, "User Auth", rsp->data[1] & 0x08);
    switch (rsp->data[1] & 0x7) {
    case 0: str = "disabled"; break;
    case 1: str = "pre-boot"; break;
    case 2: str = "always"; break;
    case 3: str = "shared"; break;
    default: str = "unknown";
    }
    ipmi_cmdlang_out(cmd_info, "Access Mode", str);
    ipmi_cmdlang_out(cmd_info, "Privilege Limit",
		     ipmi_privilege_string(rsp->data[2] & 0xf));
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_unlock(cmd_info);

 out_err:
    if (cmdlang->err) {
	cmdlang->location = "cmd_mc.c(got_chan_access)";
    }

    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static void
mc_get_chan_access(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_msg_t      msg;
    unsigned char   data[2];
    int             channel;
    get_chan_info_t *present = NULL;
    get_chan_info_t *non_volatile = NULL;


    if ((argc - curr_arg) < 2) {
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

    if (strcmp(argv[curr_arg], "non-volatile") == 0) {
	non_volatile = ipmi_mem_alloc(sizeof(*non_volatile));
	if (!non_volatile) {
	    cmdlang->err = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	}
    } else if (strcmp(argv[curr_arg], "present") == 0) {
	present = ipmi_mem_alloc(sizeof(*present));
	if (!present) {
	    cmdlang->err = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	}
    } else if (strcmp(argv[curr_arg], "both") == 0) {
	non_volatile = ipmi_mem_alloc(sizeof(*non_volatile));
	if (!non_volatile) {
	    cmdlang->err = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	}
	present = ipmi_mem_alloc(sizeof(*present));
	if (!present) {
	    ipmi_mem_free(non_volatile);
	    cmdlang->err = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	}
    } else {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "fetch type invalid";
	goto out_err;
    }

    if (present) {
	present->type = "present";
	present->cmd_info = cmd_info;
	present->channel = channel;
	data[0] = channel & 0xf;
	data[1] = 0x80;
	msg.netfn = IPMI_APP_NETFN;
	msg.cmd = IPMI_GET_CHANNEL_ACCESS_CMD;
	msg.data = data;
	msg.data_len = 2;

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_mc_send_command(mc, 0, &msg, got_chan_access, present);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->err = rv;
	    cmdlang->errstr = "Could not send command to get present value";
	    ipmi_mem_free(present);
	}
    }

    if (non_volatile) {
	non_volatile->type = "non-volatile";
	non_volatile->cmd_info = cmd_info;
	non_volatile->channel = channel;
	data[0] = channel & 0xf;
	data[1] = 0x40;
	msg.netfn = IPMI_APP_NETFN;
	msg.cmd = IPMI_GET_CHANNEL_ACCESS_CMD;
	msg.data = data;
	msg.data_len = 2;

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_mc_send_command(mc, 0, &msg, got_chan_access, non_volatile);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->err = rv;
	    cmdlang->errstr = "Could not send command to get non-volatile"
		" value";
	    ipmi_mem_free(non_volatile);
	}
    }

    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr, cmdlang->objstr_len);
    cmdlang->location = "cmd_mc.c(mc_get_chan_access)";
}

typedef struct set_chan_parm_s
{
    int alert_set;
    int alert_val;
    int msg_auth_set;
    int msg_auth_val;
    int user_auth_set;
    int user_auth_val;
    int access_mode_set;
    int access_mode_val;
    int privilege_set;
    int privilege_val;
} set_chan_parm_t;

typedef struct set_chan_info_s
{
    char            *type;
    int             set_type;
    ipmi_cmd_info_t *cmd_info;
    set_chan_parm_t parms;
    int             channel;
} set_chan_info_t;

void
set_chan_access2(ipmi_mc_t  *mc,
		 ipmi_msg_t *rsp,
		 void       *cb_data)
{
    set_chan_info_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    if (rsp->data[0] != 0) {
	cmdlang->err = IPMI_IPMI_ERR_VAL(rsp->data[0]);
	cmdlang->errstr = "Error getting channel info";
	goto out_err;
    }

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Channel Access Set", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    ipmi_cmdlang_out_int(cmd_info, "Channel", info->channel);
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_unlock(cmd_info);

 out_err:
    if (cmdlang->err) {
	cmdlang->location = "cmd_mc.c(set_chan_access2)";
    }

    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

void
set_chan_access1(ipmi_mc_t  *mc,
		 ipmi_msg_t *rsp,
		 void       *cb_data)
{
    set_chan_info_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];
    ipmi_msg_t      msg;
    unsigned char   data[3];
    int             rv;

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    if (rsp->data[0] != 0) {
	cmdlang->err = IPMI_IPMI_ERR_VAL(rsp->data[0]);
	cmdlang->errstr = "Error getting channel info";
	goto out_err;
    }

    if (rsp->data_len < 3) {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "Channel access info response too small";
	goto out_err;
    }

    data[0] = info->channel & 0xf;
    data[1] = info->set_type | (rsp->data[1] & 0x3f);
    data[2] = info->set_type | (rsp->data[2] & 0x0f);
    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_SET_CHANNEL_ACCESS_CMD;
    msg.data = data;
    msg.data_len = 3;

    if (info->parms.alert_set)
	data[1] = (data[1] & ~0x20) | info->parms.alert_val;
    if (info->parms.msg_auth_set)
	data[1] = (data[1] & ~0x10) | info->parms.msg_auth_val;
    if (info->parms.user_auth_set)
	data[1] = (data[1] & ~0x08) | info->parms.user_auth_val;
    if (info->parms.access_mode_set)
	data[1] = (data[1] & ~0x07) | info->parms.access_mode_val;
    if (info->parms.privilege_set)
	data[2] = (data[2] & ~0x0f) | info->parms.privilege_val;

    rv = ipmi_mc_send_command(mc, 0, &msg, set_chan_access2, info);
    if (rv) {
	cmdlang->err = rv;
	cmdlang->errstr = "Could not send command to get present value";
	goto out_err;
    }

    return;

 out_err:
    if (cmdlang->err) {
	cmdlang->location = "cmd_mc.c(set_chan_access1)";
    }

    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static void
mc_set_chan_access(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    ipmi_msg_t      msg;
    unsigned char   data[2];
    int             channel;
    set_chan_info_t *present = NULL;
    set_chan_info_t *non_volatile = NULL;
    set_chan_parm_t parms;

    if ((argc - curr_arg) < 2) {
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

    if (strcmp(argv[curr_arg], "non-volatile") == 0) {
	non_volatile = ipmi_mem_alloc(sizeof(*non_volatile));
	if (!non_volatile) {
	    cmdlang->err = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	    goto out_err;
	}
    } else if (strcmp(argv[curr_arg], "present") == 0) {
	present = ipmi_mem_alloc(sizeof(*present));
	if (!present) {
	    cmdlang->err = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	    goto out_err;
	}
    } else if (strcmp(argv[curr_arg], "both") == 0) {
	non_volatile = ipmi_mem_alloc(sizeof(*non_volatile));
	if (!non_volatile) {
	    cmdlang->err = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	    goto out_err;
	}
	present = ipmi_mem_alloc(sizeof(*present));
	if (!present) {
	    ipmi_mem_free(non_volatile);
	    cmdlang->err = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	    goto out_err;
	}
    } else {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "fetch type invalid";
	goto out_err;
    }
    curr_arg++;

    memset(&parms, 0, sizeof(parms));

    while (curr_arg < argc) {
	if (strcmp(argv[curr_arg], "alert") == 0) {
	    parms.alert_set = 0x20;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no alert value";
		goto out_err;
	    }
	    ipmi_cmdlang_get_bool(argv[curr_arg], &parms.alert_val, cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "invalid alert value";
		goto out_err;
	    }
	    parms.alert_val <<= 5;
	} else if (strcmp(argv[curr_arg], "msg_auth") == 0) {
	    parms.msg_auth_set = 0x20;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no msg_auth value";
		goto out_err;
	    }
	    ipmi_cmdlang_get_bool(argv[curr_arg], &parms.msg_auth_val,
				  cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "invalid msg_auth value";
		goto out_err;
	    }
	    parms.msg_auth_val <<= 4;
	} else if (strcmp(argv[curr_arg], "user_auth") == 0) {
	    parms.user_auth_set = 0x08;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no user_auth value";
		goto out_err;
	    }
	    ipmi_cmdlang_get_bool(argv[curr_arg], &parms.user_auth_val,
				  cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "invalid user_auth value";
		goto out_err;
	    }
	    parms.user_auth_val <<= 3;
	} else if (strcmp(argv[curr_arg], "access_mode") == 0) {
	    parms.access_mode_set = 0x7;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no access_mode value";
		goto out_err;
	    }
	    if (strcmp(argv[curr_arg], "disabled") == 0) {
		parms.access_mode_val = 0;
	    } else if (strcmp(argv[curr_arg], "pre-boot") == 0) {
		parms.access_mode_val = 1;
	    } else if (strcmp(argv[curr_arg], "always") == 0) {
		parms.access_mode_val = 2;
	    } else if (strcmp(argv[curr_arg], "shared") == 0) {
		parms.access_mode_val = 3;
	    } else {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "invalid access_mode value";
		goto out_err;
	    }
	} else if (strcmp(argv[curr_arg], "privilege_limit") == 0) {
	    parms.privilege_set = 0xf;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no privilege_limit value";
		goto out_err;
	    }
	    if (strcmp(argv[curr_arg], "callback") == 0) {
		parms.privilege_val = IPMI_PRIVILEGE_CALLBACK;
	    } else if (strcmp(argv[curr_arg], "user") == 0) {
		parms.privilege_val = IPMI_PRIVILEGE_USER;
	    } else if (strcmp(argv[curr_arg], "operator") == 0) {
		parms.privilege_val = IPMI_PRIVILEGE_OPERATOR;
	    } else if (strcmp(argv[curr_arg], "admin") == 0) {
		parms.privilege_val = IPMI_PRIVILEGE_ADMIN;
	    } else if (strcmp(argv[curr_arg], "oem") == 0) {
		parms.privilege_val = IPMI_PRIVILEGE_OEM;
	    } else {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "invalid privilege_limit value";
		goto out_err;
	    }
	} else {
	    cmdlang->err = EINVAL;
	    cmdlang->errstr = "invalid setting";
	    goto out_err;
	}
	curr_arg++;
    }

    if (present) {
	present->type = "present";
	present->cmd_info = cmd_info;
	present->parms = parms;
	present->channel = channel;
	present->set_type = 0x80;
	data[0] = channel & 0xf;
	data[1] = 0x80;
	msg.netfn = IPMI_APP_NETFN;
	msg.cmd = IPMI_GET_CHANNEL_ACCESS_CMD;
	msg.data = data;
	msg.data_len = 2;

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_mc_send_command(mc, 0, &msg, set_chan_access1, present);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->err = rv;
	    cmdlang->errstr = "Could not send command to get present value";
	    ipmi_mem_free(present);
	}
    }

    if (non_volatile) {
	non_volatile->type = "non-volatile";
	non_volatile->cmd_info = cmd_info;
	non_volatile->parms = parms;
	non_volatile->set_type = 0x40;
	non_volatile->channel = channel;
	data[0] = channel & 0xf;
	data[1] = 0x40;
	msg.netfn = IPMI_APP_NETFN;
	msg.cmd = IPMI_GET_CHANNEL_ACCESS_CMD;
	msg.data = data;
	msg.data_len = 2;

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_mc_send_command(mc, 0, &msg, set_chan_access1, non_volatile);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->err = rv;
	    cmdlang->errstr = "Could not send command to get non-volatile"
		" value";
	    ipmi_mem_free(non_volatile);
	}
    }

    return;

 out_err:
    if (non_volatile)
	ipmi_mem_free(non_volatile);
    if (present)
	ipmi_mem_free(present);
    ipmi_mc_get_name(mc, cmdlang->objstr, cmdlang->objstr_len);
    cmdlang->location = "cmd_mc.c(mc_get_chan_access)";
}

typedef struct user_info_s
{
    int  num;
    int  link_enabled;
    int  msg_enabled;
    int  privilege_limit;
    int  cb_only;
    char name[17];
} user_info_t;

typedef struct user_list_s
{
    int             channel;
    int             curr;
    int             max;
    int             idx;
    ipmi_cmd_info_t *cmd_info;
    user_info_t     *users;
} user_list_t;

static int list_next_user(ipmi_mc_t *mc, user_list_t *info);

static void
user_list_done(ipmi_mc_t *mc, user_list_t *info)
{
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    char            mc_name[IPMI_MC_NAME_LEN];
    int             i, j, k;
    char            *str;

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "User", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    ipmi_cmdlang_out_int(cmd_info, "Channel", info->channel);
    for (i=0; i<info->idx; i++) {
	ipmi_cmdlang_out(cmd_info, "User", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out_int(cmd_info, "Number", info->users[i].num);
	str = info->users[i].name;
	for (j=15; j>=0; j--) {
	    if (str[j] != '\0')
		break;
	}
	for (k=0; k<=j; k++) {
	    if (! isprint(str[k])) {
		str = NULL;
		break;
	    }
	}
	if (str)
	    ipmi_cmdlang_out(cmd_info, "String Name", str);
	else
	    ipmi_cmdlang_out_binary(cmd_info, "Binary Name",
				    info->users[i].name, 16);
	ipmi_cmdlang_out_bool(cmd_info, "Link Auth Enabled",
			      info->users[i].link_enabled);
	ipmi_cmdlang_out_bool(cmd_info, "Msg Auth Enabled",
			      info->users[i].msg_enabled);
	ipmi_cmdlang_out_bool(cmd_info, "Access CB Only",
			      info->users[i].cb_only);
	ipmi_cmdlang_up(cmd_info);
    }
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
    if (info->users)
	ipmi_mem_free(info->users);
    ipmi_mem_free(info);
}

static void
got_user2(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    user_list_t     *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    if (rsp->data[0] != 0) {
	cmdlang->err = IPMI_IPMI_ERR_VAL(rsp->data[0]);
	cmdlang->errstr = "Error getting user name";
	goto out_err;
    }

    if (rsp->data_len < 17) {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "User name response too small";
	goto out_err;
    }

    memcpy(info->users[info->idx].name, rsp->data+1, 16);
    info->users[info->idx].name[16] = '\0';

    if (info->curr >= info->max)
	user_list_done(mc, info);
    else {
	info->curr++;
	info->idx++;
	rv = list_next_user(mc, info);
	if (rv) {
	    cmdlang->err = rv;
	    cmdlang->errstr = "Error sending get user name cmd";
	    goto out_err;
	}
    }
    return;

 out_err:
    cmdlang->location = "cmd_mc.c(got_user2)";
    ipmi_cmdlang_cmd_info_put(cmd_info);
    if (info->users)
	ipmi_mem_free(info->users);
    ipmi_mem_free(info);
}

static void
got_user1(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    user_list_t     *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;
    int             idx;
    ipmi_msg_t      msg;
    unsigned char   data[1];


    if (rsp->data[0] != 0) {
	cmdlang->err = IPMI_IPMI_ERR_VAL(rsp->data[0]);
	cmdlang->errstr = "Error getting user info";
	goto out_err;
    }

    if (rsp->data_len < 5) {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "User access info response too small";
	goto out_err;
    }

    if (! info->users) {
	if (info->max == 0)
	    info->max = rsp->data[1] & 0x1f;
	if (info->max < 1) {
	    cmdlang->err = EINVAL;
	    cmdlang->errstr = "User access user count is zero";
	    goto out_err;
	}
	info->users = ipmi_mem_alloc(sizeof(user_info_t)
				     * (info->max - info->curr + 1));
	if (!info->users) {
	    cmdlang->err = ENOMEM;
	    cmdlang->errstr = "Could not allocate user info array";
	    goto out_err;
	}
	memset(info->users, 0,
	       sizeof(user_info_t) * (info->max - info->curr + 1));
    }

    idx = info->idx;
    info->users[idx].num = info->curr;
    info->users[idx].cb_only = (rsp->data[4] >> 6) & 1;
    info->users[idx].link_enabled = (rsp->data[4] >> 5) & 1;
    info->users[idx].msg_enabled = (rsp->data[4] >> 4) & 1;
    info->users[idx].privilege_limit = rsp->data[4] & 0x0f;

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_USER_NAME_CMD;
    msg.data = data;
    msg.data_len = 1;
    data[0] = info->curr;

    rv = ipmi_mc_send_command(mc, 0, &msg, got_user2, info);
    if (rv) {
	cmdlang->err = rv;
	cmdlang->errstr = "Error sending get user name cmd";
	goto out_err;
    }
    
    return;

 out_err:
    cmdlang->location = "cmd_mc.c(got_user1)";
    ipmi_cmdlang_cmd_info_put(cmd_info);
    if (info->users)
	ipmi_mem_free(info->users);
    ipmi_mem_free(info);
}

static int
list_next_user(ipmi_mc_t *mc, user_list_t *info)
{
    ipmi_msg_t      msg;
    unsigned char   data[2];

    if ((info->curr > 0x1f) || (info->curr < 1))
	return EINVAL;

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_USER_ACCESS_CMD;
    msg.data = data;
    msg.data_len = 2;
    data[0] = info->channel & 0xf;
    data[1] = info->curr;

    return ipmi_mc_send_command(mc, 0, &msg, got_user1, info);
}

static void
mc_user_list(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    user_list_t     *info = NULL;
    int             channel;
    int             user = 0;

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

    if (argc > curr_arg) {
	ipmi_cmdlang_get_int(argv[curr_arg], &user, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "user invalid";
	    goto out_err;
	}
	curr_arg++;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->err = ENOMEM;
	cmdlang->errstr = "Out of memory";
	goto out_err;
    }
    memset(info, 0, sizeof(*info));

    info->channel = channel;
    info->cmd_info = cmd_info;
    if (user) {
	info->curr = user;
	info->max = user;
    } else {
	info->curr = 1;
	info->max = 0;
    }

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = list_next_user(mc, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	goto out_err;
    }
    return;

 out_err:
    if (info)
	ipmi_mem_free(info);
    ipmi_mc_get_name(mc, cmdlang->objstr, cmdlang->objstr_len);
    cmdlang->location = "cmd_mc.c(mc_user_list)";
}

typedef struct user_set_s
{
    int             channel;
    int             user;
    ipmi_cmd_info_t *cmd_info;
    int             link_enabled_set;
    int             link_enabled_val;
    int             msg_enabled_set;
    int             msg_enabled_val;
    int             privilege_limit_set;
    int             privilege_limit_val;
    int             cb_only_set;
    int             cb_only_val;
    int             session_limit_set;
    int             session_limit_val;
    int             name_set;
    char            name[16];
    int             pw_set;
    int             pw2_set;
    char            pw[20];
} user_set_t;

static void set_user_done(ipmi_mc_t *mc, user_set_t *info)
{
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    char            mc_name[IPMI_MC_NAME_LEN];
    
    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "User Info Set", mc_name);
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static void
set_user4(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    user_set_t      *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    if (rsp->data[0] != 0) {
	cmdlang->err = IPMI_IPMI_ERR_VAL(rsp->data[0]);
	cmdlang->errstr = "Error setting user password";
	goto out_err;
    }
    set_user_done(mc, info);

    return;

 out_err:
    cmdlang->location = "cmd_mc.c(set_user4)";
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static int set_pw(ipmi_mc_t *mc, user_set_t *info)
{
    ipmi_msg_t      msg;
    unsigned char   data[22];

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_SET_USER_PASSWORD_CMD;
    msg.data = data;


    data[0] = info->user;
    data[1] = 0x02; /* set password */
    if (info->pw2_set) {
	msg.data_len = 22;
	memcpy(data+2, info->pw, 20);
    } else {
	msg.data_len = 18;
	memcpy(data+2, info->pw, 16);
    }
	
    return ipmi_mc_send_command(mc, 0, &msg, set_user4, info);
}

static void
set_user3(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    user_set_t      *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    if (rsp->data[0] != 0) {
	cmdlang->err = IPMI_IPMI_ERR_VAL(rsp->data[0]);
	cmdlang->errstr = "Error setting user name";
	goto out_err;
    }

    if (info->pw_set || info->pw2_set) {
	rv = set_pw(mc, info);
	if (rv) {
	    cmdlang->err = rv;
	    cmdlang->errstr = "Error sending set user password cmd";
	    goto out_err;
	}
    } else
	set_user_done(mc, info);

    return;

 out_err:
    cmdlang->location = "cmd_mc.c(set_user3)";
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static int set_name(ipmi_mc_t *mc, user_set_t *info)
{
    ipmi_msg_t      msg;
    unsigned char   data[17];

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_SET_USER_NAME_CMD;
    msg.data = data;
    msg.data_len = 17;


    data[0] = info->user;
    memcpy(data+1, info->name, 16);
	
    return ipmi_mc_send_command(mc, 0, &msg, set_user3, info);
}

static void
set_user2(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    user_set_t      *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv = 0;

    if (rsp->data[0] != 0) {
	cmdlang->err = IPMI_IPMI_ERR_VAL(rsp->data[0]);
	cmdlang->errstr = "Error setting user info";
	goto out_err;
    }

    if (info->name_set) {
	rv = set_name(mc, info);
	if (rv) {
	    cmdlang->err = rv;
	    cmdlang->errstr = "Error sending set user name cmd";
	    goto out_err;
	}
    } else if (info->pw_set || info->pw2_set) {
	rv = set_pw(mc, info);
	if (rv) {
	    cmdlang->err = rv;
	    cmdlang->errstr = "Error sending set user password cmd";
	    goto out_err;
	}
    } else
	set_user_done(mc, info);

    return;

 out_err:
    cmdlang->location = "cmd_mc.c(set_user2)";
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static void
set_user1(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    user_set_t      *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;
    ipmi_msg_t      msg;
    unsigned char   data[4];

    if (rsp->data[0] != 0) {
	cmdlang->err = IPMI_IPMI_ERR_VAL(rsp->data[0]);
	cmdlang->errstr = "Error getting user info";
	goto out_err;
    }

    if (rsp->data_len < 5) {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "User access info response too small";
	goto out_err;
    }

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_SET_USER_ACCESS_CMD;
    msg.data = data;
    msg.data_len = 3;

    data[0] = (rsp->data[4] & 0xf0) | 0x80 | info->channel;
    data[1] = info->user;
    data[2] = rsp->data[4] & 0x0f;
    if (info->link_enabled_set)
	data[0] = (data[0] & ~0x20) | info->link_enabled_val;
    if (info->msg_enabled_set)
	data[0] = (data[0] & ~0x10) | info->msg_enabled_val;
    if (info->cb_only_set)
	data[0] = (data[0] & ~0x40) | info->cb_only_val;
    if (info->privilege_limit_set)
	data[2] = (data[2] & ~0x0f) | info->privilege_limit_val;
    if (info->session_limit_set) {
	/* Optional value, afaict there is no way to get this value. */
	data[3] = (info->session_limit_val & 0x0f);
	msg.data_len++;
    }
	
    rv = ipmi_mc_send_command(mc, 0, &msg, set_user2, info);
    if (rv) {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "Error sending set user access cmd";
	goto out_err;
    }
    return;

 out_err:
    cmdlang->location = "cmd_mc.c(set_user1)";
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static void
mc_user_set(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    int             channel;
    int             user;
    user_set_t      *info = NULL;
    ipmi_msg_t      msg;
    unsigned char   data[2];

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

    ipmi_cmdlang_get_int(argv[curr_arg], &user, cmd_info);
    if (cmdlang->err || (user > 0x1f) || (user < 1)) {
	cmdlang->errstr = "user invalid";
	goto out_err;
    }
    curr_arg++;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->err = ENOMEM;
	cmdlang->errstr = "Out of memory";
	goto out_err;
    }
    memset(info, 0, sizeof(*info));
    info->channel = channel;
    info->cmd_info = cmd_info;
    info->user = user;

    while (curr_arg < argc) {
	if (strcmp(argv[curr_arg], "link_enabled") == 0) {
	    info->link_enabled_set = 1;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "link_enabled value";
		goto out_err;
	    }
	    ipmi_cmdlang_get_bool(argv[curr_arg], &info->link_enabled_val,
				  cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "invalid link_enabled value";
		goto out_err;
	    }
	    info->link_enabled_val <<= 5;
	} else if (strcmp(argv[curr_arg], "msg_enabled") == 0) {
	    info->msg_enabled_set = 1;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no msg_enabled value";
		goto out_err;
	    }
	    ipmi_cmdlang_get_bool(argv[curr_arg], &info->msg_enabled_val,
				  cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "invalid msg_auth value";
		goto out_err;
	    }
	    info->msg_enabled_val <<= 4;
	} else if (strcmp(argv[curr_arg], "cb_only") == 0) {
	    info->cb_only_set = 0x08;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no cb_only value";
		goto out_err;
	    }
	    ipmi_cmdlang_get_bool(argv[curr_arg], &info->cb_only_val,
				  cmd_info);
	    if (cmdlang->err) {
		cmdlang->errstr = "invalid cb_only value";
		goto out_err;
	    }
	    info->cb_only_val <<= 6;
	} else if (strcmp(argv[curr_arg], "privilege_limit") == 0) {
	    info->privilege_limit_set = 1;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no privilege_limit value";
		goto out_err;
	    }
	    if (strcmp(argv[curr_arg], "callback") == 0) {
		info->privilege_limit_val = IPMI_PRIVILEGE_CALLBACK;
	    } else if (strcmp(argv[curr_arg], "user") == 0) {
		info->privilege_limit_val = IPMI_PRIVILEGE_USER;
	    } else if (strcmp(argv[curr_arg], "operator") == 0) {
		info->privilege_limit_val = IPMI_PRIVILEGE_OPERATOR;
	    } else if (strcmp(argv[curr_arg], "admin") == 0) {
		info->privilege_limit_val = IPMI_PRIVILEGE_ADMIN;
	    } else if (strcmp(argv[curr_arg], "oem") == 0) {
		info->privilege_limit_val = IPMI_PRIVILEGE_OEM;
	    } else if (strcmp(argv[curr_arg], "no_access") == 0) {
		info->privilege_limit_val = 0xf;
	    } else {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "invalid privilege_limit value";
		goto out_err;
	    }
	} else if (strcmp(argv[curr_arg], "session_limit") == 0) {
	    info->session_limit_set = 1;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no session_limit value";
		goto out_err;
	    }
	    ipmi_cmdlang_get_int(argv[curr_arg], &info->session_limit_val,
				 cmd_info);
	    if ((cmdlang->err) || (info->session_limit_val > 0xf)
		|| (info->session_limit_val < 0))
	    {
		cmdlang->errstr = "invalid session_limit value";
		goto out_err;
	    }
	} else if (strcmp(argv[curr_arg], "name") == 0) {
	    info->name_set = 1;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no name value";
		goto out_err;
	    }
	    strncpy(info->name, argv[curr_arg], 16);
	} else if (strcmp(argv[curr_arg], "password") == 0) {
	    info->pw_set = 1;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no name value";
		goto out_err;
	    }
	    strncpy(info->pw, argv[curr_arg], 16);
	} else if (strcmp(argv[curr_arg], "password2") == 0) {
	    info->pw2_set = 1;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no name value";
		goto out_err;
	    }
	    strncpy(info->pw, argv[curr_arg], 20);
	} else {
	    cmdlang->err = EINVAL;
	    cmdlang->errstr = "invalid setting";
	    goto out_err;
	}
	curr_arg++;
    }

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_USER_ACCESS_CMD;
    msg.data = data;
    msg.data_len = 2;
    data[0] = info->channel & 0xf;
    data[1] = info->user;
    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_send_command(mc, 0, &msg, set_user1, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Error sending get user access cmd";
	ipmi_cmdlang_unlock(cmd_info);
	goto out_err;
    }
    return;

 out_err:
    if (info)
	ipmi_mem_free(info);
    ipmi_mc_get_name(mc, cmdlang->objstr, cmdlang->objstr_len);
    cmdlang->location = "cmd_mc.c(mc_user_list)";
}

static void
mc_active(ipmi_mc_t *mc, int active, void *cb_data)
{
    char            *errstr;
    int             rv;
    ipmi_cmd_info_t *evi;
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "MC");
    ipmi_cmdlang_out(evi, "Name", mc_name);
    ipmi_cmdlang_out(evi, "Operation", "Active Changed");
    ipmi_cmdlang_out_bool(evi, "Active", active);

    ipmi_cmdlang_cmd_info_put(evi);
    return;

 out_err:
    ipmi_cmdlang_global_err(mc_name,
			    "cmd_mc.c(presence_change)",
			    errstr, rv);
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
}

void
ipmi_cmdlang_mc_change(enum ipmi_update_e op,
		       ipmi_domain_t      *domain,
		       ipmi_mc_t          *mc,
		       void               *cb_data)
{
    char            *errstr;
    int             rv;
    ipmi_cmd_info_t *evi;
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	errstr = "Out of memory";
	rv = ENOMEM;
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "MC");
    ipmi_cmdlang_out(evi, "Name", mc_name);

    switch (op) {
    case IPMI_ADDED:
	ipmi_cmdlang_out(evi, "Operation", "Add");
	if (ipmi_cmdlang_get_evinfo())
	    mc_dump(mc, evi);
	rv = ipmi_mc_add_active_handler(mc, mc_active, NULL);
	if (rv) {
	    errstr = "ipmi_mc_add_active_handler failed";
	    goto out_err;
	}
	break;

	case IPMI_DELETED:
	    ipmi_cmdlang_out(evi, "Operation", "Delete");
	    break;

	case IPMI_CHANGED:
	    ipmi_cmdlang_out(evi, "Operation", "Change");
	    if (ipmi_cmdlang_get_evinfo())
		mc_dump(mc, evi);
	    break;
    }

    ipmi_cmdlang_cmd_info_put(evi);
    return;

 out_err:
    if (rv) {
	ipmi_cmdlang_global_err(mc_name, "cmd_mc.c(ipmi_cmdlang_mc_change)",
				errstr, rv);
    }
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
}

static ipmi_cmdlang_cmd_t *mc_cmds;
static ipmi_cmdlang_cmd_t *mc_chan_cmds;
static ipmi_cmdlang_cmd_t *mc_user_cmds;

static ipmi_cmdlang_init_t cmds_mc[] =
{
    { "mc", NULL,
      "- Commands dealing with MCs",
      NULL, NULL, &mc_cmds },
    { "list", &mc_cmds,
      "- List all the entities in the system",
      ipmi_cmdlang_domain_handler, mc_list, NULL },
    { "info", &mc_cmds,
      "<mc> - Dump information about an mc",
      ipmi_cmdlang_mc_handler, mc_info, NULL },
    { "reset", &mc_cmds,
      "<mc> <warm | cold> - Do a warm or cold reset on the given MC.  Note"
      " that this does *not* reset the main processor, and the effects of"
      " this are implementation-defined",
      ipmi_cmdlang_mc_handler, mc_reset, NULL },
    { "set_events_enable", &mc_cmds,
      "<mc> <enable | disable> - Sets if the events are enabled or disabled"
      " for an MC",
      ipmi_cmdlang_mc_handler, mc_set_events_enable, NULL },
    { "get_events_enable", &mc_cmds,
      "<mc> - Returns if the events are enabled or disabled"
      " for an MC",
      ipmi_cmdlang_mc_handler, mc_get_events_enable, NULL },
    { "sel_info", &mc_cmds,
      "<mc> - Returns information about the SEL on the MC",
      ipmi_cmdlang_mc_handler, mc_sel_info, NULL },
    { "get_sel_time", &mc_cmds,
      "<mc> - Returns SEL time on the MC",
      ipmi_cmdlang_mc_handler, mc_get_sel_time, NULL },
    { "set_sel_time", &mc_cmds,
      "<mc> <time> - Sets SEL time on the MC",
      ipmi_cmdlang_mc_handler, mc_set_sel_time, NULL },
    { "sel_rescan_time", &mc_cmds,
      "<mc> <time in seconds> - Set the time between SEL rescans"
      " for the MC.  Zero disables scans.",
      ipmi_cmdlang_mc_handler, mc_sel_rescan_time, NULL },
    { "rescan_sel", &mc_cmds,
      "<mc> - Rescan the SEL in the MC",
      ipmi_cmdlang_mc_handler, mc_rescan_sels, NULL },
    { "msg", &mc_cmds,
      "<mc> <LUN> <NetFN> <Cmd> [data...] - Send the given command"
      " to the management controller and display the response.",
      ipmi_cmdlang_mc_handler, mc_msg, NULL },
    { "sdrs", &mc_cmds,
      "<mc> <main | sensor> - fetch either the main or sensor"
      " SDRs from the given MC.",
      ipmi_cmdlang_mc_handler, mc_sdrs, NULL },
    { "chan", &mc_cmds,
      " Control and information for channels",
      NULL, NULL, &mc_chan_cmds },
    { "info", &mc_chan_cmds,
      "<mc> <channel> - Get information about the channel on the MC.",
      ipmi_cmdlang_mc_handler, mc_get_chan_info, NULL },
    { "get_access", &mc_chan_cmds,
      "<mc> <channel> non-volatile|present|both - Get access info about the"
      " channel on the MC.  Get either the the non-volatile settings,"
      " the current (volatile) settings, or both.",
      ipmi_cmdlang_mc_handler, mc_get_chan_access, NULL },
    { "set_access", &mc_chan_cmds,
      "<mc> <channel> non-volatile|present|both parm value [parm value ...]"
      " - Set access info about the channel on the MC.  This will read"
      " the values and modify the values specified in the parm/value"
      " pairs.  The parms available are:\n"
      "  alert true|false\n"
      "  msg_auth true|false\n"
      "  user_auth true|false\n"
      "  access_mode disabled|pre-boot|always|shared\n"
      "  privilege_limit callback|user|operator|admin|oem\n"
      " See the spec for details on what this means.",
      ipmi_cmdlang_mc_handler, mc_set_chan_access, NULL },
    { "user", &mc_chan_cmds,
      "Commands to view manipulate users of a channel",
      NULL, NULL, &mc_user_cmds },
    { "list", &mc_user_cmds,
      "<mc> <channel> [<num>]- List users for the given MC's channel."
      " If the user number is given, only list that user, otherwise list"
      " all the users",
      ipmi_cmdlang_mc_handler, mc_user_list, NULL },
    { "set", &mc_user_cmds,
      "<mc> <channel> <num> <parm> <value> [<parm> <value> ...] - Set info"
      " for the given user number.  The parameters are:\n"
      "  link_enabled true|false\n"
      "  msg_enabled true|false\n"
      "  cb_only true|false\n"
      "  privilege_limit callback|user|operator|admin|oem|no_access\n"
      "  session_limit <integer>\n"
      "  name <user name string>\n"
      "  password <password string, <= 16 characters>\n"
      "  password2 <password string, <= 20 characters>\n"
      " Note that setting the session limit to zero means there is no"
      " session limit.  Also note that some systems have a bug where"
      " the session limit is not optional (as the spec says it is)."
      " If you get C7 errors back from this command, you will have"
      " to always specify the session limit.  The password2 option"
      " is for IPMI 2.0 passwords that may be up to 20 characters.",
      ipmi_cmdlang_mc_handler, mc_user_set, NULL },
};
#define CMDS_MC_LEN (sizeof(cmds_mc)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_mc_init(os_handler_t *os_hnd)
{
    return ipmi_cmdlang_reg_table(cmds_mc, CMDS_MC_LEN);
}
