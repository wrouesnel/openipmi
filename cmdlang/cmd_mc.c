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
#include <OpenIPMI/ipmi_user.h>

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
    unsigned char vals[4];
    char          str[100];
    unsigned char guid[16];

    ipmi_cmdlang_out_bool(cmd_info, "Active", ipmi_mc_is_active(mc));
    if (ipmi_mc_get_guid(mc, guid) == 0)
	ipmi_cmdlang_out_binary(cmd_info, "GUID", (char *) guid, 16);
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
    ipmi_cmdlang_out_binary(cmd_info, "aux_fw_revision",
			    (char *) vals, sizeof(vals));
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
	ipmi_cmdlang_out_binary(cmd_info, "Data",
				(char *) msg->data, msg->data_len);
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
    unsigned int    i;
    int             rv;
    int             total_size = 0;

    if (err) {
	cmdlang->err = err;
	cmdlang->errstr = "Error fetching SDRs";
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
	ipmi_cmdlang_out_binary(cmd_info, "Data",
				(char *) sdr.data, sdr.length);
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

typedef struct event_log_s
{
    ipmi_cmd_info_t *cmd_info;
} event_log_t;

static void
mc_got_event_log_enable(ipmi_mc_t *mc, int err, int val, void *cb_data)
{
    event_log_t     *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char             mc_name[IPMI_MC_NAME_LEN];

    if (err) {
	cmdlang->err = err;
	cmdlang->errstr = "Error getting event log enable";
	goto out_err;
    }

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    ipmi_cmdlang_out(cmd_info, "MC", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", mc_name);
    ipmi_cmdlang_out_bool(cmd_info, "Event Log Enabled", val);
    ipmi_cmdlang_up(cmd_info);

 out_err:
    if (cmdlang->err) {
	cmdlang->location = "cmd_mc.c(mc_got_event_log_enable)";
    }
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static void
mc_get_event_log_enable(ipmi_mc_t *mc, void *cb_data)
{
    event_log_t     *info;
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;


    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->err = ENOMEM;
	cmdlang->errstr = "Could not allocate SDR data";
	goto out_err;
    }
    info->cmd_info = cmd_info;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_get_event_log_enable(mc, mc_got_event_log_enable, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Could not start event log enable fetch";
	goto out_err;
    }

    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr, cmdlang->objstr_len);
    cmdlang->location = "cmd_mc.c(mc_get_event_log_enable)";
    if (info)
	ipmi_mem_free(info);
}

static void
mc_event_log_enable_set(ipmi_mc_t *mc, int err, void *cb_data)
{
    event_log_t     *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char             mc_name[IPMI_MC_NAME_LEN];

    if (err) {
	cmdlang->err = err;
	cmdlang->errstr = "Error setting event log enable";
	goto out_err;
    }

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    ipmi_cmdlang_out(cmd_info, "Event Log Enable Set", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    ipmi_cmdlang_up(cmd_info);

 out_err:
    if (cmdlang->err) {
	cmdlang->location = "cmd_mc.c(mc_event_log_enable_set)";
    }
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static void
mc_set_event_log_enable(ipmi_mc_t *mc, void *cb_data)
{
    event_log_t     *info = NULL;
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             val;
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);


    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->err = ENOMEM;
	cmdlang->errstr = "Could not allocate SDR data";
	goto out_err;
    }
    info->cmd_info = cmd_info;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_bool(argv[curr_arg], &val, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "invalid enable setting";
	goto out_err;
    }

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_set_event_log_enable(mc, val, mc_event_log_enable_set, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	cmdlang->errstr = "Could not start event log enable set";
	goto out_err;
    }

    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr, cmdlang->objstr_len);
    cmdlang->location = "cmd_mc.c(mc_get_event_log_enable)";
    if (info)
	ipmi_mem_free(info);
    
}

static void
dump_chan_info(ipmi_mc_t           *mc,
	       ipmi_channel_info_t *info,
	       ipmi_cmd_info_t     *cmd_info)
{
    char            mc_name[IPMI_MC_NAME_LEN];
    char            *str;
    unsigned int    val;
    int             rv;
    unsigned char   data[3];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Channel Info", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    rv = ipmi_channel_info_get_channel(info, &val);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "Channel", val);
    rv = ipmi_channel_info_get_medium(info, &val);
    if (!rv) {
	ipmi_cmdlang_out_int(cmd_info, "Medium", val);
	ipmi_cmdlang_out(cmd_info, "Medium String",
			 ipmi_channel_medium_string(val));
    }
    rv = ipmi_channel_info_get_protocol_type(info, &val);
    if (!rv) {
	ipmi_cmdlang_out_int(cmd_info, "Protocol Type", val);
	ipmi_cmdlang_out(cmd_info, "Protocol Type String",
			 ipmi_channel_protocol_string(val));
    }
    rv = ipmi_channel_info_get_session_support(info, &val);
    if (!rv) {
	switch (val) {
	case IPMI_CHANNEL_SESSION_LESS: str = "session-less"; break;
	case IPMI_CHANNEL_SINGLE_SESSION: str = "single-session"; break;
	case IPMI_CHANNEL_MULTI_SESSION: str = "multi-session"; break;
	case IPMI_CHANNEL_SESSION_BASED: str = "session-based"; break;
	default: str = "unknown";
	}
	ipmi_cmdlang_out(cmd_info, "Session Support", str);
    }
    rv = ipmi_channel_info_get_vendor_id(info, data);
    if (!rv)
	ipmi_cmdlang_out_binary(cmd_info, "Vendor ID", (char *) data, 3);
    rv = ipmi_channel_info_get_aux_info(info, data);
    if (!rv)
	ipmi_cmdlang_out_binary(cmd_info, "Aux Info", (char *) data, 2);
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_unlock(cmd_info);
}

static void
got_chan_info(ipmi_mc_t           *mc,
	      int                 err,
	      ipmi_channel_info_t *info,
	      void                *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    if (err) {
	cmdlang->err = err;
	cmdlang->errstr = "Error getting channel info";
	goto out_err;
    }

    dump_chan_info(mc, info, cmd_info);

 out_err:
    if (cmdlang->err) {
	cmdlang->location = "cmd_mc.c(got_chan_info)";
    }

    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
got_chan_info_multi(ipmi_mc_t           *mc,
		    int                 err,
		    ipmi_channel_info_t *info,
		    void                *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;

    if (err)
	/* Ignore this on multiple fetches, don't print an error */
	goto out;

    dump_chan_info(mc, info, cmd_info);
	    

 out:
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
    int             channel;


    if ((argc - curr_arg) < 1) {
	int count = 0;
	/* List them all */
	for (channel=0; channel<8; channel++) {
	    ipmi_cmdlang_cmd_info_get(cmd_info);
	    rv = ipmi_mc_channel_get_info(mc, channel, got_chan_info_multi,
					  cmd_info);
	    if (rv)
		ipmi_cmdlang_cmd_info_put(cmd_info);
	    else
		count++;
	}
	if (count == 0) {
	    cmdlang->err = rv;
	    cmdlang->errstr = "Could not get channel info for any channels";
	    goto out_err;
	}
    } else {
	ipmi_cmdlang_get_int(argv[curr_arg], &channel, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "channel invalid";
	    goto out_err;
	}
	curr_arg++;

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_mc_channel_get_info(mc, channel, got_chan_info, cmd_info);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->err = rv;
	    cmdlang->errstr = "Could not get channel info";
	    goto out_err;
	}
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
} get_chan_info_t;

void
got_chan_access(ipmi_mc_t             *mc,
		int                   err,
		ipmi_channel_access_t *info,
		void                  *cb_data)
{
    get_chan_info_t *chan_info = cb_data;
    ipmi_cmd_info_t *cmd_info = chan_info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];
    char            *str;
    int             rv;
    unsigned int    val;

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    if (err) {
	cmdlang->err = err;
	cmdlang->errstr = "Error getting channel access info";
	goto out_err;
    }

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Channel Access", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    rv = ipmi_channel_access_get_channel(info, &val);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "Channel", val);
    ipmi_cmdlang_out(cmd_info, "Type", chan_info->type);
    rv = ipmi_channel_access_get_alerting_enabled(info, &val);
    if (!rv)
	ipmi_cmdlang_out_bool(cmd_info, "Alerting Enabled", val);
    rv = ipmi_channel_access_get_per_msg_auth(info, &val);
    if (!rv)
	ipmi_cmdlang_out_bool(cmd_info, "Per-Message Auth", val);
    rv = ipmi_channel_access_get_user_auth(info, &val);
    if (!rv)
	ipmi_cmdlang_out_bool(cmd_info, "User Auth", val);
    rv = ipmi_channel_access_get_access_mode(info, &val);
    if (!rv) {
	switch (val) {
	case IPMI_CHANNEL_ACCESS_MODE_DISABLED: str = "disabled"; break;
	case IPMI_CHANNEL_ACCESS_MODE_PRE_BOOT: str = "pre-boot"; break;
	case IPMI_CHANNEL_ACCESS_MODE_ALWAYS: str = "always"; break;
	case IPMI_CHANNEL_ACCESS_MODE_SHARED: str = "shared"; break;
	default: str = "unknown";
	}
	ipmi_cmdlang_out(cmd_info, "Access Mode", str);
    }
    rv = ipmi_channel_access_get_priv_limit(info, &val);
    if (!rv)
	ipmi_cmdlang_out(cmd_info, "Privilege Limit",
			 ipmi_privilege_string(val));
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_unlock(cmd_info);

 out_err:
    if (cmdlang->err) {
	cmdlang->location = "cmd_mc.c(got_chan_access)";
    }

    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(chan_info);
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

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_mc_channel_get_access(mc, channel,
					IPMI_SET_DEST_VOLATILE, 
					got_chan_access,
					present);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->err = rv;
	    cmdlang->errstr = "Could not send command to get present value";
	    ipmi_mem_free(present);
 	    present = NULL;
	}
    }

    if (non_volatile) {
	non_volatile->type = "non-volatile";
	non_volatile->cmd_info = cmd_info;

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_mc_channel_get_access(mc, channel,
					IPMI_SET_DEST_NON_VOLATILE,
					got_chan_access,
					non_volatile);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->err = rv;
	    cmdlang->errstr = "Could not send command to get non-volatile"
		" value";
	    ipmi_mem_free(non_volatile);
	    non_volatile = NULL;
	}
    }

    if ((present == NULL) && (non_volatile == NULL))
	goto out_err;

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
    char                 *type;
    enum ipmi_set_dest_e dest;
    ipmi_cmd_info_t      *cmd_info;
    set_chan_parm_t      parms;
    unsigned int         channel; 
} set_chan_info_t;

void
set_chan_access2(ipmi_mc_t *mc, int err, void *cb_data)
{
    set_chan_info_t *chan_info = cb_data;
    ipmi_cmd_info_t *cmd_info = chan_info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    if (err) {
	cmdlang->err = err;
	cmdlang->errstr = "Error getting channel info";
	goto out_err;
    }

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Channel Access Set", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    ipmi_cmdlang_out_int(cmd_info, "Channel", chan_info->channel);
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_unlock(cmd_info);

 out_err:
    if (cmdlang->err) {
	cmdlang->location = "cmd_mc.c(set_chan_access2)";
    }

    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(chan_info);
}

void
set_chan_access1(ipmi_mc_t             *mc,
		 int                   err,
		 ipmi_channel_access_t *info,
		 void                  *cb_data)
{
    set_chan_info_t *cinfo = cb_data;
    ipmi_cmd_info_t *cmd_info = cinfo->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];
    int             rv;
    unsigned int    channel;

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    if (err) {
	cmdlang->err = err;
	cmdlang->errstr = "Error getting channel info";
	goto out_err;
    }
    if (cinfo->parms.alert_set)
	ipmi_channel_access_set_alerting_enabled(info, cinfo->parms.alert_val);
    if (cinfo->parms.msg_auth_set)
	ipmi_channel_access_set_per_msg_auth(info, cinfo->parms.msg_auth_val);
    if (cinfo->parms.user_auth_set)
	ipmi_channel_access_set_user_auth(info, cinfo->parms.user_auth_val);
    if (cinfo->parms.access_mode_set)
	ipmi_channel_access_set_access_mode(info, 
					    cinfo->parms.access_mode_val);
    if (cinfo->parms.privilege_set)
	ipmi_channel_access_set_priv_limit(info, cinfo->parms.privilege_val);
    ipmi_channel_access_get_channel(info, &channel);

    rv = ipmi_mc_channel_set_access(mc, channel, cinfo->dest,
				    info, set_chan_access2, cinfo);
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
    ipmi_mem_free(cinfo);
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
	    parms.alert_set = 1;
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
	} else if (strcmp(argv[curr_arg], "msg_auth") == 0) {
	    parms.msg_auth_set = 1;
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
	} else if (strcmp(argv[curr_arg], "user_auth") == 0) {
	    parms.user_auth_set = 1;
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
	} else if (strcmp(argv[curr_arg], "access_mode") == 0) {
	    parms.access_mode_set = 1;
	    curr_arg++;
	    if (curr_arg >= argc) {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "no access_mode value";
		goto out_err;
	    }
	    if (strcmp(argv[curr_arg], "disabled") == 0) {
		parms.access_mode_val = IPMI_CHANNEL_ACCESS_MODE_DISABLED;
	    } else if (strcmp(argv[curr_arg], "pre-boot") == 0) {
		parms.access_mode_val = IPMI_CHANNEL_ACCESS_MODE_PRE_BOOT;
	    } else if (strcmp(argv[curr_arg], "always") == 0) {
		parms.access_mode_val = IPMI_CHANNEL_ACCESS_MODE_ALWAYS;
	    } else if (strcmp(argv[curr_arg], "shared") == 0) {
		parms.access_mode_val = IPMI_CHANNEL_ACCESS_MODE_SHARED;
	    } else {
		cmdlang->err = EINVAL;
		cmdlang->errstr = "invalid access_mode value";
		goto out_err;
	    }
	} else if (strcmp(argv[curr_arg], "privilege_limit") == 0) {
	    parms.privilege_set = 1;
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
	present->dest = IPMI_SET_DEST_VOLATILE;

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_mc_channel_get_access(mc, channel, present->dest,
					set_chan_access1, present);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->err = rv;
	    cmdlang->errstr = "Could not send command to get present value";
	    ipmi_mem_free(present);
	    present = NULL;
	}
    }

    if (non_volatile) {
	non_volatile->type = "non-volatile";
	non_volatile->cmd_info = cmd_info;
	non_volatile->parms = parms;
	non_volatile->channel = channel;
	non_volatile->dest = IPMI_SET_DEST_NON_VOLATILE;

	ipmi_cmdlang_cmd_info_get(cmd_info);
	rv = ipmi_mc_channel_get_access(mc, channel, non_volatile->dest,
					set_chan_access1, non_volatile);
	if (rv) {
	    ipmi_cmdlang_cmd_info_put(cmd_info);
	    cmdlang->err = rv;
	    cmdlang->errstr = "Could not send command to get non-volatile"
		" value";
	    ipmi_mem_free(non_volatile);
	    non_volatile = NULL;
	}
    }

    if ((present == NULL) && (non_volatile == NULL))
	goto out_err;

    return;

 out_err:
    if (non_volatile)
	ipmi_mem_free(non_volatile);
    if (present)
	ipmi_mem_free(present);
    ipmi_mc_get_name(mc, cmdlang->objstr, cmdlang->objstr_len);
    cmdlang->location = "cmd_mc.c(mc_get_chan_access)";
}

static void
got_users(ipmi_mc_t        *mc,
	  int              err,
	  ipmi_user_list_t *list,
	  void             *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    ipmi_user_t     *user;
    char            mc_name[IPMI_MC_NAME_LEN];
    int		    i, j, k;
    char            str[17];
    unsigned int    count;
    unsigned int    channel;
    unsigned int    val;
    int             rv;

    if (err) {
	cmdlang->err = err;
	cmdlang->errstr = "Error getting user info";
	goto out_err;
    }

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    count = ipmi_user_list_get_user_count(list);

    rv = ipmi_user_list_get_channel(list, &channel);
    if (rv) {
	cmdlang->err = rv;
	cmdlang->errstr = "Error getting channel";
	goto out_err;
    }

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    ipmi_cmdlang_out_int(cmd_info, "Channel", channel);
    rv = ipmi_user_list_get_max_user(list, &val);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "Max User", val);
    rv = ipmi_user_list_get_enabled_users(list, &val);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "Enabled Users", val);
    rv = ipmi_user_list_get_fixed_users(list, &val);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "Fixed Users", val);
    for (i=0; i<(int)count; i++) {
	user = ipmi_user_list_get_user(list, i);
	if (!user)
	    continue;
	ipmi_cmdlang_out(cmd_info, "User", NULL);
	ipmi_cmdlang_down(cmd_info);
	rv = ipmi_user_get_num(user, &val);
	if (!rv)
	    ipmi_cmdlang_out_int(cmd_info, "Number", val);
	
	val = 17;
	rv = ipmi_user_get_name(user, str, &val);
	if (!rv) {
	    val = 1;
	    for (j=15; j>=0; j--) {
		if (str[j] != '\0')
		    break;
	    }
	    for (k=0; k<=j; k++) {
		if (! isprint(str[k])) {
		    val = 0;
		    break;
		}
	    }
	    if (val)
		ipmi_cmdlang_out(cmd_info, "String Name", str);
	    else
		ipmi_cmdlang_out_binary(cmd_info, "Binary Name", str, 16);
	}
	rv = ipmi_user_get_link_auth_enabled(user, &val);
	if (!rv)
	    ipmi_cmdlang_out_bool(cmd_info, "Link Auth Enabled", val);
	rv = ipmi_user_get_msg_auth_enabled(user, &val);
	if (!rv)
	    ipmi_cmdlang_out_bool(cmd_info, "Msg Auth Enabled", val);
	rv = ipmi_user_get_access_cb_only(user, &val);
	if (!rv)
	    ipmi_cmdlang_out_bool(cmd_info, "Access CB Only", val);
	rv = ipmi_user_get_privilege_limit(user, &val);
	if (!rv)
	    ipmi_cmdlang_out(cmd_info, "Privilege Limit",
			     ipmi_privilege_string(val));
	rv = ipmi_user_get_session_limit(user, &val);
	if (!rv)
	    ipmi_cmdlang_out_bool(cmd_info, "Session Limit", val);
	ipmi_cmdlang_up(cmd_info);
	ipmi_user_free(user);
    }
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr, cmdlang->objstr_len);
    cmdlang->location = "cmd_mc.c(got_users)";
    ipmi_cmdlang_cmd_info_put(cmd_info);
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
    int             channel;
    int             user = IPMI_MC_ALL_USERS;

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

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_get_users(mc, channel, user, got_users, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	goto out_err;
    }
    return;

 out_err:
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
    int             enable_set;
    int             enable_val;
    int             name_set;
    char            name[16];
    int             pw_set;
    int             pw2_set;
    char            pw[20];
} user_set_t;

static void
set_user2(ipmi_mc_t *mc, int err, void *cb_data)
{
    user_set_t      *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            mc_name[IPMI_MC_NAME_LEN];

    if (err) {
	cmdlang->err = err;
	cmdlang->errstr = "Error setting user info";
	goto out_err;
    }

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "User Info Set", mc_name);
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);

    return;

 out_err:
    cmdlang->location = "cmd_mc.c(set_user2)";
    ipmi_cmdlang_cmd_info_put(cmd_info);
    ipmi_mem_free(info);
}

static void
set_user1(ipmi_mc_t        *mc,
	  int              err,
	  ipmi_user_list_t *list,
	  void             *cb_data)
{
    user_set_t      *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    ipmi_user_t     *user = NULL;
    int             rv = 0;

    if (err) {
	cmdlang->err = err;
	cmdlang->errstr = "Error getting user info";
	goto out_err;
    }

    user = ipmi_user_list_get_user(list, 0);
    if (!user) {
	/* Eh? */
	cmdlang->err = EINVAL;
	cmdlang->errstr = "Error getting user";
	goto out_err;
    }

    if (info->link_enabled_set)
	rv |= ipmi_user_set_link_auth_enabled(user, info->link_enabled_val);
    if (info->msg_enabled_set)
	rv |= ipmi_user_set_msg_auth_enabled(user, info->msg_enabled_val);
    if (info->cb_only_set)
	rv |= ipmi_user_set_access_cb_only(user, info->cb_only_val);
    if (info->privilege_limit_set)
	rv |= ipmi_user_set_privilege_limit(user,info->privilege_limit_val);
    if (info->session_limit_set)
	/* Optional value, afaict there is no way to get this value. */
	rv |= ipmi_user_set_session_limit(user, info->session_limit_val);
    if (info->pw2_set)
	rv |= ipmi_user_set_password2(user, info->pw, 20);
    else if (info->pw_set)
	rv |= ipmi_user_set_password(user, info->pw, 16);
    if (info->name_set)
	rv |= ipmi_user_set_name(user, info->name, strlen(info->name));
    if (info->enable_set)
	/* Optional value, afaict there is no way to get this value. */
	rv |= ipmi_user_set_enable(user, info->enable_val);
	
    rv = ipmi_mc_set_user(mc, info->channel, info->user, user,
			  set_user2, info);
    if (rv) {
	cmdlang->err = EINVAL;
	cmdlang->errstr = "Error sending set user access cmd";
	goto out_err;
    }
    ipmi_user_free(user);
    return;

 out_err:
    if (user)
	ipmi_user_free(user);
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
	} else if (strcmp(argv[curr_arg], "enable") == 0) {
	    info->enable_set = 1;
	    info->enable_val = 1;
	} else if (strcmp(argv[curr_arg], "disable") == 0) {
	    info->enable_set = 1;
	    info->enable_val = 0;
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

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_mc_get_users(mc, channel, user, set_user1, info);
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
    cmdlang->location = "cmd_mc.c(mc_user_set)";
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
			    "cmd_mc.c(mc_active)",
			    errstr, rv);
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
}

static void
mc_fully_up(ipmi_mc_t *mc, void *cb_data)
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
    ipmi_cmdlang_out(evi, "Operation", "Fully Up");

    ipmi_cmdlang_cmd_info_put(evi);
    return;

 out_err:
    ipmi_cmdlang_global_err(mc_name,
			    "cmd_mc.c(mc_fully_up)",
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
	rv = ipmi_mc_add_fully_up_handler(mc, mc_fully_up, NULL);
	if (rv) {
	    errstr = "ipmi_mc_add_fully_up_handler failed";
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
    { "get_event_log_enable", &mc_cmds,
      " <mc> - Get whether the event log is enabled on the MC.",
      ipmi_cmdlang_mc_handler, mc_get_event_log_enable, NULL },
    { "set_event_log_enable", &mc_cmds,
      " <mc> <on|off> - Set whether the event log is enabled on the MC.",
      ipmi_cmdlang_mc_handler, mc_set_event_log_enable, NULL },
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
      "  enable\n"
      "  disable\n"
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
