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
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_conn.h>

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

    ipmi_domain_iterate_mcs(domain, mc_list_handler, cmd_info);
}

static void
mc_info(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    unsigned char   vals[4];
    char            str[100];
    char            mc_name[IPMI_MC_NAME_LEN];

    ipmi_mc_get_name(mc, mc_name, sizeof(mc_name));
    ipmi_cmdlang_out(cmd_info, "MC", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", mc_name);

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
    ipmi_cmdlang_up(cmd_info);
}

static void
reset_done(ipmi_mc_t *mc, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    if (err) {
	ipmi_cmdlang_lock(cmd_info);
	cmdlang->errstr = "Error resetting MC";
	cmdlang->err = err;
	ipmi_mc_get_name(mc, cmdlang->objstr,
			 cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(reset_done)";
	ipmi_cmdlang_unlock(cmd_info);
    }
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
    rv = ipmi_mc_reset(mc, cmd, reset_done, cmd_info);
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
set_events_enabled_done(ipmi_mc_t *mc, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    if (err) {
	ipmi_cmdlang_lock(cmd_info);
	cmdlang->errstr = "Error setting events enable";
	cmdlang->err = err;
	ipmi_mc_get_name(mc, cmdlang->objstr,
			 cmdlang->objstr_len);
	cmdlang->location = "cmd_mc.c(set_events_enable_done)";
	ipmi_cmdlang_unlock(cmd_info);
    }
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
mc_set_events_enabled(ipmi_mc_t *mc, void *cb_data)
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
    rv = ipmi_mc_set_events_enable(mc, enable, set_events_enabled_done,
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
mc_get_events_enabled(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    
    ipmi_cmdlang_out_bool(cmd_info, "Events Enable",
			  ipmi_mc_get_events_enable(mc));
}

static void
mc_sel_info(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    
    ipmi_cmdlang_out_int(cmd_info, "SEL Count", ipmi_mc_sel_count(mc));
    ipmi_cmdlang_out_int(cmd_info, "SEL Slots Used",
			 ipmi_mc_sel_entries_used(mc));
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
	if (ipmi_cmdlang_get_evinfo()) {
	    ipmi_cmdlang_down(evi);
	    mc_info(mc, evi);
	    ipmi_cmdlang_up(evi);
	}
#if 0
	if (ipmi_mc_is_active(mc)) {
	    ipmi_mc_set_sdrs_first_read_handler(mc, mc_sdrs_read, NULL);
	    ipmi_mc_set_sels_first_read_handler(mc, mc_sels_read, NULL);
	}
#endif
	break;

	case IPMI_DELETED:
	    ipmi_cmdlang_out(evi, "Operation", "Delete");
	    break;

	case IPMI_CHANGED:
	    ipmi_cmdlang_out(evi, "Operation", "Change");
	    if (ipmi_cmdlang_get_evinfo()) {
		ipmi_cmdlang_down(evi);
		mc_info(mc, evi);
		ipmi_cmdlang_up(evi);
	    }
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

static ipmi_cmdlang_init_t cmds_mc[] =
{
    { "mc", NULL,
      "Commands dealing with MCs",
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
    { "set_events_enabled", &mc_cmds,
      "<mc> <enable | disable> - Sets if the events are enabled or disabled"
      " for an MC",
      ipmi_cmdlang_mc_handler, mc_set_events_enabled, NULL },
    { "get_events_enabled", &mc_cmds,
      "<mc> - Returns if the events are enabled or disabled"
      " for an MC",
      ipmi_cmdlang_mc_handler, mc_get_events_enabled, NULL },
    { "sel_info", &mc_cmds,
      "<mc> - Returns information about the SEL on the MC",
      ipmi_cmdlang_mc_handler, mc_sel_info, NULL },
    { "get_sel_time", &mc_cmds,
      "<mc> - Returns SEL time on the MC",
      ipmi_cmdlang_mc_handler, mc_get_sel_time, NULL },
    { "msg", &mc_cmds,
      "<mc> <LUN> <NetFN> <Cmd> [data...] - Send the given command"
      " to the management controller and display the response.",
      ipmi_cmdlang_mc_handler, mc_msg, NULL },
    { "sdrs", &mc_cmds,
      "<mc> <main | sensor> - fetch either the main or sensor"
      " SDRs from the given MC.",
      ipmi_cmdlang_mc_handler, mc_sdrs, NULL },
};
#define CMDS_MC_LEN (sizeof(cmds_mc)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_mc_init(void)
{
    return ipmi_cmdlang_reg_table(cmds_mc, CMDS_MC_LEN);
}
