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
#include <OpenIPMI/ipmi_event.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_conn.h>


void ipmi_cmdlang_dump_fru_info(ipmi_cmd_info_t *cmd_info, ipmi_fru_t *fru);

static void
domain_list_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

    if (cmd_info->cmdlang->err)
	return;

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
}

static void
domain_list(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_out(cmd_info, "Domains", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_domain_iterate_domains(domain_list_handler, cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static void
domain_info(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    ipmi_cmdlang_out(cmd_info, "Type",
		    ipmi_domain_get_type_string(ipmi_domain_get_type(domain)));
    ipmi_cmdlang_out_int(cmd_info, "SEL Rescan Time",
			 ipmi_domain_get_sel_rescan_time(domain));
    ipmi_cmdlang_out_int(cmd_info, "IPMB Rescan Time",
			 ipmi_domain_get_ipmb_rescan_time(domain));
}

static void
domain_con_change(ipmi_domain_t *domain,
		  int           err,
		  unsigned int  conn_num,
		  unsigned int  port_num,
		  int           still_connected,
		  void          *cb_data)
{
    char            *errstr = NULL;
    int             rv = 0;
    ipmi_cmd_info_t *evi;
    char            domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Domain");
    ipmi_cmdlang_out(evi, "Operation", "Connection Change");
    ipmi_cmdlang_out(evi, "Name", domain_name);
    ipmi_cmdlang_out_int(evi, "Connection Number", conn_num);
    ipmi_cmdlang_out_int(evi, "Port Number", port_num);
    ipmi_cmdlang_out_int(evi, "Any Connection Up", still_connected);
    ipmi_cmdlang_out_int(evi, "Error", err);

 out_err:
    if (rv) {
	ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
	ipmi_cmdlang_global_err(domain_name, "cmd_domain.c(domain_con_change)",
				errstr, rv);
    }
    ipmi_cmdlang_cmd_info_put(evi);
}

static void
get_mc_name(ipmi_mc_t *mc, void *cb_data)
{
    char *mc_name = cb_data;

    ipmi_mc_get_name(mc, mc_name, IPMI_MC_NAME_LEN);
}

static void
domain_event_handler(ipmi_domain_t *domain,
		     ipmi_event_t  *event,
		     void          *cb_data)
{
    char            *errstr = NULL;
    int             rv = 0;
    ipmi_cmd_info_t *evi;
    ipmi_mcid_t     mcid;
    char            mc_name[IPMI_MC_NAME_LEN];
    unsigned int    len;
    unsigned char   *data;
    unsigned int    i;

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    mcid = ipmi_event_get_mcid(event);
    rv = ipmi_mc_pointer_cb(mcid, get_mc_name, mc_name);
    if (rv) {
	/* The MC went away, that's actually ok, just ignore it. */
	ipmi_cmdlang_cmd_info_put(evi);
	return;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Event");
    ipmi_cmdlang_out(evi, "MC", mc_name);
    ipmi_cmdlang_out_int(evi, "Record ID", ipmi_event_get_record_id(event));
    ipmi_cmdlang_out_int(evi, "Event type", ipmi_event_get_type(event));
    ipmi_cmdlang_out_long(evi, "Timestamp",
			  (long) ipmi_event_get_timestamp(event));
    len = ipmi_event_get_data_len(event);
    if (len) {
	ipmi_cmdlang_out(evi, "Data", NULL);
	ipmi_cmdlang_down(evi);
	data = ipmi_event_get_data_ptr(event);
	for (i=0; i<len; i++) {
	    ipmi_cmdlang_out_hex(evi, "Event byte", data[i]);
	}
	ipmi_cmdlang_up(evi);
    }

 out_err:
    if (rv) {
	char domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

	ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
	ipmi_cmdlang_global_err(domain_name,
				"cmd_domain.c(domain_event_handler)",
				errstr, rv);
    }
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
}

void entity_change(enum ipmi_update_e op,
		   ipmi_domain_t      *domain,
		   ipmi_entity_t      *entity,
		   void               *cb_data);
void mc_change(enum ipmi_update_e op,
	       ipmi_domain_t      *domain,
	       ipmi_mc_t          *mc,
	       void               *cb_data);

void
domain_new_done(ipmi_domain_t *domain,
		int           err,
		unsigned int  conn_num,
		unsigned int  port_num,
		int           still_connected,
		void          *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    int             rv, rv2;
    char            *errstr;
    char            domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    /* This call will detect and ignore duplicates, no special
       handling required. */
    rv2 = ipmi_domain_add_connect_change_handler(domain, domain_con_change,
						 NULL);

    /* Remove ourselves from the connection change list. */
    rv = ipmi_domain_remove_connect_change_handler(domain, domain_new_done,
						   cb_data);
    if (rv) {
	/* If we were unable to remove ourselves, then we must not
	   have been the first one that got called in this callback.
	   Not a big deal, call the asynchronous handler. */
	domain_con_change(domain, err, conn_num, port_num, still_connected,
			  NULL);
	return;
    }

    if (rv2) {
	errstr = "Error adding connect change handler";
	rv = rv2;
	goto out_err;
    }

    /* Register handlers. */
    rv = ipmi_domain_add_event_handler(domain, domain_event_handler, NULL);
    if (rv) {
	errstr = "ipmi_register_for_events";
	goto out_err;
    }

    rv = ipmi_domain_enable_events(domain);
    if (rv) {
	errstr = "ipmi_domain_enable_events";
	goto out_err;
    }

    rv = ipmi_domain_add_entity_update_handler(domain, entity_change, domain);
    if (rv) {
	errstr = "ipmi_bmc_set_entity_update_handler";
	goto out_err;
    }

    rv = ipmi_domain_add_mc_updated_handler(domain, mc_change, domain);
    if (rv) {
	errstr = "ipmi_bmc_set_entity_update_handler";
	goto out_err;
    }

    ipmi_cmdlang_out(cmd_info, "New Domain", NULL);
    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out_int(cmd_info, "Connection Number", conn_num);
    ipmi_cmdlang_out_int(cmd_info, "Port Number", port_num);
    ipmi_cmdlang_out_int(cmd_info, "Any Connection Up", still_connected);
    ipmi_cmdlang_out_int(cmd_info, "Error", err);
    ipmi_cmdlang_up(cmd_info);

    ipmi_cmdlang_cmd_info_put(cmd_info);
    return;

 out_err:
    /* FIXME - should we shut the connection down on errors? */
    {
	ipmi_cmdlang_global_err(domain_name, "cmd_domain.c(domain_new_done)",
				errstr, rv);
    }
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
domain_new(ipmi_cmd_info_t *cmd_info)
{
    ipmi_args_t  *con_parms[2];
    int          set = 0;
    int          i;
    ipmi_con_t   *con[2];
    int          rv;
    char         *name;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	cmd_info->cmdlang->errstr = "No domain name entered";
	cmd_info->cmdlang->err = EINVAL;
	goto out;
    }
    name = cmd_info->argv[cmd_info->curr_arg];
    cmd_info->curr_arg++;

    rv = ipmi_parse_args(&cmd_info->curr_arg,
			 cmd_info->argc,
			 cmd_info->argv,
			 &con_parms[set]);
    if (rv) {
	cmd_info->cmdlang->errstr = "First connection parms are invalid";
	cmd_info->cmdlang->err = rv;
	goto out;
    }
    set++;

    if (cmd_info->curr_arg > cmd_info->argc) {
	rv = ipmi_parse_args(&cmd_info->curr_arg,
			     cmd_info->argc,
			     cmd_info->argv,
			     &con_parms[set]);
	if (rv) {
	    ipmi_free_args(con_parms[0]);
	    cmd_info->cmdlang->errstr = "Second connection parms are invalid";
	    cmd_info->cmdlang->err = rv;
	    goto out;
	}
	set++;
    }

    for (i=0; i<set; i++) {
	rv = ipmi_args_setup_con(con_parms[i],
				 cmd_info->cmdlang->os_hnd,
				 cmd_info->cmdlang->selector,
				 &con[i]);
	if (rv) {
	    cmd_info->cmdlang->errstr = "Unable to setup connection";
	    cmd_info->cmdlang->err = rv;
	    for (i=0; i<set; i++)
		ipmi_free_args(con_parms[i]);
	    goto out;
	}
    }

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_open_domain(name, con, set, domain_new_done,
			  cmd_info, NULL, 0, NULL);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmd_info->cmdlang->errstr = strerror(rv);
	cmd_info->cmdlang->err = rv;
	for (i=0; i<set; i++) {
	    ipmi_free_args(con_parms[i]);
	    con[i]->close_connection(con[i]);
	}
	goto out;
    }

    for (i=0; i<set; i++)
      ipmi_free_args(con_parms[i]);

 out:
    if (cmd_info->cmdlang->err)
	cmd_info->cmdlang->location = "cmd_domain.c(domain_new)";

    return;
}


static void
domain_fru_fetched(ipmi_fru_t *fru, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;

    if (err) {
	ipmi_domain_t *domain = ipmi_fru_get_domain(fru);

	cmd_info->cmdlang->errstr = "Error fetching FRU info";
	cmd_info->cmdlang->err = err;
	ipmi_domain_get_name(domain, cmd_info->cmdlang->objstr,
			     cmd_info->cmdlang->objstr_len);
	cmd_info->cmdlang->location = "cmd_domain.c(domain_fru_fetched)";
	goto out;
    }

    ipmi_cmdlang_dump_fru_info(cmd_info, fru);

 out:
    if (err != ECANCELED)
	ipmi_fru_destroy(fru, NULL, NULL);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
domain_fru(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    int is_logical;
    int device_addr;
    int device_id;
    int lun;
    int private_bus;
    int channel;
    int rv;
    int curr_arg = cmd_info->curr_arg;

    if ((cmd_info->argc - curr_arg) < 6) {
	/* Not enough parameters */
	cmd_info->cmdlang->errstr = "Not enough parameters";
	cmd_info->cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_bool(cmd_info->argv[curr_arg],
			  &is_logical, cmd_info->cmdlang);
    if (cmd_info->cmdlang->err) {
	cmd_info->cmdlang->errstr = "is_logical invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(cmd_info->argv[curr_arg],
			 &device_addr, cmd_info->cmdlang);
    if (cmd_info->cmdlang->err) {
	cmd_info->cmdlang->errstr = "device_address invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(cmd_info->argv[curr_arg],
			 &device_id, cmd_info->cmdlang);
    if (cmd_info->cmdlang->err) {
	cmd_info->cmdlang->errstr = "device_id invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(cmd_info->argv[curr_arg],
			 &lun, cmd_info->cmdlang);
    if (cmd_info->cmdlang->err) {
	cmd_info->cmdlang->errstr = "lun invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(cmd_info->argv[curr_arg],
			 &private_bus, cmd_info->cmdlang);
    if (cmd_info->cmdlang->err) {
	cmd_info->cmdlang->errstr = "private_bus invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(cmd_info->argv[curr_arg],
			 &channel, cmd_info->cmdlang);
    if (cmd_info->cmdlang->err) {
	cmd_info->cmdlang->errstr = "channel invalid";
	goto out_err;
    }
    curr_arg++;
    cmd_info->curr_arg = curr_arg;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_fru_alloc(domain,
			is_logical,
			device_addr,
			device_id,
			lun,
			private_bus,
			channel,
			domain_fru_fetched,
			cmd_info,
			NULL);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmd_info->cmdlang->errstr = "Error allocating FRU info";
	cmd_info->cmdlang->err = rv;
	goto out_err;
    }

    return;

 out_err:
    ipmi_domain_get_name(domain, cmd_info->cmdlang->objstr,
			 cmd_info->cmdlang->objstr_len);
    cmd_info->cmdlang->location = "cmd_domain.c(domain_fru)";
}

static int
domain_msg_handler(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_msg_t       *msg = &rspi->msg;
    ipmi_ipmb_addr_t *addr = (ipmi_ipmb_addr_t *) &rspi->addr;
    ipmi_cmd_info_t  *cmd_info = rspi->data1;

    ipmi_cmdlang_out(cmd_info, "Response", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out_int(cmd_info, "channel", addr->channel);
    ipmi_cmdlang_out_hex(cmd_info, "ipmb", addr->slave_addr);
    ipmi_cmdlang_out_int(cmd_info, "LUN", addr->lun);
    ipmi_cmdlang_out_int(cmd_info, "NetFN", msg->netfn);
    ipmi_cmdlang_out_int(cmd_info, "command", msg->cmd);
    if (msg->data_len)
	ipmi_cmdlang_out_binary(cmd_info, "Data", msg->data, msg->data_len);
    ipmi_cmdlang_up(cmd_info);

    ipmi_cmdlang_cmd_info_put(cmd_info);

    return IPMI_MSG_ITEM_NOT_USED;
}

static void
domain_msg(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    int channel;
    int ipmb;
    int is_broadcast = 0;
    int LUN;
    int NetFN;
    int command;
    unsigned char data[100];
    int rv;
    int curr_arg = cmd_info->curr_arg;
    int i;
    ipmi_ipmb_addr_t addr;
    ipmi_msg_t msg;

    if ((cmd_info->argc - curr_arg) < 5) {
	/* Not enough parameters */
	cmd_info->cmdlang->errstr = "Not enough parameters";
	cmd_info->cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(cmd_info->argv[curr_arg],
			  &channel, cmd_info->cmdlang);
    if (cmd_info->cmdlang->err) {
	cmd_info->cmdlang->errstr = "channel invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(cmd_info->argv[curr_arg],
			 &ipmb, cmd_info->cmdlang);
    if (cmd_info->cmdlang->err) {
	cmd_info->cmdlang->errstr = "ipmb invalid";
	goto out_err;
    }
    curr_arg++;

    if (ipmb == 0) {
	is_broadcast = 1;
	if ((cmd_info->argc - curr_arg) < 5) {
	    /* Not enough parameters */
	    cmd_info->cmdlang->errstr = "Not enough parameters";
	    cmd_info->cmdlang->err = EINVAL;
	    goto out_err;
	}
	ipmi_cmdlang_get_int(cmd_info->argv[curr_arg],
			     &ipmb, cmd_info->cmdlang);
	if (cmd_info->cmdlang->err) {
	    cmd_info->cmdlang->errstr = "ipmb invalid";
	    goto out_err;
	}
	curr_arg++;
    }

    ipmi_cmdlang_get_int(cmd_info->argv[curr_arg],
			 &LUN, cmd_info->cmdlang);
    if (cmd_info->cmdlang->err) {
	cmd_info->cmdlang->errstr = "LUN invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(cmd_info->argv[curr_arg],
			 &NetFN, cmd_info->cmdlang);
    if (cmd_info->cmdlang->err) {
	cmd_info->cmdlang->errstr = "NetFN invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(cmd_info->argv[curr_arg],
			 &command, cmd_info->cmdlang);
    if (cmd_info->cmdlang->err) {
	cmd_info->cmdlang->errstr = "command invalid";
	goto out_err;
    }
    curr_arg++;

    i = 0;
    while (curr_arg < cmd_info->argc) {
	ipmi_cmdlang_get_uchar(cmd_info->argv[curr_arg],
			       &data[i], cmd_info->cmdlang);
	if (cmd_info->cmdlang->err) {
	    cmd_info->cmdlang->errstr = "data invalid";
	    goto out_err;
	}
	curr_arg++;
    }

    cmd_info->curr_arg = curr_arg;
    if (is_broadcast)
	addr.addr_type = IPMI_IPMB_BROADCAST_ADDR_TYPE;
    else
	addr.addr_type = IPMI_IPMB_ADDR_TYPE;
    addr.channel = channel;
    addr.slave_addr = ipmb;
    addr.lun = LUN;
    msg.netfn = NetFN;
    msg.cmd = command;
    msg.data_len = 1;
    msg.data = data;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_send_command_addr(domain,
				(ipmi_addr_t *) &(addr),
				sizeof(addr),
				&msg,
				domain_msg_handler,
				cmd_info, NULL);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmd_info->cmdlang->errstr = "Error sending message";
	cmd_info->cmdlang->err = rv;
	goto out_err;
    }

    return;

 out_err:
    ipmi_domain_get_name(domain, cmd_info->cmdlang->objstr,
			 cmd_info->cmdlang->objstr_len);
    cmd_info->cmdlang->location = "cmd_domain.c(domain_msg)";
}

static ipmi_cmdlang_cmd_t *domain_cmds;

int
ipmi_cmdlang_domain_init(void)
{
    int rv;

    rv = ipmi_cmdlang_reg_cmd(NULL,
			      "domain",
			      "Commands dealing with domains",
			      NULL, NULL,
			      &domain_cmds);
    if (rv)
	goto out;

    rv = ipmi_cmdlang_reg_cmd(domain_cmds,
			      "list",
			      "- List all the domains in the system",
			      domain_list, NULL,
			      NULL);
    if (rv)
	goto out;

    rv = ipmi_cmdlang_reg_cmd(domain_cmds,
			      "info",
			      "<domain> - Dump information about a domain",
			      ipmi_cmdlang_domain_handler, domain_info,
			      NULL);
    if (rv)
	goto out;

    rv = ipmi_cmdlang_reg_cmd(domain_cmds,
			      "new",
			      "<domain parms> - Set up a new domain",
			      domain_new, NULL,
			      NULL);
    if (rv)
	goto out;

    rv = ipmi_cmdlang_reg_cmd(domain_cmds,
			      "fru",
			      "<domain> <is_logical> <device_address>"
			      " <device_id>"
			      " <lun> <private_bus> <channel> - Fetch FRU"
			      " data with the given parms",
			      ipmi_cmdlang_domain_handler, domain_fru,
			      NULL);
    if (rv)
	goto out;

    rv = ipmi_cmdlang_reg_cmd(domain_cmds,
			      "msg",
			      "<domain> <channel> <ipmb> <LUN> <NetFN>"
			      " <command> [data...] - Send a message to the"
			      " given address",
			      ipmi_cmdlang_domain_handler, domain_msg,
			      NULL);
    if (rv)
	goto out;

 out:

    return rv;
}

#if 0
void ipmi_domain_set_sel_rescan_time(ipmi_domain_t *domain,
				     unsigned int  seconds);
void ipmi_domain_set_ipmb_rescan_time(ipmi_domain_t *domain,
				      unsigned int  seconds);
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
#endif
