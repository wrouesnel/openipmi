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
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_conn.h>


static void
domain_list_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

    if (cmd_info->err)
	return;

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    cmd_info->err = ipmi_cmdlang_out(cmd_info, "Name", domain_name);
}

static int
domain_list(ipmi_cmd_info_t *cmd_info)
{
    cmd_info->err = 0;
    ipmi_cmdlang_out(cmd_info, "Domains", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_domain_iterate_domains(domain_list_handler, cmd_info);
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_done(cmd_info);
    return cmd_info->err;
}

static int
domain_info(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    ipmi_cmdlang_out(cmd_info, "Domain", domain_name);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Type",
		    ipmi_domain_get_type_string(ipmi_domain_get_type(domain)));
    ipmi_cmdlang_out_int(cmd_info, "SEL Rescan Time",
			 ipmi_domain_get_sel_rescan_time(domain));
    ipmi_cmdlang_out_int(cmd_info, "IPMB Rescan Time",
			 ipmi_domain_get_ipmb_rescan_time(domain));
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_done(cmd_info);
    return 0;
}

void
domain_new_done(ipmi_domain_t *domain,
		int           err,
		unsigned int  conn_num,
		unsigned int  port_num,
		int           still_connected,
		void          *cb_data)
{
}

static int
domain_new(ipmi_cmd_info_t *cmd_info)
{
    ipmi_args_t  *con_parms[2];
    int          set = 0;
    int          i;
    ipmi_con_t   *con[2];
    int          rv;
    char         *name;

    if (cmd_info->curr_arg >= cmd_info->argc) {
	cmd_info->cmdlang->err = "No domain name entered";
	return EINVAL;
    }
    name = cmd_info->argv[cmd_info->curr_arg];

    rv = ipmi_parse_args(&cmd_info->curr_arg,
			 cmd_info->argc,
			 cmd_info->argv,
			 &con_parms[set]);
    if (rv) {
	cmd_info->cmdlang->err = "First connection parms are invalid";
	return rv;
    }
    set++;

    if (cmd_info->curr_arg > cmd_info->argc) {
	rv = ipmi_parse_args(&cmd_info->curr_arg,
			     cmd_info->argc,
			     cmd_info->argv,
			     &con_parms[set]);
	if (rv) {
	    ipmi_free_args(con_parms[0]);
	    cmd_info->cmdlang->err = "Second connection parms are invalid";
	    return rv;
	}
	set++;
    }

    for (i=0; i<set; i++) {
	rv = ipmi_args_setup_con(con_parms[i],
				 cmd_info->cmdlang->os_hnd,
				 cmd_info->cmdlang->selector,
				 &con[i]);
	if (rv) {
	    cmd_info->cmdlang->err = "Unable to setup connection";
	    for (i=0; i<set; i++)
		ipmi_free_args(con_parms[i]);
	    return rv;
	}
    }

    rv = ipmi_open_domain(name, con, set, domain_new_done,
			  NULL, NULL, 0, NULL);
    if (rv) {
	cmd_info->cmdlang->err = strerror(rv);
	for (i=0; i<set; i++) {
	    ipmi_free_args(con_parms[i]);
	    con[i]->close_connection(con[i]);
	}
	return rv;
    }

    return 0;
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
	return rv;

    rv = ipmi_cmdlang_reg_cmd(domain_cmds,
			      "list",
			      "- List all the domains in the system",
			      domain_list, NULL,
			      NULL);
    if (rv)
	return rv;

    rv = ipmi_cmdlang_reg_cmd(domain_cmds,
			      "info",
			      "<domain> - Dump information about a domain",
			      ipmi_cmdlang_domain_handler, domain_info,
			      NULL);
    if (rv)
	return rv;

    rv = ipmi_cmdlang_reg_cmd(domain_cmds,
			      "new",
			      "<domain parms - Set up a new domain",
			      domain_new, NULL,
			      NULL);
    if (rv)
	return rv;

    return 0;
}

#if 0
void ipmi_domain_set_sel_rescan_time(ipmi_domain_t *domain,
				     unsigned int  seconds);
void ipmi_domain_set_ipmb_rescan_time(ipmi_domain_t *domain,
				      unsigned int  seconds);
  * fru <domain> <is_logical> <device_address> <device_id> <lun> <private_bus>
    <channel> - dump a fru given all its insundry information.
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
