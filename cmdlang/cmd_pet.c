/*
 * cmd_pet.c
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
#include <OpenIPMI/ipmi_pet.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_cmdlang.h>


static void
pet_list_handler(ipmi_pet_t *pet, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            pet_name[IPMI_PET_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_pet_get_name(pet, pet_name, sizeof(pet_name));

    ipmi_cmdlang_out(cmd_info, "Name", pet_name);
}

static void
pet_list(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char             domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "Domain", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
    ipmi_cmdlang_out(cmd_info, "PETs", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_pet_iterate_pets(domain, pet_list_handler, cmd_info);
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
pet_info(ipmi_pet_t *pet, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    int             rv;
    unsigned char   mac_addr[6];
    struct in_addr  ip_addr;
    char            pet_name[IPMI_PET_NAME_LEN];

    ipmi_pet_get_name(pet, pet_name, sizeof(pet_name));
    ipmi_cmdlang_out(cmd_info, "PET", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", pet_name);
    rv = ipmi_mc_pointer_cb(ipmi_pet_get_mc_id(pet), get_mc_name, cmd_info);
    if (rv)
	ipmi_cmdlang_out(cmd_info, "Domain", NULL);
    ipmi_cmdlang_out_int(cmd_info, "Channel", ipmi_pet_get_channel(pet));
    ipmi_cmdlang_out_ip(cmd_info, "IP Address",
			ipmi_pet_get_ip_addr(pet, &ip_addr));
    ipmi_cmdlang_out_mac(cmd_info, "MAC Address",
			 ipmi_pet_get_mac_addr(pet, mac_addr));
    ipmi_cmdlang_out_int(cmd_info, "EFT Selector", ipmi_pet_get_eft_sel(pet));
    ipmi_cmdlang_out_int(cmd_info, "Policy Number",
			 ipmi_pet_get_policy_num(pet));
    ipmi_cmdlang_out_int(cmd_info, "APT Selector", ipmi_pet_get_apt_sel(pet));
    ipmi_cmdlang_out_int(cmd_info, "LAN Dest Selector",
			 ipmi_pet_get_lan_dest_sel(pet));
    ipmi_cmdlang_up(cmd_info);
}

static void
pet_done(ipmi_pet_t *pet, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            pet_name[IPMI_PET_NAME_LEN];

    ipmi_pet_get_name(pet, pet_name, sizeof(pet_name));
    ipmi_cmdlang_out(cmd_info, "PET Created", pet_name);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
pet_new(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             connection;
    int             channel;
    struct in_addr  ip_addr;
    unsigned char   mac_addr[6];
    int             eft_selector;
    int             policy_num;
    int             apt_selector;
    int             lan_dest_selector;
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);

    if ((argc - curr_arg) < 8) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &connection, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "connection invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &channel, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "channel invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_ip(argv[curr_arg],	&ip_addr, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "ip addr invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_mac(argv[curr_arg], mac_addr, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "mac addr invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &eft_selector, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "eft_selector invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &policy_num, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "policy num invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &apt_selector, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "apt selectory invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &lan_dest_selector, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "lan dest selector invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_pet_create(domain,
			 connection,
			 channel,
			 ip_addr,
			 mac_addr,
			 eft_selector,
			 policy_num,
			 apt_selector,
			 lan_dest_selector,
			 pet_done,
			 cmd_info,
			 NULL);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error from ipmi_pet_create";
	cmdlang->err = rv;
	goto out_err;
    }

    return;

 out_err:
    ipmi_domain_get_name(domain, cmdlang->objstr,
			 cmdlang->objstr_len);
    cmdlang->location = "cmd_pet.c(pet_new)";
}

static void
pet_mcnew(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             channel;
    struct in_addr  ip_addr;
    unsigned char   mac_addr[6];
    int             eft_selector;
    int             policy_num;
    int             apt_selector;
    int             lan_dest_selector;
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);

    if ((argc - curr_arg) < 7) {
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

    ipmi_cmdlang_get_ip(argv[curr_arg],	&ip_addr, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "ip addr invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_mac(argv[curr_arg], mac_addr, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "mac addr invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &eft_selector, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "eft_selector invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &policy_num, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "policy num invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &apt_selector, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "apt selectory invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &lan_dest_selector, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "lan dest selector invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_pet_create_mc(mc,
			    channel,
			    ip_addr,
			    mac_addr,
			    eft_selector,
			    policy_num,
			    apt_selector,
			    lan_dest_selector,
			    pet_done,
			    cmd_info,
			    NULL);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error from ipmi_pet_create";
	cmdlang->err = rv;
	goto out_err;
    }

    return;

 out_err:
    ipmi_mc_get_name(mc, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_pet.c(pet_mcnew)";
}

static void
close_done(ipmi_pet_t *pet, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            pet_name[IPMI_PET_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	ipmi_pet_get_name(pet, cmdlang->objstr,
			  cmdlang->objstr_len);
	cmdlang->errstr = "Error closing PET";
	cmdlang->err = err;
	cmdlang->location = "cmd_pet.c(close_done)";
	goto out;
    }

    ipmi_pet_get_name(pet, pet_name, sizeof(pet_name));
    ipmi_cmdlang_out(cmd_info, "PET destroyed", pet_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
pet_close(ipmi_pet_t *pet, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_pet_destroy(pet, close_done, cmd_info);
    if (rv) {
	ipmi_pet_get_name(pet, cmdlang->objstr,
			  cmdlang->objstr_len);
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error closing PET";
	cmdlang->err = rv;
	cmdlang->location = "cmd_pet.c(pet_close)";
    }
}

static ipmi_cmdlang_cmd_t *pet_cmds;

static ipmi_cmdlang_init_t cmds_pet[] =
{
    { "pet", NULL,
      "- Commands dealing with Platform Event Traps (PETs)",
      NULL, NULL, &pet_cmds},
    { "list", &pet_cmds,
      "- List all the pets in the system",
      ipmi_cmdlang_domain_handler, pet_list,  NULL },
    { "new", &pet_cmds,
      "<domain> <connection> <channel> <ip addr> <mac_addr> <eft selector>"
      " <policy num> <apt selector> <lan dest selector>"
      " - Set up the domain to send PET traps from the given connection"
      " to the given IP/MAC address over the given channel",
      ipmi_cmdlang_domain_handler, pet_new, NULL },
    { "mcnew", &pet_cmds,
      "<mc> <channel> <ip addr> <mac_addr> <eft selector>"
      " <policy num> <apt selector> <lan dest selector>"
      " - Set up the domain to send PET traps from the given connection"
      " to the given IP/MAC address over the given channel",
      ipmi_cmdlang_mc_handler, pet_mcnew, NULL },
    { "info", &pet_cmds,
      "<pet> - Dump information about a pet",
      ipmi_cmdlang_pet_handler, pet_info, NULL },
    { "close", &pet_cmds,
      "<pet> - Close the pet",
      ipmi_cmdlang_pet_handler, pet_close, NULL },
};
#define CMDS_PET_LEN (sizeof(cmds_pet)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_pet_init(os_handler_t *os_hnd)
{
    return ipmi_cmdlang_reg_table(cmds_pet, CMDS_PET_LEN);
}
