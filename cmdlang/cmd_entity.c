/*
 * cmd_entity.c
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
entity_list_handler(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            entity_name[IPMI_ENTITY_NAME_LEN];

    if (cmd_info->cmdlang->err)
	return;

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));

    ipmi_cmdlang_out(cmd_info, "Name", entity_name);
}

static void
entity_iterate_handler(ipmi_entity_t *entity, ipmi_entity_t *parent,
		       void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            entity_name[IPMI_ENTITY_NAME_LEN];

    if (cmd_info->cmdlang->err)
	return;

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));

    ipmi_cmdlang_out(cmd_info, "Name", entity_name);
}

static void
entity_list(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;

    ipmi_domain_iterate_entities(domain, entity_list_handler, cmd_info);
}

static void
entity_info(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    enum ipmi_dlr_type_e type;
    static char     *ent_types[] = { "unknown", "mc", "fru",
				     "generic", "invalid" };

    type = ipmi_entity_get_type(entity);
    if (type > IPMI_ENTITY_GENERIC)
	type = IPMI_ENTITY_GENERIC + 1;
    ipmi_cmdlang_out(cmd_info, "Type", ent_types[type]);

    ipmi_cmdlang_out_int(cmd_info, "Present", ipmi_entity_is_present(entity));
    ipmi_cmdlang_out_int(cmd_info, "Presence sensor always there",
			 ipmi_entity_get_presence_sensor_always_there(entity));

    if (ipmi_entity_get_is_child(entity)) {
	ipmi_cmdlang_out(cmd_info, "Parents", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_entity_iterate_parents(entity, entity_iterate_handler, cmd_info);
	ipmi_cmdlang_up(cmd_info);
    }
    if (ipmi_entity_get_is_parent(entity)) {
	ipmi_cmdlang_out(cmd_info, "Children", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_entity_iterate_children(entity, entity_iterate_handler, cmd_info);
	ipmi_cmdlang_up(cmd_info);
    }

    switch (type) {
    case IPMI_ENTITY_MC:
	ipmi_cmdlang_out_int(cmd_info, "Channel",
			     ipmi_entity_get_channel(entity));
	ipmi_cmdlang_out_int(cmd_info, "LUN", ipmi_entity_get_lun(entity));
	ipmi_cmdlang_out_hex(cmd_info, "OEM", ipmi_entity_get_oem(entity));
	ipmi_cmdlang_out_hex(cmd_info, "Slave Address",
			     ipmi_entity_get_slave_address(entity));
	ipmi_cmdlang_out_int(cmd_info, "ACPI_system_power_notify_required",
		    ipmi_entity_get_ACPI_system_power_notify_required(entity));
	ipmi_cmdlang_out_int(cmd_info, "ACPI_device_power_notify_required",
		    ipmi_entity_get_ACPI_device_power_notify_required(entity));
	ipmi_cmdlang_out_int(cmd_info, "controller_logs_init_agent_errors",
		    ipmi_entity_get_controller_logs_init_agent_errors(entity));
	ipmi_cmdlang_out_int(cmd_info, "log_init_agent_errors_accessing",
		    ipmi_entity_get_log_init_agent_errors_accessing(entity));
	ipmi_cmdlang_out_int(cmd_info, "global_init",
			 ipmi_entity_get_global_init(entity));
	ipmi_cmdlang_out_int(cmd_info, "chassis_device",
			 ipmi_entity_get_chassis_device(entity));
	ipmi_cmdlang_out_int(cmd_info, "bridge",
			 ipmi_entity_get_bridge(entity));
	ipmi_cmdlang_out_int(cmd_info, "IPMB_event_generator",
			 ipmi_entity_get_IPMB_event_generator(entity));
	ipmi_cmdlang_out_int(cmd_info, "IPMB_event_receiver",
			 ipmi_entity_get_IPMB_event_receiver(entity));
	ipmi_cmdlang_out_int(cmd_info, "FRU_inventory_device",
			ipmi_entity_get_FRU_inventory_device(entity));
	ipmi_cmdlang_out_int(cmd_info, "SEL_device",
			 ipmi_entity_get_SEL_device(entity));
	ipmi_cmdlang_out_int(cmd_info, "SDR_repository_device",
			 ipmi_entity_get_SDR_repository_device(entity));
	ipmi_cmdlang_out_int(cmd_info, "sensor_device",
			 ipmi_entity_get_sensor_device(entity));
	break;

    case IPMI_ENTITY_FRU:
	ipmi_cmdlang_out_int(cmd_info, "Channel",
			     ipmi_entity_get_channel(entity));
	ipmi_cmdlang_out_int(cmd_info, "Lun", ipmi_entity_get_lun(entity));
	ipmi_cmdlang_out_hex(cmd_info, "OEM", ipmi_entity_get_oem(entity));
	ipmi_cmdlang_out_hex(cmd_info, "access_address",
			 ipmi_entity_get_access_address(entity));
	ipmi_cmdlang_out_hex(cmd_info, "private_bus_id",
			 ipmi_entity_get_private_bus_id(entity));
	ipmi_cmdlang_out_int(cmd_info, "device_type",
			 ipmi_entity_get_device_type(entity));
	ipmi_cmdlang_out_int(cmd_info, "device_modifier",
			 ipmi_entity_get_device_modifier(entity));
	ipmi_cmdlang_out_int(cmd_info, "is_logical_fru",
			 ipmi_entity_get_is_logical_fru(entity));
	ipmi_cmdlang_out_hex(cmd_info, "fru_device_id",
			 ipmi_entity_get_fru_device_id(entity));
	break;

    case IPMI_ENTITY_GENERIC:
	ipmi_cmdlang_out_int(cmd_info, "Channel",
			     ipmi_entity_get_channel(entity));
	ipmi_cmdlang_out_int(cmd_info, "Lun", ipmi_entity_get_lun(entity));
	ipmi_cmdlang_out_hex(cmd_info, "OEM", ipmi_entity_get_oem(entity));
	ipmi_cmdlang_out_hex(cmd_info, "access_address",
			 ipmi_entity_get_access_address(entity));
	ipmi_cmdlang_out_hex(cmd_info, "private_bus_id",
			 ipmi_entity_get_private_bus_id(entity));
	ipmi_cmdlang_out_int(cmd_info, "device_type",
			 ipmi_entity_get_device_type(entity));
	ipmi_cmdlang_out_int(cmd_info, "device_modifier",
			 ipmi_entity_get_device_modifier(entity));
	ipmi_cmdlang_out_hex(cmd_info, "slave_address",
			 ipmi_entity_get_slave_address(entity));
	ipmi_cmdlang_out_int(cmd_info, "address_span",
			 ipmi_entity_get_address_span(entity));
	break;

    default:
	break;
    }
}

static ipmi_cmdlang_cmd_t *entity_cmds;

int
ipmi_cmdlang_entity_init(void)
{
    int rv;

    rv = ipmi_cmdlang_reg_cmd(NULL,
			      "entity",
			      "Commands dealing with entities",
			      NULL, NULL,
			      &entity_cmds);
    if (rv)
	return rv;

    rv = ipmi_cmdlang_reg_cmd(entity_cmds,
			      "list",
			      "- List all the entities in the system",
			      ipmi_cmdlang_domain_handler, entity_list,
			      NULL);
    if (rv)
	return rv;

    rv = ipmi_cmdlang_reg_cmd(entity_cmds,
			      "info",
			      "<domain> - Dump information about an entity",
			      ipmi_cmdlang_entity_handler, entity_info,
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
