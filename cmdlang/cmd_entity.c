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
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_entity.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_conn.h>

/* Don't pollute the namespace iwth ipmi_fru_t. */
void ipmi_cmdlang_dump_fru_info(ipmi_cmd_info_t *cmd_info, ipmi_fru_t *fru);

void ipmi_cmdlang_sensor_change(enum ipmi_update_e op,
				ipmi_entity_t      *entity,
				ipmi_sensor_t      *sensor,
				void               *cb_data);
void ipmi_cmdlang_control_change(enum ipmi_update_e op,
				 ipmi_entity_t      *entity,
				 ipmi_control_t      *control,
				 void               *cb_data);

static void
entity_list_handler(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            entity_name[IPMI_ENTITY_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));

    ipmi_cmdlang_out(cmd_info, "Name", entity_name);
}

static void
entity_iterate_handler(ipmi_entity_t *entity, ipmi_entity_t *parent,
		       void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            entity_name[IPMI_ENTITY_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_entity_get_name(parent, entity_name, sizeof(entity_name));

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
    char            entity_name[IPMI_ENTITY_NAME_LEN];

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));

    ipmi_cmdlang_out(cmd_info, "Entity", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", entity_name);
    type = ipmi_entity_get_type(entity);
    if (type > IPMI_ENTITY_GENERIC)
	type = IPMI_ENTITY_GENERIC + 1;
    ipmi_cmdlang_out(cmd_info, "Type", ent_types[type]);

    ipmi_cmdlang_out_bool(cmd_info, "Present", ipmi_entity_is_present(entity));
    ipmi_cmdlang_out_bool(cmd_info, "Presence sensor always there",
			 ipmi_entity_get_presence_sensor_always_there(entity));
    ipmi_cmdlang_out_bool(cmd_info, "Hot swappable",
			  ipmi_entity_hot_swappable(entity));

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
	ipmi_cmdlang_out_bool(cmd_info, "ACPI_system_power_notify_required",
		    ipmi_entity_get_ACPI_system_power_notify_required(entity));
	ipmi_cmdlang_out_bool(cmd_info, "ACPI_device_power_notify_required",
		    ipmi_entity_get_ACPI_device_power_notify_required(entity));
	ipmi_cmdlang_out_bool(cmd_info, "controller_logs_init_agent_errors",
		    ipmi_entity_get_controller_logs_init_agent_errors(entity));
	ipmi_cmdlang_out_bool(cmd_info, "log_init_agent_errors_accessing",
		    ipmi_entity_get_log_init_agent_errors_accessing(entity));
	ipmi_cmdlang_out_bool(cmd_info, "global_init",
			      ipmi_entity_get_global_init(entity));
	ipmi_cmdlang_out_bool(cmd_info, "chassis_device",
			      ipmi_entity_get_chassis_device(entity));
	ipmi_cmdlang_out_bool(cmd_info, "bridge",
			      ipmi_entity_get_bridge(entity));
	ipmi_cmdlang_out_bool(cmd_info, "IPMB_event_generator",
			      ipmi_entity_get_IPMB_event_generator(entity));
	ipmi_cmdlang_out_bool(cmd_info, "IPMB_event_receiver",
			      ipmi_entity_get_IPMB_event_receiver(entity));
	ipmi_cmdlang_out_bool(cmd_info, "FRU_inventory_device",
			      ipmi_entity_get_FRU_inventory_device(entity));
	ipmi_cmdlang_out_bool(cmd_info, "SEL_device",
			      ipmi_entity_get_SEL_device(entity));
	ipmi_cmdlang_out_bool(cmd_info, "SDR_repository_device",
			      ipmi_entity_get_SDR_repository_device(entity));
	ipmi_cmdlang_out_bool(cmd_info, "sensor_device",
			      ipmi_entity_get_sensor_device(entity));
	break;

    case IPMI_ENTITY_FRU:
	ipmi_cmdlang_out_int(cmd_info, "Channel",
			     ipmi_entity_get_channel(entity));
	ipmi_cmdlang_out_int(cmd_info, "LUN", ipmi_entity_get_lun(entity));
	ipmi_cmdlang_out_hex(cmd_info, "OEM", ipmi_entity_get_oem(entity));
	ipmi_cmdlang_out_hex(cmd_info, "access_address",
			 ipmi_entity_get_access_address(entity));
	ipmi_cmdlang_out_hex(cmd_info, "private_bus_id",
			 ipmi_entity_get_private_bus_id(entity));
	ipmi_cmdlang_out_int(cmd_info, "device_type",
			 ipmi_entity_get_device_type(entity));
	ipmi_cmdlang_out_int(cmd_info, "device_modifier",
			 ipmi_entity_get_device_modifier(entity));
	ipmi_cmdlang_out_bool(cmd_info, "is_logical_fru",
			 ipmi_entity_get_is_logical_fru(entity));
	ipmi_cmdlang_out_hex(cmd_info, "fru_device_id",
			 ipmi_entity_get_fru_device_id(entity));
	break;

    case IPMI_ENTITY_GENERIC:
	ipmi_cmdlang_out_int(cmd_info, "Channel",
			     ipmi_entity_get_channel(entity));
	ipmi_cmdlang_out_int(cmd_info, "LUN", ipmi_entity_get_lun(entity));
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
    ipmi_cmdlang_up(cmd_info);
}

static void
fru_info(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_fru_t      *fru;
    char            entity_name[IPMI_ENTITY_NAME_LEN];

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));

    ipmi_cmdlang_out(cmd_info, "Entity", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", entity_name);

    /* We cheat here and don't call the entity functions, but that
       allows us to reuse the FRU output functions.  If you are
       looking at this for an example DON'T DO THIS IN YOUR CODE. */
    fru = ipmi_entity_get_fru(entity);
    if (fru)
	ipmi_cmdlang_dump_fru_info(cmd_info, fru);
    ipmi_cmdlang_up(cmd_info);
}

void fru_change(enum ipmi_update_e op,
		ipmi_entity_t      *entity,
		void               *cb_data)
{
    char            *errstr;
    int             rv;
    ipmi_cmd_info_t *evi;
    ipmi_fru_t      *fru;
    char            entity_name[IPMI_ENTITY_NAME_LEN];

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Entity FRU");
    ipmi_cmdlang_out(evi, "Name", entity_name);

    switch (op) {
    case IPMI_ADDED:
	ipmi_cmdlang_out(evi, "Operation", "Add");
	if (ipmi_cmdlang_get_evinfo()) {
	    ipmi_cmdlang_down(evi);
	    fru = ipmi_entity_get_fru(entity);
	    if (fru)
		ipmi_cmdlang_dump_fru_info(evi, fru);
	    ipmi_cmdlang_up(evi);
	}
	break;

    case IPMI_DELETED:
	ipmi_cmdlang_out(evi, "Operation", "Delete");
	break;

    case IPMI_CHANGED:
	ipmi_cmdlang_out(evi, "Operation", "Change");
	if (ipmi_cmdlang_get_evinfo()) {
	    ipmi_cmdlang_down(evi);
	    fru = ipmi_entity_get_fru(entity);
	    if (fru)
		ipmi_cmdlang_dump_fru_info(evi, fru);
	    ipmi_cmdlang_up(evi);
	}
	break;
    }

    ipmi_cmdlang_cmd_info_put(evi);
    return;

 out_err:
    ipmi_cmdlang_global_err(entity_name,
			    "cmd_entity.c(fru_change)",
			    errstr, rv);
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
}

static int
presence_change(ipmi_entity_t *entity,
		int           present,
		void          *cb_data,
		ipmi_event_t  *event)
{
    char            *errstr;
    int             rv;
    ipmi_cmd_info_t *evi;
    char            entity_name[IPMI_ENTITY_NAME_LEN];

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Entity");
    ipmi_cmdlang_out(evi, "Name", entity_name);
    ipmi_cmdlang_out(evi, "Operation", "Presence Change");
    ipmi_cmdlang_out_bool(evi, "Present", present);

    if (event)
	ipmi_cmdlang_event_out(event, evi);

    ipmi_cmdlang_cmd_info_put(evi);
    return IPMI_EVENT_HANDLED;

 out_err:
    ipmi_cmdlang_global_err(entity_name,
			    "cmd_entity.c(presence_change)",
			    errstr, rv);
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);

    return IPMI_EVENT_NOT_HANDLED;
}

void
ipmi_cmdlang_entity_change(enum ipmi_update_e op,
			   ipmi_domain_t      *domain,
			   ipmi_entity_t      *entity,
			   void               *cb_data)
{
    char            *errstr;
    int             rv;
    ipmi_cmd_info_t *evi;
    char            entity_name[IPMI_ENTITY_NAME_LEN];

    ipmi_entity_get_name(entity, entity_name, sizeof(entity_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Entity");
    ipmi_cmdlang_out(evi, "Name", entity_name);

    switch (op) {
    case IPMI_ADDED:
	ipmi_cmdlang_out(evi, "Operation", "Add");
	if (ipmi_cmdlang_get_evinfo()) {
	    ipmi_cmdlang_down(evi);
	    entity_info(entity, evi);
	    ipmi_cmdlang_up(evi);
	}
	rv = ipmi_entity_add_sensor_update_handler(entity,
						   ipmi_cmdlang_sensor_change,
						   entity);
	if (rv) {
	    errstr = "ipmi_entity_add_sensor_update_handler";
	    goto out_err;
	}
	rv = ipmi_entity_add_fru_update_handler(entity,
						fru_change,
						entity);
	if (rv) {
	    errstr = "ipmi_entity_add_control_fru_handler";
	    goto out_err;
	}
	rv = ipmi_entity_add_presence_handler(entity,
					      presence_change,
					      NULL);
	if (rv) {
	    errstr = "ipmi_entity_add_presence_handler";
	    goto out_err;
	}
	rv = ipmi_entity_add_control_update_handler
	    (entity,
	     ipmi_cmdlang_control_change,
	     entity);
	if (rv) {
	    errstr = "ipmi_entity_add_control_update_handler";
	    goto out_err;
	}
#if 0
	rv = ipmi_entity_add_hot_swap_handler(entity,
					      entity_hot_swap,
					      NULL);
	if (rv) {
	    errstr = "ipmi_entity_add_hot_swap_handler";
	    goto out_err;
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
		entity_info(entity, evi);
		ipmi_cmdlang_up(evi);
	    }
	    break;
    }

    ipmi_cmdlang_cmd_info_put(evi);
    return;

 out_err:
    ipmi_cmdlang_global_err(entity_name,
			    "cmd_entity.c(ipmi_cmdlang_entity_change)",
			    errstr, rv);
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
}

static ipmi_cmdlang_cmd_t *entity_cmds;

static ipmi_cmdlang_init_t cmds_entity[] =
{
    { "entity", NULL,
      "Commands dealing with entities",
      NULL, NULL, &entity_cmds },
    { "list", &entity_cmds,
      "- List all the entities in the system",
      ipmi_cmdlang_domain_handler, entity_list, NULL },
    { "info", &entity_cmds,
      "<entity> - Dump information about an entity",
      ipmi_cmdlang_entity_handler, entity_info, NULL },
    { "fru", &entity_cmds,
      "<entity> - Dump FRU information about an entity",
      ipmi_cmdlang_entity_handler, fru_info, NULL },
};
#define CMDS_ENTITY_LEN (sizeof(cmds_entity)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_entity_init(void)
{
    return ipmi_cmdlang_reg_table(cmds_entity, CMDS_ENTITY_LEN);
}

#if 0
* entity
  * hs - hot-swap control
    * get_act_time <entity> - Get the host-swap auto-activate time
    * set_act_time <entity> - Set the host-swap auto-activate time
    * get_deact_time <entity> - Get the host-swap auto-deactivate time
    * set_deact_time <entity> - Set the host-swap auto-deactivate time
    * activation_request <entity> Act like a user requested an
      activation of the entity.  This is generally equivalent to
      closing the handle latch or something like that.
    * activate <entity> - activate the given entity
    * deactivate <entity> - deactivate the given entity
    * state <entity> - Return the current hot-swap state of the given entity
      FIXME - combine this in with the entity info.
    * check <domain> - Audit all the entity hot-swap states
#endif
