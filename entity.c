/*
 * ipmi_entity.c
 *
 * MontaVista IPMI code for handling entities
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
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

#include <string.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_entity.h>
#include <OpenIPMI/ipmi_bits.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include "ilist.h"

/* These are the versions of IPMI we write to the SDR repository */
#define IPMI_MAJOR_NUM_SDR 1
#define IPMI_MINOR_NUM_SDR 5

/* Uniquely identifies a device in the system.  If all the values are
   zero, then it is not used (it's in the system-relative range). */
typedef struct ipmi_device_num_s
{
    unsigned char channel;
    unsigned char address;
} ipmi_device_num_t;

typedef struct ipmi_sensor_ref_s
{
    ipmi_sensor_id_t sensor;
    ilist_item_t     list_link;
} ipmi_sensor_ref_t;

typedef struct ipmi_control_ref_s
{
    ipmi_control_id_t control;
    ilist_item_t      list_link;
} ipmi_control_ref_t;

struct ipmi_entity_s
{
    ipmi_domain_t    *domain;
    ipmi_domain_id_t domain_id;
    long             seq;

    /* Key fields */
    uint8_t access_address;
    uint8_t slave_address;
    uint8_t channel;
    uint8_t lun;
    uint8_t private_bus_id;

    /* misc */
    unsigned int is_fru : 1;
    unsigned int is_mc : 1;

    /* If this entity is added by the user or comes from the main SDR
       repository, we don't delete it automatically if it goes
       away. */
    unsigned int came_from_SDR : 1;

    /* For FRU device only. */
    unsigned int is_logical_fru : 1;

    /* For MC device only. */
    unsigned int ACPI_system_power_notify_required : 1;
    unsigned int ACPI_device_power_notify_required : 1;
    unsigned int controller_logs_init_agent_errors : 1;
    unsigned int log_init_agent_errors_accessing : 1;
    unsigned int global_init : 2;

    unsigned int chassis_device : 1;
    unsigned int bridge : 1;
    unsigned int IPMB_event_generator : 1;
    unsigned int IPMB_event_receiver : 1;
    unsigned int FRU_inventory_device : 1;
    unsigned int SEL_device : 1;
    unsigned int SDR_repository_device : 1;
    unsigned int sensor_device : 1;

    /* For generic device only. */
    uint8_t address_span;

    ipmi_device_num_t device_num;
    uint8_t           entity_id;
    uint8_t           entity_instance;

    uint8_t device_type;
    uint8_t device_modifier;
    uint8_t oem;

    char id[33];

    /* From Entity Association Record. */
    unsigned int linked_ear_exists : 1;
    unsigned int presence_sensor_always_there : 1;

    /* Is the entity in the SDR database? */
    unsigned int in_db : 1;

    ilist_t *sub_entities;
    ilist_t *parent_entities;

    ilist_t *sensors;
    ilist_t *controls;

    char *entity_id_string;

    ipmi_sensor_t *presence_sensor;
    int           present;
    int           presence_possibly_changed;

    ipmi_entity_info_t *ents;

    ipmi_entity_sensor_cb sensor_handler;
    void                  *cb_data;

    ipmi_entity_control_cb control_handler;
    void                   *control_cb_data;

    entity_sdr_add_cb  sdr_gen_output;
    void               *sdr_gen_cb_data;

    ipmi_entity_presence_cb presence_handler;
    void                    *presence_cb_data;
};

typedef struct entity_child_link_s
{
    ipmi_entity_t *child;
    unsigned int  in_db : 1;
} entity_child_link_t;

struct ipmi_entity_info_s
{
    ipmi_domain_entity_cb handler;
    void                  *cb_data;
    ipmi_domain_t         *domain;
    ipmi_domain_id_t      domain_id;
    ilist_t               *entities;
};

int
ipmi_entity_info_alloc(ipmi_domain_t *domain, ipmi_entity_info_t **new_info)
{
    ipmi_entity_info_t *ents;

    ents = ipmi_mem_alloc(sizeof(*ents));
    if (!ents)
	return ENOMEM;

    ents->domain = domain;
    ents->domain_id = ipmi_domain_convert_to_id(domain);
    ents->handler = NULL;
    ents->entities = alloc_ilist();
    if (! ents->entities) {
	ipmi_mem_free(ents);
	return ENOMEM;
    }

    *new_info = ents;

    return 0;
}

static void
destroy_entity(ilist_iter_t *iter, void *item, void *cb_data)
{
    ipmi_entity_t *ent = (ipmi_entity_t *) item;

    free_ilist(ent->parent_entities);
    free_ilist(ent->sub_entities);
    free_ilist(ent->sensors);
    free_ilist(ent->controls);
    ipmi_mem_free(ent);
}

int
ipmi_entity_info_destroy(ipmi_entity_info_t *ents)
{
    ilist_iter(ents->entities, destroy_entity, NULL);
    free_ilist(ents->entities);
    ipmi_mem_free(ents);
    return 0;
}

static void
remove_child_cb(ilist_iter_t *iter, void *item, void *cb_data)
{
    ipmi_entity_remove_child(item, cb_data);
}

static void
remove_parent_cb(ilist_iter_t *iter, void *item, void *cb_data)
{
    entity_child_link_t *link = item;
    ipmi_entity_remove_child(cb_data, link->child);
}

static void
cleanup_entity(ipmi_entity_t *ent)
{
    ilist_iter_t iter;

    /* Tell the user I was destroyed. */
    if (ent->ents->handler)
	ent->ents->handler(IPMI_DELETED, ent->domain, ent, ent->ents->cb_data);

    /* First destroy the parent/child relationships. */
    ilist_iter(ent->sub_entities, remove_parent_cb, ent);
    ilist_iter(ent->parent_entities, remove_child_cb, ent);

    /* Remove it from the entities list. */
    ilist_init_iter(&iter, ent->ents->entities);
    ilist_unpositioned(&iter);
    while (ilist_next(&iter)) {
	if (ilist_get(&iter) == ent) {
	    ilist_delete(&iter);
	    break;
	}
    }

    /* The sensor and control lists should be empty now, we can just
       destroy it. */
    destroy_entity(NULL, ent, NULL);
}

typedef struct search_info_s {
    ipmi_device_num_t device_num;
    uint8_t           entity_id;
    uint8_t           entity_instance;
} search_info_t;

static int
search_entity(void *item, void *cb_data)
{
    ipmi_entity_t *ent = (ipmi_entity_t *) item;
    search_info_t *info = (search_info_t *) cb_data;

    return ((ent->device_num.channel == info->device_num.channel)
	    && (ent->device_num.address == info->device_num.address)
	    && (ent->entity_id == info->entity_id)
	    && (ent->entity_instance == info->entity_instance));
}

static int
entity_find(ipmi_entity_info_t *ents,
	    ipmi_device_num_t  device_num,
	    int                entity_id,
	    int                entity_instance,
	    ipmi_entity_t      **found_ent)
{
    ipmi_entity_t     *ent;
    search_info_t     info = {device_num, entity_id, entity_instance};

    ent = ilist_search(ents->entities, search_entity, &info);
    if (ent == NULL)
	return ENODEV;

    if (found_ent)
	*found_ent = ent;
    return 0;
}

int
ipmi_entity_find(ipmi_entity_info_t *ents,
		 ipmi_mc_t          *mc,
		 int                entity_id,
		 int                entity_instance,
		 ipmi_entity_t      **found_ent)
{
    ipmi_device_num_t device_num;

    CHECK_DOMAIN_LOCK(ents->domain);
    CHECK_DOMAIN_ENTITY_LOCK(ents->domain);

    if (mc && entity_instance >= 0x60) {
	device_num.channel = ipmi_mc_get_channel(mc);
	device_num.address = ipmi_mc_get_address(mc);
	entity_instance -= 0x60;
    } else {
	device_num.channel = 0;
	device_num.address = 0;
    }
    return entity_find(ents, device_num, entity_id, entity_instance, found_ent);
}

static int
entity_add(ipmi_entity_info_t *ents,
	   ipmi_device_num_t  device_num,
	   int                entity_id,
	   int                entity_instance,
	   entity_sdr_add_cb  sdr_gen_output,
	   void               *sdr_gen_cb_data,
	   ipmi_entity_t      **new_ent,
	   int                came_from_SDR)
{
    int           rv;
    ipmi_entity_t *ent;

    rv = entity_find(ents, device_num, entity_id, entity_instance, new_ent);
    if (! rv) {
	/* If it came from an SDR, it always will have come from an SDR. */
	if (!((*new_ent)->came_from_SDR))
	    ((*new_ent)->came_from_SDR) = came_from_SDR;

	if (sdr_gen_output != NULL) {
	    (*new_ent)->sdr_gen_output = sdr_gen_output;
	    (*new_ent)->sdr_gen_cb_data = sdr_gen_cb_data;
	}
	return 0;
    }

    ent = ipmi_mem_alloc(sizeof(*ent));
    if (!ent)
	return ENOMEM;
    memset(ent, 0, sizeof(*ent));

    ent->sdr_gen_output = sdr_gen_output;
    ent->sdr_gen_cb_data = sdr_gen_cb_data;
    ent->came_from_SDR = came_from_SDR;

    ent->domain = ents->domain;
    ent->domain_id = ents->domain_id;
    ent->seq = ipmi_get_seq();
    ent->sub_entities = alloc_ilist();
    if (!ent->sub_entities) {
	ipmi_mem_free(ent);
	return ENOMEM;
    }

    ent->parent_entities = alloc_ilist();
    if (!ent->parent_entities) {
	free_ilist(ent->sub_entities);
	ipmi_mem_free(ent);
	return ENOMEM;
    }

    ent->sensors = alloc_ilist();
    if (!ent->sensors) {
	free_ilist(ent->parent_entities);
	free_ilist(ent->sub_entities);
	ipmi_mem_free(ent);
	return ENOMEM;
    }

    ent->controls = alloc_ilist();
    if (!ent->controls) {
	free_ilist(ent->sensors);
	free_ilist(ent->parent_entities);
	free_ilist(ent->sub_entities);
	ipmi_mem_free(ent);
	return ENOMEM;
    }

    ent->presence_sensor = NULL;
    ent->present = 0;
    ent->presence_possibly_changed = 1;

    ent->ents = ents;

    ent->access_address = 0;
    ent->slave_address = 0;
    ent->channel = 0;
    ent->lun = 0;
    ent->private_bus_id = 0;
    ent->is_logical_fru = 0;
    ent->is_fru = 0;
    ent->address_span = 0;

    ent->device_type = 0;
    ent->device_modifier = 0;
    ent->oem = 0;

    ent->device_num = device_num;
    ent->entity_id = entity_id;
    ent->entity_instance = entity_instance;
    ent->sensor_handler = NULL;
    ent->control_handler = NULL;
    ent->in_db = 0;
    ent->linked_ear_exists = 0;
    ent->presence_sensor_always_there = 0;
    ent->id[0] = '\0';

    ent->entity_id_string = ipmi_get_entity_id_string(entity_id);

    if (!ilist_add_tail(ents->entities, ent, NULL)) {
	free_ilist(ent->controls);
	free_ilist(ent->sensors);
	free_ilist(ent->parent_entities);
	free_ilist(ent->sub_entities);
	ipmi_mem_free(ent);
	return ENOMEM;
    }

    if (ents->handler)
	ents->handler(IPMI_ADDED, ent->domain, ent, ents->cb_data);

    if (new_ent)
	*new_ent = ent;

    return 0;
}

int
ipmi_entity_add(ipmi_entity_info_t *ents,
		ipmi_domain_t      *domain,
		ipmi_mc_t          *mc,
		int                lun,
		int                entity_id,
		int                entity_instance,
		char               *id,
		entity_sdr_add_cb  sdr_gen_output,
		void               *sdr_gen_cb_data,
		ipmi_entity_t      **new_ent)
{
    ipmi_device_num_t device_num;
    int               rv;
    ipmi_entity_t     *ent;

    CHECK_DOMAIN_LOCK(domain);

    if (mc && (entity_instance >= 0x60)) {
	device_num.channel = ipmi_mc_get_channel(mc);
	device_num.address = ipmi_mc_get_address(mc);
	entity_instance -= 0x60;
    } else {
	device_num.channel = 0;
	device_num.address = 0;
    }

    ipmi_domain_entity_lock(domain);

    rv = entity_add(ents, device_num, entity_id, entity_instance,
		    sdr_gen_output, sdr_gen_cb_data, &ent, 0);
    if (!rv) {
	ipmi_entity_set_id(ent, id);
	ent->access_address = ipmi_mc_get_address(mc);
	ent->channel = ipmi_mc_get_channel(mc);
	ent->lun = lun;
	if (new_ent)
	    *new_ent = ent;
    }

    ipmi_domain_entity_unlock(domain);

    return 0;
}

static int
search_parent(void *item, void *cb_data)
{
    return (item == cb_data);
}

static int
search_child(void *item, void *cb_data)
{
    entity_child_link_t *link = item;
    ipmi_entity_t       *child = cb_data;

    return (link->child == child);
}

static int
add_child(ipmi_entity_t       *ent,
	  ipmi_entity_t       *child,
	  entity_child_link_t **new_link)
{
    entity_child_link_t *link;

    link = ilist_search(ent->sub_entities, search_child, child);
    if (link != NULL)
	goto found;

    link = ipmi_mem_alloc(sizeof(*link));
    if (!link)
	return ENOMEM;

    link->child = child;

    if (! ilist_add_tail(ent->sub_entities, link, NULL)) {
	ipmi_mem_free(link);
	return ENOMEM;
    }

    if (! ilist_add_tail(child->parent_entities, ent, NULL)) {
	ilist_iter_t iter;
	ilist_init_iter(&iter, ent->sub_entities);
	ilist_last(&iter);
	ilist_delete(&iter);
	ipmi_mem_free(link);
	return ENOMEM;
    }

    ent->presence_possibly_changed = 1;

 found:
    if (new_link)
	*new_link = link;
    return 0;
}

int
ipmi_entity_add_child(ipmi_entity_t       *ent,
		      ipmi_entity_t       *child)
{
    entity_child_link_t *link;

    CHECK_ENTITY_LOCK(ent);
    CHECK_ENTITY_LOCK(child);

    return add_child(ent, child, &link);
}

int
ipmi_entity_remove_child(ipmi_entity_t     *ent,
			 ipmi_entity_t     *child)
{
    entity_child_link_t *link;
    ilist_iter_t        iter;

    CHECK_ENTITY_LOCK(ent);
    CHECK_ENTITY_LOCK(child);

    ilist_init_iter(&iter, ent->sub_entities);
    ilist_unpositioned(&iter);

    /* Find the child in the parent's list. */
    link = ilist_search_iter(&iter, search_child, child);
    if (link == NULL)
	return ENODEV;

    ilist_delete(&iter);
    ipmi_mem_free(link);

    /* Find the parent in the child's list. */
    ilist_init_iter(&iter, child->parent_entities);
    ilist_unpositioned(&iter);
    if (ilist_search_iter(&iter, search_parent, ent))
	ilist_delete(&iter);

    ent->presence_possibly_changed = 1;

    return 0;
}

static void presence_parent_handler(ipmi_entity_t *ent,
				    ipmi_entity_t *parent,
				    void          *cb_data);

static void
presence_changed(ipmi_entity_t *ent,
		 int           present,
		 ipmi_event_t  *event)
{
    int handled = 0;

    if (present != ent->present) {
	ent->present = present;
	if (ent->presence_handler) {
	    ent->presence_handler(ent, present, ent->presence_cb_data, event);
	    handled = 1;
	}

	/* If our presence changes, that can affect parents, too.  So we
	   rescan them. */
	ipmi_entity_iterate_parents(ent, presence_parent_handler, NULL);
    }

    if (event && !handled)
	ipmi_handle_unhandled_event(ent->domain, event);
}

static void
presence_child_handler(ipmi_entity_t *ent,
		       ipmi_entity_t *child,
		       void          *cb_data)
{
    int *present = cb_data;

    if (child->present)
	*present = 1;
}

/* This is for iterating the parents when a sensor's presence changes.
   The parent's presence may depend on it's childrens' presence, if it
   has no sensors. */
static void
presence_parent_handler(ipmi_entity_t *ent,
			ipmi_entity_t *parent,
			void          *cb_data)
{
    int present = 0;

    if (! ilist_empty(parent->sensors))
	/* The parent has sensors, so it doesn't depend on the children
	   for presence. */
	return;

    /* If any children are present, then the parent is present. */
    ipmi_entity_iterate_children(parent, presence_child_handler, &present);
    presence_changed(parent, present, NULL);
}

static void
presence_sensor_changed(ipmi_sensor_t         *sensor,
			enum ipmi_event_dir_e dir,
			int                   offset,
			int                   severity,
			int                   prev_severity,
			void                  *cb_data,
			ipmi_event_t          *event)
{
    ipmi_entity_t *ent = cb_data;

    /* zero offset is the "present" offset, 1 or 2 means it absent or
       disabled, coupled with the assertion/deassertion. */
    if (dir == IPMI_ASSERTION)
	presence_changed(ent, offset == 0, event);
    else if (dir == IPMI_DEASSERTION)
	presence_changed(ent, offset != 0, event);
}

static void
states_read(ipmi_sensor_t *sensor,
	    int           err,
	    ipmi_states_t *states,
	    void          *cb_data)
{
    int           present;
    ipmi_entity_t *ent = cb_data;
    int           val;
    int           rv;

    if (err)
	return;

    rv = ipmi_discrete_event_readable(sensor, 0, &val);
    if (rv || !val)
	/* The present bit is not supported, so use the not present bit. */
	present = ! ipmi_is_state_set(states, 1);
    else
	/* The present bit is supported. */
	present = ipmi_is_state_set(states, 0);

    presence_changed(ent, present, NULL);
}

typedef struct ent_detect_info_s
{
    int force;
} ent_detect_info_t;

typedef struct ent_active_detect_s
{
    ipmi_entity_id_t ent_id;
    int              sensor_try_count;
    int              present;
} ent_active_detect_t;

static void
sensor_read_handler(ipmi_entity_t *ent, void *cb_data)
{
    ent_active_detect_t *info = cb_data;
    
    presence_changed(ent, info->present, NULL);
}

static void
detect_states_read(ipmi_sensor_t *sensor,
		   int           err,
		   ipmi_states_t *states,
		   void          *cb_data)
{
    ent_active_detect_t *info = cb_data;

    if (!err && ipmi_is_sensor_scanning_enabled(states))
	info->present = 1;

    info->sensor_try_count--;
    if (info->sensor_try_count == 0) {
	ipmi_entity_pointer_cb(info->ent_id, sensor_read_handler, info);
	ipmi_mem_free(info);
    }
}

static void
detect_reading_read(ipmi_sensor_t             *sensor,
		    int                       err,
		    enum ipmi_value_present_e value_present,
		    unsigned int              raw_val,
		    double                    val,
		    ipmi_states_t             *states,
		    void                      *cb_data)
{
    ent_active_detect_t *info = cb_data;

    if (!err && ipmi_is_sensor_scanning_enabled(states))
	info->present = 1;

    info->sensor_try_count--;
    if (info->sensor_try_count == 0) {
	ipmi_entity_pointer_cb(info->ent_id, sensor_read_handler, info);
	ipmi_mem_free(info);
    }
}

static void
sensor_detect_send(ipmi_entity_t *ent,
		   ipmi_sensor_t *sensor,
		   void          *cb_data)
{
    ent_active_detect_t *info = cb_data;
    int                 rv;

    rv = ipmi_reading_get(sensor, detect_reading_read, info);
    if (rv)
	rv = ipmi_states_get(sensor, detect_states_read, info);

    if (!rv)
	info->sensor_try_count++;
}

static void
ent_detect_presence(ipmi_entity_t *ent, void *cb_data)
{
    ent_detect_info_t   *info = cb_data;
    int                 rv;
    ent_active_detect_t *detect;

    if ((!info->force) && (! ent->presence_possibly_changed))
	return;
    ent->presence_possibly_changed = 0;

    if (ent->presence_sensor) {
	/* Presence sensor overrides everything. */
	rv = ipmi_states_get(ent->presence_sensor, states_read, ent);
    } else if (! ilist_empty(ent->sensors)) {
	/* It has sensors, try to see if any of those are active. */
	detect = ipmi_mem_alloc(sizeof(*detect));
	if (!detect)
	    return;

	detect->ent_id = ipmi_entity_convert_to_id(ent);
	detect->sensor_try_count = 0;
	detect->present = 0;
	ipmi_entity_iterate_sensors(ent, sensor_detect_send, detect);

	/* I couldn't message any sensors, the thing must be done. */
	if (detect->sensor_try_count == 0) {
	    presence_changed(ent, detect->present, NULL);
	    ipmi_mem_free(detect);
	}
    } else {
	/* Maybe it has children that can handle it's presence. */
	presence_parent_handler(NULL, ent, NULL);
    }
}

int
ipmi_detect_ents_presence_changes(ipmi_entity_info_t *ents, int force)
{
    ent_detect_info_t info;

    info.force = force;
    ipmi_entities_iterate_entities(ents, ent_detect_presence, &info);
    return 0;
}

static void
handle_new_presence_sensor(ipmi_entity_t *ent, ipmi_sensor_t *sensor)
{
    ipmi_event_state_t events;

    /* Add our own event handler. */
    ipmi_sensor_discrete_set_event_handler(sensor,
					   presence_sensor_changed,
					   ent);

    /* Configure the sensor per our liking (enable the proper events). */
    ipmi_event_state_init(&events);
    ipmi_event_state_set_events_enabled(&events, 1);
    ipmi_event_state_set_scanning_enabled(&events, 1);
    ipmi_discrete_event_set(&events, 0, IPMI_ASSERTION);
    ipmi_discrete_event_set(&events, 1, IPMI_ASSERTION);
    ipmi_sensor_events_enable_set(sensor, &events, NULL, NULL);

    ent->presence_possibly_changed = 1;
}

int
ipmi_entity_set_presence_handler(ipmi_entity_t           *ent,
				 ipmi_entity_presence_cb handler,
				 void                    *cb_data)
{
    CHECK_ENTITY_LOCK(ent);

    ent->presence_handler = handler;
    ent->presence_cb_data = cb_data;
    return 0;
}

void *
ipmi_entity_alloc_sensor_link(void)
{
    return ipmi_mem_alloc(sizeof(ipmi_sensor_ref_t));
}

void
ipmi_entity_free_sensor_link(void *link)
{
    ipmi_mem_free(link);
}

void *
ipmi_entity_alloc_control_link(void)
{
    return ipmi_mem_alloc(sizeof(ipmi_control_ref_t));
}

void
ipmi_entity_free_control_link(void *link)
{
    ipmi_mem_free(link);
}

void
ipmi_entity_add_sensor(ipmi_entity_t *ent,
		       ipmi_sensor_t *sensor,
		       void          *ref)
{
    ipmi_sensor_ref_t *link = (ipmi_sensor_ref_t *) ref;
    int               is_presence = 0;

    CHECK_ENTITY_LOCK(ent);

    /* The calling code should check for duplicates, no check done
       here. */
    link->sensor = ipmi_sensor_convert_to_id(sensor);
    link->list_link.malloced = 0;

    if ((ipmi_sensor_get_sensor_type(sensor) == 0x25)
	&& (ent->presence_sensor == NULL))
    {
	/* If it could possible be a presence sensor for us,
           double-check. */
	int val, rv;

	/* Check present bit */
	rv = ipmi_discrete_event_readable(sensor, 0, &val);
	if ((!rv) && (val))
	    is_presence = 1;
	else {
	    /* Check absent bit. */
	    rv = ipmi_discrete_event_readable(sensor, 1, &val);
	    if ((!rv) && (val))
		is_presence = 1;
	}
    }

    if (is_presence) {
	/* It's the presence sensor and we don't already have one.  We
	   keep this special. */
	ent->presence_sensor = sensor;
	handle_new_presence_sensor(ent, sensor);
	ipmi_entity_free_sensor_link(link);
    } else {
	ilist_add_tail(ent->sensors, link, &(link->list_link));
	if (ent->sensor_handler)
	    ent->sensor_handler(IPMI_ADDED, ent, sensor, ent->cb_data);
    }
}

static int sens_cmp(void *item, void *cb_data)
{
    ipmi_sensor_ref_t *ref1 = item;
    ipmi_sensor_id_t  *id2 = cb_data;

    return ipmi_cmp_sensor_id(ref1->sensor, *id2) == 0;
}

typedef struct sens_cmp_info_s
{
    int           equal;
    int           reading_type;
    ipmi_sensor_t *sensor;
} sens_cmp_info_t;

static void
sens_get_reading_type(ipmi_sensor_t *sensor, void *cb_data)
{
    sens_cmp_info_t *info = cb_data;

    info->sensor = sensor;
    info->equal
	= (info->reading_type == ipmi_sensor_get_event_reading_type(sensor));
}

static int sens_cmp_type(void *item, void *cb_data)
{
    ipmi_sensor_ref_t *ref = item;
    sens_cmp_info_t   *info = cb_data;
    int               rv;

    rv = ipmi_sensor_pointer_cb(ref->sensor, sens_get_reading_type, info);
    if (rv)
	return 0;
    
    return info->equal;
}

void
ipmi_entity_remove_sensor(ipmi_entity_t *ent,
			  ipmi_sensor_t *sensor)
{
    ipmi_sensor_ref_t *ref;
    ilist_iter_t      iter;

    CHECK_ENTITY_LOCK(ent);

    if (sensor == ent->presence_sensor) {
	sens_cmp_info_t info;

	/* See if there is another presence sensor. */
	info.reading_type = 0x08;
	ref = ilist_search_iter(&iter, sens_cmp_type, &info);

	if (ref) {
	    /* There is one, delete it from the list and from the
	       user, since we are taking it over. */
	    ilist_delete(&iter);

	    if (ent->sensor_handler)
		ent->sensor_handler(IPMI_DELETED, ent, info.sensor,
				    ent->cb_data);

	    ent->presence_sensor = info.sensor;
	    handle_new_presence_sensor(ent, info.sensor);

	    ipmi_mem_free(ref);
	} else {
	    ent->presence_sensor = NULL;
	}
	ent->presence_possibly_changed = 1;
    } else {
	ipmi_sensor_id_t id = ipmi_sensor_convert_to_id(sensor);
	ilist_init_iter(&iter, ent->sensors);
	ilist_unpositioned(&iter);
	ref = ilist_search_iter(&iter, sens_cmp, &id);
	if (!ref) {
	    ipmi_log(IPMI_LOG_WARNING, "User requested removal of a sensor"
		     " from an entity, but the sensor was not there");
	    return;
	}

	ilist_delete(&iter);
	ipmi_mem_free(ref);

	if (ent->sensor_handler)
	    ent->sensor_handler(IPMI_DELETED, ent, sensor, ent->cb_data);
    }

    if ((!ent->came_from_SDR)
	&& (!ent->presence_sensor)
	&& (ilist_empty(ent->sensors))
	&& (ilist_empty(ent->controls)))
    {
	cleanup_entity(ent);
    }
}

void
ipmi_entity_add_control(ipmi_entity_t  *ent,
			ipmi_control_t *control,
			void           *ref)
{
    ipmi_control_ref_t *link = (ipmi_control_ref_t *) ref;

    CHECK_ENTITY_LOCK(ent);

    /* The calling code should check for duplicates, no check done
       here. */
    link->control = ipmi_control_convert_to_id(control);
    link->list_link.malloced = 0;
    ilist_add_tail(ent->controls, link, &(link->list_link));
    if (ent->control_handler)
	ent->control_handler(IPMI_ADDED, ent, control, ent->cb_data);
}

static int control_cmp(void *item, void *cb_data)
{
    ipmi_control_ref_t *ref1 = item;
    ipmi_control_id_t  *id2 = cb_data;

    return ipmi_cmp_control_id(ref1->control, *id2);
}

void
ipmi_entity_remove_control(ipmi_entity_t  *ent,
			   ipmi_control_t *control)
{
    ipmi_control_ref_t *ref;
    ilist_iter_t       iter;
    ipmi_control_id_t  id;

    CHECK_ENTITY_LOCK(ent);

    ilist_init_iter(&iter, ent->controls);
    ilist_unpositioned(&iter);

    id = ipmi_control_convert_to_id(control);
    ref = ilist_search_iter(&iter, control_cmp, &id);
    if (!ref) {
	ipmi_log(IPMI_LOG_WARNING, "User requested removal of a control"
		 " from an entity, but the control was not there");
	return;
    }

    ilist_delete(&iter);
    ipmi_mem_free(ref);

    if (ent->control_handler)
	ent->control_handler(IPMI_DELETED, ent, control, ent->cb_data);

    if ((!ent->came_from_SDR)
	&& (!ent->presence_sensor)
	&& (ilist_empty(ent->sensors))
	&& (ilist_empty(ent->controls)))
    {
	cleanup_entity(ent);
    }
}

int
ipmi_entity_set_sensor_update_handler(ipmi_entity_t         *ent,
				      ipmi_entity_sensor_cb handler,
				      void                  *cb_data)
{
    CHECK_ENTITY_LOCK(ent);

    ent->sensor_handler = handler;
    ent->cb_data = cb_data;
    return 0;
}

int
ipmi_entity_set_control_update_handler(ipmi_entity_t          *ent,
				       ipmi_entity_control_cb handler,
				       void                   *cb_data)
{
    CHECK_ENTITY_LOCK(ent);

    ent->control_handler = handler;
    ent->control_cb_data = cb_data;
    return 0;
}

int
ipmi_entity_set_update_handler(ipmi_entity_info_t    *ents,
			       ipmi_domain_entity_cb handler,
			       void                  *cb_data)
{
    ents->handler = handler;
    ents->cb_data = cb_data;
    return 0;
}

static int
handle_ear(ipmi_entity_info_t *ents,
	   ipmi_sdr_t         *sdr)
{
    int                 rv;
    ipmi_entity_t       *ent, *sub_ent;
    int                 pos;
    entity_child_link_t *link;
    ipmi_device_num_t   device_num;

    device_num.channel = 0;
    device_num.address = 0;
    rv = entity_add(ents, device_num, sdr->data[0], sdr->data[1],
		    NULL, NULL, &ent, 1);
    if (rv)
	return rv;

    ent->linked_ear_exists = (sdr->data[2] & 0x40) == 0x40;
    ent->presence_sensor_always_there = (sdr->data[2] & 0x20) == 0x20;

    if (sdr->data[2] & 0x80) {
	/* sub-entities are specified in ranges. */
	int e_num;

	for (pos=3; pos<11; pos+=4) {
	    if (sdr->data[pos] == 0)
		/* entity ID 0 means no entry. */
		continue;
	    for (e_num=sdr->data[pos+1];
		 e_num<=sdr->data[pos+3];
		 e_num++)
	    {
		rv = entity_add(ents,
				device_num,
				sdr->data[pos],
				e_num,
				NULL,
				NULL,
				&sub_ent,
				1);
		if (rv)
		    return rv;
		rv = add_child(ent, sub_ent, &link);
		if (rv)
		    return rv;

		link->in_db = 1;
	    }
	}
    } else {
	/* sub-entities are specified one at a time. */
	for (pos=3; pos<11; pos+=2) {
	    if (sdr->data[pos] == 0)
		/* entity ID 0 means no entry. */
		continue;
	    rv = entity_add(ents,
			    device_num,
			    sdr->data[pos],
			    sdr->data[pos+1],
			    NULL,
			    NULL,
			    &sub_ent,
			    1);
	    if (rv)
		return rv;
	    rv = add_child(ent, sub_ent, &link);
	    if (rv)
		return rv;

	    link->in_db = 1;
	}
    }

    return 0;
}

static int
handle_drear(ipmi_entity_info_t *ents,
	     ipmi_sdr_t         *sdr)
{
    int                 rv;
    ipmi_entity_t       *ent, *sub_ent;
    int                 pos;
    entity_child_link_t *link;
    ipmi_device_num_t   device_num;

    device_num.channel = sdr->data[3] >> 4;
    device_num.address = sdr->data[2] & 0xfe;
    rv = entity_add(ents, device_num, sdr->data[0], sdr->data[1],
		    NULL, NULL, &ent, 1);
    if (rv)
	return rv;

    ent->linked_ear_exists = (sdr->data[4] & 0x40) == 0x40;
    ent->presence_sensor_always_there = (sdr->data[4] & 0x20) == 0x20;

    if (sdr->data[4] & 0x80) {
	/* sub-entities are specified in ranges. */
	int e_num;

	for (pos=5; pos<21; pos+=8) {
	    if (sdr->data[pos+2] == 0)
		/* entity ID 0 means no entry. */
		continue;
	    device_num.channel = sdr->data[pos+1] >> 4;
	    device_num.address = sdr->data[pos] & 0xfe;
	    for (e_num=sdr->data[pos+3];
		 e_num<=sdr->data[pos+7];
		 e_num++)
	    {
		rv = entity_add(ents,
				device_num,
				sdr->data[pos],
				e_num,
				NULL,
				NULL,
				&sub_ent,
				1);
		if (rv)
		    return rv;
		rv = add_child(ent, sub_ent, &link);
		if (rv)
		    return rv;

		link->in_db = 1;
	    }
	}
    } else {
	/* sub-entities are specified one at a time. */
	for (pos=5; pos<21; pos+=4) {
	    if (sdr->data[pos] == 0)
		continue;
	    device_num.channel = sdr->data[pos+1] >> 4;
	    device_num.address = sdr->data[pos] & 0xfe;
	    rv = entity_add(ents,
			    device_num,
			    sdr->data[pos+2],
			    sdr->data[pos+3],
			    NULL,
			    NULL,
			    &sub_ent,
			    1);
	    if (rv)
		return rv;
	    rv = add_child(ent, sub_ent, &link);
	    if (rv)
		return rv;

	    link->in_db = 1;
	}
    }

    return 0;
}

static int
gdlr_output(ipmi_entity_t *ent, ipmi_sdr_info_t *sdrs, void *cb_data)
{
    ipmi_sdr_t sdr;
    int        len;

    memset(&sdr, 0, sizeof(sdr));

    sdr.major_version = IPMI_MAJOR_NUM_SDR;
    sdr.minor_version = IPMI_MINOR_NUM_SDR;
    sdr.type = 0x10; /* Generic Device Locator */
    sdr.length = 10; /* We'll fix it later. */
    sdr.data[0] = ent->access_address;
    sdr.data[1] = ent->slave_address | (ent->channel >> 3);
    sdr.data[2] = ((ent->channel << 5)
		   | (ent->lun << 3)
		   | ent->private_bus_id);
    sdr.data[3] = ent->address_span & 0x7;
    sdr.data[4] = 0;
    sdr.data[5] = ent->device_type;
    sdr.data[6] = ent->device_modifier;
    sdr.data[7] = ent->entity_id;
    sdr.data[8] = ent->entity_instance;
    sdr.data[9] = ent->oem;
    len = 16;
    ipmi_set_device_string(ent->id, sdr.data+10, &len);
    sdr.length += len;

    return ipmi_sdr_add(sdrs, &sdr);
}

static int
handle_gdlr(ipmi_entity_info_t *ents,
	    ipmi_sdr_t         *sdr)
{
    ipmi_device_num_t device_num;
    ipmi_entity_t     *ent;
    int               rv;

    device_num.channel = (sdr->data[2] >> 5) | ((sdr->data[1] << 3) & 0x08);
    device_num.address = sdr->data[0] & 0xfe;
    rv = entity_add(ents, device_num, sdr->data[7], sdr->data[8],
		    gdlr_output, NULL, &ent, 1);
    if (rv)
	return rv;

    ent->access_address = device_num.address; 
    ent->slave_address = sdr->data[1] & 0xfe;
    ent->channel = device_num.channel;
    ent->lun = (sdr->data[2] >> 3) & 0x3;
    ent->private_bus_id = sdr->data[2] & 0x7;
    ent->address_span = sdr->data[3] & 0x7;
    ent->device_type = sdr->data[5];
    ent->device_modifier = sdr->data[6];
    ent->oem = sdr->data[9];
    ipmi_get_device_string(sdr->data+10, sdr->length-10, ent->id, 32);
    return 0;
}

static int
frudlr_output(ipmi_entity_t *ent, ipmi_sdr_info_t *sdrs, void *cb_data)
{
    ipmi_sdr_t sdr;
    int        len;

    memset(&sdr, 0, sizeof(sdr));

    sdr.major_version = IPMI_MAJOR_NUM_SDR;
    sdr.minor_version = IPMI_MINOR_NUM_SDR;
    sdr.type = 0x11; /* FRU Device Locator */
    sdr.length = 10; /* We'll fix it later. */
    sdr.data[0] = ent->access_address;
    sdr.data[1] = ent->slave_address;
    sdr.data[2] = ((ent->is_logical_fru << 7)
		   | (ent->lun << 3)
		   | ent->private_bus_id);
    sdr.data[3] = ent->channel << 4;
    sdr.data[4] = 0;
    sdr.data[5] = ent->device_type;
    sdr.data[6] = ent->device_modifier;
    sdr.data[7] = ent->entity_id;
    sdr.data[8] = ent->entity_instance;
    sdr.data[9] = ent->oem;
    len = 16;
    ipmi_set_device_string(ent->id, sdr.data+10, &len);
    sdr.length += len;

    return ipmi_sdr_add(sdrs, &sdr);
}

static int
handle_frudlr(ipmi_entity_info_t *ents,
	      ipmi_sdr_t         *sdr)
{
    ipmi_device_num_t device_num;
    ipmi_entity_t     *ent;
    int               rv;

    device_num.channel = sdr->data[3] >> 4;
    device_num.address = sdr->data[0] & 0xfe;
    rv = entity_add(ents, device_num, sdr->data[7], sdr->data[8],
		    frudlr_output, NULL, &ent, 1);
    if (rv)
	return rv;

    ent->is_fru = 1;
    ent->access_address = device_num.address; 
    ent->slave_address = sdr->data[1] & 0xfe;
    ent->channel = device_num.channel;
    ent->is_logical_fru = ((sdr->data[2] & 0x80) == 0x80);
    ent->lun = (sdr->data[2] >> 3) & 0x3;
    ent->private_bus_id = sdr->data[2] & 0x7;
    ent->device_type = sdr->data[5];
    ent->device_modifier = sdr->data[6];
    ent->oem = sdr->data[9];
    ipmi_get_device_string(sdr->data+10, sdr->length-10, ent->id, 32);
    return 0;
}

static int
mcdlr_output(ipmi_entity_t *ent, ipmi_sdr_info_t *sdrs, void *cb_data)
{
    ipmi_sdr_t sdr;
    int        len;

    memset(&sdr, 0, sizeof(sdr));

    sdr.major_version = IPMI_MAJOR_NUM_SDR;
    sdr.minor_version = IPMI_MINOR_NUM_SDR;
    sdr.type = 0x12; /* MC Device Locator */
    sdr.length = 10; /* We'll fix it later. */
    sdr.data[0] = ent->slave_address;
    sdr.data[1] = ent->channel & 0xf;
    sdr.data[2] = ((ent->ACPI_system_power_notify_required << 7)
		   || (ent->ACPI_device_power_notify_required << 6)
		   || (ent->controller_logs_init_agent_errors << 3)
		   || (ent->log_init_agent_errors_accessing << 2)
		   || (ent->global_init));
    sdr.data[3] = ((ent->chassis_device << 7)
		   || (ent->bridge << 6)
		   || (ent->IPMB_event_generator << 5)
		   || (ent->IPMB_event_receiver << 4)
		   || (ent->FRU_inventory_device << 3)
		   || (ent->SEL_device << 2)
		   || (ent->SDR_repository_device << 1)
		   || ent->sensor_device);
    sdr.data[4] = 0;
    sdr.data[5] = 0;
    sdr.data[6] = 0;
    sdr.data[7] = ent->entity_id;
    sdr.data[8] = ent->entity_instance;
    sdr.data[9] = ent->oem;
    len = 16;
    ipmi_set_device_string(ent->id, sdr.data+10, &len);
    sdr.length += len;

    return ipmi_sdr_add(sdrs, &sdr);
}

static int
handle_mcdlr(ipmi_entity_info_t *ents,
	     ipmi_sdr_t         *sdr)
{
    ipmi_device_num_t device_num;
    ipmi_entity_t     *ent;
    int               rv;

    device_num.channel = sdr->data[1] & 0xf;
    device_num.address = sdr->data[0] & 0xfe;
    rv = entity_add(ents, device_num, sdr->data[7], sdr->data[8], 
		    mcdlr_output, NULL, &ent, 1);
    if (rv)
	return rv;

    ent->is_mc = 1;
    ent->slave_address = sdr->data[0] & 0xfe;
    ent->channel = device_num.channel;

    ent->ACPI_system_power_notify_required = (sdr->data[2] >> 7) & 1;
    ent->ACPI_device_power_notify_required = (sdr->data[2] >> 6) & 1;
    ent->controller_logs_init_agent_errors = (sdr->data[2] >> 3) & 1;
    ent->log_init_agent_errors_accessing = (sdr->data[2] >> 2) & 1;
    ent->global_init = (sdr->data[2] >> 0) & 3;
    ent->chassis_device = (sdr->data[3] >> 7) & 1;
    ent->bridge = (sdr->data[3] >> 6) & 1;
    ent->IPMB_event_generator = (sdr->data[3] >> 5) & 1;
    ent->IPMB_event_receiver = (sdr->data[3] >> 4) & 1;
    ent->FRU_inventory_device = (sdr->data[3] >> 3) & 1;
    ent->SEL_device = (sdr->data[3] >> 2) & 1;
    ent->SDR_repository_device = (sdr->data[3] >> 1) & 1;
    ent->sensor_device = (sdr->data[3] >> 0) & 1;

    ent->oem = sdr->data[9];
    ipmi_get_device_string(sdr->data+10, sdr->length-10, ent->id, 32);
    return 0;
}

static void
clear_child_in_db(ilist_iter_t *iter, void *item, void *cb_data)
{
    entity_child_link_t *link = item;

    link->in_db = 0;
}

static void
clear_ent_in_db(ilist_iter_t *iter, void *item, void *cb_data)
{
    ipmi_entity_t *ent = item;

    ent->in_db = 0;
    ilist_iter(ent->sub_entities, clear_child_in_db, NULL);
}

int
ipmi_entity_scan_sdrs(ipmi_entity_info_t *ents,
		      ipmi_sdr_info_t    *sdrs)
{
    unsigned int count;
    int          i;
    int          rv;


    /* Clear out the in_db bits for everything. */
    ilist_iter(ents->entities, clear_ent_in_db, NULL);

    rv = ipmi_get_sdr_count(sdrs, &count);
    if (rv)
	return rv;

    for (i=0; i<count; i++) {
	ipmi_sdr_t sdr;

	rv = ipmi_get_sdr_by_index(sdrs, i, &sdr);
	if (rv)
	    return rv;

	switch (sdr.type) {
	    case 0x08: /* Entity Association Record */
		rv = handle_ear(ents, &sdr);
		if (rv)
		    return rv;
		break;

	    case 0x09: /* Device-relative Entity Association Record */
		rv = handle_drear(ents, &sdr);
		if (rv)
		    return rv;
		break;

	    case 0x10: /* Generic Device Locator Record */
		rv = handle_gdlr(ents, &sdr);
		if (rv)
		    return rv;
		break;

	    case 0x11: /* FRU Device Locator Record. */
		rv = handle_frudlr(ents, &sdr);
		if (rv)
		    return rv;
		break;

	    case 0x12: /* Management Controller Device Locator Record. */
		rv = handle_mcdlr(ents, &sdr);
		if (rv)
		    return rv;
		break;
	}
    }

    return 0;
}

typedef struct sdr_append_info_s
{
    int                err;
    ipmi_entity_info_t *ents;
    ipmi_sdr_info_t    *sdrs;
} sdr_append_info_t;

/* For sorting by entity ID/entity instance. */
static int
cmp_entities(void *item1, void *item2)
{
    ipmi_entity_t *ent1 = item1;
    ipmi_entity_t *ent2 = item2;

    if (ent1->entity_id < ent2->entity_id)
	return -1;
    if (ent1->entity_id > ent2->entity_id)
	return 1;
    if (ent1->entity_instance < ent2->entity_instance)
	return -1;
    if (ent1->entity_instance > ent2->entity_instance)
	return 1;
    return 0;
}

static int
do_ear_output(ipmi_sdr_info_t *sdrs,
	      ipmi_sdr_t      *sdr,
	      ipmi_entity_t   *(ents[]),
	      int             is_range,
	      int             other_entries,
	      int             len)
{
    int pos;
    int rv;
    int old_flags;
    int old_flags_pos;
    int i;

    if (sdr->type == 0x08) {
	/* not device-relative */
	memset(sdr->data+3, 0, 8);
	old_flags = sdr->data[2];
	old_flags_pos = 2;
	if (is_range)
	    sdr->data[2] |= 1 << 7;
	if (other_entries)
	    sdr->data[2] |= 1 << 6;
	pos = 3;
	for (i=0; i<len; i++) {
	    sdr->data[pos] = ents[i]->entity_id;
	    pos++;
	    sdr->data[pos] = ents[i]->entity_instance;
	    pos++;
	}
    } else {
	/* device-relative */
	memset(sdr->data+5, 0, 16);
	old_flags = sdr->data[4];
	old_flags_pos = 4;
	if (is_range)
	    sdr->data[4] |= 1 << 7;
	if (other_entries)
	    sdr->data[4] |= 1 << 6;
	pos = 5;
	for (i=0; i<len; i++) {
	    sdr->data[pos] = ents[i]->device_num.address;
	    pos++;
	    sdr->data[pos] = ents[i]->device_num.channel;
	    pos++;
	    sdr->data[pos] = ents[i]->entity_id;
	    pos++;
	    sdr->data[pos] = ents[i]->entity_instance;
	    pos++;
	}
    }

    rv = ipmi_sdr_add(sdrs, sdr);
    
    /* Restore the original value of the flags field. */
    sdr->data[old_flags_pos] = old_flags;

    return rv;
}

static int
output_child_ears(ipmi_entity_t *ent, ipmi_sdr_info_t *sdrs)
{
    ipmi_sdr_t    sdr;
    int           prev_inst;
    ipmi_entity_t *curr, *next, *last;
    int           curr_dlr_entry = 0;
    int           is_range = 0;
    ipmi_entity_t *(ents[4]);
    ilist_iter_t  iter;
    int           rv;

    if (ilist_empty(ent->sub_entities))
	return 0;

    memset(&sdr, 0, sizeof(sdr));

    sdr.major_version = IPMI_MAJOR_NUM_SDR;
    sdr.minor_version = IPMI_MINOR_NUM_SDR;
    sdr.data[0] = ent->entity_id;
    sdr.data[1] = ent->entity_instance;

    if ((sdr.major_version == 1) && (sdr.minor_version < 5)) {
	/* IPMI 1.0, we can olny use normal entity association
	   records */
	sdr.type = 0x08; /* Entity Association Record */
	sdr.length = 11;
	sdr.data[2] = (ent->presence_sensor_always_there << 5);
    } else {
	/* IPMI 1.5, we only use the device-relative EARs. */
	sdr.type = 0x09; /* Entity Association Record */
	sdr.length = 27;
	sdr.data[2] = ent->slave_address;
	sdr.data[3] = ent->channel;
	sdr.data[4] = (ent->presence_sensor_always_there << 5);
    }

    ilist_sort(ent->sub_entities, cmp_entities);

    ilist_init_iter(&iter, ent->sub_entities);
    last = NULL;
    if (ilist_first(&iter))
	next = ilist_get(&iter);
    else
	next = NULL;
    while (next) {
	curr = next;
	prev_inst = curr->entity_instance;
	if (ilist_next(&iter))
	    next = ilist_get(&iter);
	else
	    next = NULL;
	while (next
	       && (next->entity_id == curr->entity_id)
	       && (next->entity_instance == prev_inst+1))
	{
	    last = next;
	    if (ilist_next(&iter))
		next = ilist_get(&iter);
	    else
		next = NULL;
	    prev_inst++;
	}
	if (prev_inst > curr->entity_instance) {
	    /* We have a range. */
	    if ((curr_dlr_entry > 0) && (!is_range)) {
		rv = do_ear_output(sdrs, &sdr, ents,
				   is_range, 1, curr_dlr_entry);
		if (rv)
		    return rv;
	    }
	    is_range = 1;
	    ents[curr_dlr_entry] = curr;
	    ents[curr_dlr_entry+1] = last;
	    curr_dlr_entry += 2;
	} else {
	    /* Not a range. */
	    if ((curr_dlr_entry > 0) && (is_range)) {
		rv = do_ear_output(sdrs, &sdr, ents,
				   is_range, 1, curr_dlr_entry);
		if (rv)
		    return rv;
	    }
	    is_range = 0;
	    ents[curr_dlr_entry] = curr;
	    curr_dlr_entry++;
	}
	if (curr_dlr_entry >= 4) {
	    rv = do_ear_output(sdrs, &sdr, ents,
			       is_range, next != NULL, curr_dlr_entry);
	    if (rv)
		return rv;
	    curr_dlr_entry = 0;
	}
    }

    return 0;
}

static void
ent_sdr_append_handler(ipmi_entity_t *ent, void *cb_data)
{
    sdr_append_info_t *info = cb_data;

    if (info->err)
	return;

    if (ent->sdr_gen_output)
	info->err = ent->sdr_gen_output(ent, info->sdrs, ent->sdr_gen_cb_data);
    if (!info->err)
	info->err = output_child_ears(ent, info->sdrs);
}

int
ipmi_entity_append_to_sdrs(ipmi_entity_info_t *ents,
			   ipmi_sdr_info_t    *sdrs)
{
    sdr_append_info_t info = { 0, ents, sdrs };

    ipmi_entities_iterate_entities(ents, ent_sdr_append_handler, &info);
    return info.err;
}

ipmi_domain_t *
ipmi_entity_get_domain(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->domain;
}

int
ipmi_entity_get_access_address(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->access_address;
}

void
ipmi_entity_set_access_address(ipmi_entity_t *ent, int access_address)
{
    CHECK_ENTITY_LOCK(ent);

    ent->access_address = access_address;
}

int
ipmi_entity_get_slave_address(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->slave_address;
}

void
ipmi_entity_set_slave_address(ipmi_entity_t *ent, int slave_address)
{
    CHECK_ENTITY_LOCK(ent);

    ent->slave_address = slave_address;
}

int
ipmi_entity_get_channel(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->channel;
}

void
ipmi_entity_set_channel(ipmi_entity_t *ent, int channel)
{
    CHECK_ENTITY_LOCK(ent);

    ent->channel = channel;
}

int
ipmi_entity_get_lun(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->lun;
}

void
ipmi_entity_set_lun(ipmi_entity_t *ent, int lun)
{
    CHECK_ENTITY_LOCK(ent);

    ent->lun = lun;
}

int
ipmi_entity_get_private_bus_id(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->private_bus_id;
}

void
ipmi_entity_set_private_bus_id(ipmi_entity_t *ent, int private_bus_id)
{
    CHECK_ENTITY_LOCK(ent);

    ent->private_bus_id = private_bus_id;
}

int
ipmi_entity_get_is_logical_fru(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->is_logical_fru;
}

void
ipmi_entity_set_is_logical_fru(ipmi_entity_t *ent, int is_logical_fru)
{
    CHECK_ENTITY_LOCK(ent);

    ent->is_logical_fru = is_logical_fru;
}

int
ipmi_entity_get_is_fru(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->is_fru;
}

void
ipmi_entity_set_is_fru(ipmi_entity_t *ent, int is_fru)
{
    CHECK_ENTITY_LOCK(ent);

    ent->is_fru = is_fru;
}

int
ipmi_entity_get_is_mc(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->is_mc;
}

void
ipmi_entity_set_is_mc(ipmi_entity_t *ent, int is_mc)
{
    CHECK_ENTITY_LOCK(ent);

    ent->is_mc = is_mc;
}

int
ipmi_entity_get_entity_id(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->entity_id;
}

int
ipmi_entity_get_entity_instance(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->entity_instance;
}

int
ipmi_entity_get_device_type(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->device_type;
}

void
ipmi_entity_set_device_type(ipmi_entity_t *ent, int device_type)
{
    CHECK_ENTITY_LOCK(ent);

    ent->device_type = device_type;
}

int
ipmi_entity_get_device_modifier(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->device_modifier;
}

void
ipmi_entity_set_device_modifier(ipmi_entity_t *ent, int device_modifier)
{
    CHECK_ENTITY_LOCK(ent);

    ent->device_modifier = device_modifier;
}

int
ipmi_entity_get_oem(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->oem;
}

void
ipmi_entity_set_oem(ipmi_entity_t *ent, int oem)
{
    CHECK_ENTITY_LOCK(ent);

    ent->oem = oem;
}

int
ipmi_entity_get_address_span(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->address_span;
}

void
ipmi_entity_set_address_span(ipmi_entity_t *ent, int address_span)
{
    CHECK_ENTITY_LOCK(ent);

    ent->address_span = address_span;
}

int
ipmi_entity_get_id_length(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return strlen(ent->id);
}

void
ipmi_entity_get_id(ipmi_entity_t *ent, char *id, int length)
{
    CHECK_ENTITY_LOCK(ent);

    strncpy(id, ent->id, length);
    id[length] = '\0';
}

void
ipmi_entity_set_id(ipmi_entity_t *ent, char *id)
{
    CHECK_ENTITY_LOCK(ent);

    strncpy(ent->id, id, 32);
    ent->id[32] = '\0';
}

int
ipmi_entity_get_presence_sensor_always_there(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->presence_sensor_always_there;
}

void
ipmi_entity_set_presence_sensor_always_there(ipmi_entity_t *ent, int val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->presence_sensor_always_there = val;
}

int
ipmi_entity_get_in_sdr_db(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->in_db; 
}

int
ipmi_entity_get_ACPI_system_power_notify_required(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_ACPI_system_power_notify_required(ipmi_entity_t *ent,
						  int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_ACPI_device_power_notify_required(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_ACPI_device_power_notify_required(ipmi_entity_t *ent,
						  int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_controller_logs_init_agent_errors(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_controller_logs_init_agent_errors(ipmi_entity_t *ent,
						  int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_log_init_agent_errors_accessing(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_log_init_agent_errors_accessing(ipmi_entity_t *ent,
						int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_global_init(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_global_init(ipmi_entity_t *ent,
			    int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_chassis_device(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_chassis_device(ipmi_entity_t *ent,
			       int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_bridge(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_bridge(ipmi_entity_t *ent,
		       int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_IPMB_event_generator(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_IPMB_event_generator(ipmi_entity_t *ent,
				     int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_IPMB_event_receiver(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_IPMB_event_receiver(ipmi_entity_t *ent,
				    int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_FRU_inventory_device(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_FRU_inventory_device(ipmi_entity_t *ent,
				     int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_SEL_device(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_SEL_device(ipmi_entity_t *ent,
			   int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_SDR_repository_device(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_SDR_repository_device(ipmi_entity_t *ent,
				      int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_sensor_device(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->ACPI_system_power_notify_required;
}

void
ipmi_entity_set_sensor_device(ipmi_entity_t *ent,
			      int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->ACPI_system_power_notify_required = val;
}


int
ipmi_entity_get_is_child(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ! ilist_empty(ent->parent_entities);
}

int
ipmi_entity_is_present(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->present;
}

char *
ipmi_entity_get_entity_id_string(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->entity_id_string;
}

void
ipmi_entity_set_entity_id_string(ipmi_entity_t *ent, char *str)
{
    CHECK_ENTITY_LOCK(ent);

    ent->entity_id_string = str;
}

typedef struct iterate_child_info_s
{
    ipmi_entity_t                *ent;
    ipmi_entity_iterate_child_cb handler;
    void                         *cb_data;
} iterate_child_info_t;

static void
iterate_child_handler(ilist_iter_t *iter, void *item, void *cb_data)
{
    iterate_child_info_t *info = cb_data;
    info->handler(info->ent, item, info->cb_data);
}

void
ipmi_entity_iterate_children(ipmi_entity_t                *ent,
			     ipmi_entity_iterate_child_cb handler,
			     void                         *cb_data)
{
    iterate_child_info_t info = { ent, handler, cb_data };

    CHECK_ENTITY_LOCK(ent);

    ilist_iter(ent->sub_entities, iterate_child_handler, &info);
}

typedef struct iterate_parent_info_s
{
    ipmi_entity_t                 *ent;
    ipmi_entity_iterate_parent_cb handler;
    void                          *cb_data;
} iterate_parent_info_t;

static void
iterate_parent_handler(ilist_iter_t *iter, void *item, void *cb_data)
{
    iterate_parent_info_t *info = cb_data;
    info->handler(info->ent, item, info->cb_data);
}

void
ipmi_entity_iterate_parents(ipmi_entity_t                 *ent,
			    ipmi_entity_iterate_parent_cb handler,
			    void                          *cb_data)
{
    iterate_parent_info_t info = { ent, handler, cb_data };

    CHECK_ENTITY_LOCK(ent);

    ilist_iter(ent->parent_entities, iterate_parent_handler, &info);
}

typedef struct iterate_sensor_info_s
{
    ipmi_entity_t                 *ent;
    ipmi_entity_iterate_sensor_cb handler;
    void                          *cb_data;
} iterate_sensor_info_t;

static void sens_iter_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    iterate_sensor_info_t *info = cb_data;

    info->handler(info->ent, sensor, info->cb_data);
}

static void
iterate_sensor_handler(ilist_iter_t *iter, void *item, void *cb_data)
{
    ipmi_sensor_ref_t *ref = item;

    ipmi_sensor_pointer_cb(ref->sensor, sens_iter_cb, cb_data);
}

void
ipmi_entity_iterate_sensors(ipmi_entity_t                 *ent,
			    ipmi_entity_iterate_sensor_cb handler,
			    void                          *cb_data)
{
    iterate_sensor_info_t info = { ent, handler, cb_data };

    CHECK_ENTITY_LOCK(ent);

    ilist_iter(ent->sensors, iterate_sensor_handler, &info);
}


typedef struct iterate_control_info_s
{
    ipmi_entity_t                  *ent;
    ipmi_entity_iterate_control_cb handler;
    void                           *cb_data;
} iterate_control_info_t;

static void control_iter_cb(ipmi_control_t *control, void *cb_data)
{
    iterate_control_info_t *info = cb_data;

    info->handler(info->ent, control, info->cb_data);
}


static void
iterate_control_handler(ilist_iter_t *iter, void *item, void *cb_data)
{
    ipmi_control_ref_t *ref = item;

    ipmi_control_pointer_cb(ref->control, control_iter_cb, cb_data);
}

void
ipmi_entity_iterate_controls(ipmi_entity_t                  *ent,
			     ipmi_entity_iterate_control_cb handler,
			     void                           *cb_data)
{
    iterate_control_info_t info = { ent, handler, cb_data };

    CHECK_ENTITY_LOCK(ent);

    ilist_iter(ent->controls, iterate_control_handler, &info);
}

typedef struct iterate_entity_info_s
{
    ipmi_entity_info_t              *ents;
    ipmi_entities_iterate_entity_cb handler;
    void                            *cb_data;
} iterate_entity_info_t;

static void
iterate_entity_handler(ilist_iter_t *iter, void *item, void *cb_data)
{
    iterate_entity_info_t *info = cb_data;
    info->handler(item, info->cb_data);
}

void
ipmi_entities_iterate_entities(ipmi_entity_info_t              *ents,
			       ipmi_entities_iterate_entity_cb handler,
			       void                            *cb_data)
{
    iterate_entity_info_t info = { ents, handler, cb_data };
    ilist_iter(ents->entities, iterate_entity_handler, &info);
}

ipmi_entity_id_t
ipmi_entity_convert_to_id(ipmi_entity_t *ent)
{
    ipmi_entity_id_t val;

    CHECK_ENTITY_LOCK(ent);

    val.domain_id = ent->domain_id;
    val.entity_id = ent->entity_id;
    val.entity_instance = ent->entity_instance;
    val.channel = ent->device_num.channel;
    val.address = ent->device_num.address;
    val.seq = ent->seq;

    return val;
}

typedef struct mc_cb_info_s
{
    ipmi_entity_ptr_cb handler;
    void               *cb_data;
    ipmi_entity_id_t   id;
    int                err;
} mc_cb_info_t;

static void
domain_cb(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_device_num_t device_num;
    ipmi_entity_t     *ent;
    mc_cb_info_t      *info = cb_data;

    ipmi_domain_entity_lock(domain);

    device_num.channel = info->id.channel;
    device_num.address = info->id.address;
    info->err = entity_find(ipmi_domain_get_entities(domain),
			    device_num,
			    info->id.entity_id,
			    info->id.entity_instance,
			    &ent); 
    if (!info->err) {
	if (ent->seq != info->id.seq)
	    info->err = EINVAL;
    }
    if (!info->err)
	info->handler(ent, info->cb_data);

    ipmi_domain_entity_unlock(domain);
}

int
ipmi_entity_pointer_cb(ipmi_entity_id_t   id,
		       ipmi_entity_ptr_cb handler,
		       void               *cb_data)
{
    int          rv;
    mc_cb_info_t info;

    info.handler = handler;
    info.cb_data = cb_data;
    info.id = id;
    info.err = 0;

    rv = ipmi_domain_pointer_cb(id.domain_id, domain_cb, &info);
    if (!rv)
	rv = info.err;

    return rv;
}

void
ipmi_entity_lock(ipmi_entity_t *ent)
{
    ipmi_domain_entity_lock(ent->domain);
}

void
ipmi_entity_unlock(ipmi_entity_t *ent)
{
    ipmi_domain_entity_unlock(ent->domain);
}

#ifdef IPMI_CHECK_LOCKS
void
__ipmi_check_entity_lock(ipmi_entity_t *entity)
{
    __ipmi_check_domain_entity_lock(entity->domain);
}
#endif
