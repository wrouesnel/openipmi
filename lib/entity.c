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
#include <stdio.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_entity.h>
#include <OpenIPMI/ipmi_bits.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ilist.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_sdr.h>

/* These are the versions of IPMI we write to the SDR repository */
#define IPMI_MAJOR_NUM_SDR 1
#define IPMI_MINOR_NUM_SDR 5

#define ENTITY_ID_LEN 32

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

typedef struct dlr_ref_s
{
    ipmi_device_num_t device_num;
    uint8_t entity_id;
    uint8_t entity_instance;
} dlr_ref_t;

typedef struct dlr_info_s
{
    enum ipmi_dlr_type_e type;

    entity_sdr_add_cb output_handler;

    ipmi_device_num_t device_num;

    /* Key fields. */
    uint8_t access_address; /* Valid for FRU and Generic */
    uint8_t fru_device_id;  /* Valid for FRU */
    uint8_t is_logical_fru; /* Valid for FRU */
    uint8_t lun;	    /* Valid for FRU, MC, and Generic */
    uint8_t private_bus_id; /* Valid for FRU and Generic */
    uint8_t channel;        /* Valid for FRU, MC, and Generic */
    uint8_t slave_address;  /* Valid for MC and Generic. */

    /* General record fields. */
    uint8_t oem;
    uint8_t entity_id;
    uint8_t entity_instance;
    uint8_t device_type;	  /* Not in MC */
    uint8_t device_type_modifier; /* Not in MC */

    /* Note that the id is *not* nil terminated. */
    unsigned int id_len;
    enum ipmi_str_type_e id_type;
    char id[ENTITY_ID_LEN];

    /* MCDLR-specfic Record fields. */
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

    /* Generic Record fields. */
    uint8_t address_span;

    /* From an EAR or DREAR */
    uint8_t is_list;
    uint8_t linked;
    uint8_t is_ranges;
    uint8_t linked_ear_exists : 1;
    uint8_t presence_sensor_always_there;
    dlr_ref_t contained_entities[4];
} dlr_info_t;

#define ENTITY_NAME_LEN (IPMI_MAX_DOMAIN_NAME_LEN + 32)
struct ipmi_entity_s
{
    ipmi_domain_t    *domain;
    ipmi_domain_id_t domain_id;
    long             seq;

    int          destroyed;
    int          cb_in_progress;

    /* My domain's os handler. */
    os_handler_t *os_hnd;

    /* Info from the DLR. */
    dlr_info_t info;

    /* Number of users of this entity (not including sensors, this is
       mainly for other SDRs that reference this entity). */
    unsigned int ref_count;

    ilist_t *sub_entities;
    ilist_t *parent_entities;

    ilist_t *sensors;
    ilist_t *controls;

    char *entity_id_string;

    /* A standard presence sensor.  This one overrides everything. */
    ipmi_sensor_t *presence_sensor;

    /* A discrete sensor where one of the bits is used for presence.
       If one of these exists, it will be used unless there is a
       presence sensor. */
    ipmi_sensor_t *presence_bit_sensor;
    int           presence_bit_offset;

    int           present;
    int           presence_possibly_changed;

    /* Lock used by all timers and a counter so we know if timers are
       running. */
    ipmi_lock_t       *timer_lock;
    unsigned int      running_timer_count;

    /* Hot-swap sensors/controls */
    ipmi_sensor_t  *hot_swap_requester;
    int            hot_swap_offset;
    int            hot_swap_requesting_val;
    enum ipmi_hot_swap_states hot_swap_state;
    ipmi_control_t *hot_swap_power;
    ipmi_control_t *hot_swap_indicator;
    int            hot_swap_ind_act;
    int            hot_swap_ind_req_act;
    int            hot_swap_ind_req_deact;
    int            hot_swap_ind_inact;

    /* Hot-swap timing. */
    ipmi_timeout_t    hot_swap_act_timeout;
    ipmi_timeout_t    hot_swap_deact_timeout;
    os_hnd_timer_id_t *hot_swap_act_timer;
    int               hot_swap_act_timer_running;
    os_hnd_timer_id_t *hot_swap_deact_timer;
    int               hot_swap_deact_timer_running;

    ilist_t        *hot_swap_handlers;

    ipmi_entity_info_t *ents;

    ipmi_fru_t   *fru;

    int                    hot_swappable;
    ipmi_entity_hot_swap_t hs_cb;

    ilist_t            *fru_handlers;
    ipmi_entity_fru_cb fru_handler;
    void              *fru_cb_data;

    ilist_t               *sensor_handlers;
    ipmi_entity_sensor_cb sensor_handler;
    void                  *sensor_cb_data;

    ilist_t                *control_handlers;
    ipmi_entity_control_cb control_handler;
    void                   *control_cb_data;

    entity_sdr_add_cb  sdr_gen_output;
    void               *sdr_gen_cb_data;

    ilist_t                 *presence_handlers;
    ipmi_entity_presence_cb presence_handler;
    void                    *presence_cb_data;

    /* Queue we use for operations. */
    opq_t *waitq;

    /* When using the FRU device to detect presence. */
    int frudev_present;
    ipmi_mc_t *frudev_mc; /* Note that the MC cannot be destroyed
			     while we have an active monitor on it, so
			     this is safe. */
    int frudev_active;

    /* OEM info assigned to an entity, for use by plugins. */
    void                            *oem_info;
    ipmi_entity_cleanup_oem_info_cb oem_info_cleanup_handler;

    /* Name we use for reporting */
    char name[ENTITY_NAME_LEN];
};

typedef struct entity_child_link_s
{
    ipmi_entity_t *child;
    struct entity_child_link_s *tlink;
    ilist_item_t parent_link, child_link;
} entity_child_link_t;

struct ipmi_entity_info_s
{
    ipmi_domain_entity_cb handler;
    ilist_t               *update_handlers;
    void                  *cb_data;
    ipmi_domain_t         *domain;
    ipmi_domain_id_t      domain_id;
    ilist_t               *entities;
};

static void call_fru_handlers(ipmi_entity_t *ent, enum ipmi_update_e op);
static void entity_mc_active(ipmi_mc_t *mc, int active, void *cb_data);

/***********************************************************************
 *
 * The internal hot-swap callbacks.
 *
 **********************************************************************/
static int e_get_hot_swap_state(ipmi_entity_t                 *ent,
				ipmi_entity_hot_swap_state_cb handler,
				void                          *cb_data);

static int e_set_auto_activate(ipmi_entity_t  *ent,
			       ipmi_timeout_t auto_act,
			       ipmi_entity_cb done,
			       void           *cb_data);

static int e_get_auto_activate(ipmi_entity_t       *ent,
			       ipmi_entity_time_cb handler,
			       void                *cb_data);

static int e_set_auto_deactivate(ipmi_entity_t  *ent,
				 ipmi_timeout_t auto_act,
				 ipmi_entity_cb done,
				 void           *cb_data);

static int e_get_auto_deactivate(ipmi_entity_t       *ent,
				 ipmi_entity_time_cb handler,
				 void                *cb_data);

static int e_activate(ipmi_entity_t  *ent,
		      ipmi_entity_cb done,
		      void           *cb_data);

static int e_deactivate(ipmi_entity_t  *ent,
			ipmi_entity_cb done,
			void           *cb_data);

static int e_get_hot_swap_indicator(ipmi_entity_t      *ent,
				    ipmi_entity_val_cb handler,
				    void               *cb_data);

static int e_set_hot_swap_indicator(ipmi_entity_t  *ent,
				    int            val,
				    ipmi_entity_cb done,
				    void           *cb_data);

static int e_get_hot_swap_requester(ipmi_entity_t      *ent,
				    ipmi_entity_val_cb handler,
				    void               *cb_data);

static int e_check_hot_swap_state(ipmi_entity_t *ent);

static ipmi_entity_hot_swap_t internal_hs_cb =
{
    .get_hot_swap_state = e_get_hot_swap_state,
    .set_auto_activate = e_set_auto_activate,
    .get_auto_activate = e_get_auto_activate,
    .set_auto_deactivate = e_set_auto_deactivate,
    .get_auto_deactivate = e_get_auto_deactivate,
    .activate = e_activate,
    .deactivate = e_deactivate,
    .get_hot_swap_indicator = e_get_hot_swap_indicator,
    .set_hot_swap_indicator = e_set_hot_swap_indicator,
    .get_hot_swap_requester = e_get_hot_swap_requester,
    .check_hot_swap_state = e_check_hot_swap_state,
};

/***********************************************************************
 *
 * Entity allocation/destruction
 *
 **********************************************************************/
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

    ents->update_handlers = alloc_ilist();
    if (! ents->update_handlers) {
	free_ilist(ents->entities);
	ipmi_mem_free(ents);
	return ENOMEM;
    }

    *new_info = ents;

    return 0;
}

static void
entity_final_destroy(ipmi_entity_t *ent)
{
    if ((ent->running_timer_count != 0)
	|| (opq_stuff_in_progress(ent->waitq)))
    {
	ipmi_unlock(ent->timer_lock);
	return;
    }

    if (ent->frudev_present) {
	ipmi_mc_remove_active_handler(ent->frudev_mc, entity_mc_active, ent);
    }

    if (ent->oem_info_cleanup_handler)
	ent->oem_info_cleanup_handler(ent, ent->oem_info);

    if (ent->fru)
	ipmi_fru_destroy(ent->fru, NULL, NULL);

    if (ent->waitq)
	opq_destroy(ent->waitq);

    free_ilist(ent->parent_entities);
    free_ilist(ent->sub_entities);
    free_ilist(ent->sensors);
    free_ilist(ent->controls);
    ilist_twoitem_destroy(ent->hot_swap_handlers);
    ilist_twoitem_destroy(ent->presence_handlers);
    ilist_twoitem_destroy(ent->fru_handlers);
    ilist_twoitem_destroy(ent->control_handlers);
    ilist_twoitem_destroy(ent->sensor_handlers);

    ipmi_unlock(ent->timer_lock);
    ipmi_destroy_lock(ent->timer_lock);
    ipmi_mem_free(ent);
}

static void
destroy_entity(ilist_iter_t *iter, void *item, void *cb_data)
{
    ipmi_entity_t *ent = (ipmi_entity_t *) item;
    int           rv;

    ent->destroyed = 1;

    ipmi_lock(ent->timer_lock);
    if (ent->hot_swap_act_timer_running) {
	rv = ent->os_hnd->stop_timer(ent->os_hnd, ent->hot_swap_act_timer);
	if (!rv) {
	    /* Could not stop the timer, it must be in the handler. */
	    ent->running_timer_count--;
	    ent->os_hnd->free_timer(ent->os_hnd, ent->hot_swap_act_timer);
	}
    } else {
	ent->os_hnd->free_timer(ent->os_hnd, ent->hot_swap_act_timer);
    }
    if (ent->hot_swap_deact_timer_running) {
	rv = ent->os_hnd->stop_timer(ent->os_hnd, ent->hot_swap_deact_timer);
	if (!rv) {
	    /* Could not stop the timer, it must be in the handler. */
	    ent->running_timer_count--;
	    ent->os_hnd->free_timer(ent->os_hnd, ent->hot_swap_deact_timer);
	}
    } else {
	ent->os_hnd->free_timer(ent->os_hnd, ent->hot_swap_deact_timer);
    }

    entity_final_destroy(ent); /* Unlocks the lock */
}

int
ipmi_entity_info_destroy(ipmi_entity_info_t *ents)
{
    ilist_twoitem_destroy(ents->update_handlers);
    ilist_iter(ents->entities, destroy_entity, NULL);
    free_ilist(ents->entities);
    ipmi_mem_free(ents);
    return 0;
}

typedef struct ent_info_update_handler_info_s
{
    enum ipmi_update_e op;
    ipmi_domain_t      *domain;
    ipmi_entity_t      *entity;
} ent_info_update_handler_info_t;

static void call_entity_info_update_handler(void *data, void *cb_data1,
					    void *cb_data2)
{
    ent_info_update_handler_info_t *info = data;
    ipmi_domain_entity_cb          handler = cb_data1;

    handler(info->op, info->domain, info->entity, cb_data2);
}

/* Returns true if the entity was really deleted, false if not. */
static int
cleanup_entity(ipmi_entity_t *ent)
{
    ilist_iter_t                   iter;
    ent_info_update_handler_info_t info;

    /* First see if the entity is ready for cleanup. */
    if ((ent->ref_count)
	|| (ent->presence_sensor)
	|| (!ilist_empty(ent->sub_entities))
	|| (!ilist_empty(ent->parent_entities))
	|| (!ilist_empty(ent->sensors))
	|| (!ilist_empty(ent->controls)))
	return 0;

    ent->destroyed = 1;
    if (ent->cb_in_progress)
	return 1;

    /* Tell the user I was destroyed. */
    /* Call the update handler list. */
    info.op = IPMI_DELETED;
    info.entity = ent;
    info.domain = ent->domain;
    ilist_iter_twoitem(ent->ents->update_handlers,
		       call_entity_info_update_handler,
		       &info);
    /* Call the old version handler. */
    if (ent->ents->handler)
	ent->ents->handler(IPMI_DELETED, ent->domain, ent, ent->ents->cb_data);

    /* Remove it from the entities list. */
    ilist_init_iter(&iter, ent->ents->entities);
    ilist_unpositioned(&iter);
    while (ilist_next(&iter)) {
	if (ilist_get(&iter) == ent) {
	    ilist_delete(&iter);
	    break;
	}
    }

    /* The sensor, control,parent, and child lists should be empty
       now, we can just destroy it. */
    destroy_entity(NULL, ent, NULL);
    return 1;
}

void
ipmi_entity_set_oem_info(ipmi_entity_t *entity, void *oem_info,
			 ipmi_entity_cleanup_oem_info_cb cleanup_handler)
{
    entity->oem_info = oem_info;
    entity->oem_info_cleanup_handler = cleanup_handler;
}

void *
ipmi_entity_get_oem_info(ipmi_entity_t *entity)
{
    CHECK_ENTITY_LOCK(entity);

    return entity->oem_info;
}

static void
entity_set_name(ipmi_entity_t *entity)
{
    char *dname = DOMAIN_NAME(entity->domain);
    int  length;

    entity->name[0] = '(';
    if (*dname != '\0') {
	length = strlen(dname) - 3; /* Remove the "() " */
	memcpy(entity->name+1, dname+1, length);
	length++;
	entity->name[length] = '.';
	length++;
    } else
	length = 1;
    length += snprintf(entity->name+length, ENTITY_NAME_LEN-length-3,
		       "%d.%d", entity->info.entity_id,
		       entity->info.entity_instance);
    entity->name[length] = ')';
    length++;
    entity->name[length] = ' ';
    length++;
    entity->name[length] = '\0';
    length++;
}

char *
_ipmi_entity_name(ipmi_entity_t *entity)
{
    return entity->name;
}

/***********************************************************************
 *
 * Handling of adding/removing/searching entities, parents, and
 * children.
 *
 **********************************************************************/
int
ipmi_entity_info_add_update_handler(ipmi_entity_info_t    *ents,
				    ipmi_domain_entity_cb handler,
				    void                  *cb_data)
{
    if (ilist_add_twoitem(ents->update_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_info_remove_update_handler(ipmi_entity_info_t    *ents,
				       ipmi_domain_entity_cb handler,
				       void                  *cb_data)
{
    if (ilist_remove_twoitem(ents->update_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
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

    return ((ent->info.device_num.channel == info->device_num.channel)
	    && (ent->info.device_num.address == info->device_num.address)
	    && (ent->info.entity_id == info->entity_id)
	    && (ent->info.entity_instance == info->entity_instance));
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
	   ipmi_entity_t      **new_ent)
{
    int                            rv;
    ipmi_entity_t                  *ent;
    ent_info_update_handler_info_t info;
    os_handler_t                   *os_hnd;

    rv = entity_find(ents, device_num, entity_id, entity_instance, new_ent);
    if (! rv) {
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

    os_hnd = ipmi_domain_get_os_hnd(ents->domain);

    ent->sdr_gen_output = sdr_gen_output;
    ent->sdr_gen_cb_data = sdr_gen_cb_data;

    ent->domain = ents->domain;
    ent->os_hnd = ipmi_domain_get_os_hnd(ent->domain);
    ent->domain_id = ents->domain_id;
    ent->seq = ipmi_get_seq();
    ent->sub_entities = alloc_ilist();
    if (!ent->sub_entities)
	goto out_err;

    ent->parent_entities = alloc_ilist();
    if (!ent->parent_entities)
	goto out_err;

    ent->sensors = alloc_ilist();
    if (!ent->sensors)
	goto out_err;

    ent->controls = alloc_ilist();
    if (!ent->controls)
	goto out_err;

    ent->hot_swap_handlers = alloc_ilist();
    if (!ent->hot_swap_handlers)
	goto out_err;

    ent->presence_handlers = alloc_ilist();
    if (!ent->presence_handlers)
	goto out_err;

    ent->waitq = opq_alloc(os_hnd);
    if (! ent->waitq)
	return ENOMEM;

    ent->fru_handlers = alloc_ilist();
    if (!ent->fru_handlers)
	goto out_err;

    ent->sensor_handlers = alloc_ilist();
    if (!ent->sensor_handlers)
	goto out_err;

    ent->control_handlers = alloc_ilist();
    if (!ent->fru_handlers)
	goto out_err;

    rv = ipmi_create_lock(ent->domain, &ent->timer_lock);
    if (rv)
	goto out_err;

    rv = ent->os_hnd->alloc_timer(ent->os_hnd, &ent->hot_swap_act_timer);
    if (rv)
	goto out_err;

    rv = ent->os_hnd->alloc_timer(ent->os_hnd, &ent->hot_swap_deact_timer);
    if (rv)
	goto out_err;

    ent->presence_sensor = NULL;
    ent->presence_bit_sensor = NULL;
    ent->present = 0;
    ent->presence_possibly_changed = 1;

    ent->hot_swap_act_timeout = IPMI_TIMEOUT_FOREVER;
    ent->hot_swap_deact_timeout = IPMI_TIMEOUT_FOREVER;

    ent->ents = ents;

    ent->info.type = IPMI_ENTITY_UNKNOWN;
    ent->info.device_num = device_num;
    ent->info.entity_id = entity_id;
    ent->info.entity_instance = entity_instance;
    ent->info.id_type = IPMI_ASCII_STR;

    ent->entity_id_string = ipmi_get_entity_id_string(entity_id);

    if (!ilist_add_tail(ents->entities, ent, NULL))
	goto out_err;

    /* Call the update handler list. */
    info.op = IPMI_ADDED;
    info.entity = ent;
    info.domain = ent->domain;
    ilist_iter_twoitem(ents->update_handlers, call_entity_info_update_handler,
		       &info);

    /* Call the old version handler. */
    if (ents->handler)
	ents->handler(IPMI_ADDED, ent->domain, ent, ents->cb_data);

    if (new_ent)
	*new_ent = ent;

    return 0;

 out_err:
    if (ent->hot_swap_act_timer)
	ent->os_hnd->free_timer(ent->os_hnd, ent->hot_swap_act_timer);
    if (ent->hot_swap_deact_timer)
	ent->os_hnd->free_timer(ent->os_hnd, ent->hot_swap_deact_timer);
    if (ent->timer_lock)
	ipmi_destroy_lock(ent->timer_lock);
    if (ent->presence_handlers)
	ilist_twoitem_destroy(ent->presence_handlers);
    if (ent->waitq)
	opq_destroy(ent->waitq);
    if (ent->fru_handlers)
	ilist_twoitem_destroy(ent->fru_handlers);
    if (ent->control_handlers)
	ilist_twoitem_destroy(ent->control_handlers);
    if (ent->sensor_handlers)
	ilist_twoitem_destroy(ent->sensor_handlers);
    if (ent->hot_swap_handlers)
	ilist_twoitem_destroy(ent->hot_swap_handlers);
    if (ent->controls)
	free_ilist(ent->controls);
    if (ent->sensors)
	free_ilist(ent->sensors);
    if (ent->parent_entities)
	free_ilist(ent->parent_entities);
    if (ent->sub_entities)
	free_ilist(ent->sub_entities);
    ipmi_mem_free(ent);
    return ENOMEM;
}

int
ipmi_entity_add(ipmi_entity_info_t *ents,
		ipmi_domain_t      *domain,
		unsigned char      mc_channel,
		unsigned char      mc_slave_addr,
		int                lun,
		int                entity_id,
		int                entity_instance,
		char               *id,
		enum ipmi_str_type_e id_type,
		unsigned int       id_len,
		entity_sdr_add_cb  sdr_gen_output,
		void               *sdr_gen_cb_data,
		ipmi_entity_t      **new_ent)
{
    ipmi_device_num_t device_num;
    int               rv;
    ipmi_entity_t     *ent;

    CHECK_DOMAIN_LOCK(domain);

    if (entity_instance >= 0x60) {
	device_num.channel = mc_channel;
	device_num.address = mc_slave_addr;
    } else {
	device_num.channel = 0;
	device_num.address = 0;
    }

    ipmi_domain_entity_lock(domain);

    rv = entity_add(ents, device_num, entity_id, entity_instance,
		    sdr_gen_output, sdr_gen_cb_data, &ent);
    if (!rv) {
        if (!ent->info.id_len)
	    ipmi_entity_set_id(ent, id, id_type, id_len);
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

/* If linkptr is non-NULL, it must point to a child link allocated
   with ipmi_mem_alloc().  If this code takes it, the user must manage
   it. If this code uses the link, it will set what linkptr points to
   to NULL.  If linkptr is supplied, then this routine cannot fail. */
static int
add_child(ipmi_entity_t       *ent,
	  ipmi_entity_t       *child,
	  entity_child_link_t **new_link,
	  entity_child_link_t **linkptr)
{
    entity_child_link_t            *link;
    ent_info_update_handler_info_t info;

    link = ilist_search(ent->sub_entities, search_child, child);
    if (link != NULL)
	goto found;

    if (linkptr) {
	link = *linkptr;
	*linkptr = NULL;
    } else {
	link = ipmi_mem_alloc(sizeof(*link));
	if (!link)
	    return ENOMEM;
    }

    link->child = child;

    ilist_add_tail(ent->sub_entities, link, &link->child_link);
    ilist_add_tail(child->parent_entities, ent, &link->parent_link);

    ent->presence_possibly_changed = 1;

    info.op = IPMI_CHANGED;
    info.entity = ent;
    info.domain = ent->domain;
    ilist_iter_twoitem(ent->ents->update_handlers,
		       call_entity_info_update_handler,
		       &info);
    if (ent->ents->handler)
	ent->ents->handler(IPMI_CHANGED, ent->domain, ent, ent->ents->cb_data);

    info.entity = child;
    info.domain = child->domain;
    ilist_iter_twoitem(child->ents->update_handlers,
		       call_entity_info_update_handler,
		       &info);
    if (child->ents->handler)
	child->ents->handler(IPMI_CHANGED, child->domain, child,
			     child->ents->cb_data);

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

    return add_child(ent, child, &link, NULL);
}

int
ipmi_entity_remove_child(ipmi_entity_t     *ent,
			 ipmi_entity_t     *child)
{
    entity_child_link_t            *link;
    ilist_iter_t                   iter;
    ent_info_update_handler_info_t info;

    CHECK_ENTITY_LOCK(ent);
    CHECK_ENTITY_LOCK(child);

    ilist_init_iter(&iter, ent->sub_entities);
    ilist_unpositioned(&iter);

    /* Find the child in the parent's list. */
    link = ilist_search_iter(&iter, search_child, child);
    if (link == NULL)
	return ENODEV;

    ilist_delete(&iter);

    /* Find the parent in the child's list. */
    ilist_init_iter(&iter, child->parent_entities);
    ilist_unpositioned(&iter);
    if (ilist_search_iter(&iter, search_parent, ent))
	ilist_delete(&iter);

    /* Can't free the link until here, it contains the parent and
       child list entries. */
    ipmi_mem_free(link);

    ent->presence_possibly_changed = 1;

    info.op = IPMI_CHANGED;
    info.entity = ent;
    info.domain = ent->domain;
    ilist_iter_twoitem(ent->ents->update_handlers,
		       call_entity_info_update_handler,
		       &info);
    if (ent->ents->handler)
	ent->ents->handler(IPMI_CHANGED, ent->domain, ent, ent->ents->cb_data);

    info.entity = child;
    info.domain = child->domain;
    ilist_iter_twoitem(child->ents->update_handlers,
		       call_entity_info_update_handler,
		       &info);
    if (child->ents->handler)
	child->ents->handler(IPMI_CHANGED, child->domain, child,
			     child->ents->cb_data);

    return 0;
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
    entity_child_link_t *link = item;
    iterate_child_info_t *info = cb_data;
    info->handler(info->ent, link->child, info->cb_data);
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

/***********************************************************************
 *
 * Entity presence handling.
 *
 **********************************************************************/

static void presence_parent_handler(ipmi_entity_t *ent,
				    ipmi_entity_t *parent,
				    void          *cb_data);
static int handle_hot_swap_presence(ipmi_entity_t  *ent,
				    int            present,
				    ipmi_event_t   *event);

int
ipmi_entity_add_presence_handler(ipmi_entity_t                  *ent,
				 ipmi_entity_presence_change_cb handler,
				 void                           *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (ilist_add_twoitem(ent->presence_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_presence_handler(ipmi_entity_t                  *ent,
				    ipmi_entity_presence_change_cb handler,
				    void                           *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (ilist_remove_twoitem(ent->presence_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

typedef struct presence_handler_info_s
{
    ipmi_entity_t             *ent;
    int                       present;
    ipmi_event_t              *event;
    int                       handled;
} presence_handler_info_t;

static void call_presence_handler(void *data, void *cb_data1, void *cb_data2)
{
    presence_handler_info_t        *info = data;
    ipmi_entity_presence_change_cb handler = cb_data1;
    int                            handled;

    handled = handler(info->ent, info->present, cb_data2, info->event);
    if (handled == IPMI_EVENT_HANDLED) {
	info->handled = handled;
	info->event = NULL;
    }
}

static void
presence_changed(ipmi_entity_t *ent,
		 int           present,
		 ipmi_event_t  *event)
{
    int                     handled = IPMI_EVENT_NOT_HANDLED;
    presence_handler_info_t info;
    ipmi_fru_t              *fru;
    int                     old_destroyed;
    ipmi_domain_t           *domain = ent->domain;

    if (present != ent->present) {
	if (handled == IPMI_EVENT_HANDLED)
	    event = NULL;

	ent->present = present;

	if (ent->hot_swappable
	    &&(ent->hs_cb.get_hot_swap_state == e_get_hot_swap_state))
	{
	    /* Do internal presence handling if we have the internal
	       hot-swap machine installed. */
	    handled = handle_hot_swap_presence(ent, present, event);
	}

	/* When the entity becomes present or absent, fetch or destroy
	   its FRU info. */
	if (ipmi_entity_get_is_fru(ent)) {
	    if (present) {
		ipmi_entity_fetch_frus(ent);
	    } else if (ent->fru != NULL) {
		fru = ent->fru;
		ent->fru = NULL;
		ipmi_fru_destroy(fru, NULL, NULL);

		call_fru_handlers(ent, IPMI_DELETED);
	    }
	}
	
	ent->cb_in_progress++;
	old_destroyed = ent->destroyed;
	if (ent->presence_handler) {
	    ent->presence_handler(ent, present, ent->presence_cb_data, event);
	    handled = IPMI_EVENT_HANDLED;
	}
	info.ent = ent;
	info.present = present;
	info.event = event;
	info.handled = handled;
	ilist_iter_twoitem(ent->presence_handlers, call_presence_handler,
			   &info);
	handled = info.handled;
	event = info.event;

	/* If our presence changes, that can affect parents, too.  So we
	   rescan them. */
	ipmi_entity_iterate_parents(ent, presence_parent_handler, NULL);

	ent->cb_in_progress--;
	if ((ent->destroyed) && (!old_destroyed))
	    cleanup_entity(ent);
    }

    if (event && (handled == IPMI_EVENT_NOT_HANDLED))
	ipmi_handle_unhandled_event(domain, event);
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

static int
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
    return IPMI_EVENT_NOT_HANDLED;
}

static int
presence_bit_sensor_changed(ipmi_sensor_t         *sensor,
			    enum ipmi_event_dir_e dir,
			    int                   offset,
			    int                   severity,
			    int                   prev_severity,
			    void                  *cb_data,
			    ipmi_event_t          *event)
{
    ipmi_entity_t *ent = cb_data;

    if (offset != ent->presence_bit_offset)
	return IPMI_EVENT_NOT_HANDLED;

    /* Assertion means present. */
    if (dir == IPMI_ASSERTION)
	presence_changed(ent, 1, event);
    else if (dir == IPMI_DEASSERTION)
	presence_changed(ent, 0, event);
    return IPMI_EVENT_NOT_HANDLED;
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

static void
states_bit_read(ipmi_sensor_t *sensor,
		int           err,
		ipmi_states_t *states,
		void          *cb_data)
{
    int           present;
    ipmi_entity_t *ent = cb_data;

    if (err)
	return;

    present = ipmi_is_state_set(states, ent->presence_bit_offset);
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

    if (ent->hot_swappable)
	ipmi_entity_check_hot_swap_state(ent);

    if (ent->presence_sensor) {
	/* Presence sensor overrides everything. */
	rv = ipmi_states_get(ent->presence_sensor, states_read, ent);
    } else if (ent->presence_bit_sensor) {
	/* Presence bit sensor overrides everything but presence. */
	rv = ipmi_states_get(ent->presence_bit_sensor, states_bit_read, ent);
    } else if (! ilist_empty(ent->sensors)) {
	/* It has sensors, try to see if any of those are active. */
	detect = ipmi_mem_alloc(sizeof(*detect));
	if (!detect)
	    return;

	detect->ent_id = ipmi_entity_convert_to_id(ent);
	detect->sensor_try_count = 0;
	detect->present = 0;
	ipmi_entity_iterate_sensors(ent, sensor_detect_send, detect);

	/* I couldn't message any sensors, the thing must be gone. */
	if (detect->sensor_try_count == 0) {
	    ipmi_mem_free(detect);
	    if (ent->frudev_present)
		goto try_frudev;
	    else
		presence_changed(ent, 0, NULL);
	}
    } else if (ent->frudev_present) {
    try_frudev:	
	presence_changed(ent, ent->frudev_active, NULL);
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

int
ipmi_detect_entity_presence_change(ipmi_entity_t *entity, int force)
{
    ent_detect_info_t info;

    info.force = force;
    ent_detect_presence(entity, &info);
    return 0;
}

static void
entity_mc_active(ipmi_mc_t *mc, int active, void *cb_data)
{
    ipmi_entity_t *ent = cb_data;

    if (ent->frudev_active != active) {
	ent->frudev_active = active;
	ipmi_detect_entity_presence_change(ent, 1);
    }
}

static void
handle_new_presence_sensor(ipmi_entity_t *ent, ipmi_sensor_t *sensor)
{
    ipmi_event_state_t events;
    int                event_support;
    int                rv;
    int                val;


    /* If we have a presence sensor, remove the presence bit sensor. */
    if (ent->presence_bit_sensor) {
	ipmi_sensor_remove_discrete_event_handler(ent->presence_bit_sensor,
						  presence_sensor_changed,
						  ent);
	ent->presence_bit_sensor = NULL;
    }

    event_support = ipmi_sensor_get_event_support(sensor);

    /* Add our own event handler. */
    ipmi_sensor_add_discrete_event_handler(sensor,
					   presence_sensor_changed,
					   ent);

    /* Nothing to do, it will just be on. */
    if (event_support == IPMI_EVENT_SUPPORT_GLOBAL_ENABLE)
	goto out;

    /* Turn events and scanning on. */
    ipmi_event_state_init(&events);
    ipmi_event_state_set_events_enabled(&events, 1);
    ipmi_event_state_set_scanning_enabled(&events, 1);

    if (event_support == IPMI_EVENT_SUPPORT_PER_STATE) {
	/* Turn on all the event enables that we can. */
	rv = ipmi_sensor_discrete_assertion_event_supported(sensor, 0, &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, 0, IPMI_ASSERTION);
	rv = ipmi_sensor_discrete_deassertion_event_supported(sensor, 0, &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, 0, IPMI_DEASSERTION);
	rv = ipmi_sensor_discrete_assertion_event_supported(sensor, 1, &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, 1, IPMI_ASSERTION);
	rv = ipmi_sensor_discrete_deassertion_event_supported(sensor, 1, &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, 1, IPMI_DEASSERTION);
    }

    ipmi_sensor_events_enable_set(sensor, &events, NULL, NULL);

 out:
    ent->presence_possibly_changed = 1;

    if (ent->hs_cb.get_hot_swap_state == NULL) {
	/* Set the entity hot-swap capable and use our internal state
	   machine. */
	ipmi_entity_set_hot_swappable(ent, 1);
	ent->hs_cb = internal_hs_cb;
    }
}

static void
handle_new_presence_bit_sensor(ipmi_entity_t *ent, ipmi_sensor_t *sensor)
{
    ipmi_event_state_t events;
    int                event_support;


    event_support = ipmi_sensor_get_event_support(sensor);

    /* Add our own event handler. */
    ipmi_sensor_add_discrete_event_handler(sensor,
					   presence_bit_sensor_changed,
					   ent);

    /* Nothing to do, it will just be on. */
    if (event_support == IPMI_EVENT_SUPPORT_GLOBAL_ENABLE)
	goto out;

    /* Turn events and scanning on. */
    ipmi_event_state_init(&events);
    ipmi_event_state_set_events_enabled(&events, 1);
    ipmi_event_state_set_scanning_enabled(&events, 1);

    if (event_support == IPMI_EVENT_SUPPORT_PER_STATE) {
	int val;
	int rv;
	/* Turn on the event enables. */
	rv = ipmi_sensor_discrete_assertion_event_supported
	    (sensor, ent->presence_bit_offset, &val);
	if (!rv && val)
	    ipmi_discrete_event_set(&events, ent->presence_bit_offset,
				    IPMI_ASSERTION);
	rv = ipmi_sensor_discrete_deassertion_event_supported
	    (sensor, ent->presence_bit_offset, &val);
	if (!rv && val)
	    ipmi_discrete_event_set(&events, ent->presence_bit_offset,
				    IPMI_DEASSERTION);
    }

    ipmi_sensor_events_enable(sensor, &events, NULL, NULL);

 out:
    ent->presence_possibly_changed = 1;

    if (ent->hs_cb.get_hot_swap_state == NULL) {
	/* Set the entity hot-swap capable and use our internal state
	   machine. */
	ipmi_entity_set_hot_swappable(ent, 1);
	ent->hs_cb = internal_hs_cb;
    }
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

/***********************************************************************
 *
 * Handling of sensor and control addition and removal.
 *
 **********************************************************************/

int
ipmi_entity_add_sensor_update_handler(ipmi_entity_t      *ent,
				      ipmi_entity_sensor_cb handler,
				      void               *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (ilist_add_twoitem(ent->sensor_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_sensor_update_handler(ipmi_entity_t      *ent,
					 ipmi_entity_sensor_cb handler,
					 void               *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (ilist_remove_twoitem(ent->sensor_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

typedef struct sensor_handler_s
{
    enum ipmi_update_e op;
    ipmi_sensor_t      *sensor;
    ipmi_entity_t      *entity;
} sensor_handler_t;

static void
call_sensor_handler(void *data, void *cb_data1, void *cb_data2)
{
    sensor_handler_t      *info = data;
    ipmi_entity_sensor_cb handler = cb_data1;

    handler(info->op, info->entity, info->sensor, cb_data2);
}

static void
call_sensor_handlers(ipmi_entity_t *ent, ipmi_sensor_t *sensor, 
		     enum ipmi_update_e op)
{
    sensor_handler_t info;
    int              old_destroyed;

    ent->cb_in_progress++;
    old_destroyed = ent->destroyed;
    if (ent->sensor_handler)
	ent->sensor_handler(op, ent, sensor, ent->sensor_cb_data);
    info.op = op;
    info.entity = ent;
    info.sensor = sensor;
    ilist_iter_twoitem(ent->sensor_handlers, call_sensor_handler, &info);
    ent->cb_in_progress--;
    if ((ent->destroyed) && (!old_destroyed))
	cleanup_entity(ent);
}

int
ipmi_entity_add_control_update_handler(ipmi_entity_t      *ent,
				       ipmi_entity_control_cb handler,
				       void               *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (ilist_add_twoitem(ent->control_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_control_update_handler(ipmi_entity_t      *ent,
					  ipmi_entity_control_cb handler,
					  void               *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (ilist_remove_twoitem(ent->control_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

typedef struct control_handler_s
{
    enum ipmi_update_e op;
    ipmi_entity_t      *entity;
    ipmi_control_t     *control;
} control_handler_t;

static void call_control_handler(void *data, void *cb_data1, void *cb_data2)
{
    control_handler_t      *info = data;
    ipmi_entity_control_cb handler = cb_data1;

    handler(info->op, info->entity, info->control, cb_data2);
}

static void
call_control_handlers(ipmi_entity_t *ent, ipmi_control_t *control, 
		     enum ipmi_update_e op)
{
    control_handler_t info;
    int               old_destroyed;

    ent->cb_in_progress++;
    old_destroyed = ent->destroyed;
    if (ent->control_handler)
	ent->control_handler(op, ent, control, ent->control_cb_data);
    info.op = op;
    info.entity = ent;
    info.control = control;
    ilist_iter_twoitem(ent->control_handlers, call_control_handler, &info);
    ent->cb_in_progress--;
    if ((ent->destroyed) && (!old_destroyed))
	cleanup_entity(ent);
}

static void handle_new_hot_swap_requester(ipmi_entity_t *ent,
					  ipmi_sensor_t *sensor);

static int
is_hot_swap_requester(ipmi_sensor_t *sensor)
{
    if (ipmi_sensor_get_event_reading_type(sensor)
	== IPMI_EVENT_READING_TYPE_THRESHOLD)
	return 0;

    return ipmi_sensor_is_hot_swap_requester(sensor, NULL, NULL);
}

static void handle_new_hot_swap_power(ipmi_entity_t  *ent,
				      ipmi_control_t *control);

static int
is_hot_swap_power(ipmi_control_t *control)
{
    if (ipmi_control_get_type(control) != IPMI_CONTROL_POWER)
	return 0;

    if (ipmi_control_get_num_vals(control) != 1)
	return 0;

    return ipmi_control_is_hot_swap_power(control);
}

static void handle_new_hot_swap_indicator(ipmi_entity_t  *ent,
					  ipmi_control_t *control);
static int
is_hot_swap_indicator(ipmi_control_t *control)
{
    if (ipmi_control_get_type(control) != IPMI_CONTROL_LIGHT)
	return 0;

    if (ipmi_control_get_num_vals(control) != 1)
	return 0;

    return ipmi_control_is_hot_swap_indicator(control, NULL, NULL, NULL, NULL);
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

static int
is_presence_sensor(ipmi_sensor_t *sensor)
{
    int val, rv;
    int supports_present = 0;
    int supports_absent = 0;

    /* Is it the right type (a presence sensor)? */
    if (ipmi_sensor_get_sensor_type(sensor) != 0x25)
	return 0;

    /* Presense sensors that don't generate events are kind of useless. */
    if (ipmi_sensor_get_event_support(sensor) == IPMI_EVENT_SUPPORT_NONE)
	return 0;

    /* Check present bit */
    rv = ipmi_discrete_event_readable(sensor, 0, &val);
    if ((!rv) && (val))
	supports_present = 1;
    /* Check absent bit. */
    rv = ipmi_discrete_event_readable(sensor, 1, &val);
    if ((!rv) && (val))
	supports_absent = 1;

    /* What good is this?  No support for the proper bits, I need to
       be able to read them. */
    if ((!supports_present) && (!supports_absent))
	return 0;

    return 1;
}

static int
is_presence_bit_sensor(ipmi_sensor_t *sensor, int *bit_offset)
{
    int val, rv;
    int bit;
    int sensor_type = ipmi_sensor_get_sensor_type(sensor);

    /* Is it a sensor with a presence bit? */
    switch (sensor_type)
    {
    case IPMI_SENSOR_TYPE_POWER_SUPPLY: bit = 0; break;
    case IPMI_SENSOR_TYPE_BATTERY: bit = 2; break;
    case IPMI_SENSOR_TYPE_SLOT_CONNECTOR: bit = 2; break;
    default:
	return 0;
    }

    /* Presense sensors that don't generate events are kind of useless. */
    if (ipmi_sensor_get_event_support(sensor) == IPMI_EVENT_SUPPORT_NONE)
	return 0;

    /* Check if the bit is available */
    rv = ipmi_discrete_event_readable(sensor, bit, &val);
    if (rv || !val)
	return 0;

    *bit_offset = bit;

    return 1;
}

void
ipmi_entity_add_sensor(ipmi_entity_t *ent,
		       ipmi_sensor_t *sensor,
		       void          *ref)
{
    ipmi_sensor_ref_t *link = (ipmi_sensor_ref_t *) ref;

    CHECK_ENTITY_LOCK(ent);

    /* The calling code should check for duplicates, no check done
       here. */
    link->sensor = ipmi_sensor_convert_to_id(sensor);
    link->list_link.malloced = 0;

    if (is_presence_sensor(sensor) && (ent->presence_sensor == NULL)) {
	/* It's the presence sensor and we don't already have one.  We
	   keep this special. */
	ent->presence_sensor = sensor;
	handle_new_presence_sensor(ent, sensor);
	ipmi_entity_free_sensor_link(link);
    } else {
	int bit;

	if ((ent->presence_sensor == NULL)&&(ent->presence_bit_sensor == NULL)
	    && is_presence_bit_sensor(sensor, &bit))
	{
	    /* If it's a sensor with a presence bit, we use it. */
	    ent->presence_bit_sensor = sensor;
	    ent->presence_bit_offset = bit;
	    handle_new_presence_bit_sensor(ent, sensor);
	}

	if (is_hot_swap_requester(sensor)
	    && (ent->hot_swap_requester == NULL))
	{
	    handle_new_hot_swap_requester(ent, sensor);
	}
	ilist_add_tail(ent->sensors, link, &(link->list_link));
	
	call_sensor_handlers(ent, sensor, IPMI_ADDED);
    }
}

static int sens_cmp(void *item, void *cb_data)
{
    ipmi_sensor_ref_t *ref1 = item;
    ipmi_sensor_id_t  *id2 = cb_data;

    return ipmi_cmp_sensor_id(ref1->sensor, *id2) == 0;
}

typedef struct sens_find_presence_s
{
    int           is_presence;
    int           bit;
    ipmi_sensor_t *sensor;
    ipmi_sensor_t *ignore_sensor;
} sens_cmp_info_t;

static void
sens_detect_if_presence(ipmi_sensor_t *sensor, void *cb_data)
{
    sens_cmp_info_t *info = cb_data;

    info->sensor = sensor;
    info->is_presence = is_presence_sensor(sensor);
}

static int sens_cmp_if_presence(void *item, void *cb_data)
{
    ipmi_sensor_ref_t *ref = item;
    sens_cmp_info_t   *info = cb_data;
    int               rv;

    rv = ipmi_sensor_pointer_cb(ref->sensor, sens_detect_if_presence, info);
    if (rv)
	return 0;
    
    return info->is_presence;
}

static void
sens_detect_if_presence_bit(ipmi_sensor_t *sensor, void *cb_data)
{
    sens_cmp_info_t *info = cb_data;

    if (sensor == info->ignore_sensor)
	return;

    info->sensor = sensor;
    info->is_presence = is_presence_bit_sensor(sensor, &info->bit);
}

static int sens_cmp_if_presence_bit(void *item, void *cb_data)
{
    ipmi_sensor_ref_t *ref = item;
    sens_cmp_info_t   *info = cb_data;
    int               rv;

    rv = ipmi_sensor_pointer_cb(ref->sensor, sens_detect_if_presence_bit,
				info);
    if (rv)
	return 0;
    
    return info->is_presence;
}

void
ipmi_entity_remove_sensor(ipmi_entity_t *ent,
			  ipmi_sensor_t *sensor)
{
    ipmi_sensor_ref_t *ref;
    ilist_iter_t      iter;
    sens_cmp_info_t   info;

    CHECK_ENTITY_LOCK(ent);

    if (sensor == ent->presence_sensor) {
	ilist_init_iter(&iter, ent->sensors);
	ilist_unpositioned(&iter);

	/* See if there is another presence sensor. */
	ref = ilist_search_iter(&iter, sens_cmp_if_presence, &info);

	if (ref) {
	    /* There is one, delete it from the list and from the
	       user, since we are taking it over. */
	    ilist_delete(&iter);

	    call_sensor_handlers(ent, sensor, IPMI_DELETED);

	    ent->presence_sensor = info.sensor;
	    handle_new_presence_sensor(ent, info.sensor);

	    ipmi_mem_free(ref);
	} else {
	    /* See if there is a presence bit sensor. */
	    ent->presence_sensor = NULL;
	    ilist_init_iter(&iter, ent->sensors);
	    ilist_unpositioned(&iter);
	    info.ignore_sensor = NULL;
	    ref = ilist_search_iter(&iter, sens_cmp_if_presence_bit, &info);
	    if (ref) {
		ent->presence_bit_sensor = info.sensor;
		ent->presence_bit_offset = info.bit;
		handle_new_presence_bit_sensor(ent, info.sensor);
	    }
	}
	ent->presence_possibly_changed = 1;
    } else {
	ipmi_sensor_id_t id = ipmi_sensor_convert_to_id(sensor);

	if (sensor == ent->presence_bit_sensor) {
	    ilist_init_iter(&iter, ent->sensors);
	    ilist_unpositioned(&iter);
	    info.ignore_sensor = sensor;
	    ref = ilist_search_iter(&iter, sens_cmp_if_presence_bit, &info);
	    if (ref) {
		ent->presence_bit_sensor = info.sensor;
		ent->presence_bit_offset = info.bit;
		handle_new_presence_bit_sensor(ent, info.sensor);
	    } else
		ent->presence_bit_sensor = NULL;
	}

	if (sensor == ent->hot_swap_requester) {
	    ent->hot_swap_requester = NULL;
	}

	ilist_init_iter(&iter, ent->sensors);
	ilist_unpositioned(&iter);
	ref = ilist_search_iter(&iter, sens_cmp, &id);
	if (!ref) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "%sentity.c(ipmi_entity_remove_sensor):"
		     " Removal of a sensor from an entity was requested,"
		     " but the sensor was not there",
		     SENSOR_NAME(sensor));
	    return;
	}

	ilist_delete(&iter);
	ipmi_mem_free(ref);

	call_sensor_handlers(ent, sensor, IPMI_DELETED);
    }

    cleanup_entity(ent);
}

void
ipmi_entity_add_control(ipmi_entity_t  *ent,
			ipmi_control_t *control,
			void           *ref)
{
    ipmi_control_ref_t *link = (ipmi_control_ref_t *) ref;

    CHECK_ENTITY_LOCK(ent);

    if (is_hot_swap_power(control))
	handle_new_hot_swap_power(ent, control);
    if (is_hot_swap_indicator(control))
	handle_new_hot_swap_indicator(ent, control);

    /* The calling code should check for duplicates, no check done
       here. */
    link->control = ipmi_control_convert_to_id(control);
    link->list_link.malloced = 0;
    ilist_add_tail(ent->controls, link, &(link->list_link));

    call_control_handlers(ent, control, IPMI_ADDED);
}

static int control_cmp(void *item, void *cb_data)
{
    ipmi_control_ref_t *ref1 = item;
    ipmi_control_id_t  *id2 = cb_data;

    return ipmi_cmp_control_id(ref1->control, *id2) == 0;
}

void
ipmi_entity_remove_control(ipmi_entity_t  *ent,
			   ipmi_control_t *control)
{
    ipmi_control_ref_t *ref;
    ilist_iter_t       iter;
    ipmi_control_id_t  id;

    CHECK_ENTITY_LOCK(ent);

    if (control == ent->hot_swap_power)
	ent->hot_swap_power = NULL;
    if (control == ent->hot_swap_indicator)
	ent->hot_swap_indicator = NULL;

    ilist_init_iter(&iter, ent->controls);
    ilist_unpositioned(&iter);

    id = ipmi_control_convert_to_id(control);
    ref = ilist_search_iter(&iter, control_cmp, &id);
    if (!ref) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(ipmi_entity_remove_control):"
		 " Removal of a control from an entity was requested,"
		 " but the control was not there",
		 CONTROL_NAME(control));
	return;
    }

    ilist_delete(&iter);
    ipmi_mem_free(ref);

    call_control_handlers(ent, control, IPMI_DELETED);

    cleanup_entity(ent);
}

int
ipmi_entity_set_sensor_update_handler(ipmi_entity_t         *ent,
				      ipmi_entity_sensor_cb handler,
				      void                  *cb_data)
{
    CHECK_ENTITY_LOCK(ent);

    ent->sensor_handler = handler;
    ent->sensor_cb_data = cb_data;
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

/***********************************************************************
 *
 * Handling of sensor data records for entities.
 *
 **********************************************************************/

static int
decode_ear(ipmi_sdr_t *sdr,
	   dlr_info_t *info)
{
    int i;
    int pos;

    memset(info, 0, sizeof(*info));

    info->type = IPMI_ENTITY_EAR;
    info->output_handler = NULL;

    info->device_num.channel = 0;
    info->device_num.address = 0;

    info->entity_id = sdr->data[0];
    info->entity_instance = sdr->data[1];

    info->linked_ear_exists = (sdr->data[2] & 0x40) == 0x40;
    info->presence_sensor_always_there = (sdr->data[2] & 0x20) == 0x20;
    info->is_ranges = (sdr->data[2] & 0x80) == 0x80;

    for (i=0,pos=3; pos<11; pos+=2,i++) {
	info->contained_entities[i].entity_id = sdr->data[pos];
	info->contained_entities[i].entity_instance = sdr->data[pos+1];
    }

    return 0;
}

static int
decode_drear(ipmi_sdr_t *sdr,
	   dlr_info_t *info)
{
    int i;
    int pos;

    memset(info, 0, sizeof(*info));

    info->type = IPMI_ENTITY_DREAR;
    info->output_handler = NULL;

    info->entity_id = sdr->data[0];
    info->entity_instance = sdr->data[1];

    if (sdr->data[1] >= 0x60) {
	info->device_num.channel = sdr->data[3] >> 4;
	info->device_num.address = sdr->data[2] & 0xfe;
    }

    info->linked_ear_exists = (sdr->data[4] & 0x40) == 0x40;
    info->presence_sensor_always_there = (sdr->data[4] & 0x20) == 0x20;
    info->is_ranges = (sdr->data[4] & 0x80) == 0x80;

    for (i=0,pos=5; pos<21; pos+=4,i++) {
	if (sdr->data[pos+3] >= 0x60) {
	    info->contained_entities[i].device_num.address = sdr->data[pos];
	    info->contained_entities[i].device_num.channel = sdr->data[pos+1];
	}
	info->contained_entities[i].entity_id = sdr->data[pos+2];
	info->contained_entities[i].entity_instance = sdr->data[pos+3];
    }

    return 0;
}

static int
gdlr_output(ipmi_entity_t *ent, ipmi_sdr_info_t *sdrs, void *cb_data)
{
    ipmi_sdr_t sdr;
    int        len;
    dlr_info_t *info = &ent->info;

    memset(&sdr, 0, sizeof(sdr));

    sdr.major_version = IPMI_MAJOR_NUM_SDR;
    sdr.minor_version = IPMI_MINOR_NUM_SDR;
    sdr.type = IPMI_SDR_GENERIC_DEVICE_LOCATOR_RECORD;
    sdr.length = 10; /* We'll fix it later. */
    sdr.data[0] = info->access_address;
    sdr.data[1] = (info->slave_address
		   | (info->channel >> 3));
    sdr.data[2] = ((info->channel << 5)
		   | (info->lun << 3)
		   | info->private_bus_id);
    sdr.data[3] = info->address_span & 0x7;
    sdr.data[4] = 0;
    sdr.data[5] = info->device_type;
    sdr.data[6] = info->device_type_modifier;
    sdr.data[7] = info->entity_id;
    sdr.data[8] = info->entity_instance;
    sdr.data[9] = info->oem;
    len = 16;
    ipmi_set_device_string(info->id,
			   info->id_type,
			   info->id_len,
			   sdr.data+10, 0, &len);
    sdr.length += len;

    return ipmi_sdr_add(sdrs, &sdr);
}

static int
decode_gdlr(ipmi_sdr_t         *sdr,
	    dlr_info_t         *info)
{
    memset(info, 0, sizeof(*info));

    info->type = IPMI_ENTITY_GENERIC;
    info->output_handler = gdlr_output;

    if (sdr->data[8] >= 0x60) {
	info->device_num.channel = (sdr->data[2] >> 5) | ((sdr->data[1] << 3)
							  & 0x08);
	info->device_num.address = sdr->data[0] & 0xfe;
    } else {
	info->device_num.channel = 0;
        info->device_num.address = 0;
    }

    info->access_address = sdr->data[0] & 0xfe;
    info->slave_address = sdr->data[1] & 0xfe;
    info->channel = ((sdr->data[2] >> 5)
				 | ((sdr->data[1] << 3) & 0x08));
    info->lun = (sdr->data[2] >> 3) & 0x3;
    info->private_bus_id = sdr->data[2] & 0x7;
    info->address_span = sdr->data[3] & 0x7;
    info->device_type = sdr->data[5];
    info->device_type_modifier = sdr->data[6];
    info->entity_id = sdr->data[7];
    info->entity_instance = sdr->data[8];
    info->oem = sdr->data[9];
    info->id_len = ipmi_get_device_string(sdr->data+10, sdr->length-10,
					  info->id, 0,
					  &info->id_type, ENTITY_ID_LEN);

    return 0;
}

static int
frudlr_output(ipmi_entity_t *ent, ipmi_sdr_info_t *sdrs, void *cb_data)
{
    ipmi_sdr_t sdr;
    int        len;
    dlr_info_t *info = &ent->info;

    memset(&sdr, 0, sizeof(sdr));

    sdr.major_version = IPMI_MAJOR_NUM_SDR;
    sdr.minor_version = IPMI_MINOR_NUM_SDR;
    sdr.type = IPMI_SDR_FRU_DEVICE_LOCATOR_RECORD;
    sdr.length = 10; /* We'll fix it later. */
    sdr.data[0] = info->access_address;
    sdr.data[1] = info->fru_device_id;
    sdr.data[2] = ((info->is_logical_fru << 7)
		   | (info->lun << 3)
		   | info->private_bus_id);
    sdr.data[3] = info->channel << 4;
    sdr.data[4] = 0;
    sdr.data[5] = info->device_type;
    sdr.data[6] = info->device_type_modifier;
    sdr.data[7] = info->entity_id;
    sdr.data[8] = info->entity_instance;
    sdr.data[9] = info->oem;
    len = 16;
    ipmi_set_device_string(info->id,
			   info->id_type,
			   info->id_len,
			   sdr.data+10, 0, &len);
    sdr.length += len;

    return ipmi_sdr_add(sdrs, &sdr);
}

static int
decode_frudlr(ipmi_sdr_t         *sdr,
	      dlr_info_t         *info)
{
    memset(info, 0, sizeof(*info));

    info->type = IPMI_ENTITY_FRU;
    info->output_handler = frudlr_output;

    if (sdr->data[8] >= 0x60) {
       info->device_num.channel = sdr->data[3] >> 4;
       info->device_num.address = sdr->data[0] & 0xfe;
    } else {
       info->device_num.channel = 0;
       info->device_num.address = 0;
    }

    info->access_address = sdr->data[0] & 0xfe;
    info->fru_device_id = sdr->data[1];
    info->channel = sdr->data[3] >> 4;
    info->is_logical_fru = ((sdr->data[2] & 0x80) == 0x80);
    info->lun = (sdr->data[2] >> 3) & 0x3;
    info->private_bus_id = sdr->data[2] & 0x7;
    info->device_type = sdr->data[5];
    info->device_type_modifier = sdr->data[6];
    info->oem = sdr->data[9];
    info->entity_id = sdr->data[7];
    info->entity_instance = sdr->data[8];
    info->id_len = ipmi_get_device_string(sdr->data+10,
					  sdr->length-10,
					  info->id, 0,
					  &info->id_type, ENTITY_ID_LEN);

    return 0;
}

static int
mcdlr_output(ipmi_entity_t *ent, ipmi_sdr_info_t *sdrs, void *cb_data)
{
    ipmi_sdr_t sdr;
    int        len;
    dlr_info_t *info = &ent->info;

    memset(&sdr, 0, sizeof(sdr));

    sdr.major_version = IPMI_MAJOR_NUM_SDR;
    sdr.minor_version = IPMI_MINOR_NUM_SDR;
    sdr.type = IPMI_SDR_MC_DEVICE_LOCATOR_RECORD;
    sdr.length = 10; /* We'll fix it later. */
    sdr.data[0] = info->slave_address;
    sdr.data[1] = info->channel & 0xf;
    sdr.data[2] = ((info->ACPI_system_power_notify_required << 7)
		   || (info->ACPI_device_power_notify_required << 6)
		   || (info->controller_logs_init_agent_errors << 3)
		   || (info->log_init_agent_errors_accessing << 2)
		   || (info->global_init));
    sdr.data[3] = ((info->chassis_device << 7)
		   || (info->bridge << 6)
		   || (info->IPMB_event_generator << 5)
		   || (info->IPMB_event_receiver << 4)
		   || (info->FRU_inventory_device << 3)
		   || (info->SEL_device << 2)
		   || (info->SDR_repository_device << 1)
		   || info->sensor_device);
    sdr.data[4] = 0;
    sdr.data[5] = 0;
    sdr.data[6] = 0;
    sdr.data[7] = ent->info.entity_id;
    sdr.data[8] = ent->info.entity_instance;
    sdr.data[9] = info->oem;
    len = 16;
    ipmi_set_device_string(info->id,
			   info->id_type,
			   info->id_len,
			   sdr.data+10, 0, &len);
    sdr.length += len;

    return ipmi_sdr_add(sdrs, &sdr);
}

static int
decode_mcdlr(ipmi_sdr_t *sdr,
	     dlr_info_t *info)
{
    unsigned char *data;


    memset(info, 0, sizeof(*info));

    info->type = IPMI_ENTITY_MC;
    info->output_handler = mcdlr_output;

    if (sdr->data[8] >= 0x60) {
	info->device_num.channel = sdr->data[1] & 0xf;
	info->device_num.address = sdr->data[0] & 0xfe;
    } else {
	info->device_num.channel = 0;
	info->device_num.address = 0;
    }

    data = sdr->data;
    info->slave_address = *data & 0xfe;
    data++;
    if (sdr->major_version == 1 && sdr->minor_version == 0) {
	/* IPMI 1.0 SDR type 12 record, doesn't have the channel
	   field, so we have to have special handling. */
	info->channel = 0;
    } else {
	info->channel = *data & 0xf;
	data++;
    }

    info->ACPI_system_power_notify_required = (data[0] >> 7) & 1;
    info->ACPI_device_power_notify_required = (data[0] >> 6) & 1;
    info->controller_logs_init_agent_errors = (data[0] >> 3) & 1;
    info->log_init_agent_errors_accessing   = (data[0] >> 2) & 1;
    info->global_init                       = (data[0] >> 0) & 3;

    info->chassis_device = (data[1] >> 7) & 1;
    info->bridge = (data[1] >> 6) & 1;
    info->IPMB_event_generator = (data[1] >> 5) & 1;
    info->IPMB_event_receiver = (data[1] >> 4) & 1;
    info->FRU_inventory_device = (data[1] >> 3) & 1;
    info->SEL_device = (data[1] >> 2) & 1;
    info->SDR_repository_device = (data[1] >> 1) & 1;
    info->sensor_device = (data[1] >> 0) & 1;

    /* We switch back to referring to sdr->data here, because the rest
       of the offsets are the same in 1.0 and 1.5.  Only the power
       state and device capabilities change between the two
       version. */
    info->entity_id = sdr->data[7];
    info->entity_instance = sdr->data[8];

    info->oem = sdr->data[9];
    info->id_len = ipmi_get_device_string(sdr->data+10,
					  sdr->length-10,
					  info->id, 0,
					  &info->id_type, ENTITY_ID_LEN);


    /* Make sure the FRU fetch stuff works. */
    info->access_address = info->slave_address;
    info->fru_device_id = 0;
    info->is_logical_fru = 1;
    info->private_bus_id = 0;

    return 0;
}

typedef struct entity_found_s
{
    int found;
    ipmi_entity_t *ent;
    ipmi_entity_t **cent;
    unsigned int cent_next;
    unsigned int cent_len;
} entity_found_t;

typedef struct entity_sdr_info_s
{
    ipmi_entity_info_t *ents;
    unsigned int len; /* array size */
    unsigned int next; /* next member to use. */
    entity_found_t *found; /* bools and info used for comparing. */
    dlr_info_t **dlrs;
} entity_sdr_info_t;

static int
add_sdr_info(entity_sdr_info_t *infos, dlr_info_t *dlr)
{
    dlr_info_t *new_dlr;

    if (infos->len == infos->next) {
	/* Need to expand the array. */
	unsigned int   new_length = infos->len + 5;
	dlr_info_t     **new_dlrs;
	entity_found_t *new_found;

	new_dlrs = ipmi_mem_alloc(sizeof(dlr_info_t *) * new_length);
	if (!new_dlrs)
	    return ENOMEM;
	new_found = ipmi_mem_alloc(sizeof(*infos->found) * new_length);
	if (!new_found) {
	    ipmi_mem_free(new_dlrs);
	    return ENOMEM;
	}
	if (infos->dlrs) {
	    memcpy(new_dlrs, infos->dlrs, sizeof(dlr_info_t *) * infos->len);
	    ipmi_mem_free(infos->dlrs);
	    ipmi_mem_free(infos->found);
	}
	infos->dlrs = new_dlrs;
	infos->found = new_found;
	infos->len = new_length;
    }

    new_dlr = ipmi_mem_alloc(sizeof(*new_dlr));
    if (!new_dlr)
	return ENOMEM;

    memcpy(new_dlr, dlr, sizeof(*new_dlr));
    infos->dlrs[infos->next] = new_dlr;
    infos->next++;

    return 0;
}

static void
destroy_sdr_info(entity_sdr_info_t *infos)
{
    int i;

    if (infos->dlrs) {
	for (i=0; i<infos->next; i++) {
	    if (infos->found[i].cent)
		ipmi_mem_free(infos->found[i].cent);
	}
	for (i=0; i<infos->next; i++)
	    ipmi_mem_free(infos->dlrs[i]);
	ipmi_mem_free(infos->dlrs);
	ipmi_mem_free(infos->found);
    }
}

static void
cleanup_sdr_info(entity_sdr_info_t *infos)
{
    int i;

    if (infos->dlrs) {
	for (i=0; i<infos->next; i++) {
	    if (infos->found[i].cent)
		ipmi_mem_free(infos->found[i].cent);
	    infos->found[i].cent = NULL;
	    infos->found[i].cent_len = 0;
	    infos->found[i].cent_next = 0;
	}
    }
}

static int
add_child_ent(entity_found_t *found,
	      ipmi_entity_t  *ent)
{
    if (found->cent_next == found->cent_len) {
	int new_len = found->cent_len + 4;
	ipmi_entity_t **new_cent;

	new_cent = ipmi_mem_alloc(sizeof(ipmi_entity_t *) * new_len);
	if (!new_cent)
	    return ENOMEM;
	if (found->cent) {
	    memcpy(new_cent, found->cent,
		   sizeof(ipmi_entity_t *) * found->cent_len);
	    ipmi_mem_free(found->cent);
	}
	found->cent = new_cent;
	found->cent_len = new_len;
    }

    found->cent[found->cent_next] = ent;
    found->cent_next++;

    return 0;
}

/* Find all the entities for unfound dlrs, and allocate new eclinks if
   not NULL. */
static int
fill_in_entities(ipmi_entity_info_t  *ents,
		 entity_sdr_info_t   *infos,
		 entity_child_link_t **new_eclinks)
{
    entity_found_t      *found;
    entity_child_link_t *eclinks = NULL;
    entity_child_link_t *eclink;
    int                 i, j;
    int                 rv;
    ipmi_entity_t       *child;

    for (i=0; i<infos->next; i++) {
	found = infos->found+i;

	if (found->found)
	    continue;

	rv = entity_add(ents, infos->dlrs[i]->device_num,
			infos->dlrs[i]->entity_id,
			infos->dlrs[i]->entity_instance,
			infos->dlrs[i]->output_handler, NULL,
			&found->ent);
	if (rv)
	    goto out_err;

	if ((infos->dlrs[i]->type != IPMI_ENTITY_EAR)
	    && (infos->dlrs[i]->type != IPMI_ENTITY_DREAR))
	    continue;

	if (infos->dlrs[i]->is_ranges) {
	    for (j=0; j<4; j+=2) {
		dlr_ref_t *cent1 = infos->dlrs[i]->contained_entities+j;
		dlr_ref_t *cent2 = infos->dlrs[i]->contained_entities+j+1;
		int k;
		if (cent1->entity_id == 0)
		    continue;
		for (k=cent1->entity_instance; k<=cent2->entity_instance; k++){
		    rv = entity_add(ents, cent1->device_num,
				    cent1->entity_id, k,
				    NULL, NULL, &child);
		    if (rv)
			goto out_err;
		    rv = add_child_ent(found, child);
		    if (rv)
			goto out_err;
		    if (new_eclinks) {
			eclink = ipmi_mem_alloc(sizeof(*eclink));
			if (!eclink) {
			    rv = ENOMEM;
			    goto out_err;
			}
			eclink->tlink = eclinks;
			eclinks = eclink;
		    }
		}
	    }
	} else {
	    for (j=0; j<4; j++) {
		dlr_ref_t *cent = infos->dlrs[i]->contained_entities+j;
		if (cent->entity_id == 0)
		    continue;
		rv = entity_add(ents, cent->device_num,
				cent->entity_id, cent->entity_instance,
				NULL, NULL, &child);
		if (rv)
		    return rv;
		rv = add_child_ent(found, child);
		if (rv)
		    goto out_err;
		if (new_eclinks) {
		    eclink = ipmi_mem_alloc(sizeof(*eclink));
		    if (!eclink)
			return ENOMEM;
		    eclink->tlink = eclinks;
		    eclinks = eclink;
		}
	    }
	}
    }

    if (new_eclinks)
	*new_eclinks = eclinks;

    return 0;

 out_err:
    while (eclinks) {
	eclink = eclinks;
	eclinks = eclink->tlink;
	ipmi_mem_free(eclinks);
    }
    return rv;
}

int
ipmi_entity_scan_sdrs(ipmi_domain_t      *domain,
		      ipmi_mc_t          *mc,
		      ipmi_entity_info_t *ents,
		      ipmi_sdr_info_t    *sdrs)
{
    unsigned int        count;
    int                 i, j;
    int                 rv;
    entity_sdr_info_t   infos;
    entity_sdr_info_t   *old_infos;
    entity_child_link_t *eclinks = NULL;
    entity_child_link_t *eclink;
    entity_found_t      *found;

    memset(&infos, 0, sizeof(infos));

    rv = ipmi_get_sdr_count(sdrs, &count);
    if (rv)
	return rv;

    for (i=0; i<count; i++) {
	ipmi_sdr_t sdr;
	dlr_info_t dlr;

	rv = ipmi_get_sdr_by_index(sdrs, i, &sdr);
	if (rv)
	    return rv;

	switch (sdr.type) {
	    case IPMI_SDR_ENITY_ASSOCIATION_RECORD:
		rv = decode_ear(&sdr, &dlr);
		if (!rv)
		    rv = add_sdr_info(&infos, &dlr);
		break;

	    case IPMI_SDR_DR_ENITY_ASSOCIATION_RECORD:
		rv = decode_drear(&sdr, &dlr);
		if (!rv)
		    rv = add_sdr_info(&infos, &dlr);
		break;

	    case IPMI_SDR_GENERIC_DEVICE_LOCATOR_RECORD:
		rv = decode_gdlr(&sdr, &dlr);
		if (!rv)
		    rv = add_sdr_info(&infos, &dlr);
		break;

	    case IPMI_SDR_FRU_DEVICE_LOCATOR_RECORD:
		rv = decode_frudlr(&sdr, &dlr);
		if (!rv)
		    rv = add_sdr_info(&infos, &dlr);
		break;

	    case IPMI_SDR_MC_DEVICE_LOCATOR_RECORD:
		rv = decode_mcdlr(&sdr, &dlr);
		if (!rv)
		    rv = add_sdr_info(&infos, &dlr);
		break;
	}
	if (rv)
	    goto out_err;
    }

    old_infos = _ipmi_get_sdr_entities(domain, mc);
    if (!old_infos) {
	old_infos = ipmi_mem_alloc(sizeof(*old_infos));
	if (!old_infos) {
	    rv = ENOMEM;
	    goto out_err;
	}
	memset(old_infos, 0, sizeof(*old_infos));
	old_infos->ents = ents;
	_ipmi_set_sdr_entities(domain, mc, old_infos);
    }

    /* Clear out all the temporary found information we use for
       scanning. */
    for (i=0; i<old_infos->next; i++)
	memset(old_infos->found+i, 0, sizeof(entity_found_t));
    for (i=0; i<infos.next; i++)
	memset(infos.found+i, 0, sizeof(entity_found_t));

    /* For every item in the new array, try to find it in the old
       array.  This is O(n^2), but these should be small arrays. */
    for (i=0; i<infos.next; i++) {
	for (j=0; j<old_infos->next; j++) {
	    if (old_infos->found[j].found)
		continue;
	    if (!memcmp(infos.dlrs[i], old_infos->dlrs[j], sizeof(dlr_info_t)))
	    {
		infos.found[i].found = 1;
		old_infos->found[j].found = 1;
		break;
	    }
	}
    }

    /* For every item in the array that is not found, make sure
       the entities exists and we have them. */
    rv = fill_in_entities(ents, &infos, &eclinks);
    if (rv)
	goto out;
    rv = fill_in_entities(ents, old_infos, NULL);
    if (rv)
	goto out;

    /* After this, the operation cannot fail. */

    rv = 0;

    /* Destroy all the old information that was not in the new version
       of the SDRs. */
    for (i=0; i<old_infos->next; i++) {
	found = old_infos->found + i;
	if (found->found)
	    continue;

	if ((old_infos->dlrs[i]->type != IPMI_ENTITY_EAR)
	    && (old_infos->dlrs[i]->type != IPMI_ENTITY_DREAR))
	{
	    /* A real DLR, decrement the refcount, and destroy the info. */
	    found->ent->ref_count--;
	    memset(&found->ent->info, 0, sizeof(dlr_info_t));
	} else {
	    /* It's an EAR, so handling removing the children. */
	    for (j=0; j<found->cent_next; j++)
		ipmi_entity_remove_child(found->ent, found->cent[j]);
	}
    }

    /* Add all the new information that was in the new SDRs. */
    for (i=0; i<infos.next; i++) {
	found = infos.found + i;
	if (found->found)
	    continue;

	if ((infos.dlrs[i]->type != IPMI_ENTITY_EAR)
	    && (infos.dlrs[i]->type != IPMI_ENTITY_DREAR))
	{
	    uint8_t ipmb    = 0xff;
	    int     channel = -1;

	    /* A real DLR, increment the refcount, and copy the info. */
	    found->ent->ref_count++;
	    memcpy(&found->ent->info, infos.dlrs[i], sizeof(dlr_info_t));
	    entity_set_name(found->ent);
	    /* Don't fetch FRU information until present. */

	    /* Set up the MC information for the device. */
	    if (infos.dlrs[i]->type == IPMI_ENTITY_FRU) {
		channel = infos.dlrs[i]->channel;
		ipmb = infos.dlrs[i]->slave_address;
	    }
	    else if (infos.dlrs[i]->type == IPMI_ENTITY_MC)
	    {
		channel = infos.dlrs[i]->channel;
		ipmb = infos.dlrs[i]->access_address;
	    }

	    /* If we can use the FRU device presence to detect whether
	       the entity is present, we register the monitor with the
	       appropriate management controller to see if it is
	       active and base presence off of that, if no other
	       presence detection capability is there. */
	    if (ipmb == 0) {
		/* Not a valid IPMB, just ignore it. */
	    } else if ((channel != -1) && (infos.dlrs[i]->entity_id)) {
		ipmi_mc_t *mc;
		/* Attempt to create the MC. */
		rv = _ipmi_find_or_create_mc_by_slave_addr
		    (domain, channel, ipmb, &mc);
		if (rv) {
		    ipmi_log(IPMI_LOG_SEVERE,
			     "%sentity.c(ipmi_entity_scan_sdrs):"
			     " Could not add MC for MCDLR or FRUDLR,"
			     " error %x", ENTITY_NAME(found->ent), rv);
		} else if (found->ent->frudev_present) {
		    if (found->ent->frudev_mc != mc) {
			ipmi_log(IPMI_LOG_WARNING,
				 "%sentity.c(ipmi_entity_scan_sdrs):"
				 " Entity has two different MCs in"
				 " different SDRs, only using the first"
				 " for presence.  MCs are %s and %s",
				 ENTITY_NAME(found->ent),
				 MC_NAME(found->ent->frudev_mc),
				 MC_NAME(mc));
		    }
		} else {
		    rv = ipmi_mc_add_active_handler(mc,
						    entity_mc_active,
						    found->ent);
		    if (rv) {
			ipmi_log(IPMI_LOG_SEVERE,
				 "%sentity.c(ipmi_entity_scan_sdrs):"
				 " Could not add an MC active handler for"
				 " MCDLR or FRUDLR,"
				 " error %x", ENTITY_NAME(found->ent), rv);
		    } else {
			found->ent->frudev_present = 1;
			found->ent->frudev_active = ipmi_mc_is_active(mc);
			found->ent->frudev_mc = mc;
		    }
		}
	    }
	} else {
	    /* It's an EAR, so handling adding the children. */
	    for (j=0; j<found->cent_next; j++) {
		eclink = eclinks;
		eclinks = eclinks->tlink;
		add_child(found->ent, found->cent[j], NULL, &eclink);
		if (eclink)
		    ipmi_mem_free(eclink);
	    }
	}
    }

    /* Now go through the new dlrs to call the updated handler on
       them. */
    for (i=0; i<infos.next; i++) {
	ent_info_update_handler_info_t info;

	found = infos.found + i;
	if (found->found)
	    continue;

	/* Call the update handler list. */
	info.op = IPMI_CHANGED;
	info.entity = found->ent;
	info.domain = domain;
	ilist_iter_twoitem(found->ent->ents->update_handlers,
			   call_entity_info_update_handler,
			   &info);

	/* Call the old version handler. */
	if (found->ent->ents->handler)
	    found->ent->ents->handler(IPMI_CHANGED, domain, found->ent,
				      found->ent->ents->cb_data);      

	for (j=0; j<found->cent_next; j++) {
	    info.entity = found->cent[j];
	    ilist_iter_twoitem(found->cent[j]->ents->update_handlers,
			       call_entity_info_update_handler,
			       &info);
	    if (found->cent[j]->ents->handler)
		found->cent[j]->ents->handler(IPMI_CHANGED, domain,
					      found->cent[j],
					      found->cent[j]->ents->cb_data);
	}
    }

    /* Now go through all the old dlrs that were not matched to see if
       we should delete any entities associated with them. */
    for (i=0; i<old_infos->next; i++) {
	found = old_infos->found + i;
	if (found->found)
	    continue;

	cleanup_entity(found->ent);
	for (j=0; j<found->cent_next; j++)
	    cleanup_entity(found->cent[j]);
    }


    destroy_sdr_info(old_infos);
    cleanup_sdr_info(&infos);
    infos.ents = ents;
    memcpy(old_infos, &infos, sizeof(infos));

 out:
    /* Clean up any entity child links we didn't use. */
    while (eclinks) {
	eclink = eclinks;
	eclinks = eclink->tlink;
	ipmi_mem_free(eclinks);
    }
    return rv;

 out_err:
    destroy_sdr_info(&infos);
    goto out;
}

int
ipmi_sdr_entity_destroy(void *info)
{
    entity_sdr_info_t   *infos = info;
    entity_found_t      *found;
    int                 i, j;
    int                 rv;
    ipmi_entity_t       *ent, *child;

    for (i=0; i<infos->next; i++) {
	found = infos->found+i;

	rv = entity_find(infos->ents, infos->dlrs[i]->device_num,
			 infos->dlrs[i]->entity_id,
			 infos->dlrs[i]->entity_instance,
			 &ent);
	if (rv)
	    continue;

	if ((infos->dlrs[i]->type != IPMI_ENTITY_EAR)
	    && (infos->dlrs[i]->type != IPMI_ENTITY_DREAR))
	{
	    ent->ref_count--;
	} else {
	    if (infos->dlrs[i]->is_ranges) {
		for (j=0; j<4; j+=2) {
		    dlr_ref_t *cent1 = infos->dlrs[i]->contained_entities+j;
		    dlr_ref_t *cent2 = infos->dlrs[i]->contained_entities+j+1;
		    int k;
		    if (cent1->entity_id == 0)
			continue;
		    for (k=cent1->entity_instance;
			 k<=cent2->entity_instance;
			 k++)
		    {
			rv = entity_find(infos->ents, cent1->device_num,
					 cent1->entity_id, k,
					 &child);
			if (rv)
			    continue;

			ipmi_entity_remove_child(ent, child);
			cleanup_entity(child);
		    }
		}
	    } else {
		for (j=0; j<4; j++) {
		    dlr_ref_t *cent = infos->dlrs[i]->contained_entities+j;
		    if (cent->entity_id == 0)
			continue;
		    rv = entity_find(infos->ents, cent->device_num,
				     cent->entity_id, cent->entity_instance,
				     &child);
		    if (rv)
			continue;
		    ipmi_entity_remove_child(ent, child);
		    cleanup_entity(child);
		}
	    }
	}

	cleanup_entity(ent);
    }

    destroy_sdr_info(info);
    ipmi_mem_free(info);

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

    if (ent1->info.entity_id < ent2->info.entity_id)
	return -1;
    if (ent1->info.entity_id > ent2->info.entity_id)
	return 1;
    if (ent1->info.entity_instance < ent2->info.entity_instance)
	return -1;
    if (ent1->info.entity_instance > ent2->info.entity_instance)
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

    if (sdr->type == IPMI_SDR_ENITY_ASSOCIATION_RECORD) {
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
	    sdr->data[pos] = ents[i]->info.entity_id;
	    pos++;
	    sdr->data[pos] = ents[i]->info.entity_instance;
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
	    sdr->data[pos] = ents[i]->info.device_num.address;
	    pos++;
	    sdr->data[pos] = ents[i]->info.device_num.channel;
	    pos++;
	    sdr->data[pos] = ents[i]->info.entity_id;
	    pos++;
	    sdr->data[pos] = ents[i]->info.entity_instance;
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
    sdr.data[0] = ent->info.entity_id;
    sdr.data[1] = ent->info.entity_instance;

    if ((sdr.major_version == 1) && (sdr.minor_version < 5)) {
	/* IPMI 1.0, we can olny use normal entity association
	   records */
	sdr.type = IPMI_SDR_ENITY_ASSOCIATION_RECORD;
	sdr.length = 11;
	sdr.data[2] = (ent->info.presence_sensor_always_there << 5);
    } else {
	/* IPMI 1.5, we only use the device-relative EARs. */
	sdr.type = IPMI_SDR_DR_ENITY_ASSOCIATION_RECORD;
	sdr.length = 27;
	sdr.data[2] = ent->info.slave_address;
	sdr.data[3] = ent->info.channel;
	sdr.data[4] = (ent->info.presence_sensor_always_there << 5);
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
	prev_inst = curr->info.entity_instance;
	if (ilist_next(&iter))
	    next = ilist_get(&iter);
	else
	    next = NULL;
	while (next
	       && (next->info.entity_id == curr->info.entity_id)
	       && (next->info.entity_instance == prev_inst+1))
	{
	    last = next;
	    if (ilist_next(&iter))
		next = ilist_get(&iter);
	    else
		next = NULL;
	    prev_inst++;
	}
	if (prev_inst > curr->info.entity_instance) {
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

/***********************************************************************
 *
 * Get/set all the various entity values.
 *
 **********************************************************************/

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

    return ent->info.access_address;
}

void
ipmi_entity_set_access_address(ipmi_entity_t *ent, int access_address)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.access_address = access_address;
}

int
ipmi_entity_get_slave_address(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.slave_address;
}

void
ipmi_entity_set_slave_address(ipmi_entity_t *ent, int slave_address)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.slave_address = slave_address;
}

int
ipmi_entity_get_channel(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.channel;
}

void
ipmi_entity_set_channel(ipmi_entity_t *ent, int channel)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.channel = channel;
}

int
ipmi_entity_get_lun(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.lun;
}

void
ipmi_entity_set_lun(ipmi_entity_t *ent, int lun)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.lun = lun;
}

int
ipmi_entity_get_private_bus_id(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.private_bus_id;
}

void
ipmi_entity_set_private_bus_id(ipmi_entity_t *ent, int private_bus_id)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.private_bus_id = private_bus_id;
}

int
ipmi_entity_get_is_logical_fru(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.is_logical_fru;
}

void
ipmi_entity_set_is_logical_fru(ipmi_entity_t *ent, int is_logical_fru)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.is_logical_fru = is_logical_fru;
}

int
ipmi_entity_get_fru_device_id(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.fru_device_id;
}

void
ipmi_entity_set_fru_device_id(ipmi_entity_t *ent, int fru_device_id)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.fru_device_id = fru_device_id;
}

int
ipmi_entity_get_is_fru(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    if (ent->info.type == IPMI_ENTITY_FRU)
	return 1;
    if ((ent->info.type == IPMI_ENTITY_MC) && (ent->info.FRU_inventory_device))
	return 1;
    return 0;
}

int
ipmi_entity_get_is_mc(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.type == IPMI_ENTITY_MC;
}

enum ipmi_dlr_type_e
ipmi_entity_get_type(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.type;
}

void
ipmi_entity_set_type(ipmi_entity_t *ent, enum ipmi_dlr_type_e type)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.type = type;
}

int
ipmi_entity_get_entity_id(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.entity_id;
}

int
ipmi_entity_get_entity_instance(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.entity_instance;
}

int
ipmi_entity_get_device_channel(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.device_num.channel;
}

int
ipmi_entity_get_device_address(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.device_num.address;
}

int
ipmi_entity_get_device_type(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.device_type;
}

void
ipmi_entity_set_device_type(ipmi_entity_t *ent, int device_type)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.device_type = device_type;
}

int
ipmi_entity_get_device_modifier(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.device_type_modifier;
}

void
ipmi_entity_set_device_modifier(ipmi_entity_t *ent, int device_modifier)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.device_type_modifier = device_modifier;
}

int
ipmi_entity_get_oem(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.oem;
}

void
ipmi_entity_set_oem(ipmi_entity_t *ent, int oem)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.oem = oem;
}

int
ipmi_entity_get_address_span(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.address_span;
}

void
ipmi_entity_set_address_span(ipmi_entity_t *ent, int address_span)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.address_span = address_span;
}

int
ipmi_entity_get_id_length(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.id_len;
}

enum ipmi_str_type_e
ipmi_entity_get_id_type(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.id_type;
}

int
ipmi_entity_get_id(ipmi_entity_t *ent, char *id, int length)
{
    int clen;

    CHECK_ENTITY_LOCK(ent);

    if (ent->info.id_len > length)
	clen = length;
    else
	clen = ent->info.id_len;
    memcpy(id, ent->info.id, clen);

    if (ent->info.id_type == IPMI_ASCII_STR) {
	/* NIL terminate the ASCII string. */
	if (clen == length)
	    clen--;

	id[clen] = '\0';
    }

    return clen;
}

void
ipmi_entity_set_id(ipmi_entity_t *ent, char *id,
		   enum ipmi_str_type_e type, int length)
{
    CHECK_ENTITY_LOCK(ent);

    if (length > ENTITY_ID_LEN)
	length = ENTITY_ID_LEN;
    
    memcpy(ent->info.id, id, length);
    ent->info.id_type = type;
    ent->info.id_len = length;
    entity_set_name(ent);
}

int
ipmi_entity_get_presence_sensor_always_there(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.presence_sensor_always_there;
}

void
ipmi_entity_set_presence_sensor_always_there(ipmi_entity_t *ent, int val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.presence_sensor_always_there = val;
}

int
ipmi_entity_get_ACPI_system_power_notify_required(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.ACPI_system_power_notify_required;
}

void
ipmi_entity_set_ACPI_system_power_notify_required(ipmi_entity_t *ent,
						  int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.ACPI_system_power_notify_required = val;
}

int
ipmi_entity_get_ACPI_device_power_notify_required(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.ACPI_device_power_notify_required;
}

void
ipmi_entity_set_ACPI_device_power_notify_required(ipmi_entity_t *ent,
						  int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.ACPI_device_power_notify_required = val;
}

int
ipmi_entity_get_controller_logs_init_agent_errors(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.controller_logs_init_agent_errors;
}

void
ipmi_entity_set_controller_logs_init_agent_errors(ipmi_entity_t *ent,
						  int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.controller_logs_init_agent_errors = val;
}

int
ipmi_entity_get_log_init_agent_errors_accessing(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.log_init_agent_errors_accessing;
}

void
ipmi_entity_set_log_init_agent_errors_accessing(ipmi_entity_t *ent,
						int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.log_init_agent_errors_accessing = val;
}

int
ipmi_entity_get_global_init(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.global_init;
}

void
ipmi_entity_set_global_init(ipmi_entity_t *ent,
			    int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.global_init = val;
}

int
ipmi_entity_get_chassis_device(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.chassis_device;
}

void
ipmi_entity_set_chassis_device(ipmi_entity_t *ent,
			       int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.chassis_device = val;
}

int
ipmi_entity_get_bridge(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.bridge;
}

void
ipmi_entity_set_bridge(ipmi_entity_t *ent,
		       int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.bridge = val;
}

int
ipmi_entity_get_IPMB_event_generator(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.IPMB_event_generator;
}

void
ipmi_entity_set_IPMB_event_generator(ipmi_entity_t *ent,
				     int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.IPMB_event_generator = val;
}

int
ipmi_entity_get_IPMB_event_receiver(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.IPMB_event_receiver;
}

void
ipmi_entity_set_IPMB_event_receiver(ipmi_entity_t *ent,
				    int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.IPMB_event_receiver = val;
}

int
ipmi_entity_get_FRU_inventory_device(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.FRU_inventory_device;
}

void
ipmi_entity_set_FRU_inventory_device(ipmi_entity_t *ent,
				     int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.FRU_inventory_device = val;
}

int
ipmi_entity_get_SEL_device(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.SEL_device;
}

void
ipmi_entity_set_SEL_device(ipmi_entity_t *ent,
			   int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.SEL_device = val;
}

int
ipmi_entity_get_SDR_repository_device(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.SDR_repository_device;
}

void
ipmi_entity_set_SDR_repository_device(ipmi_entity_t *ent,
				      int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.SDR_repository_device = val;
}

int
ipmi_entity_get_sensor_device(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->info.sensor_device;
}

void
ipmi_entity_set_sensor_device(ipmi_entity_t *ent,
			      int           val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->info.sensor_device = val;
}


int
ipmi_entity_get_is_child(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ! ilist_empty(ent->parent_entities);
}

int
ipmi_entity_get_is_parent(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ! ilist_empty(ent->sub_entities);
}

int
ipmi_entity_is_present(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->present;
}

static void
entity_id_is_present_cb(ipmi_entity_t *ent, void *cb_data)
{
    *((int *) cb_data) = ipmi_entity_is_present(ent);
}

int
ipmi_entity_id_is_present(ipmi_entity_id_t id, int *present)
{
    return ipmi_entity_pointer_cb(id, entity_id_is_present_cb, present);
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

/***********************************************************************
 *
 * Handle conversions between entity_ids and pointers.
 *
 **********************************************************************/

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
    val.entity_id = ent->info.entity_id;
    val.entity_instance = ent->info.entity_instance;
    val.channel = ent->info.device_num.channel;
    val.address = ent->info.device_num.address;
    val.seq = ent->seq;

    return val;
}

typedef struct mc_cb_info_s
{
    ipmi_entity_ptr_cb handler;
    void               *cb_data;
    ipmi_entity_id_t   id;
    int                err;
    int                ignore_seq;
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
    if (!info->ignore_seq && !info->err) {
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
    info.ignore_seq = 0;

    rv = ipmi_domain_pointer_cb(id.domain_id, domain_cb, &info);
    if (!rv)
	rv = info.err;

    return rv;
}

static int
ipmi_entity_pointer_cb_noseq(ipmi_entity_id_t   id,
			     ipmi_entity_ptr_cb handler,
			     void               *cb_data)
{
    int          rv;
    mc_cb_info_t info;

    info.handler = handler;
    info.cb_data = cb_data;
    info.id = id;
    info.err = 0;
    info.ignore_seq = 1;

    rv = ipmi_domain_pointer_cb(id.domain_id, domain_cb, &info);
    if (!rv)
	rv = info.err;

    return rv;
}

static void
get_seq(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_entity_id_t *id = cb_data;

    *id = ipmi_entity_convert_to_id(entity);
}

int
ipmi_entity_find_id(ipmi_domain_id_t domain_id,
		    int entity_id, int entity_instance,
		    int channel, int slave_address,
		    ipmi_entity_id_t *id)
{
    int rv;

    id->domain_id = domain_id;
    id->entity_id = entity_id;
    id->entity_instance = entity_instance;
    id->channel = channel;
    id->address = slave_address;

    rv = ipmi_entity_pointer_cb_noseq(*id, get_seq, id);
    return rv;
}

int
ipmi_cmp_entity_id(ipmi_entity_id_t id1, ipmi_entity_id_t id2)
{
    int cmp;

    cmp = ipmi_cmp_domain_id(id1.domain_id, id2.domain_id);
    if (cmp)
	return cmp;

    if (id1.entity_id < id2.entity_id)
	return -1;
    if (id1.entity_id > id2.entity_id)
	return 1;

    if (id1.entity_instance < id2.entity_instance)
	return -1;
    if (id1.entity_instance > id2.entity_instance)
	return 1;

    if (id1.channel < id2.channel)
	return -1;
    if (id1.channel > id2.channel)
	return 1;

    if (id1.address < id2.address)
	return -1;
    if (id1.address > id2.address)
	return 1;

    if (id1.seq < id2.seq)
	return -1;
    if (id1.seq > id2.seq)
	return 1;

    return 0;
}

void
ipmi_entity_id_set_invalid(ipmi_entity_id_t *id)
{
    ipmi_domain_id_set_invalid(&id->domain_id);
}

int
ipmi_entity_id_is_invalid(ipmi_entity_id_t *id)
{
    return (id->domain_id.domain == NULL);
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

/***********************************************************************
 *
 * Entity FRU data handling.
 *
 **********************************************************************/

int
ipmi_entity_add_fru_update_handler(ipmi_entity_t      *ent,
				   ipmi_entity_fru_cb handler,
				   void               *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (ilist_add_twoitem(ent->fru_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_fru_update_handler(ipmi_entity_t      *ent,
				      ipmi_entity_fru_cb handler,
				      void               *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (ilist_remove_twoitem(ent->fru_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_entity_set_fru_update_handler(ipmi_entity_t     *ent,
				   ipmi_entity_fru_cb handler,
				   void              *cb_data)
{
    CHECK_ENTITY_LOCK(ent);

    ent->fru_handler = handler;
    ent->fru_cb_data = cb_data;
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

typedef struct fru_handler_s
{
    enum ipmi_update_e op;
    ipmi_entity_t      *entity;
} fru_handler_t;

static void call_fru_handler(void *data, void *cb_data1, void *cb_data2)
{
    fru_handler_t      *info = data;
    ipmi_entity_fru_cb handler = cb_data1;

    handler(info->op, info->entity, cb_data2);
}

static void
call_fru_handlers(ipmi_entity_t *ent, enum ipmi_update_e op)
{
    fru_handler_t info;
    int           old_destroyed;

    ent->cb_in_progress++;
    old_destroyed = ent->destroyed;
    if (ent->fru_handler)
	ent->fru_handler(op, ent, ent->fru_cb_data);
    info.op = op;
    info.entity = ent;
    ilist_iter_twoitem(ent->fru_handlers, call_fru_handler, &info);
    ent->cb_in_progress--;
    if ((ent->destroyed) && (!old_destroyed))
	cleanup_entity(ent);
}

typedef struct fru_ent_info_s
{
    ipmi_entity_t      *entity;
    ipmi_fru_t         *fru;
    int                err;
} fru_ent_info_t;

static void
fru_fetched_ent_cb(ipmi_entity_t *ent, void *cb_data)
{
    fru_ent_info_t *info = cb_data;

    if (!info->err) {
	enum ipmi_update_e op;
	if (ent->fru) {
	    op = IPMI_CHANGED;
	    ipmi_fru_destroy(ent->fru, NULL, NULL);
	} else {
	    op = IPMI_ADDED;
	}
	ent->fru = info->fru;

	call_fru_handlers(ent, op);
    } else {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(fru_fetched_ent_cb):"
		 "Error fetching entity %d.%d FRU: %x\n",
		 ENTITY_NAME(ent),
		 ent->info.entity_id, ent->info.entity_instance, info->err);
	if ((ent->fru) && (info->fru))
	    /* Keep the old FRU on errors. */
	    ipmi_fru_destroy(info->fru, NULL, NULL);
	else
	    /* Keep it if we got it, it might have some useful
	       information. */
	    ent->fru = info->fru;
    }
}

static void
fru_fetched_handler(ipmi_fru_t *fru, int err, void *cb_data)
{
    ipmi_entity_id_t *ent_id = cb_data;
    fru_ent_info_t   info;
    int              rv;

    info.fru = fru;
    info.err = err;

    rv = ipmi_entity_pointer_cb(*ent_id, fru_fetched_ent_cb, &info);
    if (rv)
	/* If we can't put the fru someplace, just destroy it. */
	ipmi_fru_destroy(fru, NULL, NULL);

    ipmi_mem_free(ent_id);
}

int
ipmi_entity_fetch_frus(ipmi_entity_t *ent)
{
    ipmi_entity_id_t *ent_id;
    int              rv;

    ent_id = ipmi_mem_alloc(sizeof(*ent_id));
    if (!ent_id)
	return ENOMEM;

    *ent_id = ipmi_entity_convert_to_id(ent);

    /* fetch the FRU information. */
    rv = ipmi_fru_alloc(ent->domain,
			ent->info.is_logical_fru,
			ent->info.access_address,
			ent->info.fru_device_id,
			ent->info.lun,
			ent->info.private_bus_id,
			ent->info.channel,
			fru_fetched_handler,
			ent_id,
			NULL);
    if (rv)
	ipmi_mem_free(ent_id);

    return rv;
}

ipmi_fru_t *
ipmi_entity_get_fru(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->fru;
}

/*
 * Getting the FRU values for an entity.
 */

#define FRU_VAL_GET(type, name) \
int								\
ipmi_entity_get_ ## name(ipmi_entity_t *entity,			\
			 type          *val)			\
{								\
    CHECK_ENTITY_LOCK(entity);					\
    if (!entity->fru)						\
	return ENOSYS;						\
    return ipmi_fru_get_ ## name(entity->fru, val);		\
}

#define FRU_STR_GET(name) \
int								\
ipmi_entity_get_ ## name(ipmi_entity_t *entity,			\
			 char          *str,			\
			 unsigned int  *strlen)			\
{								\
    CHECK_ENTITY_LOCK(entity);					\
    if (!entity->fru)						\
	return ENOSYS;						\
    return ipmi_fru_get_ ## name(entity->fru, str, strlen);	\
}

#define FRU_CUSTOM_GET(name) \
int									\
ipmi_entity_get_ ## name ## _custom_len(ipmi_entity_t *entity,		\
					unsigned int  num,		\
					unsigned int  *length)		\
{									\
    CHECK_ENTITY_LOCK(entity);						\
    if (!entity->fru)							\
	return ENOSYS;							\
    return ipmi_fru_get_ ## name ## _custom_len(entity->fru, num, length);\
}									\
int									\
ipmi_entity_get_## name ## _custom_type(ipmi_entity_t        *entity,	\
				        unsigned int         num,	\
				        enum ipmi_str_type_e *type)	\
{									\
    CHECK_ENTITY_LOCK(entity);						\
    if (!entity->fru)							\
	return ENOSYS;							\
    return ipmi_fru_get_ ## name ## _custom_type(entity->fru, num, type);\
}									\
int									\
ipmi_entity_get_## name ## _custom(ipmi_entity_t        *entity,	\
			           unsigned int         num,		\
			           char                 *str,		\
				   unsigned int         *str_len)	\
{									\
    CHECK_ENTITY_LOCK(entity);						\
    if (!entity->fru)							\
	return ENOSYS;							\
    return ipmi_fru_get_ ## name ## _custom(entity->fru, num, str, str_len);\
}

FRU_VAL_GET(unsigned char, internal_use_version)
FRU_VAL_GET(unsigned int,  internal_use_length)

int
ipmi_entity_get_internal_use_data(ipmi_entity_t *entity,
				  unsigned char *data,
				  unsigned int  *max_len)
{
    CHECK_ENTITY_LOCK(entity);
    if (!entity->fru)
	return ENOSYS;
    return ipmi_fru_get_internal_use_data(entity->fru, data, max_len);
}

FRU_VAL_GET(unsigned char, chassis_info_version)
FRU_VAL_GET(unsigned char, chassis_info_type)

FRU_VAL_GET(unsigned int,  chassis_info_part_number_len)
FRU_VAL_GET(enum ipmi_str_type_e, chassis_info_part_number_type)
FRU_STR_GET(chassis_info_part_number)
FRU_VAL_GET(unsigned int,  chassis_info_serial_number_len)
FRU_VAL_GET(enum ipmi_str_type_e, chassis_info_serial_number_type)
FRU_STR_GET(chassis_info_serial_number)
FRU_CUSTOM_GET(chassis_info)

FRU_VAL_GET(unsigned char, board_info_version)
FRU_VAL_GET(unsigned char, board_info_lang_code)
int ipmi_entity_get_board_info_mfg_time(ipmi_entity_t *entity,
					time_t        *time)
{
    CHECK_ENTITY_LOCK(entity);
    if (!entity->fru)
	return ENOSYS;
    return ipmi_fru_get_board_info_mfg_time(entity->fru, time);
}
FRU_VAL_GET(unsigned int,  board_info_board_manufacturer_len)
FRU_VAL_GET(enum ipmi_str_type_e, board_info_board_manufacturer_type)
FRU_STR_GET(board_info_board_manufacturer)
FRU_VAL_GET(unsigned int,  board_info_board_product_name_len)
FRU_VAL_GET(enum ipmi_str_type_e, board_info_board_product_name_type)
FRU_STR_GET(board_info_board_product_name)
FRU_VAL_GET(unsigned int,  board_info_board_serial_number_len)
FRU_VAL_GET(enum ipmi_str_type_e, board_info_board_serial_number_type)
FRU_STR_GET(board_info_board_serial_number)
FRU_VAL_GET(unsigned int, board_info_board_part_number_len)
FRU_VAL_GET(enum ipmi_str_type_e, board_info_board_part_number_type)
FRU_STR_GET(board_info_board_part_number)
FRU_VAL_GET(unsigned int,  board_info_fru_file_id_len)
FRU_VAL_GET(enum ipmi_str_type_e, board_info_fru_file_id_type)
FRU_STR_GET(board_info_fru_file_id)
FRU_CUSTOM_GET(board_info)

FRU_VAL_GET(unsigned char, product_info_version)
FRU_VAL_GET(unsigned char, product_info_lang_code)
FRU_VAL_GET(unsigned int, product_info_manufacturer_name_len)
FRU_VAL_GET(enum ipmi_str_type_e, product_info_manufacturer_name_type)
FRU_STR_GET(product_info_manufacturer_name)
FRU_VAL_GET(unsigned int,  product_info_product_name_len)
FRU_VAL_GET(enum ipmi_str_type_e, product_info_product_name_type)
FRU_STR_GET(product_info_product_name)
FRU_VAL_GET(unsigned int,  product_info_product_part_model_number_len)
FRU_VAL_GET(enum ipmi_str_type_e, product_info_product_part_model_number_type)
FRU_STR_GET(product_info_product_part_model_number)
FRU_VAL_GET(unsigned int,  product_info_product_version_len)
FRU_VAL_GET(enum ipmi_str_type_e, product_info_product_version_type)
FRU_STR_GET(product_info_product_version)
FRU_VAL_GET(unsigned int,  product_info_product_serial_number_len)
FRU_VAL_GET(enum ipmi_str_type_e, product_info_product_serial_number_type)
FRU_STR_GET(product_info_product_serial_number)
FRU_VAL_GET(unsigned int,  product_info_asset_tag_len)
FRU_VAL_GET(enum ipmi_str_type_e, product_info_asset_tag_type)
FRU_STR_GET(product_info_asset_tag)
FRU_VAL_GET(unsigned int,  product_info_fru_file_id_len)
FRU_VAL_GET(enum ipmi_str_type_e, product_info_fru_file_id_type)
FRU_STR_GET(product_info_fru_file_id)
FRU_CUSTOM_GET(product_info)

unsigned int
ipmi_entity_get_num_multi_records(ipmi_entity_t *entity)
{
    CHECK_ENTITY_LOCK(entity);
    if (!entity->fru)
	return 0;
    return ipmi_fru_get_num_multi_records(entity->fru);
}

int
ipmi_entity_get_multi_record_type(ipmi_entity_t *entity,
				  unsigned int  num,
				  unsigned char *type)
{
    CHECK_ENTITY_LOCK(entity);
    if (!entity->fru)
	return ENOSYS;
    return ipmi_fru_get_multi_record_type(entity->fru, num, type);
}

int
ipmi_entity_get_multi_record_format_version(ipmi_entity_t *entity,
					    unsigned int  num,
					    unsigned char *ver)
{
    CHECK_ENTITY_LOCK(entity);
    if (!entity->fru)
	return ENOSYS;
    return ipmi_fru_get_multi_record_format_version(entity->fru, num, ver);
}

int
ipmi_entity_get_multi_record_data_len(ipmi_entity_t *entity,
				      unsigned int  num,
				      unsigned int  *len)
{
    CHECK_ENTITY_LOCK(entity);
    if (!entity->fru)
	return ENOSYS;
    return ipmi_fru_get_multi_record_data_len(entity->fru, num, len);
}

int
ipmi_entity_get_multi_record_data(ipmi_entity_t *entity,
				  unsigned int  num,
				  unsigned char *data,
				  unsigned int  *length)
{
    CHECK_ENTITY_LOCK(entity);
    if (!entity->fru)
	return ENOSYS;
    return ipmi_fru_get_multi_record_data(entity->fru, num, data, length);
}

/***************************************************************************
 *
 * Hot swap
 *
 ***************************************************************************/

int
ipmi_entity_set_hot_swappable(ipmi_entity_t *ent, int val)
{
    ent_info_update_handler_info_t info;

    ent->hot_swappable = val;

    /* Make sure the user knows of the change. */
    info.op = IPMI_CHANGED;
    info.entity = ent;
    info.domain = ipmi_entity_get_domain(ent);
    ilist_iter_twoitem(ent->ents->update_handlers,
		       call_entity_info_update_handler,
		       &info);

    /* Call the old version handler. */
    if (ent->ents->handler)
	ent->ents->handler(IPMI_CHANGED, info.domain, ent,
			   ent->ents->cb_data);      

    return 0;
}

int
ipmi_entity_hot_swappable(ipmi_entity_t *ent)
{
    return ent->hot_swappable;
}

int
ipmi_entity_add_hot_swap_handler(ipmi_entity_t           *ent,
				 ipmi_entity_hot_swap_cb handler,
				 void                    *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (ilist_add_twoitem(ent->hot_swap_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_hot_swap_handler(ipmi_entity_t           *ent,
				    ipmi_entity_hot_swap_cb handler,
				    void                    *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (ilist_remove_twoitem(ent->hot_swap_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

void
ipmi_entity_set_hot_swap_control(ipmi_entity_t          *ent,
				 ipmi_entity_hot_swap_t *cbs)
{
    CHECK_ENTITY_LOCK(ent);

    ent->hs_cb = *cbs;
}



typedef struct hot_swap_handler_info_s
{
    ipmi_entity_t             *ent;
    enum ipmi_hot_swap_states last_state;
    enum ipmi_hot_swap_states curr_state;
    ipmi_event_t              **event;
    int                       handled;
} hot_swap_handler_info_t;

static void
call_hot_swap_handler(void *data, void *cb_data1, void *cb_data2)
{
    hot_swap_handler_info_t *info = data;
    ipmi_entity_hot_swap_cb handler = cb_data1;
    int                     handled;

    handled = handler(info->ent, info->last_state, info->curr_state,
		      cb_data2, *(info->event));
    if (handled == IPMI_EVENT_HANDLED) {
	info->handled = handled;
	*(info->event) = NULL;
    }
}

void
ipmi_entity_call_hot_swap_handlers(ipmi_entity_t             *ent,
				   enum ipmi_hot_swap_states last_state,
				   enum ipmi_hot_swap_states curr_state,
				   ipmi_event_t              **event,
				   int                       *handled)
{
    hot_swap_handler_info_t info;
    int                     old_destroyed;

    info.ent = ent;
    info.last_state = last_state;
    info.curr_state = curr_state;
    info.event = event;
    info.handled = IPMI_EVENT_NOT_HANDLED;
    ent->cb_in_progress++;
    old_destroyed = ent->destroyed;
    ilist_iter_twoitem(ent->hot_swap_handlers, call_hot_swap_handler, &info);
    if (handled)
	*handled = info.handled;
    ent->cb_in_progress--;
    if ((ent->destroyed) && (!old_destroyed))
	cleanup_entity(ent);
}

int
ipmi_entity_get_hot_swap_state(ipmi_entity_t                 *ent,
			       ipmi_entity_hot_swap_state_cb handler,
			       void                          *cb_data)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.get_hot_swap_state)
	return ENOSYS;
    return ent->hs_cb.get_hot_swap_state(ent, handler, cb_data);
}

int
ipmi_entity_set_auto_activate_time(ipmi_entity_t  *ent,
				   ipmi_timeout_t auto_act,
				   ipmi_entity_cb done,
				   void           *cb_data)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.set_auto_activate)
	return ENOSYS;
    return ent->hs_cb.set_auto_activate(ent, auto_act, done, cb_data);
}

int
ipmi_entity_get_auto_activate_time(ipmi_entity_t       *ent,
				   ipmi_entity_time_cb handler,
				   void                *cb_data)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.get_auto_activate)
	return ENOSYS;
    return ent->hs_cb.get_auto_activate(ent, handler, cb_data);
}

int
ipmi_entity_set_auto_deactivate_time(ipmi_entity_t  *ent,
				     ipmi_timeout_t auto_deact,
				     ipmi_entity_cb done,
				     void           *cb_data)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.set_auto_deactivate)
	return ENOSYS;
    return ent->hs_cb.set_auto_deactivate(ent, auto_deact, done, cb_data);
}

int
ipmi_entity_get_auto_deactivate_time(ipmi_entity_t       *ent,
				     ipmi_entity_time_cb handler,
				     void                *cb_data)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.get_auto_deactivate)
	return ENOSYS;
    return ent->hs_cb.get_auto_deactivate(ent, handler, cb_data);
}

int
ipmi_entity_activate(ipmi_entity_t  *ent,
		     ipmi_entity_cb done,
		     void           *cb_data)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.activate)
	return ENOSYS;
    return ent->hs_cb.activate(ent, done, cb_data);
}

int
ipmi_entity_deactivate(ipmi_entity_t  *ent,
		       ipmi_entity_cb done,
		       void           *cb_data)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.deactivate)
	return ENOSYS;
    return ent->hs_cb.deactivate(ent, done, cb_data);
}

int
ipmi_entity_get_hot_swap_indicator(ipmi_entity_t      *ent,
				   ipmi_entity_val_cb handler,
				   void               *cb_data)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.get_hot_swap_indicator)
	return ENOSYS;
    return ent->hs_cb.get_hot_swap_indicator(ent, handler, cb_data);
}

int
ipmi_entity_set_hot_swap_indicator(ipmi_entity_t  *ent,
				   int            val,
				   ipmi_entity_cb done,
				   void           *cb_data)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.set_hot_swap_indicator)
	return ENOSYS;
    return ent->hs_cb.set_hot_swap_indicator(ent, val, done, cb_data);
}

int
ipmi_entity_get_hot_swap_requester(ipmi_entity_t      *ent,
				   ipmi_entity_val_cb handler,
				   void               *cb_data)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.get_hot_swap_requester)
	return ENOSYS;
    return ent->hs_cb.get_hot_swap_requester(ent, handler, cb_data);
}

int
ipmi_entity_check_hot_swap_state(ipmi_entity_t *ent)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.check_hot_swap_state)
	return ENOSYS;
    return ent->hs_cb.check_hot_swap_state(ent);
}

/***********************************************************************
 *
 * Entity ID versions of the hot-swap calls.
 *
 **********************************************************************/

typedef struct entity_hot_swap_cb_info_s
{
    int                           rv;
    ipmi_entity_hot_swap_state_cb handler;
    void                          *cb_data;
} entity_hot_swap_cb_info_t;

typedef struct entity_cb_info_s
{
    int            rv;
    ipmi_timeout_t time;
    int            val;
    ipmi_entity_cb handler;
    void           *cb_data;
} entity_cb_info_t;

typedef struct entity_val_cb_info_s
{
    int                rv;
    ipmi_entity_val_cb handler;
    void               *cb_data;
} entity_val_cb_info_t;

typedef struct entity_time_cb_info_s
{
    int                 rv;
    ipmi_entity_time_cb handler;
    void                *cb_data;
} entity_time_cb_info_t;

static void
entity_id_get_hot_swap_state_cb(ipmi_entity_t *entity, void *cb_data)
{
    entity_hot_swap_cb_info_t *info = cb_data;

    info->rv = ipmi_entity_get_hot_swap_state(entity, info->handler,
					      info->cb_data);
}

int
ipmi_entity_id_get_hot_swap_state(ipmi_entity_id_t              id,
				  ipmi_entity_hot_swap_state_cb handler,
				  void                          *cb_data)
{
    int                       rv;
    entity_hot_swap_cb_info_t info;

    info.rv = 0;
    info.handler = handler;
    info.cb_data = cb_data;

    rv = ipmi_entity_pointer_cb(id, entity_id_get_hot_swap_state_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

static void
entity_get_auto_activate_time_cb(ipmi_entity_t *ent, void *cb_data)
{
    entity_time_cb_info_t *info = cb_data;

    info->rv = ipmi_entity_get_auto_activate_time(ent, info->handler,
						  info->cb_data);
}

int
ipmi_entity_id_get_auto_activate_time(ipmi_entity_id_t    id,
				      ipmi_entity_time_cb handler,
				      void                *cb_data)
{
    entity_time_cb_info_t info;
    int                   rv;

    info.rv = 0;
    info.handler = handler;
    info.cb_data = cb_data;
    rv = ipmi_entity_pointer_cb(id, entity_get_auto_activate_time_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

static void
entity_set_auto_activate_time_cb(ipmi_entity_t *ent, void *cb_data)
{
    entity_cb_info_t *info = cb_data;

    info->rv = ipmi_entity_set_auto_activate_time(ent, info->time,
						  info->handler,
						  info->cb_data);
}

int
ipmi_entity_id_set_auto_activate_time(ipmi_entity_id_t  id,
				      ipmi_timeout_t    auto_act,
				      ipmi_entity_cb    done,
				      void              *cb_data)
{
    entity_cb_info_t info;
    int              rv;

    info.rv = 0;
    info.time = auto_act;
    info.handler = done;
    info.cb_data = cb_data;
    rv = ipmi_entity_pointer_cb(id, entity_set_auto_activate_time_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

static void
entity_get_auto_deactivate_time_cb(ipmi_entity_t *ent, void *cb_data)
{
    entity_time_cb_info_t *info = cb_data;

    info->rv = ipmi_entity_get_auto_deactivate_time(ent, info->handler,
						    info->cb_data);
}

int
ipmi_entity_id_get_auto_deactivate_time(ipmi_entity_id_t    id,
					ipmi_entity_time_cb handler,
					void                *cb_data)
{
    entity_time_cb_info_t info;
    int                   rv;

    info.rv = 0;
    info.handler = handler;
    info.cb_data = cb_data;
    rv = ipmi_entity_pointer_cb(id, entity_get_auto_deactivate_time_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

static void
entity_set_auto_deactivate_time_cb(ipmi_entity_t *ent, void *cb_data)
{
    entity_cb_info_t *info = cb_data;

    info->rv = ipmi_entity_set_auto_deactivate_time(ent, info->time,
						    info->handler,
						    info->cb_data);
}

int
ipmi_entity_id_set_auto_deactivate_time(ipmi_entity_id_t id,
					ipmi_timeout_t   auto_deact,
					ipmi_entity_cb   done,
					void             *cb_data)
{
    entity_cb_info_t info;
    int              rv;

    info.rv = 0;
    info.time = auto_deact;
    info.handler = done;
    info.cb_data = cb_data;
    rv = ipmi_entity_pointer_cb(id, entity_set_auto_deactivate_time_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

static void
entity_activate_cb(ipmi_entity_t *ent, void *cb_data)
{
    entity_cb_info_t *info = cb_data;

    info->rv = ipmi_entity_activate(ent, info->handler,
				    info->cb_data);
}

int
ipmi_entity_id_activate(ipmi_entity_id_t id,
			ipmi_entity_cb   done,
			void             *cb_data)
{
    entity_cb_info_t info;
    int              rv;

    info.rv = 0;
    info.handler = done;
    info.cb_data = cb_data;
    rv = ipmi_entity_pointer_cb(id, entity_activate_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

static void
entity_deactivate_cb(ipmi_entity_t *ent, void *cb_data)
{
    entity_cb_info_t *info = cb_data;

    info->rv = ipmi_entity_deactivate(ent, info->handler,
				      info->cb_data);
}

int
ipmi_entity_id_deactivate(ipmi_entity_id_t id,
			  ipmi_entity_cb   done,
			  void             *cb_data)
{
    entity_cb_info_t info;
    int              rv;

    info.rv = 0;
    info.handler = done;
    info.cb_data = cb_data;
    rv = ipmi_entity_pointer_cb(id, entity_deactivate_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

static void
entity_get_hot_swap_indicator_cb(ipmi_entity_t *ent, void *cb_data)
{
    entity_val_cb_info_t *info = cb_data;

    info->rv = ipmi_entity_get_hot_swap_indicator(ent, info->handler,
						  info->cb_data);
}

int
ipmi_entity_id_get_hot_swap_indicator(ipmi_entity_id_t   id,
				      ipmi_entity_val_cb handler,
				      void               *cb_data)
{
    entity_val_cb_info_t info;
    int                  rv;

    info.rv = 0;
    info.handler = handler;
    info.cb_data = cb_data;
    rv = ipmi_entity_pointer_cb(id, entity_get_hot_swap_indicator_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

static void
entity_set_hot_swap_indicator_cb(ipmi_entity_t *ent, void *cb_data)
{
    entity_cb_info_t *info = cb_data;

    info->rv = ipmi_entity_set_hot_swap_indicator(ent, info->val,
						  info->handler,
						  info->cb_data);
}

int
ipmi_entity_id_set_hot_swap_indicator(ipmi_entity_id_t id,
				      int              val,
				      ipmi_entity_cb   done,
				      void             *cb_data)
{
    entity_cb_info_t info;
    int              rv;

    info.rv = 0;
    info.val = val;
    info.handler = done;
    info.cb_data = cb_data;
    rv = ipmi_entity_pointer_cb(id, entity_set_hot_swap_indicator_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

static void
entity_get_hot_swap_requester_cb(ipmi_entity_t *ent, void *cb_data)
{
    entity_val_cb_info_t *info = cb_data;

    info->rv = ipmi_entity_get_hot_swap_requester(ent, info->handler,
						  info->cb_data);
}

int
ipmi_entity_id_get_hot_swap_requester(ipmi_entity_id_t   id,
				      ipmi_entity_val_cb handler,
				      void               *cb_data)
{
    entity_val_cb_info_t info;
    int                  rv;

    info.rv = 0;
    info.handler = handler;
    info.cb_data = cb_data;
    rv = ipmi_entity_pointer_cb(id, entity_get_hot_swap_requester_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

static void
entity_check_hot_swap_state_cb(ipmi_entity_t *ent, void *cb_data)
{
    entity_val_cb_info_t *info = cb_data;

    info->rv = ipmi_entity_check_hot_swap_state(ent);
}

int
ipmi_entity_id_check_hot_swap_state(ipmi_entity_id_t id)
{
    entity_val_cb_info_t info;
    int                  rv;

    info.rv = 0;
    rv = ipmi_entity_pointer_cb(id, entity_check_hot_swap_state_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}


/***********************************************************************
 *
 * The internal hot-swap state machine.
 *
 **********************************************************************/

static int set_hot_swap_state(ipmi_entity_t             *ent,
			      enum ipmi_hot_swap_states state,
			      ipmi_event_t              *event);

static void
hot_swap_power_on(ipmi_control_t *control, int err, void *cb_data)
{
    ipmi_entity_t *ent = cb_data;

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(hot_swap_power_on):"
		 " Unable to set the hot swap power: %x",
		 CONTROL_NAME(control), err);
    } else {
	set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVE, NULL);
    }
}

static void
hot_swap_power_off(ipmi_control_t *control, int err, void *cb_data)
{
    ipmi_entity_t *ent = cb_data;

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(hot_swap_power_off):"
		 " Unable to set the hot swap power: %x",
		 CONTROL_NAME(control), err);
    } else {
	set_hot_swap_state(ent, IPMI_HOT_SWAP_INACTIVE, NULL);
    }
}

typedef struct power_cb_info_s
{
    ipmi_entity_t  *ent;
    ipmi_entity_cb handler;
    void           *cb_data;
} power_cb_info_t;

static void
hot_swap_power_on_cb(ipmi_control_t *control, int err, void *cb_data)
{
    power_cb_info_t *info = cb_data;
    ipmi_entity_t   *ent = info->ent;

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(hot_swap_power_on_cb):"
		 " Unable to set the hot swap power: %x",
		 CONTROL_NAME(control), err);
    } else {
	set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVE, NULL);
    }

    if (info->handler)
	info->handler(info->ent, err, info->cb_data);
    ipmi_mem_free(info);
}

static void
hot_swap_power_off_cb(ipmi_control_t *control, int err, void *cb_data)
{
    power_cb_info_t *info = cb_data;
    ipmi_entity_t   *ent = info->ent;

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(hot_swap_power_off_cb):"
		 " Unable to set the hot swap power: %x",
		 CONTROL_NAME(control), err);
    } else {
	set_hot_swap_state(ent, IPMI_HOT_SWAP_INACTIVE, NULL);
    }

    if (info->handler)
	info->handler(info->ent, err, info->cb_data);
    ipmi_mem_free(info);
}

static void
indicator_change(ipmi_control_t *control, int err, void *cb_data)
{
    if (err)
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(indicator_change):"
		 " Unable to set the hot swap indicator: %x",
		 CONTROL_NAME(control), err);
}

static int
hot_swap_act(ipmi_entity_t *ent, ipmi_entity_cb handler, void *cb_data)
{
    int                val;
    int                rv = ENOSYS;
    ipmi_control_op_cb cb;
    power_cb_info_t    *info = NULL;

    if (ent->hot_swap_state == IPMI_HOT_SWAP_ACTIVATION_REQUESTED) {
	if (ent->hot_swap_power) {
	    if (handler == NULL) {
		cb = hot_swap_power_on;
		cb_data = ent;
	    } else {
		info = ipmi_mem_alloc(sizeof(*info));
		if (!info)
		    return ENOMEM;
		cb = hot_swap_power_on_cb;
		info->ent = ent;
		info->handler = handler;
		info->cb_data = cb_data;
		cb_data = info;
	    }

	    val = 1;
	    rv = ipmi_control_set_val(ent->hot_swap_power,
				      &val,
				      cb,
				      cb_data);
	    if (!rv)
		set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVATION_IN_PROGRESS,
				   NULL);
	    else if (info)
		ipmi_mem_free(info);
	}
    } else {
	rv = EAGAIN;
    }

    return rv;
}

static void
hot_swap_act_cb(ipmi_entity_t *ent, void *cb_data)
{
    int rv;

    rv = hot_swap_act(ent, NULL, NULL);
    if (rv && (rv != EAGAIN))
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(hot_swap_act_cb):"
		 " Unable to set the hot swap power: %x",
		 ENTITY_NAME(ent), rv);
}

static void
hot_swap_act_timeout(void *cb_data, os_hnd_timer_id_t *timer)
{
    ipmi_entity_t    *ent = cb_data;
    ipmi_entity_id_t entity_id;

    ipmi_lock(ent->timer_lock);
    ent->running_timer_count--;
    ent->hot_swap_act_timer_running = 0;

    if (ent->destroyed) {
	entity_final_destroy(ent); /* Unlocks the lock */
	return;
    }
    entity_id = ipmi_entity_convert_to_id(ent);
    ipmi_unlock(ent->timer_lock);

    ipmi_entity_pointer_cb(entity_id, hot_swap_act_cb, NULL);
}

static int
hot_swap_deact(ipmi_entity_t *ent, ipmi_entity_cb handler, void *cb_data)
{
    int                val;
    int                rv = ENOSYS;
    ipmi_control_op_cb cb;
    power_cb_info_t    *info;

    if (ent->hot_swap_state == IPMI_HOT_SWAP_DEACTIVATION_REQUESTED) {
	if (ent->hot_swap_power) {
	    if (handler == NULL) {
		cb = hot_swap_power_off;
		cb_data = ent;
	    } else {
		info = ipmi_mem_alloc(sizeof(*info));
		if (!info)
		    return ENOMEM;
		cb = hot_swap_power_off_cb;
		info->ent = ent;
		info->handler = handler;
		info->cb_data = cb_data;
		cb_data = info;
	    }

	    val = 0;
	    rv = ipmi_control_set_val(ent->hot_swap_power,
				      &val,
				      cb,
				      cb_data);
	    if (!rv)
		set_hot_swap_state(ent, IPMI_HOT_SWAP_DEACTIVATION_IN_PROGRESS,
				   NULL);
	}
    } else {
	rv = EAGAIN;
    }

    return rv;
}

static void
hot_swap_deact_cb(ipmi_entity_t *ent, void *cb_data)
{
    int rv;

    rv = hot_swap_deact(ent, NULL, NULL);
    if (rv && (rv != EAGAIN))
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(hot_swap_deact_cb):"
		 " Unable to set the hot swap power: %x",
		 ENTITY_NAME(ent), rv);
}

static void
hot_swap_deact_timeout(void *cb_data, os_hnd_timer_id_t *timer)
{
    ipmi_entity_t    *ent = cb_data;
    ipmi_entity_id_t entity_id;

    ipmi_lock(ent->timer_lock);
    ent->running_timer_count--;
    ent->hot_swap_deact_timer_running = 0;

    if (ent->destroyed) {
	entity_final_destroy(ent); /* Unlocks the lock */
	return;
    }
    entity_id = ipmi_entity_convert_to_id(ent);
    ipmi_unlock(ent->timer_lock);

    ipmi_entity_pointer_cb(entity_id, hot_swap_deact_cb, NULL);
}

static int
set_hot_swap_state(ipmi_entity_t             *ent,
		   enum ipmi_hot_swap_states state,
		   ipmi_event_t              *event)
{
    int                       val;
    int                       set = 1;
    enum ipmi_hot_swap_states old_state;
    int                       handled = IPMI_EVENT_NOT_HANDLED;

    old_state = ent->hot_swap_state;

    switch (state)
    {
    case IPMI_HOT_SWAP_INACTIVE:
	val = ent->hot_swap_ind_inact;
	break;

    case IPMI_HOT_SWAP_ACTIVATION_REQUESTED:
	val = ent->hot_swap_ind_req_act;
	if (ent->hot_swap_act_timeout != IPMI_TIMEOUT_FOREVER) {
	    /* Need to time the operation. */
	    struct timeval timeout;

	    timeout.tv_sec = ent->hot_swap_act_timeout / 1000000000;
	    timeout.tv_usec = (ent->hot_swap_act_timeout % 1000000000) / 1000;
	    ipmi_lock(ent->timer_lock);
	    if (!ent->hot_swap_act_timer_running) {
		ent->os_hnd->start_timer(ent->os_hnd,
					 ent->hot_swap_act_timer,
					 &timeout,
					 hot_swap_act_timeout,
					 ent);
		ent->hot_swap_act_timer_running = 1;
		ent->running_timer_count++;
	    }
	    ipmi_unlock(ent->timer_lock);
	}
	break;

    case IPMI_HOT_SWAP_ACTIVE:
	val = ent->hot_swap_ind_act;
	break;

    case IPMI_HOT_SWAP_DEACTIVATION_REQUESTED:
	val = ent->hot_swap_ind_req_deact;
	if (ent->hot_swap_deact_timeout != IPMI_TIMEOUT_FOREVER) {
	    /* Need to time the operation. */
	    struct timeval timeout;

	    timeout.tv_sec = ent->hot_swap_deact_timeout / 1000000000;
	    timeout.tv_usec = ((ent->hot_swap_deact_timeout % 1000000000)
			       / 1000);
	    ipmi_lock(ent->timer_lock);
	    if (!ent->hot_swap_deact_timer_running) {
		ent->os_hnd->start_timer(ent->os_hnd,
					 ent->hot_swap_deact_timer,
					 &timeout,
					 hot_swap_deact_timeout,
					 ent);
		ent->hot_swap_deact_timer_running = 1;
		ent->running_timer_count++;
	    }
	    ipmi_unlock(ent->timer_lock);
	}
	break;

    case IPMI_HOT_SWAP_DEACTIVATION_IN_PROGRESS:
    case IPMI_HOT_SWAP_NOT_PRESENT:
    case IPMI_HOT_SWAP_OUT_OF_CON:
    default:
	set = 0;
	break;
    }

    if (set && ent->hot_swap_indicator) {
	int rv;

	rv = ipmi_control_set_val(ent->hot_swap_indicator, &val,
				  indicator_change, NULL);
	if (rv)
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%sentity.c(set_hot_swap_state): Unable to"
		     " set control value to %d, error %x",
		     CONTROL_NAME(ent->hot_swap_indicator),
		     val, rv);
    }

    if (old_state != state) {
	ent->hot_swap_state = state;
	ipmi_entity_call_hot_swap_handlers(ent, old_state, state, &event,
					   &handled);
    }

    return handled;
}

static int
hot_swap_requester_changed(ipmi_sensor_t         *sensor,
			   enum ipmi_event_dir_e dir,
			   int                   offset,
			   int                   severity,
			   int                   prev_severity,
			   void                  *cb_data,
			   ipmi_event_t          *event)
{
    ipmi_entity_t *ent = cb_data;
    int           handled = IPMI_EVENT_NOT_HANDLED;

    if (offset != ent->hot_swap_offset)
	goto out;

    if (ent->hot_swap_requesting_val && (dir == IPMI_ASSERTION)) {
	/* A hot-swap is being requested */
	switch (ent->hot_swap_state)
	{
	case IPMI_HOT_SWAP_ACTIVE:
	    handled = set_hot_swap_state
		(ent, IPMI_HOT_SWAP_DEACTIVATION_REQUESTED, event);
	    break;

	case IPMI_HOT_SWAP_ACTIVATION_REQUESTED:
	    handled = set_hot_swap_state
		(ent, IPMI_HOT_SWAP_INACTIVE, event);
	    break;

	case IPMI_HOT_SWAP_ACTIVATION_IN_PROGRESS:
	    handled = set_hot_swap_state
		(ent, IPMI_HOT_SWAP_DEACTIVATION_IN_PROGRESS, event);
	    break;

	case IPMI_HOT_SWAP_DEACTIVATION_REQUESTED:
	case IPMI_HOT_SWAP_DEACTIVATION_IN_PROGRESS:
	case IPMI_HOT_SWAP_OUT_OF_CON:
	case IPMI_HOT_SWAP_INACTIVE:
	case IPMI_HOT_SWAP_NOT_PRESENT:
	default:
	    break;
	}
    } else {
	/* A hot-swap is being derequested */
	switch (ent->hot_swap_state)
	{
	case IPMI_HOT_SWAP_DEACTIVATION_REQUESTED:
	    handled = set_hot_swap_state
		(ent, IPMI_HOT_SWAP_ACTIVE, event);
	    break;

	case IPMI_HOT_SWAP_INACTIVE:
	    handled = set_hot_swap_state
		(ent, IPMI_HOT_SWAP_ACTIVATION_REQUESTED, event);
	    break;

	case IPMI_HOT_SWAP_ACTIVATION_REQUESTED:
	case IPMI_HOT_SWAP_ACTIVATION_IN_PROGRESS:
	case IPMI_HOT_SWAP_ACTIVE:
	case IPMI_HOT_SWAP_DEACTIVATION_IN_PROGRESS:
	case IPMI_HOT_SWAP_OUT_OF_CON:
	case IPMI_HOT_SWAP_NOT_PRESENT:
	default:
	    break;
	}
    }

 out:
    return 0;
}

static void power_checked(ipmi_control_t *control,
			  int            err,
			  int            *val,
			  void           *cb_data);

static int
hot_swap_power_changed(ipmi_control_t *control,
		       int            *valid_vals,
		       int            *vals,
		       void           *cb_data,
		       ipmi_event_t   *event)
{
    ipmi_entity_t *ent = cb_data;
    int           handled = IPMI_EVENT_NOT_HANDLED;

    if (!valid_vals[0])
	return IPMI_EVENT_NOT_HANDLED;

    if (ent->present)
	power_checked(control, 0, vals, ent);
    
    return handled;
}

static void
handle_new_hot_swap_indicator(ipmi_entity_t *ent, ipmi_control_t *control)
{
    int val = 0;
    int rv;

    ipmi_control_is_hot_swap_indicator(control,
				       &ent->hot_swap_ind_req_act,
				       &ent->hot_swap_ind_act,
				       &ent->hot_swap_ind_req_deact,
				       &ent->hot_swap_ind_inact);

    ent->hot_swap_indicator = control;
    switch (ent->hot_swap_state)
    {
    case IPMI_HOT_SWAP_INACTIVE:
	val = ent->hot_swap_ind_inact;
	break;

    case IPMI_HOT_SWAP_ACTIVATION_REQUESTED:
	val = ent->hot_swap_ind_req_act;
	break;

    case IPMI_HOT_SWAP_ACTIVATION_IN_PROGRESS:
    case IPMI_HOT_SWAP_ACTIVE:
	val = ent->hot_swap_ind_act;
	break;

    case IPMI_HOT_SWAP_DEACTIVATION_REQUESTED:
    case IPMI_HOT_SWAP_DEACTIVATION_IN_PROGRESS:
	val = ent->hot_swap_ind_req_deact;
	break;

    default:
	val = ent->hot_swap_ind_inact;
	break;
    }
	
    rv = ipmi_control_set_val(control, &val, NULL, NULL);
    if (rv)
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sentity.c(handle_new_hot_swap_indicator): Unable to"
		 " set control value, error %x",
		 CONTROL_NAME(control), rv);
}

static void
requester_checked(ipmi_sensor_t *sensor,
		  int           err,
		  ipmi_states_t *states,
		  void          *cb_data)
{
    ipmi_entity_t *ent = cb_data;

    if (err) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sentity.c(requester_chedked): Unable to"
		 " get requester value, error %x",
		 SENSOR_NAME(sensor), err);
	return;
    }

    if (ipmi_is_state_set(states, ent->hot_swap_offset)
	== ent->hot_swap_requesting_val)
    {
	/* requester is requesting, change the state. */
	if (ent->hot_swap_state == IPMI_HOT_SWAP_ACTIVE)
	    set_hot_swap_state(ent, IPMI_HOT_SWAP_DEACTIVATION_REQUESTED,
			       NULL);
    } else {
	if (ent->hot_swap_state == IPMI_HOT_SWAP_INACTIVE)
	    set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVATION_REQUESTED,
			       NULL);
    }
}

static void
power_checked(ipmi_control_t *control,
	      int            err,
	      int            *val,
	      void           *cb_data)
{
    int           rv;
    ipmi_entity_t *ent = cb_data;

    if (err) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sentity.c(power_checked): Unable to"
		 " get power value, error %x",
		 CONTROL_NAME(control), err);
	return;
    }

    if (val[0])
	set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVE, NULL);
    else
	set_hot_swap_state(ent, IPMI_HOT_SWAP_INACTIVE, NULL);

    if (ent->hot_swap_requester) {
	rv = ipmi_states_get(ent->hot_swap_requester,
			     requester_checked,
			     ent);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%sentity.c(power_checked): Unable to"
		     " request requester status, error %x",
		     SENSOR_NAME(ent->hot_swap_requester), rv);
	}
    }
}

static void
handle_new_hot_swap_power(ipmi_entity_t *ent, ipmi_control_t *control)
{
    int rv;
  
    /* Add our own event handler. */
    rv = ipmi_control_add_val_event_handler(control,
					    hot_swap_power_changed,
					    ent);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sentity.c(handle_new_hot_swap_power): Unable to"
		 " add an event handler, error %x",
		 CONTROL_NAME(control), rv);
	return;
    }

    ent->hot_swap_power = control;

    if (ent->hot_swappable) {
	rv = ipmi_control_get_val(ent->hot_swap_power, power_checked,
				  ent);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%sentity.c(handle_new_hot_swap_power): Unable to"
		     " request power status, error %x",
		     CONTROL_NAME(ent->hot_swap_power), rv);
	}
    }
}

static void
handle_new_hot_swap_requester(ipmi_entity_t *ent, ipmi_sensor_t *sensor)
{
    ipmi_event_state_t events;
    int                event_support;
    int                rv;
    int                val;

    ipmi_sensor_is_hot_swap_requester(sensor,
				      &ent->hot_swap_offset,
				      &ent->hot_swap_requesting_val);

    event_support = ipmi_sensor_get_event_support(sensor);

    /* Add our own event handler. */
    rv = ipmi_sensor_add_discrete_event_handler(sensor,
						hot_swap_requester_changed,
						ent);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sentity.c(handle_new_hot_swap_requester): Unable to"
		 " add an event handler, error %x",
		 SENSOR_NAME(sensor), rv);
	return;
    }

    ent->hot_swap_requester = sensor;

    /* Nothing to do, events will just be on. */
    if (event_support == IPMI_EVENT_SUPPORT_GLOBAL_ENABLE)
	goto out;

    /* Turn events and scanning on. */
    ipmi_event_state_init(&events);
    ipmi_event_state_set_events_enabled(&events, 1);
    ipmi_event_state_set_scanning_enabled(&events, 1);

    if (event_support == IPMI_EVENT_SUPPORT_PER_STATE) {
	/* Turn on all the event enables that we can. */
	rv = ipmi_sensor_discrete_assertion_event_supported
	    (sensor,
	     ent->hot_swap_offset,
	     &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, ent->hot_swap_offset,
				    IPMI_ASSERTION);
	rv = ipmi_sensor_discrete_deassertion_event_supported
	    (sensor,
	     ent->hot_swap_offset,
	     &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, ent->hot_swap_offset,
				    IPMI_DEASSERTION);
    }

    ipmi_sensor_events_enable_set(sensor, &events, NULL, NULL);

    if (ent->hot_swappable) {
	rv = ipmi_states_get(ent->hot_swap_requester,
			     requester_checked,
			     ent);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%sentity.c(handle_new_hot_swap_requester): Unable to"
		     " request requester status, error %x",
		     SENSOR_NAME(ent->hot_swap_requester), rv);
	}
    }

 out:
    return;
}

static int
handle_hot_swap_presence(ipmi_entity_t  *ent,
			 int            present,
			 ipmi_event_t   *event)
{
    int handled = IPMI_EVENT_NOT_HANDLED;
    int rv;

    if (present) {
	if ((!ent->hot_swap_power)
	    || (hot_swap_act_timeout == IPMI_TIMEOUT_NOW))
	{
	    /* No power control or immediate timeout, it goes straight
	       to active. */
	    handled = set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVE, event);
	} else {
	    rv = ipmi_control_get_val(ent->hot_swap_power, power_checked,
				      ent);
	    if (rv) {
		ipmi_log(IPMI_LOG_SEVERE,
			 "%sentity.c(handle_hot_swap_presence): Unable to"
			 " request power status, error %x",
			 CONTROL_NAME(ent->hot_swap_power), rv);
	    }
	}
    } else {
	handled = set_hot_swap_state(ent, IPMI_HOT_SWAP_NOT_PRESENT, event);
    }

    return handled;
}

static int
e_get_hot_swap_state(ipmi_entity_t                 *ent,
		     ipmi_entity_hot_swap_state_cb handler,
		     void                          *cb_data)
{
    if (handler)
	handler(ent, 0, ent->hot_swap_state, cb_data);
    return 0;
}

static int
e_set_auto_activate(ipmi_entity_t  *ent,
		    ipmi_timeout_t auto_act,
		    ipmi_entity_cb done,
		    void           *cb_data)
{
    if (!ent->hot_swap_power)
	return ENOSYS;

    ent->hot_swap_act_timeout = auto_act;

    if (done)
	done(ent, 0, cb_data);

    return 0;
}

static int
e_get_auto_activate(ipmi_entity_t       *ent,
		    ipmi_entity_time_cb handler,
		    void                *cb_data)
{
    if (!ent->hot_swap_power)
	return ENOSYS;

    if (handler)
	handler(ent, 0, ent->hot_swap_act_timeout, cb_data);

    return 0;
}

static int
e_set_auto_deactivate(ipmi_entity_t  *ent,
		      ipmi_timeout_t auto_act,
		      ipmi_entity_cb done,
		      void           *cb_data)
{
    if (!ent->hot_swap_power)
	return ENOSYS;


    ent->hot_swap_deact_timeout = auto_act;

    if (done)
	done(ent, 0, cb_data);

    return 0;
}

static int
e_get_auto_deactivate(ipmi_entity_t       *ent,
		      ipmi_entity_time_cb handler,
		      void                *cb_data)
{
    if (!ent->hot_swap_power)
	return ENOSYS;

    if (handler)
	handler(ent, 0, ent->hot_swap_deact_timeout, cb_data);

    return 0;
}

static int
e_activate(ipmi_entity_t  *ent,
	   ipmi_entity_cb done,
	   void           *cb_data)
{
    return hot_swap_act(ent, done, cb_data);
}

static int
e_deactivate(ipmi_entity_t  *ent,
	     ipmi_entity_cb done,
	     void           *cb_data)
{
    return hot_swap_deact(ent, done, cb_data);
}

typedef struct get_hot_swap_info_s
{
    ipmi_entity_t      *ent;
    ipmi_entity_val_cb handler;
    void               *cb_data;
} get_hot_swap_info_t;

static void got_hot_swap_ind(ipmi_control_t *control,
			     int            err,
			     int            *cbval,
			     void           *cb_data)
{
    get_hot_swap_info_t *info = cb_data;
    int                 val = 0;

    if (!err)
	val = *cbval;

    info->handler(info->ent, err, val, info->cb_data);
    ipmi_mem_free(info);
}

static int
e_get_hot_swap_indicator(ipmi_entity_t      *ent,
			 ipmi_entity_val_cb handler,
			 void               *cb_data)
{
    get_hot_swap_info_t *info;
    int                 rv;

    if (! ent->hot_swap_indicator)
	return ENOSYS;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->ent = ent;
    info->handler = handler;
    info->cb_data = cb_data;
    rv = ipmi_control_get_val(ent->hot_swap_indicator,
			      got_hot_swap_ind, &info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

typedef struct set_hot_swap_ind_info_s
{
    ipmi_entity_t  *ent;
    ipmi_entity_cb handler;
    void           *cb_data;
} set_hot_swap_ind_info_t;

static void set_hot_swap_ind(ipmi_control_t *control,
			     int            err,
			     void           *cb_data)
{
    set_hot_swap_ind_info_t *info = cb_data;

    info->handler(info->ent, err, info->cb_data);
    ipmi_mem_free(info);
}

static int
e_set_hot_swap_indicator(ipmi_entity_t  *ent,
			 int            val,
			 ipmi_entity_cb done,
			 void           *cb_data)
{
    set_hot_swap_ind_info_t *info;
    int                     rv;

    if (! ent->hot_swap_indicator)
	return ENOSYS;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->ent = ent;
    info->handler = done;
    info->cb_data = cb_data;
    rv = ipmi_control_set_val(ent->hot_swap_indicator, &val,
			      set_hot_swap_ind, &info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

static void
got_hot_swap_req(ipmi_sensor_t *sensor,
		 int           err,
		 ipmi_states_t *states,
		 void          *cb_data)
{
    get_hot_swap_info_t *info = cb_data;
    int                 val = 0;

    if (!err) {
	if (ipmi_is_state_set(states, info->ent->hot_swap_offset)
	    == info->ent->hot_swap_requesting_val)
	{
	    val = 1;
	}
    }
    info->handler(info->ent, err, val, info->cb_data);
    ipmi_mem_free(info);
}

static int
e_get_hot_swap_requester(ipmi_entity_t      *ent,
			 ipmi_entity_val_cb handler,
			 void               *cb_data)
{
    get_hot_swap_info_t *info;
    int                 rv;

    if (! ent->hot_swap_requester)
	return ENOSYS;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->ent = ent;
    info->handler = handler;
    info->cb_data = cb_data;
    rv = ipmi_states_get(ent->hot_swap_requester,
			 got_hot_swap_req, &info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

typedef struct hs_check_s
{
    int           power;
    ipmi_entity_t *entity;
} hs_check_t;

static void
check_requester(ipmi_sensor_t *sensor,
		int           err,
		ipmi_states_t *states,
		void          *cb_data)
{
    hs_check_t    *info = cb_data;
    ipmi_entity_t *ent = info->entity;

    if (err) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sentity.c(requester_checked): Unable to"
		 " get requester value, error %x",
		 SENSOR_NAME(sensor), err);
	goto out;
    }

    if (ipmi_is_state_set(states, ent->hot_swap_offset)
	== ent->hot_swap_requesting_val)
    {
	/* requester is requesting, change the state. */
	if (info->power)
	    set_hot_swap_state(ent, IPMI_HOT_SWAP_DEACTIVATION_REQUESTED,
			       NULL);
	else
	    set_hot_swap_state(ent, IPMI_HOT_SWAP_INACTIVE, NULL);
    } else {
	if (info->power)
	    set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVE, NULL);
	else
	    set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVATION_REQUESTED,
			       NULL);
    }

 out:
    ipmi_mem_free(info);
}

static void
check_power(ipmi_control_t *control,
	    int            err,
	    int            *val,
	    void           *cb_data)
{
    int           rv;
    hs_check_t    *info = cb_data;
    ipmi_entity_t *ent = info->entity;

    if (err) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sentity.c(power_chedked): Unable to"
		 " get power value, error %x",
		 CONTROL_NAME(control), err);
	ipmi_mem_free(info);
	return;
    }

    info->power = val[0];

    if (ent->hot_swap_requester) {
	rv = ipmi_states_get(ent->hot_swap_requester,
			     check_requester,
			     info);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%sentity.c(power_checked): Unable to"
		     " request requester status, error %x",
		     SENSOR_NAME(ent->hot_swap_requester), rv);
	    ipmi_mem_free(info);
	}
    } else {
	if (info->power)
	    set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVE, NULL);
	else
	    set_hot_swap_state(ent, IPMI_HOT_SWAP_INACTIVE, NULL);
	ipmi_mem_free(info);
    }
}

static int
e_check_hot_swap_state(ipmi_entity_t *ent)
{
    hs_check_t *info;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->entity = ent;
    info->power = 1; /* Assume power is on if no power control. */

    if (ent->hot_swap_power)
	ipmi_control_get_val(ent->hot_swap_power, check_power, info);
    else if (ent->hot_swap_requester)
	ipmi_states_get(ent->hot_swap_requester, check_requester, info);
    else
	ipmi_mem_free(info);

    return 0;
}

/***********************************************************************
 *
 * Entity message handling.
 *
 **********************************************************************/

static void
entity_opq_ready2(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_entity_op_info_t *info = cb_data;
    if (info->__handler)
	info->__handler(entity, 0, info->__cb_data);
}

static void
entity_opq_ready(void *cb_data, int shutdown)
{
    ipmi_entity_op_info_t *info = cb_data;
    int                   rv;

    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sentity.c(entity_opq_ready): "
		 "Entity was destroyed while an operation was in progress",
		 ENTITY_NAME(info->__entity));
	if (info->__handler)
	    info->__handler(info->__entity, ECANCELED, info->__cb_data);
	return;
    }

    rv = ipmi_entity_pointer_cb(info->__entity_id, entity_opq_ready2, info);
    if (rv)
	if (info->__handler)
	    info->__handler(info->__entity, rv, info->__cb_data);
}

int
ipmi_entity_add_opq(ipmi_entity_t         *entity,
		    ipmi_entity_cb        handler,
		    ipmi_entity_op_info_t *info,
		    void                  *cb_data)
{
    info->__entity = entity;
    info->__entity_id = ipmi_entity_convert_to_id(entity);
    info->__cb_data = cb_data;
    info->__handler = handler;
    if (!opq_new_op(entity->waitq, entity_opq_ready, info, 0))
	return ENOMEM;
    return 0;
}

void
ipmi_entity_opq_done(ipmi_entity_t *entity)
{
    /* Protect myself from NULL entitys.  This way, it doesn't have to
       be done in each call. */
    if (!entity)
	return;

    CHECK_ENTITY_LOCK(entity);

    opq_op_done(entity->waitq);
}

static void
entity_rsp_handler2(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_entity_op_info_t *info = cb_data;

    if (info->__rsp_handler)
	info->__rsp_handler(entity, 0, info->__rsp, info->__cb_data);
}

static void
entity_rsp_handler(ipmi_mc_t  *mc,
		   ipmi_msg_t *rsp,
		   void       *rsp_data)
{
    ipmi_entity_op_info_t *info = rsp_data;
    int                    rv;
    ipmi_entity_t          *entity = info->__entity;

    if (entity->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sentity.c(entity_rsp_handler): "
		 "Entity was destroyed while an operation was in progress",
		 ENTITY_NAME(entity));
	if (info->__rsp_handler)
	    info->__rsp_handler(entity, ECANCELED, NULL, info->__cb_data);
	entity_final_destroy(entity);
	return;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "entity.c(entity_rsp_handler): "
		 "MC was destroyed while a entity operation was in progress");
	if (info->__rsp_handler)
	    info->__rsp_handler(entity, ECANCELED, NULL, info->__cb_data);
	return;
    }

    /* Call the next stage with the lock held. */
    info->__rsp = rsp;
    rv = ipmi_entity_pointer_cb(info->__entity_id,
				 entity_rsp_handler2,
				 info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sentity.c(entity_rsp_handler): "
		 "Could not convert entity id to a pointer",
		 MC_NAME(mc));
	if (info->__rsp_handler)
	    info->__rsp_handler(NULL, rv, NULL, info->__cb_data);
    }
}

static void
send_command_mc_cb(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_entity_op_info_t *info = cb_data;

    info->__err = ipmi_mc_send_command(mc, info->__lun, info->__msg,
				       entity_rsp_handler, info);
}

int
ipmi_entity_send_command(ipmi_entity_t         *entity,
			 ipmi_mcid_t           mcid,
			 unsigned int          lun,
			 ipmi_msg_t            *msg,
			 ipmi_entity_rsp_cb    handler,
			 ipmi_entity_op_info_t *info,
			 void                  *cb_data)
{
    int rv;

    CHECK_ENTITY_LOCK(entity);

    info->__entity = entity;
    info->__entity_id = ipmi_entity_convert_to_id(entity);
    info->__cb_data = cb_data;
    info->__rsp_handler = handler;
    info->__err = 0;
    info->__msg = msg;
    info->__lun = lun;
    rv = ipmi_mc_pointer_cb(mcid, send_command_mc_cb, info);
    if (!rv)
	rv = info->__err;
    return rv;
}

