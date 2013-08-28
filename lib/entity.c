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
#include <stdlib.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_bits.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_sdr.h>

#include <OpenIPMI/internal/ipmi_mc.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/ipmi_entity.h>
#include <OpenIPMI/internal/locked_list.h>
#include <OpenIPMI/internal/ipmi_utils.h>
#include <OpenIPMI/internal/ipmi_control.h>
#include <OpenIPMI/internal/ipmi_sensor.h>

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

typedef struct ent_timer_info_s
{
    ipmi_lock_t       *lock;
    ipmi_entity_t     *entity;
    os_hnd_timer_id_t *timer;
    int               destroyed;
    int               running;
    os_handler_t      *os_hnd;
} ent_timer_info_t;

struct ipmi_entity_s
{
    ipmi_domain_t    *domain;
    ipmi_domain_id_t domain_id;
    long             seq;

    dlr_ref_t key;

    /* Lock used for protecting misc data. */
    ipmi_lock_t *elock;

    int usecount;

    /* Used to tell that the entity destroy is being reported to the
       user. */
    int destroyed;

    /* After the entity is added, it will not be reported immediately.
       Instead, it will wait until the usecount goes to zero before
       being reported.  This marks that the add report is pending */
    int add_pending;

    /* My domain's os handler. */
    os_handler_t *os_hnd;

    /* Info from the DLR. */
    dlr_info_t info;

    /* We don't install DLR info while the entity is in use, we hold
       it here until the usecount goes to zero. */
    dlr_info_t pending_info;
    int pending_info_ready;

    /* If the entity has changed and needs to be reported when the
       entity is no longer in use, mark it here. */
    int changed;

    /* Number of users of this entity (not including sensors, this is
       mainly for other SDRs that reference this entity). */
    unsigned int ref_count;

    locked_list_t *child_entities;
    locked_list_t *parent_entities;

    locked_list_t *sensors;
    locked_list_t *controls;

    const char *entity_id_string;

    /* A standard presence sensor.  This one overrides everything. */
    ipmi_sensor_t    *presence_sensor;
    ipmi_sensor_id_t presence_sensor_id;

    /* A discrete sensor where one of the bits is used for presence.
       If one of these exists, it will be used unless there is a
       presence sensor. */
    ipmi_sensor_t    *presence_bit_sensor;
    ipmi_sensor_id_t presence_bit_sensor_id;
    int              presence_bit_offset;

    int           present;
    int           presence_possibly_changed;
    unsigned int  presence_event_count; /* Changed when presence
					   events are reported. */
    /* Only allow one presence check at a time. */
    int           in_presence_check;

    /* If the presence changes while the entity is in use, we store it
       in here and the count instead of actually changing it.  Then we
       fix it up when the entity is set not in use. */
    int           curr_present;
    int           present_change_count;

    /* Physical slot number info */
    unsigned int slot_num;
    int slot_num_present;

    /* Hot-swap timing. */
    ent_timer_info_t *hot_swap_act_info;
    ipmi_timeout_t    hot_swap_act_timeout;

    ent_timer_info_t *hot_swap_deact_info;
    ipmi_timeout_t    hot_swap_deact_timeout;


    /* Hot-swap sensors/controls */
    ipmi_sensor_t    *hot_swap_requester;
    ipmi_sensor_id_t hot_swap_requester_id;
    int              hot_swap_offset;
    int              hot_swap_requesting_val;
    enum ipmi_hot_swap_states hot_swap_state;
    ipmi_control_t    *hot_swap_power;
    ipmi_control_id_t hot_swap_power_id;
    ipmi_control_t    *hot_swap_indicator;
    ipmi_control_id_t hot_swap_indicator_id;
    int            hot_swap_ind_act;
    int            hot_swap_ind_req_act;
    int            hot_swap_ind_req_deact;
    int            hot_swap_ind_inact;

    /* A handler for hot-swap. */
    locked_list_t *hot_swap_handlers, *hot_swap_handlers_cl;

    ipmi_entity_info_t *ents;

    ipmi_fru_t   *fru;

    int                    hot_swappable;
    int                    supports_managed_hot_swap;
    ipmi_entity_hot_swap_t hs_cb;

    /* Callbacks for various events on an entity. */
    locked_list_t *fru_handlers, *fru_handlers_cl;
    locked_list_t *sensor_handlers, *sensor_handlers_cl;
    locked_list_t *control_handlers, *control_handlers_cl;
    locked_list_t *presence_handlers, *presence_handlers_cl;
    locked_list_t *fully_up_handlers, *fully_up_handlers_cl;

    /* Used for SDR output (not currently supported). */
    entity_sdr_add_cb  sdr_gen_output;
    void               *sdr_gen_cb_data;

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

    /* Name we use for reporting.  We add a ' ' onto the end, thus
       the +1. */
    char name[IPMI_ENTITY_NAME_LEN+1];


    /* Cruft */
    ipmi_entity_presence_nd_cb cruft_presence_handler;
    void                       *cruft_presence_cb_data;

    ipmi_entity_sensor_cb cruft_sensor_handler;
    void                  *cruft_sensor_cb_data;

    ipmi_entity_control_cb cruft_control_handler;
    void                   *cruft_control_cb_data;

    ipmi_entity_fru_cb cruft_fru_handler;
    void               *cruft_fru_cb_data;
};

struct ipmi_entity_info_s
{
    locked_list_t         *update_handlers;
    locked_list_t         *update_cl_handlers;
    ipmi_domain_t         *domain;
    ipmi_domain_id_t      domain_id;
    locked_list_t         *entities;
};

#define ent_lock(e) ipmi_lock(e->elock)
#define ent_unlock(e) ipmi_unlock(e->elock)

static void entity_mc_active(ipmi_mc_t *mc, int active, void *cb_data);
static void call_presence_handlers(ipmi_entity_t *ent, int present);
static void call_fully_up_handlers(ipmi_entity_t *ent);

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
 * Entity iteration helpers
 *
 **********************************************************************/
static void
entities_lock(void *cb_data)
{
    ipmi_domain_t *domain = cb_data;
    _ipmi_domain_entity_lock(domain);
}

static void
entities_unlock(void *cb_data)
{
    ipmi_domain_t *domain = cb_data;
    _ipmi_domain_entity_unlock(domain);
}

static int
iterate_entity_prefunc(void *cb_data, void *item1, void *item2)
{
    ipmi_entity_t *ent = item1;

    _ipmi_entity_get(ent);
    return LOCKED_LIST_ITER_CONTINUE;
}

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
    ents->entities = locked_list_alloc_my_lock(entities_lock,
					       entities_unlock,
					       domain);
    if (! ents->entities) {
	ipmi_mem_free(ents);
	return ENOMEM;
    }

    ents->update_handlers = locked_list_alloc(ipmi_domain_get_os_hnd(domain));
    if (! ents->update_handlers) {
	locked_list_destroy(ents->entities);
	ipmi_mem_free(ents);
	return ENOMEM;
    }

    ents->update_cl_handlers
	= locked_list_alloc(ipmi_domain_get_os_hnd(domain));
    if (! ents->update_cl_handlers) {
	locked_list_destroy(ents->update_handlers);
	locked_list_destroy(ents->entities);
	ipmi_mem_free(ents);
	return ENOMEM;
    }

    *new_info = ents;

    return 0;
}

static void
entity_start_timer(ent_timer_info_t *info,
		   ipmi_timeout_t   timeout,
		   os_timed_out_t   handler)
{
    /* Need to time the operation. */
    struct timeval tv;

    if (timeout == IPMI_TIMEOUT_FOREVER)
	return;

    tv.tv_sec = timeout / 1000000000;
    tv.tv_usec = (timeout % 1000000000) / 1000;
    ipmi_lock(info->lock);
    if (!info->running) {
	info->os_hnd->start_timer(info->os_hnd,
				  info->timer,
				  &tv,
				  handler,
				  info);
	info->running = 1;
    }
    ipmi_unlock(info->lock);
}

static int
entity_alloc_timer(ipmi_entity_t    *entity,
		   ent_timer_info_t **rinfo)
{
    ent_timer_info_t *info;
    int              rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));

    info->os_hnd = entity->os_hnd;
    info->entity = entity;

    rv = info->os_hnd->alloc_timer(info->os_hnd, &info->timer);
    if (rv) {
	ipmi_mem_free(info);
	return rv;
    }

    rv = ipmi_create_lock(entity->domain, &info->lock);
    if (rv) {
	info->os_hnd->free_timer(info->os_hnd, info->timer);
	ipmi_mem_free(info);
	return rv;
    }

    *rinfo = info;

    return 0;
}

static void
entity_destroy_timer(ent_timer_info_t *info)
{
    int rv;

    ipmi_lock(info->lock);
    if (info->running) {
	rv = info->os_hnd->stop_timer(info->os_hnd, info->timer);
	if (!rv) {
	    info->destroyed = 1;
	    ipmi_unlock(info->lock);
	    return;
	}
    }
    ipmi_unlock(info->lock);
    info->os_hnd->free_timer(info->os_hnd, info->timer);
    ipmi_destroy_lock(info->lock);
    ipmi_mem_free(info);
}

typedef struct hot_swap_cl_info_s
{
    ipmi_entity_hot_swap_cb handler;
    void                    *handler_data;
} hot_swap_cl_info_t;

static int
iterate_hot_swap_cl(void *cb_data, void *item1, void *item2)
{
    hot_swap_cl_info_t  *info = cb_data;
    ipmi_entity_hot_swap_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
hot_swap_cleanup(void *cb_data, void *item1, void *item2)
{
    ipmi_entity_t *ent = cb_data;
    hot_swap_cl_info_t info;

    info.handler = item1;
    info.handler_data = item2;
    locked_list_iterate(ent->hot_swap_handlers_cl, iterate_hot_swap_cl, &info);
    return LOCKED_LIST_ITER_CONTINUE;
}

typedef struct presence_cl_info_s
{
    ipmi_entity_presence_change_cb handler;
    void                           *handler_data;
} presence_cl_info_t;

static int
iterate_presence_cl(void *cb_data, void *item1, void *item2)
{
    presence_cl_info_t  *info = cb_data;
    ipmi_entity_presence_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
presence_cleanup(void *cb_data, void *item1, void *item2)
{
    ipmi_entity_t *ent = cb_data;
    presence_cl_info_t info;

    info.handler = item1;
    info.handler_data = item2;
    locked_list_iterate(ent->presence_handlers_cl, iterate_presence_cl, &info);
    return LOCKED_LIST_ITER_CONTINUE;
}

typedef struct fully_up_cl_info_s
{
    ipmi_entity_ptr_cb handler;
    void               *handler_data;
} fully_up_cl_info_t;

static int
iterate_fully_up_cl(void *cb_data, void *item1, void *item2)
{
    fully_up_cl_info_t  *info = cb_data;
    ipmi_entity_fully_up_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
fully_up_cleanup(void *cb_data, void *item1, void *item2)
{
    ipmi_entity_t *ent = cb_data;
    fully_up_cl_info_t info;

    info.handler = item1;
    info.handler_data = item2;
    locked_list_iterate(ent->fully_up_handlers_cl, iterate_fully_up_cl, &info);
    return LOCKED_LIST_ITER_CONTINUE;
}

typedef struct fru_cl_info_s
{
    ipmi_entity_fru_cb handler;
    void                    *handler_data;
} fru_cl_info_t;

static int
iterate_fru_cl(void *cb_data, void *item1, void *item2)
{
    fru_cl_info_t  *info = cb_data;
    ipmi_entity_fru_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
fru_cleanup(void *cb_data, void *item1, void *item2)
{
    ipmi_entity_t *ent = cb_data;
    fru_cl_info_t info;

    info.handler = item1;
    info.handler_data = item2;
    locked_list_iterate(ent->fru_handlers_cl, iterate_fru_cl, &info);
    return LOCKED_LIST_ITER_CONTINUE;
}

typedef struct control_cl_info_s
{
    ipmi_entity_control_cb handler;
    void                    *handler_data;
} control_cl_info_t;

static int
iterate_control_cl(void *cb_data, void *item1, void *item2)
{
    control_cl_info_t  *info = cb_data;
    ipmi_entity_control_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
control_cleanup(void *cb_data, void *item1, void *item2)
{
    ipmi_entity_t *ent = cb_data;
    control_cl_info_t info;

    info.handler = item1;
    info.handler_data = item2;
    locked_list_iterate(ent->control_handlers_cl, iterate_control_cl, &info);
    return LOCKED_LIST_ITER_CONTINUE;
}

typedef struct sensor_cl_info_s
{
    ipmi_entity_sensor_cb handler;
    void                    *handler_data;
} sensor_cl_info_t;

static int
iterate_sensor_cl(void *cb_data, void *item1, void *item2)
{
    sensor_cl_info_t  *info = cb_data;
    ipmi_entity_sensor_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
sensor_cleanup(void *cb_data, void *item1, void *item2)
{
    ipmi_entity_t *ent = cb_data;
    sensor_cl_info_t info;

    info.handler = item1;
    info.handler_data = item2;
    locked_list_iterate(ent->sensor_handlers_cl, iterate_sensor_cl, &info);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
destroy_entity(void *cb_data, void *item1, void *item2)
{
    ipmi_entity_t *ent = (ipmi_entity_t *) item1;

    entity_destroy_timer(ent->hot_swap_act_info);
    entity_destroy_timer(ent->hot_swap_deact_info);

    if (ent->frudev_present) {
	_ipmi_domain_mc_lock(ent->domain);
	_ipmi_mc_get(ent->frudev_mc);
	_ipmi_domain_mc_unlock(ent->domain);
	ipmi_mc_remove_active_handler(ent->frudev_mc, entity_mc_active, ent);
	_ipmi_mc_release(ent->frudev_mc);
	_ipmi_mc_put(ent->frudev_mc);
    }

    if (ent->oem_info_cleanup_handler)
	ent->oem_info_cleanup_handler(ent, ent->oem_info);

    if (ent->fru)
	ipmi_fru_destroy_internal(ent->fru, NULL, NULL);

    if (ent->waitq)
	opq_destroy(ent->waitq);

    locked_list_destroy(ent->parent_entities);
    locked_list_destroy(ent->child_entities);
    locked_list_destroy(ent->sensors);
    locked_list_destroy(ent->controls);
    locked_list_iterate(ent->hot_swap_handlers, hot_swap_cleanup, ent);
    locked_list_destroy(ent->hot_swap_handlers);
    locked_list_destroy(ent->hot_swap_handlers_cl);
    locked_list_iterate(ent->presence_handlers, presence_cleanup, ent);
    locked_list_destroy(ent->presence_handlers);
    locked_list_destroy(ent->presence_handlers_cl);
    locked_list_iterate(ent->fully_up_handlers, fully_up_cleanup, ent);
    locked_list_destroy(ent->fully_up_handlers);
    locked_list_destroy(ent->fully_up_handlers_cl);
    locked_list_iterate(ent->fru_handlers, fru_cleanup, ent);
    locked_list_destroy(ent->fru_handlers);
    locked_list_destroy(ent->fru_handlers_cl);
    locked_list_iterate(ent->control_handlers, control_cleanup, ent);
    locked_list_destroy(ent->control_handlers);
    locked_list_destroy(ent->control_handlers_cl);
    locked_list_iterate(ent->sensor_handlers, sensor_cleanup, ent);
    locked_list_destroy(ent->sensor_handlers);
    locked_list_destroy(ent->sensor_handlers_cl);

    ipmi_destroy_lock(ent->elock);

    ipmi_mem_free(ent);

    return LOCKED_LIST_ITER_CONTINUE;
}

typedef struct entity_update_cl_info_s
{
    ipmi_domain_entity_cb handler;
    void                  *handler_data;
} entity_update_cl_info_t;


static int
iterate_entity_update_cl(void *cb_data, void *item1, void *item2)
{
    entity_update_cl_info_t  *info = cb_data;
    ipmi_domain_entity_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
entity_update_cleanup(void *cb_data, void *item1, void *item2)
{
    entity_update_cl_info_t info;
    ipmi_entity_info_t      *ents = cb_data;

    info.handler = item1;
    info.handler_data = item2;
    locked_list_iterate(ents->update_cl_handlers, iterate_entity_update_cl,
			&info);
    return LOCKED_LIST_ITER_CONTINUE;
}

int
ipmi_entity_info_destroy(ipmi_entity_info_t *ents)
{
    locked_list_iterate(ents->update_handlers, entity_update_cleanup, ents);
    locked_list_destroy(ents->update_handlers);
    locked_list_destroy(ents->update_cl_handlers);
    locked_list_iterate(ents->entities, destroy_entity, NULL);
    locked_list_destroy(ents->entities);
    ipmi_mem_free(ents);
    return 0;
}

typedef struct ent_info_update_handler_info_s
{
    enum ipmi_update_e op;
    ipmi_domain_t      *domain;
    ipmi_entity_t      *entity;
} ent_info_update_handler_info_t;

static int
call_entity_info_update_handler(void *cb_data, void *item1, void *item2)
{
    ent_info_update_handler_info_t *info = cb_data;
    ipmi_domain_entity_cb          handler = item1;

    handler(info->op, info->domain, info->entity, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_entity_update_handlers(ipmi_entity_t *ent, enum ipmi_update_e op)
{
    ent_info_update_handler_info_t info;

    info.op = op;
    info.entity = ent;
    info.domain = ent->domain;
    locked_list_iterate(ent->ents->update_handlers,
			call_entity_info_update_handler,
			&info);
}

/* Returns true if the entity was really deleted, false if not.  Must
   be called with the domain entity lock, unlocks it before return if
   it destroys the entity. */
static int
cleanup_entity(ipmi_entity_t *ent)
{
    /* First see if the entity is ready for cleanup. */
    if ((ent->ref_count)
	|| opq_stuff_in_progress(ent->waitq)
	|| (locked_list_num_entries_nolock(ent->child_entities) != 0)
	|| (locked_list_num_entries_nolock(ent->parent_entities) != 0)
	|| (locked_list_num_entries_nolock(ent->sensors) != 0)
	|| (locked_list_num_entries_nolock(ent->controls) != 0))
    {
	return 0;
    }

    ent->destroyed = 1;

    _ipmi_domain_entity_unlock(ent->domain);

    /* Tell the user I was destroyed. */
    /* Call the update handler list. */
    call_entity_update_handlers(ent, IPMI_DELETED);

    _ipmi_domain_entity_lock(ent->domain);

    if (ent->destroyed) {
	/* The entity could have been resurrected, so don't do this
	   unless it has remained destroyed. */

	/* Remove it from the entities list. */
	locked_list_remove_nolock(ent->ents->entities, ent, NULL);

	/* The sensor, control, parent, and child lists should be empty
	   now, we can just destroy it. */
	destroy_entity(NULL, ent, NULL);
	return 1;
    } else {
	return 0;
    }
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
    int length = sizeof(entity->name);

    ent_lock(entity);
    length = ipmi_domain_get_name(entity->domain, entity->name, length);
    entity->name[length] = '(';
    length++;
    if (entity->key.entity_instance >= 0x60) {
	length += snprintf(entity->name+length, IPMI_ENTITY_NAME_LEN-length-3,
			   "r%d.%d.%d.%d",
			   entity->key.device_num.channel,
			   entity->key.device_num.address,
			   entity->key.entity_id,
			   entity->key.entity_instance - 0x60);
    } else {
	length += snprintf(entity->name+length, IPMI_ENTITY_NAME_LEN-length-3,
			   "%d.%d", entity->key.entity_id,
			   entity->key.entity_instance);
    }
    entity->name[length] = ')';
    length++;
    entity->name[length] = ' ';
    length++;
    entity->name[length] = '\0';
    length++;
    ent_unlock(entity);
}

const char *
_ipmi_entity_name(const ipmi_entity_t *entity)
{
    return entity->name;
}

static void
entity_get_name_cb(ipmi_entity_t *entity, void *cb_data)
{
    char **name = cb_data;
    *name = entity->name;
}

const char *
_ipmi_entity_id_name(ipmi_entity_id_t entity_id)
{
    char *name = "";
    ipmi_entity_pointer_cb(entity_id, entity_get_name_cb, &name);
    return name;
}

int
ipmi_entity_get_name(ipmi_entity_t *ent, char *name, int length)
{
    int  slen;

    if (length <= 0)
	return 0;

    /* Never changes, no lock needed. */
    slen = strlen(ent->name);
    if (slen == 0) {
	if (name)
	    *name = '\0';
	goto out;
    }

    slen -= 1; /* Remove the trailing ' ' */
    if (slen >= length)
	slen = length - 1;

    if (name) {
	memcpy(name, ent->name, slen);
	name[slen] = '\0';
    }
 out:
    return slen;
}

/***********************************************************************
 *
 * Handling of adding/removing/searching entities, parents, and
 * children.
 *
 **********************************************************************/
static void
entity_report_fully_up(ipmi_entity_t *ent, void *cb_data)
{
    if (ent)
	call_fully_up_handlers(ent);
}

/* Must be called with the _ipmi_domain_entity_lock() held. */
int
_ipmi_entity_get(ipmi_entity_t *ent)
{
    ent->usecount++;
    return 0;
}

void
_ipmi_entity_put(ipmi_entity_t *ent)
{
    ipmi_domain_t      *domain = ent->domain;
    int                entity_fru_fetch = 0;
    ipmi_entity_ptr_cb report_present = NULL;
    int                rv;

    _ipmi_domain_entity_lock(domain);
 retry:
    if (ent->usecount == 1) {
	if (ent->pending_info_ready) {
            int was_fru = ipmi_entity_get_is_fru(ent);
	    ent->info = ent->pending_info;
            /* If the entity became a fru and is present, get its fru info. */
            if (!was_fru && ipmi_entity_get_is_fru(ent) && ent->present)
		entity_fru_fetch = 1;
	    entity_set_name(ent);
	    ent->pending_info_ready = 0;
	}

	if (ent->add_pending) {
	    ent->add_pending = 0;
	    ent->changed = 0;
	    _ipmi_domain_entity_unlock(domain);
	    call_entity_update_handlers(ent, IPMI_ADDED);
	    _ipmi_domain_entity_lock(domain);

	    /* Something grabbed the entity while the lock wasn't
	       held, don't attempt the cleanup. */
	    if (ent->usecount != 1)
		goto out;
	}

	/* If the entity has changed, report it to the user. */
	if (ent->changed) {
	    ent->changed = 0;
	    _ipmi_domain_entity_unlock(domain);
	    call_entity_update_handlers(ent, IPMI_CHANGED);
	    _ipmi_domain_entity_lock(domain);

	    /* Something grabbed the entity while the lock wasn't
	       held, don't attempt the cleanup. */
	    if (ent->usecount != 1)
		goto out;
	}

	if (ent->presence_possibly_changed) {
	    _ipmi_domain_entity_unlock(domain);
	    ipmi_detect_entity_presence_change(ent, 0);
	    _ipmi_domain_entity_lock(domain);

	    if (ent->usecount != 1)
		goto out;
	}

	while (ent->present_change_count) {
	    int present;
	    ent->present = !ent->present;
	    present = ent->present;
	    ent->present_change_count--;
	    _ipmi_domain_entity_unlock(domain);
	    call_presence_handlers(ent, present);
	    _ipmi_domain_entity_lock(domain);

            if (ipmi_entity_get_is_fru(ent) && ent->present)
		entity_fru_fetch = 1;

	    report_present = entity_report_fully_up;

	    /* Something grabbed the entity while the lock wasn't
	       held, don't attempt the cleanup. */
	    if (ent->usecount != 1)
		goto out;
	}

	if (cleanup_entity(ent))
	    goto out2;

    repend:
	if ((ent->add_pending)
	    || (ent->changed)
	    || (ent->present_change_count))
	{
	    /* Something happened to the entity while we were working,
	       retry the operation to report the new thing. */
	    goto retry;
	}
    }
 out:
    ent->usecount--;
    /* Wait till here to start fetching FRUs, as we want to report the
       entity first before we start the fetch. */
    if (ent->present && entity_fru_fetch) {
	entity_fru_fetch = 0;
	ent->usecount++;
	_ipmi_domain_entity_unlock(domain);
	rv = ipmi_entity_fetch_frus_cb(ent, report_present, NULL);
	if (rv && report_present)
	    report_present(ent, NULL);
	_ipmi_domain_entity_lock(domain);
	report_present = NULL;
	goto repend;
    } else if (!ent->destroyed && report_present) {
	ent->usecount++;
	_ipmi_domain_entity_unlock(domain);
	report_present(ent, NULL);
	_ipmi_domain_entity_lock(domain);
	report_present = NULL;
	goto repend;
    }
 out2:
    _ipmi_domain_entity_unlock(domain);
}

int
_ipmi_entity_add_ref(ipmi_entity_t *ent)
{
    ent_lock(ent);
    ent->ref_count++;
    ent_unlock(ent);
    return 0;
}

int
_ipmi_entity_remove_ref(ipmi_entity_t *ent)
{
    ent_lock(ent);
    ent->ref_count--;
    ent_unlock(ent);
    return 0;
}

int
ipmi_entity_info_add_update_handler(ipmi_entity_info_t    *ents,
				    ipmi_domain_entity_cb handler,
				    void                  *cb_data)
{
    if (locked_list_add(ents->update_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_info_remove_update_handler(ipmi_entity_info_t    *ents,
				       ipmi_domain_entity_cb handler,
				       void                  *cb_data)
{
    if (locked_list_remove(ents->update_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_entity_info_add_update_handler_cl(ipmi_entity_info_t       *ents,
				       ipmi_domain_entity_cl_cb handler,
				       void                     *cb_data)
{
    if (locked_list_add(ents->update_cl_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_info_remove_update_handler_cl(ipmi_entity_info_t       *ents,
					  ipmi_domain_entity_cl_cb handler,
					  void                     *cb_data)
{
    if (locked_list_remove(ents->update_cl_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

typedef struct search_info_s {
    dlr_ref_t         key;
    ipmi_entity_t     *ent;
} search_info_t;

static int
search_entity(void *cb_data, void *item1, void *item2)
{
    ipmi_entity_t *ent = (ipmi_entity_t *) item1;
    search_info_t *info = (search_info_t *) cb_data;
    int           same;

    same = ((ent->key.device_num.channel == info->key.device_num.channel)
	    && (ent->key.device_num.address == info->key.device_num.address)
	    && (ent->key.entity_id == info->key.entity_id)
	    && (ent->key.entity_instance == info->key.entity_instance));
    if (same) {
	info->ent = ent;
	return LOCKED_LIST_ITER_STOP;
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
entity_find(ipmi_entity_info_t *ents,
	    ipmi_device_num_t  device_num,
	    int                entity_id,
	    int                entity_instance,
	    ipmi_entity_t      **found_ent)
{
    search_info_t info = { {device_num, entity_id, entity_instance}, NULL};
    int           rv = 0;

    locked_list_iterate_nolock(ents->entities, search_entity, &info);
    if (info.ent == NULL) {
	rv = ENOENT;
    } else {
	info.ent->usecount++;
	if (found_ent)
	    *found_ent = info.ent;
    }

    return rv;
}

int
ipmi_entity_find(ipmi_entity_info_t *ents,
		 ipmi_mc_t          *mc,
		 int                entity_id,
		 int                entity_instance,
		 ipmi_entity_t      **found_ent)
{
    ipmi_device_num_t device_num;
    int               rv;
    ipmi_entity_t     *ent;

    CHECK_DOMAIN_LOCK(ents->domain);

    if (mc && entity_instance >= 0x60) {
	device_num.channel = ipmi_mc_get_channel(mc);
	device_num.address = ipmi_mc_get_address(mc);
    } else {
	device_num.channel = 0;
	device_num.address = 0;
    }
    _ipmi_domain_entity_lock(ents->domain);
    rv = entity_find(ents, device_num, entity_id, entity_instance, &ent);
    if (!rv) {
	if (ent->destroyed)
	    rv = ENOENT;
	else
	    *found_ent = ent;
    }
    _ipmi_domain_entity_unlock(ents->domain);
    return rv;
}

/* Must be called with _ipmi_domain_entity_lock(), this will release
   the lock.  */
static int
entity_add(ipmi_entity_info_t *ents,
	   ipmi_device_num_t  device_num,
	   int                entity_id,
	   int                entity_instance,
	   entity_sdr_add_cb  sdr_gen_output,
	   void               *sdr_gen_cb_data,
	   ipmi_entity_t      **new_ent)
{
    int           rv;
    ipmi_entity_t *ent;
    os_handler_t  *os_hnd;

    rv = entity_find(ents, device_num, entity_id, entity_instance, &ent);
    if (! rv) {
	if (ent->destroyed) {
	    /* A destroy is currently being reported on the entity,
	       resurrect it. */
	    ent->destroyed = 0;
	    ent->add_pending = 1;
	}
	_ipmi_domain_entity_unlock(ents->domain);
	if (sdr_gen_output != NULL) {
	    ent->sdr_gen_output = sdr_gen_output;
	    ent->sdr_gen_cb_data = sdr_gen_cb_data;
	}
	*new_ent = ent;
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
    ent->child_entities = locked_list_alloc_my_lock(entities_lock,
						    entities_unlock,
						    ents->domain);
    if (!ent->child_entities)
	goto out_err;

    ent->parent_entities = locked_list_alloc_my_lock(entities_lock,
						     entities_unlock,
						     ents->domain);
    if (!ent->parent_entities)
	goto out_err;

    ent->sensors = locked_list_alloc_my_lock(entities_lock,
					     entities_unlock,
					     ents->domain);
    if (!ent->sensors)
	goto out_err;

    ent->controls = locked_list_alloc_my_lock(entities_lock,
					      entities_unlock,
					      ents->domain);
    if (!ent->controls)
	goto out_err;

    ent->hot_swap_handlers_cl = locked_list_alloc(ent->os_hnd);
    if (!ent->hot_swap_handlers_cl)
	goto out_err;
    ent->hot_swap_handlers = locked_list_alloc(ent->os_hnd);
    if (!ent->hot_swap_handlers)
	goto out_err;

    ent->presence_handlers_cl = locked_list_alloc(ent->os_hnd);
    if (!ent->presence_handlers_cl)
	goto out_err;
    ent->presence_handlers = locked_list_alloc(ent->os_hnd);
    if (!ent->presence_handlers)
	goto out_err;

    ent->fully_up_handlers_cl = locked_list_alloc(ent->os_hnd);
    if (!ent->fully_up_handlers_cl)
	goto out_err;
    ent->fully_up_handlers = locked_list_alloc(ent->os_hnd);
    if (!ent->fully_up_handlers)
	goto out_err;

    ent->waitq = opq_alloc(os_hnd);
    if (! ent->waitq)
	return ENOMEM;

    ent->fru_handlers_cl = locked_list_alloc(ent->os_hnd);
    if (!ent->fru_handlers_cl)
	goto out_err;
    ent->fru_handlers = locked_list_alloc(ent->os_hnd);
    if (!ent->fru_handlers)
	goto out_err;

    ent->sensor_handlers_cl = locked_list_alloc(ent->os_hnd);
    if (!ent->sensor_handlers_cl)
	goto out_err;
    ent->sensor_handlers = locked_list_alloc(ent->os_hnd);
    if (!ent->sensor_handlers)
	goto out_err;

    ent->control_handlers_cl = locked_list_alloc(ent->os_hnd);
    if (!ent->control_handlers_cl)
	goto out_err;
    ent->control_handlers = locked_list_alloc(ent->os_hnd);
    if (!ent->control_handlers)
	goto out_err;

    rv = ipmi_create_lock(ent->domain, &ent->elock);
    if (rv)
	goto out_err;

    rv = entity_alloc_timer(ent, &ent->hot_swap_act_info);
    if (rv)
	goto out_err;

    rv = entity_alloc_timer(ent, &ent->hot_swap_deact_info);
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
    ent->key.device_num = device_num;
    ent->key.entity_id = entity_id;
    ent->key.entity_instance = entity_instance;
    ent->info.id_type = IPMI_ASCII_STR;

    ent->entity_id_string = ipmi_get_entity_id_string(entity_id);

    ent->usecount = 1;

    entity_set_name(ent);

    if (! locked_list_add_nolock(ents->entities, ent, NULL))
	goto out_err;

    _ipmi_domain_entity_unlock(ent->domain);

    /* Report the add when the entity is put. */
    ent->add_pending = 1;

    if (new_ent)
	*new_ent = ent;

    return 0;

 out_err:
    _ipmi_domain_entity_unlock(ent->domain);
    if (ent->hot_swap_act_info)
	entity_destroy_timer(ent->hot_swap_act_info);
    if (ent->hot_swap_deact_info)
	entity_destroy_timer(ent->hot_swap_deact_info);
    if (ent->elock)
	ipmi_destroy_lock(ent->elock);
    if (ent->presence_handlers)
	locked_list_destroy(ent->presence_handlers);
    if (ent->presence_handlers_cl)
	locked_list_destroy(ent->presence_handlers_cl);
    if (ent->fully_up_handlers)
	locked_list_destroy(ent->fully_up_handlers);
    if (ent->fully_up_handlers_cl)
	locked_list_destroy(ent->fully_up_handlers_cl);
    if (ent->waitq)
	opq_destroy(ent->waitq);
    if (ent->fru_handlers)
	locked_list_destroy(ent->fru_handlers);
    if (ent->fru_handlers_cl)
	locked_list_destroy(ent->fru_handlers_cl);
    if (ent->control_handlers)
	locked_list_destroy(ent->control_handlers);
    if (ent->control_handlers_cl)
	locked_list_destroy(ent->control_handlers_cl);
    if (ent->sensor_handlers)
	locked_list_destroy(ent->sensor_handlers);
    if (ent->sensor_handlers_cl)
	locked_list_destroy(ent->sensor_handlers_cl);
    if (ent->hot_swap_handlers)
	locked_list_destroy(ent->hot_swap_handlers);
    if (ent->hot_swap_handlers_cl)
	locked_list_destroy(ent->hot_swap_handlers_cl);
    if (ent->controls)
	locked_list_destroy(ent->controls);
    if (ent->sensors)
	locked_list_destroy(ent->sensors);
    if (ent->parent_entities)
	locked_list_destroy(ent->parent_entities);
    if (ent->child_entities)
	locked_list_destroy(ent->child_entities);
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

    _ipmi_domain_entity_lock(domain);

    /* This will release the lock. */
    rv = entity_add(ents, device_num, entity_id, entity_instance,
		    sdr_gen_output, sdr_gen_cb_data, &ent);
    if (!rv) {
        if (!ent->info.id_len)
	    ipmi_entity_set_id(ent, id, id_type, id_len);
	if (new_ent)
	    *new_ent = ent;
    }

    return 0;
}

/* Must be called with both the child and parent entities used and the
   domain entity lock held. */
static void
add_child(ipmi_entity_t       *ent,
	  ipmi_entity_t       *child,
	  locked_list_entry_t *entry1,
	  locked_list_entry_t *entry2)
{
    locked_list_add_entry_nolock(ent->child_entities, child, NULL, entry1);
    locked_list_add_entry_nolock(child->parent_entities, ent, NULL, entry2);

    ent->presence_possibly_changed = 1;
}

int
ipmi_entity_add_child(ipmi_entity_t       *ent,
		      ipmi_entity_t       *child)
{
    locked_list_entry_t *entry1;
    locked_list_entry_t *entry2;
    int                 rv = 0;

    CHECK_ENTITY_LOCK(ent);
    CHECK_ENTITY_LOCK(child);

    _ipmi_domain_entity_lock(ent->domain);

    entry1 = locked_list_alloc_entry();
    if (!entry1) {
	rv = ENOMEM;
	goto out_unlock;
    }
    entry2 = locked_list_alloc_entry();
    if (!entry2) {
	locked_list_free_entry(entry1);
	rv = ENOMEM;
	goto out_unlock;
    }

    add_child(ent, child, entry1, entry2);

    ent->changed = 1;
    child->changed = 1;

    _ipmi_domain_entity_unlock(ent->domain);

    return 0;

 out_unlock:
    _ipmi_domain_entity_unlock(ent->domain);
    return rv;
}

static int
ipmi_entity_remove_child_internal(ipmi_entity_t     *ent,
				  ipmi_entity_t     *child)
{
    int rv = 0;

    CHECK_ENTITY_LOCK(ent);
    CHECK_ENTITY_LOCK(child);

    if (! locked_list_remove_nolock(ent->child_entities, child, NULL))
	rv = EINVAL;
    locked_list_remove_nolock(child->parent_entities, ent, NULL);

    ent->presence_possibly_changed = 1;

    if (!rv) {
	ent->changed = 1;
	child->changed = 1;
    }

    return rv;
}

int
ipmi_entity_remove_child(ipmi_entity_t     *ent,
			 ipmi_entity_t     *child)
{
    int rv = 0;

    CHECK_ENTITY_LOCK(ent);
    CHECK_ENTITY_LOCK(child);

    _ipmi_domain_entity_lock(ent->domain);

    if (! locked_list_remove_nolock(ent->child_entities, child, NULL))
	rv = EINVAL;
    locked_list_remove_nolock(child->parent_entities, ent, NULL);

    ent->presence_possibly_changed = 1;

    _ipmi_domain_entity_unlock(ent->domain);

    if (!rv) {
	ent->changed = 1;
	child->changed = 1;
    }

    return rv;
}

typedef struct iterate_child_info_s
{
    ipmi_entity_t                *ent;
    ipmi_entity_iterate_child_cb handler;
    void                         *cb_data;
} iterate_child_info_t;

static int
iterate_child_handler(void *cb_data, void *item1, void *item2)
{
    iterate_child_info_t *info = cb_data;
    ipmi_entity_t         *ent = item1;

    info->handler(info->ent, item1, info->cb_data);
    _ipmi_entity_put(ent);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_entity_iterate_children(ipmi_entity_t                *ent,
			     ipmi_entity_iterate_child_cb handler,
			     void                         *cb_data)
{
    iterate_child_info_t info = { ent, handler, cb_data };

    locked_list_iterate_prefunc(ent->child_entities, iterate_entity_prefunc,
				iterate_child_handler, &info);
}

typedef struct iterate_parent_info_s
{
    ipmi_entity_t                 *ent;
    ipmi_entity_iterate_parent_cb handler;
    void                          *cb_data;
} iterate_parent_info_t;

static int
iterate_parent_handler(void *cb_data, void *item1, void *item2)
{
    iterate_parent_info_t *info = cb_data;
    ipmi_entity_t         *ent = item1;

    info->handler(info->ent, item1, info->cb_data);
    _ipmi_entity_put(ent);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_entity_iterate_parents(ipmi_entity_t                 *ent,
			    ipmi_entity_iterate_parent_cb handler,
			    void                          *cb_data)
{
    iterate_parent_info_t info = { ent, handler, cb_data };

    CHECK_ENTITY_LOCK(ent);

    locked_list_iterate_prefunc(ent->parent_entities, iterate_entity_prefunc,
				iterate_parent_handler, &info);
}

/***********************************************************************
 *
 * Entity presence handling.
 *
 **********************************************************************/

static int handle_hot_swap_presence(ipmi_entity_t  *ent,
				    int            present,
				    ipmi_event_t   *event);

int
ipmi_entity_add_presence_handler(ipmi_entity_t                  *ent,
				 ipmi_entity_presence_change_cb handler,
				 void                           *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_add(ent->presence_handlers, handler, cb_data))
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
    if (locked_list_remove(ent->presence_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_entity_add_presence_handler_cl(ipmi_entity_t              *ent,
				    ipmi_entity_presence_cl_cb handler,
				    void                       *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_add(ent->presence_handlers_cl, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_presence_handler_cl(ipmi_entity_t              *ent,
				       ipmi_entity_presence_cl_cb handler,
				       void                       *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_remove(ent->presence_handlers_cl, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

typedef struct presence_handler_info_s
{
    ipmi_entity_t             *ent;
    int                       present;
} presence_handler_info_t;

static int
call_presence_handler(void *cb_data, void *item1, void *item2)
{
    presence_handler_info_t        *info = cb_data;
    ipmi_entity_presence_change_cb handler = item1;

    handler(info->ent, info->present, item2, NULL);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_presence_handlers(ipmi_entity_t *ent, int present)
{
    presence_handler_info_t info;

    info.ent = ent;
    info.present = present;
    ent_lock(ent);
    if (ent->cruft_presence_handler) {
	ipmi_entity_presence_nd_cb handler = ent->cruft_presence_handler;
	void                       *cb_data = ent->cruft_presence_cb_data;
	ent_unlock(ent);
	handler(ent, info.present, cb_data, NULL);
    } else
	ent_unlock(ent);
    locked_list_iterate(ent->presence_handlers, call_presence_handler,
			&info);
}

/* This is for iterating the parents when a sensor's presence changes.
   The parent's presence may depend on it's childrens' presence, if it
   has no sensors. */
static void
presence_parent_handler(ipmi_entity_t *ent,
			ipmi_entity_t *parent,
			void          *cb_data)
{
    /* We only set the entity to check presence.  We can't use the
       child directly because the algorithm is unfortunately
       complicated. */
    parent->presence_possibly_changed = 1;
}

static void
presence_changed(ipmi_entity_t *ent, int present)
{
    ipmi_fru_t    *fru;
    ipmi_domain_t *domain = ent->domain;
    int           entity_fru_fetch = 0;
    int           was_present;
    int           rv;

    ent->presence_event_count++;

    if (present != ent->curr_present) {
	ent->curr_present = present;

	if (ent->hot_swappable
	    &&(ent->hs_cb.get_hot_swap_state == e_get_hot_swap_state))
	{
	    /* Do internal presence handling if we have the internal
	       hot-swap machine installed. */
	    handle_hot_swap_presence(ent, present, NULL);
	}

	/* When the entity becomes present or absent, fetch or destroy
	   its FRU info. */
	if (ipmi_entity_get_is_fru(ent)) {
	    if (present) {
		entity_fru_fetch = 1;
	    } else if (ent->fru != NULL) {
		fru = ent->fru;
		ent->fru = NULL;
		ipmi_fru_destroy_internal(fru, NULL, NULL);

		_ipmi_entity_call_fru_handlers(ent, IPMI_DELETED);
	    }
	}

	/* Subtle stuff, we only report presence if no one else is
	   using the entity.  If someone else is, we save it for
	   later. */
	_ipmi_domain_entity_lock(domain);
	if (ent->usecount == 1) {
	    ent->present = !ent->present;
	    _ipmi_domain_entity_unlock(domain);
	    call_presence_handlers(ent, present);
	    _ipmi_domain_entity_lock(domain);
	    while ((ent->usecount == 1) && (ent->present_change_count)) {
		ent->present = !ent->present;
		present = ent->present;
		ent->present_change_count--;
		_ipmi_domain_entity_unlock(domain);
		call_presence_handlers(ent, present);
		_ipmi_domain_entity_lock(domain);
	    }
	} else {
	    ent->present_change_count++;
	}
	was_present = ent->present;
	_ipmi_domain_entity_unlock(domain);
	/* Wait till here to start fetching FRUs, as we want to report
	   the entity first before we start the fetch. */
	if (was_present && entity_fru_fetch) {
	    rv = ipmi_entity_fetch_frus_cb(ent, entity_report_fully_up, NULL);
	    if (rv)
		entity_report_fully_up(ent, NULL);
	} else if (was_present)
	    entity_report_fully_up(ent, NULL);

	/* If our presence changes, that can affect parents, too.  So we
	   rescan them. */
	ipmi_entity_iterate_parents(ent, presence_parent_handler, NULL);
    }
}

static void
presence_child_handler(ipmi_entity_t *ent,
		       ipmi_entity_t *child,
		       void          *cb_data)
{
    int *present = cb_data;
    int p = child->present;

    if (ent->present_change_count % 2)
	p = !p;
    if (p)
	*present = p;
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
	presence_changed(ent, offset == 0);
    else if (dir == IPMI_DEASSERTION)
	presence_changed(ent, offset != 0);
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
	presence_changed(ent, 1);
    else if (dir == IPMI_DEASSERTION)
	presence_changed(ent, 0);
    return IPMI_EVENT_NOT_HANDLED;
}

typedef struct ent_detect_info_s
{
    int force;
} ent_detect_info_t;

typedef struct ent_active_detect_s
{
    ipmi_lock_t      *lock;
    ipmi_entity_id_t ent_id;
    int              try_count;
    int              done_count;
    int              present;
    unsigned int     start_presence_event_count;
    ipmi_msg_t       *msg;
} ent_active_detect_t;

static void
detect_cleanup(ent_active_detect_t *info, ipmi_entity_t *ent,
	       ipmi_domain_t *domain)
{
    ipmi_unlock(info->lock);
    ipmi_destroy_lock(info->lock);
    ipmi_mem_free(info);
    if (ent)
	ent->in_presence_check = 0;
    _ipmi_put_domain_fully_up(domain, "detect_cleanup");
}

static void
detect_done(ipmi_entity_t *ent, ent_active_detect_t *info)
{
    ipmi_unlock(info->lock);
    presence_changed(ent, info->present);
    ipmi_destroy_lock(info->lock);
    ipmi_mem_free(info);
    ent->in_presence_check = 0;
    _ipmi_put_domain_fully_up(ent->domain, "detect_done");
}

static void
detect_frudev_handler(ipmi_entity_t *ent, void *cb_data)
{
    ent_active_detect_t *info = cb_data;

    if (info->start_presence_event_count != ent->presence_event_count) {
	/* Something else has changed the presence since we started
	   the presence detection process, then don't change the
	   value.  There are races where the entity could have been
	   set present and we detect it as not present.  However, it
	   is not possible to detect it as present and for something
	   else to set it not present. */
	detect_cleanup(info, ent, ent->domain);
	return;
    }

    if (info->msg->data[0] == 0)
	info->present = 1;

    detect_done(ent, info);
}
    
static void
detect_frudev(ipmi_mc_t  *mc,
	      ipmi_msg_t *rsp,
	      void       *rsp_data)
{
    ent_active_detect_t *info = rsp_data;

    ipmi_lock(info->lock);
    info->msg = rsp;
    if (ipmi_entity_pointer_cb(info->ent_id, detect_frudev_handler, info))
	/* We cheat and pull the domain from the entity id.  The domain
	 * still has to be around in the place, but we can't rely on the
	 * MC as it may have gone away if it failed or the domain is in
	 * shutdown. */
	detect_cleanup(info, NULL, info->ent_id.domain_id.domain);
}

/* This is the end of the line on checks.  We have to report something
   here. */
static void
try_presence_frudev(ipmi_entity_t *ent, ent_active_detect_t *info)
{
    ipmi_msg_t    msg;
    unsigned char data[1];
    int           rv;

    if ((!ent->frudev_present) || (!ent->frudev_active)) {
	detect_done(ent, info);
	return;
    }

    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_GET_FRU_INVENTORY_AREA_INFO_CMD;
    msg.data = data;
    data[0] = ent->info.fru_device_id; /* Will be 0 for MCs, so this
					  is ok even though it is not
					  in the MC record. */
    msg.data_len = 1;

    /* Send a message to the FRU device and see if we can get some
       data. */
    _ipmi_domain_mc_lock(ent->domain);
    _ipmi_mc_get(ent->frudev_mc);
    _ipmi_domain_mc_unlock(ent->domain);
    rv = ipmi_mc_send_command(ent->frudev_mc, ent->info.lun, &msg,
			      detect_frudev, info);
    _ipmi_mc_put(ent->frudev_mc);
    if (rv)
	detect_done(ent, info);
    else
	ipmi_unlock(info->lock);
}

static int
try_presence_children(ipmi_entity_t *parent, ent_active_detect_t *info)
{
    if (! ipmi_entity_get_is_parent(parent))
	return ENOSYS;

    ipmi_entity_iterate_children(parent, presence_child_handler,
				 &info->present);
    detect_done(parent, info);
    return 0;
}

static void
control_detect_handler(ipmi_entity_t *ent, void *cb_data)
{
    ent_active_detect_t *info = cb_data;
    
    if (info->start_presence_event_count != ent->presence_event_count) {
	/* Something else has changed the presence since we started
	   the presence detection process, then don't change the
	   value.  There are races where the entity could have been
	   set present and we detect it as not present.  However, it
	   is not possible to detect it as present and for something
	   else to set it not present. */
	detect_cleanup(info, ent, ent->domain);
	return;
    }

    if (!info->present) {
	/* Nothing present from the sensors, try the children. */
	if (! try_presence_children(ent, info)) {
	    /* Children got it, nothing to do */
	} else {
	    try_presence_frudev(ent, info);
	}
    } else {
	detect_done(ent, info);
    }
}

static void
detect_control_val(ipmi_control_t *control,
		   int            err,
		   int            *val,
		   void           *cb_data)
{
    ent_active_detect_t *info = cb_data;

    ipmi_lock(info->lock);
    if (!err)
	info->present = 1;

    info->done_count++;
    if (info->try_count == info->done_count) {
	if (ipmi_entity_pointer_cb(info->ent_id, control_detect_handler, info))
	    detect_cleanup(info, NULL, ipmi_control_get_domain(control));
    } else
	ipmi_unlock(info->lock);
}

static void
detect_control_light(ipmi_control_t       *control,
		     int                  err,
		     ipmi_light_setting_t *settings,
		     void                 *cb_data)
{
    ent_active_detect_t *info = cb_data;

    ipmi_lock(info->lock);
    if (!err)
	info->present = 1;

    info->done_count++;
    if (info->try_count == info->done_count) {
	if (ipmi_entity_pointer_cb(info->ent_id, control_detect_handler, info))
	    detect_cleanup(info, NULL, ipmi_control_get_domain(control));
    } else
	ipmi_unlock(info->lock);
}

static void
detect_control_id(ipmi_control_t *control,
		  int            err,
		  unsigned char  *val,
		  int            length,
		  void           *cb_data)
{
    ent_active_detect_t *info = cb_data;

    ipmi_lock(info->lock);
    if (!err)
	info->present = 1;

    info->done_count++;
    if (info->try_count == info->done_count) {
	if (ipmi_entity_pointer_cb(info->ent_id, control_detect_handler, info))
	    detect_cleanup(info, NULL, ipmi_control_get_domain(control));
    } else
	ipmi_unlock(info->lock);
}

static void
detect_control_display(ipmi_control_t *control,
		       int            err,
		       char           *str,
		       unsigned int   len,
		       void           *cb_data)
{
    ent_active_detect_t *info = cb_data;

    ipmi_lock(info->lock);
    if (!err)
	info->present = 1;

    info->done_count++;
    if (info->try_count == info->done_count) {
	if (ipmi_entity_pointer_cb(info->ent_id, control_detect_handler, info))
	    detect_cleanup(info, NULL, ipmi_control_get_domain(control));
    } else
	ipmi_unlock(info->lock);
}

static void
control_detect_send(ipmi_entity_t  *ent,
		    ipmi_control_t *control,
		    void           *cb_data)
{
    ent_active_detect_t *info = cb_data;
    int                 rv;

    if (ipmi_control_get_ignore_for_presence(control))
	/* Control should be ignored for presence. */
	return;

    info->try_count++;
    ipmi_unlock(info->lock);

    rv = ipmi_control_get_val(control, detect_control_val, info);
    if (rv)
	rv = ipmi_control_get_light(control, detect_control_light, info);
    if (rv)
	rv = ipmi_control_identifier_get_val(control, detect_control_id, info);
    if (rv)
	rv = ipmi_control_get_display_string(control, 0, 0, 1,
					     detect_control_display,
					     info);
    ipmi_lock(info->lock);
    if (rv)
	info->try_count--;
}

static int
try_presence_controls(ipmi_entity_t *ent, ent_active_detect_t *info)
{
    if (locked_list_num_entries(ent->controls) == 0)
	return ENOSYS;

    /* It has sensors, try to see if any of those are active.  Start
       the count at 1 so the callbacks don't do the call before we are
       done here. */
    info->try_count = 1;
    info->done_count = 0;
    ipmi_entity_iterate_controls(ent, control_detect_send, info);

    /* I couldn't message any controls, go on. */
    if (info->try_count == 1)
	return ENOSYS;
    info->done_count++;

    if (info->try_count == info->done_count)
	control_detect_handler(ent, info);
    else
	ipmi_unlock(info->lock);
    return 0;
}

static void
sensor_detect_handler(ipmi_entity_t *ent, void *cb_data)
{
    ent_active_detect_t *info = cb_data;
    
    if (info->start_presence_event_count != ent->presence_event_count) {
	/* Something else has changed the presence since we started
	   the presence detection process, then don't change the
	   value.  There are races where the entity could have been
	   set present and we detect it as not present.  However, it
	   is not possible to detect it as present and for something
	   else to set it not present. */
	detect_cleanup(info, ent, ent->domain);
	return;
    }

    if (!info->present) {
	/* Nothing present from the sensors, try other stuff. */
	if (! try_presence_controls(ent, info)) {
	    /* Controls got it, nothing to do */
	} else if (! try_presence_children(ent, info)) {
	    /* Children got it, nothing to do */
	} else {
	    try_presence_frudev(ent, info);
	}
    } else {
	detect_done(ent, info);
    }
}

static void
detect_states_read(ipmi_sensor_t *sensor,
		   int           err,
		   ipmi_states_t *states,
		   void          *cb_data)
{
    ent_active_detect_t *info = cb_data;

    ipmi_lock(info->lock);
    if (!err && ipmi_is_sensor_scanning_enabled(states)
        && !ipmi_is_initial_update_in_progress(states))
	info->present = 1;

    info->done_count++;
    if (info->try_count == info->done_count) {
	if (ipmi_entity_pointer_cb(info->ent_id, sensor_detect_handler, info))
	    detect_cleanup(info, NULL, ipmi_sensor_get_domain(sensor));
    } else
	ipmi_unlock(info->lock);
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

    ipmi_lock(info->lock);
    if (!err && ipmi_is_sensor_scanning_enabled(states)
        && !ipmi_is_initial_update_in_progress(states))
	info->present = 1;

    info->done_count++;
    if (info->try_count == info->done_count) {
	if (ipmi_entity_pointer_cb(info->ent_id, sensor_detect_handler, info))
	    detect_cleanup(info, NULL, ipmi_sensor_get_domain(sensor));
    } else
	ipmi_unlock(info->lock);
}

static void
sensor_detect_send(ipmi_entity_t *ent,
		   ipmi_sensor_t *sensor,
		   void          *cb_data)
{
    ent_active_detect_t *info = cb_data;
    int                 rv;

    if (ipmi_sensor_get_ignore_for_presence(sensor))
	/* Sensor should be ignored for presence. */
	return;

    info->try_count++;
    ipmi_unlock(info->lock);

    rv = ipmi_sensor_get_reading(sensor, detect_reading_read, info);
    if (rv)
	rv = ipmi_sensor_get_states(sensor, detect_states_read, info);

    ipmi_lock(info->lock);
    if (rv)
	info->try_count--;
}

static int
try_presence_sensors(ipmi_entity_t *ent, ent_active_detect_t *info)
{
    if (locked_list_num_entries(ent->sensors) == 0)
	return ENOSYS;

    /* Start the try count at 1 so the presence does not complete until
       after we are done here. */
    info->try_count = 1;
    info->done_count = 0;

    ipmi_entity_iterate_sensors(ent, sensor_detect_send, info);

    /* I couldn't message any sensors, go on. */
    if (info->try_count == 1)
	return ENOSYS;

    info->done_count++;
    if (info->try_count == info->done_count)
	sensor_detect_handler(ent, info);
    else
	ipmi_unlock(info->lock);
    return 0;
}

static void
detect_no_presence_sensor_presence(ipmi_entity_t *ent)
{
    ent_active_detect_t *detect;
    int                 rv;

    detect = ipmi_mem_alloc(sizeof(*detect));
    if (!detect) {
	ent->in_presence_check = 0;
	_ipmi_put_domain_fully_up(ent->domain,
				  "detect_no_presence_sensor_presence");
	return;
    }
    rv = ipmi_create_lock(ent->domain, &detect->lock);
    if (rv) {
	ent->in_presence_check = 0;
	_ipmi_put_domain_fully_up(ent->domain,
				  "detect_no_presence_sensor_presence(2)");
	ipmi_mem_free(detect);
	return;
    }

    detect->start_presence_event_count = ent->presence_event_count;
    detect->ent_id = ipmi_entity_convert_to_id(ent);
    detect->present = 0;
    ipmi_lock(detect->lock);

    /* The successful one below will unlock the lock and free detect. */
    if (! try_presence_sensors(ent, detect)) {
	/* Success with sensors, nothing to do */
    } else if (! try_presence_controls(ent, detect)) {
	/* Note that controls are not technically part of the spec,
	   but since we have them we use them for presence
	   detection. */
	/* Success with controls, nothing to do */
    } else if (! try_presence_children(ent, detect)) {
	/* Success with children, nothing to do */
    } else {
	try_presence_frudev(ent, detect);
    }
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

    if (err) {
	_ipmi_domain_entity_lock(ent->domain);
	_ipmi_entity_get(ent);
	_ipmi_domain_entity_unlock(ent->domain);
	detect_no_presence_sensor_presence(ent);
	_ipmi_entity_put(ent);
	return;
    }

    if (ipmi_is_initial_update_in_progress(states))
	/* Sensor did not return valid values, the entity is probably
	   not present. */
	present = 0;
    else {
	rv = ipmi_sensor_discrete_event_readable(sensor, 0, &val);
	if (rv || !val)
	    /* The present bit is not supported, so use the not present bit. */
	    present = ! ipmi_is_state_set(states, 1);
	else
	    /* The present bit is supported. */
	    present = ipmi_is_state_set(states, 0);
    }

    presence_changed(ent, present);
    ent->in_presence_check = 0;
    _ipmi_put_domain_fully_up(ipmi_sensor_get_domain(sensor), "states_read");
}

static void
states_bit_read(ipmi_sensor_t *sensor,
		int           err,
		ipmi_states_t *states,
		void          *cb_data)
{
    int           present;
    ipmi_entity_t *ent = cb_data;

    if (err) {
	_ipmi_domain_entity_lock(ent->domain);
	_ipmi_entity_get(ent);
	_ipmi_domain_entity_unlock(ent->domain);
	detect_no_presence_sensor_presence(ent);
	_ipmi_entity_put(ent);
	return;
    }

    if (ipmi_is_initial_update_in_progress(states))
	/* Sensor did not return valid values, the entity is probably
	   not present. */
	present = 0;
    else
	present = ipmi_is_state_set(states, ent->presence_bit_offset);

    presence_changed(ent, present);
    ent->in_presence_check = 0;
    _ipmi_put_domain_fully_up(ipmi_sensor_get_domain(sensor),
			      "states_bit_read");
}

static void
ent_detect_presence(ipmi_entity_t *ent, void *cb_data)
{
    ent_detect_info_t   *info = cb_data;
    int                 rv;

    ent_lock(ent);
    if (ent->in_presence_check
	|| ((!info->force) && (! ent->presence_possibly_changed)))
    {
	ent_unlock(ent);
	return;
    }
    ent->presence_possibly_changed = 0;
    ent->in_presence_check = 1;

    if (ent->hot_swappable) {
	ent_unlock(ent);
	ipmi_entity_check_hot_swap_state(ent);
	ent_lock(ent);
    }

    _ipmi_get_domain_fully_up(ent->domain, "ent_detect_presence");
    if (ent->presence_sensor) {
	/* Presence sensor overrides everything. */
	ipmi_sensor_id_t psi = ent->presence_sensor_id;
	ent_unlock(ent);
	rv = ipmi_sensor_id_get_states(psi, states_read, ent);
	if (rv) {
	    ent->in_presence_check = 0;
	    _ipmi_put_domain_fully_up(ent->domain, "ent_detect_presence(2)");
	}
    } else if (ent->presence_bit_sensor) {
	/* Presence bit sensor overrides everything but a presence sensor. */
	ipmi_sensor_id_t psi = ent->presence_bit_sensor_id;
	ent_unlock(ent);
	rv = ipmi_sensor_id_get_states(psi, states_bit_read, ent);
	if (rv) {
	    ent->in_presence_check = 0;
	    _ipmi_put_domain_fully_up(ent->domain, "ent_detect_presence(3)");
	}
    } else {
	ent_unlock(ent);
	detect_no_presence_sensor_presence(ent);
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
    int           rv;

    _ipmi_domain_entity_lock(ent->domain);
    rv = _ipmi_entity_get(ent);
    _ipmi_domain_entity_unlock(ent->domain);
    if (rv)
	return;

    if (ent->frudev_active != active) {
	ent->frudev_active = active;
	/* Only detect with frudev if there are no other
	   presence-detecting things there. */
	if ((!ent->presence_sensor) && (!ent->presence_bit_sensor)
	    && (locked_list_num_entries(ent->controls) == 0)
	    && (locked_list_num_entries(ent->sensors) == 0)
	    && (!ipmi_entity_get_is_parent(ent)))
	{
	    ipmi_detect_entity_presence_change(ent, 1);
	}
    }
    _ipmi_entity_put(ent);
}

/* Must be called with the entity lock held.  May release and reclaim it. */
static void
handle_new_presence_sensor(ipmi_entity_t *ent, ipmi_sensor_t *sensor)
{
    ipmi_event_state_t events;
    int                event_support;
    int                rv;
    int                val;

    ent->presence_sensor_id = ipmi_sensor_convert_to_id(sensor);
    ent->presence_sensor = sensor;

    /* If we have a presence sensor, remove the presence bit sensor. */
    if (ent->presence_bit_sensor) {
	ent->presence_bit_sensor = NULL;
	ipmi_sensor_remove_discrete_event_handler(ent->presence_bit_sensor,
						  presence_sensor_changed,
						  ent);
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
	rv = ipmi_sensor_discrete_event_supported(sensor, 0, IPMI_ASSERTION,
						  &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, 0, IPMI_ASSERTION);
	rv = ipmi_sensor_discrete_event_supported(sensor, 0, IPMI_DEASSERTION,
						  &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, 0, IPMI_DEASSERTION);
	rv = ipmi_sensor_discrete_event_supported(sensor, 1, IPMI_ASSERTION,
						  &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, 1, IPMI_ASSERTION);
	rv = ipmi_sensor_discrete_event_supported(sensor, 1, IPMI_DEASSERTION,
						  &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, 1, IPMI_DEASSERTION);
    }

    ent_unlock(ent);
    ipmi_sensor_set_event_enables(sensor, &events, NULL, NULL);
    ent_lock(ent);

 out:
    ent->presence_possibly_changed = 1;

    if (ent->hs_cb.get_hot_swap_state == NULL) {
	/* Set the entity hot-swap capable and use our internal state
	   machine. */
	ipmi_entity_set_hot_swappable(ent, 1);
	ent->hs_cb = internal_hs_cb;
    }
}

/* Must be called with the entity lock held.  May release and reclaim it. */
static void
handle_new_presence_bit_sensor(ipmi_entity_t *ent, ipmi_sensor_t *sensor,
			       int bit)
{
    ipmi_event_state_t events;
    int                event_support;

    ent->presence_bit_sensor = sensor;
    ent->presence_bit_offset = bit;
    ent->presence_bit_sensor_id = ipmi_sensor_convert_to_id(sensor);

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
	rv = ipmi_sensor_discrete_event_supported
	    (sensor, ent->presence_bit_offset, IPMI_ASSERTION, &val);
	if (!rv && val)
	    ipmi_discrete_event_set(&events, ent->presence_bit_offset,
				    IPMI_ASSERTION);
	rv = ipmi_sensor_discrete_event_supported
	    (sensor, ent->presence_bit_offset, IPMI_DEASSERTION, &val);
	if (!rv && val)
	    ipmi_discrete_event_set(&events, ent->presence_bit_offset,
				    IPMI_DEASSERTION);
    }

    ent_unlock(ent);
    ipmi_sensor_enable_events(sensor, &events, NULL, NULL);
    ent_lock(ent);

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
ipmi_entity_add_fully_up_handler(ipmi_entity_t      *ent,
				 ipmi_entity_ptr_cb handler,
				 void               *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_add(ent->fully_up_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_fully_up_handler(ipmi_entity_t      *ent,
				    ipmi_entity_ptr_cb handler,
				    void               *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_remove(ent->fully_up_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_entity_add_fully_up_handler_cl(ipmi_entity_t              *ent,
				    ipmi_entity_fully_up_cl_cb handler,
				    void                       *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_add(ent->fully_up_handlers_cl, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_fully_up_handler_cl(ipmi_entity_t              *ent,
				       ipmi_entity_fully_up_cl_cb handler,
				       void                       *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_remove(ent->fully_up_handlers_cl, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

static int
call_fully_up_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_entity_t      *entity = cb_data;
    ipmi_entity_ptr_cb handler = item1;

    handler(entity, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_fully_up_handlers(ipmi_entity_t *ent)
{
    locked_list_iterate(ent->fully_up_handlers, call_fully_up_handler, ent);
}

/***********************************************************************
 *
 * Handling of sensor and control addition and removal.
 *
 **********************************************************************/

int
ipmi_entity_add_sensor_update_handler(ipmi_entity_t         *ent,
				      ipmi_entity_sensor_cb handler,
				      void                  *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_add(ent->sensor_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_sensor_update_handler(ipmi_entity_t         *ent,
					 ipmi_entity_sensor_cb handler,
					 void                  *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_remove(ent->sensor_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_entity_add_sensor_update_handler_cl(ipmi_entity_t            *ent,
					 ipmi_entity_sensor_cl_cb handler,
					 void                     *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_add(ent->sensor_handlers_cl, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_sensor_update_handler_cl(ipmi_entity_t            *ent,
					    ipmi_entity_sensor_cl_cb handler,
					    void                     *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_remove(ent->sensor_handlers_cl, handler, cb_data))
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

static int
call_sensor_handler(void *cb_data, void *item1, void *item2)
{
    sensor_handler_t      *info = cb_data;
    ipmi_entity_sensor_cb handler = item1;

    handler(info->op, info->entity, info->sensor, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
_ipmi_entity_call_sensor_handlers(ipmi_entity_t *ent, ipmi_sensor_t *sensor, 
				  enum ipmi_update_e op)
{
    sensor_handler_t info;

    /* If we are reporting things, make sure the entity they are attached
       to is already reported. */
    _ipmi_domain_entity_lock(ent->domain);
    if (ent->add_pending) {
	ent->add_pending = 0;
	_ipmi_domain_entity_unlock(ent->domain);
	call_entity_update_handlers(ent, IPMI_ADDED);
    } else {
	_ipmi_domain_entity_unlock(ent->domain);
    }

    info.op = op;
    info.entity = ent;
    info.sensor = sensor;
    locked_list_iterate(ent->sensor_handlers, call_sensor_handler, &info);
}

int
ipmi_entity_add_control_update_handler(ipmi_entity_t      *ent,
				       ipmi_entity_control_cb handler,
				       void               *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_add(ent->control_handlers, handler, cb_data))
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
    if (locked_list_remove(ent->control_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_entity_add_control_update_handler_cl(ipmi_entity_t             *ent,
					  ipmi_entity_control_cl_cb handler,
					  void                      *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_add(ent->control_handlers_cl, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_control_update_handler_cl(ipmi_entity_t             *ent,
					     ipmi_entity_control_cl_cb handler,
					     void                     *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_remove(ent->control_handlers, handler, cb_data))
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

static int
call_control_handler(void *cb_data, void *item1, void *item2)
{
    control_handler_t      *info = cb_data;
    ipmi_entity_control_cb handler = item1;

    handler(info->op, info->entity, info->control, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
_ipmi_entity_call_control_handlers(ipmi_entity_t      *ent,
				   ipmi_control_t     *control, 
				   enum ipmi_update_e op)
{
    control_handler_t info;


    /* If we are reporting things, make sure the entity they are attached
       to is already reported. */
    _ipmi_domain_entity_lock(ent->domain);
    if (ent->add_pending) {
	ent->add_pending = 0;
	_ipmi_domain_entity_unlock(ent->domain);
	call_entity_update_handlers(ent, IPMI_ADDED);
    } else {
	_ipmi_domain_entity_unlock(ent->domain);
    }

    info.op = op;
    info.entity = ent;
    info.control = control;
    locked_list_iterate(ent->control_handlers, call_control_handler, &info);
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

static int
is_presence_sensor(ipmi_sensor_t *sensor)
{
    int val, rv;
    int supports_present = 0;
    int supports_absent = 0;
    int reading_type;

    /* Is it the right type (a presence sensor)? */
    if (ipmi_sensor_get_sensor_type(sensor) != 0x25)
	return 0;

    reading_type = ipmi_sensor_get_event_reading_type(sensor);
    if (reading_type != IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC)
	/* Don't know how to interpret a "generic" reating type code */
	return 0;

    /* Presense sensors that don't generate events are kind of useless. */
    if (ipmi_sensor_get_event_support(sensor) == IPMI_EVENT_SUPPORT_NONE)
	return 0;

    /* Check present bit */
    rv = ipmi_sensor_discrete_event_readable(sensor, 0, &val);
    if ((!rv) && (val))
	supports_present = 1;
    /* Check absent bit. */
    rv = ipmi_sensor_discrete_event_readable(sensor, 1, &val);
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
    int reading_type = ipmi_sensor_get_event_reading_type(sensor);

    if (reading_type != IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC)
	/* All presence bits are in sensor-specific bits, not generic ones */
	return 0;

    /* Is it a sensor with a presence bit? */
    switch (sensor_type)
    {
    case IPMI_SENSOR_TYPE_POWER_SUPPLY: bit = 0; break;
    case IPMI_SENSOR_TYPE_BATTERY: bit = 2; break;
    case IPMI_SENSOR_TYPE_SLOT_CONNECTOR: bit = 2; break;
    case IPMI_SENSOR_TYPE_PROCESSOR: bit = 7; break;
    case IPMI_SENSOR_TYPE_DRIVE_SLOT: bit = 0; break;
    case IPMI_SENSOR_TYPE_MEMORY: bit = 6; break;
    default:
	return 0;
    }

    /* Presense sensors that don't generate events are kind of useless. */
    if (ipmi_sensor_get_event_support(sensor) == IPMI_EVENT_SUPPORT_NONE)
	return 0;

    /* Check if the bit is available */
    rv = ipmi_sensor_discrete_event_readable(sensor, bit, &val);
    if (rv || !val)
	return 0;

    *bit_offset = bit;

    return 1;
}

void
ipmi_entity_add_sensor(ipmi_entity_t *ent,
		       ipmi_sensor_t *sensor,
		       void          *link)
{
    int bit;

    CHECK_ENTITY_LOCK(ent);

    ent_lock(ent);
    if (is_presence_sensor(sensor) && (ent->presence_sensor == NULL)
	&& (ent->presence_bit_sensor == NULL))
    {
	/* It's the presence sensor and we don't already have one.  We
	   keep this special. */
	handle_new_presence_sensor(ent, sensor);
    } else if ((ent->presence_sensor == NULL)
	       && (ent->presence_bit_sensor == NULL)
	       && is_presence_bit_sensor(sensor, &bit))
    {
	/* If it's a sensor with a presence bit, we use it. */
	handle_new_presence_bit_sensor(ent, sensor, bit);
    }

    if (is_hot_swap_requester(sensor) && (ent->hot_swap_requester == NULL)) {
	handle_new_hot_swap_requester(ent, sensor);
    }
    ent_unlock(ent);

    locked_list_add_entry(ent->sensors, sensor, NULL, link);
	
    ent->presence_possibly_changed = 1;
}

typedef struct sens_find_presence_s
{
    int           is_presence;
    int           bit;
    ipmi_sensor_t *sensor;
    ipmi_sensor_t *ignore_sensor;
} sens_cmp_info_t;

static void
sens_cmp_if_presence(ipmi_entity_t *ent, ipmi_sensor_t *sensor,
		     void *cb_data)
{
    sens_cmp_info_t *info = cb_data;

    if (sensor == info->ignore_sensor)
	return;

    if (info->is_presence)
	return;

    info->is_presence = is_presence_sensor(sensor);
    if (info->is_presence) {
	info->sensor = sensor;
	handle_new_presence_sensor(ent, sensor);
    }
}

static void
sens_cmp_if_presence_bit(ipmi_entity_t *ent, ipmi_sensor_t *sensor,
			 void *cb_data)
{
    sens_cmp_info_t *info = cb_data;

    if (sensor == info->ignore_sensor)
	return;

    if (info->is_presence)
	return;

    info->is_presence = is_presence_bit_sensor(sensor, &info->bit);
    if (info->is_presence) {
	info->sensor = sensor;
	handle_new_presence_bit_sensor(ent, sensor, info->bit);
    }
}

/* Must be called with the entity lock held.  May release and reclaim it. */
static void
check_for_another_presence_sensor(ipmi_entity_t *ent, ipmi_sensor_t *old)
{
    sens_cmp_info_t info;

    info.sensor = NULL;
    info.ignore_sensor = old;
    info.is_presence = 0;

    /* See if there is another presence sensor. */
    ipmi_entity_iterate_sensors(ent, sens_cmp_if_presence, &info);

    if (! info.sensor) {
	/* See if there is a presence bit sensor. */
	ent->presence_sensor = NULL;
	info.ignore_sensor = NULL;
	info.is_presence = 0;
	ipmi_entity_iterate_sensors(ent, sens_cmp_if_presence_bit, &info);
    }
}

void
ipmi_entity_remove_sensor(ipmi_entity_t *ent,
			  ipmi_sensor_t *sensor)
{
    /* Note that you *CANNOT* call ipmi_sensor_convert_to_id() (or any
       other thing like that) because the MC that the sensor belongs
       to may have disappeared already.  So be careful. */

    CHECK_ENTITY_LOCK(ent);

    ent_lock(ent);
    if (sensor == ent->presence_sensor) {
	ent->presence_sensor = NULL;
	ent->presence_possibly_changed = 1;
	check_for_another_presence_sensor(ent, sensor);
    } else if (sensor == ent->presence_bit_sensor) {
	ent->presence_bit_sensor = NULL;
	ent->presence_possibly_changed = 1;
	check_for_another_presence_sensor(ent, sensor);
    }
    if (sensor == ent->hot_swap_requester) {
	ent->hot_swap_requester = NULL;
    }
    ent_unlock(ent);

    if (! locked_list_remove(ent->sensors, sensor, NULL)) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(ipmi_entity_remove_sensor):"
		 " Removal of a sensor from an entity was requested,"
		 " but the sensor was not there",
		 SENSOR_NAME(sensor));
	return;
    }
}

void
ipmi_entity_add_control(ipmi_entity_t  *ent,
			ipmi_control_t *control,
			void           *link)
{
    CHECK_ENTITY_LOCK(ent);

    ent_lock(ent);
    if (is_hot_swap_power(control))
	handle_new_hot_swap_power(ent, control);
    if (is_hot_swap_indicator(control))
	handle_new_hot_swap_indicator(ent, control);
    ent_unlock(ent);

    locked_list_add_entry(ent->controls, control, NULL, link);
    ent->presence_possibly_changed = 1;
}

void
ipmi_entity_remove_control(ipmi_entity_t  *ent,
			   ipmi_control_t *control)
{
    /* Note that you *CANNOT* call ipmi_control_convert_to_id() (or any
       other thing like that) because the MC that the sensor belongs
       to may have disappeared already.  So be careful. */

    CHECK_ENTITY_LOCK(ent);

    ent_lock(ent);
    if (control == ent->hot_swap_power) {
	/* If don't have power control, we can't manage hot-swap. */
	ipmi_entity_set_supports_managed_hot_swap(ent, 0);

	ent->hot_swap_power = NULL;
    }
    if (control == ent->hot_swap_indicator)
	ent->hot_swap_indicator = NULL;
    ent_unlock(ent);

    if (! locked_list_remove(ent->controls, control, NULL)) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(ipmi_entity_remove_control):"
		 " Removal of a control from an entity was requested,"
		 " but the control was not there",
		 CONTROL_NAME(control));
	return;
    }
    ent->presence_possibly_changed = 1;
}

typedef struct iterate_sensor_info_s
{
    ipmi_entity_t                 *ent;
    ipmi_entity_iterate_sensor_cb handler;
    void                          *cb_data;
    int                           got_failed;
} iterate_sensor_info_t;

static int
iterate_sensor_prefunc(void *cb_data, void *item1, void *item2)
{
    iterate_sensor_info_t *info = cb_data;
    ipmi_sensor_t         *sensor = item1;
    int                   rv;
    ipmi_mc_t             *mc = ipmi_sensor_get_mc(sensor);
    ipmi_domain_t         *domain;

    if (!mc)
	goto out_err;
    domain = ipmi_mc_get_domain(mc);
    _ipmi_domain_mc_lock(domain);
    rv = _ipmi_mc_get(mc);
    _ipmi_domain_mc_unlock(domain);
    if (rv)
	goto out_err;
    rv = _ipmi_sensor_get(sensor);
    if (rv) {
	_ipmi_mc_put(mc);
	goto out_err;
    }
    info->got_failed = 0;
    return LOCKED_LIST_ITER_CONTINUE;

 out_err:
    info->got_failed = 1;
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
iterate_sensor_handler(void *cb_data, void *item1, void *item2)
{
    iterate_sensor_info_t *info = cb_data;
    ipmi_sensor_t         *sensor = item1;
    ipmi_mc_t             *mc = ipmi_sensor_get_mc(sensor);

    if (info->got_failed)
	goto out;
    info->handler(info->ent, item1, info->cb_data);
    _ipmi_sensor_put(sensor);
    _ipmi_mc_put(mc);
 out:
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_entity_iterate_sensors(ipmi_entity_t                 *ent,
			    ipmi_entity_iterate_sensor_cb handler,
			    void                          *cb_data)
{
    iterate_sensor_info_t info = { ent, handler, cb_data };

    CHECK_ENTITY_LOCK(ent);

    locked_list_iterate_prefunc(ent->sensors, iterate_sensor_prefunc,
				iterate_sensor_handler, &info);
}


typedef struct iterate_control_info_s
{
    ipmi_entity_t                  *ent;
    ipmi_entity_iterate_control_cb handler;
    void                           *cb_data;
    int                            got_failed;
} iterate_control_info_t;

static int
iterate_control_prefunc(void *cb_data, void *item1, void *item2)
{
    iterate_control_info_t *info = cb_data;
    ipmi_control_t         *control = item1;
    int                   rv;
    ipmi_mc_t             *mc = ipmi_control_get_mc(control);
    ipmi_domain_t         *domain = ipmi_mc_get_domain(mc);

    if (!mc)
	goto out_err;
    _ipmi_domain_mc_lock(domain);
    rv = _ipmi_mc_get(mc);
    _ipmi_domain_mc_unlock(domain);
    if (rv)
	goto out_err;
    rv = _ipmi_control_get(control);
    if (rv) {
	_ipmi_mc_put(mc);
	goto out_err;
    }
    info->got_failed = 0;
    return LOCKED_LIST_ITER_CONTINUE;

 out_err:
    info->got_failed = 1;
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
iterate_control_handler(void *cb_data, void *item1, void *item2)
{
    iterate_control_info_t *info = cb_data;
    ipmi_control_t         *control = item1;
    ipmi_mc_t             *mc = ipmi_control_get_mc(control);

    if (info->got_failed)
	goto out;
    info->handler(info->ent, item1, info->cb_data);
    _ipmi_control_put(control);
    _ipmi_mc_put(mc);
 out:
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_entity_iterate_controls(ipmi_entity_t                  *ent,
			     ipmi_entity_iterate_control_cb handler,
			     void                           *cb_data)
{
    iterate_control_info_t info = { ent, handler, cb_data };

    CHECK_ENTITY_LOCK(ent);

    locked_list_iterate_prefunc(ent->controls, iterate_control_prefunc,
				iterate_control_handler, &info);
}

/***********************************************************************
 *
 * Handling of sensor data records for entities.
 *
 **********************************************************************/

static int
decode_ear(ipmi_sdr_t *sdr, dlr_info_t *info, ipmi_mc_t *mc)
{
    int i;
    int pos;

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
decode_drear(ipmi_sdr_t *sdr, dlr_info_t *info, ipmi_mc_t *mc)
{
    int i;
    int pos;

    info->type = IPMI_ENTITY_DREAR;
    info->output_handler = NULL;

    info->entity_id = sdr->data[0];
    info->entity_instance = sdr->data[1];

    if (sdr->data[1] >= 0x60) {
	info->device_num.channel = sdr->data[3] >> 4;
	info->device_num.address = sdr->data[2];
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
    ipmi_sdr_t   sdr;
    unsigned int len;
    dlr_info_t  *info = &ent->info;

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
decode_gdlr(ipmi_sdr_t *sdr, dlr_info_t *info, ipmi_mc_t *mc)
{
    unsigned char *str;
    int           rv;

    info->type = IPMI_ENTITY_GENERIC;
    info->output_handler = gdlr_output;

    if (sdr->data[8] >= 0x60) {
	info->device_num.channel = (sdr->data[2] >> 5) | ((sdr->data[1] << 3)
							  & 0x08);
	info->device_num.address = sdr->data[0];
    } else {
	info->device_num.channel = 0;
        info->device_num.address = 0;
    }

    info->access_address = sdr->data[0];
    info->slave_address = sdr->data[1];
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
    str = sdr->data + 10;
    rv = ipmi_get_device_string(&str, sdr->length-10,
				info->id, IPMI_STR_SDR_SEMANTICS, 0,
				&info->id_type, ENTITY_ID_LEN, &info->id_len);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(decode_gdlr):"
		 " Error getting device ID string from SDR record %d: %d,"
		 " this entity will be named **INVALID**",
		 MC_NAME(mc), sdr->record_id, rv);
	strncpy(info->id, "**INVALID**", sizeof(info->id));
	info->id_len = strlen(info->id);
	info->id_type = IPMI_ASCII_STR;
	rv = 0;
    }

    return rv;
}

static int
frudlr_output(ipmi_entity_t *ent, ipmi_sdr_info_t *sdrs, void *cb_data)
{
    ipmi_sdr_t   sdr;
    unsigned int len;
    dlr_info_t   *info = &ent->info;

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
decode_frudlr(ipmi_sdr_t *sdr, dlr_info_t *info, ipmi_mc_t *mc)
{
    unsigned char *str;
    int           rv;

    info->type = IPMI_ENTITY_FRU;
    info->output_handler = frudlr_output;

    if (sdr->data[8] >= 0x60) {
       info->device_num.channel = sdr->data[3] >> 4;
       info->device_num.address = sdr->data[0];
    } else {
       info->device_num.channel = 0;
       info->device_num.address = 0;
    }

    info->access_address = sdr->data[0];
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
    str = sdr->data + 10;
    rv = ipmi_get_device_string(&str,
				sdr->length-10,
				info->id, IPMI_STR_SDR_SEMANTICS, 0,
				&info->id_type, ENTITY_ID_LEN, &info->id_len);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(decode_frudlr):"
		 " Error getting device ID string from SDR record %d: %d,"
		 " this entity will be named **INVALID**",
		 MC_NAME(mc), sdr->record_id, rv);
	strncpy(info->id, "**INVALID**", sizeof(info->id));
	info->id_len = strlen(info->id);
	info->id_type = IPMI_ASCII_STR;
	rv = 0;
    }

    return rv;
}

static int
mcdlr_output(ipmi_entity_t *ent, ipmi_sdr_info_t *sdrs, void *cb_data)
{
    ipmi_sdr_t   sdr;
    unsigned int len;
    dlr_info_t   *info = &ent->info;

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
    sdr.data[7] = ent->key.entity_id;
    sdr.data[8] = ent->key.entity_instance;
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
decode_mcdlr(ipmi_sdr_t *sdr, dlr_info_t *info, ipmi_mc_t *mc)
{
    unsigned char *data;
    unsigned char *str;
    int           rv;


    info->type = IPMI_ENTITY_MC;
    info->output_handler = mcdlr_output;

    if (sdr->data[8] >= 0x60) {
	info->device_num.channel = sdr->data[1] & 0xf;
	info->device_num.address = sdr->data[0];
    } else {
	info->device_num.channel = 0;
	info->device_num.address = 0;
    }

    data = sdr->data;
    info->slave_address = *data;
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
    str = sdr->data + 10;
    rv = ipmi_get_device_string(&str,
				sdr->length-10,
				info->id, IPMI_STR_SDR_SEMANTICS, 0,
				&info->id_type, ENTITY_ID_LEN, &info->id_len);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(decode_frudlr):"
		 " Error getting device ID string from SDR record %d: %d,"
		 " this entity will be named **INVALID**",
		 MC_NAME(mc), sdr->record_id, rv);
	strncpy(info->id, "**INVALID**", sizeof(info->id));
	info->id_len = strlen(info->id);
	info->id_type = IPMI_ASCII_STR;
	rv = 0;
    }

    /* Make sure the FRU fetch stuff works. */
    info->access_address = info->slave_address;
    info->fru_device_id = 0;
    info->is_logical_fru = 1;
    info->private_bus_id = 0;

    return rv;
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
	new_found = ipmi_mem_alloc(sizeof(entity_found_t) * new_length);
	if (!new_found) {
	    ipmi_mem_free(new_dlrs);
	    return ENOMEM;
	}
	if (infos->dlrs) {
	    memcpy(new_dlrs, infos->dlrs, sizeof(dlr_info_t *) * infos->len);
	    memcpy(new_found, infos->found,
		   sizeof(entity_found_t) * infos->len);
	    ipmi_mem_free(infos->dlrs);
	    ipmi_mem_free(infos->found);
	}
	memset(new_found + infos->len,
	       0,
	       sizeof(entity_found_t) * (new_length - infos->len));
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
    unsigned int i;

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
    unsigned int i;

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
add_child_ent_to_found(entity_found_t *found,
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

/* Find all the entities for unfound dlrs and make sure there is room
   in the proper child and parent lists for the new
   parents/children. */
static int
fill_in_entities(ipmi_entity_info_t  *ents,
		 entity_sdr_info_t   *infos)
{
    entity_found_t      *found;
    unsigned int        i, j;
    int                 rv;
    ipmi_entity_t       *child;
    ipmi_entity_t       *ent;

    for (i=0; i<infos->next; i++) {
	found = infos->found+i;

	if (found->found)
	    continue;

	if (infos->dlrs[i]->entity_id) {
	    _ipmi_domain_entity_lock(ents->domain);
	    rv = entity_add(ents, infos->dlrs[i]->device_num,
			    infos->dlrs[i]->entity_id,
			    infos->dlrs[i]->entity_instance,
			    infos->dlrs[i]->output_handler, NULL,
			    &found->ent);
	    if (rv)
		goto out_err;
	} else {
	    /* If entity id is null, it should be ignored. */
	    found->ent = NULL;
	    continue;
	}

	if ((infos->dlrs[i]->type != IPMI_ENTITY_EAR)
	    && (infos->dlrs[i]->type != IPMI_ENTITY_DREAR))
	    continue;

	/* Find the first previous unfound entry that has the same
	   entity as me to add the contained entities to.  This means
	   that every unfound entity will only have one set of
	   contained entities in the cent array even if it has
	   multiple DLRs.  It will always be in the first entry. */
	if (i > 0) {
	    j = i - 1;
	    ent = found->ent;
	    for (; ent == (infos->found+j)->ent; j--) {
		if ((infos->found+j)->found)
		    goto next_ent;
		if ((infos->dlrs[j]->type != IPMI_ENTITY_EAR)
		    && (infos->dlrs[j]->type != IPMI_ENTITY_DREAR))
		    goto next_ent;
		found = infos->found+j;

		/* Since this is an EAR and we are putting it's entries in
		   another place, ignore this one. */
		(infos->found+i)->found = 1;
	    next_ent:
		if (j == 0)
		    break;
	    }
	}

	if (infos->dlrs[i]->is_ranges) {
	    for (j=0; j<4; j+=2) {
		dlr_ref_t *cent1 = infos->dlrs[i]->contained_entities+j;
		dlr_ref_t *cent2 = infos->dlrs[i]->contained_entities+j+1;
		int k;
		if (cent1->entity_id == 0)
		    continue;
		for (k=cent1->entity_instance; k<=cent2->entity_instance; k++){
		    _ipmi_domain_entity_lock(ents->domain);
		    rv = entity_add(ents, cent1->device_num,
				    cent1->entity_id, k,
				    NULL, NULL, &child);
		    if (rv)
			goto out_err;
		    rv = add_child_ent_to_found(found, child);
		    if (rv) {
			_ipmi_entity_put(child);
			goto out_err;
		    }
		}
	    }
	} else {
	    for (j=0; j<4; j++) {
		dlr_ref_t *cent = infos->dlrs[i]->contained_entities+j;
		if (cent->entity_id == 0)
		    continue;
		_ipmi_domain_entity_lock(ents->domain);
		rv = entity_add(ents, cent->device_num,
				cent->entity_id, cent->entity_instance,
				NULL, NULL, &child);
		if (rv)
		    return rv;
		rv = add_child_ent_to_found(found, child);
		if (rv) {
		    _ipmi_entity_put(child);
		    goto out_err;
		}
	    }
	}
    }

    return 0;

 out_err:
    return rv;
}

static void
put_entities(entity_sdr_info_t *infos)
{
    entity_found_t      *found;
    unsigned int        i, j;

    for (i=0; i<infos->next; i++) {
	found = infos->found+i;

	if (found->ent)
	    _ipmi_entity_put(found->ent);

	/* Still put the entity even if found, as it was refcounted by
	   looking it up. */
	if (found->found)
	    continue;

	for (j=0; j<found->cent_next; j++)
	    _ipmi_entity_put(found->cent[j]);
    }
}

static int
cmp_dlr(const dlr_info_t *d1, const dlr_info_t *d2)
{

    if (d1->entity_id < d2->entity_id)
	return -1;
    if (d1->entity_id > d2->entity_id)
	return 1;
    if (d1->entity_instance < d2->entity_instance)
	return -1;
    if (d1->entity_instance > d2->entity_instance)
	return 1;
    return memcmp(d1, d2, sizeof(dlr_info_t));
}

static int
cmp_dlr_qsort(const void *a, const void *b)
{
    const dlr_info_t *d1 = *((dlr_info_t **) a);
    const dlr_info_t *d2 = *((dlr_info_t **) b);

    return cmp_dlr(d1, d2);
}

struct locked_list_entry_s
{
    locked_list_entry_t *next;
};

int
ipmi_entity_scan_sdrs(ipmi_domain_t      *domain,
		      ipmi_mc_t          *mc,
		      ipmi_entity_info_t *ents,
		      ipmi_sdr_info_t    *sdrs)
{
    unsigned int        count;
    unsigned int        i, j;
    int                 rv;
    entity_sdr_info_t   infos;
    entity_sdr_info_t   *old_infos;
    entity_found_t      *found;
    locked_list_entry_t *entries = NULL, *entry;

    memset(&infos, 0, sizeof(infos));

    rv = ipmi_get_sdr_count(sdrs, &count);
    if (rv)
	return rv;

    for (i=0; i<count; i++) {
	ipmi_sdr_t sdr;
	dlr_info_t dlr;

	rv = ipmi_get_sdr_by_index(sdrs, i, &sdr);
	if (rv)
	    goto out_err;

	memset(&dlr, 0, sizeof(dlr));

	switch (sdr.type) {
	    case IPMI_SDR_ENITY_ASSOCIATION_RECORD:
		rv = decode_ear(&sdr, &dlr, mc);
		if (!rv)
		    rv = add_sdr_info(&infos, &dlr);
		break;

	    case IPMI_SDR_DR_ENITY_ASSOCIATION_RECORD:
		rv = decode_drear(&sdr, &dlr, mc);
		if (!rv)
		    rv = add_sdr_info(&infos, &dlr);
		break;

	    case IPMI_SDR_GENERIC_DEVICE_LOCATOR_RECORD:
		rv = decode_gdlr(&sdr, &dlr, mc);
		if (!rv)
		    rv = add_sdr_info(&infos, &dlr);
		break;

	    case IPMI_SDR_FRU_DEVICE_LOCATOR_RECORD:
		rv = decode_frudlr(&sdr, &dlr, mc);
		if (!rv)
		    rv = add_sdr_info(&infos, &dlr);
		break;

	    case IPMI_SDR_MC_DEVICE_LOCATOR_RECORD:
		rv = decode_mcdlr(&sdr, &dlr, mc);
		if (!rv)
		    rv = add_sdr_info(&infos, &dlr);
		break;
	}
	if (rv)
	    goto out_err;
    }

    /* The domain and mc should be used, and there should only be one
       thread performing this operation (at least per MC), so it is
       safe to do this without locks.  Note that we do *NOT* want
       locks while we are filling in the entities, as they may add
       entities and cause added callbacks. */

    old_infos = _ipmi_get_sdr_entities(domain, mc);
    if (!old_infos) {
	old_infos = ipmi_mem_alloc(sizeof(*old_infos));
	if (!old_infos) {
	    rv = ENOMEM;
	    goto out_err_unlock_nocleaninfos;
	}
	memset(old_infos, 0, sizeof(*old_infos));
	old_infos->ents = ents;
	_ipmi_set_sdr_entities(domain, mc, old_infos);
    }

    /* Clear out all the temporary found information we use for
       scanning. */
    if (old_infos->next > 0) 
	memset(old_infos->found, 0, sizeof(entity_found_t) * old_infos->next);
    if (infos.next > 0)
	memset(infos.found, 0, sizeof(entity_found_t) * infos.next);

    /* Sort the DLRs by parent entity id/entity instance/rest of data.
       This makes the rest of the operations here O(n) instead of
       O(n^2). */
    qsort(infos.dlrs, infos.next, sizeof(dlr_info_t *), cmp_dlr_qsort);

    /* For every item in the new array, try to find it in the old
       array.  Both arrays are sorted by entity id/entity
       instance/rest of data, so this is O(n). */
    i=0;
    j=0;
    while ((i < infos.next) && (j < old_infos->next)) {
	int c = cmp_dlr(infos.dlrs[i], old_infos->dlrs[j]);
	if (c == 0) {
	    infos.found[i].found = 1;
	    old_infos->found[j].found = 1;
	    i++;
	    j++;
	} else if (c < 0)
	    i++;
	else
	    j++;
    }

    /* For every item in the array that is not found, make sure
       the entities exists and we have them. */
    rv = fill_in_entities(ents, &infos);
    if (rv)
	goto out_err_unlock;
    rv = fill_in_entities(ents, old_infos);
    if (rv)
	goto out_err_unlock;

    /* Now ensure space is in each parent for all the children and
       each child's parent entry. */
    for (i=0; i<infos.next; i++) {
	if (infos.found[i].found)
	    continue;

	/* Allocate space for all the children and parents. */
	for (j=0; j<(infos.found[i].cent_next*2); j++) {
	    entry = locked_list_alloc_entry();
	    if (!entry) {
		rv = ENOMEM;
		goto out_err_unlock;
	    }
	    entry->next = entries;
	    entries = entry;
	}
    }

    /* After this, the operation cannot fail, since we have gotten all
       the objects we need and we have allocated enough entries for
       the parent and child lists. */

    _ipmi_domain_entity_lock(domain);
    rv = 0;

    /* Destroy all the old information that was not in the new version
       of the SDRs. */
    for (i=0; i<old_infos->next; i++) {
	found = old_infos->found + i;
	if (found->found)
	    continue;
	if (!found->ent)
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
		ipmi_entity_remove_child_internal(found->ent, found->cent[j]);
	}
    }

    /* Add all the new information that was in the new SDRs. */
    for (i=0; i<infos.next; i++) {
	found = infos.found + i;
	if (found->found)
	    continue;
	if (!found->ent)
	    continue;

	if ((infos.dlrs[i]->type != IPMI_ENTITY_EAR)
	    && (infos.dlrs[i]->type != IPMI_ENTITY_DREAR))
	{
	    uint8_t ipmb    = 0xff;
	    int     channel = -1;

	    found->ent->changed = 1;

	    /* A real DLR, increment the refcount, and copy the info. */
	    found->ent->ref_count++;

	    /* Don't fetch FRU information until present. */

	    /* Set up the MC information for the device. */
	    if (infos.dlrs[i]->type == IPMI_ENTITY_FRU) {
		channel = infos.dlrs[i]->channel;
		ipmb = infos.dlrs[i]->slave_address;
		memcpy(&found->ent->pending_info, infos.dlrs[i],
		       sizeof(dlr_info_t));
		found->ent->pending_info_ready = 1;		
	    }
	    else if (infos.dlrs[i]->type == IPMI_ENTITY_MC)
	    {
		if (infos.dlrs[i]->FRU_inventory_device) {
		    channel = infos.dlrs[i]->channel;
		    ipmb = infos.dlrs[i]->access_address;
		    memcpy(&found->ent->pending_info, infos.dlrs[i],
			   sizeof(dlr_info_t));
		    found->ent->pending_info_ready = 1;		
		} else {
		    if ((!found->ent->info.FRU_inventory_device)
			&& (!found->ent->pending_info.FRU_inventory_device))
		    {
			/* We prefer to only keep the information from the
			   FRU inventory device MCDLR. */
			memcpy(&found->ent->pending_info, infos.dlrs[i],
			       sizeof(dlr_info_t));
			found->ent->pending_info_ready = 1;		
		    }

		    /* Go ahead and scan the MC if we don't do
		       anything else with this data. */
		    ipmi_start_ipmb_mc_scan(domain, infos.dlrs[i]->channel,
					    infos.dlrs[i]->access_address,
					    infos.dlrs[i]->access_address,
					    NULL, NULL);
		}
	    } else {
		memcpy(&found->ent->pending_info, infos.dlrs[i],
		       sizeof(dlr_info_t));
		found->ent->pending_info_ready = 1;		
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
		    _ipmi_mc_put(mc);
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
			_ipmi_mc_use(mc);
			found->ent->frudev_present = 1;
			found->ent->frudev_active = ipmi_mc_is_active(mc);
			found->ent->frudev_mc = mc;
			found->ent->presence_possibly_changed = 1;
		    }
		    _ipmi_mc_put(mc);
		}
	    }
	} else {
	    /* It's an EAR, so handling adding the children. */
	    for (j=0; j<found->cent_next; j++) {
		entry = entries;
		entries = entry->next->next;
		add_child(found->ent, found->cent[j], entry, entry->next);
		found->ent->changed = 1;
		found->cent[j]->changed = 1;
	    }
	}
    }

    infos.ents = ents;

    _ipmi_domain_entity_unlock(domain);

    put_entities(&infos);
    put_entities(old_infos);

    destroy_sdr_info(old_infos);
    cleanup_sdr_info(&infos);
    memcpy(old_infos, &infos, sizeof(infos));

 out:
    while (entries) {
	entry = entries;
	entries = entry->next;
	locked_list_free_entry(entry);
    }
    return rv;

 out_err_unlock:
    put_entities(&infos);
    put_entities(old_infos);

 out_err_unlock_nocleaninfos:
    _ipmi_domain_entity_unlock(domain);

 out_err:
    destroy_sdr_info(&infos);
    goto out;
}

int
ipmi_sdr_entity_destroy(void *info)
{
    entity_sdr_info_t   *infos = info;
    unsigned int        i, j;
    int                 rv;
    ipmi_entity_t       *ent, *child;

    for (i=0; i<infos->next; i++) {
	_ipmi_domain_entity_lock(infos->ents->domain);
	rv = entity_find(infos->ents, infos->dlrs[i]->device_num,
			 infos->dlrs[i]->entity_id,
			 infos->dlrs[i]->entity_instance,
			 &ent);
	_ipmi_domain_entity_unlock(infos->ents->domain);
	if (rv)
	    continue;

	if ((infos->dlrs[i]->type != IPMI_ENTITY_EAR)
	    && (infos->dlrs[i]->type != IPMI_ENTITY_DREAR))
	{
	    if (ent->frudev_present) {
		ipmi_mc_t *mc = ent->frudev_mc;
		_ipmi_domain_mc_lock(infos->ents->domain);
		_ipmi_mc_get(mc);
		_ipmi_domain_mc_unlock(infos->ents->domain);
		ipmi_mc_remove_active_handler(ent->frudev_mc,
					      entity_mc_active, ent);
		_ipmi_mc_release(ent->frudev_mc);
		_ipmi_mc_put(mc);
		ent->frudev_mc = NULL;
		ent->frudev_present = 0;
	    }

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
			_ipmi_domain_entity_lock(infos->ents->domain);
			rv = entity_find(infos->ents, cent1->device_num,
					 cent1->entity_id, k,
					 &child);
			_ipmi_domain_entity_unlock(infos->ents->domain);
			if (rv)
			    continue;

			ipmi_entity_remove_child(ent, child);
			_ipmi_entity_put(child);
		    }
		}
	    } else {
		for (j=0; j<4; j++) {
		    dlr_ref_t *cent = infos->dlrs[i]->contained_entities+j;
		    if (cent->entity_id == 0)
			continue;
		    _ipmi_domain_entity_lock(infos->ents->domain);
		    rv = entity_find(infos->ents, cent->device_num,
				     cent->entity_id, cent->entity_instance,
				     &child);
		    _ipmi_domain_entity_unlock(infos->ents->domain);
		    if (rv)
			continue;
		    ipmi_entity_remove_child(ent, child);
		    _ipmi_entity_put(child);
		}
	    }
	    ipmi_detect_entity_presence_change(ent, 0);
	}
	_ipmi_entity_put(ent);
    }

    destroy_sdr_info(info);
    ipmi_mem_free(info);

    return 0;
}

/***********************************************************************
 *
 * SDR output code.
 *
 **********************************************************************/

#if SAVE_SDR_CODE_ENABLE
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

    if (ilist_empty(ent->child_entities))
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

    ilist_sort(ent->child_entities, cmp_entities);

    ilist_init_iter(&iter, ent->child_entities);
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
#endif

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

void
ipmi_entity_set_physical_slot_num(ipmi_entity_t *ent,
				  int present,
				  unsigned int val)
{
    CHECK_ENTITY_LOCK(ent);

    ent->slot_num = val;
    ent->slot_num_present = present;
}

int
ipmi_entity_get_physical_slot_num(ipmi_entity_t *ent, unsigned int *slot_num)
{
    CHECK_ENTITY_LOCK(ent);

    if (ent->slot_num_present) {
        *slot_num = ent->slot_num;
	return 0;
    }
    else
	return ENOSYS;
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
ipmi_entity_get_mc_id(ipmi_entity_t *ent, ipmi_mcid_t *mc_id)
{
    ipmi_ipmb_addr_t sa;
    ipmi_mc_t        *mc;

    if ((ent->info.type != IPMI_ENTITY_MC)
	&& (ent->info.type != IPMI_ENTITY_GENERIC))
    {
	return ENOSYS;
    }

    sa.addr_type = IPMI_IPMB_ADDR_TYPE;
    sa.channel = ent->info.channel;
    sa.slave_addr = ent->info.slave_address;
    sa.lun = ent->info.lun;

    mc = _ipmi_find_mc_by_addr(ent->domain, (ipmi_addr_t *) &sa, sizeof(sa));
    if (!mc)
	return ENODEV;

    *mc_id = ipmi_mc_convert_to_id(mc);
    _ipmi_mc_put(mc);

    return 0;
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
    int rv = 0;
    CHECK_ENTITY_LOCK(ent);

    ent_lock(ent);
    if (ent->info.type == IPMI_ENTITY_FRU)
	rv = 1;
    if ((ent->info.type == IPMI_ENTITY_MC) && (ent->info.FRU_inventory_device))
	rv = 1;
    ent_unlock(ent);
    return rv;
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

    return ent->key.entity_id;
}

int
ipmi_entity_get_entity_instance(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->key.entity_instance;
}

int
ipmi_entity_get_device_channel(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->key.device_num.channel;
}

int
ipmi_entity_get_device_address(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->key.device_num.address;
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

    if (ent->info.id_type == IPMI_ASCII_STR)
	return ent->info.id_len+1;
    else
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

    ent_lock(ent);
    if ((int)ent->info.id_len > length)
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
    ent_unlock(ent);

    return clen;
}

void
ipmi_entity_set_id(ipmi_entity_t *ent, char *id,
		   enum ipmi_str_type_e type, int length)
{
    CHECK_ENTITY_LOCK(ent);

    if (length > ENTITY_ID_LEN)
	length = ENTITY_ID_LEN;
    
    ent_lock(ent);
    memcpy(ent->info.id, id, length);
    ent->info.id_type = type;
    ent->info.id_len = length;
    ent_unlock(ent);
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

    return locked_list_num_entries(ent->parent_entities) != 0;
}

int
ipmi_entity_get_is_parent(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return locked_list_num_entries(ent->child_entities) != 0;
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

const char *
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

static int
iterate_entity_handler(void *cb_data, void *item1, void *item2)
{
    iterate_entity_info_t *info = cb_data;
    ipmi_entity_t         *ent = item1;

    info->handler(ent, info->cb_data);
    _ipmi_entity_put(ent);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_entities_iterate_entities(ipmi_entity_info_t              *ents,
			       ipmi_entities_iterate_entity_cb handler,
			       void                            *cb_data)
{
    iterate_entity_info_t info = { ents, handler, cb_data };
    locked_list_iterate_prefunc(ents->entities, iterate_entity_prefunc,
				iterate_entity_handler, &info);
}

ipmi_entity_id_t
ipmi_entity_convert_to_id(ipmi_entity_t *ent)
{
    ipmi_entity_id_t val;

    CHECK_ENTITY_LOCK(ent);

    val.domain_id = ent->domain_id;
    val.entity_id = ent->key.entity_id;
    val.entity_instance = ent->key.entity_instance;
    val.channel = ent->key.device_num.channel;
    val.address = ent->key.device_num.address;
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

    device_num.channel = info->id.channel;
    device_num.address = info->id.address;
    _ipmi_domain_entity_lock(domain);
    info->err = entity_find(ipmi_domain_get_entities(domain),
			    device_num,
			    info->id.entity_id,
			    info->id.entity_instance,
			    &ent); 
    _ipmi_domain_entity_unlock(domain);

    if (!info->ignore_seq && !info->err) {
	if (ent->seq != info->id.seq) {
	    info->err = EINVAL;
	    _ipmi_entity_put(ent);
	}
    }
    if (!info->err) {
	info->handler(ent, info->cb_data);
	_ipmi_entity_put(ent);
    }
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
ipmi_entity_id_is_invalid(const ipmi_entity_id_t *id)
{
    return (id->domain_id.domain == NULL);
}


#ifdef IPMI_CHECK_LOCKS
void
__ipmi_check_entity_lock(const ipmi_entity_t *entity)
{
    if (!entity)
	return;

    if (!DEBUG_LOCKS)
	return;

    if (entity->usecount == 0)
	ipmi_report_lock_error(entity->os_hnd,
			       "entity not locked when it should have been");
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
    if (locked_list_add(ent->fru_handlers, handler, cb_data))
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
    if (locked_list_remove(ent->fru_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_entity_add_fru_update_handler_cl(ipmi_entity_t         *ent,
				      ipmi_entity_fru_cl_cb handler,
				      void                  *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_add(ent->fru_handlers_cl, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_fru_update_handler_cl(ipmi_entity_t         *ent,
					 ipmi_entity_fru_cl_cb handler,
					 void                  *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_remove(ent->fru_handlers_cl, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

typedef struct fru_handler_s
{
    enum ipmi_update_e op;
    ipmi_entity_t      *entity;
} fru_handler_t;

static int
call_fru_handler(void *cb_data, void *item1, void *item2)
{
    fru_handler_t      *info = cb_data;
    ipmi_entity_fru_cb handler = item1;

    handler(info->op, info->entity, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
_ipmi_entity_call_fru_handlers(ipmi_entity_t *ent, enum ipmi_update_e op)
{
    fru_handler_t info;

    info.op = op;
    info.entity = ent;
    locked_list_iterate(ent->fru_handlers, call_fru_handler, &info);
}

typedef struct fru_ent_info_s
{
    ipmi_entity_id_t   ent_id;
    ipmi_entity_ptr_cb done;
    void               *cb_data;
    ipmi_fru_t         *fru;
    int                err;
} fru_ent_info_t;

static void
fru_fetched_ent_cb(ipmi_entity_t *ent, void *cb_data)
{
    fru_ent_info_t *info = cb_data;

    if (!info->err) {
	enum ipmi_update_e op;
	ipmi_fru_t         *ofru = ent->fru;

	ent->fru = info->fru;
	if (ofru) {
	    op = IPMI_CHANGED;
	    ipmi_fru_destroy_internal(ofru, NULL, NULL);
	} else {
	    op = IPMI_ADDED;
	}

	_ipmi_entity_call_fru_handlers(ent, op);
    } else {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(fru_fetched_ent_cb):"
		 "Error fetching entity %d.%d FRU: %x",
		 ENTITY_NAME(ent),
		 ent->key.entity_id, ent->key.entity_instance, info->err);
	if ((ent->fru) && (info->fru))
	    /* Keep the old FRU on errors. */
	    ipmi_fru_destroy_internal(info->fru, NULL, NULL);
	else
	    /* Keep it if we got it, it might have some useful
	       information. */
	    ent->fru = info->fru;
	_ipmi_entity_call_fru_handlers(ent, IPMI_CHANGED);
    }

    if (info->done)
	info->done(ent, info->cb_data);
}

static void
fru_fetched_handler(ipmi_domain_t *domain, ipmi_fru_t *fru,
		    int err, void *cb_data)
{
    fru_ent_info_t *info = cb_data;
    int            rv;

    info->fru = fru;
    info->err = err;

    rv = ipmi_entity_pointer_cb(info->ent_id, fru_fetched_ent_cb, info);
    if (rv) {
	/* If we can't put the fru someplace, just destroy it. */
	ipmi_fru_destroy_internal(fru, NULL, NULL);
	if (info->done)
	    info->done(NULL, info->cb_data);
    }

    ipmi_mem_free(info);
    if (domain)
	_ipmi_put_domain_fully_up(domain, "fru_fetched_handler");
}

int
ipmi_entity_fetch_frus_cb(ipmi_entity_t      *ent,
			  ipmi_entity_ptr_cb done,
			  void               *cb_data)
{
    fru_ent_info_t   *info;
    int              rv;

    if (! ipmi_option_FRUs(ent->domain))
	return ENOSYS;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->ent_id = ipmi_entity_convert_to_id(ent);
    info->done = done;
    info->cb_data = cb_data;

    /* fetch the FRU information. */
    _ipmi_get_domain_fully_up(ent->domain, "ipmi_entity_fetch_frus_cb");
    rv = ipmi_fru_alloc_notrack(ent->domain,
				ent->info.is_logical_fru,
				ent->info.access_address,
				ent->info.fru_device_id,
				ent->info.lun,
				ent->info.private_bus_id,
				ent->info.channel,
				IPMI_FRU_ALL_AREA_MASK, 
				fru_fetched_handler,
				info,
				NULL);
    if (rv) {
	ipmi_mem_free(info);
	ipmi_log(IPMI_LOG_WARNING,
		 "%sentity.c(ipmi_entity_fetch_frus_cb):"
		 " Unable to allocate the FRU: %x",
		 ENTITY_NAME(ent), rv);
	_ipmi_put_domain_fully_up(ent->domain, "ipmi_entity_fetch_frus_cb");
    }

    return rv;
}

int
ipmi_entity_fetch_frus(ipmi_entity_t *ent)
{
    return ipmi_entity_fetch_frus_cb(ent, NULL, NULL);
}

ipmi_fru_t *
ipmi_entity_get_fru(ipmi_entity_t *ent)
{
    CHECK_ENTITY_LOCK(ent);

    return ent->fru;
}

void
_ipmi_entity_set_fru(ipmi_entity_t *ent, ipmi_fru_t *fru)
{
    CHECK_ENTITY_LOCK(ent);

    if (ent->fru)
	ipmi_fru_destroy_internal(ent->fru, NULL, NULL);
    ent->fru = fru;
}

/***************************************************************************
 *
 * Hot swap
 *
 ***************************************************************************/

int
ipmi_entity_set_hot_swappable(ipmi_entity_t *ent, int val)
{
    ent->hot_swappable = val;

    /* Make sure the user knows of the change. */
    ent->changed = 1;

    return 0;
}

int
ipmi_entity_hot_swappable(ipmi_entity_t *ent)
{
    return ent->hot_swappable;
}

int
ipmi_entity_set_supports_managed_hot_swap(ipmi_entity_t *ent, int val)
{
    ent->supports_managed_hot_swap = val;

    /* Make sure the user knows of the change. */
    ent->changed = 1;

    return 0;
}

int
ipmi_entity_supports_managed_hot_swap(ipmi_entity_t *ent)
{
    return ent->supports_managed_hot_swap;
}

int
ipmi_entity_add_hot_swap_handler(ipmi_entity_t           *ent,
				 ipmi_entity_hot_swap_cb handler,
				 void                    *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_add(ent->hot_swap_handlers, handler, cb_data))
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
    if (locked_list_remove(ent->hot_swap_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_entity_add_hot_swap_handler_cl(ipmi_entity_t              *ent,
				    ipmi_entity_hot_swap_cl_cb handler,
				    void                       *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_add(ent->hot_swap_handlers_cl, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_entity_remove_hot_swap_handler_cl(ipmi_entity_t              *ent,
				       ipmi_entity_hot_swap_cl_cb handler,
				       void                       *cb_data)
{
    CHECK_ENTITY_LOCK(ent);
    if (locked_list_remove(ent->hot_swap_handlers_cl, handler, cb_data))
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

static int
call_hot_swap_handler(void *cb_data, void *item1, void *item2)
{
    hot_swap_handler_info_t *info = cb_data;
    ipmi_entity_hot_swap_cb handler = item1;
    int                     handled;

    handled = handler(info->ent, info->last_state, info->curr_state,
		      item2, *(info->event));
    if (handled != IPMI_EVENT_NOT_HANDLED) {
	if (info->handled != IPMI_EVENT_HANDLED)
	    /* Allow handled to override handled_pass, but not the
	       other way. */
	    info->handled = handled;
	if (handled == IPMI_EVENT_HANDLED)
	    *(info->event) = NULL;
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_entity_call_hot_swap_handlers(ipmi_entity_t             *ent,
				   enum ipmi_hot_swap_states last_state,
				   enum ipmi_hot_swap_states curr_state,
				   ipmi_event_t              **event,
				   int                       *handled)
{
    hot_swap_handler_info_t info;

    info.ent = ent;
    info.last_state = last_state;
    info.curr_state = curr_state;
    info.event = event;
    if (handled)
	info.handled = *handled;
    else
	info.handled = IPMI_EVENT_NOT_HANDLED;
    locked_list_iterate(ent->hot_swap_handlers, call_hot_swap_handler, &info);
    if (handled)
	*handled = info.handled;
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
ipmi_entity_supports_auto_activate_time(ipmi_entity_t *ent)
{
    return (ent->hot_swappable && ent->hs_cb.get_auto_activate);
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
ipmi_entity_supports_auto_deactivate_time(ipmi_entity_t *ent)
{
    return (ent->hot_swappable && ent->hs_cb.get_auto_activate);
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
ipmi_entity_set_activation_requested(ipmi_entity_t  *ent,
				     ipmi_entity_cb done,
				     void           *cb_data)
{
    if (!ent->hot_swappable)
	return ENOSYS;
    if (!ent->hs_cb.activate)
	return ENOSYS;
    return ent->hs_cb.set_activation_requested(ent, done, cb_data);
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
	ent_lock(ent);
	set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVE, NULL);
	ent_unlock(ent);
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
	ent_lock(ent);
	set_hot_swap_state(ent, IPMI_HOT_SWAP_INACTIVE, NULL);
	ent_unlock(ent);
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
	ent_lock(ent);
	set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVE, NULL);
	ent_unlock(ent);
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
	ent_lock(ent);
	set_hot_swap_state(ent, IPMI_HOT_SWAP_INACTIVE, NULL);
	ent_unlock(ent);
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

    ent_lock(ent);
    if (ent->hot_swap_state == IPMI_HOT_SWAP_ACTIVATION_REQUESTED) {
	if (ent->hot_swap_power) {
	    if (handler == NULL) {
		cb = hot_swap_power_on;
		cb_data = ent;
	    } else {
		info = ipmi_mem_alloc(sizeof(*info));
		if (!info) {
		    rv = ENOMEM;
		    goto out;
		}
		cb = hot_swap_power_on_cb;
		info->ent = ent;
		info->handler = handler;
		info->cb_data = cb_data;
		cb_data = info;
	    }

	    val = 1;
	    ent_unlock(ent);
	    rv = ipmi_control_id_set_val(ent->hot_swap_power_id,
				         &val,
				         cb,
				         cb_data);
	    ent_lock(ent);
	    if (!rv)
		set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVATION_IN_PROGRESS,
				   NULL);
	    else if (info)
		ipmi_mem_free(info);
	}
    } else {
	rv = EAGAIN;
    }
 out:
    ent_unlock(ent);

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
    ent_timer_info_t *info = cb_data;
    ipmi_entity_id_t entity_id;

    ipmi_lock(info->lock);
    if (info->destroyed) {
	ipmi_unlock(info->lock);
	info->os_hnd->free_timer(info->os_hnd, info->timer);
	ipmi_mem_free(info);
	return;
    }
    info->running = 0;
    entity_id = ipmi_entity_convert_to_id(info->entity);
    ipmi_unlock(info->lock);

    ipmi_entity_pointer_cb(entity_id, hot_swap_act_cb, NULL);
}

static int
hot_swap_deact(ipmi_entity_t *ent, ipmi_entity_cb handler, void *cb_data)
{
    int                val;
    int                rv = ENOSYS;
    ipmi_control_op_cb cb;
    power_cb_info_t    *info;

    ent_lock(ent);
    if (ent->hot_swap_state == IPMI_HOT_SWAP_DEACTIVATION_REQUESTED) {
	if (ent->hot_swap_power) {
	    if (handler == NULL) {
		cb = hot_swap_power_off;
		cb_data = ent;
	    } else {
		info = ipmi_mem_alloc(sizeof(*info));
		if (!info) {
		    rv = ENOMEM;
		    goto out;
		}
		cb = hot_swap_power_off_cb;
		info->ent = ent;
		info->handler = handler;
		info->cb_data = cb_data;
		cb_data = info;
	    }

	    val = 0;
	    ent_unlock(ent);
	    rv = ipmi_control_id_set_val(ent->hot_swap_power_id,
				         &val,
				         cb,
				         cb_data);
	    ent_lock(ent);
	    if (!rv)
		set_hot_swap_state(ent, IPMI_HOT_SWAP_DEACTIVATION_IN_PROGRESS,
				   NULL);
	}
    } else {
	rv = EAGAIN;
    }
 out:
    ent_unlock(ent);

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
    ent_timer_info_t *info = cb_data;
    ipmi_entity_id_t entity_id;

    ipmi_lock(info->lock);
    if (info->destroyed) {
	ipmi_unlock(info->lock);
	info->os_hnd->free_timer(info->os_hnd, info->timer);
	ipmi_mem_free(info);
	return;
    }
    info->running = 0;
    entity_id = ipmi_entity_convert_to_id(info->entity);
    ipmi_unlock(info->lock);

    ipmi_entity_pointer_cb(entity_id, hot_swap_deact_cb, NULL);
}

/* Must be called with the entity locked.  Note that it may release
   and reclaim the lock as part of its operation. */
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
	entity_start_timer(ent->hot_swap_act_info,
			   ent->hot_swap_act_timeout,
			   hot_swap_act_timeout);
	break;

    case IPMI_HOT_SWAP_ACTIVE:
	val = ent->hot_swap_ind_act;
	break;

    case IPMI_HOT_SWAP_DEACTIVATION_REQUESTED:
	val = ent->hot_swap_ind_req_deact;
	entity_start_timer(ent->hot_swap_deact_info,
			   ent->hot_swap_deact_timeout,
			   hot_swap_deact_timeout);
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

	rv = ipmi_control_id_set_val(ent->hot_swap_indicator_id, &val,
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
	ent_unlock(ent);
	ipmi_entity_call_hot_swap_handlers(ent, old_state, state, &event,
					   &handled);
	ent_lock(ent);
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

    ent_lock(ent);
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
    ent_unlock(ent);
    return handled;
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

    if (!valid_vals[0])
	return IPMI_EVENT_NOT_HANDLED;

    if (ent->present)
	power_checked(control, 0, vals, ent);
    
    return IPMI_EVENT_NOT_HANDLED;
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

    ent->hot_swap_indicator_id = ipmi_control_convert_to_id(control);
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
	
    ent_unlock(ent);
    rv = ipmi_control_set_val(control, &val, NULL, NULL);
    ent_lock(ent);
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

    ent_lock(ent);
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
    ent_unlock(ent);
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

    ent_lock(ent);
    if (val[0])
	set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVE, NULL);
    else
	set_hot_swap_state(ent, IPMI_HOT_SWAP_INACTIVE, NULL);

    if (ent->hot_swap_requester) {
	ipmi_sensor_id_t hsr = ent->hot_swap_requester_id;
	ent_unlock(ent);
	rv = ipmi_sensor_id_get_states(hsr, requester_checked, ent);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%sentity.c(power_checked): Unable to"
		     " request requester status, error %x",
		     SENSOR_NAME(ent->hot_swap_requester), rv);
	}
    } else
	ent_unlock(ent);
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
	goto out;
    }

    ent->hot_swap_power_id = ipmi_control_convert_to_id(control);
    ent->hot_swap_power = control;

    /* If we have power control, we can manage hot-swap. */
    ipmi_entity_set_supports_managed_hot_swap(ent, 1);

    if (ent->hot_swappable) {
	ent_unlock(ent);
	rv = ipmi_control_get_val(control, power_checked, ent);
	ent_lock(ent);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%sentity.c(handle_new_hot_swap_power): Unable to"
		     " request power status, error %x",
		     CONTROL_NAME(ent->hot_swap_power), rv);
	}
    }
 out:
    return;
}

/* Must be called with the entity lock held.  May release and reclaim it. */
static void
handle_new_hot_swap_requester(ipmi_entity_t *ent, ipmi_sensor_t *sensor)
{
    ipmi_event_state_t events;
    int                event_support;
    int                rv;
    int                val;

    ent->hot_swap_requester_id = ipmi_sensor_convert_to_id(sensor);

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
	goto out;
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
	rv = ipmi_sensor_discrete_event_supported
	    (sensor,
	     ent->hot_swap_offset,
	     IPMI_ASSERTION,
	     &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, ent->hot_swap_offset,
				    IPMI_ASSERTION);
	rv = ipmi_sensor_discrete_event_supported
	    (sensor,
	     ent->hot_swap_offset,
	     IPMI_DEASSERTION,
	     &val);
	if ((!rv) && (val))
	    ipmi_discrete_event_set(&events, ent->hot_swap_offset,
				    IPMI_DEASSERTION);
    }

    ent_unlock(ent);
    ipmi_sensor_set_event_enables(sensor, &events, NULL, NULL);
    ent_lock(ent);

    if (ent->hot_swappable) {
	ipmi_sensor_id_t hsr = ent->hot_swap_requester_id;
	ent_unlock(ent);
	rv = ipmi_sensor_id_get_states(hsr, requester_checked, ent);
	ent_lock(ent);
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

    ent_lock(ent);
    if (present) {
	if ((!ent->hot_swap_power)
	    || (ent->hot_swap_act_timeout == IPMI_TIMEOUT_NOW))
	{
	    /* No power control or immediate timeout, it goes straight
	       to active. */
	    handled = set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVE, event);
	    ent_unlock(ent);
	} else {
	    ipmi_control_id_t hsp = ent->hot_swap_power_id;
	    ent_unlock(ent);
	    rv = ipmi_control_id_get_val(hsp, power_checked, ent);
	    if (rv) {
		ipmi_log(IPMI_LOG_SEVERE,
			 "%sentity.c(handle_hot_swap_presence): Unable to"
			 " request power status, error %x",
			 CONTROL_NAME(ent->hot_swap_power), rv);
	    }
	}
    } else {
	handled = set_hot_swap_state(ent, IPMI_HOT_SWAP_NOT_PRESENT, event);
	ent_unlock(ent);
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
    int rv = 0;

    ent_lock(ent);
    if (!ent->hot_swap_power)
	rv = ENOSYS;
    else
	ent->hot_swap_act_timeout = auto_act;
    ent_unlock(ent);

    if ((!rv) && (done))
	done(ent, 0, cb_data);

    return rv;
}

static int
e_get_auto_activate(ipmi_entity_t       *ent,
		    ipmi_entity_time_cb handler,
		    void                *cb_data)
{
    int            rv = 0;
    ipmi_timeout_t time = 0;

    ent_lock(ent);
    if (!ent->hot_swap_power)
	rv = ENOSYS;
    else
	time = ent->hot_swap_act_timeout;
    ent_unlock(ent);

    if ((!rv) && (handler))
	handler(ent, 0, time, cb_data);

    return rv;
}

static int
e_set_auto_deactivate(ipmi_entity_t  *ent,
		      ipmi_timeout_t auto_act,
		      ipmi_entity_cb done,
		      void           *cb_data)
{
    int rv = 0;
    
    ent_lock(ent);
    if (!ent->hot_swap_power)
	rv = ENOSYS;
    else
	ent->hot_swap_deact_timeout = auto_act;
    ent_unlock(ent);

    if ((!rv) && (done))
	done(ent, 0, cb_data);

    return rv;
}

static int
e_get_auto_deactivate(ipmi_entity_t       *ent,
		      ipmi_entity_time_cb handler,
		      void                *cb_data)
{
    int            rv = 0;
    ipmi_timeout_t time = 0;

    ent_lock(ent);
    if (!ent->hot_swap_power)
	rv = ENOSYS;
    else
	time = ent->hot_swap_deact_timeout;
    ent_unlock(ent);

    if ((!rv) && (handler))
	handler(ent, 0, time, cb_data);

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
    ipmi_control_id_t   id;

    ent_lock(ent);
    if (! ent->hot_swap_indicator) {
	ent_unlock(ent);
	return ENOSYS;
    }
    id = ent->hot_swap_indicator_id;
    ent_unlock(ent);

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->ent = ent;
    info->handler = handler;
    info->cb_data = cb_data;
    rv = ipmi_control_id_get_val(id, got_hot_swap_ind, &info);
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
    ipmi_control_id_t       id;

    ent_lock(ent);
    if (! ent->hot_swap_indicator) {
	ent_unlock(ent);
	return ENOSYS;
    }
    id = ent->hot_swap_indicator_id;
    ent_unlock(ent);

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->ent = ent;
    info->handler = done;
    info->cb_data = cb_data;
    rv = ipmi_control_id_set_val(id, &val, set_hot_swap_ind, &info);
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
	ent_lock(info->ent);
	if (ipmi_is_state_set(states, info->ent->hot_swap_offset)
	    == info->ent->hot_swap_requesting_val)
	{
	    val = 1;
	}
	ent_unlock(info->ent);
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
    ipmi_sensor_id_t    id;

    ent_lock(ent);
    if (! ent->hot_swap_requester) {
	ent_unlock(ent);
	return ENOSYS;
    }
    id = ent->hot_swap_requester_id;
    ent_unlock(ent);

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->ent = ent;
    info->handler = handler;
    info->cb_data = cb_data;
    rv = ipmi_sensor_id_get_states(id, got_hot_swap_req, &info);
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

    ent_lock(ent);
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
    ent_unlock(ent);

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
		 "%sentity.c(check_power): Unable to"
		 " get power value, error %x",
		 CONTROL_NAME(control), err);
	ipmi_mem_free(info);
	return;
    }

    info->power = val[0];

    ent_lock(ent);
    if (ent->hot_swap_requester) {
	ipmi_sensor_id_t hsr = ent->hot_swap_requester_id;
	ent_unlock(ent);
	rv = ipmi_sensor_id_get_states(hsr, check_requester, info);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%sentity.c(check_power): Unable to"
		     " request requester status, error %x",
		     SENSOR_NAME(ent->hot_swap_requester), rv);
	    ipmi_mem_free(info);
	}
    } else {
	if (info->power)
	    set_hot_swap_state(ent, IPMI_HOT_SWAP_ACTIVE, NULL);
	else
	    set_hot_swap_state(ent, IPMI_HOT_SWAP_INACTIVE, NULL);
	ent_unlock(ent);
	ipmi_mem_free(info);
    }
}

static int
e_check_hot_swap_state(ipmi_entity_t *ent)
{
    hs_check_t *info;
    int        rv = 0;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->entity = ent;
    info->power = 1; /* Assume power is on if no power control. */

    ent_lock(ent);
    if (ent->hot_swap_power) {
	ipmi_control_id_t hsp = ent->hot_swap_power_id;
	ent_unlock(ent);
	rv = ipmi_control_id_get_val(hsp, check_power, info);
    } else if (ent->hot_swap_requester) {
	ipmi_sensor_id_t hsr = ent->hot_swap_requester_id;
	ent_unlock(ent);
	rv = ipmi_sensor_id_get_states(hsr, check_requester, info);
    } else {
	ent_unlock(ent);
	ipmi_mem_free(info);
    }
	
    if (info && rv)
	ipmi_mem_free(info);

    return rv;
}



/***********************************************************************
 *
 * More hot-swap stuff.  Don't use it.  This is only here because HPI
 * requires it.
 *
 **********************************************************************/

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

static void
entity_get_hot_swap_indicator_cb(ipmi_entity_t *ent, void *cb_data)
{
    entity_val_cb_info_t *info = cb_data;

    if (!ent->hot_swappable)
	info->rv = ENOSYS;
    else if (!ent->hs_cb.get_hot_swap_indicator)
	info->rv = ENOSYS;
    else
	info->rv = ent->hs_cb.get_hot_swap_indicator(ent,
						     info->handler,
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

    if (!ent->hot_swappable)
	info->rv = ENOSYS;
    else if (!ent->hs_cb.set_hot_swap_indicator)
	info->rv = ENOSYS;
    else
	info->rv = ent->hs_cb.set_hot_swap_indicator(ent,
						     info->val,
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

    if (!ent->hot_swappable)
	info->rv = ENOSYS;
    else if (!ent->hs_cb.get_hot_swap_requester)
	info->rv = ENOSYS;
    else
	info->rv = ent->hs_cb.get_hot_swap_requester(ent,
						     info->handler,
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

static int
entity_opq_ready(void *cb_data, int shutdown)
{
    ipmi_entity_op_info_t *info = cb_data;
    int                   rv;

    if (shutdown) {
	/* Technically this can't happen, but just in case... */
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sentity.c(entity_opq_ready): "
		 "Entity was destroyed while an operation was in progress",
		 ENTITY_NAME(info->__entity));
	if (info->__handler)
	    info->__handler(info->__entity, ECANCELED, info->__cb_data);
	return OPQ_HANDLER_STARTED;
    }

    rv = ipmi_entity_pointer_cb(info->__entity_id, entity_opq_ready2, info);
    if (rv) {
	/* Technically this can't happen, but just in case... */
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sentity.c(entity_opq_ready): "
		 "Entity pointer callback failed",
		 ENTITY_NAME(info->__entity));
	if (info->__handler)
	    info->__handler(info->__entity, rv, info->__cb_data);
    }

    return OPQ_HANDLER_STARTED;
}

int
ipmi_entity_add_opq(ipmi_entity_t         *entity,
		    ipmi_entity_cb        handler,
		    ipmi_entity_op_info_t *info,
		    void                  *cb_data)
{
    if (entity->destroyed)
	return EINVAL;

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

    /* No check for the lock.  It will sometimes fail at destruction
       time. */

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

    /* Call the next stage with the lock held. */
    info->__rsp = rsp;
    rv = ipmi_entity_pointer_cb(info->__entity_id,
				entity_rsp_handler2,
				info);
    if (rv) {
	/* This really can't happen, there will be something in the
	   opq, so the entity cannot go away. */
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sentity.c(entity_rsp_handler): "
		 "Could not convert entity id to a pointer, entity was"
		 " probably destroyed while operation was in progress",
		 MC_NAME(mc));
	if (info->__rsp_handler) {
	    _ipmi_domain_entity_lock(info->__entity->domain);
	    info->__entity->usecount++;
	    _ipmi_domain_entity_unlock(info->__entity->domain);
	    info->__rsp_handler(info->__entity, rv, NULL, info->__cb_data);
	    _ipmi_entity_put(info->__entity);
	}
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

    if (entity->destroyed)
	return EINVAL;

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


/***********************************************************************
 *
 * Cruft
 *
 **********************************************************************/

int
ipmi_entity_set_presence_handler(ipmi_entity_t              *ent,
				 ipmi_entity_presence_nd_cb handler,
				 void                       *cb_data)
{
    CHECK_ENTITY_LOCK(ent);

    ent_lock(ent);
    ent->cruft_presence_handler = handler;
    ent->cruft_presence_cb_data = cb_data;
    ent_unlock(ent);
    return 0;
}

int
ipmi_entity_set_sensor_update_handler(ipmi_entity_t         *ent,
				      ipmi_entity_sensor_cb handler,
				      void                  *cb_data)
{
    int rv = 0;

    CHECK_ENTITY_LOCK(ent);

    ent_lock(ent);
    if (ent->cruft_sensor_handler)
	ipmi_entity_remove_sensor_update_handler
	    (ent,
	     ent->cruft_sensor_handler,
	     ent->cruft_sensor_cb_data);

    ent->cruft_sensor_handler = handler;
    ent->cruft_sensor_cb_data = cb_data;
    if (handler)
	rv = ipmi_entity_add_sensor_update_handler(ent, handler, cb_data);
    ent_unlock(ent);
    return rv;
}

int
ipmi_entity_set_control_update_handler(ipmi_entity_t          *ent,
				       ipmi_entity_control_cb handler,
				       void                   *cb_data)
{
    int rv = 0;

    CHECK_ENTITY_LOCK(ent);

    ent_lock(ent);
    if (ent->cruft_control_handler)
	ipmi_entity_remove_control_update_handler
	    (ent,
	     ent->cruft_control_handler,
	     ent->cruft_control_cb_data);

    ent->cruft_control_handler = handler;
    ent->cruft_control_cb_data = cb_data;
    if (handler)
	rv = ipmi_entity_add_control_update_handler(ent, handler, cb_data);
    ent_unlock(ent);
    return rv;
}

int
ipmi_entity_set_fru_update_handler(ipmi_entity_t     *ent,
				   ipmi_entity_fru_cb handler,
				   void              *cb_data)
{
    int rv = 0;

    CHECK_ENTITY_LOCK(ent);

    ent_lock(ent);
    if (ent->cruft_fru_handler)
	ipmi_entity_remove_fru_update_handler
	    (ent,
	     ent->cruft_fru_handler,
	     ent->cruft_fru_cb_data);

    ent->cruft_fru_handler = handler;
    ent->cruft_fru_cb_data = cb_data;
    if (handler)
	rv = ipmi_entity_add_fru_update_handler(ent, handler, cb_data);
    ent_unlock(ent);
    return rv;
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
