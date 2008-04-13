/*
 * control.c
 *
 * MontaVista IPMI code for handling controls
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
#include <limits.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_err.h>

#include <OpenIPMI/internal/opq.h>
#include <OpenIPMI/internal/locked_list.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_mc.h>
#include <OpenIPMI/internal/ipmi_control.h>

struct ipmi_control_info_s
{
    int                      destroyed;

    /* Indexed by control # */
    ipmi_control_t           **controls_by_idx;
    /* Size of above control array.  This will be 0 if the LUN has no
       controls. */
    unsigned int             idx_size;

    ipmi_lock_t              *idx_lock;

    /* Total number of controls we have in this. */
    unsigned int             control_count;

    opq_t *control_wait_q;
    int  wait_err;
};

#define CONTROL_ID_LEN 32
struct ipmi_control_s
{
    unsigned int usecount;

    ipmi_domain_t *domain;
    ipmi_mc_t *mc;
    unsigned char lun;
    unsigned char num;

    ipmi_mc_t *source_mc;

    ipmi_entity_t *entity;

    int destroyed;

    /* After the control is added, it will not be reported immediately.
       Instead, it will wait until the usecount goes to zero before
       being reported.  This marks that the add report is pending */
    int add_pending;

    int type;
    const char *type_str;

    int settable;
    int readable;

    unsigned int num_vals;

    int hot_swap_indicator;
    int hot_swap_active_val;
    int hot_swap_inactive_val;
    int hot_swap_req_act_val;
    int hot_swap_req_deact_val;

    int hot_swap_power;

    int has_events;

    int ignore_if_no_entity : 1;
    int ignore_for_presence : 1;

    /* A list of handlers to call when an event for the control comes
       in. */
    locked_list_t *handler_list, *handler_list_cl;

    /* For light types. */
#define MAX_LIGHTS 10
    ipmi_control_light_t *lights;
    unsigned int         colors[MAX_LIGHTS];
    int                  has_local_control[MAX_LIGHTS];

    /* For display types. */
    unsigned int columns;
    unsigned int rows;

    /* For identifier types. */
    unsigned int identifier_length;

    /* Note that this is *not* nil terminated. */
    enum ipmi_str_type_e id_type;
    unsigned int id_len;
    char id[CONTROL_ID_LEN];

    ipmi_control_cbs_t cbs;
    opq_t *waitq;

    void                             *oem_info;
    ipmi_control_cleanup_oem_info_cb oem_info_cleanup_handler;

    ipmi_control_destroy_cb destroy_handler;
    void                    *destroy_handler_cb_data;

    /* Name we use for reporting.  We add a ' ' onto the end, thus
       the +1. */
    char name[IPMI_CONTROL_NAME_LEN+1];
};

static void control_final_destroy(ipmi_control_t *control);

/***********************************************************************
 *
 * Control ID handling.
 *
 **********************************************************************/

/* Must be called with the domain entity lock held. */
int
_ipmi_control_get(ipmi_control_t *control)
{
    if (control->destroyed)
	return EINVAL;
    control->usecount++;
    return 0;
}

void
_ipmi_control_put(ipmi_control_t *control)
{
    _ipmi_domain_entity_lock(control->domain);
    if (control->usecount == 1) {
	if (control->add_pending) {
	    control->add_pending = 0;
	    _ipmi_domain_entity_unlock(control->domain);
	    _ipmi_entity_call_control_handlers(control->entity,
					       control, IPMI_ADDED);
	    _ipmi_domain_entity_lock(control->domain);
	}
	if (control->destroyed
	    && (!control->waitq
		|| (!opq_stuff_in_progress(control->waitq))))
	{
	    _ipmi_domain_entity_unlock(control->domain);
	    control_final_destroy(control);
	    return;
	}
    }
    control->usecount--;
    _ipmi_domain_entity_unlock(control->domain);
}

ipmi_control_id_t
ipmi_control_convert_to_id(ipmi_control_t *control)
{
    ipmi_control_id_t val;

    CHECK_CONTROL_LOCK(control);

    val.mcid = ipmi_mc_convert_to_id(control->mc);
    val.lun = control->lun;
    val.control_num = control->num;

    return val;
}

typedef struct mc_cb_info_s
{
    ipmi_control_ptr_cb   handler;
    void                  *cb_data;
    ipmi_control_id_t     id;
    int                   err;
} mc_cb_info_t;

static void
mc_cb(ipmi_mc_t *mc, void *cb_data)
{
    mc_cb_info_t        *info = cb_data;
    ipmi_control_info_t *controls;
    ipmi_domain_t       *domain = ipmi_mc_get_domain(mc);
    ipmi_control_t      *control;
    ipmi_entity_t       *entity = NULL;
    
    controls = _ipmi_mc_get_controls(mc);
    _ipmi_domain_entity_lock(domain);
    if (info->id.lun > 4) {
	info->err = EINVAL;
	goto out_unlock;
    }

    if (info->id.control_num >= controls->idx_size) {
	info->err = EINVAL;
	goto out_unlock;
    }

    control = controls->controls_by_idx[info->id.control_num];
    if (!control) {
	info->err = EINVAL;
	goto out_unlock;
    }

    info->err = _ipmi_entity_get(control->entity);
    if (info->err)
	goto out_unlock;
    entity = control->entity;

    info->err = _ipmi_control_get(control);
    if (info->err)
	goto out_unlock;

    _ipmi_domain_entity_unlock(domain);

    info->handler(control, info->cb_data);

    _ipmi_control_put(control);
    _ipmi_entity_put(entity);
    return;

 out_unlock:
    _ipmi_domain_entity_unlock(domain);
    if (entity)
	_ipmi_entity_put(entity);
}

int
ipmi_control_pointer_cb(ipmi_control_id_t   id,
			ipmi_control_ptr_cb handler,
			void                *cb_data)
{
    int               rv;
    mc_cb_info_t      info;

    if (id.lun >= 5)
	return EINVAL;

    info.handler = handler;
    info.cb_data = cb_data;
    info.id = id;
    info.err = 0;

    rv = ipmi_mc_pointer_cb(id.mcid, mc_cb, &info);
    if (!rv)
	rv = info.err;

    return rv;
}

int
ipmi_control_pointer_noseq_cb(ipmi_control_id_t   id,
			      ipmi_control_ptr_cb handler,
			      void                *cb_data)
{
    int               rv;
    mc_cb_info_t      info;

    if (id.lun >= 5)
	return EINVAL;

    info.handler = handler;
    info.cb_data = cb_data;
    info.id = id;
    info.err = 0;

    rv = ipmi_mc_pointer_noseq_cb(id.mcid, mc_cb, &info);
    if (!rv)
	rv = info.err;

    return rv;
}

typedef struct control_find_info_s
{
    ipmi_control_id_t id;
    char              *id_name;
    int               rv;
} control_find_info_t;

static void
control_search_cmp(ipmi_entity_t  *entity,
		   ipmi_control_t *control,
		   void           *cb_data)
{
    control_find_info_t *info = cb_data;
    char               id[33];
    int                rv;

    rv = ipmi_control_get_id(control, id, 33);
    if (rv) 
	return;
    if (strcmp(info->id_name, id) == 0) {
	info->id = ipmi_control_convert_to_id(control);
	info->rv = 0;
    }
}

static void
control_search(ipmi_entity_t *entity, void *cb_data)
{
    control_find_info_t *info = cb_data;

    ipmi_entity_iterate_controls(entity, control_search_cmp, info);
}

int
ipmi_control_find_id(ipmi_domain_id_t domain_id,
		    int entity_id, int entity_instance,
		    int channel, int slave_address,
		    char *id_name,
		    ipmi_control_id_t *id)
{
    int                rv;
    ipmi_entity_id_t   entity;
    control_find_info_t info;

    rv = ipmi_entity_find_id(domain_id, entity_id, entity_instance,
			     channel, slave_address, &entity);
    if (rv)
	return rv;

    info.id_name = id_name;
    info.rv = EINVAL;

    rv = ipmi_entity_pointer_cb(entity, control_search, &info);
    if (!rv)
	rv = info.rv;
    if (!rv)
	*id = info.id;

    return rv;
}

/***********************************************************************
 *
 * Various control allocation/deallocation/opq/etc.
 *
 **********************************************************************/

static int
control_ok_to_use(ipmi_control_t *control)
{
    return (   !control->destroyed
	    && !_ipmi_domain_in_shutdown(control->domain));
}

typedef struct handler_cl_info_s
{
    ipmi_control_val_event_cb handler;
    void                      *handler_data;
} handler_cl_info_t;

static int
iterate_handler_cl(void *cb_data, void *item1, void *item2)
{
    handler_cl_info_t            *info = cb_data;
    ipmi_control_val_event_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
handler_list_cleanup(void *cb_data, void *item1, void *item2)
{
    ipmi_control_t    *control = cb_data;
    handler_cl_info_t info;

    info.handler = item1;
    info.handler_data = item2;
    locked_list_iterate(control->handler_list_cl,
			iterate_handler_cl,
			&info);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
control_final_destroy(ipmi_control_t *control)
{
    _ipmi_entity_get(control->entity);
    _ipmi_entity_call_control_handlers(control->entity, control, IPMI_DELETED);

    control->mc = NULL;

    if (control->destroy_handler)
	control->destroy_handler(control,
				 control->destroy_handler_cb_data);

    if (control->handler_list) {
	locked_list_iterate(control->handler_list_cl, handler_list_cleanup,
			    control);
	locked_list_destroy(control->handler_list);
    }

    if (control->handler_list_cl)
	locked_list_destroy(control->handler_list_cl);

    if (control->waitq)
	opq_destroy(control->waitq);

    if (control->entity)
	ipmi_entity_remove_control(control->entity, control);

    if (control->oem_info_cleanup_handler)
	control->oem_info_cleanup_handler(control, control->oem_info);

    _ipmi_entity_put(control->entity);
    ipmi_mem_free(control);
}

int
ipmi_control_destroy(ipmi_control_t *control)
{
    ipmi_control_info_t *controls;
    ipmi_mc_t           *mc = control->mc;

    _ipmi_domain_mc_lock(control->domain);
    _ipmi_mc_get(mc);
    _ipmi_domain_mc_unlock(control->domain);
    controls = _ipmi_mc_get_controls(control->mc);

    ipmi_lock(controls->idx_lock);
    if (controls->controls_by_idx[control->num] == control) {
	controls->control_count--;
	controls->controls_by_idx[control->num] = NULL;
    }

    _ipmi_control_get(control);

    ipmi_unlock(controls->idx_lock);

    control->destroyed = 1;
    _ipmi_control_put(control);
    _ipmi_mc_put(mc);

    return 0;
}

static void
control_set_name(ipmi_control_t *control)
{
    int length;

    length = ipmi_entity_get_name(control->entity, control->name,
				  sizeof(control->name)-2);
    control->name[length] = '.';
    length++;
    length += snprintf(control->name+length, IPMI_CONTROL_NAME_LEN-length-2,
		       "%s", control->id);
    control->name[length] = ' ';
    length++;
    control->name[length] = '\0';
    length++;
}

const char *
_ipmi_control_name(const ipmi_control_t *control)
{
    return control->name;
}

int
ipmi_control_get_name(ipmi_control_t *control, char *name, int length)
{
    int rv = 0;

    if (control->entity)
	rv = ipmi_entity_get_name(control->entity, name, length);
    if (length > (int) (control->id_len + 2))
	length = control->id_len + 2; /* Leave space for the nil */
    rv += snprintf(name+rv, length, ".%s", control->id);
    return rv;
}

/***********************************************************************
 *
 * Control message handling.
 *
 **********************************************************************/

static void
control_opq_ready2(ipmi_control_t *control, void *cb_data)
{
    ipmi_control_op_info_t *info = cb_data;
    if (info->__handler)
	info->__handler(control, 0, info->__cb_data);
}

static int
control_opq_ready(void *cb_data, int shutdown)
{
    ipmi_control_op_info_t *info = cb_data;
    int                   rv;

    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%scontrol.c(control_opq_ready): "
		 "Control was destroyed while an operation was in progress",
		 CONTROL_NAME(info->__control));
	if (info->__handler)
	    info->__handler(info->__control, ECANCELED, info->__cb_data);
	return OPQ_HANDLER_STARTED;
    }

    rv = ipmi_control_pointer_cb(info->__control_id, control_opq_ready2, info);
    if (rv)
	if (info->__handler)
	    info->__handler(info->__control, rv, info->__cb_data);
    return OPQ_HANDLER_STARTED;
}

int
ipmi_control_add_opq(ipmi_control_t         *control,
		     ipmi_control_op_cb     handler,
		     ipmi_control_op_info_t *info,
		     void                   *cb_data)
{
    if (control->destroyed)
	return EINVAL;

    info->__control = control;
    info->__control_id = ipmi_control_convert_to_id(control);
    info->__cb_data = cb_data;
    info->__handler = handler;
    if (!opq_new_op(control->waitq, control_opq_ready, info, 0))
	return ENOMEM;
    return 0;
}

void
ipmi_control_opq_done(ipmi_control_t *control)
{
    /* Protect myself from NULL controls.  This way, it doesn't have to
       be done in each call. */
    if (!control)
	return;

     /* This gets called on ECANCELED error cases, if the control is
	already we need to clear out the opq. */
    if (control->destroyed) {
	if (control->waitq) {
	    opq_destroy(control->waitq);
	    control->waitq = NULL;
	}
 	return;
    }

    /* No check for the lock.  It will sometimes fail at destruction
       time. */

    opq_op_done(control->waitq);
}

static void
control_rsp_handler2(ipmi_control_t *control, void *cb_data)
{
    ipmi_control_op_info_t *info = cb_data;

    if (info->__rsp_handler)
	info->__rsp_handler(control, 0, info->__rsp, info->__cb_data);
}

static void
control_rsp_handler(ipmi_mc_t  *mc,
		    ipmi_msg_t *rsp,
		    void       *rsp_data)
{
    ipmi_control_op_info_t *info = rsp_data;
    int                    rv;
    ipmi_control_t         *control = info->__control;
    ipmi_entity_t          *entity = NULL;

    if (control->destroyed) {
	ipmi_entity_t *entity = NULL;

	_ipmi_domain_entity_lock(control->domain);
	control->usecount++;
	_ipmi_domain_entity_unlock(control->domain);

	rv = _ipmi_entity_get(control->entity);
	if (! rv)
	    entity = control->entity;

	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%scontrol.c(control_rsp_handler): "
		 "Control was destroyed while an operation was in progress",
		 CONTROL_NAME(control));
	if (info->__rsp_handler)
	    info->__rsp_handler(control, ECANCELED, NULL, info->__cb_data);

	_ipmi_control_put(control);
	if (entity)
	    _ipmi_entity_put(entity);
	return;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "control.c(control_rsp_handler): "
		 "MC was destroyed while a control operation was in progress");

	_ipmi_domain_entity_lock(control->domain);
	control->usecount++;
	_ipmi_domain_entity_unlock(control->domain);

	rv = _ipmi_entity_get(control->entity);
	if (! rv)
	    entity = control->entity;

	if (info->__rsp_handler)
	    info->__rsp_handler(control, ECANCELED, NULL, info->__cb_data);

	_ipmi_control_put(control);
	if (entity)
	    _ipmi_entity_put(entity);

	return;
    }

    /* Call the next stage with the lock held. */
    info->__rsp = rsp;
    rv = ipmi_control_pointer_cb(info->__control_id,
				 control_rsp_handler2,
				 info);
    if (rv) {
	int nrv;

	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%scontrol.c(control_rsp_handler): "
		 "Could not convert control id to a pointer",
		 MC_NAME(mc));
	_ipmi_domain_entity_lock(control->domain);
	control->usecount++;
	_ipmi_domain_entity_unlock(control->domain);

	nrv = _ipmi_entity_get(control->entity);
	if (! nrv)
	    entity = control->entity;

	if (info->__rsp_handler)
	    info->__rsp_handler(control, rv, NULL, info->__cb_data);

	_ipmi_control_put(control);
	if (entity)
	    _ipmi_entity_put(entity);
    }
}
			 
int
ipmi_control_send_command(ipmi_control_t         *control,
			  ipmi_mc_t              *mc,
			  unsigned int           lun,
			  ipmi_msg_t             *msg,
			  ipmi_control_rsp_cb    handler,
			  ipmi_control_op_info_t *info,
			  void                   *cb_data)
{
    int rv;

    CHECK_MC_LOCK(mc);
    CHECK_CONTROL_LOCK(control);

    if (control->destroyed)
	return EINVAL;

    info->__control = control;
    info->__control_id = ipmi_control_convert_to_id(control);
    info->__cb_data = cb_data;
    info->__rsp_handler = handler;
    rv = ipmi_mc_send_command(mc, lun, msg, control_rsp_handler, info);
    return rv;
}

static int
control_addr_response_handler(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_msg_t             *msg = &rspi->msg;
    ipmi_control_op_info_t *info = rspi->data1;
    int                    rv;
    ipmi_control_t         *control = info->__control;

    if (control->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%scontrol.c(control_addr_response_handler): "
		 "Control was destroyed while an operation was in progress",
		 DOMAIN_NAME(domain));
	if (info->__rsp_handler)
	    info->__rsp_handler(control, ECANCELED, NULL, info->__cb_data);

	_ipmi_domain_entity_lock(control->domain);
	control->usecount++;
	_ipmi_domain_entity_unlock(control->domain);
	_ipmi_control_put(control);
	return IPMI_MSG_ITEM_NOT_USED;
    }

    /* Call the next stage with the lock held. */
    info->__rsp = msg;
    rv = ipmi_control_pointer_cb(info->__control_id,
				 control_rsp_handler2,
				 info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%scontrol.c(control_addr_response_handler): "
		 "Could not convert control id to a pointer",
		 DOMAIN_NAME(domain));
	if (info->__rsp_handler) {
	    _ipmi_domain_entity_lock(control->domain);
	    control->usecount++;
	    _ipmi_domain_entity_unlock(control->domain);
	    info->__rsp_handler(control, rv, NULL, info->__cb_data);
	    _ipmi_control_put(control);
	}
    }
    return IPMI_MSG_ITEM_NOT_USED;
}

int
ipmi_control_send_command_addr(ipmi_domain_t          *domain,
			       ipmi_control_t         *control,
			       ipmi_addr_t            *addr,
			       unsigned int           addr_len,
			       ipmi_msg_t             *msg,
			       ipmi_control_rsp_cb    handler,
			       ipmi_control_op_info_t *info,
			       void                   *cb_data)
{
    int rv;

    CHECK_CONTROL_LOCK(control);
    CHECK_MC_LOCK(control->mc);

    info->__control = control;
    info->__control_id = ipmi_control_convert_to_id(control);
    info->__cb_data = cb_data;
    info->__rsp_handler = handler;
    rv = ipmi_send_command_addr(domain, addr, addr_len,
				msg, control_addr_response_handler, info, NULL);
    return rv;
}

int
ipmi_controls_alloc(ipmi_mc_t *mc, ipmi_control_info_t **new_controls)
{
    ipmi_control_info_t *controls;
    ipmi_domain_t       *domain;
    os_handler_t        *os_hnd;
    int                 rv;

    CHECK_MC_LOCK(mc);

    domain = ipmi_mc_get_domain(mc);
    os_hnd = ipmi_domain_get_os_hnd(domain);

    controls = ipmi_mem_alloc(sizeof(*controls));
    if (!controls)
	return ENOMEM;
    memset(controls, 0, sizeof(*controls));

    controls->control_wait_q = opq_alloc(os_hnd);
    if (! controls->control_wait_q) {
	ipmi_mem_free(controls);
	return ENOMEM;
    }

    rv = ipmi_create_lock_os_hnd(os_hnd, &controls->idx_lock);
    if (rv) {
	opq_destroy(controls->control_wait_q);
	ipmi_mem_free(controls);
	return rv;
    }

    *new_controls = controls;
    return 0;
}

unsigned int
ipmi_controls_get_count(ipmi_control_info_t *controls)
{
    return controls->control_count;
}

int
ipmi_control_alloc_nonstandard(ipmi_control_t **new_control)
{
    ipmi_control_t *control;

    control = ipmi_mem_alloc(sizeof(*control));
    if (!control)
	return ENOMEM;

    memset(control, 0, sizeof(*control));

    control->usecount = 1;
    *new_control = control;
    return 0;
}

int
ipmi_control_add_nonstandard(ipmi_mc_t               *mc,
			     ipmi_mc_t               *source_mc,
			     ipmi_control_t          *control,
			     unsigned int            num,
			     ipmi_entity_t           *ent,
			     ipmi_control_destroy_cb destroy_handler,
			     void                    *destroy_handler_cb_data)
{
    ipmi_domain_t       *domain;
    os_handler_t        *os_hnd;
    ipmi_control_info_t *controls = _ipmi_mc_get_controls(mc);
    locked_list_entry_t *link;
    int                 err;
    unsigned int        i;

    CHECK_MC_LOCK(mc);
    CHECK_ENTITY_LOCK(ent);

    domain = ipmi_mc_get_domain(mc);
    os_hnd = ipmi_domain_get_os_hnd(domain);

    if ((num >= 256) && (num != UINT_MAX))
	return EINVAL;

    _ipmi_domain_entity_lock(domain);
    ipmi_lock(controls->idx_lock);

    if (num == UINT_MAX){
	for (i=0; i<controls->idx_size; i++) {
	    if (! controls->controls_by_idx[i])
		break;
	}
	num = i;
	if (num >= 256) {
	    err = EAGAIN;
	    goto out_err;
	}
    }

    if (num >= controls->idx_size) {
	ipmi_control_t **new_array;
	unsigned int   new_size;
	unsigned int   i;

	/* Allocate the array in multiples of 16 (to avoid thrashing malloc
	   too much). */
	new_size = ((num / 16) * 16) + 16;
	new_array = ipmi_mem_alloc(sizeof(*new_array) * new_size);
	if (!new_array) {
	    err = ENOMEM;
	    goto out_err;
	}
	if (controls->controls_by_idx)
	    memcpy(new_array, controls->controls_by_idx,
		   sizeof(*new_array) * (controls->idx_size));
	for (i=controls->idx_size; i<new_size; i++)
	    new_array[i] = NULL;
	if (controls->controls_by_idx)
	    ipmi_mem_free(controls->controls_by_idx);
	controls->controls_by_idx = new_array;
	controls->idx_size = new_size;
    }

    control->waitq = opq_alloc(os_hnd);
    if (! control->waitq) {
	err = ENOMEM;
	goto out_err;
    }

    control->handler_list_cl = locked_list_alloc(os_hnd);
    if (! control->handler_list_cl) {
	opq_destroy(control->waitq);
	err = ENOMEM;
	goto out_err;
    }

    control->handler_list = locked_list_alloc(os_hnd);
    if (! control->handler_list) {
	opq_destroy(control->waitq);
	locked_list_destroy(control->handler_list_cl);
	err = ENOMEM;
	goto out_err;
    }

    link = locked_list_alloc_entry();
    if (!link) {
	opq_destroy(control->waitq);
	control->waitq = NULL;
	locked_list_destroy(control->handler_list);
	locked_list_destroy(control->handler_list_cl);
	control->handler_list = NULL;
	err = ENOMEM;
	goto out_err;
    }

    control->domain = domain;
    control->mc = mc;
    control->source_mc = source_mc;
    control->entity = ent;
    control->lun = 4;
    control->num = num;
    if (controls->controls_by_idx[num]) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%scontrol.c(ipmi_control_add_nonstandard): "
		 " Add a control at index %d, but there was already a"
		 " control there, overwriting the old control",
		 MC_NAME(mc), num);
    } else {
	controls->control_count++;
    }
    controls->controls_by_idx[num] = control;
    control->destroy_handler = destroy_handler;
    control->destroy_handler_cb_data = destroy_handler_cb_data;
    control_set_name(control);

    ipmi_unlock(controls->idx_lock);

    _ipmi_domain_entity_unlock(domain);

    ipmi_entity_add_control(ent, control, link);

    control->add_pending = 1;

    return 0;

 out_err:
    ipmi_unlock(controls->idx_lock);
    _ipmi_domain_entity_unlock(domain);
    return err;
}

int
ipmi_controls_destroy(ipmi_control_info_t *controls)
{
    unsigned int j;

    if (controls->destroyed)
	return EINVAL;

    controls->destroyed = 1;
    for (j=0; j<controls->idx_size; j++) {
	if (controls->controls_by_idx[j]) {
	    ipmi_control_destroy(controls->controls_by_idx[j]);
	}
    }
    if (controls->controls_by_idx)
	ipmi_mem_free(controls->controls_by_idx);

    if (controls->control_wait_q)
	opq_destroy(controls->control_wait_q);
    if (controls->idx_lock)
	ipmi_destroy_lock(controls->idx_lock);
    ipmi_mem_free(controls);
    return 0;
}

/***********************************************************************
 *
 * Polymorphic calls to the callback handlers.
 *
 **********************************************************************/

int
ipmi_control_set_val(ipmi_control_t     *control,
		     int                *val,
		     ipmi_control_op_cb handler,
		     void               *cb_data)
{
    if (!control_ok_to_use(control))
	return ECANCELED;
      
    CHECK_CONTROL_LOCK(control);

    if (!control->cbs.set_val)
	return ENOSYS;
    return control->cbs.set_val(control, val, handler, cb_data);
}

int
ipmi_control_get_val(ipmi_control_t      *control,
		     ipmi_control_val_cb handler,
		     void                *cb_data)
{
    if (!control_ok_to_use(control))
	return ECANCELED;
      
    CHECK_CONTROL_LOCK(control);

    if (!control->cbs.get_val)
	return ENOSYS;
    return control->cbs.get_val(control, handler, cb_data);
}

int
ipmi_control_set_display_string(ipmi_control_t     *control,
				unsigned int       start_row,
				unsigned int       start_column,
				char               *str,
				unsigned int       len,
				ipmi_control_op_cb handler,
				void               *cb_data)
{
    if (!control_ok_to_use(control))
	return ECANCELED;
      
    CHECK_CONTROL_LOCK(control);

    if (!control->cbs.set_display_string)
	return ENOSYS;
    return control->cbs.set_display_string(control,
					   start_row,
					   start_column,
					   str, len,
					   handler, cb_data);
}
				
int
ipmi_control_get_display_string(ipmi_control_t      *control,
				unsigned int        start_row,
				unsigned int        start_column,
				unsigned int        len,
				ipmi_control_str_cb handler,
				void                *cb_data)
{
    if (!control_ok_to_use(control))
	return ECANCELED;
      
    CHECK_CONTROL_LOCK(control);

    if (!control->cbs.get_display_string)
	return ENOSYS;
    return control->cbs.get_display_string(control,
					   start_row,
					   start_column,
					   len,
					   handler, cb_data);
}

int
ipmi_control_identifier_get_val(ipmi_control_t                 *control,
				ipmi_control_identifier_val_cb handler,
				void                           *cb_data)
{
    if (!control_ok_to_use(control))
	return ECANCELED;
      
    CHECK_CONTROL_LOCK(control);

    if (!control->cbs.get_identifier_val)
	return ENOSYS;
    return control->cbs.get_identifier_val(control, handler, cb_data);
}
				
int
ipmi_control_identifier_set_val(ipmi_control_t     *control,
				unsigned char      *val,
				int                length,
				ipmi_control_op_cb handler,
				void               *cb_data)
{
    if (!control_ok_to_use(control))
	return ECANCELED;
      
    CHECK_CONTROL_LOCK(control);

    if (!control->cbs.set_identifier_val)
	return ENOSYS;
    return control->cbs.set_identifier_val(control,
					   val,
					   length,
					   handler,
					   cb_data);
}

/***********************************************************************
 *
 * Polymorphic calls that take control ids.
 *
 **********************************************************************/

typedef struct control_id_set_val_s
{
    int                *val;
    ipmi_control_op_cb handler;
    void               *cb_data;
    int                rv;
} control_id_set_val_t;

static void
control_id_set_val_cb(ipmi_control_t *control, void *cb_data)
{
    control_id_set_val_t *info = cb_data;

    info->rv = ipmi_control_set_val(control,
				    info->val,
				    info->handler,
				    info->cb_data);
}

int
ipmi_control_id_set_val(ipmi_control_id_t  control_id,
			int                *val,
			ipmi_control_op_cb handler,
			void               *cb_data)
{
    control_id_set_val_t info;
    int                  rv;

    info.val = val;
    info.handler = handler;
    info.cb_data = cb_data;
    rv = ipmi_control_pointer_cb(control_id, control_id_set_val_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct control_id_get_val_s
{
    ipmi_control_val_cb handler;
    void                *cb_data;
    int                 rv;
} control_id_get_val_t;

static void
control_id_get_val_cb(ipmi_control_t *control, void *cb_data)
{
    control_id_get_val_t *info = cb_data;

    info->rv = ipmi_control_get_val(control,
				    info->handler,
				    info->cb_data);
}

int
ipmi_control_id_get_val(ipmi_control_id_t   control_id,
			ipmi_control_val_cb handler,
			void                *cb_data)
{
    control_id_get_val_t info;
    int                  rv;

    info.handler = handler;
    info.cb_data = cb_data;
    rv = ipmi_control_pointer_cb(control_id, control_id_get_val_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct control_id_identifier_set_val_s
{
    unsigned char      *val;
    int                length;
    ipmi_control_op_cb handler;
    void               *cb_data;
    int                rv;
} control_id_identifier_set_val_t;

static void
control_id_identifier_set_val_cb(ipmi_control_t *control, void *cb_data)
{
    control_id_identifier_set_val_t *info = cb_data;

    info->rv = ipmi_control_identifier_set_val(control,
					       info->val,
					       info->length,
					       info->handler,
					       info->cb_data);
}

int
ipmi_control_id_identifier_set_val(ipmi_control_id_t  control_id,
				   unsigned char      *val,
				   int                length,
				   ipmi_control_op_cb handler,
				   void               *cb_data)
{
    control_id_identifier_set_val_t info;
    int                             rv;

    info.val = val;
    info.length = length;
    info.handler = handler;
    info.cb_data = cb_data;
    rv = ipmi_control_pointer_cb(control_id,
				 control_id_identifier_set_val_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct control_id_identifier_get_val_s
{
    ipmi_control_identifier_val_cb handler;
    void                           *cb_data;
    int                            rv;
} control_id_identifier_get_val_t;

static void
control_id_identifier_get_val_cb(ipmi_control_t *control, void *cb_data)
{
    control_id_identifier_get_val_t *info = cb_data;

    info->rv = ipmi_control_identifier_get_val(control,
					       info->handler,
					       info->cb_data);
}

int
ipmi_control_id_identifier_get_val(ipmi_control_id_t              control_id,
				   ipmi_control_identifier_val_cb handler,
				   void                           *cb_data)
{
    control_id_identifier_get_val_t info;
    int                             rv;

    info.handler = handler;
    info.cb_data = cb_data;
    rv = ipmi_control_pointer_cb(control_id,
				 control_id_identifier_get_val_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

/***********************************************************************
 *
 * Event handling for controls.
 *
 **********************************************************************/

void
ipmi_control_set_has_events(ipmi_control_t *control, int val)
{
    control->has_events = val;
}

int
ipmi_control_has_events(ipmi_control_t *control)
{
    return control->has_events;
}

typedef struct control_event_info_s
{
    ipmi_control_t *control;
    int            handled;

    int            *valid_vals;
    int            *vals;

    ipmi_event_t   *event;
} control_event_info_t;

static int
control_val_event_call_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_control_val_event_cb handler = item1;
    control_event_info_t      *info = cb_data;
    int                       handled;

    handled = handler(info->control,
		      info->valid_vals,
		      info->vals,
		      item2,
		      info->event);
    if (handled != IPMI_EVENT_NOT_HANDLED) {
	if (info->handled != IPMI_EVENT_HANDLED)
	    /* Allow handled to override handled_pass, but not the
	       other way. */
	    info->handled = handled;
	if (handled == IPMI_EVENT_HANDLED)
	    info->event = NULL;
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_control_call_val_event_handlers(ipmi_control_t *control,
				     int            *valid_vals,
				     int            *vals,
				     ipmi_event_t   **event,
				     int            *handled)
{
    control_event_info_t info;

    info.control = control;
    info.valid_vals = valid_vals;
    info.vals = vals;
    info.event = *event;
    info.handled = IPMI_EVENT_NOT_HANDLED;

    locked_list_iterate(control->handler_list,
			control_val_event_call_handler, &info);

    if (handled)
	*handled = info.handled;
    *event = info.event;
}

int
ipmi_control_add_val_event_handler(ipmi_control_t            *control,
				   ipmi_control_val_event_cb handler,
				   void                      *cb_data)
{
    CHECK_CONTROL_LOCK(control);

    if (! locked_list_add(control->handler_list, handler, cb_data))
	return ENOMEM;

    return 0;
}

int ipmi_control_remove_val_event_handler(ipmi_control_t            *control,
					  ipmi_control_val_event_cb handler,
					  void                      *cb_data)
{
    CHECK_CONTROL_LOCK(control);

    if (! locked_list_remove(control->handler_list, handler, cb_data))
	return ENOENT;

    return 0;
}

int
ipmi_control_add_val_event_handler_cl(ipmi_control_t            *control,
				      ipmi_control_val_event_cl_cb handler,
				      void                      *cb_data)
{
    CHECK_CONTROL_LOCK(control);

    if (! locked_list_add(control->handler_list_cl, handler, cb_data))
	return ENOMEM;

    return 0;
}

int ipmi_control_remove_val_event_handler_cl(ipmi_control_t         *control,
					  ipmi_control_val_event_cl_cb handler,
					  void                      *cb_data)
{
    CHECK_CONTROL_LOCK(control);

    if (! locked_list_remove(control->handler_list_cl, handler, cb_data))
	return ENOENT;

    return 0;
}

/***********************************************************************
 *
 * Get/set various local information about a control.
 *
 **********************************************************************/

int
ipmi_control_get_type(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->type;
}

void
ipmi_control_set_type(ipmi_control_t *control, int val)
{
    control->type = val;
    control->type_str = ipmi_get_control_type_string(val);
}

const char *
ipmi_control_get_type_string(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->type_str;
}

int
ipmi_control_get_id_length(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    if (control->id_type == IPMI_ASCII_STR)
	return control->id_len+1;
    else
	return control->id_len;
}

enum ipmi_str_type_e
ipmi_control_get_id_type(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->id_type;
}

int
ipmi_control_get_id(ipmi_control_t *control, char *id, int length)
{
    int clen;

    CHECK_CONTROL_LOCK(control);

    if ((int) control->id_len > length)
	clen = length;
    else
	clen = control->id_len;
    memcpy(id, control->id, clen);

    if (control->id_type == IPMI_ASCII_STR) {
	/* NIL terminate the ASCII string. */
	if (clen == length)
	    clen--;

	id[clen] = '\0';
    }

    return clen;
}

void
ipmi_control_set_id(ipmi_control_t *control, char *id,
		    enum ipmi_str_type_e type, int length)
{
    if (length > CONTROL_ID_LEN)
	length = CONTROL_ID_LEN;
    
    memcpy(control->id, id, length);
    control->id_type = type;
    control->id_len = length;
    if (control->entity)
	control_set_name(control);
}

int
ipmi_control_is_settable(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->settable;
}

int
ipmi_control_is_readable(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->readable;
}

void
ipmi_control_set_settable(ipmi_control_t *control, int val)
{
    control->settable = val;
}

void
ipmi_control_set_readable(ipmi_control_t *control, int val)
{
    control->readable = val;
}

int
ipmi_control_get_entity_id(ipmi_control_t *control)
{
    return ipmi_entity_get_entity_id(control->entity);
}

int
ipmi_control_get_entity_instance(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return ipmi_entity_get_entity_instance(control->entity);
}

ipmi_entity_t *
ipmi_control_get_entity(ipmi_control_t *control)
{
    return control->entity;
}

void
ipmi_control_set_oem_info(ipmi_control_t *control, void *oem_info,
			  ipmi_control_cleanup_oem_info_cb cleanup_handler)
{
    control->oem_info = oem_info;
    control->oem_info_cleanup_handler = cleanup_handler;
}

void *
ipmi_control_get_oem_info(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->oem_info;
}

void
ipmi_control_get_display_dimensions(ipmi_control_t *control,
				    unsigned int   *columns,
				    unsigned int   *rows)
{
    CHECK_CONTROL_LOCK(control);

    *columns = control->columns;
    *rows = control->rows;
}

void
ipmi_control_set_num_elements(ipmi_control_t *control, unsigned int val)
{
    control->num_vals = val;
}

unsigned int
ipmi_control_identifier_get_max_length(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->identifier_length;
}

void
ipmi_control_identifier_set_max_length(ipmi_control_t *control,
				       unsigned int   val)
{
    control->identifier_length = val;
}

void
ipmi_control_get_callbacks(ipmi_control_t *control, ipmi_control_cbs_t *cbs)
{
    *cbs = control->cbs;
}

void
ipmi_control_set_callbacks(ipmi_control_t *control, ipmi_control_cbs_t *cbs)
{
    control->cbs = *cbs;
}

ipmi_mc_t *
ipmi_control_get_mc(ipmi_control_t *control)
{
    return control->mc;
}

ipmi_mc_t *
ipmi_control_get_source_mc(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->source_mc;
}

int
ipmi_control_get_num(ipmi_control_t *control,
		     int            *lun,
		     int            *num)
{
    CHECK_CONTROL_LOCK(control);

    if (lun)
	*lun = control->lun;
    if (num)
	*num = control->num;
    return 0;
}

int
ipmi_control_light_set_with_setting(ipmi_control_t *control)
{
    return ((control->cbs.set_light != NULL)
	    || (control->cbs.get_light != NULL));
}

void
ipmi_control_light_set_lights(ipmi_control_t       *control,
			      unsigned int         num_lights,
			      ipmi_control_light_t *lights)
{
    control->num_vals = num_lights;
    control->lights = lights;
}

int
ipmi_control_get_num_vals(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->num_vals;
}

int
ipmi_control_get_num_light_values(ipmi_control_t *control,
				  unsigned int   light)
{
    CHECK_CONTROL_LOCK(control);

    if (!control->lights)
	return -1;
    if (light >= control->num_vals)
	return -1;

    return control->lights[light].num_values;
}

int
ipmi_control_get_num_light_transitions(ipmi_control_t   *control,
				       unsigned int     light,
				       unsigned int     set)
{
    CHECK_CONTROL_LOCK(control);

    if (!control->lights)
	return -1;
    if (light >= control->num_vals)
	return -1;
    if (set >= control->lights[light].num_values)
	return -1;

    return control->lights[light].values[set].num_transitions;
}

int
ipmi_control_get_light_color(ipmi_control_t   *control,
			     unsigned int     light,
			     unsigned int     set,
			     unsigned int     num)
{
    CHECK_CONTROL_LOCK(control);

    if (!control->lights)
	return -1;
    if (light >= control->num_vals)
	return -1;
    if (set >= control->lights[light].num_values)
	return -1;
    if (num > control->lights[light].values[set].num_transitions)
	return -1;

    return control->lights[light].values[set].transitions[num].color;
}

int
ipmi_control_get_light_color_time(ipmi_control_t   *control,
				  unsigned int     light,
				  unsigned int     set,
				  unsigned int     num)
{
    CHECK_CONTROL_LOCK(control);

    if (!control->lights)
	return -1;
    if (light >= control->num_vals)
	return -1;
    if (set >= control->lights[light].num_values)
	return -1;
    if (num > control->lights[light].values[set].num_transitions)
	return -1;

    return control->lights[light].values[set].transitions[num].time;
}

int
ipmi_control_set_light(ipmi_control_t       *control,
		       ipmi_light_setting_t *settings,
		       ipmi_control_op_cb   handler,
		       void                 *cb_data)
{
    CHECK_CONTROL_LOCK(control);

    if (!control->cbs.set_light)
	return ENOSYS;
    return control->cbs.set_light(control, settings, handler, cb_data);
}

int
ipmi_control_get_light(ipmi_control_t         *control,
		       ipmi_light_settings_cb handler,
		       void                   *cb_data)
{
    CHECK_CONTROL_LOCK(control);

    if (!control->cbs.get_light)
	return ENOSYS;
    return control->cbs.get_light(control, handler, cb_data);
}


typedef struct ipmi_light_s
{
    int color;
    int on_time;
    int off_time;
    int local_control;
} ipmi_light_t;

struct ipmi_light_setting_s
{
    int          count;
    ipmi_light_t *lights;
};

unsigned int
ipmi_light_setting_get_count(ipmi_light_setting_t *setting)
{
    return setting->count;
}

int
ipmi_light_setting_in_local_control(ipmi_light_setting_t *setting,
				    int                  num,
				    int                  *lc)
{
    if (num > setting->count)
	return EINVAL;

    *lc = setting->lights[num].local_control;
    return 0;
}

int
ipmi_light_setting_set_local_control(ipmi_light_setting_t *setting,
				     int                  num,
				     int                  lc)
{
    if (num > setting->count)
	return EINVAL;

    setting->lights[num].local_control = lc;
    return 0;
}

int
ipmi_light_setting_get_color(ipmi_light_setting_t *setting, int num,
			     int *color)
{
    if (num > setting->count)
	return EINVAL;

    *color = setting->lights[num].color;
    return 0;
}

int
ipmi_light_setting_set_color(ipmi_light_setting_t *setting, int num,
			     int color)
{
    if (num > setting->count)
	return EINVAL;

    setting->lights[num].color = color;
    return 0;
}

int
ipmi_light_setting_get_on_time(ipmi_light_setting_t *setting, int num,
			       int *time)
{
    if (num > setting->count)
	return EINVAL;

    *time = setting->lights[num].on_time;
    return 0;
}

int
ipmi_light_setting_set_on_time(ipmi_light_setting_t *setting, int num,
			       int time)
{
    if (num > setting->count)
	return EINVAL;

    setting->lights[num].on_time = time;
    return 0;
}

int
ipmi_light_setting_get_off_time(ipmi_light_setting_t *setting, int num,
				int *time)
{
    if (num > setting->count)
	return EINVAL;

    *time = setting->lights[num].off_time;
    return 0;
}

int
ipmi_light_setting_set_off_time(ipmi_light_setting_t *setting, int num,
				int time)
{
    if (num > setting->count)
	return EINVAL;

    setting->lights[num].off_time = time;
    return 0;
}

ipmi_light_setting_t *
ipmi_alloc_light_settings(unsigned int count)
{
    ipmi_light_setting_t *rv;

    if (count == 0)
	return NULL;

    rv = ipmi_mem_alloc(sizeof(*rv));
    if (!rv)
	return NULL;

    rv->lights = ipmi_mem_alloc(sizeof(ipmi_light_t) * count);
    if (!rv->lights) {
	ipmi_mem_free(rv);
	return NULL;
    }

    rv->count = count;
    memset(rv->lights, 0, sizeof(ipmi_light_t) * count);
    return rv;
}

void
ipmi_free_light_settings(ipmi_light_setting_t *settings)
{
    ipmi_mem_free(settings->lights);
    ipmi_mem_free(settings);
}

ipmi_light_setting_t *
ipmi_light_settings_dup(ipmi_light_setting_t *settings)
{
    ipmi_light_setting_t *rv;

    rv = ipmi_mem_alloc(sizeof(*rv));
    if (!rv)
	return NULL;

    rv->lights = ipmi_mem_alloc(sizeof(ipmi_light_t) * settings->count);
    if (!rv->lights) {
	ipmi_mem_free(rv);
	return NULL;
    }

    rv->count = settings->count;
    memcpy(rv->lights, settings->lights,
	   sizeof(ipmi_light_t) * settings->count);
    return rv;
}

int
ipmi_control_add_light_color_support(ipmi_control_t *control,
				     int            light_num,
				     unsigned int   color)
{
    if (light_num >= MAX_LIGHTS)
	return EINVAL;
    control->colors[light_num] |= (1 << color);
    return 0;
}

int
ipmi_control_light_is_color_sup(ipmi_control_t *control,
				int            light_num,
				unsigned int   color)
{
    CHECK_CONTROL_LOCK(control);

    if (light_num >= MAX_LIGHTS)
	return 0;
    return (control->colors[light_num] & (1 << color)) != 0;
}

int
ipmi_control_light_set_has_local_control(ipmi_control_t *control,
					 int            light_num,
					 int            val)
{
    if (light_num >= MAX_LIGHTS)
	return EINVAL;
     control->has_local_control[light_num] = val;
     return 0;
}

int
ipmi_control_light_has_loc_ctrl(ipmi_control_t *control,
				int            light_num)
{
    CHECK_CONTROL_LOCK(control);

    if (light_num >= MAX_LIGHTS)
	return 0;
    return control->has_local_control[light_num];
}

int
ipmi_cmp_control_id(ipmi_control_id_t id1, ipmi_control_id_t id2)
{
    int rv = ipmi_cmp_mc_id(id1.mcid, id2.mcid);
    if (rv)
	return rv;
    if (id1.lun > id2.lun)
	return 1;
    if (id1.lun < id2.lun)
	return -1;
    if (id1.control_num > id2.control_num)
	return 1;
    if (id1.control_num < id2.control_num)
	return -1;
    return 0;
}

void
ipmi_control_id_set_invalid(ipmi_control_id_t *id)
{
    memset(id, 0, sizeof(*id));
}

int
ipmi_control_id_is_invalid(const ipmi_control_id_t *id)
{
    return (id->mcid.domain_id.domain == NULL);
}


void
ipmi_control_set_hot_swap_indicator(ipmi_control_t *control,
				    int            val,
				    int            req_act_val,
				    int            active_val,
				    int            req_deact_val,
				    int            inactive_val)
{
    control->hot_swap_indicator = val;
    control->hot_swap_active_val = active_val;
    control->hot_swap_inactive_val = inactive_val;
    control->hot_swap_req_act_val = req_act_val;
    control->hot_swap_req_deact_val = req_deact_val;
}

int
ipmi_control_is_hot_swap_indicator(ipmi_control_t *control,
				   int            *req_act_val,
				   int            *active_val,
				   int            *req_deact_val,
				   int            *inactive_val)
{
    CHECK_CONTROL_LOCK(control);

    if (control->hot_swap_indicator) {
	if (active_val)
	    *active_val = control->hot_swap_active_val;
	if (inactive_val)
	    *inactive_val = control->hot_swap_inactive_val;
	if (req_act_val)
	    *req_act_val = control->hot_swap_req_act_val;
	if (req_deact_val)
	    *req_deact_val = control->hot_swap_req_deact_val;
	return 1;
    }
    return 0; 
}

void
ipmi_control_set_hot_swap_power(ipmi_control_t *control, int val)
{
    control->hot_swap_power = val;
}

int
ipmi_control_is_hot_swap_power(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->hot_swap_power;
}

int
ipmi_control_get_ignore_if_no_entity(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->ignore_if_no_entity;
}

void
ipmi_control_set_ignore_if_no_entity(ipmi_control_t *control,
				     int            ignore_if_no_entity)
{
    control->ignore_if_no_entity = ignore_if_no_entity;
}

int
ipmi_control_get_ignore_for_presence(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->ignore_for_presence;
}

void
ipmi_control_set_ignore_for_presence(ipmi_control_t *control, int ignore)
{
    control->ignore_for_presence = ignore;
}

ipmi_domain_t *
ipmi_control_get_domain(ipmi_control_t *control)
{
    return control->domain;
}

#ifdef IPMI_CHECK_LOCKS
void
__ipmi_check_control_lock(const ipmi_control_t *control)
{
    if (!control)
	return;

    if (!DEBUG_LOCKS)
	return;

    CHECK_ENTITY_LOCK(control->entity);
    CHECK_MC_LOCK(control->mc);

    if (control->usecount == 0)
	ipmi_report_lock_error(ipmi_domain_get_os_hnd(control->domain),
			       "control not locked when it should have been");
}
#endif

/***********************************************************************
 *
 * Crufty backwards-compatible interfaces.  Don't use these as they
 * are deprecated.
 *
 **********************************************************************/

int
ipmi_control_get_num_light_settings(ipmi_control_t *control,
				    unsigned int   light)
{
    return ipmi_control_get_num_light_values(control, light);
}

int
ipmi_control_light_is_color_supported(ipmi_control_t *control,
				      unsigned int   color)
{
    return ipmi_control_light_is_color_sup(control, 0, color);
}

int
ipmi_control_light_has_local_control(ipmi_control_t *control)
{
    return ipmi_control_light_has_loc_ctrl(control, 0);
}
