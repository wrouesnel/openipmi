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

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_control.h>
#include <OpenIPMI/ilist.h>
#include <OpenIPMI/opq.h>

struct ipmi_control_info_s
{
    int                      destroyed;

    /* Indexed by control # */
    ipmi_control_t           **controls_by_idx;
    /* Size of above control array.  This will be 0 if the LUN has no
       controls. */
    int                      idx_size;

    /* Total number of controls we have in this. */
    unsigned int control_count;

    opq_t *control_wait_q;
    int  wait_err;
};

#define CONTROL_ID_LENGTH 32
struct ipmi_control_s
{
    ipmi_mc_t *mc;
    unsigned char lun;
    unsigned char num;

    ipmi_mc_t *source_mc;

    int destroyed;

    int type;
    char *type_str;

    int settable;
    int readable;

    int entity_id;
    int entity_instance;

    unsigned int num_vals;

    int hot_swap_indicator;
    int hot_swap_active_val;
    int hot_swap_inactive_val;
    int hot_swap_req_act_val;
    int hot_swap_req_deact_val;

    int hot_swap_power;

    int has_events;

    int ignore_if_no_entity;

    /* A list of handlers to call when an event for the control comes
       in. */
    ilist_t *handler_list;

    /* For light types. */
    ipmi_control_light_t *lights;

    /* For display types. */
    unsigned int columns;
    unsigned int rows;

    /* For identifier types. */
    unsigned int identifier_length;

    /* Note that this is *not* nil terminated. */
    enum ipmi_str_type_e id_type;
    unsigned int id_len;
    char id[CONTROL_ID_LENGTH];

    ipmi_control_cbs_t cbs;
    opq_t *waitq;

    void                             *oem_info;
    ipmi_control_cleanup_oem_info_cb oem_info_cleanup_handler;

    ipmi_control_destroy_cb destroy_handler;
    void                    *destroy_handler_cb_data;
};

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
    
    ipmi_domain_entity_lock(domain);
    controls = _ipmi_mc_get_controls(mc);
    if (info->id.lun != 4)
	info->err = EINVAL;
    else if (info->id.control_num > controls->idx_size)
	info->err = EINVAL;
    else if (controls->controls_by_idx[info->id.control_num] == NULL)
	info->err = EINVAL;
    else
	info->handler(controls->controls_by_idx[info->id.control_num],
		      info->cb_data);
    ipmi_domain_entity_unlock(domain);
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

static void
control_final_destroy(ipmi_control_t *control)
{
    if (control->destroy_handler)
	control->destroy_handler(control,
				 control->destroy_handler_cb_data);

    if (control->oem_info_cleanup_handler)
	control->oem_info_cleanup_handler(control, control->oem_info);

    if (control->handler_list)
	ilist_twoitem_destroy(control->handler_list);

    if (control->waitq)
	opq_destroy(control->waitq);
    ipmi_mem_free(control);
}

int
ipmi_control_destroy(ipmi_control_t *control)
{
    ipmi_control_info_t *controls = _ipmi_mc_get_controls(control->mc);
    ipmi_domain_t       *domain = ipmi_mc_get_domain(control->mc);
    ipmi_entity_info_t  *ents = ipmi_domain_get_entities(domain);
    ipmi_entity_t       *ent;
    int                 rv;

    if (controls->controls_by_idx[control->num] != control)
	return EINVAL;

    rv = ipmi_entity_find(ents,
			  control->mc,
			  control->entity_id,
			  control->entity_instance,
			  &ent);
    if (!rv)
	ipmi_entity_remove_control(ent, control);

    controls->control_count--;
    controls->controls_by_idx[control->num] = NULL;

    control->destroyed = 1;
    if (!opq_stuff_in_progress(control->waitq))
	control_final_destroy(control);

    return 0;
}

static void
control_opq_ready2(ipmi_control_t *control, void *cb_data)
{
    ipmi_control_op_info_t *info = cb_data;
    if (info->__handler)
	info->__handler(control, 0, info->__cb_data);
}

static void
control_opq_ready(void *cb_data, int shutdown)
{
    ipmi_control_op_info_t *info = cb_data;
    int                   rv;

    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Control was destroyed while an operation was in progress");
	if (info->__handler)
	    info->__handler(info->__control, ECANCELED, info->__cb_data);
	return;
    }

    rv = ipmi_control_pointer_cb(info->__control_id, control_opq_ready2, info);
    if (rv)
	if (info->__handler)
	    info->__handler(info->__control, rv, info->__cb_data);
}

int
ipmi_control_add_opq(ipmi_control_t         *control,
		     ipmi_control_op_cb     handler,
		     ipmi_control_op_info_t *info,
		     void                   *cb_data)
{
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

    CHECK_CONTROL_LOCK(control);

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

    if (control->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Control was destroyed while an operation was in progress");
	if (info->__rsp_handler)
	    info->__rsp_handler(control, ECANCELED, NULL, info->__cb_data);
	control_final_destroy(control);
	return;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "MC was destroyed while a control operation was in progress");
	if (info->__rsp_handler)
	    info->__rsp_handler(control, ECANCELED, NULL, info->__cb_data);
	return;
    }

    /* Call the next stage with the lock held. */
    info->__rsp = rsp;
    rv = ipmi_control_pointer_cb(info->__control_id,
				 control_rsp_handler2,
				 info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Could not convert control id to a pointer");
	if (info->__rsp_handler)
	    info->__rsp_handler(NULL, rv, NULL, info->__cb_data);
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

    info->__control = control;
    info->__control_id = ipmi_control_convert_to_id(control);
    info->__cb_data = cb_data;
    info->__rsp_handler = handler;
    rv = ipmi_mc_send_command(mc, lun, msg, control_rsp_handler, info);
    return rv;
}

static void
control_addr_response_handler(ipmi_domain_t *domain,
			      ipmi_addr_t   *addr,
			      unsigned int  addr_len,
			      ipmi_msg_t    *msg,
			      void          *rsp_data1,
			      void          *rsp_data2)
{
    ipmi_control_op_info_t *info = rsp_data1;
    int                    rv;
    ipmi_control_t         *control = info->__control;

    if (control->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Control was destroyed while an operation was in progress");
	if (info->__rsp_handler)
	    info->__rsp_handler(control, ECANCELED, NULL, info->__cb_data);
	control_final_destroy(control);
	return;
    }

    /* Call the next stage with the lock held. */
    info->__rsp = msg;
    rv = ipmi_control_pointer_cb(info->__control_id,
				 control_rsp_handler2,
				 info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Could not convert control id to a pointer");
	if (info->__rsp_handler)
	    info->__rsp_handler(control, rv, NULL, info->__cb_data);
    }
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

    CHECK_MC_LOCK(bmc);
    CHECK_CONTROL_LOCK(control);

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
    void                *link;

    CHECK_MC_LOCK(mc);
    CHECK_ENTITY_LOCK(ent);

    domain = ipmi_mc_get_domain(mc);
    os_hnd = ipmi_domain_get_os_hnd(domain);

    if (num >= 256)
	return EINVAL;

    if (num >= controls->idx_size) {
	ipmi_control_t **new_array;
	unsigned int   new_size;
	int            i;

	/* Allocate the array in multiples of 16 (to avoid thrashing malloc
	   too much). */
	new_size = ((num / 16) * 16) + 16;
	new_array = ipmi_mem_alloc(sizeof(*new_array) * new_size);
	if (!new_array)
	    return ENOMEM;
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
    if (! control->waitq)
	return ENOMEM;

    control->handler_list = alloc_ilist();
    if (! control->handler_list) {
	opq_destroy(control->waitq);
	return ENOMEM;
    }

    link = ipmi_entity_alloc_control_link();
    if (!link) {
	opq_destroy(control->waitq);
	control->waitq = NULL;
	return ENOMEM;
    }

    control->mc = mc;
    control->source_mc = source_mc;
    control->lun = 4;
    control->num = num;
    if (! controls->controls_by_idx[num])
	controls->control_count++;
    controls->controls_by_idx[num] = control;
    control->entity_id = ipmi_entity_get_entity_id(ent);
    control->entity_instance = ipmi_entity_get_entity_instance(ent);
    control->destroy_handler = destroy_handler;
    control->destroy_handler_cb_data = destroy_handler_cb_data;

    ipmi_entity_add_control(ent, control, link);

    return 0;
}

int
ipmi_controls_destroy(ipmi_control_info_t *controls)
{
    int j;

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
    ipmi_mem_free(controls);
    return 0;
}

int
ipmi_control_set_val(ipmi_control_t     *control,
		     int                *val,
		     ipmi_control_op_cb handler,
		     void               *cb_data)
{
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
    CHECK_CONTROL_LOCK(control);

    if (!control->cbs.get_val)
	return ENOSYS;
    return control->cbs.get_val(control, handler, cb_data);
}

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

static void
control_val_event_call_handler(void *data, void *ihandler, void *cb_data)
{
    ipmi_control_val_event_cb handler = ihandler;
    control_event_info_t      *info = data;
    int                       handled;

    handled = ! handler(info->control,
			info->valid_vals,
			info->vals,
			cb_data,
			info->event);
    if (!info->handled && handled)
	info->handled = 1;
    info->event = NULL;
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
    info.handled = 0;

    ilist_iter_twoitem(control->handler_list,
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

    if (ilist_twoitem_exists(control->handler_list, handler, cb_data))
	return EADDRINUSE;

    if (! ilist_add_twoitem(control->handler_list, handler, cb_data))
	return ENOMEM;

    return 0;
}

int ipmi_control_remove_val_event_handler(ipmi_control_t            *control,
					  ipmi_control_val_event_cb handler,
					  void                      *cb_data)
{
    CHECK_CONTROL_LOCK(control);

    if (! ilist_remove_twoitem(control->handler_list, handler, cb_data))
	return ENOENT;

    return 0;
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
    CHECK_CONTROL_LOCK(control);

    if (!control->cbs.set_identifier_val)
	return ENOSYS;
    return control->cbs.set_identifier_val(control,
					   val,
					   length,
					   handler,
					   cb_data);
}

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

char *
ipmi_control_get_type_string(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->type_str;
}

int
ipmi_control_get_id_length(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->id_len;
}

int
ipmi_control_get_id(ipmi_control_t *control, char *id, int length)
{
    int clen;

    CHECK_CONTROL_LOCK(control);

    if (control->id_len > length)
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
    if (length > CONTROL_ID_LENGTH)
	length = CONTROL_ID_LENGTH;
    
    memcpy(control->id, id, length);
    control->id_type = type;
    control->id_len = length;
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
    CHECK_CONTROL_LOCK(control);

    return control->entity_id;
}

int
ipmi_control_get_entity_instance(ipmi_control_t *control)
{
    CHECK_CONTROL_LOCK(control);

    return control->entity_instance;
}

ipmi_entity_t *
ipmi_control_get_entity(ipmi_control_t *control)
{
    int           rv;
    ipmi_entity_t *ent;
    ipmi_domain_t *domain = ipmi_mc_get_domain(control->mc);

    CHECK_CONTROL_LOCK(control);

    rv = ipmi_entity_find(ipmi_domain_get_entities(domain),
			  control->mc,
			  control->entity_id,
			  control->entity_instance,
			  &ent);
    if (rv)
	return NULL;
    return ent;
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
    CHECK_CONTROL_LOCK(control);

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
ipmi_control_get_num_light_settings(ipmi_control_t *control,
				    unsigned int   light)
{
    CHECK_CONTROL_LOCK(control);

    if (light >= control->num_vals)
	return -1;

    return control->lights[light].num_settings;
}

int
ipmi_control_get_num_light_transitions(ipmi_control_t   *control,
				       unsigned int     light,
				       unsigned int     set)
{
    CHECK_CONTROL_LOCK(control);

    if (light >= control->num_vals)
	return -1;
    if (set >= control->lights[light].num_settings)
	return -1;

    return control->lights[light].settings[set].num_transitions;
}

int
ipmi_control_get_light_color(ipmi_control_t   *control,
			     unsigned int     light,
			     unsigned int     set,
			     unsigned int     num)
{
    CHECK_CONTROL_LOCK(control);

    if (light >= control->num_vals)
	return -1;
    if (set >= control->lights[light].num_settings)
	return -1;
    if (num > control->lights[light].settings[set].num_transitions)
	return -1;

    return control->lights[light].settings[set].transitions[num].color;
}

int
ipmi_control_get_light_color_time(ipmi_control_t   *control,
				  unsigned int     light,
				  unsigned int     set,
				  unsigned int     num)
{
    CHECK_CONTROL_LOCK(control);

    if (light >= control->num_vals)
	return -1;
    if (set >= control->lights[light].num_settings)
	return -1;
    if (num > control->lights[light].settings[set].num_transitions)
	return -1;

    return control->lights[light].settings[set].transitions[num].time;
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

#ifdef IPMI_CHECK_LOCKS
void
__ipmi_check_control_lock(ipmi_control_t *control)
{
    ipmi_domain_t *domain;
    domain = ipmi_mc_get_domain(control->mc);
    __ipmi_check_domain_lock(domain);
    __ipmi_check_domain_entity_lock(domain);
}
#endif

