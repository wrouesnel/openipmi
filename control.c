/*
 * control.c
 *
 * MontaVista IPMI code for handling controls
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
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

#include <malloc.h>
#include <string.h>

#include <ipmi/ipmiif.h>
#include <ipmi/ipmi_mc.h>
#include <ipmi/ipmi_err.h>
#include <ipmi/ipmi_int.h>
#include <ipmi/ipmi_control.h>
#include "ilist.h"
#include "opq.h"

struct ipmi_control_info_s
{
    int                      destroyed;

    /* Indexed by control # */
    ipmi_control_t           **controls_by_idx;
    /* Size of above control array.  This will be 0 if the LUN has no
       controls. */
    int                      idx_size;

    opq_t *control_wait_q;
    int  wait_err;
};

#define CONTROL_ID_LENGTH 32
struct ipmi_control_s
{
    ipmi_mc_t *mc;
    unsigned char lun;
    unsigned char num;

    int destroyed;

    int type;
    char *type_str;

    int entity_id;
    int entity_instance;

    unsigned int num_vals;

    /* For light types. */
    ipmi_control_light_t *lights;

    /* For display types. */
    unsigned int columns;
    unsigned int rows;

    /* For identifier types. */
    unsigned int identifier_length;

    char id[CONTROL_ID_LENGTH+1];

    ipmi_control_cbs_t cbs;
    opq_t *waitq;

    void *oem_info;
};

ipmi_control_id_t
ipmi_control_convert_to_id(ipmi_control_t *control)
{
    ipmi_control_id_t val;
    ipmi_mc_id_t      mc_val;
    
    mc_val = ipmi_mc_convert_to_id(control->mc);
    val.bmc = mc_val.bmc;
    val.mc_num = mc_val.mc_num;
    val.channel = mc_val.channel;
    val.lun = control->lun;
    val.control_num = control->num;

    return val;
}

typedef struct mc_cb_info_s
{
    ipmi_control_cb   handler;
    void              *cb_data;
    ipmi_control_id_t id;
    int               err;
} mc_cb_info_t;

static void
mc_cb(ipmi_mc_t *mc, void *cb_data)
{
    mc_cb_info_t        *info = cb_data;
    ipmi_control_info_t *controls;
    
    ipmi_mc_entity_lock(info->id.bmc);
    controls = ipmi_mc_get_controls(mc);
    if (info->id.lun != 4)
	info->err = EINVAL;
    else if (info->id.control_num > controls->idx_size)
	info->err = EINVAL;
    else if (controls->controls_by_idx[info->id.control_num] == NULL)
	info->err = EINVAL;
    else
	info->handler(controls->controls_by_idx[info->id.control_num],
		      info->cb_data);
    ipmi_mc_entity_unlock(info->id.bmc);
}

int
ipmi_control_pointer_cb(ipmi_control_id_t id,
			ipmi_control_cb   handler,
			void              *cb_data)
{
    int               rv;
    ipmi_mc_id_t      mc_id;
    mc_cb_info_t      info;

    if (id.lun >= 5)
	return EINVAL;

    info.handler = handler;
    info.cb_data = cb_data;
    info.id = id;
    info.err = 0;

    mc_id.bmc = id.bmc;
    mc_id.channel = id.channel;
    mc_id.mc_num = id.mc_num;
    rv = ipmi_mc_pointer_cb(mc_id, mc_cb, &info);
    if (!rv)
	rv = info.err;

    return rv;
}

int
ipmi_find_control(ipmi_mc_t       *mc,
		  int             lun,
		  int             num,
		  ipmi_control_cb handler,
		  void            *cb_data)
{
    int                 rv = 0;
    ipmi_control_info_t *controls;

    if (lun != 4)
	return EINVAL;

    ipmi_mc_entity_lock(mc);
    controls = ipmi_mc_get_controls(mc);
    if (num > controls->idx_size)
	rv = EINVAL;
    else if (controls->controls_by_idx[num] == NULL)
	rv = EINVAL;
    else
	handler(controls->controls_by_idx[num], cb_data);
    ipmi_mc_entity_unlock(mc);

    return rv;
}

int
ipmi_controls_alloc(ipmi_mc_t *mc, ipmi_control_info_t **new_controls)
{
    ipmi_control_info_t *controls;

    controls = malloc(sizeof(*controls));
    if (!controls)
	return ENOMEM;
    memset(controls, 0, sizeof(*controls));
    controls->control_wait_q = opq_alloc(ipmi_mc_get_os_hnd(mc));
    if (! controls->control_wait_q) {
	free(controls);
	return ENOMEM;
    }

    *new_controls = controls;
    return 0;
}

int
ipmi_control_alloc_nonstandard(ipmi_control_t **new_control)
{
    ipmi_control_t *control;

    control = malloc(sizeof(*control));
    if (!control)
	return ENOMEM;

    memset(control, 0, sizeof(*control));

    *new_control = control;
    return 0;
}

void
ipmi_control_destroy_nonstandard(ipmi_control_t *control)
{
    free(control);
}

int
ipmi_control_add_nonstandard(ipmi_mc_t      *mc,
			     ipmi_control_t *control,
			     ipmi_entity_t  *ent)
{
    int                 i;
    int                 found = 0;
    ipmi_control_info_t *controls = ipmi_mc_get_controls(mc);
    void                *link;


    for (i=0; i<controls->idx_size; i++) {
	if (!controls->controls_by_idx[i]) {
	    found = 1;
	    break;
	}
    }

    if (!found) {
	ipmi_control_t **new_array;

	if (controls->idx_size >= 256)
	    return EMFILE;
	new_array = malloc(sizeof(*new_array) * (controls->idx_size + 16));
	if (!new_array)
	    return ENOMEM;
	memcpy(new_array, controls->controls_by_idx,
	       sizeof(*new_array) * (controls->idx_size));
	for (i=controls->idx_size; i<controls->idx_size+16; i++)
	    new_array[i] = NULL;
	if (controls->controls_by_idx)
	    free(controls->controls_by_idx);
	controls->controls_by_idx = new_array;
	i = controls->idx_size;
	controls->idx_size = i+16;
    }

    control->waitq = opq_alloc(ipmi_mc_get_os_hnd(mc));
    if (! control->waitq)
	return ENOMEM;

    link = ipmi_entity_alloc_control_link();
    if (!link) {
	opq_destroy(control->waitq);
	control->waitq = NULL;
	return ENOMEM;
    }

    control->mc = mc;
    control->lun = 4;
    control->num = i;
    controls->controls_by_idx[i] = control;
    control->entity_id = ipmi_entity_get_entity_id(ent);
    control->entity_instance = ipmi_entity_get_entity_instance(ent);

    ipmi_entity_add_control(ent, mc, control->lun, control->num, control, link);

    return 0;
}

int
ipmi_control_remove_nonstandard(ipmi_control_t *control)
{
    ipmi_control_info_t *controls = ipmi_mc_get_controls(control->mc);
    ipmi_entity_info_t  *ents = ipmi_mc_get_entities(control->mc);
    ipmi_entity_t       *ent;
    int                 rv;

    rv = ipmi_entity_find(ents,
			  control->mc,
			  control->entity_id,
			  control->entity_instance,
			  &ent);
    if (!rv)
	ipmi_entity_remove_control(ent, control->mc,
				   control->lun, control->num, control);

    controls->controls_by_idx[control->num] = 0;
    return 0;
}

static void
control_final_destroy(ipmi_control_t *control)
{
    opq_destroy(control->waitq);
    free(control);
}

void
ipmi_control_destroy(ipmi_control_t *control)
{
    control->destroyed = 1;
    if (!opq_stuff_in_progress(control->waitq))
	control_final_destroy(control);
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
	free(controls->controls_by_idx);

    if (controls->control_wait_q)
	opq_destroy(controls->control_wait_q);
    free(controls);
    return 0;
}

int
ipmi_control_set_val(ipmi_control_t     *control,
		     int                *val,
		     ipmi_control_op_cb handler,
		     void               *cb_data)
{
    return control->cbs.set_val(control, val, handler, cb_data);
}

int
ipmi_control_get_val(ipmi_control_t      *control,
		     ipmi_control_val_cb handler,
		     void                *cb_data)
{
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
    if (!control->cbs.get_identifier_val)
	return ENOSYS;
    return control->cbs.get_identifier_val(control, handler, cb_data);
}
				
int
ipmi_control_identifier_set_val(ipmi_control_t     *control,
				ipmi_control_op_cb handler,
				unsigned char      *val,
				int                length,
				void               *cb_data)
{
    if (!control->cbs.set_identifier_val)
	return ENOSYS;
    return control->cbs.set_identifier_val(control,
					   handler,
					   val,
					   length,
					   cb_data);
}

int
ipmi_control_get_type(ipmi_control_t *control)
{
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
    return control->type_str;
}

int
ipmi_control_get_id_length(ipmi_control_t *control)
{
    return strlen(control->id);
}

void
ipmi_control_get_id(ipmi_control_t *control, char *id, int length)
{
    strncpy(id, control->id, length);
}

void
ipmi_control_set_id(ipmi_control_t *control, char *id)
{
    strncpy(control->id, id, CONTROL_ID_LENGTH);
    control->id[CONTROL_ID_LENGTH] = '\0';
}

int
ipmi_control_get_entity_id(ipmi_control_t *control)
{
    return control->entity_id;
}

int
ipmi_control_get_entity_instance(ipmi_control_t *control)
{
    return control->entity_instance;
}

ipmi_entity_t *
ipmi_control_get_entity(ipmi_control_t *control)
{
    int           rv;
    ipmi_entity_t *ent;

    rv = ipmi_entity_find(ipmi_mc_get_entities(control->mc),
			  control->mc,
			  control->entity_id,
			  control->entity_instance,
			  &ent);
    if (rv)
	return NULL;
    return ent;
}

void
ipmi_control_set_oem_info(ipmi_control_t *control, void *oem_info)
{
    control->oem_info = oem_info;
}

void *
ipmi_control_get_oem_info(ipmi_control_t *control)
{
    return control->oem_info;
}

void
ipmi_control_get_display_dimensions(ipmi_control_t *control,
				    unsigned int   *columns,
				    unsigned int   *rows)
{
    *columns = control->columns;
    *rows = control->rows;
}

void
ipmi_control_set_num_relays(ipmi_control_t *control, unsigned int val)
{
    control->num_vals = val;
}

unsigned int
ipmi_control_identifier_get_max_length(ipmi_control_t *control)
{
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

int
ipmi_control_get_num(ipmi_control_t *control,
		     int            *lun,
		     int            *num)
{
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
    return control->num_vals;
}

int
ipmi_control_get_num_light_settings(ipmi_control_t *control,
				    unsigned int   light)
{
    if (light >= control->num_vals)
	return -1;

    return control->lights[light].num_settings;
}

int
ipmi_control_get_num_light_transitions(ipmi_control_t   *control,
				       unsigned int     light,
				       unsigned int     set)
{
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
    if (id1.bmc > id2.bmc)
	return 1;
    if (id1.bmc < id2.bmc)
	return -1;
    if (id1.mc_num > id2.mc_num)
	return 1;
    if (id1.mc_num < id2.mc_num)
	return -1;
    if (id1.channel > id2.channel)
	return 1;
    if (id1.channel < id2.channel)
	return -1;
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
