/*
 * ind.c
 *
 * MontaVista IPMI code for handling indicators
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
#include <ipmi/ipmi_ind.h>
#include "ilist.h"
#include "opq.h"

struct ipmi_ind_info_s
{
    int                      destroyed;

    /* Indexed by ind # */
    ipmi_ind_t            **inds_by_idx;
    /* Size of above ind array.  This will be 0 if the LUN has no
       inds. */
    int                      idx_size;

    opq_t *ind_wait_q;
    int  wait_err;
};

#define IND_ID_LENGTH 32
struct ipmi_ind_s
{
    ipmi_mc_t *mc;
    unsigned char lun;
    unsigned char num;

    int destroyed;

    int type;

    int entity_id;
    int entity_instance;

    unsigned int num_vals;

    /* For light types. */
    ipmi_ind_light_t *lights;

    /* For display types. */
    unsigned int columns;
    unsigned int rows;

    /* For identifier types. */
    unsigned int identifier_length;

    char id[IND_ID_LENGTH+1];

    ipmi_ind_cbs_t cbs;
    opq_t *waitq;

    void *oem_info;
};

ipmi_ind_id_t
ipmi_ind_convert_to_id(ipmi_ind_t *ind)
{
    ipmi_ind_id_t val;
    ipmi_mc_id_t mc_val;
    
    mc_val = ipmi_mc_convert_to_id(ind->mc);
    val.bmc = mc_val.bmc;
    val.mc_num = mc_val.mc_num;
    val.channel = mc_val.channel;
    val.lun = ind->lun;
    val.ind_num = ind->num;

    return val;
}

typedef struct mc_cb_info_s
{
    ipmi_ind_cb   handler;
    void          *cb_data;
    ipmi_ind_id_t id;
    int           err;
} mc_cb_info_t;

static void
mc_cb(ipmi_mc_t *mc, void *cb_data)
{
    mc_cb_info_t    *info = cb_data;
    ipmi_ind_info_t *inds;
    
    ipmi_mc_entity_lock(info->id.bmc);
    inds = ipmi_mc_get_inds(mc);
    if (info->id.lun != 4)
	info->err = EINVAL;
    else if (info->id.ind_num > inds->idx_size)
	info->err = EINVAL;
    else if (inds->inds_by_idx[info->id.ind_num] == NULL)
	info->err = EINVAL;
    else
	info->handler(inds->inds_by_idx[info->id.ind_num],
		      info->cb_data);
    ipmi_mc_entity_unlock(info->id.bmc);
}

int
ipmi_ind_pointer_cb(ipmi_ind_id_t id,
		    ipmi_ind_cb   handler,
		    void             *cb_data)
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
ipmi_find_ind(ipmi_mc_t *mc, int lun, int num,
	      ipmi_ind_cb handler, void *cb_data)
{
    int                rv = 0;
    ipmi_ind_info_t *inds;

    if (lun != 4)
	return EINVAL;

    ipmi_mc_entity_lock(mc);
    inds = ipmi_mc_get_inds(mc);
    if (num > inds->idx_size)
	rv = EINVAL;
    else if (inds->inds_by_idx[num] == NULL)
	rv = EINVAL;
    else
	handler(inds->inds_by_idx[num], cb_data);
    ipmi_mc_entity_unlock(mc);

    return rv;
}

int
ipmi_inds_alloc(ipmi_mc_t *mc, ipmi_ind_info_t **new_inds)
{
    ipmi_ind_info_t *inds;

    inds = malloc(sizeof(*inds));
    if (!inds)
	return ENOMEM;
    memset(inds, 0, sizeof(*inds));
    inds->ind_wait_q = opq_alloc(ipmi_mc_get_os_hnd(mc));
    if (! inds->ind_wait_q) {
	free(inds);
	return ENOMEM;
    }

    *new_inds = inds;
    return 0;
}

int
ipmi_ind_alloc_nonstandard(ipmi_ind_t **new_ind)
{
    ipmi_ind_t *ind;

    ind = malloc(sizeof(*ind));
    if (!ind)
	return ENOMEM;

    memset(ind, 0, sizeof(*ind));

    *new_ind = ind;
    return 0;
}

void
ipmi_ind_destroy_nonstandard(ipmi_ind_t *ind)
{
    free(ind);
}

int
ipmi_ind_add_nonstandard(ipmi_mc_t     *mc,
			 ipmi_ind_t    *ind,
			 ipmi_entity_t *ent)
{
    int             i;
    int             found = 0;
    ipmi_ind_info_t *inds = ipmi_mc_get_inds(mc);
    void            *link;


    for (i=0; i<inds->idx_size; i++) {
	if (!inds->inds_by_idx[i]) {
	    found = 1;
	    break;
	}
    }

    if (!found) {
	ipmi_ind_t **new_array;

	if (inds->idx_size >= 256)
	    return EMFILE;
	new_array = malloc(sizeof(*new_array) * (inds->idx_size + 16));
	if (!new_array)
	    return ENOMEM;
	memcpy(new_array, inds->inds_by_idx,
	       sizeof(*new_array) * (inds->idx_size));
	for (i=inds->idx_size; i<inds->idx_size+16; i++)
	    new_array[i] = NULL;
	if (inds->inds_by_idx)
	    free(inds->inds_by_idx);
	inds->inds_by_idx = new_array;
	i = inds->idx_size;
	inds->idx_size = i+16;
    }

    ind->waitq = opq_alloc(ipmi_mc_get_os_hnd(mc));
    if (! ind->waitq)
	return ENOMEM;

    link = ipmi_entity_alloc_ind_link();
    if (!link) {
	opq_destroy(ind->waitq);
	ind->waitq = NULL;
	return ENOMEM;
    }

    ind->mc = mc;
    ind->lun = 4;
    ind->num = i;
    inds->inds_by_idx[i] = ind;
    ind->entity_id = ipmi_entity_get_entity_id(ent);
    ind->entity_instance = ipmi_entity_get_entity_instance(ent);

    ipmi_entity_add_ind(ent, mc, ind->lun, ind->num, ind, link);

    return 0;
}

int
ipmi_ind_remove_nonstandard(ipmi_ind_t *ind)
{
    ipmi_ind_info_t    *inds = ipmi_mc_get_inds(ind->mc);
    ipmi_entity_info_t *ents = ipmi_mc_get_entities(ind->mc);
    ipmi_entity_t      *ent;
    int                rv;

    rv = ipmi_entity_find(ents,
			  ind->mc,
			  ind->entity_id,
			  ind->entity_instance,
			  &ent);
    if (!rv)
	ipmi_entity_remove_ind(ent, ind->mc,
			       ind->lun, ind->num, ind);

    inds->inds_by_idx[ind->num] = 0;
    return 0;
}

static void
ind_final_destroy(ipmi_ind_t *ind)
{
    opq_destroy(ind->waitq);
    free(ind);
}

void
ipmi_ind_destroy(ipmi_ind_t *ind)
{
    ind->destroyed = 1;
    if (!opq_stuff_in_progress(ind->waitq))
	ind_final_destroy(ind);
}

int
ipmi_inds_destroy(ipmi_ind_info_t *inds)
{
    int j;

    if (inds->destroyed)
	return EINVAL;

    inds->destroyed = 1;
    for (j=0; j<inds->idx_size; j++) {
	if (inds->inds_by_idx[j]) {
	    ipmi_ind_destroy(inds->inds_by_idx[j]);
	}
    }
    if (inds->inds_by_idx)
	free(inds->inds_by_idx);

    if (inds->ind_wait_q)
	opq_destroy(inds->ind_wait_q);
    free(inds);
    return 0;
}

int
ipmi_ind_set_val(ipmi_ind_t     *ind,
		 int            *val,
		 ipmi_ind_op_cb handler,
		 void           *cb_data)
{
    return ind->cbs.set_val(ind, val, handler, cb_data);
}

int
ipmi_ind_get_val(ipmi_ind_t *ind, ipmi_ind_val_cb handler, void *cb_data)
{
    return ind->cbs.get_val(ind, handler, cb_data);
}


int
ipmi_ind_set_display_string(ipmi_ind_t     *ind,
			    unsigned int   start_row,
			    unsigned int   start_column,
			    char           *str,
			    unsigned int   len,
			    ipmi_ind_op_cb handler,
			    void           *cb_data)
{
    if (!ind->cbs.set_display_string)
	return ENOSYS;
    return ind->cbs.set_display_string(ind,
				       start_row,
				       start_column,
				       str, len,
				       handler, cb_data);
}
				
int
ipmi_ind_get_display_string(ipmi_ind_t      *ind,
			    unsigned int    start_row,
			    unsigned int    start_column,
			    unsigned int    len,
			    ipmi_ind_str_cb handler,
			    void            *cb_data)
{
    if (!ind->cbs.get_display_string)
	return ENOSYS;
    return ind->cbs.get_display_string(ind,
				       start_row,
				       start_column,
				       len,
				       handler, cb_data);
}

int
ipmi_ind_identifier_get_val(ipmi_ind_t                 *ind,
				ipmi_ind_identifier_val_cb handler,
				void                       *cb_data)
{
    if (!ind->cbs.get_identifier_val)
	return ENOSYS;
    return ind->cbs.get_identifier_val(ind, handler, cb_data);
}
				
int
ipmi_ind_identifier_set_val(ipmi_ind_t     *ind,
			    ipmi_ind_op_cb handler,
			    unsigned char  *val,
			    int            length,
			    void           *cb_data)
{
    if (!ind->cbs.set_identifier_val)
	return ENOSYS;
    return ind->cbs.set_identifier_val(ind, handler, val, length, cb_data);
}

int
ipmi_ind_get_type(ipmi_ind_t *ind)
{
    return ind->type;
}

void
ipmi_ind_set_type(ipmi_ind_t *ind, int val)
{
    ind->type = val;
}

int
ipmi_ind_get_id_length(ipmi_ind_t *ind)
{
    return strlen(ind->id);
}

void
ipmi_ind_get_id(ipmi_ind_t *ind, char *id, int length)
{
    strncpy(id, ind->id, length);
}

void
ipmi_ind_set_id(ipmi_ind_t *ind, char *id)
{
    strncpy(ind->id, id, IND_ID_LENGTH);
    ind->id[IND_ID_LENGTH] = '\0';
}

int
ipmi_ind_get_entity_id(ipmi_ind_t *ind)
{
    return ind->entity_id;
}

int
ipmi_ind_get_entity_instance(ipmi_ind_t *ind)
{
    return ind->entity_instance;
}

ipmi_entity_t *
ipmi_ind_get_entity(ipmi_ind_t *ind)
{
    int           rv;
    ipmi_entity_t *ent;

    rv = ipmi_entity_find(ipmi_mc_get_entities(ind->mc),
			  ind->mc,
			  ind->entity_id,
			  ind->entity_instance,
			  &ent);
    if (rv)
	return NULL;
    return ent;
}

void
ipmi_ind_set_oem_info(ipmi_ind_t *ind, void *oem_info)
{
    ind->oem_info = oem_info;
}

void *
ipmi_ind_get_oem_info(ipmi_ind_t *ind)
{
    return ind->oem_info;
}

void
ipmi_ind_get_display_dimensions(ipmi_ind_t   *ind,
				unsigned int *columns,
				unsigned int *rows)
{
    *columns = ind->columns;
    *rows = ind->rows;
}

void
ipmi_ind_set_num_relays(ipmi_ind_t *ind, unsigned int val)
{
    ind->num_vals = val;
}

unsigned int
ipmi_ind_identifier_get_max_length(ipmi_ind_t *ind)
{
    return ind->identifier_length;
}

void
ipmi_ind_identifier_set_max_length(ipmi_ind_t *ind, unsigned int val)
{
    ind->identifier_length = val;
}

void
ipmi_ind_get_callbacks(ipmi_ind_t *ind, ipmi_ind_cbs_t *cbs)
{
    *cbs = ind->cbs;
}

void
ipmi_ind_set_callbacks(ipmi_ind_t *ind, ipmi_ind_cbs_t *cbs)
{
    ind->cbs = *cbs;
}

ipmi_mc_t *
ipmi_ind_get_mc(ipmi_ind_t *ind)
{
    return ind->mc;
}

int
ipmi_ind_get_num(ipmi_ind_t *ind,
		 int        *lun,
		 int        *num)
{
    if (lun)
	*lun = ind->lun;
    if (num)
	*num = ind->num;
    return 0;
}

void
ipmi_ind_light_set_lights(ipmi_ind_t       *ind,
			  unsigned int     num_lights,
			  ipmi_ind_light_t *lights)
{
    ind->num_vals = num_lights;
    ind->lights = lights;
}

int
ipmi_ind_get_num_vals(ipmi_ind_t *ind)
{
    return ind->num_vals;
}

int
ipmi_ind_get_num_light_settings(ipmi_ind_t *ind,
				unsigned int light)
{
    if (light >= ind->num_vals)
	return -1;

    return ind->lights[light].num_settings;
}

int
ipmi_ind_get_num_light_transitions(ipmi_ind_t   *ind,
				   unsigned int light,
				   unsigned int set)
{
    if (light >= ind->num_vals)
	return -1;
    if (set >= ind->lights[light].num_settings)
	return -1;

    return ind->lights[light].settings[set].num_transitions;
}

int
ipmi_ind_get_light_color(ipmi_ind_t   *ind,
			 unsigned int light,
			 unsigned int set,
			 unsigned int num)
{
    if (light >= ind->num_vals)
	return -1;
    if (set >= ind->lights[light].num_settings)
	return -1;
    if (num > ind->lights[light].settings[set].num_transitions)
	return -1;

    return ind->lights[light].settings[set].transitions[num].color;
}

int
ipmi_ind_get_light_color_time(ipmi_ind_t   *ind,
			      unsigned int light,
			      unsigned int set,
			      unsigned int num)
{
    if (light >= ind->num_vals)
	return -1;
    if (set >= ind->lights[light].num_settings)
	return -1;
    if (num > ind->lights[light].settings[set].num_transitions)
	return -1;

    return ind->lights[light].settings[set].transitions[num].time;
}
