/*
 * ipmi_ind.h
 *
 * MontaVista IPMI interface for dealing with indicators
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

#ifndef _IPMI_IND_H
#define _IPMI_IND_H

#include <ipmi/ipmi_types.h>

/* The abstract type for indicators. */
typedef struct ipmi_ind_info_s ipmi_ind_info_t;

/* Allocate a repository for holding indicators for an MC. */
int ipmi_inds_alloc(ipmi_mc_t *mc, ipmi_ind_info_t **new_inds);

/* Destroy a indicator repository and all the indicators in it. */
int ipmi_inds_destroy(ipmi_ind_info_t *inds);

/*
 * These are for OEM code to create their own indicators.
 */

/* Call the given callback with the indicator. */
int ipmi_find_ind(ipmi_mc_t *mc, int lun, int num,
		  ipmi_ind_cb handler, void *cb_data);

/* Allocate a indicator, it will not be associated with anything yet. */
int ipmi_ind_alloc_nonstandard(ipmi_ind_t **new_ind);

/* Destroy a indicators. */
void ipmi_ind_destroy_nonstandard(ipmi_ind_t *ind);

/* Add a indicator for the given MC and put it into the given entity.
   Note that indicator will NOT appear as owned by the MC, the MC is used
   for the OS handler and such. */
int ipmi_ind_add_nonstandard(ipmi_mc_t     *mc,
			     ipmi_ind_t    *ind,
			     ipmi_entity_t *ent);

/* Remove the given indicator from the entity. */
int ipmi_ind_remove_nonstandard(ipmi_ind_t *ind);

typedef int (*ipmi_ind_set_val_cb)(ipmi_ind_t     *ind,
				   int            val,
				   ipmi_ind_op_cb *handler,
				   void           *cb_data);

typedef int (*ipmi_ind_get_val_cb)(ipmi_ind_t      *ind,
				   ipmi_ind_val_cb *handler,
				   void            *cb_data);

typedef int (*ipmi_ind_set_display_string_cb)(ipmi_ind_t     *ind,
					      unsigned int   start_row,
					      unsigned int   start_column,
					      char           *str,
					      unsigned int   len,
					      ipmi_ind_op_cb *handler,
					      void           *cb_data);

typedef int (*ipmi_ind_get_display_string_cb)(ipmi_ind_t      *ind,
					      unsigned int    start_row,
					      unsigned int    start_column,
					      unsigned int    len,
					      ipmi_ind_str_cb *handler,
					      void            *cb_data);

typedef struct ipmi_ind_cbs_s
{
    ipmi_ind_set_val_cb		   set_val;
    ipmi_ind_get_val_cb		   get_val;
    ipmi_ind_set_display_string_cb set_display_string;
    ipmi_ind_get_display_string_cb get_display_string;
} ipmi_ind_cbs_t;

/* Can be used by OEM code to replace some or all of the callbacks for
   a indicator. */
void ipmi_ind_get_callbacks(ipmi_ind_t *ind, ipmi_ind_cbs_t *cbs);
void ipmi_ind_set_callbacks(ipmi_ind_t *ind, ipmi_ind_cbs_t *cbs);

/* Get the MC that the indicator is in. */
ipmi_mc_t *ipmi_ind_get_mc(ipmi_ind_t *ind);

#endif /* _IPMI_IND_H */
