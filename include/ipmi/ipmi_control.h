/*
 * ipmi_control.h
 *
 * MontaVista IPMI interface for dealing with controls
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

#ifndef _IPMI_CONTROL_H
#define _IPMI_CONTROL_H

#include <ipmi/ipmi_types.h>

/* The abstract type for controls. */
typedef struct ipmi_control_info_s ipmi_control_info_t;

/* Allocate a repository for holding controls for an MC. */
int ipmi_controls_alloc(ipmi_mc_t *mc, ipmi_control_info_t **new_controls);

/* Destroy a control repository and all the controls in it. */
int ipmi_controls_destroy(ipmi_control_info_t *controls);

/*
 * These are for OEM code to create their own controls.
 */

/* Uses ipmi_control_op_cb defined in ipmiif.h. */

typedef void (*ipmi_control_rsp_cb)(ipmi_control_t *control,
				    int            err,
				    ipmi_msg_t     *rsp,
				    void           *cb_data);

typedef struct ipmi_control_op_info_s
{
    ipmi_control_id_t   __control_id;
    ipmi_control_t      *__control;
    void                *__cb_data;
    ipmi_control_op_cb  __handler;
    ipmi_control_rsp_cb __rsp_handler;
    ipmi_msg_t          *__rsp;
} ipmi_control_op_info_t;

int ipmi_control_add_opq(ipmi_control_t        *control,
			ipmi_control_op_cb     handler,
			ipmi_control_op_info_t *info,
			void                   *cb_data);

void ipmi_control_opq_done(ipmi_control_t *control);

int ipmi_control_send_command(ipmi_control_t        *control,
			     ipmi_mc_t              *mc,
			     unsigned int           lun,
			     ipmi_msg_t             *msg,
			     ipmi_control_rsp_cb    handler,
			     ipmi_control_op_info_t *info,
			     void                   *cb_data);

/* Call the given callback with the control. */
int ipmi_find_control(ipmi_mc_t       *mc,
		      int             lun,
		      int             num,
		      ipmi_control_cb handler,
		      void            *cb_data);

/* Allocate a control, it will not be associated with anything yet. */
int ipmi_control_alloc_nonstandard(ipmi_control_t **new_control);

/* Destroy a control. */
int ipmi_control_destroy(ipmi_control_t *control);

typedef void (*ipmi_control_destroy_cb)(ipmi_control_t *control,
					void           *cb_data);
/* Add a control for the given MC and put it into the given entity.
   Note that control will NOT appear as owned by the MC, the MC is used
   for the OS handler and such. */
int ipmi_control_add_nonstandard(
    ipmi_mc_t               *mc,
    ipmi_control_t          *control,
    ipmi_entity_t           *ent,
    ipmi_control_destroy_cb destroy_handler,
    void                    *destroy_handler_cb_data);

typedef int (*ipmi_control_set_val_cb)(ipmi_control_t     *control,
				       int                *val,
				       ipmi_control_op_cb handler,
				       void               *cb_data);

typedef int (*ipmi_control_get_val_cb)(ipmi_control_t      *control,
				       ipmi_control_val_cb handler,
				       void                *cb_data);

typedef int (*ipmi_control_set_display_string_cb)(ipmi_control_t *control,
						  unsigned int   start_row,
						  unsigned int   start_column,
						  char           *str,
						  unsigned int   len,
						  ipmi_control_op_cb handler,
						  void           *cb_data);

typedef int (*ipmi_control_get_display_string_cb)(ipmi_control_t  *control,
						  unsigned int    start_row,
						  unsigned int    start_column,
						  unsigned int    len,
						  ipmi_control_str_cb handler,
						  void            *cb_data);
typedef int (*ipmi_control_identifier_get_val_cb)(
    ipmi_control_t                 *control,
    ipmi_control_identifier_val_cb handler,
    void                           *cb_data);

typedef int (*ipmi_control_identifier_set_val_cb)(ipmi_control_t     *control,
						  unsigned char      *val,
						  int                length,
						  ipmi_control_op_cb handler,
						  void               *cb_data);

typedef struct ipmi_control_cbs_s
{
    ipmi_control_set_val_cb		   set_val;
    ipmi_control_get_val_cb		   get_val;
    ipmi_control_set_display_string_cb set_display_string;
    ipmi_control_get_display_string_cb get_display_string;
    ipmi_control_identifier_get_val_cb get_identifier_val;
    ipmi_control_identifier_set_val_cb set_identifier_val;
} ipmi_control_cbs_t;

void ipmi_control_identifier_set_max_length(ipmi_control_t *control,
					    unsigned int   val);

void ipmi_control_set_id(ipmi_control_t *control, char *id);
void ipmi_control_set_type(ipmi_control_t *control, int val);
void ipmi_control_set_settable(ipmi_control_t *control, int val);
void ipmi_control_set_readable(ipmi_control_t *control, int val);
int ipmi_control_get_ignore_if_no_entity(ipmi_control_t *control);
void ipmi_control_set_ignore_if_no_entity(ipmi_control_t *control,
				          int            ignore_if_no_entity);

void ipmi_control_set_hot_swap_indicator(ipmi_control_t *control, int val);

typedef struct ipmi_control_transition_s
{
    unsigned int color;
    unsigned int time;
} ipmi_control_transition_t;
typedef struct ipmi_control_setting_s
{
    unsigned int          num_transitions;
    ipmi_control_transition_t *transitions;
} ipmi_control_setting_t;
typedef struct ipmi_control_light_s
{
    unsigned int           num_settings;
    ipmi_control_setting_t *settings;
} ipmi_control_light_t;
void ipmi_control_light_set_lights(ipmi_control_t       *control,
				   unsigned int         num_lights,
				   ipmi_control_light_t *lights);

void ipmi_control_set_num_elements(ipmi_control_t *control, unsigned int val);

int ipmi_control_get_num(ipmi_control_t *control,
			 int            *lun,
			 int            *num);

void ipmi_control_set_oem_info(ipmi_control_t *control, void *oem_info);
void *ipmi_control_get_oem_info(ipmi_control_t *control);

/* Can be used by OEM code to replace some or all of the callbacks for
   a control. */
void ipmi_control_get_callbacks(ipmi_control_t     *control,
				ipmi_control_cbs_t *cbs);
void ipmi_control_set_callbacks(ipmi_control_t     *control,
				ipmi_control_cbs_t *cbs);

/* Get the MC that the control is in. */
ipmi_mc_t *ipmi_control_get_mc(ipmi_control_t *control);

#endif /* _IPMI_CONTROL_H */
