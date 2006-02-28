/*
 * chassis.c
 *
 * Code to map chassis messages to controls
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 *  (C) 2003 MontaVista Software, Inc.
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

#include <stdlib.h>
#include <string.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>

#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_oem.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/ipmi_entity.h>
#include <OpenIPMI/internal/ipmi_control.h>
#include <OpenIPMI/internal/ipmi_mc.h>

static int
chassis_entity_sdr_add(ipmi_entity_t   *ent,
		       ipmi_sdr_info_t *sdrs,
		       void            *cb_data)
{
    /* Don't put the entities into an SDR */
    return 0;
}

typedef struct chassis_set_info_s
{
    ipmi_control_op_cb     handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
    int                    vals[1];
} chassis_set_info_t;

static void
chassis_reset_set_cb(ipmi_control_t *control,
		     int            err,
		     ipmi_msg_t     *rsp,
		     void           *cb_data)
{
    chassis_set_info_t *control_info = cb_data;

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%schassis.c(chassis_reset_set_cb): "
		 "Received IPMI error: %x",
		 CONTROL_NAME(control), rsp->data[0]);
	if (control_info->handler)
	    control_info->handler(control,
				  IPMI_IPMI_ERR_VAL(rsp->data[0]),
				  control_info->cb_data);
	goto out;
    }

    if (control_info->handler)
	control_info->handler(control, 0, control_info->cb_data);

 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
chassis_reset_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    chassis_set_info_t *control_info = cb_data;
    ipmi_msg_t         msg;
    unsigned char      data[1];
    ipmi_mc_t	       *mc = ipmi_control_get_mc(control);
    int                rv;

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = IPMI_CHASSIS_NETFN;
    msg.cmd = IPMI_CHASSIS_CONTROL_CMD;
    msg.data_len = 1;
    msg.data = data;
    data[0] = 3;

    rv = ipmi_control_send_command(control, mc, 0,
				   &msg, chassis_reset_set_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->handler)
	    control_info->handler(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
chassis_reset_set(ipmi_control_t     *control,
		  int                *val,
		  ipmi_control_op_cb handler,
		  void               *cb_data)
{
    chassis_set_info_t *control_info;
    int                rv;

    if (val[0] == 0)
	return EINVAL;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return ENOMEM;
    control_info->handler = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = val[0];
    rv = ipmi_control_add_opq(control, chassis_reset_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
chassis_power_set_cb(ipmi_control_t *control,
		     int            err,
		     ipmi_msg_t     *rsp,
		     void           *cb_data)
{
    chassis_set_info_t *control_info = cb_data;

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%schassis.c(chassis_power_set_cb): Received IPMI error: %x",
		 CONTROL_NAME(control), rsp->data[0]);
	if (control_info->handler)
	    control_info->handler(control,
				  IPMI_IPMI_ERR_VAL(rsp->data[0]),
				  control_info->cb_data);
	goto out;
    }

    if (control_info->handler)
	control_info->handler(control, 0, control_info->cb_data);

 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
chassis_power_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    chassis_set_info_t *control_info = cb_data;
    ipmi_msg_t         msg;
    unsigned char      data[1];
    ipmi_mc_t	       *mc = ipmi_control_get_mc(control);
    int                rv;

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = IPMI_CHASSIS_NETFN;
    msg.cmd = IPMI_CHASSIS_CONTROL_CMD;
    msg.data_len = 1;
    msg.data = data;
    if (control_info->vals[0])
	data[0] = 1;
    else
	data[0] = 0;

    rv = ipmi_control_send_command(control, mc, 0,
				   &msg, chassis_power_set_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->handler)
	    control_info->handler(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
chassis_power_set(ipmi_control_t     *control,
		  int                *val,
		  ipmi_control_op_cb handler,
		  void               *cb_data)
{
    chassis_set_info_t *control_info;
    int                rv;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return ENOMEM;
    control_info->handler = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = val[0];
    rv = ipmi_control_add_opq(control, chassis_power_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

typedef struct chassis_get_info_s
{
    ipmi_control_val_cb    handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
} chassis_get_info_t;

static void
chassis_power_get_cb(ipmi_control_t *control,
		     int            err,
		     ipmi_msg_t     *rsp,
		     void           *cb_data)
{
    chassis_get_info_t *control_info = cb_data;
    int                val[1];

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%schassis.c(chassis_power_get_cb): Received IPMI error: %x",
		 CONTROL_NAME(control), rsp->data[0]);
	if (control_info->handler)
	    control_info->handler(control,
				  IPMI_IPMI_ERR_VAL(rsp->data[0]),
				  NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%schassis.c(chassis_power_get_cb): response too short: %d",
		 CONTROL_NAME(control), rsp->data_len);
	if (control_info->handler)
	    control_info->handler(control, EINVAL,
				  NULL, control_info->cb_data);
	goto out;
    }

    val[0] = rsp->data[1] & 1;
    if (control_info->handler)
	control_info->handler(control, 0,
			      val, control_info->cb_data);

 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
chassis_power_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    chassis_get_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    ipmi_mc_t	       *mc = ipmi_control_get_mc(control);

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = IPMI_CHASSIS_NETFN;
    msg.cmd = IPMI_GET_CHASSIS_STATUS_CMD;
    msg.data_len = 0;
    msg.data = NULL;
    rv = ipmi_control_send_command(control, mc, 0,
				   &msg, chassis_power_get_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->handler)
	    control_info->handler(control, rv, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
chassis_power_get(ipmi_control_t      *control,
		  ipmi_control_val_cb handler,
		  void                *cb_data)
{
    chassis_get_info_t   *control_info;
    int                  rv;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return ENOMEM;
    memset(control_info, 0, sizeof(*control_info));
    control_info->handler = handler;
    control_info->cb_data = cb_data;
    rv = ipmi_control_add_opq(control, chassis_power_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
chassis_mc_control_active_handler(ipmi_mc_t *mc,
				  int       active,
				  void      *cb_data)
{
    ipmi_control_t *control = cb_data;
    ipmi_entity_t  *entity = ipmi_control_get_entity(control);
    ipmi_domain_t  *domain = ipmi_mc_get_domain(mc);

    if (active)
	return;

    ipmi_mc_remove_active_handler(mc,
				  chassis_mc_control_active_handler,
				  control);
    _ipmi_domain_entity_lock(domain);
    _ipmi_entity_get(entity);
    _ipmi_domain_entity_unlock(domain);
    ipmi_control_destroy(control);
    _ipmi_entity_put(entity);
}

int
_ipmi_chassis_create_controls(ipmi_mc_t *mc)
{
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    ipmi_entity_info_t *ents = ipmi_domain_get_entities(domain);
    ipmi_entity_t      *chassis_ent = NULL;
    ipmi_control_t     *power_control = NULL;
    ipmi_control_t     *reset_control = NULL;
    int                rv;
    ipmi_control_cbs_t cbs;

    rv = ipmi_entity_add(ents, domain, 0, 0, 0,
			 IPMI_ENTITY_ID_SYSTEM_CHASSIS, 1,
			 NULL, IPMI_ASCII_STR, 0,
			 chassis_entity_sdr_add,
			 NULL, &chassis_ent);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%schassis.c(_ipmi_chassis_create_controls): "
		 "Could not add chassis entity: %x",
		 DOMAIN_NAME(domain), rv);
	goto out;
    }
    
    /* Allocate the power control. */
    rv = ipmi_control_alloc_nonstandard(&power_control);
    if (rv) {
	goto out;
    }

    ipmi_control_set_type(power_control, IPMI_CONTROL_POWER);
    ipmi_control_set_id(power_control, "power", IPMI_ASCII_STR, 5);

    ipmi_control_set_settable(power_control, 1);
    ipmi_control_set_readable(power_control, 1);

    /* Create all the callbacks in the data structure. */
    memset(&cbs, 0, sizeof(cbs));
    cbs.set_val = chassis_power_set;
    cbs.get_val = chassis_power_get;

    ipmi_control_set_callbacks(power_control, &cbs);
    ipmi_control_set_num_elements(power_control, 1);

    /* Add it to the MC and entity.  We presume this comes from the
       "main" SDR, so set the source_mc to NULL. */
    rv = ipmi_control_add_nonstandard(mc, NULL, power_control,
				      IPMI_CHASSIS_POWER_CONTROL,
				      chassis_ent, NULL, NULL);
    if (rv) {
	ipmi_control_destroy(power_control);
	goto out;
    }

    rv = ipmi_mc_add_active_handler(mc,
				    chassis_mc_control_active_handler,
				    power_control);
    if (rv) {
	ipmi_control_destroy(power_control);
	goto out;
    }

    /* Allocate the reset control. */
    rv = ipmi_control_alloc_nonstandard(&reset_control);
    if (rv) {
	goto out;
    }

    ipmi_control_set_type(reset_control, IPMI_CONTROL_ONE_SHOT_RESET);
    ipmi_control_set_id(reset_control, "reset", IPMI_ASCII_STR, 5);

    ipmi_control_set_settable(reset_control, 1);
    ipmi_control_set_readable(reset_control, 0);

    /* Create all the callbacks in the data structure. */
    memset(&cbs, 0, sizeof(cbs));
    cbs.set_val = chassis_reset_set;

    ipmi_control_set_callbacks(reset_control, &cbs);
    ipmi_control_set_num_elements(reset_control, 1);

    /* Add it to the MC and entity.  We presume this comes from the
       "main" SDR, so set the source_mc to NULL. */
    rv = ipmi_control_add_nonstandard(mc, NULL, reset_control,
				      IPMI_CHASSIS_RESET_CONTROL,
				      chassis_ent, NULL, NULL);
    if (rv) {
	ipmi_control_destroy(reset_control);
	goto out;
    }

    rv = ipmi_mc_add_active_handler(mc,
				    chassis_mc_control_active_handler,
				    reset_control);
    if (rv) {
	ipmi_control_destroy(reset_control);
	goto out;
    }

 out:
    if (power_control)
	_ipmi_control_put(power_control);
    if (reset_control)
	_ipmi_control_put(reset_control);
    if (chassis_ent)
	_ipmi_entity_put(chassis_ent);
    return rv;
}
