/*
 * oem_atca.c
 *
 * OEM code to make ATCA chassis fit into OpenIPMI.
 *
 *  (C) 2004 MontaVista Software, Inc.
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

/* TODO:
 * Add support for setting the power up timeout
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <stdio.h> /* For sprintf */
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_oem.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_sensor.h>
#include <OpenIPMI/ipmi_control.h>
#include <OpenIPMI/ipmi_entity.h>
#include <OpenIPMI/ipmi_addr.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_event.h>
#include <OpenIPMI/ipmi_picmg.h>

/* Uncomment this if you *really* want direct power control.  Note
   that I think this is a bad idea, you should *really* use the
   hot-swap state machine to handle power control.  Plus, the code is
   untested. */
/* #define POWER_CONTROL_AVAILABLE */

/* Allow LED controls to go from 0 to 7fh. */
#define IPMC_FIRST_LED_CONTROL_NUM 0x00
#define IPMC_RESET_CONTROL_NUM     0x80
#define IPMC_POWER_CONTROL_NUM     0x81

/* This is a control attached to the system interface used to handle
   the address control, one for each possible IPMB.  These range from
   0x80 to 0xff on the SI MC. */
#define FIRST_IPMC_ADDRESS_NUM	0x80

#define PICMG_MFG_ID	0x315a

/* PICMG Site type */
#define PICMG_SITE_TYPE_PICMG_BOARD		0
#define PICMG_SITE_TYPE_POWER_ENTRY_MODULE	1
#define PICMG_SITE_TYPE_SHELF_FRU_INFO		2
#define PICMG_SITE_TYPE_DEDICATED_SHMC		3
#define PICMG_SITE_TYPE_FAN_TRAY		4
#define PICMG_SITE_TYPE_FAN_FILTER_TRAY		5
#define PICMG_SITE_TYPE_ALARM			6
#define PICMG_SITE_TYPE_PICMG_MODULE		7
#define PICMG_SITE_TYPE_PMC			8
#define PICMG_SITE_TYPE_READ_TRANSITION_MODULE	9

/* Address key types, mainly for get address info. */
#define PICMG_ADDRESS_KEY_HARDWARE	0
#define PICMG_ADDRESS_KEY_IPMB_0	1
#define PICMG_ADDRESS_KEY_PHYSICAL	3

/* PICMG Entity IDs. */
#define PICMG_ENTITY_ID_FRONT_BOARD		0xa0

typedef struct atca_shelf_s atca_shelf_t;

typedef struct atca_address_s
{
    unsigned char hw_address;
    unsigned char site_num;
    unsigned char site_type;
} atca_address_t;

typedef struct atca_ipmc_s atca_ipmc_t;
typedef struct atca_fru_s atca_fru_t;

typedef struct atca_led_s
{
    int            destroyed;
    int            op_in_progress;

    unsigned int   fru_id;
    unsigned int   num;
    unsigned int   colors; /* A bitmask, in OpenIPMI numbers. */
    int            local_control;
    atca_fru_t     *fru;
    ipmi_control_t *control;
} atca_led_t;

struct atca_fru_s
{
    atca_ipmc_t               *minfo;
    unsigned int              fru_id;
    unsigned int              num_leds;
    atca_led_t                **leds;
    ipmi_entity_t             *entity;
    enum ipmi_hot_swap_states hs_state;
    ipmi_sensor_id_t          hs_sensor_id;
    unsigned char             hs_sensor_lun;
    unsigned char             hs_sensor_num;
    ipmi_control_t            *cold_reset;
    ipmi_control_t            *power;
};

struct atca_ipmc_s
{
    atca_shelf_t  *shelf;
    int           idx; /* My index in the shelf's address and ipmc arrays. */
    unsigned char site_type;
    unsigned char site_num;
    unsigned char ipmb_address;
    ipmi_mcid_t   mcid;
    ipmi_mc_t     *mc;

    /* Because discovery of FRUs is racy (we may find frus before we
       know their max number) we allocate FRUs as an array of
       pointers.  This way, the array is easy to extend and the
       pointers remain the same even if we re-allocate the array. */
    unsigned int  num_frus;
    atca_fru_t    **frus;

    /* Control for reading the address info */
    ipmi_control_t *address_control;
};

struct atca_shelf_s
{
    int setup;

    ipmi_domain_t *domain;
    unsigned char shelf_fru_ipmb;
    unsigned char shelf_fru_device_id;
    ipmi_fru_t    *shelf_fru;
    int           curr_shelf_fru;

    unsigned char        shelf_address[40];
    enum ipmi_str_type_e shelf_address_type;
    unsigned int         shelf_address_len;

    ipmi_entity_t *shelf_entity;

    unsigned int   num_addresses;
    atca_address_t *addresses;

    unsigned int num_ipmcs;
    atca_ipmc_t  *ipmcs;

    ipmi_domain_oem_check_done startup_done;
    void                       *startup_done_cb_data;

    /* This is used to allocate address control number sequentially. */
    unsigned int next_address_control_num;

    /* Hacks for broken implementations. */

    /* The shelf address is not on the advertised shelf address
       device, it is only on the BMC. */
    unsigned int shelf_address_only_on_bmc : 1;
    unsigned int allow_sel_on_any : 1;
};

static void setup_from_shelf_fru(ipmi_domain_t *domain,
				 atca_shelf_t  *info);

static void atca_event_handler(ipmi_domain_t *domain,
			       ipmi_event_t  *event,
			       void          *event_data);

/***********************************************************************
 *
 * General functions used all over the code.
 *
 **********************************************************************/

static int
atca_entity_sdr_add(ipmi_entity_t   *ent,
		    ipmi_sdr_info_t *sdrs,
		    void            *cb_data)
{
    /* Don't put the entities into an SDR */
    return 0;
}

static int
atca_alloc_control(ipmi_mc_t                 *mc,
		   void                      *data,
		   ipmi_control_cleanup_oem_info_cb data_cleanup,
		   unsigned int              control_type,
		   char                      *id,
		   ipmi_control_set_val_cb   set_val,
		   ipmi_control_get_val_cb   get_val,
		   ipmi_control_set_light_cb set_light_val,
		   ipmi_control_get_light_cb get_light_val,
		   ipmi_control_identifier_set_val_cb set_id_val,
		   ipmi_control_identifier_get_val_cb get_id_val,
		   unsigned int              length,
		   ipmi_control_t            **control)
{
    int                   rv;
    ipmi_control_cbs_t    cbs;

    /* Allocate the control. */
    rv = ipmi_control_alloc_nonstandard(control);
    if (rv)
	return rv;

    /* Fill out default values. */
    ipmi_control_set_oem_info(*control, data, data_cleanup);
    ipmi_control_set_type(*control, control_type);
    ipmi_control_set_id(*control, id, IPMI_ASCII_STR, strlen(id));
    ipmi_control_set_ignore_if_no_entity(*control, 1);

    /* Assume we can read and set the value. */
    if ((set_val) || (set_light_val) || (set_id_val))
	ipmi_control_set_settable(*control, 1);
    if ((get_val) || (get_light_val) || (get_id_val))
	ipmi_control_set_readable(*control, 1);

    /* Create all the callbacks in the data structure. */
    memset(&cbs, 0, sizeof(cbs));
    cbs.set_val = set_val;
    cbs.get_val = get_val;
    cbs.set_light = set_light_val;
    cbs.get_light = get_light_val;
    cbs.set_identifier_val = set_id_val;
    cbs.get_identifier_val = get_id_val;

    if (control_type == IPMI_CONTROL_IDENTIFIER)
	ipmi_control_identifier_set_max_length(*control, length);

    ipmi_control_set_callbacks(*control, &cbs);

    return 0;
}

static int
atca_add_control(ipmi_mc_t      *mc,
		 ipmi_control_t **ncontrol,
		 unsigned int   num, 
		 ipmi_entity_t  *entity)
{
    ipmi_control_t *control = *ncontrol;
    int            rv;

    rv = ipmi_control_add_nonstandard(mc, mc, control, num, entity,
				      NULL, NULL);
    if (rv) {
	ipmi_control_destroy(control);
	*ncontrol = NULL;
    }

    _ipmi_control_put(control);

    return rv;
}


static int
check_for_msg_err(ipmi_mc_t *mc, int *rv, ipmi_msg_t *msg,
		  int expected_length,
		  char *func_name)
{
    if (rv && *rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_atca.c(%s): "
		 "Error from message", func_name);
	return 1;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_atca.c(%s): "
		 "MC went away", func_name);
	if (rv)
	    *rv = ENXIO;
	return 1;
    }

    if (msg->data[0] != 0) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(%s): "
		 "IPMI error: 0x%x",
		 MC_NAME(mc), func_name, msg->data[0]);
	if (rv)
	    *rv = IPMI_IPMI_ERR_VAL(msg->data[0]);
	return 1;
    }

    if (msg->data_len < expected_length) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(%s): "
		 "response not big enough, expected %d, got %d bytes",
		 MC_NAME(mc), func_name, expected_length, msg->data_len);
	if (rv)
	    *rv = EINVAL;
	return 1;
    }

    if (msg->data[1] != 0) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(%s): "
		 "Command ID not PICMG, it was 0x%x",
		 MC_NAME(mc), func_name, msg->data[1]);
	if (rv)
	    *rv = EINVAL;
	return 1;
    }

    return 0;
}


/***********************************************************************
 *
 * ATCA hot-swap handling.
 *
 **********************************************************************/

typedef struct atca_hs_info_s
{
    ipmi_entity_hot_swap_state_cb handler1;
    ipmi_entity_cb                handler2;
    void                          *cb_data;
    ipmi_entity_op_info_t         sdata;
    ipmi_sensor_op_info_t         sdata2;
    atca_fru_t                    *finfo;
    int                           op;
} atca_hs_info_t;

static enum ipmi_hot_swap_states atca_hs_to_openipmi[] =
{
    IPMI_HOT_SWAP_NOT_PRESENT,
    IPMI_HOT_SWAP_INACTIVE,
    IPMI_HOT_SWAP_ACTIVATION_REQUESTED,
    IPMI_HOT_SWAP_ACTIVATION_IN_PROGRESS,
    IPMI_HOT_SWAP_ACTIVE,
    IPMI_HOT_SWAP_DEACTIVATION_REQUESTED,
    IPMI_HOT_SWAP_DEACTIVATION_IN_PROGRESS,
    IPMI_HOT_SWAP_OUT_OF_CON,
};

static void
atca_get_hot_swap_state_done(ipmi_sensor_t *sensor,
			     int           err,
			     ipmi_states_t *states,
			     void          *cb_data)
{
    atca_hs_info_t *hs_info = cb_data;
    atca_fru_t     *finfo = hs_info->finfo;
    int            i;

    if (!sensor) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_atca.c(atca_get_hot_swap_state_done): "
		 "Sensor went away while in progress",
		 ENTITY_NAME(finfo->entity));
	if (hs_info->handler1)
	    hs_info->handler1(finfo->entity, ECANCELED, 0, hs_info->cb_data);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_atca.c(atca_get_hot_swap_state_done): "
		 "Error getting sensor value: 0x%x",
		 ENTITY_NAME(finfo->entity), err);
	if (hs_info->handler1)
	    hs_info->handler1(finfo->entity, err, 0, hs_info->cb_data);
	goto out;
    }

    for (i=0; i<=7; i++) {
	if (ipmi_is_state_set(states, i)) {
	    break;
	}
    }

    if (i > 7) {
	/* No state was set? */
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_atca.c(atca_get_hot_swap_state_done): "
		 "No valid hot-swap state set in sensor response",
		 ENTITY_NAME(finfo->entity));
	if (hs_info->handler1)
	    hs_info->handler1(finfo->entity, EINVAL, 0, hs_info->cb_data);
	goto out;
    }

    if (hs_info->handler1)
	hs_info->handler1(finfo->entity, 0, atca_hs_to_openipmi[i],
			  hs_info->cb_data);

 out:
    if (finfo->entity)
	ipmi_entity_opq_done(finfo->entity);
    ipmi_mem_free(hs_info);
}

static void
atca_get_hot_swap_state_start(ipmi_entity_t *entity, int err, void *cb_data)
{
    atca_hs_info_t *hs_info = cb_data;
    atca_fru_t     *finfo = hs_info->finfo;
    int            rv;

    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_atca.c(atca_get_hot_swap_state_start): "
		 "Error in callback: 0x%x",
		 ENTITY_NAME(entity), err);
	if (hs_info->handler1)
	    hs_info->handler1(entity, err, 0, hs_info->cb_data);
	ipmi_entity_opq_done(entity);
	ipmi_mem_free(hs_info);
	return;
    }

    if (ipmi_sensor_id_is_invalid(&finfo->hs_sensor_id)) {
	/* The sensor is not present, so the device is not present.
	   Just return our current state. */
	if (hs_info->handler1)
	    hs_info->handler1(entity, 0, finfo->hs_state, hs_info->cb_data);
	ipmi_entity_opq_done(entity);
	ipmi_mem_free(hs_info);
	return;
    }

    rv = ipmi_sensor_id_get_states(finfo->hs_sensor_id,
				   atca_get_hot_swap_state_done,
				   hs_info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_atca.c(atca_get_hot_swap_state_start): "
		 "Error sending states get: 0x%x",
		 ENTITY_NAME(entity), rv);
	if (hs_info->handler1)
	    hs_info->handler1(entity, rv, 0, hs_info->cb_data);
	ipmi_entity_opq_done(entity);
	ipmi_mem_free(hs_info);
    }
}

static int
atca_get_hot_swap_state(ipmi_entity_t                 *entity,
			ipmi_entity_hot_swap_state_cb handler,
			void                          *cb_data)
{
    atca_hs_info_t *hs_info;
    int            rv;

    hs_info = ipmi_mem_alloc(sizeof(*hs_info));
    if (!hs_info)
	return ENOMEM;
    memset(hs_info, 0, sizeof(*hs_info));

    hs_info->handler1 = handler;
    hs_info->cb_data = cb_data;
    hs_info->finfo = ipmi_entity_get_oem_info(entity);
    rv = ipmi_entity_add_opq(entity, atca_get_hot_swap_state_start,
			     &(hs_info->sdata), hs_info);
    if (rv)
	ipmi_mem_free(hs_info);
     return rv;
}

static int
atca_set_auto_activate(ipmi_entity_t  *ent,
		       ipmi_timeout_t auto_act,
		       ipmi_entity_cb done,
		       void           *cb_data)
{
    return ENOSYS;
}

static int
atca_get_auto_activate(ipmi_entity_t       *ent,
		       ipmi_entity_time_cb handler,
		       void                *cb_data)
{
    return ENOSYS;
}

static int
atca_set_auto_deactivate(ipmi_entity_t  *ent,
			 ipmi_timeout_t auto_act,
			 ipmi_entity_cb done,
			 void           *cb_data)
{
    return ENOSYS;
}

static int
atca_get_auto_deactivate(ipmi_entity_t       *ent,
			 ipmi_entity_time_cb handler,
			 void                *cb_data)
{
    return ENOSYS;
}

static void
atca_activate_done(ipmi_sensor_t *sensor,
		   int           err,
		   ipmi_msg_t    *rsp,
		   void          *cb_data)
{
    atca_hs_info_t *hs_info = cb_data;
    atca_fru_t     *finfo = hs_info->finfo;

    if (!sensor) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_atca.c(atca_activate_done): "
		 "Sensor went away while in progress",
		 ENTITY_NAME(finfo->entity));
	if (hs_info->handler2)
	    hs_info->handler2(finfo->entity, ECANCELED, hs_info->cb_data);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_atca.c(atca_activate_done): "
		 "Error setting activation: 0x%x",
		 ENTITY_NAME(finfo->entity), err);
	if (hs_info->handler2)
	    hs_info->handler2(finfo->entity, err, hs_info->cb_data);
	goto out;
    }

    if (hs_info->handler2)
	hs_info->handler2(finfo->entity, 0, hs_info->cb_data);

 out:
    if (sensor)
	ipmi_sensor_opq_done(sensor);
    /* There may be a destruction race condition.  I don't think so,
       though, because this is called at sensor destruction, and the
       entity should still be there. */
    if (finfo->entity)
	ipmi_entity_opq_done(finfo->entity);
    ipmi_mem_free(hs_info);
}

static void
atca_activate_sensor_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    atca_hs_info_t *hs_info = cb_data;
    atca_fru_t     *finfo = hs_info->finfo;
    int            rv;
    ipmi_mc_t      *mc = ipmi_sensor_get_mc(sensor);
    ipmi_msg_t     msg;
    unsigned char  data[4];

    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_atca.c(atca_activate_sensor_start): "
		 "Error in callback: 0x%x",
		 ENTITY_NAME(finfo->entity), err);
	if (hs_info->handler2)
	    hs_info->handler2(finfo->entity, err, hs_info->cb_data);
	if (sensor)
	    ipmi_sensor_opq_done(sensor);
	if (finfo->entity)
	    ipmi_entity_opq_done(finfo->entity);
	ipmi_mem_free(hs_info);
	return;
    }

    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.data = data;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = finfo->fru_id;
    if (hs_info->op == 0x100) {
	msg.cmd = IPMI_PICMG_CMD_SET_FRU_ACTIVATION_POLICY;
	data[2] = 0x01; /* Enable setting the locked bit. */
	data[3] = 0x00; /* Clear the locked bit. */
	msg.data_len = 4;
    } else {
	msg.cmd = IPMI_PICMG_CMD_SET_FRU_ACTIVATION;
	data[2] = hs_info->op;
	msg.data_len = 3;
    }
    rv = ipmi_sensor_send_command(sensor, mc, 0, &msg, atca_activate_done,
				  &hs_info->sdata2, hs_info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_atca.c(atca_activate_start): "
		 "Error adding to sensor opq: 0x%x",
		 ENTITY_NAME(finfo->entity), rv);
	if (hs_info->handler2)
	    hs_info->handler2(finfo->entity, rv, hs_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_entity_opq_done(finfo->entity);
	ipmi_mem_free(hs_info);
    }
}

static void
atca_activate_start(ipmi_entity_t *entity, int err, void *cb_data)
{
    atca_hs_info_t *hs_info = cb_data;
    atca_fru_t     *finfo = hs_info->finfo;
    int            rv;

    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_atca.c(atca_activate_start): "
		 "Error in callback: 0x%x",
		 ENTITY_NAME(entity), err);
	if (hs_info->handler2)
	    hs_info->handler2(entity, err, hs_info->cb_data);
	ipmi_entity_opq_done(entity);
	ipmi_mem_free(hs_info);
	return;
    }

    if (ipmi_sensor_id_is_invalid(&finfo->hs_sensor_id)) {
	/* The sensor is not present, so the device is not present.
	   Just return our current state. */
	if (hs_info->handler2)
	    hs_info->handler2(entity, EINVAL, hs_info->cb_data);
	ipmi_entity_opq_done(entity);
	ipmi_mem_free(hs_info);
	return;
    }

    rv = ipmi_sensor_id_add_opq(finfo->hs_sensor_id,
				atca_activate_sensor_start,
				&hs_info->sdata2,
				hs_info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_atca.c(atca_activate_start): "
		 "Error adding to sensor opq: 0x%x",
		 ENTITY_NAME(entity), rv);
	if (hs_info->handler2)
	    hs_info->handler2(entity, rv, hs_info->cb_data);
	ipmi_entity_opq_done(entity);
	ipmi_mem_free(hs_info);
    }
}

static int
atca_unlock_fru(ipmi_entity_t  *entity,
		ipmi_entity_cb done,
		void           *cb_data)
{
    atca_hs_info_t *hs_info;
    int            rv;

    hs_info = ipmi_mem_alloc(sizeof(*hs_info));
    if (!hs_info)
	return ENOMEM;
    memset(hs_info, 0, sizeof(*hs_info));

    hs_info->handler2 = done;
    hs_info->cb_data = cb_data;
    hs_info->op = 0x100; /* Do a set activation policy unlock */
    hs_info->finfo = ipmi_entity_get_oem_info(entity);
    rv = ipmi_entity_add_opq(entity, atca_activate_start,
			     &(hs_info->sdata), hs_info);
    if (rv)
	ipmi_mem_free(hs_info);
    return rv;
}

static int
atca_activate(ipmi_entity_t  *entity,
	      ipmi_entity_cb done,
	      void           *cb_data)
{
    atca_hs_info_t *hs_info;
    int            rv;

    hs_info = ipmi_mem_alloc(sizeof(*hs_info));
    if (!hs_info)
	return ENOMEM;
    memset(hs_info, 0, sizeof(*hs_info));

    hs_info->handler2 = done;
    hs_info->cb_data = cb_data;
    hs_info->finfo = ipmi_entity_get_oem_info(entity);
    hs_info->op = 1; /* Do an activation */
    rv = ipmi_entity_add_opq(entity, atca_activate_start,
			     &(hs_info->sdata), hs_info);
    if (rv)
	ipmi_mem_free(hs_info);
    return rv;
}

static int
atca_deactivate(ipmi_entity_t  *entity,
		ipmi_entity_cb done,
		void           *cb_data)
{
    atca_hs_info_t *hs_info;
    int            rv;

    hs_info = ipmi_mem_alloc(sizeof(*hs_info));
    if (!hs_info)
	return ENOMEM;
    memset(hs_info, 0, sizeof(*hs_info));

    hs_info->handler2 = done;
    hs_info->cb_data = cb_data;
    hs_info->finfo = ipmi_entity_get_oem_info(entity);
    hs_info->op = 0; /* Do a deactivation */
    rv = ipmi_entity_add_opq(entity, atca_activate_start,
			     &(hs_info->sdata), hs_info);
    if (rv)
	ipmi_mem_free(hs_info);
    return rv;
}

static int
atca_get_hot_swap_indicator(ipmi_entity_t      *ent,
			    ipmi_entity_val_cb handler,
			    void               *cb_data)
{
    return ENOSYS;
}

static int
atca_set_hot_swap_indicator(ipmi_entity_t  *ent,
			    int            val,
			    ipmi_entity_cb done,
			    void           *cb_data)
{
    return ENOSYS;
}

static int
atca_get_hot_swap_requester(ipmi_entity_t      *ent,
			    ipmi_entity_val_cb handler,
			    void               *cb_data)
{
    return ENOSYS;
}

static void
hot_swap_checker(ipmi_entity_t             *entity,
		 int                       err,
		 enum ipmi_hot_swap_states state,
		 void                      *cb_data)
{
    atca_fru_t                *finfo;
    enum ipmi_hot_swap_states old_state;
    int                       handled = IPMI_EVENT_NOT_HANDLED;
    ipmi_event_t              *event = NULL;

    if (err)
	return;

    finfo = ipmi_entity_get_oem_info(entity);

    if (state != finfo->hs_state) {
	old_state = finfo->hs_state;
	finfo->hs_state = state;
	ipmi_entity_call_hot_swap_handlers(entity, old_state, state, &event,
					   &handled);
    }
}

static int
atca_check_hot_swap_state(ipmi_entity_t *entity)
{
    return atca_get_hot_swap_state(entity, hot_swap_checker, NULL);
}

static ipmi_entity_hot_swap_t atca_hot_swap_handlers =
{
    .get_hot_swap_state       = atca_get_hot_swap_state,
    .set_auto_activate        = atca_set_auto_activate,
    .get_auto_activate        = atca_get_auto_activate,
    .set_auto_deactivate      = atca_set_auto_deactivate,
    .get_auto_deactivate      = atca_get_auto_deactivate,
    .set_activation_requested = atca_unlock_fru,
    .activate                 = atca_activate,
    .deactivate               = atca_deactivate,
    .get_hot_swap_indicator   = atca_get_hot_swap_indicator,
    .set_hot_swap_indicator   = atca_set_hot_swap_indicator,
    .get_hot_swap_requester   = atca_get_hot_swap_requester,
    .check_hot_swap_state     = atca_check_hot_swap_state,
};

static void
fetched_hot_swap_state(ipmi_sensor_t *sensor,
		       int           err,
		       ipmi_states_t *states,
		       void          *cb_data)
{
    atca_fru_t                *finfo = cb_data;
    int                       i;
    int                       handled;
    ipmi_event_t              *event = NULL;
    enum ipmi_hot_swap_states old_state;

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_atca.c(fetched_hot_swap_state): "
		 "Error getting sensor value: 0x%x",
		 SENSOR_NAME(sensor), err);
	goto out;
    }

    for (i=0; i<8; i++) {
	if (ipmi_is_state_set(states, i))
	    break;
    }

    if (i == 8) {
	/* No state set, just give up. */
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_atca.c(fetched_hot_swap_state): "
		 "hot-swap sensor value had no valid bit set: 0x%x",
		 SENSOR_NAME(sensor), err);
	goto out;
    }

    /* The OpenIPMI hot-swap states map directly to the ATCA ones. */
    old_state = finfo->hs_state;
    finfo->hs_state = i;
    handled = IPMI_EVENT_NOT_HANDLED;
    ipmi_entity_call_hot_swap_handlers(ipmi_sensor_get_entity(sensor),
				       old_state,
				       finfo->hs_state,
				       &event,
				       &handled);

 out:
    return;
}

static int
hot_swap_state_changed(ipmi_sensor_t         *sensor,
		       enum ipmi_event_dir_e dir,
		       int                   offset,
		       int                   severity,
		       int                   prev_severity,
		       void                  *cb_data,
		       ipmi_event_t          *event)
{
    atca_fru_t                *finfo = cb_data;
    enum ipmi_hot_swap_states old_state;
    int                       handled = IPMI_EVENT_NOT_HANDLED;

    /* We only want assertions. */
    if (dir != IPMI_ASSERTION)
	return handled;

    if ((offset < 0) || (offset >= 8))
	/* eh? */
	return handled;

    /* The OpenIPMI hot-swap states map directly to the ATCA ones. */
    old_state = finfo->hs_state;
    finfo->hs_state = offset;
    ipmi_entity_call_hot_swap_handlers(ipmi_sensor_get_entity(sensor),
				       old_state,
				       finfo->hs_state,
				       &event,
				       &handled);

    return handled;
}

static void
setup_fru_hot_swap(atca_fru_t *finfo, ipmi_sensor_t *sensor)
{
    int rv;

    finfo->hs_sensor_id = ipmi_sensor_convert_to_id(sensor);

    ipmi_entity_set_hot_swappable(finfo->entity, 1);
    ipmi_entity_set_hot_swap_control(finfo->entity, &atca_hot_swap_handlers);

    rv = ipmi_sensor_add_discrete_event_handler(sensor, hot_swap_state_changed,
						finfo);
    if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(setup_fru_hot_swap): "
		     "Cannot set event handler for hot-swap sensor: 0x%x",
		     SENSOR_NAME(sensor), rv);
    }

    rv = ipmi_sensor_get_states(sensor, fetched_hot_swap_state, finfo);
    if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(setup_fru_hot_swap): "
		     "Cannot fetch current hot-swap state: 0x%x",
		     SENSOR_NAME(sensor), rv);
    }
}

/***********************************************************************
 *
 * ATCA LED handling.
 *
 **********************************************************************/

typedef struct atca_control_info_s
{
    ipmi_control_op_cb     set_handler;
    ipmi_light_settings_cb get_handler;
    void                   *cb_data;

    ipmi_msg_t         msg;
    unsigned char      data[6];

    /* Light settings we pre-allocate. */
    ipmi_light_setting_t *settings;

    /* From ipmi_control.h. */
    ipmi_control_op_info_t sdata;
} atca_control_info_t;

#define ATCA_COLOR_BLUE		1
#define ATCA_COLOR_RED		2
#define ATCA_COLOR_GREEN	3
#define ATCA_COLOR_AMBER	4
#define ATCA_COLOR_ORANGE	5
#define ATCA_COLOR_WHITE	6

static int atca_to_openipmi_color[] =
{
    -1,
    IPMI_CONTROL_COLOR_BLUE,
    IPMI_CONTROL_COLOR_RED,
    IPMI_CONTROL_COLOR_GREEN,
    IPMI_CONTROL_COLOR_YELLOW,
    IPMI_CONTROL_COLOR_ORANGE,
    IPMI_CONTROL_COLOR_WHITE,
    -1
};

static int openipmi_to_atca_color[] =
{
    -1,
    ATCA_COLOR_WHITE,
    ATCA_COLOR_RED,
    ATCA_COLOR_GREEN,
    ATCA_COLOR_BLUE,
    ATCA_COLOR_AMBER,
    ATCA_COLOR_ORANGE,
    -1
};

static void
led_set_done(ipmi_control_t *control,
	     int            err,
	     ipmi_msg_t     *rsp,
	     void           *cb_data)
{
    atca_control_info_t *info = cb_data;
    ipmi_mc_t           *mc = NULL;

    if (control)
	mc = ipmi_control_get_mc(control);

    if (check_for_msg_err(mc, &err, rsp, 2, "led_set_done")) {
	if (info->set_handler)
	    info->set_handler(control, err, info->cb_data);
	goto out;
    }

    if (info->set_handler)
	info->set_handler(control, 0, info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(info);
}

static void
led_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    atca_control_info_t *info = cb_data;
    int                 rv;

    if (err) {
	if (info->set_handler)
	    info->set_handler(control, err, info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(info);
	return;
    }

    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &info->msg, led_set_done,
				   &(info->sdata), info);
    if (rv) {
	if (info->set_handler)
	    info->set_handler(control, rv, info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(info);
    }
}

static int
set_led(ipmi_control_t       *control,
	ipmi_light_setting_t *settings,
	ipmi_control_op_cb   handler,
	void                 *cb_data)
{
    atca_control_info_t *info;
    int                 rv;
    int                 color, on_time, off_time, local_control;
    atca_led_t          *l = ipmi_control_get_oem_info(control);

    rv = ipmi_light_setting_get_color(settings, 0, &color);
    if (rv)
	return rv;
    if (color > IPMI_CONTROL_COLOR_ORANGE)
	return EINVAL;
    rv = ipmi_light_setting_get_on_time(settings, 0, &on_time);
    if (rv)
	return rv;
    rv = ipmi_light_setting_get_off_time(settings, 0, &off_time);
    if (rv)
	return rv;
    rv = ipmi_light_setting_in_local_control(settings, 0, &local_control);
    if (rv)
	return rv;
    if (local_control && !l->local_control)
	return ENOSYS;

    if (color == IPMI_CONTROL_COLOR_BLACK) {
	on_time = 0;
	off_time = 1;
	color = 0xe;
    } else
	color = openipmi_to_atca_color[color];

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));
    info->set_handler = handler;
    info->cb_data = cb_data;
    info->msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    info->msg.cmd = IPMI_PICMG_CMD_SET_FRU_LED_STATE;
    info->msg.data = info->data;
    info->msg.data_len = 6;

    info->data[0] = IPMI_PICMG_GRP_EXT;
    info->data[1] = l->fru->fru_id;
    info->data[2] = l->num;
    if (local_control) {
	info->data[3] = 0xfc;
	info->data[4] = 0;
	color = 0xf;
    } else if (on_time <= 0) {
	/* Turn the LED off */
	info->data[3] = 0;
	info->data[4] = 0;
    } else if (off_time <= 0) {
	/* Turn LED on */
	info->data[3] = 0xff;
	info->data[4] = 0;
    } else {
	/* LED will blink, calculate the settings. */

	/* Convert to 10's of milliseconds. */
	on_time = (on_time + 5) / 10;
	off_time = (off_time + 5) / 10;
	if (on_time > 0xfa)
	    on_time = 0xfa;
	if (off_time > 0xfa)
	    off_time = 0xfa;
	info->data[3] = on_time;
	info->data[4] = off_time;
    }
    info->data[5] = color;

    rv = ipmi_control_add_opq(control, led_set_start, &info->sdata, info);
    if (rv)
	ipmi_mem_free(info);

    return rv;
}

static void
led_get_done(ipmi_control_t *control,
	     int            err,
	     ipmi_msg_t     *rsp,
	     void           *cb_data)
{
    atca_control_info_t *info = cb_data;
    ipmi_mc_t           *mc = NULL;
    int                 color;

    if (control)
	mc = ipmi_control_get_mc(control);

    if (check_for_msg_err(mc, &err, rsp, 6, "led_get_done")) {
	if (info->get_handler)
	    info->get_handler(control, err, info->settings, info->cb_data);
	goto out;
    }

    if (rsp->data[2] & 0x2) {
	/* In override state */
	if (check_for_msg_err(mc, &err, rsp, 9, "led_get_done")) {
	    if (info->get_handler)
		info->get_handler(control, err, info->settings, info->cb_data);
	    goto out;
	}

	if ((rsp->data[6] >= 0xfb) && (rsp->data[6] <= 0xfe)) {
	    /* Reserved on time field */
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(led_get_done): "
		     "Invalid on time value: 0x%x",
		     MC_NAME(mc), rsp->data[6]);
	    if (info->get_handler)
		info->get_handler(control, EINVAL, info->settings,
				  info->cb_data);
	    goto out;
	}

	color = rsp->data[8] & 0xf;
	if ((color == 0) || (color > 6)) {
	    /* Reserved on color value */
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(led_get_done): "
		     "Invalid color value: %d",
		     MC_NAME(mc), color);
	    if (info->get_handler)
		info->get_handler(control, EINVAL, info->settings,
				  info->cb_data);
	    goto out;
	}

	ipmi_light_setting_set_color(info->settings,
				     0,
				     atca_to_openipmi_color[color]);
	if (rsp->data[6] == 0) {
	    /* LED is off, set it to black. */
	    ipmi_light_setting_set_color(info->settings,
					 0,
					 IPMI_CONTROL_COLOR_BLACK);
	    ipmi_light_setting_set_on_time(info->settings, 0, 0);
	    ipmi_light_setting_set_off_time(info->settings, 0, 1);
	} else if (rsp->data[6] == 0xff) {
	    ipmi_light_setting_set_on_time(info->settings, 0, 1);
	    ipmi_light_setting_set_off_time(info->settings, 0, 0);
	} else {
	    ipmi_light_setting_set_on_time(info->settings, 0,
					   rsp->data[6] * 10);
	    ipmi_light_setting_set_off_time(info->settings, 0,
					    rsp->data[7] * 10);
	}
    } else {
	ipmi_light_setting_set_local_control(info->settings, 0, 1);

	if ((rsp->data[3] >= 0xfb) && (rsp->data[3] <= 0xfe)) {
	    /* Reserved on time field */
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(led_get_done): "
		     "Invalid on time value: 0x%x",
		     MC_NAME(mc), rsp->data[3]);
	    if (info->get_handler)
		info->get_handler(control, EINVAL, info->settings,
				  info->cb_data);
	    goto out;
	}

	color = rsp->data[5] & 0xf;
	if ((color == 0) || (color > 6)) {
	    /* Reserved on color value */
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(led_get_done): "
		     "Invalid color value: %d",
		     MC_NAME(mc), color);
	    if (info->get_handler)
		info->get_handler(control, EINVAL, info->settings,
				  info->cb_data);
	    goto out;
	}

	ipmi_light_setting_set_color(info->settings,
				     0,
				     atca_to_openipmi_color[color]);
	if (rsp->data[3] == 0) {
	    ipmi_light_setting_set_on_time(info->settings, 0, 0);
	    ipmi_light_setting_set_off_time(info->settings, 0, 1);
	} else if (rsp->data[3] == 0xff) {
	    ipmi_light_setting_set_on_time(info->settings, 0, 1);
	    ipmi_light_setting_set_off_time(info->settings, 0, 0);
	} else {
	    ipmi_light_setting_set_on_time(info->settings, 0,
					   rsp->data[3] * 10);
	    ipmi_light_setting_set_off_time(info->settings, 0,
					    rsp->data[4] * 10);
	}
    }
    if (info->get_handler)
	info->get_handler(control, 0, info->settings, info->cb_data);

 out:
    ipmi_control_opq_done(control);
    ipmi_free_light_settings(info->settings);
    ipmi_mem_free(info);
}

static void
led_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    atca_control_info_t *info = cb_data;
    int                 rv;

    if (err) {
	if (info->get_handler)
	    info->get_handler(control, err, info->settings, info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_free_light_settings(info->settings);
	ipmi_mem_free(info);
	return;
    }

    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &info->msg, led_get_done,
				   &(info->sdata), info);
    if (rv) {
	if (info->get_handler)
	    info->get_handler(control, rv, info->settings, info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_free_light_settings(info->settings);
	ipmi_mem_free(info);
    }
}

static int
get_led(ipmi_control_t         *control,
	ipmi_light_settings_cb handler,
	void                   *cb_data)
{
    atca_control_info_t *info;
    int                 rv;
    atca_led_t          *l = ipmi_control_get_oem_info(control);

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));

    info->settings = ipmi_alloc_light_settings(1);
    if (!info->settings) {
	ipmi_mem_free(info);
	return ENOMEM;
    }

    info->get_handler = handler;
    info->cb_data = cb_data;
    info->msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    info->msg.cmd = IPMI_PICMG_CMD_GET_FRU_LED_STATE;
    info->msg.data = info->data;
    info->msg.data_len = 3;

    info->data[0] = IPMI_PICMG_GRP_EXT;
    info->data[1] = l->fru->fru_id;
    info->data[2] = l->num;

    rv = ipmi_control_add_opq(control, led_get_start, &info->sdata, info);
    if (rv) {
	ipmi_free_light_settings(info->settings);
	ipmi_mem_free(info);
    }

    return rv;
}

static void
atca_led_control_oem_cleanup(ipmi_control_t *control,
			     void           *oem_info)
{
    atca_led_t   *l = oem_info;

    if (l->control)
	l->control = NULL;
}

static void
fru_led_cap_rsp(ipmi_mc_t  *mc,
		ipmi_msg_t *msg,
		void       *rsp_data)
{
    ipmi_domain_t *domain;
    atca_led_t    *l = rsp_data;
    atca_fru_t    *finfo;
    unsigned int  num = l->num;
    char          name[10];
    int           rv;
    int           i;

    if (l->destroyed) {
	/* The entity or MC was destroyed while the message was in
	   progress, so the memory was not freed (because this
	   function needed it).  The control didn't yet exist, so just
	   free the memory. */
	ipmi_mem_free(l);
	return;
    }
    l->op_in_progress = 0;

    if (check_for_msg_err(mc, NULL, msg, 5, "fru_led_cap_rsp"))
	return;

    finfo = l->fru;

    domain = ipmi_mc_get_domain(mc);
    _ipmi_domain_entity_lock(domain);
    if (!finfo->entity)
	rv = EINVAL;
    else
	rv = _ipmi_entity_get(finfo->entity);
    _ipmi_domain_entity_unlock(domain);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fru_led_cap_rsp): "
		 "Could not get entity: 0x%x",
		 MC_NAME(mc), rv);
	return;
    }

    if (num == 0)
	sprintf(name, "blue led");
    else
	sprintf(name, "led %d", num);
    rv = atca_alloc_control(mc, l, atca_led_control_oem_cleanup,
			    IPMI_CONTROL_LIGHT,
			    name,
			    NULL,
			    NULL,
			    set_led,
			    get_led,
			    NULL,
			    NULL,
			    1,
			    &l->control);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fru_led_cap_rsp): "
		 "Could not create LED control: 0x%x",
		 MC_NAME(mc), rv);
	_ipmi_entity_put(finfo->entity);
	return;
    }
    for (i=1; i<=6; i++) {
	if (msg->data[2] & (1 << i))
	    ipmi_control_add_light_color_support(l->control,
						 atca_to_openipmi_color[i]);
    }
     /* We always support black */
    ipmi_control_add_light_color_support(l->control,
					 IPMI_CONTROL_COLOR_BLACK);
    ipmi_control_set_num_elements(l->control, 1);
    ipmi_control_light_set_has_local_control(l->control, l->local_control);
    rv = atca_add_control(mc, 
			  &l->control,
			  num,
			  finfo->entity);
    _ipmi_entity_put(finfo->entity);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fru_led_cap_rsp): "
		 "Could not add LED control: 0x%x",
		 MC_NAME(mc), rv);
	return;
    }
}

static void
get_led_capability_2(ipmi_mc_t  *mc,
		     ipmi_msg_t *rsp,
		     void       *rsp_data)
{
    ipmi_msg_t    msg;
    unsigned char data[3];
    int           rv;
    atca_led_t    *linfo = rsp_data;

    if (linfo->destroyed) {
	/* The entity or MC was destroyed while the message was in
	   progress, so the memory was not freed (because this
	   function needed it).  The control didn't yet exist, so just
	   free the memory. */
	ipmi_mem_free(linfo);
	return;
    }

    if (check_for_msg_err(mc, NULL, rsp, 3, "get_led_capability_2"))
	return;

    linfo->local_control = rsp->data[2] & 1;

    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_GET_LED_COLOR_CAPABILITIES;
    msg.data = data;
    msg.data_len = 3;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = linfo->fru->fru_id;
    data[2] = linfo->num;
    linfo->op_in_progress = 1;
    rv = ipmi_mc_send_command(mc, 0, &msg, fru_led_cap_rsp, linfo);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(get_led_capabilities_2): "
		 "Could not send FRU LED color capablity command: 0x%x",
		 MC_NAME(mc), rv);
	/* Just go on, don't shut down the info. */
    }
}

static void
get_led_capability(ipmi_mc_t *mc, atca_fru_t *finfo, unsigned int num)
{
    ipmi_msg_t    msg;
    unsigned char data[3];
    int           rv;
    atca_led_t    *linfo = finfo->leds[num];

    linfo->num = num;
    linfo->fru = finfo;

    /* First we get the LED state because that is where we know if the
       LED supports local control.  Too bad it is not in the
       capabilities. */
    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_GET_FRU_LED_STATE;
    msg.data = data;
    msg.data_len = 3;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = linfo->fru->fru_id;
    data[2] = linfo->num;
    linfo->op_in_progress = 1;
    rv = ipmi_mc_send_command(mc, 0, &msg, get_led_capability_2, linfo);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(get_led_capabilities): "
		 "Could not send FRU LED state command: 0x%x",
		 MC_NAME(mc), rv);
	/* Just go on, don't shut down the info. */
    }
}

static void
fru_led_prop_rsp(ipmi_mc_t  *mc,
		 ipmi_msg_t *rsp,
		 void       *rsp_data)
{
    atca_fru_t   *finfo = rsp_data;
    int          i, j;
    unsigned int num_leds;

    if (check_for_msg_err(mc, NULL, rsp, 4, "fru_led_prop_rsp"))
	return;

    /* Note that while the MC exists, finfo is guaranteed to exist
       because we never decrease the number of FRUs. */

    if (finfo->leds)
	/* There is a race here, it is possible to have two LED
	   fetches running at the same time.  If they have already
	   been fetched, just ignore this message. */
	return;

    if (!finfo->entity)
	/* The entity was destroyed while the message was in progress. */
	return;
    
    num_leds = 4 + rsp->data[3];
    finfo->leds = ipmi_mem_alloc(sizeof(atca_led_t *) * num_leds);
    if (!finfo->leds) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fru_led_prop_rsp): "
		 "Could not allocate memory LEDs",
		 MC_NAME(mc));
	return;
    }
    memset(finfo->leds, 0, sizeof(atca_led_t *) * num_leds);
    finfo->num_leds = num_leds;

    for (i=0; i<4; i++) {
	if (rsp->data[2] & (1 << i)) {
	    /* We support this LED.  Fetch its capabilities */
	    finfo->leds[i] = ipmi_mem_alloc(sizeof(atca_led_t));
	    if (!finfo->leds[i]) {
		ipmi_log(IPMI_LOG_SEVERE,
			 "%soem_atca.c(fru_led_prop_rsp): "
			 "Could not allocate memory for an LED",
			 MC_NAME(mc));
		return;
	    }
	    memset(finfo->leds[i], 0, sizeof(atca_led_t));
	    get_led_capability(mc, finfo, i);
	}
    }

    for (j=0; j<rsp->data[3]; j++, i++) {
	if (i >= 128)
	    /* We only support 128 LEDs. */
	    break;
	/* We support this LED, Fetch it's capabilities. */
	finfo->leds[i] = ipmi_mem_alloc(sizeof(atca_led_t));
	if (!finfo->leds[i]) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(fru_led_prop_rsp): "
		     "Could not allocate memory for an aux LED",
		     MC_NAME(mc));
	    return;
	}
	memset(finfo->leds[i], 0, sizeof(atca_led_t));
	get_led_capability(mc, finfo, i);
    }
}

static void
fetch_fru_leds_mc_cb(ipmi_mc_t *mc, void *cb_info)
{
    atca_fru_t    *finfo = cb_info;
    ipmi_msg_t    msg;
    unsigned char data[2];
    int           rv;

    /* Now fetch the LED information. */
    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_GET_FRU_LED_PROPERTIES;
    msg.data = data;
    msg.data_len = 2;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = finfo->fru_id;
    rv = ipmi_mc_send_command(mc, 0, &msg, fru_led_prop_rsp, finfo);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fetch_fru_leds_mc_cb): "
		 "Could not send FRU LED properties command: 0x%x",
		 MC_NAME(mc), rv);
	/* Just go on, don't shut down the info. */
    }
}

static void
fetch_fru_leds(atca_fru_t *finfo)
{
    int rv;

    if (finfo->leds)
	/* We already have the LEDs fetched. */
	return;
    
    rv = ipmi_mc_pointer_cb(finfo->minfo->mcid, fetch_fru_leds_mc_cb, finfo);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fetch_fru_leds): "
		 "Could not convert an mcid to a pointer: 0x%x",
		 ENTITY_NAME(finfo->entity), rv);
    }
}

static void
destroy_fru_leds(atca_fru_t *finfo)
{
    int i;

    if (finfo->leds) {
	for (i=0; i<finfo->num_leds; i++) {
	    atca_led_t *linfo = finfo->leds[i];
	    if (!linfo)
		continue;
	    if (linfo->op_in_progress) {
		linfo->destroyed = 1;
	    } else {
		if (linfo->control)
		    ipmi_control_destroy(linfo->control);
		ipmi_mem_free(linfo);
	    }
	}
	ipmi_mem_free(finfo->leds);
	finfo->leds = NULL;
	finfo->num_leds = 0;
    }
}

/***********************************************************************
 *
 * ATCA FRU control handling.  This is for the FRU control command.
 *
 **********************************************************************/

typedef struct atca_cold_reset_s
{
    ipmi_control_op_cb     handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
} atca_cold_reset_t;

static void
set_cold_reset_done(ipmi_control_t *control,
		    int            err,
		    ipmi_msg_t     *rsp,
		    void           *cb_data)
{
    atca_cold_reset_t *info = cb_data;
    ipmi_mc_t         *mc = NULL;

    if (control)
	mc = ipmi_control_get_mc(control);

    if (check_for_msg_err(mc, &err, rsp, 2, "set_cold_reset_done")) {
	if (info->handler)
	    info->handler(control, err, info->cb_data);
	goto out;
    }

    if (info->handler)
	info->handler(control, 0, info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(info);
}

static void
set_cold_reset_start(ipmi_control_t *control, int err, void *cb_data)
{
    atca_cold_reset_t *info = cb_data;
    atca_fru_t        *finfo = ipmi_control_get_oem_info(control);
    ipmi_msg_t        msg;
    unsigned char     data[3];
    int               rv;

    if (err) {
	if (info->handler)
	    info->handler(control, err, info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(info);
	return;
    }

    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_FRU_CONTROL;
    msg.data = data;
    msg.data_len = 3;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = finfo->fru_id;
    data[2] = 0; /* Cold reset */
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, set_cold_reset_done,
				   &info->sdata, info);
    if (err) {
	if (info->handler)
	    info->handler(control, err, info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(info);
	return;
    }
}

static int
set_cold_reset(ipmi_control_t     *control,
	       int                *val,
	       ipmi_control_op_cb handler,
	       void               *cb_data)
{
    atca_cold_reset_t *info;
    int               rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->handler = handler;
    info->cb_data = cb_data;
    rv = ipmi_control_add_opq(control, set_cold_reset_start,
			      &info->sdata, info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

static void
add_fru_control_mc_cb(ipmi_mc_t *mc, void *cb_info)
{
    atca_fru_t *finfo = cb_info;
    int        rv;

    rv = atca_alloc_control(mc, finfo, NULL,
			    IPMI_CONTROL_ONE_SHOT_RESET,
			    "cold reset",
			    set_cold_reset,
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    1,
			    &finfo->cold_reset);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_fru_control_mc_cb): "
		 "Could allocate the reset control: 0x%x",
		 ENTITY_NAME(finfo->entity), rv);
    }

    rv = atca_add_control(mc, 
			  &finfo->cold_reset,
			  IPMC_RESET_CONTROL_NUM,
			  finfo->entity);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_fru_control_mc_cb): "
		 "Could not add reset control: 0x%x",
		 MC_NAME(mc), rv);
	return;
    }
}

static void
add_fru_control_handling(atca_fru_t *finfo)
{
    int rv;

    if (finfo->cold_reset)
	return;
    
    rv = ipmi_mc_pointer_cb(finfo->minfo->mcid, add_fru_control_mc_cb, finfo);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_fru_control_handling): "
		 "Could not convert an mcid to a pointer: 0x%x",
		 ENTITY_NAME(finfo->entity), rv);
    }
}

static void
destroy_fru_control_handling(atca_fru_t *finfo)
{
    if (finfo->cold_reset) {
	ipmi_control_t *control = finfo->cold_reset;

	/* We *HAVE* to clear the value first, destroying this can
	   cause something else to be destroyed and end up in the
	   function again before we return from
	   ipmi_control_destroy(). */
	finfo->cold_reset = NULL;
	ipmi_control_destroy(control);
    }
}

#ifdef POWER_CONTROL_AVAILABLE
/***********************************************************************
 *
 * ATCA FRU power handling.  This is for the FRU power level commands.
 *
 **********************************************************************/

typedef struct atca_power_s
{
    ipmi_control_op_cb     set_handler;
    ipmi_control_val_cb    get_handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
    int                    level;
} atca_power_t;

static void
set_power_done(ipmi_control_t *control,
	       int            err,
	       ipmi_msg_t     *rsp,
	       void           *cb_data)
{
    atca_power_t *info = cb_data;
    ipmi_mc_t    *mc = NULL;

    if (control)
	mc = ipmi_control_get_mc(control);

    if (check_for_msg_err(mc, &err, rsp, 2, "set_power_done")) {
	if (info->set_handler)
	    info->set_handler(control, err, info->cb_data);
	goto out;
    }

    if (info->set_handler)
	info->set_handler(control, 0, info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(info);
}

static void
set_power_start(ipmi_control_t *control, int err, void *cb_data)
{
    atca_power_t  *info = cb_data;
    atca_fru_t    *finfo = ipmi_control_get_oem_info(control);
    ipmi_msg_t    msg;
    unsigned char data[4];
    int           rv;

    if (err) {
	if (info->set_handler)
	    info->set_handler(control, err, info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(info);
	return;
    }

    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_SET_POWER_LEVEL;
    msg.data = data;
    msg.data_len = 4;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = finfo->fru_id;
    data[2] = info->level;
    data[3] = info->level;
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, set_power_done,
				   &info->sdata, info);
    if (err) {
	if (info->set_handler)
	    info->set_handler(control, err, info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(info);
	return;
    }
}

static int
set_power(ipmi_control_t     *control,
	  int                *val,
	  ipmi_control_op_cb handler,
	  void               *cb_data)
{
    atca_power_t *info;
    int          rv;

    if ((*val < 0) || (*val > 14))
	return EINVAL;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->set_handler = handler;
    info->cb_data = cb_data;
    info->level = *val;
    rv = ipmi_control_add_opq(control, set_power_start, &info->sdata, info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

static void
get_power_done(ipmi_control_t *control,
	       int            err,
	       ipmi_msg_t     *rsp,
	       void           *cb_data)
{
    atca_power_t *info = cb_data;
    ipmi_mc_t    *mc = NULL;

    if (control)
	mc = ipmi_control_get_mc(control);

    if (check_for_msg_err(mc, &err, rsp, 3, "get_power_done")) {
	if (info->get_handler)
	    info->get_handler(control, err, &info->level, info->cb_data);
	goto out;
    }

    info->level = rsp->data[2] & 0xf;

    if (info->get_handler)
	info->get_handler(control, 0, &info->level, info->cb_data);

 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(info);
}

static void
get_power_start(ipmi_control_t *control, int err, void *cb_data)
{
    atca_power_t  *info = cb_data;
    atca_fru_t    *finfo = ipmi_control_get_oem_info(control);
    int           rv;
    ipmi_msg_t    msg;
    unsigned char data[3];

    if (err) {
	if (info->get_handler)
	    info->get_handler(control, err, &info->level, info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(info);
	return;
    }

    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_GET_POWER_LEVEL;
    msg.data = data;
    msg.data_len = 3;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = finfo->fru_id;
    data[2] = 0; /* Get current levels */

    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, get_power_done,
				   &(info->sdata), info);
    if (rv) {
	if (info->get_handler)
	    info->get_handler(control, rv, &info->level, info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(info);
    }
}

static int
get_power(ipmi_control_t      *control,
	  ipmi_control_val_cb handler,
	  void                *cb_data)
{
    atca_power_t *info;
    int          rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));

    info->get_handler = handler;
    info->cb_data = cb_data;
    info->level = 0;

    rv = ipmi_control_add_opq(control, get_power_start, &info->sdata, info);
    if (rv)
	ipmi_mem_free(info);

    return rv;
}

static void
add_power_mc_cb(ipmi_mc_t *mc, void *cb_info)
{
    atca_fru_t *finfo = cb_info;
    int        rv;

    rv = atca_alloc_control(mc, finfo, NULL,
			    IPMI_CONTROL_ONE_SHOT_RESET,
			    "power",
			    set_power,
			    get_power,
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    1,
			    &finfo->power);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_power_mc_cb): "
		 "Could not alloc control: 0x%x",
		 ENTITY_NAME(finfo->entity), rv);
    }

    rv = atca_add_control(mc, 
			  &finfo->power,
			  IPMC_POWER_CONTROL_NUM,
			  finfo->entity);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_power_mc_cb): "
		 "Could not add power control: 0x%x",
		 MC_NAME(mc), rv);
	return;
    }
}

static void
add_power_handling(atca_fru_t *finfo)
{
    int rv;

    if (finfo->power)
	return;
    
    rv = ipmi_mc_pointer_cb(finfo->minfo->mcid, add_power_mc_cb, finfo);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_power_handling): "
		 "Could not convert an mcid to a pointer: 0x%x",
		 ENTITY_NAME(finfo->entity), rv);
    }
}

static void
destroy_power_handling(atca_fru_t *finfo)
{
    if (finfo->power) {
	ipmi_control_t *control = finfo->power;

	/* We *HAVE* to clear the value first, destroying this can
	   cause something else to be destroyed and end up in the
	   function again before we return from
	   ipmi_control_destroy(). */
	finfo->power = NULL;
	ipmi_control_destroy(control);
    }
}

#endif /* POWER_CONTROL_AVAILABLE */


/***********************************************************************
 *
 * Control for the address
 *
 **********************************************************************/

static int
get_address(ipmi_control_t                 *control,
	    ipmi_control_identifier_val_cb handler,
	    void                           *cb_data)
{
    atca_ipmc_t   *ipmc = ipmi_control_get_oem_info(control);
    unsigned char val[4];

    val[0] = ipmc->site_type;
    val[1] = ipmc->site_num;
    val[2] = ipmc->ipmb_address / 2;
    val[3] = ipmc->ipmb_address;

    /* Just call the callback immediately, we have the data. */
    handler(control, 0, val, 4, cb_data);

    return 0;
}

static void
add_address_control(atca_shelf_t *info, atca_ipmc_t *ipmc)
{
    int                          rv;
    ipmi_system_interface_addr_t si;
    ipmi_mc_t                    *si_mc;

    if (ipmc->address_control)
	return;
    
    if (info->next_address_control_num == 0xff) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_address_control_mc_cb): "
		 "Could not add control, out of address control numbers",
		 ENTITY_NAME(ipmc->frus[0]->entity));
	return;
    }

    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;

    si_mc = _ipmi_find_mc_by_addr(ipmc->shelf->domain,
				  (ipmi_addr_t *) &si,
				  sizeof(si));
    if (!si_mc) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_address_control): "
		 "Could not find system interface mc",
		 ENTITY_NAME(ipmc->frus[0]->entity));
	return;
    }

    rv = atca_alloc_control(si_mc, ipmc, NULL,
			    IPMI_CONTROL_IDENTIFIER,
			    "address",
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    get_address,
			    4,
			    &ipmc->address_control);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_address_control_mc_cb): "
		 "Could not alloc control: 0x%x",
		 ENTITY_NAME(ipmc->frus[0]->entity), rv);
	goto out;
    }

    
    rv = atca_add_control(si_mc,
			  &ipmc->address_control,
			  info->next_address_control_num,
			  ipmc->frus[0]->entity);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_address_control_mc_cb): "
		 "Could not add control: 0x%x",
		 ENTITY_NAME(ipmc->frus[0]->entity), rv);
	goto out;
    }

    info->next_address_control_num++;

 out:
    _ipmi_mc_put(si_mc);
}

static void
destroy_address_control(atca_ipmc_t *ipmc)
{
    if (ipmc->address_control) {
	ipmi_control_t *control = ipmc->address_control;

	/* We *HAVE* to clear the value first, destroying this can
	   cause something else to be destroyed and end up in the
	   function again before we return from
	   ipmi_control_destroy(). */
	ipmc->address_control = NULL;
	ipmi_control_destroy(control);
    }
}


/***********************************************************************
 *
 * FRU entity handling
 *
 **********************************************************************/

static int
realloc_frus(atca_ipmc_t *minfo, unsigned int num_frus)
{
    atca_fru_t   **old_frus;
    atca_fru_t   **new_frus;
    unsigned int old_num_frus;
    int          i, j;

    old_num_frus = minfo->num_frus;
    if (old_num_frus >= num_frus)
	return 0;

    old_frus = minfo->frus;

    /* Allocate a new array of pointers. */
    new_frus = ipmi_mem_alloc(sizeof(atca_fru_t *) * num_frus);
    if (!new_frus)
	return ENOMEM;

    /* Allocate the items to go into the array. */
    memcpy(new_frus, old_frus, sizeof(atca_fru_t *) * old_num_frus);
    for (i=old_num_frus; i<num_frus; i++) {
	new_frus[i] = ipmi_mem_alloc(sizeof(atca_fru_t));
	if (!new_frus[i]) {
	    /* An allocation failed, free all the items that we
	       allocated. */
	    j = i; /* Keeps static analyzers happy, use a new var. */
	    for (j--; j>=old_num_frus; j--)
		ipmi_mem_free(new_frus[j]);
	    ipmi_mem_free(new_frus);
	    return ENOMEM;
	}
	memset(new_frus[i], 0, sizeof(atca_fru_t));
	new_frus[i]->minfo = minfo;
	new_frus[i]->fru_id = i;
	new_frus[i]->hs_state = IPMI_HOT_SWAP_NOT_PRESENT;
    }

    minfo->frus = new_frus;
    minfo->num_frus = num_frus;
    if (old_frus)
	ipmi_mem_free(old_frus);
    return 0;
}

static atca_fru_t *
atca_find_fru_info(atca_shelf_t *info, ipmi_entity_t *entity)
{
    int         ipmb_addr;
    int         fru_id;
    int         i;
    atca_ipmc_t *minfo = NULL;
    int         rv;

    /* Has to be a logical FRU. */
    if (!ipmi_entity_get_is_logical_fru(entity))
	return NULL;

    ipmb_addr = ipmi_entity_get_access_address(entity);
    fru_id = ipmi_entity_get_fru_device_id(entity);
    for (i=0; i<info->num_ipmcs; i++) {
	if (info->ipmcs[i].ipmb_address == ipmb_addr) {
	    minfo = &(info->ipmcs[i]);
	    break;
	}
    }
    if (!minfo) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_find_fru_info): "
		 "Could not find address associated with the FRU: 0x%x",
		 ENTITY_NAME(entity), ipmb_addr);
	return NULL;
    }
    rv = realloc_frus(minfo, fru_id+1);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_find_fru_info): "
		 "Could not allocate information for FRUs: 0x%x",
		 ENTITY_NAME(entity), rv);
	return NULL;
    }
    return minfo->frus[fru_id];
}

static atca_fru_t *
atca_find_mc_fru_info(atca_shelf_t *info, ipmi_entity_t *entity)
{
    int         ipmb_addr;
    int         i;
    atca_ipmc_t *minfo = NULL;
    int         rv;

    ipmb_addr = ipmi_entity_get_slave_address(entity);
    for (i=0; i<info->num_ipmcs; i++) {
	if (info->ipmcs[i].ipmb_address == ipmb_addr) {
	    minfo = &(info->ipmcs[i]);
	    break;
	}
    }
    if (!minfo) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_find_mc_fru_info): "
		 "Could find address associated with the MC: 0x%x",
		 ENTITY_NAME(entity), ipmb_addr);
	return NULL;
    }

    rv = realloc_frus(minfo, 1);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_find_mc_fru_info): "
		 "Could not allocate information for FRUs: 0x%x",
		 ENTITY_NAME(entity), rv);
	return NULL;
    }
    return minfo->frus[0];
}

static void
atca_sensor_update_handler(enum ipmi_update_e op,
			   ipmi_entity_t      *entity,
			   ipmi_sensor_t      *sensor,
			   void               *cb_data)
{
    atca_fru_t *finfo = cb_data;
    int        lun;
    int        num;
    int        rv;

    /* Only look for the hot-swap sensor for now */
    if (ipmi_sensor_get_sensor_type(sensor) != 0xf0)
	return;

    switch (op) {
    case IPMI_ADDED:
	rv = ipmi_sensor_get_num(sensor, &lun, &num);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(atca_sensor_update_handler): "
		     "Could not get sensor number for hot-swap sensor: 0x%x",
		     ENTITY_NAME(entity), rv);
	    return;
	}
	setup_fru_hot_swap(finfo, sensor);
	break;

    case IPMI_DELETED:
	ipmi_sensor_id_set_invalid(&finfo->hs_sensor_id);
	/* Tell the user that we went away, if necessary. */
	/* FIXME - what about out-of-comm state? */
	if (finfo->hs_state != IPMI_HOT_SWAP_NOT_PRESENT) {
	    int                       handled;
	    enum ipmi_hot_swap_states old_state;
	    ipmi_event_t              *event = NULL;

	    old_state = finfo->hs_state;
	    finfo->hs_state = IPMI_HOT_SWAP_NOT_PRESENT;
	    ipmi_entity_call_hot_swap_handlers(entity,
					       old_state,
					       finfo->hs_state,
					       &event,
					       &handled);
	    ipmi_entity_set_hot_swappable(entity, 0);
	}
	break;

    default:
	break;
    }
}

static void
add_fru_controls(atca_fru_t *finfo)
{
    fetch_fru_leds(finfo);
    add_fru_control_handling(finfo);
#ifdef POWER_CONTROL_AVAILABLE
    add_power_handling(finfo);
#endif
}

static void
destroy_fru_controls(atca_fru_t *finfo)
{
    destroy_fru_leds(finfo);
    destroy_fru_control_handling(finfo);
#ifdef POWER_CONTROL_AVAILABLE
    destroy_power_handling(finfo);
#endif
}

static int
any_fru_controls(atca_fru_t *finfo)
{
    return ((finfo->leds) || (finfo->cold_reset) || (finfo->power));
}

static int
atca_entity_presence_handler(ipmi_entity_t *entity,
			     int           present,
			     void          *cb_data,
			     ipmi_event_t  *event)
{
    atca_fru_t *finfo = cb_data;

    if (present)
	add_fru_controls(finfo);
    else
	destroy_fru_controls(finfo);
    return IPMI_EVENT_NOT_HANDLED;
}

static void
atca_entity_update_handler(enum ipmi_update_e op,
			   ipmi_domain_t      *domain,
			   ipmi_entity_t      *entity,
			   void               *cb_data)
{
    atca_shelf_t         *info = cb_data;
    atca_fru_t           *finfo;
    enum ipmi_dlr_type_e etype = ipmi_entity_get_type(entity);
    int                  rv;

    if (op == IPMI_ADDED) {
	/* Set meaningful entity id strings. */
	switch (ipmi_entity_get_entity_id(entity)) {
	case 0xa0:
	    ipmi_entity_set_entity_id_string(entity, "ATCA Board");
	    break;
	case 0xc0:
	    ipmi_entity_set_entity_id_string(entity, "ATCA RTM");
	    break;
	case 0xf0:
	    ipmi_entity_set_entity_id_string(entity, "ATCA ShMC");
	    break;
	case 0xf1:
	    ipmi_entity_set_entity_id_string(entity, "ATCA Filtration Unit");
	    break;
	case 0xf2:
	    ipmi_entity_set_entity_id_string(entity, "ATCA Shelf FRU");
	    break;
	}
    }

    /* We only care about FRU and MC entities. */
    if (etype == IPMI_ENTITY_FRU)
	finfo = atca_find_fru_info(info, entity);
    else if (etype == IPMI_ENTITY_MC) {
	if (ipmi_entity_get_slave_address(entity) == 0x20)
	    /* We ignore the floating IPMB address if it comes up. */
	    return;
	finfo = atca_find_mc_fru_info(info, entity);
    } else
	return;

    if (!finfo) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_entity_update_handler): "
		 "Unable to find fru info",
		 ENTITY_NAME(entity));
	return;
    }

    switch (op) {
    case IPMI_ADDED:
    case IPMI_CHANGED:
	if (finfo->entity){
	    void *tmp;

	    if (finfo->entity != entity) {
		/* If the entity is set, then this has already been
		   done. */
		ipmi_log(IPMI_LOG_SEVERE,
			 "%soem_atca.c(atca_entity_update_handler): "
			 "Entity mismatch on fru %d, old entity was %s",
			 ENTITY_NAME(entity), finfo->fru_id,
			 ENTITY_NAME(finfo->entity));
		return;
	    }

	    /* If OEM info is already set, then we don't need to do
	       this again. */
	    tmp = ipmi_entity_get_oem_info(entity);
	    if (tmp != NULL) {
		if (tmp != finfo) {
		    ipmi_log(IPMI_LOG_SEVERE,
			     "%soem_atca.c(atca_entity_update_handler): "
			     "Entity OEM info mismatch on fru %d",
			     ENTITY_NAME(entity), finfo->fru_id);
		}
		return;
	    }
	}
	finfo->entity = entity;
	rv = ipmi_entity_add_presence_handler(entity,
					      atca_entity_presence_handler,
					      finfo);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(atca_entity_update_handler): "
		     "Could not set entity presence handler: 0x%x",
		     ENTITY_NAME(entity), rv);
	}
	rv = ipmi_entity_add_sensor_update_handler(entity,
						   atca_sensor_update_handler,
						   finfo);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(atca_entity_update_handler): "
		     "Could not register sensor update handler: 0x%x",
		     ENTITY_NAME(entity), rv);
	}
	ipmi_entity_set_oem_info(entity, finfo, NULL);
	break;

    case IPMI_DELETED:
	finfo->entity = NULL;
	destroy_fru_controls(finfo);
	break;

    default:
	break;
    }
}

/***********************************************************************
 *
 * IPMC handling
 *
 **********************************************************************/

static void
fru_picmg_prop_rsp(ipmi_mc_t  *mc,
		   ipmi_msg_t *rsp,
		   void       *rsp_data)
{
    atca_ipmc_t        *minfo = rsp_data;
    int                rv;
    unsigned int       num_frus;
    unsigned int       ipm_fru_id;

    if (check_for_msg_err(mc, NULL, rsp, 5, "fru_picmg_prop_rsp"))
	return;

    num_frus = rsp->data[3] + 1;
    ipm_fru_id = rsp->data[4];

    if (ipm_fru_id >= num_frus) {
	/* Something is bad here, give up. */
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fru_picmg_prop_rsp): "
		 "IPMI controller FRU id is larger than number of FRUs",
		 MC_NAME(mc));
	return;
    }
    /* Note that the above also checks for num_frus==0. */

    rv = realloc_frus(minfo, num_frus);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fru_picmg_prop_rsp): "
		 "Could not allocate FRU memory",
		 MC_NAME(mc));
	return;
    }
}

static void
atca_ipmc_removal_handler(ipmi_domain_t *domain, ipmi_mc_t *mc,
			  atca_shelf_t *info)
{
    atca_ipmc_t   *minfo = NULL;
    atca_fru_t    *finfo;
    int           i;
    unsigned int  ipmb_addr;
    int           rv;

    ipmb_addr = ipmi_mc_get_address(mc);
    if (ipmb_addr == 0x20)
	/* We ignore the floating IPMB address if it comes up. */
	return;

    for (i=0; i<info->num_ipmcs; i++) {
	if (ipmb_addr == info->ipmcs[i].ipmb_address) {
	    minfo = &(info->ipmcs[i]);
	    break;
	}
    }
    if (!minfo) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_ipmc_removal_handler): "
		 "Could not find IPMC info",
		 MC_NAME(mc));
	return;
    }

    if (minfo->frus) {
	for (i=0; i<minfo->num_frus; i++) {
	    finfo = minfo->frus[i];
	    if (!finfo)
		continue;

	    if (any_fru_controls(finfo)) {
		_ipmi_domain_entity_lock(domain);
		if (! finfo->entity)
		    rv = ENOENT;
		else
		    rv = _ipmi_entity_get(finfo->entity);
		_ipmi_domain_entity_unlock(domain);
		if (rv)
		    continue;
		destroy_fru_controls(finfo);
		_ipmi_entity_put(finfo->entity);
	    }
	    /* We always leave FRU 0 around until we destroy the domain. */
	    if (i != 0) {
		ipmi_mem_free(finfo);
		minfo->frus[i] = NULL;
	    }
	}
    }
}

static void
atca_con_up(ipmi_domain_t *domain, void *cb_data)
{
    atca_shelf_t *info = cb_data;

    /* We wait until here to set up everything for the first time so
       it will be reported to the user properly. */
    if (!info->setup)
	setup_from_shelf_fru(domain, info);
}

static void
atca_handle_new_mc(ipmi_domain_t *domain, ipmi_mc_t *mc, atca_shelf_t *info)
{
    atca_ipmc_t   *minfo = NULL;
    ipmi_msg_t    msg;
    unsigned char data[1];
    int           rv;
    int           i;
    unsigned int  ipmb_addr;

    ipmb_addr = ipmi_mc_get_address(mc);
    if (ipmb_addr == 0x20)
	/* We ignore the floating IPMB address if it comes up. */
	return;

    for (i=0; i<info->num_ipmcs; i++) {
	if (ipmb_addr == info->ipmcs[i].ipmb_address) {
	    minfo = &(info->ipmcs[i]);
	    break;
	}
    }
    if (!minfo) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_handle_new_mc): "
		 "Could not find IPMC info",
		 MC_NAME(mc));
	return;
    }

    minfo->mcid = ipmi_mc_convert_to_id(mc);
    minfo->mc = mc;

    /* Now fetch the properties. */
    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_GET_PROPERTIES;
    msg.data = data;
    msg.data_len = 1;
    data[0] = IPMI_PICMG_GRP_EXT;
    rv = ipmi_mc_send_command(mc, 0, &msg, fru_picmg_prop_rsp, minfo);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_handle_new_mc): "
		 "Could not send FRU properties command: 0x%x",
		 MC_NAME(mc), rv);
	/* Just go on, don't shut down the info. */
    }
}

static void
ipmc_active(ipmi_mc_t *mc, int active, void *cb_data)
{
    ipmi_domain_t *domain = ipmi_mc_get_domain(mc);

    if (active)
	atca_handle_new_mc(domain, mc, cb_data);
    else
	atca_ipmc_removal_handler(domain, mc, cb_data);
}

static void
atca_mc_update_handler(enum ipmi_update_e op,
		       ipmi_domain_t      *domain,
		       ipmi_mc_t          *mc,
		       void               *cb_data)
{
    int rv;

    switch (op) {
    case IPMI_ADDED:
	rv = ipmi_mc_add_active_handler(mc, ipmc_active, cb_data);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_mc_update_handler): "
		     "Could not set active handler for mc: 0x%x",
		     MC_NAME(mc), rv);
	}
	if (ipmi_mc_is_active(mc))
	    atca_handle_new_mc(domain, mc, cb_data);
	break;

    case IPMI_DELETED:
	atca_ipmc_removal_handler(domain, mc, cb_data);
	break;

    default:
	break;
    }
}

static void
atca_fix_sel_handler(enum ipmi_update_e op,
		     ipmi_domain_t      *domain,
		     ipmi_mc_t          *mc,
		     void               *cb_data)
{
    atca_shelf_t *info = cb_data;

    switch (op) {
    case IPMI_ADDED:
    case IPMI_CHANGED:
	/* Turn off SEL device support for all devices that are not
	   the BMC. */
	if ((ipmi_mc_get_address(mc) != 0x20) && (!info->allow_sel_on_any))
	    ipmi_mc_set_sel_device_support(mc, 0);
	break;

    default:
	break;
    }
}

/***********************************************************************
 *
 * Shelf handling
 *
 **********************************************************************/

static void
atca_iterate_mcs(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    atca_mc_update_handler(IPMI_ADDED, domain, mc, cb_data);
}

static void
atca_iterate_entities(ipmi_entity_t *entity, void *cb_data)
{
    atca_entity_update_handler(IPMI_ADDED, ipmi_entity_get_domain(entity),
			       entity, cb_data);
}

static void shelf_fru_fetched(ipmi_fru_t *fru, int err, void *cb_data);

static void
atca_scan_done(ipmi_domain_t *domain, int err, void *cb_data)
{
    _ipmi_mc_scan_done(domain);
}

static void
setup_from_shelf_fru(ipmi_domain_t *domain,
		     atca_shelf_t  *info)
{
    ipmi_entity_info_t *ents;
    char               *name;
    int                i;
    int                rv;

    ents = ipmi_domain_get_entities(domain);

    /* Create the main shelf entity. */
    name = "ATCA Shelf";
    rv = ipmi_entity_add(ents, domain, 0, 0, 0,
			 IPMI_ENTITY_ID_SYSTEM_CHASSIS, 1,
			 name, IPMI_ASCII_STR, strlen(name),
			 atca_entity_sdr_add,
			 NULL, &info->shelf_entity);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_atca.c(shelf_fru_fetched): "
		 "Could not add chassis entity: %x",
		 DOMAIN_NAME(domain), rv);
	goto out;
    }

    info->ipmcs = ipmi_mem_alloc(sizeof(atca_ipmc_t) * info->num_addresses);
    if (!info->ipmcs) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(shelf_fru_fetched): "
		 "could not allocate memory for ipmcs",
		 DOMAIN_NAME(domain));
	goto out;
    }
    memset(info->ipmcs, 0, sizeof(atca_ipmc_t) * info->num_addresses);

    info->num_ipmcs = info->num_addresses;
    for (i=0; i<info->num_addresses; i++) {
	/* Process each IPMC. */
	atca_ipmc_t *b = &(info->ipmcs[i]);
	char        *name;
	int         entity_id;

	b->shelf = info;
	b->idx = i;
	b->ipmb_address = info->addresses[i].hw_address * 2;
	b->site_type = info->addresses[i].site_type;
	b->site_num = info->addresses[i].site_num;
	ipmi_mc_id_set_invalid(&b->mcid);

	if ((i+1) == info->num_addresses) {
	    /* When the last one completes, we report that we are done. */
	    ipmi_start_ipmb_mc_scan(domain, 0, b->ipmb_address,
				    b->ipmb_address, atca_scan_done, NULL);
	} else {
	    ipmi_start_ipmb_mc_scan(domain, 0, b->ipmb_address,
				    b->ipmb_address, NULL, NULL);
	}

	rv = realloc_frus(b, 1); /* Start with 1 FRU for the MC. */
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(shelf_fru_fetched): "
		     "Could not allocate FRU memory",
		     DOMAIN_NAME(domain));
	    goto out;
	}

	switch (b->site_type) {
	case 0:
	    name = "ATCA Board";
	    entity_id = 0xa0;
	    break;

	case 1: /* Power entry module */
	    name = "Power Unit";
	    entity_id = 0x0a;
	    break;

	case 2: /* Shelf FRU info */
	    name = "Shelf FRU";
	    entity_id = 0xf2;
	    break;

	case 3: /* Dedicated ShMC */
	    name = "ShMC";
	    entity_id = 0xf0;
	    break;

	case 4: /* Fan Tray */
	    name = "Fan Tray";
	    entity_id = 0x1e;
	    break;

	case 5: /* Fan Filter Tray */
	    name = "Fan Filters";
	    entity_id = 0xf1;
	    break;

	case 9: /* Rear Transition Module */
	    name = "RTM";
	    entity_id = 0xc0;
	    break;

	case 6: /* Alarm */
	case 7: /* AdvancedMC Module */
	case 8: /* PMC */
	default:
	    /* Skip adding the entity. */
	    continue;
	}

	rv = ipmi_entity_add(ents, domain, 0, b->ipmb_address, 0,
			     entity_id,
			     0x60, /* Always device relative */
			     name, IPMI_ASCII_STR, strlen(name),
			     atca_entity_sdr_add,
			     NULL, &b->frus[0]->entity);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "%soem_atca.c(shelf_fru_fetched): "
		     " Could not add board entity: %x",
		     DOMAIN_NAME(domain), rv);
	    goto out;
	}
	rv = ipmi_entity_add_child(info->shelf_entity, b->frus[0]->entity);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "%soem_atca.c(shelf_fru_fetched): "
		     "Could not add child ipmc: %x",
		     DOMAIN_NAME(domain), rv);
	    _ipmi_entity_put(b->frus[0]->entity);
	    goto out;
	}
	add_address_control(info, b);
	_ipmi_entity_put(b->frus[0]->entity);
    }

    info->setup = 1;

 out:
    if (info->shelf_entity)
	_ipmi_entity_put(info->shelf_entity);
    return;
}

static int
alt_shelf_fru_cb(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_msg_t   *msg = &rspi->msg;
    atca_shelf_t *info;
    int          rv;

    if (!domain)
	return IPMI_MSG_ITEM_NOT_USED;

    info = ipmi_domain_get_oem_data(domain);

    if (msg->data[0] != 0) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(alt_shelf_fru_cb): "
		 "Error getting alternate FRU information: 0x%x",
		 DOMAIN_NAME(domain), msg->data[0]);
	rv = EINVAL;
	goto out_err;
    }

    if (msg->data_len < 8) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(alt_shelf_fru_cb): "
		 "ATCA get address response not long enough",
		 DOMAIN_NAME(domain));
	rv = EINVAL;
	goto out_err;
    }

    info->shelf_fru_ipmb = msg->data[3];
    info->shelf_fru_device_id = msg->data[5];

    rv = ipmi_fru_alloc(domain,
			1,
			info->shelf_fru_ipmb,
			1,
			0,
			0,
			0,
			shelf_fru_fetched,
			info,
			&info->shelf_fru);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_atca.c(alt_shelf_fru_cb): "
		 "Error allocating fru information: 0x%x", rv);
	goto out_err;
    }

    return IPMI_MSG_ITEM_NOT_USED;

 out_err:
    info->startup_done(domain, rv, info->startup_done_cb_data);
    return IPMI_MSG_ITEM_NOT_USED;
}

static void
shelf_fru_fetched(ipmi_fru_t *fru, int err, void *cb_data)
{
    atca_shelf_t       *info = cb_data;
    ipmi_domain_t      *domain = info->domain;
    int                count;
    int                found;
    int                i, j, k, l;
    int                rv;

    if (err) {
	ipmi_system_interface_addr_t si;
	ipmi_msg_t                   msg;
	unsigned char 		     data[5];

	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(shelf_fru_fetched): "
		 "Error getting FRU information: 0x%x",
		 DOMAIN_NAME(domain), err);

	ipmi_fru_destroy(info->shelf_fru, NULL, NULL);
	info->shelf_fru = NULL;

	/* Try 2 shelf FRUs. */
	info->curr_shelf_fru++;
	if (info->curr_shelf_fru > 2) {
	    rv = EINVAL;
	    goto out;
	}

	/* Send the ATCA Get Address Info command to get the shelf FRU info. */
	si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si.channel = 0xf;
	si.lun = 0;
	msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
	msg.cmd = IPMI_PICMG_CMD_GET_ADDRESS_INFO;
	data[0] = IPMI_PICMG_GRP_EXT;
	data[1] = 0; /* Ignored for physical address */
	data[2] = PICMG_ADDRESS_KEY_PHYSICAL;
	data[3] = info->curr_shelf_fru; /* Look for the next Shelf FRU */
	data[4] = PICMG_SITE_TYPE_SHELF_FRU_INFO;
	msg.data = data;
	msg.data_len = 5;

	rv = ipmi_send_command_addr(domain,
				    (ipmi_addr_t *) &si, sizeof(si),
				    &msg,
				    alt_shelf_fru_cb, NULL, NULL);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(shelf_fru_fetched): "
		     "Error getting alternate FRU information: 0x%x",
		     DOMAIN_NAME(domain), rv);
	    goto out;
	}
	return;
    }

    /* We got the shelf FRU info, now hunt through it for the address
       table. */
    found = 0;
    count = ipmi_fru_get_num_multi_records(fru);
    for (i=0; i<count; i++) {
	unsigned char type;
	unsigned char ver;
	unsigned int  len;
	unsigned char *data;
	unsigned int  mfg_id;
	unsigned char *p;
	    
	if ((ipmi_fru_get_multi_record_type(fru, i, &type) != 0)
	    || (ipmi_fru_get_multi_record_format_version(fru, i, &ver) != 0)
	    || (ipmi_fru_get_multi_record_data_len(fru, i, &len) != 0))
	    continue;

	if ((type != 0xc0) || (ver != 2) || (len < 27))
	    continue;

	data = ipmi_mem_alloc(len);
	if (!data) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(shelf_fru_fetched): "
		     "could not allocate memory for shelf data",
		     DOMAIN_NAME(domain));
	    continue;
	}

	if (ipmi_fru_get_multi_record_data(fru, i, data, &len) != 0) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(shelf_fru_fetched): "
		     "could not fetch shelf data item %d",
		     DOMAIN_NAME(domain), i);
	    goto next_data_item;
	}

	mfg_id = data[0] | (data[1] << 8) | (data[2] << 16);
	if (mfg_id != PICMG_MFG_ID)
	    goto next_data_item;

	if (data[3] != 0x10) /* Address table record id */
	    goto next_data_item;

	if (data[4] != 0) /* We only know version 0 */
	    goto next_data_item;

	if (len < (27 + (3 * data[26])))
	    /* length does not meet the minimum possible length. */
	    goto next_data_item;

	info->shelf_address_len
	    = ipmi_get_device_string(data+5, 21,
				     info->shelf_address, 0,
				     &info->shelf_address_type,
				     sizeof(info->shelf_address));

	info->addresses = ipmi_mem_alloc(sizeof(atca_address_t) * data[26]);
	if (!info->addresses) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(shelf_fru_fetched): "
		     "could not allocate memory for shelf addresses",
		     DOMAIN_NAME(domain));
	    ipmi_mem_free(data);
	    rv = ENOMEM;
	    goto out;
	}
	memset(info->addresses, 0, sizeof(atca_address_t) * data[26]);

	info->num_addresses = data[26];
	p = data+27;
	for (j=0, l=0; l<data[26]; l++, p += 3) {
	    int skip = 0;

	    /* O(n^2), sigh. */
	    for (k=0; k<j; k++) {
		if ((info->addresses[k].hw_address == p[0])
		    && (info->addresses[k].site_num == p[1])
		    && (info->addresses[k].site_type == p[2]))
		{
		    /* Duplicate entries are bad because they will
		       have the same entity, and that can cause a
		       crash at shutdown because the entity will be
		       destroyed and then the child removal will
		       happen again. */
		    ipmi_log(IPMI_LOG_WARNING,
			     "%soem_atca.c(shelf_fru_fetched): "
			     "Shelf address entry %d is the same as shelf"
			     " address entry %d, ignoring second entry",
			     DOMAIN_NAME(domain), k, j);
		    skip = 1;
		}
	    }
	    if (skip) {
		info->num_addresses--;
	    } else {
		info->addresses[j].hw_address = p[0];
		info->addresses[j].site_num = p[1];
		info->addresses[j].site_type = p[2];
		j++;
	    }
	}

    next_data_item:
	ipmi_mem_free(data);
    }

    /* Add a handler for when MCs are added to the domain, so we can
       add in our custom sensors. */
    rv = ipmi_domain_add_mc_updated_handler(domain,
					    atca_mc_update_handler,
					    info);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_atca.c(shelf_fru_fetched): "
		 "Could not add MC update handler: %x",
		 DOMAIN_NAME(domain), rv);
	goto out;
    }

    /* Catch any MCs that were added before now. */
    ipmi_domain_iterate_mcs(domain, atca_iterate_mcs, info);

    rv = ipmi_domain_add_entity_update_handler(domain,
					       atca_entity_update_handler,
					       info);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_atca.c(shelf_fru_fetched): "
		 "Could not add entity update handler: %x",
		 DOMAIN_NAME(domain), rv);
	goto out;
    }

    /* Catch any entities that were added before now. */
    ipmi_domain_iterate_entities(domain, atca_iterate_entities, info);

 out:
    info->startup_done(domain, rv, info->startup_done_cb_data);
}

static void
atca_oem_domain_shutdown_handler(ipmi_domain_t *domain)
{
    atca_shelf_t *info = ipmi_domain_get_oem_data(domain);

    ipmi_domain_remove_event_handler(domain, atca_event_handler, info);

    /* Remove all the parent/child relationships we previously
       defined. */
    _ipmi_entity_get(info->shelf_entity);
    if (info->ipmcs) {
	int i;
	for (i=0; i<info->num_ipmcs; i++) {
	    atca_ipmc_t *b = &(info->ipmcs[i]);

	    if (b->frus[0]->entity) {
		_ipmi_entity_get(b->frus[0]->entity);
		destroy_address_control(b);
		destroy_fru_controls(b->frus[0]);

		ipmi_entity_remove_child(info->shelf_entity,
					 b->frus[0]->entity);
		_ipmi_entity_put(b->frus[0]->entity);
	    }
	}
    }
    _ipmi_entity_put(info->shelf_entity);
}

static void
atca_oem_data_destroyer(ipmi_domain_t *domain, void *oem_data)
{
    atca_shelf_t *info = oem_data;

    if (info->shelf_fru)
	ipmi_fru_destroy(info->shelf_fru, NULL, NULL);
    if (info->addresses)
	ipmi_mem_free(info->addresses);
    if (info->ipmcs) {
	int i;
	for (i=0; i<info->num_ipmcs; i++) {
	    atca_ipmc_t *b = &(info->ipmcs[i]);

	    ipmi_mem_free(b->frus[0]);
	    ipmi_mem_free(b->frus);
	    b->frus = NULL;
	}
	ipmi_mem_free(info->ipmcs);
    }
    ipmi_mem_free(info);
}

static void
atca_event_handler(ipmi_domain_t *domain,
		   ipmi_event_t  *event,
		   void          *event_data)
{
    unsigned char data[13];

    /* Here we look for hot-swap events so we know to start the
       process of scanning for an IPMC when it is installed. */
    if (ipmi_event_get_type(event) != 2)
	/* Not a system event */
	return;

    ipmi_event_get_data(event, data, 0, 13);
    if (data[6] != 4)
	/* Not IPMI 1.5 */
	return;

    if (data[7] != 0xf0)
	/* Not a hot-swap event. */
	return;

    if (((data[10] & 0xf) == 0) || ((data[11] & 0xf) != 0))
	/* We only scan if the current or previous state was not
	   installed. */
	return;

    /* We have a hot-swap event where the previous state was not
       installed or the current state is not installed.  Scan the
       MC. */
    ipmi_start_ipmb_mc_scan(domain, data[5] & 0xf, data[4], data[4],
			    NULL, 0);
}

static void
set_up_atca_domain(ipmi_domain_t *domain, ipmi_msg_t *get_addr,
		   ipmi_domain_oem_check_done done, void *done_cb_data)
{
    ipmi_system_interface_addr_t saddr;
    ipmi_mc_t    *mc;
    atca_shelf_t *info;
    int          rv;

    if (get_addr->data_len < 8) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(set_up_atca_domain): "
		 "ATCA get address response not long enough",
		 DOMAIN_NAME(domain));
	done(domain, EINVAL, done_cb_data);
	goto out;
    }

    info = ipmi_domain_get_oem_data(domain);
    if (info) {
	/* We have already initialized this domain, ignore this. */
	done(domain, 0, done_cb_data);
	goto out;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(set_up_atca_domain): "
		 "Could not allocate ATCA information structure",
		 DOMAIN_NAME(domain));
	done(domain, ENOMEM, done_cb_data);
	goto out;
    }
    memset(info, 0, sizeof(*info));

    info->next_address_control_num = FIRST_IPMC_ADDRESS_NUM;

    saddr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    saddr.channel = IPMI_BMC_CHANNEL;
    mc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &saddr, sizeof(saddr));
    if (!mc) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(set_up_atca_domain): "
		 "Could not find system interface MC, assuming this is"
		 " a valid working ATCA chassis",
		 DOMAIN_NAME(domain));
    } else {
	int mfg_id, prod_id;
	mfg_id = ipmi_mc_manufacturer_id(mc);
	prod_id = ipmi_mc_product_id(mc);
	if ((mfg_id == 0x000157) && (prod_id == 0x0841)) {
	    /* info->shelf_address_only_on_bmc = 1; */
	    info->allow_sel_on_any = 1;
	}
	_ipmi_mc_put(mc);
    }

    info->startup_done = done;
    info->startup_done_cb_data = done_cb_data;
    info->domain = domain;
    info->shelf_fru_ipmb = get_addr->data[3];
    info->shelf_fru_device_id = get_addr->data[5];

    info->curr_shelf_fru = 1;

    if (info->shelf_address_only_on_bmc)
	info->shelf_fru_ipmb = 0x20;

    rv = ipmi_domain_add_event_handler(domain, atca_event_handler, info);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_atca.c(set_up_atca_domain): "
		 "Could not register for events: 0x%x", rv);
	ipmi_mem_free(info);
	done(domain, rv, done_cb_data);
	goto out;
    }

    rv = ipmi_fru_alloc(domain,
			1,
			info->shelf_fru_ipmb,
			1,
			0,
			0,
			0,
			shelf_fru_fetched,
			info,
			&info->shelf_fru);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_atca.c(set_up_atca_domain): "
		 "Error allocating fru information: 0x%x", rv);
	ipmi_domain_remove_event_handler(domain, atca_event_handler, info);
	ipmi_mem_free(info);
	done(domain, rv, done_cb_data);
	goto out;
    }

    ipmi_domain_set_oem_data(domain, info, atca_oem_data_destroyer);
    ipmi_domain_set_oem_shutdown_handler(domain,
					 atca_oem_domain_shutdown_handler);

    ipmi_domain_add_mc_updated_handler(domain,
				       atca_fix_sel_handler,
				       info);

    ipmi_domain_set_con_up_handler(domain, atca_con_up, info);

 out:
    return;
}

/***********************************************************************
 *
 * Various fixups
 *
 **********************************************************************/

static void
atca_entity_fixup(ipmi_mc_t *mc, unsigned char *id, unsigned char *instance)
{
    unsigned char inst = *instance & 0x7f;
    unsigned char addr;

    switch (*id) {
    case 0:
    case 7:
	addr = ipmi_mc_get_address(mc);
	if ((addr == 0x62) || (addr == 0x64)) {
	    /* Power unit. */
	    *id = 10;
	    inst = 0x60;
	} else if (addr == 0x42) {
	    /* Fan tray */
	    *id = 30;
	    inst = 0x60;
	} else {
	    *id = 0xa0;
	    inst = 0x60;
	}
	break;

    case 6:
	*id = 0xf0;
	inst = 0x60;
	break;

    case 3:
	if (inst < 0x60)
	    inst = 0x60;
	break;

    case 23:
	if ((inst == 1) || (inst == 2)) {
	    *id = 0xf2;
	    inst = 0x60;
	} else if (inst == 3) {
	    *id = 0xf1;
	    inst = 0x60;
	}
	break;

    case 34:
	inst = 0x60;
	break;
    }

    *instance = (*instance & 0x80) | (inst & 0x7f);
}

static void
misc_sdrs_fixup(ipmi_mc_t       *mc,
		ipmi_sdr_info_t *sdrs,
		void            *cb_data)
{
    unsigned int count;
    int          i;
    ipmi_sdr_t   sdr;
    int          rv;

    rv = ipmi_get_sdr_count(sdrs, &count);
    if (rv)
	return;

    for (i=0; i<count; i++) {
	rv = ipmi_get_sdr_by_index(sdrs, i, &sdr);
	if (rv)
	    break;

	/* Fix up the entity instances for the SDRs. */
	switch (sdr.type) {
	case IPMI_SDR_FULL_SENSOR_RECORD:
	case IPMI_SDR_COMPACT_SENSOR_RECORD:
	    /* Make it device relative. */
	    atca_entity_fixup(mc, &sdr.data[3], &sdr.data[4]);
	    ipmi_set_sdr_by_index(sdrs, i, &sdr);
	    break;
	case IPMI_SDR_MC_DEVICE_LOCATOR_RECORD:
	case IPMI_SDR_FRU_DEVICE_LOCATOR_RECORD:
	    atca_entity_fixup(mc, &sdr.data[7], &sdr.data[8]);
	    ipmi_set_sdr_by_index(sdrs, i, &sdr);
	    break;
	}
    }
}

static int
misc_sdrs_fixup_reg(ipmi_mc_t     *mc,
		    void          *cb_data)
{
    /* Setting the event reciever on these MCs seems to be broken. */
    ipmi_mc_set_ipmb_event_generator_support(mc, 0);
    
    ipmi_mc_set_sdrs_fixup_handler(mc, misc_sdrs_fixup, NULL);
    return 0;
}

static void
atca_register_fixups(void)
{
    ipmi_register_oem_handler(0x000157, 0x7008,
			      misc_sdrs_fixup_reg, NULL, NULL);
    ipmi_register_oem_handler(0x000157, 0x0808,
			      misc_sdrs_fixup_reg, NULL, NULL);
    ipmi_register_oem_handler(0xf00157, 0x0808,
			      misc_sdrs_fixup_reg, NULL, NULL);
    ipmi_register_oem_handler(0x000157, 0x0841,
			      misc_sdrs_fixup_reg, NULL, NULL);
    ipmi_register_oem_handler(0x000157, 0x080a,
			      misc_sdrs_fixup_reg, NULL, NULL);
}

/***********************************************************************
 *
 * ATCA initialization and detection
 *
 **********************************************************************/

static int
check_if_atca_cb(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_msg_t                 *msg = &rspi->msg;
    ipmi_domain_oem_check_done done = rspi->data1;

    if (!domain)
	return IPMI_MSG_ITEM_NOT_USED;

    if (msg->data[0] == 0) {
	/* It's an ATCA system, set it up */
	ipmi_domain_set_type(domain, IPMI_DOMAIN_TYPE_ATCA);
	set_up_atca_domain(domain, msg, done, rspi->data2);
    } else {
	done(domain, ENOSYS, rspi->data2);
    }
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
check_if_atca(ipmi_domain_t              *domain,
	      ipmi_domain_oem_check_done done,
	      void                       *cb_data)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    unsigned char 		 data[5];

    /* Send the ATCA Get Address Info command to get the shelf FRU info. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_GET_ADDRESS_INFO;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = 0; /* Ignored for physical address */
    data[2] = PICMG_ADDRESS_KEY_PHYSICAL;
    data[3] = 1; /* Look for Shelf FRU 1 */
    data[4] = PICMG_SITE_TYPE_SHELF_FRU_INFO;
    msg.data = data;
    msg.data_len = 5;

    return ipmi_send_command_addr(domain,
				  (ipmi_addr_t *) &si, sizeof(si),
				  &msg,
				  check_if_atca_cb, done, cb_data);
}

int
ipmi_oem_atca_init(void)
{
    int rv;

    atca_register_fixups();

    rv = ipmi_register_domain_oem_check(check_if_atca, NULL);
    if (rv)
	return rv;

    return 0;
}

void
ipmi_oem_atca_shutdown(void)
{
    ipmi_deregister_domain_oem_check(check_if_atca, NULL);
}
