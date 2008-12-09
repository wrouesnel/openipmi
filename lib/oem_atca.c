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
#include <ctype.h>
#include <stdio.h> /* For sprintf */
#include <limits.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_addr.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_picmg.h>

#include <OpenIPMI/internal/ipmi_event.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/ipmi_oem.h>
#include <OpenIPMI/internal/ipmi_mc.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_sensor.h>
#include <OpenIPMI/internal/ipmi_control.h>
#include <OpenIPMI/internal/ipmi_entity.h>
#include <OpenIPMI/internal/ipmi_utils.h>
#include <OpenIPMI/internal/ipmi_fru.h>

/* Uncomment this if you *really* want direct power control.  Note
   that I think this is a bad idea, you should *really* use the
   hot-swap state machine to handle power control.  Plus, the code is
   untested. */
/* #define POWER_CONTROL_AVAILABLE */

/* A control attached to the system interface used to fetch the power
   feed information. */
#define POWER_FEED_CONTROL_NUM	0x00
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
    ipmi_control_t            *warm_reset;
    ipmi_control_t            *graceful_reboot;
    ipmi_control_t            *diagnostic_interrupt;
    ipmi_control_t            *power;
    unsigned int              fru_capabilities;
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

    unsigned int mfg_id;
    unsigned int prod_id;

    /* ATCA version from the get properties message to the shelf
       manager.  Note that this is nibble-swapped so it compares and
       works nicely, eg version 2.1 will be 0x21.  This is backwards
       from what comes in on the message. */
    unsigned char atca_version;

    char                 shelf_address[40];
    enum ipmi_str_type_e shelf_address_type;
    unsigned int         shelf_address_len;

    unsigned int nr_power_feeds;
    ipmi_control_t *power_feed_control;

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

    /* local blade-only connection */
    unsigned int is_local : 1;
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
    else
	ipmi_control_set_num_elements(*control, length);

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
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "oem_atca.c(%s): "
		 "Error from message", func_name);
	return 1;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "oem_atca.c(%s): "
		 "MC went away", func_name);
	if (rv)
	    *rv = ECANCELED;
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

static atca_ipmc_t *
atca_find_minfo_from_ipmb(unsigned int ipmb_addr, atca_shelf_t *info)
{
    atca_ipmc_t  *minfo = NULL;
    unsigned int i;

    if (ipmb_addr == 0x20)
	/* We ignore the floating IPMB address if it comes up. */
	return NULL;

    for (i=0; i<info->num_ipmcs; i++) {
	if (ipmb_addr == info->ipmcs[i].ipmb_address) {
	    minfo = &(info->ipmcs[i]);
	    break;
	}
    }

    return minfo;
}

static atca_ipmc_t *
atca_find_minfo_from_mc(ipmi_mc_t *mc, atca_shelf_t *info)
{
    return atca_find_minfo_from_ipmb(ipmi_mc_get_address(mc), info);
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

#if 0
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
#endif

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
#if 0
    .set_auto_activate        = atca_set_auto_activate,
    .get_auto_activate        = atca_get_auto_activate,
    .set_auto_deactivate      = atca_set_auto_deactivate,
    .get_auto_deactivate      = atca_get_auto_deactivate,
#else
    .set_auto_activate        = NULL,
    .get_auto_activate        = NULL,
    .set_auto_deactivate      = NULL,
    .get_auto_deactivate      = NULL,
#endif
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

static void
atca_event_scan_mc_done(ipmi_domain_t *domain, int err, void *cb_data)
{
    ipmi_entity_t *entity = cb_data;

    if (!entity)
	return;

    ipmi_detect_entity_presence_change(entity, 1);
    _ipmi_entity_put(entity);
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
    ipmi_entity_t             *entity;

    /* We only want assertions. */
    if (dir != IPMI_ASSERTION)
	return handled;

    if ((offset < 0) || (offset >= 8))
	/* eh? */
	return handled;

    entity = ipmi_sensor_get_entity(sensor);

    /* The OpenIPMI hot-swap states map directly to the ATCA ones. */
    old_state = finfo->hs_state;
    finfo->hs_state = offset;
    ipmi_entity_call_hot_swap_handlers(entity,
				       old_state,
				       finfo->hs_state,
				       &event,
				       &handled);
    if ((old_state == IPMI_HOT_SWAP_NOT_PRESENT) 
	|| (finfo->hs_state == IPMI_HOT_SWAP_NOT_PRESENT))
    {
	/* The new state is not present, scan the mc to clear it out. */
	unsigned char ipmb_addr = finfo->minfo->ipmb_address;
	int           rv;

	_ipmi_entity_get(entity);
	rv = ipmi_start_ipmb_mc_scan(ipmi_entity_get_domain(entity),
				     0, ipmb_addr, ipmb_addr,
				     atca_event_scan_mc_done, entity);
	if (rv)
	    _ipmi_entity_put(entity);
    }

    return handled;
}

static void
setup_fru_hot_swap(atca_fru_t *finfo, ipmi_sensor_t *sensor)
{
    int rv;

    finfo->hs_sensor_id = ipmi_sensor_convert_to_id(sensor);

    ipmi_entity_set_hot_swappable(finfo->entity, 1);
    ipmi_entity_set_supports_managed_hot_swap(finfo->entity, 1);
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
	goto out;
    }
    l->op_in_progress = 0;

    if (check_for_msg_err(mc, NULL, msg, 5, "fru_led_cap_rsp"))
	goto out;

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
	goto out;
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
	goto out;
    }
    for (i=1; i<=6; i++) {
	if (msg->data[2] & (1 << i))
	    ipmi_control_add_light_color_support(l->control, 0,
						 atca_to_openipmi_color[i]);
    }
     /* We always support black */
    ipmi_control_add_light_color_support(l->control, 0,
					 IPMI_CONTROL_COLOR_BLACK);
    ipmi_control_set_num_elements(l->control, 1);
    ipmi_control_light_set_has_local_control(l->control, 0, l->local_control);
    rv = atca_add_control(mc, 
			  &l->control,
			  UINT_MAX, /* Let the control code pick the number */
			  finfo->entity);
    _ipmi_entity_put(finfo->entity);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fru_led_cap_rsp): "
		 "Could not add LED control: 0x%x",
		 MC_NAME(mc), rv);
	goto out;
    }
 out:
    return;
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

    if (check_for_msg_err(mc, NULL, rsp, 3, "get_led_capability_2")) {
	linfo->op_in_progress = 0;
	return;
    }

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
	linfo->op_in_progress = 0;
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
		 "%soem_atca.c(get_led_capability): "
		 "Could not send FRU LED state command: 0x%x",
		 MC_NAME(mc), rv);
	linfo->op_in_progress = 0;
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
	goto out;

    /* Note that while the MC exists, finfo is guaranteed to exist
       because we never decrease the number of FRUs. */

    if (finfo->leds)
	/* There is a race here, it is possible to have two LED
	   fetches running at the same time.  If they have already
	   been fetched, just ignore this message. */
	goto out;

    if (!finfo->entity)
	/* The entity was destroyed while the message was in progress. */
	goto out;
    
    num_leds = 4 + rsp->data[3];
    finfo->leds = ipmi_mem_alloc(sizeof(atca_led_t *) * num_leds);
    if (!finfo->leds) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fru_led_prop_rsp): "
		 "Could not allocate memory LEDs",
		 MC_NAME(mc));
	goto out;
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
		goto out;
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
	    goto out;
	}
	memset(finfo->leds[i], 0, sizeof(atca_led_t));
	get_led_capability(mc, finfo, i);
    }
 out:
    return;
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
    unsigned int i;

    if (finfo->leds) {
	for (i=0; i<finfo->num_leds; i++) {
	    atca_led_t *linfo = finfo->leds[i];
	    if (!linfo)
		continue;
	    if (linfo->control)
		ipmi_control_destroy(linfo->control);
	    if (linfo->op_in_progress)
		linfo->destroyed = 1;
	    else
		ipmi_mem_free(linfo);
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

typedef struct atca_fru_control_s
{
    unsigned char          option;
    ipmi_control_op_cb     handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
} atca_fru_control_t;

static void
set_fru_control_done(ipmi_control_t *control,
		    int            err,
		    ipmi_msg_t     *rsp,
		    void           *cb_data)
{
    atca_fru_control_t *info = cb_data;
    ipmi_mc_t          *mc = NULL;

    if (control)
	mc = ipmi_control_get_mc(control);

    if (check_for_msg_err(mc, &err, rsp, 2, "set_fru_control_done")) {
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
set_fru_control_start(ipmi_control_t *control, int err, void *cb_data)
{
    atca_fru_control_t *info = cb_data;
    atca_fru_t         *finfo = ipmi_control_get_oem_info(control);
    ipmi_msg_t         msg;
    unsigned char      data[3];
    int                rv;

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
    data[2] = info->option;
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, set_fru_control_done,
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
set_fru_control(ipmi_control_t     *control,
		unsigned int       option,
		ipmi_control_op_cb handler,
		void               *cb_data)
{
    atca_fru_control_t *info;
    int                rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->option = option;
    info->handler = handler;
    info->cb_data = cb_data;
    rv = ipmi_control_add_opq(control, set_fru_control_start,
			      &info->sdata, info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

static int
set_cold_reset(ipmi_control_t     *control,
	       int                *val,
	       ipmi_control_op_cb handler,
	       void               *cb_data)
{
    return set_fru_control(control, 0, handler, cb_data);
}

static int
set_warm_reset(ipmi_control_t     *control,
	       int                *val,
	       ipmi_control_op_cb handler,
	       void               *cb_data)
{
    return set_fru_control(control, 1, handler, cb_data);
}

static int
set_graceful_reboot(ipmi_control_t     *control,
		    int                *val,
		    ipmi_control_op_cb handler,
		    void               *cb_data)
{
    return set_fru_control(control, 2, handler, cb_data);
}

static int
set_diagnostic_interrupt(ipmi_control_t     *control,
			 int                *val,
			 ipmi_control_op_cb handler,
			 void               *cb_data)
{
    return set_fru_control(control, 3, handler, cb_data);
}

static void
add_atca_fru_control(ipmi_mc_t               *mc,
		     atca_fru_t              *finfo,
		     char                    *name,
		     unsigned int            control_type,
		     ipmi_control_set_val_cb set_val,
		     ipmi_control_t          **control)
{
    int rv;

    rv = atca_alloc_control(mc, finfo, NULL,
			    control_type,
			    name,
			    set_val,
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    1,
			    control);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_atca_fru_control): "
		 "Could allocate the '%s' control: 0x%x",
		 ENTITY_NAME(finfo->entity), name, rv);
	return;
    }

    rv = atca_add_control(mc, 
			  control,
			  UINT_MAX,
			  finfo->entity);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_atca_fru_control): "
		 "Could not add '%s' control: 0x%x",
		 MC_NAME(mc), name, rv);
    }
}

static void
fru_control_capabilities_rsp(ipmi_mc_t  *mc,
			     ipmi_msg_t *rsp,
			     void       *rsp_data)
{
    ipmi_domain_t *domain;
    atca_fru_t    *finfo = rsp_data;
    int           rv;

    if (!check_for_msg_err(mc, NULL, rsp, 3, "fru_control_capabilities_rsp"))
	finfo->fru_capabilities = rsp->data[2];

    if (!mc)
	goto out;

    domain = ipmi_mc_get_domain(mc);

    /* If the command fails, we just go on, as the system doesn't
       support the query, but still must support at least cold
       reset. */

    _ipmi_domain_entity_lock(domain);
    if (!finfo->entity) {
	rv = EINVAL;
    } else
	rv = _ipmi_entity_get(finfo->entity);
    _ipmi_domain_entity_unlock(domain);
    if (rv)
	/* The entity was destroyed while the message was in progress. */
	goto out;

    /* Always support cold reset. */
    add_atca_fru_control(mc, finfo, "cold reset", IPMI_CONTROL_ONE_SHOT_RESET,
			 set_cold_reset, &finfo->cold_reset);
    if (finfo->fru_capabilities & 0x02)
	add_atca_fru_control(mc, finfo, "warm reset",
			     IPMI_CONTROL_ONE_SHOT_RESET,
			     set_warm_reset, &finfo->warm_reset);
    if (finfo->fru_capabilities & 0x04)
	add_atca_fru_control(mc, finfo, "graceful reboot",
			     IPMI_CONTROL_ONE_SHOT_RESET,
			     set_graceful_reboot,
			     &finfo->graceful_reboot);
    if (finfo->fru_capabilities & 0x08)
	add_atca_fru_control(mc, finfo, "diagnostic interrupt",
			     IPMI_CONTROL_ONE_SHOT_RESET,
			     set_diagnostic_interrupt,
			     &finfo->diagnostic_interrupt);
    _ipmi_entity_put(finfo->entity);

 out:
    return;

}

static void
fetch_fru_control_mc_cb(ipmi_mc_t *mc, void *cb_info)
{
    atca_fru_t    *finfo = cb_info;
    ipmi_msg_t    msg;
    unsigned char data[2];
    int           rv;

    /* Now fetch the LED information. */
    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_FRU_CONTROL_CAPABILITIES;
    msg.data = data;
    msg.data_len = 2;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = finfo->fru_id;
    rv = ipmi_mc_send_command(mc, 0, &msg, fru_control_capabilities_rsp, finfo);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fetch_fru_leds_mc_cb): "
		 "Could not send FRU LED properties command: 0x%x",
		 MC_NAME(mc), rv);
	/* Just go on, don't shut down the info. */
    }
}

static void
fetch_fru_control_handling(atca_fru_t *finfo)
{
    int rv;

    if (finfo->cold_reset)
	return;
    
    rv = ipmi_mc_pointer_cb(finfo->minfo->mcid, fetch_fru_control_mc_cb, finfo);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fetch_fru_control_handling): "
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
    if (finfo->warm_reset) {
	ipmi_control_t *control = finfo->warm_reset;
	finfo->warm_reset = NULL;
	ipmi_control_destroy(control);
    }
    if (finfo->graceful_reboot) {
	ipmi_control_t *control = finfo->graceful_reboot;
	finfo->graceful_reboot = NULL;
	ipmi_control_destroy(control);
    }
    if (finfo->diagnostic_interrupt) {
	ipmi_control_t *control = finfo->diagnostic_interrupt;
	finfo->diagnostic_interrupt = NULL;
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
			  UINT_MAX,
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
 * Control for the power feeds
 *
 **********************************************************************/

typedef struct atca_power_feed_s
{
    ipmi_control_val_cb    get_handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
    unsigned int           curr_feed;
    int                    *vals;
} atca_power_feed_t;

static void get_power_feed_start(ipmi_control_t *control, int err,
				 void *cb_data);

static void
get_power_feed_done(ipmi_control_t *control,
		    int            err,
		    ipmi_msg_t     *rsp,
		    void           *cb_data)
{
    atca_power_feed_t *info = cb_data;
    atca_shelf_t      *sinfo = ipmi_control_get_oem_info(control);
    ipmi_mc_t         *mc = NULL;
    unsigned int      expected_feeds;
    unsigned int      i;

    if (control)
	mc = ipmi_control_get_mc(control);

    expected_feeds = sinfo->nr_power_feeds - info->curr_feed;
    if (expected_feeds > 10)
	expected_feeds = 10;

    if (check_for_msg_err(mc, &err, rsp, 4 + (expected_feeds * 2),
			  "get_power_feed_done"))
    {
	if (info->get_handler)
	    info->get_handler(control, err, info->vals, info->cb_data);
	goto out;
    }

    for (i=0; i<expected_feeds; i++) {
	info->vals[info->curr_feed] = ipmi_get_uint16(rsp->data+4+(i*2));
	info->curr_feed++;
    }

    if (info->curr_feed < sinfo->nr_power_feeds) {
	/* Not done, continue fetching. */
	get_power_feed_start(control, 0, info);
	return;
    }

    if (info->get_handler)
	info->get_handler(control, 0, info->vals, info->cb_data);

 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(info->vals);
    ipmi_mem_free(info);
}


static void
get_power_feed_start(ipmi_control_t *control, int err, void *cb_data)
{
    atca_power_feed_t *info = cb_data;
    ipmi_msg_t        msg;
    unsigned char     data[2];
    int               rv;

    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_SHELF_POWER_ALLOCATION;
    msg.data = data;
    msg.data_len = 2;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = info->curr_feed;

    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, get_power_feed_done,
				   &(info->sdata), info);
    if (rv) {
	if (info->get_handler)
	    info->get_handler(control, rv, info->vals, info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(info->vals);
	ipmi_mem_free(info);
    }
}

static int
get_power_feed(ipmi_control_t      *control,
	       ipmi_control_val_cb handler,
	       void                *cb_data)
{
    atca_power_feed_t *info;
    atca_shelf_t      *sinfo = ipmi_control_get_oem_info(control);
    int               rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->vals = ipmi_mem_alloc(sizeof(unsigned int) * sinfo->nr_power_feeds);
    if (!info->vals) {
	ipmi_mem_free(info);
	return ENOMEM;
    }

    info->curr_feed = 0;
    info->get_handler = handler;
    info->cb_data = cb_data;

    rv = ipmi_control_add_opq(control, get_power_feed_start,
			      &info->sdata, info);
    if (rv) {
	ipmi_mem_free(info->vals);
	ipmi_mem_free(info);
    }
    return rv;
}

static void
add_power_feed_control(atca_shelf_t *info)
{
    int                          rv;
    ipmi_system_interface_addr_t si;
    ipmi_mc_t                    *si_mc;

    if (info->power_feed_control)
	return;

    if ((info->atca_version < 0x22) || (info->nr_power_feeds == 0))
	return;
    
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;

    si_mc = _ipmi_find_mc_by_addr(info->domain,
				  (ipmi_addr_t *) &si,
				  sizeof(si));
    if (!si_mc) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_power_feed_control): "
		 "Could not find system interface mc",
		 DOMAIN_NAME(info->domain));
	return;
    }

    rv = atca_alloc_control(si_mc, info, NULL,
			    IPMI_CONTROL_POWER,
			    "power_feeds",
			    NULL,
			    get_power_feed,
			    NULL,
			    NULL,
			    NULL,
			    NULL,
			    info->nr_power_feeds,
			    &info->power_feed_control);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_power_feed_control): "
		 "Could not alloc control: 0x%x",
		 DOMAIN_NAME(info->domain), rv);
	goto out;
    }

    rv = atca_add_control(si_mc,
			  &info->power_feed_control,
			  POWER_FEED_CONTROL_NUM,
			  info->shelf_entity);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(add_power_feed_control): "
		 "Could not add power feed control: 0x%x",
		 DOMAIN_NAME(info->domain), rv);
	goto out;
    }

 out:
    _ipmi_mc_put(si_mc);
}

static void
destroy_power_feed_control(atca_shelf_t *info)
{
    ipmi_system_interface_addr_t si;
    ipmi_mc_t                    *si_mc;

    if (info->power_feed_control) {
	ipmi_control_t *control = info->power_feed_control;

	si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si.channel = 0xf;
	si.lun = 0;

	si_mc = _ipmi_find_mc_by_addr(info->domain,
				      (ipmi_addr_t *) &si,
				      sizeof(si));
	if (!si_mc) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(destroy_power_feed_control): "
		     "Could not find system interface mc",
		     DOMAIN_NAME(info->domain));
	    return;
	}

	/* We *HAVE* to clear the value first, destroying this can
	   cause something else to be destroyed and end up in the
	   function again before we return from
	   ipmi_control_destroy(). */
	info->power_feed_control = NULL;
	ipmi_control_destroy(control);
	_ipmi_mc_put(si_mc);
    }
}

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

    /* Ignore the address control for presence. */
    ipmi_control_set_ignore_for_presence(ipmc->address_control, 1);
    
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
    ipmi_system_interface_addr_t si;
    ipmi_mc_t                    *si_mc;

    if (ipmc->address_control) {
	ipmi_control_t *control = ipmc->address_control;

	si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si.channel = 0xf;
	si.lun = 0;

	si_mc = _ipmi_find_mc_by_addr(ipmc->shelf->domain,
				      (ipmi_addr_t *) &si,
				      sizeof(si));
	if (!si_mc) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(destroy_address_control): "
		     "Could not find system interface mc",
		     ENTITY_NAME(ipmc->frus[0]->entity));
	    return;
	}

	/* We *HAVE* to clear the value first, destroying this can
	   cause something else to be destroyed and end up in the
	   function again before we return from
	   ipmi_control_destroy(). */
	ipmc->address_control = NULL;
	ipmi_control_destroy(control);
	_ipmi_mc_put(si_mc);
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
    unsigned int i, j;

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
    int          ipmb_addr;
    int          fru_id;
    unsigned int i;
    atca_ipmc_t  *minfo = NULL;
    int          rv;

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
    int          ipmb_addr;
    unsigned int i;
    atca_ipmc_t  *minfo = NULL;
    int          rv;

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
	    int                       handled = IPMI_EVENT_NOT_HANDLED;
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
	    ipmi_entity_set_supports_managed_hot_swap(entity, 0);
	}
	break;

    default:
	break;
    }
}

static void
add_fru_controls(atca_fru_t *finfo)
{
    if (finfo->cold_reset)
	return;
    fetch_fru_leds(finfo);
    fetch_fru_control_handling(finfo);
#ifdef POWER_CONTROL_AVAILABLE
    add_power_handling(finfo);
#endif
}

static void
destroy_fru_controls(atca_fru_t *finfo)
{
    if (!finfo->minfo->mc)
	return;

    _ipmi_mc_get(finfo->minfo->mc);
    destroy_fru_leds(finfo);
    destroy_fru_control_handling(finfo);
#ifdef POWER_CONTROL_AVAILABLE
    destroy_power_handling(finfo);
#endif
    _ipmi_mc_put(finfo->minfo->mc);
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

	/* If the entity isn't set up yet but is present, handle that. */
	if (ipmi_entity_is_present(entity))
	    add_fru_controls(finfo);
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
    unsigned int  i;
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
    ipmi_mc_id_set_invalid(&minfo->mcid);
    minfo->mc = NULL;
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
    ipmi_msg_t    msg;
    unsigned char data[1];
    int           rv;
    atca_ipmc_t   *minfo;

    minfo = atca_find_minfo_from_mc(mc, info);
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

    if (ipmi_mc_get_address(mc) & 0x01)
	/* Ignore MCs with system software ID addresses. */
	return;

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
 * Special FRU handling for FRU device 254 on the shelf manager.
 *
 **********************************************************************/

typedef struct atca_fru_254_info_s
{
    uint16_t lock_id;
} atca_fru_254_info_t;

static void
atca_fru_254_info_cleanup(ipmi_fru_t *fru, void *data)
{
    ipmi_mem_free(data);
}

static int
atca_fru_254_get_timestamp_done(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_fru_t             *fru = rspi->data1;
    _ipmi_fru_timestamp_cb handler = rspi->data2;
    ipmi_msg_t             *msg = &rspi->msg;
    unsigned char          *data = msg->data;

    if (!domain) {
	handler(fru, domain, ECANCELED, 0);
	goto out;
    }

    if (data[0] != 0) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_get_timestamp_done): "
		 "Error fetching the FRU timestamp: 0x%x",
		 DOMAIN_NAME(domain), data[0]);
	handler(fru, domain, IPMI_IPMI_ERR_VAL(data[0]), 0);
	goto out;
    }

    if (msg->data_len < 8) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_get_timestamp_done): "
		 "FRU timestamp fetch too small: %d",
		 DOMAIN_NAME(domain), msg->data_len);
	handler(fru, domain, EINVAL, 0);
    }

    handler(fru, domain, 0, ipmi_get_uint32(data+4));

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
atca_fru_254_get_timestamp(ipmi_fru_t             *fru,
			   ipmi_domain_t          *domain,
			   _ipmi_fru_timestamp_cb handler)
{
    ipmi_addr_t   addr;
    unsigned int  addr_len;
    ipmi_msg_t    msg;
    unsigned char data[5];

    _ipmi_fru_get_addr(fru, &addr, &addr_len);

    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_FRU_INVENTORY_DEVICE_LOCK_CONTROL;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = 254;
    data[2] = 0; /* Fetch timestamp */
    data[3] = 0;
    data[4] = 0;
    msg.data = data;
    msg.data_len = 5;

    return ipmi_send_command_addr(domain,
				  &addr, addr_len,
				  &msg,
				  atca_fru_254_get_timestamp_done,
				  fru,
				  handler);
}

static int
atca_fru_254_prepare_write_done(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_fru_t          *fru = rspi->data1;
    _ipmi_fru_op_cb     handler = rspi->data2;
    ipmi_msg_t          *msg = &rspi->msg;
    unsigned char       *data = msg->data;
    atca_fru_254_info_t *info;

    if (!domain) {
	handler(fru, domain, ECANCELED);
	goto out;
    }

    if (data[0] != 0) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_prepare_write_done): "
		 "Error getting the lock: 0x%x",
		 DOMAIN_NAME(domain), data[0]);
	handler(fru, domain, IPMI_IPMI_ERR_VAL(data[0]));
	goto out;
    }

    if (msg->data_len < 8) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_prepare_write_done): "
		 "lock fetch response too small: %d",
		 DOMAIN_NAME(domain), msg->data_len);
	handler(fru, domain, EINVAL);
    }

    info = _ipmi_fru_get_setup_data(fru);
    info->lock_id = ipmi_get_uint16(data+2);

    handler(fru, domain, 0);

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
atca_fru_254_prepare_write(ipmi_fru_t      *fru,
			   ipmi_domain_t   *domain,
			   uint32_t        timestamp,
			   _ipmi_fru_op_cb done)
{
    ipmi_addr_t   addr;
    unsigned int  addr_len;
    ipmi_msg_t    msg;
    unsigned char data[5];

    _ipmi_fru_get_addr(fru, &addr, &addr_len);

    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_FRU_INVENTORY_DEVICE_LOCK_CONTROL;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = 254;
    data[2] = 1; /* get lock */
    data[3] = 0;
    data[4] = 0;
    msg.data = data;
    msg.data_len = 5;

    return ipmi_send_command_addr(domain,
				  &addr, addr_len,
				  &msg,
				  atca_fru_254_prepare_write_done,
				  fru,
				  done);
}

static int
atca_fru_254_write_done(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_fru_t      *fru = rspi->data1;
    _ipmi_fru_op_cb handler = rspi->data2;
    ipmi_msg_t      *msg = &rspi->msg;
    unsigned char   *data = msg->data;

    if (!domain) {
	handler(fru, domain, ECANCELED);
	goto out;
    }

    if (data[0] != 0) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_write_done): "
		 "Error writing FRU data: 0x%x",
		 DOMAIN_NAME(domain), data[0]);
	handler(fru, domain, IPMI_IPMI_ERR_VAL(data[0]));
	goto out;
    }

    if (msg->data_len < 3) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_write_done): "
		 "Write response too small: %d",
		 DOMAIN_NAME(domain), msg->data_len);
	handler(fru, domain, EINVAL);
    }

    handler(fru, domain, 0);

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
atca_fru_254_write(ipmi_fru_t      *fru,
		   ipmi_domain_t   *domain,
		   unsigned char   *idata,
		   unsigned int    idata_len,
		   _ipmi_fru_op_cb done)
{
    ipmi_addr_t         addr;
    unsigned int        addr_len;
    ipmi_msg_t          msg;
    unsigned char       data[MAX_IPMI_DATA_SIZE];
    atca_fru_254_info_t *info;

    if (idata_len < 3)
	return EINVAL;
    if ((idata_len + 3) > sizeof(data))
	return E2BIG;

    info = _ipmi_fru_get_setup_data(fru);

    _ipmi_fru_get_addr(fru, &addr, &addr_len);

    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_FRU_INVENTORY_DEVICE_WRITE;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = idata[0];
    ipmi_set_uint16(data+2, info->lock_id);
    memcpy(data+4, idata+1, idata_len-1);
    msg.data = data;
    msg.data_len = idata_len + 3;

    return ipmi_send_command_addr(domain,
				  &addr, addr_len,
				  &msg,
				  atca_fru_254_write_done,
				  fru,
				  done);
}

static int
atca_fru_254_complete_write_done(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_fru_t      *fru = rspi->data1;
    _ipmi_fru_op_cb handler = rspi->data2;
    ipmi_msg_t      *msg = &rspi->msg;
    unsigned char   *data = msg->data;


    if (!domain) {
	handler(fru, domain, ECANCELED);
	goto out;
    }

    if (data[0] != 0) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_complete_write_done): "
		 "Error releasing the FRU data lock: 0x%x",
		 DOMAIN_NAME(domain), data[0]);
	handler(fru, domain, IPMI_IPMI_ERR_VAL(data[0]));
	goto out;
    }

    if (msg->data_len < 8) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_complete_write_done): "
		 "FRU lock release too small: %d",
		 DOMAIN_NAME(domain), msg->data_len);
	handler(fru, domain, EINVAL);
    }

    handler(fru, domain, 0);

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
atca_fru_254_complete_write(ipmi_fru_t      *fru,
			    ipmi_domain_t   *domain,
			    int             err,
			    uint32_t        timestamp,
			    _ipmi_fru_op_cb done)
{
    ipmi_addr_t         addr;
    unsigned int        addr_len;
    ipmi_msg_t          msg;
    unsigned char       data[5];
    atca_fru_254_info_t *info;


    _ipmi_fru_get_addr(fru, &addr, &addr_len);

    info = _ipmi_fru_get_setup_data(fru);

    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_FRU_INVENTORY_DEVICE_LOCK_CONTROL;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = 254;
    if (err)
	data[2] = 2; /* unlock and discard */
    else
	data[2] = 3; /* unlock and commit */
    ipmi_set_uint16(data+3, info->lock_id);
    msg.data = data;
    msg.data_len = 5;

    return ipmi_send_command_addr(domain,
				  &addr, addr_len,
				  &msg,
				  atca_fru_254_complete_write_done,
				  fru,
				  done);
}

static int
atca_fru_254_setup(ipmi_domain_t *domain,
		   unsigned char is_logical,
		   unsigned char device_address,
		   unsigned char device_id,
		   unsigned char lun,
		   unsigned char private_bus,
		   unsigned char channel,
		   ipmi_fru_t    *fru,
		   void          *cb_data)
{
    int                 rv;
    atca_fru_254_info_t *info;

    if (!is_logical || (device_address != 0x20) || (device_id != 254))
	return 0;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    _ipmi_fru_set_setup_data(fru, info, atca_fru_254_info_cleanup);

    rv = _ipmi_fru_set_get_timestamp_handler(fru, atca_fru_254_get_timestamp);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_setup): "
		 "Unable to register timestamp handler",
		 DOMAIN_NAME(domain));
	return rv;
    }

    rv = _ipmi_fru_set_prepare_write_handler(fru, atca_fru_254_prepare_write);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_setup): "
		 "Unable to register prepare write handler",
		 DOMAIN_NAME(domain));
	return rv;
    }

    rv = _ipmi_fru_set_write_handler(fru, atca_fru_254_write);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_setup): "
		 "Unable to register write handler",
		 DOMAIN_NAME(domain));
	return rv;
    }

    rv = _ipmi_fru_set_complete_write_handler(fru,
					      atca_fru_254_complete_write);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_fru_254_setup): "
		 "Unable to register write complete handler",
		 DOMAIN_NAME(domain));
	return rv;
    }

    return 0;
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

static void shelf_fru_fetched(ipmi_domain_t *domain, ipmi_fru_t *fru,
			      int err, void *cb_data);

static void
setup_from_shelf_fru(ipmi_domain_t *domain,
		     atca_shelf_t  *info)
{
    ipmi_entity_info_t *ents;
    char               *name;
    unsigned int       i;
    int                rv;

    ents = ipmi_domain_get_entities(domain);

    if (!info->is_local) {
	/* Create the main shelf entity. */
	name = "ATCA Shelf";
	rv = ipmi_entity_add(ents, domain, 0, 0, 0,
			     IPMI_ENTITY_ID_SYSTEM_CHASSIS, 1,
			     name, IPMI_ASCII_STR, strlen(name),
			     atca_entity_sdr_add,
			     NULL, &info->shelf_entity);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "%soem_atca.c(setup_from_shelf_fru): "
		     "Could not add chassis entity: %x",
		     DOMAIN_NAME(domain), rv);
	    goto out;
	}

	/* Set up shelf FRU data for the shelf entity, and pass our shelf
	   fru onto the entity. */
	ipmi_entity_set_is_logical_fru(info->shelf_entity, 1);
	ipmi_entity_set_access_address(info->shelf_entity, info->shelf_fru_ipmb);
	ipmi_entity_set_fru_device_id(info->shelf_entity,
				      info->shelf_fru_device_id);
	ipmi_entity_set_lun(info->shelf_entity, 0);
	ipmi_entity_set_private_bus_id(info->shelf_entity, 0);
	ipmi_entity_set_channel(info->shelf_entity, 0);
	_ipmi_entity_set_fru(info->shelf_entity, info->shelf_fru);
	info->shelf_fru = NULL;
    }

    /* Make sure the shelf entity is reported first. */
    if (info->shelf_entity) {
	_ipmi_entity_add_ref(info->shelf_entity);
	_ipmi_entity_put(info->shelf_entity);
	_ipmi_entity_get(info->shelf_entity);

	/* We added FRU info, report it. */
	_ipmi_entity_call_fru_handlers(info->shelf_entity, IPMI_ADDED);
    }

    add_power_feed_control(info);

    info->ipmcs = ipmi_mem_alloc(sizeof(atca_ipmc_t) * info->num_addresses);
    if (!info->ipmcs) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(setup_from_shelf_fru): "
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

	_ipmi_domain_mc_lock(domain);
	_ipmi_start_mc_scan_one(domain, 0, b->ipmb_address, b->ipmb_address);
	_ipmi_domain_mc_unlock(domain);

	rv = realloc_frus(b, 1); /* Start with 1 FRU for the MC. */
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(setup_from_shelf_fru): "
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
		     "%soem_atca.c(setup_from_shelf_fru): "
		     " Could not add board entity: %x",
		     DOMAIN_NAME(domain), rv);
	    goto out;
	}
	_ipmi_entity_add_ref(b->frus[0]->entity);

	/* Store the site_num as the physical slot number */
	ipmi_entity_set_physical_slot_num(b->frus[0]->entity, 1,
					  info->addresses[i].site_num);

	if (info->shelf_entity) {
	    rv = ipmi_entity_add_child(info->shelf_entity, b->frus[0]->entity);
	    if (rv) {
		ipmi_log(IPMI_LOG_WARNING,
			 "%soem_atca.c(setup_from_shelf_fru): "
			 "Could not add child ipmc: %x",
			 DOMAIN_NAME(domain), rv);
		_ipmi_entity_put(b->frus[0]->entity);
		goto out;
	    }
	}

	add_address_control(info, b);
	_ipmi_entity_put(b->frus[0]->entity);
    }

    info->setup = 1;

 out:
    if (info->shelf_entity)
	_ipmi_entity_put(info->shelf_entity);
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

    if (!info->shelf_address_only_on_bmc)
	info->shelf_fru_ipmb = msg->data[3];
    info->shelf_fru_device_id = 1; /* Always at FRU ID 1 */

    rv = ipmi_fru_alloc_notrack(domain,
				1,
				info->shelf_fru_ipmb,
				info->shelf_fru_device_id,
				0,
				0,
				0,
				IPMI_FRU_ALL_AREA_MASK,
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

static int
handle_power_map(ipmi_domain_t *domain,
		 atca_shelf_t  *info,
		 ipmi_fru_t    *fru,
		 unsigned char *data,
		 unsigned int  len)
{
    if (data[4] != 0) { /* We only know version 0 */
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(handle_power_map): "
		 "powermap table was version %d but I only know version 0",
		 DOMAIN_NAME(domain), data[4]);
	return 0;
    }

    if (len < 6) {
	/* length does not meet the minimum possible length. */
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(handle_power_map): "
		 "power map was %d bytes long, but must be at least 6 bytes.",
		 DOMAIN_NAME(domain), len);
	return 0;
    }

    info->nr_power_feeds = data[5];
    return 0;
}

static int
handle_address_table(ipmi_domain_t *domain,
		     atca_shelf_t  *info,
		     ipmi_fru_t    *fru,
		     unsigned char *data,
		     unsigned int  len)
{
    unsigned char *str;
    unsigned char *p;
    int           j, k, l;
    int           has_ipmb_32 = 0;
    int           rv;

    if (data[4] != 0) { /* We only know version 0 */
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(handle_address_table): "
		 "Address table was version %d but I only know version 0",
		 DOMAIN_NAME(domain), data[4]);
	return 0;
    }

    if (len < (unsigned int) (27 + (3 * data[26]))) {
	/* length does not meet the minimum possible length. */
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(handle_address_table): "
		 "Address table was %d bytes long, but the number"
		 " of entries (%d) requires %d bytes.  Error in the"
		 " address table.",
		 DOMAIN_NAME(domain), len - 27, data[26], data[26] * 3);
	return 0;
    }

    str = data + 5;
	
    rv = ipmi_get_device_string(&str, 21,
				info->shelf_address,
				IPMI_STR_FRU_SEMANTICS, 0,
				&info->shelf_address_type,
				sizeof(info->shelf_address),
				&info->shelf_address_len);
    if (rv)
	return rv;

    /* We add 1 for adding 0x20 */
    info->num_addresses = data[26] + 1;
    info->addresses = ipmi_mem_alloc(sizeof(atca_address_t) * (data[26]+1));
    if (!info->addresses) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(handle_address_table): "
		 "could not allocate memory for shelf addresses",
		 DOMAIN_NAME(domain));
	ipmi_mem_free(data);
	return ENOMEM;
    }
    memset(info->addresses, 0, sizeof(atca_address_t) * (data[26]+1));

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
			 "%soem_atca.c(handle_address_table): "
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
	    if ((p[0]*2) == 32)
		has_ipmb_32 = 1;
	    j++;
	}
    }

    if (has_ipmb_32)
	info->num_addresses--;
    else {
	/* If we don't find the "main" address, add it. */
	info->addresses[j].hw_address = 32 >> 1;
	info->addresses[j].site_num = 0;
	info->addresses[j].site_type = PICMG_SITE_TYPE_DEDICATED_SHMC;
	j++;
    }

    return 0;
}

static void
shelf_fru_fetched(ipmi_domain_t *domain, ipmi_fru_t *fru, int err,
		  void *cb_data)
{
    atca_shelf_t *info = cb_data;
    int          count;
    int          found;
    int          i;
    int          rv = 0;

    if (err) {
	ipmi_system_interface_addr_t si;
	ipmi_msg_t                   msg;
	unsigned char 		     data[5];

	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(shelf_fru_fetched): "
		 "Error getting FRU information: 0x%x",
		 DOMAIN_NAME(domain), err);

	ipmi_fru_destroy_internal(info->shelf_fru, NULL, NULL);
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

	    
	if ((ipmi_fru_get_multi_record_type(fru, i, &type) != 0)
	    || (ipmi_fru_get_multi_record_format_version(fru, i, &ver) != 0)
	    || (ipmi_fru_get_multi_record_data_len(fru, i, &len) != 0))
	    continue;

	if ((type != 0xc0) || (ver != 2) || (len < 4))
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

	if (data[3] == 0x10) /* Address table record id */
	    rv = handle_address_table(domain, info, fru, data, len);
	else if (data[3] == 0x11) /* Power distribution record */
	    rv = handle_power_map(domain, info, fru, data, len);

    next_data_item:
	ipmi_mem_free(data);

	if (rv)
	    goto out;
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
    _ipmi_domain_entity_lock(domain);
    if (info->shelf_entity)
	_ipmi_entity_get(info->shelf_entity);
    _ipmi_domain_entity_unlock(domain);
    if (info->ipmcs) {
	unsigned int i;
	for (i=0; i<info->num_ipmcs; i++) {
	    atca_ipmc_t *b = &(info->ipmcs[i]);

	    if (b->frus[0]->entity) {
		_ipmi_entity_get(b->frus[0]->entity);
		destroy_address_control(b);
		destroy_fru_controls(b->frus[0]);

		if (info->shelf_entity)
		    ipmi_entity_remove_child(info->shelf_entity,
					     b->frus[0]->entity);
		_ipmi_entity_remove_ref(b->frus[0]->entity);
		_ipmi_entity_put(b->frus[0]->entity);
	    }
	}
    }
    destroy_power_feed_control(info);
    if (info->shelf_entity) {
	_ipmi_entity_remove_ref(info->shelf_entity);
	_ipmi_entity_put(info->shelf_entity);
    }
}

static void
atca_oem_data_destroyer(ipmi_domain_t *domain, void *oem_data)
{
    atca_shelf_t *info = oem_data;

    if (info->shelf_fru)
	ipmi_fru_destroy_internal(info->shelf_fru, NULL, NULL);
    if (info->addresses)
	ipmi_mem_free(info->addresses);
    if (info->ipmcs) {
	unsigned int i, j;
	for (i=0; i<info->num_ipmcs; i++) {
	    atca_ipmc_t *b = &(info->ipmcs[i]);

	    ipmi_mem_free(b->frus[0]);
	    for (j=1; j<b->num_frus; j++) {
		if (b->frus[j])
		    ipmi_mem_free(b->frus[j]);
	    }
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
    unsigned char old_state;
    unsigned char new_state;
    unsigned char sensor_type;
    ipmi_mc_t     *mc;

    /* Here we look for hot-swap events so we know to start the
       process of scanning for an IPMC when it is installed.  We also
       look for version change events and re-read data for the MC
       involved.*/
    if (ipmi_event_get_type(event) != 2)
	/* Not a system event */
	return;

    ipmi_event_get_data(event, data, 0, 13);
    if (data[6] != 4)
	/* Not IPMI 1.5 */
	return;

    if (ipmi_event_is_old(event))
	/* It's an old event, ignore it. */
	return;

    sensor_type = data[7];

    switch(sensor_type) {
    case 0xf0:
	old_state = data[10] & 0xf;
	new_state = data[11] & 0xf;
	if ((old_state == 0) || (new_state == 0)) {
	    if (data[12] != 0) {
		/* FRU id is not 0, it's an AMC module (or something else the
		   IPMC manages).  If the device has gone away or is newly
		   inserted, rescan the SDRs on the IPMC. */
		ipmi_ipmb_addr_t addr;
		ipmi_mc_t        *mc;
		
		addr.addr_type = IPMI_IPMB_ADDR_TYPE;
		addr.channel = data[5] >> 4;
		addr.slave_addr = data[4];
		addr.lun = 0;

		mc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &addr,
					   sizeof(addr));
		if (mc) {
		    ipmi_mc_reread_sensors(mc, NULL, NULL);
		    _ipmi_mc_put(mc);
		}
	    }
	} else {
	    /* We have a hot-swap event on the main where the previous
	       state was not installed.  Scan the MC to make it appear.
	       Note that we always do this, in case we missed a hot-swap
	       removal and this is a changed MC. */
	    ipmi_start_ipmb_mc_scan(domain, (data[5] >> 4) & 0xf,
				    data[4], data[4], NULL, NULL);
	}
	break;

    case IPMI_SENSOR_TYPE_VERSION_CHANGE:
	if ((data[10] != 1) && (data[10] != 7))
	    break;
	mc = _ipmi_event_get_generating_mc(domain, NULL, event);
	if (!mc)
	    break;
	ipmi_mc_reread_sensors(mc, NULL, NULL);
	_ipmi_mc_put(mc);
	/* FIXME - what about FRU data? */
	break;
    }
}

static void
atca_new_sensor_handler(ipmi_domain_t *domain,
                        ipmi_sensor_t *sensor,
                        void          *cb_data)
{
    int sensor_type = ipmi_sensor_get_sensor_type(sensor);
    if (sensor_type == 0xf0) {
        ipmi_sensor_set_sensor_type_string(sensor, "ATCA Hotswap");
    } else if (sensor_type == 0xf1) {
        ipmi_sensor_set_sensor_type_string(sensor, "ATCA IPMB Stat");
    }
}

static void
set_up_atca_domain(ipmi_domain_t *domain, ipmi_msg_t *get_properties,
		   ipmi_domain_oem_check_done done, void *done_cb_data)
{
    ipmi_system_interface_addr_t saddr;
    ipmi_mc_t    *mc;
    atca_shelf_t *info;
    int          rv;

    if (get_properties->data_len < 5) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(set_up_atca_domain): "
		 "ATCA get properties response not long enough",
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

    info->atca_version = ((get_properties->data[2] >> 4)
			  | (get_properties->data[2] << 4));

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
	info->mfg_id = ipmi_mc_manufacturer_id(mc);
	info->prod_id = ipmi_mc_product_id(mc);
	if ((info->mfg_id == 0x000157) && (info->prod_id == 0x0841)) {
	    /* info->shelf_address_only_on_bmc = 1; */
	    /* info->allow_sel_on_any = 1; */
	}
	_ipmi_mc_put(mc);
    }

    info->startup_done = done;
    info->startup_done_cb_data = done_cb_data;
    info->domain = domain;

    /* We don't fetch the shelf FRU from the shelf FRU devices at
       first. We fetch it from the shelf manager (per the ECN 1.1
       spec, it's at 0xfe on the shelf manager).  If that fails, we go
       onto shelf FRUs. */
    info->curr_shelf_fru = 0;

    rv = ipmi_domain_add_event_handler(domain, atca_event_handler, info);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_atca.c(set_up_atca_domain): "
		 "Could not register for events: 0x%x", rv);
	ipmi_mem_free(info);
	done(domain, rv, done_cb_data);
	goto out;
    }

    if (info->atca_version >= 0x22) {
	rv = _ipmi_domain_fru_set_special_setup(domain, atca_fru_254_setup,
						NULL);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "oem_atca.c(set_up_atca_domain): "
		     "Could not register special FRU locking handler: 0x%x",
		     rv);
	    ipmi_mem_free(info);
	    done(domain, rv, done_cb_data);
	    goto out;
	}
    }

    /* Per ECN001, FRU data is on a shelf manager FRU id 254 */
    info->shelf_fru_ipmb = 0x20;
    info->shelf_fru_device_id = 254;
    rv = ipmi_fru_alloc_notrack(domain,
				1,
				0x20,
				254,
				0,
				0,
				0,
				IPMI_FRU_ALL_AREA_MASK,
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

    ipmi_domain_add_new_sensor_handler(domain, atca_new_sensor_handler, NULL);

 out:
    return;
}

/***********************************************************************
 *
 * Blade-only setup
 *
 **********************************************************************/
static int
atca_blade_info(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_msg_t   *msg = &rspi->msg;
    atca_shelf_t *info;
    int          rv = 0;
    int          ipmb;

    if (!domain)
	return IPMI_MSG_ITEM_NOT_USED;

    info = ipmi_domain_get_oem_data(domain);

    if (msg->data[0] != 0) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_blade_info): "
		 "Error getting address information: 0x%x",
		 DOMAIN_NAME(domain), msg->data[0]);
	rv = EINVAL;
	goto out_err;
    }

    if (msg->data_len < 8) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_blade_info): "
		 "ATCA get address response not long enough",
		 DOMAIN_NAME(domain));
	rv = EINVAL;
	goto out_err;
    }

    /* Only one IPMC */
    info->num_addresses = 1;
    info->addresses = ipmi_mem_alloc(sizeof(atca_address_t));
    if (!info->addresses) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_blade_info): "
		 "could not allocate memory for shelf addresses",
		 DOMAIN_NAME(domain));
	rv = ENOMEM;
	goto out_err;
    }

    ipmb = msg->data[2] << 1;
    info->addresses[0].hw_address = msg->data[2];
    info->addresses[0].site_type = msg->data[7];
    info->addresses[0].site_num = msg->data[6];

    /* Completely turn off scanning on channel 0 except for the one
       address for the blade. */
    ipmi_domain_add_ipmb_ignore_range(domain, 0, 0x00, ipmb - 1);
    ipmi_domain_add_ipmb_ignore_range(domain, 0, ipmb + 1, 0xff);

    /* Add a handler for when MCs are added to the domain, so we can
       add in our custom sensors. */
    rv = ipmi_domain_add_mc_updated_handler(domain,
					    atca_mc_update_handler,
					    info);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_atca.c(atca_blade_info): "
		 "Could not add MC update handler: %x",
		 DOMAIN_NAME(domain), rv);
	goto out_err;
    }

    rv = ipmi_domain_add_entity_update_handler(domain,
					       atca_entity_update_handler,
					       info);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_atca.c(atca_blade_info): "
		 "Could not add entity update handler: %x",
		 DOMAIN_NAME(domain), rv);
	goto out_err;
    }


 out_err:
    info->startup_done(domain, rv, info->startup_done_cb_data);
    return IPMI_MSG_ITEM_NOT_USED;
}

static void
set_up_atca_blade(ipmi_domain_t *domain, ipmi_msg_t *get_properties,
		  ipmi_domain_oem_check_done done, void *done_cb_data)
{
    ipmi_system_interface_addr_t si, saddr;
    ipmi_msg_t                   msg;
    unsigned char 		 data[1];
    ipmi_mc_t                    *mc;
    atca_shelf_t                 *info;
    int                          rv;

    if (get_properties->data_len < 5) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(set_up_atca_blade): "
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
		 "%soem_atca.c(set_up_atca_blade): "
		 "Could not allocate ATCA information structure",
		 DOMAIN_NAME(domain));
	done(domain, ENOMEM, done_cb_data);
	goto out;
    }
    memset(info, 0, sizeof(*info));
    info->is_local = 1;

    info->next_address_control_num = FIRST_IPMC_ADDRESS_NUM;

    saddr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    saddr.channel = IPMI_BMC_CHANNEL;
    mc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &saddr, sizeof(saddr));
    if (!mc) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(set_up_atca_blade): "
		 "Could not find system interface MC, assuming this is"
		 " a valid working ATCA chassis",
		 DOMAIN_NAME(domain));
    } else {
	info->mfg_id = ipmi_mc_manufacturer_id(mc);
	info->prod_id = ipmi_mc_product_id(mc);
	_ipmi_mc_put(mc);
    }

    info->startup_done = done;
    info->startup_done_cb_data = done_cb_data;
    info->domain = domain;

    ipmi_domain_set_oem_data(domain, info, atca_oem_data_destroyer);
    ipmi_domain_set_oem_shutdown_handler(domain,
					 atca_oem_domain_shutdown_handler);

    ipmi_domain_set_con_up_handler(domain, atca_con_up, info);

    ipmi_domain_add_new_sensor_handler(domain, atca_new_sensor_handler, NULL);

    /* Send the ATCA Get Address Info command to get the blade info. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_GET_ADDRESS_INFO;
    data[0] = IPMI_PICMG_GRP_EXT;
    msg.data = data;
    msg.data_len = 1;

    rv = ipmi_send_command_addr(domain,
				(ipmi_addr_t *) &si, sizeof(si),
				&msg,
				atca_blade_info, NULL, NULL);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(set_up_atca_blade): "
		 "Could not send get addrss command",
		 DOMAIN_NAME(domain));
	done(domain, ENOMEM, done_cb_data);
	goto out;
    }

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
	break;

    case 23:
	if ((inst == 1) || (inst == 2)) {
	    *id = 0xf2;
	    inst += 0x60 - 1;
	} else if (inst == 3) {
	    *id = 0xf1;
	    inst = 0x60;
	}
	break;

     case 0xa0:
     case 0xf0:
 	/* These instances should all be set to 0x60 */
 	inst = 0x60;
 	break;
    }
    if (inst < 0x60)
	inst += 0x60;

    *instance = (*instance & 0x80) | (inst & 0x7f);
}

typedef struct inst_list_s
{
    unsigned int entity_id;
    unsigned int entity_instance;
} inst_list_t;

static void
add_inst(inst_list_t *inst, unsigned int *curr,
	 unsigned int entity_id, unsigned int entity_instance,
	 unsigned int *container_id)
{
    unsigned int i;

    /* Ignore system-relative ones. */
    if (entity_instance < 0x60)
	return;

    /* Ignore the containers. */
    switch (entity_id) {
    case 10:
    case 30:
    case 0xa0:
    case 0xf0:
#if 0
    /* These are on the CMM */
    case 0xf1:
    case 0xf2:
#endif
	*container_id = entity_id;
	return;
    }

    for (i=0; i<*curr; i++) {
	if ((inst[i].entity_id == entity_id)
	    && (inst[i].entity_instance == entity_instance))
	{
	    return;
	}
    }

    inst[i].entity_id = entity_id;
    inst[i].entity_instance = entity_instance;
    *curr = i+1;
}

/*
 * This function gets the sensor id ane looks for "CPU".  IF it finds it
 * and a number, it assigns the entity to be CPU and the proper instance.
 */
static void
sensor_fixup(ipmi_mc_t *mc, ipmi_sdr_t *sdr)
{
    char name[33];
    unsigned int name_len = 0;
    enum ipmi_str_type_e type;
    char *cpustart;
    unsigned char *str;
    int rv;

    if (sdr->data[3] != 0xa0)
	/* Only do this fixup for boards. */
	return;

    switch (sdr->type) {
    case IPMI_SDR_FULL_SENSOR_RECORD:
	    str = sdr->data+42,
	    rv = ipmi_get_device_string(&str, sdr->length-42,
					name, IPMI_STR_SDR_SEMANTICS, 0,
					&type, 32, &name_len);
	    if (rv)
		name_len = 0;
	    break;

    case IPMI_SDR_COMPACT_SENSOR_RECORD:
	    str = sdr->data+26,
	    rv = ipmi_get_device_string(&str, sdr->length-26,
					name, IPMI_STR_SDR_SEMANTICS, 0,
					&type, 32, &name_len);
	    if (rv)
		name_len = 0;
	    break;
    }
    name[name_len] = '\0';
    cpustart = strstr(name, "CPU");
    if (!cpustart)
	return;
    cpustart += 3;
    while (isspace(*cpustart))
	cpustart++;
    if (*cpustart == '1') {
	sdr->data[3] = 3;
	sdr->data[4] = 0x61;
    } else if (*cpustart == '2') {
	sdr->data[3] = 3;
	sdr->data[4] = 0x62;
    }
}

static void
misc_sdrs_fixup(ipmi_mc_t       *mc,
		ipmi_sdr_info_t *sdrs,
		void            *cb_data)
{
    unsigned int count;
    unsigned int i, j;
    ipmi_sdr_t   sdr;
    int          rv;
    inst_list_t  *inst = NULL;
    unsigned int next_inst = 0;
    unsigned int entity_id;
    unsigned int entity_instance;
    uint16_t     last_rec = 0;
    unsigned int addr, chan;
    unsigned int container_id = 0xa0;

    rv = ipmi_get_sdr_count(sdrs, &count);
    if (rv)
	return;

    if (count > 0) {
	inst = ipmi_mem_alloc(sizeof(*inst) * count);
	if (!inst)
	    return;
    }

    for (i=0; i<count; i++) {
	rv = ipmi_get_sdr_by_index(sdrs, i, &sdr);
	if (rv)
	    break;

	if (sdr.record_id > last_rec)
	    last_rec = sdr.record_id;

	/* Fix up the entity instances for the SDRs. */
	switch (sdr.type) {
	case IPMI_SDR_FULL_SENSOR_RECORD:
	case IPMI_SDR_COMPACT_SENSOR_RECORD:
	    /* Make it device relative. */
	    atca_entity_fixup(mc, &sdr.data[3], &sdr.data[4]);
	    sensor_fixup(mc, &sdr);
	    ipmi_set_sdr_by_index(sdrs, i, &sdr);
	    entity_id = sdr.data[3];
	    entity_instance = sdr.data[4];
	    break;
	case IPMI_SDR_MC_DEVICE_LOCATOR_RECORD:
	case IPMI_SDR_FRU_DEVICE_LOCATOR_RECORD:
	    atca_entity_fixup(mc, &sdr.data[7], &sdr.data[8]);
	    ipmi_set_sdr_by_index(sdrs, i, &sdr);
	    entity_id = sdr.data[7];
	    entity_instance = sdr.data[8];
	    break;

	default:
	    continue;
	}

	add_inst(inst, &next_inst, entity_id, entity_instance, &container_id);
    }

    /* Add entity association records for all the entities. */
    addr = ipmi_mc_get_address(mc);
    chan = ipmi_mc_get_channel(mc);

    memset(&sdr, 0, sizeof(sdr));
    sdr.major_version = 1;
    sdr.minor_version = 5;
    sdr.type = 9;
    sdr.length = 27;
    sdr.data[0] = container_id;
    sdr.data[1] = 0x60;
    sdr.data[2] = addr;
    sdr.data[3] = chan;
    sdr.data[4] = 0;
    sdr.data[5] = addr;
    sdr.data[6] = chan;
    sdr.data[9] = addr;
    sdr.data[10] = chan;
    sdr.data[13] = addr;
    sdr.data[14] = chan;
    sdr.data[17] = addr;
    sdr.data[18] = chan;
    for (i=0; i<next_inst; ) {
	last_rec++;
	sdr.record_id = last_rec;
	for (j=0; (j<4)&&(i<next_inst); j++, i++) {
	    sdr.data[7+(j*4)] = inst[i].entity_id;
	    sdr.data[8+(j*4)] = inst[i].entity_instance;
	}
	for (; j<4; j++) {
	    sdr.data[5+(j*4)] = 0;
	    sdr.data[6+(j*4)] = 0;
	    sdr.data[7+(j*4)] = 0;
	    sdr.data[8+(j*4)] = 0;
	}
	ipmi_sdr_add(sdrs, &sdr);
    }

    ipmi_mem_free(inst);
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
    ipmi_register_oem_handler(0x000157, 0x0850,
			      misc_sdrs_fixup_reg, NULL, NULL);
    ipmi_register_oem_handler(0x000157, 0x0870,
			      misc_sdrs_fixup_reg, NULL, NULL);
    ipmi_register_oem_handler(0x0009e9, 0x0000,
			      misc_sdrs_fixup_reg, NULL, NULL);
}

/***********************************************************************
 *
 * ATCA initialization and detection
 *
 **********************************************************************/

static void
check_if_local(ipmi_domain_t *domain, int conn, void *cb_data)
{
    ipmi_con_t *con;

    if (_ipmi_domain_get_connection(domain, conn, &con))
	return;
    if (con->con_type && (strcmp(con->con_type, "smi") == 0))
	/* It's a system management interface. */
	_ipmi_option_set_local_only_if_not_specified(domain, 1);
}

static int
check_if_atca_cb(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_msg_t                 *msg = &rspi->msg;
    ipmi_domain_oem_check_done done = rspi->data1;

    if (!domain)
	return IPMI_MSG_ITEM_NOT_USED;

    if (msg->data[0] == 0) {
	/* It's an ATCA system, set it up */
	ipmi_domain_iterate_connections(domain, check_if_local, NULL);
	if (ipmi_option_local_only(domain)) {
	    /* Only hook to the local blade. */
	    ipmi_domain_set_type(domain, IPMI_DOMAIN_TYPE_ATCA_BLADE);
	    set_up_atca_blade(domain, msg, done, rspi->data2);
	} else {
	    /* Do the entire system. */
	    ipmi_domain_set_type(domain, IPMI_DOMAIN_TYPE_ATCA);
	    set_up_atca_domain(domain, msg, done, rspi->data2);
	}
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
    unsigned char 		 data[1];

    /* Send the ATCA Get Properties to know if we are ATCA. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_GET_PROPERTIES;
    data[0] = IPMI_PICMG_GRP_EXT;
    msg.data = data;
    msg.data_len = 1;

    return ipmi_send_command_addr(domain,
				  (ipmi_addr_t *) &si, sizeof(si),
				  &msg,
				  check_if_atca_cb, done, cb_data);
}

int _ipmi_atca_fru_get_mr_root(ipmi_fru_t          *fru,
			       unsigned int        mr_rec_num,
			       unsigned int        manufacturer_id,
			       unsigned char       record_type_id,
			       unsigned char       *mr_data,
			       unsigned int        mr_data_len,
			       void                *cb_data,
			       const char          **name,
			       ipmi_fru_node_t     **node);

static int atca_initialized;

int
ipmi_oem_atca_init(void)
{
    int rv;

    if (atca_initialized)
	return 0;

    rv = ipmi_register_domain_oem_check(check_if_atca, NULL);
    if (rv)
        return rv;

    rv = _ipmi_fru_register_multi_record_oem_handler(PICMG_MFG_ID,
						     0xc0,
						     _ipmi_atca_fru_get_mr_root,
						     NULL);
    if (rv) {
	ipmi_deregister_domain_oem_check(check_if_atca, NULL);
        return rv;
    }

    atca_register_fixups();

    atca_initialized = 1;

    return 0;
}

void
ipmi_oem_atca_shutdown(void)
{
    if (atca_initialized) {
	ipmi_deregister_domain_oem_check(check_if_atca, NULL);
	_ipmi_fru_deregister_multi_record_oem_handler(PICMG_MFG_ID, 0xc0);
	atca_initialized = 0;
    }
}
