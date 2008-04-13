/*
 * sensor.c
 *
 * MontaVista IPMI code for handling sensors
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
#include <math.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_sdr.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_err.h>

#include <OpenIPMI/internal/locked_list.h>
#include <OpenIPMI/internal/opq.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/ipmi_sensor.h>
#include <OpenIPMI/internal/ipmi_entity.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_mc.h>
#include <OpenIPMI/internal/ipmi_event.h>

struct ipmi_sensor_info_s
{
    int                      destroyed;

    /* Indexed by LUN and sensor # */
    ipmi_sensor_t            **(sensors_by_idx[5]);
    /* Size of above sensor array, per LUN.  This will be 0 if the
       LUN has no sensors. */
    unsigned int             idx_size[5];
    /* In the above two, the 5th index is for non-standard sensors. */

    ipmi_lock_t              *idx_lock;

    /* Total number of sensors we have in this. */
    unsigned int             sensor_count;
};

#define SENSOR_ID_LEN 32 /* 16 bytes are allowed for a sensor. */
struct ipmi_sensor_s
{
    unsigned int  usecount;

    ipmi_domain_t *domain; /* Domain I am in. */

    ipmi_mc_t     *mc; /* My owner, NOT the SMI mc (unless that
                          happens to be my direct owner). */

    ipmi_mc_t     *source_mc; /* If the sensor came from the main SDR,
				 this will be NULL.  Otherwise, it
				 will be the MC that owned the device
				 SDR this came from. */
    int           source_idx; /* The index into the source array where
				 this is stored.  This will be -1 if
				 it does not have a source index (ie
				 it's a non-standard sensor) */
    int           source_recid; /* The SDR record ID the sensor came from. */
    ipmi_sensor_t **source_array; /* This is the source array where
                                     the sensor is stored. */

    int           destroyed;

    /* After the sensor is added, it will not be reported immediately.
       Instead, it will wait until the usecount goes to zero before
       being reported.  This marks that the add report is pending */
    int add_pending;

    unsigned char owner;
    unsigned char channel;
    unsigned char lun;
    unsigned char num;

    /* For OEM sensors, the sending LUN might be different that the
       LUN we use for storage. */
    unsigned char send_lun;

    ipmi_entity_t *entity;

    unsigned char entity_id;
    unsigned char entity_instance;

    /* Can the sensor be read?  Event-only sensors and sensors with
       software ID owners cannot be read.  */
    unsigned int  readable : 1;

    unsigned int  entity_instance_logical : 1;
    unsigned int  sensor_init_scanning : 1;
    unsigned int  sensor_init_events : 1;
    unsigned int  sensor_init_thresholds : 1;
    unsigned int  sensor_init_hysteresis : 1;
    unsigned int  sensor_init_type : 1;
    unsigned int  sensor_init_pu_events : 1;
    unsigned int  sensor_init_pu_scanning : 1;
    unsigned int  ignore_if_no_entity : 1;
    unsigned int  supports_auto_rearm : 1;
    unsigned int  hysteresis_support : 2;
    unsigned int  threshold_access : 2;
    unsigned int  event_support : 2;

    unsigned int sensor_direction : 2;

    unsigned int  ignore_for_presence : 1;

    int          hot_swap_requester;
    int          hot_swap_requester_val;

    unsigned char sensor_type;

    unsigned char event_reading_type;

#define IPMI_SENSOR_GET_MASK_BIT(mask, bit) (((mask) >> (bit)) & 1)
#define IPMI_SENSOR_SET_MASK_BIT(mask, bit, v) \
	(mask) = v ? (mask) | (1 << (bit)) : (mask) & ~(1 << (bit))
    uint16_t mask1;
    uint16_t mask2;
    uint16_t mask3;

    unsigned int  analog_data_format : 2;

    unsigned int  rate_unit : 3;

    unsigned int  modifier_unit_use : 2;

    unsigned int  percentage : 1;

    unsigned char base_unit;
    unsigned char modifier_unit;

    unsigned char linearization;

    struct {
	int m : 10;
	unsigned int tolerance : 6;
	int b : 10;
	int r_exp : 4;
	unsigned int accuracy_exp : 2;
	int accuracy : 10;
	int b_exp : 4;
    } conv[256];

    unsigned int  normal_min_specified : 1;
    unsigned int  normal_max_specified : 1;
    unsigned int  nominal_reading_specified : 1;

    unsigned char nominal_reading;
    unsigned char normal_max;
    unsigned char normal_min;
    unsigned char sensor_max;
    unsigned char sensor_min;
    unsigned char default_thresholds[6];
    unsigned char positive_going_threshold_hysteresis;
    unsigned char negative_going_threshold_hysteresis;


    unsigned char oem1;

    /* Note that the ID is *not* nil terminated. */
    enum ipmi_str_type_e id_type;
    unsigned int id_len;
    char id[SENSOR_ID_LEN]; /* The ID from the device SDR. */

    const char *sensor_type_string;
    const char *event_reading_type_string;
    const char *rate_unit_string;
    const char *base_unit_string;
    const char *modifier_unit_string;

    /* A list of handlers to call when an event for the sensor comes
       in. */
    locked_list_t *handler_list, *handler_list_cl;

    opq_t *waitq;
    ipmi_event_state_t event_state;

    /* Polymorphic functions. */
    ipmi_sensor_cbs_t cbs;

    /* OEM info */
    void                            *oem_info;
    ipmi_sensor_cleanup_oem_info_cb oem_info_cleanup_handler;

    ipmi_sensor_destroy_cb destroy_handler;
    void                   *destroy_handler_cb_data;

    /* Name we use for reporting.  We add a ' ' onto the end, thus
       the +1. */
    char name[IPMI_SENSOR_NAME_LEN+1];

    /* Used for temporary linking. */
    ipmi_sensor_t *tlink;

    /* Cruft. */
    ipmi_sensor_threshold_event_handler_nd_cb threshold_event_handler;
    ipmi_sensor_discrete_event_handler_nd_cb  discrete_event_handler;
    void                         *cb_data;
};

static void sensor_final_destroy(ipmi_sensor_t *sensor);

/***********************************************************************
 *
 * Sensor ID handling.
 *
 **********************************************************************/

/* Must be called with the domain entity lock held. */
int
_ipmi_sensor_get(ipmi_sensor_t *sensor)
{
    if (sensor->destroyed)
	return EINVAL;
    sensor->usecount++;
    return 0;
}

void
_ipmi_sensor_put(ipmi_sensor_t *sensor)
{
    ipmi_domain_t *domain = sensor->domain;
    _ipmi_domain_entity_lock(domain);
    if (sensor->usecount == 1) {
	if (sensor->add_pending) {
	    sensor->add_pending = 0;
	    _ipmi_domain_entity_unlock(sensor->domain);
	    _ipmi_entity_call_sensor_handlers(sensor->entity,
					      sensor, IPMI_ADDED);
	    _ipmi_domain_entity_lock(sensor->domain);
	}
	if (sensor->destroyed
	    && (!sensor->waitq
		|| (!opq_stuff_in_progress(sensor->waitq))))
	{
	    _ipmi_domain_entity_unlock(domain);
	    sensor_final_destroy(sensor);
	    return;
	}
    }
    sensor->usecount--;
    _ipmi_domain_entity_unlock(domain);
}

ipmi_sensor_id_t
ipmi_sensor_convert_to_id(ipmi_sensor_t *sensor)
{
    ipmi_sensor_id_t val;

    CHECK_SENSOR_LOCK(sensor);

    val.mcid = ipmi_mc_convert_to_id(sensor->mc);
    val.lun = sensor->lun;
    val.sensor_num = sensor->num;

    return val;
}

int
ipmi_cmp_sensor_id(ipmi_sensor_id_t id1, ipmi_sensor_id_t id2)
{
    int rv;

    rv = ipmi_cmp_mc_id(id1.mcid, id2.mcid);
    if (rv)
	return rv;
    if (id1.lun > id2.lun)
	return 1;
    if (id1.lun < id2.lun)
	return -1;
    if (id1.sensor_num > id2.sensor_num)
	return 1;
    if (id1.sensor_num < id2.sensor_num)
	return -1;
    return 0;
}

void
ipmi_sensor_id_set_invalid(ipmi_sensor_id_t *id)
{
    memset(id, 0, sizeof(*id));
}

int
ipmi_sensor_id_is_invalid(const ipmi_sensor_id_t *id)
{
    return (id->mcid.domain_id.domain == NULL);
}

typedef struct mc_cb_info_s
{
    ipmi_sensor_ptr_cb handler;
    void               *cb_data;
    ipmi_sensor_id_t   id;
    int                err;
} mc_cb_info_t;

static void
mc_cb(ipmi_mc_t *mc, void *cb_data)
{
    mc_cb_info_t       *info = cb_data;
    ipmi_sensor_info_t *sensors;
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    ipmi_sensor_t      *sensor;
    ipmi_entity_t      *entity = NULL;
    
    sensors = _ipmi_mc_get_sensors(mc);
    _ipmi_domain_entity_lock(domain);
    if (info->id.lun > 4) {
	info->err = EINVAL;
	goto out_unlock;
    }

    if (info->id.sensor_num >= sensors->idx_size[info->id.lun]) {
	info->err = EINVAL;
	goto out_unlock;
    }

    sensor = sensors->sensors_by_idx[info->id.lun][info->id.sensor_num];
    if (!sensor) {
	info->err = EINVAL;
	goto out_unlock;
    }

    info->err = _ipmi_entity_get(sensor->entity);
    if (info->err)
	goto out_unlock;
    entity = sensor->entity;

    info->err = _ipmi_sensor_get(sensor);
    if (info->err)
	goto out_unlock;

    _ipmi_domain_entity_unlock(domain);

    info->handler(sensor, info->cb_data);

    _ipmi_sensor_put(sensor);
    _ipmi_entity_put(entity);
    return;

 out_unlock:
    _ipmi_domain_entity_unlock(domain);
    if (entity)
	_ipmi_entity_put(entity);
}

int
ipmi_sensor_pointer_cb(ipmi_sensor_id_t   id,
		       ipmi_sensor_ptr_cb handler,
		       void               *cb_data)
{
    int          rv;
    mc_cb_info_t info;

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
ipmi_sensor_pointer_noseq_cb(ipmi_sensor_id_t   id,
			     ipmi_sensor_ptr_cb handler,
			     void               *cb_data)
{
    int          rv;
    mc_cb_info_t info;

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

typedef struct sensor_find_info_s
{
    ipmi_sensor_id_t id;
    char             *id_name;
    int              rv;
} sensor_find_info_t;

static void
sensor_search_cmp(ipmi_entity_t *entity, ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_find_info_t *info = cb_data;
    char               id[33];
    int                rv;

    rv = ipmi_sensor_get_id(sensor, id, 33);
    if (rv) 
	return;
    if (strcmp(info->id_name, id) == 0) {
	info->id = ipmi_sensor_convert_to_id(sensor);
	info->rv = 0;
    }
}

static void
sensor_search(ipmi_entity_t *entity, void *cb_data)
{
    sensor_find_info_t *info = cb_data;

    ipmi_entity_iterate_sensors(entity, sensor_search_cmp, info);
}

int
ipmi_sensor_find_id(ipmi_domain_id_t domain_id,
		    int entity_id, int entity_instance,
		    int channel, int slave_address,
		    char *id_name,
		    ipmi_sensor_id_t *id)
{
    int                rv;
    ipmi_entity_id_t   entity;
    sensor_find_info_t info;

    rv = ipmi_entity_find_id(domain_id, entity_id, entity_instance,
			     channel, slave_address, &entity);
    if (rv)
	return rv;

    info.id_name = id_name;
    info.rv = EINVAL;

    rv = ipmi_entity_pointer_cb(entity, sensor_search, &info);
    if (!rv)
	rv = info.rv;
    if (!rv)
	*id = info.id;

    return rv;
}

/***********************************************************************
 *
 * Various sensor allocation/deallocation/opq/etc.
 *
 **********************************************************************/

static int
sensor_ok_to_use(ipmi_sensor_t *sensor)
{
    return (   !sensor->destroyed
	    && !_ipmi_domain_in_shutdown(sensor->domain));
}

static void sensor_set_name(ipmi_sensor_t *sensor);

static void
sensor_opq_ready2(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_sensor_op_info_t *info = cb_data;
    if (info->__handler)
	info->__handler(sensor, 0, info->__cb_data);
}

static int
sensor_opq_ready(void *cb_data, int shutdown)
{
    ipmi_sensor_op_info_t *info = cb_data;
    int                   rv;

    if (shutdown) {
	if (info->__handler)
	    info->__handler(info->__sensor, ECANCELED, info->__cb_data);
	return OPQ_HANDLER_STARTED;
    }

    rv = ipmi_sensor_pointer_cb(info->__sensor_id, sensor_opq_ready2, info);
    if (rv)
	if (info->__handler)
	    info->__handler(info->__sensor, rv, info->__cb_data);
    return OPQ_HANDLER_STARTED;
}

int
ipmi_sensor_add_opq(ipmi_sensor_t         *sensor,
		    ipmi_sensor_op_cb     handler,
		    ipmi_sensor_op_info_t *info,
		    void                  *cb_data)
{
    if (sensor->destroyed)
	return EINVAL;

    info->__sensor = sensor;
    info->__sensor_id = ipmi_sensor_convert_to_id(sensor);
    info->__cb_data = cb_data;
    info->__handler = handler;
    if (!opq_new_op(sensor->waitq, sensor_opq_ready, info, 0))
	return ENOMEM;
    return 0;
}

static void
sensor_id_add_opq_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_sensor_op_info_t *info = cb_data;

    info->__sensor = sensor;
    if (!opq_new_op(sensor->waitq, sensor_opq_ready, info, 0))
	info->__err = ENOMEM;
}

int
ipmi_sensor_id_add_opq(ipmi_sensor_id_t      sensor_id,
		       ipmi_sensor_op_cb     handler,
		       ipmi_sensor_op_info_t *info,
		       void                  *cb_data)
{
    int rv;

    info->__sensor_id = sensor_id;
    info->__cb_data = cb_data;
    info->__handler = handler;
    info->__err = 0;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_add_opq_cb, info);
    if (!rv)
	rv = info->__err;
    return rv;
}

void
ipmi_sensor_opq_done(ipmi_sensor_t *sensor)
{
    /* Protect myself from NULL sensors.  This way, it doesn't have to
       be done in each call. */
    if (!sensor)
	return;

    /* This gets called on ECANCELLED error cases, if the sensor is
       already destroyed we need to clear out the opq. */
    if (sensor->destroyed) {
	if (sensor->waitq) {
	    opq_destroy(sensor->waitq);
	    sensor->waitq = NULL;
	}
	return;
    }

    /* No check for the sensor lock.  It will sometimes fail at
       destruction time. */

    opq_op_done(sensor->waitq);
}

static void
sensor_rsp_handler2(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_sensor_op_info_t *info = cb_data;

    if (info->__rsp_handler)
	info->__rsp_handler(sensor, 0, info->__rsp, info->__cb_data);
}

static void
sensor_rsp_handler(ipmi_mc_t  *mc,
		   ipmi_msg_t *rsp,
		   void       *rsp_data)
{
    ipmi_sensor_op_info_t *info = rsp_data;
    int                   rv;
    ipmi_sensor_t         *sensor = info->__sensor;
    ipmi_entity_t         *entity = NULL;

    if (sensor->destroyed) {
	_ipmi_domain_entity_lock(sensor->domain);
	sensor->usecount++;
	rv = _ipmi_entity_get(sensor->entity);
	if (! rv)
	    entity = sensor->entity;
	_ipmi_domain_entity_unlock(sensor->domain);

	if (info->__rsp_handler)
	    info->__rsp_handler(sensor, ECANCELED, NULL, info->__cb_data);

	_ipmi_sensor_put(sensor);
	if (entity)
	    _ipmi_entity_put(entity);
	return;
    }

    if (!mc) {
	_ipmi_domain_entity_lock(sensor->domain);
	sensor->usecount++;
	rv = _ipmi_entity_get(sensor->entity);
	if (! rv)
	    entity = sensor->entity;
	_ipmi_domain_entity_unlock(sensor->domain);

	if (info->__rsp_handler)
	    info->__rsp_handler(sensor, ECANCELED, rsp, info->__cb_data);

	_ipmi_sensor_put(sensor);
	if (entity)
	    _ipmi_entity_put(entity);
	return;
    }

    /* Call the next stage with the lock held. */
    info->__rsp = rsp;
    rv = ipmi_sensor_pointer_cb(info->__sensor_id,
				sensor_rsp_handler2,
				info);
    if (rv) {
	int nrv;

	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(sensor_rsp_handler):"
		 " Could not convert sensor id to a pointer",
		 MC_NAME(mc));

	_ipmi_domain_entity_lock(sensor->domain);
	sensor->usecount++;
	nrv = _ipmi_entity_get(sensor->entity);
	if (! nrv)
	    entity = sensor->entity;
	_ipmi_domain_entity_unlock(sensor->domain);

	if (info->__rsp_handler)
	    info->__rsp_handler(sensor, rv, NULL, info->__cb_data);

	_ipmi_sensor_put(sensor);
	if (entity)
	    _ipmi_entity_put(entity);
    }
}
			 
int
ipmi_sensor_send_command(ipmi_sensor_t         *sensor,
			 ipmi_mc_t             *mc,
			 unsigned int          lun,
			 ipmi_msg_t            *msg,
			 ipmi_sensor_rsp_cb    handler,
			 ipmi_sensor_op_info_t *info,
			 void                  *cb_data)
{
    int rv;

    CHECK_MC_LOCK(mc);
    CHECK_SENSOR_LOCK(sensor);

    if (sensor->destroyed)
	return EINVAL;

    info->__sensor = sensor;
    info->__sensor_id = ipmi_sensor_convert_to_id(sensor);
    info->__cb_data = cb_data;
    info->__rsp_handler = handler;
    rv = ipmi_mc_send_command(mc, lun, msg, sensor_rsp_handler, info);
    return rv;
}

static int
sensor_addr_response_handler(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_msg_t            *msg = &rspi->msg;
    ipmi_sensor_op_info_t *info = rspi->data1;
    int                   rv;
    ipmi_sensor_t         *sensor = info->__sensor;

    if (sensor->destroyed) {
	if (info->__rsp_handler) {
	    _ipmi_domain_mc_lock(sensor->domain);
	    _ipmi_mc_get(sensor->mc);
	    _ipmi_domain_mc_unlock(sensor->domain);
	    _ipmi_domain_entity_lock(sensor->domain);
	    _ipmi_entity_get(sensor->entity);
	    sensor->usecount++;
	    _ipmi_domain_entity_unlock(sensor->domain);
	    info->__rsp_handler(NULL, ECANCELED, NULL, info->__cb_data);
	    _ipmi_sensor_put(sensor);
	    _ipmi_mc_put(sensor->mc);
	    _ipmi_entity_put(sensor->entity);
	}
	return IPMI_MSG_ITEM_NOT_USED;
    }

    /* Call the next stage with the lock held. */
    info->__rsp = msg;
    rv = ipmi_sensor_pointer_cb(info->__sensor_id,
				sensor_rsp_handler2,
				info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(sensor_addr_rsp_handler):"
		 " Could not convert sensor id to a pointer",
		 DOMAIN_NAME(domain));
	if (info->__rsp_handler) {
	    _ipmi_domain_mc_lock(sensor->domain);
	    _ipmi_mc_get(sensor->mc);
	    _ipmi_domain_mc_unlock(sensor->domain);
	    _ipmi_domain_entity_lock(sensor->domain);
	    _ipmi_entity_get(sensor->entity);
	    sensor->usecount++;
	    _ipmi_domain_entity_unlock(sensor->domain);
	    info->__rsp_handler(sensor, rv, NULL, info->__cb_data);
	    _ipmi_sensor_put(sensor);
	    _ipmi_mc_put(sensor->mc);
	    _ipmi_entity_put(sensor->entity);
	}
    }
    return IPMI_MSG_ITEM_NOT_USED;
}

int
ipmi_sensor_send_command_addr(ipmi_domain_t         *domain,
			      ipmi_sensor_t         *sensor,
			      ipmi_addr_t           *addr,
			      unsigned int          addr_len,
			      ipmi_msg_t            *msg,
			      ipmi_sensor_rsp_cb    handler,
			      ipmi_sensor_op_info_t *info,
			      void                  *cb_data)
{
    int rv;

    CHECK_SENSOR_LOCK(sensor);
    CHECK_MC_LOCK(sensor->mc);

    info->__sensor = sensor;
    info->__sensor_id = ipmi_sensor_convert_to_id(sensor);
    info->__cb_data = cb_data;
    info->__rsp_handler = handler;
    rv = ipmi_send_command_addr(domain, addr, addr_len,
				msg, sensor_addr_response_handler, info, NULL);
    return rv;
}

int
ipmi_sensors_alloc(ipmi_mc_t *mc, ipmi_sensor_info_t **new_sensors)
{
    ipmi_sensor_info_t *sensors;
    ipmi_domain_t      *domain;
    os_handler_t       *os_hnd;
    int                i;
    int                rv;

    CHECK_MC_LOCK(mc);

    domain = ipmi_mc_get_domain(mc);
    os_hnd = ipmi_domain_get_os_hnd(domain);

    sensors = ipmi_mem_alloc(sizeof(*sensors));
    if (!sensors)
	return ENOMEM;

    rv = ipmi_create_lock_os_hnd(os_hnd, &sensors->idx_lock);
    if (rv) {
	ipmi_mem_free(sensors);
	return rv;
    }

    sensors->destroyed = 0;
    sensors->sensor_count = 0;
    for (i=0; i<5; i++) {
	sensors->sensors_by_idx[i] = NULL;
	sensors->idx_size[i] = 0;
    }

    *new_sensors = sensors;
    return 0;
}

unsigned int
ipmi_sensors_get_count(ipmi_sensor_info_t *sensors)
{
    return sensors->sensor_count;
}

int
ipmi_sensor_alloc_nonstandard(ipmi_sensor_t **new_sensor)
{
    ipmi_sensor_t *sensor;

    sensor = ipmi_mem_alloc(sizeof(*sensor));
    if (!sensor)
	return ENOMEM;

    memset(sensor, 0, sizeof(*sensor));

    sensor->hot_swap_requester = -1;
    sensor->usecount = 1;
    sensor->readable = 1;

    *new_sensor = sensor;
    return 0;
}

int
ipmi_sensor_add_nonstandard(ipmi_mc_t              *mc,
			    ipmi_mc_t              *source_mc,
			    ipmi_sensor_t          *sensor,
			    unsigned int           num,
			    unsigned int           send_lun,
			    ipmi_entity_t          *ent,
			    ipmi_sensor_destroy_cb destroy_handler,
			    void                   *destroy_handler_cb_data)
{
    ipmi_sensor_info_t *sensors = _ipmi_mc_get_sensors(mc);
    ipmi_domain_t      *domain;
    os_handler_t       *os_hnd;
    void               *link;
    int                err;
    unsigned int       i;

    CHECK_MC_LOCK(mc);
    CHECK_ENTITY_LOCK(ent);

    domain = ipmi_mc_get_domain(mc);
    os_hnd = ipmi_domain_get_os_hnd(domain);

    if ((num >= 256) && (num != UINT_MAX))
	return EINVAL;

    _ipmi_domain_entity_lock(domain);
    ipmi_lock(sensors->idx_lock);

    if (num == UINT_MAX){
	for (i=0; i<sensors->idx_size[4]; i++) {
	    if (! sensors->sensors_by_idx[4][i])
		break;
	}
	num = i;
	if (num >= 256) {
	    err = EAGAIN;
	    goto out_err;
	}
    }

    if (num >= sensors->idx_size[4]) {
	ipmi_sensor_t **new_array;
	unsigned int  new_size;
	unsigned int  i;

	/* Allocate the array in multiples of 16 (to avoid thrashing malloc
	   too much). */
	new_size = ((num / 16) * 16) + 16;
	new_array = ipmi_mem_alloc(sizeof(*new_array) * new_size);
	if (!new_array) {
	    err = ENOMEM;
	    goto out_err;
	}
	if (sensors->sensors_by_idx[4]) {
	    memcpy(new_array, sensors->sensors_by_idx[4],
		   sizeof(*new_array) * (sensors->idx_size[4]));
	    ipmi_mem_free(sensors->sensors_by_idx[4]);
	}
	for (i=sensors->idx_size[4]; i<new_size; i++)
	    new_array[i] = NULL;
	sensors->sensors_by_idx[4] = new_array;
	sensors->idx_size[4] = new_size;
    }

    sensor->waitq = opq_alloc(os_hnd);
    if (! sensor->waitq) {
	err = ENOMEM;
	goto out_err;
    }

    sensor->handler_list = locked_list_alloc(os_hnd);
    if (! sensor->handler_list) {
	opq_destroy(sensor->waitq);
	err = ENOMEM;
	goto out_err;
    }

    sensor->handler_list_cl = locked_list_alloc(os_hnd);
    if (! sensor->handler_list_cl) {
	locked_list_destroy(sensor->handler_list);
	opq_destroy(sensor->waitq);
	err = ENOMEM;
	goto out_err;
    }

    link = locked_list_alloc_entry();
    if (!link) {
	opq_destroy(sensor->waitq);
	sensor->waitq = NULL;
	locked_list_destroy(sensor->handler_list);
	locked_list_destroy(sensor->handler_list_cl);
	sensor->handler_list = NULL;
	err = ENOMEM;
	goto out_err;
    }

    sensor->domain = domain;
    sensor->mc = mc;
    sensor->source_mc = source_mc;
    sensor->lun = 4;
    sensor->send_lun = send_lun;
    sensor->num = num;
    sensor->source_idx = -1;
    sensor->source_array = NULL;
    if (!sensors->sensors_by_idx[4][num])
	sensors->sensor_count++;
    sensors->sensors_by_idx[4][num] = sensor;
    sensor->entity = ent;
    sensor->entity_id = ipmi_entity_get_entity_id(ent);
    sensor->entity_instance = ipmi_entity_get_entity_instance(ent);
    sensor->destroy_handler = destroy_handler;
    sensor->destroy_handler_cb_data = destroy_handler_cb_data;
    sensor_set_name(sensor);

    ipmi_unlock(sensors->idx_lock);

    _ipmi_domain_entity_unlock(domain);

    ipmi_entity_add_sensor(ent, sensor, link);

    sensor->add_pending = 1;

    return 0;

 out_err:
    ipmi_unlock(sensors->idx_lock);
    _ipmi_domain_entity_unlock(domain);
    return err;
}

typedef struct threshold_handler_cl_info_s
{
    ipmi_sensor_threshold_event_cb handler;
    void                           *handler_data;
} threshold_handler_cl_info_t;

static int
iterate_threshold_handler_cl(void *cb_data, void *item1, void *item2)
{
    threshold_handler_cl_info_t       *info = cb_data;
    ipmi_sensor_threshold_event_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

typedef struct discrete_handler_cl_info_s
{
    ipmi_sensor_discrete_event_cb handler;
    void                          *handler_data;
} discrete_handler_cl_info_t;

static int
iterate_discrete_handler_cl(void *cb_data, void *item1, void *item2)
{
    discrete_handler_cl_info_t       *info = cb_data;
    ipmi_sensor_discrete_event_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
handler_list_cleanup(void *cb_data, void *item1, void *item2)
{
    ipmi_sensor_t *sensor = cb_data;

    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD) {
	threshold_handler_cl_info_t info;
	info.handler = item1;
	info.handler_data = item2;
	locked_list_iterate(sensor->handler_list_cl,
			    iterate_threshold_handler_cl,
			    &info);
    } else {
	discrete_handler_cl_info_t info;
	info.handler = item1;
	info.handler_data = item2;
	locked_list_iterate(sensor->handler_list_cl,
			    iterate_discrete_handler_cl,
			    &info);
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
sensor_final_destroy(ipmi_sensor_t *sensor)
{
    _ipmi_entity_get(sensor->entity);
    _ipmi_entity_call_sensor_handlers(sensor->entity, sensor, IPMI_DELETED);

    sensor->mc = NULL;

    if (sensor->destroy_handler)
	sensor->destroy_handler(sensor, sensor->destroy_handler_cb_data);

    if (sensor->waitq)
	opq_destroy(sensor->waitq);

    if (sensor->handler_list) {
	locked_list_iterate(sensor->handler_list, handler_list_cleanup,
			    sensor);
	locked_list_destroy(sensor->handler_list);
    }

    if (sensor->handler_list_cl)
	locked_list_destroy(sensor->handler_list_cl);

    if (sensor->entity)
	ipmi_entity_remove_sensor(sensor->entity, sensor);

    if (sensor->oem_info_cleanup_handler)
	sensor->oem_info_cleanup_handler(sensor, sensor->oem_info);

    _ipmi_entity_put(sensor->entity);
    ipmi_mem_free(sensor);
}

int
ipmi_sensor_destroy(ipmi_sensor_t *sensor)
{
    ipmi_sensor_info_t *sensors;
    ipmi_mc_t          *mc = sensor->mc;

    _ipmi_domain_mc_lock(sensor->domain);
    _ipmi_mc_get(mc);
    _ipmi_domain_mc_unlock(sensor->domain);
    sensors = _ipmi_mc_get_sensors(sensor->mc);

    ipmi_lock(sensors->idx_lock);
    if (sensor == sensors->sensors_by_idx[sensor->lun][sensor->num]) {
	sensors->sensor_count--;
	sensors->sensors_by_idx[sensor->lun][sensor->num] = NULL;
    }

    _ipmi_sensor_get(sensor);

    if (sensor->source_array)
	sensor->source_array[sensor->source_idx] = NULL;

    ipmi_unlock(sensors->idx_lock);

    sensor->destroyed = 1;
    _ipmi_sensor_put(sensor);
    _ipmi_mc_put(mc);
    return 0;
}

int
ipmi_sensors_destroy(ipmi_sensor_info_t *sensors)
{
    unsigned int i, j;

    if (sensors->destroyed)
	return EINVAL;

    sensors->destroyed = 1;
    for (i=0; i<=4; i++) {
	for (j=0; j<sensors->idx_size[i]; j++) {
	    if (sensors->sensors_by_idx[i][j]) {
		ipmi_sensor_destroy(sensors->sensors_by_idx[i][j]);
	    }
	}
	if (sensors->sensors_by_idx[i])
	    ipmi_mem_free(sensors->sensors_by_idx[i]);
    }
    if (sensors->idx_lock)
	ipmi_destroy_lock(sensors->idx_lock);
    ipmi_mem_free(sensors);
    return 0;
}

static void
sensor_set_name(ipmi_sensor_t *sensor)
{
    int length;

    length = ipmi_entity_get_name(sensor->entity, sensor->name,
				  sizeof(sensor->name)-2);
    sensor->name[length] = '.';
    length++;
    length += snprintf(sensor->name+length, IPMI_SENSOR_NAME_LEN-length-2,
		       "%s", sensor->id);
    sensor->name[length] = ' ';
    length++;
    sensor->name[length] = '\0';
    length++;
}

const char *
_ipmi_sensor_name(const ipmi_sensor_t *sensor)
{
    return sensor->name;
}

int
ipmi_sensor_get_name(ipmi_sensor_t *sensor, char *name, int length)
{
    int  slen;

    if (length <= 0)
	return 0;

    /* Never changes, no lock needed. */
    slen = strlen(sensor->name);
    if (slen == 0) {
	if (name)
	    *name = '\0';
	goto out;
    }

    slen -= 1; /* Remove the trailing ' ' */
    if (slen >= length)
	slen = length - 1;

    if (name) {
	memcpy(name, sensor->name, slen);
	name[slen] = '\0';
    }
 out:
    return slen;
}

/***********************************************************************
 *
 * Sensor SDR handling
 *
 **********************************************************************/

static int
get_sensors_from_sdrs(ipmi_domain_t      *domain,
		      ipmi_mc_t          *source_mc,
		      ipmi_sdr_info_t    *sdrs,
		      ipmi_sensor_t      ***sensors,
		      unsigned int       *sensor_count)
{
    ipmi_sdr_t    sdr;
    unsigned int  count;
    ipmi_sensor_t **s = NULL;
    unsigned int  p, s_size = 0;
    int           val;
    int           rv;
    unsigned int  i;
    int           j;
    int           share_count;
    int           id_string_mod_type;
    int           entity_instance_incr;
    int           id_string_modifier_offset;
    unsigned char *str;
    unsigned int  str_len;
    

    rv = ipmi_get_sdr_count(sdrs, &count);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%ssensor.c(get_sensors_from_sdrs):"
		 " Could not fetch SDR count fron the SDR record.",
		 MC_NAME(source_mc));
	goto out_err;
    }
    
    /* Get a real count on the number of sensors, since a single SDR can
       contain multiple sensors. */
    p = 0;
    for (i=0; i<count; i++) {
	int incr;
	int lun;

	rv = ipmi_get_sdr_by_index(sdrs, i, &sdr);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "%ssensor.c(get_sensors_from_sdrs):"
		     " SDR record %d could not be fetched from the SDR"
		     " record: %d",
		     MC_NAME(source_mc), i, rv);
	    goto out_err;
	}

	lun = sdr.data[1] & 0x03;
	if (sdr.type == 1) {
	    incr = 1;
	} else if (sdr.type == 2) {
	    if (sdr.data[18] & 0x0f)
		incr = sdr.data[18] & 0x0f;
	    else
		incr = 1;
	} else if (sdr.type == 3) {
	    if (sdr.data[7] & 0x0f)
		incr = sdr.data[7] & 0x0f;
	    else
		incr = 1;
	} else
	    continue;

	p += incr;
    }

    /* Setup memory to hold the sensors. */
    s = ipmi_mem_alloc(sizeof(*s) * p);
    if (!s)
	goto out_err_enomem;
    s_size = p;
    memset(s, 0, sizeof(*s) * p);

    p = 0;
    for (i=0; i<count; i++) {
	rv = ipmi_get_sdr_by_index(sdrs, i, &sdr);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "%ssensor.c(get_sensors_from_sdrs):"
		     " SDR record %d could not be fetched from the SDR"
		     " record index: %d (2)",
		     MC_NAME(source_mc), i, rv);
	    goto out_err;
	}

	if ((sdr.type != 1) && (sdr.type != 2) && (sdr.type != 3))
	    continue;

	s[p] = ipmi_mem_alloc(sizeof(*s[p]));
	if (!s[p])
	    goto out_err_enomem;
	memset(s[p], 0, sizeof(*s[p]));

	s[p]->source_recid = sdr.record_id;
	s[p]->hot_swap_requester = -1;

	s[p]->waitq = opq_alloc(ipmi_domain_get_os_hnd(domain));
	if (!s[p]->waitq)
	    goto out_err_enomem;

	s[p]->handler_list_cl
	    = locked_list_alloc(ipmi_domain_get_os_hnd(domain));
	if (! s[p]->handler_list_cl) {
	    opq_destroy(s[p]->waitq);
	    goto out_err_enomem;
	}

	s[p]->handler_list = locked_list_alloc(ipmi_domain_get_os_hnd(domain));
	if (! s[p]->handler_list) {
	    locked_list_destroy(s[i]->handler_list_cl);
	    opq_destroy(s[p]->waitq);
	    goto out_err_enomem;
	}

	s[p]->destroyed = 0;
	s[p]->destroy_handler = NULL;

	rv = _ipmi_find_or_create_mc_by_slave_addr(domain,
						   sdr.data[1] >> 4,
						   sdr.data[0],
						   &(s[p]->mc));
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "%ssensor.c(get_sensors_from_sdrs):"
		     " Could not create MC for SDR record %d, channel %d"
		     " owner 0x%x: %d",
		     MC_NAME(source_mc), i, sdr.data[1] >> 4, sdr.data[0], rv);
	    goto out_err;
	}

	share_count = 0;
	id_string_mod_type = 0;
	entity_instance_incr = 0;
	id_string_modifier_offset = 0;

	s[p]->usecount = 1;
	s[p]->domain = domain;
	s[p]->source_mc = source_mc;
	s[p]->source_idx = p;
	s[p]->source_array = s;
	s[p]->owner = sdr.data[0];
	s[p]->channel = sdr.data[1] >> 4;
	s[p]->lun = sdr.data[1] & 0x03;
	s[p]->send_lun = s[p]->lun;
	s[p]->num = sdr.data[2];
	s[p]->entity_id = sdr.data[3];
	s[p]->entity_instance_logical = sdr.data[4] >> 7;
	s[p]->entity_instance = sdr.data[4] & 0x7f;
	if ((sdr.type == 1) || (sdr.type == 2)) {
	    /* If the lower bit is set, the owner is a system software
	       id and it cannot be read. */
	    s[p]->readable = (sdr.data[0] & 1) != 1;

	    s[p]->sensor_init_scanning = (sdr.data[5] >> 6) & 1;
	    s[p]->sensor_init_events = (sdr.data[5] >> 5) & 1;
	    s[p]->sensor_init_thresholds = (sdr.data[5] >> 4) & 1;
	    s[p]->sensor_init_hysteresis = (sdr.data[5] >> 3) & 1;
	    s[p]->sensor_init_type = (sdr.data[5] >> 2) & 1;
	    s[p]->sensor_init_pu_events = (sdr.data[5] >> 1) & 1;
	    s[p]->sensor_init_pu_scanning = (sdr.data[5] >> 0) & 1;
	    s[p]->ignore_if_no_entity = (sdr.data[6] >> 7) & 1;
	    s[p]->supports_auto_rearm = (sdr.data[6] >> 6) & 1 ;
	    s[p]->hysteresis_support = (sdr.data[6] >> 4) & 3;
	    s[p]->threshold_access = (sdr.data[6] >> 2) & 3;
	    s[p]->event_support = sdr.data[6] & 3;
	    s[p]->sensor_type = sdr.data[7];
	    s[p]->event_reading_type = sdr.data[8];

	    s[p]->mask1 = ipmi_get_uint16(sdr.data+9);
	    s[p]->mask2 = ipmi_get_uint16(sdr.data+11);
	    s[p]->mask3 = ipmi_get_uint16(sdr.data+13);

	    s[p]->analog_data_format = (sdr.data[15] >> 6) & 3;
	    s[p]->rate_unit = (sdr.data[15] >> 3) & 7;
	    s[p]->modifier_unit_use = (sdr.data[15] >> 1) & 3;
	    s[p]->percentage = sdr.data[15] & 1;
	    s[p]->base_unit = sdr.data[16];
	    s[p]->modifier_unit = sdr.data[17];
	}

	if (sdr.type == 1) {
	    /* A full sensor record. */
	    s[p]->linearization = sdr.data[18] & 0x7f;

	    if (s[p]->linearization <= 11) {
		for (j=0; j<256; j++) {
		    s[p]->conv[j].m = sdr.data[19] | ((sdr.data[20] & 0xc0) << 2);
		    s[p]->conv[j].tolerance = sdr.data[20] & 0x3f;
		    s[p]->conv[j].b = sdr.data[21] | ((sdr.data[22] & 0xc0) << 2);
		    s[p]->conv[j].accuracy = ((sdr.data[22] & 0x3f)
					     | ((sdr.data[23] & 0xf0) << 2));
		    s[p]->conv[j].accuracy_exp = (sdr.data[23] >> 2) & 0x3;
		    s[p]->conv[j].r_exp = (sdr.data[24] >> 4) & 0xf;
		    s[p]->conv[j].b_exp = sdr.data[24] & 0xf;
		}
	    }

	    s[p]->sensor_direction = sdr.data[23] & 0x3;
	    s[p]->normal_min_specified = (sdr.data[25] >> 2) & 1;
	    s[p]->normal_max_specified = (sdr.data[25] >> 1) & 1;
	    s[p]->nominal_reading_specified = sdr.data[25] & 1;
	    s[p]->nominal_reading = sdr.data[26];
	    s[p]->normal_max = sdr.data[27];
	    s[p]->normal_min = sdr.data[28];
	    s[p]->sensor_max = sdr.data[29];
	    s[p]->sensor_min = sdr.data[30];
	    s[p]->default_thresholds[IPMI_UPPER_NON_RECOVERABLE]= sdr.data[31];
	    s[p]->default_thresholds[IPMI_UPPER_CRITICAL] = sdr.data[32];
	    s[p]->default_thresholds[IPMI_UPPER_NON_CRITICAL] = sdr.data[33];
	    s[p]->default_thresholds[IPMI_LOWER_NON_RECOVERABLE] = sdr.data[34];
	    s[p]->default_thresholds[IPMI_LOWER_CRITICAL] = sdr.data[35];
	    s[p]->default_thresholds[IPMI_LOWER_NON_CRITICAL] = sdr.data[36];
	    s[p]->positive_going_threshold_hysteresis = sdr.data[37];
	    s[p]->negative_going_threshold_hysteresis = sdr.data[38];
	    s[p]->oem1 = sdr.data[41];

	    str = sdr.data + 42;
	    str_len = sdr.length - 42;

	    if (s[p]->entity)
		sensor_set_name(s[p]);
	} else if (sdr.type == 2) {
	    /* FIXME - make sure this is not a threshold sensor.  The
               question is, what do I do if it is? */
	    /* A short sensor record. */

	    s[p]->sensor_direction = (sdr.data[18] >> 6) & 0x3;

	    s[p]->positive_going_threshold_hysteresis = sdr.data[20];
	    s[p]->negative_going_threshold_hysteresis = sdr.data[21];
	    s[p]->oem1 = sdr.data[25];

	    str = sdr.data + 26;
	    str_len = sdr.length - 26;

	    share_count = sdr.data[18] & 0x0f;
	    if (share_count == 0)
		share_count = 1;
	    id_string_mod_type = (sdr.data[18] >> 4) & 0x3;
	    entity_instance_incr = (sdr.data[19] >> 7) & 0x01;
	    id_string_modifier_offset = sdr.data[19] & 0x7f;
	} else {
	    /* Event-only sensor.  It is not readable. */

	    s[p]->sensor_type = sdr.data[5];
	    s[p]->event_reading_type = sdr.data[6];
	    s[p]->oem1 = sdr.data[9];

	    str = sdr.data + 10;
	    str_len = sdr.length - 10;

	    share_count = sdr.data[7] & 0x0f;
	    if (share_count == 0)
		share_count = 1;
	    id_string_mod_type = (sdr.data[7] >> 4) & 0x3;
	    entity_instance_incr = (sdr.data[8] >> 7) & 0x01;
	    id_string_modifier_offset = sdr.data[8] & 0x7f;
	}

	rv = ipmi_get_device_string(&str, str_len,
				    s[p]->id, IPMI_STR_SDR_SEMANTICS, 0,
				    &s[p]->id_type, SENSOR_ID_LEN,
				    &s[p]->id_len);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "%ssensor.c(get_sensors_from_sdrs):"
		     " Error getting device ID string from SDR record %d: %d,"
		     " this sensor will be named **INVALID**",
		     MC_NAME(source_mc), sdr.record_id, rv);
	    strncpy(s[p]->id, "**INVALID**", sizeof(s[p]->id));
	    s[p]->id_len = strlen(s[p]->id);
	    s[p]->id_type = IPMI_ASCII_STR;
	}

	if (share_count) {
	    /* Duplicate the sensor records for each instance.  Go
	       backwards to avoid destroying the first one until we
	       finish the others. */
	    for (j=share_count-1; j>=0; j--) {
		int len;

		if (j != 0) {
		    /* The first one is already allocated, we are
                       using it to copy to the other ones, so this is
                       not necessary.  We still have to iterate the
                       first one to set its string name, though. */
		    s[p+j] = ipmi_mem_alloc(sizeof(ipmi_sensor_t));
		    if (!s[p+j])
			goto out_err_enomem;
		    memcpy(s[p+j], s[p], sizeof(ipmi_sensor_t));
		    
		    /* In case of error */
		    s[p+j]->handler_list = NULL;

		    /* For every sensor except the first, increment the usage
		       count for the MC so that it will decrement properly.
		       This cannot fail because we have already gotten it
		       before. */
		    _ipmi_find_or_create_mc_by_slave_addr(domain,
							  s[p+j]->channel,
							  s[p+j]->owner,
							  &(s[p+j]->mc));

		    s[p+j]->waitq = opq_alloc(ipmi_domain_get_os_hnd(domain));
		    if (!s[p+j]->waitq)
			goto out_err_enomem;

		    s[p+j]->handler_list_cl
			= locked_list_alloc(ipmi_domain_get_os_hnd(domain));
		    if (! s[p+j]->handler_list_cl)
			goto out_err_enomem;

		    s[p+j]->handler_list
			= locked_list_alloc(ipmi_domain_get_os_hnd(domain));
		    if (! s[p+j]->handler_list)
			goto out_err_enomem;

		    s[p+j]->num += j;

		    if (entity_instance_incr & 0x80) {
			s[p+j]->entity_instance += j;
		    }

		    s[p+j]->source_idx += j;
		}

		val = id_string_modifier_offset + j;
		len = s[p+j]->id_len;
		switch (id_string_mod_type) {
		    case 0: /* Numeric */
			if ((val / 10) > 0) {
			    if (len < SENSOR_ID_LEN) {
				s[p+j]->id[len] = (val/10) + '0';
				len++;
			    }
			}
			if (len < SENSOR_ID_LEN) {
			    s[p+j]->id[len] = (val%10) + '0';
			    len++;
			}
			break;
		    case 1: /* Alpha */
			if ((val / 26) > 0) {
			    if (len < SENSOR_ID_LEN) {
				s[p+j]->id[len] = (val/26) + 'A';
				len++;
			    }
			}
			if (len < SENSOR_ID_LEN) {
			    s[p+j]->id[len] = (val%26) + 'A';
			    len++;
			}
			break;
		    /* FIXME - unicode handling? */
		}
		s[p+j]->id_len = len;
		if (s[p+j]->entity)
		    sensor_set_name(s[p+j]);
	    }

	    p += share_count;
	} else
	    p++;
    }

    *sensors = s;
    *sensor_count = s_size;
    return 0;

 out_err_enomem:
    rv = ENOMEM;
    ipmi_log(IPMI_LOG_WARNING,
	     "%ssensor.c(get_sensors_from_sdrs):"
	     " Out of memory while processing the SDRS.",
	     MC_NAME(source_mc));
 out_err:
    if (s) {
	for (i=0; i<s_size; i++)
	    if (s[i]) {
		if (s[i]->mc)
		    _ipmi_mc_put(s[i]->mc);
		if (s[i]->waitq)
		    opq_destroy(s[i]->waitq);
		if (s[i]->handler_list)
		    locked_list_destroy(s[i]->handler_list);
		if (s[i]->handler_list_cl)
		    locked_list_destroy(s[i]->handler_list_cl);
		ipmi_mem_free(s[i]);
	    }
	ipmi_mem_free(s);
    }
    return rv;
}

static void
handle_new_sensor(ipmi_domain_t *domain,
		  ipmi_sensor_t *sensor,
		  void          *link)
{
    ipmi_entity_info_t *ents;


    /* Call this before the OEM call so the OEM call can replace it. */
    sensor->cbs = ipmi_standard_sensor_cb;
    sensor->sensor_type_string
	= ipmi_get_sensor_type_string(sensor->sensor_type);
    sensor->event_reading_type_string
	= ipmi_get_event_reading_type_string(sensor->event_reading_type);
    sensor->rate_unit_string
	= ipmi_get_rate_unit_string(sensor->rate_unit);
    sensor->base_unit_string
	= ipmi_get_unit_type_string(sensor->base_unit);
    sensor->modifier_unit_string
	= ipmi_get_unit_type_string(sensor->modifier_unit);

    ents = ipmi_domain_get_entities(domain);

    sensor_set_name(sensor);

    if ((sensor->source_mc)
	&& (_ipmi_mc_new_sensor(sensor->source_mc, sensor->entity,
				sensor, link)))
    {
        /* Nothing to do, OEM code handled the sensor. */
    } else {
	ipmi_entity_add_sensor(sensor->entity, sensor, link);
    }

    _call_new_sensor_handlers(domain, sensor);
}

static int cmp_sensor(ipmi_sensor_t *s1,
		      ipmi_sensor_t *s2)
{
    int i;

    if (s1->entity_instance_logical != s2->entity_instance_logical) return 0;
    if (s1->sensor_init_scanning != s2->sensor_init_scanning) return 0;
    if (s1->sensor_init_events != s2->sensor_init_events) return 0;
    if (s1->sensor_init_thresholds != s2->sensor_init_thresholds) return 0;
    if (s1->sensor_init_hysteresis != s2->sensor_init_hysteresis) return 0;
    if (s1->sensor_init_type != s2->sensor_init_type) return 0;
    if (s1->sensor_init_pu_events != s2->sensor_init_pu_events) return 0;
    if (s1->sensor_init_pu_scanning != s2->sensor_init_pu_scanning) return 0;
    if (s1->ignore_if_no_entity != s2->ignore_if_no_entity) return 0;
    if (s1->supports_auto_rearm != s2->supports_auto_rearm) return 0;
    if (s1->hysteresis_support != s2->hysteresis_support) return 0;
    if (s1->threshold_access != s2->threshold_access) return 0;
    if (s1->event_support != s2->event_support) return 0;
    if (s1->sensor_type != s2->sensor_type) return 0;
    if (s1->event_reading_type != s2->event_reading_type) return 0;

    if (s1->mask1 != s2->mask1) return 0;
    if (s1->mask2 != s2->mask2) return 0;
    if (s1->mask3 != s2->mask3) return 0;
    
    if (s1->analog_data_format != s2->analog_data_format) return 0;
    if (s1->rate_unit != s2->rate_unit) return 0;
    if (s1->modifier_unit_use != s2->modifier_unit_use) return 0;
    if (s1->percentage != s2->percentage) return 0;
    if (s1->base_unit != s2->base_unit) return 0;
    if (s1->modifier_unit != s2->modifier_unit) return 0;
    if (s1->linearization != s2->linearization) return 0;
    if (s1->linearization <= 11) {
	if (s1->conv[0].m != s2->conv[0].m) return 0;
	if (s1->conv[0].tolerance != s2->conv[0].tolerance) return 0;
	if (s1->conv[0].b != s2->conv[0].b) return 0;
	if (s1->conv[0].accuracy != s2->conv[0].accuracy) return 0;
	if (s1->conv[0].accuracy_exp != s2->conv[0].accuracy_exp) return 0;
	if (s1->conv[0].r_exp != s2->conv[0].r_exp) return 0;
	if (s1->conv[0].b_exp != s2->conv[0].b_exp) return 0;
    }
    if (s1->normal_min_specified != s2->normal_min_specified) return 0;
    if (s1->normal_max_specified != s2->normal_max_specified) return 0;
    if (s1->nominal_reading_specified != s2->nominal_reading_specified) return 0;
    if (s1->nominal_reading != s2->nominal_reading) return 0;
    if (s1->normal_max != s2->normal_max) return 0;
    if (s1->normal_min != s2->normal_min) return 0;
    if (s1->sensor_max != s2->sensor_max) return 0;
    if (s1->sensor_min != s2->sensor_min) return 0;
    for (i=0; i<6; i++) {
	if (s1->default_thresholds[i] != s2->default_thresholds[i])
	    return 0;
    }
    if (s1->positive_going_threshold_hysteresis
	!= s2->positive_going_threshold_hysteresis)
	return 0;
    if (s1->negative_going_threshold_hysteresis
	!= s2->negative_going_threshold_hysteresis)
	return 0;
    if (s1->oem1 != s2->oem1) return 0;

    if (s1->id_type != s2->id_type) return 0;
    if (s1->id_len != s2->id_len) return 0;
    if (memcmp(s1->id, s2->id, s1->id_len) != 0) return 0;
    
    return 1;
}

enum entity_list_op { ENT_LIST_OLD, ENT_LIST_NEW, ENT_LIST_DUP };
typedef struct entity_list_s
{
    ipmi_entity_t        *ent;
    ipmi_sensor_t        *sensor;
    ipmi_sensor_t        *osensor;
    ipmi_mc_t            *mc;
    enum entity_list_op  op;
    struct entity_list_s *next;
} entity_list_t;

/* Assume it has enough space for one pointer. */
struct locked_list_entry_s
{
    locked_list_entry_t *next;
};

int
ipmi_sensor_handle_sdrs(ipmi_domain_t   *domain,
			ipmi_mc_t       *source_mc,
			ipmi_sdr_info_t *sdrs)
{
    int                 rv;
    unsigned int        i, j;
    ipmi_sensor_t       **sdr_sensors = NULL;
    ipmi_sensor_t       **old_sdr_sensors;
    unsigned int        old_count;
    unsigned int        count = 0;
    ipmi_entity_info_t  *ents;
    ipmi_entity_t       *ent;
    entity_list_t       *new_sensors = NULL;
    entity_list_t       *del_sensors = NULL;
    entity_list_t       *ent_item;
    entity_list_t       *new_ent_item;
    locked_list_entry_t *link, *links = NULL;
    ipmi_sensor_t       **sens_tmp;
    

    CHECK_DOMAIN_LOCK(domain);
    if (source_mc)
	CHECK_MC_LOCK(source_mc);

    rv = get_sensors_from_sdrs(domain, source_mc, sdrs, &sdr_sensors, &count);
    if (rv)
	goto out_err;

    ents = ipmi_domain_get_entities(domain);

    /* Pre-allocate all the links we will need for registering sensors
       with the entities, and we make sure all the entities exist. */
    for (i=0; i<count; i++) {
	ipmi_sensor_t      *nsensor = sdr_sensors[i];

	ent = NULL;

	if (nsensor != NULL) {
	    ipmi_sensor_info_t *sensors;

	    /* Make sure the entity exists for ALL sensors in the
	       new list.  This way, if a sensor has changed
	       entities, the new entity will exist. */
	    rv = ipmi_entity_add(ents,
				 domain,
				 ipmi_mc_get_channel(nsensor->mc),
				 ipmi_mc_get_address(nsensor->mc),
				 i,
				 nsensor->entity_id,
				 nsensor->entity_instance,
				 "",
				 IPMI_ASCII_STR,
				 0,
				 NULL,
				 NULL,
				 &ent);
	    if (rv)
		goto out_err_free;

	    nsensor->entity = ent;

	    sensors = _ipmi_mc_get_sensors(nsensor->mc);

	    ipmi_lock(sensors->idx_lock);
	    if (nsensor->num >= sensors->idx_size[nsensor->lun]) {
		/* There's not enough room in the sensor repository
		   for the new item, so expand the array. */
		ipmi_sensor_t **new_by_idx;
		unsigned int  new_size = nsensor->num+10;
		new_by_idx = ipmi_mem_alloc(sizeof(ipmi_sensor_t *) * new_size);
		if (!new_by_idx) {
		    ipmi_unlock(sensors->idx_lock);
		    rv = ENOMEM;
		    _ipmi_entity_put(ent);
		    goto out_err_free;
		}
		if (sensors->sensors_by_idx[nsensor->lun]) {
		    memcpy(new_by_idx,
			   sensors->sensors_by_idx[nsensor->lun],
			   (sensors->idx_size[nsensor->lun]
			    * sizeof(ipmi_sensor_t *)));
		    ipmi_mem_free(sensors->sensors_by_idx[nsensor->lun]);
		}
		for (j=sensors->idx_size[nsensor->lun]; j<new_size; j++)
		    new_by_idx[j] = NULL;
		sensors->sensors_by_idx[nsensor->lun] = new_by_idx;
		sensors->idx_size[nsensor->lun] = new_size;
	    }
	    ipmi_unlock(sensors->idx_lock);

	    /* Keep track of each entity/sensor pair. */
	    new_ent_item = ipmi_mem_alloc(sizeof(*new_ent_item));
	    if (!new_ent_item) {
		_ipmi_entity_put(ent);
		goto out_err_free;
	    }
	    new_ent_item->ent = ent;
	    new_ent_item->sensor = nsensor;
	    new_ent_item->osensor = NULL;
	    new_ent_item->mc = nsensor->mc;
	    new_ent_item->op = ENT_LIST_OLD;
	    new_ent_item->next = new_sensors;
	    new_sensors = new_ent_item;

	    /* Pre-allocate link entries for putting the sensor into
	       the entity. */
	    link = locked_list_alloc_entry();
	    if (!link)
		goto out_err_free;
	    link->next = links;
	    links = link;
	}
    }

    /* Check for duplicate sensor numbers in the new sensor set. */
    sens_tmp = ipmi_mem_alloc(256 * sizeof(ipmi_sensor_t **));
    if (!sens_tmp) {
	rv = ENOMEM;
	goto out_err_free;
    }
    memset(sens_tmp, 0, 256 * sizeof(ipmi_sensor_t **));
    ent_item = new_sensors;
    while (ent_item) {
	ipmi_sensor_t *nsensor = ent_item->sensor;
	ipmi_sensor_t *csensor;

	if ((!ent_item->ent) || (!nsensor)) {
	    ent_item = ent_item->next;
	    continue;
	}

	csensor = sens_tmp[nsensor->num];
	while (csensor) {
	    if ((csensor->lun == nsensor->lun)
		&& (csensor->num == nsensor->num)
		&& (csensor->mc == nsensor->mc))
	    {
		break;
	    }
	    csensor = csensor->tlink;
	}
	if (csensor) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "%ssensor.c(ipmi_sensor_handle_sdrs):"
		     " SDR record %d has the same sensor number as record"
		     " %d in the repository.  Ignoring second sensor."
		     " Fix your SDRs!",
		     SENSOR_NAME(nsensor),
		     csensor->source_recid,
		     nsensor->source_recid);
	    ent_item->op = ENT_LIST_DUP;
	    ent_item->osensor = NULL;
	} else {
	    nsensor->tlink = sens_tmp[nsensor->num];
	    sens_tmp[nsensor->num] = nsensor;
	}
	ent_item = ent_item->next;
    }
    ipmi_mem_free(sens_tmp);

    _ipmi_domain_entity_lock(domain);

    _ipmi_get_sdr_sensors(domain, source_mc,
			  &old_sdr_sensors, &old_count);

    ent_item = new_sensors;
    while (ent_item) {
	ipmi_sensor_t      *nsensor = ent_item->sensor;
	ipmi_sensor_info_t *sensors;

	if ((!ent_item->ent) || (!nsensor) || (ent_item->op == ENT_LIST_DUP)) {
	    ent_item = ent_item->next;
	    continue;
	}

	sensors = _ipmi_mc_get_sensors(nsensor->mc);
	ipmi_lock(sensors->idx_lock);
	if (sensors->sensors_by_idx[nsensor->lun]
	    && (nsensor->num < sensors->idx_size[nsensor->lun])
	    && sensors->sensors_by_idx[nsensor->lun][nsensor->num])
	{
	    /* A sensor is already there. */
	    ipmi_sensor_t *osensor
		= sensors->sensors_by_idx[nsensor->lun][nsensor->num];

	    if (cmp_sensor(nsensor, osensor)) {
		/* Since the data is the same, there is no need to get
		   the old sensor entity or mc, since they are already
		   gotten by the new sensor. */
		ent_item->op = ENT_LIST_DUP;
		ent_item->osensor = osensor;
	    } else {
		/* We have to delete the old sensor. */
		new_ent_item = ipmi_mem_alloc(sizeof(*new_ent_item));
		if (!new_ent_item) {
		    ipmi_unlock(sensors->idx_lock);
		    rv = ENOMEM;
		    goto out_err_free_unlock;
		}
		/* It's possible this can fail, but that means that
		   the MC is currently being destroyed.  No big deal,
		   just ignore it. */
		new_ent_item->mc = NULL;
		_ipmi_find_or_create_mc_by_slave_addr(domain,
						      osensor->channel,
						      osensor->owner,
						      &new_ent_item->mc);
		_ipmi_entity_get(osensor->entity);
		_ipmi_sensor_get(osensor);
		new_ent_item->ent = osensor->entity;
		new_ent_item->sensor = osensor;
		new_ent_item->next = del_sensors;
		del_sensors = new_ent_item;
		ent_item->op = ENT_LIST_NEW;
	    }
	} else {
	    ent_item->op = ENT_LIST_NEW;
	}
	ipmi_unlock(sensors->idx_lock);

	ent_item = ent_item->next;
    }

    _ipmi_domain_entity_unlock(domain);

    /* After this point, the operation cannot fail.  Nothing above
       this actually changes anything, it just gets it ready.  Now we
       put into place all the changes. */

    /* First delete the sensors that we are replacing. */
    ent_item = del_sensors;
    while (ent_item) {
	ipmi_sensor_t *osensor = ent_item->sensor;

	if (osensor->source_array) {
	    osensor->source_array[osensor->source_idx] = NULL;
	    osensor->source_array = NULL;
	}
	/* Note that the actual destroy is deferred until we put the
	   sensor. */
	ipmi_sensor_destroy(osensor);

	ent_item = ent_item->next;
    }

    ent_item = new_sensors;
    while (ent_item) {
	ipmi_sensor_t      *nsensor = ent_item->sensor;
	ipmi_sensor_t      *osensor = ent_item->osensor;
	ipmi_sensor_info_t *sensors;

	if ((!ent_item->ent) || (!nsensor)) {
	    ent_item = ent_item->next;
	    continue;
	}

	sensors = _ipmi_mc_get_sensors(nsensor->mc);
	ipmi_lock(sensors->idx_lock);
	switch (ent_item->op) {
	case ENT_LIST_NEW:
	    sensors->sensors_by_idx[nsensor->lun][nsensor->num] = nsensor;
	    sensors->sensor_count++;
	    link = links;
	    links = link->next;
	    handle_new_sensor(domain, nsensor, link);
	    break;

	case ENT_LIST_OLD:
	    break;

	case ENT_LIST_DUP:
	    /* They compare, prefer to keep the old data. */
	    i = nsensor->source_idx;
	    opq_destroy(nsensor->waitq);
	    locked_list_destroy(nsensor->handler_list);
	    locked_list_destroy(nsensor->handler_list_cl);
	    ipmi_mem_free(nsensor);
	    ent_item->sensor = NULL;
	    sdr_sensors[i] = osensor;
	    if (osensor) {
		if (osensor->source_array)
		    osensor->source_array[osensor->source_idx] = NULL;
		osensor->source_idx = i;
		osensor->source_array = sdr_sensors;
	    }
	    break;
	}
	ipmi_unlock(sensors->idx_lock);
	ent_item = ent_item->next;
    }

    _ipmi_set_sdr_sensors(domain, source_mc, sdr_sensors, count);

    if (old_sdr_sensors) {
	for (i=0; i<old_count; i++) {
	    ipmi_sensor_t *osensor = old_sdr_sensors[i];
	    if (osensor != NULL) {
		/* This sensor was not in the new repository, so it must
		   have been deleted. */
		_ipmi_domain_entity_lock(domain);
		_ipmi_sensor_get(osensor);
		_ipmi_domain_entity_unlock(domain);
		ipmi_sensor_destroy(osensor);
	    }
	}
    }

    if (old_sdr_sensors) {
	for (i=0; i<old_count; i++) {
	    ipmi_sensor_t *osensor = old_sdr_sensors[i];
	    if (osensor != NULL) {
		_ipmi_sensor_put(osensor);
	    }
	}
	ipmi_mem_free(old_sdr_sensors);
    }

    /* Free up all the deleted sensors. */
    while (del_sensors) {
	ent_item = del_sensors;
	del_sensors = del_sensors->next;
	if (ent_item->sensor)
	    _ipmi_sensor_put(ent_item->sensor);
	if (ent_item->ent)
	    _ipmi_entity_put(ent_item->ent);
	if (ent_item->mc)
	    _ipmi_mc_put(ent_item->mc);
	ipmi_mem_free(ent_item);
    }

    /* Report then free up all the new sensors. */
    while (new_sensors) {
	ent_item = new_sensors;
	new_sensors = new_sensors->next;

	if (ent_item->ent && ent_item->sensor)
	    ent_item->sensor->add_pending = 1;
	if (ent_item->sensor)
	    _ipmi_sensor_put(ent_item->sensor);
	if (ent_item->ent)
	    _ipmi_entity_put(ent_item->ent);
	if (ent_item->mc)
	    _ipmi_mc_put(ent_item->mc);
	ipmi_mem_free(ent_item);
    }

 out:
    /* Cleanup unused links. */
    while (links) {
	link = links;
	links = link->next;
	locked_list_free_entry(link);
    }

    return rv;

 out_err:
    /* Release all the entities, sensors, etc. */
    while (del_sensors) {
	ent_item = del_sensors;
	del_sensors = del_sensors->next;
	if (ent_item->sensor)
	    _ipmi_sensor_put(ent_item->sensor);
	if (ent_item->ent)
	    _ipmi_entity_put(ent_item->ent);
	if (ent_item->mc)
	    _ipmi_mc_put(ent_item->mc);
	ipmi_mem_free(ent_item);
    }
    while (new_sensors) {
	ent_item = new_sensors;
	new_sensors = new_sensors->next;
	if (ent_item->sensor)
	    _ipmi_sensor_put(ent_item->sensor);
	if (ent_item->ent)
	    _ipmi_entity_put(ent_item->ent);
	if (ent_item->mc)
	    _ipmi_mc_put(ent_item->mc);
	ipmi_mem_free(ent_item);
    }
    goto out;

 out_err_free_unlock:
    _ipmi_domain_entity_unlock(domain);
 out_err_free:
    /* Free up the usecounts on all the MCs we got. */
    for (i=0; i<count; i++) {
	ipmi_sensor_t *nsensor = sdr_sensors[i];

	if ((nsensor) && (nsensor->mc))
	    _ipmi_mc_put(nsensor->mc);
    }
    goto out_err;
}
			
/***********************************************************************
 *
 * Get/set various local information about a sensor.
 *
 **********************************************************************/

int
ipmi_sensor_get_nominal_reading(ipmi_sensor_t *sensor,
				double *nominal_reading)
{
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->nominal_reading_specified)
	return ENOSYS;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->nominal_reading,
					 nominal_reading));
}

int
ipmi_sensor_get_normal_max(ipmi_sensor_t *sensor, double *normal_max)
{
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->normal_max_specified)
	return ENOSYS;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->normal_max,
					 normal_max));
}

int
ipmi_sensor_get_normal_min(ipmi_sensor_t *sensor, double *normal_min)
{
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->normal_min_specified)
	return ENOSYS;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->normal_min,
					 normal_min));
}

int
ipmi_sensor_get_sensor_max(ipmi_sensor_t *sensor, double *sensor_max)
{
    CHECK_SENSOR_LOCK(sensor);

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->sensor_max,
					 sensor_max));
}

int
ipmi_sensor_get_sensor_min(ipmi_sensor_t *sensor, double *sensor_min)
{
    CHECK_SENSOR_LOCK(sensor);

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->sensor_min,
					 sensor_min));
}

int ipmi_sensor_set_raw_default_threshold(ipmi_sensor_t *sensor,
					  int           threshold,
					  int           val)
{
    if ((threshold < 0) || (threshold > 5))
	return EINVAL;

    sensor->default_thresholds[threshold] = val;
    return 0;
}

int ipmi_sensor_get_default_threshold_raw(ipmi_sensor_t *sensor,
					  int           threshold,
					  int           *raw)
{
    int rv;
    int val;

    CHECK_SENSOR_LOCK(sensor);

    if ((threshold < 0) || (threshold > 5))
	return EINVAL;

    rv = ipmi_sensor_threshold_settable(sensor, threshold, &val);
    if (rv)
	return rv;

    if (!val)
	return ENOSYS;

    if (!ipmi_sensor_get_sensor_init_thresholds(sensor))
	return ENOSYS;

    *raw = sensor->default_thresholds[threshold];
    return 0;
}

int ipmi_sensor_get_default_threshold_cooked(ipmi_sensor_t *sensor,
					     int           threshold,
					     double        *cooked)
{
    int rv;
    int val;

    CHECK_SENSOR_LOCK(sensor);

    if ((threshold < 0) || (threshold > 5))
	return EINVAL;

    rv = ipmi_sensor_threshold_settable(sensor, threshold, &val);
    if (rv)
	return rv;

    if (!val)
	return ENOSYS;

    if (!ipmi_sensor_get_sensor_init_thresholds(sensor))
	return ENOSYS;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->default_thresholds[threshold],
					 cooked));
}

ipmi_mc_t *
ipmi_sensor_get_mc(ipmi_sensor_t *sensor)
{
    return sensor->mc;
}

ipmi_mc_t *
ipmi_sensor_get_source_mc(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->source_mc;
}

int
ipmi_sensor_get_num(ipmi_sensor_t *sensor,
		    int           *lun,
		    int           *num)
{
    CHECK_SENSOR_LOCK(sensor);

    if (lun)
	*lun = sensor->lun;
    if (num)
	*num = sensor->num;
    return 0;
}

static void
ipmi_sensor_get_event_masks(ipmi_sensor_t *sensor,
			    uint16_t      *mask1,
			    uint16_t      *mask2)
{
    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD) {
	/* Remove the reading mask, as that is not part of the event
	   values allowed. */
	*mask1 = sensor->mask1 & 0x0fff;
	*mask2 = sensor->mask2 & 0x0fff;
    } else {
	/* Cannot set bit 15 */
	*mask1 = sensor->mask1 & 0x7fff;
	*mask2 = sensor->mask2 & 0x7fff;
    }
}

int
ipmi_sensor_threshold_event_supported(ipmi_sensor_t               *sensor,
				      enum ipmi_thresh_e          event,
				      enum ipmi_event_value_dir_e value_dir,
				      enum ipmi_event_dir_e       dir,
				      int                         *val)
{
    int      idx;
    uint16_t mask;

    CHECK_SENSOR_LOCK(sensor);

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;
    if (sensor->threshold_access == IPMI_THRESHOLD_ACCESS_SUPPORT_NONE) {
	/* No thresholds supported. */
	*val = 0;
	return 0;
    }

    if (dir == IPMI_ASSERTION)
	mask = sensor->mask1;
    else if (dir == IPMI_DEASSERTION)
	mask = sensor->mask2;
    else
	return EINVAL;

    idx = (event * 2) + value_dir;
    if (idx > 11)
	return EINVAL;

    *val = IPMI_SENSOR_GET_MASK_BIT(mask, idx);
    return 0;
}

void
ipmi_sensor_set_threshold_assertion_event_supported(
    ipmi_sensor_t               *sensor,
    enum ipmi_thresh_e          event,
    enum ipmi_event_value_dir_e dir,
    int                         val)
{
    int idx;

    idx = (event * 2) + dir;
    if (idx > 11)
	return;

    IPMI_SENSOR_SET_MASK_BIT(sensor->mask1, idx, val);
}

void
ipmi_sensor_set_threshold_deassertion_event_supported(
    ipmi_sensor_t               *sensor,
    enum ipmi_thresh_e          event,
    enum ipmi_event_value_dir_e dir,
    int                         val)
{
    int idx;

    idx = (event * 2) + dir;
    if (idx > 11)
	return;

    IPMI_SENSOR_SET_MASK_BIT(sensor->mask2, idx, val);
}

int
ipmi_sensor_threshold_reading_supported(ipmi_sensor_t      *sensor,
					enum ipmi_thresh_e thresh,
					int                *val)
{
    CHECK_SENSOR_LOCK(sensor);

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    switch(thresh) {
    case IPMI_LOWER_NON_CRITICAL:
	*val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask1, 12);
	break;
    case IPMI_LOWER_CRITICAL:
	*val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask1, 13);
	break;
    case IPMI_LOWER_NON_RECOVERABLE:
	*val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask1, 14);
	break;
    case IPMI_UPPER_NON_CRITICAL:
	*val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask2, 12);
	break;
    case IPMI_UPPER_CRITICAL:
	*val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask2, 13);
	break;
    case IPMI_UPPER_NON_RECOVERABLE:
	*val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask2, 14);
	break;
    default:
	return EINVAL;
    }
    return 0;
}

int
ipmi_sensor_threshold_settable(ipmi_sensor_t      *sensor,
			       enum ipmi_thresh_e event,
			       int                *val)
{
    CHECK_SENSOR_LOCK(sensor);

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;
    if (sensor->threshold_access != IPMI_THRESHOLD_ACCESS_SUPPORT_SETTABLE) {
	/* Threshold setting not supported for any thresholds. */
	*val = 0;
	return 0;
    }

    if (event > IPMI_UPPER_NON_RECOVERABLE)
	return EINVAL;

    *val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask3, event + 8);
    return 0;
}

void
ipmi_sensor_threshold_set_settable(ipmi_sensor_t      *sensor,
				   enum ipmi_thresh_e event,
				   int                val)
{
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return;

    if (event > IPMI_UPPER_NON_RECOVERABLE)
	return;

    IPMI_SENSOR_SET_MASK_BIT(sensor->mask3, event + 8, val);
}

int
ipmi_sensor_threshold_readable(ipmi_sensor_t      *sensor,
			       enum ipmi_thresh_e event,
			       int                *val)
{
    CHECK_SENSOR_LOCK(sensor);

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;
    if ((sensor->threshold_access == IPMI_THRESHOLD_ACCESS_SUPPORT_NONE)
	|| (sensor->threshold_access == IPMI_THRESHOLD_ACCESS_SUPPORT_FIXED))
    {
	/* Threshold reading not supported for any thresholds. */
	*val = 0;
	return 0;
    }

    if (event > IPMI_UPPER_NON_RECOVERABLE)
	return EINVAL;

    *val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask3, event);
    return 0;
}

void
ipmi_sensor_threshold_set_readable(ipmi_sensor_t      *sensor,
				   enum ipmi_thresh_e event,
				   int                val)
{
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return;

    if (event > IPMI_UPPER_NON_RECOVERABLE)
	return;

    IPMI_SENSOR_SET_MASK_BIT(sensor->mask3, event, val);
}

int
ipmi_sensor_discrete_event_supported(ipmi_sensor_t         *sensor,
				     int                   event,
				     enum ipmi_event_dir_e dir,
				     int                   *val)
{
    uint16_t mask;

    CHECK_SENSOR_LOCK(sensor);

    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have events. */
	return ENOSYS;

    if (dir == IPMI_ASSERTION)
	mask = sensor->mask1;
    else if (dir == IPMI_DEASSERTION)
	mask = sensor->mask2;
    else
	return EINVAL;

    if (event > 14)
	return EINVAL;

    *val = IPMI_SENSOR_GET_MASK_BIT(mask, event);
    return 0;
}

void
ipmi_sensor_set_discrete_assertion_event_supported(ipmi_sensor_t *sensor,
						   int           event,
						   int           val)
{
    if (event > 14)
	return;

    IPMI_SENSOR_SET_MASK_BIT(sensor->mask1, event, val);
}

void
ipmi_sensor_set_discrete_deassertion_event_supported(ipmi_sensor_t *sensor,
						     int           event,
						     int           val)
{
    if (event > 14)
	return;

    IPMI_SENSOR_SET_MASK_BIT(sensor->mask2, event, val);
}

int
ipmi_sensor_discrete_event_readable(ipmi_sensor_t *sensor,
				    int           event,
				    int           *val)
{
    CHECK_SENSOR_LOCK(sensor);

    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have events. */
	return ENOSYS;

    if (event > 14)
	return EINVAL;

    *val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask3, event);
    return 0;
}

void
ipmi_sensor_discrete_set_event_readable(ipmi_sensor_t *sensor,
					int           event,
					int           val)
{
    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have events. */
	return;

    if (event > 14)
	return;

    IPMI_SENSOR_SET_MASK_BIT(sensor->mask3, event, val);
}

int
ipmi_sensor_get_owner(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->owner;
}

int
ipmi_sensor_get_channel(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->channel;
}

int
ipmi_sensor_get_entity_id(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->entity_id;
}

int
ipmi_sensor_get_entity_instance(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->entity_instance;
}

int
ipmi_sensor_get_entity_instance_logical(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->entity_instance_logical;
}

int
ipmi_sensor_get_sensor_init_scanning(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_init_scanning;
}

int
ipmi_sensor_get_sensor_init_events(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_init_events;
}

int
ipmi_sensor_get_sensor_init_thresholds(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_init_thresholds;
}

int
ipmi_sensor_get_sensor_init_hysteresis(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_init_hysteresis;
}

int
ipmi_sensor_get_sensor_init_type(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_init_type;
}

int
ipmi_sensor_get_sensor_init_pu_events(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_init_pu_events;
}

int
ipmi_sensor_get_sensor_init_pu_scanning(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_init_pu_scanning;
}

int
ipmi_sensor_get_ignore_if_no_entity(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->ignore_if_no_entity;
}

int
ipmi_sensor_get_ignore_for_presence(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->ignore_for_presence;
}

int
ipmi_sensor_get_supports_auto_rearm(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->supports_auto_rearm;
}

int
ipmi_sensor_get_hysteresis_support(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->hysteresis_support;
}

int
ipmi_sensor_get_threshold_access(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->threshold_access;
}

int
ipmi_sensor_get_event_support(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->event_support;
}

int
ipmi_sensor_get_sensor_type(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_type;
}

int
ipmi_sensor_get_event_reading_type(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->event_reading_type;
}

int
ipmi_sensor_get_sensor_direction(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_direction;
}

int
ipmi_sensor_get_is_readable(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->readable;
}

int
ipmi_sensor_get_analog_data_format(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->analog_data_format;
}

enum ipmi_rate_unit_e
ipmi_sensor_get_rate_unit(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->rate_unit;
}

enum ipmi_modifier_unit_use_e
ipmi_sensor_get_modifier_unit_use(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->modifier_unit_use;
}

int
ipmi_sensor_get_percentage(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->percentage;
}

enum ipmi_unit_type_e
ipmi_sensor_get_base_unit(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->base_unit;
}

enum ipmi_unit_type_e
ipmi_sensor_get_modifier_unit(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->modifier_unit;
}

int
ipmi_sensor_get_linearization(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->linearization;
}

int
ipmi_sensor_get_raw_m(ipmi_sensor_t *sensor, int val)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->conv[val].m;
}

int
ipmi_sensor_get_raw_tolerance(ipmi_sensor_t *sensor, int val)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->conv[val].tolerance;
}

int
ipmi_sensor_get_raw_b(ipmi_sensor_t *sensor, int val)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->conv[val].b;
}

int
ipmi_sensor_get_raw_accuracy(ipmi_sensor_t *sensor, int val)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->conv[val].accuracy;
}

int
ipmi_sensor_get_raw_accuracy_exp(ipmi_sensor_t *sensor, int val)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->conv[val].accuracy_exp;
}

int
ipmi_sensor_get_raw_r_exp(ipmi_sensor_t *sensor, int val)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->conv[val].r_exp;
}

int
ipmi_sensor_get_raw_b_exp(ipmi_sensor_t *sensor, int val)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->conv[val].b_exp;
}

int
ipmi_sensor_get_normal_min_specified(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->normal_min_specified;
}

int
ipmi_sensor_get_normal_max_specified(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->normal_max_specified;
}

int
ipmi_sensor_get_nominal_reading_specified(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->nominal_reading_specified;
}

int
ipmi_sensor_get_raw_nominal_reading(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->nominal_reading;
}

int
ipmi_sensor_get_raw_normal_max(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->normal_max;
}

int
ipmi_sensor_get_raw_normal_min(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->normal_min;
}

int
ipmi_sensor_get_raw_sensor_max(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_max;
}

int
ipmi_sensor_get_raw_sensor_min(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_min;
}

int
ipmi_sensor_get_positive_going_threshold_hysteresis(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->positive_going_threshold_hysteresis;
}

int
ipmi_sensor_get_negative_going_threshold_hysteresis(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->negative_going_threshold_hysteresis;
}

int
ipmi_sensor_get_oem1(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->oem1;
}

int
ipmi_sensor_get_id_length(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    if (sensor->id_type == IPMI_ASCII_STR)
	return sensor->id_len+1;
    else
	return sensor->id_len;
}

enum ipmi_str_type_e
ipmi_sensor_get_id_type(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->id_type;
}

int
ipmi_sensor_get_id(ipmi_sensor_t *sensor, char *id, int length)
{
    int clen;

    CHECK_SENSOR_LOCK(sensor);

    if ((int) sensor->id_len > length)
	clen = length;
    else
	clen = sensor->id_len;
    memcpy(id, sensor->id, clen);

    if (sensor->id_type == IPMI_ASCII_STR) {
	/* NIL terminate the ASCII string. */
	if (clen == length)
	    clen--;

	id[clen] = '\0';
    }

    return clen;
}

void
ipmi_sensor_set_owner(ipmi_sensor_t *sensor, int owner)
{
    sensor->owner = owner;
}

void
ipmi_sensor_set_channel(ipmi_sensor_t *sensor, int channel)
{
    sensor->channel = channel;
}

void
ipmi_sensor_set_entity_id(ipmi_sensor_t *sensor, int entity_id)
{
    sensor->entity_id = entity_id;
}

void
ipmi_sensor_set_entity_instance(ipmi_sensor_t *sensor, int entity_instance)
{
    sensor->entity_instance = entity_instance;
}

void
ipmi_sensor_set_entity_instance_logical(ipmi_sensor_t *sensor,
					int           entity_instance_logical)
{
    sensor->entity_instance_logical = entity_instance_logical;
}

void
ipmi_sensor_set_sensor_init_scanning(ipmi_sensor_t *sensor,
				     int           sensor_init_scanning)
{
    sensor->sensor_init_scanning = sensor_init_scanning;
}

void
ipmi_sensor_set_sensor_init_events(ipmi_sensor_t *sensor,
				   int           sensor_init_events)
{
    sensor->sensor_init_events = sensor_init_events;
}

void
ipmi_sensor_set_sensor_init_thresholds(ipmi_sensor_t *sensor,
				       int           sensor_init_thresholds)
{
    sensor->sensor_init_thresholds = sensor_init_thresholds;
}

void
ipmi_sensor_set_sensor_init_hysteresis(ipmi_sensor_t *sensor,
				       int           sensor_init_hysteresis)
{
    sensor->sensor_init_hysteresis = sensor_init_hysteresis;
}

void
ipmi_sensor_set_sensor_init_type(ipmi_sensor_t *sensor, int sensor_init_type)
{
    sensor->sensor_init_type = sensor_init_type;
}

void
ipmi_sensor_set_sensor_init_pu_events(ipmi_sensor_t *sensor,
				      int           sensor_init_pu_events)
{
    sensor->sensor_init_pu_events = sensor_init_pu_events;
}

void
ipmi_sensor_set_sensor_init_pu_scanning(ipmi_sensor_t *sensor,
					int           sensor_init_pu_scanning)
{
    sensor->sensor_init_pu_scanning = sensor_init_pu_scanning;
}

void
ipmi_sensor_set_ignore_if_no_entity(ipmi_sensor_t *sensor,
				    int           ignore_if_no_entity)
{
    sensor->ignore_if_no_entity = ignore_if_no_entity;
}

void
ipmi_sensor_set_ignore_for_presence(ipmi_sensor_t *sensor, int ignore)
{
    sensor->ignore_for_presence = ignore;
}

void
ipmi_sensor_set_supports_auto_rearm(ipmi_sensor_t *sensor, int val)
{
    sensor->supports_auto_rearm = val;
}

void
ipmi_sensor_set_hysteresis_support(ipmi_sensor_t *sensor,
				   int           hysteresis_support)
{
    sensor->hysteresis_support = hysteresis_support;
}

void
ipmi_sensor_set_threshold_access(ipmi_sensor_t *sensor, int threshold_access)
{
    sensor->threshold_access = threshold_access;
}

void
ipmi_sensor_set_event_support(ipmi_sensor_t *sensor, int event_support)
{
    sensor->event_support = event_support;
}

void
ipmi_sensor_set_sensor_type(ipmi_sensor_t *sensor, int sensor_type)
{
    sensor->sensor_type = sensor_type;
}

void
ipmi_sensor_set_event_reading_type(ipmi_sensor_t *sensor,
				   int           event_reading_type)
{
    sensor->event_reading_type = event_reading_type;
}

void
ipmi_sensor_set_direction(ipmi_sensor_t *sensor,
			  int           direction)
{
    sensor->sensor_direction = direction;
}

void
ipmi_sensor_set_is_readable(ipmi_sensor_t *sensor,
			    int           readable)
{
    sensor->readable = readable != 0;
}

void
ipmi_sensor_set_analog_data_format(ipmi_sensor_t *sensor,
				   int           analog_data_format)
{
    sensor->analog_data_format = analog_data_format;
}

void
ipmi_sensor_set_rate_unit(ipmi_sensor_t *sensor, int rate_unit)
{
    sensor->rate_unit = rate_unit;
}

void
ipmi_sensor_set_modifier_unit_use(ipmi_sensor_t *sensor, int modifier_unit_use)
{
    sensor->modifier_unit_use = modifier_unit_use;
}

void
ipmi_sensor_set_percentage(ipmi_sensor_t *sensor, int percentage)
{
    sensor->percentage = percentage;
}

void
ipmi_sensor_set_base_unit(ipmi_sensor_t *sensor, int base_unit)
{
    sensor->base_unit = base_unit;
}

void
ipmi_sensor_set_modifier_unit(ipmi_sensor_t *sensor, int modifier_unit)
{
    sensor->modifier_unit = modifier_unit;
}

void
ipmi_sensor_set_linearization(ipmi_sensor_t *sensor, int linearization)
{
    sensor->linearization = linearization;
}

void
ipmi_sensor_set_raw_m(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].m = val;
}

void
ipmi_sensor_set_raw_tolerance(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].tolerance = val;
}

void
ipmi_sensor_set_raw_b(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].b = val;
}

void
ipmi_sensor_set_raw_accuracy(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].accuracy = val;
}

void
ipmi_sensor_set_raw_accuracy_exp(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].accuracy_exp = val;
}

void
ipmi_sensor_set_raw_r_exp(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].r_exp = val;
}

void
ipmi_sensor_set_raw_b_exp(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].b_exp = val;
}

void
ipmi_sensor_set_normal_min_specified(ipmi_sensor_t *sensor,
				     int           normal_min_specified)
{
    sensor->normal_min_specified = normal_min_specified;
}

void
ipmi_sensor_set_normal_max_specified(ipmi_sensor_t *sensor,
				     int           normal_max_specified)
{
    sensor->normal_max_specified = normal_max_specified;
}

void
ipmi_sensor_set_nominal_reading_specified(
    ipmi_sensor_t *sensor,
    int            nominal_reading_specified)
{
    sensor->nominal_reading_specified = nominal_reading_specified;
}

void
ipmi_sensor_set_raw_nominal_reading(ipmi_sensor_t *sensor,
				    int           raw_nominal_reading)
{
    sensor->nominal_reading = raw_nominal_reading;
}

void
ipmi_sensor_set_raw_normal_max(ipmi_sensor_t *sensor, int raw_normal_max)
{
    sensor->normal_max = raw_normal_max;
}

void
ipmi_sensor_set_raw_normal_min(ipmi_sensor_t *sensor, int raw_normal_min)
{
    sensor->normal_min = raw_normal_min;
}

void
ipmi_sensor_set_raw_sensor_max(ipmi_sensor_t *sensor, int raw_sensor_max)
{
    sensor->sensor_max = raw_sensor_max;
}

void
ipmi_sensor_set_raw_sensor_min(ipmi_sensor_t *sensor, int raw_sensor_min)
{
    sensor->sensor_min = raw_sensor_min;
}

void
ipmi_sensor_set_positive_going_threshold_hysteresis(
    ipmi_sensor_t *sensor,
    int           positive_going_threshold_hysteresis)
{
    sensor->positive_going_threshold_hysteresis
	= positive_going_threshold_hysteresis;
}

void
ipmi_sensor_set_negative_going_threshold_hysteresis(
    ipmi_sensor_t *sensor,
    int           negative_going_threshold_hysteresis)
{
    sensor->negative_going_threshold_hysteresis
	= negative_going_threshold_hysteresis;
}

void
ipmi_sensor_set_oem1(ipmi_sensor_t *sensor, int oem1)
{
    sensor->oem1 = oem1;
}

void
ipmi_sensor_set_id(ipmi_sensor_t *sensor, char *id,
		   enum ipmi_str_type_e type, int length)
{
    if (length > SENSOR_ID_LEN)
	length = SENSOR_ID_LEN;
    
    memcpy(sensor->id, id, length);
    sensor->id_type = type;
    sensor->id_len = length;
    if (sensor->entity)
	sensor_set_name(sensor);
}

void
ipmi_sensor_set_oem_info(ipmi_sensor_t *sensor, void *oem_info,
			 ipmi_sensor_cleanup_oem_info_cb cleanup_handler)
{
    sensor->oem_info = oem_info;
    sensor->oem_info_cleanup_handler = cleanup_handler;
}

void *
ipmi_sensor_get_oem_info(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->oem_info;
}

const char *
ipmi_sensor_get_sensor_type_string(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->sensor_type_string;
}

void
ipmi_sensor_set_sensor_type_string(ipmi_sensor_t *sensor, const char *str)
{
    sensor->sensor_type_string = str;
}

const char *
ipmi_sensor_get_event_reading_type_string(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->event_reading_type_string;
}

void
ipmi_sensor_set_event_reading_type_string(ipmi_sensor_t *sensor,
					  const char    *str)
{
    sensor->event_reading_type_string = str;
}

const char *
ipmi_sensor_get_rate_unit_string(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->rate_unit_string;
}

void
ipmi_sensor_set_rate_unit_string(ipmi_sensor_t *sensor,
				 const char    *str)
{
    sensor->rate_unit_string = str;
}

const char *
ipmi_sensor_get_base_unit_string(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->base_unit_string;
}

void
ipmi_sensor_set_base_unit_string(ipmi_sensor_t *sensor, const char *str)
{
    sensor->base_unit_string = str;
}

const char *
ipmi_sensor_get_modifier_unit_string(ipmi_sensor_t *sensor)
{
    CHECK_SENSOR_LOCK(sensor);

    return sensor->modifier_unit_string;
}

void
ipmi_sensor_set_modifier_unit_string(ipmi_sensor_t *sensor, const char *str)
{
    sensor->modifier_unit_string = str;
}

void
ipmi_sensor_set_hot_swap_requester(ipmi_sensor_t *sensor,
				   int           offset,
				   int           val_when_requesting)
{
    sensor->hot_swap_requester = offset;
    sensor->hot_swap_requester_val = val_when_requesting;
}

int
ipmi_sensor_is_hot_swap_requester(ipmi_sensor_t *sensor,
				  int           *offset,
				  int           *val_when_requesting)
{
    CHECK_SENSOR_LOCK(sensor);

    if (sensor->hot_swap_requester != -1) {
	if (offset)
	    *offset = sensor->hot_swap_requester;
	if (val_when_requesting)
	    *val_when_requesting = sensor->hot_swap_requester_val;
	return 1;
    }
    return 0;
}

ipmi_domain_t *
ipmi_sensor_get_domain(ipmi_sensor_t *sensor)
{
    return sensor->domain;
}

ipmi_entity_t *
ipmi_sensor_get_entity(ipmi_sensor_t *sensor)
{
    return sensor->entity;
}


/***********************************************************************
 *
 * Incoming event handling for sensors.
 *
 **********************************************************************/

int
ipmi_sensor_threshold_set_event_handler(
    ipmi_sensor_t                             *sensor,
    ipmi_sensor_threshold_event_handler_nd_cb handler,
    void                                      *cb_data)
{
    CHECK_SENSOR_LOCK(sensor);

    sensor->threshold_event_handler = handler;
    sensor->cb_data = cb_data;
    return 0;
}

int
ipmi_sensor_add_threshold_event_handler(
    ipmi_sensor_t                  *sensor,
    ipmi_sensor_threshold_event_cb handler,
    void                           *cb_data)
{
    CHECK_SENSOR_LOCK(sensor);

    if (! locked_list_add(sensor->handler_list, handler, cb_data))
	return ENOMEM;

    return 0;
}

int
ipmi_sensor_remove_threshold_event_handler(
    ipmi_sensor_t                  *sensor,
    ipmi_sensor_threshold_event_cb handler,
    void                           *cb_data)
{
    CHECK_SENSOR_LOCK(sensor);

    if (! locked_list_remove(sensor->handler_list, handler, cb_data))
	return ENOENT;

    return 0;
}

int
ipmi_sensor_add_threshold_event_handler_cl(
    ipmi_sensor_t                     *sensor,
    ipmi_sensor_threshold_event_cl_cb handler,
    void                              *cb_data)
{
    CHECK_SENSOR_LOCK(sensor);

    if (! locked_list_add(sensor->handler_list_cl, handler, cb_data))
	return ENOMEM;

    return 0;
}

int
ipmi_sensor_remove_threshold_event_handler_cl(
    ipmi_sensor_t                     *sensor,
    ipmi_sensor_threshold_event_cl_cb handler,
    void                              *cb_data)
{
    CHECK_SENSOR_LOCK(sensor);

    if (! locked_list_remove(sensor->handler_list_cl, handler, cb_data))
	return ENOENT;

    return 0;
}


int
ipmi_sensor_discrete_set_event_handler(
    ipmi_sensor_t                            *sensor,
    ipmi_sensor_discrete_event_handler_nd_cb handler,
    void                                     *cb_data)
{
    CHECK_SENSOR_LOCK(sensor);

    sensor->discrete_event_handler = handler;
    sensor->cb_data = cb_data;
    return 0;
}

int
ipmi_sensor_add_discrete_event_handler(
    ipmi_sensor_t                 *sensor,
    ipmi_sensor_discrete_event_cb handler,
    void                          *cb_data)
{
    CHECK_SENSOR_LOCK(sensor);

    if (! locked_list_add(sensor->handler_list, handler, cb_data))
	return ENOMEM;

    return 0;
}

int
ipmi_sensor_remove_discrete_event_handler(
    ipmi_sensor_t                 *sensor,
    ipmi_sensor_discrete_event_cb handler,
    void                          *cb_data)
{
    CHECK_SENSOR_LOCK(sensor);

    if (! locked_list_remove(sensor->handler_list, handler, cb_data))
	return ENOENT;

    return 0;
}

int
ipmi_sensor_add_discrete_event_handler_cl(
    ipmi_sensor_t                    *sensor,
    ipmi_sensor_discrete_event_cl_cb handler,
    void                             *cb_data)
{
    CHECK_SENSOR_LOCK(sensor);

    if (! locked_list_add(sensor->handler_list_cl, handler, cb_data))
	return ENOMEM;

    return 0;
}

int
ipmi_sensor_remove_discrete_event_handler_cl(
    ipmi_sensor_t                    *sensor,
    ipmi_sensor_discrete_event_cl_cb handler,
    void                             *cb_data)
{
    CHECK_SENSOR_LOCK(sensor);

    if (! locked_list_remove(sensor->handler_list_cl, handler, cb_data))
	return ENOENT;

    return 0;
}

typedef struct sensor_event_info_s
{
    ipmi_sensor_t               *sensor;
    int                         handled;

    enum ipmi_event_dir_e       dir;
    enum ipmi_thresh_e          threshold;
    enum ipmi_event_value_dir_e high_low;
    enum ipmi_value_present_e   value_present;
    unsigned int                raw_value;
    double                      value;

    int                         offset;
    int                         severity;
    int                         prev_severity;

    ipmi_event_t                *event;
} sensor_event_info_t;

static int
threshold_sensor_event_call_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_sensor_threshold_event_cb handler = item1;
    sensor_event_info_t            *info = cb_data;
    int                            handled;

    handled = handler(info->sensor, info->dir,
		      info->threshold,
		      info->high_low,
		      info->value_present,
		      info->raw_value, info->value,
		      item2, info->event);
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
ipmi_sensor_call_threshold_event_handlers
(ipmi_sensor_t               *sensor,
 enum ipmi_event_dir_e       dir,
 enum ipmi_thresh_e          threshold,
 enum ipmi_event_value_dir_e high_low,
 enum ipmi_value_present_e   value_present,
 unsigned int                raw_value,
 double                      value,
 ipmi_event_t                **event,
 int                         *handled)
{
    sensor_event_info_t info;

    info.sensor = sensor;
    info.dir = dir;
    info.threshold = threshold;
    info.high_low = high_low;
    info.value_present = value_present;
    info.raw_value = raw_value;
    info.value = value;
    info.event = *event;
    if (handled)
	info.handled = *handled;
    else
	info.handled = IPMI_EVENT_NOT_HANDLED;

    if (sensor->threshold_event_handler) {
	sensor->threshold_event_handler(sensor, info.dir,
					info.threshold,
					info.high_low,
					info.value_present,
					info.raw_value, info.value,
					sensor->cb_data, info.event);
	if (info.event)
	    info.handled = IPMI_EVENT_HANDLED;
	info.event = NULL;
    }
    locked_list_iterate(sensor->handler_list,
			threshold_sensor_event_call_handler, &info);

    if (handled)
	*handled = info.handled;
    *event = info.event;
}

static int
discrete_sensor_event_call_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_sensor_discrete_event_cb handler = item1;
    sensor_event_info_t           *info = cb_data;
    int                           handled;

    handled = handler(info->sensor, info->dir, info->offset,
		      info->severity,
		      info->prev_severity,
		      item2, info->event);
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
ipmi_sensor_call_discrete_event_handlers(ipmi_sensor_t         *sensor,
					 enum ipmi_event_dir_e dir,
					 int                   offset,
					 int                   severity,
					 int                   prev_severity,
					 ipmi_event_t          **event,
					 int                   *handled)
{
    sensor_event_info_t info;

    info.sensor = sensor;
    info.dir = dir;
    info.offset = offset;
    info.severity = severity;
    info.prev_severity = prev_severity;
    info.event = *event;
    if (handled)
	info.handled = *handled;
    else
	info.handled = IPMI_EVENT_NOT_HANDLED;

    if (sensor->discrete_event_handler) {
	sensor->discrete_event_handler(sensor, info.dir, info.offset,
				       info.severity,
				       info.prev_severity,
				       sensor->cb_data, info.event);
	if (info.event)
	    info.handled = IPMI_EVENT_HANDLED;
	info.event = NULL;
    }
    locked_list_iterate(sensor->handler_list,
			discrete_sensor_event_call_handler, &info);

    if (handled)
	*handled = info.handled;
    *event = info.event;
}

int
ipmi_sensor_event(ipmi_sensor_t *sensor, ipmi_event_t *event)
{
    int rv;
    int handled;

    CHECK_SENSOR_LOCK(sensor);

    handled = IPMI_EVENT_NOT_HANDLED;

    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD) {
	enum ipmi_event_dir_e       dir;
	enum ipmi_thresh_e          threshold;
	enum ipmi_event_value_dir_e high_low;
	enum ipmi_value_present_e   value_present;
	unsigned int                raw_value;
	double                      value;
	const unsigned char         *data;

	data = ipmi_event_get_data_ptr(event);
	dir = data[9] >> 7;
	threshold = (data[10] >> 1) & 0x07;
	high_low = data[10] & 1;
	raw_value = data[11];
	value = 0.0;

	if ((data[10] >> 6) == 2) {
	    rv = ipmi_sensor_convert_from_raw(sensor, raw_value, &value);
	    if (!rv)
		value_present = IPMI_RAW_VALUE_PRESENT;
	    else
		value_present = IPMI_BOTH_VALUES_PRESENT;
	} else {
	    value_present = IPMI_NO_VALUES_PRESENT;
	}
	ipmi_sensor_call_threshold_event_handlers(sensor, dir,
						  threshold,
						  high_low,
						  value_present,
						  raw_value, value,
						  &event,
						  &handled);
    } else {
	enum ipmi_event_dir_e dir;
	int                   offset;
	int                   severity = 0;
	int                   prev_severity = 0;
	const unsigned char   *data;

	data = ipmi_event_get_data_ptr(event);
	dir = data[9] >> 7;
	offset = data[10] & 0x0f;
	if ((data[10] >> 6) == 2) {
	    severity = data[11] >> 4;
	    prev_severity = data[11] & 0xf;
	    if (severity == 0xf)
		severity = -1;
	    if (prev_severity == 0xf)
		prev_severity = -1;
	}

	ipmi_sensor_call_discrete_event_handlers(sensor, dir, offset,
						 severity,
						 prev_severity,
						 &event,
						 &handled);
    }

    /* Make sure the caller knows if we didn't deliver the event. */
    if (handled == IPMI_EVENT_NOT_HANDLED)
	return EINVAL;
    return 0;
}

/***********************************************************************
 *
 * Standard sensor messaging.
 *
 **********************************************************************/

typedef void (*sensor_done_handler_cb)(ipmi_sensor_t *sensor,
				       int           err,
				       void          *sinfo);

static int
sensor_done_check_rsp(ipmi_sensor_t          *sensor,
		      int                    err,
		      ipmi_msg_t             *rsp,
		      unsigned int           min_length,
		      char                   *name,
		      sensor_done_handler_cb done,
		      void                   *sinfo)
{
    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(%s): Got error: %x",
		 SENSOR_NAME(sensor), name, err);
	done(sensor, err, sinfo);
	return err;
    }

    if (!sensor) {
	/* This *should* never happen, but we check it to shake out
	   bugs. */
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(%s): Sensor when away during operation",
		 SENSOR_NAME(sensor), name);
	done(sensor, ECANCELED, sinfo);
	return ECANCELED;
    }

    if (rsp && rsp->data[0]) {
#if 0
	/* This is sometimes expected. */
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(%s): Got IPMI error in response: %x",
		 SENSOR_NAME(sensor), name, rsp->data[0]);
#endif
	done(sensor, IPMI_IPMI_ERR_VAL(rsp->data[0]), sinfo);
	return IPMI_IPMI_ERR_VAL(rsp->data[0]);
    }

    if (rsp && (rsp->data_len < min_length)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(%s): Response was too short, got %d, expected %d",
		 SENSOR_NAME(sensor), name, rsp->data_len, min_length);
	done(sensor, EINVAL, sinfo);
	return EINVAL;
    }

    return 0;
}

typedef struct event_enable_info_s
{
    ipmi_sensor_op_info_t sdata;
    ipmi_event_state_t    state;
    ipmi_sensor_done_cb   done;
    void                  *cb_data;
    int                   do_enable;
    int                   do_disable;
} event_enable_info_t;

static void enables_done_handler(ipmi_sensor_t *sensor,
				 int           err,
				 void          *sinfo)
{
    event_enable_info_t *info = sinfo;

    if (info->done)
	info->done(sensor, err, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(info);
}

static void
disables_set(ipmi_sensor_t *sensor,
	     int           err,
	     ipmi_msg_t    *rsp,
	     void          *cb_data)
{
    event_enable_info_t *info = cb_data;

    if (sensor_done_check_rsp(sensor, err, rsp, 1, "disables_set",
			      enables_done_handler, info))
	return;

    enables_done_handler(sensor, 0, info);
}

static void
enables_set(ipmi_sensor_t *sensor,
	    int           err,
	    ipmi_msg_t    *rsp,
	    void          *cb_data)
{
    event_enable_info_t *info = cb_data;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;

    if (sensor_done_check_rsp(sensor, err, rsp, 1, "enables_set",
			      enables_done_handler, info))
	return;

    if (info->do_disable) {
	/* Enables were set, now disable all the other ones.  Make
	   sure we only set event bits that we support. */
	uint16_t val1, val2;

	cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
	cmd_msg.cmd = IPMI_SET_SENSOR_EVENT_ENABLE_CMD;
	cmd_msg.data_len = 6;
	cmd_msg.data = cmd_data;
	cmd_data[0] = sensor->num;
	cmd_data[1] = (info->state.status & 0xc0) | (0x02 << 4);
	ipmi_sensor_get_event_masks(sensor, &val1, &val2);
	val1 &= ~info->state.__assertion_events;
	val2 &= ~info->state.__deassertion_events;
	ipmi_set_uint16(cmd_data+2, val1);
	ipmi_set_uint16(cmd_data+4, val2);
	rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				      &cmd_msg, disables_set,
				      &(info->sdata), info);
	if (rv) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%ssensors.c(enables_set):"
		     " Error sending event enable command to clear events: %x",
		     SENSOR_NAME(sensor), rv);
	    enables_done_handler(sensor, rv, info);
	}
    } else {
	/* Just doing enables, we are done. */
	enables_done_handler(sensor, 0, info);
    }
}

static void
event_enable_set_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    event_enable_info_t *info = cb_data;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 event_support;
    int                 rv;

    if (sensor_done_check_rsp(sensor, err, NULL, 0, "event_enable_set_start",
			      enables_done_handler, info))
	return;

    event_support = ipmi_sensor_get_event_support(sensor);

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_SET_SENSOR_EVENT_ENABLE_CMD;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    if (event_support == IPMI_EVENT_SUPPORT_ENTIRE_SENSOR) {
	/* We can only turn on/off the entire sensor, just pass the
           status to the sensor. */
	cmd_data[1] = info->state.status & 0xc0;
	cmd_msg.data_len = 2;
	rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				      &cmd_msg, disables_set, &(info->sdata),
				      info);
    } else if (info->do_enable) {
	/* Start by first setting the enables, then set the disables
           in a second operation.  We do this because enables and
           disables cannot both be set at the same time, and it's
           safer to first enable the new events then to disable the
           events we want disabled.  It would be *really* nice if IPMI
           had a way to do this in one operation, such as using 11b in
           the request byte 2 bits 5:4 to say "set the events to
           exactly this state". */
	cmd_data[1] = (info->state.status & 0xc0) | (0x01 << 4);
	cmd_data[2] = info->state.__assertion_events & 0xff;
	cmd_data[3] = info->state.__assertion_events >> 8;
	cmd_data[4] = info->state.__deassertion_events & 0xff;
	cmd_data[5] = info->state.__deassertion_events >> 8;
	cmd_msg.data_len = 6;
	rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				      &cmd_msg, enables_set, &(info->sdata),
				      info);
    } else {
	/* We are only doing disables. */
	cmd_data[1] = (info->state.status & 0xc0) | (0x02 << 4);
	cmd_data[2] = info->state.__assertion_events & 0xff;
	cmd_data[3] = info->state.__assertion_events >> 8;
	cmd_data[4] = info->state.__deassertion_events & 0xff;
	cmd_data[5] = info->state.__deassertion_events >> 8;
	cmd_msg.data_len = 6;
	rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				      &cmd_msg, disables_set,
				      &(info->sdata), info);
    }
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(event_enable_set_start):"
		 " Error sending event enable command: %x",
		 SENSOR_NAME(sensor), rv);
	enables_done_handler(sensor, rv, info);
    }
}

static int
check_events_capability(ipmi_sensor_t      *sensor,
			ipmi_event_state_t *states)
{
    int event_support;

    event_support = ipmi_sensor_get_event_support(sensor);
    if ((event_support == IPMI_EVENT_SUPPORT_NONE)
	|| (event_support == IPMI_EVENT_SUPPORT_GLOBAL_ENABLE))
    {
	/* We don't support setting events for this sensor. */
	return EINVAL;
    }

    if ((event_support == IPMI_EVENT_SUPPORT_ENTIRE_SENSOR)
	&& ((states->__assertion_events != 0)
	    || (states->__deassertion_events != 0)))
    {
	/* This sensor does not support individual event states, but
           the user is trying to set them. */
	return EINVAL;
    }

    if (event_support == IPMI_EVENT_SUPPORT_PER_STATE) {
	uint16_t mask1, mask2;

	ipmi_sensor_get_event_masks(sensor, &mask1, &mask2);
	if (((~mask1) & states->__assertion_events)
	    || ((~mask2) & states->__deassertion_events))
	{
	    /* The user is attempting to set a state that the
	       sensor does not support. */
	    return EINVAL;
	}
    }

    return 0;
}

static int
stand_ipmi_sensor_set_event_enables(ipmi_sensor_t         *sensor,
				    ipmi_event_state_t    *states,
				    ipmi_sensor_done_cb   done,
				    void                  *cb_data)
{
    event_enable_info_t *info;
    int                 rv;

    rv = check_events_capability(sensor, states);
    if (rv)
	return rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->state = *states;
    info->done = done;
    info->cb_data = cb_data;
    info->do_enable = 1;
    info->do_disable = 1;
    rv = ipmi_sensor_add_opq(sensor, event_enable_set_start,
			     &(info->sdata), info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

static int
stand_ipmi_sensor_enable_events(ipmi_sensor_t         *sensor,
				ipmi_event_state_t    *states,
				ipmi_sensor_done_cb   done,
				void                  *cb_data)
{
    event_enable_info_t *info;
    int                 rv;

    rv = check_events_capability(sensor, states);
    if (rv)
	return rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->state = *states;
    info->done = done;
    info->cb_data = cb_data;
    info->do_enable = 1;
    info->do_disable = 0;
    rv = ipmi_sensor_add_opq(sensor, event_enable_set_start,
			     &(info->sdata), info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

static int
stand_ipmi_sensor_disable_events(ipmi_sensor_t         *sensor,
				 ipmi_event_state_t    *states,
				 ipmi_sensor_done_cb   done,
				 void                  *cb_data)
{
    event_enable_info_t *info;
    int                 rv;

    rv = check_events_capability(sensor, states);
    if (rv)
	return rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->state = *states;
    info->done = done;
    info->cb_data = cb_data;
    info->do_enable = 0;
    info->do_disable = 1;
    rv = ipmi_sensor_add_opq(sensor, event_enable_set_start,
			     &(info->sdata), info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

typedef struct event_enable_get_info_s
{
    ipmi_sensor_op_info_t        sdata;
    ipmi_event_state_t           state;
    ipmi_sensor_event_enables_cb done;
    void                         *cb_data;
} event_enable_get_info_t;

static void enables_get_done_handler(ipmi_sensor_t *sensor,
				     int           err,
				     void          *sinfo)
{
    event_enable_get_info_t *info = sinfo;

    if (info->done)
	info->done(sensor, err, &info->state, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(info);
}

static void
enables_get(ipmi_sensor_t *sensor,
	    int           err,
	    ipmi_msg_t    *rsp,
	    void          *cb_data)
{
    event_enable_get_info_t *info = cb_data;

    if (sensor_done_check_rsp(sensor, err, rsp, 2, "enables_get",
			      enables_get_done_handler, info))
	return;

    info->state.status = rsp->data[1] & 0xc0;
    if (rsp->data_len >= 3)
	info->state.__assertion_events = rsp->data[2];
    if (rsp->data_len >= 4)
        info->state.__assertion_events |= rsp->data[3] << 8;
    if (rsp->data_len >= 5)
        info->state.__deassertion_events = rsp->data[4];
    if (rsp->data_len >= 6)
        info->state.__deassertion_events |= rsp->data[5] << 8;

    /* Mask off reserved bits */
    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD) {
	info->state.__assertion_events &= 0x0fff;
        info->state.__deassertion_events &= 0x0fff;
    } else {
	info->state.__assertion_events &= 0x7fff;
        info->state.__deassertion_events &= 0x7fff;
    }

    /* It is possible that there are events set here that are not in
       sensor->mask1 (assertion events) or sensor->mask2 (deassertion
       events).  That's a bug in the sensor; it shouldn't be setting
       those bits.  If it ever comes to the point where we need to
       handle that here, a simple mask operation would do it. */

    enables_get_done_handler(sensor, 0, info);
}

static void
event_enable_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    event_enable_get_info_t *info = cb_data;
    unsigned char           cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t              cmd_msg;
    int                     rv;

    if (sensor_done_check_rsp(sensor, err, NULL, 0, "event_enable_get_start",
			      enables_get_done_handler, info))
	return;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_EVENT_ENABLE_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				  &cmd_msg, enables_get, &(info->sdata), info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(event_enable_get_start):"
		 " Error sending get event enables command: %x",
		 SENSOR_NAME(sensor), rv);
	enables_get_done_handler(sensor, rv, info);
    }
}

static int
stand_ipmi_sensor_get_event_enables(ipmi_sensor_t                *sensor,
				    ipmi_sensor_event_enables_cb done,
				    void                         *cb_data)
{
    event_enable_get_info_t *info;
    int                     rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(info));
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, event_enable_get_start,
			     &(info->sdata), info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

typedef struct sensor_rearm_info_s
{
    ipmi_sensor_op_info_t sdata;
    ipmi_event_state_t    state;
    int                   global_enable;
    ipmi_sensor_done_cb   done;
    void                  *cb_data;
} sensor_rearm_info_t;

static void sensor_rearm_done_handler(ipmi_sensor_t *sensor,
				      int           err,
				      void          *sinfo)
{
    sensor_rearm_info_t *info = sinfo;

    if (info->done)
	info->done(sensor, err, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(info);
}

static void
sensor_rearm(ipmi_sensor_t *sensor,
	     int           err,
	     ipmi_msg_t    *rsp,
	     void          *cb_data)
{
    sensor_rearm_info_t *info = cb_data;

    if (sensor_done_check_rsp(sensor, err, rsp, 1, "sensor_rearm",
			      sensor_rearm_done_handler, info))
	return;

    sensor_rearm_done_handler(sensor, 0, info);
}

static void
sensor_rearm_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    sensor_rearm_info_t *info = cb_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;

    if (sensor_done_check_rsp(sensor, err, NULL, 0, "sensor_rearm_start",
			      sensor_rearm_done_handler, info))
	return;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_REARM_SENSOR_EVENTS_CMD;
    if (info->global_enable) {
	cmd_msg.data_len = 2;
	cmd_msg.data = cmd_data;
	cmd_data[0] = sensor->num;
	cmd_data[1] = 0; /* Rearm all events. */
    } else {
	cmd_msg.data_len = 6;
	cmd_msg.data = cmd_data;
	cmd_data[0] = sensor->num;
	cmd_data[1] = 0x80; /* Rearm only specific sensors. */
	cmd_data[2] = info->state.__assertion_events & 0xff;
	cmd_data[3] = info->state.__assertion_events >> 8;
	cmd_data[4] = info->state.__deassertion_events & 0xff;
	cmd_data[5] = info->state.__deassertion_events >> 8;
    }
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				  &cmd_msg, sensor_rearm,
				  &(info->sdata), info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(sensor_rearm_start):"
		 " Error sending rearm command: %x",
		 SENSOR_NAME(sensor), rv);
	sensor_rearm_done_handler(sensor, rv, info);
    }
}

static int
stand_ipmi_sensor_rearm(ipmi_sensor_t       *sensor,
			int                 global_enable,
			ipmi_event_state_t  *state,
			ipmi_sensor_done_cb done,
			void                *cb_data)
{
    sensor_rearm_info_t *info;
    int                 rv;
    
    if (!global_enable && !state)
	return EINVAL;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    info->global_enable = global_enable;
    if (state)
	memcpy(&info->state, state, sizeof(info->state));
    rv = ipmi_sensor_add_opq(sensor, sensor_rearm_start, &(info->sdata), info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

typedef struct hyst_get_info_s
{
    ipmi_sensor_op_info_t     sdata;
    ipmi_sensor_hysteresis_cb done;
    void                      *cb_data;
    unsigned int              positive;
    unsigned int              negative;
} hyst_get_info_t;

static void hyst_get_done_handler(ipmi_sensor_t *sensor,
				  int           err,
				  void          *sinfo)
{
    hyst_get_info_t *info = sinfo;

    if (info->done)
	info->done(sensor, err, info->positive, info->negative, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(info);
}

static void
hyst_get(ipmi_sensor_t *sensor,
	 int           err,
	 ipmi_msg_t    *rsp,
	 void          *cb_data)
{
    hyst_get_info_t *info = cb_data;

    if (sensor_done_check_rsp(sensor, err, rsp, 3, "hyst_get",
			      hyst_get_done_handler, info))
	return;

    info->positive = rsp->data[1];
    info->negative = rsp->data[2];
    hyst_get_done_handler(sensor, 0, info);
}

static void
hyst_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    hyst_get_info_t *info = cb_data;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;

    if (sensor_done_check_rsp(sensor, err, NULL, 0, "hyst_get_start",
			      hyst_get_done_handler, info))
	return;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_HYSTERESIS_CMD;
    cmd_msg.data_len = 2;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    cmd_data[1] = 0xff;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				  &cmd_msg, hyst_get, &(info->sdata), info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(hyst_get_start):"
		 " Error sending hysteresis get command: %x",
		 SENSOR_NAME(sensor), rv);
	hyst_get_done_handler(sensor, rv, info);
    }
}

static int
stand_ipmi_sensor_get_hysteresis(ipmi_sensor_t             *sensor,
				 ipmi_sensor_hysteresis_cb done,
				 void                      *cb_data)
{
    hyst_get_info_t *info;
    int             rv;
    
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if ((sensor->hysteresis_support != IPMI_HYSTERESIS_SUPPORT_READABLE)
        && (sensor->hysteresis_support != IPMI_HYSTERESIS_SUPPORT_SETTABLE))
	return ENOSYS;
    
    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, hyst_get_start, &(info->sdata), info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

typedef struct hyst_set_info_s
{
    ipmi_sensor_op_info_t sdata;
    unsigned int          positive, negative;
    ipmi_sensor_done_cb   done;
    void                  *cb_data;
} hyst_set_info_t;

static void hyst_set_done_handler(ipmi_sensor_t *sensor,
				  int           err,
				  void          *sinfo)
{
    hyst_set_info_t *info = sinfo;

    if (info->done)
	info->done(sensor, err, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(info);
}

static void
hyst_set(ipmi_sensor_t *sensor,
	 int           err,
	 ipmi_msg_t    *rsp,
	 void          *cb_data)
{
    hyst_set_info_t *info = cb_data;

    if (sensor_done_check_rsp(sensor, err, rsp, 1, "hyst_set",
			      hyst_set_done_handler, info))
	return;

    hyst_set_done_handler(sensor, 0, info);
}

static void
hyst_set_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    hyst_set_info_t *info = cb_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;

    if (sensor_done_check_rsp(sensor, err, NULL, 0, "hyst_set_start",
			      hyst_set_done_handler, info))
	return;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_SET_SENSOR_HYSTERESIS_CMD;
    cmd_msg.data_len = 4;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    cmd_data[1] = 0xff;
    cmd_data[2] = info->positive;
    cmd_data[3] = info->negative;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				  &cmd_msg, hyst_set, &(info->sdata), info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(hyst_set_start):"
		 " Error sending hysteresis set command: %x",
		 SENSOR_NAME(sensor), rv);
	hyst_set_done_handler(sensor, rv, info);
    }
}

static int
stand_ipmi_sensor_set_hysteresis(ipmi_sensor_t       *sensor,
				 unsigned int        positive_hysteresis,
				 unsigned int        negative_hysteresis,
				 ipmi_sensor_done_cb done,
				 void                *cb_data)
{
    hyst_set_info_t *info;
    int             rv;
    
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (sensor->hysteresis_support != IPMI_HYSTERESIS_SUPPORT_SETTABLE)
	return ENOSYS;
    
    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->positive = positive_hysteresis;
    info->negative = negative_hysteresis;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, hyst_set_start, &(info->sdata), info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

typedef struct thresh_get_info_s
{
    ipmi_sensor_op_info_t     sdata;
    ipmi_thresholds_t         th;
    ipmi_sensor_thresholds_cb done;
    void                      *cb_data;
} thresh_get_info_t;

static void thresh_get_done_handler(ipmi_sensor_t *sensor,
				    int           err,
				    void          *sinfo)
{
    thresh_get_info_t *info = sinfo;

    if (info->done)
	info->done(sensor, err, &info->th, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(info);
}

static void
thresh_get(ipmi_sensor_t *sensor,
	   int           err,
	   ipmi_msg_t    *rsp,
	   void          *cb_data)
{
    thresh_get_info_t  *info = cb_data;
    enum ipmi_thresh_e th;

    if (sensor_done_check_rsp(sensor, err, rsp, 8, "thresh_get",
			      thresh_get_done_handler, info))
	return;
    
    for (th=IPMI_LOWER_NON_CRITICAL; th<=IPMI_UPPER_NON_RECOVERABLE; th++) {
	int rv;
	if (rsp->data[1] & (1 << th)) {
	    info->th.vals[th].status = 1;
	    rv = ipmi_sensor_convert_from_raw(sensor,
					      rsp->data[th+2],
					      &(info->th.vals[th].val));
	    if (rv) {
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "%ssensor.c(thresh_get):"
			 " Could not convert raw threshold value: %x",
			 SENSOR_NAME(sensor), rv);
		thresh_get_done_handler(sensor, rv, info);
		return;
	    }
	} else {
	    info->th.vals[th].status = 0;
	}
    }

    thresh_get_done_handler(sensor, 0, info);
}

int
ipmi_get_default_sensor_thresholds(ipmi_sensor_t     *sensor,
				   ipmi_thresholds_t *th)
{
    enum ipmi_thresh_e thnum;
    int                rv = 0;

    CHECK_SENSOR_LOCK(sensor);

    for (thnum = IPMI_LOWER_NON_CRITICAL;
	 thnum <= IPMI_UPPER_NON_RECOVERABLE;
	 thnum++)
    {
	th->vals[thnum].status = 1;
	rv = ipmi_sensor_convert_from_raw(sensor,
					  sensor->default_thresholds[thnum],
					  &(th->vals[thnum].val));
	if (rv)
	    goto out;
    }
 out:
    return rv;
}

static void
thresh_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    thresh_get_info_t *info = cb_data;
    unsigned char     cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t        cmd_msg;
    int               rv;

    if (sensor_done_check_rsp(sensor, err, NULL, 0, "thresh_get_start",
			      thresh_get_done_handler, info))
	return;
    
    if (sensor->threshold_access == IPMI_THRESHOLD_ACCESS_SUPPORT_FIXED) {
	int thnum;
	/* Thresholds are fixed, they cannot be read. */
	for (thnum = IPMI_LOWER_NON_CRITICAL;
	     thnum <= IPMI_UPPER_NON_RECOVERABLE;
	     thnum++)
	{
	    info->th.vals[thnum].status = 0;
	}
	thresh_get_done_handler(sensor, 0, info);
	return;
    }

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_THRESHOLD_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				  &cmd_msg, thresh_get, &(info->sdata), info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(thresh_get_start):"
		 " Error sending threshold get command: %x",
		 SENSOR_NAME(sensor), rv);
	thresh_get_done_handler(sensor, rv, info);
    }
}

static int
stand_ipmi_sensor_get_thresholds(ipmi_sensor_t             *sensor,
				 ipmi_sensor_thresholds_cb done,
				 void                      *cb_data)
{
    thresh_get_info_t *info;
    int               rv;
    
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (sensor->threshold_access == IPMI_THRESHOLD_ACCESS_SUPPORT_NONE)
	return ENOSYS;
    
    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, thresh_get_start, &(info->sdata), info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

typedef struct thresh_set_info_s
{
    ipmi_sensor_op_info_t sdata;
    ipmi_thresholds_t     th;
    ipmi_sensor_done_cb   done;
    void                  *cb_data;
} thresh_set_info_t;

static void thresh_set_done_handler(ipmi_sensor_t *sensor,
				    int           err,
				    void          *sinfo)
{
    thresh_set_info_t *info = sinfo;

    if (info->done)
	info->done(sensor, err, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(info);
}

static void
thresh_set(ipmi_sensor_t *sensor,
	   int           err,
	   ipmi_msg_t    *rsp,
	   void          *cb_data)
{
    thresh_set_info_t *info = cb_data;

    if (sensor_done_check_rsp(sensor, err, rsp, 1, "thresh_set",
			      thresh_set_done_handler, info))
	return;

    thresh_set_done_handler(sensor, 0, info);
}

static void
thresh_set_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    thresh_set_info_t  *info = cb_data;
    unsigned char      cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t         cmd_msg;
    int                rv;
    enum ipmi_thresh_e th;

    if (sensor_done_check_rsp(sensor, err, NULL, 0, "thresh_set_start",
			      thresh_set_done_handler, info))
	return;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_SET_SENSOR_THRESHOLD_CMD;
    cmd_msg.data_len = 8;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    cmd_data[1] = 0;
    for (th=IPMI_LOWER_NON_CRITICAL; th<=IPMI_UPPER_NON_RECOVERABLE; th++) {
	int val;
	if (info->th.vals[th].status) {
	    cmd_data[1] |= (1 << th);
	    rv = ipmi_sensor_convert_to_raw(sensor,
					    ROUND_NORMAL,
					    info->th.vals[th].val,
					    &val);
	    if (rv) {
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "%ssensor.c(thresh_set_start):"
			 "Error converting threshold to raw: %x",
			 SENSOR_NAME(sensor), rv);
		thresh_set_done_handler(sensor, rv, info);
		return;
	    }
	} else {
	    val = 0;
	}
	cmd_data[th+2] = val;
    }

    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				  &cmd_msg, thresh_set, &(info->sdata), info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(thresh_set_start):"
		 "Error sending thresholds set command: %x",
		 SENSOR_NAME(sensor), rv);
	thresh_set_done_handler(sensor, rv, info);
    }
}

static int
stand_ipmi_sensor_set_thresholds(ipmi_sensor_t       *sensor,
				 ipmi_thresholds_t   *thresholds,
				 ipmi_sensor_done_cb done,
				 void                *cb_data)
{
    thresh_set_info_t *info;
    int               rv;
    
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (sensor->threshold_access != IPMI_THRESHOLD_ACCESS_SUPPORT_SETTABLE)
	return ENOSYS;
    
    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->th = *thresholds;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, thresh_set_start, &(info->sdata), info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

typedef struct reading_get_info_s
{
    ipmi_sensor_op_info_t      sdata;
    ipmi_sensor_reading_cb     done;
    void                       *cb_data;
    ipmi_states_t              states;
    enum ipmi_value_present_e  value_present;
    double                     raw_val;
    double                     cooked_val;
} reading_get_info_t;

static void reading_get_done_handler(ipmi_sensor_t *sensor,
				     int           err,
				     void          *sinfo)
{
    reading_get_info_t *info = sinfo;

    if (info->done)
	info->done(sensor, err, info->value_present,
		   info->raw_val, info->cooked_val, &info->states,
		   info->cb_data);
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(info);
}

static void
reading_get(ipmi_sensor_t *sensor,
	    int           err,
	    ipmi_msg_t    *rsp,
	    void          *rsp_data)
{
    reading_get_info_t        *info = rsp_data;
    int                       rv;

    if (sensor_done_check_rsp(sensor, err, rsp, 3, "reading_get",
			      reading_get_done_handler, info))
	return;

    info->raw_val = rsp->data[1];
    if (sensor->analog_data_format != IPMI_ANALOG_DATA_FORMAT_NOT_ANALOG) {
	rv = ipmi_sensor_convert_from_raw(sensor,
					  info->raw_val,
					  &info->cooked_val);
	if (rv)
	    info->value_present = IPMI_RAW_VALUE_PRESENT;
	else
	    info->value_present = IPMI_BOTH_VALUES_PRESENT;
    } else {
	info->value_present = IPMI_NO_VALUES_PRESENT;
    }

    info->states.__event_messages_enabled = (rsp->data[2] >> 7) & 1;
    info->states.__sensor_scanning_enabled = (rsp->data[2] >> 6) & 1;
    info->states.__initial_update_in_progress = (rsp->data[2] >> 5) & 1;
    if (rsp->data_len >= 4)
	info->states.__states = rsp->data[3];

    reading_get_done_handler(sensor, 0, info);
}

static void
reading_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    reading_get_info_t *info = cb_data;
    unsigned char      cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t         cmd_msg;
    int                rv;

    if (sensor_done_check_rsp(sensor, err, NULL, 0, "reading_get_start",
			      reading_get_done_handler, info))
	return;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_READING_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				  &cmd_msg, reading_get,
				  &(info->sdata), info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssensor.c(reading_get_start):"
		 "Error sending reading get command: %x",
		 SENSOR_NAME(sensor), rv);
	reading_get_done_handler(sensor, rv, info);
    }
}

static int
stand_ipmi_sensor_get_reading(ipmi_sensor_t          *sensor,
			      ipmi_sensor_reading_cb done,
			      void                   *cb_data)
{
    reading_get_info_t *info;
    int                rv;
    
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;
    if (!sensor->readable)
	return ENOSYS;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    info->value_present = IPMI_NO_VALUES_PRESENT;
    info->raw_val = 0;
    info->cooked_val = 0.0;
    ipmi_init_states(&info->states);
    rv = ipmi_sensor_add_opq(sensor, reading_get_start, &(info->sdata), info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}


typedef struct states_get_info_s
{
    ipmi_sensor_op_info_t sdata;
    ipmi_sensor_states_cb done;
    void                  *cb_data;
    ipmi_states_t         states;
} states_get_info_t;

static void states_get_done_handler(ipmi_sensor_t *sensor,
				    int           err,
				    void          *sinfo)
{
    states_get_info_t *info = sinfo;

    if (info->done)
	info->done(sensor, err, &info->states, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(info);
}

static void
states_get(ipmi_sensor_t *sensor,
	   int           err,
	   ipmi_msg_t    *rsp,
	   void          *cb_data)
{
    states_get_info_t *info = cb_data;

    if (sensor_done_check_rsp(sensor, err, rsp, 3, "states_get",
			      states_get_done_handler, info))
	return;

    info->states.__event_messages_enabled = (rsp->data[2] >> 7) & 1;
    info->states.__sensor_scanning_enabled = (rsp->data[2] >> 6) & 1;
    info->states.__initial_update_in_progress = (rsp->data[2] >> 5) & 1;

    if (rsp->data_len >= 4)
	info->states.__states |= rsp->data[3];
    if (rsp->data_len >= 5)
	info->states.__states |= rsp->data[4] << 8;

    states_get_done_handler(sensor, 0, info);
}

static void
states_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    states_get_info_t *info = cb_data;
    unsigned char     cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t        cmd_msg;
    int               rv;

    if (sensor_done_check_rsp(sensor, err, NULL, 0, "states_get_start",
			      states_get_done_handler, info))
	return;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_READING_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->send_lun,
				  &cmd_msg, states_get,
				  &(info->sdata), info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sstates.c(states_get_start):"
		 " Error sending states get command: %x",
		 SENSOR_NAME(sensor), rv);
	states_get_done_handler(sensor, rv, info);
    }
}

static int
stand_ipmi_sensor_get_states(ipmi_sensor_t         *sensor,
			     ipmi_sensor_states_cb done,
			     void                  *cb_data)
{
    states_get_info_t *info;
    int               rv;
    
    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have states. */
	return ENOSYS;
    if (!sensor->readable)
	return ENOSYS;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    ipmi_init_states(&info->states);
    rv = ipmi_sensor_add_opq(sensor, states_get_start, &(info->sdata), info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

/***********************************************************************
 *
 * Various data conversion stuff.
 *
 **********************************************************************/

static double c_linear(double val)
{
    return val;
}

static double c_log2(double val)
{
    return log(val) / 0.69314718 /* log(2) */;
}

static double c_exp10(double val)
{
    return pow(10.0, val);
}

static double c_exp2(double val)
{
    return pow(2.0, val);
}

static double c_1_over_x(double val)
{
    return 1.0 / val;
}

static double c_sqr(double val)
{
    return pow(val, 2.0);
}

static double c_cube(double val)
{
    return pow(val, 3.0);
}

static double c_1_over_cube(double val)
{
    return 1.0 / pow(val, 3.0);
}

typedef double (*linearizer)(double val);
static linearizer linearize[12] =
{
    c_linear,
    log,
    log10,
    c_log2,
    exp,
    c_exp10,
    c_exp2,
    c_1_over_x,
    c_sqr,
    c_cube,
    sqrt,
    c_1_over_cube
};

static int
sign_extend(int m, int bits)
{
    if (m & (1 << (bits-1)))
	return m | (-1 << bits);
    else
	return m & (~(-1 << bits));
}

static int
stand_ipmi_sensor_convert_from_raw(ipmi_sensor_t *sensor,
				   int           val,
				   double        *result)
{
    double m, b, b_exp, r_exp, fval;
    linearizer c_func;

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (sensor->linearization == IPMI_LINEARIZATION_NONLINEAR)
	c_func = c_linear;
    else if (sensor->linearization <= 11)
	c_func = linearize[sensor->linearization];
    else
	return EINVAL;

    val &= 0xff;

    m = sensor->conv[val].m;
    b = sensor->conv[val].b;
    r_exp = sensor->conv[val].r_exp;
    b_exp = sensor->conv[val].b_exp;

    switch(sensor->analog_data_format) {
	case IPMI_ANALOG_DATA_FORMAT_UNSIGNED:
	    fval = val;
	    break;
	case IPMI_ANALOG_DATA_FORMAT_1_COMPL:
	    val = sign_extend(val, 8);
	    if (val < 0)
		val += 1;
	    fval = val;
	    break;
	case IPMI_ANALOG_DATA_FORMAT_2_COMPL:
	    fval = sign_extend(val, 8);
	    break;
	default:
	    return EINVAL;
    }

    *result = c_func(((m * fval) + (b * pow(10, b_exp))) * pow(10, r_exp));
    return 0;
}

static int
stand_ipmi_sensor_convert_to_raw(ipmi_sensor_t     *sensor,
				 enum ipmi_round_e rounding,
				 double            val,
				 int               *result)
{
    double cval;
    int    lowraw, highraw, raw, maxraw, minraw, next_raw;
    int    rv;

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    switch(sensor->analog_data_format) {
	case IPMI_ANALOG_DATA_FORMAT_UNSIGNED:
	    lowraw = 0;
	    highraw = 255;
	    minraw = 0;
	    maxraw = 255;
	    next_raw = 128;
	    break;
	case IPMI_ANALOG_DATA_FORMAT_1_COMPL:
	    lowraw = -127;
	    highraw = 127;
	    minraw = -127;
	    maxraw = 127;
	    next_raw = 0;
	    break;
	case IPMI_ANALOG_DATA_FORMAT_2_COMPL:
	    lowraw = -128;
	    highraw = 127;
	    minraw = -128;
	    maxraw = 127;
	    next_raw = 0;
	    break;
	default:
	    return EINVAL;
    }

    /* We do a binary search for the right value.  Yuck, but I don't
       have a better plan that will work with non-linear sensors. */
    do {
	raw = next_raw;
	rv = ipmi_sensor_convert_from_raw(sensor, raw, &cval);
	if (rv)
	    return rv;

	if (cval < val) {
	    next_raw = ((highraw - raw) / 2) + raw;
	    lowraw = raw;
	} else {
	    next_raw = ((raw - lowraw) / 2) + lowraw;
	    highraw = raw;
	}
    } while (raw != next_raw);

    /* The above loop gets us to within 1 of what it should be, we
       have to look at rounding to make the final decision. */
    switch (rounding)
    {
	case ROUND_NORMAL:
	    if (val > cval) {
		if (raw < maxraw) {
		    double nval;
		    rv = ipmi_sensor_convert_from_raw(sensor, raw+1, &nval);
		    if (rv)
			return rv;
		    nval = cval + ((nval - cval) / 2.0);
		    if (val >= nval)
			raw++;
		}
	    } else {
		if (raw > minraw) {
		    double pval;
		    rv = ipmi_sensor_convert_from_raw(sensor, raw-1, &pval);
		    if (rv)
			return rv;
		    pval = pval + ((cval - pval) / 2.0);
		    if (val < pval)
			raw--;
		}
	    }
	    break;
	case ROUND_UP:
	    if ((val > cval) && (raw < maxraw)) {
		raw++;
	    }
	    break;
	case ROUND_DOWN:
	    if ((val < cval) && (raw > minraw)) {
		raw--;
	    }
	    break;
    }

    if (sensor->analog_data_format == IPMI_ANALOG_DATA_FORMAT_1_COMPL) {
	if (raw < 0)
	    raw -= 1;
    }

    *result = raw & 0xff;
    return 0;
}

static int
stand_ipmi_sensor_get_tolerance(ipmi_sensor_t *sensor,
				int           val,
				double        *tolerance)
{
    double m, r_exp, fval;
    linearizer c_func;

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (sensor->linearization == IPMI_LINEARIZATION_NONLINEAR)
	c_func = c_linear;
    else if (sensor->linearization <= 11)
	c_func = linearize[sensor->linearization];
    else
	return EINVAL;

    val &= 0xff;

    m = sensor->conv[val].m;
    r_exp = sensor->conv[val].r_exp;

    fval = sign_extend(val, 8);

    *tolerance = c_func(((m * fval) / 2.0) * pow(10, r_exp));
    return 0;
}

/* Returns accuracy as a percentage value. */
static int
stand_ipmi_sensor_get_accuracy(ipmi_sensor_t *sensor, int val, double *accuracy)
{
    double a, a_exp;

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    val &= 0xff;

    a = sensor->conv[val].accuracy;
    a_exp = sensor->conv[val].r_exp;

    *accuracy = (a * pow(10, a_exp)) / 100.0;
    return 0;
}

static const char *
stand_ipmi_sensor_reading_name_string(ipmi_sensor_t *sensor, int offset)
{
    return ipmi_get_reading_name(sensor->event_reading_type,
				 sensor->sensor_type,
				 offset);
}

/***********************************************************************
 *
 * The standard callback structure
 *
 **********************************************************************/

const ipmi_sensor_cbs_t ipmi_standard_sensor_cb =
{
    .ipmi_sensor_set_event_enables = stand_ipmi_sensor_set_event_enables,
    .ipmi_sensor_get_event_enables = stand_ipmi_sensor_get_event_enables,
    .ipmi_sensor_enable_events     = stand_ipmi_sensor_enable_events,
    .ipmi_sensor_disable_events    = stand_ipmi_sensor_disable_events,
    .ipmi_sensor_rearm             = stand_ipmi_sensor_rearm,

    .ipmi_sensor_convert_from_raw  = stand_ipmi_sensor_convert_from_raw,
    .ipmi_sensor_convert_to_raw    = stand_ipmi_sensor_convert_to_raw,
    .ipmi_sensor_get_accuracy      = stand_ipmi_sensor_get_accuracy,
    .ipmi_sensor_get_tolerance     = stand_ipmi_sensor_get_tolerance,
    .ipmi_sensor_get_hysteresis    = stand_ipmi_sensor_get_hysteresis,
    .ipmi_sensor_set_hysteresis    = stand_ipmi_sensor_set_hysteresis,
    .ipmi_sensor_set_thresholds    = stand_ipmi_sensor_set_thresholds,
    .ipmi_sensor_get_thresholds    = stand_ipmi_sensor_get_thresholds,
    .ipmi_sensor_get_reading       = stand_ipmi_sensor_get_reading,

    .ipmi_sensor_get_states        = stand_ipmi_sensor_get_states,
    .ipmi_sensor_reading_name_string = stand_ipmi_sensor_reading_name_string,
};

void
ipmi_sensor_get_callbacks(ipmi_sensor_t *sensor, ipmi_sensor_cbs_t *cbs)
{
    *cbs = sensor->cbs;
}

void
ipmi_sensor_set_callbacks(ipmi_sensor_t *sensor, ipmi_sensor_cbs_t *cbs)
{
    sensor->cbs = *cbs;
}

/***********************************************************************
 *
 * Polymorphic calls to the callback handlers.
 *
 **********************************************************************/

int
ipmi_sensor_set_event_enables(ipmi_sensor_t         *sensor,
			      ipmi_event_state_t    *states,
			      ipmi_sensor_done_cb   done,
			      void                  *cb_data)
{
    if (!sensor_ok_to_use(sensor))
	return ECANCELED;
      
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_set_event_enables)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_set_event_enables(sensor,
						     states,
						     done,
						     cb_data);
}

int
ipmi_sensor_enable_events(ipmi_sensor_t         *sensor,
			  ipmi_event_state_t    *states,
			  ipmi_sensor_done_cb   done,
			  void                  *cb_data)
{
    if (!sensor_ok_to_use(sensor))
	return ECANCELED;
      
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_enable_events)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_enable_events(sensor,
						 states,
						 done,
						 cb_data);
}

int
ipmi_sensor_disable_events(ipmi_sensor_t         *sensor,
			   ipmi_event_state_t    *states,
			   ipmi_sensor_done_cb   done,
			   void                  *cb_data)
{
    if (!sensor_ok_to_use(sensor))
	return ECANCELED;
      
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_disable_events)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_disable_events(sensor,
						  states,
						  done,
						  cb_data);
}

int
ipmi_sensor_rearm(ipmi_sensor_t       *sensor,
		  int                 global_enable,
		  ipmi_event_state_t  *state,
		  ipmi_sensor_done_cb done,
		  void                *cb_data)
{
    if (!sensor_ok_to_use(sensor))
	return ECANCELED;
      
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_rearm)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_rearm(sensor,
					 global_enable,
					 state,
					 done,
					 cb_data);
}

int
ipmi_sensor_get_event_enables(ipmi_sensor_t                *sensor,
			      ipmi_sensor_event_enables_cb done,
			      void                         *cb_data)
{
    if (!sensor_ok_to_use(sensor))
	return ECANCELED;
      
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_get_event_enables)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_get_event_enables(sensor,
						     done,
						     cb_data);
}

int
ipmi_sensor_get_hysteresis(ipmi_sensor_t             *sensor,
			   ipmi_sensor_hysteresis_cb done,
			   void                      *cb_data)
{
    if (!sensor_ok_to_use(sensor))
	return ECANCELED;
      
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_get_hysteresis)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_get_hysteresis(sensor,
						  done,
						  cb_data);
}

int
ipmi_sensor_set_hysteresis(ipmi_sensor_t       *sensor,
			   unsigned int        positive_hysteresis,
			   unsigned int        negative_hysteresis,
			   ipmi_sensor_done_cb done,
			   void                *cb_data)
{
    if (!sensor_ok_to_use(sensor))
	return ECANCELED;
      
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_set_hysteresis)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_set_hysteresis(sensor,
						  positive_hysteresis,
						  negative_hysteresis,
						  done,
						  cb_data);
}

int
ipmi_sensor_get_thresholds(ipmi_sensor_t             *sensor,
			   ipmi_sensor_thresholds_cb done,
			   void                      *cb_data)
{
    if (!sensor_ok_to_use(sensor))
	return ECANCELED;
      
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_get_thresholds)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_get_thresholds(sensor, done, cb_data);
}

int
ipmi_sensor_set_thresholds(ipmi_sensor_t       *sensor,
			   ipmi_thresholds_t   *thresholds,
			   ipmi_sensor_done_cb done,
			   void                *cb_data)
{
    if (!sensor_ok_to_use(sensor))
	return ECANCELED;
      
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_set_thresholds)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_set_thresholds(sensor, thresholds,
						  done, cb_data);
}

int
ipmi_sensor_get_reading(ipmi_sensor_t          *sensor,
			ipmi_sensor_reading_cb done,
			void                   *cb_data)
{
    if (!sensor_ok_to_use(sensor))
	return ECANCELED;
      
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_get_reading)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_get_reading(sensor, done, cb_data);
}

int
ipmi_sensor_get_states(ipmi_sensor_t         *sensor,
		       ipmi_sensor_states_cb done,
		       void                  *cb_data)
{
    if (!sensor_ok_to_use(sensor))
	return ECANCELED;
      
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_get_states)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_get_states(sensor, done, cb_data);
}

const char *
ipmi_sensor_reading_name_string(ipmi_sensor_t *sensor, int offset)
{
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_reading_name_string)
	return NULL;
    return sensor->cbs.ipmi_sensor_reading_name_string(sensor, offset);
}

int
ipmi_sensor_convert_from_raw(ipmi_sensor_t *sensor,
			     int           val,
			     double        *result)
{
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_convert_from_raw)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_convert_from_raw(sensor, val, result);
}

int
ipmi_sensor_convert_to_raw(ipmi_sensor_t     *sensor,
			   enum ipmi_round_e rounding,
			   double            val,
			   int               *result)
{
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_convert_to_raw)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_convert_to_raw(sensor,
						  rounding,
						  val,
						  result);
}

int
ipmi_sensor_get_tolerance(ipmi_sensor_t *sensor, int val, double *tolerance)
{
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_get_tolerance)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_get_tolerance(sensor, val, tolerance);
}

/* Returns accuracy as a percentage value. */
int
ipmi_sensor_get_accuracy(ipmi_sensor_t *sensor, int val, double *accuracy)
{
    CHECK_SENSOR_LOCK(sensor);

    if (!sensor->cbs.ipmi_sensor_get_accuracy)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_get_accuracy(sensor, val, accuracy);
}


/***********************************************************************
 *
 * Convenience functions that take ids.
 *
 **********************************************************************/

typedef struct sensor_id_events_enable_set_s
{
    ipmi_event_state_t    *states;
    ipmi_sensor_done_cb   done;
    void                  *cb_data;
    int                   rv;
} sensor_id_events_enable_set_t;

static void
sensor_id_set_event_enables_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_id_events_enable_set_t *info = cb_data;

    info->rv = ipmi_sensor_set_event_enables(sensor, info->states,
					     info->done, info->cb_data);
}

int
ipmi_sensor_id_set_event_enables(ipmi_sensor_id_t      sensor_id,
				 ipmi_event_state_t    *states,
				 ipmi_sensor_done_cb   done,
				 void                  *cb_data)
{
    sensor_id_events_enable_set_t info;
    int                           rv;

    info.states = states;
    info.done = done;
    info.cb_data = cb_data;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_set_event_enables_cb,
				&info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct sensor_id_events_enable_s
{
    ipmi_event_state_t    *states;
    ipmi_sensor_done_cb   done;
    void                  *cb_data;
    int                   rv;
} sensor_id_events_enable_t;

static void
sensor_id_enable_events_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_id_events_enable_t *info = cb_data;

    info->rv = ipmi_sensor_enable_events(sensor,
					 info->states,
					 info->done,
					 info->cb_data);
}

int
ipmi_sensor_id_enable_events(ipmi_sensor_id_t      sensor_id,
			     ipmi_event_state_t    *states,
			     ipmi_sensor_done_cb   done,
			     void                  *cb_data)
{
    sensor_id_events_enable_t info;
    int                       rv;

    info.states = states;
    info.done = done;
    info.cb_data = cb_data;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_enable_events_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct sensor_id_events_disable_s
{
    ipmi_event_state_t    *states;
    ipmi_sensor_done_cb   done;
    void                  *cb_data;
    int                   rv;
} sensor_id_events_disable_t;

static void
sensor_id_disable_events_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_id_events_disable_t *info = cb_data;

    info->rv = ipmi_sensor_disable_events(sensor,
					  info->states,
					  info->done,
					  info->cb_data);
}

int
ipmi_sensor_id_disable_events(ipmi_sensor_id_t      sensor_id,
			      ipmi_event_state_t    *states,
			      ipmi_sensor_done_cb   done,
			      void                  *cb_data)
{
    sensor_id_events_enable_t info;
    int                       rv;

    info.states = states;
    info.done = done;
    info.cb_data = cb_data;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_disable_events_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct sensor_id_events_enable_get_s
{
    ipmi_sensor_event_enables_cb done;
    void                         *cb_data;
    int                          rv;
} sensor_id_events_enable_get_t;

static void
sensor_id_get_event_enables_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_id_events_enable_get_t *info = cb_data;

    info->rv = ipmi_sensor_get_event_enables(sensor,
					     info->done,
					     info->cb_data);
}

int
ipmi_sensor_id_get_event_enables(ipmi_sensor_id_t             sensor_id,
				 ipmi_sensor_event_enables_cb done,
				 void                         *cb_data)
{
    sensor_id_events_enable_get_t info;
    int                           rv;

    info.done = done;
    info.cb_data = cb_data;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_get_event_enables_cb,
				&info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct sensor_id_rearm_s
{
    int                 global_enable;
    ipmi_event_state_t  *state;
    ipmi_sensor_done_cb done;
    void                *cb_data;
    int                 rv;
} sensor_id_rearm_t;

static void
sensor_id_rearm_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_id_rearm_t *info = cb_data;

    info->rv = ipmi_sensor_rearm(sensor,
				 info->global_enable,
				 info->state,
				 info->done,
				 info->cb_data);
}

int
ipmi_sensor_id_rearm(ipmi_sensor_id_t    sensor_id,
		     int                 global_enable,
		     ipmi_event_state_t  *state,
		     ipmi_sensor_done_cb done,
		     void                *cb_data)
{
    sensor_id_rearm_t info;
    int               rv;

    info.global_enable = global_enable;
    info.state = state;
    info.done = done;
    info.cb_data = cb_data;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_rearm_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct sensor_id_get_hysteresis_s
{
    ipmi_sensor_hysteresis_cb done;
    void                      *cb_data;
    int                       rv;
} sensor_id_get_hysteresis_t;

static void
sensor_id_get_hysteresis_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_id_get_hysteresis_t *info = cb_data;

    info->rv = ipmi_sensor_get_hysteresis(sensor,
					  info->done,
					  info->cb_data);
}

int
ipmi_sensor_id_get_hysteresis(ipmi_sensor_id_t          sensor_id,
			      ipmi_sensor_hysteresis_cb done,
			      void                      *cb_data)
{
    sensor_id_get_hysteresis_t info;
    int                        rv;

    info.done = done;
    info.cb_data = cb_data;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_get_hysteresis_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct sensor_id_set_hysteresis_s
{
    unsigned int        positive_hysteresis;
    unsigned int        negative_hysteresis;
    ipmi_sensor_done_cb done;
    void                *cb_data;
    int                 rv;
} sensor_id_set_hysteresis_t;

static void
sensor_id_set_hysteresis_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_id_set_hysteresis_t *info = cb_data;

    info->rv = ipmi_sensor_set_hysteresis(sensor,
					  info->positive_hysteresis,
					  info->negative_hysteresis,
					  info->done,
					  info->cb_data);
}

int
ipmi_sensor_id_set_hysteresis(ipmi_sensor_id_t    sensor_id,
			      unsigned int        positive_hysteresis,
			      unsigned int        negative_hysteresis,
			      ipmi_sensor_done_cb done,
			      void                *cb_data)
{
    sensor_id_set_hysteresis_t info;
    int                        rv;

    info.positive_hysteresis = positive_hysteresis;
    info.negative_hysteresis = negative_hysteresis;
    info.done = done;
    info.cb_data = cb_data;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_set_hysteresis_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct sensor_id_thresholds_set_s
{
    ipmi_thresholds_t   *thresholds;
    ipmi_sensor_done_cb done;
    void                *cb_data;
    int                 rv;
} sensor_id_thresholds_set_t;

static void
sensor_id_set_thresholds_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_id_thresholds_set_t *info = cb_data;

    info->rv = ipmi_sensor_set_thresholds(sensor,
					  info->thresholds,
					  info->done,
					  info->cb_data);
}

int
ipmi_sensor_id_set_thresholds(ipmi_sensor_id_t    sensor_id,
			      ipmi_thresholds_t   *thresholds,
			      ipmi_sensor_done_cb done,
			      void                *cb_data)
{
    sensor_id_thresholds_set_t info;
    int               rv;

    info.thresholds = thresholds;
    info.done = done;
    info.cb_data = cb_data;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_set_thresholds_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct sensor_id_thresholds_get_s
{
    ipmi_sensor_thresholds_cb done;
    void                      *cb_data;
    int                       rv;
} sensor_id_thresholds_get_t;

static void
sensor_id_get_thresholds_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_id_thresholds_get_t *info = cb_data;

    info->rv = ipmi_sensor_get_thresholds(sensor,
					  info->done,
					  info->cb_data);
}

int
ipmi_sensor_id_get_thresholds(ipmi_sensor_id_t          sensor_id,
			      ipmi_sensor_thresholds_cb done,
			      void                      *cb_data)
{
    sensor_id_thresholds_get_t info;
    int                        rv;

    info.done = done;
    info.cb_data = cb_data;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_get_thresholds_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct sensor_id_reading_get_s
{
    ipmi_sensor_reading_cb done;
    void                   *cb_data;
    int                    rv;
} sensor_id_reading_get_t;

static void
sensor_id_get_reading_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_id_reading_get_t *info = cb_data;
    
    info->rv = ipmi_sensor_get_reading(sensor,
				       info->done,
				       info->cb_data);
}

int
ipmi_sensor_id_get_reading(ipmi_sensor_id_t       sensor_id,
			   ipmi_sensor_reading_cb done,
			   void                   *cb_data)
{
    sensor_id_reading_get_t info;
    int                     rv;

    info.done = done;
    info.cb_data = cb_data;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_get_reading_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

typedef struct sensor_id_states_get_s
{
    ipmi_sensor_states_cb done;
    void                  *cb_data;
    int                   rv;
} sensor_id_states_get_t;

static void
sensor_id_get_states_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    sensor_id_states_get_t *info = cb_data;

    info->rv = ipmi_sensor_get_states(sensor,
				      info->done,
				      info->cb_data);
}

int
ipmi_sensor_id_get_states(ipmi_sensor_id_t      sensor_id,
			  ipmi_sensor_states_cb done,
			  void                  *cb_data)
{
    sensor_id_states_get_t info;
    int                    rv;

    info.done = done;
    info.cb_data = cb_data;
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_id_get_states_cb, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}


#ifdef IPMI_CHECK_LOCKS
void
__ipmi_check_sensor_lock(const ipmi_sensor_t *sensor)
{
    if (!sensor)
	return;

    if (!DEBUG_LOCKS)
	return;

    CHECK_ENTITY_LOCK(sensor->entity);
    CHECK_MC_LOCK(sensor->mc);

    if (sensor->usecount == 0)
	ipmi_report_lock_error(ipmi_domain_get_os_hnd(sensor->domain),
			       "sensor not locked when it should have been");
}
#endif

/***********************************************************************
 *
 * Cruft
 *
 **********************************************************************/

int
ipmi_sensor_threshold_assertion_event_supported(
    ipmi_sensor_t               *sensor,
    enum ipmi_thresh_e          event,
    enum ipmi_event_value_dir_e dir,
    int                         *val)
{
    int idx;

    CHECK_SENSOR_LOCK(sensor);

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    idx = (event * 2) + dir;
    if (idx > 11)
	return EINVAL;

    *val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask1, idx);
    return 0;
}

int
ipmi_sensor_threshold_deassertion_event_supported(
    ipmi_sensor_t               *sensor,
    enum ipmi_thresh_e          event,
    enum ipmi_event_value_dir_e dir,
    int                         *val)
{
    int idx;

    CHECK_SENSOR_LOCK(sensor);

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    idx = (event * 2) + dir;
    if (idx > 11)
	return 0;

    *val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask2, idx);
    return 0;
}

int
ipmi_sensor_discrete_assertion_event_supported(ipmi_sensor_t *sensor,
					       int           event,
					       int           *val)
{
    CHECK_SENSOR_LOCK(sensor);

    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have events. */
	return ENOSYS;

    if (event > 14)
	return EINVAL;

    *val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask1, event);
    return 0;
}

int
ipmi_sensor_discrete_deassertion_event_supported(ipmi_sensor_t *sensor,
						 int           event,
						 int           *val)
{
    CHECK_SENSOR_LOCK(sensor);

    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have events. */
	return ENOSYS;

    if (event > 14)
	return EINVAL;

    *val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask2, event);
    return 0;
}

int
ipmi_sensor_events_enable_get(ipmi_sensor_t                *sensor,
			      ipmi_sensor_event_enables_cb done,
			      void                         *cb_data)
{
    return ipmi_sensor_get_event_enables(sensor, done, cb_data);
}

int
ipmi_sensor_events_disable(ipmi_sensor_t         *sensor,
			   ipmi_event_state_t    *states,
			   ipmi_sensor_done_cb   done,
			   void                  *cb_data)
{
    return ipmi_sensor_disable_events(sensor, states, done, cb_data);
}

int
ipmi_sensor_events_enable(ipmi_sensor_t         *sensor,
			  ipmi_event_state_t    *states,
			  ipmi_sensor_done_cb   done,
			  void                  *cb_data)
{
    return ipmi_sensor_enable_events(sensor, states, done, cb_data);
}

int ipmi_sensor_events_enable_set(ipmi_sensor_t         *sensor,
				  ipmi_event_state_t    *states,
				  ipmi_sensor_done_cb   done,
				  void                  *cb_data)
{
    return ipmi_sensor_set_event_enables(sensor, states, done, cb_data);
}

int
ipmi_sensor_id_events_enable_set(ipmi_sensor_id_t      sensor_id,
				 ipmi_event_state_t    *states,
				 ipmi_sensor_done_cb   done,
				 void                  *cb_data)
{
    return ipmi_sensor_id_set_event_enables(sensor_id, states, done, cb_data);
}

int
ipmi_sensor_id_events_enable(ipmi_sensor_id_t      sensor_id,
			     ipmi_event_state_t    *states,
			     ipmi_sensor_done_cb   done,
			     void                  *cb_data)
{
    return ipmi_sensor_id_enable_events(sensor_id, states, done, cb_data);
}

int
ipmi_sensor_id_events_disable(ipmi_sensor_id_t      sensor_id,
			      ipmi_event_state_t    *states,
			      ipmi_sensor_done_cb   done,
			      void                  *cb_data)
{
    return ipmi_sensor_id_disable_events(sensor_id, states, done, cb_data);
}

int
ipmi_sensor_id_events_enable_get(ipmi_sensor_id_t             sensor_id,
				 ipmi_sensor_event_enables_cb done,
				 void                         *cb_data)
{
    return ipmi_sensor_id_get_event_enables(sensor_id, done, cb_data);
}

int
ipmi_states_get(ipmi_sensor_t         *sensor,
		ipmi_sensor_states_cb done,
		void                  *cb_data)
{
    return ipmi_sensor_get_states(sensor, done, cb_data);
}

int
ipmi_reading_get(ipmi_sensor_t          *sensor,
		 ipmi_sensor_reading_cb done,
		 void                   *cb_data)
{
    return ipmi_sensor_get_reading(sensor, done, cb_data);
}

int
ipmi_thresholds_set(ipmi_sensor_t       *sensor,
		    ipmi_thresholds_t   *thresholds,
		    ipmi_sensor_done_cb done,
		    void                *cb_data)
{
    return ipmi_sensor_set_thresholds(sensor, thresholds, done, cb_data);
}

int
ipmi_thresholds_get(ipmi_sensor_t             *sensor,
		    ipmi_sensor_thresholds_cb done,
		    void                      *cb_data)
{
    return ipmi_sensor_get_thresholds(sensor, done, cb_data);
}

int
ipmi_sensor_id_thresholds_set(ipmi_sensor_id_t    sensor_id,
			      ipmi_thresholds_t   *thresholds,
			      ipmi_sensor_done_cb done,
			      void                *cb_data)
{
    return ipmi_sensor_id_set_thresholds(sensor_id, thresholds, done, cb_data);
}

int
ipmi_sensor_id_thresholds_get(ipmi_sensor_id_t          sensor_id,
			      ipmi_sensor_thresholds_cb done,
			      void                      *cb_data)
{
    return ipmi_sensor_id_get_thresholds(sensor_id, done, cb_data);
}

int
ipmi_sensor_id_reading_get(ipmi_sensor_id_t       sensor_id,
			   ipmi_sensor_reading_cb done,
			   void                   *cb_data)
{
    return ipmi_sensor_id_get_reading(sensor_id, done, cb_data);
}

int
ipmi_sensor_id_states_get(ipmi_sensor_id_t      sensor_id,
			  ipmi_sensor_states_cb done,
			  void                  *cb_data)
{
    return ipmi_sensor_id_get_states(sensor_id, done, cb_data);
}

int
ipmi_discrete_event_readable(ipmi_sensor_t *sensor,
			     int           event,
			     int           *val)
{
    CHECK_SENSOR_LOCK(sensor);

    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have events. */
	return ENOSYS;

    if (event > 14)
	return EINVAL;

    *val = IPMI_SENSOR_GET_MASK_BIT(sensor->mask3, event);
    return 0;
}
