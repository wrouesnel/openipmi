/*
 * sensor.c
 *
 * MontaVista IPMI code for handling sensors
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
#include <math.h>

#include <ipmi/ipmiif.h>
#include <ipmi/ipmi_sdr.h>
#include <ipmi/ipmi_sensor.h>
#include <ipmi/ipmi_entity.h>
#include <ipmi/ipmi_msgbits.h>
#include <ipmi/ipmi_mc.h>
#include <ipmi/ipmi_err.h>
#include <ipmi/ipmi_int.h>
#include "ilist.h"
#include "opq.h"

struct ipmi_sensor_info_s
{
    int                      destroyed;

    /* Indexed by LUN and sensor # */
    ipmi_sensor_t            **(sensors_by_idx[5]);
    /* Size of above sensor array, per LUN.  This will be 0 if the
       LUN has no sensors. */
    int                      idx_size[5];
    /* In the above two, the 5th index is for non-standard sensors. */

    opq_t *sensor_wait_q;
    int  wait_err;
};

#define SENSOR_ID_LEN 32
struct ipmi_sensor_s
{
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

    int           destroyed;

    unsigned char owner;
    unsigned char channel;
    unsigned char lun;
    unsigned char num;

    unsigned char entity_id;
    unsigned char entity_instance;

    unsigned char entity_instance_logical : 1;
    unsigned int  sensor_init_scanning : 1;
    unsigned int  sensor_init_events : 1;
    unsigned int  sensor_init_thresholds : 1;
    unsigned int  sensor_init_hysteresis : 1;
    unsigned int  sensor_init_type : 1;
    unsigned int  sensor_init_pu_events : 1;
    unsigned int  sensor_init_pu_scanning : 1;
    unsigned int  ignore_if_no_entity : 1;
    unsigned int  supports_rearm : 1;
    unsigned int  hot_swap_requester : 1;
    unsigned int  hysteresis_support : 2;
    unsigned int  threshold_access : 2;
    unsigned int  event_support : 2;

    unsigned char sensor_type;

    unsigned char event_reading_type;

    unsigned char mask1[16];
    unsigned char mask2[16];
    unsigned char mask3[16];

    unsigned int  analog_data_format : 2;

    unsigned int  rate_unit : 3;

    unsigned int  modifier_unit_use : 2;

    unsigned int  percentage : 1;

    unsigned char base_unit;
    unsigned char modifier_unit;

    unsigned char linearization;

    struct {
	unsigned int m : 10;
	unsigned int tolerance : 6;
	unsigned int b : 10;
	unsigned int r_exp : 4;
	unsigned int accuracy_exp : 2;
	unsigned int accuracy : 10;
	unsigned int b_exp : 4;
    } conv[256];

    unsigned int  normal_min_specified : 1;
    unsigned int  normal_max_specified : 1;
    unsigned int  nominal_reading_specified : 1;

    unsigned char nominal_reading;
    unsigned char normal_max;
    unsigned char normal_min;
    unsigned char sensor_max;
    unsigned char sensor_min;
    unsigned char upper_non_recoverable_threshold;
    unsigned char upper_critical_threshold;
    unsigned char upper_non_critical_threshold;
    unsigned char lower_non_recoverable_threshold;
    unsigned char lower_critical_threshold;
    unsigned char lower_non_critical_threshold;
    unsigned char positive_going_threshold_hysteresis;
    unsigned char negative_going_threshold_hysteresis;

    unsigned char oem1;

    char id[SENSOR_ID_LEN+1]; /* The ID from the device SDR. */

    char *sensor_type_string;
    char *event_reading_type_string;
    char *rate_unit_string;
    char *base_unit_string;
    char *modifier_unit_string;

    ipmi_sensor_threshold_event_handler_cb threshold_event_handler;
    ipmi_sensor_discrete_event_handler_cb  discrete_event_handler;
    void                         *cb_data;

    opq_t *waitq;
    ipmi_event_state_t event_state;

    /* Polymorphic functions. */
    ipmi_sensor_cbs_t cbs;

    /* OEM info */
    void *oem_info;

    ipmi_sensor_destroy_cb destroy_handler;
    void                   *destroy_handler_cb_data;
};

ipmi_sensor_id_t
ipmi_sensor_convert_to_id(ipmi_sensor_t *sensor)
{
    ipmi_sensor_id_t val;
    ipmi_mc_id_t mc_val;
    
    mc_val = ipmi_mc_convert_to_id(sensor->mc);
    val.bmc = mc_val.bmc;
    val.mc_num = mc_val.mc_num;
    val.channel = mc_val.channel;
    val.lun = sensor->lun;
    val.sensor_num = sensor->num;

    return val;
}

int
ipmi_cmp_sensor_id(ipmi_sensor_id_t id1, ipmi_sensor_id_t id2)
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
    if (id1.sensor_num > id2.sensor_num)
	return 1;
    if (id1.sensor_num < id2.sensor_num)
	return -1;
    return 0;
}

typedef struct mc_cb_info_s
{
    ipmi_sensor_cb   handler;
    void             *cb_data;
    ipmi_sensor_id_t id;
    int              err;
} mc_cb_info_t;

static void
mc_cb(ipmi_mc_t *mc, void *cb_data)
{
    mc_cb_info_t       *info = cb_data;
    ipmi_sensor_info_t *sensors;
    
    ipmi_mc_entity_lock(info->id.bmc);
    sensors = ipmi_mc_get_sensors(mc);
    if (info->id.lun > 4)
	info->err = EINVAL;
    else if (info->id.sensor_num > sensors->idx_size[info->id.lun])
	info->err = EINVAL;
    else if (sensors->sensors_by_idx[info->id.lun][info->id.sensor_num]
	     == NULL)
	info->err = EINVAL;
    else
	info->handler(
	    sensors->sensors_by_idx[info->id.lun][info->id.sensor_num],
	    info->cb_data);
    ipmi_mc_entity_unlock(info->id.bmc);
}

int
ipmi_sensor_pointer_cb(ipmi_sensor_id_t id,
		       ipmi_sensor_cb   handler,
		       void             *cb_data)
{
    int          rv;
    ipmi_mc_id_t mc_id;
    mc_cb_info_t info;

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

static void
sensor_final_destroy(ipmi_sensor_t *sensor)
{
    if (sensor->destroy_handler)
	sensor->destroy_handler(sensor, sensor->destroy_handler_cb_data);

    opq_destroy(sensor->waitq);
    free(sensor);
}

static void
sensor_opq_ready2(ipmi_sensor_t *sensor, void *cb_data)
{
    ipmi_sensor_op_info_t *info = cb_data;
    if (info->__handler)
	info->__handler(sensor, 0, info->__cb_data);
}

static void
sensor_opq_ready(void *cb_data, int shutdown)
{
    ipmi_sensor_op_info_t *info = cb_data;
    int                   rv;

    if (shutdown) {
	if (info->__handler)
	    info->__handler(info->__sensor, ECANCELED, info->__cb_data);
	return;
    }

    rv = ipmi_sensor_pointer_cb(info->__sensor_id, sensor_opq_ready2, info);
    if (rv)
	if (info->__handler)
	    info->__handler(info->__sensor, rv, info->__cb_data);
}

int
ipmi_sensor_add_opq(ipmi_sensor_t         *sensor,
		    ipmi_sensor_op_cb     handler,
		    ipmi_sensor_op_info_t *info,
		    void                  *cb_data)
{
    info->__sensor = sensor;
    info->__sensor_id = ipmi_sensor_convert_to_id(sensor);
    info->__cb_data = cb_data;
    info->__handler = handler;
    if (!opq_new_op(sensor->waitq, sensor_opq_ready, info, 0))
	return ENOMEM;
    return 0;
}

void
ipmi_sensor_opq_done(ipmi_sensor_t *sensor)
{
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

    if (sensor->destroyed) {
	if (info->__rsp_handler)
	    info->__rsp_handler(sensor, ECANCELED, NULL, info->__cb_data);
	sensor_final_destroy(sensor);
	return;
    }

    if (!mc) {
	if (info->__rsp_handler)
	    info->__rsp_handler(sensor, ENXIO, rsp, info->__cb_data);
	return;
    }

    /* Call the next stage with the lock held. */
    info->__rsp = rsp;
    rv = ipmi_sensor_pointer_cb(info->__sensor_id,
				sensor_rsp_handler2,
				info);
    if (rv) {
	if (info->__rsp_handler)
	    info->__rsp_handler(sensor, rv, NULL, info->__cb_data);
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

    info->__sensor = sensor;
    info->__sensor_id = ipmi_sensor_convert_to_id(sensor);
    info->__cb_data = cb_data;
    info->__rsp_handler = handler;
    rv = ipmi_send_command(mc, lun, msg, sensor_rsp_handler, info);
    return rv;
}

int
ipmi_sensor_send_command_addr(ipmi_mc_t             *bmc,
			      ipmi_sensor_t         *sensor,
			      ipmi_addr_t           *addr,
			      unsigned int          addr_len,
			      ipmi_msg_t            *msg,
			      ipmi_sensor_rsp_cb    handler,
			      ipmi_sensor_op_info_t *info,
			      void                  *cb_data)
{
    int rv;

    info->__sensor = sensor;
    info->__sensor_id = ipmi_sensor_convert_to_id(sensor);
    info->__cb_data = cb_data;
    info->__rsp_handler = handler;
    rv = ipmi_bmc_send_command_addr(bmc, addr, addr_len,
				    msg, sensor_rsp_handler, info);
    return rv;
}

int
ipmi_find_sensor(ipmi_mc_t *mc, int lun, int num,
		 ipmi_sensor_cb handler, void *cb_data)
{
    int                rv = 0;
    ipmi_sensor_info_t *sensors;

    if (lun > 4)
	return EINVAL;

    ipmi_mc_entity_lock(mc);
    sensors = ipmi_mc_get_sensors(mc);
    if (num >= sensors->idx_size[lun])
	rv = EINVAL;
    else if (sensors->sensors_by_idx[lun][num] == NULL)
	rv = EINVAL;
    else
	handler(sensors->sensors_by_idx[lun][num], cb_data);
    ipmi_mc_entity_unlock(mc);

    return rv;
}

int
ipmi_sensors_alloc(ipmi_mc_t *mc, ipmi_sensor_info_t **new_sensors)
{
    ipmi_sensor_info_t *sensors;
    int                i;

    sensors = malloc(sizeof(*sensors));
    if (!sensors)
	return ENOMEM;
    sensors->sensor_wait_q = opq_alloc(ipmi_mc_get_os_hnd(mc));
    if (! sensors->sensor_wait_q) {
	free(sensors);
	return ENOMEM;
    }

    sensors->destroyed = 0;
    for (i=0; i<5; i++) {
	sensors->sensors_by_idx[i] = NULL;
	sensors->idx_size[i] = 0;
    }

    *new_sensors = sensors;
    return 0;
}

int
ipmi_sensor_alloc_nonstandard(ipmi_sensor_t **new_sensor)
{
    ipmi_sensor_t *sensor;

    sensor = malloc(sizeof(*sensor));
    if (!sensor)
	return ENOMEM;

    memset(sensor, 0, sizeof(*sensor));

    *new_sensor = sensor;
    return 0;
}

int
ipmi_sensor_add_nonstandard(ipmi_mc_t              *mc,
			    ipmi_sensor_t          *sensor,
			    unsigned int           num,
			    ipmi_entity_t          *ent,
			    ipmi_sensor_destroy_cb destroy_handler,
			    void                   *destroy_handler_cb_data)
{
    ipmi_sensor_info_t *sensors = ipmi_mc_get_sensors(mc);
    void               *link;

    if (num >= 256)
	return EINVAL;

    if (num >= sensors->idx_size[4]) {
	ipmi_sensor_t **new_array;
	unsigned int  new_size;
	int           i;

	/* Allocate the array in multiples of 16 (to avoid thrashing malloc
	   too much). */
	new_size = ((num % 16) * 16) + 16;
	new_array = malloc(sizeof(*new_array) * new_size);
	if (!new_array)
	    return ENOMEM;
	if (sensors->sensors_by_idx[4])
	    memcpy(new_array, sensors->sensors_by_idx[4],
		   sizeof(*new_array) * (sensors->idx_size[4]));
	for (i=sensors->idx_size[4]; i<new_size; i++)
	    new_array[i] = NULL;
	if (sensors->sensors_by_idx[4])
	    free(sensors->sensors_by_idx[4]);
	sensors->sensors_by_idx[4] = new_array;
	sensors->idx_size[4] = new_size;
    }

    sensor->waitq = opq_alloc(ipmi_mc_get_os_hnd(mc));
    if (! sensor->waitq)
	return ENOMEM;

    link = ipmi_entity_alloc_sensor_link();
    if (!link) {
	opq_destroy(sensor->waitq);
	sensor->waitq = NULL;
	return ENOMEM;
    }

    sensor->mc = mc;
    sensor->lun = 4;
    sensor->num = num;
    sensor->source_idx = -1;
    sensors->sensors_by_idx[4][num] = sensor;
    sensor->entity_id = ipmi_entity_get_entity_id(ent);
    sensor->entity_instance = ipmi_entity_get_entity_instance(ent);
    sensor->destroy_handler = destroy_handler;
    sensor->destroy_handler_cb_data = destroy_handler_cb_data;

    ipmi_entity_add_sensor(ent, mc, sensor->lun, sensor->num, sensor, link);

    return 0;
}

int
ipmi_sensor_destroy(ipmi_sensor_t *sensor)
{
    ipmi_sensor_info_t *sensors = ipmi_mc_get_sensors(sensor->mc);
    ipmi_mc_t          *bmc = ipmi_mc_get_bmc(sensor->mc);
    ipmi_sensor_t      **sdr_sensors;
    unsigned int       count;
    ipmi_entity_info_t *ents = ipmi_mc_get_entities(bmc);
    ipmi_entity_t      *ent;
    int                rv;

    if (sensor != sensors->sensors_by_idx[sensor->lun][sensor->num])
	return EINVAL;

    if (sensor->source_idx >= 0) {
	ipmi_mc_get_sdr_sensors(ipmi_mc_get_bmc(sensor->mc),
				sensor->source_mc,
				&sdr_sensors,
				&count);
	if (sdr_sensors[sensor->source_idx] != sensor)
	    return EINVAL;

	sdr_sensors[sensor->source_idx] = NULL;
    }

    rv = ipmi_entity_find(ents,
			  bmc,
			  sensor->entity_id,
			  sensor->entity_instance,
			  &ent);
    if (!rv)
	ipmi_entity_remove_sensor(ent, bmc, sensor->lun, sensor->num, sensor);

    sensors->sensors_by_idx[sensor->lun][sensor->num] = NULL;

    sensor->destroyed = 1;
    if (!opq_stuff_in_progress(sensor->waitq))
	sensor_final_destroy(sensor);
    return 0;
}

int
ipmi_sensors_destroy(ipmi_sensor_info_t *sensors)
{
    int i, j;

    if (sensors->destroyed)
	return EINVAL;

    sensors->destroyed = 1;
    for (i=0; i<4; i++) {
	for (j=0; j<sensors->idx_size[i]; j++) {
	    if (sensors->sensors_by_idx[i][j]) {
		ipmi_sensor_destroy(sensors->sensors_by_idx[i][j]);
	    }
	}
	if (sensors->sensors_by_idx[i])
	    free(sensors->sensors_by_idx[i]);
    }
    if (sensors->sensor_wait_q)
	opq_destroy(sensors->sensor_wait_q);
    free(sensors);
    return 0;
}

static int
get_sensors_from_sdrs(ipmi_mc_t          *bmc,
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
    int           i, j;

    rv = ipmi_get_sdr_count(sdrs, &count);
    if (rv)
	goto out_err;

    /* Get a real count on the number of sensors, since a single SDR can
       contain multiple sensors. */
    p = 0;
    for (i=0; i<count; i++) {
	int incr;
	int lun;

	rv = ipmi_get_sdr_by_index(sdrs, i, &sdr);
	if (rv)
	    goto out_err;

	lun = sdr.data[1] & 0x03;
	if (sdr.type == 1) {
	    incr = 1;
	} else if (sdr.type == 2) {
	    if (sdr.data[18] & 0x0f)
		incr = sdr.data[18] & 0x0f;
	    else
		incr = 1;
	} else
	    continue;

	p += incr;
    }

    /* Setup memory to hold the sensors. */
    s = malloc(sizeof(*s) * p);
    if (!s) {
	rv = ENOMEM;
	goto out_err;
    }
    s_size = p;
    memset(s, 0, sizeof(*s) * p);

    p = 0;
    for (i=0; i<count; i++) {
	rv = ipmi_get_sdr_by_index(sdrs, i, &sdr);
	if (rv)
	    goto out_err;

	if ((sdr.type != 1) && (sdr.type != 2))
	    continue;

	s[p] = malloc(sizeof(*s[p]));
	if (!s[p]) {
	    rv = ENOMEM;
	    goto out_err;
	}
	memset(s[p], 0, sizeof(*s[p]));

	s[p]->waitq = opq_alloc(ipmi_mc_get_os_hnd(bmc));
	if (!s[p]->waitq) {
	    rv = ENOMEM;
	    goto out_err;
	}

	s[p]->destroyed = 0;
	s[p]->destroy_handler = NULL;

	rv = ipmi_mc_find_or_create_mc_by_slave_addr(bmc,
						     sdr.data[0],
						     &(s[p]->mc));
	if (rv)
	    goto out_err;
	s[p]->source_mc = source_mc;
	s[p]->source_idx = p;
	s[p]->owner = sdr.data[0];
	s[p]->channel = sdr.data[1] >> 4;
	s[p]->lun = sdr.data[1] & 0x03;
	s[p]->num = sdr.data[2];
	s[p]->entity_id = sdr.data[3];
	s[p]->entity_instance_logical = sdr.data[4] >> 7;
	s[p]->entity_instance = sdr.data[4] & 0x7f;
	s[p]->sensor_init_scanning = (sdr.data[5] >> 6) & 1;
	s[p]->sensor_init_events = (sdr.data[5] >> 5) & 1;
	s[p]->sensor_init_thresholds = (sdr.data[5] >> 4) & 1;
	s[p]->sensor_init_hysteresis = (sdr.data[5] >> 3) & 1;
	s[p]->sensor_init_type = (sdr.data[5] >> 2) & 1;
	s[p]->sensor_init_pu_events = (sdr.data[5] >> 1) & 1;
	s[p]->sensor_init_pu_scanning = (sdr.data[5] >> 0) & 1;
	s[p]->ignore_if_no_entity = (sdr.data[6] >> 7) & 1;
	s[p]->supports_rearm = (sdr.data[6] >> 6) & 1 ;
	s[p]->hysteresis_support = (sdr.data[6] >> 5) & 3;
	s[p]->threshold_access = (sdr.data[6] >> 3) & 3;
	s[p]->event_support = sdr.data[6] & 3;
	s[p]->sensor_type = sdr.data[7];
	s[p]->event_reading_type = sdr.data[8];

	val = ipmi_get_uint16(sdr.data+9);
	for (j=0; j<16; j++) {
	    s[p]->mask1[j] = val & 1;
	    val >>= 1;
	}
	val = ipmi_get_uint16(sdr.data+11);
	for (j=0; j<16; j++) {
	    s[p]->mask2[j] = val & 1;
	    val >>= 1;
	}
	val = ipmi_get_uint16(sdr.data+13);
	for (j=0; j<16; j++) {
	    s[p]->mask3[j] = val & 1;
	    val >>= 1;
	}

	s[p]->analog_data_format = (sdr.data[15] >> 6) & 3;
	s[p]->rate_unit = (sdr.data[15] >> 3) & 7;
	s[p]->modifier_unit_use = (sdr.data[15] >> 1) & 3;
	s[p]->percentage = sdr.data[15] & 1;
	s[p]->base_unit = sdr.data[16];
	s[p]->modifier_unit = sdr.data[17];

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

	    s[p]->normal_min_specified = (sdr.data[25] >> 2) & 1;
	    s[p]->normal_max_specified = (sdr.data[25] >> 1) & 1;
	    s[p]->nominal_reading_specified = sdr.data[25] & 1;
	    s[p]->nominal_reading = sdr.data[26];
	    s[p]->normal_max = sdr.data[27];
	    s[p]->normal_min = sdr.data[28];
	    s[p]->sensor_max = sdr.data[29];
	    s[p]->sensor_min = sdr.data[30];
	    s[p]->upper_non_recoverable_threshold = sdr.data[31];
	    s[p]->upper_critical_threshold = sdr.data[32];
	    s[p]->upper_non_critical_threshold = sdr.data[33];
	    s[p]->lower_non_recoverable_threshold = sdr.data[34];
	    s[p]->lower_critical_threshold = sdr.data[35];
	    s[p]->lower_non_critical_threshold = sdr.data[36];
	    s[p]->positive_going_threshold_hysteresis = sdr.data[37];
	    s[p]->negative_going_threshold_hysteresis = sdr.data[38];
	    s[p]->oem1 = sdr.data[41];

	    ipmi_get_device_string(sdr.data+42, sdr.length-42, s[p]->id,
				   SENSOR_ID_LEN);

	    p++;
	} else {
	    /* FIXME - make sure this is not a threshold sensor.  The
               question is, what do I do if it is? */
	    /* A short sensor record. */
	    s[p]->positive_going_threshold_hysteresis = sdr.data[20];
	    s[p]->negative_going_threshold_hysteresis = sdr.data[21];
	    s[p]->oem1 = sdr.data[25];

	    ipmi_get_device_string(sdr.data+26, sdr.length-26, s[p]->id,
				   SENSOR_ID_LEN);

	    /* Duplicate the sensor records for each instance.  Go
	       backwards to avoid destroying the first one until we
	       finish the others. */
	    for (j=(sdr.data[18] & 0x0f)-1; j>=0; j--) {
		int len;

		s[p+j] = s[p];

		s[p+j]->num += j;

		if (sdr.data[19] & 0x80) {
		    s[p+j]->entity_instance += j;
		}
		val = (sdr.data[19] & 0x3f) + j;
		len = strlen(s[p+j]->id);
		switch ((sdr.data[18] >> 4) & 0x03) {
		    case 0: /* Numeric */
			if ((val / 10) > 0) {
			    if (len < SENSOR_ID_LEN) {
				s[p+j]->id[len] =  (val/10) + '0';
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
		}
		s[p+j]->id[len] = '\0';
	    }

	    if (sdr.data[18] & 0x0f)
		p += sdr.data[18] & 0x0f;
	    else
		p++;
	}
    }

    *sensors = s;
    *sensor_count = s_size;
    return 0;

 out_err:
    if (s) {
	for (i=0; i<s_size; i++)
	    if (s[i])
		free(s[i]);
	free(s);
    }
    return rv;
}

typedef struct sdr_fetch_info_s
{
    ipmi_mc_t                *bmc;
    ipmi_mc_t                *source_mc; /* This is used to scan the SDRs. */
    ipmi_mc_done_cb          done;
    void                     *done_data;
    ipmi_sensor_info_t       *sensors;
} sdr_fetch_info_t;

static void
handle_new_sensor(ipmi_mc_t     *bmc,
		  ipmi_sensor_t *sensor,
		  void          *link)
{
    ipmi_entity_info_t *ents;
    ipmi_entity_t      *ent;


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

    ents = ipmi_mc_get_entities(bmc);

    /* This can't fail, we have pre-added it while we held the lock. */
    ipmi_entity_find(ents,
		     bmc,
		     sensor->entity_id,
		     sensor->entity_instance,
		     &ent);

    if (! ipmi_bmc_oem_new_sensor(bmc, ent, sensor, link)) {
	ipmi_entity_add_sensor(ent, bmc,
			       sensor->lun, sensor->num, sensor, link);
    }
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
    if (s1->supports_rearm != s2->supports_rearm) return 0;
    if (s1->hysteresis_support != s2->hysteresis_support) return 0;
    if (s1->threshold_access != s2->threshold_access) return 0;
    if (s1->event_support != s2->event_support) return 0;
    if (s1->sensor_type != s2->sensor_type) return 0;
    if (s1->event_reading_type != s2->event_reading_type) return 0;

    for (i=0; i<16; i++) {
	if (s1->mask1[i] != s2->mask1[i]) return 0;
	if (s1->mask2[i] != s2->mask2[i]) return 0;
	if (s1->mask3[i] != s2->mask3[i]) return 0;
    }
    
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
    if (s1->upper_non_recoverable_threshold
	!= s2->upper_non_recoverable_threshold)
	return 0;
    if (s1->upper_critical_threshold != s2->upper_critical_threshold) return 0;
    if (s1->upper_non_critical_threshold
	!= s2->upper_non_critical_threshold)
	return 0;
    if (s1->lower_non_recoverable_threshold
	!= s2->lower_non_recoverable_threshold)
	return 0;
    if (s1->lower_critical_threshold != s2->lower_critical_threshold) return 0;
    if (s1->lower_non_critical_threshold
	!= s2->lower_non_critical_threshold)
	return 0;
    if (s1->positive_going_threshold_hysteresis
	!= s2->positive_going_threshold_hysteresis)
	return 0;
    if (s1->negative_going_threshold_hysteresis
	!= s2->negative_going_threshold_hysteresis)
	return 0;
    if (s1->oem1 != s2->oem1) return 0;

    if (strcmp(s1->id, s2->id) != 0) return 0;
    
    return 1;
}

static void
handle_deleted_sensor(ipmi_mc_t         *bmc,
		      ipmi_sensor_t     *sensor)
{
    ipmi_entity_info_t *ents;
    ipmi_entity_t      *ent;
    int                rv;

    ents = ipmi_mc_get_entities(bmc);

    rv = ipmi_entity_find(ents,
			  bmc,
			  sensor->entity_id,
			  sensor->entity_instance,
			  &ent);
    if (!rv)
	ipmi_entity_remove_sensor(ent, bmc, sensor->lun, sensor->num, sensor);
}

static void
sensor_reread_done(sdr_fetch_info_t *info, int err)
{
    if (info->done)
	info->done(info->bmc, err, info->done_data);
    opq_op_done(info->sensors->sensor_wait_q);
    free(info);
}

typedef struct dummy_link_s dummy_link_t;
struct dummy_link_s
{
    dummy_link_t *next;
};
int
ipmi_sensor_handle_sdrs(ipmi_mc_t       *bmc,
			ipmi_mc_t       *source_mc,
			ipmi_sdr_info_t *sdrs)
{
    int                rv;
    int                i, j;
    dummy_link_t       *sref = NULL;
    dummy_link_t       *snext = NULL;
    ipmi_sensor_t      **sdr_sensors;
    ipmi_sensor_t      **old_sdr_sensors;
    unsigned int       old_count;
    unsigned int       count;
    ipmi_entity_info_t *ents;

    rv = get_sensors_from_sdrs(bmc, source_mc, sdrs, &sdr_sensors, &count);
    if (rv)
	goto out_err;

    ipmi_mc_entity_lock(bmc);

    ents = ipmi_mc_get_entities(bmc);

    /* Pre-allocate all the links we will need for registering sensors
       with the entities, and we make sure all the entities exist. */
    for (i=0; i<count; i++) {
	ipmi_sensor_t      *nsensor = sdr_sensors[i];
	ipmi_sensor_info_t *sensors = ipmi_mc_get_sensors(nsensor->mc);

	if (nsensor != NULL) {
	    /* Make sure the entity exists for ALL sensors in the
	       new list.  This way, if a sensor has changed
	       entities, the new entity will exist. */
	    rv = ipmi_entity_add(ents,
				 nsensor->mc,
				 i,
				 nsensor->entity_id,
				 nsensor->entity_instance,
				 "",
				 NULL,
				 NULL,
				 NULL);
	    if (rv)
		goto out_err_unlock_free;

	    /* There's not enough room in the sensor repository for the new
	       item, so expand the array. */
	    if (nsensor->num >= sensors->idx_size[nsensor->lun]) {
		ipmi_sensor_t **new_by_idx;
		unsigned int  new_size = nsensor->num+10;
		new_by_idx = malloc(sizeof(ipmi_sensor_t *) * new_size);
		if (!new_by_idx) {
		    rv = ENOMEM;
		    goto out_err_unlock_free;
		}
		memcpy(new_by_idx,
		       sensors->sensors_by_idx[nsensor->lun],
		       sensors->idx_size[nsensor->lun]);
		for (j=sensors->idx_size[nsensor->lun]; j<new_size; j++)
		    new_by_idx[j] = NULL;
		free(sensors->sensors_by_idx[nsensor->lun]);
		sensors->sensors_by_idx[nsensor->lun] = new_by_idx;
		sensors->idx_size[nsensor->lun] = new_size;
	    }

	    /* Just in case, allocate a sensor link for it. */
	    snext = ipmi_entity_alloc_sensor_link();
	    if (!snext) {
		rv = ENOMEM;
		goto out_err_unlock_free;
	    }
	    snext->next = sref;
	    sref = snext;
	}
    }

    /* FIXME - find and report duplicate sensors numbers/luns. */

    /* After this point, the operation cannot fail. */

    ipmi_mc_get_sdr_sensors(bmc, source_mc, &old_sdr_sensors, &old_count);

    /* For each new sensor, put it into the MC it belongs with. */
    for (i=0; i<count; i++) {
	ipmi_sensor_t *nsensor = sdr_sensors[i];
	ipmi_sensor_info_t *sensors = ipmi_mc_get_sensors(nsensor->mc);
	ipmi_sensor_t *osensor;

	osensor = sensors->sensors_by_idx[nsensor->lun][nsensor->num];
	if (osensor == NULL) {
	    /* It's a new sensor. */
	    sensors->sensors_by_idx[nsensor->lun][nsensor->num] = nsensor;
	    snext = sref;
	    sref = sref->next;
	    handle_new_sensor(bmc, nsensor, snext);
	} else {
	    /* It's already there. */
	    if (cmp_sensor(nsensor, osensor)) {
		/* They compare, prefer to keep the old data. */
		free(nsensor);
		sdr_sensors[i] = osensor;
		old_sdr_sensors[osensor->source_idx] = NULL;
		osensor->source_idx = i;
	    } else {
		/* Destroy the old sensor, add the new one. */
		handle_deleted_sensor(bmc, osensor);
		old_sdr_sensors[osensor->source_idx] = NULL;
		free(osensor);
		sensors->sensors_by_idx[nsensor->lun][nsensor->num] = nsensor;
		snext = sref;
		sref = sref->next;
		handle_new_sensor(bmc, nsensor, snext);
	    }
	}
    }

    ipmi_mc_set_sdr_sensors(bmc, source_mc, sdr_sensors, count);

    if (old_sdr_sensors) {
	for (i=0; i<old_count; i++) {
	    ipmi_sensor_t *osensor = old_sdr_sensors[i];
	    if (osensor != NULL) {
		/* This sensor was not in the new repository, so it must
		   have been deleted. */
		
		ipmi_sensor_info_t *sensors = ipmi_mc_get_sensors(osensor->mc);
		
		handle_deleted_sensor(bmc, old_sdr_sensors[i]);
		sensors->sensors_by_idx[osensor->lun][osensor->num] = NULL;
		free(osensor);
	    }
	}
	free(old_sdr_sensors);
    }

    /* Free up the extra links that we didn't use. */
    while (sref) {
	snext = sref->next;
	ipmi_entity_free_sensor_link(sref);
	sref = snext;
    }
    return 0;

 out_err_unlock_free:
    ipmi_mc_entity_unlock(bmc);
 out_err:
    while (sref) {
	snext = sref->next;
	free(sref);
	sref = snext;
    }
    return rv;
}
			

static void
sdrs_fetched(ipmi_sdr_info_t *sdrs,
	     int             err,
	     int             changed,
	     unsigned int    count,
	     void            *cb_data)
{
    sdr_fetch_info_t   *info = (sdr_fetch_info_t *) cb_data;
    int                rv;

    if (err) {
	sensor_reread_done(info, err);
	return;
    }

    rv = ipmi_sensor_handle_sdrs(info->bmc, info->source_mc, sdrs);
    sensor_reread_done(info, rv);
}

static void
sensor_read_handler(void *cb_data, int shutdown)
{
    sdr_fetch_info_t *info = (sdr_fetch_info_t *) cb_data;
    int              rv;

    if (shutdown) {
	sensor_reread_done(info, ECANCELED);
	return;
    }

    rv = ipmi_sdr_fetch(ipmi_mc_get_sdrs(info->source_mc), sdrs_fetched, info);
    if (rv)
	sensor_reread_done(info, rv);
}

int ipmi_mc_reread_sensors(ipmi_mc_t       *mc,
			   ipmi_mc_done_cb done,
			   void            *done_data)
{
    sdr_fetch_info_t *info;
    int              rv = 0;

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->sensors = ipmi_mc_get_sensors(mc);

    info->source_mc = mc;
    info->bmc = ipmi_mc_get_bmc(mc);
    info->done = done;
    info->done_data = done_data;

    if (! opq_new_op(info->sensors->sensor_wait_q,
		     sensor_read_handler, info, 0))
	rv = ENOMEM;

    if (rv) {
	free(info);
    } else {
	ipmi_detect_bmc_presence_changes(info->bmc, 0);
    }
    return rv;
}

int
ipmi_sensor_get_nominal_reading(ipmi_sensor_t *sensor,
				double *nominal_reading)
{
    if (!sensor->nominal_reading_specified)
	return ENOSYS;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->nominal_reading,
					 nominal_reading));
}

int
ipmi_sensor_get_normal_max(ipmi_sensor_t *sensor, double *normal_max)
{
    if (!sensor->normal_max_specified)
	return ENOSYS;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->normal_max,
					 normal_max));
}

int
ipmi_sensor_get_normal_min(ipmi_sensor_t *sensor, double *normal_min)
{
    if (!sensor->normal_min_specified)
	return ENOSYS;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->normal_min,
					 normal_min));
}

int
ipmi_sensor_get_sensor_max(ipmi_sensor_t *sensor, double *sensor_max)
{
    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->sensor_max,
					 sensor_max));
}

int
ipmi_sensor_get_sensor_min(ipmi_sensor_t *sensor, double *sensor_min)
{
    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->sensor_min,
					 sensor_min));
}

int
ipmi_sensor_get_upper_non_recoverable_threshold
(ipmi_sensor_t *sensor,
 double *upper_non_recoverable_threshold)
{
    int val, rv;

    rv = ipmi_sensor_threshold_readable(sensor,
					IPMI_UPPER_NON_RECOVERABLE,
					&val);
    if (rv)
	return rv;

    if (!val)
	return ENOTSUP;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->upper_non_recoverable_threshold,
					 upper_non_recoverable_threshold));
}

int
ipmi_sensor_get_upper_critical_threshold(ipmi_sensor_t *sensor,
					 double *upper_critical_threshold)
{
    int val, rv;

    rv = ipmi_sensor_threshold_readable(sensor,
					IPMI_UPPER_CRITICAL,
					&val);
    if (rv)
	return rv;

    if (!val)
	return ENOTSUP;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->upper_critical_threshold,
					 upper_critical_threshold));
}

int
ipmi_sensor_get_upper_non_critical_threshold
(ipmi_sensor_t *sensor,
 double *upper_non_critical_threshold)
{
    int val, rv;

    rv = ipmi_sensor_threshold_readable(sensor,
					IPMI_UPPER_NON_CRITICAL,
					&val);
    if (rv)
	return rv;

    if (!val)
	return ENOTSUP;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->upper_non_critical_threshold,
					 upper_non_critical_threshold));
}

int
ipmi_sensor_get_lower_non_recoverable_threshold
(ipmi_sensor_t *sensor,
 double *lower_non_recoverable_threshold)
{
    int val, rv;

    rv = ipmi_sensor_threshold_readable(sensor,
					IPMI_LOWER_NON_RECOVERABLE,
					&val);
    if (rv)
	return rv;

    if (!val)
	return ENOTSUP;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->lower_non_recoverable_threshold,
					 lower_non_recoverable_threshold));
}

int ipmi_sensor_get_lower_critical_threshold(ipmi_sensor_t *sensor,
					     double *lower_critical_threshold)
{
    int val, rv;

    rv = ipmi_sensor_threshold_readable(sensor,
					IPMI_LOWER_CRITICAL,
					&val);
    if (rv)
	return rv;

    if (!val)
	return ENOTSUP;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->lower_critical_threshold,
					 lower_critical_threshold));
}

int
ipmi_sensor_get_lower_non_critical_threshold
(ipmi_sensor_t *sensor,
 double *lower_non_critical_threshold)
{
    int val, rv;

    rv = ipmi_sensor_threshold_readable(sensor,
					IPMI_LOWER_NON_CRITICAL,
					&val);
    if (rv)
	return rv;

    if (!val)
	return ENOTSUP;

    return (ipmi_sensor_convert_from_raw(sensor,
					 sensor->lower_non_critical_threshold,
					 lower_non_critical_threshold));
}

ipmi_mc_t *
ipmi_sensor_get_mc(ipmi_sensor_t *sensor)
{
    return sensor->mc;
}

int
ipmi_sensor_get_num(ipmi_sensor_t *sensor,
		    int           *lun,
		    int           *num)
{
    if (lun)
	*lun = sensor->lun;
    if (num)
	*num = sensor->num;
    return 0;
}

int
ipmi_sensor_threshold_assertion_event_supported(
    ipmi_sensor_t               *sensor,
    enum ipmi_thresh_e          event,
    enum ipmi_event_value_dir_e dir,
    int                         *val)
{
    int idx;

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    idx = (event * 2) + dir;
    if (idx > 11)
	return EINVAL;

    *val = sensor->mask1[idx];
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

    sensor->mask1[idx] = val;
}

int
ipmi_sensor_threshold_deassertion_event_supported(
    ipmi_sensor_t               *sensor,
    enum ipmi_thresh_e          event,
    enum ipmi_event_value_dir_e dir,
    int                         *val)
{
    int idx;

    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    idx = (event * 2) + dir;
    if (idx > 11)
	return 0;

    *val = sensor->mask2[idx];
    return 0;
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

    sensor->mask2[idx] = val;
}

int
ipmi_sensor_threshold_settable(ipmi_sensor_t      *sensor,
			       enum ipmi_thresh_e event,
			       int                *val)
{
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (event > IPMI_UPPER_NON_RECOVERABLE)
	return EINVAL;

    *val = sensor->mask3[event + 8];
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

    sensor->mask3[event + 8] = val;
}

int
ipmi_sensor_threshold_readable(ipmi_sensor_t      *sensor,
			       enum ipmi_thresh_e event,
			       int                *val)
{
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (event > IPMI_UPPER_NON_RECOVERABLE)
	return EINVAL;

    *val = sensor->mask3[event];
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

    sensor->mask3[event] = val;
}

int
ipmi_sensor_discrete_assertion_event_supported(ipmi_sensor_t *sensor,
					       int           event,
					       int           *val)
{
    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have events. */
	return ENOSYS;

    if (event > 14)
	return EINVAL;

    *val = sensor->mask1[event];
    return 0;
}

void
ipmi_sensor_set_discrete_assertion_event_supported(ipmi_sensor_t *sensor,
						   int           event,
						   int           val)
{
    if (event > 14)
	return;

    sensor->mask1[event] = val;
}

int
ipmi_sensor_discrete_deassertion_event_supported(ipmi_sensor_t *sensor,
						 int           event,
						 int           *val)
{
    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have events. */
	return ENOSYS;

    if (event > 14)
	return EINVAL;

    *val = sensor->mask2[event];
    return 0;
}

void
ipmi_sensor_set_discrete_deassertion_event_supported(ipmi_sensor_t *sensor,
						     int           event,
						     int           val)
{
    if (event > 14)
	return;

    sensor->mask2[event] = val;
}

int
ipmi_discrete_event_readable(ipmi_sensor_t *sensor,
			     int           event,
			     int           *val)
{
    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have events. */
	return ENOSYS;

    if (event > 14)
	return EINVAL;

    *val = sensor->mask3[event];
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

    sensor->mask3[event] = val;
}

int
ipmi_sensor_get_owner(ipmi_sensor_t *sensor)
{
    return sensor->owner;
}

int
ipmi_sensor_get_channel(ipmi_sensor_t *sensor)
{
    return sensor->channel;
}

int
ipmi_sensor_get_entity_id(ipmi_sensor_t *sensor)
{
    return sensor->entity_id;
}

int
ipmi_sensor_get_entity_instance(ipmi_sensor_t *sensor)
{
    return sensor->entity_instance;
}

int
ipmi_sensor_get_entity_instance_logical(ipmi_sensor_t *sensor)
{
    return sensor->entity_instance_logical;
}

int
ipmi_sensor_get_sensor_init_scanning(ipmi_sensor_t *sensor)
{
    return sensor->sensor_init_scanning;
}

int
ipmi_sensor_get_sensor_init_events(ipmi_sensor_t *sensor)
{
    return sensor->sensor_init_events;
}

int
ipmi_sensor_get_sensor_init_thresholds(ipmi_sensor_t *sensor)
{
    return sensor->sensor_init_thresholds;
}

int
ipmi_sensor_get_sensor_init_hysteresis(ipmi_sensor_t *sensor)
{
    return sensor->sensor_init_hysteresis;
}

int
ipmi_sensor_get_sensor_init_type(ipmi_sensor_t *sensor)
{
    return sensor->sensor_init_type;
}

int
ipmi_sensor_get_sensor_init_pu_events(ipmi_sensor_t *sensor)
{
    return sensor->sensor_init_pu_events;
}

int
ipmi_sensor_get_sensor_init_pu_scanning(ipmi_sensor_t *sensor)
{
    return sensor->sensor_init_pu_scanning;
}

int
ipmi_sensor_get_ignore_if_no_entity(ipmi_sensor_t *sensor)
{
    return sensor->ignore_if_no_entity;
}

int
ipmi_sensor_get_supports_rearm(ipmi_sensor_t *sensor)
{
    return sensor->supports_rearm;
}

int
ipmi_sensor_get_hysteresis_support(ipmi_sensor_t *sensor)
{
    return sensor->hysteresis_support;
}

int
ipmi_sensor_get_threshold_access(ipmi_sensor_t *sensor)
{
    return sensor->threshold_access;
}

int
ipmi_sensor_get_event_support(ipmi_sensor_t *sensor)
{
    return sensor->event_support;
}

int
ipmi_sensor_get_sensor_type(ipmi_sensor_t *sensor)
{
    return sensor->sensor_type;
}

int
ipmi_sensor_get_event_reading_type(ipmi_sensor_t *sensor)
{
    return sensor->event_reading_type;
}

int
ipmi_sensor_get_analog_data_format(ipmi_sensor_t *sensor)
{
    return sensor->analog_data_format;
}

int
ipmi_sensor_get_rate_unit(ipmi_sensor_t *sensor)
{
    return sensor->rate_unit;
}

int
ipmi_sensor_get_modifier_unit_use(ipmi_sensor_t *sensor)
{
    return sensor->modifier_unit_use;
}

int
ipmi_sensor_get_percentage(ipmi_sensor_t *sensor)
{
    return sensor->percentage;
}

int
ipmi_sensor_get_base_unit(ipmi_sensor_t *sensor)
{
    return sensor->base_unit;
}

int
ipmi_sensor_get_modifier_unit(ipmi_sensor_t *sensor)
{
    return sensor->modifier_unit;
}

int
ipmi_sensor_get_linearization(ipmi_sensor_t *sensor)
{
    return sensor->linearization;
}

int
ipmi_sensor_get_raw_m(ipmi_sensor_t *sensor, int val)
{
    return sensor->conv[val].m;
}

int
ipmi_sensor_get_raw_tolerance(ipmi_sensor_t *sensor, int val)
{
    return sensor->conv[val].tolerance;
}

int
ipmi_sensor_get_raw_b(ipmi_sensor_t *sensor, int val)
{
    return sensor->conv[val].b;
}

int
ipmi_sensor_get_raw_accuracy(ipmi_sensor_t *sensor, int val)
{
    return sensor->conv[val].accuracy;
}

int
ipmi_sensor_get_raw_accuracy_exp(ipmi_sensor_t *sensor, int val)
{
    return sensor->conv[val].accuracy_exp;
}

int
ipmi_sensor_get_raw_r_exp(ipmi_sensor_t *sensor, int val)
{
    return sensor->conv[val].r_exp;
}

int
ipmi_sensor_get_raw_b_exp(ipmi_sensor_t *sensor, int val)
{
    return sensor->conv[val].b_exp;
}

int
ipmi_sensor_get_normal_min_specified(ipmi_sensor_t *sensor)
{
    return sensor->normal_min_specified;
}

int
ipmi_sensor_get_normal_max_specified(ipmi_sensor_t *sensor)
{
    return sensor->normal_max_specified;
}

int
ipmi_sensor_get_nominal_reading_specified(ipmi_sensor_t *sensor)
{
    return sensor->nominal_reading_specified;
}

int
ipmi_sensor_get_raw_nominal_reading(ipmi_sensor_t *sensor)
{
    return sensor->nominal_reading;
}

int
ipmi_sensor_get_raw_normal_max(ipmi_sensor_t *sensor)
{
    return sensor->normal_max;
}

int
ipmi_sensor_get_raw_normal_min(ipmi_sensor_t *sensor)
{
    return sensor->normal_min;
}

int
ipmi_sensor_get_raw_sensor_max(ipmi_sensor_t *sensor)
{
    return sensor->sensor_max;
}

int
ipmi_sensor_get_raw_sensor_min(ipmi_sensor_t *sensor)
{
    return sensor->sensor_min;
}

int
ipmi_sensor_get_raw_upper_non_recoverable_threshold(ipmi_sensor_t *sensor)
{
    return sensor->upper_non_recoverable_threshold;
}

int
ipmi_sensor_get_raw_upper_critical_threshold(ipmi_sensor_t *sensor)
{
    return sensor->upper_critical_threshold;
}

int
ipmi_sensor_get_raw_upper_non_critical_threshold(ipmi_sensor_t *sensor)
{
    return sensor->upper_non_critical_threshold;
}

int
ipmi_sensor_get_raw_lower_non_recoverable_threshold(ipmi_sensor_t *sensor)
{
    return sensor->lower_non_recoverable_threshold;
}

int
ipmi_sensor_get_raw_lower_critical_threshold(ipmi_sensor_t *sensor)
{
    return sensor->lower_critical_threshold;
}

int
ipmi_sensor_get_raw_lower_non_critical_threshold(ipmi_sensor_t *sensor)
{
    return sensor->lower_non_critical_threshold;
}

int
ipmi_sensor_get_positive_going_threshold_hysteresis(ipmi_sensor_t *sensor)
{
    return sensor->positive_going_threshold_hysteresis;
}

int
ipmi_sensor_get_negative_going_threshold_hysteresis(ipmi_sensor_t *sensor)
{
    return sensor->negative_going_threshold_hysteresis;
}

int
ipmi_sensor_get_oem1(ipmi_sensor_t *sensor)
{
    return sensor->oem1;
}

int
ipmi_sensor_get_id_length(ipmi_sensor_t *sensor)
{
    return strlen(sensor->id);
}

void
ipmi_sensor_get_id(ipmi_sensor_t *sensor, char *id, int length)
{
    strncpy(id, sensor->id, length);
    id[length] = '\0';
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
ipmi_sensor_set_supports_rearm(ipmi_sensor_t *sensor, int supports_rearm)
{
    sensor->supports_rearm = supports_rearm;
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
    sensor->conv[idx].m = idx;
}

void
ipmi_sensor_set_raw_tolerance(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].tolerance = idx;
}

void
ipmi_sensor_set_raw_b(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].b = idx;
}

void
ipmi_sensor_set_raw_accuracy(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].accuracy = idx;
}

void
ipmi_sensor_set_raw_accuracy_exp(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].accuracy_exp = idx;
}

void
ipmi_sensor_set_raw_r_exp(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].r_exp = idx;
}

void
ipmi_sensor_set_raw_b_exp(ipmi_sensor_t *sensor, int idx, int val)
{
    sensor->conv[idx].b_exp = idx;
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
ipmi_sensor_set_raw_upper_non_recoverable_threshold(
    ipmi_sensor_t *sensor,
    int           raw_upper_non_recoverable_threshold)
{
    sensor->upper_non_recoverable_threshold
	= raw_upper_non_recoverable_threshold;
}

void
ipmi_sensor_set_raw_upper_critical_threshold(
    ipmi_sensor_t *sensor,
    int           raw_upper_critical_threshold)
{
    sensor->upper_critical_threshold = raw_upper_critical_threshold;
}

void
ipmi_sensor_set_raw_upper_non_critical_threshold(
    ipmi_sensor_t *sensor,
    int           raw_upper_non_critical_threshold)
{
    sensor->upper_non_critical_threshold = raw_upper_non_critical_threshold;
}

void
ipmi_sensor_set_raw_lower_non_recoverable_threshold(
    ipmi_sensor_t *sensor,
    int           raw_lower_non_recoverable_threshold)
{
    sensor->lower_non_recoverable_threshold
	= raw_lower_non_recoverable_threshold;
}

void
ipmi_sensor_set_raw_lower_critical_threshold(
    ipmi_sensor_t *sensor,
    int           raw_lower_critical_threshold)
{
    sensor->lower_critical_threshold = raw_lower_critical_threshold;
}

void
ipmi_sensor_set_raw_lower_non_critical_threshold(
    ipmi_sensor_t *sensor,
    int           raw_lower_non_critical_threshold)
{
    sensor->lower_non_critical_threshold = raw_lower_non_critical_threshold;
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
ipmi_sensor_set_id(ipmi_sensor_t *sensor, char *id)
{
    strncpy(sensor->id, id, SENSOR_ID_LEN);
    sensor->id[SENSOR_ID_LEN] = '\0';
}

int
ipmi_sensor_threshold_set_event_handler(
    ipmi_sensor_t                          *sensor,
    ipmi_sensor_threshold_event_handler_cb handler,
    void                                   *cb_data)
{
    sensor->threshold_event_handler = handler;
    sensor->cb_data = cb_data;
    return 0;
}

void
ipmi_sensor_threshold_get_event_handler(
    ipmi_sensor_t                          *sensor,
    ipmi_sensor_threshold_event_handler_cb *handler,
    void                                   **cb_data)
{
    *handler = sensor->threshold_event_handler;
    *cb_data = sensor->cb_data;
}

int
ipmi_sensor_discrete_set_event_handler(
    ipmi_sensor_t                         *sensor,
    ipmi_sensor_discrete_event_handler_cb handler,
    void                                  *cb_data)
{
    sensor->discrete_event_handler = handler;
    sensor->cb_data = cb_data;
    return 0;
}

void
ipmi_sensor_discrete_get_event_handler(
    ipmi_sensor_t                         *sensor,
    ipmi_sensor_discrete_event_handler_cb *handler,
    void                                  **cb_data)
{
    *handler = sensor->discrete_event_handler;
    *cb_data = sensor->cb_data;
}

int
ipmi_sensor_event(ipmi_sensor_t *sensor, ipmi_log_t *log)
{
    enum ipmi_event_dir_e dir;
    int                   rv;

    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD) {
	enum ipmi_value_present_e   value_present;
	double                      value = 0.0;
	enum ipmi_thresh_e          threshold;
	enum ipmi_event_value_dir_e high_low;

	if (!sensor->threshold_event_handler)
	    return EINVAL;

	dir = log->data[9] >> 7;
	threshold = (log->data[10] >> 1) & 0x07;
	high_low = log->data[10] & 1;

	if ((log->data[10] >> 6) == 2) {
	    rv = ipmi_sensor_convert_from_raw(sensor, log->data[11], &value);
	    if (!rv)
		value_present = IPMI_RAW_VALUE_PRESENT;
	    else
		value_present = IPMI_BOTH_VALUES_PRESENT;
	} else {
	    value_present = IPMI_NO_VALUES_PRESENT;
	}
	sensor->threshold_event_handler(sensor, dir, threshold, high_low,
					value_present, log->data[11], value,
					sensor->cb_data, log);
    } else {
	int offset;
	int severity = -1, prev_severity = -1;

	if (!sensor->discrete_event_handler)
	    return EINVAL;

	dir = log->data[9] >> 7;
	offset = log->data[10] & 0x0f;
	if ((log->data[10] >> 6) == 2) {
	    severity = log->data[11] >> 4;
	    prev_severity = log->data[11] & 0xf;
	    if (severity == 0xf)
		severity = -1;
	    if (prev_severity == 0xf)
		prev_severity = -11;
	}
	sensor->discrete_event_handler(sensor, dir, offset,
				       severity,
				       prev_severity,
				       sensor->cb_data, log);
    }

    return 0;
}

typedef struct event_enable_info_s
{
    ipmi_sensor_op_info_t sdata;
    ipmi_event_state_t    state;
    ipmi_sensor_done_cb   done;
    void                  *cb_data;
} event_enable_info_t;

static void
disables_set(ipmi_sensor_t *sensor,
	     int           err,
	     ipmi_msg_t    *rsp,
	     void          *cb_data)
{
    event_enable_info_t *info = cb_data;

    if (err) {
	if (info->done)
	    info->done(sensor, err, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (rsp->data[0]) {
	if (info->done)
	    info->done(sensor,
		       IPMI_IPMI_ERR_VAL(rsp->data[0]),
		       info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (info->done)
	info->done(sensor, 0, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    free(info);
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

    if (err) {
	if (info->done)
	    info->done(sensor, err, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (rsp->data[0]) {
	if (info->done)
	    info->done(sensor,
		       IPMI_IPMI_ERR_VAL(rsp->data[0]),
		       info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    /* Enables were set, now disable all the other ones. */
    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_SET_SENSOR_EVENT_ENABLE_CMD;
    cmd_msg.data_len = 6;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    cmd_data[1] = (info->state.status & 0xc0) | (0x02 << 4);
    cmd_data[2] = ~(info->state.__assertion_events & 0xff);
    cmd_data[3] = ~(info->state.__assertion_events >> 8);
    cmd_data[4] = ~(info->state.__deassertion_events & 0xff);
    cmd_data[5] = ~(info->state.__deassertion_events >> 8);
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->lun,
				  &cmd_msg, disables_set,
				  &(info->sdata), info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
    }
}

static void
event_enable_set_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    event_enable_info_t *info = cb_data;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;

    if (err) {
	if (info->done)
	    info->done(sensor, err, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_SET_SENSOR_EVENT_ENABLE_CMD;
    cmd_msg.data_len = 6;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    cmd_data[1] = (info->state.status & 0xc0) | (0x01 << 4);
    cmd_data[2] = info->state.__assertion_events & 0xff;
    cmd_data[3] = info->state.__assertion_events >> 8;
    cmd_data[4] = info->state.__deassertion_events & 0xff;
    cmd_data[5] = info->state.__deassertion_events >> 8;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->lun,
				  &cmd_msg, enables_set, &(info->sdata), info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
    }
}

static int
stand_ipmi_sensor_events_enable_set(ipmi_sensor_t         *sensor,
				    ipmi_event_state_t    *states,
				    ipmi_sensor_done_cb   done,
				    void                  *cb_data)
{
    event_enable_info_t *info;
    int                 rv;
    
    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->state = *states;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, event_enable_set_start,
			     &(info->sdata), info);
    if (rv)
	free(info);
    return rv;
}

typedef struct event_enable_get_info_s
{
    ipmi_sensor_op_info_t     sdata;
    ipmi_event_state_t        state;
    ipmi_event_enables_get_cb done;
    void                      *cb_data;
} event_enable_get_info_t;

static void
enables_get(ipmi_sensor_t *sensor,
	    int           err,
	    ipmi_msg_t    *rsp,
	    void          *cb_data)
{
    event_enable_get_info_t *info = cb_data;

    if (err) {
	if (info->done)
	    info->done(sensor, err, &info->state, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (rsp->data[0]) {
	if (info->done)
	    info->done(sensor,
		       IPMI_IPMI_ERR_VAL(rsp->data[0]),
		       &info->state,
		       info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    info->state.status = rsp->data[1] & 0xc0;
    info->state.__assertion_events = (rsp->data[2]
				      | (rsp->data[3] << 8));
    info->state.__deassertion_events = (rsp->data[4]
					| (rsp->data[5] << 8));
    if (info->done)
	info->done(sensor, 0, &info->state, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    free(info);
}

static void
event_enable_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    event_enable_get_info_t *info = cb_data;
    unsigned char           cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t              cmd_msg;
    int                     rv;

    if (err) {
	if (info->done)
	    info->done(sensor, err, &info->state, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_EVENT_ENABLE_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->lun,
				  &cmd_msg, enables_get, &(info->sdata), info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, &info->state, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
    }
}

static int
stand_ipmi_sensor_events_enable_get(ipmi_sensor_t             *sensor,
				    ipmi_event_enables_get_cb done,
				    void                      *cb_data)
{
    event_enable_get_info_t *info;
    int                     rv;

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, event_enable_get_start,
			     &(info->sdata), info);
    if (rv)
	free(info);
    return rv;
}

typedef struct hyst_get_info_s
{
    ipmi_sensor_op_info_t  sdata;
    ipmi_hysteresis_get_cb done;
    void                   *cb_data;
} hyst_get_info_t;

static void
hyst_get(ipmi_sensor_t *sensor,
	 int           err,
	 ipmi_msg_t    *rsp,
	 void          *cb_data)
{
    hyst_get_info_t *info = cb_data;

    if (err) {
	if (info->done)
	    info->done(sensor, err, 0, 0, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (rsp->data[0]) {
	if (info->done)
	    info->done(sensor,
		       IPMI_IPMI_ERR_VAL(rsp->data[0]),
		       0,
		       0,
		       info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (info->done)
	info->done(sensor,
		   0,
		   rsp->data[1],
		   rsp->data[2],
		   info->cb_data);
    ipmi_sensor_opq_done(sensor);
    free(info);
}

static void
hyst_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    hyst_get_info_t *info = cb_data;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;

    if (err) {
	if (info->done)
	    info->done(sensor, err, 0, 0, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_HYSTERESIS_CMD;
    cmd_msg.data_len = 2;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    cmd_data[1] = 0xff;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->lun,
				  &cmd_msg, hyst_get, &(info->sdata), info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, 0, 0, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
    }
}

static int
stand_ipmi_sensor_get_hysteresis(ipmi_sensor_t          *sensor,
				 ipmi_hysteresis_get_cb done,
				 void                   *cb_data)
{
    hyst_get_info_t *info;
    int             rv;
    
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (sensor->hysteresis_support != IPMI_HYSTERESIS_SUPPORT_READABLE)
	return ENOTSUP;
    
    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, hyst_get_start, &(info->sdata), info);
    if (rv)
	free(info);
    return rv;
}

typedef struct hyst_set_info_s
{
    ipmi_sensor_op_info_t sdata;
    unsigned int          positive, negative;
    ipmi_sensor_done_cb   done;
    void                  *cb_data;
} hyst_set_info_t;

static void
hyst_set(ipmi_sensor_t *sensor,
	 int           err,
	 ipmi_msg_t    *rsp,
	 void          *cb_data)
{
    hyst_set_info_t *info = cb_data;

    if (err) {
	if (info->done)
	    info->done(sensor, err, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (rsp->data[0]) {
	if (info->done)
	    info->done(sensor,
		       IPMI_IPMI_ERR_VAL(rsp->data[0]),
		       info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (info->done)
	info->done(sensor, 0, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    free(info);
}

static void
hyst_set_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    hyst_set_info_t *info = cb_data;
    unsigned char   cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t      cmd_msg;
    int             rv;

    if (err) {
	if (info->done)
	    info->done(sensor, err, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_SET_SENSOR_HYSTERESIS_CMD;
    cmd_msg.data_len = 2;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    cmd_data[1] = 0xff;
    cmd_data[2] = info->positive;
    cmd_data[3] = info->negative;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->lun,
				  &cmd_msg, hyst_set, &(info->sdata), info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
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
	return ENOTSUP;
    
    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->positive = positive_hysteresis;
    info->negative = negative_hysteresis;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, hyst_set_start, &(info->sdata), info);
    if (rv)
	free(info);
    return rv;
}

typedef struct thresh_get_info_s
{
    ipmi_sensor_op_info_t sdata;
    ipmi_thresholds_t     th;
    ipmi_thresh_get_cb    done;
    void                  *cb_data;
} thresh_get_info_t;

static void
thresh_get(ipmi_sensor_t *sensor,
	   int           err,
	   ipmi_msg_t    *rsp,
	   void          *cb_data)
{
    thresh_get_info_t  *info = cb_data;
    enum ipmi_thresh_e th;

    if (err) {
	if (info->done)
	    info->done(sensor, err, &(info->th), info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (rsp->data[0]) {
	if (info->done)
	    info->done(sensor,
		       IPMI_IPMI_ERR_VAL(rsp->data[0]),
		       &(info->th),
		       info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }
    
    for (th=IPMI_LOWER_NON_CRITICAL; th<=IPMI_UPPER_NON_RECOVERABLE; th++) {
	int rv;
	if (rsp->data[1] & (1 << th)) {
	    info->th.vals[th].status = 1;
	    rv = ipmi_sensor_convert_from_raw(sensor,
					      rsp->data[th+2],
					      &(info->th.vals[th].val));
	    if (rv) {
		info->done(sensor, rv, &(info->th), info->cb_data);
		ipmi_sensor_opq_done(sensor);
		free(info);
		return;
	    }
	} else {
	    info->th.vals[th].status = 0;
	}
    }

    if (info->done)
	info->done(sensor, 0, &(info->th), info->cb_data);
    ipmi_sensor_opq_done(sensor);
    free(info);
}

int
ipmi_get_default_sensor_thresholds(ipmi_sensor_t     *sensor,
				   int               raw,
				   ipmi_thresholds_t *th)
{
    int                val;
    enum ipmi_thresh_e thnum;
    int                rv = 0;

    for (thnum = IPMI_LOWER_NON_CRITICAL;
	 thnum <= IPMI_UPPER_NON_RECOVERABLE;
	 thnum++)
    {
	ipmi_sensor_threshold_readable(sensor, thnum, &val);
	if (val) {
	    th->vals[thnum].status = 1;
	    rv = ipmi_sensor_convert_from_raw(sensor,
					      raw,
					      &(th->vals[thnum].val));
	    if (rv)
		goto out;
	} else {
	    th->vals[thnum].status = 0;
	}
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

    if (err) {
	if (info->done)
	    info->done(sensor, err, &(info->th), info->cb_data);
	free(info);
	ipmi_sensor_opq_done(sensor);
	return;
    }

    if (sensor->threshold_access == IPMI_THRESHOLD_ACCESS_SUPPORT_FIXED) {
	/* Thresholds are fixed, pull them from the SDR. */
	rv = ipmi_get_default_sensor_thresholds(sensor, 0, &(info->th));
	if (info->done)
	    info->done(sensor, rv, &(info->th), info->cb_data);
	free(info);
	ipmi_sensor_opq_done(sensor);
	return;
    }

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_THRESHOLD_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->lun,
				  &cmd_msg, thresh_get, &(info->sdata), info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, &(info->th), info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
    }
}

static int
stand_ipmi_thresholds_get(ipmi_sensor_t      *sensor,
			  ipmi_thresh_get_cb done,
			  void               *cb_data)
{
    thresh_get_info_t *info;
    int               rv;
    
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (sensor->threshold_access == IPMI_THRESHOLD_ACCESS_SUPPORT_NONE)
	return ENOTSUP;
    
    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, thresh_get_start, &(info->sdata), info);
    if (rv)
	free(info);
    return rv;
}

typedef struct thresh_set_info_s
{
    ipmi_sensor_op_info_t sdata;
    ipmi_thresholds_t     th;
    ipmi_sensor_done_cb   done;
    void                  *cb_data;
} thresh_set_info_t;

static void
thresh_set(ipmi_sensor_t *sensor,
	   int           err,
	   ipmi_msg_t    *rsp,
	   void          *cb_data)
{
    thresh_set_info_t *info = cb_data;

    if (err) {
	if (info->done)
	    info->done(sensor, err, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (rsp->data[0]) {
	if (info->done)
	    info->done(sensor,
		       IPMI_IPMI_ERR_VAL(rsp->data[0]),
		       info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (info->done)
	info->done(sensor, 0, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    free(info);
}

static void
thresh_set_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    thresh_set_info_t  *info = cb_data;
    unsigned char      cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t         cmd_msg;
    int                rv;
    enum ipmi_thresh_e th;

    if (err) {
	if (info->done)
	    info->done(sensor, err, info->cb_data);
	free(info);
	return;
    }

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_SET_SENSOR_THRESHOLD_CMD;
    cmd_msg.data_len = 8;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    cmd_data[1] = 0;
    for (th=IPMI_LOWER_NON_CRITICAL; th<=IPMI_UPPER_NON_RECOVERABLE; th++) {
	if (info->th.vals[th].status) {
	    int val;
	    cmd_data[1] |= (1 << th);
	    rv = ipmi_sensor_convert_to_raw(sensor,
					    ROUND_NORMAL,
					    info->th.vals[th].val,
					    &val);
	    if (rv) {
		info->done(sensor, rv, info->cb_data);
		free(info);
		return;
	    }
	    cmd_data[th+2] = val;
	}
    }

    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->lun,
				  &cmd_msg, thresh_set, &(info->sdata), info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
    }
}

static int
stand_ipmi_thresholds_set(ipmi_sensor_t       *sensor,
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
	return ENOTSUP;
    
    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->th = *thresholds;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, thresh_set_start, &(info->sdata), info);
    if (rv)
	free(info);
    return rv;
}

typedef struct reading_get_info_s
{
    ipmi_sensor_op_info_t sdata;
    ipmi_reading_done_cb  done;
    void                  *cb_data;
} reading_get_info_t;

static void
reading_get(ipmi_sensor_t *sensor,
	    int           err,
	    ipmi_msg_t    *rsp,
	    void          *rsp_data)
{
    reading_get_info_t        *info = rsp_data;
    ipmi_states_t             states;
    int                       rv;
    double                    val = 0.0;
    enum ipmi_value_present_e val_present;

    ipmi_init_states(&states);

    if (err) {
	if (info->done)
	    info->done(sensor, err,
		       IPMI_NO_VALUES_PRESENT, 0, 0.0,
		       &states, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (rsp->data[0]) {
	if (info->done)
	    info->done(sensor,
		       IPMI_IPMI_ERR_VAL(rsp->data[0]),
		       IPMI_NO_VALUES_PRESENT,
		       0,
		       0.0,
		       &states,
		       info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    if (sensor->analog_data_format != IPMI_ANALOG_DATA_FORMAT_NOT_ANALOG) {
	rv = ipmi_sensor_convert_from_raw(sensor,
					  rsp->data[1],
					  &val);
	if (rv)
	    val_present = IPMI_RAW_VALUE_PRESENT;
	else
	    val_present = IPMI_BOTH_VALUES_PRESENT;
    } else {
	val_present = IPMI_NO_VALUES_PRESENT;
    }

    states.__event_messages_disabled = (rsp->data[2] >> 7) & 1;
    states.__sensor_scanning_disabled = (rsp->data[2] >> 6) & 1;
    states.__initial_update_in_progress = (rsp->data[2] >> 5) & 1;
    states.__states = rsp->data[3];

    if (info->done)
	info->done(sensor, 0,
		   val_present, rsp->data[1], val, &states,
		   info->cb_data);
    ipmi_sensor_opq_done(sensor);
    free(info);
}

static void
reading_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    reading_get_info_t *info = cb_data;
    unsigned char      cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t         cmd_msg;
    int                rv;
    ipmi_states_t      states;

    ipmi_init_states(&states);

    if (err) {
	if (info->done)
	    info->done(sensor, err,
		       IPMI_NO_VALUES_PRESENT, 0, 0.0, &states,
		       info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_READING_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->lun,
				  &cmd_msg, reading_get,
				  &(info->sdata), info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv,
		       IPMI_NO_VALUES_PRESENT, 0, 0.0, &states,
		       info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
    }
}

static int
stand_ipmi_reading_get(ipmi_sensor_t        *sensor,
		       ipmi_reading_done_cb done,
		       void                 *cb_data)
{
    reading_get_info_t *info;
    int                rv;
    
    if (sensor->event_reading_type != IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, reading_get_start, &(info->sdata), info);
    if (rv)
	free(info);
    return rv;
}


typedef struct states_get_info_s
{
    ipmi_sensor_op_info_t sdata;
    ipmi_states_read_cb   done;
    void                  *cb_data;
} states_get_info_t;

static void
states_get(ipmi_sensor_t *sensor,
	   int           err,
	   ipmi_msg_t    *rsp,
	   void          *cb_data)
{
    states_get_info_t *info = cb_data;
    ipmi_states_t     states;

    ipmi_init_states(&states);

    if (err) {
	if (info->done)
	    info->done(sensor, err, &states, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
    }

    if (rsp->data[0]) {
	if (info->done)
	    info->done(sensor,
		       IPMI_IPMI_ERR_VAL(rsp->data[0]),
		       &states,
		       info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    states.__event_messages_disabled = (rsp->data[2] >> 7) & 1;
    states.__sensor_scanning_disabled = (rsp->data[2] >> 6) & 1;
    states.__initial_update_in_progress = (rsp->data[2] >> 5) & 1;
    states.__states = (rsp->data[4] << 8) | rsp->data[3];

    if (info->done)
	info->done(sensor, 0, &states, info->cb_data);
    ipmi_sensor_opq_done(sensor);
    free(info);
}

static void
states_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    states_get_info_t *info = cb_data;
    unsigned char     cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t        cmd_msg;
    int               rv;
    ipmi_states_t     states;

    ipmi_init_states(&states);

    if (err) {
	if (info->done)
	    info->done(sensor, err, &states, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
	return;
    }

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_READING_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_sensor_send_command(sensor, sensor->mc, sensor->lun,
				  &cmd_msg, states_get,
				  &(info->sdata), info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, &states, info->cb_data);
	ipmi_sensor_opq_done(sensor);
	free(info);
    }
}

static int
stand_ipmi_states_get(ipmi_sensor_t       *sensor,
		      ipmi_states_read_cb done,
		      void                *cb_data)
{
    states_get_info_t *info;
    int               rv;
    
    if (sensor->event_reading_type == IPMI_EVENT_READING_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have states. */
	return ENOSYS;

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, states_get_start, &(info->sdata), info);
    if (rv)
	free(info);
    return rv;
}

static double c_linear(double val)
{
    return val;
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
static linearizer linearize[11] =
{
    c_linear,
    log,
    log10,
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

    m = sign_extend(sensor->conv[val].m, 10);
    b = sign_extend(sensor->conv[val].b, 10);
    r_exp = sign_extend(sensor->conv[val].r_exp, 4);
    b_exp = sign_extend(sensor->conv[val].b_exp, 4);

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

	if (cval > val) {
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

    m = sign_extend(sensor->conv[val].m, 10);
    r_exp = sign_extend(sensor->conv[val].r_exp, 4);

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

static char *
stand_ipmi_sensor_reading_name_string(ipmi_sensor_t *sensor, int val)
{
    return ipmi_get_reading_name(sensor->event_reading_type,
				 sensor->sensor_type,
				 val);
}

ipmi_sensor_cbs_t ipmi_standard_sensor_cb =
{
    .ipmi_sensor_events_enable_set = stand_ipmi_sensor_events_enable_set,
    .ipmi_sensor_events_enable_get = stand_ipmi_sensor_events_enable_get,

    .ipmi_sensor_convert_from_raw  = stand_ipmi_sensor_convert_from_raw,
    .ipmi_sensor_convert_to_raw    = stand_ipmi_sensor_convert_to_raw,
    .ipmi_sensor_get_accuracy      = stand_ipmi_sensor_get_accuracy,
    .ipmi_sensor_get_tolerance     = stand_ipmi_sensor_get_tolerance,
    .ipmi_sensor_get_hysteresis    = stand_ipmi_sensor_get_hysteresis,
    .ipmi_sensor_set_hysteresis    = stand_ipmi_sensor_set_hysteresis,
    .ipmi_thresholds_set           = stand_ipmi_thresholds_set,
    .ipmi_thresholds_get           = stand_ipmi_thresholds_get,
    .ipmi_reading_get              = stand_ipmi_reading_get,

    .ipmi_states_get               = stand_ipmi_states_get,
    .ipmi_sensor_reading_name_string = stand_ipmi_sensor_reading_name_string,
};

int
ipmi_sensor_events_enable_set(ipmi_sensor_t         *sensor,
			      ipmi_event_state_t    *states,
			      ipmi_sensor_done_cb   done,
			      void                  *cb_data)
{
    if (!sensor->cbs.ipmi_sensor_events_enable_set)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_events_enable_set(sensor,
						     states,
						     done,
						     cb_data);
}

int
ipmi_sensor_events_enable_get(ipmi_sensor_t             *sensor,
			      ipmi_event_enables_get_cb done,
			      void                      *cb_data)
{
    if (!sensor->cbs.ipmi_sensor_events_enable_get)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_events_enable_get(sensor,
						     done,
						     cb_data);
}

int
ipmi_sensor_get_hysteresis(ipmi_sensor_t          *sensor,
			   ipmi_hysteresis_get_cb done,
			   void                   *cb_data)
{
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
    if (!sensor->cbs.ipmi_sensor_set_hysteresis)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_set_hysteresis(sensor,
						  positive_hysteresis,
						  negative_hysteresis,
						  done,
						  cb_data);
}

int
ipmi_thresholds_get(ipmi_sensor_t      *sensor,
		    ipmi_thresh_get_cb done,
		    void               *cb_data)
{
    if (!sensor->cbs.ipmi_thresholds_get)
	return ENOSYS;
    return sensor->cbs.ipmi_thresholds_get(sensor, done, cb_data);
}

int
ipmi_thresholds_set(ipmi_sensor_t       *sensor,
		    ipmi_thresholds_t   *thresholds,
		    ipmi_sensor_done_cb done,
		    void                *cb_data)
{
    if (!sensor->cbs.ipmi_thresholds_set)
	return ENOSYS;
    return sensor->cbs.ipmi_thresholds_set(sensor, thresholds, done, cb_data);
}

int
ipmi_reading_get(ipmi_sensor_t        *sensor,
		 ipmi_reading_done_cb done,
		 void                 *cb_data)
{
    if (!sensor->cbs.ipmi_reading_get)
	return ENOSYS;
    return sensor->cbs.ipmi_reading_get(sensor, done, cb_data);
}

int
ipmi_states_get(ipmi_sensor_t       *sensor,
		ipmi_states_read_cb done,
		void                *cb_data)
{
    if (!sensor->cbs.ipmi_states_get)
	return ENOSYS;
    return sensor->cbs.ipmi_states_get(sensor, done, cb_data);
}

char *
ipmi_sensor_reading_name_string(ipmi_sensor_t *sensor, int val)
{
    if (!sensor->cbs.ipmi_sensor_reading_name_string)
	return NULL;
    return sensor->cbs.ipmi_sensor_reading_name_string(sensor, val);
}

int
ipmi_sensor_convert_from_raw(ipmi_sensor_t *sensor,
			     int           val,
			     double        *result)
{
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
    if (!sensor->cbs.ipmi_sensor_get_tolerance)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_get_tolerance(sensor, val, tolerance);
}

/* Returns accuracy as a percentage value. */
int
ipmi_sensor_get_accuracy(ipmi_sensor_t *sensor, int val, double *accuracy)
{
    if (!sensor->cbs.ipmi_sensor_get_accuracy)
	return ENOSYS;
    return sensor->cbs.ipmi_sensor_get_accuracy(sensor, val, accuracy);
}

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

void
ipmi_sensor_set_oem_info(ipmi_sensor_t *sensor, void *oem_info)
{
    sensor->oem_info = oem_info;
}

void *
ipmi_sensor_get_oem_info(ipmi_sensor_t *sensor)
{
    return sensor->oem_info;
}

char *
ipmi_sensor_get_sensor_type_string(ipmi_sensor_t *sensor)
{
    return sensor->sensor_type_string;
}

void
ipmi_sensor_set_sensor_type_string(ipmi_sensor_t *sensor, char *str)
{
    sensor->sensor_type_string = str;
}

char *
ipmi_sensor_get_event_reading_type_string(ipmi_sensor_t *sensor)
{
    return sensor->event_reading_type_string;
}

void
ipmi_sensor_set_event_reading_type_string(ipmi_sensor_t *sensor, char *str)
{
    sensor->event_reading_type_string = str;
}

char *
ipmi_sensor_get_rate_unit_string(ipmi_sensor_t *sensor)
{
    return sensor->rate_unit_string;
}

void
ipmi_sensor_set_rate_unit_string(ipmi_sensor_t *sensor, char *str)
{
    sensor->rate_unit_string = str;
}

char *
ipmi_sensor_get_base_unit_string(ipmi_sensor_t *sensor)
{
    return sensor->base_unit_string;
}

void
ipmi_sensor_set_base_unit_string(ipmi_sensor_t *sensor, char *str)
{
    sensor->base_unit_string = str;
}

char *
ipmi_sensor_get_modifier_unit_string(ipmi_sensor_t *sensor)
{
    return sensor->modifier_unit_string;
}

void
ipmi_sensor_set_modifier_unit_string(ipmi_sensor_t *sensor, char *str)
{
    sensor->modifier_unit_string = str;
}

ipmi_entity_t *
ipmi_sensor_get_entity(ipmi_sensor_t *sensor)
{
    int           rv;
    ipmi_entity_t *ent;

    rv = ipmi_entity_find(ipmi_mc_get_entities(sensor->mc),
			  sensor->mc,
			  sensor->entity_id,
			  sensor->entity_instance,
			  &ent);
    if (rv)
	return NULL;
    return ent;
}

void
ipmi_sensor_set_hot_swap_requester(ipmi_sensor_t *sensor, int val)
{
    sensor->hot_swap_requester = val;
}

int
ipmi_sensor_is_hot_swap_requester(ipmi_sensor_t *sensor)
{
    return sensor->hot_swap_requester;
}
