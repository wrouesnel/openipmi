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

extern ipmi_sensor_cbs_t standard_sensor_cb;

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

    char id[SENSOR_ID_LEN+1];

    ipmi_sensor_event_handler_cb event_handler;
    void                         *cb_data;

    opq_t *waitq;
    ipmi_event_state_t event_state;

    /* Polymorphic functions. */
    ipmi_sensor_cbs_t cbs;
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

typedef struct mc_cb_info_s
{
    ipmi_sensor_cb   handler;
    void             *cb_data;
    ipmi_sensor_id_t id;
    int              err;
} mc_cb_info_t;

static void mc_cb(ipmi_mc_t *mc, void *cb_data)
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
ipmi_find_sensor(ipmi_mc_t *mc, int lun, int num,
		 ipmi_sensor_cb handler, void *cb_data)
{
    int                rv = 0;
    ipmi_sensor_info_t *sensors;

    if (lun > 4)
	return EINVAL;

    ipmi_mc_entity_lock(mc);
    sensors = ipmi_mc_get_sensors(mc);
    if (num > sensors->idx_size[lun])
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

void
ipmi_sensor_destroy_nonstandard(ipmi_sensor_t *sensor)
{
    free(sensor);
}

int
ipmi_sensor_add_nonstandard(ipmi_mc_t     *mc,
			    ipmi_sensor_t *sensor,
			    ipmi_entity_t *ent)
{
    int                i;
    int                found = 0;
    ipmi_sensor_info_t *sensors = ipmi_mc_get_sensors(mc);
    void               *link;


    for (i=0; i<sensors->idx_size[4]; i++) {
	if (!sensors->sensors_by_idx[4][i]) {
	    found = 1;
	}
    }

    if (!found) {
	ipmi_sensor_t **new_array;

	if (sensors->idx_size[4] >= 256)
	    return EMFILE;
	new_array = malloc(sizeof(*new_array) * (sensors->idx_size[4] + 16));
	if (!new_array)
	    return ENOMEM;
	memcpy(new_array, sensors->sensors_by_idx[4],
	       sizeof(*new_array) * (sensors->idx_size[4]));
	for (i=sensors->idx_size[4]; i<sensors->idx_size[4]+16; i++)
	    new_array[i] = NULL;
	if (sensors->sensors_by_idx[4])
	    free(sensors->sensors_by_idx[4]);
	sensors->sensors_by_idx[4] = new_array;
	i = sensors->idx_size[4];
	sensors->idx_size[4] = i+16;
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
    sensor->num = i;
    sensors->sensors_by_idx[4][i] = sensor;
    sensor->entity_id = ipmi_entity_get_entity_id(ent);
    sensor->entity_instance = ipmi_entity_get_entity_instance(ent);

    ipmi_entity_add_sensor(ent, mc, sensor->lun, sensor->num, sensor, link);

    return 0;
}

int
ipmi_sensor_remove_nonstandard(ipmi_sensor_t *sensor)
{
    ipmi_sensor_info_t *sensors = ipmi_mc_get_sensors(sensor->mc);
    ipmi_entity_info_t *ents = ipmi_mc_get_entities(sensor->mc);
    ipmi_entity_t      *ent;
    int                rv;

    rv = ipmi_entity_find(ents,
			  sensor->mc,
			  sensor->entity_id,
			  sensor->entity_instance,
			  &ent);
    if (!rv)
	ipmi_entity_remove_sensor(ent, sensor->mc,
				  sensor->lun, sensor->num, sensor);

    sensors->sensors_by_idx[4][sensor->num] = 0;
    return 0;
}

static void
sensor_final_destroy(ipmi_sensor_t *sensor)
{
    opq_destroy(sensor->waitq);
    free(sensor);
}

void
ipmi_sensor_destroy(ipmi_sensor_t *sensor)
{
    sensor->destroyed = 1;
    if (!opq_stuff_in_progress(sensor->waitq))
	sensor_final_destroy(sensor);
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
get_sensors_from_sdrs(ipmi_mc_t          *mc,
		      ipmi_sdr_info_t    *sdrs,
		      ipmi_sensor_t      **(new_by_idx[4]),
		      int                new_idx_size[4])
{
    ipmi_sdr_t    sdr;
    unsigned int  count;
    ipmi_sensor_t **s = NULL;
    unsigned int  p, s_size = 0;
    int           val;
    int           rv;
    int           i, j;
    int           max_sensor_num[4];
    ipmi_sensor_t **sl[4];

    for (i=0; i<4; i++) {
	max_sensor_num[i] = 0;
	sl[i] = NULL;
    }

    rv = ipmi_get_sdr_count(sdrs, &count);
    if (rv)
	goto out_err;

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

	if ((sdr.data[2]+incr-1) > max_sensor_num[lun])
	    max_sensor_num[lun] = sdr.data[2] + incr - 1;
	p += incr;
    }

    s = malloc(sizeof(*s) * p);
    if (!s) {
	rv = ENOMEM;
	goto out_err;
    }
    s_size = p;
    memset(s, 0, sizeof(*s) * p);

    for (i=0; i<4; i++) {
	if (max_sensor_num[i] >= 0) {
	    sl[i] = malloc(sizeof(*(sl[i])) * (max_sensor_num[i]+1));
	    if (! sl[i]) {
		rv = ENOMEM;
		goto out_err;
	    }
	    memset(sl[i], 0, sizeof(*(sl[i])) * (max_sensor_num[i]+1));
	}
    }

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

	s[p]->waitq = opq_alloc(ipmi_mc_get_os_hnd(mc));
	if (!s[p]->waitq) {
	    rv = ENOMEM;
	    goto out_err;
	}

	s[p]->destroyed = 0;

	s[p]->mc = mc;
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

	    sl[s[p]->lun][s[p]->num] = s[p];

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

	    /* Go backwards to avoid destroying the first one until we finish
	       the others. */
	    for (j=(sdr.data[18] & 0x0f)-1; j>=0; j--) {
		int len;

		s[p+j] = s[p];

		s[p+j]->num += j;

		sl[s[p+j]->lun][s[p+j]->num] = s[p+j];

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

    memcpy(new_by_idx, sl, sizeof(sl));
    for (i=0; i<4; i++)
	new_idx_size[i] = max_sensor_num[i] + 1;
    free(s);
    return 0;

 out_err:
    for (i=0; i<4; i++)
	if (sl[i])
	    free(sl[i]);
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
    ipmi_mc_t                *mc;
    ipmi_mc_done_cb          done;
    void                     *done_data;
    ipmi_sensor_info_t       *sensors;
} sdr_fetch_info_t;

static void
handle_new_sensor(ipmi_mc_t     *mc,
		  ipmi_sensor_t *sensor,
		  void          *link)
{
    ipmi_entity_info_t *ents;
    ipmi_entity_t      *ent;


    /* Call this before the OEM call so the OEM call can replace it. */
    sensor->cbs = standard_sensor_cb;

    ents = ipmi_mc_get_entities(mc);

    /* This can't fail, we have pre-added it while we held the lock. */
    ipmi_entity_find(ents,
		     mc,
		     sensor->entity_id,
		     sensor->entity_instance,
		     &ent);

    if (! ipmi_bmc_oem_new_sensor(ipmi_mc_get_bmc(mc), ent, sensor, link))
	ipmi_entity_add_sensor(ent, mc,
			       sensor->lun, sensor->num, sensor, link);
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
swap_sensor_info(ipmi_mc_t         *mc,
		 ipmi_sensor_t     **old,
		 ipmi_sensor_t     **new)
{
    opq_t         *tmp_waitq = (*old)->waitq;
    ipmi_sensor_t tmp, *ptmp;

    /* Swap the information int he new and old sensor structure. */
    tmp = **old;
    **old = **new;
    **new = tmp;

    /* We keep the waitq unchanged, though. */
    (*old)->waitq = (*new)->waitq;
    (*new)->waitq = tmp_waitq;

    /* Now swap the pointers. */
    ptmp = *old;
    *old = *new;
    *new = ptmp;
}

static void
handle_changed_sensor(ipmi_mc_t         *mc,
		      ipmi_sensor_t     *old,
		      ipmi_sensor_t     *new)
{
    ipmi_entity_info_t *ents;
    ipmi_entity_t      *ent;

    ents = ipmi_mc_get_entities(mc);

    ipmi_entity_find(ents,
		     mc,
		     old->entity_id,
		     old->entity_instance,
		     &ent);

    /* The entity has to be there because it's in the list, no need to
       check for errors. */
    ipmi_entity_sensor_changed(ent, mc, old->lun, old->num, old, new);
}

static void
handle_deleted_sensor(ipmi_mc_t         *mc,
		      ipmi_sensor_t     *sensor)
{
    ipmi_entity_info_t *ents;
    ipmi_entity_t      *ent;
    int                rv;

    ents = ipmi_mc_get_entities(mc);

    rv = ipmi_entity_find(ents,
			  mc,
			  sensor->entity_id,
			  sensor->entity_instance,
			  &ent);
    if (!rv)
	ipmi_entity_remove_sensor(ent, mc, sensor->lun, sensor->num, sensor);
}

static void
sensor_reread_done(sdr_fetch_info_t *info, int err)
{
    if (info->done)
	info->done(info->mc, err, info->done_data);
    opq_op_done(info->sensors->sensor_wait_q);
    free(info);
}

typedef struct dummy_link_s dummy_link_t;
struct dummy_link_s
{
    dummy_link_t *next;
};
static void
sdrs_fetched(ipmi_sdr_info_t *sdrs,
	     int             err,
	     int             changed,
	     unsigned int    count,
	     void            *cb_data)
{
    sdr_fetch_info_t   *info = (sdr_fetch_info_t *) cb_data;
    ipmi_mc_t          *mc = info->mc;
    int                rv;
    int                i, j;
    ipmi_sensor_t      **(old_by_idx[4]);
    int                old_idx_size[4];
    ipmi_sensor_t      **(new_by_idx[4]);
    int                new_idx_size[4];
    dummy_link_t       *sref = NULL;
    dummy_link_t       *snext = NULL;

    if (err) {
	rv = err;
	goto out_err;
    }

    for (i=0; i<4; i++) {
	old_by_idx[i] = info->sensors->sensors_by_idx[i];
	old_idx_size[i] = info->sensors->idx_size[i];
    }

    rv = get_sensors_from_sdrs(mc, sdrs, new_by_idx, new_idx_size);
    if (rv)
	goto out_err;

    ipmi_mc_entity_lock(mc);

    /* Pre-allocate all the links we will need for registering sensors
       with the entities, and we make sure all the entities exist. */
    for (i=0; i<4; i++) {
	ipmi_entity_info_t *ents = ipmi_mc_get_entities(mc);

	for (j=0; j<new_idx_size[i]; j++) {
	    ipmi_sensor_t *nsensor = new_by_idx[i][j];
	    if (nsensor != NULL) {
		/* Make sure the entity exists for ALL sensors in the
		   new list.  This way, if a sensor has changed
		   entities, the new entity will exist. */
		rv = ipmi_entity_add(ents,
				     mc,
				     i,
				     nsensor->entity_id,
				     nsensor->entity_instance,
				     NULL,
				     NULL,
				     NULL);
		if (rv)
		    goto out_err_unlock_free;

		/* A sensor is new if it's number is beyond the old
                   number, if it's number didn't exist in the old
                   list, or if it's entity changed. */
		if ((j >= old_idx_size[i])
		    || (old_by_idx[i][j] == NULL)
		    || ((old_by_idx[i][j]->entity_id
			 != new_by_idx[i][j]->entity_id)
			|| (old_by_idx[i][j]->entity_instance
			    != new_by_idx[i][j]->entity_instance)))
		{
		    /* It's a new sensor, allocate a link item for
                       it. */
		    snext = ipmi_entity_alloc_sensor_link();
		    if (!snext) {
			rv = ENOMEM;
			goto out_err_unlock_free;
		    }
		    snext->next = sref;
		    sref = snext;
		}
	    }
	}
    }

    /* FIXME - find and report duplicate sensors numbers/luns. */

    /* After this point, the operation cannot fail. */

    /* We prefer to keep the old sensor data structures, because that
       way the pointers don't change and we don't have to do any
       messing around in any other tables. */
    for (i=0; i<4; i++) {
	for (j=0; j<old_idx_size[i] && j<new_idx_size[i]; j++) {
	    if (old_by_idx[i][j] && new_by_idx[i][j]) {
		if ((old_by_idx[i][j]->entity_id
		     != new_by_idx[i][j]->entity_id)
		    || (old_by_idx[i][j]->entity_instance
			!= new_by_idx[i][j]->entity_instance))
		{
		    /* In this case, we are destroying the old sensor and
		       creating a new sensor, so no need to copy. */
		} else {
		    /* If we have a sensor that existed before, swap the
		       old and the new, we prefer to keep the pointers th
		       same. */
		    swap_sensor_info(mc,
				     &(old_by_idx[i][j]),
				     &(new_by_idx[i][j]));
		}
	    }
	}
    }

    for (i=0; i<4; i++) {
	info->sensors->sensors_by_idx[i] = new_by_idx[i];
	info->sensors->idx_size[i] = new_idx_size[i];
    }

    /* Now go through all the sensors and try to find new ones, ones
       that have changed, and ones that have gone away. */
    for (i=0; i<4; i++) {
	for (j=0; j<old_idx_size[i] && j<new_idx_size[i]; j++) {
	    if ((old_by_idx[i][j] == NULL)
		&& (new_by_idx[i][j] != NULL))
	    {
		snext = sref;
		sref = sref->next;
		handle_new_sensor(mc, new_by_idx[i][j], snext);
	    }
	}
	for (; j<new_idx_size[i]; j++) {
	    if (new_by_idx[i][j]) {
		snext = sref;
		sref = sref->next;
		handle_new_sensor(mc, new_by_idx[i][j], snext);
	    }
	}
    }

    for (i=0; i<4; i++) {
	for (j=0; j<old_idx_size[i] && j<new_idx_size[i]; j++) {
	    if (old_by_idx[i][j] && new_by_idx[i][j]) {
		if ((old_by_idx[i][j]->entity_id
		     != new_by_idx[i][j]->entity_id)
		    || (old_by_idx[i][j]->entity_instance
			!= new_by_idx[i][j]->entity_instance))
		{
		    /* If the sensor changes target IDs, we need to delete the
		       old sensor and add the new one, since it's really a new
		       sensor. */
		    handle_deleted_sensor(mc, old_by_idx[i][j]);
		    snext = sref;
		    sref = sref->next;
		    handle_new_sensor(mc, new_by_idx[i][j], snext);
		} else if (cmp_sensor(old_by_idx[i][j],
				      new_by_idx[i][j]))
		    handle_changed_sensor(mc,
					  old_by_idx[i][j],
					  new_by_idx[i][j]);
	    }
	}
    }

    for (i=0; i<4; i++) {
	for (j=0; j<new_idx_size[i] && j<old_idx_size[i]; j++) {
	    if ((old_by_idx[i][j] != NULL)
		&& (new_by_idx[i][j] == NULL))
	    {
		handle_deleted_sensor(mc, old_by_idx[i][j]);
	    }
	}
	for (; j<old_idx_size[i]; j++)
	    if (old_by_idx[i][j])
		handle_deleted_sensor(mc, old_by_idx[i][j]);
    }

    ipmi_mc_entity_unlock(mc);

    /* Free all the old information. */
    for (i=0; i<4; i++) {
	for (j=0; j<old_idx_size[i]; j++) {
	    if (old_by_idx[i][j]) {
		ipmi_sensor_destroy(old_by_idx[i][j]);
	    }
	}
	if (old_by_idx[i])
	    free(old_by_idx[i]);
    }

    sensor_reread_done(info, err);

    /* These should be all used up, but just in case... */
    while (sref) {
	snext = sref->next;
	ipmi_entity_free_sensor_link(sref);
	sref = snext;
    }
    return;

 out_err_unlock_free:
    ipmi_mc_entity_unlock(mc);
    for (i=0; i<4; i++) {
	for (j=0; j<new_idx_size[i]; j++) {
	    if (new_by_idx[i][j]) {
		if (new_by_idx[i][j]->waitq)
		    opq_destroy(new_by_idx[i][j]->waitq);
		free(new_by_idx[i][j]);
	    }
	}
	if (new_by_idx[i])
	    free(new_by_idx[i]);
    }
 out_err:
    while (sref) {
	snext = sref->next;
	free(sref);
	sref = snext;
    }
    sensor_reread_done(info, err);
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

    rv = ipmi_sdr_fetch(ipmi_mc_get_sdrs(info->mc), sdrs_fetched, info);
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

    info->mc = mc;
    info->done = done;
    info->done_data = done_data;

    if (! opq_new_op(info->sensors->sensor_wait_q, sensor_read_handler, info, 0))
	rv = ENOMEM;

    if (rv) {
	free(info);
    } else {
	ipmi_detect_bmc_presence_changes(info->mc, 0);
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

    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    idx = (event * 2) + dir;
    if (idx > 11)
	return EINVAL;

    *val = sensor->mask1[idx];
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

    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    idx = (event * 2) + dir;
    if (idx > 11)
	return 0;

    *val = sensor->mask2[idx];
    return 0;
}

int
ipmi_sensor_threshold_settable(ipmi_sensor_t      *sensor,
			       enum ipmi_thresh_e event,
			       int                *val)
{
    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (event > IPMI_UPPER_NON_RECOVERABLE)
	return EINVAL;

    *val = sensor->mask3[event + 8];
    return 0;
}

int
ipmi_sensor_threshold_readable(ipmi_sensor_t      *sensor,
			       enum ipmi_thresh_e event,
			       int                *val)
{
    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (event > IPMI_UPPER_NON_RECOVERABLE)
	return EINVAL;

    *val = sensor->mask3[event];
    return 0;
}

int
ipmi_discrete_assertion_event_supported(ipmi_sensor_t *sensor,
					int           event,
					int           *val)
{
    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (event > 14)
	return EINVAL;

    *val = sensor->mask1[event];
    return 0;
}

int
ipmi_discrete_deassertion_event_supported(ipmi_sensor_t *sensor,
					  int           event,
					  int           *val)
{
    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (event > 14)
	return EINVAL;

    *val = sensor->mask2[event];
    return 0;
}

int
ipmi_discrete_event_readable(ipmi_sensor_t *sensor,
			     int           event,
			     int           *val)
{
    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (event > 14)
	return EINVAL;

    *val = sensor->mask3[event];
    return 0;
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
ipmi_sensor_set_event_handler(ipmi_sensor_t                *sensor,
			      ipmi_sensor_event_handler_cb handler,
			      void                         *cb_data)
{
    sensor->event_handler = handler;
    sensor->cb_data = cb_data;
    return 0;
}

int
ipmi_sensor_event(ipmi_sensor_t *sensor, ipmi_msg_t *event)
{
    enum ipmi_event_dir_e dir;
    int                   value_present = 0;
    double                value = 0.0;
    int                   offset;
    int                   rv;

    if (!sensor->event_handler)
	return EINVAL;

    dir = event->data[12] >> 7;
    offset = event->data[12] & 0x0f;
    if (sensor->event_reading_type == IPMI_EVENT_TYPE_THRESHOLD) {
	if ((event->data[13] >> 6) == 2) {
	    rv = ipmi_sensor_convert_from_raw(sensor, event->data[14], &value);
	    if (!rv)
		value_present = 1;
	}
    }
    sensor->event_handler(sensor, dir, offset, value_present, value,
			  sensor->cb_data);
    return 0;
}

typedef struct event_enable_info_s
{
    ipmi_event_state_t    state;
    ipmi_sensor_done_cb   done;
    void                  *cb_data;
    ipmi_sensor_id_t      sensor_id;
    ipmi_sensor_t         *sensor;
    ipmi_msg_t            *rsp;
} event_enable_info_t;

static void
disables_set2(ipmi_sensor_t *sensor, void *cb_data)
{
    event_enable_info_t *info = cb_data;

    if (info->rsp->data[0]) {
	if (info->done)
	    info->done(info->sensor,
		       IPMI_IPMI_ERR_VAL(info->rsp->data[0]),
		       info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->done)
	info->done(info->sensor, 0, info->cb_data);
    opq_op_done(info->sensor->waitq);
    free(info);
}

static void
disables_set(ipmi_mc_t  *mc,
	     ipmi_msg_t *rsp,
	     void       *rsp_data)
{
    event_enable_info_t *info = rsp_data;
    mc_cb_info_t        mc_info;

    if (!mc) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->sensor->destroyed) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->cb_data);
	free(info);
	sensor_final_destroy(info->sensor);
	return;
    }

    /* Call the next stage with the lock held. */
    info->rsp = rsp;
    mc_info.err = 0;
    mc_info.id = info->sensor_id;
    mc_info.cb_data = info;
    mc_info.handler = disables_set2;
    mc_cb(mc, &mc_info);
    if (mc_info.err) {
	if (info->done)
	    info->done(info->sensor, mc_info.err, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
enables_set2(ipmi_sensor_t *sensor,
	     void          *cb_data)
{
    event_enable_info_t *info = cb_data;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;

    if (info->rsp->data[0]) {
	if (info->done)
	    info->done(info->sensor,
		       IPMI_IPMI_ERR_VAL(info->rsp->data[0]),
		       info->cb_data);
	opq_op_done(info->sensor->waitq);
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
    rv = ipmi_send_command(sensor->mc, sensor->lun, &cmd_msg,
			   disables_set, info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
enables_set(ipmi_mc_t  *mc,
	    ipmi_msg_t *rsp,
	    void       *rsp_data)
{
    event_enable_info_t *info = rsp_data;
    mc_cb_info_t        mc_info;

    if (!mc) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->sensor->destroyed) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->cb_data);
	free(info);
	sensor_final_destroy(info->sensor);
	return;
    }

    /* Call the next stage with the lock held. */
    info->rsp = rsp;
    mc_info.err = 0;
    mc_info.id = info->sensor_id;
    mc_info.cb_data = info;
    mc_info.handler = enables_set2;
    mc_cb(mc, &mc_info);
    if (mc_info.err) {
	if (info->done)
	    info->done(info->sensor, mc_info.err, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
event_enable_set_start2(ipmi_sensor_t *sensor, void *cb_data)
{
    event_enable_info_t *info = cb_data;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;

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
    rv = ipmi_send_command(sensor->mc, sensor->lun, &cmd_msg, enables_set, info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
event_enable_set_start(void *cb_data, int shutdown)
{
    event_enable_info_t *info = cb_data;
    int                 rv;

    if (shutdown) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    rv = ipmi_sensor_pointer_cb(info->sensor_id, event_enable_set_start2, info);
    if (rv) {
	if (info->done)
	    info->done(info->sensor, rv, info->cb_data);
	opq_op_done(info->sensor->waitq);
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
    
    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->state = *states;
    info->done = done;
    info->cb_data = cb_data;
    info->sensor = sensor;
    info->sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!opq_new_op(sensor->waitq, event_enable_set_start, info, 0)) {
	free(info);
	return ENOMEM;
    }
    return 0;
}

typedef struct event_enable_get_info_s
{
    ipmi_event_state_t        state;
    ipmi_event_enables_get_cb done;
    void                      *cb_data;
    ipmi_sensor_id_t          sensor_id;
    ipmi_sensor_t             *sensor;
    ipmi_msg_t                *rsp;
} event_enable_get_info_t;

static void
enables_get2(ipmi_sensor_t *sensor,
	     void          *cb_data)
{
    event_enable_get_info_t *info = cb_data;

    if (info->rsp->data[0]) {
	if (info->done)
	    info->done(info->sensor,
		       IPMI_IPMI_ERR_VAL(info->rsp->data[0]),
		       info->state,
		       info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    info->state.status = info->rsp->data[1] & 0xc0;
    info->state.__assertion_events = (info->rsp->data[2]
				      | (info->rsp->data[3] << 8));
    info->state.__deassertion_events = (info->rsp->data[4]
					| (info->rsp->data[5] << 8));
    if (info->done)
	info->done(sensor, 0, info->state, info->cb_data);
    opq_op_done(info->sensor->waitq);
    free(info);
}

static void
enables_get(ipmi_mc_t  *mc,
	    ipmi_msg_t *rsp,
	    void       *rsp_data)
{
    event_enable_get_info_t *info = rsp_data;
    mc_cb_info_t        mc_info;

    if (!mc) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->state, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->sensor->destroyed) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->state, info->cb_data);
	free(info);
	sensor_final_destroy(info->sensor);
	return;
    }

    /* Call the next stage with the lock held. */
    info->rsp = rsp;
    mc_info.err = 0;
    mc_info.id = info->sensor_id;
    mc_info.cb_data = info;
    mc_info.handler = enables_get2;
    mc_cb(mc, &mc_info);
    if (mc_info.err) {
	if (info->done)
	    info->done(info->sensor, mc_info.err, info->state, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
event_enable_get_start2(ipmi_sensor_t *sensor, void *cb_data)
{
    event_enable_get_info_t *info = cb_data;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_EVENT_ENABLE_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_send_command(sensor->mc, sensor->lun, &cmd_msg, enables_get, info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, info->state, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
event_enable_get_start(void *cb_data, int shutdown)
{
    event_enable_get_info_t *info = cb_data;
    int                 rv;

    if (shutdown) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->state, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    rv = ipmi_sensor_pointer_cb(info->sensor_id, event_enable_get_start2, info);
    if (rv) {
	if (info->done)
	    info->done(info->sensor, rv, info->state, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static int
stand_ipmi_sensor_events_enable_get(ipmi_sensor_t             *sensor,
				    ipmi_event_enables_get_cb done,
				    void                      *cb_data)
{
    event_enable_get_info_t *info;

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    info->sensor = sensor;
    info->sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!opq_new_op(sensor->waitq, event_enable_get_start, info, 0)) {
	free(info);
	return ENOMEM;
    }
    return 0;
}

typedef struct hyst_get_info_s
{
    ipmi_hysteresis_get_cb    done;
    void                      *cb_data;
    ipmi_sensor_id_t          sensor_id;
    ipmi_sensor_t             *sensor;
    ipmi_msg_t                *rsp;
} hyst_get_info_t;

static void
hyst_get2(ipmi_sensor_t *sensor,
	  void          *cb_data)
{
    hyst_get_info_t *info = cb_data;

    if (info->rsp->data[0]) {
	if (info->done)
	    info->done(info->sensor,
		       IPMI_IPMI_ERR_VAL(info->rsp->data[0]),
		       0,
		       0,
		       info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->done)
	info->done(sensor,
		   0,
		   info->rsp->data[1],
		   info->rsp->data[2],
		   info->cb_data);
    opq_op_done(info->sensor->waitq);
    free(info);
}

static void
hyst_get(ipmi_mc_t  *mc,
	 ipmi_msg_t *rsp,
	 void       *rsp_data)
{
    hyst_get_info_t *info = rsp_data;
    mc_cb_info_t    mc_info;

    if (!mc) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, 0, 0, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->sensor->destroyed) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, 0, 0, info->cb_data);
	free(info);
	sensor_final_destroy(info->sensor);
	return;
    }

    /* Call the next stage with the lock held. */
    info->rsp = rsp;
    mc_info.err = 0;
    mc_info.id = info->sensor_id;
    mc_info.cb_data = info;
    mc_info.handler = hyst_get2;
    mc_cb(mc, &mc_info);
    if (mc_info.err) {
	if (info->done)
	    info->done(info->sensor, mc_info.err, 0, 0, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
hyst_get_start2(ipmi_sensor_t *sensor, void *cb_data)
{
    hyst_get_info_t *info = cb_data;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_HYSTERESIS_CMD;
    cmd_msg.data_len = 2;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    cmd_data[1] = 0xff;
    rv = ipmi_send_command(sensor->mc, sensor->lun, &cmd_msg, hyst_get, info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, 0, 0, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
hyst_get_start(void *cb_data, int shutdown)
{
    hyst_get_info_t *info = cb_data;
    int                 rv;

    if (shutdown) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, 0, 0, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    rv = ipmi_sensor_pointer_cb(info->sensor_id, hyst_get_start2, info);
    if (rv) {
	if (info->done)
	    info->done(info->sensor, rv, 0, 0, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static int
stand_ipmi_sensor_get_hysteresis(ipmi_sensor_t          *sensor,
				 ipmi_hysteresis_get_cb done,
				 void                   *cb_data)
{
    hyst_get_info_t *info;
    
    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (sensor->hysteresis_support != IPMI_HYSTERESIS_SUPPORT_READABLE)
	return ENOTSUP;
    
    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    info->sensor = sensor;
    info->sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!opq_new_op(sensor->waitq, hyst_get_start, info, 0)) {
	free(info);
	return ENOMEM;
    }
    return 0;
}

typedef struct hyst_set_info_s
{
    unsigned int        positive, negative;
    ipmi_sensor_done_cb done;
    void                *cb_data;
    ipmi_sensor_id_t    sensor_id;
    ipmi_sensor_t       *sensor;
    ipmi_msg_t          *rsp;
} hyst_set_info_t;

static void
hyst_set2(ipmi_sensor_t *sensor,
	  void          *cb_data)
{
    hyst_set_info_t *info = cb_data;

    if (info->rsp->data[0]) {
	if (info->done)
	    info->done(info->sensor,
		       IPMI_IPMI_ERR_VAL(info->rsp->data[0]),
		       info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->done)
	info->done(sensor, 0, info->cb_data);
    opq_op_done(info->sensor->waitq);
    free(info);
}

static void
hyst_set(ipmi_mc_t  *mc,
	 ipmi_msg_t *rsp,
	 void       *rsp_data)
{
    hyst_set_info_t *info = rsp_data;
    mc_cb_info_t    mc_info;

    if (!mc) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->sensor->destroyed) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->cb_data);
	free(info);
	sensor_final_destroy(info->sensor);
	return;
    }

    /* Call the next stage with the lock held. */
    info->rsp = rsp;
    mc_info.err = 0;
    mc_info.id = info->sensor_id;
    mc_info.cb_data = info;
    mc_info.handler = hyst_set2;
    mc_cb(mc, &mc_info);
    if (mc_info.err) {
	if (info->done)
	    info->done(info->sensor, mc_info.err, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
hyst_set_start2(ipmi_sensor_t *sensor, void *cb_data)
{
    hyst_set_info_t *info = cb_data;
    unsigned char       cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t          cmd_msg;
    int                 rv;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_SET_SENSOR_HYSTERESIS_CMD;
    cmd_msg.data_len = 2;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    cmd_data[1] = 0xff;
    cmd_data[2] = info->positive;
    cmd_data[3] = info->negative;
    rv = ipmi_send_command(sensor->mc, sensor->lun, &cmd_msg, hyst_set, info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
hyst_set_start(void *cb_data, int shutdown)
{
    hyst_set_info_t *info = cb_data;
    int                 rv;

    if (shutdown) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    rv = ipmi_sensor_pointer_cb(info->sensor_id, hyst_set_start2, info);
    if (rv) {
	if (info->done)
	    info->done(info->sensor, rv, info->cb_data);
	opq_op_done(info->sensor->waitq);
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
    
    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
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
    info->sensor = sensor;
    info->sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!opq_new_op(sensor->waitq, hyst_set_start, info, 0)) {
	free(info);
	return ENOMEM;
    }
    return 0;
}

typedef struct thresh_get_info_s
{
    ipmi_thresholds_t  th;
    ipmi_thresh_get_cb done;
    void               *cb_data;
    ipmi_sensor_id_t   sensor_id;
    ipmi_sensor_t      *sensor;
    ipmi_msg_t         *rsp;
} thresh_get_info_t;

static void
thresh_get2(ipmi_sensor_t *sensor,
	    void          *cb_data)
{
    thresh_get_info_t  *info = cb_data;
    enum ipmi_thresh_e th;

    if (info->rsp->data[0]) {
	if (info->done)
	    info->done(info->sensor,
		       IPMI_IPMI_ERR_VAL(info->rsp->data[0]),
		       &(info->th),
		       info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }
    
    for (th=IPMI_LOWER_NON_CRITICAL; th<=IPMI_UPPER_NON_RECOVERABLE; th++) {
	int rv;
	if (info->rsp->data[1] & (1 << th)) {
	    info->th.vals[th].status = IPMI_SENSOR_EVENTS_ENABLED;
	    rv = ipmi_sensor_convert_from_raw(sensor,
					      info->rsp->data[th+2],
					      &(info->th.vals[th].val));
	    if (rv) {
		info->done(info->sensor, rv, &(info->th), info->cb_data);
		opq_op_done(info->sensor->waitq);
		free(info);
		return;
	    }
	} else {
	    info->th.vals[th].status = 0;
	}
    }

    if (info->done)
	info->done(sensor,
		   0,
		   &(info->th),
		   info->cb_data);
    opq_op_done(info->sensor->waitq);
    free(info);
}

static void
thresh_get(ipmi_mc_t  *mc,
	   ipmi_msg_t *rsp,
	   void       *rsp_data)
{
    thresh_get_info_t *info = rsp_data;
    mc_cb_info_t      mc_info;

    if (!mc) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, &(info->th), info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->sensor->destroyed) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, &(info->th), info->cb_data);
	free(info);
	sensor_final_destroy(info->sensor);
	return;
    }

    /* Call the next stage with the lock held. */
    info->rsp = rsp;
    mc_info.err = 0;
    mc_info.id = info->sensor_id;
    mc_info.cb_data = info;
    mc_info.handler = thresh_get2;
    mc_cb(mc, &mc_info);
    if (mc_info.err) {
	if (info->done)
	    info->done(info->sensor, mc_info.err, &(info->th), info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static int
get_default_sensor_val(ipmi_sensor_t      *sensor,
		       enum ipmi_thresh_e thnum,
		       int                raw,
		       ipmi_thresholds_t  *th)
{
    int val;

    ipmi_sensor_threshold_readable(sensor, IPMI_LOWER_NON_CRITICAL, &val);
    if (val) {
	th->vals[thnum].status = IPMI_SENSOR_EVENTS_ENABLED;
	return ipmi_sensor_convert_from_raw(sensor, raw, &(th->vals[thnum].val));
    }
    return 0;
}

static void
thresh_get_start2(ipmi_sensor_t *sensor, void *cb_data)
{
    thresh_get_info_t *info = cb_data;
    unsigned char     cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t        cmd_msg;
    int               rv;

    if (sensor->threshold_access == IPMI_THRESHOLD_ACCESS_SUPPORT_FIXED) {
	/* Thresholds are fixed, pull them from the SDR. */
	ipmi_thresholds_init(&(info->th));
	rv = get_default_sensor_val(sensor,
				    IPMI_LOWER_NON_CRITICAL,
				    sensor->lower_non_critical_threshold,
				    &(info->th));
	if (!rv)
	    rv = get_default_sensor_val(sensor,
					IPMI_LOWER_CRITICAL,
					sensor->lower_critical_threshold,
					&(info->th));
	if (!rv)
	    rv = get_default_sensor_val(sensor,
					IPMI_LOWER_NON_RECOVERABLE,
					sensor->lower_non_recoverable_threshold,
					&(info->th));
	if (!rv)
	    rv = get_default_sensor_val(sensor,
					IPMI_UPPER_NON_CRITICAL,
					sensor->upper_non_critical_threshold,
					&(info->th));
	if (!rv)
	    rv = get_default_sensor_val(sensor,
					IPMI_UPPER_CRITICAL,
					sensor->upper_critical_threshold,
					&(info->th));
	if (!rv)
	    rv = get_default_sensor_val(sensor,
					IPMI_UPPER_NON_RECOVERABLE,
					sensor->upper_non_recoverable_threshold,
					&(info->th));
	if (info->done)
	    info->done(sensor, rv, &(info->th), info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_THRESHOLD_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_send_command(sensor->mc, sensor->lun, &cmd_msg, thresh_get, info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, &(info->th), info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
thresh_get_start(void *cb_data, int shutdown)
{
    thresh_get_info_t *info = cb_data;
    int                 rv;

    if (shutdown) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, &(info->th), info->cb_data);
	free(info);
	return;
    }

    rv = ipmi_sensor_pointer_cb(info->sensor_id, thresh_get_start2, info);
    if (rv) {
	if (info->done)
	    info->done(info->sensor, rv, &(info->th), info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static int
stand_ipmi_thresholds_get(ipmi_sensor_t      *sensor,
			  ipmi_thresh_get_cb done,
			  void               *cb_data)
{
    thresh_get_info_t *info;
    
    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    if (sensor->threshold_access != IPMI_THRESHOLD_ACCESS_SUPPORT_READABLE)
	return ENOTSUP;
    
    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    info->sensor = sensor;
    info->sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!opq_new_op(sensor->waitq, thresh_get_start, info, 0)) {
	free(info);
	return ENOMEM;
    }
    return 0;
}

typedef struct thresh_set_info_s
{
    ipmi_thresholds_t   th;
    ipmi_sensor_done_cb done;
    void                *cb_data;
    ipmi_sensor_id_t    sensor_id;
    ipmi_sensor_t       *sensor;
    ipmi_msg_t          *rsp;
} thresh_set_info_t;

static void
thresh_set2(ipmi_sensor_t *sensor,
	    void          *cb_data)
{
    thresh_set_info_t *info = cb_data;

    if (info->rsp->data[0]) {
	if (info->done)
	    info->done(info->sensor,
		       IPMI_IPMI_ERR_VAL(info->rsp->data[0]),
		       info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->done)
	info->done(sensor, 0, info->cb_data);
    opq_op_done(info->sensor->waitq);
    free(info);
}

static void
thresh_set(ipmi_mc_t  *mc,
	 ipmi_msg_t *rsp,
	 void       *rsp_data)
{
    thresh_set_info_t *info = rsp_data;
    mc_cb_info_t    mc_info;

    if (!mc) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->sensor->destroyed) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->cb_data);
	free(info);
	sensor_final_destroy(info->sensor);
	return;
    }

    /* Call the next stage with the lock held. */
    info->rsp = rsp;
    mc_info.err = 0;
    mc_info.id = info->sensor_id;
    mc_info.cb_data = info;
    mc_info.handler = thresh_set2;
    mc_cb(mc, &mc_info);
    if (mc_info.err) {
	if (info->done)
	    info->done(info->sensor, mc_info.err, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
thresh_set_start2(ipmi_sensor_t *sensor, void *cb_data)
{
    thresh_set_info_t *info = cb_data;
    unsigned char      cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t         cmd_msg;
    int                rv;
    enum ipmi_thresh_e th;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_SET_SENSOR_THRESHOLD_CMD;
    cmd_msg.data_len = 8;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    cmd_data[1] = 0;
    for (th=IPMI_LOWER_NON_CRITICAL; th<=IPMI_UPPER_NON_RECOVERABLE; th++) {
	if (info->th.vals[th].status & IPMI_SENSOR_EVENTS_ENABLED) {
	    int val;
	    info->rsp->data[1] |= (1 << th);
	    rv = ipmi_sensor_convert_to_raw(sensor,
					    ROUND_NORMAL,
					    info->th.vals[th].val,
					    &val);
	    if (rv) {
		info->done(info->sensor, rv, info->cb_data);
		free(info);
		return;
	    }
	    cmd_data[th+2] = val;
	}
    }

    rv = ipmi_send_command(sensor->mc, sensor->lun, &cmd_msg, thresh_set, info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
thresh_set_start(void *cb_data, int shutdown)
{
    thresh_set_info_t *info = cb_data;
    int                 rv;

    if (shutdown) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, info->cb_data);
	free(info);
	return;
    }

    rv = ipmi_sensor_pointer_cb(info->sensor_id, thresh_set_start2, info);
    if (rv) {
	if (info->done)
	    info->done(info->sensor, rv, info->cb_data);
	opq_op_done(info->sensor->waitq);
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
    
    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
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
    info->sensor = sensor;
    info->sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!opq_new_op(sensor->waitq, thresh_set_start, info, 0)) {
	free(info);
	return ENOMEM;
    }
    return 0;
}

typedef struct reading_get_info_s
{
    ipmi_reading_done_cb done;
    void                 *cb_data;
    ipmi_sensor_id_t     sensor_id;
    ipmi_sensor_t        *sensor;
    ipmi_msg_t           *rsp;
} reading_get_info_t;

static void
reading_get2(ipmi_sensor_t *sensor,
	    void          *cb_data)
{
    reading_get_info_t  *info = cb_data;
    int                 rv;
    double              val;

    if (info->rsp->data[0]) {
	if (info->done)
	    info->done(info->sensor,
		       IPMI_IPMI_ERR_VAL(info->rsp->data[0]),
		       0.0,
		       info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }
    
    rv = ipmi_sensor_convert_from_raw(sensor,
				      info->rsp->data[1],
				      &val);
    if (rv) {
	info->done(info->sensor, rv, 0.0, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->done)
	info->done(sensor, 0, val, info->cb_data);
    opq_op_done(info->sensor->waitq);
    free(info);
}

static void
reading_get(ipmi_mc_t  *mc,
	    ipmi_msg_t *rsp,
	    void       *rsp_data)
{
    reading_get_info_t *info = rsp_data;
    mc_cb_info_t      mc_info;

    if (!mc) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, 0.0, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->sensor->destroyed) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, 0.0, info->cb_data);
	free(info);
	sensor_final_destroy(info->sensor);
	return;
    }

    /* Call the next stage with the lock held. */
    info->rsp = rsp;
    mc_info.err = 0;
    mc_info.id = info->sensor_id;
    mc_info.cb_data = info;
    mc_info.handler = reading_get2;
    mc_cb(mc, &mc_info);
    if (mc_info.err) {
	if (info->done)
	    info->done(info->sensor, mc_info.err, 0.0, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
reading_get_start2(ipmi_sensor_t *sensor, void *cb_data)
{
    reading_get_info_t *info = cb_data;
    unsigned char     cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t        cmd_msg;
    int               rv;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_READING_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_send_command(sensor->mc, sensor->lun, &cmd_msg, reading_get, info);
    if (rv) {
	if (info->done)
	    info->done(sensor, rv, 0.0, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
reading_get_start(void *cb_data, int shutdown)
{
    reading_get_info_t *info = cb_data;
    int                 rv;

    if (shutdown) {
	if (info->done)
	    info->done(info->sensor, ECANCELED, 0.0, info->cb_data);
	free(info);
	return;
    }

    rv = ipmi_sensor_pointer_cb(info->sensor_id, reading_get_start2, info);
    if (rv) {
	if (info->done)
	    info->done(info->sensor, rv, 0.0, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static int
stand_ipmi_reading_get(ipmi_sensor_t        *sensor,
		       ipmi_reading_done_cb done,
		       void                 *cb_data)
{
    reading_get_info_t *info;
    
    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    info->sensor = sensor;
    info->sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!opq_new_op(sensor->waitq, reading_get_start, info, 0)) {
	free(info);
	return ENOMEM;
    }
    return 0;
}


typedef struct states_get_info_s
{
    ipmi_states_read_cb done;
    void                *cb_data;
    ipmi_sensor_id_t    sensor_id;
    ipmi_sensor_t       *sensor;
    ipmi_msg_t          *rsp;
} states_get_info_t;

static void
states_get2(ipmi_sensor_t *sensor,
	    void          *cb_data)
{
    states_get_info_t *info = cb_data;
    ipmi_states_t     states = {0};

    if (info->rsp->data[0]) {
	if (info->done)
	    info->done(info->sensor,
		       IPMI_IPMI_ERR_VAL(info->rsp->data[0]),
		       states,
		       info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    states.__states = (info->rsp->data[3] << 8) | info->rsp->data[4];

    if (info->done)
	info->done(sensor, 0, states, info->cb_data);
    opq_op_done(info->sensor->waitq);
    free(info);
}

static void
states_get(ipmi_mc_t  *mc,
	    ipmi_msg_t *rsp,
	    void       *rsp_data)
{
    states_get_info_t *info = rsp_data;
    mc_cb_info_t      mc_info;

    if (!mc) {
	ipmi_states_t states = {0};
	if (info->done)
	    info->done(info->sensor, ECANCELED, states, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
	return;
    }

    if (info->sensor->destroyed) {
	ipmi_states_t states = {0};
	if (info->done)
	    info->done(info->sensor, ECANCELED, states, info->cb_data);
	free(info);
	sensor_final_destroy(info->sensor);
	return;
    }

    /* Call the next stage with the lock held. */
    info->rsp = rsp;
    mc_info.err = 0;
    mc_info.id = info->sensor_id;
    mc_info.cb_data = info;
    mc_info.handler = states_get2;
    mc_cb(mc, &mc_info);
    if (mc_info.err) {
	ipmi_states_t states = {0};
	if (info->done)
	    info->done(info->sensor, mc_info.err, states, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
states_get_start2(ipmi_sensor_t *sensor, void *cb_data)
{
    states_get_info_t *info = cb_data;
    unsigned char     cmd_data[MAX_IPMI_DATA_SIZE];
    ipmi_msg_t        cmd_msg;
    int               rv;

    cmd_msg.data = cmd_data;
    cmd_msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    cmd_msg.cmd = IPMI_GET_SENSOR_READING_CMD;
    cmd_msg.data_len = 1;
    cmd_msg.data = cmd_data;
    cmd_data[0] = sensor->num;
    rv = ipmi_send_command(sensor->mc, sensor->lun, &cmd_msg, states_get, info);
    if (rv) {
	ipmi_states_t states = {0};
	if (info->done)
	    info->done(sensor, rv, states, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static void
states_get_start(void *cb_data, int shutdown)
{
    states_get_info_t *info = cb_data;
    int               rv;

    if (shutdown) {
	ipmi_states_t states = {0};
	if (info->done)
	    info->done(info->sensor, ECANCELED, states, info->cb_data);
	free(info);
	return;
    }

    rv = ipmi_sensor_pointer_cb(info->sensor_id, states_get_start2, info);
    if (rv) {
	ipmi_states_t states = {0};
	if (info->done)
	    info->done(info->sensor, rv, states, info->cb_data);
	opq_op_done(info->sensor->waitq);
	free(info);
    }
}

static int
stand_ipmi_states_get(ipmi_sensor_t       *sensor,
		      ipmi_states_read_cb done,
		      void                *cb_data)
{
    states_get_info_t *info;
    
    if (sensor->event_reading_type == IPMI_EVENT_TYPE_THRESHOLD)
	/* A threshold sensor, it doesn't have states. */
	return ENOSYS;

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;
    info->sensor = sensor;
    info->sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!opq_new_op(sensor->waitq, states_get_start, info, 0)) {
	free(info);
	return ENOMEM;
    }
    return 0;
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

    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
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

    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
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

    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
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

    if (sensor->event_reading_type != IPMI_EVENT_TYPE_THRESHOLD)
	/* Not a threshold sensor, it doesn't have readings. */
	return ENOSYS;

    val &= 0xff;

    a = sensor->conv[val].accuracy;
    a_exp = sensor->conv[val].r_exp;

    *accuracy = (a * pow(10, a_exp)) / 100.0;
    return 0;
}

static ipmi_sensor_cbs_t standard_sensor_cb =
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
};

int
ipmi_sensor_events_enable_set(ipmi_sensor_t         *sensor,
			      ipmi_event_state_t    *states,
			      ipmi_sensor_done_cb   done,
			      void                  *cb_data)
{
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
    return sensor->cbs.ipmi_sensor_events_enable_get(sensor,
						     done,
						     cb_data);
}

int
ipmi_sensor_get_hysteresis(ipmi_sensor_t          *sensor,
			   ipmi_hysteresis_get_cb done,
			   void                   *cb_data)
{
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
    return sensor->cbs.ipmi_thresholds_get(sensor, done, cb_data);
}

int
ipmi_thresholds_set(ipmi_sensor_t       *sensor,
		    ipmi_thresholds_t   *thresholds,
		    ipmi_sensor_done_cb done,
		    void                *cb_data)
{
    return sensor->cbs.ipmi_thresholds_set(sensor, thresholds, done, cb_data);
}

int
ipmi_reading_get(ipmi_sensor_t        *sensor,
		 ipmi_reading_done_cb done,
		 void                 *cb_data)
{
    return sensor->cbs.ipmi_reading_get(sensor, done, cb_data);
}

int
ipmi_states_get(ipmi_sensor_t       *sensor,
		ipmi_states_read_cb done,
		void                *cb_data)
{
    return sensor->cbs.ipmi_states_get(sensor, done, cb_data);
}

int
ipmi_sensor_convert_from_raw(ipmi_sensor_t *sensor,
			     int           val,
			     double        *result)
{
    return sensor->cbs.ipmi_sensor_convert_from_raw(sensor, val, result);
}

int
ipmi_sensor_convert_to_raw(ipmi_sensor_t     *sensor,
			   enum ipmi_round_e rounding,
			   double            val,
			   int               *result)
{
    return sensor->cbs.ipmi_sensor_convert_to_raw(sensor,
						  rounding,
						  val,
						  result);
}

int
ipmi_sensor_get_tolerance(ipmi_sensor_t *sensor, int val, double *tolerance)
{
    return sensor->cbs.ipmi_sensor_get_tolerance(sensor, val, tolerance);
}

/* Returns accuracy as a percentage value. */
int
ipmi_sensor_get_accuracy(ipmi_sensor_t *sensor, int val, double *accuracy)
{
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

int ipmi_thresholds_init(ipmi_thresholds_t *th)
{
    int i;
    for (i=0; i<6; i++)
	th->vals[i].status = 0;
    return 0;
}

int ipmi_threshold_set(ipmi_thresholds_t  *th,
		       ipmi_sensor_t      *sensor,
		       enum ipmi_thresh_e threshold,
		       double             value)
{
    int rv = 0;

    if (threshold > IPMI_UPPER_NON_RECOVERABLE)
	return EINVAL;

    if (sensor) {
	int val;
	rv = ipmi_sensor_threshold_settable(sensor, threshold, &val);
	if (rv)
	    return rv;
	if (!val)
	    return ENOTSUP;
    }

    th->vals[threshold].status |= IPMI_SENSOR_EVENTS_ENABLED;
    th->vals[threshold].val = value;
    return 0;
}

int ipmi_threshold_get(ipmi_thresholds_t  *th,
		       enum ipmi_thresh_e threshold,
		       double             *value)
{
    if (threshold > IPMI_UPPER_NON_RECOVERABLE)
	return EINVAL;

    if (th->vals[threshold].status & IPMI_SENSOR_EVENTS_ENABLED) {
	*value = th->vals[threshold].val;
	return 0;
    } else {
	return ENOTSUP;
    }
}

int is_state_set(ipmi_states_t states,
		 int           state_num)
{
    return (states.__states & (1 << state_num)) != 0;
}

