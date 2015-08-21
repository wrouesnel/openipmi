/*
 * bmc_sensor.c
 *
 * MontaVista IPMI code for emulating a MC.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2003,2012,2013 MontaVista Software Inc.
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
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include "bmc.h"

#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_bits.h>

static void sensor_poll(void *cb_data);

static void
handle_get_event_receiver(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len,
			  void          *cb_data)
{
    if (!(mc->device_support & IPMI_DEVID_IPMB_EVENT_GEN)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    rdata[0] = 0;
    rdata[1] = mc->event_receiver;
    rdata[2] = mc->event_receiver_lun & 0x3;
    *rdata_len = 3;
}

static void
handle_set_event_receiver(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len,
			  void          *cb_data)
{
    if (!(mc->device_support & IPMI_DEVID_IPMB_EVENT_GEN)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    mc->event_receiver = msg->data[0] & 0xfe;
    mc->event_receiver_lun = msg->data[1] & 0x3;

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_device_sdr_info(lmc_data_t    *mc,
			   msg_t         *msg,
			   unsigned char *rdata,
			   unsigned int  *rdata_len,
			   void          *cb_data)
{
    if (! mc->has_device_sdrs) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    rdata[0] = 0;
    rdata[1] = mc->num_sensors_per_lun[msg->rs_lun];
    rdata[2] = ((mc->dynamic_sensor_population << 7)
		| (mc->lun_has_sensors[3] << 3)
		| (mc->lun_has_sensors[2] << 2)
		| (mc->lun_has_sensors[1] << 1)
		| (mc->lun_has_sensors[0] << 0));
    if (!mc->dynamic_sensor_population) {
	*rdata_len = 3;
	return;
    }

    ipmi_set_uint32(rdata+3, mc->sensor_population_change_time);
    *rdata_len = 7;
}

static void
handle_reserve_device_sdr_repository(lmc_data_t    *mc,
				     msg_t         *msg,
				     unsigned char *rdata,
				     unsigned int  *rdata_len,
				     void          *cb_data)
{
    if (!(mc->has_device_sdrs)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (!(mc->dynamic_sensor_population)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    mc->device_sdrs[msg->rs_lun].reservation++;
    if (mc->device_sdrs[msg->rs_lun].reservation == 0)
	mc->device_sdrs[msg->rs_lun].reservation++;

    rdata[0] = 0;
    ipmi_set_uint16(rdata+1, mc->device_sdrs[msg->rs_lun].reservation);
    *rdata_len = 3;
}

static void
handle_get_device_sdr(lmc_data_t    *mc,
		      msg_t         *msg,
		      unsigned char *rdata,
		      unsigned int  *rdata_len,
		      void          *cb_data)
{
    uint16_t     record_id;
    unsigned int offset;
    unsigned int count;
    sdr_t        *entry;

    if (!(mc->has_device_sdrs)) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 6, rdata, rdata_len))
	return;

    if (mc->dynamic_sensor_population) {
	uint16_t reservation = ipmi_get_uint16(msg->data+0);

	if ((reservation != 0)
	    && (reservation != mc->device_sdrs[msg->rs_lun].reservation))
	{
	    rdata[0] = IPMI_INVALID_RESERVATION_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    record_id = ipmi_get_uint16(msg->data+2);
    offset = msg->data[4];
    count = msg->data[5];

    if (record_id == 0) {
	entry = mc->device_sdrs[msg->rs_lun].sdrs;
    } else if (record_id == 0xffff) {
	entry = mc->device_sdrs[msg->rs_lun].sdrs;
	if (entry) {
	    while (entry->next) {
		entry = entry->next;
	    }
	}
    } else {
	entry = find_sdr_by_recid(&mc->device_sdrs[msg->rs_lun],
				  record_id, NULL);
    }

    if (entry == NULL) {
	rdata[0] = IPMI_NOT_PRESENT_CC;
	*rdata_len = 1;
	return;
    }

    if (offset >= entry->length) {
	rdata[0] = IPMI_PARAMETER_OUT_OF_RANGE_CC;
	*rdata_len = 1;
	return;
    }

    if ((offset+count) > entry->length)
	count = entry->length - offset;
    if (count+3 > *rdata_len) {
	/* Too much data to put into response. */
	rdata[0] = IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    if (entry->next)
	ipmi_set_uint16(rdata+1, entry->next->record_id);
    else {
	rdata[1] = 0xff;
	rdata[2] = 0xff;
    }

    memcpy(rdata+3, entry->data+offset, count);
    *rdata_len = count + 3;
}

static void
handle_set_sensor_hysteresis(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len,
			     void          *cb_data)
{
    int      sens_num;
    sensor_t *sensor;

    if (check_msg_length(msg, 4, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if (sensor->hysteresis_support != IPMI_HYSTERESIS_SUPPORT_SETTABLE) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    sensor->positive_hysteresis = msg->data[2];
    sensor->negative_hysteresis = msg->data[3];

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_sensor_hysteresis(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len,
			     void          *cb_data)
{
    int      sens_num;
    sensor_t *sensor;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if ((sensor->hysteresis_support != IPMI_HYSTERESIS_SUPPORT_SETTABLE)
	&& (sensor->hysteresis_support != IPMI_HYSTERESIS_SUPPORT_READABLE))
    {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = sensor->positive_hysteresis;
    rdata[2] = sensor->negative_hysteresis;
    *rdata_len = 3;
}

static void
do_event(lmc_data_t    *mc,
	 sensor_t      *sensor,
	 int           gen_event,
	 unsigned char direction,
	 unsigned char byte1,
	 unsigned char byte2,
	 unsigned char byte3)
{
    lmc_data_t    *dest_mc;
    unsigned char data[13];
    int           rv;

    if ((mc->event_receiver == 0)
	|| (!sensor->enabled)
	|| (!sensor->events_enabled)
	|| (!gen_event))
	return;

    rv = ipmi_emu_get_mc_by_addr(mc->emu, mc->event_receiver, &dest_mc);
    if (rv)
	return;

    /* Timestamp is ignored. */
    data[0] = 0;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;

    data[4] = mc->ipmb;
    data[5] = sensor->lun;
    data[6] = 0x04; /* Event message revision for IPMI 1.5. */
    data[7] = sensor->sensor_type;
    data[8] = sensor->num;
    data[9] = (direction << 7) | sensor->event_reading_code;
    data[10] = byte1;
    data[11] = byte2;
    data[12] = byte3;

    mc_new_event(dest_mc, 0x02, data);
}

void
set_sensor_bit(lmc_data_t *mc, sensor_t *sensor, unsigned char bit,
	       unsigned char value,
	       unsigned char evd1, unsigned char evd2, unsigned char evd3,
	       int gen_event)
{
    if (sensor->event_only) {
	if (value)
	    do_event(mc, sensor, gen_event, IPMI_ASSERTION,
		     evd1 | bit, evd2, evd3);
	else
	    do_event(mc, sensor, gen_event, IPMI_DEASSERTION,
		     evd1 | bit, evd2, evd3);
    } else if (value != bit_set(sensor->event_status, bit)) {
	/* The bit value has changed. */
	set_bit(sensor->event_status, bit, value);
	if (value && bit_set(sensor->event_enabled[0], bit)) {
	    do_event(mc, sensor, gen_event, IPMI_ASSERTION,
		     evd1 | bit, evd2, evd3);
	} else if (!value && bit_set(sensor->event_enabled[1], bit)) {
	    do_event(mc, sensor, gen_event, IPMI_DEASSERTION,
		     evd1 | bit, evd2, evd3);
	}
    }
}

static void
check_thresholds(lmc_data_t *mc, sensor_t *sensor, int gen_event)
{
    int i;
    int bits_to_set = 0;
    int bits_to_clear = 0;

    for (i=0; i<3; i++) {
	if (bit_set(sensor->threshold_supported, i)) {
	    if (sensor->value <= sensor->thresholds[i])
		bits_to_set |= (1 << i);
	    else if ((sensor->value - sensor->negative_hysteresis)
		     > sensor->thresholds[i])
		bits_to_clear |= (1 << i);
	}
    }
    for (; i<6; i++) {
	if (bit_set(sensor->threshold_supported, i)) {
	    if (sensor->value >= sensor->thresholds[i])
		bits_to_set |= (1 << i);
	    else if ((sensor->value + sensor->positive_hysteresis)
		     < sensor->thresholds[i])
		bits_to_clear |= (1 << i);
	}
    }

    /* We don't support lower assertions for high thresholds or higher
       assertions for low thresholds because that's just stupid. */
    for (i=0; i<3; i++) {
	if (((bits_to_set >> i) & 1) && !bit_set(sensor->event_status, i)) {
	    /* This bit was not set, but we need to set it. */
	    set_bit(sensor->event_status, i, 1);
	    if (bit_set(sensor->event_enabled[0], i * 2)) {
		do_event(mc, sensor, gen_event, IPMI_ASSERTION,
			 0x50 | (i*2), sensor->value, sensor->thresholds[i]);
	    }
	} else if (((bits_to_clear >> i) & 1)
		   && bit_set(sensor->event_status, i)) {
	    /* This bit was not clear, but we need to clear it. */
	    set_bit(sensor->event_status, i, 0);
	    if (bit_set(sensor->event_enabled[1], i * 2)) {
		do_event(mc, sensor, gen_event, IPMI_DEASSERTION,
			 0x50 | (i*2), sensor->value, sensor->thresholds[i]);
	    }
	}
    }
    for (; i<6; i++) {
	if (((bits_to_set >> i) & 1) && !bit_set(sensor->event_status, i)) {
	    /* This bit was not set, but we need to set it. */
	    set_bit(sensor->event_status, i, 1);
	    if (bit_set(sensor->event_enabled[0], i * 2 + 1)) {
		do_event(mc, sensor, gen_event, IPMI_ASSERTION,
			 0x50 | (i*2+1), sensor->value, sensor->thresholds[i]);
	    }
	} else if (((bits_to_clear >> i) & 1)
		   && bit_set(sensor->event_status, i)) {
	    /* This bit was not clear, but we need to clear it. */
	    set_bit(sensor->event_status, i, 0);
	    if (bit_set(sensor->event_enabled[1], i * 2 + 1)) {
		do_event(mc, sensor, gen_event, IPMI_DEASSERTION,
			 0x50 | (i*2+1), sensor->value, sensor->thresholds[i]);
	    }
	}
    }
}

static void
handle_set_sensor_thresholds(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len,
			     void          *cb_data)
{
    int      sens_num;
    sensor_t *sensor;
    int      i;

    if (check_msg_length(msg, 8, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if ((sensor->event_reading_code != IPMI_EVENT_READING_TYPE_THRESHOLD)
	|| (sensor->threshold_support != IPMI_THRESHOLD_ACCESS_SUPPORT_SETTABLE))
    {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    for (i=0; i<6; i++) {
	if ((msg->data[1] & (1 << i))
		&& (!bit_set(sensor->threshold_supported, i))) {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    for (i=0; i<6; i++) {
	if (msg->data[1] & (1 << i)) {
	    sensor->thresholds[i] = msg->data[i+2];
	}
    }

    check_thresholds(mc, sensor, 1);

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_sensor_thresholds(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len,
			     void          *cb_data)
{
    int      sens_num;
    sensor_t *sensor;
    int      i;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if ((sensor->event_reading_code != IPMI_EVENT_READING_TYPE_THRESHOLD)
	|| ((sensor->threshold_support != IPMI_THRESHOLD_ACCESS_SUPPORT_SETTABLE)
	    && (sensor->threshold_support != IPMI_THRESHOLD_ACCESS_SUPPORT_READABLE)))
    {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = 0;
    for (i=0; i<6; i++) {
	if (bit_set(sensor->threshold_supported, i)) {
	    rdata[1] |= 1 << i;
	    rdata[2+i] = sensor->thresholds[i];
	} else
	    rdata[2+i] = 0;
    }
    *rdata_len = 8;
}

static void
handle_set_sensor_event_enable(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len,
			       void          *cb_data)
{
    int           sens_num;
    sensor_t      *sensor;
    unsigned int  i;
    int           j, e;
    unsigned char op;

    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if ((sensor->event_support == IPMI_EVENT_SUPPORT_NONE)
	|| (sensor->event_support == IPMI_EVENT_SUPPORT_GLOBAL_ENABLE))
    {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    op = (msg->data[1] >> 4) & 0x3;
    if (sensor->event_support == IPMI_EVENT_SUPPORT_ENTIRE_SENSOR) {
	if (op != 0) {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    if (op == 3) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor->events_enabled = (msg->data[1] >> 7) & 1;
    sensor->scanning_enabled = (msg->data[1] >> 6) & 1;

    sensor_poll(sensor);
	
    if (op == 0)
	return;
    else if (op == 1)
	/* Enable selected events */
	op = 1;
    else
	/* Disable selected events */
	op = 0;

    e = 0;
    for (i=2; i<=3; i++) {
	if (msg->len <= i)
	    break;
	for (j=0; j<8; j++, e++) {
	    if (e >= 15)
		break;
	    if (((msg->data[i] >> j) & 1)
		    && bit_set(sensor->event_supported[0], e))
		set_bit(sensor->event_enabled[0], e, op);
	}
    }
    e = 0;
    for (i=4; i<=5; i++) {
	if (msg->len <= i)
	    break;
	for (j=0; j<8; j++, e++) {
	    if (e >= 15)
		break;
	    if (((msg->data[i] >> j) & 1)
		    && bit_set(sensor->event_supported[1], e))
		set_bit(sensor->event_enabled[1], e, op);
	}
    }

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_sensor_event_enable(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len,
			       void          *cb_data)
{
    int           sens_num;
    sensor_t      *sensor;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    if ((sensor->event_support == IPMI_EVENT_SUPPORT_NONE)
	|| (sensor->event_support == IPMI_EVENT_SUPPORT_GLOBAL_ENABLE))
    {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = ((sensor->events_enabled << 7)
		| ((sensor->scanning_enabled && sensor->enabled) << 6));
	
    if (sensor->event_support == IPMI_EVENT_SUPPORT_ENTIRE_SENSOR) {
	*rdata_len = 2;
	return;
    }

    rdata[2] = sensor->event_enabled[0] & 0xff;
    rdata[3] = (sensor->event_enabled[0] >> 8) & 0xff;
    rdata[4] = sensor->event_enabled[1] & 0xff;
    rdata[5] = (sensor->event_enabled[1] >> 8) & 0xff;

    *rdata_len = 6;
}

static void
handle_set_sensor_type(lmc_data_t    *mc,
		       msg_t         *msg,
		       unsigned char *rdata,
		       unsigned int  *rdata_len,
		       void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_get_sensor_type(lmc_data_t    *mc,
		       msg_t         *msg,
		       unsigned char *rdata,
		       unsigned int  *rdata_len,
		       void          *cb_data)
{
    int           sens_num;
    sensor_t      *sensor;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];
    rdata[0] = 0;
    rdata[1] = sensor->sensor_type;
    rdata[2] = sensor->event_reading_code;
    *rdata_len = 3;
}

static void
handle_get_sensor_reading(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len,
			  void          *cb_data)
{
    int      sens_num;
    sensor_t *sensor;

    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];

    if (sensor->event_only) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = sensor->value;
    rdata[2] = ((sensor->events_enabled << 7)
		| ((sensor->scanning_enabled && sensor->enabled) << 6));
    rdata[3] = sensor->event_status & 0xff;
    rdata[4] = (sensor->event_status >> 8) & 0xff;
    *rdata_len = 5;
}

static void
handle_rearm_sensor_events(lmc_data_t    *mc,
			   msg_t         *msg,
			   unsigned char *rdata,
			   unsigned int  *rdata_len,
			   void          *cb_data)
{
    int      sens_num;
    sensor_t *sensor;
    uint16_t rearm_assert = 0, rearm_deassert = 0;
    unsigned int i;
    int rv;

    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    sens_num = msg->data[0];
    if ((sens_num >= 255) || (!mc->sensors[msg->rs_lun][sens_num])) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    sensor = mc->sensors[msg->rs_lun][sens_num];

    if (msg->data[1] & (1 << 7)) {
	rearm_assert = 0x7fff;
	rearm_deassert = 0x7fff;
    } else {
	if (msg->len > 2)
	    rearm_assert = msg->data[2];
	if (msg->len > 3)
	    rearm_assert |= msg->data[3] << 8;
	if (msg->len > 4)
	    rearm_deassert = msg->data[4];
	if (msg->len > 5)
	    rearm_deassert |= msg->data[5] << 8;
    }

    if (sensor->rearm_handler) {
	rv = sensor->rearm_handler(sensor->rearm_cb_data,
				   rearm_assert, rearm_deassert);
	if (rv) {
	    rdata[0] = 0xff;
	    *rdata_len = 1;
	    return;
	}
    }

    rearm_assert &= sensor->event_enabled[0] & sensor->event_status;
    rearm_deassert &= sensor->event_enabled[1] & ~sensor->event_status;

    for (i = 0; i < 15; i++) {
	if (bit_set(rearm_assert, i))
	    do_event(mc, sensor, 1, IPMI_ASSERTION, 0, 0xff, 0xff);
	else if (bit_set(rearm_deassert, i))
	    do_event(mc, sensor, 1, IPMI_DEASSERTION, 0, 0xff, 0xff);
    }
    rdata[0] = 0;
    *rdata_len = 1;
}

int
ipmi_mc_sensor_add_rearm_handler(lmc_data_t    *mc,
				 unsigned char lun,
				 unsigned char sens_num,
				 int (*handler)(void *cb_data,
						uint16_t assert,
						uint16_t deassert),
				 void *cb_data)
{
    sensor_t *sensor;

    if ((sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];
    sensor->rearm_handler = handler;
    sensor->rearm_cb_data = cb_data;
    return 0;
}

int
ipmi_mc_sensor_set_bit(lmc_data_t   *mc,
		       unsigned char lun,
		       unsigned char sens_num,
		       unsigned char bit,
		       unsigned char value,
		       int           gen_event)
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    if (bit >= 15)
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];

    set_sensor_bit(mc, sensor, bit, value, 0, 0xff, 0xff, gen_event);

    if (sensor->sensor_update_handler)
	sensor->sensor_update_handler(mc, sensor);

    return 0;
}

int
ipmi_mc_sensor_set_bit_clr_rest(lmc_data_t   *mc,
				unsigned char lun,
				unsigned char sens_num,
				unsigned char bit,
				int           gen_event)
{
    sensor_t *sensor;
    int      i;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    if (bit >= 15)
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];

    /* Clear all the other bits. */
    for (i=0; i<15; i++) {
	if ((i != bit) && bit_set(sensor->event_status, i))
	    set_sensor_bit(mc, sensor, i, 0, 0, 0xff, 0xff, gen_event);
    }

    sensor->value = bit;
    set_sensor_bit(mc, sensor, bit, 1, 0, 0xff, 0xff, gen_event);

    if (sensor->sensor_update_handler)
	sensor->sensor_update_handler(mc, sensor);

    return 0;
}

int
ipmi_mc_sensor_set_enabled(lmc_data_t    *mc,
			   unsigned char lun,
			   unsigned char sens_num,
			   unsigned char enabled)
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];

    sensor->enabled = enabled;

    sensor_poll(sensor);

    return 0;
}

static void
set_sensor_value(lmc_data_t    *mc,
		 sensor_t      *sensor,
		 unsigned char value,
		 int           gen_event)
{
    sensor->value = value;

    if (sensor->sensor_update_handler)
	sensor->sensor_update_handler(mc, sensor);

    check_thresholds(mc, sensor, gen_event);
}

int
ipmi_mc_sensor_set_value(lmc_data_t    *mc,
			 unsigned char lun,
			 unsigned char sens_num,
			 unsigned char value,
			 int           gen_event)
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];

    set_sensor_value(mc, sensor, value, gen_event);
    return 0;
}

int
ipmi_mc_sensor_set_hysteresis(lmc_data_t    *mc,
			      unsigned char lun,
			      unsigned char sens_num,
			      unsigned char support,
			      unsigned char positive,
			      unsigned char negative)
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];

    sensor->hysteresis_support = support;
    sensor->positive_hysteresis = positive;
    sensor->negative_hysteresis = negative;

    return 0;
}

int
ipmi_mc_sensor_set_threshold(lmc_data_t    *mc,
			     unsigned char lun,
			     unsigned char sens_num,
			     unsigned char support,
			     uint16_t supported,
			     int set_values,
			     unsigned char values[6])
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];
    sensor->threshold_support = support;
    sensor->threshold_supported = supported;
    if (set_values)
	memcpy(sensor->thresholds, values, 6);

    return 0;
}

int
ipmi_mc_sensor_set_event_support(lmc_data_t    *mc,
				 unsigned char lun,
				 unsigned char sens_num,
				 unsigned char init_events,
				 unsigned char events_enable,
				 unsigned char init_scanning,
				 unsigned char scanning_enable,
				 unsigned char event_support,
				 uint16_t assert_supported,
				 uint16_t deassert_supported,
				 uint16_t assert_enabled,
				 uint16_t deassert_enabled)
{
    sensor_t *sensor;

    if ((lun >= 4) || (sens_num >= 255) || (!mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = mc->sensors[lun][sens_num];

    if (init_events)
	sensor->events_enabled = events_enable;
    if (init_scanning)
	sensor->scanning_enabled = scanning_enable;
    sensor->event_support = event_support;
    sensor->event_supported[0] = assert_supported;
    sensor->event_supported[1] = deassert_supported;
    sensor->event_enabled[0] = assert_enabled & assert_supported;
    sensor->event_enabled[1] = deassert_enabled & deassert_supported;

    sensor_poll(sensor);
	
    return 0;
}

static int
init_sensor_from_sdr(lmc_data_t *mc, unsigned char *sdr)
{
    int err;
    unsigned int len = sdr[4];
    unsigned char num = sdr[7];
    unsigned char lun = sdr[6] & 0x3;
    uint16_t assert_sup, deassert_sup, assert_en, deassert_en;
    unsigned char events_on = (sdr[10] >> 1) & 1;
    unsigned char scan_on = (sdr[10] >> 0) & 1;
    unsigned char init_events = (sdr[10] >> 5) & 1;
    unsigned char init_scan = (sdr[10] >> 6) & 1;
    unsigned char init_thresh = (sdr[10] >> 4) & 1;
    unsigned char init_hyst = (sdr[10] >> 3) & 1;
    unsigned char init_type = (sdr[10] >> 2) & 1;
    unsigned char event_sup = sdr[11] & 0x3;
    unsigned char thresh_sup = (sdr[11] >> 2) & 0x3;
    uint16_t thresh_set;
    unsigned char hyst_sup = (sdr[11] >> 4) & 3;
    sensor_t *sensor;

    if ((lun >= 4) || (num >= 255) || (!mc->sensors[lun][num]))
	return EINVAL;

    sensor = mc->sensors[lun][num];

    if (len < 20)
	return 0;
    if ((sdr[3] < 1) || (sdr[3] > 2))
	return 0; /* Not a sensor SDR we set from */

    thresh_set = ((sdr[15] >> 4) & 0x7) | (((sdr[17] >> 4) & 0x7) << 3);
    assert_sup = sdr[14] | (sdr[15] << 8);
    deassert_sup = sdr[16] | (sdr[17] << 8);
    assert_en = sdr[14] | (sdr[15] << 8);
    deassert_en = sdr[16] | (sdr[17] << 8);

    if (init_type) {
	sensor->sensor_type = sdr[12];
	sensor->event_reading_code = sdr[13];
    }

    err = ipmi_mc_sensor_set_event_support(mc, lun, num,
					   init_events,
					   events_on,
					   init_scan,
					   scan_on,
					   event_sup,
					   assert_sup,
					   deassert_sup,
					   assert_en,
					   deassert_en);
    if (err)
	return err;

    if (init_thresh) {
	if (thresh_sup == 2 && sdr[3] == 1) {
	    unsigned char thresh_val[6];
	    thresh_val[0] = sdr[41];
	    thresh_val[1] = sdr[40];
	    thresh_val[2] = sdr[39];
	    thresh_val[3] = sdr[38];
	    thresh_val[4] = sdr[37];
	    thresh_val[5] = sdr[36];
	    err = ipmi_mc_sensor_set_threshold(mc, lun, num,
					       thresh_sup, thresh_set,
					       1, thresh_val);
	} else {
	    err = ipmi_mc_sensor_set_threshold(mc, lun, num,
					       thresh_sup, thresh_set,
					       0, NULL);
	}
	if (err)
	    return err;
    }

    if (init_hyst) {
	if (sdr[3] == 1) {
	    err = ipmi_mc_sensor_set_hysteresis(mc, lun, num,
						hyst_sup, sdr[42], sdr[43]);
	} else if (sdr[3] == 2) {
	    err = ipmi_mc_sensor_set_hysteresis(mc, lun, num,
						hyst_sup, sdr[25], sdr[26]);
	}
    }

    return err;
}

static int check_sensor_sdr(lmc_data_t *mc, unsigned char *sdr,
			    unsigned int len, void *cb_data)
{
    sensor_t *sensor = cb_data;
    uint8_t mc_ipmb = ipmi_mc_get_ipmb(mc);

    if (len < 8)
	return 0;
    if ((sdr[3] != 1) && (sdr[3] != 2))
	return 0;
    if (sdr[5] != mc_ipmb)
	return 0;
    if ((sdr[6] & 0x3) != sensor->lun)
	return 0;
    if (sdr[7] != sensor->num)
	return 0;

    init_sensor_from_sdr(mc, sdr);

    return 1;
}

int
ipmi_mc_add_sensor(lmc_data_t    *mc,
		   unsigned char lun,
		   unsigned char sens_num,
		   unsigned char type,
		   unsigned char event_reading_code,
		   int           event_only)
{
    sensor_t *sensor;
    lmc_data_t *bmc;

    if ((lun >= 4) || (sens_num >= 255) || (mc->sensors[lun][sens_num]))
	return EINVAL;

    sensor = malloc(sizeof(*sensor));
    if (!sensor)
	return ENOMEM;
    memset(sensor, 0, sizeof(*sensor));

    sensor->mc = mc;
    sensor->lun = lun;
    sensor->num = sens_num;
    sensor->sensor_type = type;
    sensor->event_reading_code = event_reading_code;
    sensor->event_only = event_only;
    mc->sensors[lun][sens_num] = sensor;

    if (mc->emu->atca_mode && (type == 0xf0)) {
	/* This is the ATCA hot-swap sensor. */
	mc->hs_sensor = sensor;
	sensor->sensor_update_handler = picmg_led_set;
    }

    bmc = ipmi_emu_get_bmc_mc(mc->emu);
    if (bmc)
	iterate_sdrs(mc, &bmc->main_sdrs, check_sensor_sdr, sensor);

    /* Delay enable so the above process won't generate any events. */
    sensor->enabled = 1;
    /* Clear any status we might have just generated. */
    sensor->event_status = 0;

    return 0;
}

struct file_data {
    char *filename;
    unsigned int offset;
    unsigned int length;
    unsigned int mask;
    unsigned int initstate;
    int is_raw;
    int mult;
    int div;
    int sub;
    int base;
    emu_data_t *emu;
    lmc_data_t *sensor_mc;
    unsigned char sensor_lun;
    unsigned char sensor_num;
    unsigned char depends_mc_addr;
    unsigned char depends_lun;
    unsigned char depends_sensor_num;
    unsigned char depends_sensor_bit;
};

static int
file_poll(void *cb_data, unsigned int *rval, const char **errstr)
{
    struct file_data *f = cb_data;
    int fd;
    int rv;
    int val;
    char *end;
    int errv;

    if (f->depends_mc_addr) {
	lmc_data_t *mc = f->sensor_mc;
	sensor_t *sensor, *dsensor;

	sensor = mc->sensors[f->sensor_lun][f->sensor_num];
	if (!sensor) {
	    *errstr = "Invalid sensor";
	    return EINVAL;
	}

	errv = ipmi_emu_get_mc_by_addr(mc->emu, f->depends_mc_addr, &mc);
	if (errv) {
	    *errstr = "Invalid depends mc address";
	    return errv;
	}
	dsensor = mc->sensors[f->depends_lun][f->depends_sensor_num];
	if (!dsensor) {
	    *errstr = "Invalid depends sensor number or LUN";
	    return EINVAL;
	}
	sensor->enabled = bit_set(dsensor->event_status, f->depends_sensor_bit);
	if (!sensor->enabled) 
	    return 0;
    }

    fd = open(f->filename, O_RDONLY);
    if (fd == -1) {
	errv = errno;
	*errstr = "Unable to open sensor file";
	return errv;
    }

    if (f->offset) {
	if (lseek(fd, f->offset, SEEK_SET) == -1) {
	    errv = errno;
	    close(fd);
	    *errstr = "Unable to seek file";
	    return errv;
	}
    }

    if (f->is_raw) {
	unsigned char data[4];
	int i;
	int length = f->length;

	if (length > 4)
	    length = 4;
	rv = read(fd, data, length);
	errv = errno;
	close(fd);
	if (rv == -1) {
	    *errstr = "No data read from file";
	    return errv;
	} else if (rv < length) {
	    *errstr = "Short data read from file";
	    return -1;
	}
	val = 0;
	for (i = 0; i < length; i++)
	    val |= data[i] << (i * 8);
    } else {
	char data[100];

	rv = read(fd, data, sizeof(data) - 1);
	errv = errno;
	close(fd);
	if (rv == -1) {
	    *errstr = "No data read from file";
	    return errv;
	}
	data[rv] = '\0';

	val = strtol(data, &end, f->base);
	if ((*end != '\0' && !isspace(*end)) || (end == data)) {
	    *errstr = "Invalid data read from file";
	    return EINVAL;
	}
    }

    if (f->mask)
	val &= f->mask;

    val -= f->sub;

    if (f->mult)
	val = val * f->mult;

    if (f->div)
	val = (val + (f->div / 2)) / f->div;

    *rval = val;
    return 0;
}

static int
file_init(lmc_data_t *mc,
	  unsigned char lun, unsigned char sensor_num,
	  char **toks, void *cb_data, void **rcb_data,
	  const char **errstr)
{
    const char *fname;
    struct file_data *f;
    char *end;
    int err;
    const char *tok;

    if (lun >= 4) {
	*errstr = "Invalid sensor LUN";
	return EINVAL;
    }

    err = get_delim_str(toks, &fname, errstr);
    if (err)
	return err;
    f = malloc(sizeof(*f));
    if (!f)
	return ENOMEM;
    memset(f, 0, sizeof(*f));
    f->emu = mc->emu;
    f->sensor_mc = mc;
    f->sensor_lun = lun;
    f->sensor_num = sensor_num;
    tok = mystrtok(NULL, " \t\n", toks);
    while (tok) {
	if (strncmp("div=", tok, 4) == 0) {
	    f->div = strtol(tok + 4, &end, 0);
	    if (*end != '\0') {
		*errstr = "Invalid div value";
		goto out_err;
	    }
	} else if (strncmp("mult=", tok, 5) == 0) {
	    f->mult = strtol(tok + 5, &end, 0);
	    if (*end != '\0') {
		*errstr = "Invalid mult value";
		goto out_err;
	    }
	} else if (strncmp("sub=", tok, 4) == 0) {
	    f->sub = strtol(tok + 4, &end, 0);
	    if (*end != '\0') {
		*errstr = "Invalid sub value";
		goto out_err;
	    }
	} else if (strncmp("base=", tok, 5) == 0) {
	    f->base = strtol(tok + 5, &end, 0);
	    if (*end != '\0') {
		*errstr = "Invalid base value";
		goto out_err;
	    }
	} else if (strncmp("mask=", tok, 5) == 0) {
	    f->mask = strtol(tok + 5, &end, 0);
	    if (*end != '\0') {
		*errstr = "Invalid mask value";
		goto out_err;
	    }
	} else if (strncmp("initstate=", tok, 5) == 0) {
	    f->initstate = strtol(tok + 5, &end, 0);
	    if (*end != '\0') {
		*errstr = "Invalid initstate value";
		goto out_err;
	    }
	} else if (strcmp("raw", tok) == 0) {
	    f->is_raw = 1;
	} else if (strcmp("ascii", tok) == 0) {
	    f->is_raw = 0;
	} else if (strncmp("offset=", tok, 7) == 0) {
	    f->offset = strtoul(tok + 7, &end, 0);
	    if (*end != '\0') {
		*errstr = "Invalid offset value";
		goto out_err;
	    }
	} else if (strncmp("length=", tok, 7) == 0) {
	    f->length = strtoul(tok + 7, &end, 0);
	    if (*end != '\0') {
		*errstr = "Invalid length value";
		goto out_err;
	    }
	} else if (strncmp("depends=", tok, 8) == 0) {
	    char *toks2;

	    tok = mystrtok((char *) tok + 8, ",", &toks2);
	    if (!tok) {
		*errstr = "No mc address for sensor depends";
		goto out_err;
	    }
	    f->depends_mc_addr = strtoul((char *) tok, &end, 0);
	    if (*end != '\0') {
		*errstr = "Invalid depends mc addr";
		goto out_err;
	    }

	    tok = mystrtok(NULL, ",", &toks2);
	    if (!tok) {
		*errstr = "No lun for sensor depends";
		goto out_err;
	    }
	    f->depends_lun = strtoul(tok, &end, 0);
	    if (*end != '\0' || f->depends_lun >= 4) {
		*errstr = "Invalid depends lun";
		goto out_err;
	    }

	    tok = mystrtok(NULL, ",", &toks2);
	    if (!tok) {
		*errstr = "No sensor number for sensor depends";
		goto out_err;
	    }
	    f->depends_sensor_num = strtoul(tok, &end, 0);
	    if (*end != '\0') {
		*errstr = "Invalid depends sensor_number";
		goto out_err;
	    }

	    tok = mystrtok(NULL, ",", &toks2);
	    if (!tok) {
		*errstr = "No sensor bit for sensor depends";
		goto out_err;
	    }
	    f->depends_sensor_bit = strtoul(tok, &end, 0);
	    if (*end != '\0' || f->depends_sensor_bit >= 15) {
		*errstr = "Invalid depends sensor_number";
		goto out_err;
	    }
	} else {
	    *errstr = "Invalid file option, options are div= and base=";
	    goto out_err;
	}
	tok = mystrtok(NULL, " \t\n", toks);
    }

    f->filename = strdup(fname);
    if (!f->filename) {
	free(f);
	return ENOMEM;
    }

    *rcb_data = f;
    return 0;

  out_err:
    free(f);
    return -1;
}

static int
file_post_init(void *cb_data, const char **errstr)
{
    struct file_data *f = cb_data;
    lmc_data_t *mc = f->sensor_mc;
    sensor_t *sensor;

    sensor = mc->sensors[f->sensor_lun][f->sensor_num];
    if (!sensor) {
	*errstr = "Unable to find sensor"; 
	return EINVAL;
    }

    sensor->event_status = f->initstate;

    return 0;
}

static ipmi_sensor_handler_t file_sensor =
{
    .name = "file",
    .poll = file_poll,
    .init = file_init,
    .postinit = file_post_init
};

static ipmi_sensor_handler_t *sensor_handlers = &file_sensor;

int
ipmi_sensor_add_handler(ipmi_sensor_handler_t *handler)
{
    handler->next = sensor_handlers;
    sensor_handlers = handler;
    return 0;
}

ipmi_sensor_handler_t *
ipmi_sensor_find_handler(const char *name)
{
    ipmi_sensor_handler_t *handler = sensor_handlers;

    while (handler) {
	if (strcmp(handler->name, name) == 0)
	    return handler;
	handler = handler->next;
    }
    return NULL;
}

static void
free_sensor(lmc_data_t *mc, sensor_t *sensor)
{
    mc->sensors[sensor->lun][sensor->num] = NULL;
    free(sensor);
}

static void
sensor_poll(void *cb_data)
{
    sensor_t *sensor = cb_data;

    if (sensor->poll && sensor->scanning_enabled) {
	lmc_data_t *mc = sensor->mc;
	unsigned int val;
	const char *errstr;
	int err;

	err = sensor->poll(sensor->cb_data, &val, &errstr);
	if (err) {
	    mc->sysinfo->log(mc->sysinfo, OS_ERROR, NULL,
			     "Error getting sensor value (%2.2x,%d,%d): %s, %s",
			     ipmi_mc_get_ipmb(mc), sensor->lun, sensor->num,
			     strerror(err), errstr);
	    goto out_restart;
	}
	
	if (sensor->event_reading_code == IPMI_EVENT_READING_TYPE_THRESHOLD) {
	    if (val < 0)
		val = 0;
	    else if (val > 255)
		val = 255;
	    set_sensor_value(mc, sensor, val, 1);
	} else {
	    unsigned int i;
	    
	    for (i = 0; i < 15; i++)
		set_sensor_bit(mc, sensor,
			       i, ((val >> i) & 1), 0, 0xff, 0xff, 1);
	}

      out_restart:
	mc->sysinfo->start_timer(sensor->poll_timer, &sensor->poll_timer_time);
    }
}

int
ipmi_mc_add_polled_sensor(lmc_data_t    *mc,
			  unsigned char lun,
			  unsigned char sens_num,
			  unsigned char type,
			  unsigned char event_reading_code,
			  unsigned int poll_rate,
			  int (*poll)(void *cb_data, unsigned int *val,
				      const char **errstr),
			  void *cb_data)
{
    sensor_t *sensor;
    int err;

    err = ipmi_mc_add_sensor(mc, lun, sens_num, type, event_reading_code, 0);
    if (err)
	return err;

    sensor = mc->sensors[lun][sens_num];

    sensor->poll = poll;
    sensor->poll_timer_time.tv_sec = poll_rate / 1000;
    sensor->poll_timer_time.tv_usec = (poll_rate % 1000) * 1000;
    sensor->cb_data = cb_data;
    
    err = mc->sysinfo->alloc_timer(mc->sysinfo, sensor_poll, sensor,
				   &sensor->poll_timer);
    if (err) {
	free_sensor(mc, sensor);
	return err;
    }

    mc->sysinfo->start_timer(sensor->poll_timer, &sensor->poll_timer_time);

    return 0;
}

static void
handle_ipmi_get_pef_capabilities(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len,
				 void          *cb_data)
{
    if (!mc->sysinfo) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = 0x51; /* version */
    rdata[2] = 0x3f; /* support everything but OEM */
    rdata[3] = MAX_EVENT_FILTERS;
    *rdata_len = 4;
}

static void
handle_ipmi_set_pef_config_parms(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len,
				 void          *cb_data)
{
    unsigned char err = 0;
    int           set, block;
    sys_data_t    *sys = mc->sysinfo;

    if (msg->len < 2) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if (!sys) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    switch (msg->data[0] & 0x7f)
    {
    case 0:
	switch (msg->data[1] & 0x3)
	{
	case 0:
	    if (mc->pef.set_in_progress) {
		/* rollback */
		memcpy(&mc->pef, &mc->pef_rollback,
		       sizeof(mc->pef));
	    }
	    /* No affect otherwise */
	    break;

	case 1:
	    if (mc->pef.set_in_progress)
		err = 0x81; /* Another user is writing. */
	    else {
		/* Save rollback data */
		memcpy(&mc->pef_rollback, &mc->pef,
		       sizeof(mc->pef));
		mc->pef.set_in_progress = 1;
	    }
	    break;

	case 2:
	    if (mc->pef.commit)
		mc->pef.commit(sys);
	    memset(&mc->pef.changed, 0, sizeof(mc->pef.changed));
	    mc->pef.set_in_progress = 0;
	    break;

	case 3:
	    err = IPMI_INVALID_DATA_FIELD_CC;
	}
	break;

    case 5:
    case 8:
    case 11:
	err = 0x82; /* Read-only data */
	break;

    case 1:
	mc->pef.pef_control = msg->data[1];
	mc->pef.changed.pef_control = 1;
	break;

    case 2:
	mc->pef.pef_action_global_control = msg->data[1];
	mc->pef.changed.pef_action_global_control = 1;
	break;

    case 3:
	mc->pef.pef_startup_delay = msg->data[1];
	mc->pef.changed.pef_startup_delay = 1;
	break;

    case 4:
	mc->pef.pef_alert_startup_delay = msg->data[1];
	mc->pef.changed.pef_alert_startup_delay = 1;
	break;

    case 6:
	set = msg->data[1] & 0x7f;
	if (msg->len < 22)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if ((set <= 0) || (set >= mc->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(mc->pef.event_filter_table[set], msg->data+1, 21);
	    mc->pef.changed.event_filter_table[set] = 1;
	}
	break;

    case 7:
	set = msg->data[1] & 0x7f;
	if (msg->len < 3)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if ((set <= 0) || (set >= mc->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(mc->pef.event_filter_data1[set], msg->data+1, 2);
	    mc->pef.changed.event_filter_data1[set] = 1;
	}
	break;

    case 9:
	set = msg->data[1] & 0x7f;
	if (msg->len < 5)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if ((set <= 0) || (set >= mc->pef.num_alert_policies))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(mc->pef.alert_policy_table[set], msg->data+1, 4);
	    mc->pef.changed.alert_policy_table[set] = 1;
	}
	break;

    case 10:
	if (msg->len < 18)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else {
	    memcpy(mc->pef.system_guid, msg->data+1, 17);
	    mc->pef.changed.system_guid = 1;
	}
	break;

    case 12:
	set = msg->data[1] & 0x7f;
	if (msg->len < 4)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if (set >= mc->pef.num_alert_strings)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    set = msg->data[1] & 0x7f;
	    memcpy(mc->pef.alert_string_keys[set], msg->data+1, 3);
	    mc->pef.changed.alert_string_keys[set] = 1;
	}
	break;

    case 13:
	set = msg->data[1] & 0x7f;
	if (msg->len < 4)
	    err =  IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	else if (set >= mc->pef.num_alert_strings)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else if (msg->data[2] == 0)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    int dlen = msg->len - 3;
	    set = msg->data[1] & 0x7f;
	    block = msg->data[2] - 1;
	    if (((block*16) + dlen) > MAX_ALERT_STRING_LEN) {
		err = IPMI_PARAMETER_OUT_OF_RANGE_CC;
		break;
	    }
	    memcpy(mc->pef.alert_strings[set]+(block*16), msg->data+3, dlen);
	    mc->pef.changed.alert_strings[set] = 1;
	}
	break;

    default:
	err = 0x80; /* Parm not supported */
    }

    rdata[0] = err;
    *rdata_len = 1;
}

static void
handle_ipmi_get_pef_config_parms(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len,
				 void          *cb_data)
{
    int           set, block;
    unsigned char databyte = 0;
    unsigned char *data = NULL;
    unsigned int  length = 0;
    unsigned char err = 0;
    unsigned char tmpdata[18];

    sys_data_t    *sys = mc->sysinfo;

    if (msg->len < 3) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    if (!sys) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    switch (msg->data[0] & 0x7f)
    {
    case 0:
	databyte = mc->pef.set_in_progress;
	break;

    case 5:
	databyte = mc->pef.num_event_filters - 1;
	break;

    case 8:
	databyte = mc->pef.num_alert_policies - 1;
	break;

    case 11:
	databyte = mc->pef.num_alert_strings - 1;
	break;

    case 1:
	databyte = mc->pef.pef_control;
	break;

    case 2:
	databyte = mc->pef.pef_action_global_control;
	break;

    case 3:
	databyte = mc->pef.pef_startup_delay;
	break;

    case 4:
	databyte = mc->pef.pef_alert_startup_delay;
	break;

    case 6:
	set = msg->data[1] & 0x7f;
	if ((set <= 0) || (set >= mc->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = mc->pef.event_filter_table[set];
	    length = 21;
	}
	break;

    case 7:
	set = msg->data[1] & 0x7f;
	if ((set <= 0) || (set >= mc->pef.num_event_filters))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = mc->pef.event_filter_data1[set];
	    length = 2;
	}
	break;

    case 9:
	set = msg->data[1] & 0x7f;
	if ((set <= 0) || (set >= mc->pef.num_alert_policies))
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = mc->pef.alert_policy_table[set];
	    length = 4;
	}
	break;

    case 10:
	data = mc->pef.system_guid;
	length = 17;
	break;

    case 12:
	set = msg->data[1] & 0x7f;
	if (set >= mc->pef.num_alert_strings)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    data = mc->pef.alert_string_keys[set];
	    length = 3;
	}
	break;

    case 13:
	set = msg->data[1] & 0x7f;
	if (set >= mc->pef.num_alert_strings)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else if (msg->data[2] == 0)
	    err = IPMI_INVALID_DATA_FIELD_CC;
	else {
	    block = msg->data[2] - 1;
	    if ((block*16) > MAX_ALERT_STRING_LEN) {
		err = IPMI_PARAMETER_OUT_OF_RANGE_CC;
		break;
	    }
	    tmpdata[0] = set;
	    tmpdata[1] = block + 1;
	    memcpy(tmpdata+2, mc->pef.alert_strings[set]+(block*16), 16);
	    data = tmpdata;
	    length = 18;
	}
	break;

    default:
	err = 0x80; /* Parm not supported */
    }

    rdata[0] = err;
    if (err) {
	*rdata_len = 1;
	return;
    }

    rdata[1] = 0x11; /* rev */
    if (msg->data[0] & 0x80) {
	*rdata_len = 2;
    } else if (data) {
	memcpy(rdata + 2, data, length);
	*rdata_len = length + 2;
    } else {
	rdata[2] = databyte;
	*rdata_len = 3;
    }
}

cmd_handler_f sensor_event_netfn_handlers[256] = {
    [IPMI_GET_EVENT_RECEIVER_CMD] = handle_get_event_receiver,
    [IPMI_SET_EVENT_RECEIVER_CMD] = handle_set_event_receiver,
    [IPMI_GET_DEVICE_SDR_INFO_CMD] = handle_get_device_sdr_info,
    [IPMI_RESERVE_DEVICE_SDR_REPOSITORY_CMD] = handle_reserve_device_sdr_repository,
    [IPMI_GET_DEVICE_SDR_CMD] = handle_get_device_sdr,
    [IPMI_SET_SENSOR_HYSTERESIS_CMD] = handle_set_sensor_hysteresis,
    [IPMI_GET_SENSOR_HYSTERESIS_CMD] = handle_get_sensor_hysteresis,
    [IPMI_SET_SENSOR_THRESHOLD_CMD] = handle_set_sensor_thresholds,
    [IPMI_GET_SENSOR_THRESHOLD_CMD] = handle_get_sensor_thresholds,
    [IPMI_SET_SENSOR_EVENT_ENABLE_CMD] = handle_set_sensor_event_enable,
    [IPMI_GET_SENSOR_EVENT_ENABLE_CMD] = handle_get_sensor_event_enable,
    [IPMI_SET_SENSOR_TYPE_CMD] = handle_set_sensor_type,
    [IPMI_GET_SENSOR_TYPE_CMD] = handle_get_sensor_type,
    [IPMI_GET_SENSOR_READING_CMD] = handle_get_sensor_reading,
    [IPMI_GET_PEF_CAPABILITIES_CMD] = handle_ipmi_get_pef_capabilities,
    [IPMI_SET_PEF_CONFIG_PARMS_CMD] = handle_ipmi_set_pef_config_parms,
    [IPMI_GET_PEF_CONFIG_PARMS_CMD] = handle_ipmi_get_pef_config_parms,
    [IPMI_GET_SENSOR_EVENT_STATUS_CMD] = NULL,
    [IPMI_REARM_SENSOR_EVENTS_CMD] = handle_rearm_sensor_events,
    [IPMI_GET_SENSOR_READING_FACTORS_CMD] = NULL
};
