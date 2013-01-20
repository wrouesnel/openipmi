/*
 * bmc_picmg.c
 *
 * MontaVista IPMI code for emulating a MC.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2003,2012 MontaVista Software Inc.
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
#include <malloc.h>
#include <string.h>

#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_picmg.h>

int
ipmi_mc_set_power(lmc_data_t *mc, unsigned char power, int gen_event)
{
    lmc_data_t    *dest_mc;
    unsigned char data[13];
    int           rv;

    if (mc->power_value == power)
	return 0;

    mc->power_value = power;

    if ((mc->event_receiver == 0)
	|| (!gen_event))
	return 0;

    rv = ipmi_emu_get_mc_by_addr(mc->emu, mc->event_receiver, &dest_mc);
    if (rv)
	return 0;

    /* Timestamp is ignored. */
    data[0] = 0;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;

    data[4] = 0x20; /* These come from 0x20. */
    data[5] = 0;
    data[6] = 0x01; /* Version 1. */
    data[7] = 0;
    data[8] = 0x40; /* IPMB of the device being powered. */
    data[9] = 0;
    data[10] = power;
    data[11] = 0;
    data[12] = 0;

    mc_new_event(dest_mc, 0xc0, data);
	
    return 0;
}

static void
handle_set_power(lmc_data_t    *mc,
		 msg_t         *msg,
		 unsigned char *rdata,
		 unsigned int  *rdata_len,
		 void          *cb_data)
{
    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    ipmi_mc_set_power(mc, msg->data[0], 1);

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_power(lmc_data_t    *mc,
		 msg_t         *msg,
		 unsigned char *rdata,
		 unsigned int  *rdata_len,
		 void          *cb_data)
{
    rdata[0] = 0;
    rdata[1] = mc->power_value;
    *rdata_len = 2;
}

static void
handle_set_hs_led(lmc_data_t    *mc,
		  msg_t         *msg,
		  unsigned char *rdata,
		  unsigned int  *rdata_len,
		  void          *cb_data)
{
    if (check_msg_length(msg, 1, rdata, rdata_len))
	return;

    mc->leds[0].color = msg->data[0];

    printf("Setting hotswap LED to %d\n", msg->data[0]);

    rdata[0] = 0;
    *rdata_len = 1;
}

static void
handle_get_hs_led(lmc_data_t    *mc,
		  msg_t         *msg,
		  unsigned char *rdata,
		  unsigned int  *rdata_len,
		  void          *cb_data)
{
    rdata[0] = 0;
    rdata[1] = mc->leds[0].color;
    *rdata_len = 2;
}

cmd_handler_f oem0_netfn_handlers[256] = {
    [0x01] = handle_set_power,
    [0x02] = handle_get_power,
    [0x03] = handle_set_hs_led,
    [0x04] = handle_get_hs_led
};

static void
handle_picmg_get_properties(lmc_data_t    *mc,
			    msg_t         *msg,
			    unsigned char *rdata,
			    unsigned int  *rdata_len,
			    void          *cb_data)
{
    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = 0x22; /* Version 2.2 */
    rdata[3] = 0; /* Only have one FRU. */
    rdata[4] = 0; /* As defined by spec. */
    *rdata_len = 5;
}

static void
handle_picmg_get_address_info(lmc_data_t    *mc,
			      msg_t         *msg,
			      unsigned char *rdata,
			      unsigned int  *rdata_len,
			      void          *cb_data)
{
    atca_site_t  *sites = mc->emu->atca_sites;
    unsigned char hw_addr = mc->ipmb >> 1;
    unsigned char devid = 0;
    int           i;

    if (msg->len == 3) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (msg->len >= 2)
	devid = msg->data[1];

    if (msg->len >= 4) {
	switch (msg->data[2]) {
	case 0:
	    hw_addr = msg->data[3];
	    break;

	case 1:
	    hw_addr = msg->data[3] >> 1;
	    break;

	case 3:
	    if (msg->len < 5) {
		rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
		*rdata_len = 1;
		return;
	    }
	    for (i=0; i<128; i++) {
		if (sites[i].valid
		    && (sites[i].site_type == msg->data[4])
		    && (sites[i].site_number == msg->data[3]))
		{
		    break;
		}
	    }
	    if (i == 128) {
		rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
		*rdata_len = 1;
		return;
	    }
	    hw_addr = i;
	    break;
		
	default:
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}
    }

    if ((hw_addr >= 128) || (!sites[hw_addr].valid) || (devid > 0)) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = hw_addr;
    rdata[3] = hw_addr << 1;
    rdata[4] = 0xff;
    rdata[5] = devid;
    rdata[6] = sites[hw_addr].site_number;
    rdata[7] = sites[hw_addr].site_type;
    *rdata_len = 8;
}

static void
handle_picmg_cmd_fru_control(lmc_data_t    *mc,
			     msg_t         *msg,
			     unsigned char *rdata,
			     unsigned int  *rdata_len,
			     void          *cb_data)
{
    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    if (msg->data[2] >= 4) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    /* Nothing to reset. */
    printf("Fru control set to %d\n", msg->data[2]);

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    *rdata_len = 2;
}

static void
handle_picmg_cmd_get_fru_led_properties(lmc_data_t    *mc,
					msg_t         *msg,
					unsigned char *rdata,
					unsigned int  *rdata_len,
					void          *cb_data)
{
    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    if (mc->num_leds <= 2) {
	mc->num_leds = 2;
	rdata[2] = 0x03; /* We support the first 2 LEDs. */
	rdata[3] = 0x00;
    } else if (mc->num_leds == 3) {
	rdata[2] = 0x07; /* We support the first 3 LEDs. */
	rdata[3] = 0x00;
    } else {
	rdata[2] = 0xf; /* We support the first 4 LEDs. */
	rdata[3] = mc->num_leds = 4; /* How many more do we support? */
    }
    *rdata_len = 4;
}

static void
handle_picmg_cmd_get_led_color_capabilities(lmc_data_t    *mc,
					    msg_t         *msg,
					    unsigned char *rdata,
					    unsigned int  *rdata_len,
					    void          *cb_data)
{
    unsigned int led;

    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    led = msg->data[2];
    if (led >= mc->num_leds) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = mc->leds[led].color_sup;
    rdata[3] = mc->leds[led].def_loc_cnt_color;
    rdata[4] = mc->leds[led].def_override_color;

    *rdata_len = 5;
}

void
picmg_led_set(lmc_data_t *mc, sensor_t *sensor)
{
    printf("ATCA hot-swap state is %d\n", sensor->value);

    switch (sensor->value) {
    case 0:
    case 3:
    case 4:
	/* off */
	mc->leds[0].def_off_dur = 0;
	mc->leds[0].def_on_dur = 0;
	break;

    case 1:
	/* on */
	mc->leds[0].def_off_dur = 0xff;
	mc->leds[0].def_on_dur = 0;
	break;

    case 2:
	/* long blink */
	mc->leds[0].def_off_dur = 10;
	mc->leds[0].def_on_dur = 90;
	break;

    case 5:
    case 6:
	/* short blink */
	mc->leds[0].def_off_dur = 90;
	mc->leds[0].def_on_dur = 10;
	break;
		
    case 7:
	/* Nothing to do */
	break;
    }

    if (mc->leds[0].loc_cnt) {
	mc->leds[0].off_dur = mc->leds[0].def_off_dur;
	mc->leds[0].on_dur = mc->leds[0].def_on_dur;
	printf("Setting ATCA LED %d to %s %x %x %x\n",
	       0,
	       mc->leds[0].loc_cnt ? "local_control" : "override",
	       mc->leds[0].off_dur,
	       mc->leds[0].on_dur,
	       mc->leds[0].color);
    }
}

static void
handle_picmg_cmd_set_fru_led_state(lmc_data_t    *mc,
				   msg_t         *msg,
				   unsigned char *rdata,
				   unsigned int  *rdata_len,
				   void          *cb_data)
{
    unsigned int led;

    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    led = msg->data[2];
    if (led >= mc->num_leds) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    switch (msg->data[3]) {
    case 0xfc: /* Local control */
	if (!mc->leds[led].loc_cnt_sup) {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}

	mc->leds[led].loc_cnt = 1;

	mc->leds[led].off_dur = mc->leds[led].def_off_dur;
	mc->leds[led].on_dur = mc->leds[led].def_on_dur;
	mc->leds[led].color = mc->leds[led].def_loc_cnt_color;
	break;

    case 0xfb:
    case 0xfd:
    case 0xfe:
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;

    default: /* Override mode */
	mc->leds[led].loc_cnt = 0;
	mc->leds[led].off_dur = msg->data[3];
	mc->leds[led].on_dur = msg->data[4];
	if (msg->data[5] == 0xf)
	    mc->leds[led].color = mc->leds[led].def_override_color;
	else if (msg->data[5] != 0xe) /* 0xe is don't change. */
	    mc->leds[led].color = msg->data[5];
    }

    printf("Setting ATCA LED %d to %s %x %x %x\n",
	   led,
	   mc->leds[led].loc_cnt ? "local_control" : "override",
	   mc->leds[led].off_dur,
	   mc->leds[led].on_dur,
	   mc->leds[led].color);

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    *rdata_len = 2;
}

static void
handle_picmg_cmd_get_fru_led_state(lmc_data_t    *mc,
				   msg_t         *msg,
				   unsigned char *rdata,
				   unsigned int  *rdata_len,
				   void          *cb_data)
{
    unsigned int led;

    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    led = msg->data[2];
    if (led >= mc->num_leds) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = 0x00;
    if (mc->leds[led].loc_cnt_sup)
	rdata[2] |= 0x01; /* Local control support */

    if (mc->leds[led].loc_cnt) {
	rdata[3] = mc->leds[led].off_dur;
	rdata[4] = mc->leds[led].on_dur;
	rdata[5] = mc->leds[led].color;
	*rdata_len = 6;
    } else {
	rdata[2] |= 0x02; /* override state. */
	rdata[3] = mc->leds[led].def_off_dur;
	rdata[4] = mc->leds[led].def_on_dur;
	rdata[5] = mc->leds[led].def_loc_cnt_color;
	rdata[6] = mc->leds[led].off_dur;
	rdata[7] = mc->leds[led].on_dur;
	rdata[8] = mc->leds[led].color;
	*rdata_len = 9;
    }
}

static void
handle_picmg_cmd_get_shelf_address_info(lmc_data_t    *mc,
					msg_t         *msg,
					unsigned char *rdata,
					unsigned int  *rdata_len,
					void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_shelf_address_info(lmc_data_t    *mc,
					msg_t         *msg,
					unsigned char *rdata,
					unsigned int  *rdata_len,
					void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_ipmb_state(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len,
				void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_fru_activation_policy(lmc_data_t    *mc,
					   msg_t         *msg,
					   unsigned char *rdata,
					   unsigned int  *rdata_len,
					   void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_fru_activation_policy(lmc_data_t    *mc,
					   msg_t         *msg,
					   unsigned char *rdata,
					   unsigned int  *rdata_len,
					   void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_fru_activation(lmc_data_t    *mc,
				    msg_t         *msg,
				    unsigned char *rdata,
				    unsigned int  *rdata_len,
				    void          *cb_data)
{
    int      op;
    sensor_t *hssens;

    if (check_msg_length(msg, 3, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    if (! mc->hs_sensor) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    op = msg->data[2];
    if (op >= 2) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    hssens = mc->hs_sensor;
    switch (op) {
    case 0:
	if (bit_set(hssens->event_status, 3)
	    || bit_set(hssens->event_status, 4)
	    || bit_set(hssens->event_status, 5))
	{
	    /* Transition to m6. */
	    ipmi_mc_sensor_set_bit_clr_rest(mc, hssens->lun, hssens->num,
					    6, 1);

	    /* Transition to m1. */
	    ipmi_mc_sensor_set_bit_clr_rest(mc, hssens->lun, hssens->num,
					    1, 1);
	}
	break;

    case 1:
	if (bit_set(hssens->event_status, 2)) {
	    /* Transition to m3. */
	    ipmi_mc_sensor_set_bit_clr_rest(mc, hssens->lun, hssens->num,
					    3, 1);

	    /* Transition to m4. */
	    ipmi_mc_sensor_set_bit_clr_rest(mc, hssens->lun, hssens->num,
					    4, 1);
	}
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    *rdata_len = 2;
}

static void
handle_picmg_cmd_get_device_locator_record(lmc_data_t    *mc,
					   msg_t         *msg,
					   unsigned char *rdata,
					   unsigned int  *rdata_len,
					   void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_port_state(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len,
				void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_port_state(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len,
				void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_compute_power_properties(lmc_data_t    *mc,
					  msg_t         *msg,
					  unsigned char *rdata,
					  unsigned int  *rdata_len,
					  void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_power_level(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len,
				 void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_power_level(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len,
				 void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_renegotiate_power(lmc_data_t    *mc,
				   msg_t         *msg,
				   unsigned char *rdata,
				   unsigned int  *rdata_len,
				   void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_fan_speed_properties(lmc_data_t    *mc,
					  msg_t         *msg,
					  unsigned char *rdata,
					  unsigned int  *rdata_len,
					  void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_fan_level(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len,
			       void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_fan_level(lmc_data_t    *mc,
			       msg_t         *msg,
			       unsigned char *rdata,
			       unsigned int  *rdata_len,
			       void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_bused_resource(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len,
				void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_ipmb_link_info(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len,
				void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_shelf_power_allocation(lmc_data_t    *mc,
					msg_t         *msg,
					unsigned char *rdata,
					unsigned int  *rdata_len,
					void          *cb_data)
{
    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    if (msg->data[1] > 1) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    ipmi_set_uint16(rdata+2, 0);
    if (msg->data[1] == 0) {
	ipmi_set_uint16(rdata+4, 105);
	ipmi_set_uint16(rdata+6, 227);
	*rdata_len = 8;
    } else {
	ipmi_set_uint16(rdata+4, 227);
	*rdata_len = 6;
    }
}

static void
handle_picmg_cmd_shelf_manager_ipmb_address(lmc_data_t    *mc,
					    msg_t         *msg,
					    unsigned char *rdata,
					    unsigned int  *rdata_len,
					    void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_set_fan_policy(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len,
				void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}

static void
handle_picmg_cmd_get_fan_policy(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len,
				void          *cb_data)
{
    handle_invalid_cmd(mc, rdata, rdata_len);
}


static void
handle_picmg_cmd_fru_control_capabilities(lmc_data_t    *mc,
					  msg_t         *msg,
					  unsigned char *rdata,
					  unsigned int  *rdata_len,
					  void          *cb_data)
{
    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    if (msg->data[1] != 0) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = 0x0e;
    *rdata_len = 3;
}

static void
handle_picmg_cmd_fru_inventory_device_lock_control(lmc_data_t    *mc,
						   msg_t         *msg,
						   unsigned char *rdata,
						   unsigned int  *rdata_len,
						   void          *cb_data)
{
    emu_data_t *emu = mc->emu;
    uint16_t   lock_id;
    fru_data_t *fru;

    if (mc->ipmb != 0x20) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 5, rdata, rdata_len))
	return;

    if (msg->data[1] != 254) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;

    switch (msg->data[2]) {
    case 0:
	rdata[2] = 0;
	rdata[3] = 0;
	ipmi_set_uint32(rdata+4, emu->atca_fru_inv_curr_timestamp);
	*rdata_len = 8;
	break;

    case 1:
	if (emu->atca_fru_inv_locked) {
	    rdata[0] = 0x81;
	    *rdata_len = 1;
	    break;
	}
	fru = find_fru(mc, 254);
	if (!fru || fru->length == 0) {
	    rdata[0] = IPMI_NOT_SUPPORTED_IN_PRESENT_STATE_CC;
	    *rdata_len = 1;
	    break;
	}
	emu->temp_fru_inv_data = malloc(fru->length);
	if (!emu->temp_fru_inv_data) {
	    rdata[0] = IPMI_OUT_OF_SPACE_CC;
	    *rdata_len = 1;
	    break;
	}
	emu->temp_fru_inv_data_len = fru->length;
	memcpy(emu->temp_fru_inv_data, fru->data, 
	       emu->temp_fru_inv_data_len);

	emu->atca_fru_inv_locked = 1;
	emu->atca_fru_inv_curr_lock_id++;
	ipmi_set_uint16(rdata+2, emu->atca_fru_inv_curr_lock_id);
	ipmi_set_uint32(rdata+4, emu->atca_fru_inv_curr_timestamp);
	*rdata_len = 8;
	emu->atca_fru_inv_lock_timeout = 20;
	break;

    case 2:
	lock_id = ipmi_get_uint16(msg->data+3);
	if (!emu->atca_fru_inv_locked
	    || (lock_id != emu->atca_fru_inv_curr_lock_id))
	{
	    rdata[0] = 0x81;
	    *rdata_len = 1;
	    break;
	}
	emu->atca_fru_inv_locked = 0;
	rdata[2] = 0;
	rdata[3] = 0;
	ipmi_set_uint32(rdata+4, emu->atca_fru_inv_curr_timestamp);
	*rdata_len = 8;
	free(emu->temp_fru_inv_data);
	emu->temp_fru_inv_data = NULL;
	break;

    case 3:
	lock_id = ipmi_get_uint16(msg->data+3);
	if (!emu->atca_fru_inv_locked
	    || (lock_id != emu->atca_fru_inv_curr_lock_id))
	{
	    rdata[0] = 0x81;
	    *rdata_len = 1;
	    break;
	}
	emu->atca_fru_inv_locked = 0;
	rdata[2] = 0;
	rdata[3] = 0;
	ipmi_set_uint32(rdata+4, emu->atca_fru_inv_curr_timestamp);
	*rdata_len = 8;
	emu->atca_fru_inv_curr_timestamp++;
	/* FIXME - validate data. */
	fru = find_fru(mc, 254);
	if (!fru || fru->length == 0) {
	    rdata[0] = IPMI_NOT_SUPPORTED_IN_PRESENT_STATE_CC;
	    *rdata_len = 1;
	    break;
	}
	memcpy(fru->data, emu->temp_fru_inv_data,
	       emu->temp_fru_inv_data_len);
	free(emu->temp_fru_inv_data);
	emu->temp_fru_inv_data = NULL;
	break;

    default:
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	break;
    }
}

static void
handle_picmg_cmd_fru_inventory_device_write(lmc_data_t    *mc,
					    msg_t         *msg,
					    unsigned char *rdata,
					    unsigned int  *rdata_len,
					    void          *cb_data)
{
    emu_data_t   *emu = mc->emu;
    uint16_t     lock_id;
    unsigned int offset;
    unsigned int count;

    if (mc->ipmb != 0x20) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 6, rdata, rdata_len))
	return;

    if (msg->data[1] != 254) {
	rdata[0] = IPMI_DESTINATION_UNAVAILABLE_CC;
	*rdata_len = 1;
	return;
    }

    lock_id = ipmi_get_uint16(msg->data+2);
    if (!emu->atca_fru_inv_locked
	|| (lock_id != emu->atca_fru_inv_curr_lock_id))
    {
	rdata[0] = 0x80;
	*rdata_len = 1;
	return;
    }

    /* Reset the timer. */
    emu->atca_fru_inv_lock_timeout = 20;

    offset = ipmi_get_uint16(msg->data+4);
    count = msg->len - 6;

    if (offset >= emu->temp_fru_inv_data_len) {
	rdata[0] = IPMI_PARAMETER_OUT_OF_RANGE_CC;
	*rdata_len = 1;
	return;
    }

    if ((offset+count) > emu->temp_fru_inv_data_len) {
	/* Too much data to put into FRU. */
	rdata[0] = IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC;
	*rdata_len = 1;
	return;
    }

    memcpy(emu->temp_fru_inv_data+offset, msg->data+6, count);

    rdata[0] = 0;
    rdata[1] = IPMI_PICMG_GRP_EXT;
    rdata[2] = count;
    *rdata_len = 3;
}

static void
handle_picmg_cmd_get_shelf_manager_ip_addresses(lmc_data_t    *mc,
						msg_t         *msg,
						unsigned char *rdata,
						unsigned int  *rdata_len,
						void          *cb_data)
{
    emu_data_t   *emu = mc->emu;
    unsigned int addr;
    unsigned int count;
    emu_addr_t   *ap = NULL;
    int          i;

    if (check_msg_length(msg, 2, rdata, rdata_len))
	return;

    addr = msg->data[1];
    
    for (count=0, i=0; i<MAX_EMU_ADDR; i++) {
	if (emu->addr[i].valid) {
	    if (count == addr)
		ap = &(emu->addr[i]);
	    count++;
	}
    }

    if (addr >= count) {
	rdata[0] = IPMI_PARAMETER_OUT_OF_RANGE_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    ipmi_set_uint32(rdata+1, emu->last_addr_change_time.tv_sec);
    rdata[5] = count;
    rdata[6] = 0x03;
    rdata[7] = addr - 1;
    rdata[8] = 20;

    rdata[9] = ap->addr_type;
    if (addr == 0)
	rdata[9] |= 0x80;
    memcpy(rdata+10, ap->addr_data, ap->addr_len);
    *rdata_len = 10 + ap->addr_len;
}

int
ipmi_emu_atca_enable(emu_data_t *emu)
{
    emu->atca_mode = 1;
    return 0;
}

int
ipmi_emu_atca_set_site(emu_data_t    *emu,
		       unsigned char hw_address,
		       unsigned char site_type,
		       unsigned char site_number)
{
    if (hw_address >= 128)
	return EINVAL;

    emu->atca_sites[hw_address].valid = 1;
    emu->atca_sites[hw_address].hw_address = hw_address;
    emu->atca_sites[hw_address].site_type = site_type;
    emu->atca_sites[hw_address].site_number = site_number;
    return 0;
}

void
handle_picmg_msg(lmc_data_t    *mc,
		 msg_t         *msg,
		 unsigned char *rdata,
		 unsigned int  *rdata_len)
{
    switch(msg->cmd) {
    case IPMI_PICMG_CMD_GET_PROPERTIES:
	handle_picmg_get_properties(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_GET_ADDRESS_INFO:
	handle_picmg_get_address_info(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_FRU_CONTROL:
	handle_picmg_cmd_fru_control(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_GET_FRU_LED_PROPERTIES:
	handle_picmg_cmd_get_fru_led_properties(mc, msg, rdata, rdata_len,
						NULL);
	break;

    case IPMI_PICMG_CMD_GET_LED_COLOR_CAPABILITIES:
	handle_picmg_cmd_get_led_color_capabilities(mc, msg, rdata, rdata_len,
						    NULL);
	break;

    case IPMI_PICMG_CMD_SET_FRU_LED_STATE:
	handle_picmg_cmd_set_fru_led_state(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_GET_FRU_LED_STATE:
	handle_picmg_cmd_get_fru_led_state(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_GET_SHELF_ADDRESS_INFO:
	handle_picmg_cmd_get_shelf_address_info(mc, msg, rdata, rdata_len,
						NULL);
	break;

    case IPMI_PICMG_CMD_SET_SHELF_ADDRESS_INFO:
	handle_picmg_cmd_set_shelf_address_info(mc, msg, rdata, rdata_len,
						NULL);
	break;

    case IPMI_PICMG_CMD_SET_IPMB_STATE:
	handle_picmg_cmd_set_ipmb_state(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_SET_FRU_ACTIVATION_POLICY:
	handle_picmg_cmd_set_fru_activation_policy(mc, msg, rdata, rdata_len,
						   NULL);
	break;

    case IPMI_PICMG_CMD_GET_FRU_ACTIVATION_POLICY:
	handle_picmg_cmd_get_fru_activation_policy(mc, msg, rdata, rdata_len,
						   NULL);
	break;

    case IPMI_PICMG_CMD_SET_FRU_ACTIVATION:
	handle_picmg_cmd_set_fru_activation(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_GET_DEVICE_LOCATOR_RECORD:
	handle_picmg_cmd_get_device_locator_record(mc, msg, rdata, rdata_len,
						   NULL);
	break;

    case IPMI_PICMG_CMD_SET_PORT_STATE:
	handle_picmg_cmd_set_port_state(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_GET_PORT_STATE:
	handle_picmg_cmd_get_port_state(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_COMPUTE_POWER_PROPERTIES:
	handle_picmg_cmd_compute_power_properties(mc, msg, rdata, rdata_len,
						  NULL);
	break;

    case IPMI_PICMG_CMD_SET_POWER_LEVEL:
	handle_picmg_cmd_set_power_level(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_GET_POWER_LEVEL:
	handle_picmg_cmd_get_power_level(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_RENEGOTIATE_POWER:
	handle_picmg_cmd_renegotiate_power(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_GET_FAN_SPEED_PROPERTIES:
	handle_picmg_cmd_get_fan_speed_properties(mc, msg, rdata, rdata_len,
						  NULL);
	break;

    case IPMI_PICMG_CMD_SET_FAN_LEVEL:
	handle_picmg_cmd_set_fan_level(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_GET_FAN_LEVEL:
	handle_picmg_cmd_get_fan_level(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_BUSED_RESOURCE:
	handle_picmg_cmd_bused_resource(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_IPMB_LINK_INFO:
	handle_picmg_cmd_ipmb_link_info(mc, msg, rdata, rdata_len, NULL);
	break;
      
    case IPMI_PICMG_CMD_SHELF_POWER_ALLOCATION:
	handle_picmg_cmd_shelf_power_allocation(mc, msg, rdata, rdata_len,
						NULL);
	break;

    case IPMI_PICMG_CMD_SHELF_MANAGER_IPMB_ADDRESS:
	handle_picmg_cmd_shelf_manager_ipmb_address(mc, msg, rdata, rdata_len,
						    NULL);
	break;

    case IPMI_PICMG_CMD_SET_FAN_POLICY:
	handle_picmg_cmd_set_fan_policy(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_GET_FAN_POLICY:
	handle_picmg_cmd_get_fan_policy(mc, msg, rdata, rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_FRU_CONTROL_CAPABILITIES:
	handle_picmg_cmd_fru_control_capabilities(mc, msg, rdata, rdata_len,
						  NULL);
	break;

    case IPMI_PICMG_CMD_FRU_INVENTORY_DEVICE_LOCK_CONTROL:
	handle_picmg_cmd_fru_inventory_device_lock_control(mc, msg, rdata,
							   rdata_len, NULL);
	break;

    case IPMI_PICMG_CMD_FRU_INVENTORY_DEVICE_WRITE:
	handle_picmg_cmd_fru_inventory_device_write(mc, msg, rdata, rdata_len,
						    NULL);
	break;

    case IPMI_PICMG_CMD_GET_SHELF_MANAGER_IP_ADDRESSES:
	handle_picmg_cmd_get_shelf_manager_ip_addresses(mc, msg, rdata,
							rdata_len, NULL);
	break;

    default:
	handle_invalid_cmd(mc, rdata, rdata_len);
	break;
    }
}
