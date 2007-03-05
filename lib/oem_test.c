/*
 * sensor.c
 *
 * MontaVista IPMI code for handling sensors
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2004 MontaVista Software Inc.
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
#include <errno.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_err.h>

#include <OpenIPMI/internal/ipmi_event.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_mc.h>
#include <OpenIPMI/internal/ipmi_oem.h>
#include <OpenIPMI/internal/ipmi_sensor.h>
#include <OpenIPMI/internal/ipmi_control.h>
#include <OpenIPMI/internal/ipmi_int.h>

/* We use a block of MontaVista's private enterprise IDs for our own
   purposes. */
#define MONTAVISTA_MFG_ID	4753
#define MONTAVISTA_TEST_START	0xf00
#define MONTAVISTA_TEST_END	0xfff

/* Control numbers. */
#define POWER_CONTROL(ipmb)	((ipmb) >> 1)
#define HS_LED_CONTROL(ipmb)	(((ipmb) >> 1) | 0x80)

static int
dummy_entity_sdr_add(ipmi_entity_t   *ent,
		     ipmi_sdr_info_t *sdrs,
		     void            *cb_data)
{
    /* Don't put the entities into an SDR */
    return 0;
}

/***********************************************************************
 *
 * Sensor handling.
 *
 **********************************************************************/

static int
test_sensor_handler_0(ipmi_mc_t     *mc,
		      ipmi_entity_t *ent,
		      ipmi_sensor_t *sensor,
		      void          *link,
		      void          *cb_data)
{
    int lun, num;
    int rv;

    rv = ipmi_sensor_get_num(sensor, &lun, &num);
    if (rv)
	return rv;

    /* This is the slot sensor.  Set the hot-swap requester bit. */
    if ((lun == 0) && (num == 1)) {
	ipmi_sensor_set_hot_swap_requester(sensor, 6, 1);
    }
    return 0;
}

/***********************************************************************
 *
 * Event handling.
 *
 **********************************************************************/

typedef struct event_info_s
{
    int          err;
    ipmi_event_t *event;
    int          valid_vals[1];
    int          vals[1];
    int          handled;
} event_info_t;

void
event_control_cb(ipmi_control_t *control, void *cb_data)
{
    event_info_t *info = cb_data;

    ipmi_control_call_val_event_handlers(control,
					 info->valid_vals,
					 info->vals,
					 &info->event,
					 &info->handled);
    if (info->handled == IPMI_EVENT_NOT_HANDLED)
	info->err = EINVAL;
}

static int
test_event_handler_0(ipmi_mc_t    *mc,
		     ipmi_event_t *event,
		     void         *cb_data)
{
    unsigned char    data[13];
    ipmi_domain_t    *domain = ipmi_mc_get_domain(mc);
    ipmi_mc_t        *src_mc;
    ipmi_ipmb_addr_t addr;

    if (ipmi_event_get_type(event) == 0xc0) {
	ipmi_control_id_t id;
	event_info_t      info;
	int               rv;
	ipmi_time_t       timestamp;

	if (ipmi_event_get_data(event, data, 0, 13) != 13)
	    return 0;

	timestamp = ipmi_get_uint32(&data[0]);

	if (timestamp < ipmi_mc_get_startup_SEL_time(mc))
	    /* It's an old event, ignore it. */
	    return 0;

	if (data[6] != 1)
	    /* Wrong version */
	    return 0;

	addr.addr_type = IPMI_IPMB_ADDR_TYPE;
	addr.channel = 0;
	addr.lun = 0;
	addr.slave_addr = data[4];

	/* Find the MC. */
	src_mc = _ipmi_find_mc_by_addr(domain,
				       (ipmi_addr_t *) &addr,
				       sizeof(addr));
	if (!src_mc)
	    return 0;

	id.mcid = ipmi_mc_convert_to_id(src_mc);
	id.lun = 4;
	id.control_num = POWER_CONTROL(data[8]);

	info.err = 0;
	info.event = event;
	info.valid_vals[0] = 1;
	info.vals[0] = data[10];
	info.handled = IPMI_EVENT_NOT_HANDLED;

	rv = ipmi_control_pointer_cb(id, event_control_cb, &info);
	if (!rv)
	    rv = info.err;

	_ipmi_mc_put(src_mc);

	if (!rv)
	    return 1;
    }

    return 0;
}

/***********************************************************************
 *
 * The hot-swap led control.
 *
 **********************************************************************/

typedef struct hs_led_set_info_s
{
    ipmi_control_op_cb     handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
    int                    vals[1];
} hs_led_set_info_t;

static void
hs_led_set_cb(ipmi_control_t *control,
	      int            err,
	      ipmi_msg_t     *rsp,
	      void           *cb_data)
{
    hs_led_set_info_t *control_info = cb_data;

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_test.c(hs_led_set_cb): Received IPMI error: %x",
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
hs_led_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    hs_led_set_info_t *control_info = cb_data;
    ipmi_msg_t       msg;
    unsigned char    data[1];
    ipmi_mc_t	     *mc = ipmi_control_get_mc(control);
    int              rv;

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = 0x30; /* OEM NETFN */
    msg.cmd = 0x03; /* Set hs_led */
    msg.data_len = 1;
    msg.data = data;
    data[0] = control_info->vals[0];

    rv = ipmi_control_send_command(control, mc, 0,
				   &msg, hs_led_set_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->handler)
	    control_info->handler(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
hs_led_set(ipmi_control_t     *control,
	   int                *val,
	   ipmi_control_op_cb handler,
	   void               *cb_data)
{
    hs_led_set_info_t  *control_info;
    int                rv;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return ENOMEM;
    control_info->handler = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = val[0];
    rv = ipmi_control_add_opq(control, hs_led_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

typedef struct hs_led_get_info_s
{
    ipmi_control_val_cb    handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
} hs_led_get_info_t;

static void
hs_led_get_cb(ipmi_control_t *control,
	     int            err,
	     ipmi_msg_t     *rsp,
	     void           *cb_data)
{
    hs_led_get_info_t *control_info = cb_data;
    int              val[1];

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_test.c(hs_led_get_cb): Received IPMI error: %x",
		 CONTROL_NAME(control), rsp->data[0]);
	if (control_info->handler)
	    control_info->handler(control,
				  IPMI_IPMI_ERR_VAL(rsp->data[0]),
				  NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_test.c(hs_led_get_cb): response too short: %d",
		 CONTROL_NAME(control), rsp->data_len);
	if (control_info->handler)
	    control_info->handler(control, EINVAL,
				  NULL, control_info->cb_data);
	goto out;
    }

    val[0] = rsp->data[1];
    if (control_info->handler)
	control_info->handler(control, 0,
			      val, control_info->cb_data);

 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
hs_led_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    hs_led_get_info_t *control_info = cb_data;
    int              rv;
    ipmi_msg_t       msg;
    ipmi_mc_t	     *mc = ipmi_control_get_mc(control);

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = 0x30; /* OEM netfn */
    msg.cmd = 0x04; /* Get hs_led */
    msg.data_len = 0;
    msg.data = NULL;
    rv = ipmi_control_send_command(control, mc, 0,
				   &msg, hs_led_get_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->handler)
	    control_info->handler(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
hs_led_get(ipmi_control_t      *control,
	   ipmi_control_val_cb handler,
	   void                *cb_data)
{
    hs_led_get_info_t *control_info;
    int               rv;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return ENOMEM;
    memset(control_info, 0, sizeof(*control_info));
    control_info->handler = handler;
    control_info->cb_data = cb_data;
    rv = ipmi_control_add_opq(control, hs_led_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

/***********************************************************************
 *
 * The test power control.
 *
 **********************************************************************/

typedef struct power_set_info_s
{
    ipmi_control_op_cb     handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
    int                    vals[1];
} power_set_info_t;

static void
power_set_cb(ipmi_control_t *control,
		     int            err,
		     ipmi_msg_t     *rsp,
		     void           *cb_data)
{
    power_set_info_t *control_info = cb_data;

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_test.c(power_set_cb): Received IPMI error: %x",
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
power_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    power_set_info_t *control_info = cb_data;
    ipmi_msg_t       msg;
    unsigned char    data[1];
    ipmi_mc_t	     *mc = ipmi_control_get_mc(control);
    int              rv;

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = 0x30; /* OEM NETFN */
    msg.cmd = 0x01; /* Set power */
    msg.data_len = 1;
    msg.data = data;
    if (control_info->vals[0])
	data[0] = 1;
    else
	data[0] = 0;

    rv = ipmi_control_send_command(control, mc, 0,
				   &msg, power_set_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->handler)
	    control_info->handler(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
power_set(ipmi_control_t     *control,
	  int                *val,
	  ipmi_control_op_cb handler,
	  void               *cb_data)
{
    power_set_info_t  *control_info;
    int                rv;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return ENOMEM;
    control_info->handler = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = val[0];
    rv = ipmi_control_add_opq(control, power_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

typedef struct power_get_info_s
{
    ipmi_control_val_cb    handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
} power_get_info_t;

static void
power_get_cb(ipmi_control_t *control,
	     int            err,
	     ipmi_msg_t     *rsp,
	     void           *cb_data)
{
    power_get_info_t *control_info = cb_data;
    int              val[1];

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_test.c(power_get_cb): Received IPMI error: %x",
		 CONTROL_NAME(control), rsp->data[0]);
	if (control_info->handler)
	    control_info->handler(control,
				  IPMI_IPMI_ERR_VAL(rsp->data[0]),
				  NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_test.c(power_get_cb): response too short: %d",
		 CONTROL_NAME(control), rsp->data_len);
	if (control_info->handler)
	    control_info->handler(control, EINVAL,
				  NULL, control_info->cb_data);
	goto out;
    }

    val[0] = rsp->data[1] != 0;
    if (control_info->handler)
	control_info->handler(control, 0,
			      val, control_info->cb_data);

 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
power_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    power_get_info_t *control_info = cb_data;
    int              rv;
    ipmi_msg_t       msg;
    ipmi_mc_t	     *mc = ipmi_control_get_mc(control);

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = 0x30; /* OEM netfn */
    msg.cmd = 0x02; /* Get power */
    msg.data_len = 0;
    msg.data = NULL;
    rv = ipmi_control_send_command(control, mc, 0,
				   &msg, power_get_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->handler)
	    control_info->handler(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
power_get(ipmi_control_t      *control,
	  ipmi_control_val_cb handler,
	  void                *cb_data)
{
    power_get_info_t *control_info;
    int              rv;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return ENOMEM;
    memset(control_info, 0, sizeof(*control_info));
    control_info->handler = handler;
    control_info->cb_data = cb_data;
    rv = ipmi_control_add_opq(control, power_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

/***********************************************************************
 *
 * The main setup for the test MC 0.
 *
 **********************************************************************/

static void
mc_control_removal_handler(ipmi_domain_t *domain,
			   ipmi_mc_t     *mc,
			   void          *cb_data)
{
    ipmi_control_t *control = cb_data;

    ipmi_control_destroy(control);
}

static ipmi_control_transition_t off_led[] = { {IPMI_CONTROL_COLOR_BLACK, 1 } };
static ipmi_control_transition_t on_blue_led[] = { { IPMI_CONTROL_COLOR_BLUE, 1 } };
static ipmi_control_transition_t blue_led1[] =
{
    { IPMI_CONTROL_COLOR_BLUE, 100 },
    { IPMI_CONTROL_COLOR_BLACK, 900 },
};
static ipmi_control_transition_t blue_led2[] =
{
    { IPMI_CONTROL_COLOR_BLUE, 900 },
    { IPMI_CONTROL_COLOR_BLACK, 100 },
};


static ipmi_control_value_t hs_led_values[] =
{
    { 2, blue_led1 },
    { 1, off_led },
    { 2, blue_led2 },
    { 1, on_blue_led },
};
static ipmi_control_light_t hs_led[] = {{ 4, hs_led_values }};

static int
test_handler_0(ipmi_mc_t *mc,
	       void      *cb_data)
{
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    ipmi_entity_info_t *ents = ipmi_domain_get_entities(domain);
    ipmi_entity_t      *ent = NULL;
    ipmi_control_t     *control;
    int                rv = 0;
    ipmi_control_cbs_t cbs;

    if (ipmi_mc_get_channel(mc) == IPMI_BMC_CHANNEL) 
	/* Ignore the connection MCs. */
	return 0;

    rv = ipmi_mc_set_oem_new_sensor_handler(mc, test_sensor_handler_0, NULL);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_test.c(test_handler_0): "
		 "Could not set OEM sensor handler: %x",
		 MC_NAME(mc), rv);
	goto out;
    }

    rv = ipmi_mc_set_sel_oem_event_handler(mc, test_event_handler_0, NULL);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_test.c(test_handler_0): "
		 "Could not set OEM event handler: %x",
		 MC_NAME(mc), rv);
	goto out;
    }

    /* Power control for the entity for MC 0x40 (18.2) */
    rv = ipmi_entity_add(ents, domain, 0, 0, 0,
			 IPMI_ENTITY_ID_PROCESSOR_BOARD, 0x20,
			 NULL, IPMI_ASCII_STR, 0,
			 dummy_entity_sdr_add,
			 NULL, &ent);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_test.c(test_handler_0): "
		 "Could not add the MC entity: %x",
		 MC_NAME(mc), rv);
	goto out;
    }
    
    /* Allocate the power control. */
    rv = ipmi_control_alloc_nonstandard(&control);
    if (rv) {
	goto out;
    }

    ipmi_control_set_type(control, IPMI_CONTROL_POWER);
    ipmi_control_set_ignore_for_presence(control, 1);
    ipmi_control_set_id(control, "power", IPMI_ASCII_STR, 5);
    ipmi_control_set_hot_swap_power(control, 1);

    ipmi_control_set_settable(control, 1);
    ipmi_control_set_readable(control, 1);

    /* Create all the callbacks in the data structure. */
    memset(&cbs, 0, sizeof(cbs));
    cbs.set_val = power_set;
    cbs.get_val = power_get;

    ipmi_control_set_callbacks(control, &cbs);
    ipmi_control_set_num_elements(control, 1);

    /* Add it to the MC and entity.  We presume this comes from the
       "main" SDR, so set the source_mc to NULL. */
    rv = ipmi_control_add_nonstandard(mc, NULL, control,
				      POWER_CONTROL(0x40),
				      ent, NULL, NULL);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_test.c(test_handler_0): "
		 "Could not add the power control: %x",
		 MC_NAME(mc), rv);
	ipmi_control_destroy(control);
	goto out;
    }

    rv = ipmi_mc_add_oem_removed_handler(mc,
					 mc_control_removal_handler,
					 control);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_test.c(test_handler_0): "
		 "Could not add the power control removal handler: %x",
		 MC_NAME(mc), rv);
	ipmi_control_destroy(control);
	goto out;
    }

    /* Allocate the LED control. */
    rv = ipmi_control_alloc_nonstandard(&control);
    if (rv) {
	goto out;
    }

    ipmi_control_set_type(control, IPMI_CONTROL_LIGHT);
    ipmi_control_set_ignore_for_presence(control, 1);
    ipmi_control_set_id(control, "Hotswap LED", IPMI_ASCII_STR, 11);
    ipmi_control_light_set_lights(control, 1, hs_led);
    ipmi_control_set_hot_swap_indicator(control, 1, 0, 1, 2, 3);

    ipmi_control_set_settable(control, 1);
    ipmi_control_set_readable(control, 1);

    /* Create all the callbacks in the data structure. */
    memset(&cbs, 0, sizeof(cbs));
    cbs.set_val = hs_led_set;
    cbs.get_val = hs_led_get;

    ipmi_control_set_callbacks(control, &cbs);
    ipmi_control_set_num_elements(control, 1);

    /* Add it to the MC and entity.  We presume this comes from the
       "main" SDR, so set the source_mc to NULL. */
    rv = ipmi_control_add_nonstandard(mc, NULL, control,
				      HS_LED_CONTROL(0x40),
				      ent, NULL, NULL);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_test.c(test_handler_0): "
		 "Could not add the power control: %x",
		 MC_NAME(mc), rv);
	ipmi_control_destroy(control);
	_ipmi_control_put(control);
	goto out;
    }

    rv = ipmi_mc_add_oem_removed_handler(mc,
					 mc_control_removal_handler,
					 control);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_test.c(test_handler_0): "
		 "Could not add the power control removal handler: %x",
		 MC_NAME(mc), rv);
	ipmi_control_destroy(control);
	_ipmi_control_put(control);
	goto out;
    }

    _ipmi_control_put(control);

 out:
    if (ent)
	_ipmi_entity_put(ent);
    return rv;
}

/***********************************************************************
 *
 * Setup.
 *
 **********************************************************************/

int
init_oem_test(void)
{
    int rv;

    rv = ipmi_register_oem_handler(MONTAVISTA_MFG_ID,
				   MONTAVISTA_TEST_START+0,
				   test_handler_0,
				   NULL,
				   NULL);
    if (rv)
	return rv;
    return 0;
}
