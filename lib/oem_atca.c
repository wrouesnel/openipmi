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

/* PICMG Commands */
#define PICMG_NETFN				0x2c
#define PICMG_ID				0x00
#define PICMG_CMD_GET_ADDRESS_INFO		0x01
#define PICMG_CMD_GET_SHELF_ADDRESS_INFO	0x02
#define PICMG_CMD_SET_SHELF_ADDRESS_INFO	0x03
#define PICMG_CMD_FRU_CONTROL			0x04
#define PICMG_CMD_GET_FRU_LED_PROPERTIES	0x05
#define PICMG_CMD_GET_LED_COLOR_CAPABILITIES	0x06
#define PICMG_CMD_SET_FRU_LED_STATE		0x07
#define PICMG_CMD_GET_FRU_LED_STATE		0x08
#define PICMG_CMD_SET_IPMB_STATE		0x09
#define PICMG_CMD_SET_FRU_ACTIVATION_POLICY	0x0a
#define PICMG_CMD_GET_FRU_ACTIVATION_POLICY	0x0b
#define PICMG_CMD_SET_FRU_ACTIVATION		0x0c
#define PICMG_CMD_GET_DEVICE_LOCATOR_RECORD	0x0d
#define PICMG_CMD_SET_PORT_STATE		0x0e
#define PICMG_CMD_GET_PORT_STATE		0x0f
#define PICMG_CMD_COMPUTE_POWER_PROPERTIES	0x10
#define PICMG_CMD_SET_POWER_LEVEL		0x11
#define PICMG_CMD_GET_POWER_LEVEL		0x12
#define PICMG_CMD_RENEGOTIATE_POWER		0x13
#define PICMG_CMD_GET_FAN_SPEED_PROPERTIES	0x14
#define PICMG_CMD_SET_FAN_LEVEL			0x15
#define PICMG_CMD_GET_FAN_LEVEL			0x16
#define PICMG_CMD_BUSED_RESOURCE		0x17


typedef struct atca_info_s atca_info_t;

typedef struct atca_address_s
{
    unsigned char hw_address;
    unsigned char site_num;
    unsigned char site_type;
} atca_address_t;

typedef struct atca_board_s
{
    atca_info_t   *shelf;
    int           idx; /* My index in the shelf's boards. */
    unsigned char site_num;
    unsigned char ipmb_address;
    ipmi_entity_t *entity;
} atca_board_t;

struct atca_info_s
{
    ipmi_domain_t *domain;
    unsigned char shelf_fru_ipmb;
    unsigned char shelf_fru_device_id;
    ipmi_fru_t    *shelf_fru;

    unsigned char        shelf_address[40];
    enum ipmi_str_type_e shelf_address_type;
    unsigned int         shelf_address_len;

    ipmi_entity_t *shelf_entity;

    unsigned int   num_addresses;
    atca_address_t *addresses;

    unsigned int   num_boards;
    atca_board_t   *boards;
};

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

static int
atca_entity_sdr_add(ipmi_entity_t   *ent,
		    ipmi_sdr_info_t *sdrs,
		    void            *cb_data)
{
    /* Don't put the entities into an SDR */
    return 0;
}

typedef struct atca_board_info_s atca_board_info_t;

typedef struct atca_led_s
{
    unsigned int      num;
    unsigned int      colors; /* A bitmask, in OpenIPMI numbers. */
    atca_board_info_t *sinfo;
    ipmi_control_t    *control;
} atca_led_t;

struct atca_board_info_s
{
    unsigned int  num_leds;
    atca_led_t    *leds;
    ipmi_entity_t *entity;
};

/* Information common to all controls. */
typedef struct atca_control_header_s
{
    /* Depending on the control, this will hold:
       Power Supply - A pointer to mxp_power_supply_t
       Fan - A pointer to mxp_fan_t
       Boards, switches, and AMC led controls  - A pointer
       to the mxp_board_t structure for the board.
       Board/switch/AMC blue light controls - not used (NULL)
       Board/switch power/reset controls - not used (NULL)
       Other AMC controls - A pointer to amc_info_t for the AMC.
       Chassis controls - A pointer to mxp_info_t for the chassis.
    */
    void         *data;
} atca_control_header_t;

static void
atca_cleanup_control_oem_info(ipmi_control_t *control, void *oem_info)
{
    atca_control_header_t *hdr = oem_info;

    if (hdr) {
	ipmi_mem_free(hdr);
    }
}

static int
atca_alloc_control(ipmi_mc_t                 *mc,
		   void                      *data,
		   unsigned int              control_type,
		   char                      *id,
		   ipmi_control_set_val_cb   set_val,
		   ipmi_control_get_val_cb   get_val,
		   ipmi_control_set_light_cb set_light_val,
		   ipmi_control_get_light_cb get_light_val,
		   ipmi_control_t            **control)
{
    int                   rv;
    ipmi_control_cbs_t    cbs;
    atca_control_header_t *hdr;

    hdr = ipmi_mem_alloc(sizeof(*hdr));
    if (!hdr)
	return ENOMEM;

    hdr->data = data;

    /* Allocate the control. */
    rv = ipmi_control_alloc_nonstandard(control);
    if (rv) {
	ipmi_mem_free(hdr);
	return rv;
    }

    /* Fill out default values. */
    ipmi_control_set_oem_info(*control, hdr, atca_cleanup_control_oem_info);
    ipmi_control_set_type(*control, control_type);
    ipmi_control_set_id(*control, id, IPMI_ASCII_STR, strlen(id));
    ipmi_control_set_ignore_if_no_entity(*control, 1);

    /* Assume we can read and set the value. */
    if ((set_val) || (set_light_val))
	ipmi_control_set_settable(*control, 1);
    if ((get_val) || (get_light_val))
	ipmi_control_set_readable(*control, 1);

    /* Create all the callbacks in the data structure. */
    memset(&cbs, 0, sizeof(cbs));
    cbs.set_val = set_val;
    cbs.get_val = get_val;
    cbs.set_light = set_light_val;
    cbs.get_light = get_light_val;

    ipmi_control_set_callbacks(*control, &cbs);

    return 0;
}

static int
atca_add_control(ipmi_mc_t      *mc,
		 ipmi_control_t **control,
		 unsigned int   num, 
		 ipmi_entity_t  *entity)
{
    int rv;

    rv = ipmi_control_add_nonstandard(mc, mc, *control, num, entity,
				      NULL, NULL);
    if (rv) {
	ipmi_control_destroy(*control);
	*control = NULL;
    }
    return rv;
}


void
atca_board_removal_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    atca_board_info_t *sinfo = cb_data;
    int               i;

    if (sinfo->leds) {
	for (i=0; i<sinfo->num_leds; i++) {
	    if (sinfo->leds[i].control)
		ipmi_control_destroy(sinfo->leds[i].control);
	}
	ipmi_mem_free(sinfo->leds);
    }
}

static int
check_for_msg_err(ipmi_mc_t *mc, int rv, ipmi_msg_t *msg,
		  int expected_length,
		  char *func_name)
{
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_atca.c(%s): "
		 "Error from message", func_name);
	return 1;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_atca.c(%s): "
		 "MC went away", func_name);
	return 1;
    }

    if (msg->data[0] != 0) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(%s): "
		 "IPMI error: 0x%x",
		 MC_NAME(mc), func_name, msg->data[0]);
	return 1;
    }

    if (msg->data_len < expected_length) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(%s): "
		 "response not big enough, expected %d, got %d bytes",
		 MC_NAME(mc), func_name, expected_length, msg->data_len);
	return 1;
    }

    if (msg->data[1] != 0) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(%s): "
		 "Command ID not PICMG, it was 0x%x",
		 MC_NAME(mc), func_name, msg->data[1]);
	return 1;
    }

    return 0;
}

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

    if (check_for_msg_err(mc, err, rsp, 6, "led_get_done")) {
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
    int                 color, on_time, off_time;
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
    if (color > IPMI_CONTROL_COLOR_BLACK) {
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
    info->msg.netfn = PICMG_NETFN;
    info->msg.cmd = PICMG_CMD_SET_FRU_LED_STATE;
    info->msg.data = info->data;
    info->msg.data_len = 6;

    info->data[0] = PICMG_ID;
    info->data[1] = 0;
    info->data[2] = l->num;
    if (on_time <= 0) {
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

    if (check_for_msg_err(mc, err, rsp, 6, "led_get_done")) {
	if (info->get_handler)
	    info->get_handler(control, err, info->settings, info->cb_data);
	goto out;
    }

    if ((rsp->data[3] >= 0xfb) && (rsp->data[3] <= 0xfe)) {
	/* Reserved on time field */
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(led_get_done): "
		 "Invalid on time value: 0x%x",
		 MC_NAME(mc), rsp->data[3]);
	if (info->get_handler)
	    info->get_handler(control, EINVAL, info->settings, info->cb_data);
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
	    info->get_handler(control, EINVAL, info->settings, info->cb_data);
	goto out;
    }

    ipmi_light_setting_set_color(info->settings,
				 0,
				 atca_to_openipmi_color[color]);
    if (rsp->data[3] == 0) {
	ipmi_light_setting_set_on_time(info->settings, 0, 0);
	ipmi_light_setting_set_off_time(info->settings, 0,1);
    } else if (rsp->data[3] == 0xff) {
	ipmi_light_setting_set_on_time(info->settings, 0, 1);
	ipmi_light_setting_set_off_time(info->settings, 0, 0);
    } else {
	ipmi_light_setting_set_on_time(info->settings, 0, rsp->data[3] * 10);
	ipmi_light_setting_set_off_time(info->settings, 0, rsp->data[4] * 10);
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
    info->msg.netfn = PICMG_NETFN;
    info->msg.cmd = PICMG_CMD_GET_FRU_LED_STATE;
    info->msg.data = info->data;
    info->msg.data_len = 3;

    info->data[0] = PICMG_ID;
    info->data[1] = 0;
    info->data[2] = l->num;

    rv = ipmi_control_add_opq(control, led_get_start, &info->sdata, info);
    if (rv) {
	ipmi_free_light_settings(info->settings);
	ipmi_mem_free(info);
    }

    return rv;
}

static void
fru_led_cap_rsp(ipmi_mc_t  *mc,
		ipmi_msg_t *msg,
		void       *rsp_data)
{
    atca_led_t        *l = rsp_data;
    atca_board_info_t *sinfo = l->sinfo;
    unsigned int      num = l->num;
    char              name[10];
    int               rv;
    int               i;

    if (check_for_msg_err(mc, 0, msg, 5, "fru_led_cap_rsp"))
	return;

    if (num == 0)
	sprintf(name, "blue led");
    else
	sprintf(name, "led %d", num);
    rv = atca_alloc_control(mc, l,
			    IPMI_CONTROL_LIGHT,
			    name,
			    NULL,
			    NULL,
			    set_led,
			    get_led,
			    &l->control);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fru_led_cap_rsp): "
		 "Could not create LED control: 0x%x",
		 MC_NAME(mc), rv);
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
    rv = atca_add_control(mc, 
			  &l->control,
			  num,
			  sinfo->entity);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fru_led_cap_rsp): "
		 "Could not add LED control: 0x%x",
		 MC_NAME(mc), rv);
	return;
    }
}

static void
get_led_capability(ipmi_mc_t *mc, atca_board_info_t *sinfo, unsigned int num)
{
    ipmi_msg_t    msg;
    unsigned char data[3];
    int           rv;

    sinfo->leds[num].num = num;
    sinfo->leds[num].sinfo = sinfo;

    msg.netfn = PICMG_NETFN;
    msg.cmd = PICMG_CMD_GET_LED_COLOR_CAPABILITIES;
    msg.data = data;
    msg.data_len = 3;
    data[0] = PICMG_ID;
    data[1] = 0;
    data[2] = num;
    rv = ipmi_mc_send_command(mc, 0, &msg, fru_led_cap_rsp, &sinfo->leds[num]);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(get_led_capabilities): "
		 "Could not send FRU LED color capablity command: 0x%x",
		 MC_NAME(mc), rv);
	/* Just go on, don't shut down the info. */
    }
}

static void
fru_led_prop_rsp(ipmi_mc_t  *mc,
		 ipmi_msg_t *msg,
		 void       *rsp_data)
{
    atca_board_info_t *sinfo = rsp_data;
    int               i, j;
    unsigned int      num_leds;

    if (check_for_msg_err(mc, 0, msg, 4, "fru_led_prop_rsp"))
	return;

    num_leds = 4 * msg->data[3];
    sinfo->leds = ipmi_mem_alloc(sizeof(atca_led_t) * num_leds);
    if (!sinfo->leds) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(fru_led_prop_rsp): "
		 "Could not allocate memory LEDs",
		 MC_NAME(mc));
	return;
    }
    memset(sinfo->leds, 0, sizeof(atca_led_t) * num_leds);
    sinfo->num_leds = num_leds;

    for (i=0; i<4; i++) {
	if (msg->data[2] & (1 << i)) {
	    /* We support this LED.  Fetch its capabilities */
	    get_led_capability(mc, sinfo, i);
	}
    }

    for (j=0; j<msg->data[3]; j++, i++) {
	if (i >= 128)
	    /* We only support 128 LEDs. */
	    break;
	/* We support this LED, Fetch it's capabilities. */
	get_led_capability(mc, sinfo, i);
    }
}

static void
atca_handle_new_mc(ipmi_domain_t *domain, ipmi_mc_t *mc, atca_info_t *info)
{
    int                addr = ipmi_mc_get_address(mc);
    int                channel = ipmi_mc_get_channel(mc);
    ipmi_entity_info_t *ents;
    atca_board_info_t  *sinfo = NULL;
    int                rv;
    char               *name;
    ipmi_msg_t         msg;
    unsigned char      data[2];

    sinfo = ipmi_mem_alloc(sizeof(*sinfo));
    if (!sinfo) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_handle_new_mc): "
		 "Could not allocate board sensor info",
		 MC_NAME(mc));
	return;
    }
    memset(sinfo, 0, sizeof(*sinfo));

    ents = ipmi_domain_get_entities(domain);
    name = "ATCA Board";
    rv = ipmi_entity_add(ents, domain, channel, addr, 0,
			 IPMI_ENTITY_ID_PROCESSING_BLADE,
			 0x60, /* Always device relative. */
			 name, IPMI_ASCII_STR, strlen(name),
			 atca_entity_sdr_add,
			 NULL, &sinfo->entity);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_handle_new_mc): "
		 "Could not create entity: 0x%x",
		 MC_NAME(mc), rv);
	goto out_err;
    }

    rv = ipmi_mc_add_oem_removed_handler(mc, atca_board_removal_handler,
					 sinfo, NULL);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_handle_new_mc): "
		 "Could not add OEM removal handler: 0x%x",
		 MC_NAME(mc), rv);
	goto out_err;
    }

    /* Now fetch the LED information. */
    msg.netfn = PICMG_NETFN;
    msg.cmd = PICMG_CMD_GET_FRU_LED_PROPERTIES;
    msg.data = data;
    msg.data_len = 2;
    data[0] = PICMG_ID;
    data[1] = 0;
    rv = ipmi_mc_send_command(mc, 0, &msg, fru_led_prop_rsp, sinfo);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(atca_handle_new_mc): "
		 "Could not send FRU LED properties command: 0x%x",
		 MC_NAME(mc), rv);
	/* Just go on, don't shut down the info. */
    }

    return;

 out_err:
    if (sinfo)
	ipmi_mem_free(sinfo);
}

static void
atca_mc_update_handler(enum ipmi_update_e op,
		       ipmi_domain_t      *domain,
		       ipmi_mc_t          *mc,
		       void               *cb_data)
{
    switch (op) {
    case IPMI_ADDED:
	atca_handle_new_mc(domain, mc, cb_data);
	break;

    default:
	break;
    }
}

static void
shelf_fru_fetched(ipmi_fru_t *fru, int err, void *cb_data)
{
    atca_info_t        *info = cb_data;
    ipmi_domain_t      *domain = info->domain;
    unsigned int       count;
    int                found;
    int                i, j;
    ipmi_entity_info_t *ents;
    char               *name;
    int                rv;

    if (err) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(shelf_fru_fetched): "
		 "Error getting FRU information: 0x%x",
		 DOMAIN_NAME(domain), err);
	goto out;
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
	    || (ipmi_fru_get_multi_record_type(fru, i, &ver) != 0)
	    || (ipmi_fru_get_multi_record_data_len(fru, i, &len) != 0))
	    continue;

	if ((type != 0xc0) || (ver != 2) || (len < 27))
	    continue;

	data = ipmi_mem_alloc(len);
	if (ipmi_fru_get_multi_record_data(fru, i, data, &len) != 0) {
	    ipmi_mem_free(data);
	    continue;
	}

	mfg_id = data[0] | (data[1] << 8) | (data[2] << 16);
	if (mfg_id != PICMG_MFG_ID)
	    continue;

	if (data[4] != 0x10) /* Address table record id */
	    continue;

	if (data[5] != 0) /* We only know version 0 */
	    continue;

	if (len < (27 + (3 * data[26])))
	    /* length does not meet the minimum possible length. */
	    continue;

	info->shelf_address_len
	    = ipmi_get_device_string(data+6, 21,
				     info->shelf_address, 0,
				     &info->shelf_address_type,
				     sizeof(info->shelf_address));

	info->addresses = ipmi_mem_alloc(sizeof(atca_address_t) * data[26]);
	if (!info->addresses) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%soem_atca.c(shelf_fru_fetched): "
		     "could not allocate memory for shelf addresses",
		     DOMAIN_NAME(domain));
	    goto out;
	}
	memset(info->addresses, 0, sizeof(atca_address_t) * data[26]);

	info->num_addresses = data[26];
	p = data+27;
	for (j=0; j<data[26]; j++, p += 3) {
	    info->addresses[j].hw_address = p[0];
	    info->addresses[j].site_num = p[1];
	    info->addresses[j].site_type = p[2];
	}

	ipmi_mem_free(data);
    }

    ents = ipmi_domain_get_entities(domain);

    /* Add a handler for when MCs are added to the domain, so we can
       add in our custom sensors. */
    rv = ipmi_domain_register_mc_update_handler(domain,
						atca_mc_update_handler,
						info,
						NULL);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%soem_atca.c(shelf_fru_fetched): "
		 "Could not add MC update handler: %x",
		 DOMAIN_NAME(domain), rv);
	goto out;
    }

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

    count = 0;
    for (i=0; i<info->num_addresses; i++) {
	/* Count the number of boards in the system. */
	if (info->addresses[i].site_type == PICMG_SITE_TYPE_PICMG_BOARD)
	    count++;
    }
    info->boards = ipmi_mem_alloc(sizeof(atca_board_t) * count);
    if (!info->boards) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(shelf_fru_fetched): "
		 "could not allocate memory for boards",
		 DOMAIN_NAME(domain));
	goto out;
    }
    memset(info->boards, 0, sizeof(atca_board_t) * count);

    info->num_boards = count;
    j = 0;
    for (i=0; i<info->num_boards; i++) {
	/* Process each board. */
	if (info->addresses[i].site_type == PICMG_SITE_TYPE_PICMG_BOARD) {
	    atca_board_t *b = &(info->boards[j]);

	    b->shelf = info;
	    b->idx = j;
	    b->ipmb_address = info->addresses[i].hw_address * 2;
	    b->site_num = info->addresses[i].site_num;
	    name = "ATCA Board";
	    rv = ipmi_entity_add(ents, domain, 0, b->ipmb_address, 0,
				 IPMI_ENTITY_ID_PROCESSING_BLADE,
				 0x60, /* Always device relative */
				 name, IPMI_ASCII_STR, strlen(name),
				 atca_entity_sdr_add,
				 NULL, &b->entity);
	    if (rv) {
		ipmi_log(IPMI_LOG_WARNING,
			 "%soem_atca.c(shelf_fru_fetched): "
			 " Could not add board entity: %x",
			 DOMAIN_NAME(domain), rv);
		goto out;
	    }
	    rv = ipmi_entity_add_child(info->shelf_entity, b->entity);
	    if (rv) {
		ipmi_log(IPMI_LOG_WARNING,
			 "%soem_atca.c(shelf_fru_fetched): "
			 "Could not add child board: %x",
			 DOMAIN_NAME(domain), rv);
		goto out;
	    }
	    j++;
	}
    }

 out:
    return;
}

static void
atca_oem_data_destroyer(ipmi_domain_t *domain, void *oem_data)
{
    atca_info_t *info = oem_data;
    int         i;

    if (info->boards) {
	for (i=0; i<info->num_boards; i++) {
	    atca_board_t *b = &(info->boards[i]);
	    if (info->shelf_entity && b->entity)
		ipmi_entity_remove_child(info->shelf_entity, b->entity);
	}
    }

    if (info->addresses)
	ipmi_mem_free(info->addresses);
    if (info->boards)
	ipmi_mem_free(info->boards);
    ipmi_mem_free(info);
}

static void
set_up_atca_domain(ipmi_domain_t *domain, ipmi_msg_t *get_addr)
{
    atca_info_t *info;
    int         rv;

    if (get_addr->data_len < 8) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(set_up_atca_domain): "
		 "ATCA get address response not long enough",
		 DOMAIN_NAME(domain));
	goto out;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(set_up_atca_domain): "
		 "Could not allocate ATCA information structure",
		 DOMAIN_NAME(domain));
	goto out;
    }
    memset(info, 0, sizeof(*info));

    info->domain = domain;
    info->shelf_fru_ipmb = get_addr->data[3];
    info->shelf_fru_device_id = get_addr->data[5];

    rv = ipmi_fru_alloc(domain,
			1,
			info->shelf_fru_ipmb,
			info->shelf_fru_device_id,
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
	ipmi_mem_free(info);
	goto out;
    }

    ipmi_domain_set_oem_data(domain, info, atca_oem_data_destroyer);

 out:
    return;
}

static void
check_if_atca_cb(ipmi_domain_t *domain,
		 ipmi_addr_t   *addr,
		 unsigned int  addr_len,
		 ipmi_msg_t    *msg,
		 void          *rsp_data1,
		 void          *rsp_data2)
{
    ipmi_domain_oem_check_done done = rsp_data1;

    if (!domain)
	return;

    if (msg->data[0] == 0) {
	/* It's an ATCA system, set it up */
	set_up_atca_domain(domain, msg);
    }
    done(domain, rsp_data2);
}

int
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
    msg.netfn = PICMG_NETFN;
    msg.cmd = PICMG_CMD_GET_ADDRESS_INFO;
    data[0] = PICMG_ID;
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
