/*
 * oem_motorola_mxp.c
 *
 * OEM code to make the Motorola MXP fit into OpenIPMI.
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
#include <errno.h>
#include <math.h>
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

/*
 * This code provides the OEM customization for the Motorola MXP and
 * related Motorola cards.
 *
 * The addressing of the MXP AMCs is rather unusual, but is the best
 * way I could think of to solve the problem.  Each AMC has its own
 * system interface IPMI address.  As well, the 0x20 address is
 * allowed to be detected and be the connection to whichever AMC is
 * active.  Generic chassis sensors are attached to the 0x20 MC,
 * and AMC-specific sensors are attached to each AMC.
 *
 * This has the unfortunate side effect that the AMCs and 0x20 MC have
 * no direct connection.  Their creation order cannot be controlled,
 * so one may exist before the other.
 *
 * That causes a problem because the SELs are attached to the AMCs
 * directly.  There is a hack to get the 0x20 MC (and thus the
 * mxp_info_t structure for the domain) for this scenario.
 */

/* These are the identifiers used in the get device id command to
   identify the various board types. */
#define MXP_MANUFACTURER_ID	0x0000a1
#define MXP_AMC_PRODUCT_ID	0x0004
#define ZYNX_SWITCH_PRODUCT_ID	0x0031
#define MXP_805_PRODUCT_ID	0x0001
#define MXP_5365_PRODUCT_ID	0x0003
#define MXP_5385_PRODUCT_ID	0x0002
#define MXP_PPRB_PRODUCT_ID	0x0006

#define ZYNX_MANUFACTURER_ID	0x0002b0
#define ZYNX_SWITCH_PRODUCT_ID2	0x3100

/* Various numbers and index offsets.  The indexes are used to index
   into the array of boards. */
#define MXP_POWER_SUPPLIES 3
#define MXP_BOARD_IDX_OFFSET 0
#define MXP_BOARDS 18
#define MXP_ALARM_CARD_IDX_OFFSET MXP_BOARDS
#define MXP_ALARM_CARDS 2
#define MXP_IP_SWITCH_IDX_OFFSET (MXP_BOARDS+MXP_ALARM_CARDS)
#define MXP_IP_SWITCHES 2
#define MXP_TOTAL_BOARDS (MXP_BOARDS + MXP_ALARM_CARDS + MXP_IP_SWITCHES)

/* The alarm card has a custom entity id. */
#define MXP_ENTITY_ID_ALARM_CARD	0x90

/* These are the various MXP OEM commands. */
#define MXP_NETFN_MXP1		0x30
#define MXP_OEM_GET_CHASSIS_TYPE_CMD		0x08
#define MXP_OEM_SET_CHASSIS_TYPE_CMD		0x09
#define MXP_OEM_GET_CHASSIS_ID_CMD		0x0a
#define MXP_OEM_GET_RELAYS_CMD			0x0b
#define MXP_OEM_SET_RELAYS_CMD			0x0c
#define MXP_OEM_GET_SLOT_HS_STATUS_CMD		0x0d
#define MXP_OEM_GET_SGA_CMD			0x0e
#define MXP_OEM_SET_SGA_CMD			0x0f
#define MXP_OEM_SET_HB_TIMEOUT_CMD		0x10
#define MXP_OEM_GET_SLOT_STATUS_CMD		0x11
#define MXP_OEM_SET_SLOT_POWER_CMD		0x12
#define MXP_OEM_SET_SLOT_BLUE_LED_CMD		0x13
#define MXP_OEM_SET_SLOT_LED_CMD		0x14
#define MXP_OEM_SET_SLOT_RESET_CMD		0x15
#define MXP_OEM_GET_AMC_STATUS_CMD		0x16
#define MXP_OEM_SET_POWER_CONFIG_CMD		0x18
#define MXP_OEM_GET_FAN_STATUS_CMD		0x19
#define MXP_OEM_GET_PS_STATUS_CMD		0x20
#define MXP_OEM_SET_PS_ENABLE_CMD		0x21
#define MXP_OEM_SET_PS_LED_CMD			0x23
#define MXP_OEM_SET_FAN_SPEED_CMD		0x24
#define MXP_OEM_SET_FAN_LED_CMD			0x25
#define MXP_OEM_SET_FW_DOWNLOAD_CMD		0x26
#define MXP_OEM_SET_CHASSIS_ID_CMD		0x27
#define MXP_OEM_SET_IPMB_ISOLATE_CMD		0x29
#define MXP_OEM_SET_AUTO_IPMB_ISOLATE_CMD	0x2a
#define MXP_OEM_GET_IPMB_STATUS_CMD		0x2b
#define MXP_OEM_BDSEL_CMD			0x31
#define MXP_OEM_PCIRST_CMD			0x32
#define MXP_OEM_SET_ALL_SLOT_LED_CMD		0x33
#define MXP_OEM_GET_ALL_SLOT_LED_CMD		0x34
#define MXP_OEM_SET_AMC_LED_CMD			0x35
#define MXP_OEM_GET_AMC_LED_CMD			0x36
#define MXP_OEM_SET_SYS_LED_CMD			0x37
#define MXP_OEM_GET_SYS_LED_CMD			0x38
#define MXP_OEM_SET_DATA_OUT_BIT_CMD		0x39
#define MXP_OEM_SET_DATA_OUT_BYTE_CMD		0x3a
#define MXP_OEM_GET_DATA_INOUT_CMD		0x3b
#define MXP_OEM_SET_SLOT_INIT_CMD		0x3c
#define MXP_OEM_SET_QUEUE_LOCK_CMD		0x3e
#define MXP_OEM_GET_SLOT_SIGNALS_CMD		0x40
#define MXP_OEM_SET_DUAL_CONTROL_CMD		0x4a

#define MXP_CHASSIS_CONFIG_6U		0
#define MXP_CHASSIS_CONFIG_3U		1

/* Sensor numbers in the MXP.
 *
 * The sensor numbers used for the non-standard sensors (and controls)
 * that are global (owned by the AMC(s) are as follows:
 *
 * Chassis sensors/controls: 0-15
 * Power supply sensors/controls: 16-63 (16 each)
 * Board sensors/controls: 64-239 (8 each, 22 boards)
 *
 * Note that 239-255 are reserved for use by OpenIPMI, so we can't use those.
 *
 */

/* Chassis sensors/controls */
#define MXP_SYS_LED_CONTROL_NUM		1
#define MXP_CHASSIS_ID_CONTROL_NUM	2
#define MXP_CHASSIS_TYPE_CONTROL_NUM	3
#define MXP_RELAY_CONTROL_NUM	        4
#define MXP_SHELF_GA_CONTROL_NUM	5

/* Power supply and fan sensors/controls */
#define MXP_PS_SENSNUM_START 16
#define MXP_PS_SENSOR_NUM(idx, num) (((idx)*16)+(num)+MXP_PS_SENSNUM_START)
#define MXP_PS_PRESENCE_NUM(idx) MXP_PS_SENSOR_NUM(idx, 1)
#define MXP_PS_PS_NUM(idx) MXP_PS_SENSOR_NUM(idx, 2)
#define MXP_FAN_PRESENCE_NUM(idx) MXP_PS_SENSOR_NUM(idx, 3)
#define MXP_FAN_SPEED_NUM(idx) MXP_PS_SENSOR_NUM(idx, 4)
#define MXP_FAN_COOLING_NUM(idx) MXP_PS_SENSOR_NUM(idx, 5)

/* Power supply sensors/controls */
#define MXP_PS_CONTROLNUM_START 16
#define MXP_PS_CONTROL_NUM(idx, num) (((idx)*16)+(num)+MXP_PS_CONTROLNUM_START)
#define MXP_PS_ENABLE_NUM(idx) MXP_PS_CONTROL_NUM(idx, 1)
#define MXP_PS_OOS_LED_NUM(idx) MXP_PS_CONTROL_NUM(idx, 2)
#define MXP_PS_INS_LED_NUM(idx) MXP_PS_CONTROL_NUM(idx, 3)
#define MXP_FAN_SPEEDCONTROL_NUM(idx) MXP_PS_CONTROL_NUM(idx, 4)
#define MXP_FAN_OOS_LED_NUM(idx) MXP_PS_CONTROL_NUM(idx, 5)
#define MXP_FAN_INS_LED_NUM(idx) MXP_PS_CONTROL_NUM(idx, 6)
#define MXP_PS_TYPE_NUM(idx) MXP_PS_CONTROL_NUM(idx, 7)
#define MXP_PS_REVISION_NUM(idx) MXP_PS_CONTROL_NUM(idx, 8)
#define MXP_FAN_TYPE_NUM(idx) MXP_PS_CONTROL_NUM(idx, 9)
#define MXP_FAN_REVISION_NUM(idx) MXP_PS_CONTROL_NUM(idx, 10)
#define MXP_FAN_I2C_ENABLE_NUM(idx) MXP_PS_CONTROL_NUM(idx, 11)

/* Board senors/controls. */
#define MXP_BOARD_SENSNUM_START 64
#define MXP_BOARD_SENSOR_NUM(idx,num) (((idx)*8)+(num)+MXP_BOARD_SENSNUM_START)
#define MXP_BOARD_PRESENCE_NUM(idx) MXP_BOARD_SENSOR_NUM(idx, 1)

#define MXP_BOARD_CONTROLNUM_START 64
#define MXP_BOARD_CONTROL_NUM(idx,num) (((idx)*8)+(num)+MXP_BOARD_CONTROLNUM_START)
#define MXP_BOARD_OOS_LED_NUM(idx) MXP_BOARD_CONTROL_NUM(idx, 1)
#define MXP_BOARD_INS_LED_NUM(idx) MXP_BOARD_CONTROL_NUM(idx, 2)
#define MXP_BOARD_BD_SEL_NUM(idx) MXP_BOARD_CONTROL_NUM(idx, 3)
#define MXP_BOARD_PCI_RESET_NUM(idx) MXP_BOARD_CONTROL_NUM(idx, 4)
#define MXP_SLOT_INIT_NUM(idx) MXP_BOARD_CONTROL_NUM(idx, 5)
#define MXP_SLOT_I2C_ISOLATE_NUM(idx) MXP_BOARD_CONTROL_NUM(idx, 6)


/* Information common to all sensors.  A pointer to this is put into
   the OEM field of the sensor. */
typedef struct mxp_sensor_header_s
{
    /* We store the sensor's supported events in these bitmasks. */
    unsigned int assert_events;
    unsigned int deassert_events;

    /* Depending on the sensor, this will hold:
       Power Supply/fans - A pointer to mxp_power_supply_t
       Boards, switches, and AMC presense sensors  - A pointer
         to the mxp_board_t structure for the board.
       Board/switch/AMC slot sensors - not used (NULL)
       Other AMC sensors - A pointer to amc_info_t for the AMC.
       Chassis sensors - there aren't any currently.

       Note that if the data is dynamically allocated, you can provide
       a function to free the data, it will be called when the sensor
       is destroyed. */
    void         *data;
    void         (*data_freer)(void *);
} mxp_sensor_header_t;

/* Information common to all controls. */
typedef struct mxp_control_header_s
{
    /* Depending on the control, this will hold:
       Power Supply/fans - A pointer to mxp_power_supply_t
       Boards, switches, and AMC led controls  - A pointer
         to the mxp_board_t structure for the board.
       Board/switch/AMC blue light controls - not used (NULL)
       Board/switch power/reset controls - not used (NULL)
       Other AMC controls - A pointer to amc_info_t for the AMC.
       Chassis controls - A pointer to mxp_info_t for the chassis.
    */
    void         *data;
} mxp_control_header_t;

typedef struct mxp_info_s mxp_info_t;

typedef struct mxp_power_supply_s
{
    mxp_info_t    *info;
    int           idx;
    unsigned int  ipmb_addr;

    ipmi_entity_t *ent;
    ipmi_entity_t *fan_ent;

    ipmi_sensor_t *presence;
    ipmi_sensor_t *ps;

    ipmi_control_t *enable;
    ipmi_control_t *oos_led;
    ipmi_control_t *inserv_led;
    ipmi_control_t *ps_type;
    ipmi_control_t *ps_revision;

    ipmi_sensor_t *fan;
    ipmi_sensor_t *fan_presence;
    ipmi_sensor_t *cooling;
    ipmi_sensor_t *fan_i2c_enable;

    ipmi_control_t *fan_speed;
    ipmi_control_t *fan_oos_led;
    ipmi_control_t *fan_inserv_led;
    ipmi_control_t *fan_type;
    ipmi_control_t *fan_revision;
} mxp_power_supply_t;

typedef struct mxp_board_s {
    mxp_info_t    *info;
    int           idx;
    unsigned int  ipmb_addr;
    int           is_amc;

    ipmi_entity_t *ent;

    /* The first time we read the presence we will scan the address, if
       necessary. */
    int           presence_read;
    
    ipmi_sensor_t *presence;
    ipmi_sensor_t *slot;

    ipmi_control_t *oos_led;
    ipmi_control_t *inserv_led;
    ipmi_control_t *bd_sel;
    ipmi_control_t *pci_reset;
    ipmi_control_t *slot_init;
    ipmi_control_t *i2c_isolate;
} mxp_board_t;
#define BOARD_HAS_RESET_CONTROL(board) (!((board)->is_amc))
#define BOARD_HAS_POWER_CONTROL(board) (!((board)->is_amc))

typedef struct domain_up_info_s
{
    int                      up;
    ipmi_mcid_t              mcid;
    ipmi_domain_con_change_t *con_chid;
    mxp_info_t		     *info;
} domain_up_info_t;

/* The AMC MC's store one of these in their OEM data. */
typedef struct amc_info_s
{
    /* This is NULL at startup, and will be calculated on received events. */
    mxp_info_t    *mxp_info;

    ipmi_mc_t     *mc;
    ipmi_entity_t *ent;

    /* Now all the sensors. */
    ipmi_sensor_t *slot;
    ipmi_sensor_t *s5v;
    ipmi_sensor_t *s3_3v;
    ipmi_sensor_t *s2_5v;
    ipmi_sensor_t *s8v;
    ipmi_sensor_t *temp;
    ipmi_sensor_t *offline;

    /* The controls. */
    ipmi_control_t *blue_led;
    ipmi_control_t *hw_version;
    ipmi_control_t *fw_version;
    ipmi_control_t *fpga_version;
    ipmi_control_t *temp_cool_led;
    ipmi_control_t *last_reset_reason;
} amc_info_t;

struct mxp_info_s {
    unsigned char      chassis_type;
    unsigned char      chassis_config;
    unsigned int       mfg_id;
    ipmi_domain_t      *domain;
    ipmi_mc_t          *mc;
    ipmi_entity_t      *chassis_ent;
    mxp_power_supply_t power_supply[MXP_POWER_SUPPLIES];
    mxp_board_t        board[MXP_TOTAL_BOARDS];

    /* Chassis info */
    ipmi_control_t *chassis_id;
    ipmi_control_t *chassis_type_control;
    ipmi_control_t *shelf_ga_control;
    ipmi_control_t *sys_led;
    ipmi_control_t *relays;

    domain_up_info_t *con_ch_info;

    ipmi_domain_mc_upd_t *mc_upd_id;

    int amc_present[2];
};

/***********************************************************************
 *
 * Various LED settings.
 *
 **********************************************************************/

static ipmi_control_transition_t off_led[] = { {IPMI_CONTROL_COLOR_BLACK, 1 } };
static ipmi_control_transition_t on_red_led[] = { { IPMI_CONTROL_COLOR_RED, 1 } };
static ipmi_control_transition_t on_blue_led[] = { { IPMI_CONTROL_COLOR_RED, 1 } };
static ipmi_control_transition_t on_green_led[] = { { IPMI_CONTROL_COLOR_GREEN, 1 } };
static ipmi_control_transition_t on_yellow_led[] = { { IPMI_CONTROL_COLOR_YELLOW, 1 } };

static ipmi_control_transition_t blue_led1[] =
{
    { IPMI_CONTROL_COLOR_BLUE, 500 },
    { IPMI_CONTROL_COLOR_BLACK, 500 },
};

static ipmi_control_setting_t blue_blinking_led_set[] =
{
    { 1, off_led },
    { 1, on_blue_led },
    { 2, blue_led1 },
};

static ipmi_control_setting_t blue_led_set[] =
{
    { 1, off_led },
    { 1, on_blue_led },
};

static ipmi_control_setting_t red_led_set[] =
{
    { 1, off_led },
    { 1, on_red_led },
};

static ipmi_control_setting_t green_led_set[] =
{
    { 1, off_led },
    { 1, on_green_led },
};

static ipmi_control_setting_t yellow_led_set[] =
{
    { 1, off_led },
    { 1, on_yellow_led },
};

static ipmi_control_light_t blue_blinking_led[] = {{ 3, blue_blinking_led_set }};
static ipmi_control_light_t blue_led[] = {{ 2, blue_led_set }};
static ipmi_control_light_t red_led[] = {{ 2, red_led_set }};
static ipmi_control_light_t green_led[] = {{ 2, green_led_set }};

static ipmi_control_light_t sys_leds[] =
{
    { 1, red_led_set },
    { 1, green_led_set },
    { 1, yellow_led_set },
};

static ipmi_control_light_t amc_temp_cool_leds[] =
{
    { 1, red_led_set },
    { 1, red_led_set }
};

/***********************************************************************
 *
 * Handling for generic discrete sensor read operations.  For most
 * sensors, the read operation allocates a sens info structure, fills
 * it in, and lets this code handle the rest of the read operation.
 *
 **********************************************************************/

typedef struct mxp_sens_info_s mxp_sens_info_t;

/* Handler for getting the information from a message when no error
   occurs.  The message is passed in the "data" field, the states
   should be set by the call (they are initialized for you). */
typedef void (*mxp_states_get_val_cb)(ipmi_sensor_t   *sensor,
				      mxp_sens_info_t *sens_info,
				      unsigned char   *data,
				      ipmi_states_t   *states);

/* Handler for message errors.  Some message errors are expected and
   are not actually errors, this routine should fill in the states and
   return error they wish to report to the user.  Note that the error
   is the raw IPMI error (0xc3 for timeout, for instance).  This is
   only called on IPMI errors, not system errors. */
typedef int (*mxp_states_err_cb)(ipmi_sensor_t   *sensor,
				 mxp_sens_info_t *sens_info,
				 int             err,
				 unsigned char   *data,
				 ipmi_states_t   *states);

struct mxp_sens_info_s
{
    /* See the sensor code for information on this. */
    ipmi_sensor_op_info_t sdata;

    /* Generic info for use by the specific sensor. */
    void                  *sdinfo;

    /* The miminum length of the response message. */
    unsigned int          min_rsp_length;

    /* Routines to handle getting the states from the data.  The
       err_states routine does not have to be supplied (may be NULL),
       in that case the error from the message is returned. */
    mxp_states_get_val_cb get_states;
    mxp_states_err_cb     err_states;

    /* The user callback info. */
    ipmi_states_read_cb   done;
    void                  *cb_data;

    /* Use for board presence. */
    ipmi_sensor_id_t      sens_id;
    ipmi_msg_t            *rsp;
};

static mxp_sens_info_t *
alloc_sens_info(void *sdinfo, ipmi_states_read_cb done, void *cb_data)
{
    mxp_sens_info_t *sens_info;

    sens_info = ipmi_mem_alloc(sizeof(*sens_info));
    if (!sens_info)
	return NULL;
    memset(sens_info, 0, sizeof(*sens_info));
    sens_info->sdinfo = sdinfo;
    sens_info->done = done;
    sens_info->cb_data = cb_data;
    return sens_info;
}

static void
mxp_sensor_get_done(ipmi_sensor_t *sensor,
		    int           err,
		    ipmi_msg_t    *rsp,
		    void          *cb_data)
{
    mxp_sens_info_t *sens_info = cb_data;
    ipmi_states_t   states;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (sens_info->done)
	    sens_info->done(sensor, err,
			    &states, sens_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	/* Check the error handler first, and let it handle the error. */
	if (sens_info->err_states) {
	    err = sens_info->err_states(sensor, sens_info, rsp->data[0],
					rsp->data, &states);
	    if (!err)
		goto deliver;
	}

	ipmi_log(IPMI_LOG_ERR_INFO,
		 "mxp_sensor_get_done: Received IPMI error: %x",
		 rsp->data[0]);
	if (sens_info->done)
	    sens_info->done(sensor, IPMI_IPMI_ERR_VAL(rsp->data[0]),
			    &states, sens_info->cb_data);
	goto out;
    }

    if (rsp->data_len < sens_info->min_rsp_length) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "mxp_sensor_get_done: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, sens_info->min_rsp_length);
	if (sens_info->done)
	    sens_info->done(sensor, EINVAL,
			    &states, sens_info->cb_data);
	goto out;
    }

    sens_info->get_states(sensor, sens_info, rsp->data, &states);

 deliver:
    if (sens_info->done)
	sens_info->done(sensor, 0, &states, sens_info->cb_data);
 out:
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(sens_info);
}

/* This data structure is used by a lot of the sensors to hold what
   they are doing */
typedef struct mxp_reading_done_s
{
    ipmi_sensor_op_info_t sdata;
    void                  *sdinfo;
    ipmi_reading_done_cb  done;
    void                  *cb_data;
} mxp_reading_done_t;

/***********************************************************************
 *
 * Handling for generic control get/set operations.  A simple control
 * operation can use this code to handle most of the work of reading
 * and setting the control.
 *
 **********************************************************************/

typedef struct mxp_control_info_s mxp_control_info_t;

typedef int (*mxp_control_get_val_cb)(ipmi_control_t     *control,
				      mxp_control_info_t *control_info,
				      unsigned char      *data);

struct mxp_control_info_s
{
    /* From ipmi_control.h. */
    ipmi_control_op_info_t         sdata;

    /* Controls on the MXP can have up to 4 values, we store them here
       for setting. */
    unsigned char                  vals[4];

    /* The miminum length of the response message. */
    unsigned int                   min_rsp_length;

    /* For use by the specific code. */
    unsigned long                  misc;

    /* Pointer for use by the specific control code, not used in this
       code. */
    void                           *idinfo;

    /* The user routines to call when we are done. */
    ipmi_control_op_cb             done_set;
    ipmi_control_val_cb            done_get;
    void                           *cb_data;

    /* Routines to get the value from the received message data. */
    mxp_control_get_val_cb         get_val;
    ipmi_control_identifier_val_cb get_identifier_val;
};

static mxp_control_info_t *
alloc_control_info(void *idinfo)
{
    mxp_control_info_t *control_info;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return NULL;
    memset(control_info, 0, sizeof(*control_info));
    control_info->idinfo = idinfo;
    return control_info;
}

static void
mxp_control_set_done(ipmi_control_t *control,
		     int            err,
		     ipmi_msg_t     *rsp,
		     void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "mxp_control_set_done: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->done_set)
	    control_info->done_set(control,
				   IPMI_IPMI_ERR_VAL(rsp->data[0]),
				   control_info->cb_data);
	goto out;
    }

    if (control_info->done_set)
	control_info->done_set(control, 0, control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
mxp_control_get_done(ipmi_control_t *control,
		     int            err,
		     ipmi_msg_t     *rsp,
		     void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                val;

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "mxp_control_get_done: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->done_get)
	    control_info->done_get(control,
				   IPMI_IPMI_ERR_VAL(rsp->data[0]),
				   NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < control_info->min_rsp_length) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "mxp_control_get_done: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 9);
	if (control_info->done_set)
	    control_info->done_set(control, EINVAL, control_info->cb_data);
	goto out;
    }

    val = control_info->get_val(control, control_info, rsp->data);
    if (control_info->done_get)
	control_info->done_get(control, 0, &val, control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

/***********************************************************************
 *
 * Generic fixup and data functions used throughout the code.
 *
 **********************************************************************/

static void
add_mxp_mfg_id(unsigned char *data)
{
    data[0] = MXP_MANUFACTURER_ID & 0xff;
    data[1] = (MXP_MANUFACTURER_ID >> 8) & 0xff;
    data[2] = (MXP_MANUFACTURER_ID >> 16) & 0xff;
}

/* We convert addresses to instances by taking the actual I2C address
   (the upper 7 bits of the IPMB address) and subtracting 57 from it.
   Boards start at 0x58, so this makes the instance numbers for boards
   start at one. */
static unsigned int
mxp_addr_to_instance(unsigned int slave_addr)
{
    switch (slave_addr) {
    case 0xe4:
	return 1; /* IP switch 1 */

    case 0xe6:
	return 2; /* IP switch 2 */

    default:
	slave_addr /= 2;
    	if (slave_addr >= 0x58) {
	    if (slave_addr >= 0x61)
                slave_addr--;
            return slave_addr - 0x57;
        } else
            return slave_addr;
    }
}

/* This will search for a slave address in the MXP boards and return
   the instance for the address. */
static int
mxp_board_addr_to_index(unsigned int slave_addr, mxp_info_t *info)
{
    int i;
    for (i=0; i<MXP_TOTAL_BOARDS; i++) {
	if (info->board[i].ipmb_addr == slave_addr)
	    return i;
    }
    return -1;
}

static mxp_board_t *
mxp_find_board_by_addr(mxp_info_t *info, unsigned int slave_addr)
{
    int i;

    if (slave_addr == 0xea) {
	/* The amc1 reports itself as 0xea */
	return &(info->board[MXP_ALARM_CARD_IDX_OFFSET]);
    }

    if (slave_addr == 0xec) {
	/* The amc2 reports itself as 0xec */
	return &(info->board[MXP_ALARM_CARD_IDX_OFFSET+1]);
    }

    for (i=0; i<MXP_TOTAL_BOARDS; i++) {
	if (info->board[i].ipmb_addr == slave_addr) {
	    return &(info->board[i]);
	}
    }

    return NULL;
}

/* We are passed in a pointer to an MC in the domain of an MXP sensor,
   find the mxp_info data structure. */
static void
amc_get_mxp_info_cb(ipmi_mc_t *mc, void *cb_data)
{
    mxp_info_t **mxp_info = cb_data;

    *mxp_info = ipmi_mc_get_oem_data(mc);
}
static mxp_info_t *
amc_get_mxp_info(ipmi_mc_t *mc, amc_info_t *ainfo)
{
    ipmi_mcid_t mc_id;
    mxp_info_t  *mxp_info = NULL;

    if (ainfo->mxp_info)
	return ainfo->mxp_info;

    mc_id = ipmi_mc_convert_to_id(mc);
    mc_id.channel = 0;
    mc_id.mc_num = 0x20;
    ipmi_mc_pointer_noseq_cb(mc_id, amc_get_mxp_info_cb, &mxp_info);
    ainfo->mxp_info = mxp_info;

    return mxp_info;
}

static int
mxp_3u_to_6u_addr(mxp_info_t *mxpinfo, int addr)
{
    /* For the 6U chassis, the IPMB addresses come in wrong, and we
       have to recalculate it. */
    if (mxpinfo->chassis_config == MXP_CHASSIS_CONFIG_6U) {
	if (addr == 0xe4) /* switch 1 */
	    addr = 0xb2;
	else if (addr == 0xe6) /* switch 2 */
	    addr = 0xb4;
	else if ((addr > 0xc2) || ((addr+6) < 0xc2))
	    addr += 6;
	else
	    /* Special adjustment to skip over 0xc2. */
	    addr += 8;
    }

    return addr;
}

static int
fix_led_addr(mxp_info_t *mxpinfo, int addr, int amc_idx)
{
    /* For the 6U chassis, the IPMB addresses used for setting LED
       values are wrong and we have to recalculate it. */
    if (mxpinfo->chassis_config == MXP_CHASSIS_CONFIG_6U) {
	if (addr == 0x20) /* AMC */
	    addr = 0xec;
	else if (addr == 0xb2) /* switch 1 */
	    addr = 0xe4;
	else if (addr == 0xb4) /* switch 2 */
	    addr = 0xe6;
	else if ((addr > 0xc2) && ((addr-6) <= 0xc2))
	    /* Special adjustment to skip over 0xc2. */
	    addr -= 8;
	else
	    addr -= 6;
    } else if (addr == 0x20) {
	addr = 0xea + (amc_idx * 2);
    }

    return addr;
}

/* The voltage sensors are converted with the formula:

     y = nominal + ((raw - 198) * ticksize)

     Basically, 198 is always the nominal value.

     For instance, for the 5V sensor, the nominal value is 5.0, and the
     ticksize is .025.  However, we have to transform this to go into
     the IPMI equation:

     y = (raw * ticksize) + (nominal - (198 * ticksize))

     So ticksize will be M, and (nominal - (198 * ticksize)) will be B.
     IPMI is limited to 10-bit signed values for M and the B base value,
     and M may only be a signed integer value, so we have to expand M
     out and fit it into 9 bits plus sign, and set the r_exp appropriately.
     The B value can have a 10*b_exp multiplier, so we are
     safe there.  We try to get as much accuracy as we can in this, but it's
     not very good.
*/

static void
set_volt_conv(ipmi_sensor_t *sensor, double val,
	      int m, int b, int b_exp, int r_exp)
{
    int                         i;
    enum ipmi_thresh_e          event;
    enum ipmi_event_value_dir_e dir;
    double                      v, step;
    int                         offset;

    /* The voltage sensors. */
    for (i=0; i<256; i++) {
	ipmi_sensor_set_raw_m(sensor, i, m);
	ipmi_sensor_set_raw_b(sensor, i, b);
	ipmi_sensor_set_raw_b_exp(sensor, i, b_exp);
	ipmi_sensor_set_raw_r_exp(sensor, i, r_exp);
        ipmi_sensor_set_raw_accuracy(sensor, i, m);
        ipmi_sensor_set_raw_accuracy_exp(sensor, i, r_exp);
    }
    for (event = IPMI_LOWER_NON_CRITICAL;
	 event < IPMI_UPPER_NON_RECOVERABLE;
	 event++)
    {
	for (dir = IPMI_GOING_LOW; dir <= IPMI_GOING_HIGH; dir++) {
	    ipmi_sensor_set_threshold_assertion_event_supported
		(sensor, event, dir, 0);
	    ipmi_sensor_set_threshold_deassertion_event_supported
		(sensor, event, dir, 0);
	}
    }
    ipmi_sensor_set_event_support(sensor, IPMI_EVENT_SUPPORT_NONE);

    v = val * 0.05;
    step = ((float) m) * pow(10.0, r_exp);
    v /= step;
    offset = v; /* We want truncation. */
    ipmi_sensor_set_raw_normal_min(sensor, 198-offset);
    ipmi_sensor_set_normal_min_specified(sensor, 1);
    ipmi_sensor_set_raw_normal_max(sensor, 198+offset);
    ipmi_sensor_set_normal_max_specified(sensor, 1);
    ipmi_sensor_set_raw_nominal_reading(sensor, 198);
    ipmi_sensor_set_nominal_reading_specified(sensor, 1);
    
}

/* Fixups for the SDRs on the MXP.  They are fairly broken. */
static int
mxp_new_sensor(ipmi_mc_t     *mc,
	       ipmi_entity_t *ent,
	       ipmi_sensor_t *sensor,
	       void          *link,
	       void          *cb_data)
{
    int                         lun, num;
    int                         i;
    enum ipmi_thresh_e          event;
    enum ipmi_event_value_dir_e dir;

    ipmi_sensor_get_num(sensor, &lun, &num);

    switch (num) {
	case 0x0a:
	    /* The LM77 temperature sensor. */
	    for (i=0; i<256; i++) {
		/* It seems that the lower and upper bits of the LM77
                   sensor value are truncated to return this, so it's
                   a simple 1-1 relationship between degrees C and the
                   value. */
		ipmi_sensor_set_raw_m(sensor, i, 1);
		ipmi_sensor_set_raw_r_exp(sensor, i, 0);
	    }
	    for (event = IPMI_LOWER_NON_CRITICAL;
		 event < IPMI_UPPER_NON_RECOVERABLE;
		 event++)
	    {
		for (dir = IPMI_GOING_LOW; dir <= IPMI_GOING_HIGH; dir++) {
		    ipmi_sensor_set_threshold_assertion_event_supported
			(sensor, event, dir, 0);
		    ipmi_sensor_set_threshold_deassertion_event_supported
			(sensor, event, dir, 0);
		}
	    }
	    ipmi_sensor_set_event_support(sensor, IPMI_EVENT_SUPPORT_NONE);
	    ipmi_sensor_set_raw_normal_max(sensor, 55);
	    ipmi_sensor_set_normal_max_specified(sensor, 1);
	    break;

	case 0x40: /* 5V */
	    set_volt_conv(sensor, 5.0, 25, 50, 0, -3);
	    break;

	case 0x41: /* 3.3V */
	    set_volt_conv(sensor, 3.3, 165, 330, 0, -4);
	    break;

	case 0x42: /* 2.5V */
	    set_volt_conv(sensor, 2.5, 125, 250, 0, -4);
	    break;

	case 0x44: /* 8V */
	    set_volt_conv(sensor, 8.0, 40, 80, 0, -3);
	    break;

	case 0x43:
	    /* The "Cool" sensor. */
	    for (i=0; i<256; i++) {
		ipmi_sensor_set_raw_m(sensor, i, 1);
		ipmi_sensor_set_raw_r_exp(sensor, i, -1);
	    }
	    for (event = IPMI_LOWER_NON_CRITICAL;
		 event < IPMI_UPPER_NON_RECOVERABLE;
		 event++)
	    {
		for (dir = IPMI_GOING_LOW; dir <= IPMI_GOING_HIGH; dir++) {
		    ipmi_sensor_set_threshold_assertion_event_supported
			(sensor, event, dir, 0);
		    ipmi_sensor_set_threshold_deassertion_event_supported
			(sensor, event, dir, 0);
		}
	    }
	    ipmi_sensor_set_event_support(sensor, IPMI_EVENT_SUPPORT_NONE);
	    break;
    }
    return 0;
}

/* No MXP sensor supports modifying event enables. */
static int
mxp_events_enable_set(ipmi_sensor_t         *sensor,
		      ipmi_event_state_t    *states,
		      ipmi_sensor_done_cb   done,
		      void                  *cb_data)
{
    return ENOTSUP;
}

static int
mxp_events_enable_get(ipmi_sensor_t             *sensor,
		      ipmi_event_enables_get_cb done,
		      void                      *cb_data)
{
    ipmi_event_state_t  state;
    mxp_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);

    /* Event enables are stored in the header data structure. */
    if (done) {
	ipmi_event_state_init(&state);
	ipmi_event_state_set_scanning_enabled(&state, 1);
	state.__assertion_events = hdr->assert_events;
	state.__deassertion_events = hdr->deassert_events;
	done(sensor, 0, &state, cb_data);
    }
    return 0;
}

/* All MXP sensors readings are the value * 10. */
static int
mxp_sensor_convert_from_raw(ipmi_sensor_t *sensor,
			    int           val,
			    double        *result)
{
    double dval = val;

    *result = dval / 10;
    return 0;
}

static int
mxp_sensor_convert_to_raw(ipmi_sensor_t     *sensor,
			  enum ipmi_round_e rounding,
			  double            val,
			  int               *result)
{
    switch (rounding)
    {
	case ROUND_NORMAL:
	    val += .5;
	    break;

	case ROUND_UP:
	    val = ceil(val);
	    break;

	case ROUND_DOWN:
	    val = floor(val);
	    break;
    }

    *result = val * 10.0;
    return 0;
}

static int
mxp_sensor_get_hysteresis(ipmi_sensor_t          *sensor,
			  ipmi_hysteresis_get_cb done,
			  void                   *cb_data)
{
    return ENOSYS;
}

static int
mxp_sensor_set_hysteresis(ipmi_sensor_t       *sensor,
			  unsigned int        positive_hysteresis,
			  unsigned int        negative_hysteresis,
			  ipmi_sensor_done_cb done,
			  void                *cb_data)
{
    return ENOSYS;
}

static int
mxp_thresholds_get(ipmi_sensor_t      *sensor,
		   ipmi_thresh_get_cb done,
		   void               *cb_data)
{
    ipmi_thresholds_t th;
    int               rv;

    rv = ipmi_get_default_sensor_thresholds(sensor, 0, &th);
    if (done)
	done(sensor, rv, &th, cb_data);
    return 0;
}

static int
mxp_thresholds_set(ipmi_sensor_t       *sensor,
		   ipmi_thresholds_t   *thresholds,
		   ipmi_sensor_done_cb done,
		   void                *cb_data)
{
    return ENOSYS;
}

static int
mxp_sensor_get_tolerance(ipmi_sensor_t *sensor,
			 int           val,
			 double        *tolerance)
{
    return ENOSYS;
}

static int
mxp_sensor_get_accuracy(ipmi_sensor_t *sensor,
			int           val,
			double        *accuracy)
{
    return ENOSYS;
}

/***********************************************************************
 *
 * General sensor creation code.
 *
 **********************************************************************/

static void
mxp_cleanup_sensor_oem_info(ipmi_sensor_t *sensor, void *oem_info)
{
    mxp_sensor_header_t *hdr = oem_info;

    if (hdr) {
	if (hdr->data_freer)
	    hdr->data_freer(hdr->data);
	ipmi_mem_free(hdr);
    }
}

/* Call this to allocate the sensor.  Then fix it up and call the
   finish operation */
static int
mxp_alloc_basic_sensor(
    void                               *data,
    void			       (*data_freer)(void *),
    unsigned int                       sensor_type,
    unsigned int                       reading_type,
    char                               *id,
    unsigned int                       assert_events,
    unsigned int                       deassert_events,
    ipmi_sensor_t                      **sensor)
{
    int                 rv;
    mxp_sensor_header_t *hdr;

    hdr = ipmi_mem_alloc(sizeof(*hdr));
    if (!hdr)
	return ENOMEM;

    hdr->assert_events = assert_events;
    hdr->deassert_events = deassert_events;
    hdr->data = data;
    hdr->data_freer = data_freer;

    /* Allocate the sensor. */
    rv = ipmi_sensor_alloc_nonstandard(sensor);
    if (rv) {
	ipmi_mem_free(hdr);
	return rv;
    }

    /* Fill out a bunch of default values. */
    ipmi_sensor_set_oem_info(*sensor, hdr, mxp_cleanup_sensor_oem_info);
    ipmi_sensor_set_entity_instance_logical(*sensor, 0);
    ipmi_sensor_set_sensor_init_scanning(*sensor, 1);
    ipmi_sensor_set_sensor_init_events(*sensor, 0);
    ipmi_sensor_set_sensor_init_thresholds(*sensor, 0);
    ipmi_sensor_set_sensor_init_hysteresis(*sensor, 0);
    ipmi_sensor_set_sensor_init_type(*sensor, 1);
    ipmi_sensor_set_sensor_init_pu_events(*sensor, 0);
    ipmi_sensor_set_sensor_init_pu_scanning(*sensor, 1);
    ipmi_sensor_set_ignore_if_no_entity(*sensor, 1);
    ipmi_sensor_set_supports_auto_rearm(*sensor, 1);
    if (assert_events || deassert_events)
        ipmi_sensor_set_event_support(*sensor, 
                                      IPMI_EVENT_SUPPORT_GLOBAL_ENABLE);
    else
        ipmi_sensor_set_event_support(*sensor, IPMI_EVENT_SUPPORT_NONE);

    ipmi_sensor_set_sensor_type(*sensor, sensor_type);
    ipmi_sensor_set_event_reading_type(*sensor, reading_type);
    ipmi_sensor_set_id(*sensor, id, IPMI_ASCII_STR, strlen(id));

    ipmi_sensor_set_sensor_type_string(
	*sensor,
	ipmi_get_sensor_type_string(sensor_type));
    ipmi_sensor_set_event_reading_type_string(
	*sensor,
	ipmi_get_event_reading_type_string(reading_type));

    return rv;
}

/* Add the sensor to the domain. */
static int
mxp_finish_sensor(ipmi_mc_t     *mc,
		  ipmi_sensor_t *sensor,
		  unsigned int  num,
		  ipmi_entity_t *entity)
{
    int rv;

    /* Add it to the MC and entity. */
    rv = ipmi_sensor_add_nonstandard(mc, mc, sensor, num, 0, entity,
				     NULL, NULL);
    if (rv) {
	void *hdr;
        hdr = ipmi_sensor_get_oem_info(sensor);
	ipmi_sensor_destroy(sensor);
	ipmi_mem_free(hdr);
    }

    return rv;
}

static int
mxp_alloc_discrete_sensor(
    ipmi_mc_t                          *mc,
    ipmi_entity_t                      *entity,
    unsigned int                       num,
    void                               *data,
    void			       (*data_freer)(void *),
    unsigned int                       sensor_type,
    unsigned int                       reading_type,
    char                               *id,
    unsigned int                       assert_events,
    unsigned int                       deassert_events,
    ipmi_states_get_cb                 states_get,
    ipmi_sensor_reading_name_string_cb sensor_reading_name_string,
    ipmi_sensor_t                      **sensor)
{
    int                 rv;
    ipmi_sensor_cbs_t   cbs;
    int                 i;

    rv = mxp_alloc_basic_sensor(data,
				data_freer,
				sensor_type,
				reading_type,
				id,
				assert_events,
				deassert_events,
				sensor);
    if (rv)
	return rv;

    /* If the event can be asserted or deasserted, assume it can be
       returned and generates an event both ways. */
    for (i=0; i<=14; i++) {
        int aval = assert_events & 1;
        int dval = deassert_events & 1;

        ipmi_sensor_set_discrete_assertion_event_supported(*sensor, i, aval);
        ipmi_sensor_set_discrete_deassertion_event_supported(*sensor, i, dval);
        ipmi_sensor_discrete_set_event_readable(*sensor, i, aval | dval);
        assert_events >>= 1;
        deassert_events >>= 1;
    }

    /* Create all the callbacks in the data structure. */
    memset(&cbs, 0, sizeof(cbs));
    cbs.ipmi_sensor_events_enable_set = mxp_events_enable_set;
    cbs.ipmi_sensor_events_enable = mxp_events_enable_set;
    cbs.ipmi_sensor_events_disable = mxp_events_enable_set;
    cbs.ipmi_sensor_events_enable_get = mxp_events_enable_get;
    cbs.ipmi_states_get = states_get;

    /* If ths user supply a function to get the name strings, use it.
       Otherwise use the standard one. */
    if (sensor_reading_name_string)
	cbs.ipmi_sensor_reading_name_string = sensor_reading_name_string;
    else
	cbs.ipmi_sensor_reading_name_string
	    = ipmi_standard_sensor_cb.ipmi_sensor_reading_name_string;

    ipmi_sensor_set_callbacks(*sensor, &cbs);

    rv = mxp_finish_sensor(mc, *sensor, num, entity);

    return rv;
}

/* Allocate a threshold sensor and use the MXP-specific conversion
   routines. */
static int
mxp_alloc_threshold_sensor(
    ipmi_mc_t                          *mc,
    ipmi_entity_t                      *entity,
    unsigned int                       num,
    void                               *data,
    void			       (*data_freer)(void *),
    unsigned int                       sensor_type,
    unsigned int                       base_unit,
    char                               *id,
    unsigned int                       assert_events,
    unsigned int                       deassert_events,
    ipmi_reading_get_cb                reading_get,
    int                                raw_nominal, /* -1 disables. */
    int                                raw_normal_min, /* -1 disables. */
    int                                raw_normal_max, /* -1 disables. */
    ipmi_sensor_t                      **sensor)
{
    int                 rv;
    ipmi_sensor_cbs_t   cbs;
    int                 i;
    enum ipmi_thresh_e  thresh;

    rv = mxp_alloc_basic_sensor(data,
				data_freer,
				sensor_type,
				IPMI_EVENT_READING_TYPE_THRESHOLD,
				id,
				assert_events,
				deassert_events,
				sensor);
    if (rv)
	return rv;

    ipmi_sensor_set_rate_unit_string(*sensor,
				     ipmi_get_rate_unit_string(0));
    ipmi_sensor_set_base_unit_string(*sensor,
				     ipmi_get_unit_type_string(base_unit));
    ipmi_sensor_set_modifier_unit_string(*sensor,
					 ipmi_get_unit_type_string(0));

    ipmi_sensor_set_hysteresis_support(*sensor, 0);
    ipmi_sensor_set_threshold_access(*sensor, 0);
    ipmi_sensor_set_analog_data_format(*sensor,
				       IPMI_ANALOG_DATA_FORMAT_UNSIGNED);
    ipmi_sensor_set_rate_unit(*sensor, 0);
    ipmi_sensor_set_modifier_unit_use(*sensor, 0);
    ipmi_sensor_set_percentage(*sensor, 0);
    ipmi_sensor_set_base_unit(*sensor, base_unit);
    ipmi_sensor_set_modifier_unit(*sensor, 0);
    ipmi_sensor_set_linearization(*sensor, 0);
    for (i=0; i<256; i++) {
	ipmi_sensor_set_raw_m(*sensor, i, 0);
	ipmi_sensor_set_raw_tolerance(*sensor, i, 0);
	ipmi_sensor_set_raw_b(*sensor, i, 0);
	ipmi_sensor_set_raw_accuracy(*sensor, i, 0);
	ipmi_sensor_set_raw_accuracy_exp(*sensor, i, 0);
	ipmi_sensor_set_raw_r_exp(*sensor, i, 0);
	ipmi_sensor_set_raw_b_exp(*sensor, i, 0);
    }
    if (raw_normal_min >= 0) {
	ipmi_sensor_set_raw_normal_min(*sensor, raw_normal_min);
	ipmi_sensor_set_normal_min_specified(*sensor, 1);
    } else {
	ipmi_sensor_set_raw_normal_min(*sensor, 0);
	ipmi_sensor_set_normal_min_specified(*sensor, 0);
    }
    if (raw_normal_max >= 0) {
	ipmi_sensor_set_raw_normal_max(*sensor, raw_normal_max);
	ipmi_sensor_set_normal_max_specified(*sensor, 1);
    } else {
	ipmi_sensor_set_raw_normal_max(*sensor, 0);
	ipmi_sensor_set_normal_max_specified(*sensor, 0);
    }
    if (raw_nominal >= 0) {
	ipmi_sensor_set_raw_nominal_reading(*sensor, raw_nominal);
	ipmi_sensor_set_nominal_reading_specified(*sensor, 1);
    } else {
	ipmi_sensor_set_raw_nominal_reading(*sensor, 0);
	ipmi_sensor_set_nominal_reading_specified(*sensor, 0);
    }
    ipmi_sensor_set_raw_sensor_max(*sensor, 0xff);
    ipmi_sensor_set_raw_sensor_min(*sensor, 0);
    ipmi_sensor_set_raw_upper_non_recoverable_threshold(*sensor, 0);
    ipmi_sensor_set_raw_upper_critical_threshold(*sensor, 0);
    ipmi_sensor_set_raw_upper_non_critical_threshold(*sensor, 0);
    ipmi_sensor_set_raw_lower_non_recoverable_threshold(*sensor, 0);
    ipmi_sensor_set_raw_lower_critical_threshold(*sensor, 0);
    ipmi_sensor_set_raw_lower_non_critical_threshold(*sensor, 0);
    ipmi_sensor_set_positive_going_threshold_hysteresis(*sensor, 0);
    ipmi_sensor_set_negative_going_threshold_hysteresis(*sensor, 0);

    for (thresh = IPMI_LOWER_NON_CRITICAL;
	 thresh <= IPMI_UPPER_NON_RECOVERABLE;
	 thresh++)
    {
	if ((1 << ((thresh*2) + IPMI_GOING_LOW)) & assert_events)
	    ipmi_sensor_set_threshold_assertion_event_supported
		(*sensor,
		 thresh,
		 IPMI_GOING_LOW,
		 1);
	if ((1 << ((thresh*2) + IPMI_GOING_HIGH)) & assert_events)
	    ipmi_sensor_set_threshold_assertion_event_supported
		(*sensor,
		 thresh,
		 IPMI_GOING_HIGH,
		 1);
	if ((1 << ((thresh*2) + IPMI_GOING_LOW)) & deassert_events)
	    ipmi_sensor_set_threshold_deassertion_event_supported
		(*sensor,
		 thresh,
		 IPMI_GOING_LOW,
		 1);
	if ((1 << ((thresh*2) + IPMI_GOING_HIGH)) & deassert_events)
	    ipmi_sensor_set_threshold_deassertion_event_supported
		(*sensor,
		 thresh,
		 IPMI_GOING_HIGH,
		 1);

	/* No thresholds are readable, they are all fixed. */
	ipmi_sensor_threshold_set_readable(*sensor, thresh, 0);
	ipmi_sensor_threshold_set_settable(*sensor, thresh, 0);
    }

    /* Create all the callbacks in the data structure. */
    memset(&cbs, 0, sizeof(cbs));
    cbs.ipmi_sensor_events_enable_set = mxp_events_enable_set;
    cbs.ipmi_sensor_events_enable_get = mxp_events_enable_get;
    cbs.ipmi_sensor_convert_from_raw = mxp_sensor_convert_from_raw;
    cbs.ipmi_sensor_convert_to_raw = mxp_sensor_convert_to_raw;
    cbs.ipmi_sensor_get_accuracy = mxp_sensor_get_accuracy;
    cbs.ipmi_sensor_get_tolerance = mxp_sensor_get_tolerance;
    cbs.ipmi_sensor_get_hysteresis = mxp_sensor_get_hysteresis;
    cbs.ipmi_sensor_set_hysteresis = mxp_sensor_set_hysteresis;
    cbs.ipmi_thresholds_set = mxp_thresholds_set;
    cbs.ipmi_thresholds_get = mxp_thresholds_get;
    cbs.ipmi_reading_get = reading_get;
    ipmi_sensor_set_callbacks(*sensor, &cbs);

    rv = mxp_finish_sensor(mc, *sensor, num, entity);

    return rv;
}

/* Allocate a threshold sensor and supply the conversion values.  This
   code will set it up so the standard conversion code will work with
   the sensor. */
static int
mxp_alloc_semi_stand_threshold_sensor(
    ipmi_mc_t                          *mc,
    ipmi_entity_t                      *entity,
    unsigned int                       num,
    void                               *data,
    void			       (*data_freer)(void *),
    unsigned int                       sensor_type,
    unsigned int                       base_unit,
    char                               *id,
    unsigned int                       assert_events,
    unsigned int                       deassert_events,
    ipmi_reading_get_cb                reading_get,
    int                                raw_nominal, /* -1 disables. */
    int                                raw_normal_min, /* -1 disables. */
    int                                raw_normal_max, /* -1 disables. */
    int                                m,
    int                                b,
    int                                b_exp,
    int                                r_exp,
    ipmi_sensor_t                      **sensor)
{
    int                 rv;
    ipmi_sensor_cbs_t   cbs;
    int                 i;
    enum ipmi_thresh_e  thresh;

    rv = mxp_alloc_basic_sensor(data,
				data_freer,
				sensor_type,
				IPMI_EVENT_READING_TYPE_THRESHOLD,
				id,
				assert_events,
				deassert_events,
				sensor);
    if (rv)
	return rv;

    ipmi_sensor_set_rate_unit_string(*sensor,
				     ipmi_get_rate_unit_string(0));
    ipmi_sensor_set_base_unit_string(*sensor,
				     ipmi_get_unit_type_string(base_unit));
    ipmi_sensor_set_modifier_unit_string(*sensor,
					 ipmi_get_unit_type_string(0));

    ipmi_sensor_set_hysteresis_support(*sensor, 0);
    ipmi_sensor_set_threshold_access(*sensor, 0);
    ipmi_sensor_set_analog_data_format(*sensor,
				       IPMI_ANALOG_DATA_FORMAT_UNSIGNED);
    ipmi_sensor_set_rate_unit(*sensor, 0);
    ipmi_sensor_set_modifier_unit_use(*sensor, 0);
    ipmi_sensor_set_percentage(*sensor, 0);
    ipmi_sensor_set_base_unit(*sensor, base_unit);
    ipmi_sensor_set_modifier_unit(*sensor, 0);
    ipmi_sensor_set_linearization(*sensor, 0);
    if (raw_normal_min >= 0) {
	ipmi_sensor_set_raw_normal_min(*sensor, raw_normal_min);
	ipmi_sensor_set_normal_min_specified(*sensor, 1);
    } else {
	ipmi_sensor_set_raw_normal_min(*sensor, 0);
	ipmi_sensor_set_normal_min_specified(*sensor, 0);
    }
    if (raw_normal_max >= 0) {
	ipmi_sensor_set_raw_normal_max(*sensor, raw_normal_max);
	ipmi_sensor_set_normal_max_specified(*sensor, 1);
    } else {
	ipmi_sensor_set_raw_normal_max(*sensor, 0);
	ipmi_sensor_set_normal_max_specified(*sensor, 0);
    }
    if (raw_nominal >= 0) {
	ipmi_sensor_set_raw_nominal_reading(*sensor, raw_nominal);
	ipmi_sensor_set_nominal_reading_specified(*sensor, 1);
    } else {
	ipmi_sensor_set_raw_nominal_reading(*sensor, 0);
	ipmi_sensor_set_nominal_reading_specified(*sensor, 0);
    }
    ipmi_sensor_set_raw_sensor_max(*sensor, 0xff);
    ipmi_sensor_set_raw_sensor_min(*sensor, 0);
    ipmi_sensor_set_raw_upper_non_recoverable_threshold(*sensor, 0);
    ipmi_sensor_set_raw_upper_critical_threshold(*sensor, 0);
    ipmi_sensor_set_raw_upper_non_critical_threshold(*sensor, 0);
    ipmi_sensor_set_raw_lower_non_recoverable_threshold(*sensor, 0);
    ipmi_sensor_set_raw_lower_critical_threshold(*sensor, 0);
    ipmi_sensor_set_raw_lower_non_critical_threshold(*sensor, 0);
    ipmi_sensor_set_positive_going_threshold_hysteresis(*sensor, 0);
    ipmi_sensor_set_negative_going_threshold_hysteresis(*sensor, 0);

    for (thresh = IPMI_LOWER_NON_CRITICAL;
	 thresh <= IPMI_UPPER_NON_RECOVERABLE;
	 thresh++)
    {
	if ((1 << ((thresh*2) + IPMI_GOING_LOW)) & assert_events)
	    ipmi_sensor_set_threshold_assertion_event_supported
		(*sensor,
		 thresh,
		 IPMI_GOING_LOW,
		 1);
	if ((1 << ((thresh*2) + IPMI_GOING_HIGH)) & assert_events)
	    ipmi_sensor_set_threshold_assertion_event_supported
		(*sensor,
		 thresh,
		 IPMI_GOING_HIGH,
		 1);
	if ((1 << ((thresh*2) + IPMI_GOING_LOW)) & deassert_events)
	    ipmi_sensor_set_threshold_deassertion_event_supported
		(*sensor,
		 thresh,
		 IPMI_GOING_LOW,
		 1);
	if ((1 << ((thresh*2) + IPMI_GOING_HIGH)) & deassert_events)
	    ipmi_sensor_set_threshold_deassertion_event_supported
		(*sensor,
		 thresh,
		 IPMI_GOING_HIGH,
		 1);

	/* No thresholds are readable, they are all fixed. */
	ipmi_sensor_threshold_set_readable(*sensor, thresh, 0);
	ipmi_sensor_threshold_set_settable(*sensor, thresh, 0);
    }

    for (i=0; i<256; i++) {
	ipmi_sensor_set_raw_m(*sensor, i, m);
	ipmi_sensor_set_raw_b(*sensor, i, b);
	ipmi_sensor_set_raw_b_exp(*sensor, i, b_exp);
	ipmi_sensor_set_raw_r_exp(*sensor, i, r_exp);
	ipmi_sensor_set_raw_accuracy(*sensor, i, m);
	ipmi_sensor_set_raw_accuracy_exp(*sensor, i, r_exp);
    }

    /* Create all the callbacks in the data structure. */
    memset(&cbs, 0, sizeof(cbs));
    cbs.ipmi_sensor_events_enable_set = mxp_events_enable_set;
    cbs.ipmi_sensor_events_enable_get = mxp_events_enable_get;
    cbs.ipmi_sensor_convert_from_raw
	= ipmi_standard_sensor_cb.ipmi_sensor_convert_from_raw;
    cbs.ipmi_sensor_convert_to_raw
	= ipmi_standard_sensor_cb.ipmi_sensor_convert_to_raw;
    cbs.ipmi_sensor_get_accuracy = mxp_sensor_get_accuracy;
    cbs.ipmi_sensor_get_tolerance = mxp_sensor_get_tolerance;
    cbs.ipmi_sensor_get_hysteresis = mxp_sensor_get_hysteresis;
    cbs.ipmi_sensor_set_hysteresis = mxp_sensor_set_hysteresis;
    cbs.ipmi_thresholds_set = mxp_thresholds_set;
    cbs.ipmi_thresholds_get = mxp_thresholds_get;
    cbs.ipmi_reading_get = reading_get;
    ipmi_sensor_set_callbacks(*sensor, &cbs);

    rv = mxp_finish_sensor(mc, *sensor, num, entity);

    return rv;
}

/***********************************************************************
 *
 * General control creation code.
 *
 **********************************************************************/

static void
mxp_cleanup_control_oem_info(ipmi_control_t *control, void *oem_info)
{
    mxp_sensor_header_t *hdr = oem_info;

    if (hdr) {
	ipmi_mem_free(hdr);
    }
}

static int
mxp_alloc_control(ipmi_mc_t               *mc,
		  ipmi_entity_t           *entity,
		  unsigned int            num,
		  void                    *data,
		  unsigned int            control_type,
		  char                    *id,
		  ipmi_control_set_val_cb set_val,
		  ipmi_control_get_val_cb get_val,
		  ipmi_control_t          **control)
{
    int                  rv;
    ipmi_control_cbs_t   cbs;
    mxp_control_header_t *hdr;

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
    ipmi_control_set_oem_info(*control, hdr, mxp_cleanup_control_oem_info);
    ipmi_control_set_type(*control, control_type);
    ipmi_control_set_id(*control, id, IPMI_ASCII_STR, strlen(id));
    ipmi_control_set_ignore_if_no_entity(*control, 1);

    /* Assume we can read and set the value. */
    if (set_val)
	ipmi_control_set_settable(*control, 1);
    if (get_val)
	ipmi_control_set_readable(*control, 1);

    /* Create all the callbacks in the data structure. */
    memset(&cbs, 0, sizeof(cbs));
    cbs.set_val = set_val;
    cbs.get_val = get_val;

    ipmi_control_set_callbacks(*control, &cbs);

    /* Add it to the MC and entity. */
    rv = ipmi_control_add_nonstandard(mc, mc, *control, num, entity,
				      NULL, NULL);
    if (rv) {
	ipmi_control_destroy(*control);
	ipmi_mem_free(hdr);
	*control = NULL;
    }

    return rv;
}

/***********************************************************************
 *
 * Chassis-specific controls and sensors start here.
 *
 **********************************************************************/

static void
chassis_id_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t   *control_info = cb_data;
    mxp_info_t           *info = control_info->idinfo;
    int                  rv;
    ipmi_msg_t           msg;
    unsigned char        data[7];

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_CHASSIS_ID_CMD;
    msg.data_len = 7;
    msg.data = data;
    add_mxp_mfg_id(data);
    memcpy(data+3, control_info->vals, 4);

    rv = ipmi_control_send_command(control, info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
chassis_id_set(ipmi_control_t     *control,
	       unsigned char      *val,
	       int                length,
	       ipmi_control_op_cb handler,
	       void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_info_t           *info = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    if (length != 4)
	return EINVAL;

    control_info = alloc_control_info(info);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    memcpy(control_info->vals, val, 4);
    rv = ipmi_control_add_opq(control, chassis_id_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
chassis_id_get_cb(ipmi_control_t *control,
		  int            err,
		  ipmi_msg_t     *rsp,
		  void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "chassis_id_get_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control,
					     IPMI_IPMI_ERR_VAL(rsp->data[0]),
					     NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 9) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "chassis_id_get_cb: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 9);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, EINVAL, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (control_info->get_identifier_val)
	control_info->get_identifier_val(control, 0,
					 rsp->data+4, 4,
					 control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
chassis_id_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t   *control_info = cb_data;
    mxp_info_t           *info = control_info->idinfo;
    int                  rv;
    ipmi_msg_t           msg;
    unsigned char        data[3];

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_CHASSIS_ID_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, info->mc, 0,
				   &msg, chassis_id_get_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, rv, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }
}

static int
chassis_id_get(ipmi_control_t                 *control,
	       ipmi_control_identifier_val_cb handler,
	       void                           *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_info_t           *info = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(info);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;
    rv = ipmi_control_add_opq(control, chassis_id_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
chassis_type_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t   *control_info = cb_data;
    mxp_info_t           *info = control_info->idinfo;
    int                  rv;
    ipmi_msg_t           msg;
    unsigned char        data[4];

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_CHASSIS_TYPE_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    memcpy(data+3, control_info->vals, 1);

    rv = ipmi_control_send_command(control, info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
chassis_type_set(ipmi_control_t     *control,
		 unsigned char      *val,
		 int                length,
		 ipmi_control_op_cb handler,
		 void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_info_t           *info = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    if (length != 1)
	return EINVAL;

    control_info = alloc_control_info(info);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;
    rv = ipmi_control_add_opq(control, chassis_type_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
chassis_type_get_cb(ipmi_control_t *control,
		    int            err,
		    ipmi_msg_t     *rsp,
		    void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

   if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "chassis_type_get_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control,
					     IPMI_IPMI_ERR_VAL(rsp->data[0]),
					     NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 5) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "chassis_type_get_cb: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 5);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, EINVAL, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

   if (control_info->get_identifier_val)
       control_info->get_identifier_val(control, 0,
					rsp->data+4, 1,
					control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
chassis_type_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t   *control_info = cb_data;
    mxp_info_t           *info = control_info->idinfo;
    int                  rv;
    ipmi_msg_t           msg;
    unsigned char        data[3];

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_CHASSIS_TYPE_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, info->mc, 0,
				   &msg, chassis_type_get_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, rv, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
chassis_type_get(ipmi_control_t                 *control,
		 ipmi_control_identifier_val_cb handler,
		 void                           *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_info_t           *info = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(info);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;
    rv = ipmi_control_add_opq(control, chassis_type_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
shelf_ga_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t   *control_info = cb_data;
    mxp_info_t           *info = control_info->idinfo;
    int                  rv;
    ipmi_msg_t           msg;
    unsigned char        data[4];

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_SGA_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    memcpy(data+3, control_info->vals, 1);

    rv = ipmi_control_send_command(control, info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
shelf_ga_set(ipmi_control_t     *control,
	     unsigned char      *val,
	     int                length,
	     ipmi_control_op_cb handler,
	     void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_info_t           *info = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    if (length != 1)
	return EINVAL;

    control_info = alloc_control_info(info);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;
    rv = ipmi_control_add_opq(control, shelf_ga_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
shelf_ga_get_cb(ipmi_control_t *control,
		int            err,
		ipmi_msg_t     *rsp,
		void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "shelf_ga_get_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control,
					     IPMI_IPMI_ERR_VAL(rsp->data[0]),
					     NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 5) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "shelf_ga_get_cb: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 5);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, EINVAL, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

   if (control_info->get_identifier_val)
       control_info->get_identifier_val(control, 0,
					rsp->data+4, 1,
					control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
shelf_ga_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t   *control_info = cb_data;
    mxp_info_t           *info = control_info->idinfo;
    int                  rv;
    ipmi_msg_t           msg;
    unsigned char        data[3];

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_SGA_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, info->mc, 0,
				   &msg, shelf_ga_get_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, rv, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
shelf_ga_get(ipmi_control_t                 *control,
	     ipmi_control_identifier_val_cb handler,
	     void                           *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_info_t           *info = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(info);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;
    rv = ipmi_control_add_opq(control, shelf_ga_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
sys_led_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_info_t         *info = control_info->idinfo;
    ipmi_msg_t         msg;
    unsigned char      data[4];
    int                rv;

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_SYS_LED_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = control_info->vals[0];

    rv = ipmi_control_send_command(control, info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
sys_led_set(ipmi_control_t     *control,
	    int                *val,
	    ipmi_control_op_cb handler,
	    void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_info_t           *info = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(info);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = (((val[0] & 0x3) << 6)
			     | ((val[1] & 0x3) << 4)
			     | ((val[2] & 0x3) << 2));
    rv = ipmi_control_add_opq(control, sys_led_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
sys_led_get_cb(ipmi_control_t *control,
	       int            err,
	       ipmi_msg_t     *rsp,
	       void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                val[3];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "sys_led_get_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->done_get)
	    control_info->done_get(control,
				   IPMI_IPMI_ERR_VAL(rsp->data[0]),
				   NULL, control_info->cb_data);
	goto out;
    }

    val[0] = (rsp->data[4] >> 6) & 0x3;
    val[1] = (rsp->data[4] >> 4) & 0x3;
    val[2] = (rsp->data[4] >> 2) & 0x3;
    if (control_info->done_get)
	control_info->done_get(control, 0,
			       val, control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
sys_led_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_info_t         *info = control_info->idinfo;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[3];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_SYS_LED_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, info->mc, 0,
				   &msg, sys_led_get_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }
}

static int
sys_led_get(ipmi_control_t      *control,
	    ipmi_control_val_cb handler,
	    void                *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_info_t           *info = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(info);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    rv = ipmi_control_add_opq(control, sys_led_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
relay_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_info_t         *info = control_info->idinfo;
    ipmi_msg_t         msg;
    unsigned char      data[4];
    int                rv;

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_RELAYS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = control_info->vals[0];

    rv = ipmi_control_send_command(control, info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
relay_set(ipmi_control_t     *control,
	  int                *val,
	  ipmi_control_op_cb handler,
	  void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_info_t           *info = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(info);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = ((val[0] & 1) | ((val[1] & 1) << 1)
			     | ((val[2] & 1) << 2) | ((val[3] & 1) << 3));
    rv = ipmi_control_add_opq(control, relay_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
relay_get_done(ipmi_control_t *control,
	       int            err,
	       ipmi_msg_t     *rsp,
	       void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                val[4];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "relay_get_done: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->done_get)
	    control_info->done_get(control,
				   IPMI_IPMI_ERR_VAL(rsp->data[0]),
				   NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 5) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "relay_get_done: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 5);
	if (control_info->done_get)
	    control_info->done_get(control, EINVAL, NULL,
				   control_info->cb_data);
	goto out;
    }

    val[0] = (rsp->data[4] >> 0) & 0x1;
    val[1] = (rsp->data[4] >> 1) & 0x1;
    val[2] = (rsp->data[4] >> 2) & 0x1;
    val[3] = (rsp->data[4] >> 3) & 0x1;
    if (control_info->done_get)
	control_info->done_get(control, 0, val, control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
relay_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_info_t           *info = hdr->data;
    mxp_control_info_t   *control_info = cb_data;
    int                  rv;
    ipmi_msg_t           msg;
    unsigned char        data[3];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_RELAYS_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, info->mc, 0,
				   &msg, relay_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, rv, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
relay_get(ipmi_control_t      *control,
	  ipmi_control_val_cb handler,
	  void                *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_info_t           *info = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(info);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    rv = ipmi_control_add_opq(control, relay_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static int
mxp_add_chassis_sensors(mxp_info_t *info)
{
    int                rv;
    ipmi_control_cbs_t control_cbs;


    /* The System LEDS (both OOS and inserv controls). */
    rv = mxp_alloc_control(info->mc, info->chassis_ent,
			   MXP_SYS_LED_CONTROL_NUM,
			   info,
			   IPMI_CONTROL_LIGHT,
			   "SYS LEDS",
			   sys_led_set,
			   sys_led_get,
			   &(info->sys_led));
    if (rv)
	goto out_err;
    ipmi_control_light_set_lights(info->sys_led, 3, sys_leds);

    /* The Chassis ID. */
    rv = mxp_alloc_control(info->mc, info->chassis_ent,
			   MXP_CHASSIS_ID_CONTROL_NUM,
			   info,
			   IPMI_CONTROL_IDENTIFIER,
			   "Chassis ID",
			   NULL,
			   NULL,
			   &(info->chassis_id));
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(info->chassis_id, 4);
    ipmi_control_get_callbacks(info->chassis_id, &control_cbs);
    control_cbs.set_identifier_val = chassis_id_set;
    control_cbs.get_identifier_val = chassis_id_get;
    ipmi_control_set_settable(info->chassis_id, 1);
    ipmi_control_set_readable(info->chassis_id, 1);
    ipmi_control_set_callbacks(info->chassis_id, &control_cbs);

    /* The Chassis Type. */
    rv = mxp_alloc_control(info->mc, info->chassis_ent,
			   MXP_CHASSIS_TYPE_CONTROL_NUM,
			   info,
			   IPMI_CONTROL_IDENTIFIER,
			   "Chassis Type",
			   NULL,
			   NULL,
			   &(info->chassis_type_control));
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(info->chassis_type_control, 1);
    ipmi_control_get_callbacks(info->chassis_type_control, &control_cbs);
    control_cbs.set_identifier_val = chassis_type_set;
    control_cbs.get_identifier_val = chassis_type_get;
    ipmi_control_set_settable(info->chassis_type_control, 1);
    ipmi_control_set_readable(info->chassis_type_control, 1);
    ipmi_control_set_callbacks(info->chassis_type_control, &control_cbs);

    /* The Shelf Geographic Address (GA). */
    rv = mxp_alloc_control(info->mc, info->chassis_ent,
			   MXP_SHELF_GA_CONTROL_NUM,
			   info,
			   IPMI_CONTROL_IDENTIFIER,
			   "Shelf GA",
			   NULL,
			   NULL,
			   &(info->shelf_ga_control));
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(info->shelf_ga_control, 1);
    ipmi_control_get_callbacks(info->shelf_ga_control, &control_cbs);
    control_cbs.set_identifier_val = shelf_ga_set;
    control_cbs.get_identifier_val = shelf_ga_get;
    ipmi_control_set_settable(info->shelf_ga_control, 1);
    ipmi_control_set_readable(info->shelf_ga_control, 1);
    ipmi_control_set_callbacks(info->shelf_ga_control, &control_cbs);

    /* Now the relays. */
    rv = mxp_alloc_control(info->mc, info->chassis_ent,
			   MXP_RELAY_CONTROL_NUM,
			   info,
			   IPMI_CONTROL_RELAY,
			   "Telco Relays",
			   relay_set,
			   relay_get,
			   &(info->relays));
    if (rv)
	goto out_err;
    ipmi_control_set_num_elements(info->relays, 4);

 out_err:
    return rv;
}

/***********************************************************************
 *
 * Power supply and fan specific controls and sensor start here.
 *
 **********************************************************************/
static void
ps_presence_states_get_cb(ipmi_sensor_t   *sensor,
			  mxp_sens_info_t *sens_info,
			  unsigned char   *data,
			  ipmi_states_t   *states)
{
    if (data[5] & 1)
	ipmi_set_state(states, 0, 1); /* present */
    else
	ipmi_set_state(states, 1, 1); /* absent */
}

static int
ps_presence_states_err_cb(ipmi_sensor_t   *sensor,
			  mxp_sens_info_t *sens_info,
			  int             err,
			  unsigned char   *data,
			  ipmi_states_t   *states)
{
    if (err == 0xc2) {
	ipmi_set_state(states, 1, 1); /* absent */
	return 0;
    }
    return err;
}

static void
ps_presence_states_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    mxp_sens_info_t    *get_info = cb_data;
    mxp_power_supply_t *psinfo = get_info->sdinfo;
    ipmi_msg_t         msg;
    unsigned char      data[4];
    int                rv;
    ipmi_states_t      states;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_PS_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_sensor_send_command(sensor, psinfo->info->mc, 0,
				  &msg, mxp_sensor_get_done,
				  &(get_info->sdata), get_info);
    if (rv) {
	if (get_info->done)
	    get_info->done(sensor, rv, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
    }
}

static int
ps_presence_states_get(ipmi_sensor_t       *sensor,
		       ipmi_states_read_cb done,
		       void                *cb_data)
{
    mxp_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);
    mxp_power_supply_t  *psinfo = hdr->data;
    int                 rv;
    mxp_sens_info_t     *get_info;


    get_info = alloc_sens_info(psinfo, done, cb_data);
    if (!get_info)
	return ENOMEM;
    get_info->get_states = ps_presence_states_get_cb;
    get_info->err_states = ps_presence_states_err_cb;
    get_info->min_rsp_length = 6;
    rv = ipmi_sensor_add_opq(sensor, ps_presence_states_get_start,
			     &(get_info->sdata), get_info);
    if (rv)
	ipmi_mem_free(get_info);
    return rv;
}

static void
ps_ps_states_get_cb(ipmi_sensor_t   *sensor,
		    mxp_sens_info_t *sens_info,
		    unsigned char   *data,
		    ipmi_states_t   *states)
{
    /* In the states, offset 13 is feed A failed and offset 14 is feed
       B failed. */
    ipmi_set_state(states, 13, data[6] & 0x1);
    ipmi_set_state(states, 14, (data[6] >> 1) & 0x1);

    /* Presence. */
    ipmi_set_state(states, 0, data[5] & 0x1);

    /* Power output is good.  The bit in the power supply sensor is
       a power fail sensor, so we have to invert it. */
    ipmi_set_state(states, 1, !((data[5] >> 2) & 0x1));
}

static int
ps_ps_states_err_cb(ipmi_sensor_t   *sensor,
		    mxp_sens_info_t *sens_info,
		    int             err,
		    unsigned char   *data,
		    ipmi_states_t   *states)
{
    if (err == 0xc2) {
	/* Report no presence. */
	ipmi_set_state(states, 0, 0);
	return 0;
    }
    return err;
}

static void
ps_ps_states_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    mxp_sens_info_t    *get_info = cb_data;
    mxp_power_supply_t *psinfo = get_info->sdinfo;
    ipmi_msg_t         msg;
    unsigned char      data[4];
    int                rv;
    ipmi_states_t      states;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_PS_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_sensor_send_command(sensor, psinfo->info->mc, 0,
				  &msg, mxp_sensor_get_done,
				  &(get_info->sdata), get_info);
    if (rv) {
	if (get_info->done)
	    get_info->done(sensor, rv, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }
}

static int
ps_ps_states_get(ipmi_sensor_t       *sensor,
		   ipmi_states_read_cb done,
		   void                *cb_data)
{
    mxp_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);
    mxp_power_supply_t  *psinfo = hdr->data;
    int                 rv;
    mxp_sens_info_t     *get_info;


    get_info = alloc_sens_info(psinfo, done, cb_data);
    if (!get_info)
	return ENOMEM;
    get_info->get_states = ps_ps_states_get_cb;
    get_info->err_states = ps_ps_states_err_cb;
    get_info->min_rsp_length = 7;
    rv = ipmi_sensor_add_opq(sensor, ps_ps_states_get_start,
			     &(get_info->sdata), get_info);
    if (rv)
	ipmi_mem_free(get_info);
    return rv;
}

static char *
ps_ps_reading_name_string(ipmi_sensor_t *sensor, int val)
{
    if (val == 13)
	/* Feed A offset */
	return "feed A failure";
    else if (val == 14)
	/* Feed B offset */
	return "feed B failure";
    else
	return ipmi_standard_sensor_cb.ipmi_sensor_reading_name_string(
	    sensor, val);
}

static void
ps_enable_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    ipmi_msg_t         msg;
    unsigned char      data[5];
    int                rv;

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_PS_ENABLE_CMD;
    msg.data_len = 5;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    data[4] = control_info->vals[0];
    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
ps_enable_set(ipmi_control_t     *control,
	      int                *val,
	      ipmi_control_op_cb handler,
	      void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;

    rv = ipmi_control_add_opq(control, ps_enable_set_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static int
ps_enable_get_cb(ipmi_control_t     *control,
		 mxp_control_info_t *control_info,
		 unsigned char      *data)
{
    return (data[5] >> 1) & 1;
}

static void
ps_enable_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    ipmi_msg_t         msg;
    unsigned char      data[4];
    int                rv;

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_PS_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, mxp_control_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, rv, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }
}

static int
ps_enable_get(ipmi_control_t      *control,
	      ipmi_control_val_cb handler,
	      void                *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    control_info->min_rsp_length = 6;
    control_info->get_val = ps_enable_get_cb;

    rv = ipmi_control_add_opq(control, ps_enable_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
ps_led_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[6];

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_PS_LED_CMD;
    msg.data_len = 6;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;

    /* Set which LED to set. */
    if (control == psinfo->oos_led)
	data[4] = 1;
    else
	data[4] = 2;
    data[5] = control_info->vals[0];

    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
ps_led_set(ipmi_control_t     *control,
	   int                *val,
	   ipmi_control_op_cb handler,
	   void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;

    rv = ipmi_control_add_opq(control, ps_led_set_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static int
ps_led_get_cb(ipmi_control_t     *control,
	      mxp_control_info_t *control_info,
	      unsigned char      *data)
{
    mxp_power_supply_t *psinfo = control_info->idinfo;

    /* Get the requested LED. */
    if (control == psinfo->oos_led)
	return data[4] & 1;
    else
	return (data[4] >> 1) & 1;
}

static void
ps_led_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[5];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_PS_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, mxp_control_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, rv, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
ps_led_get(ipmi_control_t      *control,
	   ipmi_control_val_cb handler,
	   void                *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    control_info->get_val = ps_led_get_cb;
    control_info->min_rsp_length = 5;

    rv = ipmi_control_add_opq(control, ps_led_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
ps_type_get_done(ipmi_control_t *control,
		 int            err,
		 ipmi_msg_t     *rsp,
		 void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

   if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ps_type_get_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control,
					     IPMI_IPMI_ERR_VAL(rsp->data[0]),
					     NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 8) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ps_type_get_done: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 8);
	if (control_info->done_get)
	    control_info->done_get(control, EINVAL, NULL,
				   control_info->cb_data);
	goto out;
    }

    if (control_info->get_identifier_val)
	control_info->get_identifier_val(control, 0,
					 rsp->data+7, 1,
					 control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
ps_type_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[5];

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_PS_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, ps_type_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, rv, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
ps_type_get(ipmi_control_t                 *control,
	    ipmi_control_identifier_val_cb handler,
	    void                           *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;

    rv = ipmi_control_add_opq(control, ps_type_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
ps_revision_get_done(ipmi_control_t *control,
		     int            err,
		     ipmi_msg_t     *rsp,
		     void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

   if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ps_revision_get_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control,
					     IPMI_IPMI_ERR_VAL(rsp->data[0]),
					     NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 10) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ps_revision_get_done: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 10);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, EINVAL, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (control_info->get_identifier_val)
	control_info->get_identifier_val(control, 0,
					 rsp->data+8, 2,
					 control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
ps_revision_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[5];

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_PS_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, ps_revision_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, rv, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
ps_revision_get(ipmi_control_t                 *control,
		ipmi_control_identifier_val_cb handler,
		void                           *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;

    rv = ipmi_control_add_opq(control, ps_revision_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
fan_presence_states_get_cb(ipmi_sensor_t   *sensor,
			   mxp_sens_info_t *sens_info,
			   unsigned char   *data,
			   ipmi_states_t   *states)
{
    if (data[5] & 1)
	ipmi_set_state(states, 0, 1); /* present */
    else
	ipmi_set_state(states, 1, 1); /* absent */
}

static int
fan_presence_states_err_cb(ipmi_sensor_t   *sensor,
			   mxp_sens_info_t *sens_info,
			   int             err,
			   unsigned char   *data,
			   ipmi_states_t   *states)
{
    if (err == 0xc2) {
	ipmi_set_state(states, 1, 1); /* absent */
	return 0;
    }
    return err;
}

static void
fan_presence_states_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    mxp_sens_info_t    *get_info = cb_data;
    mxp_power_supply_t *psinfo = get_info->sdinfo;
    ipmi_states_t      states;
    ipmi_msg_t         msg;
    unsigned char      data[4];
    int                rv;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_FAN_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_sensor_send_command(sensor, psinfo->info->mc, 0,
				  &msg, mxp_sensor_get_done,
				  &(get_info->sdata), get_info);
    if (rv) {
	if (get_info->done)
	    get_info->done(sensor, rv, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
    }
}

static int
fan_presence_states_get(ipmi_sensor_t       *sensor,
			ipmi_states_read_cb done,
			void                *cb_data)
{
    mxp_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);
    mxp_power_supply_t  *psinfo = hdr->data;
    int                 rv;
    mxp_sens_info_t     *get_info;


    get_info = alloc_sens_info(psinfo, done, cb_data);
    if (!get_info)
	return ENOMEM;
    get_info->get_states = fan_presence_states_get_cb;
    get_info->err_states = fan_presence_states_err_cb;
    get_info->min_rsp_length = 6;

    rv = ipmi_sensor_add_opq(sensor, fan_presence_states_get_start,
			     &(get_info->sdata), get_info);
    if (rv)
	ipmi_mem_free(get_info);

    return rv;
}

static void
fan_i2c_enable_states_get_cb(ipmi_sensor_t   *sensor,
			   mxp_sens_info_t *sens_info,
			   unsigned char   *data,
			   ipmi_states_t   *states)
{
    if (data[5] & 2)
	ipmi_set_state(states, 1, 1); /* enabled */
    else
	ipmi_set_state(states, 0, 1); /* disabled */
}

static void
fan_i2c_enable_states_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    mxp_sens_info_t    *get_info = cb_data;
    mxp_power_supply_t *psinfo = get_info->sdinfo;
    ipmi_states_t      states;
    ipmi_msg_t         msg;
    unsigned char      data[4];
    int                rv;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_FAN_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_sensor_send_command(sensor, psinfo->info->mc, 0,
				  &msg, mxp_sensor_get_done,
				  &(get_info->sdata), get_info);
    if (rv) {
	if (get_info->done)
	    get_info->done(sensor, rv, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
    }
}

static int
fan_i2c_enable_states_get(ipmi_sensor_t       *sensor,
			ipmi_states_read_cb done,
			void                *cb_data)
{
    mxp_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);
    mxp_power_supply_t  *psinfo = hdr->data;
    int                 rv;
    mxp_sens_info_t     *get_info;


    get_info = alloc_sens_info(psinfo, done, cb_data);
    if (!get_info)
	return ENOMEM;
    get_info->get_states = fan_i2c_enable_states_get_cb;
    get_info->min_rsp_length = 6;

    rv = ipmi_sensor_add_opq(sensor, fan_i2c_enable_states_get_start,
			     &(get_info->sdata), get_info);
    if (rv)
	ipmi_mem_free(get_info);

    return rv;
}

static void
fan_speed_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[5];

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_FAN_SPEED_CMD;
    msg.data_len = 5;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    data[4] = control_info->vals[0];

    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
fan_speed_set(ipmi_control_t     *control,
	      int                *val,
	      ipmi_control_op_cb handler,
	      void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;

    rv = ipmi_control_add_opq(control, fan_speed_set_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static int
fan_speed_get_cb(ipmi_control_t     *control,
		 mxp_control_info_t *control_info,
		 unsigned char      *data)
{
    return data[10];
}

static void
fan_speed_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[5];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_FAN_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, mxp_control_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, rv, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
fan_speed_get(ipmi_control_t      *control,
	      ipmi_control_val_cb handler,
	      void                *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    control_info->get_val = fan_speed_get_cb;
    control_info->min_rsp_length = 11;

    rv = ipmi_control_add_opq(control, fan_speed_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
fan_led_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[6];

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_FAN_LED_CMD;
    msg.data_len = 6;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;

    /* Set which LED to set. */
    if (control == psinfo->fan_oos_led)
	data[4] = 1;
    else
	data[4] = 2;
    data[5] = control_info->vals[0];

    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
fan_led_set(ipmi_control_t     *control,
	    int                *val,
	    ipmi_control_op_cb handler,
	    void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;

    rv = ipmi_control_add_opq(control, fan_led_set_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static int
fan_led_get_cb(ipmi_control_t     *control,
	       mxp_control_info_t *control_info,
	       unsigned char      *data)
{
    mxp_power_supply_t *psinfo = control_info->idinfo;

    /* Get the requested LED. */
    if (control == psinfo->fan_oos_led)
	return data[4] & 1;
    else
	return (data[4] >> 1) & 1;
}

static void
fan_led_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[5];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_FAN_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;

    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, mxp_control_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, rv, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
fan_led_get(ipmi_control_t      *control,
	   ipmi_control_val_cb handler,
	   void                *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    control_info->get_val = fan_led_get_cb;
    control_info->min_rsp_length = 5;

    rv = ipmi_control_add_opq(control, fan_led_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
fan_type_get_done(ipmi_control_t *control,
		  int            err,
		  ipmi_msg_t     *rsp,
		  void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

   if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "fan_type_get_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control,
					     IPMI_IPMI_ERR_VAL(rsp->data[0]),
					     NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 8) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "fan_type_get_done: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 8);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, EINVAL, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (control_info->get_identifier_val)
	control_info->get_identifier_val(control, 0,
					 rsp->data+7, 1,
					 control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
fan_type_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[5];

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_FAN_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, fan_type_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, rv, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
fan_type_get(ipmi_control_t                 *control,
	     ipmi_control_identifier_val_cb handler,
	     void                           *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;

    rv = ipmi_control_add_opq(control, fan_type_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
fan_revision_get_done(ipmi_control_t *control,
		      int            err,
		      ipmi_msg_t     *rsp,
		      void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

   if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "fan_revision_get_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control,
					     IPMI_IPMI_ERR_VAL(rsp->data[0]),
					     NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 10) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "fan_revision_get_done: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 10);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, EINVAL, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (control_info->get_identifier_val)
	control_info->get_identifier_val(control, 0,
					 rsp->data+8, 2,
					 control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
fan_revision_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_power_supply_t *psinfo = control_info->idinfo;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[5];

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_FAN_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_control_send_command(control, psinfo->info->mc, 0,
				   &msg, fan_revision_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, rv, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
fan_revision_get(ipmi_control_t                 *control,
		 ipmi_control_identifier_val_cb handler,
		 void                           *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_power_supply_t   *psinfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(psinfo);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;

    rv = ipmi_control_add_opq(control, fan_revision_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
mxp_fan_reading_cb(ipmi_sensor_t *sensor,
		   int           err,
		   ipmi_msg_t    *rsp,
		   void          *cb_data)
{
    mxp_reading_done_t *get_info = cb_data;
    mxp_power_supply_t *psinfo = get_info->sdinfo;
    ipmi_states_t      states;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err,
			   IPMI_NO_VALUES_PRESENT, 0, 0.0, &states,
			   get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "mxp_fan_reading_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (get_info->done)
	    get_info->done(sensor,
			   IPMI_IPMI_ERR_VAL(rsp->data[0]),
			   IPMI_NO_VALUES_PRESENT,
			   0,
			   0.0,
			   &states,
			   get_info->cb_data);
	goto out;
    }

    /* Can't get a reading, but can get the states. */
    if (sensor == psinfo->fan) {
	/* The fan sensor is being queried. */
	if (rsp->data[6] & 0x04)
	    /* A fan failure event is present. */
	    ipmi_set_threshold_out_of_range(&states, IPMI_LOWER_CRITICAL, 1);
    } else {
	/* The cooling sensor is being queried. */
	if (rsp->data[6] & 0x02)
	    /* A cooling alarm is present. */
	    ipmi_set_threshold_out_of_range(&states,
					    IPMI_UPPER_NON_CRITICAL, 1);
	if (rsp->data[6] & 0x01)
	    /* A cooling fault is present. */
	    ipmi_set_threshold_out_of_range(&states, IPMI_UPPER_CRITICAL, 1);
    }

    if (get_info->done)
	get_info->done(sensor,
		       0,
		       IPMI_NO_VALUES_PRESENT,
		       0,
		       0.0,
		       &states,
		       get_info->cb_data);

 out:
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(get_info);
}

static void
mxp_fan_reading_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    mxp_reading_done_t *get_info = cb_data;
    mxp_power_supply_t *psinfo = get_info->sdinfo;
    ipmi_msg_t         msg;
    unsigned char      data[4];
    int                rv;
    ipmi_states_t      states;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err,
			   IPMI_NO_VALUES_PRESENT, 0, 0.0, &states,
			   get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_FAN_STATUS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = psinfo->ipmb_addr;
    rv = ipmi_sensor_send_command(sensor, psinfo->info->mc, 0,
				  &msg, mxp_fan_reading_cb,
				  &(get_info->sdata), get_info);
    if (rv) {
	if (get_info->done)
	    get_info->done(sensor, rv,
			   IPMI_NO_VALUES_PRESENT, 0, 0.0, &states,
			   get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
    }
}

static int
mxp_fan_reading_get_cb(ipmi_sensor_t        *sensor,
		       ipmi_reading_done_cb done,
		       void                 *cb_data)
{
    mxp_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);
    mxp_power_supply_t  *psinfo = hdr->data;
    int                 rv;
    mxp_reading_done_t  *get_info;


    get_info = ipmi_mem_alloc(sizeof(*get_info));
    if (!get_info)
	return ENOMEM;
    get_info->sdinfo = psinfo;
    get_info->done = done;
    get_info->cb_data = cb_data;

    rv = ipmi_sensor_add_opq(sensor, mxp_fan_reading_get_start,
			     &(get_info->sdata), get_info);
    if (rv)
	ipmi_mem_free(get_info);

    return rv;
}

static int
mxp_add_power_supply_sensors(mxp_info_t         *info,
			     mxp_power_supply_t *ps)
{
    int                rv;
    unsigned int       assert, deassert;
    ipmi_control_cbs_t control_cbs;

    /* Power supply presence */
    rv = mxp_alloc_discrete_sensor(info->mc, ps->ent,
				   MXP_PS_PRESENCE_NUM(ps->idx),
				   ps, NULL,
				   IPMI_SENSOR_TYPE_ENTITY_PRESENCE,
				   IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC,
				   "presence",
				   0x3, 0x3,
				   ps_presence_states_get,
				   NULL,
				   &(ps->presence));
    if (rv)
	goto out_err;
    ipmi_sensor_set_ignore_if_no_entity(ps->presence, 0);

    /* Power supply sensor.  Offset 0 and 1 are standard presence and
       failure bits.  Offsets 13 and 14 are a-feed and b-feed
       sensors. */
    rv = mxp_alloc_discrete_sensor(
	info->mc, ps->ent,
	MXP_PS_PS_NUM(ps->idx),
	ps, NULL,
	IPMI_SENSOR_TYPE_POWER_SUPPLY,
	IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC,
	"Power Supply",
	0x6003, 0x6003,
	ps_ps_states_get,
	ps_ps_reading_name_string,
	&(ps->ps));
    if (rv)
	goto out_err;

    /* Enabled control */
    rv = mxp_alloc_control(info->mc, ps->ent,
			   MXP_PS_ENABLE_NUM(ps->idx),
			   ps,
			   IPMI_CONTROL_POWER,
			   "enable",
			   ps_enable_set,
			   ps_enable_get,
			   &(ps->enable));
    if (rv)
	goto out_err;
    ipmi_control_set_num_elements(ps->enable, 1);
		       
    /* LED controls */
    rv = mxp_alloc_control(info->mc, ps->ent,
			   MXP_PS_OOS_LED_NUM(ps->idx),
			   ps,
			   IPMI_CONTROL_LIGHT,
			   "OOS LED",
			   ps_led_set,
			   ps_led_get,
			   &(ps->oos_led));
    if (rv)
	goto out_err;
    ipmi_control_light_set_lights(ps->oos_led, 1, red_led);

    rv = mxp_alloc_control(info->mc, ps->ent,
			   MXP_PS_INS_LED_NUM(ps->idx),
			   ps,
			   IPMI_CONTROL_LIGHT,
			   "InS LED",
			   ps_led_set,
			   ps_led_get,
			   &(ps->inserv_led));
    if (rv)
	goto out_err;
    ipmi_control_light_set_lights(ps->inserv_led, 1, green_led);

    /* Power Supply Type ID */
    rv = mxp_alloc_control(info->mc, ps->ent,
			   MXP_PS_TYPE_NUM(ps->idx),
			   ps,
			   IPMI_CONTROL_IDENTIFIER,
			   "type",
			   NULL,
			   NULL,
			   &ps->ps_type);
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(ps->ps_type, 1);
    ipmi_control_get_callbacks(ps->ps_type, &control_cbs);
    control_cbs.get_identifier_val = ps_type_get;
    ipmi_control_set_readable(ps->ps_type, 1);
    ipmi_control_set_callbacks(ps->ps_type, &control_cbs);

    /* Power Supply Revision */
    rv = mxp_alloc_control(info->mc, ps->ent,
			   MXP_PS_REVISION_NUM(ps->idx),
			   ps,
			   IPMI_CONTROL_IDENTIFIER,
			   "revision",
			   NULL,
			   NULL,
			   &ps->ps_revision);
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(ps->ps_revision, 2);
    ipmi_control_get_callbacks(ps->ps_revision, &control_cbs);
    control_cbs.get_identifier_val = ps_revision_get;
    ipmi_control_set_readable(ps->ps_revision, 1);
    ipmi_control_set_callbacks(ps->ps_revision, &control_cbs);

    /* Fan presence sensor */
    rv = mxp_alloc_discrete_sensor(info->mc, ps->fan_ent,
				   MXP_FAN_PRESENCE_NUM(ps->idx),
				   ps, NULL,
				   IPMI_SENSOR_TYPE_ENTITY_PRESENCE,
				   IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC,
				   "presence",
				   0x7, 0,
				   fan_presence_states_get,
				   NULL,
				   &(ps->fan_presence));
    if (rv)
	goto out_err;
    ipmi_sensor_set_ignore_if_no_entity(ps->fan_presence, 0);

    /* Fan I2C enable sensor */
    rv = mxp_alloc_discrete_sensor(info->mc, ps->fan_ent,
				   MXP_FAN_I2C_ENABLE_NUM(ps->idx),
				   ps, NULL,
				   IPMI_SENSOR_TYPE_CABLE_INTERCONNECT,
				   IPMI_EVENT_READING_TYPE_DISCRETE_DEVICE_ENABLE,
				   "I2C Enable",
				   0x3, 0,
				   fan_i2c_enable_states_get,
				   NULL,
				   &(ps->fan_i2c_enable));
    if (rv)
	goto out_err;
    ipmi_sensor_set_ignore_if_no_entity(ps->fan_presence, 0);

    /* Fan speed sensor */
    assert = 1 << ((IPMI_LOWER_CRITICAL * 2) + IPMI_GOING_LOW);
    deassert = 1 << ((IPMI_LOWER_CRITICAL * 2) + IPMI_GOING_LOW);
    rv = mxp_alloc_threshold_sensor(info->mc, ps->fan_ent,
				    MXP_FAN_SPEED_NUM(ps->idx),
				    ps, NULL,
				    IPMI_SENSOR_TYPE_FAN,
				    IPMI_UNIT_TYPE_RPM,
				    "speed",
				    assert, deassert,
				    mxp_fan_reading_get_cb,
				    -1, -1, -1,
				    &(ps->fan));
    if (rv)
	goto out_err;

    /* Cooling sensor */
    assert = ((1 << ((IPMI_UPPER_NON_CRITICAL * 2) + IPMI_GOING_HIGH))
	      | (1 << ((IPMI_UPPER_CRITICAL * 2) + IPMI_GOING_HIGH)));
    deassert = ((1 << ((IPMI_UPPER_NON_CRITICAL * 2) + IPMI_GOING_HIGH))
		| (1 << ((IPMI_UPPER_CRITICAL * 2) + IPMI_GOING_HIGH)));
    rv = mxp_alloc_threshold_sensor(info->mc, ps->fan_ent,
				    MXP_FAN_COOLING_NUM(ps->idx),
				    ps, NULL,
				    IPMI_SENSOR_TYPE_COOLING_DEVICE,
				    IPMI_UNIT_TYPE_UNSPECIFIED,
				    "cooling",
				    assert, deassert,
				    mxp_fan_reading_get_cb,
				    -1, -1, -1,
				    &(ps->cooling));
    if (rv)
	goto out_err;

    /* Fan speed control */
    rv = mxp_alloc_control(info->mc, ps->fan_ent,
			   MXP_FAN_SPEEDCONTROL_NUM(ps->idx),
			   ps,
			   IPMI_CONTROL_FAN_SPEED,
			   "speed",
			   fan_speed_set,
			   fan_speed_get,
			   &(ps->fan_speed));
    if (rv)
	goto out_err;
    ipmi_control_set_num_elements(ps->fan_speed, 1);

    /* FAN LED controls. */
    rv = mxp_alloc_control(info->mc, ps->fan_ent,
			   MXP_FAN_OOS_LED_NUM(ps->idx),
			   ps,
			   IPMI_CONTROL_LIGHT,
			   "OOS LED",
			   fan_led_set,
			   fan_led_get,
			   &(ps->fan_oos_led));
    if (rv)
	goto out_err;
    ipmi_control_light_set_lights(ps->fan_oos_led, 1, red_led);

    rv = mxp_alloc_control(info->mc, ps->fan_ent,
			   MXP_FAN_INS_LED_NUM(ps->idx),
			   ps,
			   IPMI_CONTROL_LIGHT,
			   "InS LED",
			   fan_led_set,
			   fan_led_get,
			   &(ps->fan_inserv_led));
    if (rv)
	goto out_err;
    ipmi_control_light_set_lights(ps->fan_inserv_led, 1, red_led);
		       
    /* Fan Type ID */
    rv = mxp_alloc_control(info->mc, ps->fan_ent,
			   MXP_FAN_TYPE_NUM(ps->idx),
			   ps,
			   IPMI_CONTROL_IDENTIFIER,
			   "type",
			   NULL,
			   NULL,
			   &ps->fan_type);
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(ps->fan_type, 1);
    ipmi_control_get_callbacks(ps->fan_type, &control_cbs);
    control_cbs.get_identifier_val = fan_type_get;
    ipmi_control_set_readable(ps->fan_type, 1);
    ipmi_control_set_callbacks(ps->fan_type, &control_cbs);

    /* Fan Revision */
    rv = mxp_alloc_control(info->mc, ps->fan_ent,
			   MXP_FAN_REVISION_NUM(ps->idx),
			   ps,
			   IPMI_CONTROL_IDENTIFIER,
			   "revision",
			   NULL,
			   NULL,
			   &ps->fan_revision);
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(ps->fan_revision, 1);
    ipmi_control_get_callbacks(ps->fan_revision, &control_cbs);
    control_cbs.get_identifier_val = fan_revision_get;
    ipmi_control_set_readable(ps->fan_revision, 1);
    ipmi_control_set_callbacks(ps->fan_revision, &control_cbs);

    /* Voltage sensors */
    /* There aren't any */

 out_err:
    return rv;
}

/***********************************************************************
 *
 * Board sensors and controls handled by the AMC start here.
 *
 **********************************************************************/

static void
board_presence_states_get_cb(ipmi_sensor_t   *sensor,
			     mxp_sens_info_t *sens_info,
			     unsigned char   *data,
			     ipmi_states_t   *states)
{
    mxp_board_t *binfo = sens_info->sdinfo;

    if (data[4] & 1) {
	ipmi_set_state(states, 0, 1); /* present */

	if (!binfo->presence_read) {
	    binfo->presence_read = 1;
	    ipmi_start_ipmb_mc_scan(binfo->info->domain, 0,
				    binfo->ipmb_addr, binfo->ipmb_addr,
				    NULL, NULL);
	}
    } else
	ipmi_set_state(states, 1, 1); /* absent */
}

static void
board_presence_states_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    mxp_sens_info_t    *get_info = cb_data;
    mxp_board_t        *binfo = get_info->sdinfo;
    ipmi_msg_t         msg;
    int                rv;
    ipmi_states_t      states;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    if (binfo->is_amc) {
	int i = binfo->idx - MXP_ALARM_CARD_IDX_OFFSET;
	ipmi_system_interface_addr_t si;
	ipmi_mc_t                    *mc;

	si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si.channel = i;
	si.lun = 0;
	mc = _ipmi_find_mc_by_addr(binfo->info->domain,
				   (ipmi_addr_t *) &si, sizeof(si));
	if (mc)
	    binfo->info->amc_present[i] = 1;
	else 
	    binfo->info->amc_present[i] = 0;
	
	if (binfo->info->amc_present[i])
	    ipmi_set_state(&states, 0, 1); /* present */
	else
	    ipmi_set_state(&states, 1, 1); /* absent */

	if (get_info->done)
	    get_info->done(sensor, 0, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
    } else {
	unsigned char data[4];

	msg.netfn = MXP_NETFN_MXP1;
	msg.cmd = MXP_OEM_GET_SLOT_SIGNALS_CMD;
	msg.data_len = 4;
	msg.data = data;
	add_mxp_mfg_id(data);
	data[3] = binfo->ipmb_addr;
	rv = ipmi_sensor_send_command(sensor, binfo->info->mc, 0,
				      &msg, mxp_sensor_get_done,
				      &(get_info->sdata), get_info);
	if (rv) {
	    if (get_info->done)
		get_info->done(sensor, rv, &states, get_info->cb_data);
	    ipmi_sensor_opq_done(sensor);
	    ipmi_mem_free(get_info);
	    return;
	}
    }
}

static int
board_presence_states_get(ipmi_sensor_t       *sensor,
			  ipmi_states_read_cb done,
			  void                *cb_data)
{
    mxp_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);
    mxp_board_t         *binfo = hdr->data;
    int                 rv;
    mxp_sens_info_t     *get_info;


    get_info = alloc_sens_info(binfo, done, cb_data);
    if (!get_info)
	return ENOMEM;
    get_info->sens_id = ipmi_sensor_convert_to_id(sensor);
    get_info->get_states = board_presence_states_get_cb;
    get_info->min_rsp_length = 5;

    rv = ipmi_sensor_add_opq(sensor, board_presence_states_get_start,
			     &(get_info->sdata), get_info);
    if (rv)
	ipmi_mem_free(get_info);

    return rv;
}

static void
board_led_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_board_t        *binfo = control_info->idinfo;
    mxp_info_t         *info = binfo->info;
    ipmi_msg_t         msg;
    unsigned char      data[6];
    int                rv;

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_SLOT_LED_CMD;
    msg.data_len = 6;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = fix_led_addr(info, binfo->ipmb_addr,
			   binfo->idx - MXP_ALARM_CARD_IDX_OFFSET);
    if (control == binfo->oos_led)
	data[4] = 1;
    else
	data[4] = 2;
    data[5] = control_info->vals[0];

    rv = ipmi_control_send_command(control, binfo->info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
board_led_set(ipmi_control_t     *control,
	      int                *val,
	      ipmi_control_op_cb handler,
	      void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_board_t          *binfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(binfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;
    rv = ipmi_control_add_opq(control, board_led_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static int
board_led_get_cb(ipmi_control_t     *control,
		 mxp_control_info_t *control_info,
		 unsigned char      *data)
{
    mxp_board_t *binfo = control_info->idinfo;
    mxp_info_t  *info = binfo->info;
    int         idx;
    int         shift;

    if (binfo->idx >= MXP_IP_SWITCH_IDX_OFFSET) {
	/* It's a switch card. */
	idx = 0;
	shift = 2 - ((binfo->idx - MXP_IP_SWITCH_IDX_OFFSET) * 2);
    } else if (binfo->idx >= MXP_ALARM_CARD_IDX_OFFSET) {
	/* It's an alarm card. */
	idx = 0;
	if (info->chassis_config == MXP_CHASSIS_CONFIG_6U)
	    shift = 4;
	else
	    shift = 6 - ((binfo->idx - MXP_ALARM_CARD_IDX_OFFSET) * 2);
    } else {
	int i = binfo->idx - MXP_BOARD_IDX_OFFSET;
	/* It's a payload board. */
	idx = i / 4;
	shift = 6 - ((i % 4) * 2);
	idx++; /* Skip over the switch and AMC LEDs. */
    }

    if (control == binfo->oos_led)
	return (data[idx+4] >> shift) & 0x3;
    else
	return (data[idx+10] >> shift) & 0x3;
}

static void
board_led_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t   *control_info = cb_data;
    mxp_board_t          *binfo = control_info->idinfo;
    int                  rv;
    ipmi_msg_t           msg;
    unsigned char        data[3];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_ALL_SLOT_LED_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, binfo->info->mc, 0,
				   &msg, mxp_control_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }
}

static int
board_led_get(ipmi_control_t      *control,
	      ipmi_control_val_cb handler,
	      void                *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_board_t          *binfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(binfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    control_info->get_val = board_led_get_cb;
    control_info->min_rsp_length = 21;

    rv = ipmi_control_add_opq(control, board_led_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
bd_sel_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_board_t        *binfo = control_info->idinfo;
    ipmi_msg_t         msg;
    unsigned char      data[5];
    int                rv;

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_BDSEL_CMD;
    msg.data_len = 5;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = binfo->ipmb_addr;
    data[4] = control_info->vals[0];

    rv = ipmi_control_send_command(control, binfo->info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
bd_sel_set(ipmi_control_t     *control,
	   int                *val,
	   ipmi_control_op_cb handler,
	   void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_board_t          *binfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(binfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;
    rv = ipmi_control_add_opq(control, bd_sel_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static int
bd_sel_get_cb(ipmi_control_t     *control,
	      mxp_control_info_t *control_info,
	      unsigned char      *data)
{
    return (data[4] >> 2) & 1;
}

static void
bd_sel_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t   *control_info = cb_data;
    mxp_board_t          *binfo = control_info->idinfo;
    int                  rv;
    ipmi_msg_t           msg;
    unsigned char        data[4];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_SLOT_SIGNALS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = binfo->ipmb_addr;
    rv = ipmi_control_send_command(control, binfo->info->mc, 0,
				   &msg, mxp_control_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }
}

static int
bd_sel_get(ipmi_control_t      *control,
	   ipmi_control_val_cb handler,
	   void                *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_board_t          *binfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(binfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    control_info->get_val = bd_sel_get_cb;
    control_info->min_rsp_length = 21;

    rv = ipmi_control_add_opq(control, bd_sel_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
pci_reset_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_board_t        *binfo = control_info->idinfo;
    ipmi_msg_t         msg;
    unsigned char      data[5];
    int                rv;

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_PCIRST_CMD;
    msg.data_len = 5;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = binfo->ipmb_addr;
    data[4] = control_info->vals[0];

    rv = ipmi_control_send_command(control, binfo->info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
pci_reset_set(ipmi_control_t     *control,
	      int                *val,
	      ipmi_control_op_cb handler,
	      void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_board_t          *binfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(binfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;
    rv = ipmi_control_add_opq(control, pci_reset_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static int
pci_reset_get_cb(ipmi_control_t     *control,
		 mxp_control_info_t *control_info,
		 unsigned char      *data)
{
    return (data[4] >> 3) & 1;
}

static void
pci_reset_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t   *control_info = cb_data;
    mxp_board_t          *binfo = control_info->idinfo;
    int                  rv;
    ipmi_msg_t           msg;
    unsigned char        data[4];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_SLOT_SIGNALS_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = binfo->ipmb_addr;
    rv = ipmi_control_send_command(control, binfo->info->mc, 0,
				   &msg, mxp_control_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }
}

static int
pci_reset_get(ipmi_control_t      *control,
	      ipmi_control_val_cb handler,
	      void                *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_board_t          *binfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(binfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    control_info->get_val = pci_reset_get_cb;
    control_info->min_rsp_length = 5;

    rv = ipmi_control_add_opq(control, pci_reset_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
slot_init_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_board_t        *binfo = control_info->idinfo;
    ipmi_msg_t         msg;
    unsigned char      data[4];
    int                rv;

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_SLOT_INIT_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = binfo->ipmb_addr;


    rv = ipmi_control_send_command(control, binfo->info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
slot_init_set(ipmi_control_t     *control,
	      int                *val,
	      ipmi_control_op_cb handler,
	      void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_board_t          *binfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    if (*val == 0)
	return EINVAL;

    control_info = alloc_control_info(binfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;
    rv = ipmi_control_add_opq(control, slot_init_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
i2c_isolate_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    mxp_board_t        *binfo = control_info->idinfo;
    ipmi_msg_t         msg;
    unsigned char      data[5];
    int                rv;

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_IPMB_ISOLATE_CMD;
    msg.data_len = 5;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = binfo->ipmb_addr;
    data[4] = control_info->vals[0];

    rv = ipmi_control_send_command(control, binfo->info->mc, 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
i2c_isolate_set(ipmi_control_t     *control,
		int                *val,
		ipmi_control_op_cb handler,
		void               *cb_data)
{
    mxp_control_header_t *hdr = ipmi_control_get_oem_info(control);
    mxp_board_t          *binfo = hdr->data;
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(binfo);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;
    rv = ipmi_control_add_opq(control, i2c_isolate_set_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static int
mxp_add_board_sensors(mxp_info_t  *info,
		      mxp_board_t *board)
{
    int rv;

    /* Presence sensor */
    rv = mxp_alloc_discrete_sensor(board->info->mc, board->ent,
				   MXP_BOARD_PRESENCE_NUM(board->idx),
				   board, NULL,
				   IPMI_SENSOR_TYPE_ENTITY_PRESENCE,
				   IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC,
				   "presence",
				   0x3, 0x3,
				   board_presence_states_get,
				   NULL,
				   &(board->presence));
    if (rv)
	goto out_err;
    ipmi_sensor_set_ignore_if_no_entity(board->presence, 0);

    /* out-of-service LED control */
    rv = mxp_alloc_control(board->info->mc, board->ent,
			   MXP_BOARD_OOS_LED_NUM(board->idx),
			   board,
			   IPMI_CONTROL_LIGHT,
			   "OOS LED",
			   board_led_set,
			   board_led_get,
			   &(board->oos_led));
    if (rv)
	goto out_err;
    ipmi_control_light_set_lights(board->oos_led, 1, red_led);
    ipmi_control_set_ignore_if_no_entity(board->oos_led, 0);

    /* in-service LED control */
    rv = mxp_alloc_control(board->info->mc, board->ent,
			   MXP_BOARD_INS_LED_NUM(board->idx),
			   board,
			   IPMI_CONTROL_LIGHT,
			   "InS LED",
			   board_led_set,
			   board_led_get,
			   &(board->inserv_led));
    if (rv)
	goto out_err;
    ipmi_control_light_set_lights(board->inserv_led, 1, green_led);
    ipmi_control_set_ignore_if_no_entity(board->inserv_led, 0);

    if (!board->is_amc) {
	/* Board Select control */
	rv = mxp_alloc_control(board->info->mc, board->ent,
			       MXP_BOARD_BD_SEL_NUM(board->idx),
			       board,
			       IPMI_CONTROL_POWER,
			       "Bd Sel",
			       bd_sel_set,
			       bd_sel_get,
			       &(board->bd_sel));
	if (rv)
	    goto out_err;
	ipmi_control_set_num_elements(board->bd_sel, 1);

	/* PCI Reset control */
	rv = mxp_alloc_control(board->info->mc, board->ent,
			       MXP_BOARD_PCI_RESET_NUM(board->idx),
			       board,
			       IPMI_CONTROL_RESET,
			       "PCI Reset",
			       pci_reset_set,
			       pci_reset_get,
			       &(board->pci_reset));
	if (rv)
	    goto out_err;
	ipmi_control_set_num_elements(board->pci_reset, 1);

	/* Slot init control */
	rv = mxp_alloc_control(board->info->mc, board->ent,
			       MXP_SLOT_INIT_NUM(board->idx),
			       board,
			       IPMI_CONTROL_ONE_SHOT_OUTPUT,
			       "Slot Init",
			       slot_init_set,
			       NULL,
			       &(board->slot_init));
	if (rv)
	    goto out_err;
	ipmi_control_set_num_elements(board->slot_init, 1);

	/* I2C enable control */
	rv = mxp_alloc_control(board->info->mc, board->ent,
			       MXP_SLOT_I2C_ISOLATE_NUM(board->idx),
			       board,
			       IPMI_CONTROL_OUTPUT,
			       "I2C Isolate",
			       i2c_isolate_set,
			       NULL,
			       &(board->i2c_isolate));
	if (rv)
	    goto out_err;
	ipmi_control_set_num_elements(board->i2c_isolate, 1);
    }

 out_err:
    return rv;
}

/***********************************************************************
 *
 * The main code to add all the entities, sensors and controls that
 * the AMC handles.
 *
 **********************************************************************/

static int
mxp_entity_sdr_add(ipmi_entity_t   *ent,
		   ipmi_sdr_info_t *sdrs,
		   void            *cb_data)
{
    /* Don't put the entities into an SDR */
    return 0;
}

static char *board_entity_str[MXP_TOTAL_BOARDS] =
{
    "BD01",
    "BD02",
    "BD03",
    "BD04",
    "BD05",
    "BD06",
    "BD07",
    "BD08",
    "BD09",
    "BD10",
    "BD11",
    "BD12",
    "BD13",
    "BD14",
    "BD15",
    "BD16",
    "BD17",
    "BD18",
    "AMC1",
    "AMC2",
    "SW 1",
    "SW 2",
};

static char *ps_entity_str[MXP_POWER_SUPPLIES] =
{
    "PS 1",
    "PS 2",
    "PS 3",
};

static char *fan_entity_str[MXP_POWER_SUPPLIES] =
{
    "FAN 1",
    "FAN 2",
    "FAN 3",
};

static int
mxp_create_entities(ipmi_mc_t  *mc,
		    mxp_info_t *info)
{
    int                rv;
    ipmi_entity_info_t *ents;
    int                i;
    int                ipmb_addr;
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    char               *name;

    ipmi_domain_entity_lock(domain);

    ents = ipmi_domain_get_entities(domain);
    name = "Chassis";
    rv = ipmi_entity_add(ents, domain, mc, 0,
			 IPMI_ENTITY_ID_SYSTEM_CHASSIS, 1,
			 name, IPMI_ASCII_STR, strlen(name),
			 mxp_entity_sdr_add,
			 NULL, &(info->chassis_ent));
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "mxp_create_entities: Could not add chassis entity: %x",
		 rv);
	goto out;
    }
    rv = mxp_add_chassis_sensors(info);
    if (rv)
	goto out;

    for (i=0; i<MXP_ALARM_CARDS; i++) {
	int idx = MXP_ALARM_CARD_IDX_OFFSET + i;
	ipmb_addr = 0x20;
	name = board_entity_str[idx];
	rv = ipmi_entity_add(ents, domain, info->mc, 0,
			     MXP_ENTITY_ID_ALARM_CARD,
			     i+1,
			     name, IPMI_ASCII_STR, strlen(name),
			     mxp_entity_sdr_add,
			     NULL, &(info->board[idx].ent));
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "mxp_create_entities: Could not add alarm card: %x",
		     rv);
	    goto out;
	}
	ipmi_entity_set_type(info->board[idx].ent, IPMI_ENTITY_MC);
	ipmi_entity_set_FRU_inventory_device(info->board[idx].ent, 1);
	ipmi_entity_set_is_logical_fru(info->board[idx].ent, 1);
	ipmi_entity_set_access_address(info->board[idx].ent, ipmb_addr);
	ipmi_entity_set_fru_device_id(info->board[idx].ent, 0);
	ipmi_entity_set_lun(info->board[idx].ent, 0);
	ipmi_entity_set_private_bus_id(info->board[idx].ent, 0);
	ipmi_entity_set_channel(info->board[idx].ent, 0);
	ipmi_entity_fetch_frus(info->board[idx].ent);
	info->board[idx].info = info;
	info->board[idx].idx = idx;
	info->board[idx].is_amc = 1;
	info->board[idx].ipmb_addr = ipmb_addr;
	/* We don't scan the BMC, because scanning the BMC doesn't
	   work and we have other ways to detect it's presence. */
	info->board[idx].presence_read = 1;

	rv = ipmi_entity_add_child(info->chassis_ent,
				   info->board[idx].ent);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "mxp_create_entities: add child alarm card: %x",
		     rv);
	    goto out;
	}
	rv = mxp_add_board_sensors(info, &(info->board[idx]));
	if (rv)
	    goto out;
    }

    for (i=0; i<MXP_IP_SWITCHES; i++) {
	int idx = i + MXP_IP_SWITCH_IDX_OFFSET;

	if (info->chassis_config == MXP_CHASSIS_CONFIG_6U)
	    ipmb_addr = 0xb2 + (i*2);
	else
	    ipmb_addr = 0xe4 + (i*2);

	name = board_entity_str[idx];
	rv = ipmi_entity_add(ents, domain, info->mc, 0,
			     IPMI_ENTITY_ID_CONNECTIVITY_SWITCH,
			     i+1,
			     name, IPMI_ASCII_STR, strlen(name),
			     mxp_entity_sdr_add,
			     NULL, &(info->board[idx].ent));
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "mxp_create_entities: Could not add ip switch: %x",
		     rv);
	    goto out;
	}
	ipmi_entity_set_type(info->board[idx].ent, IPMI_ENTITY_MC);
	ipmi_entity_set_FRU_inventory_device(info->board[idx].ent, 1);
	ipmi_entity_set_is_logical_fru(info->board[idx].ent, 1);
	ipmi_entity_set_access_address(info->board[idx].ent, ipmb_addr);
	ipmi_entity_set_fru_device_id(info->board[idx].ent, 0);
	ipmi_entity_set_lun(info->board[idx].ent, 0);
	ipmi_entity_set_private_bus_id(info->board[idx].ent, 0);
	ipmi_entity_set_channel(info->board[idx].ent, 0);
	info->board[idx].info = info;
	info->board[idx].idx = idx;
	info->board[idx].is_amc = 0;
	info->board[idx].ipmb_addr = ipmb_addr;
	rv = ipmi_entity_add_child(info->chassis_ent,
				   info->board[idx].ent);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "mxp_create_entities: add child alarm card: %x",
		     rv);
	    goto out;
	}
	rv = mxp_add_board_sensors(info, &(info->board[idx]));
	if (rv)
	    goto out;
    }

    for (i=0; i<MXP_POWER_SUPPLIES; i++) {
	ipmb_addr = 0x54 + (i*2);
	info->power_supply[i].ipmb_addr = ipmb_addr;

	name = ps_entity_str[i];
	rv = ipmi_entity_add(ents, domain, info->mc, 0,
			     IPMI_ENTITY_ID_POWER_SUPPLY,
			     i+1,
			     name, IPMI_ASCII_STR, strlen(name),
			     mxp_entity_sdr_add,
			     NULL, &(info->power_supply[i].ent));
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "mxp_create_entities: Could not add power supply: %x",
		     rv);
	    goto out;
	}
	ipmi_entity_set_type(info->power_supply[i].ent, IPMI_ENTITY_FRU);
	/* FIXME - is there FRU information someplace? */
	name = fan_entity_str[i];
	rv = ipmi_entity_add(ents, domain, info->mc, 0,
			     IPMI_ENTITY_ID_FAN_COOLING,
			     i+1,
			     name, IPMI_ASCII_STR, strlen(name),
			     mxp_entity_sdr_add,
			     NULL, &(info->power_supply[i].fan_ent));
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "mxp_create_entities: Could not add power supply: %x",
		     rv);
	    goto out;
	}
	info->power_supply[i].info = info;
	info->power_supply[i].idx = i;

	rv = ipmi_entity_add_child(info->chassis_ent,
				   info->power_supply[i].ent);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "mxp_create_entities: add child power supply: %x",
		     rv);
	    goto out;
	}
	rv = ipmi_entity_add_child(info->power_supply[i].ent,
				   info->power_supply[i].fan_ent);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "mxp_create_entities: add child fan: %x",
		     rv);
	    goto out;
	}
	rv = mxp_add_power_supply_sensors(info, &(info->power_supply[i]));
	if (rv)
	    goto out;
    }

    for (i=0; i<MXP_BOARDS; i++) {
	int idx = i + MXP_BOARD_IDX_OFFSET;
	if (info->chassis_config == MXP_CHASSIS_CONFIG_6U)
	    ipmb_addr = 0xB6 + (i*2);
	else
	    ipmb_addr = 0xB0 + (i*2);
	if (ipmb_addr >= 0xc2)
	    ipmb_addr += 2;

	name = board_entity_str[idx];
	rv = ipmi_entity_add(ents, domain, info->mc, 0,
			     IPMI_ENTITY_ID_PROCESSING_BLADE,
			     mxp_addr_to_instance(ipmb_addr),
			     name, IPMI_ASCII_STR, strlen(name),
			     mxp_entity_sdr_add,
			     NULL, &(info->board[idx].ent));
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "mxp_create_entities: Could not add board: %x",
		     rv);
	    goto out;
	}
	ipmi_entity_set_type(info->board[idx].ent, IPMI_ENTITY_MC);
	ipmi_entity_set_FRU_inventory_device(info->board[idx].ent, 1);
	ipmi_entity_set_is_logical_fru(info->board[idx].ent, 1);
	ipmi_entity_set_access_address(info->board[idx].ent, ipmb_addr);
	ipmi_entity_set_fru_device_id(info->board[idx].ent, 0);
	ipmi_entity_set_lun(info->board[idx].ent, 0);
	ipmi_entity_set_private_bus_id(info->board[idx].ent, 0);
	ipmi_entity_set_channel(info->board[idx].ent, 0);
	info->board[idx].info = info;
	info->board[idx].idx = idx;
	info->board[idx].is_amc = 0;
	info->board[idx].ipmb_addr = ipmb_addr;
	rv = ipmi_entity_add_child(info->chassis_ent, info->board[idx].ent);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "mxp_create_entities: add child board: %x",
		     rv);
	    goto out;
	}
	rv = mxp_add_board_sensors(info, &(info->board[idx]));
	if (rv)
	    goto out;
    }

 out:
    ipmi_domain_entity_unlock(domain);
    return rv;
}

/***********************************************************************
 *
 * Handling for sensors and controls that are on a board.  Note that
 * the blue led and slot code is also used by the AMC code.
 *
 **********************************************************************/

static void
board_reset_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[4];

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_SLOT_RESET_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = control_info->vals[0];
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
board_reset_set(ipmi_control_t     *control,
		int                *val,
		ipmi_control_op_cb handler,
		void               *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;

    rv = ipmi_control_add_opq(control, board_reset_set_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
board_power_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[4];

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_SLOT_POWER_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = control_info->vals[0];
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
board_power_set(ipmi_control_t     *control,
		int                *val,
		ipmi_control_op_cb handler,
		void               *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;

    rv = ipmi_control_add_opq(control, board_power_set_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static int
board_power_get_cb(ipmi_control_t     *control,
		   mxp_control_info_t *control_info,
		   unsigned char      *data)
{
    return data[5];
}

static void
board_power_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[3];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_SLOT_HS_STATUS_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, mxp_control_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, rv, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
board_power_get(ipmi_control_t      *control,
		ipmi_control_val_cb handler,
		void                *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    control_info->get_val = board_power_get_cb;
    control_info->min_rsp_length = 6;

    rv = ipmi_control_add_opq(control, board_power_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
board_slot_get_cb(ipmi_sensor_t   *sensor,
		  mxp_sens_info_t *sens_info,
		  unsigned char   *data,
		  ipmi_states_t   *states)
{
    if (data[5] & 1)
	ipmi_set_state(states, 5, 0); /* power is not off */
    else
	ipmi_set_state(states, 5, 1); /* power is off */

    if (data[13])
	ipmi_set_state(states, 6, 1); /* Ejector extraction request */
    else
	ipmi_set_state(states, 6, 0); /* Ejector is closed */
}

static void
board_slot_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    mxp_sens_info_t *get_info = cb_data;
    ipmi_msg_t      msg;
    unsigned char   data[3];
    int             rv;
    ipmi_states_t   states;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_SLOT_HS_STATUS_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_sensor_send_command(sensor, ipmi_sensor_get_mc(sensor), 0,
				  &msg, mxp_sensor_get_done,
				  &(get_info->sdata), get_info);
    if (rv) {
	if (get_info->done)
	    get_info->done(sensor, rv, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
    }
}

static int
board_slot_get(ipmi_sensor_t       *sensor,
	       ipmi_states_read_cb done,
	       void                *cb_data)
{
    int                 rv;
    mxp_sens_info_t     *get_info;

    get_info = alloc_sens_info(NULL, done, cb_data);
    if (!get_info)
	return ENOMEM;
    get_info->get_states = board_slot_get_cb;
    get_info->min_rsp_length = 14;

    rv = ipmi_sensor_add_opq(sensor, board_slot_get_start,
			     &(get_info->sdata), get_info);
    if (rv)
	ipmi_mem_free(get_info);

    return rv;
}

static void
board_blue_led_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[4];

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_SLOT_BLUE_LED_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = control_info->vals[0];
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
board_blue_led_set(ipmi_control_t     *control,
		   int                *val,
		   ipmi_control_op_cb handler,
		   void               *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;

    rv = ipmi_control_add_opq(control, board_blue_led_set_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static int
board_blue_led_get_cb(ipmi_control_t     *control,
		      mxp_control_info_t *control_info,
		      unsigned char      *data)
{
    return data[12];
}

static void
board_blue_led_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[3];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_SLOT_HS_STATUS_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, mxp_control_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, rv, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
board_blue_led_get(ipmi_control_t      *control,
		   ipmi_control_val_cb handler,
		   void                *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    control_info->get_val = board_blue_led_get_cb;
    control_info->min_rsp_length = 13;

    rv = ipmi_control_add_opq(control, board_blue_led_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
board_power_config_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[6];

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_POWER_CONFIG_CMD;
    msg.data_len = 6;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = control_info->vals[0];
    data[4] = control_info->vals[1];
    data[5] = control_info->vals[2];
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
board_power_config_set(ipmi_control_t     *control,
		   int                *val,
		   ipmi_control_op_cb handler,
		   void               *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = val[0];
    control_info->vals[1] = val[1];
    control_info->vals[2] = val[2];

    rv = ipmi_control_add_opq(control, board_power_config_set_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
board_power_config_get_done(ipmi_control_t *control,
		       int            err,
		       ipmi_msg_t     *rsp,
		       void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                val[3];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "board_power_config_get_done: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->done_get)
	    control_info->done_get(control,
				   IPMI_IPMI_ERR_VAL(rsp->data[0]),
				   NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 9) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "board_power_config_get_done: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 5);
	if (control_info->done_get)
	    control_info->done_get(control, EINVAL, NULL,
				   control_info->cb_data);
	goto out;
    }

    val[0] = rsp->data[7]; /* MXP/CPCI mode. */
    val[1] = rsp->data[8]; /* Wait for command */
    val[2] = rsp->data[6]; /* Power delay */
    if (control_info->done_get)
	control_info->done_get(control, 0, val, control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
board_power_config_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[3];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_SLOT_HS_STATUS_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, board_power_config_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, rv, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
board_power_config_get(ipmi_control_t      *control,
		   ipmi_control_val_cb handler,
		   void                *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;

    rv = ipmi_control_add_opq(control, board_power_config_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
slot_ga_get_done(ipmi_control_t *control,
		 int            err,
		 ipmi_msg_t     *rsp,
		 void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "last_reset_reason_get_done: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control,
					     IPMI_IPMI_ERR_VAL(rsp->data[0]),
					     NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 9) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "last_reset_reason_get_done: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 9);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, EINVAL, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (control_info->get_identifier_val)
	control_info->get_identifier_val(control, 0, rsp->data+8, 1,
					 control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
slot_ga_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[3];

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_SLOT_STATUS_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, slot_ga_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, rv, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
slot_ga_get(ipmi_control_t                 *control,
	    ipmi_control_identifier_val_cb handler,
	    void                           *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;

    rv = ipmi_control_add_opq(control, slot_ga_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

typedef struct board_sensor_info_s
{
    ipmi_sensor_t  *slot;
    ipmi_control_t *reset;
    ipmi_control_t *power;
    ipmi_control_t *blue_led;
    ipmi_control_t *slot_ga;
    ipmi_control_t *power_config;
} board_sensor_info_t;

static void
destroy_board_sensors(ipmi_mc_t *mc, board_sensor_info_t *sinfo)
{
    if (sinfo->slot)
	ipmi_sensor_destroy(sinfo->slot);
    if (sinfo->reset)
	ipmi_control_destroy(sinfo->reset);
    if (sinfo->power)
	ipmi_control_destroy(sinfo->power);
    if (sinfo->blue_led)
	ipmi_control_destroy(sinfo->blue_led);
    if (sinfo->slot_ga)
	ipmi_control_destroy(sinfo->slot_ga);
    if (sinfo->power_config)
	ipmi_control_destroy(sinfo->power_config);
}

/*
 * The sensors that we add for MXP-compliant boards that are on the
 * board themselves (their MC is the board's MC.
 */

/* Numbers for sensors that are on the board (their MC is the board's
   MC). */
#define MXP_BOARD_SLOT_NUM 1

/* Numbers for controls that are on the board (their MC is the board's
   MC). */
#define MXP_BOARD_RESET_NUM		1 /* PM only */
#define MXP_BOARD_POWER_NUM		2 /* PM only */
#define MXP_BOARD_BLUE_LED_NUM		3
#define MXP_BOARD_HW_VER_NUM		4 /* AMC only */
#define MXP_BOARD_FW_VER_NUM		5 /* AMC only */
#define MXP_BOARD_FPGA_VER_NUM		6 /* AMC only */
#define MXP_BOARD_TEMP_COOL_LED_NUM	7 /* AMC only */
#define MXP_BOARD_LAST_RESET_REASON_NUM 8 /* AMC only */
#define MXP_BOARD_SLOT_GA_NUM		9 /* PM only */
#define MXP_BOARD_POWER_CONFIG_NUM	10 /* PM only */

static int
new_board_sensors(ipmi_mc_t           *mc,
		  ipmi_entity_t       *ent,
		  mxp_info_t          *info,
		  board_sensor_info_t *sinfo)
{
    int                rv;
    ipmi_control_cbs_t control_cbs;

    /* The slot sensor */
    rv = mxp_alloc_discrete_sensor(
	mc, ent,
	MXP_BOARD_SLOT_NUM,
	NULL, NULL,
	IPMI_SENSOR_TYPE_SLOT_CONNECTOR,
	IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC,
	"slot",
	0x60, 0x60, /* offsets 5 and 6 are supported (power and
                       hot-swap requester). */
	board_slot_get,
	NULL,
	&(sinfo->slot));
    if (rv)
	goto out_err;
    ipmi_sensor_set_hot_swap_requester(sinfo->slot, 6, 1); /* offset 6 is for
							      hot-swap */

    /* Reset control */
    rv = mxp_alloc_control(mc, ent,
			   MXP_BOARD_RESET_NUM,
			   NULL,
			   IPMI_CONTROL_RESET,
			   "reset",
			   board_reset_set,
			   NULL,
			   &(sinfo->reset));
    if (rv)
	goto out_err;
    ipmi_control_set_num_elements(sinfo->reset, 1);

    /* Power control */
    rv = mxp_alloc_control(mc, ent,
			   MXP_BOARD_POWER_NUM,
			   NULL,
			   IPMI_CONTROL_POWER,
			   "power",
			   board_power_set,
			   board_power_get,
			   &(sinfo->power));
    if (rv)
	goto out_err;
    ipmi_control_set_num_elements(sinfo->power, 1);

    /* Blue LED control */
    rv = mxp_alloc_control(mc, ent,
			   MXP_BOARD_BLUE_LED_NUM,
			   NULL,
			   IPMI_CONTROL_LIGHT,
			   "blue led",
			   board_blue_led_set,
			   board_blue_led_get,
			   &(sinfo->blue_led));
    if (rv)
	goto out_err;
    ipmi_control_light_set_lights(sinfo->blue_led, 1, blue_blinking_led);
    ipmi_control_set_hot_swap_indicator(sinfo->blue_led, 1);

    /* Slot gegraphic address */
    rv = mxp_alloc_control(mc, ent,
			   MXP_BOARD_SLOT_GA_NUM,
			   NULL,
			   IPMI_CONTROL_IDENTIFIER,
			   "Geog Addr",
			   NULL,
			   NULL,
			   &sinfo->slot_ga);
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(sinfo->slot_ga, 1);
    ipmi_control_get_callbacks(sinfo->slot_ga, &control_cbs);
    control_cbs.get_identifier_val = slot_ga_get;
    ipmi_control_set_readable(sinfo->slot_ga, 1);
    ipmi_control_set_callbacks(sinfo->slot_ga, &control_cbs);

    /* Board power mode */
    rv = mxp_alloc_control(mc, ent,
			   MXP_BOARD_POWER_CONFIG_NUM,
			   NULL,
			   IPMI_CONTROL_IDENTIFIER,
			   "Power Config",
			   board_power_config_set,
			   board_power_config_get,
			   &sinfo->power_config);
    if (rv)
	goto out_err;
    ipmi_control_set_num_elements(sinfo->reset, 3);

 out_err:
    return rv;
}

/***********************************************************************
 *
 * Handling for the AMC boards.  We detect them using the MC creation
 * callback.
 *
 **********************************************************************/

/* Sensor numbers for the MC number field for the AMC.  These come
   after the normal board sensors. */
#define MXP_5V_SENSOR_NUM	2
#define MXP_3_3V_SENSOR_NUM	3
#define MXP_2_5V_SENSOR_NUM	4
#define MXP_8V_SENSOR_NUM	5
#define MXP_AMC_OFFLINE_NUM     6

/* Must match the real sensor number */
#define MXP_AMC_TEMP_SENSOR_NUM	10

static void
amc_offline_get_cb(ipmi_sensor_t   *sensor,
		   mxp_sens_info_t *sens_info,
		   unsigned char   *data,
		   ipmi_states_t   *states)
{
    if (data[4] & 1)
	ipmi_set_state(states, 2, 0); /* Not offline */
    else
	ipmi_set_state(states, 2, 1); /* offline */
}

static void
amc_offline_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    mxp_sens_info_t *get_info = cb_data;
    ipmi_msg_t      msg;
    unsigned char   data[3];
    int             rv;
    ipmi_states_t   states;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_AMC_STATUS_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_sensor_send_command(sensor, ipmi_sensor_get_mc(sensor), 0,
				  &msg, mxp_sensor_get_done,
				  &(get_info->sdata), get_info);
    if (rv) {
	if (get_info->done)
	    get_info->done(sensor, rv, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
    }
}

static int
amc_offline_get(ipmi_sensor_t       *sensor,
		ipmi_states_read_cb done,
		void                *cb_data)
{
    int                 rv;
    mxp_sens_info_t     *get_info;

    get_info = alloc_sens_info(NULL, done, cb_data);
    if (!get_info)
	return ENOMEM;
    get_info->get_states = amc_offline_get_cb;
    get_info->min_rsp_length = 5;

    rv = ipmi_sensor_add_opq(sensor, amc_offline_get_start,
			     &(get_info->sdata), get_info);
    if (rv)
	ipmi_mem_free(get_info);

    return rv;
}

static void
mxp_voltage_reading_cb(ipmi_sensor_t *sensor,
		       int           err,
		       ipmi_msg_t    *rsp,
		       void          *cb_data)
{
    mxp_reading_done_t *get_info = cb_data;
    amc_info_t         *info = get_info->sdinfo;
    ipmi_states_t      states;
    unsigned int       raw_val;
    double             val;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err,
			   IPMI_NO_VALUES_PRESENT, 0, 0.0, &states,
			   get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "mxp_voltage_reading_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (get_info->done)
	    get_info->done(sensor,
			   IPMI_IPMI_ERR_VAL(rsp->data[0]),
			   IPMI_NO_VALUES_PRESENT,
			   0,
			   0.0,
			   &states,
			   get_info->cb_data);
	goto out;
    }

    if (sensor == info->s5v)
	raw_val = rsp->data[15];
    else if (sensor == info->s3_3v)
	raw_val = rsp->data[16];
    else if (sensor == info->s2_5v)
	raw_val = rsp->data[17];
    else if (sensor == info->s8v)
	raw_val = rsp->data[19];
    else {
	ipmi_log(IPMI_LOG_WARNING, "mxp_voltage_reading_cb: Invalid sensor");
	if (get_info->done)
	    get_info->done(sensor,
			   EINVAL,
			   IPMI_NO_VALUES_PRESENT,
			   0,
			   0.0,
			   &states,
			   get_info->cb_data);
	goto out; /* Not a valid sensor. */
    }

    val = ((double) raw_val) / 10.0;

    /* FIXME - Are there threshold states? */

    if (get_info->done)
	get_info->done(sensor,
		       0,
		       IPMI_BOTH_VALUES_PRESENT,
		       raw_val,
		       val,
		       &states,
		       get_info->cb_data);

 out:
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(get_info);
}

static void
mxp_voltage_reading_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    mxp_reading_done_t *get_info = cb_data;
    amc_info_t         *info = get_info->sdinfo;
    ipmi_msg_t         msg;
    unsigned char      data[3];
    int                rv;
    ipmi_states_t      states;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err,
			   IPMI_NO_VALUES_PRESENT, 0, 0.0, &states,
			   get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_AMC_STATUS_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_sensor_send_command(sensor, info->mc, 0,
				  &msg, mxp_voltage_reading_cb,
				  &(get_info->sdata), get_info);
    if (rv) {
	if (get_info->done)
	    get_info->done(sensor, rv,
			   IPMI_NO_VALUES_PRESENT, 0, 0.0, &states,
			   get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
    }
}

static int
mxp_voltage_reading_get_cb(ipmi_sensor_t        *sensor,
			   ipmi_reading_done_cb done,
			   void                 *cb_data)
{
    mxp_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);
    amc_info_t          *info = hdr->data;
    int                 rv;
    mxp_reading_done_t  *get_info;


    get_info = ipmi_mem_alloc(sizeof(*get_info));
    if (!get_info)
	return ENOMEM;
    get_info->sdinfo = info;
    get_info->done = done;
    get_info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, mxp_voltage_reading_get_start,
			     &(get_info->sdata), get_info);
    if (rv)
	ipmi_mem_free(get_info);
    return rv;
}

static void
amc_version_get_cb(ipmi_control_t *control,
		   int            err,
		   ipmi_msg_t     *rsp,
		   void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "amc_version_get_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control,
					     IPMI_IPMI_ERR_VAL(rsp->data[0]),
					     NULL, 0,
					     control_info->cb_data);
	goto out;
    }
    if (rsp->data_len < 12) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "amc_version_get_cb: Received short msg: %d bytes",
		 rsp->data_len);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control,
					     EINVAL,
					     NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (control_info->get_identifier_val)
	control_info->get_identifier_val(control, 0,
					 rsp->data+control_info->misc, 1,
					 control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
amc_version_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t   *control_info = cb_data;
    int                  rv;
    ipmi_msg_t           msg;
    unsigned char        data[3];

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_AMC_STATUS_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, amc_version_get_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, rv, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
amc_hw_version_get(ipmi_control_t                 *control,
		   ipmi_control_identifier_val_cb handler,
		   void                           *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;
    control_info->misc = 9; /* Offset of the hw version */
    rv = ipmi_control_add_opq(control, amc_version_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static int
amc_fw_version_get(ipmi_control_t                 *control,
		   ipmi_control_identifier_val_cb handler,
		   void                           *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;
    control_info->misc = 10; /* Offset of the fw version */
    rv = ipmi_control_add_opq(control, amc_version_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static int
amc_fpga_version_get(ipmi_control_t                 *control,
		     ipmi_control_identifier_val_cb handler,
		     void                           *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;
    control_info->misc = 11; /* Offset of the fpga version */
    rv = ipmi_control_add_opq(control, amc_version_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
amc_temp_cool_led_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[4];

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_AMC_LED_CMD;
    msg.data_len = 4;
    msg.data = data;
    add_mxp_mfg_id(data);
    data[3] = (((control_info->vals[0] & 0x3) << 4)
	       | ((control_info->vals[1] & 0x3) << 6));
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, mxp_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
amc_temp_cool_led_set(ipmi_control_t     *control,
		      int                *val,
		      ipmi_control_op_cb handler,
		      void               *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = val[0];
    control_info->vals[1] = val[1];

    rv = ipmi_control_add_opq(control, amc_temp_cool_led_set_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
amc_temp_cool_get_done(ipmi_control_t *control,
		       int            err,
		       ipmi_msg_t     *rsp,
		       void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                val[2];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "amc_temp_cool_get_done: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->done_get)
	    control_info->done_get(control,
				   IPMI_IPMI_ERR_VAL(rsp->data[0]),
				   NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 5) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "amc_temp_cool_get_done: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 5);
	if (control_info->done_get)
	    control_info->done_get(control, EINVAL, NULL,
				   control_info->cb_data);
	goto out;
    }

    val[0] = (rsp->data[4] >> 4) & 0x3;
    val[1] = (rsp->data[4] >> 6) & 0x3;
    if (control_info->done_get)
	control_info->done_get(control, 0, val, control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
amc_temp_cool_led_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[3];

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_AMC_LED_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, amc_temp_cool_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, rv, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
amc_temp_cool_led_get(ipmi_control_t      *control,
		      ipmi_control_val_cb handler,
		      void                *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;

    rv = ipmi_control_add_opq(control, amc_temp_cool_led_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
amc_last_reset_reason_get_done(ipmi_control_t *control,
			       int            err,
			       ipmi_msg_t     *rsp,
			       void           *cb_data)
{
    mxp_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "last_reset_reason_get_done: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control,
					     IPMI_IPMI_ERR_VAL(rsp->data[0]),
					     NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 9) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "last_reset_erason_get_done: Received invalid msg length: %d,"
		 " expected %d",
		 rsp->data_len, 9);
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, EINVAL, NULL, 0,
					     control_info->cb_data);
	goto out;
    }

    if (control_info->get_identifier_val)
	control_info->get_identifier_val(control, 0, rsp->data+8, 1,
					 control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
amc_last_reset_reason_get_start(ipmi_control_t *control, int err,
				void *cb_data)
{
    mxp_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;
    unsigned char      data[3];

    if (err) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, err, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_AMC_STATUS_CMD;
    msg.data_len = 3;
    msg.data = data;
    add_mxp_mfg_id(data);
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, amc_last_reset_reason_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->get_identifier_val)
	    control_info->get_identifier_val(control, rv, NULL, 0,
					     control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
amc_last_reset_reason_get(ipmi_control_t                 *control,
			  ipmi_control_identifier_val_cb handler,
			  void                           *cb_data)
{
    mxp_control_info_t   *control_info;
    int                  rv;

    control_info = alloc_control_info(NULL);
    if (!control_info)
	return ENOMEM;
    control_info->get_identifier_val = handler;
    control_info->cb_data = cb_data;

    rv = ipmi_control_add_opq(control, amc_last_reset_reason_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

static void
amc_removal_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    amc_info_t *info = cb_data;

    if (!info->s5v)
	/* It hasn't been initialized, so just free the data structure. */
	goto out;

    if (info->slot)
	ipmi_sensor_destroy(info->slot);
    if (info->s5v)
	ipmi_sensor_destroy(info->s5v);
    if (info->s3_3v)
	ipmi_sensor_destroy(info->s3_3v);
    if (info->s2_5v)
	ipmi_sensor_destroy(info->s2_5v);
    if (info->s8v)
	ipmi_sensor_destroy(info->s8v);
    if (info->temp)
	ipmi_sensor_destroy(info->temp);
    if (info->offline)
	ipmi_sensor_destroy(info->offline);
    if (info->blue_led)
	ipmi_control_destroy(info->blue_led);
    if (info->temp_cool_led)
	ipmi_control_destroy(info->temp_cool_led);
    if (info->last_reset_reason)
	ipmi_control_destroy(info->last_reset_reason);
    if (info->hw_version)
	ipmi_control_destroy(info->hw_version);
    if (info->fw_version)
	ipmi_control_destroy(info->fw_version);
    if (info->fpga_version)
	ipmi_control_destroy(info->fpga_version);

out:
    ipmi_mem_free(info);
}

static int mxp_event_handler(ipmi_mc_t    *mc,
			     ipmi_event_t *event,
			     void         *cb_data);

static int
amc_board_handler(ipmi_mc_t *mc)
{
    int                i;
    int                rv;
    amc_info_t         *info;
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    ipmi_entity_info_t *ents;
    unsigned int       assert, deassert;
    char               *name;
    ipmi_control_cbs_t control_cbs;
    int (*get)(ipmi_sensor_t *, ipmi_reading_done_cb, void *)
	= ipmi_standard_sensor_cb.ipmi_reading_get;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));

    info->mc = mc;

    rv = ipmi_mc_set_sel_oem_event_handler(mc, mxp_event_handler, info);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "mxp_handler: could not register event handler");
	goto out_err;
    }

    ents = ipmi_domain_get_entities(domain);

    /* Get whether we are card 1 or 2. */
    i = ipmi_mc_get_address(mc);

    name = board_entity_str[MXP_ALARM_CARD_IDX_OFFSET+i];
    rv = ipmi_entity_add(ents, domain, mc, 0,
			 MXP_ENTITY_ID_ALARM_CARD,
			 i+1,
			 name, IPMI_ASCII_STR, strlen(name),
			 mxp_entity_sdr_add,
			 NULL, &info->ent);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "amc_board_handler: Could not add alarm card entity: %x",
		 rv);
	goto out_err;
    }

    /* The MXP has an SEL. */
    ipmi_mc_set_sel_device_support(mc, 1);

    /* AMC slot sensor */
    rv = mxp_alloc_discrete_sensor(
	mc, info->ent,
	MXP_BOARD_SLOT_NUM,
	NULL, NULL,
	IPMI_SENSOR_TYPE_SLOT_CONNECTOR,
	IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC,
	"slot",
	0x40, 0x40, /* offset 6 is supported (hot-swap requester). */
	board_slot_get,
	NULL,
	&info->slot);
    if (rv)
	goto out_err;
    /* offset 6 is for hot-swap */
    ipmi_sensor_set_hot_swap_requester(info->slot, 6, 1);

    /* AMC offline sensor */
    rv = mxp_alloc_discrete_sensor(
	mc, info->ent,
	MXP_AMC_OFFLINE_NUM,
	NULL, NULL,
	IPMI_SENSOR_TYPE_MANAGEMENT_SUBSYSTEM_HEALTH,
	IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC,
	"offline",
	0x04, 0x04, /* Management Controller Offline. */
	amc_offline_get,
	NULL,
	&info->offline);
    if (rv)
	goto out_err;

    rv = mxp_alloc_control(mc, info->ent,
			   MXP_BOARD_BLUE_LED_NUM,
			   NULL,
			   IPMI_CONTROL_LIGHT,
			   "blue led",
			   board_blue_led_set,
			   board_blue_led_get,
			   &info->blue_led);
    if (rv)
	goto out_err;
    ipmi_control_light_set_lights(info->blue_led, 1, blue_led);
    ipmi_control_set_hot_swap_indicator(info->blue_led, 1);

    /* Temperature and cooling LEDs. */
    rv = mxp_alloc_control(mc, info->ent,
			   MXP_BOARD_TEMP_COOL_LED_NUM,
			   NULL,
			   IPMI_CONTROL_LIGHT,
			   "temp cool led",
			   amc_temp_cool_led_set,
			   amc_temp_cool_led_get,
			   &info->temp_cool_led);
    if (rv)
	goto out_err;
    ipmi_control_light_set_lights(info->temp_cool_led, 2, amc_temp_cool_leds);

    /* Last reset reason. */
    rv = mxp_alloc_control(mc, info->ent,
			   MXP_BOARD_LAST_RESET_REASON_NUM,
			   NULL,
			   IPMI_CONTROL_IDENTIFIER,
			   "Last Reset Rsn",
			   NULL,
			   NULL,
			   &info->last_reset_reason);
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(info->last_reset_reason, 1);
    ipmi_control_get_callbacks(info->last_reset_reason, &control_cbs);
    control_cbs.get_identifier_val = amc_last_reset_reason_get;
    ipmi_control_set_readable(info->last_reset_reason, 1);
    ipmi_control_set_callbacks(info->last_reset_reason, &control_cbs);

    rv = mxp_alloc_control(mc, info->ent,
			   MXP_BOARD_HW_VER_NUM,
			   NULL,
			   IPMI_CONTROL_IDENTIFIER,
			   "hw version",
			   NULL,
			   NULL,
			   &info->hw_version);
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(info->hw_version, 1);
    ipmi_control_get_callbacks(info->hw_version, &control_cbs);
    control_cbs.get_identifier_val = amc_hw_version_get;
    ipmi_control_set_readable(info->hw_version, 1);
    ipmi_control_set_callbacks(info->hw_version, &control_cbs);

    rv = mxp_alloc_control(mc, info->ent,
			   MXP_BOARD_FW_VER_NUM,
			   NULL,
			   IPMI_CONTROL_IDENTIFIER,
			   "fw version",
			   NULL,
			   NULL,
			   &info->fw_version);
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(info->fw_version, 1);
    ipmi_control_get_callbacks(info->fw_version, &control_cbs);
    control_cbs.get_identifier_val = amc_fw_version_get;
    ipmi_control_set_readable(info->fw_version, 1);
    ipmi_control_set_callbacks(info->fw_version, &control_cbs);

    rv = mxp_alloc_control(mc, info->ent,
			   MXP_BOARD_FPGA_VER_NUM,
			   NULL,
			   IPMI_CONTROL_IDENTIFIER,
			   "fpga version",
			   NULL,
			   NULL,
			   &info->fpga_version);
    if (rv)
	goto out_err;
    ipmi_control_identifier_set_max_length(info->fpga_version, 1);
    ipmi_control_get_callbacks(info->fpga_version, &control_cbs);
    control_cbs.get_identifier_val = amc_fpga_version_get;
    ipmi_control_set_readable(info->fpga_version, 1);
    ipmi_control_set_callbacks(info->fpga_version, &control_cbs);

    /* 5V */
    assert = 0;
    deassert = 0;
    rv = mxp_alloc_threshold_sensor(mc, info->ent,
				    MXP_5V_SENSOR_NUM,
				    info, NULL,
				    IPMI_SENSOR_TYPE_VOLTAGE,
				    IPMI_UNIT_TYPE_VOLTS,
				    "5V",
				    assert, deassert,
				    mxp_voltage_reading_get_cb,
				    50, 48, 52,
				    &(info->s5v));
    if (rv)
	goto out_err;
    ipmi_sensor_set_ignore_if_no_entity(info->s5v, 0);

    /* 3.3V */
    assert = 0;
    deassert = 0;
    rv = mxp_alloc_threshold_sensor(mc, info->ent,
				    MXP_3_3V_SENSOR_NUM,
				    info, NULL,
				    IPMI_SENSOR_TYPE_VOLTAGE,
				    IPMI_UNIT_TYPE_VOLTS,
				    "3.3V",
				    assert, deassert,
				    mxp_voltage_reading_get_cb,
				    33, 32, 34,
				    &(info->s3_3v));
    if (rv)
	goto out_err;

    /* 2.5V */
    assert = 0;
    deassert = 0;
    rv = mxp_alloc_threshold_sensor(mc, info->ent,
				    MXP_2_5V_SENSOR_NUM,
				    info, NULL,
				    IPMI_SENSOR_TYPE_VOLTAGE,
				    IPMI_UNIT_TYPE_VOLTS,
				    "2.5V",
				    assert, deassert,
				    mxp_voltage_reading_get_cb,
				    25, 24, 26,
				    &(info->s2_5v));
    if (rv)
	goto out_err;

    /* 8V */
    assert = 0;
    deassert = 0;
    rv = mxp_alloc_threshold_sensor(mc, info->ent,
				    MXP_8V_SENSOR_NUM,
				    info, NULL,
				    IPMI_SENSOR_TYPE_VOLTAGE,
				    IPMI_UNIT_TYPE_VOLTS,
				    "8V",
				    assert, deassert,
				    mxp_voltage_reading_get_cb,
				    80, 76, 84,
				    &(info->s8v));
    if (rv)
	goto out_err;

    /* Temperature */
    rv = mxp_alloc_semi_stand_threshold_sensor(mc, info->ent,
					       MXP_AMC_TEMP_SENSOR_NUM,
		   			       info, NULL,
					       IPMI_SENSOR_TYPE_TEMPERATURE,
					       IPMI_UNIT_TYPE_DEGREES_C,
					       "Temp",
					       0, 0,
					       get,
					       -1, -1, -1,
					       1, 0, 0, 0,
					       &info->temp);
    if (rv)
	goto out_err;

    rv = ipmi_mc_add_oem_removed_handler(mc, amc_removal_handler, info, NULL);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "mxp_handler: could not register removal handler");
	goto out_err;
    }

    ipmi_mc_set_oem_data(mc, info);

out_err:
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

/***********************************************************************
 *
 * Event handling code.
 *
 **********************************************************************/

/* We use MC add/remove callbacks to generate presence events for the
   AMCs. */
typedef struct amc_presence_info_s
{
    int present;
    int idx;
} amc_presence_info_t;

static void
amc_presence_event(ipmi_sensor_t *sensor, void *cb_data)
{
    mxp_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);
    mxp_board_t         *binfo = hdr->data;
    mxp_info_t          *info = binfo->info;
    amc_presence_info_t                   *pinfo = cb_data;
    ipmi_sensor_discrete_event_handler_cb handler;
    void                                  *h_cb_data;
    int                                   offset;
    int                                   deoffset;


    if (pinfo->present == info->amc_present[pinfo->idx])
	return;

    info->amc_present[pinfo->idx] = pinfo->present;

    if (pinfo->present) {
	offset = 0; /* Board is present. */
	deoffset = 1; /* Board is present. */
    } else {
	offset = 1; /* Board is absent. */
	deoffset = 0; /* Board is absent. */
    }

    ipmi_sensor_discrete_get_event_handler(sensor, &handler, &h_cb_data);
    if (handler) {
	handler(sensor,
		IPMI_ASSERTION,
		offset,
		-1, -1,
		h_cb_data,
		NULL);
	handler(sensor,
		IPMI_DEASSERTION,
		deoffset,
		-1, -1,
		h_cb_data,
		NULL);
    }
}

static void
mc_upd_handler(enum ipmi_update_e op,
	       ipmi_domain_t      *domain,
	       ipmi_mc_t          *mc,
	       void               *cb_data)
{
    amc_presence_info_t pinfo;
    int                 i;
    ipmi_sensor_id_t    id;

    pinfo.present = (op == IPMI_ADDED);

    if (ipmi_mc_get_channel(mc) != IPMI_BMC_CHANNEL)
	return;

    i = ipmi_mc_get_address(mc);
    if ((i < 0) || (i >= 2))
	return;

    pinfo.idx = i;

    id.mcid.domain_id.domain = domain;
    id.mcid.channel = 0;
    id.mcid.mc_num = 0x20;
    id.lun = 4;
    id.sensor_num = MXP_BOARD_PRESENCE_NUM(MXP_ALARM_CARD_IDX_OFFSET+i);
    ipmi_sensor_pointer_noseq_cb(id, amc_presence_event, &pinfo);
}

/* This is created in the main event handler and passed down. */
typedef struct mc_event_info_s
{
    ipmi_sensor_op_info_t sdata;
    mxp_info_t            *info;
    ipmi_event_t          *event;
    ipmi_event_t          event_copy;
    int                   handled;
} mc_event_info_t;

static void
mxp_board_power_changed_event(ipmi_sensor_t *sensor, void *cb_data)
{
    mc_event_info_t                       *einfo = cb_data;
    ipmi_sensor_discrete_event_handler_cb handler;
    void                                  *h_cb_data;
    enum ipmi_event_dir_e                 assertion;
    ipmi_event_t                          *event = &(einfo->event_copy);

    if (event->data[10])
	assertion = IPMI_DEASSERTION;
    else
	assertion = IPMI_ASSERTION;

    ipmi_sensor_discrete_get_event_handler(sensor, &handler, &h_cb_data);
    if (handler) {
	handler(sensor,
		assertion,
		5, /* Offset 5 is the power offset. */
		-1, -1,
		h_cb_data,
		einfo->event);
	einfo->event = NULL;
    }
}

static void
mxp_board_ejector_changed_event(ipmi_sensor_t *sensor, void *cb_data)
{
    mc_event_info_t                       *einfo = cb_data;
    ipmi_sensor_discrete_event_handler_cb handler;
    void                                  *h_cb_data;
    enum ipmi_event_dir_e                 assertion;
    ipmi_event_t                          *event = &(einfo->event_copy);

    if (event->data[9] & 0x80)
	assertion = IPMI_DEASSERTION;
    else
	assertion = IPMI_ASSERTION;

    ipmi_sensor_discrete_get_event_handler(sensor, &handler, &h_cb_data);
    if (handler) {
	handler(sensor,
		assertion,
		6, /* Offset 6 is the ejector offset. */
		-1, -1,
		h_cb_data,
		einfo->event);
	einfo->event = NULL;
    }
}

typedef struct rescan_info_s
{
    ipmi_domain_id_t domain_id;
    int              addr;
    os_handler_t     *hnd;
} rescan_info_t;

static void
timed_rescan_bus2(ipmi_domain_t *domain, void *cb_data)
{
    rescan_info_t *info = cb_data;

    /* Do an MC query on the board.  If it has become present, it will
       be added.  If it has gone away it will be deleted. */
    ipmi_start_ipmb_mc_scan(domain, 0, info->addr, info->addr, NULL, NULL);
    ipmi_mem_free(info);
}

static void
timed_rescan_bus(void *cb_data, os_hnd_timer_id_t *id)
{
    rescan_info_t *info = cb_data;
    int           rv;

    info->hnd->free_timer(info->hnd, id);

    rv = ipmi_domain_pointer_cb(info->domain_id, timed_rescan_bus2, info);
    if (rv)
	ipmi_mem_free(info);
}

static void
mxp_board_presence_event(ipmi_sensor_t *sensor, void *cb_data)
{
    mc_event_info_t                       *einfo = cb_data;
    ipmi_sensor_discrete_event_handler_cb handler;
    void                                  *h_cb_data;
    unsigned int                          addr;
    int                                   offset;
    int                                   deoffset;
    ipmi_event_t                          *event = &(einfo->event_copy);
    ipmi_mc_t                             *mc;
    ipmi_domain_t                         *domain;
    os_handler_t                          *hnd;
    os_hnd_timer_id_t                     *timer;
    struct timeval                        timeout;
    rescan_info_t			  *info;
    int                                   rv;
    mxp_info_t                            *mxpinfo;

    if (event->data[9] & 0x80) {
	offset = 1; /* Board is absent. */
	deoffset = 0; /* Board is absent. */
    } else {
	offset = 0; /* Board is present. */
	deoffset = 1; /* Board is present. */
    }

    ipmi_sensor_discrete_get_event_handler(sensor, &handler, &h_cb_data);
    if (handler) {
	handler(sensor,
		IPMI_ASSERTION,
		offset,
		-1, -1,
		h_cb_data,
		einfo->event);
	einfo->event = NULL;
	handler(sensor,
		IPMI_DEASSERTION,
		deoffset,
		-1, -1,
		h_cb_data,
		NULL);
    }
    
    mc = ipmi_sensor_get_mc(sensor);
    domain = ipmi_mc_get_domain(mc);
    /* We are hanging off the main MC, it's OEM data is the info. */
    mxpinfo = ipmi_mc_get_oem_data(mc);

    if (event->data[4] & 1)
	/* It's from the BMC, the address is in the data1 byte. */
	addr = mxp_3u_to_6u_addr(mxpinfo, event->data[10]);
    else
	/* It's from the board, the address is the generator. */
	addr = event->data[4];

    /* Schedule an MC query for the board in 3 seconds, to give it time to
       come up. */
    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	ipmi_log(IPMI_LOG_WARNING,
		 "mxp_board_presence_event: unable to allocate timer memory");
	return;
    }
    hnd = ipmi_domain_get_os_hnd(domain);
    info->hnd = hnd;
    info->domain_id = ipmi_domain_convert_to_id(domain);
    info->addr = addr;
    rv = hnd->alloc_timer(hnd, &timer);
    if (rv) {
	ipmi_mem_free(info);
	ipmi_log(IPMI_LOG_WARNING,
		 "mxp_board_presence_event: unable to allocate timer");
	return;
    }
    timeout.tv_sec = 3; /* The Zynx switches seem to need 3 seconds to
			   get started. */
    timeout.tv_usec = 0;
    rv = hnd->start_timer(hnd, timer, &timeout, timed_rescan_bus, info);
    if (rv) {
	hnd->free_timer(hnd, timer);
	ipmi_mem_free(info);
	ipmi_log(IPMI_LOG_WARNING,
		 "mxp_board_presence_event: unable to start timer");
	return;
    }
}

/* Used when the presence/absense is in the assert/deassert field. */
static void
mxp_gen_presence_event(ipmi_sensor_t *sensor, void *cb_data)
{
    mc_event_info_t                       *einfo = cb_data;
    ipmi_sensor_discrete_event_handler_cb handler;
    void                                  *h_cb_data;
    int                                   offset;
    int                                   deoffset;
    ipmi_event_t                          *event = &(einfo->event_copy);

    /* An offset of 0 means the PS is present, an offset of one is not
       present. */
    if (event->data[9] & 0x80) {
	offset = 1; /* PS is absent. */
	deoffset = 0; /* PS is absent. */
    } else {
	offset = 0; /* PS is present. */
	deoffset = 1; /* PS is present. */
    }

    ipmi_sensor_discrete_get_event_handler(sensor, &handler, &h_cb_data);
    if (handler) {
	handler(sensor,
		IPMI_ASSERTION,
		offset,
		-1, -1,
		h_cb_data,
		einfo->event);
	einfo->event = NULL;
	handler(sensor,
		IPMI_DEASSERTION,
		deoffset,
		-1, -1,
		h_cb_data,
		NULL);
    }
}

static void
mxp_fan_cooling_event(ipmi_sensor_t *sensor, void *cb_data)
{
    mc_event_info_t                        *einfo = cb_data;
    ipmi_sensor_threshold_event_handler_cb handler;
    void                                   *h_cb_data;
    enum ipmi_event_dir_e                 assertion;
    ipmi_event_t                          *event = &(einfo->event_copy);

    ipmi_sensor_threshold_get_event_handler(sensor, &handler, &h_cb_data);

    if (!handler)
	return;

    /* The set bits tell if the value has changed.  The assertion bit
       tells if the value is asserted or not. */

    if (event->data[9] & 0x80)
	assertion = IPMI_DEASSERTION;
    else
	assertion = IPMI_ASSERTION;

    /* The cooling event has two levels, non-critical and critical. */

    if (event->data[11] & 2) {
	handler(sensor,
		assertion,
		IPMI_UPPER_NON_CRITICAL,
		IPMI_GOING_HIGH,
		IPMI_NO_VALUES_PRESENT,
		0, 0.0,
		h_cb_data,
		einfo->event);
	einfo->event = NULL;
    }

    if (event->data[11] & 4) {
	handler(sensor,
		assertion,
		IPMI_UPPER_CRITICAL,
		IPMI_GOING_HIGH,
		IPMI_NO_VALUES_PRESENT,
		0, 0.0,
		h_cb_data,
		einfo->event);
	einfo->event = NULL;
    }
}

static void
mxp_fan_speed_event(ipmi_sensor_t *sensor, void *cb_data)
{
    mc_event_info_t                        *einfo = cb_data;
    ipmi_sensor_threshold_event_handler_cb handler;
    void                                   *h_cb_data;
    enum ipmi_event_dir_e                  assertion;
    ipmi_event_t                          *event = &(einfo->event_copy);

    ipmi_sensor_threshold_get_event_handler(sensor, &handler, &h_cb_data);

    if (!handler)
	return;

    if (event->data[9] & 0x80)
	assertion = IPMI_DEASSERTION;
    else
	assertion = IPMI_ASSERTION;

    /* The set bits tell if the value has changed.  The assertion bit
       tells if the value is asserted or not. */

    if (event->data[11] & 1) {
	handler(sensor,
		assertion,
		IPMI_LOWER_CRITICAL,
		IPMI_GOING_LOW,
		IPMI_NO_VALUES_PRESENT,
		0, 0.0,
		h_cb_data,
		einfo->event);
	einfo->event = NULL;
    }
}

static void
mxp_ps_alarm_event(ipmi_sensor_t *sensor, void *cb_data)
{
    mc_event_info_t                       *einfo = cb_data;
    ipmi_sensor_discrete_event_handler_cb handler;
    void                                  *h_cb_data;
    enum ipmi_event_dir_e                 assertion;
    ipmi_event_t                          *event = &(einfo->event_copy);

    ipmi_sensor_discrete_get_event_handler(sensor, &handler, &h_cb_data);
    if (!handler)
	return;

    /* The set bits tell if the value has changed.  The assertion bit
       tells if the value is asserted or not. */

    if (event->data[9] & 0x80)
	assertion = IPMI_DEASSERTION;
    else
	assertion = IPMI_ASSERTION;

    /* Report a feed A status change. */
    if (event->data[11] & 0x1) {
	handler(sensor,
		assertion,
		13,
		-1, -1,
		h_cb_data,
		einfo->event);
	einfo->event = NULL;
    }

    /* Report a feed B status change. */
    if (event->data[11] & 0x2) {
	handler(sensor,
		assertion,
		14,
		-1, -1,
		h_cb_data,
		einfo->event);
	einfo->event = NULL;
    }

    /* Report a power good change.  We have to invert the assertion,
       becase it's a power good bit but a power supply sensor has a
       power fail bit. */
    if (event->data[11] & 0x8) {
	if (event->data[9] & 0x80)
	    assertion = IPMI_ASSERTION;
	else
	    assertion = IPMI_DEASSERTION;
	handler(sensor,
		assertion,
		1,
		-1, -1,
		h_cb_data,
		einfo->event);
	einfo->event = NULL;
    }
}

static void
mxp_amc_failover_event(ipmi_sensor_t *sensor, void *cb_data)
{
    mc_event_info_t                       *einfo = cb_data;
    ipmi_sensor_discrete_event_handler_cb handler;
    void                                  *h_cb_data;
    enum ipmi_event_dir_e                 assertion;
    ipmi_event_t                          *event = &(einfo->event_copy);

    ipmi_sensor_discrete_get_event_handler(sensor, &handler, &h_cb_data);
    if (!handler)
	return;

    /* The set bits tell if the value has changed.  The assertion bit
       tells if the value is asserted or not. */

    if (event->data[11])
	assertion = IPMI_DEASSERTION; /* Taking control */
    else
	assertion = IPMI_ASSERTION; /* Loosing control */

    handler(sensor,
	    assertion,
	    2,
	    -1, -1,
	    h_cb_data,
	    einfo->event);
    einfo->event = NULL;
}

static void
mc_event(ipmi_mc_t *mc, void *cb_data)
{
    mc_event_info_t  *einfo = cb_data;
    ipmi_event_t     *event = einfo->event;
    mxp_info_t       *info = einfo->info;
    ipmi_sensor_id_t id;
    mxp_board_t      *binfo;
    int              rv;
    int              i;

    id.mcid = ipmi_mc_convert_to_id(mc);
    id.mcid.channel = 0;
    id.mcid.mc_num = 0x20;
    id.lun = 4;
    switch (event->data[7])
    {
    case 0xd0:
	if ((event->data[8] == 0x01) || (event->data[8] == 0x02)) {
	    /* HS Power and HS Bdsel.  We treat these the same, they
               should both mean that a board power is present or
               absent. */
	    id.mcid.mc_num = event->data[4];
	    id.sensor_num = MXP_BOARD_SLOT_NUM;
	    rv = ipmi_sensor_pointer_noseq_cb(id,
					      mxp_board_power_changed_event,
					      einfo);
	    if (!rv)
		einfo->handled = 1;
	} else if ((event->data[8] == 0x03) || (event->data[8] == 0x0e)) {
	    /* HS Reset and HS Healthy, we use it to trigger that a
               board is present. */
	    if (event->data[4] & 1)
		/* It's from the BMC, the address is in the data1 byte. */
		binfo = mxp_find_board_by_addr(
		    info, mxp_3u_to_6u_addr(info, event->data[10]));
	    else
		/* It's from the board, the address is the generator. */
		binfo = mxp_find_board_by_addr(info, event->data[4]);
	    if (!binfo)
		return;
	    id.sensor_num = MXP_BOARD_PRESENCE_NUM(binfo->idx);
	    rv = ipmi_sensor_pointer_noseq_cb(id, mxp_board_presence_event,
					      einfo);
	    if (!rv)
		einfo->handled = 1;
	} else if (event->data[8] == 0x04) {
	    /* HS Eject */
	    if (event->data[4] & 1) {
		if (event->data[10] == 0xea) {
		    id.mcid.channel = IPMI_BMC_CHANNEL;
		    id.mcid.mc_num = 0;
		} else if (event->data[10] == 0xec) {
		    id.mcid.channel = IPMI_BMC_CHANNEL;
		    id.mcid.mc_num = 1;
		}
	    } else {
		id.mcid.mc_num = event->data[4];
	    }
	    id.sensor_num = MXP_BOARD_SLOT_NUM;
	    rv = ipmi_sensor_pointer_noseq_cb(id,
					      mxp_board_ejector_changed_event,
					      einfo);
	    if (!rv)
		einfo->handled = 1;
	} else if (event->data[8] == 0x05) {
	    /* HS Hearbeat */
	    einfo->handled = 1; /* Nothing to do for these. */
	}
	break;

    case 0xd1:
	if (event->data[8] == 0x06) {
	    /* AMC LAN */
	    einfo->handled = 1; /* Nothing to do for these. */
	} else if (event->data[8] == 0x07) {
	    /* AMC Failover, find the AMC-specific MC */
	    id.mcid.channel = IPMI_BMC_CHANNEL;
	    if (event->data[10] == 0xea)
		/* AMC 1 */
		id.mcid.mc_num = 0;
	    else if (event->data[10] == 0xec)
		/* AMC 2 */
		id.mcid.mc_num = 1;
	    else {
		break;
	    }
	    id.sensor_num = MXP_AMC_OFFLINE_NUM;
	    rv = ipmi_sensor_pointer_noseq_cb(id, mxp_amc_failover_event,
					      einfo);
	    if (!rv)
		einfo->handled = 1;
	}
	break;

    case 0xd2:
	for (i=0; i<MXP_POWER_SUPPLIES; i++) {
	    if (event->data[10] == info->power_supply[i].ipmb_addr)
		break;
	}
	if (i >= MXP_POWER_SUPPLIES)
	    /* Didn't find it in the power supplies. */
	    break;

	rv = EINVAL; /* Guilty until proven innocent. */
	if (event->data[8] == 0x02) {
	    /* According to Motorola, this is no longer used. */
	} else if (event->data[8] == 0x09) {
	    /* PS Alarm, for PS faults. */
	    id.sensor_num = MXP_PS_PS_NUM(i);
	    rv = ipmi_sensor_pointer_noseq_cb(id, mxp_ps_alarm_event, einfo);
	} else if (event->data[8] == 0x0a) {
	    /* PS Present */
	    id.sensor_num = MXP_PS_PRESENCE_NUM(i);
	    rv = ipmi_sensor_pointer_noseq_cb(id, mxp_gen_presence_event,
					      einfo);
	}
	if (!rv)
	    einfo->handled = 1;
	break;

    case 0xd3:
	for (i=0; i<MXP_POWER_SUPPLIES; i++) {
	    if (event->data[10] == info->power_supply[i].ipmb_addr)
		break;
	}
	if (i >= MXP_POWER_SUPPLIES)
	    /* Didn't find it in the power supplies. */
	    break;

	rv = EINVAL; /* Guilty until proven innocent. */
	if (event->data[8] == 0x0b) {
	    /* Fan Alarm.  This contains alarms for both the fan
               cooling events and for the fan speed, so we have to
               ping both sensors. */
	    id.sensor_num = MXP_FAN_COOLING_NUM(i);
	    rv = ipmi_sensor_pointer_noseq_cb(id, mxp_fan_cooling_event,
					      einfo);
	    if (!rv) {
		id.sensor_num = MXP_FAN_SPEED_NUM(i);
		rv = ipmi_sensor_pointer_noseq_cb(id, mxp_fan_speed_event,
						  einfo);
	    }
	} else if (event->data[8] == 0x0c) {
	    /* Fan Present */
	    id.sensor_num = MXP_FAN_PRESENCE_NUM(i);
	    rv = ipmi_sensor_pointer_noseq_cb(id, mxp_gen_presence_event,
					      einfo);
	}
	if (!rv)
	    einfo->handled = 1;
	break;

    case 0xd4:
	if (event->data[8] == 0x0d) {
	    /* IPMB Fail */
	    einfo->handled = 1; /* Nothing to do for these. */
	}
	break;

    }
}

static int
mxp_event_handler(ipmi_mc_t    *mc,
		  ipmi_event_t *event,
		  void         *cb_data)
{
    ipmi_mcid_t     mc_id = ipmi_mc_convert_to_id(mc);
    int             rv;
    mc_event_info_t einfo;
    unsigned long   timestamp;
    amc_info_t      *ainfo = cb_data;

    if ((event->type != 2) && (event->type != 3) && (event->type != 0xc0))
	/* Not a system event record or MXP event. */
	return 0;

    if ((event->data[6] != 3) && (event->data[6] != 4))
	/* Not a 1.5 event version or an MXP event */
	return 0;

    timestamp = ipmi_get_uint32(&(event->data[0]));

    if (timestamp < ipmi_mc_get_startup_SEL_time(mc))
	/* It's an old event, ignore it. */
	return 0;

    /* If the low bit of data[4] is set, then it's from the MC,
       otherwise it's from a card.  Power supply messages also come in
       with their IPMB address, but we don't want to use those because
       we don't have MCs for the power supplies. */
    if (((event->data[4] & 1) == 0)
	&& !((event->data[4] == 0x54)
	     || (event->data[4] == 0x56)
	     || (event->data[4] == 0x58)
	     /* For some reason, events from the AMC ejector handle
                come in as 1e in this field. */
	     || (event->data[4] == 0x1e)))
    {
	mc_id.channel = 0;
        mc_id.mc_num = event->data[4];
    } else {
	mc_id.channel = 0;
        mc_id.mc_num = 0x20;
    }

    /* For some reason, events from the AMC ejector handle sometimes
       come in as 1e in this field. */
    if (event->data[4] == 0x1e)
	event->data[4] = 0x1d;

    einfo.event = event;
    einfo.event_copy = *event;
    einfo.handled = 0;
    einfo.info = amc_get_mxp_info(mc, ainfo);

    rv = ipmi_mc_pointer_noseq_cb(mc_id, mc_event, &einfo);

    if (rv)
	return 0;

    /* If the event was handled but not delivered to the user, then
       deliver it to the unhandled handler. */
    if (einfo.handled && (einfo.event != NULL))
	ipmi_handle_unhandled_event(ipmi_mc_get_domain(mc), event);

    return einfo.handled;
}

/***********************************************************************
 *
 * Generic I2C handling code for I2C sensors.
 *
 **********************************************************************/

static void
i2c_write(ipmi_mc_t    *mc,
	  unsigned int bus,
	  unsigned int addr,
	  unsigned int offset,
	  unsigned int val)
{
    ipmi_msg_t         msg;
    unsigned char      data[5];
    int                rv;

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_MASTER_READ_WRITE_CMD;
    msg.data_len = 4;
    msg.data = data;
    data[0] = bus;
    data[1] = addr;
    data[2] = 0; /* Read no bytes */
    data[3] = offset;
    data[4] = val;
    rv = ipmi_mc_send_command(mc, 0, &msg, NULL, NULL);
    if (rv)
	ipmi_log(IPMI_LOG_WARNING,
		 "Could not to I2C write to %x.%x.%x, error %x\n",
		 bus, addr, offset, rv);
}

typedef struct i2c_sens_s
{
    unsigned int bus;
    unsigned int addr;
    unsigned int offset;
} i2c_sens_t;

static void
i2c_sens_reading_cb(ipmi_sensor_t *sensor,
		    int           err,
		    ipmi_msg_t    *rsp,
		    void          *cb_data)
{
    mxp_reading_done_t        *get_info = cb_data;
    ipmi_states_t             states;
    unsigned int              raw_val;
    double                    val;
    enum ipmi_value_present_e present;
    int                       rv;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err,
			   IPMI_NO_VALUES_PRESENT, 0, 0.0, &states,
			   get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "i2c_sens_reading_cb: Received IPMI error: %x",
		 rsp->data[0]);
	if (get_info->done)
	    get_info->done(sensor,
			   IPMI_IPMI_ERR_VAL(rsp->data[0]),
			   IPMI_NO_VALUES_PRESENT,
			   0,
			   0.0,
			   &states,
			   get_info->cb_data);
	goto out;
    }

    raw_val = rsp->data[1];

    rv = ipmi_sensor_convert_from_raw(sensor, raw_val, &val);
    if (rv)
	present = IPMI_RAW_VALUE_PRESENT;
    else
	present = IPMI_BOTH_VALUES_PRESENT;

    if (get_info->done)
	get_info->done(sensor,
		       0,
		       present,
		       raw_val,
		       val,
		       &states,
		       get_info->cb_data);

 out:
    ipmi_sensor_opq_done(sensor);
    ipmi_mem_free(get_info);
}

static void
i2c_sens_get_reading_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    mxp_reading_done_t *get_info = cb_data;
    i2c_sens_t         *info = get_info->sdinfo;
    ipmi_msg_t         msg;
    unsigned char      data[4];
    int                rv;
    ipmi_states_t      states;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	if (get_info->done)
	    get_info->done(sensor, err,
			   IPMI_NO_VALUES_PRESENT, 0, 0.0, &states,
			   get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
	return;
    }

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_MASTER_READ_WRITE_CMD;
    msg.data_len = 4;
    msg.data = data;
    data[0] = info->bus;
    data[1] = info->addr;
    data[2] = 1; /* Read one byte */
    data[3] = info->offset;
    rv = ipmi_sensor_send_command(sensor, ipmi_sensor_get_mc(sensor), 0,
				  &msg, i2c_sens_reading_cb,
				  &(get_info->sdata), get_info);
    if (rv) {
	if (get_info->done)
	    get_info->done(sensor, rv,
			   IPMI_NO_VALUES_PRESENT, 0, 0.0, &states,
			   get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
    }
}

static int
i2c_sens_get_reading(ipmi_sensor_t        *sensor,
		    ipmi_reading_done_cb done,
		    void                 *cb_data)
{
    mxp_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);
    i2c_sens_t           *info = hdr->data;
    int                 rv;
    mxp_reading_done_t  *get_info;


    get_info = ipmi_mem_alloc(sizeof(*get_info));
    if (!get_info)
	return ENOMEM;
    get_info->sdinfo = info;
    get_info->done = done;
    get_info->cb_data = cb_data;
    rv = ipmi_sensor_add_opq(sensor, i2c_sens_get_reading_start,
			     &(get_info->sdata), get_info);
    if (rv)
	ipmi_mem_free(get_info);
    return rv;
}

/***********************************************************************
 *
 * Handlers to create sensors for various boards.
 *
 **********************************************************************/

typedef struct mxp_805_info_s
{
    board_sensor_info_t   board;
} mxp_805_info_t;

static void
mxp_805_removal_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    mxp_805_info_t *sinfo = cb_data;

    destroy_board_sensors(mc, &(sinfo->board));
    ipmi_mem_free(sinfo);
}

static int
mxp_805_handler(ipmi_mc_t     *mc,
		void          *cb_data)
{
    unsigned int       slave_addr = ipmi_mc_get_address(mc);
    ipmi_entity_info_t *ents;
    ipmi_entity_t      *ent;
    int                rv;
    char               *board_name;
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    ipmi_mc_t          *bmc;
    mxp_info_t         *info = NULL;
    mxp_805_info_t     *sinfo = NULL;
    ipmi_ipmb_addr_t   addr = {IPMI_IPMB_ADDR_TYPE, 0, 0x20, 0};

    ipmi_domain_entity_lock(domain);

    bmc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &addr, sizeof(addr));
    if (bmc
	&& (ipmi_mc_manufacturer_id(bmc) == MXP_MANUFACTURER_ID)
	&& (ipmi_mc_product_id(bmc) == MXP_AMC_PRODUCT_ID))
    {
	int        i;

	info = ipmi_mc_get_oem_data(bmc);
	/* We are in an MXP chassis, we can get the index and the name
           from the table */
	i = mxp_board_addr_to_index(slave_addr, info);
	if (i < 0)
	    board_name = "805 board";
	else
	    board_name = board_entity_str[i];
    } else {
	/* Not in an MXP chassis, just give it a generic name. */
	board_name = "805 board";
    }
	    
    sinfo = ipmi_mem_alloc(sizeof(*sinfo));
    if (!sinfo) {
	rv = ENOMEM;
	goto out;
    }

    ents = ipmi_domain_get_entities(domain);
    rv = ipmi_entity_add(ents, domain, mc, 0,
			 IPMI_ENTITY_ID_PROCESSING_BLADE,
			 mxp_addr_to_instance(slave_addr),
			 board_name, IPMI_ASCII_STR, strlen(board_name),
			 mxp_entity_sdr_add,
			 NULL, &ent);
    if (rv)
	goto out;

    rv = new_board_sensors(mc, ent, info, &(sinfo->board));
    if (rv)
	goto out;

    rv = ipmi_mc_add_oem_removed_handler(mc, mxp_805_removal_handler, sinfo, NULL);

 out:
    if (rv && sinfo)
	ipmi_mem_free(sinfo);
    ipmi_domain_entity_unlock(domain);
    return rv;
}

typedef struct adm1021_sensor_info_s
{
    ipmi_sensor_t *sensor;
} adm1021_sensor_info_t;

static void
destroy_adm1021_sensors(ipmi_mc_t *mc, adm1021_sensor_info_t *sinfo)
{
    ipmi_sensor_destroy(sinfo->sensor);
}

static int
alloc_adm1021_sensor(ipmi_mc_t             *mc,
		     ipmi_entity_t         *ent,
		     unsigned int          num,
		     unsigned int          bus,
		     unsigned int          addr,
		     char                  *id,
		     adm1021_sensor_info_t *sinfo)
{
    int               rv;
    i2c_sens_t        *info;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->bus = bus;
    info->addr = addr;
    info->offset = 1; /* Offset 1 is the remote temp sens. */

    i2c_write(mc, bus, addr, 0xa, 4); /* Do 1 conversion a second. */
    i2c_write(mc, bus, addr, 0x9, 0); /* Enable conversion. */

    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, num,
		   			       info, ipmi_mem_free,
					       IPMI_SENSOR_TYPE_TEMPERATURE,
					       IPMI_UNIT_TYPE_DEGREES_C,
					       id,
					       0, 0,
					       i2c_sens_get_reading,
					       -1, -1, 105,
					       1, 0, 0, 0,
					       &(sinfo->sensor));
    if (rv) {
	ipmi_mem_free(info);
	goto out;
    }
    ipmi_sensor_set_analog_data_format(sinfo->sensor,
				       IPMI_ANALOG_DATA_FORMAT_2_COMPL);
    ipmi_sensor_set_raw_sensor_max(sinfo->sensor, 0x7f);
    ipmi_sensor_set_raw_sensor_min(sinfo->sensor, 0x80);

 out:
    return rv;
}

typedef struct adm9240_sensor_info_s
{
    ipmi_sensor_t *board_temp;
    ipmi_sensor_t *v1_5;
    ipmi_sensor_t *v3_3;
    ipmi_sensor_t *v5;
    ipmi_sensor_t *v12;
    ipmi_sensor_t *vneg12;
    ipmi_sensor_t *vccp;
} adm9240_sensor_info_t;

static void
destroy_adm9240_sensors(ipmi_mc_t *mc, adm9240_sensor_info_t *sinfo)
{
    ipmi_sensor_destroy(sinfo->board_temp);
    ipmi_sensor_destroy(sinfo->v1_5);
    ipmi_sensor_destroy(sinfo->v3_3);
    ipmi_sensor_destroy(sinfo->v5);
    ipmi_sensor_destroy(sinfo->v12);
    ipmi_sensor_destroy(sinfo->vneg12);
    ipmi_sensor_destroy(sinfo->vccp);
}

static int
alloc_adm9240_sensor(ipmi_mc_t             *mc,
		     ipmi_entity_t         *ent,
		     unsigned int          num,
		     unsigned int          bus,
		     unsigned int          addr,
		     adm9240_sensor_info_t *sinfo)
{
    int               rv;
    i2c_sens_t        *info;

    i2c_write(mc, bus, addr, 0x40, 1); /* Enable conversion. */

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->bus = bus;
    info->addr = addr;
    info->offset = 0x27; /* Offset 0x27 is the temp sens. */
    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, num,
		   			       info, ipmi_mem_free,
					       IPMI_SENSOR_TYPE_TEMPERATURE,
					       IPMI_UNIT_TYPE_DEGREES_C,
					       "Board Temp",
					       0, 0,
					       i2c_sens_get_reading,
					       -1, -1, 55,
					       1, 0, 0, 0,
					       &(sinfo->board_temp));
    if (rv) {
	ipmi_mem_free(info);
	goto out;
    }
    ipmi_sensor_set_analog_data_format(sinfo->board_temp,
				       IPMI_ANALOG_DATA_FORMAT_2_COMPL);
    ipmi_sensor_set_raw_sensor_max(sinfo->board_temp, 0x7f);
    ipmi_sensor_set_raw_sensor_min(sinfo->board_temp, 0x80);

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->bus = bus;
    info->addr = addr;
    info->offset = 0x20; /* Offset 0x20 is the 1.5V sens. */
    /* Nominal is 117 (1.5V), step is 13mV. */
    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, num+1,
		   			       info, ipmi_mem_free,
					       IPMI_SENSOR_TYPE_VOLTAGE,
					       IPMI_UNIT_TYPE_VOLTS,
					       "1.5V",
					       0, 0,
					       i2c_sens_get_reading,
					       117, 112, 122,
					       13, 4, 0, -3,
					       &(sinfo->v1_5));
    if (rv) {
	ipmi_mem_free(info);
	goto out;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->bus = bus;
    info->addr = addr;
    info->offset = 0x22; /* Offset 0x22 is the 3.3V sens. */
    /* Nominal is 192 (3.3V), step is 17.2mV. */
    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, num+2,
		   			       info, ipmi_mem_free,
					       IPMI_SENSOR_TYPE_VOLTAGE,
					       IPMI_UNIT_TYPE_VOLTS,
					       "3.3V",
					       0, 0,
					       i2c_sens_get_reading,
					       192, 182, 202,
					       172, 24, 0, -4,
					       &(sinfo->v3_3));
    if (rv) {
	ipmi_mem_free(info);
	goto out;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->bus = bus;
    info->addr = addr;
    info->offset = 0x23; /* Offset 0x23 is the 5V sens. */
    /* Nominal is 192 (5V), step is 26mV. */
    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, num+3,
		   			       info, ipmi_mem_free,
					       IPMI_SENSOR_TYPE_VOLTAGE,
					       IPMI_UNIT_TYPE_VOLTS,
					       "5V",
					       0, 0,
					       i2c_sens_get_reading,
					       192, 183, 201,
					       26, 8, 0, -3,
					       &(sinfo->v5));
    if (rv) {
	ipmi_mem_free(info);
	goto out;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->bus = bus;
    info->addr = addr;
    info->offset = 0x24; /* Offset 0x24 is the 12V sens. */
    /* Nominal is 192 (12V), step is 62.5mV.  Since 625 is too
       large for 10-bit signed, we use 63 and modify the B value
       to make it exactly 12v at the nominal value. */
    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, num+4,
		   			       info, ipmi_mem_free,
					       IPMI_SENSOR_TYPE_VOLTAGE,
					       IPMI_UNIT_TYPE_VOLTS,
					       "12V",
					       0, 0,
					       i2c_sens_get_reading,
					       192, 183, 201,
					       63, -96, 0, -3,
					       &(sinfo->v12));
    if (rv) {
	ipmi_mem_free(info);
	goto out;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->bus = bus;
    info->addr = addr;
    info->offset = 0x21; /* Offset 0x21 is the Vcpp1 sens., which is -12V */
    /* Nominal is 105 (-12V), step is 68mV.  The Vccp1 itself is 14.1mV
       per step and zero-based, the equation for the resistor network is
       V = (4.8265 * Vccp1) - 19.1326. */
    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, num+5,
		   			       info, ipmi_mem_free,
					       IPMI_SENSOR_TYPE_VOLTAGE,
					       IPMI_UNIT_TYPE_VOLTS,
					       "-12V",
					       0, 0,
					       i2c_sens_get_reading,
					       105, 87, 123,
					       68, -191, 2, -3,
					       &sinfo->vneg12);
    if (rv) {
	ipmi_mem_free(info);
	goto out;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->bus = bus;
    info->addr = addr;
    info->offset = 0x25; /* Offset 0x25 is the Vcpp2 sens., which is 1.5V */
    /* Nominal is 117 (1.5V), step is 14.1mV. */
    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, num+6,
		   			       info, ipmi_mem_free,
					       IPMI_SENSOR_TYPE_VOLTAGE,
					       IPMI_UNIT_TYPE_VOLTS,
					       "Vccp",
					       0, 0,
					       i2c_sens_get_reading,
					       117, 112, 122,
					       141, -70, 0, -4,
					       &sinfo->vccp);
    if (rv) {
	ipmi_mem_free(info);
	goto out;
    }

 out:
    return rv;
}

typedef struct mxp_5365_info_s
{
    adm1021_sensor_info_t adm1021;
    adm9240_sensor_info_t adm9240;
    board_sensor_info_t   board;
} mxp_5365_info_t;

static void
mxp_5365_removal_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    mxp_5365_info_t *sinfo = cb_data;

    destroy_board_sensors(mc, &(sinfo->board));
    destroy_adm1021_sensors(mc, &(sinfo->adm1021));
    destroy_adm9240_sensors(mc, &(sinfo->adm9240));
    ipmi_mem_free(sinfo);
}

static int
mxp_5365_handler(ipmi_mc_t     *mc,
		 void          *cb_data)
{
    unsigned int       slave_addr = ipmi_mc_get_address(mc);
    ipmi_entity_info_t *ents;
    ipmi_entity_t      *ent;
    int                rv;
    char               *board_name;
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    ipmi_mc_t          *bmc;
    mxp_info_t         *info = NULL;
    mxp_5365_info_t    *sinfo = NULL;
    ipmi_ipmb_addr_t   addr = {IPMI_IPMB_ADDR_TYPE, 0, 0x20, 0};

    ipmi_domain_entity_lock(domain);

    bmc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &addr, sizeof(addr));
    if (bmc
	&& (ipmi_mc_manufacturer_id(bmc) == MXP_MANUFACTURER_ID)
	&& (ipmi_mc_product_id(bmc) == MXP_AMC_PRODUCT_ID))
    {
	int        i;

	info = ipmi_mc_get_oem_data(bmc);
	/* We are in an MXP chassis, we can get the index and the name
           from the table */
	i = mxp_board_addr_to_index(slave_addr, info);
	if (i < 0)
	    board_name = "5365 board";
	else
	    board_name = board_entity_str[i];
    } else {
	/* Not in an MXP chassis, just give it a generic name. */
	board_name = "5365 board";
    }

    sinfo = ipmi_mem_alloc(sizeof(*sinfo));
    if (!sinfo) {
	rv = ENOMEM;
	goto out;
    }

    ents = ipmi_domain_get_entities(domain);
    rv = ipmi_entity_add(ents, domain, mc, 0,
			 IPMI_ENTITY_ID_PROCESSING_BLADE,
			 mxp_addr_to_instance(slave_addr),
			 board_name, IPMI_ASCII_STR, strlen(board_name),
			 mxp_entity_sdr_add,
			 NULL, &ent);
    if (rv)
	goto out;

    rv = new_board_sensors(mc, ent, info, &(sinfo->board));
    if (rv)
	goto out;

    rv = alloc_adm1021_sensor(mc, ent, 0x80, 0x01, 0x9c, "Proc Temp",
			      &(sinfo->adm1021));
    if (rv)
	goto out;

    rv = alloc_adm9240_sensor(mc, ent, 0x81, 0x01, 0x5a, &(sinfo->adm9240));
    if (rv)
	goto out;

    rv = ipmi_mc_add_oem_removed_handler(mc, mxp_5365_removal_handler, sinfo, NULL);

 out:
    if (rv && sinfo)
	ipmi_mem_free(sinfo);
    ipmi_domain_entity_unlock(domain);
    return rv;
}

typedef struct mxp_5385_info_s
{
    board_sensor_info_t   board;
} mxp_5385_info_t;

static void
mxp_5385_removal_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    mxp_5385_info_t *sinfo = cb_data;

    destroy_board_sensors(mc, &(sinfo->board));
    ipmi_mem_free(sinfo);
}

static int
mxp_5385_handler(ipmi_mc_t     *mc,
		 void          *cb_data)
{
    unsigned int       slave_addr = ipmi_mc_get_address(mc);
    ipmi_entity_info_t *ents;
    ipmi_entity_t      *ent;
    int                rv;
    char               *board_name;
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    ipmi_mc_t          *bmc;
    mxp_info_t         *info = NULL;
    mxp_5385_info_t    *sinfo = NULL;
    ipmi_ipmb_addr_t   addr = {IPMI_IPMB_ADDR_TYPE, 0, 0x20, 0};

    ipmi_domain_entity_lock(domain);

    bmc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &addr, sizeof(addr));
    if (bmc
	&& (ipmi_mc_manufacturer_id(bmc) == MXP_MANUFACTURER_ID)
	&& (ipmi_mc_product_id(bmc) == MXP_AMC_PRODUCT_ID))
    {
	int        i;

	info = ipmi_mc_get_oem_data(bmc);
	/* We are in an MXP chassis, we can get the index and the name
           from the table */
	i = mxp_board_addr_to_index(slave_addr, info);
	if (i < 0)
	    board_name = "5385 board";
	else
	    board_name = board_entity_str[i];
    } else {
	/* Not in an MXP chassis, just give it a generic name. */
	board_name = "5385 board";
    }
	    
    sinfo = ipmi_mem_alloc(sizeof(*sinfo));
    if (!sinfo) {
	rv = ENOMEM;
	goto out;
    }

    ents = ipmi_domain_get_entities(domain);
    rv = ipmi_entity_add(ents, domain, mc, 0,
			 IPMI_ENTITY_ID_PROCESSING_BLADE,
			 mxp_addr_to_instance(slave_addr),
			 board_name, IPMI_ASCII_STR, strlen(board_name),
			 mxp_entity_sdr_add,
			 NULL, &ent);
    if (rv)
	goto out;

    rv = new_board_sensors(mc, ent, info, &(sinfo->board));
    if (rv)
	goto out;

    rv = ipmi_mc_add_oem_removed_handler(mc, mxp_5385_removal_handler, sinfo, NULL);

 out:
    if (rv && sinfo)
	ipmi_mem_free(sinfo);
    ipmi_domain_entity_unlock(domain);
    return rv;
}

typedef struct mxp_pprb_info_s
{
    board_sensor_info_t   board;
} mxp_pprb_info_t;

static void
mxp_pprb_removal_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    mxp_pprb_info_t *sinfo = cb_data;

    destroy_board_sensors(mc, &(sinfo->board));
    ipmi_mem_free(sinfo);
}

static int
mxp_pprb_handler(ipmi_mc_t     *mc,
		 void          *cb_data)
{
    unsigned int       slave_addr = ipmi_mc_get_address(mc);
    ipmi_entity_info_t *ents;
    ipmi_entity_t      *ent;
    int                rv;
    char               *board_name;
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    ipmi_mc_t          *bmc;
    mxp_info_t         *info = NULL;
    mxp_pprb_info_t    *sinfo = NULL;
    ipmi_ipmb_addr_t   addr = {IPMI_IPMB_ADDR_TYPE, 0, 0x20, 0};

    ipmi_domain_entity_lock(domain);

    bmc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &addr, sizeof(addr));
    if (bmc
	&& (ipmi_mc_manufacturer_id(bmc) == MXP_MANUFACTURER_ID)
	&& (ipmi_mc_product_id(bmc) == MXP_AMC_PRODUCT_ID))
    {
	int        i;

	info = ipmi_mc_get_oem_data(bmc);
	/* We are in an MXP chassis, we can get the index and the name
           from the table */
	i = mxp_board_addr_to_index(slave_addr, info);
	if (i < 0)
	    board_name = "pprb board";
	else
	    board_name = board_entity_str[i];
    } else {
	/* Not in an MXP chassis, just give it a generic name. */
	board_name = "pprb board";
    }
	    
    sinfo = ipmi_mem_alloc(sizeof(*sinfo));
    if (!sinfo) {
	rv = ENOMEM;
	goto out;
    }

    ents = ipmi_domain_get_entities(domain);
    rv = ipmi_entity_add(ents, domain, mc, 0,
			 IPMI_ENTITY_ID_PROCESSING_BLADE,
			 mxp_addr_to_instance(slave_addr),
			 board_name, IPMI_ASCII_STR, strlen(board_name),
			 mxp_entity_sdr_add,
			 NULL, &ent);
    if (rv)
	goto out;

    rv = new_board_sensors(mc, ent, info, &(sinfo->board));
    if (rv)
	goto out;

    rv = ipmi_mc_add_oem_removed_handler(mc, mxp_pprb_removal_handler, sinfo, NULL);

 out:
    if (rv && sinfo)
	ipmi_mem_free(sinfo);
    ipmi_domain_entity_unlock(domain);
    return rv;
}

typedef struct zynx_info_s
{
    board_sensor_info_t board;
    ipmi_sensor_t *board_temp;
    ipmi_sensor_t *v2_5;
    ipmi_sensor_t *v1_8;
    ipmi_sensor_t *v3_3;
    ipmi_sensor_t *v5;
} zynx_info_t;

static void
zynx_removal_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    zynx_info_t *sinfo = cb_data;

    destroy_board_sensors(mc, &(sinfo->board));
    if (sinfo->board_temp)
	ipmi_sensor_destroy(sinfo->board_temp);
    if (sinfo->v2_5)
	ipmi_sensor_destroy(sinfo->v2_5);
    if (sinfo->v1_8)
	ipmi_sensor_destroy(sinfo->v1_8);
    if (sinfo->v3_3)
	ipmi_sensor_destroy(sinfo->v3_3);
    if (sinfo->v5)
	ipmi_sensor_destroy(sinfo->v5);
    ipmi_mem_free(sinfo);
}

static int
zynx_switch_handler(ipmi_mc_t     *mc,
		    void          *cb_data)
{
    unsigned int       slave_addr = ipmi_mc_get_address(mc);
    ipmi_entity_info_t *ents;
    ipmi_entity_t      *ent;
    int                rv;
    char               *board_name;
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    ipmi_mc_t          *bmc;
    mxp_info_t         *info = NULL;
    int                i;
    zynx_info_t        *sinfo = NULL;
    ipmi_ipmb_addr_t   addr = {IPMI_IPMB_ADDR_TYPE, 0, 0x20, 0};
    int (*get)(ipmi_sensor_t *, ipmi_reading_done_cb, void *)
	= ipmi_standard_sensor_cb.ipmi_reading_get;

    ipmi_domain_entity_lock(domain);

    bmc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &addr, sizeof(addr));
    if (bmc
	&& (ipmi_mc_manufacturer_id(bmc) == MXP_MANUFACTURER_ID)
	&& (ipmi_mc_product_id(bmc) == MXP_AMC_PRODUCT_ID))
    {
	info = ipmi_mc_get_oem_data(bmc);
	/* We are in an MXP chassis, we can get the index and the name
           from the table */
	i = mxp_board_addr_to_index(slave_addr, info);
	if (i < 0)
	    board_name = "MXP SWTCH";
	else
	    board_name = board_entity_str[i];
    } else {
	/* Not in an MXP chassis, just give it a generic name. */
	board_name = "MXP SWTCH";
    }

    sinfo = ipmi_mem_alloc(sizeof(*sinfo));
    if (!sinfo) {
	rv = ENOMEM;
	goto out;
    }

    ents = ipmi_domain_get_entities(domain);
    rv = ipmi_entity_add(ents, domain, mc, 0,
			 IPMI_ENTITY_ID_CONNECTIVITY_SWITCH,
			 mxp_addr_to_instance(slave_addr),
			 board_name, IPMI_ASCII_STR, strlen(board_name),
			 mxp_entity_sdr_add,
			 NULL, &ent);
    if (rv)
	goto out;

    rv = new_board_sensors(mc, ent, info, &(sinfo->board));
    if (rv)
	goto out;

    /* This is the temperature sensor on the board.  It's accessed
       using a standard reading command, but there's no SDR for it. */
    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, 0x60, info, NULL,
					       IPMI_SENSOR_TYPE_TEMPERATURE,
					       IPMI_UNIT_TYPE_DEGREES_C,
					       "Board Temp",
					       0, 0,
					       get,
					       -1, -1, 55,
					       1, 0, 0, 0,
					       &(sinfo->board_temp));
    if (rv)
	goto out;
    ipmi_sensor_set_analog_data_format(sinfo->board_temp,
				       IPMI_ANALOG_DATA_FORMAT_2_COMPL);
    ipmi_sensor_set_raw_sensor_max(sinfo->board_temp, 0x7f);
    ipmi_sensor_set_raw_sensor_min(sinfo->board_temp, 0x80);


    /*
     * Here's the calculations from ZYNX for converting the voltage
     * readings from raw values to cooked values.:
     *
     * Voltage rails      SensorNumber      Normalized Value     Tolerance
     * Calculation
     * -------------------------------------------------------------------
     * 2.5 V              0x41              ~2.0 V                 5%
     *  Actual Voltage on 2.5V Rail = 1.23 * ((SV41/255) * 3.3)
     * 1.8 V              0x42              ~1.8 V                 5%
     *  Actual Voltage on 1.8V Rail =  (SV42/255) * 3.3
     * 3.3 V              0x43              ~2.0 V		   5%
     *  Actual Voltage on 3.3V Rail = 1.67 * ((SV43/255) * 3.3)
     * 5.0 V              0x45              ~2.0 V                 5%
     *  Actual Voltage on 5V Rail = 2.48* ((SV45/255) * 3.3)
     */

    /* This is the voltage sensors on the board.  It's accessed
       using a standard reading command, but there's no SDR for it. */
    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, 0x41, info, NULL,
					       IPMI_SENSOR_TYPE_VOLTAGE,
					       IPMI_UNIT_TYPE_VOLTS,
					       "2.5V",
					       0, 0,
					       get,
					       157, 150, 165,
					       159, 0, 0, -4,
					       &(sinfo->v2_5));
    if (rv)
	goto out;

    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, 0x42, info, NULL,
					       IPMI_SENSOR_TYPE_VOLTAGE,
					       IPMI_UNIT_TYPE_VOLTS,
					       "1.8V",
					       0, 0,
					       get,
					       139, 133, 146,
					       129, 0, 0, -4,
					       &(sinfo->v1_8));
    if (rv)
	goto out;

    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, 0x43, info, NULL,
					       IPMI_SENSOR_TYPE_VOLTAGE,
					       IPMI_UNIT_TYPE_VOLTS,
					       "3.3V",
					       0, 0,
					       get,
					       153, 146, 160,
					       216, 0, 0, -4,
					       &(sinfo->v3_3));
    if (rv)
	goto out;

    rv = mxp_alloc_semi_stand_threshold_sensor(mc, ent, 0x45, info, NULL,
					       IPMI_SENSOR_TYPE_VOLTAGE,
					       IPMI_UNIT_TYPE_VOLTS,
					       "5V",
					       0, 0,
					       get,
					       156, 148, 163,
					       321, 0, 0, -4,
					       &(sinfo->v5));
    if (rv)
	goto out;

    rv = ipmi_mc_add_oem_removed_handler(mc, zynx_removal_handler, sinfo, NULL);

 out:
    if (rv && sinfo)
	ipmi_mem_free(sinfo);
    ipmi_domain_entity_unlock(domain);
    return rv;
}

/***********************************************************************
 *
 * Handling for the MXP startup and shutdown.
 *
 **********************************************************************/

static void
mxp_chassis_type_rsp(ipmi_mc_t  *src,
		     ipmi_msg_t *msg,
		     void       *rsp_data)
{
    mxp_info_t *info = rsp_data;

    if (msg->data[0] != 0) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "mxp_chassis_type_rsp: Error getting chassis id: 0x%x",
		 msg->data[0]);
	/* Destroy the MC so it will be detected again late,r and hopefully
	   will work that time. */
	_ipmi_cleanup_mc(src);
	return;
    }

    info->chassis_type = msg->data[4];
    switch (info->chassis_type) {
	case 1:
	    info->chassis_config = MXP_CHASSIS_CONFIG_6U;
	    break;

	case 2:
        case 3: /* AC Supply */
        case 4: /* DC supply */
	    info->chassis_config = MXP_CHASSIS_CONFIG_3U;
	    break;

	default:
	    ipmi_log(IPMI_LOG_WARNING,
		     "mxp_chassis_type_rsp: Unknown chassis type: 0x%x",
		     info->chassis_type);

	    /* Default to 3U. */
	    info->chassis_config = MXP_CHASSIS_CONFIG_3U;
	    return;
    }

    mxp_create_entities(info->mc, info);
    ipmi_detect_domain_presence_changes(info->domain, 1);
}

static void
mxp_setup_finished(ipmi_mc_t *mc, mxp_info_t *info)
{
    ipmi_msg_t    msg;
    unsigned char data[3];
    int           rv;

    /* Query the chassis type, continue from there. */
    add_mxp_mfg_id(data);
    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_CHASSIS_TYPE_CMD;
    msg.data_len = 3;
    msg.data = data;
    rv = ipmi_mc_send_command(info->mc, 0, &msg, mxp_chassis_type_rsp, info);
    if (rv)
	ipmi_log(IPMI_LOG_WARNING,
		 "mxp_setup_finished: Error sending chassis type request: %x",
		 rv);
}

static void
mxp_removal_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    mxp_info_t *info = cb_data;
    int        i;

    if (!info->chassis_id)
	/* It hasn't been initialized, so just free the data structure. */
	goto out;

    for (i=0; i<MXP_POWER_SUPPLIES; i++) {
	if (info->power_supply[i].ent)
	    ipmi_entity_remove_child(info->chassis_ent,
				     info->power_supply[i].ent);
	if (info->power_supply[i].fan_ent)
	    ipmi_entity_remove_child(info->power_supply[i].ent,
				     info->power_supply[i].fan_ent);
	if (info->power_supply[i].presence)
	    ipmi_sensor_destroy(info->power_supply[i].presence);
	if (info->power_supply[i].ps)
	    ipmi_sensor_destroy(info->power_supply[i].ps);
	if (info->power_supply[i].enable)
	    ipmi_control_destroy(info->power_supply[i].enable);
	if (info->power_supply[i].oos_led)
	    ipmi_control_destroy(info->power_supply[i].oos_led);
	if (info->power_supply[i].inserv_led)
	    ipmi_control_destroy(info->power_supply[i].inserv_led);
	if (info->power_supply[i].ps_type)
	    ipmi_control_destroy(info->power_supply[i].ps_type);
	if (info->power_supply[i].ps_revision)
	    ipmi_control_destroy(info->power_supply[i].ps_revision);
	if (info->power_supply[i].fan_presence)
	    ipmi_sensor_destroy(info->power_supply[i].fan_presence);
	if (info->power_supply[i].fan_i2c_enable)
	    ipmi_sensor_destroy(info->power_supply[i].fan_i2c_enable);
	if (info->power_supply[i].fan_type)
	    ipmi_control_destroy(info->power_supply[i].fan_type);
	if (info->power_supply[i].fan_revision)
	    ipmi_control_destroy(info->power_supply[i].fan_revision);
	if (info->power_supply[i].fan)
	    ipmi_sensor_destroy(info->power_supply[i].fan);
	if (info->power_supply[i].cooling)
	    ipmi_sensor_destroy(info->power_supply[i].cooling);
	if (info->power_supply[i].fan_speed)
	    ipmi_control_destroy(info->power_supply[i].fan_speed);
	if (info->power_supply[i].fan_oos_led)
	    ipmi_control_destroy(info->power_supply[i].fan_oos_led);
	if (info->power_supply[i].fan_inserv_led)
	    ipmi_control_destroy(info->power_supply[i].fan_inserv_led);
    }

    for (i=0; i<MXP_TOTAL_BOARDS; i++) {
	ipmi_entity_remove_child(info->chassis_ent, info->board[i].ent);
	if (info->board[i].presence)
	    ipmi_sensor_destroy(info->board[i].presence);
	if (info->board[i].slot)
	    ipmi_sensor_destroy(info->board[i].slot);
	if (info->board[i].oos_led)
	    ipmi_control_destroy(info->board[i].oos_led);
	if (info->board[i].inserv_led)
	    ipmi_control_destroy(info->board[i].inserv_led);
	if (info->board[i].bd_sel)
	    ipmi_control_destroy(info->board[i].bd_sel);
	if (info->board[i].pci_reset)
	    ipmi_control_destroy(info->board[i].pci_reset);
	if (info->board[i].slot_init)
	    ipmi_control_destroy(info->board[i].slot_init);
	if (info->board[i].i2c_isolate)
	    ipmi_control_destroy(info->board[i].i2c_isolate);
    }
    
    if (info->chassis_id)
	ipmi_control_destroy(info->chassis_id);
    if (info->chassis_type_control)
	ipmi_control_destroy(info->chassis_type_control);
    if (info->shelf_ga_control)
	ipmi_control_destroy(info->shelf_ga_control);
    if (info->relays)
	ipmi_control_destroy(info->relays);
    if (info->sys_led)
	ipmi_control_destroy(info->sys_led);

    if (info->con_ch_info)
    	ipmi_domain_remove_con_change_handler(domain,
					      info->con_ch_info->con_chid);
    ipmi_domain_remove_mc_update_handler(domain, info->mc_upd_id);
    ipmi_mem_free(info->con_ch_info);

 out:
    ipmi_mem_free(info);
}

static void
con_up_mc(ipmi_mc_t *mc, void *cb_data)
{
    mxp_info_t *info = ipmi_mc_get_oem_data(mc);

    mxp_setup_finished(mc, info);
}

static void
con_up_handler(ipmi_domain_t *domain,
	       int           err,
	       unsigned int  conn_num,
	       unsigned int  port_num,
	       int           still_connected,
	       void          *cb_data)
{
    domain_up_info_t *info = cb_data;

    if (!info->up && still_connected) {
	ipmi_mc_pointer_cb(info->mcid, con_up_mc, info);
	info->up = 1;
    }
}

/* Handle the BMC connection (address 0x20) */
static int
mxp_bmc_handler(ipmi_mc_t *mc)
{
    int           rv;
    mxp_info_t    *info;
    ipmi_domain_t *domain = ipmi_mc_get_domain(mc);

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));

    /* Fixups for problems in configuration. */
    /* Disable the SEL for the BMC device, just use the AMC devices to
       get the events. */
    ipmi_mc_set_sel_device_support(mc, 0);

    info->mc = mc;
    info->mfg_id = MXP_MANUFACTURER_ID;
    info->domain = domain;

    ipmi_mc_set_oem_data(mc, info);

    rv = ipmi_mc_add_oem_removed_handler(mc, mxp_removal_handler, info, NULL);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "mxp_handler: could not register removal handler");
	goto out_err;
    }

    rv = ipmi_mc_set_oem_new_sensor_handler(mc, mxp_new_sensor, info);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "mxp_handler: could not register new sensor handler");
	goto out_err;
    }

    /* Ignore the IPMB addresses of the power supplies. */
    rv = ipmi_domain_add_ipmb_ignore(domain, 0x54);
    if (rv)
	ipmi_log(IPMI_LOG_WARNING,
		 "mxp_handler: could not ignore IPMB address 0x54");
    rv = ipmi_domain_add_ipmb_ignore(domain, 0x56);
    if (rv)
	ipmi_log(IPMI_LOG_WARNING,
		 "mxp_handler: could not ignore IPMB address 0x56");
    rv = ipmi_domain_add_ipmb_ignore(domain, 0x58);
    if (rv)
	ipmi_log(IPMI_LOG_WARNING,
		 "mxp_handler: could not ignore IPMB address 0x58");

    if (ipmi_domain_con_up(domain)) {
	/* The domain is already up, just start the process. */
	mxp_setup_finished(mc, info);
	rv = 0;
    } else {
	info->con_ch_info = ipmi_mem_alloc(sizeof(domain_up_info_t));
	if (!info->con_ch_info) {
	    rv = ENOMEM;
	    goto out_err;
	}
	info->con_ch_info->up = 0;
	info->con_ch_info->mcid = ipmi_mc_convert_to_id(mc);
	info->con_ch_info->info = info;
	rv = ipmi_domain_add_con_change_handler(domain, con_up_handler,
						info->con_ch_info,
					       	&info->con_ch_info->con_chid);
	if (rv) {
	    ipmi_mem_free(info->con_ch_info);
	    goto out_err;
	}
	
	rv = ipmi_domain_register_mc_update_handler(domain, mc_upd_handler,
						    NULL, &info->mc_upd_id);
	if (rv)
	    goto out_err;
    }

 out_err:
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

static int
mxp_handler(ipmi_mc_t *mc,
	    void      *cb_data)
{
    int           rv;
    ipmi_domain_t *domain = ipmi_mc_get_domain(mc);

    /* The MXP AMC does not support generating events on the IPMB. */
    ipmi_mc_set_ipmb_event_generator_support(mc, 0);

    /* Broadcasting is currently broken on the MXP. */
    ipmi_domain_set_broadcast_broken(domain, 1);

    if (ipmi_mc_get_channel(mc) == IPMI_BMC_CHANNEL) {
	rv = amc_board_handler(mc);
    } else {
	rv = mxp_bmc_handler(mc);
    }

    return rv;
}

/* We don't actually fetch the IPMB address, since it is alway 0x20.
   Instead, we get the AMC status to see if we are active or not. */
static void
ipmb_handler(ipmi_con_t   *ipmi,
	     ipmi_addr_t  *addr,
	     unsigned int addr_len,
	     ipmi_msg_t   *msg,
	     void         *rsp_data1,
	     void         *rsp_data2,
	     void         *rsp_data3,
	     void         *rsp_data4)
{
    ipmi_ll_ipmb_addr_cb handler = rsp_data1;
    void                 *cb_data = rsp_data2;
    int                  active = 0;
    int                  err = 0;
    
    if (msg->data[0] != 0)
	err = IPMI_IPMI_ERR_VAL(msg->data[0]);
    else if (msg->data_len < 23)
	err = EINVAL;
    /* The MXP doc says "0" is inactive, but the AMC seems to return 2
       when inactive. */
    else if ((msg->data[4] == 0) || (msg->data[4] == 2))
	active = 0;
    else
	active = 1;

    if (!err)
	ipmi->set_ipmb_addr(ipmi, 0x20, active);

    if (handler)
	handler(ipmi, err, 0x20, active, cb_data);
}

static int
mxp_ipmb_fetch(ipmi_con_t *conn, ipmi_ll_ipmb_addr_cb handler, void *cb_data)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    unsigned char		 data[3];

    /* Send the OEM command to get the IPMB address. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_GET_AMC_STATUS_CMD;
    msg.data = data;
    msg.data_len = 3;
    add_mxp_mfg_id(data);

    return conn->send_command(conn, (ipmi_addr_t *) &si, sizeof(si), &msg,
			      ipmb_handler, handler, cb_data, NULL, NULL);
}

static void
activate_handler(ipmi_con_t   *ipmi,
		 ipmi_addr_t  *addr,
		 unsigned int addr_len,
		 ipmi_msg_t   *rmsg,
		 void         *rsp_data1,
		 void         *rsp_data2,
		 void         *rsp_data3,
		 void         *rsp_data4)
{
    ipmi_ll_ipmb_addr_cb         handler = rsp_data1;
    void                         *cb_data = rsp_data2;
    unsigned char                ipmb = 0;
    int                          err = 0;
    int                          rv;
    
    if (rmsg->data[0] != 0) {
	err = IPMI_IPMI_ERR_VAL(rmsg->data[0]);
	if (handler)
	    handler(ipmi, err, ipmb, 0, cb_data);
    } else {
	rv = mxp_ipmb_fetch(ipmi, handler, cb_data);
	if (rv) {
	    if (handler)
		handler(ipmi, rv, ipmb, 0, cb_data);
	}
    }
}

static int
mxp_activate(ipmi_con_t           *conn,
	     int                  active,
	     ipmi_ll_ipmb_addr_cb handler,
	     void                 *cb_data)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    unsigned char                data[5];

    /* Send the OEM command to set the IPMB address. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;

    msg.netfn = MXP_NETFN_MXP1;
    msg.cmd = MXP_OEM_SET_DUAL_CONTROL_CMD;
    msg.data = data;
    msg.data_len = 5;
    add_mxp_mfg_id(data);
    if (active)
	data[3] = 2; /* Takeover */
    else
	data[3] = 1; /* Release */
    data[4] = 1; /* Always force it. */

    return conn->send_command(conn, (ipmi_addr_t *) &si, sizeof(si), &msg,
			      activate_handler, handler, cb_data, NULL, NULL);
}

static int
mxp_handle_send_rsp_err(ipmi_con_t *ipmi, ipmi_msg_t *rsp)
{
    ipmi_msg_t                   msg;
    unsigned char                data[3];
    ipmi_system_interface_addr_t si;

    if (rsp->data[0] == 0x82) {
	/* If we get a 0x82 response from an MXP send, we send an IPMB
	   auto-isolate command to clean up the bus. */
	msg.netfn = MXP_NETFN_MXP1;
	msg.cmd = MXP_OEM_SET_AUTO_IPMB_ISOLATE_CMD;
	msg.data = data;
	msg.data_len = 3;
	add_mxp_mfg_id(data);
	si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si.channel = 0;
	si.lun = 0;
	ipmi->send_command(ipmi, (ipmi_addr_t *) &si, sizeof(si), &msg,
			   NULL, NULL, NULL, NULL, NULL);

	/* Don't handle the message, let a timeout and resend occur. */
	return 1;
    }

    return 0;
}

static int
mxp_conn_handler(ipmi_con_t *conn, void *cb_data)
{
    conn->get_ipmb_addr = mxp_ipmb_fetch;
    conn->set_active_state = mxp_activate;
    conn->handle_send_rsp_err = mxp_handle_send_rsp_err;
    return 0;
}

int
ipmi_oem_motorola_mxp_init(void)
{
    int rv;

    rv = ipmi_register_oem_conn_handler(MXP_MANUFACTURER_ID,
					MXP_AMC_PRODUCT_ID,
					mxp_conn_handler,
					NULL);
    if (rv)
	return rv;

    rv = ipmi_register_oem_handler(MXP_MANUFACTURER_ID,
				   MXP_AMC_PRODUCT_ID,
				   mxp_handler,
				   NULL,
				   NULL);
    if (rv)
	return rv;

    rv = ipmi_register_oem_handler(MXP_MANUFACTURER_ID,
				   MXP_805_PRODUCT_ID,
				   mxp_805_handler,
				   NULL,
				   NULL);
    if (rv)
	return rv;

    rv = ipmi_register_oem_handler(MXP_MANUFACTURER_ID,
				   MXP_5365_PRODUCT_ID,
				   mxp_5365_handler,
				   NULL,
				   NULL);
    if (rv)
	return rv;

    rv = ipmi_register_oem_handler(MXP_MANUFACTURER_ID,
				   MXP_5385_PRODUCT_ID,
				   mxp_5385_handler,
				   NULL,
				   NULL);
    if (rv)
	return rv;

    rv = ipmi_register_oem_handler(MXP_MANUFACTURER_ID,
				   MXP_PPRB_PRODUCT_ID,
				   mxp_pprb_handler,
				   NULL,
				   NULL);
    if (rv)
	return rv;

    rv = ipmi_register_oem_handler(ZYNX_MANUFACTURER_ID,
				   ZYNX_SWITCH_PRODUCT_ID2,
				   zynx_switch_handler,
				   NULL,
				   NULL);
    if (rv)
	return rv;

    return ipmi_register_oem_handler(MXP_MANUFACTURER_ID,
				     ZYNX_SWITCH_PRODUCT_ID,
				     zynx_switch_handler,
				     NULL,
				     NULL);
}
