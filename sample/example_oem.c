/*
 * example_oem.c
 *
 * Example OEM code
 *
 * (C) 2003 MontaVista Software, Inc.  All right reserved.
 *
 * This code is placed into the public domain, you may use this code
 * incorporate it into a design, or whatever you want.
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
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <OpenIPMI/ipmi_oem.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_sensor.h>
#include <OpenIPMI/ipmi_control.h>
#include <OpenIPMI/ipmi_entity.h>
#include <OpenIPMI/ipmi_addr.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_msgbits.h>

/* These are the identifiers used in the get device id command to
   identify the various board types. */
#define OEM_MANUFACTURER_ID	0x998877
#define OEM_PRODUCT_ID		0x6655

/* Information common to all sensors. */
typedef struct oem_sensor_header_s
{
    unsigned int assert_events;
    unsigned int deassert_events;
    void         *data;
    void         (*data_freer)(void *);
} oem_sensor_header_t;

/* Information common to all controls. */
typedef struct oem_control_header_s
{
    void         *data;
} oem_control_header_t;

/* Various LED settings. */
static ipmi_control_transition_t off_led[]
= { {IPMI_CONTROL_COLOR_BLACK, 1 } };
static ipmi_control_transition_t on_blue_led[]
= { { IPMI_CONTROL_COLOR_BLUE, 1 } };
static ipmi_control_transition_t blue_led1[] = /* A flashing blue LED. */
{
    { IPMI_CONTROL_COLOR_BLUE, 500 },
    { IPMI_CONTROL_COLOR_BLACK, 500 },
};

/* Setting 0 if off, setting 1 is solid on, setting 2 is flashing. */
static ipmi_control_setting_t blue_blinking_led_set[] =
{
    { 1, off_led },
    { 1, on_blue_led },
    { 2, blue_led1 },
};

static ipmi_control_light_t blue_blinking_led[]
= {{ 3, blue_blinking_led_set }};

typedef struct oem_sens_info_s oem_sens_info_t;

typedef void (*oem_states_get_val_cb)(ipmi_sensor_t   *sensor,
				      oem_sens_info_t *sens_info,
				      unsigned char   *data,
				      ipmi_states_t   *states);

/* Should return the new error. */
typedef int (*oem_states_err_cb)(ipmi_sensor_t   *sensor,
				 oem_sens_info_t *sens_info,
				 int             err,
				 unsigned char   *data,
				 ipmi_states_t   *states);

struct oem_sens_info_s
{
    ipmi_sensor_op_info_t sdata;
    void                  *sdinfo;
    oem_states_get_val_cb get_states;
    oem_states_err_cb     err_states;
    ipmi_states_read_cb   done;
    void                  *cb_data;
};

static oem_sens_info_t *
alloc_sens_info(void *sdinfo, ipmi_states_read_cb done, void *cb_data)
{
    oem_sens_info_t *sens_info;

    sens_info = ipmi_mem_alloc(sizeof(*sens_info));
    if (!sens_info)
	return NULL;
    memset(sens_info, 0, sizeof(*sens_info));
    sens_info->sdinfo = sdinfo;
    sens_info->done = done;
    sens_info->cb_data = cb_data;
    return sens_info;
}

typedef struct oem_control_info_s oem_control_info_t;

typedef int (*oem_control_get_val_cb)(ipmi_control_t     *control,
				      oem_control_info_t *control_info,
				      unsigned char      *data);

struct oem_control_info_s
{
    ipmi_control_op_info_t         sdata;
    unsigned char                  vals[4];
    void                           *idinfo;
    ipmi_control_op_cb             done_set;
    ipmi_control_val_cb            done_get;
    oem_control_get_val_cb         get_val;
    ipmi_control_identifier_val_cb get_identifier_val;
    void                           *cb_data;
};

typedef struct oem_reading_done_s
{
    ipmi_sensor_op_info_t sdata;
    void                  *sdinfo;
    ipmi_reading_done_cb  done;
    void                  *cb_data;
} oem_reading_done_t;

/* If registered against an MC, this will be called with each sensor.
   If you return 1, the sensor will NOT be added to the standard set
   of sensors for the MC. */
static int
oem_new_sensor(ipmi_mc_t     *mc,
	       ipmi_entity_t *ent,
	       ipmi_sensor_t *sensor,
	       void          *link,
	       void          *cb_data)
{
    int lun, num;

    ipmi_sensor_get_num(sensor, &lun, &num);

    /* This is where you fix up broken SDR info, and set sensors as
       hot-swap sensors, and the like.  You can also set custom data
       converters or whatever you like here. */
    switch (num) {
	default:
    }
    return 0;
}

/* The following are various OEM operations that you will need to
   override (or just use the standard ones */
static int
oem_events_enable_set(ipmi_sensor_t         *sensor,
		      ipmi_event_state_t    *states,
		      ipmi_sensor_done_cb   done,
		      void                  *cb_data)
{
    return ENOTSUP;
}

static int
oem_events_enable_get(ipmi_sensor_t             *sensor,
		      ipmi_event_enables_get_cb done,
		      void                      *cb_data)
{
    ipmi_event_state_t  state;
    oem_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);

    if (done) {
	ipmi_event_state_init(&state);
	ipmi_event_state_set_scanning_enabled(&state, 1);
	state.__assertion_events = hdr->assert_events;
	state.__deassertion_events = hdr->deassert_events;
	done(sensor, 0, &state, cb_data);
    }
    return 0;
}

static int
oem_sensor_get_hysteresis(ipmi_sensor_t          *sensor,
			  ipmi_hysteresis_get_cb done,
			  void                   *cb_data)
{
    return ENOSYS;
}

static int
oem_sensor_set_hysteresis(ipmi_sensor_t       *sensor,
			  unsigned int        positive_hysteresis,
			  unsigned int        negative_hysteresis,
			  ipmi_sensor_done_cb done,
			  void                *cb_data)
{
    return ENOSYS;
}

static int
oem_thresholds_get(ipmi_sensor_t      *sensor,
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
oem_thresholds_set(ipmi_sensor_t       *sensor,
		   ipmi_thresholds_t   *thresholds,
		   ipmi_sensor_done_cb done,
		   void                *cb_data)
{
    return ENOSYS;
}

static int
oem_sensor_get_tolerance(ipmi_sensor_t *sensor,
			 int           val,
			 double        *tolerance)
{
    return ENOSYS;
}

static int
oem_sensor_get_accuracy(ipmi_sensor_t *sensor,
			int           val,
			double        *accuracy)
{
    return ENOSYS;
}

/*
 * The get done operation for most discrete sensors is pretty
 * standard.  We call a function to extract the states from the
 * message, then call the user's callback.
 */
static void
oem_discrete_sensor_get_done(ipmi_sensor_t *sensor,
			     int           err,
			     ipmi_msg_t    *rsp,
			     void          *cb_data)
{
    oem_sens_info_t *sens_info = cb_data;
    ipmi_states_t   states;

    ipmi_init_states(&states);
    ipmi_set_sensor_scanning_enabled(&states, 1);

    if (err) {
	/* Check the error handler first, and let it handle the error. */
	if (sens_info->err_states) {
	    err = sens_info->err_states(sensor, sens_info, err,
					rsp->data, &states);
	    if (!err)
		goto deliver;
	}
	if (sens_info->done)
	    sens_info->done(sensor, err,
			    &states, sens_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "oem_discrete_sensor_get_done: Received IPMI error: %x",
		 rsp->data[0]);
	if (sens_info->done)
	    sens_info->done(sensor, IPMI_IPMI_ERR_VAL(rsp->data[0]),
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

/* Called to free the OEM data we attach to the sensor. */
static void
oem_cleanup_sensor_oem_info(ipmi_sensor_t *sensor, void *oem_info)
{
    oem_sensor_header_t *hdr = oem_info;

    if (hdr) {
	if (hdr->data_freer)
	    hdr->data_freer(hdr->data);
	ipmi_mem_free(hdr);
    }
}

/* Allocate basic sensor information. The parms are:
 *    data - Generic data for the sensor-specific handling to use.
 *    data_freer() - a function to handle cleaning up data when the
 *		sensor is freed
 *    sensor_type - the IPMI sensor type.
 *    reading_type - the IPMI reading type.
 *    id - The string name for the sensor.
 *    assert_events - The supported assertion event bitmask
 *    deassert_events - The supported deassertion event bitmask
 */
static int
oem_alloc_basic_sensor(
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
    oem_sensor_header_t *hdr;

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
    ipmi_sensor_set_oem_info(*sensor, hdr, oem_cleanup_sensor_oem_info);
    ipmi_sensor_set_entity_instance_logical(*sensor, 0);
    ipmi_sensor_set_sensor_init_scanning(*sensor, 1);
    ipmi_sensor_set_sensor_init_events(*sensor, 0);
    ipmi_sensor_set_sensor_init_thresholds(*sensor, 0);
    ipmi_sensor_set_sensor_init_hysteresis(*sensor, 0);
    ipmi_sensor_set_sensor_init_type(*sensor, 1);
    ipmi_sensor_set_sensor_init_pu_events(*sensor, 0);
    ipmi_sensor_set_sensor_init_pu_scanning(*sensor, 1);
    ipmi_sensor_set_ignore_for_presence(*sensor, 1);
    ipmi_sensor_set_supports_auto_rearm(*sensor, 1);
    if (assert_events || deassert_events)
        ipmi_sensor_set_event_support(*sensor, 
                                      IPMI_EVENT_SUPPORT_GLOBAL_ENABLE);
    else
        ipmi_sensor_set_event_support(*sensor, IPMI_EVENT_SUPPORT_NONE);

    ipmi_sensor_set_sensor_type(*sensor, sensor_type);
    ipmi_sensor_set_event_reading_type(*sensor, reading_type);
    ipmi_sensor_set_id(*sensor, id);

    ipmi_sensor_set_sensor_type_string(
	*sensor,
	ipmi_get_sensor_type_string(sensor_type));
    ipmi_sensor_set_event_reading_type_string(
	*sensor,
	ipmi_get_event_reading_type_string(reading_type));

    return rv;
}

/*
 * Finish the sensor handling, basically add it to the MC and entity.
 */
static int
oem_finish_sensor(ipmi_mc_t     *mc,
		  ipmi_sensor_t *sensor,
		  unsigned int  num,
		  ipmi_entity_t *entity)
{
    int rv;

    /* Add it to the MC and entity. */
    rv = ipmi_sensor_add_nonstandard(mc, sensor, num, entity, NULL, NULL);
    if (rv) {
	void *hdr;
        hdr = ipmi_sensor_get_oem_info(sensor);
	ipmi_sensor_destroy(sensor);
	ipmi_mem_free(hdr);
    }

    return rv;
}

/*
 * Allocate discrete sensor information. The first are the same as for the
 * basic sensor above.  The other parms are:
 *    states_get - A function that gets the current states.
 *    sensor_reading_name_string - A function to get the reading type
 *              string.  This may be NULL and the standard one will be
 *		used.
 */
static int
oem_alloc_discrete_sensor(
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

    rv = oem_alloc_basic_sensor(data,
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
    cbs.ipmi_sensor_events_enable_set = oem_events_enable_set;
    cbs.ipmi_sensor_events_enable_get = oem_events_enable_get;
    cbs.ipmi_states_get = states_get;

    /* If ths user supply a function to get the name strings, use it.
       Otherwise use the standard one. */
    if (sensor_reading_name_string)
	cbs.ipmi_sensor_reading_name_string = sensor_reading_name_string;
    else
	cbs.ipmi_sensor_reading_name_string
	    = ipmi_standard_sensor_cb.ipmi_sensor_reading_name_string;

    ipmi_sensor_set_callbacks(*sensor, &cbs);

    rv = oem_finish_sensor(mc, *sensor, num, entity);

    return rv;
}

/*
 * Allocate a semi-standard threshold sensor information. Semi-standard
 * means that it can use standard conversion formulas, is linear, and
 * is a more "normal" sensor.  The first parmse are the same as for the
 * basic sensor above.  The other parms are:
 *    reading_get - A function that gets the current reading.
 *    raw_nominal - the raw (0-255) value for the nominal reading.
 *    raw_normal_max - the raw value for the max value inside the
 *		threshold.
 *    raw_normal_max - the raw value for the min value inside the
 *		threshold.
 *    m, b, b_exp, r_exp - The sensor conversion values.
 */
static int
oem_alloc_semi_stand_threshold_sensor(
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

    rv = oem_alloc_basic_sensor(data,
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
    cbs.ipmi_sensor_events_enable_set = oem_events_enable_set;
    cbs.ipmi_sensor_events_enable_get = oem_events_enable_get;
    cbs.ipmi_sensor_convert_from_raw
	= ipmi_standard_sensor_cb.ipmi_sensor_convert_from_raw;
    cbs.ipmi_sensor_convert_to_raw
	= ipmi_standard_sensor_cb.ipmi_sensor_convert_to_raw;
    cbs.ipmi_sensor_get_accuracy = oem_sensor_get_accuracy;
    cbs.ipmi_sensor_get_tolerance = oem_sensor_get_tolerance;
    cbs.ipmi_sensor_get_hysteresis = oem_sensor_get_hysteresis;
    cbs.ipmi_sensor_set_hysteresis = oem_sensor_set_hysteresis;
    cbs.ipmi_thresholds_set = oem_thresholds_set;
    cbs.ipmi_thresholds_get = oem_thresholds_get;
    cbs.ipmi_reading_get = reading_get;
    ipmi_sensor_set_callbacks(*sensor, &cbs);

    rv = oem_finish_sensor(mc, *sensor, num, entity);

    return rv;
}

/*
 * This is used for controls, the handling for the set_done is common
 * for controls, so just do it in one place.
 */
static void
oem_control_set_done(ipmi_control_t *control,
		     int            err,
		     ipmi_msg_t     *rsp,
		     void           *cb_data)
{
    oem_control_info_t *control_info = cb_data;

    if (err) {
	if (control_info->done_set)
	    control_info->done_set(control, err, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "oem_control_set_done: Received IPMI error: %x",
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

/*
 * This is used for controls, the handling for the get_done is usually
 * common for controls, so just do it in one place.  Note that this
 * only handles controls with one value, multi-valued controls need
 * their own custom handler.
 */
static void
oem_control_get_done(ipmi_control_t *control,
		     int            err,
		     ipmi_msg_t     *rsp,
		     void           *cb_data)
{
    oem_control_info_t *control_info = cb_data;
    int                val;

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, 0, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "oem_control_get_done: Received IPMI error: %x",
		 rsp->data[0]);
	if (control_info->done_get)
	    control_info->done_get(control,
				   IPMI_IPMI_ERR_VAL(rsp->data[0]),
				   NULL, control_info->cb_data);
	goto out;
    }

    val = control_info->get_val(control, control_info, rsp->data);
    if (control_info->done_get)
	control_info->done_get(control, 0, &val, control_info->cb_data);
 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

/* Called to free the OEM data we attach to the control. */
static void
oem_cleanup_control_oem_info(ipmi_control_t *control, void *oem_info)
{
    oem_sensor_header_t *hdr = oem_info;

    if (hdr) {
	ipmi_mem_free(hdr);
    }
}

/*
 * Allocate a control.  The parms are:
 *   mc - The MC the control sits on.
 *   entity - The entity the control belongs to.
 *   num - The number of the control in the MC.  This must be unique
 *		for the given MC.
 *   data - generic data for the specific control.
 *   control_type - The type of control (from ipmiif.h).
 *   id - The string name of the control.
 *   set_val - The function to set the value of the control.
 *   get_val - The function to get the current value of the control.
 */
static int
oem_alloc_control(ipmi_mc_t               *mc,
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
    oem_control_header_t *hdr;

    hdr = ipmi_mem_alloc(sizeof(*hdr));
    if (!hdr)
	return ENOMEM;

    hdr->data = data;

    /* Allocate the sensor. */
    rv = ipmi_control_alloc_nonstandard(control);
    if (rv) {
	ipmi_mem_free(hdr);
	return rv;
    }

    /* Fill out default values. */
    ipmi_control_set_oem_info(*control, hdr, oem_cleanup_control_oem_info);
    ipmi_control_set_type(*control, control_type);
    ipmi_control_set_id(*control, id);
    ipmi_control_set_ignore_for_presence(*control, 1);

    /* Assume we can read and set the value. */
    ipmi_control_set_settable(*control, 1);
    ipmi_control_set_readable(*control, 1);

    /* Create all the callbacks in the data structure. */
    memset(&cbs, 0, sizeof(cbs));
    cbs.set_val = set_val;
    cbs.get_val = get_val;

    ipmi_control_set_callbacks(*control, &cbs);

    /* Add it to the MC and entity. */
    rv = ipmi_control_add_nonstandard(mc, *control, num, entity, NULL, NULL);
    if (rv) {
	ipmi_control_destroy(*control);
	ipmi_mem_free(hdr);
	*control = NULL;
    }

    return rv;
}

typedef struct oem_info_s
{
    int dummy; /* No OEM info for now. */
} oem_info_t;

/* These are the sensor numbers for our board. */
#define OEM_SLOT_SENSOR_NUM	0

/* These are the control numbers for our board. */
#define OEM_BOARD_RESET_NUM	0
#define OEM_BOARD_BLUE_LED_NUM	1

/* These are the message definitions for doing some OEM operations
   on a board. */
#define OEM_NETFN_OEM1	       0x30
#define OEM_SET_SLOT_RESET_CMD 1
#define OEM_GET_SLOT_EJECT_CMD 2
#define OEM_SET_BLUE_LED_CMD   3
#define OEM_GET_BLUE_LED_CMD   4

/*
 * Some events are system-specific, and need special handling.  The
 * following is an example, because we have a special sensor for the
 * ejector handle, we need to handle it's events, too.
 */

/* Structure passed around to handle events. */
typedef struct mc_event_info_s
{
    oem_info_t            *info;
    ipmi_mc_t             *mc;
    ipmi_event_t          *event;
    ipmi_event_t          event_copy;
    int                   handled;
} mc_event_info_t;

static void
oem_board_ejector_changed_event(ipmi_sensor_t *sensor, void *cb_data)
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

static int
oem_event_handler(ipmi_mc_t    *mc,
		  ipmi_event_t *event,
		  void         *cb_data)
{
    int              rv;
    ipmi_sensor_id_t id;
    mc_event_info_t  einfo;
    unsigned long    timestamp;
    ipmi_mc_id_t     mc_id;
    ipmi_mc_t        *bmc = ipmi_mc_get_bmc(mc);

    if ((event->type != 2) && (event->type != 3))
	/* Not a system event record or OEM event. */
	return 0;

    if (event->data[6] != 3)
	/* Not a 1.5 event version */
	return 0;

    timestamp = ipmi_get_uint32(&(event->data[0]));

    if (timestamp < ipmi_bmc_get_startup_SEL_time(bmc))
	/* It's an old event, ignore it. */
	return 0;

    einfo.info = ipmi_mc_get_oem_data(mc);
    einfo.mc = mc;
    einfo.event = event;
    memcpy(&einfo.event_copy, event, sizeof(einfo.event_copy));
    einfo.handled = 0;

    /* We have to do a sensor callback so we hold the sensor lock when
       we operate on it. */
    mc_id = ipmi_mc_convert_to_id(mc);

    id.bmc = mc_id.bmc;
    id.channel = mc_id.channel;
    id.mc_num = mc_id.mc_num;
    id.lun = 4;

    switch (event->data[8]) {
	case 1:
	    id.sensor_num = OEM_SLOT_SENSOR_NUM;
	    rv = ipmi_sensor_pointer_cb(id,
					oem_board_ejector_changed_event,
					&einfo);
	    break;
    }
    

    /* If the event was handled but not delivered to the user, then
       deliver it to the unhandled handler. */
    if (einfo.handled && (einfo.event != NULL))
	ipmi_handle_unhandled_event(bmc, event);

    return einfo.handled;
}

/* Start a reset operation for the board. */
static void
board_reset_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    oem_control_info_t *control_info = cb_data;
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

    msg.netfn = OEM_NETFN_OEM1;
    msg.cmd = OEM_SET_SLOT_RESET_CMD;
    msg.data_len = 1;
    msg.data = data;
    data[0] = control_info->vals[0];
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, oem_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

/*
 * This is the startup operation for setting the board's reset value.
 */
static int
board_reset_set(ipmi_control_t     *control,
		int                *val,
		ipmi_control_op_cb handler,
		void               *cb_data)
{
    oem_control_info_t   *control_info;
    int                  rv;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return ENOMEM;
    control_info->done_set = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = *val;

    /* We use the control's operation queue to serialize operations to
       the control.  Basically, for each control, only one operation a
       time is allowed. */
    rv = ipmi_control_add_opq(control, board_reset_set_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

/*
 * Get the reset value.  This is not supported.
 */
static int
board_reset_get(ipmi_control_t      *control,
		ipmi_control_val_cb handler,
		void                *cb_data)
{
    return ENOSYS;
}

/*
 * This is for the board slot sensor, we set the states properly from
 * the response to the OEM_GET_SLOT_EJECT_CMD we sent earlier.
 */
static void
board_slot_get_cb(ipmi_sensor_t   *sensor,
		  oem_sens_info_t *sens_info,
		  unsigned char   *data,
		  ipmi_states_t   *states)
{
    if (data[1])
	ipmi_set_state(states, 6, 1); /* Ejector extraction request */
    else
	ipmi_set_state(states, 6, 0); /* Ejector is closed */
}

/*
 * Actually start the slot get operation, once the opq runs us.  This
 * will send the message to get the ejector handle's current state.
 */
static void
board_slot_get_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    oem_sens_info_t *get_info = cb_data;
    ipmi_msg_t      msg;
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

    msg.netfn = OEM_NETFN_OEM1;
    msg.cmd = OEM_GET_SLOT_EJECT_CMD;
    msg.data_len = 0;
    msg.data = NULL;
    rv = ipmi_sensor_send_command(sensor, ipmi_sensor_get_mc(sensor), 0,
				  &msg, oem_discrete_sensor_get_done,
				  &(get_info->sdata), get_info);
    if (rv) {
	if (get_info->done)
	    get_info->done(sensor, rv, &states, get_info->cb_data);
	ipmi_sensor_opq_done(sensor);
	ipmi_mem_free(get_info);
    }
}

/*
 * Called to get the board's ejector handle state.  This will allocate
 * some info and schedule an operation to happen.
 */
static int
board_slot_get(ipmi_sensor_t       *sensor,
	       ipmi_states_read_cb done,
	       void                *cb_data)
{
    int                 rv;
    oem_sens_info_t     *get_info;

    get_info = alloc_sens_info(NULL, done, cb_data);
    if (!get_info)
	return ENOMEM;
    get_info->get_states = board_slot_get_cb;

    rv = ipmi_sensor_add_opq(sensor, board_slot_get_start,
			     &(get_info->sdata), get_info);
    if (rv)
	ipmi_mem_free(get_info);

    return rv;
}

/*
 * Send the message to set the blue led value.
 */
static void
board_blue_led_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    oem_control_info_t *control_info = cb_data;
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

    msg.netfn = OEM_NETFN_OEM1;
    msg.cmd = OEM_SET_BLUE_LED_CMD;
    msg.data_len = 1;
    data[0] = control_info->vals[0];
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, oem_control_set_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_set)
	    control_info->done_set(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

/*
 * Allocate info an schedule us to set the blue led info.
 */
static int
board_blue_led_set(ipmi_control_t     *control,
		   int                *val,
		   ipmi_control_op_cb handler,
		   void               *cb_data)
{
    oem_control_info_t   *control_info;
    int                  rv;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
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

/*
 * Get the value of the blue led from the response to
 * OEM_GET_BLUE_LED_CMD.
 */
static int
board_blue_led_get_cb(ipmi_control_t     *control,
		      oem_control_info_t *control_info,
		      unsigned char      *data)
{
    return data[1];
}

/* Start the operation to get the blue LED's value. */
static void
board_blue_led_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    oem_control_info_t *control_info = cb_data;
    int                rv;
    ipmi_msg_t         msg;

    if (err) {
	if (control_info->done_get)
	    control_info->done_get(control, err, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    msg.netfn = OEM_NETFN_OEM1;
    msg.cmd = OEM_GET_BLUE_LED_CMD;
    msg.data_len = 0;
    msg.data = NULL;
    rv = ipmi_control_send_command(control, ipmi_control_get_mc(control), 0,
				   &msg, oem_control_get_done,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->done_get)
	    control_info->done_get(control, rv, NULL, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

/*
 * Allocate info and schedule an operation to get the blue LED's
 * value.
 */
static int
board_blue_led_get(ipmi_control_t      *control,
		   ipmi_control_val_cb handler,
		   void                *cb_data)
{
    oem_control_info_t   *control_info;
    int                  rv;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return ENOMEM;
    control_info->done_get = handler;
    control_info->cb_data = cb_data;
    control_info->get_val = board_blue_led_get_cb;

    rv = ipmi_control_add_opq(control, board_blue_led_get_start,
			      &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);

    return rv;
}

/*
 * Allocate new general board sensors for the board.
 */
static int
new_board_sensors(ipmi_mc_t     *mc,
		  ipmi_entity_t *ent,
		  oem_info_t    *info)
{
    int            rv;
    ipmi_sensor_t  *sensor;
    ipmi_control_t *control;

    /* The slot sensor */
    rv = oem_alloc_discrete_sensor(
	mc, ent,
	OEM_SLOT_SENSOR_NUM,
	info, NULL,
	IPMI_SENSOR_TYPE_SLOT_CONNECTOR,
	IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC,
	"slot",
	0x40, 0x40, /* offset 6 is supported (hot-swap requester). */
	board_slot_get,
	NULL,
	&sensor);
    if (rv)
	goto out_err;
    ipmi_sensor_set_hot_swap_requester(sensor, 6, 1); /* offset 6 is for
							 hot-swap */

    /* Reset control */
    rv = oem_alloc_control(mc, ent,
			   OEM_BOARD_RESET_NUM,
			   info,
			   IPMI_CONTROL_RESET,
			   "reset",
			   board_reset_set,
			   board_reset_get,
			   &control);
    if (rv)
	goto out_err;
    ipmi_control_set_num_elements(control, 1);

    /* The reset control is not readable. */
    ipmi_control_set_readable(control, 0);

    /* Blue LED control */
    rv = oem_alloc_control(mc, ent,
			   OEM_BOARD_BLUE_LED_NUM,
			   info,
			   IPMI_CONTROL_LIGHT,
			   "blue led",
			   board_blue_led_set,
			   board_blue_led_get,
			   &control);
    if (rv)
	goto out_err;
    ipmi_control_light_set_lights(control, 1, blue_blinking_led);
    ipmi_control_set_hot_swap_indicator(control, 1);

 out_err:
    return rv;
}

/* Write some I2C data on an MC. */
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
    rv = ipmi_send_command(mc, 0, &msg, NULL, NULL);
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

/*
 * Handle data read back from the I2C.  Convert it and present it
 * as the sensor's data.
 */
static void
i2c_sens_reading_cb(ipmi_sensor_t *sensor,
		    int           err,
		    ipmi_msg_t    *rsp,
		    void          *cb_data)
{
    oem_reading_done_t        *get_info = cb_data;
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

/*
 * Send the master read/write command to read a byte from the
 * I2C bus to be reported as the sensor reading.
 */
static void
i2c_sens_get_reading_start(ipmi_sensor_t *sensor, int err, void *cb_data)
{
    oem_reading_done_t *get_info = cb_data;
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
    data[3] = info->offset; /* Offset to read from. */
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

/*
 * Allocate some info and schedule an operation to read some data
 * from I2C to report as the sensor's reading.
 */
static int
i2c_sens_get_reading(ipmi_sensor_t        *sensor,
		    ipmi_reading_done_cb done,
		    void                 *cb_data)
{
    oem_sensor_header_t *hdr = ipmi_sensor_get_oem_info(sensor);
    i2c_sens_t           *info = hdr->data;
    int                 rv;
    oem_reading_done_t  *get_info;


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

/*
 * Allocate a sensor for an ADM 1021 temperature sensor.
 */
static int
alloc_adm1021_sensor(ipmi_mc_t     *mc,
		     ipmi_entity_t *ent,
		     unsigned int  num,
		     unsigned int  bus,
		     unsigned int  addr,
		     char          *id)
{
    int               rv;
    i2c_sens_t        *info;
    ipmi_sensor_t     *sensor;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->bus = bus;
    info->addr = addr;
    info->offset = 1; /* Offset 1 is the remote temp sens. */

    i2c_write(mc, bus, addr, 0xa, 4); /* Do 1 conversion a second. */
    i2c_write(mc, bus, addr, 0x9, 0); /* Enable conversion. */

    rv = oem_alloc_semi_stand_threshold_sensor(mc, ent, num,
		   			       info, ipmi_mem_free,
					       IPMI_SENSOR_TYPE_TEMPERATURE,
					       IPMI_UNIT_TYPE_DEGREES_C,
					       id,
					       0, 0,
					       i2c_sens_get_reading,
					       -1, -1, 105,
					       1, 0, 0, 0,
					       &sensor);
    if (rv) {
	ipmi_mem_free(info);
	goto out;
    }
    ipmi_sensor_set_analog_data_format(sensor,
				       IPMI_ANALOG_DATA_FORMAT_2_COMPL);
    ipmi_sensor_set_raw_sensor_max(sensor, 0x7f);
    ipmi_sensor_set_raw_sensor_min(sensor, 0x80);

 out:
    return rv;
}

/*
 * Called to add the entity to the SDR info.  We don't support this.
 */
static int
oem_entity_sdr_add(ipmi_entity_t   *ent,
		   ipmi_sdr_info_t *sdrs,
		   void            *cb_data)
{
    /* Don't put the entities into an SDR */
    return 0;
}

/* 
 * Called when the MC is removed from the system.
 */
static void oem_mc_removed(ipmi_mc_t *bmc,
			   ipmi_mc_t *mc,
			   void      *cb_data)
{
    free(cb_data);
}

/* We convert addresses to instances by taking the actual I2C address
   (the upper 7 bits of the IPMB address) and subtracting 58 from it.
   Boards start at 0x58, so this makes the instance numbers for boards
   start at zero. */
static unsigned int
oem_addr_to_instance(unsigned int slave_addr)
{
    slave_addr /= 2;
    if (slave_addr >= 0x58) {
	if (slave_addr >= 0x61)
            slave_addr--;
        return slave_addr - 0x58;
    } else
        return slave_addr;
}

/*
 * Called when an MC with the matching manufacturer and product id
 * are detected.
 */
static int
oem_handler(ipmi_mc_t *mc,
	    void      *cb_data)
{
    unsigned int       slave_addr = ipmi_mc_get_address(mc);
    ipmi_entity_info_t *ents;
    ipmi_entity_t      *ent;
    int                rv;
    oem_info_t         *info;
    ipmi_mc_t          *bmc = ipmi_mc_get_bmc(mc);

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    ipmi_mc_entity_lock(bmc);

    ents = ipmi_mc_get_entities(bmc);
    rv = ipmi_entity_add(ents, bmc, 0,
			 IPMI_ENTITY_ID_PROCESSING_BLADE,
			 oem_addr_to_instance(slave_addr),
			 "my-name",
			 oem_entity_sdr_add,
			 NULL, &ent);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "oem_handler: could not add entity");
	goto out;
    }

    rv = ipmi_mc_set_oem_new_sensor_handler(mc, oem_new_sensor, info);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "oem_handler: could not register new sensor handler");
	goto out;
    }

    rv = ipmi_mc_set_oem_removed_handler(mc, oem_mc_removed, info);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "oem_handler: could not set OEM removal handler");
	goto out;
    }

    ipmi_mc_set_oem_data(mc, info);

    rv = new_board_sensors(mc, ent, info);
    if (rv)
	goto out;

    rv = alloc_adm1021_sensor(mc, ent, 0x80, 0x01, 0x9c, "Proc Temp");
    if (rv)
	goto out;

    rv = ipmi_mc_set_oem_event_handler(mc, oem_event_handler, info);

 out:
    ipmi_mc_entity_unlock(bmc);

    
    return rv;
}

/*
 * The user calls this to set up handling for this OEM MC.  This should
 * be the only non-static function in this file.
 */
int
my_oem_init(void)
{
    int rv;

    rv = ipmi_register_oem_handler(OEM_MANUFACTURER_ID,
				   OEM_PRODUCT_ID,
				   oem_handler,
				   NULL,
				   NULL);
    return rv;
}
