/*
 * ipmi_sensor.h
 *
 * MontaVista IPMI interface for dealing with sensors
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

#ifndef _IPMI_SENSOR_H
#define _IPMI_SENSOR_H

#include <ipmi/ipmi_types.h>
#include <ipmi/ipmi_addr.h>

/* The abstract type for sensors. */
typedef struct ipmi_sensor_info_s ipmi_sensor_info_t;

/* Allocate a repository for holding sensors for an MC. */
int ipmi_sensors_alloc(ipmi_mc_t *mc, ipmi_sensor_info_t **new_sensors);

/* Destroy a sensor repository and all the sensors in it. */
int ipmi_sensors_destroy(ipmi_sensor_info_t *sensors);

/*
 * These are for OEM code to create their own sensors.
 */

/* Call the given callback with the sensor. */
int ipmi_find_sensor(ipmi_mc_t *mc, int lun, int num,
		     ipmi_sensor_cb handler, void *cb_data);

/* Allocate a sensor, it will not be associated with anything yet. */
int ipmi_sensor_alloc_nonstandard(ipmi_sensor_t **new_sensor);

typedef void (*ipmi_sensor_destroy_cb)(ipmi_sensor_t *sensor,
				       void          *cb_data);

/* Add a sensor for the given MC and put it into the given entity.
   Note that sensor will NOT appear as owned by the MC, the MC is used
   for the OS handler and such.  A handler can be supplied if the OEM
   code wants to be called when the sensor is destroyed, or NULL can
   be supplied if none is needed. */
int ipmi_sensor_add_nonstandard(
    ipmi_mc_t              *mc,
    ipmi_sensor_t          *sensor,
    ipmi_entity_t          *ent,
    ipmi_sensor_destroy_cb destroy_handler,
    void                   *destroy_handler_cb_data);

/* Extract the sensors from the given SDRs.  The SDRs should have come
   from the source_mc, or if from the main SDR repository, source_mc
   should be NULL. */
int ipmi_sensor_handle_sdrs(ipmi_mc_t       *bmc,
			    ipmi_mc_t       *source_mc,
			    ipmi_sdr_info_t *sdrs);

/* Destroy the sensor from the internal data. */
int ipmi_sensor_destroy(ipmi_sensor_t *sensor);

/* Called by when an event occurs for the given sensor.  This may be use
   by OEM code to deliver non-standard events to sensors. */
int ipmi_sensor_event(ipmi_sensor_t *sensor, ipmi_log_t *event);

/* Fetch boatloads of internal information about sensors. */
int ipmi_sensor_get_owner(ipmi_sensor_t *sensor);
int ipmi_sensor_get_channel(ipmi_sensor_t *sensor);
int ipmi_sensor_get_entity_id(ipmi_sensor_t *sensor);
int ipmi_sensor_get_entity_instance(ipmi_sensor_t *sensor);
int ipmi_sensor_get_entity_instance_logical(ipmi_sensor_t *sensor);
int ipmi_sensor_get_raw_m(ipmi_sensor_t *sensor, int val);
int ipmi_sensor_get_raw_tolerance(ipmi_sensor_t *sensor, int val);
int ipmi_sensor_get_raw_b(ipmi_sensor_t *sensor, int val);
int ipmi_sensor_get_raw_accuracy(ipmi_sensor_t *sensor, int val);
int ipmi_sensor_get_raw_accuracy_exp(ipmi_sensor_t *sensor, int val);
int ipmi_sensor_get_raw_r_exp(ipmi_sensor_t *sensor, int val);
int ipmi_sensor_get_raw_b_exp(ipmi_sensor_t *sensor, int val);
int ipmi_sensor_get_raw_nominal_reading(ipmi_sensor_t *sensor);
int ipmi_sensor_get_raw_normal_max(ipmi_sensor_t *sensor);
int ipmi_sensor_get_raw_normal_min(ipmi_sensor_t *sensor);
int ipmi_sensor_get_raw_sensor_max(ipmi_sensor_t *sensor);
int ipmi_sensor_get_raw_sensor_min(ipmi_sensor_t *sensor);
int ipmi_sensor_get_raw_upper_non_recoverable_threshold(ipmi_sensor_t *sensor);
int ipmi_sensor_get_raw_upper_critical_threshold(ipmi_sensor_t *sensor);
int ipmi_sensor_get_raw_upper_non_critical_threshold(ipmi_sensor_t *sensor);
int ipmi_sensor_get_raw_lower_non_recoverable_threshold(ipmi_sensor_t *sensor);
int ipmi_sensor_get_raw_lower_critical_threshold(ipmi_sensor_t *sensor);
int ipmi_sensor_get_raw_lower_non_critical_threshold(ipmi_sensor_t *sensor);

/* Controls rounding on conversions from flow.  NORMAL does normal
   rounding (ie 1.4->1, 1.5->2, 1.6->2, etc.).  DOWN sets the value to
   the one just less than the value (ie, 1.x->1).  UP sets the value
   to the one just above the value (ie 1.x->2 if x>0). */
enum ipmi_round_e { ROUND_NORMAL, ROUND_DOWN, ROUND_UP };

/* Conversion routines for converting between raw and floating-point
   values. */
int ipmi_sensor_convert_from_raw(ipmi_sensor_t     *sensor,
				 int               val,
				 double            *result);
int ipmi_sensor_convert_to_raw(ipmi_sensor_t     *sensor,
			       enum ipmi_round_e rounding,
			       double            val,
			       int               *result);

/* The user normally shouldn't need these, the lower-level code uses them
   if it needs them. */
int ipmi_sensor_get_upper_non_recoverable_threshold(
    ipmi_sensor_t *sensor,
    double *upper_non_recoverable_threshold);
int ipmi_sensor_get_upper_critical_threshold(
    ipmi_sensor_t *sensor,
    double *upper_critical_threshold);
int ipmi_sensor_get_upper_non_critical_threshold(
    ipmi_sensor_t *sensor,
    double *upper_non_critical_threshold);
int ipmi_sensor_get_lower_non_recoverable_threshold(
    ipmi_sensor_t *sensor,
    double *lower_non_recoverable_threshold);
int ipmi_sensor_get_lower_critical_threshold(
    ipmi_sensor_t *sensor,
    double *lower_critical_threshold);
int ipmi_sensor_get_lower_non_critical_threshold(
    ipmi_sensor_t *sensor,
    double *lower_non_critical_threshold);
int ipmi_sensor_get_positive_going_threshold_hysteresis(ipmi_sensor_t *sensor);
int ipmi_sensor_get_negative_going_threshold_hysteresis(ipmi_sensor_t *sensor);

int ipmi_get_default_sensor_thresholds(ipmi_sensor_t     *sensor,
				       int               raw,
				       ipmi_thresholds_t *th);

/* These calls allow OEM code to set up a sensor. */
void ipmi_sensor_set_owner(ipmi_sensor_t *sensor, int owner);
void ipmi_sensor_set_channel(ipmi_sensor_t *sensor, int channel);
void ipmi_sensor_set_entity_id(ipmi_sensor_t *sensor, int entity_id);
void ipmi_sensor_set_entity_instance(ipmi_sensor_t *sensor,
				     int           entity_instance);
void ipmi_sensor_set_entity_instance_logical(
    ipmi_sensor_t *sensor,
    int           entity_instance_logical);
void ipmi_sensor_set_sensor_init_scanning(ipmi_sensor_t *sensor,
					  int           sensor_init_scanning);
void ipmi_sensor_set_sensor_init_events(ipmi_sensor_t *sensor,
					int           sensor_init_events);
void ipmi_sensor_set_sensor_init_thresholds(
    ipmi_sensor_t *sensor,
    int           sensor_init_thresholds);
void ipmi_sensor_set_sensor_init_hysteresis(
    ipmi_sensor_t *sensor,
    int           sensor_init_hysteresis);
void ipmi_sensor_set_sensor_init_type(ipmi_sensor_t *sensor,
				      int           sensor_init_type);
void ipmi_sensor_set_sensor_init_pu_events(
    ipmi_sensor_t *sensor,
    int           sensor_init_pu_events);
void ipmi_sensor_set_sensor_init_pu_scanning(
    ipmi_sensor_t *sensor,
    int           sensor_init_pu_scanning);
void ipmi_sensor_set_ignore_if_no_entity(ipmi_sensor_t *sensor,
					 int           ignore_if_no_entity);
void ipmi_sensor_set_supports_rearm(ipmi_sensor_t *sensor, int supports_rearm);
void ipmi_sensor_set_hysteresis_support(ipmi_sensor_t *sensor,
					int           hysteresis_support);
void ipmi_sensor_set_threshold_access(ipmi_sensor_t *sensor,
				      int           threshold_access);
void ipmi_sensor_set_event_support(ipmi_sensor_t *sensor, int event_support);
void ipmi_sensor_set_sensor_type(ipmi_sensor_t *sensor, int sensor_type);
void ipmi_sensor_set_event_reading_type(ipmi_sensor_t *sensor,
					int           event_reading_type);
void ipmi_sensor_set_analog_data_format(ipmi_sensor_t *sensor,
					int           analog_data_format);
void ipmi_sensor_set_rate_unit(ipmi_sensor_t *sensor, int rate_unit);
void ipmi_sensor_set_modifier_unit_use(ipmi_sensor_t *sensor,
				       int           modifier_unit_use);
void ipmi_sensor_set_percentage(ipmi_sensor_t *sensor, int percentage);
void ipmi_sensor_set_base_unit(ipmi_sensor_t *sensor, int base_unit);
void ipmi_sensor_set_modifier_unit(ipmi_sensor_t *sensor, int modifier_unit);
void ipmi_sensor_set_linearization(ipmi_sensor_t *sensor, int linearization);
void ipmi_sensor_set_raw_m(ipmi_sensor_t *sensor, int idx, int val);
void ipmi_sensor_set_raw_tolerance(ipmi_sensor_t *sensor, int idx, int val);
void ipmi_sensor_set_raw_b(ipmi_sensor_t *sensor, int idx, int val);
void ipmi_sensor_set_raw_accuracy(ipmi_sensor_t *sensor, int idx, int val);
void ipmi_sensor_set_raw_accuracy_exp(ipmi_sensor_t *sensor, int idx, int val);
void ipmi_sensor_set_raw_r_exp(ipmi_sensor_t *sensor, int idx, int val);
void ipmi_sensor_set_raw_b_exp(ipmi_sensor_t *sensor, int idx, int val);
void ipmi_sensor_set_normal_min_specified(ipmi_sensor_t *sensor,
					  int           normal_min_specified);
void ipmi_sensor_set_normal_max_specified(ipmi_sensor_t *sensor,
					  int           normal_max_specified);
void ipmi_sensor_set_nominal_reading_specified(
    ipmi_sensor_t *sensor,
    int            nominal_reading_specified);
void ipmi_sensor_set_raw_nominal_reading(ipmi_sensor_t *sensor,
					 int           raw_nominal_reading);
void ipmi_sensor_set_raw_normal_max(ipmi_sensor_t *sensor, int raw_normal_max);
void ipmi_sensor_set_raw_normal_min(ipmi_sensor_t *sensor, int raw_normal_min);
void ipmi_sensor_set_raw_sensor_max(ipmi_sensor_t *sensor, int raw_sensor_max);
void ipmi_sensor_set_raw_sensor_min(ipmi_sensor_t *sensor, int raw_sensor_min);
void ipmi_sensor_set_raw_upper_non_recoverable_threshold(
    ipmi_sensor_t *sensor,
    int           raw_upper_non_recoverable_threshold);
void ipmi_sensor_set_raw_upper_critical_threshold(
    ipmi_sensor_t *sensor,
    int           raw_upper_critical_threshold);
void ipmi_sensor_set_raw_upper_non_critical_threshold(
    ipmi_sensor_t *sensor,
    int           raw_upper_non_critical_threshold);
void ipmi_sensor_set_raw_lower_non_recoverable_threshold(
    ipmi_sensor_t *sensor,
    int           raw_lower_non_recoverable_threshold);
void ipmi_sensor_set_raw_lower_critical_threshold(
    ipmi_sensor_t *sensor,
    int           raw_lower_critical_threshold);
void ipmi_sensor_set_raw_lower_non_critical_threshold(
    ipmi_sensor_t *sensor,
    int           raw_lower_non_critical_threshold);
void ipmi_sensor_set_positive_going_threshold_hysteresis(
    ipmi_sensor_t *sensor,
    int           positive_going_threshold_hysteresis);
void ipmi_sensor_set_negative_going_threshold_hysteresis(
    ipmi_sensor_t *sensor,
    int           negative_going_threshold_hysteresis);
void ipmi_sensor_set_oem1(ipmi_sensor_t *sensor, int oem1);
void ipmi_sensor_set_id(ipmi_sensor_t *sensor, char *id);

void ipmi_sensor_set_discrete_assertion_event_supported(
    ipmi_sensor_t *sensor,
    int           event,
    int           val);
void ipmi_sensor_set_discrete_deassertion_event_supported(
    ipmi_sensor_t *sensor,
    int           event,
    int           val);
void ipmi_sensor_discrete_set_event_readable(ipmi_sensor_t *sensor,
					     int           event,
					     int           val);

void ipmi_sensor_set_threshold_assertion_event_supported(
    ipmi_sensor_t               *sensor,
    enum ipmi_thresh_e          event,
    enum ipmi_event_value_dir_e dir,
    int                         val);
void ipmi_sensor_set_threshold_deassertion_event_supported(
    ipmi_sensor_t               *sensor,
    enum ipmi_thresh_e          event,
    enum ipmi_event_value_dir_e dir,
    int                         val);
void ipmi_sensor_threshold_set_readable(ipmi_sensor_t      *sensor,
					enum ipmi_thresh_e thresh,
					int                val);
void ipmi_sensor_threshold_set_settable(ipmi_sensor_t      *sensor,
					enum ipmi_thresh_e thresh,
					int                val);

void ipmi_sensor_set_hot_swap_requester(ipmi_sensor_t *sensor, int val);



/* Typedefs for the sensor polymorphic functions. */
typedef int (*ipmi_sensor_convert_from_raw_cb)(
    ipmi_sensor_t *sensor,
    int           val,
    double        *result);
typedef int (*ipmi_sensor_convert_to_raw_cb)(
    ipmi_sensor_t     *sensor,
    enum ipmi_round_e rounding,
    double            val,
    int               *result);
typedef int (*ipmi_sensor_get_tolerance_cb)(ipmi_sensor_t *sensor,
					    int           val,
					    double        *tolerance);
typedef int (*ipmi_sensor_get_accuracy_cb)(ipmi_sensor_t *sensor,
					   int           val,
					   double        *accuracy);

typedef int (*ipmi_sensor_events_enable_set_cb)(
    ipmi_sensor_t         *sensor,
    ipmi_event_state_t    *states,
    ipmi_sensor_done_cb   done,
    void                  *cb_data);
typedef int (*ipmi_sensor_events_enable_get_cb)(
    ipmi_sensor_t             *sensor,
    ipmi_event_enables_get_cb done,
    void                      *cb_data);

typedef int (*ipmi_sensor_get_hysteresis_cb)(
    ipmi_sensor_t           *sensor,
    ipmi_hysteresis_get_cb done,
    void                   *cb_data);
typedef int (*ipmi_sensor_set_hysteresis_cb)(
    ipmi_sensor_t       *sensor,
    unsigned int        positive_hysteresis,
    unsigned int        negative_hysteresis,
    ipmi_sensor_done_cb done,
    void                *cb_data);

typedef int (*ipmi_thresholds_set_cb)(
    ipmi_sensor_t       *sensor,
    ipmi_thresholds_t   *thresholds,
    ipmi_sensor_done_cb done,
    void                *cb_data);
typedef int (*ipmi_thresholds_get_cb)(
    ipmi_sensor_t      *sensor,
    ipmi_thresh_get_cb done,
    void               *cb_data);

typedef int (*ipmi_reading_get_cb)(
    ipmi_sensor_t        *sensor,
    ipmi_reading_done_cb done,
    void                 *cb_data);
typedef int (*ipmi_states_get_cb)(ipmi_sensor_t       *sensor,
				  ipmi_states_read_cb done,
				  void                *cb_data);
typedef char *(*ipmi_sensor_reading_name_string_cb)(
    ipmi_sensor_t *sensor, int val);

typedef struct ipmi_sensor_cbs_s
{
    ipmi_sensor_events_enable_set_cb ipmi_sensor_events_enable_set;
    ipmi_sensor_events_enable_get_cb ipmi_sensor_events_enable_get;

    /* These are for threshold sensors only. */
    ipmi_sensor_convert_from_raw_cb  ipmi_sensor_convert_from_raw;
    ipmi_sensor_convert_to_raw_cb    ipmi_sensor_convert_to_raw;
    ipmi_sensor_get_accuracy_cb      ipmi_sensor_get_accuracy;
    ipmi_sensor_get_tolerance_cb     ipmi_sensor_get_tolerance;
    ipmi_sensor_get_hysteresis_cb    ipmi_sensor_get_hysteresis;
    ipmi_sensor_set_hysteresis_cb    ipmi_sensor_set_hysteresis;
    ipmi_thresholds_set_cb           ipmi_thresholds_set;
    ipmi_thresholds_get_cb           ipmi_thresholds_get;
    ipmi_reading_get_cb              ipmi_reading_get;

    /* This is for a discrete sensor. */
    ipmi_states_get_cb               ipmi_states_get;
    ipmi_sensor_reading_name_string_cb ipmi_sensor_reading_name_string;
} ipmi_sensor_cbs_t;

/* Can be used by OEM code to replace some or all of the callbacks for
   a sensor. */
void ipmi_sensor_get_callbacks(ipmi_sensor_t *sensor, ipmi_sensor_cbs_t *cbs);
void ipmi_sensor_set_callbacks(ipmi_sensor_t *sensor, ipmi_sensor_cbs_t *cbs);

/* The standard callbacks.  This is read-only, don't change them. */
extern ipmi_sensor_cbs_t ipmi_standard_sensor_cb;

void ipmi_sensor_set_oem_info(ipmi_sensor_t *sensor, void *oem_info);
void *ipmi_sensor_get_oem_info(ipmi_sensor_t *sensor);

/* Operations and callbacks for sensor operations.  Operations on a
   sensor that can be delayed should be serialized (to avoid user
   confusion and for handling multi-part operations properly), thus
   each sensor has an operation queue, only one operation at a time
   may be running.  If you want to do an operation that requires
   sending a message and getting a response, you must put that
   operation into the opq.  When the handler you registered in the opq
   is called, you can actually perform the operation.  When your
   operation completes (no matter what, you must call it, even if the
   operation fails), you must call ipmi_sensor_opq_done.  The sensor
   will be locked properly for your callback.  To handle the sensor
   locking for you for command responses, you can send the message
   with ipmi_sensor_send_command, it will return the response when it
   comes in to your handler with the sensor locked. */

typedef void (*ipmi_sensor_op_cb)(ipmi_sensor_t *sensor,
				  int           err,
				  void          *cb_data);

typedef void (*ipmi_sensor_rsp_cb)(ipmi_sensor_t *sensor,
				   int           err,
				   ipmi_msg_t    *rsp,
				   void          *cb_data);

typedef struct ipmi_sensor_op_info_s
{
    ipmi_sensor_id_t   __sensor_id;
    ipmi_sensor_t      *__sensor;
    void               *__cb_data;
    ipmi_sensor_op_cb  __handler;
    ipmi_sensor_rsp_cb __rsp_handler;
    ipmi_msg_t         *__rsp;
} ipmi_sensor_op_info_t;

int ipmi_sensor_add_opq(ipmi_sensor_t         *sensor,
			ipmi_sensor_op_cb     handler,
			ipmi_sensor_op_info_t *info,
			void                  *cb_data);

void ipmi_sensor_opq_done(ipmi_sensor_t *sensor);

int ipmi_sensor_send_command(ipmi_sensor_t         *sensor,
			     ipmi_mc_t             *mc,
			     unsigned int          lun,
			     ipmi_msg_t            *msg,
			     ipmi_sensor_rsp_cb    handler,
			     ipmi_sensor_op_info_t *info,
			     void                  *cb_data);

int ipmi_sensor_send_command_addr(ipmi_mc_t             *bmc,
				  ipmi_sensor_t         *sensor,
				  ipmi_addr_t           *addr,
				  unsigned int          addr_len,
				  ipmi_msg_t            *msg,
				  ipmi_sensor_rsp_cb    handler,
				  ipmi_sensor_op_info_t *info,
				  void                  *cb_data);

void ipmi_sensor_set_sensor_type_string(ipmi_sensor_t *sensor, char *str);
void ipmi_sensor_set_event_reading_type_string(ipmi_sensor_t *sensor,
					       char          *str);
void ipmi_sensor_set_rate_unit_string(ipmi_sensor_t *sensor, char *str);
void ipmi_sensor_set_base_unit_string(ipmi_sensor_t *sensor, char *str);
void ipmi_sensor_set_modifier_unit_string(ipmi_sensor_t *sensor, char *str);

/* Get the MC that the sensor is in. */
ipmi_mc_t *ipmi_sensor_get_mc(ipmi_sensor_t *sensor);

#endif /* _IPMI_SENSOR_H */
