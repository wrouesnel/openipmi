/*
 * ipmiif.h
 *
 * MontaVista IPMI main interface
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

#ifndef __IPMIIF_H
#define __IPMIIF_H

/*
 * This is the main include file for dealing with IPMI.  It provides
 * an abstract interface to the IPMI system, so you don't have to deal
 * with all the nitty-gritty details of IPMI.  You only deal with
 * three things:
 *
 *  The BMC - This is the main interface to the IPMI system.
 *  Entities - These are things that sensors monitor, they can be
 *             FRUs, or whatnot.
 *  Sensors - These are monitors for FRUs.
 *
 * You don't have to deal with Management Controllers (MCs), IPMI
 * addressing, or anything like that.  This software will go out onto
 * the IPMI bus, detect all the entities present there, and call you
 * when it detects something.  It reads the SDR database and detects
 * all the entities and entity relationships.  It lets you add
 * entities and relationships to the local copies, and write the
 * information back into the database.
 *
 * You have to be careful with locking in this system.  The three things
 * you deal with all have two ways to get at them: An ID, and a pointer.
 * The ID is always valid, you can store that off on your own and use it
 * later.  The pointer is only valid inside a callback, the system is
 * free to change the pointers for a thing when no callbacks are active.
 *
 * To convert an ID to a pointer that you can work on, you have to go
 * through a callback.  These are provided for each type.  This is a
 * little inconvenient, but it's a lot faster than copying a lot of
 * data around all the time or re-validating an ID on every operation.
 * If a callback gives you a pointer to a sensor, entity, or mc, the
 * lock for that things will be held while you are in the callback.
 *
 * This interface is completely event-driven, meaning that a call will
 * never block.  Instead, if a call cannot complete inside the call
 * itself, you provide a "callback" that will be called when the
 * operation completes.  If you don't care about the results, you can
 * provide a NULL callback.  However, you will not receive any error
 * information about the operation; if it fails you will not know.
 * Note that if a function that you provide a callback returns an
 * error, the callback will NEVER be called.
 *
 * Callbacks are possible on things that have ceased to exist.  For
 * example, if you start an operation on a sensor and the sensor
 * ceases to exist during the operation, you will get an error
 * callback with a NULL sensor.  The same goes for 
 *
 * You should NEVER block in a callback.  Locks are held in callbacks,
 * so you will constipate the system if you block in callbacks.  Just
 * don't do it.
 *
 * asdf */

#include <ipmi/ipmi_types.h>
#include <ipmi/ipmi_bits.h>
#include <ipmi/os_handler.h>

/* This is how you convert a pointer to and ID and convert an ID to a
   pointer.  Pointers are ONLY valid in callbacks, the system is free
   to change the pointer value outside the callback.  So you should
   only store IDs.  IDs are good all the time, but you must go through
   the "pointer_cb" functions to get a usable pointer you can operate
   on.  This is how the locking works for this, inside the callback
   you will hold the locks so the item you are using will not change.
   It's kind of a pain, but it improves reliability.  This way, you
   cannot "forget" to release the lock for something. */
ipmi_mc_id_t ipmi_mc_convert_to_id(ipmi_mc_t *mc);
typedef void (*ipmi_mc_cb)(ipmi_mc_t *mc, void *cb_data);
int ipmi_mc_pointer_cb(ipmi_mc_id_t id, ipmi_mc_cb handler, void *cb_data);

ipmi_entity_id_t ipmi_entity_convert_to_id(ipmi_entity_t *ent);
typedef void (*ipmi_entity_cb)(ipmi_entity_t *entity, void *cb_data);
int ipmi_entity_pointer_cb(ipmi_entity_id_t id,
			   ipmi_entity_cb   handler,
			   void             *cb_data);

ipmi_sensor_id_t ipmi_sensor_convert_to_id(ipmi_sensor_t *sensor);
typedef void (*ipmi_sensor_cb)(ipmi_sensor_t *sensor, void *cb_data);
int ipmi_sensor_pointer_cb(ipmi_sensor_id_t id,
			   ipmi_sensor_cb   handler,
			   void             *cb_data);
int ipmi_cmp_sensor_id(ipmi_sensor_id_t id1, ipmi_sensor_id_t id2);

ipmi_control_id_t ipmi_control_convert_to_id(ipmi_control_t *ind);
typedef void (*ipmi_control_cb)(ipmi_control_t *ind, void *cb_data);
int ipmi_control_pointer_cb(ipmi_control_id_t id,
			    ipmi_control_cb   handler,
			    void              *cb_data);
int ipmi_cmp_control_id(ipmi_control_id_t id1, ipmi_control_id_t id2);

/* Events come in this format. */
typedef void (*ipmi_event_handler_t)(ipmi_mc_t  *bmc,
				     ipmi_msg_t *event,
				     void       *event_data);

typedef struct ipmi_event_handler_id_s ipmi_event_handler_id_t;

/* Register a handler to receive events.  Multiple handlers may be
   registered, they will all receive all events.  The event_data will
   be passed in with every event received.  The MC must be the BMC MC.
   This will only catch events that are not sent to a sensor, so if
   you get a system software event or an event from a sensor the
   software doesn't know about, this handler will get it. */
int ipmi_register_for_events(ipmi_mc_t               *bmc,
			     ipmi_event_handler_t    handler,
			     void                    *event_data,
			     ipmi_event_handler_id_t **id);
/* Deregister an event handler. */
int ipmi_deregister_for_events(ipmi_mc_t               *bmc,
			       ipmi_event_handler_id_t *id);

/* Globally enable or disable events on the BMC. */
int ipmi_bmc_enable_events(ipmi_mc_t *bmc);
int ipmi_bmc_disable_events(ipmi_mc_t *bmc);

enum ipmi_update_e { ADDED, DELETED, CHANGED };
/* A callback that will be called when entities are added to and
   removed from the BMC, and when their presence changes. */
typedef void (*ipmi_bmc_entity_cb)(enum ipmi_update_e op,
				   ipmi_mc_t          *bmc,
				   ipmi_entity_t      *entity,
				   void               *cb_data);

/* Set the handler to be called when an entity is added or deleted. */
int ipmi_bmc_set_entity_update_handler(ipmi_mc_t          *bmc,
				       ipmi_bmc_entity_cb handler,
				       void               *cb_data);

/* Iterate over all the entities in the bmc, calling the given
   function with each entity.  The entities will not change while this
   is happening. */
typedef void (*ipmi_entities_iterate_entity_cb)(ipmi_entity_t *entity,
						void          *cb_data);
int ipmi_bmc_iterate_entities(ipmi_mc_t                       *bmc,
			      ipmi_entities_iterate_entity_cb handler,
			      void                            *cb_data);

/* Store all the information I have locally into the SDR repository. */
typedef void (*ipmi_bmc_cb)(ipmi_mc_t *bmc, int err, void *cb_data);
int ipmi_bmc_store_entities(ipmi_mc_t *bmc, ipmi_bmc_cb done, void *cb_data);

/* For the given entity, iterate over all the children of the entity,
   calling the given handler with each child.  The children will not
   change while this is happening. */
typedef void (*ipmi_entity_iterate_child_cb)(ipmi_entity_t *ent,
					     ipmi_entity_t *child,
					     void          *cb_data);
void ipmi_entity_iterate_children(ipmi_entity_t                *ent,
				  ipmi_entity_iterate_child_cb handler,
				  void                         *cb_data);

/* Iterate over the parents of the given entitiy.
   FIXME - can an entity have more than one parent? */
typedef void (*ipmi_entity_iterate_parent_cb)(ipmi_entity_t *ent,
					      ipmi_entity_t *parent,
					      void          *cb_data);
void ipmi_entity_iterate_parents(ipmi_entity_t                 *ent,
				 ipmi_entity_iterate_parent_cb handler,
				 void                          *cb_data);

/* Iterate over all the sensors of an entity. */
typedef void (*ipmi_entity_iterate_sensor_cb)(ipmi_entity_t *ent,
					      ipmi_sensor_t *sensor,
					      void          *cb_data);
void ipmi_entity_iterate_sensors(ipmi_entity_t                 *ent,
				 ipmi_entity_iterate_sensor_cb handler,
				 void                          *cb_data);

/* Iterate over all the indicators of an entity. */
typedef void (*ipmi_entity_iterate_control_cb)(ipmi_entity_t  *ent,
					       ipmi_control_t *ind,
					       void           *cb_data);
void ipmi_entity_iterate_controls(ipmi_entity_t                  *ent,
				  ipmi_entity_iterate_control_cb handler,
				  void                           *cb_data);

/* Set the handle to monitor the presence of an entity.  Only one handler
   may be specified, add a NULL handler to remove the current handler. */
typedef void (*ipmi_entity_presence_cb)(ipmi_entity_t *entity,
					int           present,
					void          *cb_data);
int ipmi_entity_set_presence_handler(ipmi_entity_t           *ent,
				     ipmi_entity_presence_cb handler,
				     void                    *cb_data);

/* Get information about an entity.  Most of this is IPMI specific. */
ipmi_mc_t *ipmi_entity_get_bmc(ipmi_entity_t *ent);
int ipmi_entity_get_access_address(ipmi_entity_t *ent);
int ipmi_entity_get_slave_address(ipmi_entity_t *ent);
int ipmi_entity_get_channel(ipmi_entity_t *ent);
int ipmi_entity_get_lun(ipmi_entity_t *ent);
int ipmi_entity_get_private_bus_id(ipmi_entity_t *ent);
int ipmi_entity_get_is_logical_fru(ipmi_entity_t *ent);
int ipmi_entity_get_is_fru(ipmi_entity_t *ent);
int ipmi_entity_get_entity_id(ipmi_entity_t *ent);
int ipmi_entity_get_entity_instance(ipmi_entity_t *ent);
int ipmi_entity_get_device_type(ipmi_entity_t *ent);
int ipmi_entity_get_device_modifier(ipmi_entity_t *ent);
int ipmi_entity_get_oem(ipmi_entity_t *ent);
int ipmi_entity_get_presense_sensor_always_there(ipmi_entity_t *ent);
int ipmi_entity_get_in_sdr_db(ipmi_entity_t *ent);
int ipmi_entity_get_is_child(ipmi_entity_t *ent);
int ipmi_entity_get_ACPI_system_power_notify_required(ipmi_entity_t *ent);
int ipmi_entity_get_ACPI_device_power_notify_required(ipmi_entity_t *ent);
int ipmi_entity_get_controller_logs_init_agent_errors(ipmi_entity_t *ent);
int ipmi_entity_get_log_init_agent_errors_accessing(ipmi_entity_t *ent);
int ipmi_entity_get_global_init(ipmi_entity_t *ent);
int ipmi_entity_get_chassis_device(ipmi_entity_t *ent);
int ipmi_entity_get_bridge(ipmi_entity_t *ent);
int ipmi_entity_get_IPMB_event_generator(ipmi_entity_t *ent);
int ipmi_entity_get_IPMB_event_receiver(ipmi_entity_t *ent);
int ipmi_entity_get_FRU_inventory_device(ipmi_entity_t *ent);
int ipmi_entity_get_SEL_device(ipmi_entity_t *ent);
int ipmi_entity_get_SDR_repository_device(ipmi_entity_t *ent);
int ipmi_entity_get_sensor_device(ipmi_entity_t *ent);
char *ipmi_entity_get_entity_id_string(ipmi_entity_t *ent);

/* The ID from the SDR. */
int ipmi_entity_get_id_length(ipmi_entity_t *ent);
void ipmi_entity_get_id(ipmi_entity_t *ent, char *id, int length);

/* Is the entity currently present? */
int ipmi_entity_is_present(ipmi_entity_t *ent);

/* Register a handler that will be called when a sensor that monitors
   this entity is added, deleted, or modified.  If you call this in
   the entity added callback for the BMC, you are guaranteed to get
   this set before any sensors exist. */
typedef void (*ipmi_entity_sensor_cb)(enum ipmi_update_e op,
				      ipmi_entity_t      *ent,
				      ipmi_sensor_t      *sensor,
				      void               *cb_data);
int ipmi_entity_set_sensor_update_handler(ipmi_entity_t         *ent,
					  ipmi_entity_sensor_cb handler,
					  void                  *cb_data);

/* Register a handler that will be called when an indicator on
   this entity is added, deleted, or modified.  If you call this in
   the entity added callback for the BMC, you are guaranteed to get
   this set before any sensors exist. */
typedef void (*ipmi_entity_control_cb)(enum ipmi_update_e op,
				       ipmi_entity_t      *ent,
				       ipmi_control_t     *ind,
				       void               *cb_data);
int ipmi_entity_set_control_update_handler(ipmi_entity_t          *ent,
					   ipmi_entity_control_cb handler,
					   void                   *cb_data);

/* Handles events from the given sensor with the handler.  Only one
   handler may be registered against a sensor, if you call this again
   with a new handler, the old handler will be replaced.  Set the
   handler to NULL to disable it.  The dir variable tells if the
   threshold is being asserted or deasserted.  The high_low value
   tells if the value is going high or low, and the threshold value
   tells which threshold is being reported.  if value_present is true,
   the the "value" has been reported in the event and has been
   converted to a linear value. */
typedef void (*ipmi_sensor_threshold_event_handler_cb)(
    ipmi_sensor_t               *sensor,
    enum ipmi_event_dir_e       dir,
    enum ipmi_thresh_e          threshold,
    enum ipmi_event_value_dir_e high_low,
    int                         value_present,
    double                      value,
    void                        *cb_data);
int
ipmi_sensor_threshold_set_event_handler(
    ipmi_sensor_t                          *sensor,
    ipmi_sensor_threshold_event_handler_cb handler,
    void                                   *cb_data);

/* Register a handler for a discrete sensor.  Only one handler may be
   registered against a sensor, if you call this again with a new
   handler, the old handler will be replaced.  Set the handler to NULL
   to disable it.  When an event comes in from the sensor, the
   callback function will be called.  The "dir" variable tells if the
   state is being asserted or deasserted, the offset is the state that
   is being asserted or deasserted. */
typedef void (*ipmi_sensor_discrete_event_handler_cb)(
    ipmi_sensor_t         *sensor,
    enum ipmi_event_dir_e dir,
    int                   offset,
    int                   severity_present,
    int                   severity,
    int			  prev_severity_present,
    int                   prev_severity,
    void                  *cb_data);
int
ipmi_sensor_discrete_set_event_handler(
    ipmi_sensor_t                         *sensor,
    ipmi_sensor_discrete_event_handler_cb handler,
    void                                  *cb_data);

/* The event state is which events are set and cleared for the given
   sensor.  Events are enumerated for threshold events and numbered
   for discrete events.  Use the provided functions to initialize,
   read, and modify an event state, sense the internals of the event
   state structure are subject to change. */
#define IPMI_SENSOR_EVENTS_ENABLED	0x80
#define IPMI_SENSOR_SCANNING_ENABLED	0x40
#define IPMI_SENSOR_BUSY		0x20
typedef struct ipmi_event_state_s ipmi_event_state_t;
struct ipmi_event_state_s
{
    int          status;
    /* Pay no attention to the implementation. */
    unsigned int __assertion_events;
    unsigned int __deassertion_events;
};
static inline void
ipmi_event_state_init(ipmi_event_state_t *events)
{
    events->status = 0;
    events->__assertion_events = 0;
    events->__deassertion_events = 0;
}
static inline void
ipmi_threshold_event_clear(ipmi_event_state_t          *events,
			   enum ipmi_thresh_e          type,
			   enum ipmi_event_value_dir_e value_dir,
			   enum ipmi_event_dir_e       dir)
{
    if (dir == IPMI_ASSERTION) {
	events->__assertion_events &= ~(1 << (type*2+value_dir));
    } else {
	events->__deassertion_events &= ~(1 << (type*2+value_dir));
    }
}
static inline void
ipmi_threshold_event_set(ipmi_event_state_t          *events,
			 enum ipmi_thresh_e          type,
			 enum ipmi_event_value_dir_e value_dir,
			 enum ipmi_event_dir_e       dir)
{
    if (dir == IPMI_ASSERTION) {
	events->__assertion_events |= 1 << (type*2+value_dir);
    } else {
	events->__deassertion_events |= 1 << (type*2+value_dir);
    }
}

static inline int
ipmi_is_threshold_event_set(ipmi_event_state_t          *events,
			    enum ipmi_thresh_e          type,
			    enum ipmi_event_value_dir_e value_dir,
			    enum ipmi_event_dir_e       dir)
{
    if (dir == IPMI_ASSERTION) {
	return (events->__assertion_events & (1 << (type*2+value_dir))) != 0;
    } else {
	return (events->__deassertion_events & (1 << (type*2+value_dir))) != 0;
    }
}

static inline void
ipmi_discrete_event_clear(ipmi_event_state_t    *events,
			  int                   event_offset,
			  enum ipmi_event_dir_e dir)
{
    if (dir == IPMI_ASSERTION) {
	events->__assertion_events &= ~(1 << event_offset);
    } else {
	events->__deassertion_events &= ~(1 << event_offset);
    }
}
static inline void
ipmi_discrete_event_set(ipmi_event_state_t    *events,
			int                   event_offset,
			enum ipmi_event_dir_e dir)
{
    if (dir == IPMI_ASSERTION) {
	events->__assertion_events |= 1 << event_offset;
    } else {
	events->__deassertion_events |= 1 << event_offset;
    }
}
static inline int
ipmi_is_discrete_event_set(ipmi_event_state_t    *events,
			   int                   event_offset,
			   enum ipmi_event_dir_e dir)
{
    if (dir == IPMI_ASSERTION) {
	return (events->__assertion_events & (1 << event_offset)) != 0;
    } else {
	return (events->__deassertion_events & (1 << event_offset)) != 0;
    }
}

/* A generic callback for a lot of things. */
typedef void (*ipmi_sensor_done_cb)(ipmi_sensor_t *sensor,
				    int           err,
				    void          *cb_data);

/* Set the event enables for the given sensor. */
int ipmi_sensor_events_enable_set(ipmi_sensor_t         *sensor,
				  ipmi_event_state_t    *states,
				  ipmi_sensor_done_cb   done,
				  void                  *cb_data);

/* Get the event enables for the given sensor. */
typedef void (*ipmi_event_enables_get_cb)(ipmi_sensor_t      *sensor,
					  int                err,
					  int                global_enable,
					  int                scanning_enabled,
					  ipmi_event_state_t states,
					  void               *cb_data);
int ipmi_sensor_events_enable_get(ipmi_sensor_t             *sensor,
				  ipmi_event_enables_get_cb done,
				  void                      *cb_data);

/* Get the hysteresis values for the given sensor.
   FIXME - these are currently the raw values, how do I get the
   cooked values?  There doesn't seem to be an easy way to calculate them. */
typedef void (*ipmi_hysteresis_get_cb)(ipmi_sensor_t *sensor,
				       int           err,
				       unsigned int  positive_hysteresis,
				       unsigned int  negative_hysteresis,
				       void          *cb_data);
int ipmi_sensor_get_hysteresis(ipmi_sensor_t           *sensor,
			       ipmi_hysteresis_get_cb done,
			       void                   *cb_data);

/* Set the hysteresis values for the given sensor.
   FIXME - these are currently the raw values, how do I handle the
   cooked values?  There doesn't seem to be an easy way to calculate them. */
int ipmi_sensor_set_hysteresis(ipmi_sensor_t       *sensor,
			       unsigned int        positive_hysteresis,
			       unsigned int        negative_hysteresis,
			       ipmi_sensor_done_cb done,
			       void                *cb_data);

/* Get the LUN and sensor number for the sensor, as viewed from its
   management controller. */
int ipmi_sensor_get_num(ipmi_sensor_t *sensor,
			int           *lun,
			int           *num);

/* Strings for various values for a sensor.  We put them in here, and
   they will be the correct strings even for OEM values. */
char *ipmi_sensor_get_sensor_type_string(ipmi_sensor_t *sensor);
char *ipmi_sensor_get_event_reading_type_string(ipmi_sensor_t *sensor);
char *ipmi_sensor_get_reading_name_string(ipmi_sensor_t *sensor);
char *ipmi_sensor_get_rate_unit_string(ipmi_sensor_t *sensor);
char *ipmi_sensor_get_base_unit_string(ipmi_sensor_t *sensor);
char *ipmi_sensor_get_modifier_unit_string(ipmi_sensor_t *sensor);

/* Get the entity the sensor is hooked to. */
int ipmi_sensor_get_entity_id(ipmi_sensor_t *sensor);
int ipmi_sensor_get_entity_instance(ipmi_sensor_t *sensor);
ipmi_entity_t *ipmi_sensor_get_entity(ipmi_sensor_t *sensor);

/* Information about a sensor from it's SDR.  These are things that
   are specified by IPMI, see the spec for more details. */
int ipmi_sensor_get_sensor_init_scanning(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_events(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_thresholds(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_hysteresis(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_type(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_pu_events(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_pu_scanning(ipmi_sensor_t *sensor);
int ipmi_sensor_get_ignore_if_no_entity(ipmi_sensor_t *sensor);
int ipmi_sensor_get_supports_rearm(ipmi_sensor_t *sensor);
int ipmi_sensor_get_hysteresis_support(ipmi_sensor_t *sensor);
int ipmi_sensor_get_threshold_access(ipmi_sensor_t *sensor);
int ipmi_sensor_get_event_support(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_type(ipmi_sensor_t *sensor);
int ipmi_sensor_get_event_reading_type(ipmi_sensor_t *sensor);
int ipmi_sensor_get_analog_data_format(ipmi_sensor_t *sensor);
int ipmi_sensor_get_rate_unit(ipmi_sensor_t *sensor);
int ipmi_sensor_get_modifier_unit_use(ipmi_sensor_t *sensor);
int ipmi_sensor_get_percentage(ipmi_sensor_t *sensor);
int ipmi_sensor_threshold_assertion_event_supported(
    ipmi_sensor_t               *sensor,
    enum ipmi_thresh_e          event,
    enum ipmi_event_value_dir_e dir,
    int                         *val);
int ipmi_sensor_threshold_deassertion_event_supported(
    ipmi_sensor_t               *sensor,
    enum ipmi_thresh_e          event,
    enum ipmi_event_value_dir_e dir,
    int                         *val);
int ipmi_sensor_threshold_settable(ipmi_sensor_t      *sensor,
				   enum ipmi_thresh_e event,
				   int                *val);
int ipmi_sensor_threshold_readable(ipmi_sensor_t      *sensor,
				   enum ipmi_thresh_e event,
				   int                *val);
int ipmi_sensor_discrete_assertion_event_supported(ipmi_sensor_t *sensor,
						   int           event,
						   int           *val);
int ipmi_sensor_discrete_deassertion_event_supported(ipmi_sensor_t *sensor,
						     int           event,
						     int           *val);
int ipmi_discrete_event_readable(ipmi_sensor_t *sensor,
				 int           event,
				 int           *val);
int ipmi_sensor_get_base_unit(ipmi_sensor_t *sensor);
int ipmi_sensor_get_modifier_unit(ipmi_sensor_t *sensor);
int ipmi_sensor_get_linearization(ipmi_sensor_t *sensor);
int ipmi_sensor_get_tolerance(ipmi_sensor_t *sensor,
			      int           val,
			      double        *tolerance);
int ipmi_sensor_get_accuracy(ipmi_sensor_t *sensor, int val, double *accuracy);
int ipmi_sensor_get_normal_min_specified(ipmi_sensor_t *sensor);
int ipmi_sensor_get_normal_max_specified(ipmi_sensor_t *sensor);
int ipmi_sensor_get_nominal_reading_specified(ipmi_sensor_t *sensor);
int ipmi_sensor_get_nominal_reading(ipmi_sensor_t *sensor,
				    double *nominal_reading);
int ipmi_sensor_get_normal_max(ipmi_sensor_t *sensor, double *normal_max);
int ipmi_sensor_get_normal_min(ipmi_sensor_t *sensor, double *normal_min);
int ipmi_sensor_get_sensor_max(ipmi_sensor_t *sensor, double *sensor_max);
int ipmi_sensor_get_sensor_min(ipmi_sensor_t *sensor, double *sensor_min);
int ipmi_sensor_get_oem1(ipmi_sensor_t *sensor);
int ipmi_sensor_get_id_length(ipmi_sensor_t *sensor);
void ipmi_sensor_get_id(ipmi_sensor_t *sensor, char *id, int length);
/* The ID from the main SDR. */
int ipmi_sensor_get_assigned_id_length(ipmi_sensor_t *sensor);
void ipmi_sensor_get_assigned_id(ipmi_sensor_t *sensor, char *id, int length);


/* This is the implementation for a set of thresholds for a
   threshold-based sensor.  Don't directly use the contents of the
   structure, use the helper functions to initialize, read, and modify
   this structure. */
typedef struct ipmi_thresholds_s
{
    /* Pay no attention to the implementation here. */
    struct {
	unsigned int status; /* Is this threshold enabled? */
	double       val;
    } vals[6];
} ipmi_thresholds_t;
int ipmi_thresholds_init(ipmi_thresholds_t *th);
/* Is sensor is non-null, it verifies that the given threshold can be set
   for the sensor. */
int ipmi_threshold_set(ipmi_thresholds_t  *th,
		       ipmi_sensor_t      *sensor,
		       enum ipmi_thresh_e threshold,
		       double             value);
int ipmi_threshold_get(ipmi_thresholds_t  *th,
		       enum ipmi_thresh_e threshold,
		       double             *value);
		       
/* Set the thresholds for the given sensor. */
int ipmi_thresholds_set(ipmi_sensor_t       *sensor,
			ipmi_thresholds_t   *thresholds,
			ipmi_sensor_done_cb done,
			void                *cb_data);

/* Fetch the thresholds from the given sensor. */
typedef void (*ipmi_thresh_get_cb)(ipmi_sensor_t     *sensor,
				   int               err,
				   ipmi_thresholds_t *th,
				   void              *cb_data);
int ipmi_thresholds_get(ipmi_sensor_t      *sensor,
			ipmi_thresh_get_cb done,
			void               *cb_data);

/* Discrete states, or threshold status. */
typedef struct ipmi_states_s
{
    unsigned int __states;
} ipmi_states_t;

static inline void ipmi_init_states(ipmi_states_t *states)
{
    states->__states = 0;
}

/* Read the current value of the given threshold sensor. */
int ipmi_is_threshold_out_of_range(ipmi_states_t      *states,
				   enum ipmi_thresh_e thresh);
void ipmi_set_threshold_out_of_range(ipmi_states_t      *states,
				     enum ipmi_thresh_e thresh,
				     int                val);
typedef void (*ipmi_reading_done_cb)(ipmi_sensor_t *sensor,
				     int           err,
				     int           val_present,
				     double        val,
				     ipmi_states_t states,
				     void          *cb_data);
int ipmi_reading_get(ipmi_sensor_t        *sensor,
		     ipmi_reading_done_cb done,
		     void                 *cb_data);

/* Read the current states from the discrete sensor. */
int ipmi_is_state_set(ipmi_states_t *states,
		      int           state_num);
void ipmi_set_state(ipmi_states_t *states,
		    int           state_num,
		    int           val);
typedef void (*ipmi_states_read_cb)(ipmi_sensor_t *sensor,
				    int           err,
				    ipmi_states_t states,
				    void          *cb_data);
int ipmi_states_get(ipmi_sensor_t       *sensor,
		    ipmi_states_read_cb done,
		    void                *cb_data);


/*
 * Indicators are lights, relays, displays, alarms, or other things of
 * that nature.  Basically, output devices.  IPMI does not define
 * these, but they are pretty fundamental for system management.  */
int ipmi_control_get_type(ipmi_control_t *ind);
int ipmi_control_get_id_length(ipmi_control_t *sensor);
void ipmi_control_get_id(ipmi_control_t *sensor, char *id, int length);
int ipmi_control_get_entity_id(ipmi_control_t *ind);
int ipmi_control_get_entity_instance(ipmi_control_t *ind);
ipmi_entity_t *ipmi_control_get_entity(ipmi_control_t *ind);
char *ipmi_control_get_type_string(ipmi_control_t *ind);

/* Get the number of values the indicator supports. */
int ipmi_control_get_num_vals(ipmi_control_t *ind);


/* A general callback for indicator operations that don't received
   any data. */
typedef void (*ipmi_control_op_cb)(ipmi_control_t *ind, int err, void *cb_data);

/* Set the setting of an indicator.  Note that an indicator may
 support more than one element, the array passed in to "val" must
 match the number of elements the indicator supports.  All the
 elements will be set simultaneously. */
int ipmi_control_set_val(ipmi_control_t     *ind,
		     int            *val,
		     ipmi_control_op_cb handler,
		     void           *cb_data);

/* Get the setting of an indicator.  Like setting indicators, this
   returns an array of values, one for each of the number of elements
   the indicator supports. */
typedef void (*ipmi_control_val_cb)(ipmi_control_t *ind,
				int        err,
				int        *val,
				void       *cb_data);
int ipmi_control_get_val(ipmi_control_t      *ind,
		     ipmi_control_val_cb handler,
		     void            *cb_data);

/* For LIGHT types.  */

/* A light indicator may control one or more lights.  If a light
   indicator controls more than one light, the lights may not
   be set individually, they are controlled as a group, one set
   command will set them all. */

/* Get the number of settings the light supports. */
int ipmi_control_get_num_light_settings(ipmi_control_t   *ind,
				    unsigned int light);

/* This describes a setting for a light.  For each setting each light
   is defined to go through a number of transitions.  Each transition
   is described by a color, a time (in milliseconds) that the color is
   present.  For non-blinking lights, there will only be one transition.
   For blinking lights, there will be one or more transition.. */

/* Get the setting for the specific setting.  These return -1 for
   an invalid num. */
int ipmi_control_get_num_light_transitions(ipmi_control_t   *ind,
				       unsigned int light,
				       unsigned int setting);
int ipmi_control_get_light_color(ipmi_control_t   *ind,
			     unsigned int light,
			     unsigned int setting,
			     unsigned int num);
int ipmi_control_get_light_color_time(ipmi_control_t   *ind,
				  unsigned int light,
				  unsigned int setting,
				  unsigned int num);

/* RELAY types have no settings. */

/* ALARM types have no settings. */

/* CONTROL types are represented as arrays of unsigned data.
   Identifiers do not support multiple elements, and have their own
   setting function. */
typedef void (*ipmi_control_identifier_val_cb)(ipmi_control_t *ind,
					       int            err,
					       unsigned char  *val,
					       int            length,
					       void           *cb_data);
int ipmi_control_identifier_get_val(ipmi_control_t                 *ind,
				    ipmi_control_identifier_val_cb handler,
				    void                           *cb_data);
int ipmi_control_identifier_set_val(ipmi_control_t     *ind,
				    ipmi_control_op_cb handler,
				    unsigned char      *val,
				    int                length,
				    void               *cb_data);
unsigned int ipmi_control_identifier_get_max_length(ipmi_control_t *ind);


/* For DISPLAY types, which are string displays. Displays do not
   support multiple elements, and have their own setting function. */
/* Get the dimensions of the display device.  This assumes a square, which
   is usually (but maybe not always) a good assumption. */
void ipmi_control_get_display_dimensions(ipmi_control_t *ind,
					 unsigned int   *columns,
					 unsigned int   *rows);

int ipmi_control_set_display_string(ipmi_control_t     *ind,
				    unsigned int       start_row,
				    unsigned int       start_column,
				    char               *str,
				    unsigned int       len,
				    ipmi_control_op_cb handler,
				    void               *cb_data);
				
/* Fetch a string from the display. */
typedef void (*ipmi_control_str_cb)(ipmi_control_t *ind,
				    int            err,
				    char           *str,
				    unsigned int   len,
				    void           *cb_data);
int ipmi_control_get_display_string(ipmi_control_t      *ind,
				    unsigned int        start_row,
				    unsigned int        start_column,
				    unsigned int        len,
				    ipmi_control_str_cb handler,
				    void                *cb_data);

/*
 * System Event Log stuff
 */

/* This must be called before calling any other IPMI functions.  It
   sets a mutex and mutex operations for the smi.  You must provide
   an OS handler to use for the system. */
int ipmi_init(os_handler_t *handler);

void *ipmi_get_user_data(ipmi_mc_t *mc);

/* Close an IPMI connection.  This will free all memory associated
   with the connections, any outstanding responses will be lost, etc.
   The passed in MC must be a SMI MC.  All slave MC's will also be
   closed when this is closed. */
typedef void (*close_done_t)(ipmi_mc_t *mc, void *cb_data);
int ipmi_close_connection(ipmi_mc_t    *mc,
			  close_done_t close_done,
			  void         *cb_data);

/* This function will be called when the IPMI BMC has completed
   all the operations required to be fully functional.  It may be
   NULL, and then will be ignored.  If "err" is non-zero, then an
   error has occured, and the ipmi connection is not operational and
   will be closed automatically by the system. */
typedef void (*ipmi_setup_done_t)(ipmi_mc_t *mc,
				  void      *user_data,
				  int       err);

/* Extract a 32-bit integer from the data, IPMI (little-endian) style. */
static inline unsigned int ipmi_get_uint32(unsigned char *data)
{
    return (data[0]
	    | (data[1] << 8)
	    | (data[2] << 16)
	    | (data[3] << 24));
}

/* Extract a 16-bit integer from the data, IPMI (little-endian) style. */
static inline unsigned int ipmi_get_uint16(unsigned char *data)
{
    return (data[0]
	    | (data[1] << 8));
}

/* Add a 32-bit integer to the data, IPMI (little-endian) style. */
static inline void ipmi_set_uint32(unsigned char *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
    data[2] = (val >> 16) & 0xff;
    data[3] = (val >> 24) & 0xff;
}

/* Add a 16-bit integer to the data, IPMI (little-endian) style. */
static inline void ipmi_set_uint16(unsigned char *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
}

/* Fetch an IPMI device string as defined in section 37.14 of the IPMI
   version 1.5 manual.  The in_len is the number of input bytes in the
   string, including the type/length byte.  The max_out_len is the
   maximum number of characters to output, including the nil */
void ipmi_get_device_string(unsigned char *input,
			    int           in_len,
			    char          *output,
			    int           max_out_len);

/* Store an IPMI device string in the most compact form possible.
   input is the input string (nil terminated), output is where to
   place the output (including the type/length byte) and out_len is a
   pointer to the max size of output (including the type/length byte).
   Upon return, out_len will be set to the actual output length. */
void ipmi_set_device_string(char          *input,
			    unsigned char *output,
			    int           *out_len);

/* Log information for the IPMI log. */
void ipmi_log(char *format, ...);

#endif /* __IPMIIF_H */
