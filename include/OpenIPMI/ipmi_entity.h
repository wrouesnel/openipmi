/*
 * ipmi_entity.h
 *
 * MontaVista IPMI interface for dealing with entities
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
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

#ifndef _IPMI_ENTITY_H
#define _IPMI_ENTITY_H
#include <OpenIPMI/ipmi_types.h>
#include <OpenIPMI/ipmi_sdr.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmiif.h>

/* This is an abstract type that identifies an entity. */
typedef struct ipmi_entity_info_s ipmi_entity_info_t;

/* Allocate and destroy an entity.  This should be used by OEM code
   that needs to create it's own entities. */
int ipmi_entity_info_alloc(ipmi_domain_t      *domain,
			   ipmi_entity_info_t **new_ents);
int ipmi_entity_info_destroy(ipmi_entity_info_t *ents);

/* Find an entity in the domain's set of entities that has the given
   entity id and entity instance.  The MC is the mc the entity came
   from, or NULL if from the main SDR repository. */
int ipmi_entity_find(ipmi_entity_info_t *ents,
		     ipmi_mc_t          *mc,
		     int                entity_id,
		     int                entity_instance,
		     ipmi_entity_t      **found_ent);

/* Add an entity to the list of entities in the BMC.  You must
   register a "gen_output" handler, that will be called when the SDRs
   are output.  This is so an OEM entity can create their own SDRs. */
typedef int (*entity_sdr_add_cb)(ipmi_entity_t   *ent,
				 ipmi_sdr_info_t *sdrs,
				 void            *cb_data);
int ipmi_entity_add(ipmi_entity_info_t *ents,
		    ipmi_domain_t      *domain,
		    ipmi_mc_t          *mc, /* SDR repository the MC is from */
		    int                lun,
		    int                entity_id,
		    int                entity_instance,
		    char               *id,
		    enum ipmi_str_type_e id_type,
		    unsigned int       id_len,
		    entity_sdr_add_cb  sdr_gen_output,
		    void               *sdr_gen_cb_data,
		    ipmi_entity_t      **new_ent);

/* Called only when the MC that the entity came from is destroyed.
   Note that this may not actually remove the entity, that depends on
   if it has sensors referencing it. */
int ipmi_sdr_entity_destroy(void *info);

/* More OEM stuff, handle entity associations. */
int ipmi_entity_add_child(ipmi_entity_t       *ent,
			  ipmi_entity_t       *child);
int ipmi_entity_remove_child(ipmi_entity_t     *ent,
			     ipmi_entity_t     *child);

/* Get the number of child entities that the entity has. */
int ipmi_entity_subentity_count(ipmi_entity_t *ent,
				unsigned int  *count);

/* Return a child entity by it's index. */
int ipmi_entity_get_subentity(ipmi_entity_t *ent,
			      int           index,
			      ipmi_entity_t **sub_ent);

/* This is an internal call used to pre-allocate an internal data
   structure used by the entity code, used by the next call.  This
   will return NULL on a failure. */
void *ipmi_entity_alloc_sensor_link(void);
void ipmi_entity_free_sensor_link(void *link);
void *ipmi_entity_alloc_control_link(void);
void ipmi_entity_free_control_link(void *link);

/* Add a sensor/indicator to the entity.  The "ref" must be allocated with the
   above call.  This call is guaranteed to succeed. */
void ipmi_entity_add_sensor(ipmi_entity_t *ent,
			    ipmi_sensor_t *sensor,
			    void          *ref);
void ipmi_entity_add_control(ipmi_entity_t  *ent,
			     ipmi_control_t *control,
			     void           *ref);

/* Remove a sensor/indicator from an entity.  This call is guaranteed
   to succeed. */
void ipmi_entity_remove_sensor(ipmi_entity_t *ent,
			       ipmi_sensor_t *sensor);
void ipmi_entity_remove_control(ipmi_entity_t  *ent,
				ipmi_control_t *control);

/* A sensor/ind that is attached the entity has had it's information
   changed by the remote system.  This does NOT mean the sensor's
   value changed, see the sensor code for that. */
void ipmi_entity_sensor_changed(ipmi_entity_t *ent,
				ipmi_mc_t     *mc,
				int           lun,
				int           num,
				ipmi_sensor_t *old,
				ipmi_sensor_t *new);
void ipmi_entity_control_changed(ipmi_entity_t  *ent,
				 ipmi_mc_t      *mc,
				 int            lun,
				 int            num,
				 ipmi_control_t *old,
				 ipmi_control_t *new);

/* Create an SDR record for the entity and append it to the set of SDRs. */
int ipmi_entity_append_to_sdrs(ipmi_entity_info_t *ents,
			       ipmi_sdr_info_t    *sdrs);

/* Scan the SDRs (generally from the main set) for association records
   and other entity-related things.  This will create new entities and
   add them to the "ents".  The MC should be the MC the entity came
   from, or NULL if from the main SDR repository and the the domain
   should be set. */
int ipmi_entity_scan_sdrs(ipmi_domain_t      *domain,
			  ipmi_mc_t          *mc,
			  ipmi_entity_info_t *ents,
			  ipmi_sdr_info_t    *sdrs);

/* Sets a handler that will be called when an entity in the list
   changes.  User's should not normally call this, they should call
   the BMC version .*/
int ipmi_entity_set_update_handler(ipmi_entity_info_t    *ents,
				   ipmi_domain_entity_cb handler,
				   void                  *cb_data);

/* Iterate over all the entities in the entity info. */
void ipmi_entities_iterate_entities(ipmi_entity_info_t              *ent,
				    ipmi_entities_iterate_entity_cb handler,
				    void                            *cb_data);

/* Scan all the entities in the container and re-detect their precence
   if a presence-modifying event has occurred.  Non-event operations
   (like adding and removing sensors) will not automatically rescan
   presence (to avoid trashing).  For instance, if you rescan sensors
   or SDRs, you probably want to call this. */
int ipmi_detect_ents_presence_changes(ipmi_entity_info_t *ents, int force);

void ipmi_entity_set_access_address(ipmi_entity_t *ent, int access_address);
void ipmi_entity_set_slave_address(ipmi_entity_t *ent, int slave_address);
void ipmi_entity_set_channel(ipmi_entity_t *ent, int channel);
void ipmi_entity_set_lun(ipmi_entity_t *ent, int lun);
void ipmi_entity_set_private_bus_id(ipmi_entity_t *ent, int private_bus_id);
void ipmi_entity_set_is_logical_fru(ipmi_entity_t *ent, int is_logical_fru);
void ipmi_entity_set_fru_device_id(ipmi_entity_t *ent, int fru_device_id);
void ipmi_entity_set_type(ipmi_entity_t *ent, enum ipmi_dlr_type_e type);
void ipmi_entity_set_device_type(ipmi_entity_t *ent, int device_type);
void ipmi_entity_set_device_modifier(ipmi_entity_t *ent, int device_modifier);
void ipmi_entity_set_oem(ipmi_entity_t *ent, int oem);

/* This value is copied into an internal array, so no need to save or
   manage. */
void ipmi_entity_set_id(ipmi_entity_t *ent, char *id,
			enum ipmi_str_type_e type, int length);

void ipmi_entity_set_presence_sensor_always_there(ipmi_entity_t *ent, int val);
void ipmi_entity_set_ACPI_system_power_notify_required(ipmi_entity_t *ent,
						       int           val);
void ipmi_entity_set_ACPI_device_power_notify_required(ipmi_entity_t *ent,
						       int           val);
void ipmi_entity_set_controller_logs_init_agent_errors(ipmi_entity_t *ent,
						       int           val);
void ipmi_entity_set_log_init_agent_errors_accessing(ipmi_entity_t *ent,
						     int           val);
void ipmi_entity_set_global_init(ipmi_entity_t *ent,
				 int           val);
void ipmi_entity_set_chassis_device(ipmi_entity_t *ent,
				    int           val);
void ipmi_entity_set_bridge(ipmi_entity_t *ent,
			    int           val);
void ipmi_entity_set_IPMB_event_generator(ipmi_entity_t *ent,
					  int           val);
void ipmi_entity_set_IPMB_event_receiver(ipmi_entity_t *ent,
					 int           val);
void ipmi_entity_set_FRU_inventory_device(ipmi_entity_t *ent,
					  int           val);
void ipmi_entity_set_SEL_device(ipmi_entity_t *ent,
				int           val);
void ipmi_entity_set_SDR_repository_device(ipmi_entity_t *ent,
					   int           val);
void ipmi_entity_set_sensor_device(ipmi_entity_t *ent,
				   int           val);

/* This pointer is kept in the data structure.  You should use a
   static string here, which should always be doable, I think.  If
   not, a management interface needs to be added for this. */
void ipmi_entity_set_entity_id_string(ipmi_entity_t *ent, char *str);

/* Return the FRU for this entity, or NULL if it doesn't have one
   or the fetch has not completed. */
ipmi_fru_t *ipmi_entity_get_fru(ipmi_entity_t *ent);

/* Fetch the FRUs for this entity. */
int ipmi_entity_fetch_frus(ipmi_entity_t *ent);

/* Set the entity as hot-swappable. */
int ipmi_entity_set_hot_swappable(ipmi_entity_t *ent, int val);

/* Hot-swap state callbacks. */
typedef struct ipmi_entity_hot_swap_s
{
    int (*get_hot_swap_state)(ipmi_entity_t           *ent,
			      ipmi_entity_hot_swap_cb handler,
			      void                    *cb_data);

    int (*set_auto_activate)(ipmi_entity_t  *ent,
			     int            auto_act,
			     ipmi_entity_cb done,
			     void           *cb_data);

    int (*get_auto_activate)(ipmi_entity_t      *ent,
			     ipmi_entity_val_cb handler,
			     void               *cb_data);

    int (*set_auto_deactivate)(ipmi_entity_t  *ent,
			       int            auto_act,
			       ipmi_entity_cb done,
			       void           *cb_data);

    int (*get_auto_deactivate)(ipmi_entity_t      *ent,
			       ipmi_entity_val_cb handler,
			       void               *cb_data);

    int (*activate)(ipmi_entity_t  *ent,
		    ipmi_entity_cb done,
		    void           *cb_data);

    int (*deactivate)(ipmi_entity_t  *ent,
		      ipmi_entity_cb done,
		      void           *cb_data);

    int (*get_hot_swap_indicator)(ipmi_entity_t      *ent,
				  ipmi_entity_val_cb handler,
				  void               *cb_data);

    int (*set_hot_swap_indicator)(ipmi_entity_t  *ent,
				  int            val,
				  ipmi_entity_cb done,
				  void           *cb_data);

    int (*get_hot_swap_requester)(ipmi_entity_t      *ent,
				  ipmi_entity_val_cb handler,
				  void               *cb_data);
} ipmi_entity_hot_swap_t;

/* Set the hot-swap control state machine. */
void ipmi_entity_set_hot_swap_control(ipmi_entity_t          *ent,
				      ipmi_entity_hot_swap_t *cbs);

/* There is a built-in hot-swap engine for entities that will be used
   if all the right things are set on a entity and a hot-swap control
   state machine is not already installed (get_hot_swap_state is not
   NULL).

   If an entity has a presence sensor and other criteria are not met,
   a simplified (active/inactive) hot-swap state machine is
   implemented.

   If an entity has the following, then an inactive state is added with
   possible setting of auto-activate.  Note that these need to be there
   even if the entity is not present:
   * A presence sensor
   * A power control with "ipmi_control_is_hot_swap_power" returning true

   If the following are present, then the extraction pending state will
   be used:
   * A presence sensor
   * A discrete sensor with "ipmi_sensor_is_hot_swap_requester" returning
     true.
   This sensor may appear later, it does not have to always be present.

   If a hot-swap indicator appears (an LED control with one LED for
   which "ipmi_control_is_hot_swap_indicator" returns true, it will be
   automatically controlled.  This control does not have to be present
   all the time, but should generally appear except in not present
   state.
*/

/* Locks for the entity. */
void ipmi_entity_lock(ipmi_entity_t *ent);
void ipmi_entity_unlock(ipmi_entity_t *ent);

#endif /* _IPMI_ENTITY_H */
