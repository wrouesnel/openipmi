/*
 * ipmi_mc.h
 *
 * MontaVista IPMI interface for management controllers
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

#ifndef _IPMI_MC_H
#define _IPMI_MC_H
#include <OpenIPMI/ipmi_types.h>
#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/ipmi_entity.h>
#include <OpenIPMI/ipmi_sensor.h>
#include <OpenIPMI/ipmi_control.h>
#include <OpenIPMI/ipmi_sdr.h>
#include <OpenIPMI/ipmi_addr.h>

/* A response comes back in this format. */
typedef void (*ipmi_mc_response_handler_t)(ipmi_mc_t  *src,
					   ipmi_msg_t *msg,
					   void       *rsp_data);

/* Send the command in "msg" and register a handler to handle the
   response.  This will return without blocking; when the response
   comes back the handler will be called.  The handler may be NULL;
   then the response is ignored.  Note that if non-NULL the response
   handler will always be called; if no response is received in time
   the code will return a timeout response. rsp_data is passed to the
   response handler, it may contain anything the user likes.  Note
   that if the mc goes away between the time the command is sent and
   the response comes back, this callback WILL be called, but the MC
   value will be NULL.  You must handle that. */
int ipmi_mc_send_command(ipmi_mc_t                  *mc,
			 unsigned int               lun,
			 ipmi_msg_t                 *cmd,
			 ipmi_mc_response_handler_t rsp_handler,
			 void                       *rsp_data);

/* Basic information about a MC.  */
int ipmi_mc_provides_device_sdrs(ipmi_mc_t *mc);
int ipmi_mc_device_available(ipmi_mc_t *mc);
int ipmi_mc_chassis_support(ipmi_mc_t *mc);
int ipmi_mc_bridge_support(ipmi_mc_t *mc);
int ipmi_mc_ipmb_event_generator_support(ipmi_mc_t *mc);
int ipmi_mc_ipmb_event_receiver_support(ipmi_mc_t *mc);
int ipmi_mc_fru_inventory_support(ipmi_mc_t *mc);
int ipmi_mc_sel_device_support(ipmi_mc_t *mc);
int ipmi_mc_sdr_repository_support(ipmi_mc_t *mc);
int ipmi_mc_sensor_device_support(ipmi_mc_t *mc);
int ipmi_mc_device_id(ipmi_mc_t *mc);
int ipmi_mc_device_revision(ipmi_mc_t *mc);
int ipmi_mc_major_fw_revision(ipmi_mc_t *mc);
int ipmi_mc_minor_fw_revision(ipmi_mc_t *mc);
int ipmi_mc_major_version(ipmi_mc_t *mc);
int ipmi_mc_minor_version(ipmi_mc_t *mc);
int ipmi_mc_manufacturer_id(ipmi_mc_t *mc);
int ipmi_mc_product_id(ipmi_mc_t *mc);
void ipmi_mc_aux_fw_revision(ipmi_mc_t *mc, unsigned char val[]);

/* Some stupid systems don't have some settings right, this lets the
   OEM code fix it. */
void ipmi_mc_set_provides_device_sdrs(ipmi_mc_t *mc, int val);
void ipmi_mc_set_sel_device_support(ipmi_mc_t *mc, int val);
void ipmi_mc_set_sdr_repository_support(ipmi_mc_t *mc, int val);
void ipmi_mc_set_sensor_device_support(ipmi_mc_t *mc, int val);
void ipmi_mc_set_device_available(ipmi_mc_t *mc, int val);
void ipmi_mc_set_chassis_support(ipmi_mc_t *mc, int val);
void ipmi_mc_set_bridge_support(ipmi_mc_t *mc, int val);
void ipmi_mc_set_ipmb_event_generator_support(ipmi_mc_t *mc, int val);
void ipmi_mc_set_ipmb_event_receiver_support(ipmi_mc_t *mc, int val);
void ipmi_mc_set_fru_inventory_support(ipmi_mc_t *mc, int val);

/* Reread all the sensors for a given mc.  This will request the
   sensor SDRs for that mc (And only for that MC) and change the
   sensors as necessary. */
typedef void (*ipmi_mc_done_cb)(ipmi_mc_t *mc, int err, void *cb_data);
int ipmi_mc_reread_sensors(ipmi_mc_t       *mc,
			   ipmi_mc_done_cb done,
			   void            *done_data);

/* Get and set the setting to enable events for the entire MC.  The
   value returned by the get function is a boolean telling whether
   events are enabled.  The "val" passed in to the set function is a
   boolean telling whether to turn events on (true) or off (false). */
int ipmi_mc_get_events_enable(ipmi_mc_t *mc);
int ipmi_mc_set_events_enable(ipmi_mc_t       *mc,
			      int             val,
			      ipmi_mc_done_cb done,
			      void            *cb_data);

/* Use the "main" SDR repository as a device SDR repository. This
   means that any SDRs in the "main" SDR repository on the MC will
   appear as sensors, etc as if they were in the device SDR
   repository. */
int ipmi_mc_set_main_sdrs_as_device(ipmi_mc_t *mc);

/* Check to see if the MC is operational in the system.  If this is
   false, then the MC was referred to by an SDR, but it doesn't really
   exist. */
int ipmi_mc_is_active(ipmi_mc_t *mc);
void _ipmi_mc_set_active(ipmi_mc_t *mc, int val);

/* Used to monitor when the MC goes active or inactive. */
typedef void (*ipmi_mc_active_cb)(ipmi_mc_t *mc,
				  int       active,
				  void      *cb_data);
int ipmi_mc_add_active_handler(ipmi_mc_t         *mc,
			       ipmi_mc_active_cb handler,
			       void              *cb_data);
int ipmi_mc_remove_active_handler(ipmi_mc_t         *mc,
				  ipmi_mc_active_cb handler,
				  void              *cb_data);

/* Reset the MC, either a cold or warm reset depending on the type.
   Note that the effects of a reset are not defined by IPMI, so this
   might do wierd things.  Some systems do not support resetting the
   MC.  This is not a standard control because there is no entity to
   hang if from and you don't want people messing with it unless they
   really know what they are doing. */
#define IPMI_MC_RESET_COLD 1
#define IPMI_MC_RESET_WARM 2
int ipmi_mc_reset(ipmi_mc_t       *mc,
		  int             reset_type,
		  ipmi_mc_done_cb done,
		  void            *cb_data);

/* Return the domain for the given MC. */
ipmi_domain_t *ipmi_mc_get_domain(ipmi_mc_t *mc);

/* Get the sensors that the given MC owns. */
ipmi_sensor_info_t *_ipmi_mc_get_sensors(ipmi_mc_t *mc);

/* Get the controls that the given MC owns. */
ipmi_control_info_t *_ipmi_mc_get_controls(ipmi_mc_t *mc);

/* Get the sensor SDRs for the given MC. */
ipmi_sdr_info_t *ipmi_mc_get_sdrs(ipmi_mc_t *mc);

/* Get the IPMI slave address of the given MC. */
unsigned ipmi_mc_get_address(ipmi_mc_t *mc);

/* Get the MC's full IPMI address. */
void ipmi_mc_get_ipmi_address(ipmi_mc_t    *mc,
			      ipmi_addr_t  *addr,
			      unsigned int *addr_len);

/* Get the channel for the given MC. */
unsigned ipmi_mc_get_channel(ipmi_mc_t *mc);

void ipmi_mc_set_sel_rescan_time(ipmi_mc_t *mc, unsigned int seconds);
unsigned int ipmi_mc_get_sel_rescan_time(ipmi_mc_t *mc);

int _ipmi_create_mc(ipmi_domain_t *domain,
		    ipmi_addr_t   *addr,
		    unsigned int  addr_len,
		    ipmi_mc_t     **new_mc);

/* Destroy an MC. */
void _ipmi_cleanup_mc(ipmi_mc_t *mc);

#if 0
/* FIXME - need to handle this somehow. */
/* This should be called from OEM code for an SMI, ONLY WHEN THE NEW
   MC HANDLER IS CALLED, if the slave address of the SMI is not 0x20.
   This will allow the bmc t know it's own address, which is pretty
   important.  You pass in a function that the code will call (and
   pass in it's own function) when it wants the address. */
typedef void (*ipmi_mc_got_slave_addr_cb)(ipmi_mc_t    *bmc,
					  int          err,
					  unsigned int addr,
					  void         *cb_data);
typedef int (*ipmi_mc_slave_addr_fetch_cb)(
    ipmi_mc_t                 *bmc,
    ipmi_mc_got_slave_addr_cb handler,
    void                      *cb_data);
int ipmi_bmc_set_smi_slave_addr_fetcher(
    ipmi_mc_t                   *bmc,
    ipmi_mc_slave_addr_fetch_cb handler);
#endif

/* Return the timestamp that was fetched before the first SEL fetch.
   This is so that OEM code can properly ignore old events.  Note that
   this value will be set to zero after the first SEL fetch, it really
   not good for anything but comparing timestamps to see if the event
   is old. */
ipmi_time_t ipmi_mc_get_startup_SEL_time(ipmi_mc_t *bmc);

/* Reread the sel.  When the hander is called, all the events in the
   SEL have been fetched into the local copy of the SEL (with the
   obvious caveat that this is a distributed system and other things
   may have come in after the read has finised). */
int ipmi_mc_reread_sel(ipmi_mc_t       *mc,
		       ipmi_mc_done_cb handler,
		       void            *cb_data);

/* Fetch the current time from the SEL. */
typedef void (*sel_get_time_cb)(ipmi_mc_t     *mc,
				int           err,
				unsigned long time,
				void          *cb_data);
int ipmi_mc_get_current_sel_time(ipmi_mc_t       *mc,
				 sel_get_time_cb handler,
				 void            *cb_data);

/* Set the time for the SEL.  Note that this function is rather
   dangerous to do, especially if you don't set it to the current
   time, as it can cause old events to be interpreted as new
   events on this and other systems. */
int ipmi_mc_set_current_sel_time(ipmi_mc_t       *mc,
				 const struct timeval  *time,
				 ipmi_mc_done_cb handler,
				 void            *cb_data);


typedef void (*ipmi_mc_cb)(ipmi_mc_t *mc, int err, void *cb_data);

typedef void (ipmi_mc_del_event_done_cb)(ipmi_mc_t *mc, int err, void *cb_data);
int ipmi_mc_del_event(ipmi_mc_t                 *mc,
		      ipmi_event_t              *event, 
		      ipmi_mc_del_event_done_cb handler,
		      void                      *cb_data);

/* Add an event to the real SEL.  This does not directly put it into
   the internal copy of the SEL. */
typedef void (*ipmi_mc_add_event_done_cb)(ipmi_mc_t    *mc,
					  unsigned int record_id,
					  int          err,
					  void         *cb_data);
int ipmi_mc_add_event_to_sel(ipmi_mc_t                 *mc,
			     ipmi_event_t              *event,
			     ipmi_mc_add_event_done_cb handler,
			     void                      *cb_data);

/* Some OEM boxes may have special SEL delete requirements, so we have
   a special hook to let the OEM code delete events on an MC with SEL
   support. */
typedef int (*ipmi_mc_del_event_cb)(ipmi_mc_t    *mc,
				    ipmi_event_t *event,
				    ipmi_mc_cb   done_handler,
				    void         *cb_data);
void ipmi_mc_set_del_event_handler(ipmi_mc_t            *mc,
				   ipmi_mc_del_event_cb handler);
typedef int (*ipmi_mc_add_event_cb)(ipmi_mc_t                 *mc,
				    ipmi_event_t              *event,
				    ipmi_mc_add_event_done_cb done_handler,
				    void                      *cb_data);
void ipmi_mc_set_add_event_handler(ipmi_mc_t            *mc,
				   ipmi_mc_add_event_cb handler);

/* Check the event receiver for the MC. */
void _ipmi_mc_check_event_rcvr(ipmi_mc_t *mc);


int _ipmi_mc_init(void);
void _ipmi_mc_shutdown(void);

/* Returns EEXIST if the event is already there. */
int _ipmi_mc_sel_event_add(ipmi_mc_t *mc, ipmi_event_t *event);

ipmi_event_t *ipmi_mc_first_event(ipmi_mc_t *mc);
ipmi_event_t *ipmi_mc_last_event(ipmi_mc_t *mc);
ipmi_event_t *ipmi_mc_next_event(ipmi_mc_t *mc, ipmi_event_t *event);
ipmi_event_t *ipmi_mc_prev_event(ipmi_mc_t *mc, ipmi_event_t *event);
ipmi_event_t *ipmi_mc_event_by_recid(ipmi_mc_t *mc,
				     unsigned int record_id);
int ipmi_mc_sel_count(ipmi_mc_t *mc);
int ipmi_mc_sel_entries_used(ipmi_mc_t *mc);
int ipmi_mc_sel_get_major_version(ipmi_mc_t *mc);
int ipmi_mc_sel_get_minor_version(ipmi_mc_t *mc);
int ipmi_mc_sel_get_overflow(ipmi_mc_t *mc);
int ipmi_mc_sel_get_supports_delete_sel(ipmi_mc_t *mc);
int ipmi_mc_sel_get_supports_partial_add_sel(ipmi_mc_t *mc);
int ipmi_mc_sel_get_supports_reserve_sel(ipmi_mc_t *mc);
int ipmi_mc_sel_get_supports_get_sel_allocation(ipmi_mc_t *mc);
int ipmi_mc_sel_get_last_addition_timestamp(ipmi_mc_t *mc);

int _ipmi_mc_check_oem_event_handler(ipmi_mc_t *mc, ipmi_event_t *event);
int _ipmi_mc_check_sel_oem_event_handler(ipmi_mc_t *mc, ipmi_event_t *event);

/* Set and get the OEM data pointer in the mc. */
void ipmi_mc_set_oem_data(ipmi_mc_t *mc, void *data);
void *ipmi_mc_get_oem_data(ipmi_mc_t *mc);

/* Used by the sensor code to report a new sensor to the MC.  The new
   sensor call should return 1 if the sensor code should not add the
   sensor to its database. */
void _ipmi_mc_fixup_sensor(ipmi_mc_t     *mc,
			   ipmi_sensor_t *sensor);
int _ipmi_mc_new_sensor(ipmi_mc_t     *mc,
			ipmi_entity_t *ent,
			ipmi_sensor_t *sensor,
			void          *link);

/* This should be called with a new device id for an MC we don't have
   active in the system (it may be inactive). */
int _ipmi_mc_get_device_id_data_from_rsp(ipmi_mc_t *mc, ipmi_msg_t *rsp);

/* Compares the data in a get device id response (in rsp) with the
   data in the MC, returns true if they are the same and false if
   not.  Must be called with an error-free message. */
int _ipmi_mc_device_data_compares(ipmi_mc_t *mc, ipmi_msg_t *rsp);

/* Called when a new MC has been added to the system, to kick of
   processing it. */
int _ipmi_mc_handle_new(ipmi_mc_t *mc);

/* Allow sensors to keep information that came from an MC in the MC
   itself so that when the MC is destroyed, it can be cleaned up. */
void _ipmi_mc_get_sdr_sensors(ipmi_mc_t     *mc,
			      ipmi_sensor_t ***sensors,
			      unsigned int  *count);
void _ipmi_mc_set_sdr_sensors(ipmi_mc_t     *mc,
			      ipmi_sensor_t **sensors,
			      unsigned int  count);

/* Allow entities to keep information that came from an MC in the MC
   itself so that when the MC is destroyed, it can be cleaned up. */
void *_ipmi_mc_get_sdr_entities(ipmi_mc_t *mc);
void _ipmi_mc_set_sdr_entities(ipmi_mc_t *mc, void *entities);

ipmi_mcid_t ipmi_mc_convert_to_id(ipmi_mc_t *mc);
typedef void (*ipmi_mc_ptr_cb)(ipmi_mc_t *mc, void *cb_data);
int ipmi_mc_pointer_cb(ipmi_mcid_t    id,
		       ipmi_mc_ptr_cb handler,
		       void           *cb_data);
int ipmi_mc_pointer_noseq_cb(ipmi_mcid_t    id,
			     ipmi_mc_ptr_cb handler,
			     void           *cb_data);
int ipmi_cmp_mc_id(ipmi_mcid_t id1, ipmi_mcid_t id2);
int ipmi_cmp_mc_id_noseq(ipmi_mcid_t id1, ipmi_mcid_t id2);
void ipmi_mc_id_set_invalid(ipmi_mcid_t *id);
/* Is it the invalid MCID? */
int ipmi_mc_id_is_invalid(ipmi_mcid_t *id);

/* Used to create external references to an MC so it won't go away
   even if it is released. */
void _ipmi_mc_use(ipmi_mc_t *mc);
void _ipmi_mc_release(ipmi_mc_t *mc);

/* Used to periodically check that the MC data is current and valid. */
void _ipmi_mc_check_mc(ipmi_mc_t *mc);

/* Create chassis conrols for an MC. */
int _ipmi_chassis_create_controls(ipmi_mc_t *mc);

#endif /* _IPMI_MC_H */
