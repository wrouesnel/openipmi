/*
 * ipmi_mc.h
 *
 * MontaVista IPMI interface for management controllers
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
typedef void (*ipmi_response_handler_t)(ipmi_mc_t  *src,
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
int ipmi_send_command(ipmi_mc_t               *mc,
		      unsigned int            lun,
		      ipmi_msg_t              *cmd,
		      ipmi_response_handler_t rsp_handler,
		      void                    *rsp_data);

/* Like ipmi_send_command, but sends it directly to the address
   specified, not to an MC. */
int
ipmi_bmc_send_command_addr(ipmi_mc_t               *bmc,
			   ipmi_addr_t		   *addr,
			   unsigned int            addr_len,
			   ipmi_msg_t              *msg,
			   ipmi_response_handler_t rsp_handler,
			   void                    *rsp_data);

/*
 * Registration for receiving incoming commands.  Not all systems
 * support this, you will receive an ENOSYS error if that's the case.
 */

/* Called when a registered command comes in. */
typedef void (*ipmi_command_handler_t)(ipmi_mc_t  *src,
				       ipmi_msg_t *cmd,
				       long       sequence,
				       void       *cmd_data);

/* Note that in command handlers you may ONLY deregister
   the command being handled, you may not deregister any other
   commands. */

/* Send a response to a received command, the response in in "msg".
   Make sure to set the proper netfn for a response!.  The "sequence"
   should be the same number passed into the command handler. */
int ipmi_send_response(ipmi_mc_t  *mc,
		       ipmi_msg_t *msg,
		       long       sequence);

/* Register to receive a specific netfn/command pair.  You have to
   register for each netfn/command you receive.  All other recieved
   commands will automatically have an unhandled command response
   returned.  Only one handler may be registered against a
   netfn/command.  The cmd_data passed in here will be passed in to
   each command handler call.  */
int ipmi_register_for_command(ipmi_mc_t              *mc,
			      unsigned char          netfn,
			      unsigned char          cmd,
			      ipmi_command_handler_t handler,
			      void                   *cmd_data);

/* Remove the registration for a command. */
int ipmi_deregister_for_command(ipmi_mc_t    *mc,
				unsigned char netfn,
				unsigned char cmd);

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

/* Iterate over all the mc's that the given BMC represents. */
typedef void (*ipmi_bmc_iterate_mcs_cb)(ipmi_mc_t *bmc,
					ipmi_mc_t *mc,
					void      *cb_data);
int ipmi_bmc_iterate_mcs(ipmi_mc_t               *mc,
			 ipmi_bmc_iterate_mcs_cb handler,
			 void                    *cb_data);

/*
 * Channel information for a BMC.
 */
typedef struct ipmi_chan_info_s
{
    unsigned int medium : 7;
    unsigned int xmit_support : 1;
    unsigned int recv_lun : 3;
    unsigned int protocol : 5;
    unsigned int session_support : 2;
    unsigned int vendor_id : 24;
    unsigned int aux_info : 16;
} ipmi_chan_info_t;

/* Get the number of channels the BMC supports. */
int ipmi_bmc_get_num_channels(ipmi_mc_t *mc, int *val);

/* Get information about a channel by index.  The index is not
   necessarily the channel number, just an array index (up to the
   number of channels).  Get the channel number from the returned
   information. */
int ipmi_bmc_get_channel(ipmi_mc_t *mc, int index, ipmi_chan_info_t *chan);

/* Validate that the given MC is still valid. */
int ipmi_mc_validate(ipmi_mc_t *mc);

/* Check to see if the MC is operational in the system.  If this is
   false, then the MC was referred to by an SDR, but it doesn't really
   exist. */
int ipmi_mc_is_active(ipmi_mc_t *mc);

/* Return the OS handler used by the mc. */
os_handler_t *ipmi_mc_get_os_hnd(ipmi_mc_t *mc);

/* Return the BMC for the given MC. */
ipmi_mc_t *ipmi_mc_get_bmc(ipmi_mc_t *mc);

/* Return the entity info for the given MC's BMC. */
ipmi_entity_info_t *ipmi_mc_get_entities(ipmi_mc_t *mc);

/* Lock/unlock the entities for the given MC's BMC. */
void ipmi_mc_entity_lock(ipmi_mc_t *mc);
void ipmi_mc_entity_unlock(ipmi_mc_t *mc);

/* Get the sensors that the given MC owns. */
ipmi_sensor_info_t *ipmi_mc_get_sensors(ipmi_mc_t *mc);

/* Get the indicators that the given MC owns. */
ipmi_control_info_t *ipmi_mc_get_controls(ipmi_mc_t *mc);

/* Rescan the entities for possible presence changes.  "force" causes
   a full rescan even if nothing on an entity has changed. */
int ipmi_detect_bmc_presence_changes(ipmi_mc_t *mc, int force);

/* Get the sensor SDRs for the given MC. */
ipmi_sdr_info_t *ipmi_mc_get_sdrs(ipmi_mc_t *mc);

/* Get the IPMI slave address of the given MC. */
unsigned ipmi_mc_get_address(ipmi_mc_t *mc);

/* Get the channel for the given MC. */
unsigned ipmi_mc_get_channel(ipmi_mc_t *mc);

/* Should the BMC do a full bus scan at startup?  This is so OEM
   code can turn this function off.  The value is a boolean. */
int ipmi_bmc_set_full_bus_scan(ipmi_mc_t *bmc, int val);

/* Allocate an MC in the BMC.  It doesn't add it to the BMC's list, to
   allow the MC to be setup before that happens. */
int ipmi_create_mc(ipmi_mc_t    *bmc,
		   ipmi_addr_t  *addr,
		   unsigned int addr_len,
		   ipmi_mc_t    **new_mc);

/* Attempt to find the MC, and if it doesn't exist create it and
   return it. */
int ipmi_mc_find_or_create_mc_by_slave_addr(ipmi_mc_t    *bmc,
					    unsigned int slave_addr,
					    ipmi_mc_t    **mc);

void ipmi_mc_get_sdr_sensors(ipmi_mc_t     *bmc,
			     ipmi_mc_t     *mc,
			     ipmi_sensor_t ***sensors,
			     unsigned int  *count);

void ipmi_mc_set_sdr_sensors(ipmi_mc_t     *bmc,
			     ipmi_mc_t     *mc,
			     ipmi_sensor_t **sensors,
			     unsigned int  count);

/* Add an MC to the list of MCs in the BMC. */
int ipmi_add_mc_to_bmc(ipmi_mc_t *bmc, ipmi_mc_t *mc);

/* Destroy an MC. */
void ipmi_cleanup_mc(ipmi_mc_t *mc);

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

/* Scan a set of addresses on the bmc for mcs.  This can be used by OEM
   code to add an MC if it senses that one has become present. */
void ipmi_start_ipmb_mc_scan(ipmi_mc_t    *bmc,
	       		     int          channel,
	       		     unsigned int start_addr,
			     unsigned int end_addr,
                             ipmi_bmc_cb  done_handler,
			     void         *cb_data);

/* Add an IPMB address to a list of addresses to not scan.  This way,
   if you have weak puny devices in IPMB that will break if you do
   normal IPMB operations, you can have them be ignored. */
int ipmi_bmc_add_ipmb_ignore(ipmi_mc_t *bmc, unsigned char ipmb_addr);

/* Return the timestamp that was fetched before the first SEL fetch.
   This is so that OEM code can properly ignore old events. */
unsigned long ipmi_mc_get_startup_SEL_time(ipmi_mc_t *bmc);

/* If OEM code gets and event and it doesn't deliver it to the user,
   it should deliver it this way, that way it can be delivered to the
   user to be deleted. */
void ipmi_handle_unhandled_event(ipmi_mc_t *bmc, ipmi_event_t *event);

/* Some OEM boxes may have special SEL delete requirements, so we have
   a special hook to let the OEM code delete events on an MC with SEL
   support. */
typedef int (*ipmi_mc_del_event_cb)(ipmi_mc_t    *mc,
				    ipmi_event_t *event,
				    ipmi_bmc_cb  done_handler,
				    void         *cb_data);
void ipmi_mc_set_del_event_handler(ipmi_mc_t            *mc,
				   ipmi_mc_del_event_cb handler);

/* Set and get the OEM data pointer in the mc. */
void ipmi_mc_set_oem_data(ipmi_mc_t *mc, void *data);
void *ipmi_mc_get_oem_data(ipmi_mc_t *mc);

/* Initialize the MC code, called only once at init time. */
int ipmi_mc_init(void);

/* Clean up the global MC memory. */
void ipmi_mc_shutdown(void);

/* Do a pointer callback but ignore the sequence number.  This is
   primarily for handling incoming events, where the sequence number
   doesn't matter. */
int ipmi_mc_pointer_noseq_cb(ipmi_mc_id_t id,
			     ipmi_mc_cb   handler,
			     void         *cb_data);

#endif /* _IPMI_MC_H */
