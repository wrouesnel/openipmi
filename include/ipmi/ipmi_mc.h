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
#include <ipmi/ipmi_types.h>
#include <ipmi/os_handler.h>
#include <ipmi/ipmi_entity.h>
#include <ipmi/ipmi_sensor.h>
#include <ipmi/ipmi_control.h>
#include <ipmi/ipmi_sdr.h>
#include <ipmi/ipmi_addr.h>

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
int ipmi_mc_get_address(ipmi_mc_t *mc);

/* Get the channel for the given MC. */
int ipmi_mc_get_channel(ipmi_mc_t *mc);

/* Should the BMC do a full bus scan at startup?  This is so OEM
   code can turn this function off.  The value is a boolean. */
int ipmi_bmc_set_full_bus_scan(ipmi_mc_t *bmc, int val);

/* Allocate an MC in the BMC.  It doesn't add it to the BMC's list, to
   allow the MC to be setup before that happens. */
int ipmi_create_mc(ipmi_mc_t    *bmc,
		   ipmi_addr_t  *addr,
		   unsigned int addr_len,
		   ipmi_mc_t    **new_mc);

/* Add an MC to the list of MCs in the BMC. */
int ipmi_add_mc_to_bmc(ipmi_mc_t *bmc, ipmi_mc_t *mc);

/* Destroy an MC. */
void ipmi_cleanup_mc(ipmi_mc_t *mc);

/* Initialize the MC code, called only once at init time. */
int ipmi_mc_init(void);

#endif /* _IPMI_MC_H */
