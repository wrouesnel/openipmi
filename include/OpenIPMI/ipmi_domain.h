/*
 * ipmi_domain.h
 *
 * MontaVista IPMI interface for management domains
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

#ifndef _IPMI_DOMAIN_H
#define _IPMI_DOMAIN_H
#include <OpenIPMI/ipmi_types.h>
#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/ipmi_entity.h>
#include <OpenIPMI/ipmi_sensor.h>
#include <OpenIPMI/ipmi_control.h>
#include <OpenIPMI/ipmi_sdr.h>
#include <OpenIPMI/ipmi_addr.h>

/* A response comes back in this format. */
typedef int (*ipmi_addr_response_handler_t)(ipmi_domain_t *domain,
					    ipmi_msgi_t   *rspi);

/* Like ipmi_send_command, but sends it directly to the address
   specified, not to an MC. */
int
ipmi_send_command_addr(ipmi_domain_t                *domain,
		       ipmi_addr_t	            *addr,
		       unsigned int                 addr_len,
		       ipmi_msg_t                   *msg,
		       ipmi_addr_response_handler_t rsp_handler,
		       void                         *rsp_data1,
		       void                         *rsp_data2);

/* Handle validation and usecounts on domains. */
int _ipmi_domain_get(ipmi_domain_t *domain);
void _ipmi_domain_put(ipmi_domain_t *domain);

/* Iterate over all the mc's that the given domain represents. */
typedef void (*ipmi_domain_iterate_mcs_cb)(ipmi_domain_t *domain,
					   ipmi_mc_t     *mc,
					   void          *cb_data);
int ipmi_domain_iterate_mcs(ipmi_domain_t              *domain,
			    ipmi_domain_iterate_mcs_cb handler,
			    void                       *cb_data);
int ipmi_domain_iterate_mcs_rev(ipmi_domain_t              *domain,
				ipmi_domain_iterate_mcs_cb handler,
				void                       *cb_data);

/* Return the OS handler used by the mc. */
os_handler_t *ipmi_domain_get_os_hnd(ipmi_domain_t *domain);

/* Return the entity info for the given domain. */
ipmi_entity_info_t *ipmi_domain_get_entities(ipmi_domain_t *domain);

/* Rescan the entities for possible presence changes.  "force" causes
   a full rescan even if nothing on an entity has changed. */
int ipmi_detect_domain_presence_changes(ipmi_domain_t *domain, int force);

/* Should the BMC do a full bus scan at startup?  This is so OEM
   code can turn this function off.  The value is a boolean. */
int ipmi_domain_set_full_bus_scan(ipmi_domain_t *domain, int val);

int ipmi_domain_get_event_rcvr(ipmi_domain_t *domain);

/* Allocate an MC in the domain.  It doesn't add it to the domain's
   list, to allow the MC to be setup before that happens. */
int ipmi_create_mc(ipmi_domain_t *domain,
		   ipmi_addr_t   *addr,
		   unsigned int  addr_len,
		   ipmi_mc_t     **new_mc);

int _ipmi_remove_mc_from_domain(ipmi_domain_t *domain, ipmi_mc_t *mc);

/* Attempt to find the MC, and if it doesn't exist create it and
   return it. */
int _ipmi_find_or_create_mc_by_slave_addr(ipmi_domain_t *domain,
					  unsigned int  channel,
					  unsigned int  slave_addr,
					  ipmi_mc_t     **mc);

/* Find the MC with the given IPMI address, or return NULL if not
   found. */
ipmi_mc_t *_ipmi_find_mc_by_addr(ipmi_domain_t *domain,
				 ipmi_addr_t   *addr,
				 unsigned int  addr_len);

/* Return the SDRs for the given MC, or the main set of SDRs if the MC
   is NULL. */
void _ipmi_get_sdr_sensors(ipmi_domain_t *domain,
			   ipmi_mc_t     *mc,
			   ipmi_sensor_t ***sensors,
			   unsigned int  *count);

/* Set the SDRs for the given MC, or the main set of SDRs if the MC is
   NULL. */
void _ipmi_set_sdr_sensors(ipmi_domain_t *domain,
			   ipmi_mc_t     *mc,
			   ipmi_sensor_t **sensors,
			   unsigned int  count);

/* Returns/set the SDRs entity info for the given MC, or the main set
   of SDRs if the MC is NULL. */
void *_ipmi_get_sdr_entities(ipmi_domain_t *domain,
			     ipmi_mc_t     *mc);
void _ipmi_set_sdr_entities(ipmi_domain_t *domain,
			    ipmi_mc_t     *mc,
			    void          *entities);

/* Add an MC to the list of MCs in the domain. */
int ipmi_add_mc_to_domain(ipmi_domain_t *domain, ipmi_mc_t *mc);

/* Remove an MC from the list of MCs in the domain. */
int ipmi_remove_mc_from_domain(ipmi_domain_t *domain, ipmi_mc_t *mc);

/* Register a handler to be called when an MC is added to the domain
   or removed from the domain. */
typedef void (*ipmi_domain_mc_upd_cb)(enum ipmi_update_e op,
				      ipmi_domain_t      *domain,
				      ipmi_mc_t          *mc,
				      void               *cb_data);
int ipmi_domain_add_mc_updated_handler(ipmi_domain_t         *domain,
				       ipmi_domain_mc_upd_cb handler,
				       void                  *cb_data);
int ipmi_domain_remove_mc_updated_handler(ipmi_domain_t        *domain,
					  ipmi_domain_mc_upd_cb handler,
					  void                  *cb_data);

/* The old interfaces (for backwards compatability).  DON'T USE THESE!! */
struct ipmi_domain_mc_upd_s;
typedef struct ipmi_domain_mc_upd_s ipmi_domain_mc_upd_t
     IPMI_TYPE_DEPRECATED;
int ipmi_domain_register_mc_update_handler(ipmi_domain_t         *domain,
					   ipmi_domain_mc_upd_cb handler,
					   void                  *cb_data,
					   struct ipmi_domain_mc_upd_s  **id)
     IPMI_FUNC_DEPRECATED;
void ipmi_domain_remove_mc_update_handler(ipmi_domain_t        *domain,
					  struct ipmi_domain_mc_upd_s *id)
     IPMI_FUNC_DEPRECATED;

/* Call any OEM handlers for the given MC. */
int _ipmi_domain_check_oem_handlers(ipmi_domain_t *domain, ipmi_mc_t *mc);

/* Scan a set of addresses on the bmc for mcs.  This can be used by OEM
   code to add an MC if it senses that one has become present. */
int ipmi_start_ipmb_mc_scan(ipmi_domain_t  *domain,
			    int            channel,
			    unsigned int   start_addr,
			    unsigned int   end_addr,
			    ipmi_domain_cb done_handler,
			    void           *cb_data);

/* Set a handler that will be called when bus is scanned.  This is 
   primarily here for OpenHPI to meet their requirements */
int ipmi_domain_set_bus_scan_handler(ipmi_domain_t  *domain,
				     ipmi_domain_cb handler,
				     void           *cb_data);

/* Scan a system interface address for an MC. */
void ipmi_start_si_scan(ipmi_domain_t *domain,
			int            si_num,
			ipmi_domain_cb done_handler,
			void           *cb_data);

/* Add an IPMB address to a list of addresses to not scan.  This way,
   if you have weak puny devices in IPMB that will break if you do
   normal IPMB operations, you can have them be ignored. */
int ipmi_domain_add_ipmb_ignore(ipmi_domain_t *domain,
				unsigned char ipmb_addr);
int ipmi_domain_add_ipmb_ignore_range(ipmi_domain_t *domain,
				      unsigned char first_ipmb_addr,
				      unsigned char last_ipmb_addr);

/* If OEM code gets and event and it doesn't deliver it to the user,
   it should deliver it this way, that way it can be delivered to the
   user to be deleted. */
void ipmi_handle_unhandled_event(ipmi_domain_t *domain, ipmi_event_t *event);

/* Handle a new event from something, usually from an SEL. */
void _ipmi_domain_system_event_handler(ipmi_domain_t *domain,
				       ipmi_mc_t     *mc,
				       ipmi_event_t  *event);

/* Returns if the domain thinks it has a connection up. */
int ipmi_domain_con_up(ipmi_domain_t *domain);

/* Iterate through the connections on a domain. */
typedef void (*ipmi_connection_ptr_cb)(ipmi_domain_t *domain, int conn,
				       void *cb_data);
void ipmi_domain_iterate_connections(ipmi_domain_t          *domain,
				     ipmi_connection_ptr_cb handler,
				     void                   *cb_data);

/* Attempt to activate a given connection. */
int ipmi_domain_activate_connection(ipmi_domain_t *domain,
				    unsigned int  connection);

/* Returns if a connection is active. */
int ipmi_domain_is_connection_active(ipmi_domain_t *domain,
				     unsigned int  connection,
				     unsigned int  *active);

/* Returns the main SDR repository for the domain, or NULL if there is
   not one. */
ipmi_sdr_info_t *ipmi_domain_get_main_sdrs(ipmi_domain_t *domain);

/* Get the number of channels the domain supports. */
int ipmi_domain_get_num_channels(ipmi_domain_t *domain, int *val);

/* Get information about a channel by index.  The index is not
   necessarily the channel number, just an array index (up to the
   number of channels).  Get the channel number from the returned
   information. */
int ipmi_domain_get_channel(ipmi_domain_t    *domain,
			    int              index,
			    ipmi_chan_info_t *chan);

/* These calls deal with OEM-type handlers for domains.  Certain
   domains can be detected with special means (beyond just the
   manufacturer and product id) and this allows handlers for these
   types of domains to be registered.  At the very initial connection
   of every domain, the handler will be called and it must detect
   whether this is the specific type of domain or not, do any setup
   for that domain type, and then call the done routine passed in.
   Note that the done routine may be called later, (allowing this
   handler to send messages and the like) but it *must* be called.
   Note that the error value in the check_done routine should be
   ENOSYS if the specific OEM handlers were not applicable, 0 if the
   OEM handlers were installed, and anything else for specific
   errors installing the OEM handlers. */
typedef void (*ipmi_domain_oem_check_done)(ipmi_domain_t *domain,
					   int           err,
					   void          *cb_data);
typedef int (*ipmi_domain_oem_check)(ipmi_domain_t              *domain,
				     ipmi_domain_oem_check_done done,
				     void                       *cb_data);
int ipmi_register_domain_oem_check(ipmi_domain_oem_check check,
				   void                  *cb_data);
int ipmi_deregister_domain_oem_check(ipmi_domain_oem_check check,
				     void                  *cb_data);

/* Register OEM data for the domain.  Note that you can set a function
   that will be called after all the domain messages have been flushed
   but before anything else is destroyed.  If the OEM data or
   destroyer is NULL, it will not be called. */
typedef void (*ipmi_domain_destroy_oem_data_cb)(ipmi_domain_t *domain,
						void          *oem_data);
void ipmi_domain_set_oem_data(ipmi_domain_t                   *domain,
			      void                            *oem_data,
			      ipmi_domain_destroy_oem_data_cb destroyer);
void *ipmi_domain_get_oem_data(ipmi_domain_t *domain);

/* Register a call that will be done at the beginning of the domain
   shutdown process.  Setting it to NULL will disable it. */
typedef void (*ipmi_domain_shutdown_cb)(ipmi_domain_t *domain);
void ipmi_domain_set_oem_shutdown_handler(ipmi_domain_t           *domain,
					  ipmi_domain_shutdown_cb handler);

/* Set the domain type for a domain. */
void ipmi_domain_set_type(ipmi_domain_t *domain, enum ipmi_domain_type dtype);

/* OEM code can call then when it know that an MC scan is complete, to
   speed things up. */
void _ipmi_mc_scan_done(ipmi_domain_t *domain);

/* Can be used to generate unique numbers for a domain. */
unsigned int ipmi_domain_get_unique_num(ipmi_domain_t *domain);

/* Initialize the domain code, called only once at init time. */
int _ipmi_domain_init(void);

/* Clean up the global domain memory. */
void _ipmi_domain_shutdown(void);

/* Option settings. */
int ipmi_option_SDRs(ipmi_domain_t *domain);
int ipmi_option_SEL(ipmi_domain_t *domain);
int ipmi_option_FRUs(ipmi_domain_t *domain);
int ipmi_option_IPMB_scan(ipmi_domain_t *domain);
int ipmi_option_OEM_init(ipmi_domain_t *domain);
int ipmi_option_set_event_rcvr(ipmi_domain_t *domain);

#endif /* _IPMI_DOMAIN_H */
