/*
 * ipmi_lanparm.h
 *
 * Routines for setting up a connection to an IPMI LAN interface.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2004 MontaVista Software Inc.
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

#ifndef _IPMI_LANPARM_H
#define _IPMI_LANPARM_H

#include <OpenIPMI/ipmi_types.h>

/* The abstract type for lanparm. */
typedef struct ipmi_lanparm_s ipmi_lanparm_t;


/* Generic callback used to tell when a LANPARM operation is done. */
typedef void (*ipmi_lanparm_done_cb)(ipmi_lanparm_t *lanparm,
				     int            err,
				     void           *cb_data);

/* Allocate a LANPARM. */
int ipmi_lanparm_alloc(ipmi_mc_t      *mc,
		       unsigned int   channel,
		       ipmi_lanparm_t **new_lanparm);

/* Destroy a LANPARM. */
int ipmi_lanparm_destroy(ipmi_lanparm_t       *lanparm,
			 ipmi_lanparm_done_cb handler,
			 void                 *cb_data);

/* Fetch a parameter value from the LANPARM.  The "set" and "block"
   parameters are the set selector and block selectors.  If those are
   not relevant for the given parm, then set them to zero.  Note that
   on the return data, the first byte (byte 0) is the revision number,
   the data starts in the second byte. */
typedef void (*ipmi_lanparm_get_cb)(ipmi_lanparm_t    *lanparm,
				    int               err,
				    unsigned char     *data,
				    unsigned int      data_len,
				    void              *cb_data);
int ipmi_lanparm_get_parm(ipmi_lanparm_t      *lanparm,
			  unsigned int        parm,
			  unsigned int        set,
			  unsigned int        block,
			  ipmi_lanparm_get_cb done,
			  void                *cb_data);

/* Set the parameter value in the LANPARM to the given data. */
int ipmi_lanparm_set_parm(ipmi_lanparm_t       *lanparm,
			  unsigned int         parm,
			  unsigned char        *data,
			  unsigned int         data_len,
			  ipmi_lanparm_done_cb done,
			  void                 *cb_data);

/* The various LAN config parms. */
#define IPMI_LANPARM_SET_IN_PROGRESS		0
#define IPMI_LANPARM_AUTH_TYPE_SUPPORT		1
#define IPMI_LANPARM_AUTH_TYPE_ENABLES		2
#define IPMI_LANPARM_IP_ADDRESS			3
#define IPMI_LANPARM_IP_ADDRESS_SRC		4
#define IPMI_LANPARM_MAX_ADDRESS		5
#define IPMI_LANPARM_SUBNET_MASK		6
#define IPMI_LANPARM_IPV4_HDR_PARMS		7
#define IPMI_LANPARM_PRIMARY_RMCP_PORT		8
#define IPMI_LANPARM_SECONDARY_RMCP_PORT	9
#define IPMI_LANPARM_BMC_GENERATED_ARP_CNTL	10
#define IPMI_LANPARM_GRATUIDOUS_ARP_INTERVAL	11
#define IPMI_LANPARM_DEFAULT_GATEWAY_ADDR	12
#define IPMI_LANPARM_DEFAULT_GATEWAY_MAC_ADDR	13
#define IPMI_LANPARM_BACKUP_GATEWAY_ADDR	14
#define IPMI_LANPARM_BACKUP_GATEWAY_MAC_ADDR	15
#define IPMI_LANPARM_COMMUNITY_STRING		16
#define IPMI_LANPARM_NUM_DESTINATIONS		17
#define IPMI_LANPARM_DEST_TYPE			18
#define IPMI_LANPARM_DEST_ADDR			19

/* A full LAN configuration.  Note that you cannot allocate one of
   these, you can only fetch them, modify them, set them, and free
   them. */
typedef struct ipmi_lan_config_s ipmi_lan_config_t;

/* Get the full LAN configuration.  Note that the config in the
   callback *must* be freed by you. */
typedef void (*ipmi_lan_get_config_cb)(ipmi_lanparm_t    *lanparm,
				       int               err,
				       ipmi_lan_config_t *config,
				       void              *cb_data);
int ipmi_lan_get_config(ipmi_lanparm_t         *lanparm,
			ipmi_lan_get_config_cb done,
			void                   *cb_data);

/* Set the full LAN configuration.  Note that the config is copied, so
   you are free to do whatever you like with your config after you
   call this. */
int ipmi_lan_set_config(ipmi_lanparm_t       *lanparm,
			ipmi_lan_config_t    *config,
			ipmi_lanparm_done_cb done,
			void                 *cb_data);

/* Free a LAN config. */
void ipmi_lan_free_config(ipmi_lan_config_t *config);

/*
 * Boatloads of data from the LAN config.  Note that all IP addresses,
 * ports, etc. are in network order.
 */

/* The first set of parameters here must be present, so they are
   returned directly, no errors for getting.  Setting returns an
   error. */

/* Supported authentication types. This is read-only. */
unsigned int ipmi_lanconfig_get_support_auth_oem(ipmi_lan_config_t *lanc);
unsigned int ipmi_lanconfig_get_support_auth_straight(ipmi_lan_config_t *lanc);
unsigned int ipmi_lanconfig_get_support_auth_md5(ipmi_lan_config_t *lanc);
unsigned int ipmi_lanconfig_get_support_auth_md2(ipmi_lan_config_t *lanc);
unsigned int ipmi_lanconfig_get_support_auth_none(ipmi_lan_config_t *lanc);

/* Various IP-related information. */
unsigned int ipmi_lanconfig_get_ip_addr_source(ipmi_lan_config_t *lanc);
int ipmi_lanconfig_set_ip_addr_source(ipmi_lan_config_t *lanc,
				      unsigned int      val);

/* Number of allowed alert destinations.  This is read-only. */
unsigned int ipmi_lanconfig_get_num_alert_destinations(ipmi_lan_config_t *c);


/* Everything else below returns an error. */
int ipmi_lanconfig_get_ipv4_ttl(ipmi_lan_config_t *lanc,
				unsigned int      *val);
int ipmi_lanconfig_set_ipv4_ttl(ipmi_lan_config_t *lanc,
				unsigned int      val);
int ipmi_lanconfig_get_ipv4_flags(ipmi_lan_config_t *lanc,
				  unsigned int      *val);
int ipmi_lanconfig_set_ipv4_flags(ipmi_lan_config_t *lanc,
				  unsigned int      val);
int ipmi_lanconfig_get_ipv4_precedence(ipmi_lan_config_t *lanc,
				       unsigned int      *val);
int ipmi_lanconfig_set_ipv4_precedence(ipmi_lan_config_t *lanc,
				       unsigned int      val);
int ipmi_lanconfig_get_ipv4_tos(ipmi_lan_config_t *lanc,
				unsigned int      *val);
int ipmi_lanconfig_set_ipv4_tos(ipmi_lan_config_t *lanc,
				unsigned int      val);

/* Authorization enables for the various authentication levels. */
int ipmi_lanconfig_get_enable_auth_oem(ipmi_lan_config_t *lanc,
				       unsigned int      auth,
				       unsigned int      *val);
int ipmi_lanconfig_get_enable_auth_straight(ipmi_lan_config_t *lanc,
					    unsigned int      auth,
					    unsigned int      *val);
int ipmi_lanconfig_get_enable_auth_md5(ipmi_lan_config_t *lanc,
				       unsigned int      auth,
				       unsigned int      *val);
int ipmi_lanconfig_get_enable_auth_md2(ipmi_lan_config_t *lanc,
				       unsigned int      auth,
				       unsigned int      *val);
int ipmi_lanconfig_get_enable_auth_none(ipmi_lan_config_t *lanc,
					unsigned int      auth,
					unsigned int      *val);
int ipmi_lanconfig_set_enable_auth_oem(ipmi_lan_config_t *lanc,
				       unsigned int      auth,
				       unsigned int      val);
int ipmi_lanconfig_set_enable_auth_straight(ipmi_lan_config_t *lanc,
					    unsigned int      auth,
					    unsigned int      val);
int ipmi_lanconfig_set_enable_auth_md5(ipmi_lan_config_t *lanc,
				       unsigned int      auth,
				       unsigned int      val);
int ipmi_lanconfig_set_enable_auth_md2(ipmi_lan_config_t *lanc,
				       unsigned int      auth,
				       unsigned int      val);
int ipmi_lanconfig_set_enable_auth_none(ipmi_lan_config_t *lanc,
					unsigned int      auth,
					unsigned int      val);

/* Addressing for the BMC. */
int ipmi_lanconfig_get_ip_addr(ipmi_lan_config_t *lanc,
			       unsigned char     *data,
			       unsigned int      *data_len);
int ipmi_lanconfig_set_ip_addr(ipmi_lan_config_t *lanc,
			       unsigned char     *data,
			       unsigned int      data_len);

int ipmi_lanconfig_get_mac_addr(ipmi_lan_config_t *lanc,
				unsigned char     *data,
				unsigned int      *data_len);
int ipmi_lanconfig_set_mac_addr(ipmi_lan_config_t *lanc,
				unsigned char     *data,
				unsigned int      data_len);

int ipmi_lanconfig_get_subnet_mask(ipmi_lan_config_t *lanc,
				   unsigned char     *data,
				   unsigned int      *data_len);
int ipmi_lanconfig_set_subnet_mask(ipmi_lan_config_t *lanc,
				   unsigned char     *data,
				   unsigned int      data_len);

int ipmi_lanconfig_get_primary_rmcp_port(ipmi_lan_config_t *lanc,
					 unsigned char     *data,
					 unsigned int      *data_len);
int ipmi_lanconfig_set_primary_rmcp_port(ipmi_lan_config_t *lanc,
					 unsigned char     *data,
					 unsigned int      data_len);
int ipmi_lanconfig_get_secondary_rmcp_port(ipmi_lan_config_t *lanc,
					   unsigned char     *data,
					   unsigned int      *data_len);
int ipmi_lanconfig_set_secondary_rmcp_port(ipmi_lan_config_t *lanc,
					   unsigned char     *data,
					   unsigned int      data_len);

/* Control of ARP-ing.  These are optional and so may return errors. */
int ipmi_lanconfig_get_bmc_generated_arps(ipmi_lan_config_t *lanc,
					  unsigned int      *val);
int ipmi_lanconfig_set_bmc_generated_arps(ipmi_lan_config_t *lanc,
					  unsigned int      val);
int ipmi_lanconfig_get_bmc_generated_garps(ipmi_lan_config_t *lanc,
					   unsigned int      *val);
int ipmi_lanconfig_set_bmc_generated_garps(ipmi_lan_config_t *lanc,
					   unsigned int      val);
int ipmi_lanconfig_get_garp_interval(ipmi_lan_config_t *lanc,
				     unsigned int      *val);
int ipmi_lanconfig_set_garp_interval(ipmi_lan_config_t *lanc,
				     unsigned int      val);

/* Gateway handling */
int ipmi_lanconfig_get_default_gateway_ip_addr(ipmi_lan_config_t *lanc,
					       unsigned char     *data,
					       unsigned int      *data_len);
int ipmi_lanconfig_set_default_gateway_ip_addr(ipmi_lan_config_t *lanc,
					       unsigned char     *data,
					       unsigned int      data_len);
int ipmi_lanconfig_get_default_gateway_mac_addr(ipmi_lan_config_t *lanc,
						unsigned char     *data,
						unsigned int      *data_len);
int ipmi_lanconfig_set_default_gateway_mac_addr(ipmi_lan_config_t *lanc,
						unsigned char     *data,
						unsigned int      data_len);
int ipmi_lanconfig_get_backup_gateway_ip_addr(ipmi_lan_config_t *lanc,
					      unsigned char     *data,
					      unsigned int      *data_len);
int ipmi_lanconfig_set_backup_gateway_ip_addr(ipmi_lan_config_t *lanc,
					      unsigned char     *data,
					      unsigned int      data_len);
int ipmi_lanconfig_get_backup_gateway_mac_addr(ipmi_lan_config_t *lanc,
					       unsigned char     *data,
					       unsigned int      *data_len);
int ipmi_lanconfig_set_backup_gateway_mac_addr(ipmi_lan_config_t *lanc,
					       unsigned char     *data,
					       unsigned int      data_len);

/* The community string for SNMP traps sent. */
int ipmi_lanconfig_get_community_string(ipmi_lan_config_t *lanc,
					unsigned char     *data,
					unsigned int      *data_len);
int ipmi_lanconfig_set_community_string(ipmi_lan_config_t *lanc,
					unsigned char     *data,
					unsigned int      data_len);

/* Everthing else is part of the LAN Alert destination table and is
   addressed on a per-destination basis. */
int ipmi_lanconfig_get_alert_ack(ipmi_lan_config_t *lanc,
				 unsigned int      dest,
				 unsigned int      *val);
int ipmi_lanconfig_set_alert_ack(ipmi_lan_config_t *lanc,
				 unsigned int      dest,
				 unsigned int      val);
int ipmi_lanconfig_get_dest_type(ipmi_lan_config_t *lanc,
				 unsigned int      dest,
				 unsigned int      *val);
int ipmi_lanconfig_set_dest_type(ipmi_lan_config_t *lanc,
				 unsigned int      dest,
				 unsigned int      val);
int ipmi_lanconfig_get_alert_retry_interval(ipmi_lan_config_t *lanc,
					    unsigned int      dest,
					    unsigned int      *val);
int ipmi_lanconfig_set_alert_retry_interval(ipmi_lan_config_t *lanc,
					    unsigned int      dest,
					    unsigned int      val);
int ipmi_lanconfig_get_max_alert_retries(ipmi_lan_config_t *lanc,
					 unsigned int      dest,
					 unsigned int      *val);
int ipmi_lanconfig_set_max_alert_retries(ipmi_lan_config_t *lanc,
					 unsigned int      dest,
					 unsigned int      val);
int ipmi_lanconfig_get_dest_format(ipmi_lan_config_t *lanc,
				   unsigned int      dest,
				   unsigned int      *val);
int ipmi_lanconfig_set_dest_format(ipmi_lan_config_t *lanc,
				   unsigned int      dest,
				   unsigned int      val);
int ipmi_lanconfig_get_gw_to_use(ipmi_lan_config_t *lanc,
				 unsigned int      dest,
				 unsigned int      *val);
int ipmi_lanconfig_set_gw_to_use(ipmi_lan_config_t *lanc,
				 unsigned int      dest,
				 unsigned int      val);
int ipmi_lanconfig_get_dest_ip_addr(ipmi_lan_config_t *lanc,
				    unsigned int      dest,
				    unsigned char     *data,
				    unsigned int      *data_len);
int ipmi_lanconfig_set_dest_ip_addr(ipmi_lan_config_t *lanc,
				    unsigned int      dest,
				    unsigned char     *data,
				    unsigned int      data_len);
int ipmi_lanconfig_get_dest_mac_addr(ipmi_lan_config_t *lanc,
				     unsigned int      dest,
				     unsigned char     *data,
				     unsigned int      *data_len);
int ipmi_lanconfig_set_dest_mac_addr(ipmi_lan_config_t *lanc,
				     unsigned int      dest,
				     unsigned char     *data,
				     unsigned int      data_len);

#endif /* _IPMI_LANPARM_H */
