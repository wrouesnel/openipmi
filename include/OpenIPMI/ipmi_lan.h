/*
 * ipmi_lan.h
 *
 * Routines for setting up a connection to an IPMI Lan interface.
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

#ifndef __IPMI_LAN_H
#define __IPMI_LAN_H

#include <OpenIPMI/ipmiif.h>
#include <netinet/in.h>

#define IPMI_LAN_STD_PORT	623

/*
 * Yet another interface to set up a LAN connection.  This is the
 * most flexible, and hopefully will be the last one.  This one is
 * flexible enough to handle RMCP+ connections and will also handle
 * normal LAN connections.  The parameters are:
 *
 *  ip_addrs - The IP addresses of the remote BMC.  You may list
 *     multiple IP addresses in an array, each address *must* be to the
 *     same BMC.  This is an array of string pointers to the string
 *     representations of the IP addresses, you can pass in names or
 *     dot notation.  It takes IPV4 and IPV6 addresses.
 *  ports - The UDP ports to use, one for each address.  It should
 *     generally be IPMI_LAN_STD_PORT.  This is an array of string
 *     pointers to string representations of the port.  You can pass
 *     in names or numeric values.
 *  num_ip_addrs - The number of ip addresses (and thus ports) in the
 *     arrays above.
 *  parms - An array of items used to configure the connection.
 *     See the individual parms for details.  This may be NULL if
 *     num_parms is zero.
 *  num_parms - The number of parms in the parms array.
 *  handlers - The set of OS handlers to use for this connection.
 *  user_data - This will be put into the BMC and may be fetched by the
 *     user.  The user can use it for anything they like.
 *  new_con - The new connection is returned here.
 */
typedef struct ipmi_lanp_parm_s
{
    int          parm_id;
    int          parm_val;
    void         *parm_data;
    unsigned int parm_data_len;
} ipmi_lanp_parm_t;
int ipmi_lanp_setup_con(ipmi_lanp_parm_t *parms,
			unsigned int     num_parms,
			os_handler_t     *handlers,
			void             *user_data,
			ipmi_con_t       **new_con);

/* Set the authorization type for a connection.  If not specified,
   this will default to the best available one.  The type is in the
   parm_val, the parm_data is not used. */
#define IPMI_LANP_PARMID_AUTHTYPE	1

/* Set the privilege level requested for a connection.  If not
   specified, this will default to admin.  The type is in the
   parm_val, the parm_data is not used. */
#define IPMI_LANP_PARMID_PRIVILEGE	2

/* Set the password for the connection.  If not specified, a NULL
   password will be used.  The password is in the parm_data, the
   parm_val is not used. */
#define IPMI_LANP_PARMID_PASSWORD	3

/* Set the password for the connection.  If not specified, User 1 (the
   default user) will be used.  The name is in the parm_data, the
   parm_val is not used. */
#define IPMI_LANP_PARMID_USERNAME	4

/* Set the addresses used for the connection.  This should be supplied
   as an array of pointers to characters in the parm_data value.  The
   parm_val is not used.  To use this, have something like:
     char *ips[2];
     ips[0] = ...;
     ips[1] = ...;
     parms[i].parm_id = IPMI_LANP_PARMID_ADDRS;
     parms[i].parm_data = ips;
     parms[i].parm_data_len = 2;
   Note that the parm_data_len is the number of elements in the array
   of addresses, not the size of the array.  This parameter must be
   specified. */
#define IPMI_LANP_PARMID_ADDRS		5

/* Set the ports used for the connection.  This should be supplied
   as an array of pointers to characters in the parm_data value.  The
   parm_val is not used.  To use this, have something like:
     char *ips[2];
     ips[0] = ...;
     ips[1] = ...;
     parms[i].parm_id = IPMI_LANP_PARMID_ADDRS;
     parms[i].parm_data = ips;
     parms[i].parm_data_len = 2;
   Note that the parm_data_len is the number of elements in the array
   of addresses, not the size of the array.  If not specified, this
   defaults to IPMI_LAN_STD_PORT for every address.  Note that the length
   of this must match the length of the number of addresses. */
#define IPMI_LANP_PARMID_PORTS		6


/*
 * Set up an IPMI LAN connection.  The boatload of parameters are:
 *
 *  ip_addrs - The IP addresses of the remote BMC.  You may list
 *     multiple IP addresses in an array, each address *must* be to the
 *     same BMC.  This is an array of string pointers to the string
 *     representations of the IP addresses, you can pass in names or
 *     dot notation.  It takes IPV4 and IPV6 addresses.
 *  ports - The UDP ports to use, one for each address.  It should
 *     generally be IPMI_LAN_STD_PORT.  This is an array of string
 *     pointers to string representations of the port.  You can pass
 *     in names or numeric values.
 *  num_ip_addrs - The number of ip addresses (and thus ports) in the
 *     arrays above.
 *  authtype - The authentication type to use, from ipmi_auth.h
 *  privilege - The privilege level to request for the connection, from
 *     the set of values in ipmi_auth.h.
 *  username - The 16-byte max username to use for the connection.
 *  username_len - The length of username.
 *  password - The 16-byte max password to use for the connection.
 *  password_len - The length of password.
 *  handlers - The set of OS handlers to use for this connection.
 *  user_data - This will be put into the BMC and may be fetched by the
 *     user.  The user can use it for anything they like.
 *  new_con - The new connection is returned here.
 */
int ipmi_ip_setup_con(char         * const ip_addrs[],
		      char         * const ports[],
		      unsigned int num_ip_addrs,
		      unsigned int authtype,
		      unsigned int privilege,
		      void         *username,
		      unsigned int username_len,
		      void         *password,
		      unsigned int password_len,
		      os_handler_t *handlers,
		      void         *user_data,
		      ipmi_con_t   **new_con);

/* This is the old version of the above call, it only works on IPv4
   addresses.  Its use is deprecated. */
int ipmi_lan_setup_con(struct in_addr *ip_addrs,
		       int            *ports,
		       unsigned int   num_ip_addrs,
		       unsigned int   authtype,
		       unsigned int   privilege,
		       void           *username,
		       unsigned int   username_len,
		       void           *password,
		       unsigned int   password_len,
		       os_handler_t   *handlers,
		       void           *user_data,
		       ipmi_con_t     **new_con);

/* Used to handle SNMP traps.  If the msg is NULL, that means that the
   trap sender didn't send enough information to handle the trap
   immediately, and the SEL needs to be scanned. */
int ipmi_lan_handle_external_event(struct sockaddr *src_addr,
				   ipmi_msg_t      *msg,
				   unsigned char   *pet_ack);

#endif /* __IPMI_LAN_H */
