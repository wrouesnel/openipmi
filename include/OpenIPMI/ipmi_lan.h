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

#endif /* __IPMI_LAN_H */
