/*
 * mxp_ipmi.h
 *
 * Interfaces to the MXP OEM code.
 *
 * (C) 2003 MontaVista Software, Inc.  All right reserved.
 *
 * This program is licensed under the MontaVista Software,
 * Inc. License Agreement ("License Agreement"), and is for the
 * purposes of the License Agreement a MontaVista Licensed Deployment
 * Program.  The License requires that you have a valid Product
 * Subscription with MontaVista Software, Inc., or are a Named Contact
 * with active access to the MontaVista Zone, or have a Software
 * License Agreement with MontaVista Software, Inc. This program comes
 * with no warranties other than those provided for in the Product
 * Subscription agreement. The License Agreement grants you the right
 * to install, modify and use the program.  You may distribute the
 * object code and scripts for this program, but you have no right to
 * distribute the source code for this program.
 */

#ifndef _MXP_IPMI_H
#define _MXP_IPMI_H

/* Set up a connection to an MXP.  addrs is the list of IP addresses
   for the AMC (one or two), num_addrs is the number of addresses
   provided.  Note that the addresses MUST be different.  You MUST
   supply a unique swid (Software Id), all other software that talks
   to this MXP must have a different swid.  fail_con_cb is called with
   cb_data when a connection goes down. */
#include <OpenIPMI/ipmiif.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IPMI_MXP_STD_PORT	623

/*
 * Set up an IPMI LAN connection to a Motorola MXP chassis.  Note that the
 * parameters are exactly the same as a standard IPMI LAN connection.  Talking
 * directly to the AMC works just like normal IPMI LAN.  Talking on the IPMB
 * bus is completely different than normal IPMI, though, so you must use this
 * interface when using the MXP.
 *
 * The boatload of parameters are:
 *
 *  ip_addrs - The IP addresses of the remote BMC.  You may list
 *     multiple IP addresses in an array, each address *must* be to the
 *     same BMC.
 *  ports - The UDP ports to use, one for each address.  It should
 *     generally be IPMI_LAN_STD_PORT.
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
int mxp_lan_setup_con(struct in_addr            *ip_addrs,
		      int                       *ports,
		      unsigned int              num_ip_addrs,
		      unsigned int              authtype,
		      unsigned int              privilege,
		      void                      *username,
		      unsigned int              username_len,
		      void                      *password,
		      unsigned int              password_len,
		      os_handler_t              *handlers,
		      void                      *user_data,
		      unsigned char             swid,
		      ipmi_con_t                **new_con);

#ifdef __cplusplus
}
#endif

#endif /* _MXP_IPMI_H */
