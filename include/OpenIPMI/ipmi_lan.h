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
#include <OpenIPMI/ipmi_addr.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

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

/* Set the specific cypher suite the user wants to use.  If none is
   specified, this will default to RAKP-HMAC-SHA1, HMAC-SHA1-96,
   AES-CBC-128.  Note that this just sets the algorithm, integrity,
   and confidentiality settings (below this). */
#define IPMI_LANP_CIPHER_SUITE		7
#define IPMI_LANP_CIPHER_SUITE_DEFAULT	(~0)
#define IPMI_LANP_CIPHER_SUITE_RAKP__NONE__NONE				0
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_SHA1__NONE__NONE		1
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_SHA1__HMAC_SHA1_96__NONE	2
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_SHA1__HMAC_SHA1_96__AES_CBC_128 3
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_SHA1__HMAC_SHA1_96__xRC4_128	4
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_SHA1__HMAC_SHA1_96__xRC4_40	5
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_MD5__NONE__NONE		6
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_MD5__HMAC_MD5_128__NONE	7
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_MD5__HMAC_MD5_128__AES_CBC_128	8
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_MD5__HMAC_MD5_128__xRC4_128	9
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_MD5__HMAC_MD5_128__xRC4_40	10
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_MD5__MD5_128__NONE		11
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_MD5__MD5_128__AES_CBC_128	12
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_MD5__MD5_128__xRC4_128		13
#define IPMI_LANP_CIPHER_SUITE_RAKP_HMAC_MD5__MD5_128__xRC4_40		14

/* Allow the specific authentication, integrity, and confidentiality
   algorithms to be specified by the user.  Note that you can specify
   OEM values here.  If you pick the default values, that will let the
   BMC pick the authentication algorithms. */
#define IPMI_LANP_AUTHENTICATION_ALGORITHM	8
#define IPMI_LANP_AUTHENTICATION_ALGORITHM_DEFAULT		(~0)
#define IPMI_LANP_AUTHENTICATION_ALGORITHM_RACKP_NONE		0
#define IPMI_LANP_AUTHENTICATION_ALGORITHM_RACKP_HMAC_SHA1	1
#define IPMI_LANP_AUTHENTICATION_ALGORITHM_RACKP_HMAC_MD5	2
#define IPMI_LANP_INTEGRITY_ALGORITHM		9
#define IPMI_LANP_INTEGRITY_ALGORITHM_DEFAULT			(~0)
#define IPMI_LANP_INTEGRITY_ALGORITHM_NONE			0
#define IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_SHA1_96		1
#define IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_MD5_128		2
#define IPMI_LANP_INTEGRITY_ALGORITHM_MD5_128			3
#define IPMI_LANP_CONFIDENTIALITY_ALGORITHM	10
#define IPMI_LANP_CONFIDENTIALITY_ALGORITHM_DEFAULT		(~0)
#define IPMI_LANP_CONFIDENTIALITY_ALGORITHM_NONE		0
#define IPMI_LANP_CONFIDENTIALITY_ALGORITHM_AES_CBC_128		1
#define IPMI_LANP_CONFIDENTIALITY_ALGORITHM_xRC4_128		2
#define IPMI_LANP_CONFIDENTIALITY_ALGORITHM_xRC4_40		3

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

#define IPMI_RMCPP_PAYLOAD_TYPE_IPMI		0
#define IPMI_RMCPP_PAYLOAD_TYPE_SOL		1
#define IPMI_RMCPP_PAYLOAD_TYPE_OEM_EXPLICIT	2

#define IPMI_RMCPP_PAYLOAD_TYPE_OPEN_SESSION_REQUEST	0x10
#define IPMI_RMCPP_PAYLOAD_TYPE_OPEN_SESSION_RESPONSE	0x11
#define IPMI_RMCPP_PAYLOAD_TYPE_RAKP_1			0x11
#define IPMI_RMCPP_PAYLOAD_TYPE_RAKP_2			0x12
#define IPMI_RMCPP_PAYLOAD_TYPE_RAKP_3			0x13
#define IPMI_RMCPP_PAYLOAD_TYPE_RAKP_4			0x14

typedef struct ipmi_payload_s
{
    /* Format a message for transmit on this payload.  The address and
       message is the one specified by the user.  The out_data is a
       pointer to where to store the output, out_data_len will point
       to the length of the buffer to store the output and should be
       updatated to be the actual length.  The seq is a 6-bit value
       that should be store somewhere so the that response to this
       message can be identified.  If the netfn is odd, the sequence
       number is not used. */
    int (*format_for_xmit)(ipmi_con_t    *conn,
			   ipmi_addr_t   *addr,
			   unsigned int  addr_len,
			   ipmi_msg_t    *msg,
			   unsigned char *out_data,
			   unsigned int  *out_data_len,
			   unsigned char seq);

    /* Get the recv sequence number from the message.  Return ENOSYS
       if the sequence number is not valid for the message (it is
       asynchronous). */
    int (*get_recv_seq)(ipmi_con_t    *conn,
			unsigned char *data,
			unsigned int  data_len,
			unsigned char *seq);

    /* Fill in the rspi data structure from the given data. */
    int (*handle_recv)(ipmi_con_t    *conn,
		       ipmi_msgi_t   *rspi,
		       ipmi_addr_t   *orig_addr,
		       unsigned int  orig_addr_len,
		       ipmi_msg_t    *orig_msg,
		       unsigned char *data,
		       unsigned int  data_len);
} ipmi_payload_t;

typedef struct ipmi_rmcp_confidentiality_s
{
    int (*conf_init)(void **conf_data);
    void (*conf_free)(void *conf_data);

    /* This adds the confidentiality header and trailer.  The payload
       points to a pointer to the payload data itself.  The header
       length points to the number of bytes available before the
       payload.  The payload length points to the length of the
       payload.  The function should add the header and trailer to the
       payload, update the payload to point to the start of the
       header, update the header length to remove the data it used for
       its header, and update the payload length for any trailer used.
       It should not exceed the max_payload_len for the trailer nor
       should header_len go negative. */
    int (*conf_add)(void          *conf_data,
		    unsigned char **payload,
		    unsigned int  *header_len,
		    unsigned int  *payload_len,
		    unsigned int  max_payload_len);


    /* Decrypt the given data (in place).  The payload starts at
       beginning of the confidentiality header and the payload length
       includes the confidentiality trailer.  This function should
       update the payload to remove the header and the payload_len to
       remove any headers and trailers, including all padding. */
    int (*conf_check)(void          *conf_data,
		      unsigned char **payload,
		      unsigned int  *payload_len);

} ipmi_rmcp_confidentiality_t;

typedef struct ipmi_rmcp_integrity_s
{
    int (*integ_init)(void **integ_data);
    void (*integ_free)(void *integ_data);

    /* This adds the integrity trailer after the payload data.  It
       should add any padding after the payload and update the payload
       length.  It should set the trailer length to the amount of data
       it used (after the payload and padding).  The payload_len plus
       the trailer_len should not exceed max_payload_len.  The payload
       starts at beginning of the user message (the RMCP version). */
    int (*integ_add)(void          *integ_data,
		     unsigned char *payload,
		     unsigned int  *payload_len,
		     unsigned int  *trailer_len,
		     unsigned int  max_payload_len);

    /* Verify the integrity of the given data.  The payload starts at
       beginning of the user message (the RMCP version).  The payload
       length is the length including any integrity padding but not
       the next header or authcode data. The total length includes all
       the data, including the autocode data. */
    int (*integ_check)(void          *integ_data,
		       unsigned char *payload,
		       unsigned int  payload_len,
		       unsigned int  total_len);

} ipmi_rmcp_integrity_t;

#ifdef __cplusplus
}
#endif

#endif /* __IPMI_LAN_H */
