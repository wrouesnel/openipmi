/*
 * ipmi_conn.h
 *
 * MontaVista IPMI interface, definition for a low-level connection (like a
 * LAN interface, or system management interface, etc.).
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

#ifndef _IPMI_CONN_H
#define _IPMI_CONN_H

#include <OpenIPMI/ipmi_types.h>
#include <OpenIPMI/ipmi_addr.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/os_handler.h>

/* This represents a low-level connection. */
typedef struct ipmi_con_s ipmi_con_t;

/* This represents a registration for an event handler. */
typedef struct ipmi_ll_event_handler_id_s ipmi_ll_event_handler_id_t;

/* Called when an IPMI response to a command comes in from the BMC. */
typedef void (*ipmi_ll_rsp_handler_t)(ipmi_con_t   *ipmi,
				      ipmi_addr_t  *addr,
				      unsigned int addr_len,
				      ipmi_msg_t   *msg,
				      void         *rsp_data,
				      void         *data2,
				      void         *data3);

/* Called when an IPMI event comes in from the BMC. */
typedef void (*ipmi_ll_evt_handler_t)(ipmi_con_t   *ipmi,
				      ipmi_addr_t  *addr,
				      unsigned int addr_len,
				      ipmi_msg_t   *event,
				      void         *event_data,
				      void         *data2);

/* Called when an incoming command is received by the IPMI code. */
typedef void (*ipmi_ll_cmd_handler_t)(ipmi_con_t   *ipmi,
				      ipmi_addr_t  *addr,
				      unsigned int addr_len,
				      ipmi_msg_t   *cmd,
				      long         sequence,
				      void         *cmd_data,
				      void         *data2,
				      void         *data3);

/* Called when a low-level connection has failed or come up.  If err
   is zero, the connection has come up after being failed.  if err is
   non-zero, it's an error number to report why the failure
   occurred. */
typedef void (*ipmi_ll_con_failed_cb)(ipmi_con_t *ipmi,
				      int        err,
				      void       *cb_data);

/* The data structure representing a connection.  The low-level handler
   fills this out then calls ipmi_init_con() with the connection. */
struct ipmi_con_s
{
    /* The low-level handler should provide one of these for doing os-type
       things (locks, random numbers, etc. */
    os_handler_t *os_hnd;

    /* This data can be fetched by the user and used for anything they
       like. */
    void *user_data;

    /* This is called by the IPMI code when it finishes setting up a
       connections, fetching SDRs, detecting sensors, etc. */
    ipmi_setup_done_t setup_cb;
    void              *setup_cb_data;

    /* Connection-specific data for the underlying connection. */
    void *con_data;

    /* Calls for the interface.  These should all return standard
       "errno" errors if they fail. */

    /* Set the callback to call when the connection goes down or up.
       There is only one of these handlers, changing it overwrites it.
       Setting it to NULL disables it. */
    void (*set_con_fail_handler)(ipmi_con_t            *ipmi,
				 ipmi_ll_con_failed_cb handler,
				 void                  *cb_data);

    /* Send an IPMI command (in "msg".  on the "ipmi" connection to
       the given "addr".  When the response comes in or the message
       times out, rsp_handler will be called with the following three
       data items.  Note that the lower layer MUST guarantee that the
       reponse handler is called, even if it fails or the message is
       dropped. */
    int (*send_command)(ipmi_con_t            *ipmi,
			ipmi_addr_t           *addr,
			unsigned int          addr_len,
			ipmi_msg_t            *msg,
			ipmi_ll_rsp_handler_t rsp_handler,
			void                  *rsp_data,
			void                  *data2,
			void                  *data3);

    /* Register to receive IPMI events from the interface.  Return a
       handle that can be used for later deregistration. */
    int (*register_for_events)(ipmi_con_t                 *ipmi,
			       ipmi_ll_evt_handler_t      handler,
			       void                       *event_data,
			       void                       *data2,
			       ipmi_ll_event_handler_id_t **id);

    /* Remove an event registration. */
    int (*deregister_for_events)(ipmi_con_t                 *ipmi,
				 ipmi_ll_event_handler_id_t *id);

    /* Send a response message.  This is not supported on all
       interfaces, primarily only on system management interfaces.  If
       not supported, this should return ENOSYS. */
    int (*send_response)(ipmi_con_t   *ipmi,
			 ipmi_addr_t  *addr,
			 unsigned int addr_len,
			 ipmi_msg_t   *msg,
			 long         sequence);

    /* Register to receive incoming commands.  This is not supported
       on all interfaces, primarily only on system management
       interfaces.  If not supported, this should return ENOSYS. */
    int (*register_for_command)(ipmi_con_t            *ipmi,
				unsigned char         netfn,
				unsigned char         cmd,
				ipmi_ll_cmd_handler_t handler,
				void                  *cmd_data,
				void                  *data2,
				void                  *data3);

    /* Deregister a command registration.  This is not supported on
       all interfaces, primarily only on system management interfaces.
       If not supported, this should return ENOSYS. */
    int (*deregister_for_command)(ipmi_con_t    *ipmi,
				  unsigned char netfn,
				  unsigned char cmd);

    /* Close an IPMI connection. */
    int (*close_connection)(ipmi_con_t *ipmi);
};

/* This should be called by the low-level connection code once it has
   a working channel up to the BMC.  This will continue the
   registration process.  Make sure to pass in the IPMB address of the
   BMC as my_slave_addr. */
int ipmi_init_con(ipmi_con_t   *con,
		  ipmi_addr_t  *mc_addr,
		  int          mc_addr_len,
		  unsigned int my_slave_addr);

/* Different types of low-level handlers must register themselves with
   the IPMI code.  This is currently used so the IPMI code can validate
   that a connection is a good working connection. */
typedef struct ll_ipmi_s
{
    /* Validate that the given connection is a good connection. */
    int (*valid_ipmi)(ipmi_con_t *ipmi);

    /* Stuff below here is used internally by the IPMI code.  Set the
       values to zero or NULL. */
    volatile int registered;
    struct ll_ipmi_s *next;
} ll_ipmi_t;
void ipmi_register_ll(ll_ipmi_t *ll);

/* Called by the IPMI code in various places to validate a connection. */
int __ipmi_validate(ipmi_con_t *ipmi);

#endif /* _IPMI_CONN_H */
