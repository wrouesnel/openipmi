/*
 * ipmi_lan.h
 *
 * Routines for setting up a connection to an IPMI Lan interface.
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

#ifndef __IPMI_LAN_H
#define __IPMI_LAN_H

#include <OpenIPMI/ipmiif.h>
#include <netinet/in.h>

#define IPMI_LAN_STD_PORT	623

/*
 * Set up an IPMI LAN connection.  The boatload of parameters are:
 *
 *  ip - The IP address of the remote BMC.
 *  port - The UDP port to use, it should generally be IPMI_LAN_STD_PORT
 *  privilege - The privilege level to request for the connection, from
 *     the set of values in ipmi_auth.h.
 *  username - The 16-byte max username to use for the connection.
 *  username_len - The length of username.
 *  password - The 16-byte max password to use for the connection.
 *  password_len - The length of password.
 *  handlers - The set of OS handlers to use for this connection.
 *  user_data - This will be put into the BMC and may be fetched by the
 *     user.  The user can use it for anything they like.
 *  setup_cb - The function to call when the setup of the connection is
 *     complete, or when the connection setup fails.
 *  cb_data - passed to setup_cb when it is called.
 */
int ipmi_lan_setup_con(struct in_addr    ip,
		       int               port,
		       unsigned int      authtype,
		       unsigned int      privilege,
		       void              *username,
		       unsigned int      username_len,
		       void              *password,
		       unsigned int      password_len,
		       os_handler_t      *handlers,
		       void              *user_data,
		       ipmi_setup_done_t setup_cb,
		       void              *cb_data);

#endif /* __IPMI_LAN_H */
