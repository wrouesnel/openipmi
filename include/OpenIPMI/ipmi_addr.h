/*
 * ipmi_addr.h
 *
 * Addressing information for IPMI interfaces.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at your
 *  option) any later version.
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __IPMI_ADDR_H
#define __IPMI_ADDR_H

/* To get a socket. */
#include <netinet/in.h>

/* The formats of these MUST match the formats for the kernel. */

#ifndef __LINUX_IPMI_H /* Don't include this if we are including the kernel */

/* This is an overlay for all the address types, so it's easy to
   determine the actual address type.  This is kind of like addresses
   work for sockets. */
#define IPMI_MAX_ADDR_SIZE 32
typedef struct ipmi_addr
{
	 /* Try to take these from the "Channel Medium Type" table
	    in section 6.5 of the IPMI 1.5 manual. */
	int   addr_type;
	short channel;
	char  data[IPMI_MAX_ADDR_SIZE];
} ipmi_addr_t;

/* When the address is not used, the type will be set to this value.
   The channel is the BMC's channel number for the channel (usually
   0), or IPMC_BMC_CHANNEL if communicating directly with the BMC. */
#define IPMI_SYSTEM_INTERFACE_ADDR_TYPE	0xc
typedef struct ipmi_system_interface_addr
{
	int           addr_type;
	short         channel;
	unsigned char lun;
} ipmi_system_interface_addr_t;

/* An IPMB Address. */
#define IPMI_IPMB_ADDR_TYPE	1
/* Used for broadcast get device id as described in section 17.9 of the
   IPMI 1.5 manual. */
#define IPMI_IPMB_BROADCAST_ADDR_TYPE   0x41
typedef struct ipmi_ipmb_addr
{
	int           addr_type;
	short         channel;
	unsigned char slave_addr;
	unsigned char lun;
} ipmi_ipmb_addr_t;

/* Channel for talking directly with the BMC.  When using this
   channel, This is for the system interface address type only.
   FIXME - is this right, or should we use -1? */
#define IPMI_BMC_CHANNEL  0xf
#define IPMI_NUM_CHANNELS 0x10

#else /* _LINUX_IPMI_H */

/* Generate types for the kernel versions of these. */
typedef struct ipmi_addr ipmi_addr_t;
typedef struct ipmi_system_interface_addr ipmi_system_interface_addr_t;
typedef struct ipmi_ipmb_addr ipmi_ipmb_addr_t;

#endif /* _LINUX_IPMI_H */

/* An 802.3 LAN address */
#define IPMI_802_3_ADDR_TYPE 4
typedef struct ipmi_802_3_addr_s
{
	int            addr_type;
	short          channel;
	struct in_addr addr;
	unsigned short port;
} ipmi_802_3_addr_t;

/* Compare two IPMI addresses, and return false if they are equal and
   true if they are not. */
int ipmi_addr_equal(ipmi_addr_t *addr1,
		    int         addr1_len,
		    ipmi_addr_t *addr2,
		    int         addr2_len);
unsigned int ipmi_addr_get_lun(ipmi_addr_t *addr);
int ipmi_addr_set_lun(ipmi_addr_t *addr, unsigned int lun);

/* Get the slsave address from the address, returns 0 if the address
   does not have a slave address. */
unsigned int ipmi_addr_get_slave_addr(ipmi_addr_t *addr);

#endif /* __IPMI_ADDR_H */
