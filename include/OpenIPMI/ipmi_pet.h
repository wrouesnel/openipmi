/*
 * ipmi_pet.h
 *
 * MontaVista IPMI interface for setting up and handling platform event
 * traps.
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

#ifndef _IPMI_PET_H
#define _IPMI_PET_H

#include <OpenIPMI/ipmi_types.h>

typedef struct ipmi_pet_s ipmi_pet_t;

typedef void (*ipmi_pet_done_cb)(ipmi_pet_t *pet, int err, void *cb_data);

/* Create and configure a Platform Event Trap handler for the given
 * domain.  Parameters are: 
 *
 *  ip_addr - The IP address to tell the PET to send messages to, if
 *      applicable for this domain.
 *  mac_addr - The MAC address to tell the PET to send messages to,
 *      if applicable for this domain.
 *  eft_sel - the Event Filter selector to use for this PET destination.
 *      Note that this does *not* need to be unique for different OpenIPMI
 *      instances that are using the same channel, since the configuration
 *      will be exactly the same for all EFT entries using the same
 *      channel.
 *  apt_sel - The Alert Policy selector to use for this PET destination.
 *      Note that as eft_sel, this does not need to be unique for different
 *      OpenIPMI instances on the same channel.
 *  lan_dest_sel - The LAN configuration destination selector for this PET
 *      destination.  Unlike eft_sel and apt_sel, this *must* be unique
 *      for each OpenIPMI instance on the same channel.
 *
 * Creating one of these in a domain will cause event traps to be received
 * and handled as standard events in OpenIPMI.
 *
 * Note that this uses the standard SNMP trap port (162), so you
 * cannot run SNMP software that receives traps and an OpenIPMI PET at
 * the same time on the same machine.
 */
int ipmi_pet_create(ipmi_domain_t    *domain,
		    struct in_addr   ip_addr,
		    unsigned char    mac_addr[6],
		    unsigned int     eft_sel,
		    unsigned int     apt_sel,
		    unsigned int     lan_dest_sel,
		    ipmi_pet_done_cb done,
		    void             *cb_data,
		    ipmi_pet_t       **pet);

/* Destroy a PET.  Note that if you destroy all PETs, this will result
   in the SNMP trap UDP port being closed. */
int ipmi_pet_destroy(ipmi_pet_t       *pet,
		     ipmi_pet_done_cb done,
		     void             *cb_data);

#endif /* _IPMI_PET_H */
