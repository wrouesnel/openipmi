/*
 * ipmi_event.h
 *
 * Routines for dealing with events.
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

#ifndef __IPMI_EVENT_H
#define __IPMI_EVENT_H

#include <OpenIPMI/ipmi_types.h>

/* The event code here is considered internal to OpenIPMI, normal
   users shouldn't use it. */

/* Allocate an event with the given data. */
ipmi_event_t *ipmi_event_alloc(ipmi_mcid_t   mcid,
			       unsigned int  record_id,
			       unsigned int  type,
			       ipmi_time_t   timestamp,
			       unsigned char *data,
			       unsigned int  data_len);

/* The only part of an event that can be set is the mcid, because the
   lower layers may need to allocate an event without knowing what the
   MC is.  Normal users shouldn't do this, obviously, it should be a
   one-time thing done in the domain code. */
void ipmi_event_set_mcid(ipmi_event_t *event, ipmi_mcid_t mcid);

/* Return the management controller that "owns" the event (where the
   event is stored). */
ipmi_mcid_t ipmi_event_get_mcid(ipmi_event_t *event);

/* Return a unique (in the MC) record identifier for the event. */
unsigned int ipmi_event_get_record_id(ipmi_event_t *event);

#define OPENIPMI_OEM_EVENT_START	0x10000
/* Return the event type.  Normal IPMI events should be in the
   000-0xff range.  Other events should start at
   OPENIPMI_OEM_EVENT_START and higher.*/
unsigned int ipmi_event_get_type(ipmi_event_t *event);

/* Get the timestamp for the event.  This will be IPMI_INVALID_TIME if
   the timestamp is invalid. */
ipmi_time_t ipmi_event_get_timestamp(ipmi_event_t *event);

/* Get the length of the data attached to the event. */
unsigned int ipmi_event_get_data_len(ipmi_event_t *event);

/* Copy some of the data attached to the event, starting at the given
   offset to an array.  Copy "len" bytes. */
unsigned int ipmi_event_get_data(ipmi_event_t *event, char *data,
				 unsigned int offset, unsigned int len);

/* Get a pointer to the event's data.  Note that this pointer will be
   valid only as long as the event is valid. */
unsigned char *ipmi_event_get_data_ptr(ipmi_event_t *event);

#endif /* __IPMI_EVENT_H */
