/*
 * event.c
 *
 * MontaVista IPMI code for dealing with events.
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

#include <string.h>

#include <OpenIPMI/ipmi_event.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_int.h>

struct ipmi_event_s
{
    ipmi_mcid_t   mcid; /* The MC this event is stored in. */

    ipmi_lock_t   *lock;
    unsigned int  refcount;
    unsigned int  record_id;
    unsigned int  type;
    ipmi_time_t   timestamp;
    unsigned int  data_len;
    unsigned char data[0];
};

ipmi_event_t *
ipmi_event_alloc(ipmi_mcid_t   mcid,
		 unsigned int  record_id,
		 unsigned int  type,
		 ipmi_time_t   timestamp,
		 unsigned char *data,
		 unsigned int  data_len)
{
    ipmi_event_t *rv;

    rv = ipmi_mem_alloc(sizeof(ipmi_event_t) + data_len);
    if (!rv)
	return NULL;

    if (ipmi_create_global_lock(&rv->lock)) {
	ipmi_mem_free(rv);
	return NULL;
    }
    rv->mcid = mcid;
    rv->record_id = record_id;
    rv->type = type;
    rv->timestamp = timestamp;
    memcpy(rv->data, data, data_len);

    rv->refcount = 1;
    return rv;
}

ipmi_event_t *
ipmi_event_dup(ipmi_event_t *event)
{
    ipmi_lock(event->lock);
    event->refcount++;
    ipmi_unlock(event->lock);
    return event;
}

void
ipmi_event_free(ipmi_event_t *event)
{
    ipmi_lock(event->lock);
    event->refcount--;
    if (event->refcount == 0) {
	ipmi_unlock(event->lock);
	ipmi_mem_free(event);
	return;
    }
    ipmi_unlock(event->lock);
}

ipmi_mcid_t
ipmi_event_get_mcid(ipmi_event_t *event)
{
    return event->mcid;
}

void
ipmi_event_set_mcid(ipmi_event_t *event, ipmi_mcid_t mcid)
{
    event->mcid = mcid;
}

unsigned int
ipmi_event_get_record_id(ipmi_event_t *event)
{
    return event->record_id;
}

unsigned int
ipmi_event_get_type(ipmi_event_t *event)
{
    return event->type;
}

ipmi_time_t
ipmi_event_get_timestamp(ipmi_event_t *event)
{
    return event->timestamp;
}

unsigned int
ipmi_event_get_data_len(ipmi_event_t *event)
{
    return event->data_len;
}

unsigned int
ipmi_event_get_data(ipmi_event_t *event, char *data,
		    unsigned int offset, unsigned int len)
{
    if (offset > event->data_len)
	return 0;

    if (offset+len > event->data_len)
	len = event->data_len = offset;

    memcpy(data, event->data+offset, len);

    return len;
}

unsigned char *
ipmi_event_get_data_ptr(ipmi_event_t *event)
{
    
}
