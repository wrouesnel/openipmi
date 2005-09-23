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
#include <errno.h>

#include <OpenIPMI/ipmiif.h>

#include <OpenIPMI/internal/ipmi_event.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/ipmi_mc.h>
#include <OpenIPMI/internal/ipmi_domain.h>

struct ipmi_event_s
{
    ipmi_mcid_t   mcid; /* The MC this event is stored in. */

    ipmi_lock_t   *lock;
    unsigned int  refcount;
    unsigned int  record_id;
    unsigned int  type;
    ipmi_time_t   timestamp;
    unsigned int  data_len;
    unsigned char old;
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
    rv->data_len = data_len;
    rv->old = 0;
    if (data_len)
	memcpy(rv->data, data, data_len);

    rv->refcount = 1;
    return rv;
}

ipmi_event_t *
ipmi_event_dup(ipmi_event_t *event)
{
    if (!event)
	return NULL;
    ipmi_lock(event->lock);
    event->refcount++;
    ipmi_unlock(event->lock);
    return event;
}

void
ipmi_event_free(ipmi_event_t *event)
{
    if (!event)
	return;
    ipmi_lock(event->lock);
    event->refcount--;
    if (event->refcount == 0) {
	ipmi_unlock(event->lock);
	ipmi_destroy_lock(event->lock);
	ipmi_mem_free(event);
	return;
    }
    ipmi_unlock(event->lock);
}

ipmi_mcid_t
ipmi_event_get_mcid(const ipmi_event_t *event)
{
    return event->mcid;
}

void
ipmi_event_set_mcid(ipmi_event_t *event, ipmi_mcid_t mcid)
{
    event->mcid = mcid;
}

unsigned int
ipmi_event_get_record_id(const ipmi_event_t *event)
{
    return event->record_id;
}

unsigned int
ipmi_event_get_type(const ipmi_event_t *event)
{
    return event->type;
}

ipmi_time_t
ipmi_event_get_timestamp(const ipmi_event_t *event)
{
    return event->timestamp;
}

unsigned int
ipmi_event_get_data_len(const ipmi_event_t *event)
{
    return event->data_len;
}

unsigned int
ipmi_event_get_data(const ipmi_event_t *event, unsigned char *data,
		    unsigned int offset, unsigned int len)
{
    if (offset > event->data_len)
	return 0;

    if (offset+len > event->data_len)
	len = event->data_len - offset;

    memcpy(data, event->data+offset, len);

    return len;
}

const unsigned char *
ipmi_event_get_data_ptr(const ipmi_event_t *event)
{
    return event->data;
}

int
ipmi_event_is_old(const ipmi_event_t *event)
{
    return event->old;
}

void
ipmi_event_set_is_old(ipmi_event_t *event, int val)
{
    event->old = val;
}

typedef struct del_event_info_s
{
    ipmi_event_t   *event;
    ipmi_domain_cb done_handler;
    void           *cb_data;
    int            rv;
} del_event_info_t;

static void
mc_del_event_done(ipmi_mc_t *mc, int err, void *cb_data)
{
    del_event_info_t *info = cb_data;

    if (info->done_handler) {
	ipmi_domain_t *domain = NULL;
	if (mc)
	    domain = ipmi_mc_get_domain(mc);
	info->done_handler(domain, err, info->cb_data);
    }
    ipmi_mem_free(info);
}

static void
del_event_handler(ipmi_mc_t *mc, void *cb_data)
{
    del_event_info_t *info = cb_data;
    del_event_info_t *ninfo;

    ninfo = ipmi_mem_alloc(sizeof(*ninfo));
    if (!ninfo) {
	info->rv = ENOMEM;
	return;
    }
    *ninfo = *info;

    info->rv = ipmi_mc_del_event(mc, info->event, mc_del_event_done, ninfo);
    if (info->rv)
	ipmi_mem_free(ninfo);
}

int
ipmi_event_delete(ipmi_event_t   *event,
		  ipmi_domain_cb done_handler,
		  void           *cb_data)
{
    int              rv;
    del_event_info_t info;
    ipmi_mcid_t      mcid = ipmi_event_get_mcid(event);

    info.event = event;
    info.done_handler = done_handler;
    info.cb_data = cb_data;
    info.rv = 0;
    rv = ipmi_mc_pointer_cb(mcid, del_event_handler, &info);
    if (!rv)
	rv = info.rv;

    return rv;
}

ipmi_mc_t *
_ipmi_event_get_generating_mc(ipmi_domain_t      *domain,
			      ipmi_mc_t          *sel_mc,
			      const ipmi_event_t *event)
{
    ipmi_ipmb_addr_t    addr;
    const unsigned char *data;
    unsigned int        type = ipmi_event_get_type(event);

    if (type != 0x02)
	/* It's not a standard IPMI event. */
	return NULL;

    data = ipmi_event_get_data_ptr(event);
    addr.addr_type = IPMI_IPMB_ADDR_TYPE;
    /* See if the MC has an OEM handler for this. */
    if (data[6] == 0x03) {
	addr.channel = 0;
    } else {
	addr.channel = data[5] >> 4;
    }
    if ((data[4] & 0x01) == 0) {
	addr.slave_addr = data[4];
    } else if (sel_mc) {
	/* A software ID, assume it comes from the MC where we go it. */
	ipmi_addr_t iaddr;

	ipmi_mc_get_ipmi_address(sel_mc, &iaddr, NULL);
	addr.slave_addr = ipmi_addr_get_slave_addr(&iaddr);
	if (addr.slave_addr == 0)
	    /* A system interface, just assume it's the BMC. */
	    addr.slave_addr = 0x20;
    } else {
	return NULL;
    }
    addr.lun = 0;

    return _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &addr, sizeof(addr));
}

ipmi_sensor_id_t
ipmi_event_get_generating_sensor_id(ipmi_domain_t       *domain,
			            ipmi_mc_t           *sel_mc,
			            const ipmi_event_t  *event)
{
    ipmi_sensor_id_t    id;
    ipmi_mc_t           *mc;
    const unsigned char *data;
    unsigned int        type = ipmi_event_get_type(event);


    if (type != 0x02)
	/* It's not a standard IPMI event. */
	goto out_invalid;

    mc = _ipmi_event_get_generating_mc(domain, sel_mc, event);
    if (!mc)
	goto out_invalid;

    data = ipmi_event_get_data_ptr(event);
    id.mcid = ipmi_mc_convert_to_id(mc);
    id.lun = data[5] & 0x3;
    id.sensor_num = data[8];

    _ipmi_mc_put(mc);

    return id;

 out_invalid:
    ipmi_sensor_id_set_invalid(&id);
    return id;
}

struct ipmi_event_handlers_s
{
    ipmi_sensor_threshold_event_cb threshold;
    ipmi_sensor_discrete_event_cb  discrete;
};

ipmi_event_handlers_t *
ipmi_event_handlers_alloc(void)
{
    ipmi_event_handlers_t *rv;
    rv = ipmi_mem_alloc(sizeof(*rv));
    if (!rv)
	return NULL;
    memset(rv, 0, sizeof(*rv));
    return rv;
}

void
ipmi_event_handlers_free(ipmi_event_handlers_t *handlers)
{
    ipmi_mem_free(handlers);
}

void
ipmi_event_handlers_set_threshold(ipmi_event_handlers_t         *handlers,
				  ipmi_sensor_threshold_event_cb handler)
{
    handlers->threshold = handler;
}

void
ipmi_event_handlers_set_discrete(ipmi_event_handlers_t         *handlers,
				 ipmi_sensor_discrete_event_cb handler)
{
    handlers->discrete = handler;
}

typedef struct event_call_handlers_s
{
    ipmi_domain_t         *domain;
    ipmi_event_handlers_t *handlers;
    ipmi_event_t          *event;
    int                   rv;
    void                  *cb_data;
} event_call_handlers_t;

static void
sensor_event_call(ipmi_sensor_t *sensor, void *cb_data)
{
    event_call_handlers_t *info = cb_data;
    int                   rv;

    if (ipmi_sensor_get_event_reading_type(sensor)
	== IPMI_EVENT_READING_TYPE_THRESHOLD)
    {
	enum ipmi_event_dir_e       dir;
	enum ipmi_thresh_e          threshold;
	enum ipmi_event_value_dir_e high_low;
	enum ipmi_value_present_e   value_present;
	unsigned int                raw_value;
	double                      value;
	const unsigned char         *data;

	data = ipmi_event_get_data_ptr(info->event);
	dir = data[9] >> 7;
	threshold = (data[10] >> 1) & 0x07;
	high_low = data[10] & 1;
	raw_value = data[11];
	value = 0.0;

	if ((data[10] >> 6) == 2) {
	    rv = ipmi_sensor_convert_from_raw(sensor, raw_value, &value);
	    if (!rv)
		value_present = IPMI_RAW_VALUE_PRESENT;
	    else
		value_present = IPMI_BOTH_VALUES_PRESENT;
	} else {
	    value_present = IPMI_NO_VALUES_PRESENT;
	}
	if (info->handlers->threshold)
	    info->handlers->threshold(sensor, dir,
				      threshold,
				      high_low,
				      value_present,
				      raw_value, value,
				      info->cb_data,
				      info->event);

	else
	    info->rv = EAGAIN;
    } else {
	enum ipmi_event_dir_e dir;
	int                   offset;
	int                   severity = 0;
	int                   prev_severity = 0;
	const unsigned char   *data;

	data = ipmi_event_get_data_ptr(info->event);
	dir = data[9] >> 7;
	offset = data[10] & 0x0f;
	if ((data[10] >> 6) == 2) {
	    severity = data[11] >> 4;
	    prev_severity = data[11] & 0xf;
	    if (severity == 0xf)
		severity = -1;
	    if (prev_severity == 0xf)
		prev_severity = -1;
	}

	if (info->handlers->discrete)
	    info->handlers->discrete(sensor, dir, offset,
				     severity,
				     prev_severity,
				     info->cb_data,
				     info->event);
	else
	    info->rv = EAGAIN;
    }
}

static void
sel_mc_handler(ipmi_mc_t *mc, void *cb_data)
{
    ipmi_sensor_id_t      sensor_id;
    event_call_handlers_t *info = cb_data;
    int                   rv;

    sensor_id = ipmi_event_get_generating_sensor_id(info->domain, mc,
						    info->event);
    rv = ipmi_sensor_pointer_cb(sensor_id, sensor_event_call, info);
    if (rv)
	info->rv = rv;
}

int
ipmi_event_call_handler(ipmi_domain_t         *domain,
			ipmi_event_handlers_t *handlers,
			ipmi_event_t          *event,
			void                  *cb_data)
{


    ipmi_sensor_id_t      sensor_id;
    event_call_handlers_t info;
    int                   rv = 0;
    ipmi_mcid_t           mc_id;

    info.domain = domain;
    info.handlers = handlers;
    info.event = event;
    info.rv = 0;
    info.cb_data = cb_data;

    /* We try first to get the MC the event is stored in.  If that
       doesn't work, then just attempt to do the sensor without an MC. */
    mc_id = ipmi_event_get_mcid(event);
    if (ipmi_mc_pointer_cb(mc_id, sel_mc_handler, &info) != 0) {
	sensor_id = ipmi_event_get_generating_sensor_id(domain, NULL, event);
	rv = ipmi_sensor_pointer_cb(sensor_id, sensor_event_call, &info);
    }
    if (!rv)
	rv = info.rv;
    return rv;
}
