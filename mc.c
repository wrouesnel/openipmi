/*
 * mc.c
 *
 * MontaVista IPMI code for handling management controllers
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

#include <malloc.h>
#include <string.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_sdr.h>
#include <OpenIPMI/ipmi_sel.h>
#include <OpenIPMI/ipmi_entity.h>
#include <OpenIPMI/ipmi_sensor.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_oem.h>

#include "ilist.h"
#include "opq.h"

/* Rescan the bus for MCs every 10 minutes */
#define IPMI_RESCAN_BUS_INTERVAL 600

/* Re-query the SEL every 10 seconds. */
#define IPMI_SEL_QUERY_INTERVAL 10

enum ipmi_con_state_e { DEAD = 0,
			QUERYING_DEVICE_ID,
			QUERYING_MAIN_SDRS,
			QUERYING_SENSOR_SDRS,
			QUERYING_CHANNEL_INFO,
			OPERATIONAL };

#define MAX_IPMI_USED_CHANNELS 8

/* Timer structure fo rereading the SEL. */
typedef struct bmc_reread_info_s
{
    int cancelled;
    ipmi_mc_t *bmc;
} bmc_reread_info_t;
    
/* Timer structure fo rescanning the bus. */
typedef struct bmc_rescan_bus_info_s
{
    int       cancelled;
    ipmi_mc_t *bmc;
} bmc_rescan_bus_info_t;

typedef struct ipmi_bmc_s
{
    /* The main set of SDRs on a BMC. */
    ipmi_sdr_info_t *main_sdrs;

    enum ipmi_con_state_e state;

    ipmi_chan_info_t chan[MAX_IPMI_USED_CHANNELS];
    unsigned char    msg_int_type;
    unsigned char    event_msg_int_type;

    /* The sensors that came from the main SDR. */
    ipmi_sensor_t **sensors_in_my_sdr;
    unsigned int  sensors_in_my_sdr_count;

    ilist_t            *mc_list;
    ipmi_lock_t        *mc_list_lock;

    ipmi_event_handler_id_t  *event_handlers;
    ipmi_lock_t              *event_handlers_lock;
    ipmi_oem_event_handler_cb oem_event_handler;
    void                      *oem_event_cb_data;

    /* Are we in the middle of an MC bus scan? */
    int                scanning_bus;

    ipmi_entity_info_t *entities;
    ipmi_lock_t        *entities_lock;
    ipmi_bmc_entity_cb entity_handler;

    ipmi_ll_event_handler_id_t *ll_event_id;

    ipmi_con_t  *conn;

    /* The SEL time when the connection first came up. */
    unsigned long startup_SEL_time;

    /* The handler to call for delete event operations. */
    ipmi_bmc_del_event_cb sel_del_event_handler;

    ipmi_bmc_oem_new_entity_cb new_entity_handler;
    void                       *new_entity_cb_data;

    ipmi_bmc_oem_new_mc_cb     new_mc_handler;
    void                       *new_mc_cb_data;

    ipmi_oem_setup_finished_cb setup_finished_handler;
    void                       *setup_finished_cb_data;

    /* Should I do a full bus scan for devices on the bus? */
    int                        do_bus_scan;

    /* The system event log, for querying and storing events. */
    ipmi_sel_info_t *sel;

    /* Timer for rescanning the bus periodically. */
    os_hnd_timer_id_t     *bus_scan_timer;
    bmc_rescan_bus_info_t *bus_scan_timer_info;

    /* Timer for rescanning the sel periodically. */
    os_hnd_timer_id_t *sel_timer;
    bmc_reread_info_t *sel_timer_info;
} ipmi_bmc_t;

struct ipmi_mc_s
{
    ipmi_mc_t   *bmc_mc; /* Pointer to the MC that is the BMC. */
    ipmi_addr_t addr;
    int         addr_len;

    ipmi_bmc_t  *bmc; /* Will be NULL if not a BMC. */

    /* The device SDRs on the MC. */
    ipmi_sdr_info_t *sdrs;

    /* The sensors that came from the device SDR on this MC. */
    ipmi_sensor_t **sensors_in_my_sdr;
    unsigned int  sensors_in_my_sdr_count;

    /* Sensors that this MC owns (you message this MC to talk to this
       sensor, and events report the MC as the owner. */
    ipmi_sensor_info_t  *sensors;

    ipmi_control_info_t *controls;

    int provides_device_sdrs : 1;
    int device_available : 1;

    int chassis_support : 1;
    int bridge_support : 1;
    int IPMB_event_generator_support : 1;
    int IPMB_event_receiver_support : 1;
    int FRU_inventory_support : 1;
    int SEL_device_support : 1;
    int SDR_repository_support : 1;
    int sensor_device_support : 1;

    int in_bmc_list : 1; /* Tells if we are in the list of our BMC yet. */

    uint8_t device_id;

    uint8_t device_revision;

    uint8_t major_fw_revision;
    uint8_t minor_fw_revision;

    uint8_t major_version;
    uint8_t minor_version;

    uint32_t manufacturer_id;
    uint16_t product_id;

    uint8_t  aux_fw_revision[4];

    ipmi_mc_oem_new_sensor_cb new_sensor_handler;
    void                      *new_sensor_cb_data;

    ipmi_oem_event_handler_cb oem_event_handler;
    void                      *oem_event_handler_cb_data;

    void *oem_data;
};

struct ipmi_event_handler_id_s
{
    ipmi_mc_t                  *mc;
    ipmi_event_handler_t       handler;
    void                       *event_data;

    ipmi_event_handler_id_t *next, *prev;
};

typedef struct oem_handlers_s {
    unsigned int                 manufacturer_id;
    unsigned int                 product_id;
    ipmi_oem_mc_match_handler_cb handler;
    void                         *cb_data;
} oem_handlers_t;
/* FIXME - do we need a lock?  Probably, add it. */
static ilist_t *oem_handlers;

int
ipmi_mc_init(void)
{
    static int mc_initialized = 0;

    if (mc_initialized)
	return 0;

    oem_handlers = alloc_ilist();
    if (!oem_handlers)
	return ENOMEM;

    mc_initialized = 1;

    return 0;
}

int
ipmi_register_oem_handler(unsigned int                 manufacturer_id,
			  unsigned int                 product_id,
			  ipmi_oem_mc_match_handler_cb handler,
			  void                         *cb_data)
{
    oem_handlers_t *new_item;
    int            rv;

    /* This might be called before initialization, so be 100% sure.. */
    rv = ipmi_mc_init();
    if (rv)
	return rv;

    new_item = malloc(sizeof(*new_item));
    if (!new_item)
	return ENOMEM;

    new_item->manufacturer_id = manufacturer_id;
    new_item->product_id = product_id;
    new_item->handler = handler;
    new_item->cb_data = cb_data;

    if (! ilist_add_tail(oem_handlers, new_item, NULL)) {
	free(new_item);
	return ENOMEM;
    }

    return 0;
}

static int
oem_handler_cmp(void *item, void *cb_data)
{
    oem_handlers_t *hndlr = item;
    ipmi_mc_t      *mc = cb_data;

    return ((hndlr->manufacturer_id == mc->manufacturer_id)
	    && (hndlr->product_id == mc->product_id));
}

static int
check_oem_handlers(ipmi_mc_t *mc)
{
    oem_handlers_t *hndlr;

    hndlr = ilist_search(oem_handlers, oem_handler_cmp, mc);
    if (hndlr) {
	return hndlr->handler(mc, hndlr->cb_data);
    }
    return 0;
}

int
ipmi_mc_validate(ipmi_mc_t *mc)
{
    int rv;
    /* FIXME - add more validation. */
    rv = __ipmi_validate(mc->bmc_mc->bmc->conn);
    return rv;
}

typedef struct mc_cmp_info_s
{
    ipmi_addr_t addr;
    int         addr_len;
} mc_cmp_info_t;

static
int mc_cmp(void *item, void *cb_data)
{
    ipmi_mc_t     *mc = item;
    mc_cmp_info_t *info = cb_data;

    return ipmi_addr_equal(&(mc->addr), mc->addr_len,
			   &(info->addr), info->addr_len);
}
static ipmi_mc_t *
find_mc_by_addr(ipmi_mc_t   *bmc,
		ipmi_addr_t *addr,
		int         addr_len)
{
    mc_cmp_info_t    info;

    /* Cheap hack to handle the BMC LUN. */
    if (addr->addr_type == IPMI_IPMB_ADDR_TYPE) {
	ipmi_ipmb_addr_t *ipmb = (ipmi_ipmb_addr_t *) addr;
	if (ipmb->slave_addr == 0x20)
	    return bmc;
    }

    memcpy(&(info.addr), addr, addr_len);
    info.addr_len = addr_len;
    return ilist_search(bmc->bmc->mc_list, mc_cmp, &info);
}

int
ipmi_mc_find_or_create_mc_by_slave_addr(ipmi_mc_t    *bmc,
					unsigned int slave_addr,
					ipmi_mc_t    **new_mc)
{
    ipmi_mc_t        *mc;
    ipmi_ipmb_addr_t addr;
    int              rv;

    addr.addr_type = IPMI_IPMB_ADDR_TYPE;
    addr.channel = 0;
    addr.lun = 0;
    addr.slave_addr = slave_addr;

    mc = find_mc_by_addr(bmc, (ipmi_addr_t *) &addr, sizeof(addr));
    if (mc) {
	*new_mc = mc;
	return 0;
    }

    rv = ipmi_create_mc(bmc, (ipmi_addr_t *) &addr, sizeof(addr), &mc);
    if (rv)
	return rv;
    *new_mc = mc;
    return 0;
}

static void ll_rsp_handler(ipmi_con_t   *ipmi,
			   ipmi_addr_t  *addr,
			   unsigned int addr_len,
			   ipmi_msg_t   *msg,
			   void         *rsp_data,
			   void         *data2,
			   void         *data3)
{
    ipmi_response_handler_t rsp_handler = data2;
    ipmi_mc_t               *bmc = data3;
    ipmi_mc_t               *mc;
    int                     rv;

    if (rsp_handler) {
	ipmi_read_lock();
	rv = ipmi_mc_validate(bmc);
	if (rv)
	    rsp_handler(NULL, msg, rsp_data);
	else {
	    ipmi_lock(bmc->bmc->mc_list_lock);
	    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
		mc = bmc;
	    } else {
		mc = find_mc_by_addr(bmc, addr, addr_len);
	    }
	    rsp_handler(mc, msg, rsp_data);
	    ipmi_unlock(bmc->bmc->mc_list_lock);
	}
	ipmi_read_unlock();
    }
}

int
ipmi_send_command(ipmi_mc_t               *mc,
		  unsigned int            lun,
		  ipmi_msg_t              *msg,
		  ipmi_response_handler_t rsp_handler,
		  void                    *rsp_data)
{
    int         rv;
    ipmi_addr_t addr = mc->addr;

    CHECK_MC_LOCK(mc);

    rv = ipmi_addr_set_lun(&addr, lun);
    if (rv)
	return rv;

    rv = mc->bmc_mc->bmc->conn->send_command(mc->bmc_mc->bmc->conn,
					     &addr, mc->addr_len,
					     msg,
					     ll_rsp_handler, rsp_data,
					     rsp_handler, mc->bmc_mc);
    return rv;
}

int
ipmi_bmc_send_command_addr(ipmi_mc_t               *bmc,
			   ipmi_addr_t		   *addr,
			   unsigned int            addr_len,
			   ipmi_msg_t              *msg,
			   ipmi_response_handler_t rsp_handler,
			   void                    *rsp_data)
{
    int rv;

    if (bmc->bmc == NULL)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    rv = bmc->bmc->conn->send_command(bmc->bmc->conn,
				      addr, addr_len,
				      msg,
				      ll_rsp_handler, rsp_data,
				      rsp_handler, bmc);
    return rv;
}

/* Must be called with event_lock held. */
static void
add_event_handler(ipmi_mc_t                *mc,
		  ipmi_event_handler_id_t  *event)
{
    event->mc = mc;

    event->next = mc->bmc->event_handlers;
    event->prev = NULL;
    if (mc->bmc->event_handlers)
	mc->bmc->event_handlers->prev = event;
    mc->bmc->event_handlers = event;
}

static int
remove_event_handler(ipmi_mc_t               *mc,
		     ipmi_event_handler_id_t *event)
{
    ipmi_event_handler_id_t *ev;

    ev = mc->bmc->event_handlers;
    while (ev != NULL) {
	if (ev == event)
	    break;
	ev = ev->next;
    }

    if (!ev)
	return EINVAL;

    if (event->next)
	event->next->prev = event->prev;
    if (event->prev)
	event->prev->next = event->next;
    else
	mc->bmc->event_handlers = event->next;

    return 0;
}

typedef struct event_sensor_info_s
{
    int          handled;
    int          err;
    ipmi_event_t *event;
} event_sensor_info_t;

void
event_sensor_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    event_sensor_info_t *info = cb_data;

    /* It's an event for a specific sensor, and the sensor exists. */
    info->err = ipmi_sensor_event(sensor, info->event);
}

int
ipmi_bmc_set_oem_event_handler(ipmi_mc_t                 *bmc,
			       ipmi_oem_event_handler_cb handler,
			       void                      *cb_data)
{
    if (bmc->bmc == NULL)
	return EINVAL;

    bmc->bmc->oem_event_handler = handler;
    bmc->bmc->oem_event_cb_data = cb_data;
    return 0;
}

int
ipmi_mc_set_oem_event_handler(ipmi_mc_t                 *mc,
			      ipmi_oem_event_handler_cb handler,
			      void                      *cb_data)
{
    mc->oem_event_handler = handler;
    mc->oem_event_handler_cb_data = cb_data;
    return 0;
}

void
mc_event_cb(ipmi_mc_t *mc, void *cb_data)
{
    event_sensor_info_t *info = cb_data;

    if (mc->oem_event_handler)
	info->handled = mc->oem_event_handler(mc,
					      info->event,
					      mc->oem_event_handler_cb_data);
}

void
ipmi_handle_unhandled_event(ipmi_mc_t *bmc, ipmi_event_t *event)
{
    ipmi_event_handler_id_t *l;

    ipmi_lock(bmc->bmc->event_handlers_lock);
    l = bmc->bmc->event_handlers;
    while (l) {
	l->handler(bmc, event, l->event_data);
	l = l->next;
    }
    ipmi_unlock(bmc->bmc->event_handlers_lock);
}

static void
system_event_handler(ipmi_mc_t    *bmc,
		     ipmi_event_t *event)
{
    int                 rv = 1;
    ipmi_sensor_id_t    id;
    event_sensor_info_t info;
    unsigned long       timestamp;

    if (DEBUG_EVENTS) {
	ipmi_log(IPMI_LOG_DEBUG,
		 "Event recid:%4.4x type:%2.2x:"
		 " %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x"
		 " %2.2x %2.2x %2.2x %2.2x %2.2x",
		 event->record_id, event->type,
		 event->data[0], event->data[1], event->data[2],
		 event->data[3], event->data[4], event->data[5],
		 event->data[6], event->data[7], event->data[8],
		 event->data[9], event->data[10], event->data[11],
		 event->data[12]);
    }

    /* Let the OEM handler have a go at it first.  Note that OEM
       handlers must look at the time themselves. */
    if (bmc->bmc->oem_event_handler) {
	if (bmc->bmc->oem_event_handler(bmc,
					event,
					bmc->bmc->oem_event_cb_data))
	    return;
    }

    timestamp = ipmi_get_uint32(&(event->data[0]));

    /* It's a system event record from an MC, and the timestamp is
       later than our startup timestamp. */
    if ((event->type == 0x02)
	&& ((event->data[4] & 0x01) == 0)
	&& (timestamp >= bmc->bmc->startup_SEL_time))
    {
	ipmi_mc_id_t mc_id;

	info.handled = 0;
	info.err = 0;
	info.event = event;

	/* See if the MC has an OEM handler for this. */
	mc_id.bmc = bmc;
	if (event->data[6] == 0x03) {
	    mc_id.channel = 0;
	} else {
	    mc_id.channel = event->data[5] >> 4;
	}
	mc_id.mc_num = event->data[4];
	ipmi_mc_pointer_cb(mc_id, mc_event_cb, &info);

	/* It's from an MC. */
	id.bmc = bmc;
	if (event->data[6] == 0x03) {
	    id.channel = 0;
	} else {
	    id.channel = event->data[5] >> 4;
	}
	id.mc_num = event->data[4];
	id.lun = event->data[5] & 0x3;
	id.sensor_num = event->data[8];

	rv = ipmi_sensor_pointer_cb(id, event_sensor_cb, &info);
	if (!rv) {
	    rv = info.err;
	}
    }

    /* It's an event from system software, or the info couldn't be found. */
    if (rv)
	ipmi_handle_unhandled_event(bmc, event);
}

/* Got a new event in the system event log that we didn't have before. */
static void
bmc_sel_new_event_handler(ipmi_sel_info_t *sel,
			  ipmi_event_t    *event,
			  void            *cb_data)
{
    system_event_handler(cb_data, event);
}


unsigned long
ipmi_bmc_get_startup_SEL_time(ipmi_mc_t *bmc)
{
    return bmc->bmc->startup_SEL_time;
}

void
ipmi_bmc_set_del_event_handler(ipmi_mc_t             *bmc,
			       ipmi_bmc_del_event_cb handler)
{
    bmc->bmc->sel_del_event_handler = handler;
}

int
ipmi_bmc_rescan_events(ipmi_mc_t *bmc)
{
    if (bmc->bmc == NULL)
	/* It's not the BMC. */
	return EINVAL;

    return ipmi_sel_get(bmc->bmc->sel, NULL, NULL);
}

static void
ll_event_handler(ipmi_con_t   *ipmi,
		 ipmi_addr_t  *addr,
		 unsigned int addr_len,
		 ipmi_msg_t   *event,
		 void         *event_data,
		 void         *data2)
{
    ipmi_event_t devent;
    ipmi_mc_t    *bmc = data2;

    devent.record_id = ipmi_get_uint16(event->data);
    devent.type = event->data[2];
    memcpy(devent.data, event+3, IPMI_MAX_SEL_DATA);

    /* Add it to the system event log. */
    ipmi_sel_event_add(bmc->bmc->sel, &devent);

    /* Call the handler on it. */
    system_event_handler(bmc, &devent);
}

int
ipmi_register_for_events(ipmi_mc_t               *bmc,
			 ipmi_event_handler_t    handler,
			 void                    *event_data,
			 ipmi_event_handler_id_t **id)
{
    ipmi_event_handler_id_t *elem;

    /* Make sure it's an SMI mc. */
    if (bmc->bmc_mc != bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    elem = malloc(sizeof(*elem));
    if (!elem)
	return ENOMEM;
    elem->handler = handler;
    elem->event_data = event_data;

    ipmi_lock(bmc->bmc->event_handlers_lock);
    add_event_handler(bmc, elem);
    ipmi_unlock(bmc->bmc->event_handlers_lock);

    *id = elem;

    return 0;
}

int
ipmi_deregister_for_events(ipmi_mc_t               *bmc,
			   ipmi_event_handler_id_t *id)
{
    int        rv;

    /* Make sure it's an SMI mc. */
    if (bmc->bmc_mc != bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    ipmi_lock(bmc->bmc->event_handlers_lock);
    rv = remove_event_handler(bmc, id);
    ipmi_unlock(bmc->bmc->event_handlers_lock);

    return rv;
}

int
ipmi_bmc_disable_events(ipmi_mc_t *bmc)
{
    int rv;

    /* Make sure it's an SMI mc. */
    if (bmc->bmc_mc != bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    if (! bmc->bmc->ll_event_id)
	return EINVAL;

    rv = bmc->bmc->conn->deregister_for_events(bmc->bmc->conn,
					       bmc->bmc->ll_event_id);
    if (!rv)
	bmc->bmc->ll_event_id = NULL;
    return rv;
}

int
ipmi_bmc_enable_events(ipmi_mc_t *bmc)
{
    int rv;

    /* Make sure it's an SMI mc. */
    if (bmc->bmc_mc != bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    if (bmc->bmc->ll_event_id)
	return EINVAL;

    rv = bmc->bmc->conn->register_for_events(bmc->bmc->conn,
					     ll_event_handler, NULL, bmc,
					     &(bmc->bmc->ll_event_id));
    return rv;
}


int
ipmi_send_response(ipmi_mc_t  *mc,
		   ipmi_msg_t *msg,
		   long       sequence)
{
    int        rv;
    ipmi_con_t *ipmi;

    CHECK_MC_LOCK(mc);

    ipmi = mc->bmc_mc->bmc->conn;
    rv = ipmi->send_response(ipmi, 
			     &(mc->addr), mc->addr_len,
			     msg, sequence);

    return rv;
}

typedef struct ipmi_addr_info_s
{
    ipmi_addr_t *addr;
    int         addr_len;
} ipmi_addr_info_t;

static int
cmp_ipmi_addr_cb(void *item, void *cb_data)
{
    ipmi_mc_t        *mc = (ipmi_mc_t *) item;
    ipmi_addr_info_t *info = (ipmi_addr_info_t *) cb_data;

    return ipmi_addr_equal(info->addr, info->addr_len, &mc->addr, mc->addr_len);
}

static void
ll_cmd_handler(ipmi_con_t   *ipmi,
	       ipmi_addr_t  *addr,
	       unsigned int addr_len,
	       ipmi_msg_t   *cmd,
	       long         sequence,
	       void         *cmd_data,
	       void         *data2,
	       void         *data3)
{
    ipmi_command_handler_t handler = (ipmi_command_handler_t) data2;
    ipmi_mc_t              *bmc = (ipmi_mc_t *) data3;
    ipmi_mc_t              *mc;
    ipmi_addr_info_t       info = { addr, addr_len };

    ipmi_lock(bmc->bmc->mc_list_lock);
    if (cmp_ipmi_addr_cb(bmc, &info))
	mc = bmc;
    else
	mc = ilist_search(bmc->bmc->mc_list, cmp_ipmi_addr_cb, &info);

    if (mc) {
	handler(mc, cmd, sequence, cmd_data);
    } else {
	/* FIXME - send error response. */
    }
    ipmi_unlock(bmc->bmc->mc_list_lock);
}

int
ipmi_register_for_command(ipmi_mc_t              *mc,
			  unsigned char          netfn,
			  unsigned char          cmd,
			  ipmi_command_handler_t handler,
			  void                   *cmd_data)
{
    int        rv;
    ipmi_con_t *ipmi;

    CHECK_MC_LOCK(mc);

    ipmi = mc->bmc_mc->bmc->conn;

    rv = ipmi->register_for_command(ipmi, netfn, cmd, ll_cmd_handler,
				    cmd_data, handler, mc->bmc_mc);

    return rv;
}

/* Remove the registration for a command. */
int
ipmi_deregister_for_command(ipmi_mc_t     *mc,
			    unsigned char netfn,
			    unsigned char cmd)
{
    int        rv;
    ipmi_con_t *ipmi;

    CHECK_MC_LOCK(mc);

    ipmi = mc->bmc_mc->bmc->conn;

    rv = ipmi->deregister_for_command(ipmi, netfn, cmd);

    return rv;
}

int
ipmi_close_connection(ipmi_mc_t    *mc,
		      close_done_t close_done,
		      void         *cb_data)
{
    int        rv;
    ipmi_con_t *ipmi;
    int        i;

    if (mc->bmc_mc != mc)
	return EINVAL;

    CHECK_MC_LOCK(mc);

    ipmi_write_lock();
    if ((rv = ipmi_mc_validate(mc)))
	goto out_unlock;

    ipmi = mc->bmc->conn;

    /* FIXME - handle cleaning up the mc list. */

    if (mc->bmc->sel_timer_info)
        mc->bmc->sel_timer_info->cancelled = 1;

    if (mc->bmc->bus_scan_timer_info)
        mc->bmc->bus_scan_timer_info->cancelled = 1;

    if (mc->sensors_in_my_sdr) {
	for (i=0; i<mc->sensors_in_my_sdr_count; i++) {
	    ipmi_sensor_destroy(mc->sensors_in_my_sdr[i]);
	}
	free(mc->sensors_in_my_sdr);
    }

    if (mc->bmc->sensors_in_my_sdr) {
	for (i=0; i<mc->bmc->sensors_in_my_sdr_count; i++) {
	    ipmi_sensor_destroy(mc->bmc->sensors_in_my_sdr[i]);
	}
	free(mc->bmc->sensors_in_my_sdr);
    }

    free(mc->sensors_in_my_sdr);

    if (mc->sdrs)
	ipmi_sdr_info_destroy(mc->sdrs, NULL, NULL);

    if (mc->sensors)
	ipmi_sensors_destroy(mc->sensors);

    if (mc->controls)
	ipmi_controls_destroy(mc->controls);

    if (mc->bmc->main_sdrs)
	ipmi_sdr_info_destroy(mc->bmc->main_sdrs, NULL, NULL);

    ipmi_lock(mc->bmc->event_handlers_lock);
    while (mc->bmc->event_handlers)
	remove_event_handler(mc, mc->bmc->event_handlers);
    ipmi_unlock(mc->bmc->event_handlers_lock);

    ipmi->close_connection(ipmi);
 out_unlock:
    ipmi_write_unlock();
    return rv;
}

static int
get_device_id_data_from_rsp(ipmi_mc_t  *mc,
			    ipmi_msg_t *rsp)
{
    unsigned char *rsp_data = rsp->data;

    if (rsp_data[0] != 0) {
	return IPMI_IPMI_ERR_VAL(rsp_data[0]);
    }

    if (rsp->data_len < 12) {
	return EINVAL;
    }

    mc->device_id = rsp_data[1];
    mc->device_revision = rsp_data[2] & 0xf;
    mc->provides_device_sdrs = (rsp_data[2] & 0x80) == 0x80;
    mc->device_available = (rsp_data[3] & 0x80) == 0x80;
    mc->major_fw_revision = rsp_data[3] & 0x7f;
    mc->minor_fw_revision = rsp_data[4];
    mc->major_version = rsp_data[5] & 0xf;
    mc->minor_version = (rsp_data[5] >> 4) & 0xf;
    mc->chassis_support = (rsp_data[6] & 0x80) == 0x80;
    mc->bridge_support = (rsp_data[6] & 0x40) == 0x40;
    mc->IPMB_event_generator_support = (rsp_data[6] & 0x20) == 0x20;
    mc->IPMB_event_receiver_support = (rsp_data[6] & 0x10) == 0x10;
    mc->FRU_inventory_support = (rsp_data[6] & 0x08) == 0x08;
    mc->SEL_device_support = (rsp_data[6] & 0x04) == 0x04;
    mc->SDR_repository_support = (rsp_data[6] & 0x02) == 0x02;
    mc->sensor_device_support = (rsp_data[6] & 0x01) == 0x01;
    mc->manufacturer_id = (rsp_data[7]
			     | (rsp_data[8] << 8)
			     | (rsp_data[9] << 16));
    mc->product_id = rsp_data[10] | (rsp_data[11] << 8);

    if (rsp->data_len < 16) {
	/* no aux revision. */
	memset(mc->aux_fw_revision, 0, 4);
    } else {
	memcpy(mc->aux_fw_revision, rsp_data + 12, 4);
    }

    return check_oem_handlers(mc);
}

void
ipmi_cleanup_mc(ipmi_mc_t *mc)
{
    int i;

    if (mc->sensors_in_my_sdr) {
	for (i=0; i<mc->sensors_in_my_sdr_count; i++) {
	    ipmi_sensor_destroy(mc->sensors_in_my_sdr[i]);
	}
	free(mc->sensors_in_my_sdr);
    }

    if (mc->sensors)
	ipmi_sensors_destroy(mc->sensors);
    if (mc->controls)
	ipmi_controls_destroy(mc->controls);
    if (mc->bmc) {
	if (mc->bmc->sensors_in_my_sdr) {
	    for (i=0; i<mc->bmc->sensors_in_my_sdr_count; i++) {
		ipmi_sensor_destroy(mc->bmc->sensors_in_my_sdr[i]);
	    }
	    free(mc->bmc->sensors_in_my_sdr);
	}

	if (mc->bmc->mc_list)
	    free_ilist(mc->bmc->mc_list);
	if (mc->bmc->mc_list_lock)
	    ipmi_destroy_lock(mc->bmc->mc_list_lock);
	if (mc->bmc->event_handlers_lock)
	    ipmi_destroy_lock(mc->bmc->event_handlers_lock);
	if (mc->bmc->entities)
	    ipmi_entity_info_destroy(mc->bmc->entities);
	if (mc->bmc->sel)
	    ipmi_sel_destroy(mc->bmc->sel, NULL, NULL);
	if (mc->bmc->entities_lock)
	    ipmi_destroy_lock(mc->bmc->entities_lock);
	if (mc->bmc->ll_event_id)
	    mc->bmc->conn->deregister_for_events(mc->bmc->conn,
						 mc->bmc->ll_event_id);
	free(mc->bmc);
    } else if (mc->in_bmc_list) {
	ilist_iter_t iter;
	int          rv;

	/* Remove it from the BMC list. */
	ipmi_lock(mc->bmc_mc->bmc->mc_list_lock);
	ilist_init_iter(&iter, mc->bmc_mc->bmc->mc_list);
	rv = ilist_first(&iter);
	while (rv) {
	    if (ilist_get(&iter) == mc) {
		ilist_delete(&iter);
		break;
	    }
	    rv = ilist_next(&iter);
	}
	ipmi_unlock(mc->bmc_mc->bmc->mc_list_lock);
    }
    free(mc);
}

int
ipmi_create_mc(ipmi_mc_t    *bmc,
	       ipmi_addr_t  *addr,
	       unsigned int addr_len,
	       ipmi_mc_t    **new_mc)
{
    ipmi_mc_t *mc;
    int       rv = 0;

    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    mc = malloc(sizeof(*mc));
    if (!mc)
	return ENOMEM;

    mc->bmc_mc = bmc;

    mc->bmc = NULL;
    mc->sensors = NULL;
    mc->sensors_in_my_sdr = NULL;
    mc->sensors_in_my_sdr_count = 0;
    mc->controls = NULL;
    mc->new_sensor_handler = NULL;

    memcpy(&(mc->addr), addr, addr_len);
    mc->addr_len = addr_len;
    mc->sdrs = NULL;

    rv = ipmi_sensors_alloc(mc, &(mc->sensors));
    if (rv)
	goto out_err;

    rv = ipmi_controls_alloc(mc, &(mc->controls));
    if (rv)
	goto out_err;

 out_err:
    if (rv) {
	ipmi_cleanup_mc(mc);
    }
    else
	*new_mc = mc;

    return rv;
}

static void
bmc_reread_sel(void *cb_data, os_hnd_timer_id_t *id)
{
    struct timeval    timeout;
    bmc_reread_info_t *info = cb_data;
    ipmi_mc_t         *bmc = info->bmc;

    ipmi_lock(bmc->bmc->mc_list_lock);
    if (info->cancelled) {
	free(info);
	return;
    }

    ipmi_sel_get(bmc->bmc->sel, NULL, NULL);

    timeout.tv_sec = IPMI_SEL_QUERY_INTERVAL;
    timeout.tv_usec = 0;
    bmc->bmc->conn->os_hnd->start_timer(bmc->bmc->conn->os_hnd,
					id,
					&timeout,
					bmc_reread_sel,
					info);
    ipmi_unlock(bmc->bmc->mc_list_lock);
}

static void
start_SEL_timer(ipmi_mc_t *mc)
{
    struct timeval timeout;
    int            rv;

    timeout.tv_sec = IPMI_SEL_QUERY_INTERVAL;
    timeout.tv_usec = 0;
    rv = mc->bmc->conn->os_hnd->start_timer(mc->bmc->conn->os_hnd,
					    mc->bmc->sel_timer,
					    &timeout,
					    bmc_reread_sel,
					    mc->bmc->sel_timer_info);
    if (rv)
	ipmi_log(IPMI_LOG_SEVERE,
		 "Unable to start the SEL fetch timer due to error: %x",
		 rv);
}

static void
sels_fetched(ipmi_sel_info_t *sel,
	     int             err,
	     int             changed,
	     unsigned int    count,
	     void            *cb_data)
{
    ipmi_mc_t *mc = cb_data;

    if (!sel)
	return;

    /* We can assume the MC is locked because we got the SEL. */

    /* After the first SEL fetch, disable looking at the timestamp, in
       case someone messes with the SEL time. */
    bmc->bmc->startup_SEL_time = 0;

    start_SEL_timer(mc);
}

static void
got_sel_time(ipmi_mc_t  *mc,
	     ipmi_msg_t *rsp,
	     void       *rsp_data)
{
    if (!mc) {
	ipmi_log(IPMI_LOG_WARNING, "MC went away during SEL time fetch");
	return;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_WARNING,
		 "Unable to fetch the SEL time due to error: %x",
		 rsp->data[0]);
	mc->bmc->startup_SEL_time = 0;
    } else if (rsp->data_len < 5) {
	ipmi_log(IPMI_LOG_WARNING,
		 "Unable to fetch the SEL time message was too short");
	mc->bmc->startup_SEL_time = 0;
    } else {
	mc->bmc->startup_SEL_time = ipmi_get_uint32(&(rsp->data[1]));
    }

    ipmi_sel_get(mc->bmc->sel, sels_fetched, mc);
}

/* This is called after the first sensor scan for the MC, we start up
   timers and things like that here. */
static void
sensors_reread(ipmi_mc_t *mc, int err, void *cb_data)
{
    bmc_reread_info_t *info;
    int               rv;
    ipmi_msg_t        msg;

    ipmi_detect_bmc_presence_changes(mc, 0);

    /* Allocate the system event log fetch timer. */
    info = malloc(sizeof(*info));
    if (!info) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "Unable to allocate info for system event log timer."
		 " System event log will not be queried");
	return;
    }
    info->bmc = mc;
    info->cancelled = 0;
    rv = mc->bmc->conn->os_hnd->alloc_timer(mc->bmc->conn->os_hnd,
					    &(mc->bmc->sel_timer));
    if (rv) {
	free(info);
	ipmi_log(IPMI_LOG_SEVERE,
		 "Unable to allocate the system event log timer."
		 " System event log will not be queried");
    } else {
	mc->bmc->sel_timer_info = info;
    }

    /* Fetch the current system event log.  We do this here so we can
       be sure that the entities are all there before reporting
       events. */
    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_GET_SEL_TIME_CMD;
    msg.data = NULL;
    msg.data_len = 0;
    rv = ipmi_send_command(mc, 0, &msg, got_sel_time, NULL);
    if (rv) {
	ipmi_log(IPMI_LOG_DEBUG,
		 "Unable to start SEL time fetch due to error: %x\n",
		 rv);
	mc->bmc->startup_SEL_time = 0;
	ipmi_sel_get(mc->bmc->sel, NULL, NULL);
    }
}


int
ipmi_add_mc_to_bmc(ipmi_mc_t *bmc, ipmi_mc_t *mc)
{
    int rv;

    CHECK_MC_LOCK(bmc);

    ipmi_lock(mc->bmc_mc->bmc->mc_list_lock);
    rv = !ilist_add_tail(bmc->bmc->mc_list, mc, NULL);
    if (!rv)
	mc->in_bmc_list = 1;
    ipmi_unlock(bmc->bmc->mc_list_lock);

    return rv;
}

static void
mc_sdr_handler(ipmi_sdr_info_t *sdrs,
	       int             err,
	       int             changed,
	       unsigned int    count,
	       void            *cb_data)
{
    ipmi_mc_t  *mc = (ipmi_mc_t *) cb_data;
    int        rv;

    if (err) {
	ipmi_cleanup_mc(mc);
	return;
    }

    rv = ipmi_add_mc_to_bmc(mc->bmc_mc, mc);
    if (rv)
	ipmi_cleanup_mc(mc);
    else {
	if (mc->bmc_mc->bmc->new_mc_handler)
	    mc->bmc_mc->bmc->new_mc_handler(mc->bmc_mc, mc,
					    mc->bmc_mc->bmc->new_mc_cb_data);
	/* Scan all the sensors and call sensors_reread() when done. */
	ipmi_mc_reread_sensors(mc, sensors_reread, NULL);
    }
}

typedef struct mc_ipbm_scan_info_s
{
    ipmi_ipmb_addr_t addr;
    ipmi_mc_t        *bmc;
    ipmi_msg_t       msg;
    unsigned int     end_addr;
    ipmi_bmc_cb      done_handler;
    void             *cb_data;
} mc_ipmb_scan_info_t;

static void devid_bc_rsp_handler(ipmi_con_t   *ipmi,
				 ipmi_addr_t  *addr,
				 unsigned int addr_len,
				 ipmi_msg_t   *msg,
				 void         *rsp_data,
				 void         *data2,
				 void         *data3)
{
    mc_ipmb_scan_info_t *info = rsp_data;
    int                 rv;

    ipmi_read_lock();
    rv = ipmi_mc_validate(info->bmc);
    if (rv) {
	ipmi_log(IPMI_LOG_INFO,
		 "BMC went away while scanning for MCs");
	ipmi_read_unlock();
	return;
    }

    if (msg->data[0] == 0) {
	/* Found one, start the discovery process on it. */
	ipmi_mc_t *mc;

	ipmi_lock(info->bmc->bmc->mc_list_lock);
	mc = find_mc_by_addr(info->bmc, addr, addr_len);
	if (!mc) {
	    /* It doesn't already exist, so add it. */
	    rv = ipmi_create_mc(info->bmc, addr, addr_len, &mc);
	    if (rv) {
		/* Out of memory, just give up for now. */
		free(info);
		ipmi_unlock(info->bmc->bmc->mc_list_lock);
		goto out;
	    }
	    rv = get_device_id_data_from_rsp(mc, msg);
	    if (rv)
		goto next_addr;

	    rv = ipmi_sdr_info_alloc(mc, 0, 1, &(mc->sdrs));
	    if (!rv) {
		if (mc->sensor_device_support)
		    rv = ipmi_sdr_fetch(mc->sdrs, mc_sdr_handler, mc);
	        else
	 	    rv = ipmi_add_mc_to_bmc(mc->bmc_mc, mc);
	    }
	    if (rv)
		ipmi_cleanup_mc(mc);
	}
 next_addr:
	ipmi_unlock(info->bmc->bmc->mc_list_lock);
    }

    if (info->addr.slave_addr == info->end_addr) {
	/* We've hit the end, we can quit now. */
	if (info->done_handler)
	    info->done_handler(info->bmc, 0, info->cb_data);
	free(info);
	goto out;
    }
    info->addr.slave_addr += 2;

    rv = info->bmc->bmc->conn->send_command(info->bmc->bmc->conn,
					    (ipmi_addr_t *) &(info->addr),
					    sizeof(info->addr),
					    &(info->msg),
					    devid_bc_rsp_handler,
					    info, NULL, NULL);
    while ((rv) && (info->addr.slave_addr < info->end_addr)) {
	info->addr.slave_addr += 2;
	rv = info->bmc->bmc->conn->send_command(info->bmc->bmc->conn,
						(ipmi_addr_t *) &(info->addr),
						sizeof(info->addr),
						&(info->msg),
						devid_bc_rsp_handler,
						info, NULL, NULL);
    }

    if (rv)
	free(info);
 out:
    ipmi_read_unlock();
}

void
ipmi_start_ipmb_mc_scan(ipmi_mc_t    *bmc,
	       		int          channel,
	       		unsigned int start_addr,
			unsigned int end_addr,
			ipmi_bmc_cb  done_handler,
			void         *cb_data)
{
    mc_ipmb_scan_info_t *info;
    int                 rv;

    CHECK_MC_LOCK(bmc);

    info = malloc(sizeof(*info));
    if (!info)
	return;

    info->bmc = bmc;
    info->addr.addr_type = IPMI_IPMB_BROADCAST_ADDR_TYPE;
    info->addr.channel = channel;
    info->addr.slave_addr = start_addr;
    info->addr.lun = 0;
    info->msg.netfn = IPMI_APP_NETFN;
    info->msg.cmd = IPMI_GET_DEVICE_ID_CMD;
    info->msg.data = NULL;
    info->msg.data_len = 0;
    info->end_addr = end_addr;
    info->done_handler = done_handler;
    info->cb_data = cb_data;
    rv = bmc->bmc->conn->send_command(bmc->bmc->conn,
				      (ipmi_addr_t *) &(info->addr),
				      sizeof(info->addr),
				      &(info->msg),
				      devid_bc_rsp_handler,
				      info, NULL, NULL);

    while ((rv) && (info->addr.slave_addr < end_addr)) {
	info->addr.slave_addr += 2;
	rv = bmc->bmc->conn->send_command(bmc->bmc->conn,
					  (ipmi_addr_t *) &(info->addr),
					  sizeof(info->addr),
					  &(info->msg),
					  devid_bc_rsp_handler,
					  info, NULL, NULL);
    }

    if (rv)
	free(info);
}

static void
mc_scan_done(ipmi_mc_t *bmc, int err, void *cb_data)
{
    bmc->bmc->scanning_bus = 0;
}

static void
start_mc_scan(ipmi_mc_t *bmc)
{
    int i;

    if (!bmc->bmc->do_bus_scan)
	return;

    if (bmc->bmc->scanning_bus)
	return;

    bmc->bmc->scanning_bus = 1;

    for (i=0; i<MAX_IPMI_USED_CHANNELS; i++) {
	if (bmc->bmc->chan[i].medium == 1) /* IPMB */
	    ipmi_start_ipmb_mc_scan(bmc, i, 0x10, 0xf0, mc_scan_done, NULL);
    }
}

static void
bmc_rescan_bus(void *cb_data, os_hnd_timer_id_t *id)
{
    struct timeval        timeout;
    bmc_rescan_bus_info_t *info = cb_data;
    ipmi_mc_t             *bmc = info->bmc;

    if (info->cancelled) {
	free(info);
	return;
    }

    /* Rescan all the presence sensors to make sure they are valid. */
    ipmi_detect_bmc_presence_changes(bmc, 1);

    ipmi_lock(bmc->bmc->mc_list_lock);
    start_mc_scan(bmc);
    timeout.tv_sec = IPMI_RESCAN_BUS_INTERVAL;
    timeout.tv_usec = 0;
    bmc->bmc->conn->os_hnd->start_timer(bmc->bmc->conn->os_hnd,
					id,
					&timeout,
					bmc_rescan_bus,
					info);
    ipmi_unlock(bmc->bmc->mc_list_lock);
}

static void
set_operational(ipmi_mc_t *mc)
{
    struct timeval        timeout;
    bmc_rescan_bus_info_t *info;
    int                   rv;

    /* Report this before we start scanning for entities and
       sensors so the user can register a callback handler for
       those. */
    mc->bmc->state = OPERATIONAL;
    if (mc->bmc->conn->setup_cb)
	mc->bmc->conn->setup_cb(mc, mc->bmc->conn->setup_cb_data, 0);

    /* Call the OEM setup finish if it is registered. */
    if (mc->bmc->setup_finished_handler)
	mc->bmc->setup_finished_handler(mc,
					mc->bmc->setup_finished_cb_data);

    /* Start an SDR scan. */
    ipmi_entity_scan_sdrs(mc->bmc->entities, mc->bmc->main_sdrs);
    ipmi_sensor_handle_sdrs(mc, NULL, mc->bmc->main_sdrs);

    /* Scan all the sensors and call sensors_reread() when done. */
    ipmi_mc_reread_sensors(mc, sensors_reread, NULL);
    start_mc_scan(mc);

    /* Start the timer to rescan the bus periodically. */
    info = malloc(sizeof(*info));
    if (!info)
	rv = ENOMEM;
    else {
	info->bmc = mc;
	info->cancelled = 0;
        timeout.tv_sec = IPMI_RESCAN_BUS_INTERVAL;
        timeout.tv_usec = 0;
        rv = mc->bmc->conn->os_hnd->alloc_timer(mc->bmc->conn->os_hnd,
						&(mc->bmc->bus_scan_timer));
	if (!rv) {
	    rv = mc->bmc->conn->os_hnd->start_timer(mc->bmc->conn->os_hnd,
						    mc->bmc->bus_scan_timer,
						    &timeout,
						    bmc_rescan_bus,
						    info);
	    if (rv)
		mc->bmc->conn->os_hnd->free_timer(mc->bmc->conn->os_hnd,
						  mc->bmc->bus_scan_timer);
	}
    }
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "Unable to start the bus scan timer."
		 " The bus will not be scanned periodically.");
    } else {
	mc->bmc->bus_scan_timer_info = info;
    }
}

static void
chan_info_rsp_handler(ipmi_mc_t  *mc,
		      ipmi_msg_t *rsp,
		      void       *rsp_data)
{
    int  rv = 0;
    long curr = (long) rsp_data;

    if (rsp->data[0] != 0) {
	rv = IPMI_IPMI_ERR_VAL(rsp->data[0]);
    } else if (rsp->data_len < 8) {
	rv = EINVAL;
    }

    if (rv) {
	/* Got an error, could be out of channels. */
	if (curr == 0) {
	    /* Didn't get any channels, just set up a default channel
	       zero and IPMB. */
	    mc->bmc->chan[0].medium = 1; /* IPMB */
	    mc->bmc->chan[0].xmit_support = 1;
	    mc->bmc->chan[0].recv_lun = 0;
	    mc->bmc->chan[0].protocol = 1; /* IPMB */
	    mc->bmc->chan[0].session_support = 0; /* Session-less */
	    mc->bmc->chan[0].vendor_id = 0x001bf2;
	    mc->bmc->chan[0].aux_info = 0;
	}
	goto chan_info_done;
    }

    /* Get the info from the channel info response. */
    mc->bmc->chan[curr].medium = rsp->data[2] & 0x7f;
    mc->bmc->chan[curr].xmit_support = rsp->data[2] >> 7;
    mc->bmc->chan[curr].recv_lun = (rsp->data[2] >> 4) & 0x7;
    mc->bmc->chan[curr].protocol = rsp->data[3] & 0x1f;
    mc->bmc->chan[curr].session_support = rsp->data[4] >> 6;
    mc->bmc->chan[curr].vendor_id = (rsp->data[5]
				     || (rsp->data[6] << 8)
				     || (rsp->data[7] << 16));
    mc->bmc->chan[curr].aux_info = rsp->data[8] | (rsp->data[9] << 8);

    curr++;
    if (curr < MAX_IPMI_USED_CHANNELS) {
	ipmi_msg_t    cmd_msg;
	unsigned char cmd_data[1];

	cmd_msg.netfn = IPMI_APP_NETFN;
	cmd_msg.cmd = IPMI_GET_CHANNEL_INFO_CMD;
	cmd_msg.data = cmd_data;
	cmd_msg.data_len = 1;
	cmd_data[0] = curr;

	rv = ipmi_send_command(mc, 0 ,&cmd_msg, chan_info_rsp_handler,
			       (void *) curr);
    } else {
	goto chan_info_done;
    }

    if (rv) {
	if (mc->bmc->conn->setup_cb)
	    mc->bmc->conn->setup_cb(mc, mc->bmc->conn->setup_cb_data, rv);
	ipmi_close_connection(mc, NULL, NULL);
	return;
    }

    return;

 chan_info_done:
    mc->bmc->msg_int_type = 0xff;
    mc->bmc->event_msg_int_type = 0xff;

    set_operational(mc);
}

static int
finish_mc_handling(ipmi_mc_t *mc)
{
    int major, minor;
    int rv = 0;

    major = ipmi_mc_major_version(mc);
    minor = ipmi_mc_minor_version(mc);
    if ((major > 1) || ((major == 1) && (minor >= 5))) {
	ipmi_msg_t    cmd_msg;
	unsigned char cmd_data[1];

	mc->bmc->state = QUERYING_CHANNEL_INFO;

	/* IPMI 1.5 or later, use a get channel command. */
	cmd_msg.netfn = IPMI_APP_NETFN;
	cmd_msg.cmd = IPMI_GET_CHANNEL_INFO_CMD;
	cmd_msg.data = cmd_data;
	cmd_msg.data_len = 1;
	cmd_data[0] = 0;

	rv = ipmi_send_command(mc, 0, &cmd_msg, chan_info_rsp_handler,
			       (void *) 0);
    } else {
	ipmi_sdr_t sdr;

	/* Get the channel info record. */
	rv = ipmi_get_sdr_by_type(mc->bmc->main_sdrs, 0x14, &sdr);
	if (rv)
	    /* Maybe it's in the device SDRs. */
	    rv = ipmi_get_sdr_by_type(mc->sdrs, 0x14, &sdr);

	if (rv) {
	    /* Add a dummy channel zero and finish. */
	    mc->bmc->chan[0].medium = 1; /* IPMB */
	    mc->bmc->chan[0].xmit_support = 1;
	    mc->bmc->chan[0].recv_lun = 0;
	    mc->bmc->chan[0].protocol = 1; /* IPMB */
	    mc->bmc->chan[0].session_support = 0; /* Session-less */
	    mc->bmc->chan[0].vendor_id = 0x001bf2;
	    mc->bmc->chan[0].aux_info = 0;
	    mc->bmc->msg_int_type = 0xff;
	    mc->bmc->event_msg_int_type = 0xff;
	    rv = 0;
	} else {
	    int i;

	    for (i=0; i<MAX_IPMI_USED_CHANNELS; i++) {
		int protocol = sdr.data[i] & 0xf;
		
		if (protocol != 0) {
		    mc->bmc->chan[i].medium = 1; /* IPMB */
		    mc->bmc->chan[i].xmit_support = 1;
		    mc->bmc->chan[i].recv_lun = 0;
		    mc->bmc->chan[i].protocol = protocol;
		    mc->bmc->chan[i].session_support = 0; /* Session-less */
		    mc->bmc->chan[i].vendor_id = 0x001bf2;
		    mc->bmc->chan[i].aux_info = 0;
		}
	    }
	    mc->bmc->msg_int_type = sdr.data[8];
	    mc->bmc->event_msg_int_type = sdr.data[9];
	}

	set_operational(mc);
    }

    return rv;
}

static void
sdr_handler(ipmi_sdr_info_t *sdrs,
	    int             err,
	    int             changed,
	    unsigned int    count,
	    void            *cb_data)
{
    ipmi_mc_t  *mc = (ipmi_mc_t *) cb_data;
    int        rv;

    if (err) {
	rv = err;
	goto out_err;
    }

    if ((mc->bmc->state == QUERYING_MAIN_SDRS) 
	&& (mc->provides_device_sdrs))
    {
	/* Got the main SDRs, now get the device SDRs. */
	mc->bmc->state = QUERYING_SENSOR_SDRS;

	rv = ipmi_sdr_fetch(mc->sdrs, sdr_handler, mc);
	if (rv)
	    goto out_err;
	return;
    }

    rv = finish_mc_handling(mc);
    if (rv)
	goto out_err;

    return;

 out_err:
    if (mc->bmc->conn->setup_cb)
	mc->bmc->conn->setup_cb(mc, mc->bmc->conn->setup_cb_data, rv);
    ipmi_close_connection(mc, NULL, NULL);
}

static void
dev_id_rsp_handler(ipmi_mc_t  *mc,
		   ipmi_msg_t *rsp,
		   void       *rsp_data)
{
    int rv;

    rv = ipmi_mc_validate(mc);
    if (rv)
	goto out;

    ipmi_lock(mc->bmc_mc->bmc->mc_list_lock);

    rv = get_device_id_data_from_rsp(mc, rsp);

    mc->bmc->state = QUERYING_MAIN_SDRS;

    if (!rv)
	rv = ipmi_sdr_info_alloc(mc, 0, 0, &mc->bmc->main_sdrs);
    if (!rv)
	rv = ipmi_sdr_info_alloc(mc, 0, 1, &mc->sdrs);
    if (!rv) {
	if (mc->SDR_repository_support)
	    rv = ipmi_sdr_fetch(mc->bmc->main_sdrs, sdr_handler, mc);
	else if (mc->sensor_device_support) {
	    mc->bmc->state = QUERYING_SENSOR_SDRS;
	    rv = ipmi_sdr_fetch(mc->sdrs, sdr_handler, mc);
	} else {
	    rv = finish_mc_handling(mc);
	}
    }

 out:
    ipmi_unlock(mc->bmc_mc->bmc->mc_list_lock);

    if (rv) {
	if (mc->bmc->conn->setup_cb)
	    mc->bmc->conn->setup_cb(mc, mc->bmc->conn->setup_cb_data, rv);
	ipmi_lock(mc->bmc_mc->bmc->mc_list_lock);
	ipmi_close_connection(mc, NULL, NULL);
	ipmi_unlock(mc->bmc_mc->bmc->mc_list_lock);
	return;
    }
}

static int
setup_bmc(ipmi_con_t  *ipmi,
	  ipmi_addr_t *mc_addr,
	  int         mc_addr_len,
	  ipmi_mc_t   **new_mc)
{
    ipmi_mc_t *mc;
    int       rv;

    if (mc_addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    mc = malloc(sizeof(*mc));
    if (!mc)
	return ENOMEM;
    memset(mc, 0, sizeof(*mc));

    mc->bmc_mc = mc;

    mc->bmc = NULL;
    mc->sensors = NULL;
    mc->sensors_in_my_sdr = NULL;
    mc->sensors_in_my_sdr_count = 0;
    mc->controls = NULL;
    mc->new_sensor_handler = NULL;

    memcpy(&(mc->addr), mc_addr, mc_addr_len);
    mc->addr_len = mc_addr_len;
    mc->sdrs = NULL;

    mc->bmc = malloc(sizeof(*(mc->bmc)));
    if (! (mc->bmc)) {
	rv = ENOMEM;
	goto out_err;
    }
    memset(mc->bmc, 0, sizeof(*(mc->bmc)));

    mc->bmc->conn = ipmi;

    /* Create the locks before anything else. */
    mc->bmc->mc_list_lock = NULL;
    mc->bmc->entities_lock = NULL;
    mc->bmc->event_handlers_lock = NULL;

    rv = ipmi_create_lock(mc, &mc->bmc->mc_list_lock);
    if (rv)
	goto out_err;
    /* Lock this first thing. */
    ipmi_lock(mc->bmc->mc_list_lock);

    rv = ipmi_create_lock(mc, &mc->bmc->entities_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock(mc, &mc->bmc->event_handlers_lock);
    if (rv)
	goto out_err;

    mc->bmc->main_sdrs = NULL;
    mc->bmc->scanning_bus = 0;
    mc->bmc->event_handlers = NULL;
    mc->bmc->oem_event_handler = NULL;
    mc->bmc->mc_list = NULL;
    mc->bmc->entities = NULL;
    mc->bmc->sel = NULL;
    mc->bmc->entity_handler = NULL;
    mc->bmc->new_entity_handler = NULL;
    mc->bmc->new_mc_handler = NULL;
    mc->bmc->setup_finished_handler = NULL;
    mc->bmc->do_bus_scan = 1;

    mc->bmc->mc_list = alloc_ilist();
    if (! mc->bmc->mc_list) {
	rv = ENOMEM;
	goto out_err;
    }

    rv = ipmi_entity_info_alloc(mc, &(mc->bmc->entities));
    if (rv)
	goto out_err;

    rv = ipmi_sel_alloc(mc, 0, &(mc->bmc->sel));
    if (rv)
	goto out_err;
    /* When we get new logs, handle them. */
    ipmi_sel_set_new_event_handler(mc->bmc->sel,
				   bmc_sel_new_event_handler,
				   mc);

    rv = ipmi_sensors_alloc(mc, &(mc->sensors));
    if (rv)
	goto out_err;

    rv = ipmi_controls_alloc(mc, &(mc->controls));
    if (rv)
	goto out_err;

    memset(mc->bmc->chan, 0, sizeof(mc->bmc->chan));

 out_err:
    if (mc->bmc->mc_list_lock)
	ipmi_unlock(mc->bmc->mc_list_lock);

    if (rv) {
	ipmi_cleanup_mc(mc);
    }
    else
	*new_mc = mc;

    return rv;
}

int
ipmi_init_con(ipmi_con_t  *ipmi,
	      ipmi_addr_t *mc_addr,
	      int         mc_addr_len)
{
    ipmi_msg_t cmd_msg;
    int        rv = 0;
    ipmi_mc_t  *mc;

    rv = setup_bmc(ipmi, mc_addr, mc_addr_len, &mc);
    if (rv)
	return rv;

    ipmi_lock(mc->bmc_mc->bmc->mc_list_lock);

    cmd_msg.netfn = IPMI_APP_NETFN;
    cmd_msg.cmd = IPMI_GET_DEVICE_ID_CMD;
    cmd_msg.data_len = 0;

    rv = ipmi_send_command(mc, 0, &cmd_msg, dev_id_rsp_handler, NULL);
    if (rv)
	goto close_and_quit;

    mc->bmc->state = QUERYING_DEVICE_ID;

 close_and_quit:
    if (rv)
	ipmi_close_connection(mc, NULL, NULL);

    ipmi_unlock(mc->bmc_mc->bmc->mc_list_lock);

    return rv;
}

int
ipmi_detect_bmc_presence_changes(ipmi_mc_t *mc, int force)
{
    int rv;
    CHECK_MC_LOCK(mc);
    
    ipmi_mc_entity_lock(mc);
    rv = ipmi_detect_ents_presence_changes(mc->bmc_mc->bmc->entities, force);
    ipmi_mc_entity_unlock(mc);
    return rv;
}

int
ipmi_mc_provides_device_sdrs(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->provides_device_sdrs;
}

int
ipmi_mc_device_available(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->device_available;
}

int
ipmi_mc_chassis_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->chassis_support;
}

int
ipmi_mc_bridge_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->bridge_support;
}

int
ipmi_mc_ipmb_event_generator_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->IPMB_event_generator_support;
}

int
ipmi_mc_ipmb_event_receiver_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->IPMB_event_receiver_support;
}

int
ipmi_mc_fru_inventory_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->FRU_inventory_support;
}

int
ipmi_mc_sel_device_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->SEL_device_support;
}

void
ipmi_mc_set_sel_device_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    mc->SEL_device_support = val;
}

int
ipmi_mc_sdr_repository_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->SDR_repository_support;
}

int
ipmi_mc_sensor_device_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->sensor_device_support;
}

int
ipmi_mc_device_id(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->device_id;
}

int
ipmi_mc_device_revision(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->device_revision;
}

int
ipmi_mc_major_fw_revision(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->major_fw_revision;
}

int
ipmi_mc_minor_fw_revision(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->minor_fw_revision;
}

int
ipmi_mc_major_version(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->major_version;
}

int
ipmi_mc_minor_version(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->minor_version;
}

int
ipmi_mc_manufacturer_id(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->manufacturer_id;
}

int
ipmi_mc_product_id(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->product_id;
}

void
ipmi_mc_aux_fw_revision(ipmi_mc_t *mc, unsigned char val[])
{
    CHECK_MC_LOCK(mc);
    memcpy(val, mc->aux_fw_revision, sizeof(mc->aux_fw_revision));
}

void *
ipmi_get_user_data(ipmi_mc_t *mc)
{
    ipmi_con_t *ipmi;

    CHECK_MC_LOCK(mc);
    ipmi = mc->bmc_mc->bmc->conn;
    return ipmi->user_data;
}

void
ipmi_mc_set_oem_data(ipmi_mc_t *mc, void *data)
{
    CHECK_MC_LOCK(mc);
    mc->oem_data = data;
}

void *
ipmi_mc_get_oem_data(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->oem_data;
}

int
ipmi_bmc_get_num_channels(ipmi_mc_t *mc, int *val)
{
    CHECK_MC_LOCK(mc);

    /* Make sure it's an SMI mc. */
    if (mc->bmc_mc != mc)
	return EINVAL;

    *val = MAX_IPMI_USED_CHANNELS;
    return 0;
}

int
ipmi_bmc_get_channel(ipmi_mc_t *mc, int index, ipmi_chan_info_t *chan)
{
    CHECK_MC_LOCK(mc);

    /* Make sure it's an SMI mc. */
    if (mc->bmc_mc != mc)
	return EINVAL;

    if (index >= MAX_IPMI_USED_CHANNELS)
	return EINVAL;

    *chan = mc->bmc->chan[index];
    return 0;
}

os_handler_t *
ipmi_mc_get_os_hnd(ipmi_mc_t *mc)
{
    if (mc->bmc_mc->bmc->mc_list_lock)
	CHECK_MC_LOCK(mc);
    return mc->bmc_mc->bmc->conn->os_hnd;
}

ipmi_entity_info_t *
ipmi_mc_get_entities(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->bmc_mc->bmc->entities;
}

void
ipmi_mc_entity_lock(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->bmc_mc->bmc->entities_lock);
}

void
ipmi_mc_entity_unlock(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    ipmi_unlock(mc->bmc_mc->bmc->entities_lock);
}

ipmi_sensor_info_t *
ipmi_mc_get_sensors(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->sensors;
}

ipmi_control_info_t *
ipmi_mc_get_controls(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->controls;
}

void
ipmi_mc_get_sdr_sensors(ipmi_mc_t     *bmc,
			ipmi_mc_t     *mc,
			ipmi_sensor_t ***sensors,
			unsigned int  *count)
{
    if (mc) {
	CHECK_MC_LOCK(mc);
	*sensors = mc->sensors_in_my_sdr;
	*count = mc->sensors_in_my_sdr_count;
    } else {
	CHECK_MC_LOCK(bmc);
	*sensors = bmc->bmc->sensors_in_my_sdr;
	*count = bmc->bmc->sensors_in_my_sdr_count;
    }
}

void
ipmi_mc_set_sdr_sensors(ipmi_mc_t     *bmc,
			ipmi_mc_t     *mc,
			ipmi_sensor_t **sensors,
			unsigned int  count)
{
    if (mc) {
	CHECK_MC_LOCK(mc);
	mc->sensors_in_my_sdr = sensors;
	mc->sensors_in_my_sdr_count = count;
    } else {
	CHECK_MC_LOCK(bmc);
	bmc->bmc->sensors_in_my_sdr = sensors;
	bmc->bmc->sensors_in_my_sdr_count = count;
    }
}

ipmi_sdr_info_t *
ipmi_mc_get_sdrs(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->sdrs;
}

unsigned int
ipmi_mc_get_address(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    if (mc->addr.addr_type == IPMI_IPMB_ADDR_TYPE) {
	ipmi_ipmb_addr_t *ipmb_addr = (ipmi_ipmb_addr_t *) &(mc->addr);
	return ipmb_addr->slave_addr;
    }

    /* Address is ignore for other types. */
    return 0;
}

unsigned int
ipmi_mc_get_channel(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->addr.channel;
}

int
ipmi_bmc_set_entity_update_handler(ipmi_mc_t          *bmc,
				   ipmi_bmc_entity_cb handler,
				   void               *cb_data)
{
    CHECK_MC_LOCK(bmc);

    /* Make sure it's an SMI mc. */
    if (bmc->bmc_mc != bmc)
	return EINVAL;

    return ipmi_entity_set_update_handler(bmc->bmc->entities,
					  handler,
					  cb_data);
}

int
ipmi_bmc_iterate_entities(ipmi_mc_t                       *bmc,
			  ipmi_entities_iterate_entity_cb handler,
			  void                            *cb_data)
{
    CHECK_MC_LOCK(bmc);
    ipmi_mc_entity_lock(bmc);
    ipmi_entities_iterate_entities(bmc->bmc->entities, handler, cb_data);
    ipmi_mc_entity_unlock(bmc);
    return 0;
}

typedef struct iterate_mc_info_s
{
    ipmi_mc_t               *bmc;
    ipmi_bmc_iterate_mcs_cb handler;
    void                    *cb_data;
} iterate_mc_info_t;

static void
iterate_mcs_handler(ilist_iter_t *iter, void *item, void *cb_data)
{
    iterate_mc_info_t *info = cb_data;
    info->handler(info->bmc, item, info->cb_data);
}

int
ipmi_bmc_iterate_mcs(ipmi_mc_t               *bmc,
		     ipmi_bmc_iterate_mcs_cb handler,
		     void                    *cb_data)
{
    iterate_mc_info_t info = { bmc, handler, cb_data };

    if (bmc->bmc == NULL)
	/* Not a BMC */
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    ipmi_lock(bmc->bmc->mc_list_lock);
    ilist_iter(bmc->bmc->mc_list, iterate_mcs_handler, &info);
    ipmi_unlock(bmc->bmc->mc_list_lock);
    return 0;
}

ipmi_mc_id_t
ipmi_mc_convert_to_id(ipmi_mc_t *mc)
{
    ipmi_mc_id_t val;

    CHECK_MC_LOCK(mc);

    val.bmc = mc->bmc_mc;
    val.channel = mc->addr.channel;
    if (mc->addr.addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	/* The BMC address is always zero. */
	val.mc_num = 0;
    } else {
	ipmi_ipmb_addr_t *ipmb = (ipmi_ipmb_addr_t *) &(mc->addr);
	val.mc_num = ipmb->slave_addr;
    }
    return val;
}

int
ipmi_mc_pointer_cb(ipmi_mc_id_t id, ipmi_mc_cb handler, void *cb_data)
{
    int       rv;

    ipmi_read_lock();
    rv = ipmi_mc_validate(id.bmc);
    if (rv)
	goto out_unlock;
    ipmi_lock(id.bmc->bmc->mc_list_lock);
    if (id.mc_num == 0) {
	handler(id.bmc, cb_data);
    } else {
	ipmi_ipmb_addr_t ipmb = {IPMI_IPMB_ADDR_TYPE, id.channel,
				 id.mc_num, 0};
	ipmi_mc_t *mc;
	mc = find_mc_by_addr(id.bmc, (ipmi_addr_t *) &ipmb, sizeof(ipmb));
	if (!mc)
	    rv = EINVAL;
	else
	/* We don't have a lock for the mc itself, we rely on the BMC lock
	   for this right now. */
	    handler(mc, cb_data);
    }
    ipmi_unlock(id.bmc->bmc->mc_list_lock);
 out_unlock:
    ipmi_read_unlock();

    return rv;
}

typedef struct sdrs_saved_info_s
{
    ipmi_mc_t   *bmc;
    ipmi_bmc_cb done;
    void        *cb_data;
} sdrs_saved_info_t;

static void
sdrs_saved(ipmi_sdr_info_t *sdrs, int err, void *cb_data)
{
    sdrs_saved_info_t *info = cb_data;

    info->done(info->bmc, err, info->cb_data);
    free(info);
}

int
ipmi_bmc_store_entities(ipmi_mc_t *bmc, ipmi_bmc_cb done, void *cb_data)
{
    int               rv;
    ipmi_sdr_info_t   *stored_sdrs;
    sdrs_saved_info_t *info;

    /* Make sure it's the BMC. */
    if (bmc->bmc_mc != bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    /* Create an SDR repository to store. */
    rv = ipmi_sdr_info_alloc(bmc, 0, 0, &stored_sdrs);
    if (rv) {
	free(info);
	return rv;
    }

    /* Now store a channel SDR if we are less than 1.5. */
    if ((bmc->major_version <= 1) && (bmc->minor_version < 5)) {
	ipmi_sdr_t sdr;
	int        i;
	
	sdr.major_version = bmc->major_version;
	sdr.minor_version = bmc->minor_version;
	sdr.type = 0x14; /*  */
	sdr.length = 11;
	for (i=0; i<8; i++) {
	    /* FIXME - what about the LUN and transmit support? */
	    if (bmc->bmc->chan[i].protocol) {
		sdr.data[i] = (bmc->bmc->chan[i].protocol
			       | (bmc->bmc->chan[i].xmit_support << 7)
			       | (bmc->bmc->chan[i].recv_lun << 4));
	    } else {
		sdr.data[i] = 0;
	    }
	}
	sdr.data[8] = bmc->bmc->msg_int_type;
	sdr.data[9] = bmc->bmc->event_msg_int_type;
	sdr.data[10] = 0;

	rv = ipmi_sdr_add(stored_sdrs, &sdr);
	if (rv)
	    goto out_err;
    }

    rv = ipmi_entity_append_to_sdrs(bmc->bmc->entities, stored_sdrs);
    if (rv)
	goto out_err;

    info->bmc = bmc;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sdr_save(stored_sdrs, sdrs_saved, info);

 out_err:
    if (rv)
	free(info);
    ipmi_sdr_info_destroy(stored_sdrs, NULL, NULL);
    return rv;
}

ipmi_mc_t *ipmi_mc_get_bmc(ipmi_mc_t *mc)
{
    return mc->bmc_mc;
}

int
ipmi_bmc_oem_new_sensor(ipmi_mc_t     *mc,
			ipmi_entity_t *ent,
			ipmi_sensor_t *sensor,
			void          *link)
{
    int rv = 0;

    CHECK_MC_LOCK(mc);

    ipmi_entity_lock(ent);
    if (mc->new_sensor_handler)
	rv = mc->new_sensor_handler(mc, ent, sensor, link,
				    mc->new_sensor_cb_data);
    ipmi_entity_unlock(ent);
    return rv;
}

int
ipmi_mc_set_oem_new_sensor_handler(ipmi_mc_t                 *mc,
				   ipmi_mc_oem_new_sensor_cb handler,
				   void                      *cb_data)
{
    CHECK_MC_LOCK(mc);
    mc->new_sensor_handler = handler;
    mc->new_sensor_cb_data = cb_data;
    return 0;
}

void
ipmi_bmc_oem_new_entity(ipmi_mc_t *bmc, ipmi_entity_t *ent)
{
    CHECK_MC_LOCK(bmc);

    ipmi_entity_lock(ent);
    if (bmc->bmc->new_entity_handler)
	bmc->bmc->new_entity_handler(bmc, ent,
				     bmc->bmc->new_entity_cb_data);
    ipmi_entity_unlock(ent);
}

int
ipmi_bmc_set_oem_new_entity_handler(ipmi_mc_t                  *bmc,
				    ipmi_bmc_oem_new_entity_cb handler,
				    void                       *cb_data)
{
    /* Make sure it's an SMI mc. */
    if (bmc->bmc_mc != bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    bmc->bmc->new_entity_handler = handler;
    bmc->bmc->new_entity_cb_data = cb_data;
    return 0;
}

int
ipmi_bmc_set_oem_new_mc_handler(ipmi_mc_t              *bmc,
				ipmi_bmc_oem_new_mc_cb handler,
				void                   *cb_data)
{
    /* Make sure it's an SMI mc. */
    if (bmc->bmc_mc != bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    bmc->bmc->new_mc_handler = handler;
    bmc->bmc->new_mc_cb_data = cb_data;
    return 0;
}

int
ipmi_bmc_set_full_bus_scan(ipmi_mc_t *bmc, int val)
{
    /* Make sure it's an SMI mc. */
    if (bmc->bmc_mc != bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    bmc->bmc->do_bus_scan = val;
    return 0;
}

int
ipmi_bmc_set_oem_setup_finished_handler(ipmi_mc_t                  *bmc,
					ipmi_oem_setup_finished_cb handler,
					void                       *cb_data)
{
    /* Make sure it's an SMI mc. */
    if (bmc->bmc_mc != bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    bmc->bmc->setup_finished_handler = handler;
    bmc->bmc->setup_finished_cb_data = cb_data;
    return 0;
}

typedef struct sel_op_done_info_s
{
    ipmi_mc_t   *bmc;
    ipmi_bmc_cb done;
    void        *cb_data;
} sel_op_done_info_t;

static void
sel_op_done(ipmi_sel_info_t *sel,
	    void            *cb_data,
	    int             err)
{
    sel_op_done_info_t *info = cb_data;

    /* No need to lock, the BMC should already be locked. */
    if (info->done)
        info->done(info->bmc, err, info->cb_data);
}

int
ipmi_bmc_del_event(ipmi_mc_t    *bmc,
		   ipmi_event_t *event,
		   ipmi_bmc_cb  done_handler,
		   void         *cb_data)
{
    sel_op_done_info_t *info;

    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    /* If we have an OEM handler, call it instead. */
    if (bmc->bmc->sel_del_event_handler)
	return bmc->bmc->sel_del_event_handler(bmc, event,
					       done_handler, cb_data);

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->bmc = bmc;
    info->done = done_handler;
    info->cb_data = cb_data;

    return ipmi_sel_del_event(bmc->bmc->sel, event, sel_op_done, info);
}

int
ipmi_bmc_del_event_by_recid(ipmi_mc_t    *bmc,
			    unsigned int record_id,
			    ipmi_bmc_cb  done_handler,
			    void         *cb_data)
{
    sel_op_done_info_t *info;

    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    info = malloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->bmc = bmc;
    info->done = done_handler;
    info->cb_data = cb_data;

    return ipmi_sel_del_event_by_recid(bmc->bmc->sel, record_id,
				       sel_op_done, info);
}

int
ipmi_bmc_first_event(ipmi_mc_t *bmc, ipmi_event_t *event)
{
    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    return ipmi_sel_get_first_event(bmc->bmc->sel, event);
}

int
ipmi_bmc_last_event(ipmi_mc_t *bmc, ipmi_event_t *event)
{
    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    return ipmi_sel_get_last_event(bmc->bmc->sel, event);
}

int
ipmi_bmc_next_event(ipmi_mc_t *bmc, ipmi_event_t *event)
{
    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    return ipmi_sel_get_next_event(bmc->bmc->sel, event);
}

int
ipmi_bmc_prev_event(ipmi_mc_t *bmc, ipmi_event_t *event)
{
    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    return ipmi_sel_get_prev_event(bmc->bmc->sel, event);
}

#ifdef IPMI_CHECK_LOCKS
void
__ipmi_check_mc_lock(ipmi_mc_t *mc)
{
    ipmi_check_lock(mc->bmc_mc->bmc->mc_list_lock,
		    "MC not locked when it should have been");
}

void
__ipmi_check_mc_entity_lock(ipmi_mc_t *mc)
{
    ipmi_check_lock(mc->bmc_mc->bmc->entities_lock,
		    "Entity not locked when it should have been");
}
#endif
