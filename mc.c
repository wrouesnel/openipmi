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

/* Rescan the bus for MCs every 10 minutes by default. */
#define IPMI_RESCAN_BUS_INTERVAL 600

/* Re-query the SEL every 10 seconds by default. */
#define IPMI_SEL_QUERY_INTERVAL 10

/* This is the number of device ID queries that an MC must not respond
   to in a row to be considered dead. */
#define MAX_MC_MISSED_RESPONSES 10

enum ipmi_con_state_e { DEAD = 0,
			QUERYING_DEVICE_ID,
			QUERYING_MAIN_SDRS,
			QUERYING_SENSOR_SDRS,
			QUERYING_CHANNEL_INFO,
			OPERATIONAL };

#define MAX_IPMI_USED_CHANNELS 8

/* Timer structure fo rereading the SEL. */
typedef struct mc_reread_sel_s
{
    int cancelled;
    ipmi_mc_t *mc;
} mc_reread_sel_t;
    
/* Timer structure fo rescanning the bus. */
typedef struct bmc_rescan_bus_info_s
{
    int       cancelled;
    ipmi_mc_t *bmc;
} bmc_rescan_bus_info_t;

struct ipmi_bmc_con_fail_s
{
    ipmi_bmc_cb handler;
    void        *cb_data;
};

/* Used to keep a record of a bus scan. */
typedef struct mc_ipbm_scan_info_s mc_ipmb_scan_info_t;
struct mc_ipbm_scan_info_s
{
    ipmi_ipmb_addr_t addr;
    ipmi_mc_t        *bmc;
    ipmi_msg_t       msg;
    unsigned int     end_addr;
    ipmi_bmc_cb      done_handler;
    void             *cb_data;
    mc_ipmb_scan_info_t *next;
};

typedef struct ipmi_bmc_s
{
    /* The main set of SDRs on a BMC. */
    ipmi_sdr_info_t *main_sdrs;

    enum ipmi_con_state_e state;

    ipmi_chan_info_t chan[MAX_IPMI_USED_CHANNELS];
    unsigned char    msg_int_type;
    unsigned char    event_msg_int_type;

    /* This is the actual address of the BMC. */
    unsigned char bmc_slave_addr;
    ipmi_mc_slave_addr_fetch_cb slave_addr_fetcher;

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

    ipmi_bmc_oem_new_entity_cb new_entity_handler;
    void                       *new_entity_cb_data;

    ipmi_bmc_oem_new_mc_cb     new_mc_handler;
    void                       *new_mc_cb_data;

    ipmi_oem_setup_finished_cb setup_finished_handler;
    void                       *setup_finished_cb_data;

    /* Should I do a full bus scan for devices on the bus? */
    int                        do_bus_scan;

    /* Timer for rescanning the bus periodically. */
    unsigned int          bus_scan_interval; /* seconds between scans */
    os_hnd_timer_id_t     *bus_scan_timer;
    bmc_rescan_bus_info_t *bus_scan_timer_info;

    /* This is a list of all the bus scans currently happening, so
       they can be properly freed. */
    mc_ipmb_scan_info_t *bus_scans_running;

    unsigned int      sel_scan_interval; /* seconds between SEL scans */

    ilist_t *con_fail_handlers;

    /* A list of IPMB addresses to not scan. */
    ilist_t *ipmb_ignores;

    /* Is the low-level connection up? */
    int connection_up;

    ipmi_bmc_cb setup_done;
    void        *setup_done_cb_data;

} ipmi_bmc_t;

struct ipmi_mc_s
{
    ipmi_mc_t   *bmc_mc; /* Pointer to the MC that is the BMC. */
    ipmi_addr_t addr;
    int         addr_len;

    /* If the MC is known to be good in the system, then active is
       true.  If active is false, that means that there are sensors
       that refer to this MC, but the MC is not currently in the
       system. */
    int active;

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

    unsigned int in_bmc_list : 1; /* Tells if we are in the list of
                                     our BMC yet. */

    /* The system event log, for querying and storing events. */
    ipmi_sel_info_t *sel;

    /* The handler to call for delete event operations.  This is NULL
       normally and is only used if the MC has a special delete event
       handler. */
    ipmi_mc_del_event_cb sel_del_event_handler;

    /* Timer for rescanning the sel periodically. */
    os_hnd_timer_id_t *sel_timer;
    mc_reread_sel_t   *sel_timer_info;

    /* The SEL time when the connection first came up. */
    unsigned long startup_SEL_time;


    /* This is a retry count for missed pings from an MC query. */
    int missed_responses;

    void *oem_data;

    ipmi_mc_oem_new_sensor_cb new_sensor_handler;
    void                      *new_sensor_cb_data;

    ipmi_oem_event_handler_cb oem_event_handler;
    void                      *oem_event_handler_cb_data;

    ipmi_mc_oem_removed_cb removed_mc_handler;
    void                   *removed_mc_cb_data;

    /* The rest is the actual data from the SDRs.  There's the real
       version and the normal version, the real version is the one
       from the get device id response, the normal version may have
       been adjusted by the OEM code. */

    uint8_t device_id;

    uint8_t device_revision;

    unsigned int provides_device_sdrs : 1;
    unsigned int device_available : 1;

    unsigned int chassis_support : 1;
    unsigned int bridge_support : 1;
    unsigned int IPMB_event_generator_support : 1;
    unsigned int IPMB_event_receiver_support : 1;
    unsigned int FRU_inventory_support : 1;
    unsigned int SEL_device_support : 1;
    unsigned int SDR_repository_support : 1;
    unsigned int sensor_device_support : 1;

    uint8_t major_fw_revision;
    uint8_t minor_fw_revision;

    uint8_t major_version;
    uint8_t minor_version;

    uint32_t manufacturer_id;
    uint16_t product_id;

    uint8_t  aux_fw_revision[4];

    uint8_t real_device_id;

    uint8_t real_device_revision;

    unsigned int real_provides_device_sdrs : 1;
    unsigned int real_device_available : 1;

    unsigned int real_chassis_support : 1;
    unsigned int real_bridge_support : 1;
    unsigned int real_IPMB_event_generator_support : 1;
    unsigned int real_IPMB_event_receiver_support : 1;
    unsigned int real_FRU_inventory_support : 1;
    unsigned int real_SEL_device_support : 1;
    unsigned int real_SDR_repository_support : 1;
    unsigned int real_sensor_device_support : 1;

    uint8_t real_major_fw_revision;
    uint8_t real_minor_fw_revision;

    uint8_t real_major_version;
    uint8_t real_minor_version;

    uint32_t real_manufacturer_id;
    uint16_t real_product_id;

    uint8_t  real_aux_fw_revision[4];

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
    ipmi_oem_shutdown_handler_cb shutdown;
    void                         *cb_data;
} oem_handlers_t;
/* FIXME - do we need a lock?  Probably, add it. */
static ilist_t *oem_handlers;

static int mc_initialized = 0;

static void start_mc_scan(ipmi_mc_t *bmc);

int
ipmi_mc_init(void)
{
    if (mc_initialized)
	return 0;

    oem_handlers = alloc_ilist();
    if (!oem_handlers)
	return ENOMEM;

    mc_initialized = 1;

    return 0;
}

void
ipmi_mc_shutdown(void)
{
    if (mc_initialized) {
	oem_handlers_t *hndlr;
	ilist_iter_t   iter;

	/* Destroy the members of the OEM list. */
	ilist_init_iter(&iter, oem_handlers);
	while (ilist_first(&iter)) {
	    hndlr = ilist_get(&iter);
	    if (hndlr->shutdown)
		hndlr->shutdown(hndlr->cb_data);
	    ilist_delete(&iter);
	    ipmi_mem_free(hndlr);
	}

	free_ilist(oem_handlers);
	oem_handlers = NULL;
	mc_initialized = 0;
    }
}

void
ipmi_bmc_set_sel_rescan_time(ipmi_mc_t *bmc, unsigned int seconds)
{
    CHECK_MC_LOCK(bmc);

    bmc->bmc->sel_scan_interval = seconds;
}

unsigned int
ipmi_bmc_get_sel_rescan_time(ipmi_mc_t *bmc)
{
    CHECK_MC_LOCK(bmc);

    return bmc->bmc->sel_scan_interval;
}

void
ipmi_bmc_set_ipmb_rescan_time(ipmi_mc_t *bmc, unsigned int seconds)
{
    CHECK_MC_LOCK(bmc);

    bmc->bmc->bus_scan_interval = seconds;
}

unsigned int
ipmi_bmc_get_ipmb_rescan_time(ipmi_mc_t *bmc)
{
    CHECK_MC_LOCK(bmc);

    return bmc->bmc->bus_scan_interval;
}

int
ipmi_register_oem_handler(unsigned int                 manufacturer_id,
			  unsigned int                 product_id,
			  ipmi_oem_mc_match_handler_cb handler,
			  ipmi_oem_shutdown_handler_cb shutdown,
			  void                         *cb_data)
{
    oem_handlers_t *new_item;
    int            rv;

    /* This might be called before initialization, so be 100% sure.. */
    rv = ipmi_mc_init();
    if (rv)
	return rv;

    new_item = ipmi_mem_alloc(sizeof(*new_item));
    if (!new_item)
	return ENOMEM;

    new_item->manufacturer_id = manufacturer_id;
    new_item->product_id = product_id;
    new_item->handler = handler;
    new_item->shutdown = shutdown;
    new_item->cb_data = cb_data;

    if (! ilist_add_tail(oem_handlers, new_item, NULL)) {
	ipmi_mem_free(new_item);
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

int
ipmi_deregister_oem_handler(unsigned int manufacturer_id,
			    unsigned int product_id)
{
    oem_handlers_t *hndlr;
    ilist_iter_t   iter;

    ilist_init_iter(&iter, oem_handlers);
    ilist_unpositioned(&iter);
    hndlr = ilist_search_iter(&iter, oem_handler_cmp, NULL);
    if (hndlr) {
	ilist_delete(&iter);
	ipmi_mem_free(hndlr);
	return 0;
    }
    return ENOENT;
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

int
ipmi_mc_is_active(ipmi_mc_t *mc)
{
    return mc->active;
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
    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	return bmc;
    }
    if (addr->addr_type == IPMI_IPMB_ADDR_TYPE) {
	struct ipmi_ipmb_addr *ipmb_addr = (void *) addr;

	if (ipmb_addr->slave_addr == bmc->bmc->bmc_slave_addr) {
	    return bmc;
	}

	memcpy(&(info.addr), addr, addr_len);
	info.addr_len = addr_len;
	return ilist_search(bmc->bmc->mc_list, mc_cmp, &info);
    }
    return NULL;
}

static int
in_ipmb_ignores(ipmi_mc_t *bmc, unsigned char ipmb_addr)
{
    unsigned long addr;
    ilist_iter_t iter;

    ilist_init_iter(&iter, bmc->bmc->ipmb_ignores);
    ilist_unpositioned(&iter);
    while (ilist_next(&iter)) {
	addr = (unsigned long) ilist_get(&iter);
	if (addr == ipmb_addr)
	    return 1;
    }

    return 0;
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

    if (slave_addr == bmc->bmc->bmc_slave_addr) {
	*new_mc = bmc;
	return 0;
    }

    mc = find_mc_by_addr(bmc, (ipmi_addr_t *) &addr, sizeof(addr));
    if (mc) {
	*new_mc = mc;
	return 0;
    }

    rv = ipmi_create_mc(bmc, (ipmi_addr_t *) &addr, sizeof(addr), &mc);
    if (rv)
	return rv;

    mc->active = 0;

    rv = ipmi_add_mc_to_bmc(bmc, mc);
    if (rv) {
	ipmi_cleanup_mc(mc);
	return rv;
    }

    *new_mc = mc;
    return 0;
}

int
ipmi_bmc_add_con_fail_handler(ipmi_mc_t           *bmc,
			      ipmi_bmc_cb         handler,
			      void                *cb_data,
			      ipmi_bmc_con_fail_t **id)
{
    ipmi_bmc_con_fail_t *new_id;

    if (bmc->bmc_mc != bmc)
	/* Not a BMC. */
	return EINVAL;

    new_id = ipmi_mem_alloc(sizeof(*new_id));
    if (!new_id)
	return ENOMEM;

    new_id->handler = handler;
    new_id->cb_data = cb_data;
    if (! ilist_add_tail(bmc->bmc->con_fail_handlers, new_id, NULL)) {
	ipmi_mem_free(new_id);
	return ENOMEM;
    }

    return 0;
}

int
ipmi_bmc_add_ipmb_ignore(ipmi_mc_t *bmc, unsigned char ipmb_addr)
{
    unsigned long addr = ipmb_addr;

    if (bmc->bmc_mc != bmc)
	/* Not a BMC. */
	return EINVAL;

    if (! ilist_add_tail(bmc->bmc->ipmb_ignores, (void *) addr, NULL))
	return ENOMEM;

    return 0;
}

void
ipmi_bmc_remove_con_fail_handler(ipmi_mc_t           *bmc,
				 ipmi_bmc_con_fail_t *id)
{
    ilist_iter_t iter;
    int          rv;

    if (bmc->bmc_mc != bmc)
	/* Not a BMC. */
	return;

    ilist_init_iter(&iter, bmc->bmc->con_fail_handlers);
    rv = ilist_first(&iter);
    while (rv) {
	if (ilist_get(&iter) == id) {
	    ilist_delete(&iter);
	    ipmi_mem_free(id);
	    break;
	}
	rv = ilist_next(&iter);
    }
}

typedef struct con_fail_info_s
{
    ipmi_mc_t *bmc;
    int       err;
} con_fail_info_t;

static void
iterate_con_fails(ilist_iter_t *iter, void *item, void *cb_data)
{
    con_fail_info_t     *info = cb_data;
    ipmi_bmc_con_fail_t *id = item;

    id->handler(info->bmc, info->err, id->cb_data);
}

static void
ll_con_failed(ipmi_con_t *ipmi,
	      int        err,
	      void       *cb_data)
{
    ipmi_mc_t       *bmc = cb_data;
    con_fail_info_t info = {bmc, err};
    int             rv;

    ipmi_read_lock();
    rv = ipmi_mc_validate(bmc);
    if (rv)
	/* So the connection failed.  So what, there's no BMC. */
	goto out_unlock;

    if (err)
	bmc->bmc->connection_up = 0;
    else {
	bmc->bmc->connection_up = 1;
	/* When a connection comes back up, rescan the bus and do
           entity presence detection. */
	ipmi_lock(bmc->bmc->mc_list_lock);
	start_mc_scan(bmc);
	ipmi_detect_ents_presence_changes(bmc->bmc->entities, 1);
	ipmi_unlock(bmc->bmc->mc_list_lock);
    }

    ilist_iter(bmc->bmc->con_fail_handlers, iterate_con_fails, &info);

 out_unlock:
    ipmi_read_unlock();
}

static void
ll_rsp_handler(ipmi_con_t   *ipmi,
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
	    mc = find_mc_by_addr(bmc, addr, addr_len);
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

    ipmi_mem_free(event);

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
ipmi_handle_unhandled_event(ipmi_mc_t *mc, ipmi_event_t *event)
{
    ipmi_event_handler_id_t *l;

    ipmi_lock(mc->bmc_mc->bmc->event_handlers_lock);
    l = mc->bmc_mc->bmc->event_handlers;
    while (l) {
	l->handler(mc, event, l->event_data);
	l = l->next;
    }
    ipmi_unlock(mc->bmc_mc->bmc->event_handlers_lock);
}

static void
system_event_handler(ipmi_mc_t    *mc,
		     ipmi_event_t *event)
{
    int                 rv = 1;
    ipmi_sensor_id_t    id;
    event_sensor_info_t info;
    unsigned long       timestamp;

    if (DEBUG_EVENTS) {
	ipmi_log(IPMI_LOG_DEBUG,
		 "Event recid mc (%d 0x%x):%4.4x type:%2.2x:"
		 " %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x"
		 " %2.2x %2.2x %2.2x %2.2x %2.2x",
		 event->mc_id.channel, event->mc_id.mc_num,
		 event->record_id, event->type,
		 event->data[0], event->data[1], event->data[2],
		 event->data[3], event->data[4], event->data[5],
		 event->data[6], event->data[7], event->data[8],
		 event->data[9], event->data[10], event->data[11],
		 event->data[12]);
    }

    /* Let the OEM handler have a go at it first.  Note that OEM
       handlers must look at the time themselves. */
    if (mc->bmc_mc->bmc->oem_event_handler) {
	if (mc->bmc_mc->bmc->oem_event_handler(
	    mc,
	    event,
	    mc->bmc_mc->bmc->oem_event_cb_data))
	    return;
    }

    timestamp = ipmi_get_uint32(&(event->data[0]));

    /* It's a system event record from an MC, and the timestamp is
       later than our startup timestamp. */
    if ((event->type == 0x02)
	&& ((event->data[4] & 0x01) == 0)
	&& (timestamp >= mc->startup_SEL_time))
    {
	ipmi_mc_id_t mc_id;

	info.handled = 0;
	info.err = 0;
	info.event = event;

	/* See if the MC has an OEM handler for this. */
	mc_id.bmc = mc->bmc_mc;
	if (event->data[6] == 0x03) {
	    mc_id.channel = 0;
	} else {
	    mc_id.channel = event->data[5] >> 4;
	}
	mc_id.mc_num = event->data[4];
	ipmi_mc_pointer_cb(mc_id, mc_event_cb, &info);

	if (info.handled) {
	    rv = 0;
	} else {
	    /* The OEM code didn't handle it. */
	    id.bmc = mc->bmc_mc;
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
    }

    /* It's an event from system software, or the info couldn't be found. */
    if (rv)
	ipmi_handle_unhandled_event(mc, event);
}

/* Got a new event in the system event log that we didn't have before. */
static void
mc_sel_new_event_handler(ipmi_sel_info_t *sel,
			 ipmi_event_t    *event,
			 void            *cb_data)
{
    system_event_handler(cb_data, event);
}


unsigned long
ipmi_mc_get_startup_SEL_time(ipmi_mc_t *mc)
{
    return mc->startup_SEL_time;
}

void
ipmi_mc_set_del_event_handler(ipmi_mc_t            *mc,
			      ipmi_mc_del_event_cb handler)
{
    mc->sel_del_event_handler = handler;
}

static void
mc_rescan_event_handler(ipmi_mc_t *bmc, ipmi_mc_t *mc, void *cb_data)
{
    if (mc->SEL_device_support)
	ipmi_sel_get(mc->sel, NULL, NULL);
}

int
ipmi_bmc_rescan_events(ipmi_mc_t *bmc)
{
    if (bmc->bmc == NULL)
	/* It's not the BMC. */
	return EINVAL;

    if (bmc->SEL_device_support)
	ipmi_sel_get(bmc->sel, NULL, NULL);

    return ipmi_bmc_iterate_mcs(bmc, mc_rescan_event_handler, NULL);
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

    /* Events coming in through the event handler are always from the
       BMC. */
    devent.mc_id = ipmi_mc_convert_to_id(bmc);
    devent.record_id = ipmi_get_uint16(event->data);
    devent.type = event->data[2];
    memcpy(devent.data, event+3, IPMI_MAX_SEL_DATA);

    /* Add it to the system event log. */
    ipmi_sel_event_add(bmc->sel, &devent);

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

    elem = ipmi_mem_alloc(sizeof(*elem));
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

/* Closing a connection is subtle because of locks.  We schedule it to
   be done in a timer callback, that way we can handle all the locks
   as part of the close. */
typedef struct close_info_s
{
    close_done_t close_done;
    void         *cb_data;
    ipmi_mc_t    *bmc;
} close_info_t;

static void
real_close_connection(void *cb_data, os_hnd_timer_id_t *id)
{
    close_info_t *info = cb_data;
    ipmi_mc_t    *bmc = info->bmc;
    ipmi_con_t   *ipmi;

    bmc->bmc->conn->os_hnd->free_timer(bmc->bmc->conn->os_hnd, id);

    ipmi_write_lock();
    ipmi = bmc->bmc->conn;

    ipmi_cleanup_mc(bmc);

    ipmi->close_connection(ipmi);

    ipmi_write_unlock();

    if (info->close_done)
	info->close_done(info->cb_data);
    ipmi_mem_free(info);
}

int
ipmi_close_connection(ipmi_mc_t    *bmc,
		      close_done_t close_done,
		      void         *cb_data)
{
    int               rv;
    close_info_t      *close_info = NULL;
    os_hnd_timer_id_t *timer = NULL;
    struct timeval    timeout;

    if (bmc->bmc_mc != bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    close_info = ipmi_mem_alloc(sizeof(*close_info));
    if (!close_info)
	return ENOMEM;

    rv = bmc->bmc->conn->os_hnd->alloc_timer(bmc->bmc->conn->os_hnd, &timer);
    if (rv)
	goto out;

    if ((rv = ipmi_mc_validate(bmc)))
	goto out;

    close_info->bmc = bmc;
    close_info->close_done = close_done;
    close_info->cb_data = cb_data;

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    rv = bmc->bmc->conn->os_hnd->start_timer(bmc->bmc->conn->os_hnd,
					     timer,
					     &timeout,
					     real_close_connection,
					     close_info);
 out:
    if (rv) {
	if (close_info)
	    ipmi_mem_free(close_info);
	if (timer)
	    bmc->bmc->conn->os_hnd->free_timer(bmc->bmc->conn->os_hnd, timer);
    }
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

    /* Copy these to the version we use for comparison. */

    mc->real_device_id = mc->device_id;
    mc->real_device_revision = mc->device_revision;
    mc->real_provides_device_sdrs = mc->provides_device_sdrs;
    mc->real_device_available = mc->device_available;
    mc->real_chassis_support = mc->chassis_support;
    mc->real_bridge_support = mc->bridge_support;
    mc->real_IPMB_event_generator_support = mc->IPMB_event_generator_support;
    mc->real_IPMB_event_receiver_support = mc->IPMB_event_receiver_support;
    mc->real_FRU_inventory_support = mc->FRU_inventory_support;
    mc->real_SEL_device_support = mc->SEL_device_support;
    mc->real_SDR_repository_support = mc->SDR_repository_support;
    mc->real_sensor_device_support = mc->sensor_device_support;
    mc->real_major_fw_revision = mc->major_fw_revision;
    mc->real_minor_fw_revision = mc->minor_fw_revision;
    mc->real_major_version = mc->major_version;
    mc->real_minor_version = mc->minor_version;
    mc->real_manufacturer_id = mc->manufacturer_id;
    mc->real_product_id = mc->product_id;
    memcpy(mc->real_aux_fw_revision, mc->aux_fw_revision,
	   sizeof(mc->real_aux_fw_revision));

    return check_oem_handlers(mc);
}

/* This should be called with an error-free message. */
static int
mc_device_data_compares(ipmi_mc_t  *mc,
			ipmi_msg_t *rsp)
{
    unsigned char *rsp_data = rsp->data;

    if (rsp->data_len < 12) {
	return EINVAL;
    }

    if (mc->real_device_id != rsp_data[1])
	return 0;

    if (mc->real_device_revision != (rsp_data[2] & 0xf))
	return 0;
    
    if (mc->real_provides_device_sdrs != ((rsp_data[2] & 0x80) == 0x80))
	return 0;

    if (mc->real_device_available != ((rsp_data[3] & 0x80) == 0x80))
	return 0;

    if (mc->real_major_fw_revision != (rsp_data[3] & 0x7f))
	return 0;

    if (mc->real_minor_fw_revision != (rsp_data[4]))
	return 0;

    if (mc->real_major_version != (rsp_data[5] & 0xf))
	return 0;

    if (mc->real_minor_version != ((rsp_data[5] >> 4) & 0xf))
	return 0;

    if (mc->real_chassis_support != ((rsp_data[6] & 0x80) == 0x80))
	return 0;

    if (mc->real_bridge_support != ((rsp_data[6] & 0x40) == 0x40))
	return 0;

    if (mc->real_IPMB_event_generator_support != ((rsp_data[6] & 0x20)==0x20))
	return 0;

    if (mc->real_IPMB_event_receiver_support != ((rsp_data[6] & 0x10) == 0x10))
	return 0;

    if (mc->real_FRU_inventory_support != ((rsp_data[6] & 0x08) == 0x08))
	return 0;

    if (mc->real_SEL_device_support != ((rsp_data[6] & 0x04) == 0x04))
	return 0;

    if (mc->real_SDR_repository_support != ((rsp_data[6] & 0x02) == 0x02))
	return 0;

    if (mc->real_sensor_device_support != ((rsp_data[6] & 0x01) == 0x01))
	return 0;

    if (mc->real_manufacturer_id != (rsp_data[7]
				     | (rsp_data[8] << 8)
				     | (rsp_data[9] << 16)))
	return 0;

    if (mc->real_product_id != (rsp_data[10] | (rsp_data[11] << 8)))
	return 0;

    if (rsp->data_len < 16) {
	/* no aux revision, it should be all zeros. */
	if ((mc->real_aux_fw_revision[0] != 0)
	    || (mc->real_aux_fw_revision[1] != 0)
	    || (mc->real_aux_fw_revision[2] != 0)
	    || (mc->real_aux_fw_revision[3] != 0))
	    return 0;
    } else {
	if (memcmp(mc->real_aux_fw_revision, rsp_data + 12, 4) != 0)
	    return 0;
    }

    /* Everything's the same. */
    return 1;
}

static void
iterate_cleanup_mc(ilist_iter_t *iter, void *item, void *cb_data)
{
    ipmi_cleanup_mc(item);
}

void
ipmi_cleanup_mc(ipmi_mc_t *mc)
{
    int i;
    int rv;
    ipmi_mc_t *bmc = mc->bmc_mc;

    /* First the device SDR sensors, since they can be there for any
       MC. */
    if (mc->sensors_in_my_sdr) {
	for (i=0; i<mc->sensors_in_my_sdr_count; i++) {
	    if (mc->sensors_in_my_sdr[i])
		ipmi_sensor_destroy(mc->sensors_in_my_sdr[i]);
	}
	ipmi_mem_free(mc->sensors_in_my_sdr);
	mc->sensors_in_my_sdr = NULL;
    }

    /* Make sure the timer stops. */
    if (mc->sel_timer_info) {
	mc->sel_timer_info->cancelled = 1;
	rv = bmc->bmc->conn->os_hnd->stop_timer(bmc->bmc->conn->os_hnd,
						mc->sel_timer);
	if (!rv) {
	    /* If we can stop the timer, free it and it's info.
	       If we can't stop the timer, that means that the
	       code is currently in the timer handler, so we let
	       the "cancelled" value do this for us. */
	    bmc->bmc->conn->os_hnd->free_timer(bmc->bmc->conn->os_hnd,
					       mc->sel_timer);
	    ipmi_mem_free(mc->sel_timer_info);
	}
	mc->sel_timer_info = NULL;
    }

    /* FIXME - clean up entities that came from this device. */

    /* Call the OEM handler for removal, if it has been registered. */
    if (mc->removed_mc_handler)
	mc->removed_mc_handler(bmc, mc, mc->removed_mc_cb_data);

    if (mc->bmc) {
	/* It's a BMC, clean up all the bmc-specific information. */

	/* Delete the sensors from the main SDR repository. */
	if (mc->bmc->sensors_in_my_sdr) {
	    for (i=0; i<mc->bmc->sensors_in_my_sdr_count; i++) {
		if (mc->bmc->sensors_in_my_sdr[i])
		    ipmi_sensor_destroy(mc->bmc->sensors_in_my_sdr[i]);
	    }
	    ipmi_mem_free(mc->bmc->sensors_in_my_sdr);
	}

	/* We cleanup the MCs twice.  Some MCs may not be destroyed
           (but only left inactive) in the first pass due to
           references form other MCs SDR repositories.  The second
           pass will get them all. */
	ilist_iter(mc->bmc->mc_list, iterate_cleanup_mc, NULL);
	ilist_iter(mc->bmc->mc_list, iterate_cleanup_mc, NULL);

	/* Destroy the main SDR repository, if it exists. */
	if (mc->bmc->main_sdrs)
	    ipmi_sdr_info_destroy(mc->bmc->main_sdrs, NULL, NULL);

	if (mc->bmc->bus_scan_timer_info) {
	    mc->bmc->bus_scan_timer_info->cancelled = 1;
	    rv = mc->bmc->conn->os_hnd->stop_timer(mc->bmc->conn->os_hnd,
						   mc->bmc->bus_scan_timer);
	    if (!rv) {
		/* If we can stop the timer, free it and it's info.
                   If we can't stop the timer, that means that the
                   code is currently in the timer handler, so we let
                   the "cancelled" value do this for us. */
		mc->bmc->conn->os_hnd->free_timer(mc->bmc->conn->os_hnd,
						  mc->bmc->bus_scan_timer);
		ipmi_mem_free(mc->bmc->bus_scan_timer_info);
	    }
	}

	ipmi_lock(mc->bmc->event_handlers_lock);
	while (mc->bmc->event_handlers)
	    remove_event_handler(mc, mc->bmc->event_handlers);
	ipmi_unlock(mc->bmc->event_handlers_lock);

	if (mc->bmc->mc_list)
	    free_ilist(mc->bmc->mc_list);
	if (mc->bmc->con_fail_handlers) {
	    ilist_iter_t iter;
	    void         *data;
	    ilist_init_iter(&iter, mc->bmc->con_fail_handlers);
	    while (ilist_first(&iter)) {
		data = ilist_get(&iter);
		ilist_delete(&iter);
		ipmi_mem_free(data);
	    }
	    free_ilist(mc->bmc->con_fail_handlers);
	}
	if (mc->bmc->ipmb_ignores) {
	    ilist_iter_t iter;
	    ilist_init_iter(&iter, mc->bmc->ipmb_ignores);
	    while (ilist_first(&iter)) {
		ilist_delete(&iter);
	    }
	    free_ilist(mc->bmc->ipmb_ignores);
	}
	if (mc->bmc->bus_scans_running) {
	    mc_ipmb_scan_info_t *item;
	    while (mc->bmc->bus_scans_running) {
		item = mc->bmc->bus_scans_running;
		mc->bmc->bus_scans_running = item->next;
		ipmi_mem_free(item);
	    }
	}
	if (mc->bmc->mc_list_lock)
	    ipmi_destroy_lock(mc->bmc->mc_list_lock);
	if (mc->bmc->event_handlers_lock)
	    ipmi_destroy_lock(mc->bmc->event_handlers_lock);
	if (mc->bmc->ll_event_id)
	    mc->bmc->conn->deregister_for_events(mc->bmc->conn,
						 mc->bmc->ll_event_id);

	/* Remove all the connection fail handlers. */
	mc->bmc->conn->set_con_fail_handler(mc->bmc->conn, NULL,  NULL);

	/* When cleaning up a BMC, we always destroy these. */
	if (mc->sdrs)
	    ipmi_sdr_info_destroy(mc->sdrs, NULL, NULL);
	if (mc->sel)
	    ipmi_sel_destroy(mc->sel, NULL, NULL);
	if (mc->sensors)
	    ipmi_sensors_destroy(mc->sensors);
	if (mc->controls)
	    ipmi_controls_destroy(mc->controls);

	/* Destroy the entities last, since sensors and controls may
           refer to them. */
	if (mc->bmc->entities)
	    ipmi_entity_info_destroy(mc->bmc->entities);
	if (mc->bmc->entities_lock)
	    ipmi_destroy_lock(mc->bmc->entities_lock);

	ipmi_mem_free(mc->bmc);
	ipmi_mem_free(mc);
    }
    else if ((ipmi_controls_get_count(mc->controls) == 0)
	     && (ipmi_sensors_get_count(mc->sensors) == 0))
    {
	/* There are no sensors associated with this MC, so it's safe
           to delete it.  If there are sensors that stil reference
           this MC (such as from another MC's SDR repository, or the
           main SDR repository) we have to leave it inactive but not
           delete it. */
	if (mc->in_bmc_list) {
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

	if (mc->sensors)
	    ipmi_sensors_destroy(mc->sensors);
	if (mc->controls)
	    ipmi_controls_destroy(mc->controls);
	if (mc->sdrs)
	    ipmi_sdr_info_destroy(mc->sdrs, NULL, NULL);
	if (mc->sel)
	    ipmi_sel_destroy(mc->sel, NULL, NULL);

	ipmi_mem_free(mc);
    } else {
	mc->active = 0;
    }
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

    mc = ipmi_mem_alloc(sizeof(*mc));
    if (!mc)
	return ENOMEM;
    memset(mc, 0, sizeof(*mc));

    mc->bmc_mc = bmc;

    mc->active = 1;

    mc->bmc = NULL;
    mc->sensors = NULL;
    mc->sensors_in_my_sdr = NULL;
    mc->sensors_in_my_sdr_count = 0;
    mc->controls = NULL;
    mc->new_sensor_handler = NULL;
    mc->removed_mc_handler = NULL;
    mc->sel = NULL;
    mc->sel_timer_info = NULL;

    memcpy(&(mc->addr), addr, addr_len);
    mc->addr_len = addr_len;
    mc->sdrs = NULL;

    rv = ipmi_sensors_alloc(mc, &(mc->sensors));
    if (rv)
	goto out_err;

    rv = ipmi_controls_alloc(mc, &(mc->controls));
    if (rv)
	goto out_err;

    rv = ipmi_sel_alloc(mc, 0, &(mc->sel));
    if (rv)
	goto out_err;
    /* When we get new logs, handle them. */
    ipmi_sel_set_new_event_handler(mc->sel,
				   mc_sel_new_event_handler,
				   mc);

 out_err:
    if (rv) {
	ipmi_cleanup_mc(mc);
    }
    else
	*new_mc = mc;

    return rv;
}

static void mc_reread_sel(void *cb_data, os_hnd_timer_id_t *id);

static void
sels_fetched_start_timer(ipmi_sel_info_t *sel,
			 int             err,
			 int             changed,
			 unsigned int    count,
			 void            *cb_data)
{
    mc_reread_sel_t *info = cb_data;
    ipmi_mc_t       *mc = info->mc;
    ipmi_mc_t       *bmc = mc->bmc_mc;
    struct timeval  timeout;

    if (info->cancelled) {
	ipmi_mem_free(info);
	return;
    }

    timeout.tv_sec = bmc->bmc->sel_scan_interval;
    timeout.tv_usec = 0;
    bmc->bmc->conn->os_hnd->start_timer(bmc->bmc->conn->os_hnd,
					mc->sel_timer,
					&timeout,
					mc_reread_sel,
					info);
}

static void
mc_reread_sel(void *cb_data, os_hnd_timer_id_t *id)
{
    mc_reread_sel_t *info = cb_data;
    ipmi_mc_t       *mc = info->mc;
    int             rv = EINVAL;

    if (info->cancelled) {
	ipmi_mem_free(info);
	return;
    }

    /* Only fetch the SEL if we know the connection is up. */
    if (mc->bmc_mc->bmc->connection_up)
	rv = ipmi_sel_get(mc->sel, sels_fetched_start_timer, info);

    /* If we couldn't run the SEL get, then restart the timer now. */
    if (rv)
	sels_fetched_start_timer(mc->sel, 0, 0, 0, info);
}

static void
start_SEL_timer(ipmi_mc_t *mc)
{
    struct timeval timeout;
    int            rv;
    ipmi_mc_t      *bmc = mc->bmc_mc;

    timeout.tv_sec = bmc->bmc->sel_scan_interval;
    timeout.tv_usec = 0;
    rv = bmc->bmc->conn->os_hnd->start_timer(bmc->bmc->conn->os_hnd,
					     mc->sel_timer,
					     &timeout,
					     mc_reread_sel,
					     mc->sel_timer_info);
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
    mc->startup_SEL_time = 0;

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
	mc->startup_SEL_time = 0;
    } else if (rsp->data_len < 5) {
	ipmi_log(IPMI_LOG_WARNING,
		 "Unable to fetch the SEL time message was too short");
	mc->startup_SEL_time = 0;
    } else {
	mc->startup_SEL_time = ipmi_get_uint32(&(rsp->data[1]));
    }

    ipmi_sel_get(mc->sel, sels_fetched, mc);
}

static void
check_event_rcvr(ipmi_mc_t *bmc, ipmi_mc_t *mc, void *cb_data)
{
    if (mc->SEL_device_support) {
	unsigned int *addr = cb_data;
	*addr = ipmi_addr_get_slave_addr(&mc->addr);
    }
}

/* Find a valid event receiver in the system. */
static unsigned int
find_event_rcvr(ipmi_mc_t *bmc)
{
    unsigned int addr = 0;

    if (bmc->SEL_device_support) {
	return bmc->bmc->bmc_slave_addr;
    }
    ipmi_bmc_iterate_mcs(bmc, check_event_rcvr, &addr);
    return addr;
}

static void
set_event_rcvr_done(ipmi_mc_t  *mc,
		    ipmi_msg_t *rsp,
		    void       *rsp_data)
{
    if (!mc)
	return; /* The MC went away, no big deal. */

    if (rsp->data[0] != 0) {
	/* Error setting the event receiver, report it. */
	ipmi_log(IPMI_LOG_WARNING,
		 "Could not set event receiver for MC at 0x%x",
		 ipmi_addr_get_slave_addr(&mc->addr));
    }
}

static void
send_set_event_rcvr(ipmi_mc_t *mc, unsigned int addr)
{
    ipmi_msg_t    msg;
    unsigned char data[2];
    
    msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    msg.cmd = IPMI_SET_EVENT_RECEIVER_CMD;
    msg.data = data;
    msg.data_len = 2;
    data[0] = addr;
    data[1] = 0; /* LUN is 0 per the spec (section 7.2 of 1.5 spec). */
    ipmi_send_command(mc, 0, &msg, set_event_rcvr_done, NULL);
    /* No care about return values, if this fails it will be done
       again later. */
}

static void
get_event_rcvr_done(ipmi_mc_t  *mc,
		    ipmi_msg_t *rsp,
		    void       *rsp_data)
{
    unsigned long addr = (long) rsp_data;

    if (!mc)
	return; /* The MC went away, no big deal. */

    if (rsp->data[0] != 0) {
	/* Error getting the event receiver, report it. */
	ipmi_log(IPMI_LOG_WARNING,
		 "Could not get event receiver for MC at 0x%x",
		 ipmi_addr_get_slave_addr(&mc->addr));
    } else if (rsp->data[1] != addr) {
	/* The event receiver doesn't match, so change it. */
	send_set_event_rcvr(mc, addr);
    }
}

static void
send_get_event_rcvr(ipmi_mc_t *mc, unsigned int addr)
{
    ipmi_msg_t    msg;
    
    msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    msg.cmd = IPMI_GET_EVENT_RECEIVER_CMD;
    msg.data = NULL;
    msg.data_len = 0;
    ipmi_send_command(mc, 0, &msg, get_event_rcvr_done,
		      (void *) (unsigned long) addr);
    /* No care about return values, if this fails it will be done
       again later. */
}

static void
do_event_rcvr(ipmi_mc_t *mc)
{
    if (mc && mc->IPMB_event_generator_support) {
	/* We have an MC that is live (or still live) and generates
	   events, make sure the event receiver is set properly. */
	unsigned int event_rcvr = find_event_rcvr(mc->bmc_mc);

	if (event_rcvr) {
	    send_get_event_rcvr(mc, event_rcvr);
	}
    }
}

/* This is called after the first sensor scan for the MC, we start up
   timers and things like that here. */
static void
sensors_reread(ipmi_mc_t *mc, int err, void *cb_data)
{
    /* See if any presence has changed with the new sensors. */ 
    ipmi_detect_bmc_presence_changes(mc, 0);

    /* We set the event receiver here, so that we know all the SDRs
       are installed.  That way any incoming events from the device
       will have the proper sensor set. */
    if (mc) {
	unsigned int event_rcvr = 0;

	if (mc->IPMB_event_generator_support)
	    event_rcvr = find_event_rcvr(mc->bmc_mc);
	else if (mc->SEL_device_support) {
	    /* If it is an SEL device and not an event receiver, then
                set it's event receiver to itself. */
	    struct ipmi_ipmb_addr *ipmb_addr = (void *) &mc->addr;
	    if (mc->bmc)
		event_rcvr = mc->bmc->bmc_slave_addr;
	    else
		event_rcvr = ipmb_addr->slave_addr;
	}

	if (event_rcvr) {
	    send_set_event_rcvr(mc, event_rcvr);
	}
    }

    if (mc->SEL_device_support) {
	mc_reread_sel_t *info;
	int             rv;
	ipmi_msg_t      msg;
	ipmi_mc_t       *bmc = mc->bmc_mc;

	/* If the MC supports an SEL, start scanning its SEL. */

	/* Allocate the system event log fetch timer. */
	info = ipmi_mem_alloc(sizeof(*info));
	if (!info) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "Unable to allocate info for system event log timer."
		     " System event log will not be queried");
	    return;
	}
	info->mc = mc;
	info->cancelled = 0;
	rv = bmc->bmc->conn->os_hnd->alloc_timer(bmc->bmc->conn->os_hnd,
						&(mc->sel_timer));
	if (rv) {
	    ipmi_mem_free(info);
	    ipmi_log(IPMI_LOG_SEVERE,
		     "Unable to allocate the system event log timer."
		     " System event log will not be queried");
	} else {
	    mc->sel_timer_info = info;
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
	    mc->startup_SEL_time = 0;
	    ipmi_sel_get(mc->sel, NULL, NULL);
	}
    }
}


int
ipmi_add_mc_to_bmc(ipmi_mc_t *bmc, ipmi_mc_t *mc)
{
    int rv;

    CHECK_MC_LOCK(bmc);

    ipmi_lock(bmc->bmc->mc_list_lock);
    rv = !ilist_add_tail(bmc->bmc->mc_list, mc, NULL);
    if (!rv)
	mc->in_bmc_list = 1;

    if (bmc->bmc->new_mc_handler)
	bmc->bmc->new_mc_handler(bmc, mc, bmc->bmc->new_mc_cb_data);

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

    if (err) {
	ipmi_cleanup_mc(mc);
	return;
    }

    /* Scan all the sensors and call sensors_reread() when done. */
    if (mc->provides_device_sdrs)
	ipmi_mc_reread_sensors(mc, sensors_reread, NULL);
    else
	sensors_reread(mc, 0, NULL);
}

static void
add_bus_scans_running(ipmi_mc_t *bmc, mc_ipmb_scan_info_t *info)
{
    info->next = bmc->bmc->bus_scans_running;
    bmc->bmc->bus_scans_running = info;
}

static void
remove_bus_scans_running(ipmi_mc_t *bmc, mc_ipmb_scan_info_t *info)
{
    mc_ipmb_scan_info_t *i2;

    i2 = bmc->bmc->bus_scans_running;
    if (i2 == info)
	bmc->bmc->bus_scans_running = info->next;
    else
	while (i2->next != NULL) {
	    if (i2->next == info) {
		i2->next = info->next;
		break;
	    }
	    i2 = i2->next;
	}
}

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
    ipmi_mc_t           *mc;
    int                 created_here = 0;


    ipmi_read_lock();
    rv = ipmi_mc_validate(info->bmc);
    if (rv) {
	ipmi_log(IPMI_LOG_INFO,
		 "BMC went away while scanning for MCs");
	ipmi_read_unlock();
	return;
    }

    ipmi_lock(info->bmc->bmc->mc_list_lock);
    /* Found one, start the discovery process on it. */
    mc = find_mc_by_addr(info->bmc, addr, addr_len);
    if (msg->data[0] == 0) {
	if (mc)
	    mc->missed_responses = 0;
	if (mc && mc->active && !mc_device_data_compares(mc, msg)) {
	    /* The MC was replaced with a new one, so clear the old
               one and add a new one. */
	    ipmi_cleanup_mc(mc);
	    mc = NULL;
	}
	if (!mc || !mc->active) {
	    /* It doesn't already exist, or it's inactive, so add
               it. */
	    if (!mc) {
		/* If it's not there, then add it.  If it's just not
                   active, reuse the same data. */
		rv = ipmi_create_mc(info->bmc, addr, addr_len, &mc);
		if (rv) {
		    /* Out of memory, just give up for now. */
		    remove_bus_scans_running(info->bmc, info);
		    ipmi_mem_free(info);
		    ipmi_unlock(info->bmc->bmc->mc_list_lock);
		    goto out;
		}

		rv = ipmi_sdr_info_alloc(mc, 0, 1, &(mc->sdrs));
		if (!rv)
		    rv = ipmi_add_mc_to_bmc(mc->bmc_mc, mc);
		if (rv) {
		    ipmi_cleanup_mc(mc);
		    goto next_addr;
		}
	    }
	    rv = get_device_id_data_from_rsp(mc, msg);
	    if (rv) {
		/* If we couldn't handle the device data, just leave
                   it inactive. */
		mc->active = 0;
		goto next_addr;
	    }

	    if (!rv) {
		created_here = 1;
		if (mc->provides_device_sdrs)
		    rv = ipmi_sdr_fetch(mc->sdrs, mc_sdr_handler, mc);
		else
		    sensors_reread(mc, 0, NULL);
	    }
	    if (rv)
		ipmi_cleanup_mc(mc);
	}
    } else if (mc && mc->active) {
	/* Didn't get a response.  Maybe the MC has gone away? */
	mc->missed_responses++;
	if (mc->missed_responses >= MAX_MC_MISSED_RESPONSES) {
	    ipmi_cleanup_mc(mc);
	    goto next_addr;
	} else {
	    /* Try again right now. */
	    ipmi_unlock(info->bmc->bmc->mc_list_lock);
	    goto retry_addr;
	}
    }

    /* If we didn't create the MC above, then check the event
       receiver.  If the MC was created above, then setting the event
       receiver will be done after the SDRs are read. */
    if (!created_here)
	do_event_rcvr(mc);

 next_addr:
    ipmi_unlock(info->bmc->bmc->mc_list_lock);

 next_addr_nolock:
    if (info->addr.slave_addr == info->end_addr) {
	/* We've hit the end, we can quit now. */
	if (info->done_handler)
	    info->done_handler(info->bmc, 0, info->cb_data);
	remove_bus_scans_running(info->bmc, info);
	ipmi_mem_free(info);
	goto out;
    }
    info->addr.slave_addr += 2;
    if ((info->addr.slave_addr == info->bmc->bmc->bmc_slave_addr)
	|| (in_ipmb_ignores(info->bmc, info->addr.slave_addr)))
    {
	/* We don't scan the BMC, that would be scary.  We also check
           the ignores list. */
	goto next_addr_nolock;
    }

 retry_addr:
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

    if (rv) {
	remove_bus_scans_running(info->bmc, info);
	ipmi_mem_free(info);
    }
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

    info = ipmi_mem_alloc(sizeof(*info));
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
	ipmi_mem_free(info);
    else
	add_bus_scans_running(bmc, info);
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
	ipmi_mem_free(info);
	return;
    }

    /* Only operate if we know the connection is up. */
    if (bmc->bmc->connection_up) {
	/* Rescan all the presence sensors to make sure they are valid. */
	ipmi_detect_bmc_presence_changes(bmc, 1);

	ipmi_lock(bmc->bmc->mc_list_lock);
	start_mc_scan(bmc);
	ipmi_unlock(bmc->bmc->mc_list_lock);
    }

    timeout.tv_sec = bmc->bmc->bus_scan_interval;
    timeout.tv_usec = 0;
    bmc->bmc->conn->os_hnd->start_timer(bmc->bmc->conn->os_hnd,
					id,
					&timeout,
					bmc_rescan_bus,
					info);
}

static void
set_operational(ipmi_mc_t *bmc)
{
    struct timeval        timeout;
    bmc_rescan_bus_info_t *info;
    int                   rv;

    /* Report this before we start scanning for entities and
       sensors so the user can register a callback handler for
       those. */
    bmc->bmc->state = OPERATIONAL;
    if (bmc->bmc->setup_done)
	bmc->bmc->setup_done(bmc, 0, bmc->bmc->setup_done_cb_data);

    /* Call the OEM setup finish if it is registered. */
    if (bmc->bmc->setup_finished_handler)
	bmc->bmc->setup_finished_handler(bmc,
					 bmc->bmc->setup_finished_cb_data);

    /* Start an SDR scan. */
    ipmi_entity_scan_sdrs(bmc->bmc->entities, bmc->bmc->main_sdrs);
    ipmi_sensor_handle_sdrs(bmc, NULL, bmc->bmc->main_sdrs);

    /* Scan all the sensors and call sensors_reread() when done. */
    if (bmc->provides_device_sdrs)
	ipmi_mc_reread_sensors(bmc, sensors_reread, NULL);
    else
	sensors_reread(bmc, 0, NULL);

    start_mc_scan(bmc);

    /* Start the timer to rescan the bus periodically. */
    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	rv = ENOMEM;
    else {
	info->bmc = bmc;
	info->cancelled = 0;
        timeout.tv_sec = bmc->bmc->bus_scan_interval;
        timeout.tv_usec = 0;
        rv = bmc->bmc->conn->os_hnd->alloc_timer(bmc->bmc->conn->os_hnd,
						 &(bmc->bmc->bus_scan_timer));
	if (!rv) {
	    rv = bmc->bmc->conn->os_hnd->start_timer(bmc->bmc->conn->os_hnd,
						     bmc->bmc->bus_scan_timer,
						     &timeout,
						     bmc_rescan_bus,
						     info);
	    if (rv)
		bmc->bmc->conn->os_hnd->free_timer(bmc->bmc->conn->os_hnd,
						   bmc->bmc->bus_scan_timer);
	}
    }
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "Unable to start the bus scan timer."
		 " The bus will not be scanned periodically.");
    } else {
	bmc->bmc->bus_scan_timer_info = info;
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
	if (mc->bmc->setup_done)
	    mc->bmc->setup_done(mc, rv, mc->bmc->setup_done_cb_data);
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

    /* If we get an error while querying device SDRs, then we just
       don't have any device SDRs. */
    if (err && (mc->bmc->state != QUERYING_SENSOR_SDRS)) {

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
    if (mc->bmc->setup_done)
	mc->bmc->setup_done(mc, rv, mc->bmc->setup_done_cb_data);
    ipmi_close_connection(mc, NULL, NULL);
}

static void
got_slave_addr(ipmi_mc_t    *bmc,
	       int          err,
	       unsigned int addr,
	       void         *cb_data)
{
    int rv;

    ipmi_lock(bmc->bmc->mc_list_lock);
    if (err) {
	rv = err;
	goto out;
    }

    if (bmc->SDR_repository_support)
	rv = ipmi_sdr_fetch(bmc->bmc->main_sdrs, sdr_handler, bmc);
    else if (bmc->provides_device_sdrs) {
	bmc->bmc->state = QUERYING_SENSOR_SDRS;
	rv = ipmi_sdr_fetch(bmc->sdrs, sdr_handler, bmc);
    } else {
	rv = finish_mc_handling(bmc);
    }

 out:
    if (rv) {
	if (bmc->bmc->setup_done)
	    bmc->bmc->setup_done(bmc, rv, bmc->bmc->setup_done_cb_data);
	ipmi_close_connection(bmc, NULL, NULL);
    }

    ipmi_lock(bmc->bmc->mc_list_lock);
}

static void
dev_id_rsp_handler(ipmi_mc_t  *bmc,
		   ipmi_msg_t *rsp,
		   void       *rsp_data)
{
    int rv;

    ipmi_lock(bmc->bmc->mc_list_lock);

    rv = get_device_id_data_from_rsp(bmc, rsp);

    bmc->bmc->state = QUERYING_MAIN_SDRS;

    if (!rv)
	rv = ipmi_sdr_info_alloc(bmc, 0, 0, &bmc->bmc->main_sdrs);
    if (!rv)
	rv = ipmi_sdr_info_alloc(bmc, 0, 1, &bmc->sdrs);
    if (!rv) {
	if (bmc->bmc->slave_addr_fetcher) {
	    /* The OEM code added a way to fetch our address.  Call
               it. */
	    rv = bmc->bmc->slave_addr_fetcher(bmc, got_slave_addr, NULL);
	} else if (bmc->SDR_repository_support)
	    rv = ipmi_sdr_fetch(bmc->bmc->main_sdrs, sdr_handler, bmc);
	else if (bmc->provides_device_sdrs) {
	    bmc->bmc->state = QUERYING_SENSOR_SDRS;
	    rv = ipmi_sdr_fetch(bmc->sdrs, sdr_handler, bmc);
	} else {
	    rv = finish_mc_handling(bmc);
	}
    }

    if (rv) {
	if (bmc->bmc->setup_done)
	    bmc->bmc->setup_done(bmc, rv, bmc->bmc->setup_done_cb_data);
	ipmi_close_connection(bmc, NULL, NULL);
    }
    ipmi_unlock(bmc->bmc->mc_list_lock);
}

static int
setup_bmc(ipmi_con_t   *ipmi,
	  ipmi_addr_t  *mc_addr,
	  int          mc_addr_len,
	  unsigned int my_slave_addr,
	  ipmi_mc_t    **new_mc)
{
    ipmi_mc_t *mc;
    int       rv;

    if (mc_addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    mc = ipmi_mem_alloc(sizeof(*mc));
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
    mc->removed_mc_handler = NULL;
    mc->sel = NULL;

    memcpy(&(mc->addr), mc_addr, mc_addr_len);
    mc->addr_len = mc_addr_len;
    mc->sdrs = NULL;

    mc->bmc = ipmi_mem_alloc(sizeof(*(mc->bmc)));
    if (! (mc->bmc)) {
	rv = ENOMEM;
	goto out_err;
    }
    memset(mc->bmc, 0, sizeof(*(mc->bmc)));

    mc->bmc->bmc_slave_addr = my_slave_addr;
    mc->bmc->slave_addr_fetcher = NULL;

    mc->bmc->conn = ipmi;

    /* Create the locks before anything else. */
    mc->bmc->mc_list_lock = NULL;
    mc->bmc->entities_lock = NULL;
    mc->bmc->event_handlers_lock = NULL;

    /* Set the default timer intervals. */
    mc->bmc->sel_scan_interval = IPMI_SEL_QUERY_INTERVAL;
    mc->bmc->bus_scan_interval = IPMI_RESCAN_BUS_INTERVAL;

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
    mc->bmc->entity_handler = NULL;
    mc->bmc->new_entity_handler = NULL;
    mc->bmc->new_mc_handler = NULL;
    mc->bmc->setup_finished_handler = NULL;
    mc->bmc->do_bus_scan = 1;

    mc->bmc->connection_up = 1;
    mc->bmc->conn->set_con_fail_handler(mc->bmc->conn, ll_con_failed, mc);

    mc->bmc->mc_list = alloc_ilist();
    if (! mc->bmc->mc_list) {
	rv = ENOMEM;
	goto out_err;
    }

    mc->bmc->con_fail_handlers = alloc_ilist();
    if (! mc->bmc->con_fail_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    mc->bmc->ipmb_ignores = alloc_ilist();
    if (! mc->bmc->ipmb_ignores) {
	rv = ENOMEM;
	goto out_err;
    }

    mc->bmc->bus_scans_running = NULL;

    rv = ipmi_entity_info_alloc(mc, &(mc->bmc->entities));
    if (rv)
	goto out_err;

    rv = ipmi_sensors_alloc(mc, &(mc->sensors));
    if (rv)
	goto out_err;

    rv = ipmi_controls_alloc(mc, &(mc->controls));
    if (rv)
	goto out_err;

    memset(mc->bmc->chan, 0, sizeof(mc->bmc->chan));

    rv = ipmi_sel_alloc(mc, 0, &(mc->sel));
    if (rv)
	goto out_err;
    /* When we get new logs, handle them. */
    ipmi_sel_set_new_event_handler(mc->sel,
				   mc_sel_new_event_handler,
				   mc);

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

typedef struct init_con_info_s
{
    ipmi_bmc_cb handler;
    void        *cb_data;
} init_con_info_t;

static void
ipmi_init_con(ipmi_con_t   *ipmi,
	      int          err,
	      ipmi_addr_t  *mc_addr,
	      int          mc_addr_len,
	      unsigned int my_slave_addr,
	      void         *cb_data)
{
    init_con_info_t *info = cb_data;
    ipmi_msg_t      cmd_msg;
    int             rv = 0;
    ipmi_mc_t       *mc;

    rv = setup_bmc(ipmi, mc_addr, mc_addr_len, my_slave_addr, &mc);
    if (rv) {
	ipmi->close_connection(ipmi);
	info->handler(NULL, rv, info->cb_data);
	goto out;
    }

    mc->bmc->setup_done = info->handler;
    mc->bmc->setup_done_cb_data = info->cb_data;

    ipmi_lock(mc->bmc_mc->bmc->mc_list_lock);

    cmd_msg.netfn = IPMI_APP_NETFN;
    cmd_msg.cmd = IPMI_GET_DEVICE_ID_CMD;
    cmd_msg.data_len = 0;

    rv = ipmi_send_command(mc, 0, &cmd_msg, dev_id_rsp_handler, NULL);
    if (rv)
	goto close_and_quit;

    mc->bmc->state = QUERYING_DEVICE_ID;

 close_and_quit:
    if (rv) {
	ipmi_close_connection(mc, NULL, NULL);
	info->handler(NULL, rv, info->cb_data);
    }

    ipmi_unlock(mc->bmc_mc->bmc->mc_list_lock);

 out:
    ipmi_mem_free(info);
}

int
ipmi_init_bmc(ipmi_con_t  *con,
	      ipmi_bmc_cb handler,
	      void        *cb_data)
{
    init_con_info_t *info;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->handler = handler;
    info->cb_data = cb_data;
    return con->start_con(con, ipmi_init_con, info);
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

void
ipmi_mc_set_provides_device_sdrs(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    mc->provides_device_sdrs = val;
}

int
ipmi_mc_device_available(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->device_available;
}

void
ipmi_mc_set_device_available(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    mc->device_available = val;
}

int
ipmi_mc_chassis_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->chassis_support;
}

void
ipmi_mc_set_chassis_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    mc->chassis_support = val;
}

int
ipmi_mc_bridge_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->bridge_support;
}

void
ipmi_mc_set_bridge_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    mc->bridge_support = val;
}

int
ipmi_mc_ipmb_event_generator_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->IPMB_event_generator_support;
}

void
ipmi_mc_set_ipmb_event_generator_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    mc->IPMB_event_generator_support = val;
}

int
ipmi_mc_ipmb_event_receiver_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->IPMB_event_receiver_support;
}

void
ipmi_mc_set_ipmb_event_receiver_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    mc->IPMB_event_receiver_support = val;
}

int
ipmi_mc_fru_inventory_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->FRU_inventory_support;
}

void
ipmi_mc_set_fru_inventory_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    mc->FRU_inventory_support = val;
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

void
ipmi_mc_set_sdr_repository_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    mc->SDR_repository_support = val;
}

int
ipmi_mc_sensor_device_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->sensor_device_support;
}

void
ipmi_mc_set_sensor_device_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    mc->sensor_device_support = val;
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

static int
ipmi_bmc_iterate_mcs_rev(ipmi_mc_t               *bmc,
			 ipmi_bmc_iterate_mcs_cb handler,
			 void                    *cb_data)
{
    iterate_mc_info_t info = { bmc, handler, cb_data };

    if (bmc->bmc == NULL)
	/* Not a BMC */
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    ipmi_lock(bmc->bmc->mc_list_lock);
    ilist_iter_rev(bmc->bmc->mc_list, iterate_mcs_handler, &info);
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

int
ipmi_cmp_mc_id(ipmi_mc_id_t id1, ipmi_mc_id_t id2)
{
    if (id1.bmc > id2.bmc)
	return 1;
    if (id1.bmc < id2.bmc)
	return -1;
    if (id1.mc_num > id2.mc_num)
	return 1;
    if (id1.mc_num < id2.mc_num)
	return -1;
    if (id1.channel > id2.channel)
	return 1;
    if (id1.channel < id2.channel)
	return -1;
    return 0;
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
    ipmi_mem_free(info);
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

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    /* Create an SDR repository to store. */
    rv = ipmi_sdr_info_alloc(bmc, 0, 0, &stored_sdrs);
    if (rv) {
	ipmi_mem_free(info);
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
	ipmi_mem_free(info);
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
ipmi_mc_set_oem_removed_handler(ipmi_mc_t              *mc,
				ipmi_mc_oem_removed_cb handler,
				void                   *cb_data)
{
    CHECK_MC_LOCK(mc);

    mc->removed_mc_handler = handler;
    mc->removed_mc_cb_data = cb_data;
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
    ipmi_mc_t   *mc;
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
        info->done(info->mc->bmc_mc, err, info->cb_data);
    ipmi_mem_free(info);
}

typedef struct del_event_info_s
{
    ipmi_event_t *event;
    ipmi_bmc_cb  done_handler;
    void         *cb_data;
    int          rv;
} del_event_info_t;

static void
del_event_handler(ipmi_mc_t *mc, void *cb_data)
{
    del_event_info_t   *info = cb_data;
    sel_op_done_info_t *sel_info;

    if (!mc->SEL_device_support) {
	info->rv = EINVAL;
	return;
    }

    /* If we have an OEM handler, call it instead. */
    if (mc->sel_del_event_handler) {
	info->rv = mc->sel_del_event_handler(mc,
					     info->event,
					     info->done_handler,
					     info->cb_data);
	return;
    }

    sel_info = ipmi_mem_alloc(sizeof(*sel_info));
    if (!sel_info) {
	info->rv = ENOMEM;
	return;
    }

    sel_info->mc = mc;
    sel_info->done = info->done_handler;
    sel_info->cb_data = cb_data;

    info->rv = ipmi_sel_del_event(mc->sel, info->event, sel_op_done, sel_info);
    if (info->rv)
	ipmi_mem_free(sel_info);
}

int
ipmi_bmc_del_event(ipmi_mc_t    *bmc,
		   ipmi_event_t *event,
		   ipmi_bmc_cb  done_handler,
		   void         *cb_data)
{
    int              rv;
    del_event_info_t info;

    CHECK_MC_LOCK(bmc);

    info.event = event;
    info.done_handler = done_handler;
    info.cb_data = cb_data;
    info.rv = 0;
    rv = ipmi_mc_pointer_cb(event->mc_id, del_event_handler, &info);
    if (rv)
	return rv;
    else
	return info.rv;
}

typedef struct next_event_handler_info_s
{
    int          rv;
    ipmi_event_t *event;
    int          found_curr_mc;
    int          do_prev; /* If going backwards, this will be 1. */
} next_event_handler_info_t;

static void
next_event_handler(ipmi_mc_t *bmc, ipmi_mc_t *mc, void *cb_data)
{
    next_event_handler_info_t *info = cb_data;
    ipmi_mc_id_t              mc_id = ipmi_mc_convert_to_id(mc);

    if (!info->rv)
	/* We've found an event already, just return. */
	return;

    if (info->do_prev) {
	if (info->found_curr_mc)
	    /* We've found the MC that had the event, but it didn't have
	       any more events.  Look for last events now. */
	    info->rv = ipmi_sel_get_last_event(mc->sel, info->event);
	else if (ipmi_cmp_mc_id(info->event->mc_id, mc_id) == 0) {
	    info->found_curr_mc = 1;
	    info->rv = ipmi_sel_get_prev_event(mc->sel, info->event);
	}
    } else {
	if (info->found_curr_mc)
	    /* We've found the MC that had the event, but it didn't have
	       any more events.  Look for first events now. */
	    info->rv = ipmi_sel_get_first_event(mc->sel, info->event);
	else if (ipmi_cmp_mc_id(info->event->mc_id, mc_id) == 0) {
	    info->found_curr_mc = 1;
	    info->rv = ipmi_sel_get_next_event(mc->sel, info->event);
	}
    }
}

int
ipmi_bmc_first_event(ipmi_mc_t *bmc, ipmi_event_t *event)
{
    int                       rv;
    next_event_handler_info_t info;

    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    rv = ipmi_sel_get_first_event(bmc->sel, event);
    if (rv) {
	info.rv = ENODEV;
	info.event = event;
	info.found_curr_mc = 1;
	info.do_prev = 0;
	rv = ipmi_bmc_iterate_mcs(bmc, next_event_handler, &info);
	if (!rv)
	    rv = info.rv;
    }

    return rv;
}

int
ipmi_bmc_last_event(ipmi_mc_t *bmc, ipmi_event_t *event)
{
    int                       rv;
    next_event_handler_info_t info;

    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    info.rv = ENODEV;
    info.event = event;
    info.found_curr_mc = 1;
    info.do_prev = 1;
    rv = ipmi_bmc_iterate_mcs(bmc, next_event_handler, &info);
    if (!rv)
	rv = info.rv;
    if (rv)
	rv = ipmi_sel_get_last_event(bmc->sel, event);

    return rv;
}

int
ipmi_bmc_next_event(ipmi_mc_t *bmc, ipmi_event_t *event)
{
    int                       rv;
    next_event_handler_info_t info;
    ipmi_mc_id_t              mc_id = ipmi_mc_convert_to_id(bmc);

    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    rv = ENODEV;
    if (ipmi_cmp_mc_id(event->mc_id, mc_id) == 0)
	/* If the event is from the BMC, try the next event in the BMC. */
	rv = ipmi_sel_get_next_event(bmc->sel, event);
    if (rv) {
	info.rv = ENODEV;
	info.event = event;
	info.found_curr_mc = 1;
	info.do_prev = 0;
	rv = ipmi_bmc_iterate_mcs(bmc, next_event_handler, &info);
	if (!rv)
	    rv = info.rv;
    }

    return rv;
}

int
ipmi_bmc_prev_event(ipmi_mc_t *bmc, ipmi_event_t *event)
{
    int                       rv;
    next_event_handler_info_t info;
    ipmi_mc_id_t              mc_id = ipmi_mc_convert_to_id(bmc);

    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    rv = ENODEV;
    if (ipmi_cmp_mc_id(event->mc_id, mc_id) == 0) {
	/* If the event is from the BMC, try the prev event in the BMC. */
	rv = ipmi_sel_get_prev_event(bmc->sel, event);
    } else {
	info.rv = ENODEV;
	info.event = event;
	info.found_curr_mc = 1;
	info.do_prev = 1;
	rv = ipmi_bmc_iterate_mcs_rev(bmc, next_event_handler, &info);
	if (!rv)
	    rv = info.rv;
	if (rv)
	    /* If we weren't on the bmc SEL but didn't find anything
               else, then we try the last on in the BMC sel. */
	    rv = ipmi_sel_get_last_event(bmc->sel, event);
    }

    return rv;
}

static void
sel_count_handler(ipmi_mc_t *bmc, ipmi_mc_t *mc, void *cb_data)
{
    int *count = cb_data;
    int nc = 0;

    ipmi_get_sel_count(mc->sel, &nc);
    *count += nc;
}

int
ipmi_bmc_sel_count(ipmi_mc_t    *bmc,
		   unsigned int *count)
{
    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    *count = 0;
    ipmi_get_sel_count(bmc->sel, count);
    ipmi_bmc_iterate_mcs(bmc, sel_count_handler, count);
    return 0;
}

static void
sel_entries_used_handler(ipmi_mc_t *bmc, ipmi_mc_t *mc, void *cb_data)
{
    int *count = cb_data;
    int nc = 0;

    ipmi_get_sel_entries_used(mc->sel, &nc);
    *count += nc;
}

int ipmi_bmc_sel_entries_used(ipmi_mc_t    *bmc,
			      unsigned int *count)
{
    if (!bmc->bmc)
	return EINVAL;

    CHECK_MC_LOCK(bmc);

    *count = 0;
    ipmi_get_sel_entries_used(bmc->sel, count);
    ipmi_bmc_iterate_mcs(bmc, sel_entries_used_handler, count);
    return 0;
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
