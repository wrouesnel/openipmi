/*
 * domain.c
 *
 * MontaVista IPMI code for handling IPMI domains
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
#include <OpenIPMI/ipmi_domain.h>
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

/* Rescan the bus for MCs every 10 minutes by default. */
#define IPMI_RESCAN_BUS_INTERVAL 600

/* Re-query the SEL every 10 seconds by default. */
#define IPMI_SEL_QUERY_INTERVAL 10

struct ipmi_domain_con_change_s
{
    ipmi_domain_con_cb handler;
    void               *cb_data;
};

/* Timer structure for rescanning the bus. */
typedef struct rescan_bus_info_s
{
    int           cancelled;
    os_handler_t  *os_hnd;
    ipmi_domain_t *domain;
} rescan_bus_info_t;

/* Used to keep a record of a bus scan. */
typedef struct mc_ipbm_scan_info_s mc_ipmb_scan_info_t;
struct mc_ipbm_scan_info_s
{
    ipmi_ipmb_addr_t    addr;
    ipmi_domain_t       *domain;
    ipmi_msg_t          msg;
    unsigned int        end_addr;
    ipmi_domain_cb      done_handler;
    void                *cb_data;
    mc_ipmb_scan_info_t *next;
    unsigned int        missed_responses;
};

/* This structure tracks messages sent to the domain, it is primarily
   here so messages can be rerouted to other connections when a
   connection fails. */
typedef struct ll_msg_s
{
    ipmi_domain_t                *domain;
    int                          con;

    ipmi_addr_t                  addr;
    unsigned int                 addr_len;

    ipmi_msg_t                   msg;
    unsigned char                msg_data[IPMI_MAX_MSG_LENGTH];

    ipmi_addr_response_handler_t rsp_handler;
    void                         *rsp_data1;
    void                         *rsp_data2;

    long                         seq;

    ilist_item_t link;
} ll_msg_t;

typedef struct activate_timer_info_s
{
    int           cancelled;
    ipmi_domain_t *domain;
    os_handler_t  *os_hnd;
    ipmi_lock_t   *lock;
    volatile int  running;
} activate_timer_info_t;

struct ipmi_domain_s
{
    /* Used to handle shutdown race conditions. */
    int             valid;

    /* OS handler to use for domain operations. */
    os_handler_t *os_hnd;

    /* The main set of SDRs on a BMC. */
    ipmi_sdr_info_t *main_sdrs;

    /* The sensors that came from the main SDR. */
    ipmi_sensor_t **sensors_in_main_sdr;
    unsigned int  sensors_in_main_sdr_count;

    /* Major and minor versions of the connection. */
    unsigned int major_version : 4;
    unsigned int minor_version : 4;
    unsigned int SDR_repository_support : 1;

    /* A special MC used to represent the system interface. */
    ipmi_mc_t *si_mc;

    ilist_t            *mc_list;
    ipmi_lock_t        *mc_list_lock;

    /* A list of outstanding messages.  We use this so we can reroute
       messages to another connection in case a connection fails. */
    ilist_t     *cmds;
    ipmi_lock_t *cmds_lock;
    long        cmds_seq; /* Sequence number for messages to avoid
			     reuse problems. */

    ipmi_event_handler_id_t  *event_handlers;
    ipmi_lock_t              *event_handlers_lock;
    ipmi_oem_event_handler_cb oem_event_handler;
    void                      *oem_event_cb_data;

    /* Are we in the middle of an MC bus scan? */
    int                scanning_bus;

    ipmi_entity_info_t    *entities;
    ipmi_lock_t           *entities_lock;
    ipmi_domain_entity_cb entity_handler;

#define MAX_CONS 2
    int           working_conn;
    ipmi_con_t    *conn[MAX_CONS];
    int           con_active[MAX_CONS];
    unsigned char con_ipmb_addr[MAX_CONS];

    ipmi_ll_event_handler_id_t *ll_event_id[MAX_CONS];

    int           con_up[MAX_CONS];

    /* Are any low-level connections up? */
    int connection_up;

    /* Are we in the process of connecting? */
    int connecting;

#define MAX_PORTS_PER_CON 4
    /* -1 if not valid, 0 if not up, 1 if up. */
    int           port_up[MAX_PORTS_PER_CON][MAX_CONS];

    /* Should I do a full bus scan for devices on the bus? */
    int                        do_bus_scan;

    /* Timer for rescanning the bus periodically. */
    unsigned int      bus_scan_interval; /* seconds between scans */
    os_hnd_timer_id_t *bus_scan_timer;
    rescan_bus_info_t *bus_scan_timer_info;

    /* This is a list of all the bus scans currently happening, so
       they can be properly freed. */
    mc_ipmb_scan_info_t *bus_scans_running;

    ipmi_chan_info_t chan[MAX_IPMI_USED_CHANNELS];
    unsigned char    msg_int_type;
    unsigned char    event_msg_int_type;

    /* A list of connection fail handler, separate from the main one. */
    ilist_t *con_change_handlers;

    /* A list of IPMB addresses to not scan. */
    ilist_t *ipmb_ignores;

    /* This is a timer that waits a little while before activating a
       connection if all connections are not active.  It avoids race
       conditions with activiation. */
    os_hnd_timer_id_t     *activate_timer;
    activate_timer_info_t *activate_timer_info;

    unsigned int default_sel_rescan_time;

    /* Keep a linked-list of these. */
    ipmi_domain_t *next, *prev;
};

static int remove_event_handler(ipmi_domain_t           *domain,
				ipmi_event_handler_id_t *event);

static void domain_rescan_bus(void *cb_data, os_hnd_timer_id_t *id);

/***********************************************************************
 *
 * Domain data structure creation and destruction
 *
 **********************************************************************/

static void
iterate_cleanup_mc(ilist_iter_t *iter, void *item, void *cb_data)
{
    _ipmi_cleanup_mc(item);
}

void
cleanup_domain(ipmi_domain_t *domain)
{
    int i;
    int rv;

    /* Nuke all outstanding messages first. */
    if ((domain->cmds_lock) && (domain->cmds)) {
	ll_msg_t     *nmsg;
	int          ok;
	ilist_iter_t iter;

	ipmi_lock(domain->cmds_lock);

	ilist_init_iter(&iter, domain->cmds);
	ok = ilist_first(&iter);
	while (ok) {
	    ipmi_msg_t    msg;
	    unsigned char err;

	    nmsg = ilist_get(&iter);

	    msg.netfn = nmsg->msg.netfn | 1;
	    msg.cmd = nmsg->msg.cmd;
	    msg.data = &err;
	    msg.data_len = 1;
	    err = IPMI_UNKNOWN_ERR_CC;
	    nmsg->rsp_handler(domain, &nmsg->addr, nmsg->addr_len, &nmsg->msg,
			      nmsg->rsp_data1, nmsg->rsp_data2);
	    
	    ilist_delete(&iter);
	    ipmi_mem_free(nmsg);
	    ok = ilist_first(&iter);
	}
	ipmi_unlock(domain->cmds_lock);
    }
    if (domain->cmds_lock)
	ipmi_destroy_lock(domain->cmds_lock);
    if (domain->cmds)
	free_ilist(domain->cmds);

    /* Delete the sensors from the main SDR repository. */
    if (domain->sensors_in_main_sdr) {
	for (i=0; i<domain->sensors_in_main_sdr_count; i++) {
	    if (domain->sensors_in_main_sdr[i])
		ipmi_sensor_destroy(domain->sensors_in_main_sdr[i]);
	}
	ipmi_mem_free(domain->sensors_in_main_sdr);
    }

    if (domain->activate_timer_info) {
	if (domain->activate_timer_info->lock) {
	    ipmi_lock(domain->activate_timer_info->lock);
	    if (domain->activate_timer) {
		int arv = 0;
		if (domain->activate_timer_info->running)
		    arv = domain->os_hnd->stop_timer(domain->os_hnd,
						     domain->activate_timer);

		if (!arv) {
		    /* If we can stop the timer, free it and it's info.
		       If we can't stop the timer, that means that the
		       code is currently in the timer handler, so we let
		       the "cancelled" value do this for us. */
		    domain->os_hnd->free_timer(domain->os_hnd,
					       domain->activate_timer);
		    ipmi_unlock(domain->activate_timer_info->lock);
		    ipmi_destroy_lock(domain->activate_timer_info->lock);
		    ipmi_mem_free(domain->activate_timer_info);
		} else {
		    domain->activate_timer_info->cancelled = 1;
		    ipmi_unlock(domain->activate_timer_info->lock);
		}
	    } else {
		ipmi_unlock(domain->activate_timer_info->lock);
		ipmi_destroy_lock(domain->activate_timer_info->lock);
	    }
	} else {
	    ipmi_mem_free(domain->activate_timer_info);
	}
    }

    /* We cleanup the MCs twice.  Some MCs may not be destroyed (but
       only left inactive) in the first pass due to references form
       other MCs SDR repositories.  The second pass will get them
       all. */
    ilist_iter(domain->mc_list, iterate_cleanup_mc, NULL);
    ilist_iter(domain->mc_list, iterate_cleanup_mc, NULL);

    if (domain->si_mc)
	_ipmi_cleanup_mc(domain->si_mc);

    /* Destroy the main SDR repository, if it exists. */
    if (domain->main_sdrs)
	ipmi_sdr_info_destroy(domain->main_sdrs, NULL, NULL);

    if (domain->bus_scan_timer_info) {
	domain->bus_scan_timer_info->cancelled = 1;
	rv = domain->os_hnd->stop_timer(domain->os_hnd,
					domain->bus_scan_timer);
	if (!rv) {
	    /* If we can stop the timer, free it and it's info.
	       If we can't stop the timer, that means that the
	       code is currently in the timer handler, so we let
	       the "cancelled" value do this for us. */
	    domain->os_hnd->free_timer(domain->os_hnd,
				       domain->bus_scan_timer);
	    ipmi_mem_free(domain->bus_scan_timer_info);
	}
    }

    ipmi_lock(domain->event_handlers_lock);
    while (domain->event_handlers)
	remove_event_handler(domain, domain->event_handlers);
    ipmi_unlock(domain->event_handlers_lock);

    if (domain->mc_list)
	free_ilist(domain->mc_list);
    if (domain->con_change_handlers) {
	ilist_iter_t iter;
	void         *data;
	ilist_init_iter(&iter, domain->con_change_handlers);
	while (ilist_first(&iter)) {
	    data = ilist_get(&iter);
	    ilist_delete(&iter);
	    ipmi_mem_free(data);
	}
	free_ilist(domain->con_change_handlers);
    }
    if (domain->ipmb_ignores) {
	ilist_iter_t iter;
	ilist_init_iter(&iter, domain->ipmb_ignores);
	while (ilist_first(&iter)) {
	    ilist_delete(&iter);
	}
	free_ilist(domain->ipmb_ignores);
    }
    if (domain->bus_scans_running) {
	mc_ipmb_scan_info_t *item;
	while (domain->bus_scans_running) {
	    item = domain->bus_scans_running;
	    domain->bus_scans_running = item->next;
	    ipmi_mem_free(item);
	}
    }
    if (domain->mc_list_lock)
	ipmi_destroy_lock(domain->mc_list_lock);
    if (domain->event_handlers_lock)
	ipmi_destroy_lock(domain->event_handlers_lock);
    for (i=0; i<MAX_CONS; i++) {
	if (!domain->conn[i])
	    continue;

	if (domain->ll_event_id[i])
	    domain->conn[i]->deregister_for_events(domain->conn[i],
						   domain->ll_event_id[i]);

	/* Remove the connection fail handler. */
	domain->conn[i]->set_con_change_handler(domain->conn[i], NULL,  NULL);
    }
    /* Destroy the entities last, since sensors and controls may
       refer to them. */
    if (domain->entities)
	ipmi_entity_info_destroy(domain->entities);
    if (domain->entities_lock)
	ipmi_destroy_lock(domain->entities_lock);

    ipmi_mem_free(domain);
}

static int
setup_domain(ipmi_con_t    *ipmi[],
	     int           num_con,
	     ipmi_domain_t **new_domain)
{
    struct timeval               timeout;
    ipmi_domain_t                *domain;
    int                          rv;
    ipmi_system_interface_addr_t si;
    int                          i, j;

    domain = ipmi_mem_alloc(sizeof(*domain));
    if (!domain)
	return ENOMEM;
    memset(domain, 0, sizeof(*domain));

    domain->os_hnd = ipmi[0]->os_hnd;

    domain->valid = 1;

    for (i=0; i<num_con; i++) {
	domain->conn[i] = ipmi[i];
	domain->con_ipmb_addr[i] = 0x20; /* Assume this until told othersize */
	domain->con_active[i] = 1;
	domain->con_up[i] = 0;

	for (j=0; j<MAX_PORTS_PER_CON; j++)
	    domain->port_up[j][i] = -1;
    }

    domain->connection_up = 0;

    /* Create the locks before anything else. */
    domain->mc_list_lock = NULL;
    domain->entities_lock = NULL;
    domain->event_handlers_lock = NULL;
    domain->default_sel_rescan_time = IPMI_SEL_QUERY_INTERVAL;

    /* Set the default timer intervals. */
    domain->bus_scan_interval = IPMI_RESCAN_BUS_INTERVAL;

    rv = ipmi_create_lock(domain, &domain->mc_list_lock);
    if (rv)
	goto out_err;
    /* Lock this first thing. */
    ipmi_lock(domain->mc_list_lock);

    rv = ipmi_create_lock(domain, &domain->entities_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock(domain, &domain->event_handlers_lock);
    if (rv)
	goto out_err;

    domain->activate_timer_info = ipmi_mem_alloc(sizeof(activate_timer_info_t));
    if (!domain->activate_timer_info) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->activate_timer_info->lock = NULL;
    domain->activate_timer_info->domain = domain;
    domain->activate_timer_info->cancelled = 0;
    domain->activate_timer_info->os_hnd = domain->os_hnd;

    rv = ipmi_create_lock(domain, &domain->activate_timer_info->lock);
    if (rv)
	goto out_err;

    rv = domain->os_hnd->alloc_timer(domain->os_hnd,
				     &(domain->activate_timer));
    if (rv)
	goto out_err;

    domain->main_sdrs = NULL;
    domain->scanning_bus = 0;
    domain->event_handlers = NULL;
    domain->oem_event_handler = NULL;
    domain->mc_list = NULL;
    domain->entities = NULL;
    domain->entity_handler = NULL;
    domain->do_bus_scan = 1;

    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = IPMI_BMC_CHANNEL;
    si.lun = 0;
    rv = _ipmi_create_mc(domain,
			 (ipmi_addr_t *) &si, sizeof(si),
			 &domain->si_mc);
    if (rv)
	goto out_err;

    rv = ipmi_sdr_info_alloc(domain, domain->si_mc, 0, 0, &domain->main_sdrs);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock(domain, &domain->cmds_lock);
    if (rv)
	goto out_err;

    domain->cmds = alloc_ilist();
    if (! domain->cmds) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->mc_list = alloc_ilist();
    if (! domain->mc_list) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->con_change_handlers = alloc_ilist();
    if (! domain->con_change_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->ipmb_ignores = alloc_ilist();
    if (! domain->ipmb_ignores) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->bus_scans_running = NULL;

    domain->bus_scan_timer_info = ipmi_mem_alloc(sizeof(rescan_bus_info_t));
    if (!domain->bus_scan_timer_info) {
	rv = ENOMEM;
	goto out_err;
    }
	
    domain->bus_scan_timer_info->domain = domain;
    domain->bus_scan_timer_info->os_hnd = domain->os_hnd;
    domain->bus_scan_timer_info->cancelled = 0;
    rv = domain->os_hnd->alloc_timer(domain->os_hnd,
				     &(domain->bus_scan_timer));
    if (rv)
	goto out_err;

    timeout.tv_sec = domain->bus_scan_interval;
    timeout.tv_usec = 0;
    domain->os_hnd->start_timer(domain->os_hnd,
				domain->bus_scan_timer,
				&timeout,
				domain_rescan_bus,
				domain->bus_scan_timer_info);

    rv = ipmi_entity_info_alloc(domain, &(domain->entities));
    if (rv)
	goto out_err;

    memset(domain->chan, 0, sizeof(domain->chan));

 out_err:
    if (domain->mc_list_lock)
	ipmi_unlock(domain->mc_list_lock);

    if (rv)
	cleanup_domain(domain);
    else
	*new_domain = domain;

    return rv;
}

/***********************************************************************
 *
 * Locking handling
 *
 **********************************************************************/

#ifdef IPMI_CHECK_LOCKS
void
__ipmi_check_domain_lock(ipmi_domain_t *domain)
{
    ipmi_check_lock(domain->mc_list_lock,
		    "MC not locked when it should have been");
}

void
__ipmi_check_domain_entity_lock(ipmi_domain_t *domain)
{
    ipmi_check_lock(domain->entities_lock,
		    "Entity not locked when it should have been");
}
#endif

void
ipmi_domain_entity_lock(ipmi_domain_t *domain)
{
    CHECK_DOMAIN_LOCK(domain);
    ipmi_lock(domain->entities_lock);
}

void
ipmi_domain_entity_unlock(ipmi_domain_t *domain)
{
    CHECK_DOMAIN_LOCK(domain);
    ipmi_unlock(domain->entities_lock);
}

/***********************************************************************
 *
 * Domain validation
 *
 **********************************************************************/

/* A list of all the registered domains. */
static ipmi_domain_t *domains = NULL;

static void
add_known_domain(ipmi_domain_t *domain)
{
    domain->prev = NULL;
    domain->next = domains;
    if (domains)
	domains->prev = domain;
    domains = domain;
}

static void
remove_known_domain(ipmi_domain_t *domain)
{
    if (domain->next)
	domain->next->prev = domain->prev;
    if (domain->prev)
	domain->prev->next = domain->next;
    else
	domains = domain->next;
}

/* Validate that the domain and it's underlying connection is valid.
   This must be called with the read lock held. */
static int
ipmi_domain_validate(ipmi_domain_t *domain)
{
    ipmi_domain_t *c;

    c = domains;
    while (c != NULL) {
	if (c == domain)
	    break;
	c = c->next;
    }
    if (c == NULL)
	return EINVAL;

    /* We do this check after we find the domain in the list, because
       want to make sure the pointer is good before we do this. */
    if (!domain->valid)
	return EINVAL;

    return 0;
}

/***********************************************************************
 *
 * MC handling
 *
 **********************************************************************/

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
    ipmi_addr_t   addr;
    unsigned int  addr_len;

    ipmi_mc_get_ipmi_address(mc, &addr, &addr_len);

    return ipmi_addr_equal(&addr, addr_len,
			   &(info->addr), info->addr_len);
}

ipmi_mc_t *
_ipmi_find_mc_by_addr(ipmi_domain_t *domain,
		      ipmi_addr_t   *addr,
		      unsigned int  addr_len)
{
    mc_cmp_info_t    info;

    if (addr_len > sizeof(ipmi_addr_t))
	return NULL;

    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	return domain->si_mc;
    }

    memcpy(&(info.addr), addr, addr_len);
    info.addr_len = addr_len;
    return ilist_search(domain->mc_list, mc_cmp, &info);

    return NULL;
}

static int
in_ipmb_ignores(ipmi_domain_t *domain, unsigned char ipmb_addr)
{
    unsigned long addr;
    ilist_iter_t iter;

    ilist_init_iter(&iter, domain->ipmb_ignores);
    ilist_unpositioned(&iter);
    while (ilist_next(&iter)) {
	addr = (unsigned long) ilist_get(&iter);
	if (addr == ipmb_addr)
	    return 1;
    }

    return 0;
}

int
ipmi_domain_add_ipmb_ignore(ipmi_domain_t *domain, unsigned char ipmb_addr)
{
    unsigned long addr = ipmb_addr;

    if (! ilist_add_tail(domain->ipmb_ignores, (void *) addr, NULL))
	return ENOMEM;

    return 0;
}

static int
add_mc_to_domain(ipmi_domain_t *domain, ipmi_mc_t *mc)
{
    int rv = 0;
    int success;

    CHECK_DOMAIN_LOCK(domain);

    ipmi_lock(domain->mc_list_lock);
    success = ilist_add_tail(domain->mc_list, mc, NULL);
    if (!success)
	rv = ENOMEM;
    ipmi_unlock(domain->mc_list_lock);

    return rv;
}

int
_ipmi_remove_mc_from_domain(ipmi_domain_t *domain, ipmi_mc_t *mc)
{
    int          rv;
    int          found = 0;
    ilist_iter_t iter;

    ipmi_lock(domain->mc_list_lock);
    ilist_init_iter(&iter, domain->mc_list);
    rv = ilist_first(&iter);
    while (rv) {
	if (ilist_get(&iter) == mc) {
	    ilist_delete(&iter);
	    found = 1;
	    break;
	}
	rv = ilist_next(&iter);
    }
    ipmi_unlock(domain->mc_list_lock);

    if (found)
	return 0;
    else
	return ENODEV;
}

int
_ipmi_find_or_create_mc_by_slave_addr(ipmi_domain_t *domain,
				      unsigned int  slave_addr,
				      ipmi_mc_t     **new_mc)
{
    ipmi_mc_t        *mc;
    ipmi_ipmb_addr_t addr;
    int              rv;

    addr.addr_type = IPMI_IPMB_ADDR_TYPE;
    addr.channel = 0;
    addr.lun = 0;
    addr.slave_addr = slave_addr;

    mc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &addr, sizeof(addr));
    if (mc) {
	*new_mc = mc;
	return 0;
    }

    rv = _ipmi_create_mc(domain, (ipmi_addr_t *) &addr, sizeof(addr), &mc);
    if (rv)
	return rv;

    _ipmi_mc_set_active(mc, 0);

    rv = add_mc_to_domain(domain, mc);
    if (rv) {
	_ipmi_cleanup_mc(mc);
	return rv;
    }

    *new_mc = mc;
    return 0;
}

/***********************************************************************
 *
 * Command/response handling
 *
 **********************************************************************/

static int cmp_nmsg(void *item, void *cb_data)
{
    ll_msg_t *nmsg1 = item;
    ll_msg_t *nmsg2 = cb_data;

    return ((nmsg1 == nmsg2)
	    && (nmsg1->domain == nmsg2->domain));
}

static int
find_and_remove_msg(ipmi_domain_t *domain, ll_msg_t *nmsg, long seq)
{
    ilist_iter_t iter;
    int          rv = 0;

    ipmi_lock(domain->cmds_lock);
    ilist_init_iter(&iter, domain->cmds);
    ilist_unpositioned(&iter);
    if ((ilist_search_iter(&iter, cmp_nmsg, nmsg) != NULL)
	&& (nmsg->seq == seq))
    {
	ilist_delete(&iter);
	rv = 1;
    }
    ipmi_unlock(domain->cmds_lock);
    return rv;
}

static void
ll_rsp_handler(ipmi_con_t   *ipmi,
	       ipmi_addr_t  *addr,
	       unsigned int addr_len,
	       ipmi_msg_t   *msg,
	       void         *rsp_data1,
	       void         *rsp_data2,
	       void         *rsp_data3,
	       void         *rsp_data4)
{
    ipmi_domain_t                *domain = rsp_data1;
    ll_msg_t                     *nmsg = rsp_data2;
    long                         seq = (long) rsp_data3;
    int                          rv;

    ipmi_read_lock();
    rv = ipmi_domain_validate(domain);
    if (rv)
	goto out_unlock;

    if (!find_and_remove_msg(domain, nmsg, seq))
	goto out_unlock;

    if (nmsg->rsp_handler)
	nmsg->rsp_handler(domain, addr, addr_len, msg,
			  nmsg->rsp_data1, nmsg->rsp_data2);
    ipmi_mem_free(nmsg);
 out_unlock:
    ipmi_read_unlock();
}

int
ipmi_send_command_addr(ipmi_domain_t                *domain,
		       ipmi_addr_t		    *addr,
		       unsigned int                 addr_len,
		       ipmi_msg_t                   *msg,
		       ipmi_addr_response_handler_t rsp_handler,
		       void                         *rsp_data1,
		       void                         *rsp_data2)
{
    int      rv;
    int      u;
    ll_msg_t *nmsg;

    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    if (msg->data_len > IPMI_MAX_MSG_LENGTH)
	return EINVAL;

    CHECK_DOMAIN_LOCK(domain);

    nmsg = ipmi_mem_alloc(sizeof(*nmsg));
    if (!nmsg)
	return ENOMEM;

    u = domain->working_conn;

    /* If we don't have any working connection, just use connection
       zero. */
    if (u == -1)
	u = 0;

    nmsg->domain = domain;
    nmsg->con = u;
    memcpy(&nmsg->addr, addr, addr_len);
    nmsg->addr_len = addr_len;

    memcpy(&nmsg->msg, msg, sizeof(nmsg->msg));
    nmsg->msg.data = nmsg->msg_data;
    nmsg->msg.data_len = msg->data_len;
    memcpy(nmsg->msg.data, msg->data, msg->data_len);

    nmsg->rsp_handler = rsp_handler;
    nmsg->rsp_data1 = rsp_data1;
    nmsg->rsp_data2 = rsp_data2;

    ipmi_lock(domain->cmds_lock);
    nmsg->seq = domain->cmds_seq;
    domain->cmds_seq++;

    rv = domain->conn[u]->send_command(domain->conn[u],
				       addr, addr_len,
				       msg,
				       ll_rsp_handler,
				       domain,
				       nmsg,
				       (void *) nmsg->seq,
				       NULL);

    if (!rv)
	ilist_add_tail(domain->cmds, nmsg, &nmsg->link);
    ipmi_unlock(domain->cmds_lock);

    return rv;
}

/* Take all the commands for any inactive or down connection and
   resend them on another connection.  */
static void
reroute_cmds(ipmi_domain_t *domain, int new_con)
{
    ilist_iter_t iter;
    int          rv;
    ll_msg_t     *nmsg;

    ipmi_lock(domain->cmds_lock);
    ilist_init_iter(&iter, domain->cmds);
    rv = ilist_first(&iter);
    while (rv) {
	nmsg = ilist_get(&iter);
	if ((!domain->con_active[nmsg->con])
	    || (!domain->con_up[nmsg->con]))
	{
	    nmsg->seq = domain->cmds_seq;
	    domain->cmds_seq++; /* Make the message unique so a
                                   response from the other connection
                                   will not match. */
	    nmsg->con = new_con;

	    rv = domain->conn[new_con]->send_command(domain->conn[new_con],
						     &nmsg->addr,
						     nmsg->addr_len,
						     &nmsg->msg,
						     ll_rsp_handler,
						     domain,
						     nmsg,
						     (void *) nmsg->seq,
						     NULL);
	    if (rv) {
		/* Couldn't send the message, just fail it. */
		if (nmsg->rsp_handler) {
		    ipmi_msg_t    msg;
		    unsigned char err;

		    msg.netfn = nmsg->msg.netfn | 1;
		    msg.cmd = nmsg->msg.cmd;
		    msg.data = &err;
		    msg.data_len = 1;
		    err = IPMI_UNKNOWN_ERR_CC;
		    nmsg->rsp_handler(domain, &nmsg->addr, nmsg->addr_len,
				      &nmsg->msg,
				      nmsg->rsp_data1, nmsg->rsp_data2);
		}
		rv = ilist_delete(&iter);
		ipmi_mem_free(nmsg);
		continue;
	    }
	}
	rv = ilist_next(&iter);
    }
    ipmi_unlock(domain->cmds_lock);
}

/***********************************************************************
 *
 * Bus scanning
 *
 **********************************************************************/

/* This is the number of device ID queries that an MC must not respond
   to in a row to be considered dead. */
#define MAX_MC_MISSED_RESPONSES 10

void
ipmi_domain_set_ipmb_rescan_time(ipmi_domain_t *domain, unsigned int seconds)
{
    CHECK_DOMAIN_LOCK(domain);

    domain->bus_scan_interval = seconds;
}

unsigned int
ipmi_domain_get_ipmb_rescan_time(ipmi_domain_t *domain)
{
    CHECK_DOMAIN_LOCK(domain);

    return domain->bus_scan_interval;
}

int
ipmi_domain_set_full_bus_scan(ipmi_domain_t *domain, int val)
{
    CHECK_DOMAIN_LOCK(domain);

    domain->do_bus_scan = val;
    return 0;
}

static void
add_bus_scans_running(ipmi_domain_t *domain, mc_ipmb_scan_info_t *info)
{
    info->next = domain->bus_scans_running;
    domain->bus_scans_running = info;
}

static void
remove_bus_scans_running(ipmi_domain_t *domain, mc_ipmb_scan_info_t *info)
{
    mc_ipmb_scan_info_t *i2;

    i2 = domain->bus_scans_running;
    if (i2 == info)
	domain->bus_scans_running = info->next;
    else
	while (i2->next != NULL) {
	    if (i2->next == info) {
		i2->next = info->next;
		break;
	    }
	    i2 = i2->next;
	}
}

static void devid_bc_rsp_handler(ipmi_domain_t *domain,
				 ipmi_addr_t   *addr,
				 unsigned int  addr_len,
				 ipmi_msg_t    *msg,
				 void          *rsp_data1,
				 void          *rsp_data2)
{
    mc_ipmb_scan_info_t *info = rsp_data1;
    int                 rv;
    ipmi_mc_t           *mc;


    ipmi_read_lock();
    rv = ipmi_domain_validate(domain);
    if (rv) {
	ipmi_log(IPMI_LOG_INFO,
		 "BMC went away while scanning for MCs");
	ipmi_read_unlock();
	return;
    }

    ipmi_lock(domain->mc_list_lock);

    mc = _ipmi_find_mc_by_addr(domain, addr, addr_len);
    if (msg->data[0] == 0) {
	if (mc && ipmi_mc_is_active(mc)
	    && !_ipmi_mc_device_data_compares(mc, msg))
	{
	    /* The MC was replaced with a new one, so clear the old
               one and add a new one. */
	    _ipmi_cleanup_mc(mc);
	    mc = NULL;
	}
	if (!mc || !ipmi_mc_is_active(mc)) {
	    /* It doesn't already exist, or it's inactive, so add
               it. */
	    if (!mc) {
		/* If it's not there, then add it.  If it's just not
                   active, reuse the same data. */
		rv = _ipmi_create_mc(domain, addr, addr_len, &mc);
		if (rv) {
		    /* Out of memory, just give up for now. */
		    remove_bus_scans_running(domain, info);
		    ipmi_mem_free(info);
		    ipmi_unlock(domain->mc_list_lock);
		    goto out;
		}

		rv = add_mc_to_domain(domain, mc);
		if (rv) {
		    _ipmi_cleanup_mc(mc);
		    goto next_addr;
		}
	    }

	    rv = _ipmi_mc_get_device_id_data_from_rsp(mc, msg);
	    if (rv) {
		/* If we couldn't handle the device data, just clean
                   it up */
		_ipmi_cleanup_mc(mc);
	    } else
		_ipmi_mc_handle_new(mc);
	} else {
	    /* Periodically check the event receiver for existing MCs. */
	    _ipmi_mc_check_event_rcvr(mc);
	}
    } else if (mc && ipmi_mc_is_active(mc)) {
	/* Didn't get a response.  Maybe the MC has gone away? */
	info->missed_responses++;
	if (info->missed_responses >= MAX_MC_MISSED_RESPONSES) {
	    _ipmi_cleanup_mc(mc);
	    goto next_addr;
	} else {
	    /* Try again right now. */
	    ipmi_unlock(domain->mc_list_lock);
	    goto retry_addr;
	}
    }

 next_addr:
    ipmi_unlock(domain->mc_list_lock);

 next_addr_nolock:
    if (info->addr.slave_addr >= info->end_addr) {
	/* We've hit the end, we can quit now. */
	if (info->done_handler)
	    info->done_handler(domain, 0, info->cb_data);
	remove_bus_scans_running(domain, info);
	ipmi_mem_free(info);
	goto out;
    }
    info->addr.slave_addr += 2;
    info->missed_responses = 0;
    if (in_ipmb_ignores(domain, info->addr.slave_addr))
	goto next_addr_nolock;

 retry_addr:
    rv = ipmi_send_command_addr(domain,
				(ipmi_addr_t *) &(info->addr),
				sizeof(info->addr),
				&(info->msg),
				devid_bc_rsp_handler,
				info, NULL);
    if (rv)
	goto next_addr_nolock;

 out:
    ipmi_read_unlock();
}

void
ipmi_start_ipmb_mc_scan(ipmi_domain_t  *domain,
	       		int            channel,
	       		unsigned int   start_addr,
			unsigned int   end_addr,
			ipmi_domain_cb done_handler,
			void           *cb_data)
{
    mc_ipmb_scan_info_t *info;
    int                 rv;

    CHECK_DOMAIN_LOCK(domain);

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return;

    info->domain = domain;
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
    info->missed_responses = 0;
    rv = ipmi_send_command_addr(domain,
				(ipmi_addr_t *) &(info->addr),
				sizeof(info->addr),
				&(info->msg),
				devid_bc_rsp_handler,
				info, NULL);
    while ((rv) && (info->addr.slave_addr < end_addr)) {
	info->addr.slave_addr += 2;
	rv = ipmi_send_command_addr(domain,
				    (ipmi_addr_t *) &(info->addr),
				    sizeof(info->addr),
				    &(info->msg),
				    devid_bc_rsp_handler,
				    info, NULL);
    }

    if (rv)
	ipmi_mem_free(info);
    else
	add_bus_scans_running(domain, info);
}

static void
mc_scan_done(ipmi_domain_t *domain, int err, void *cb_data)
{
    domain->scanning_bus = 0;
}

static void
start_mc_scan(ipmi_domain_t *domain)
{
    int i;

    if (!domain->do_bus_scan)
	return;

    if (domain->scanning_bus)
	return;

    domain->scanning_bus = 1;

    for (i=0; i<MAX_IPMI_USED_CHANNELS; i++) {
	if (domain->chan[i].medium == 1) /* IPMB */
	    ipmi_start_ipmb_mc_scan(domain, i, 0x10, 0xf0, mc_scan_done, NULL);
    }
}

static void
domain_rescan_bus(void *cb_data, os_hnd_timer_id_t *id)
{
    struct timeval    timeout;
    rescan_bus_info_t *info = cb_data;
    ipmi_domain_t     *domain = info->domain;

    if (info->cancelled) {
	info->os_hnd->free_timer(info->os_hnd, id);
	ipmi_mem_free(info);
	return;
    }

    /* Only operate if we know a connection is up. */
    if (domain->connection_up) {
	/* Rescan all the presence sensors to make sure they are valid. */
	ipmi_detect_domain_presence_changes(domain, 1);

	ipmi_lock(domain->mc_list_lock);
	start_mc_scan(domain);
	ipmi_unlock(domain->mc_list_lock);
    }

    timeout.tv_sec = domain->bus_scan_interval;
    timeout.tv_usec = 0;
    domain->os_hnd->start_timer(domain->os_hnd,
				id,
				&timeout,
				domain_rescan_bus,
				info);
}

/***********************************************************************
 *
 * Incoming event handling.
 *
 **********************************************************************/

struct ipmi_event_handler_id_s
{
    ipmi_domain_t         *domain;
    ipmi_event_handler_cb handler;
    void                  *event_data;

    ipmi_event_handler_id_t *next, *prev;
};

/* Must be called with event_lock held. */
static void
add_event_handler(ipmi_domain_t           *domain,
		  ipmi_event_handler_id_t *event)
{
    event->domain = domain;
    event->next = domain->event_handlers;
    event->prev = NULL;
    if (domain->event_handlers)
	domain->event_handlers->prev = event;
    domain->event_handlers = event;
}

static int
remove_event_handler(ipmi_domain_t           *domain,
		     ipmi_event_handler_id_t *event)
{
    ipmi_event_handler_id_t *ev;

    ev = domain->event_handlers;
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
	domain->event_handlers = event->next;

    ipmi_mem_free(event);

    return 0;
}

typedef struct event_sensor_info_s
{
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

void
_ipmi_domain_system_event_handler(ipmi_domain_t *domain,
				  ipmi_mc_t     *mc,
				  ipmi_event_t  *event)
{
    int                 rv = 1;
    unsigned long       timestamp;

    if (DEBUG_EVENTS) {
	ipmi_log(IPMI_LOG_DEBUG,
		 "Event recid mc (0x%x):%4.4x type:%2.2x:"
		 " %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x"
		 " %2.2x %2.2x %2.2x %2.2x %2.2x",
		 event->mcid.mc_num,
		 event->record_id, event->type,
		 event->data[0], event->data[1], event->data[2],
		 event->data[3], event->data[4], event->data[5],
		 event->data[6], event->data[7], event->data[8],
		 event->data[9], event->data[10], event->data[11],
		 event->data[12]);
    }

    /* Let the OEM handler for the MC that the message came from have
       a go at it first.  Note that OEM handlers must look at the time
       themselves. */
    if (_ipmi_mc_check_sel_oem_event_handler(mc, event))
	return;

    timestamp = ipmi_get_uint32(&(event->data[0]));

    /* It's a system event record from an MC, and the timestamp is
       later than our startup timestamp. */
    if ((event->type == 0x02)
	&& ((event->data[4] & 0x01) == 0)
	&& (timestamp >= ipmi_mc_get_startup_SEL_time(mc)))
    {
	ipmi_mc_t           *mc;
	ipmi_ipmb_addr_t    addr;
	ipmi_sensor_id_t    id;
	event_sensor_info_t info;

	addr.addr_type = IPMI_IPMB_ADDR_TYPE;
	/* See if the MC has an OEM handler for this. */
	if (event->data[6] == 0x03) {
	    addr.channel = 0;
	} else {
	    addr.channel = event->data[5] >> 4;
	}
	addr.slave_addr = event->data[4];
	addr.lun = 0;

	mc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &addr, sizeof(addr));
	if (!mc)
	    goto out;

	/* Let the OEM handler for the MC that sent the event try
	   next. */
	if (_ipmi_mc_check_oem_event_handler(mc, event))
	    return;

	/* The OEM code didn't handle it. */
	id.mcid = _ipmi_mc_convert_to_id(mc);
	id.lun = event->data[5] & 0x3;
	id.sensor_num = event->data[8];

	info.event = event;

	rv = ipmi_sensor_pointer_cb(id, event_sensor_cb, &info);
	if (!rv)
	    rv = info.err;
    }

 out:
    /* It's an event from system software, or the info couldn't be found. */
    if (rv)
	ipmi_handle_unhandled_event(domain, event);
}

static void
ll_event_handler(ipmi_con_t   *ipmi,
		 ipmi_addr_t  *addr,
		 unsigned int addr_len,
		 ipmi_msg_t   *event,
		 void         *event_data,
		 void         *data2)
{
    ipmi_event_t  devent;
    ipmi_domain_t *domain = data2;
    ipmi_mc_t     *mc;
    int           rv;

    ipmi_read_lock();
    rv = ipmi_domain_validate(domain);
    if (rv)
	goto out;

    /* It came from an MC, so find the MC. */
    mc = _ipmi_find_mc_by_addr(domain, addr, addr_len);
    if (!mc)
	goto out;

    devent.mcid = _ipmi_mc_convert_to_id(mc);
    devent.record_id = ipmi_get_uint16(event->data);
    devent.type = event->data[2];
    memcpy(devent.data, event+3, IPMI_MAX_SEL_DATA);

    /* Add it to the mc's event log. */
    _ipmi_mc_sel_event_add(mc, &devent);

    /* Call the handler on it. */
    _ipmi_domain_system_event_handler(domain, mc, &devent);

 out:
    ipmi_read_unlock();
}

void
ipmi_handle_unhandled_event(ipmi_domain_t *domain, ipmi_event_t *event)
{
    ipmi_event_handler_id_t *l;

    ipmi_lock(domain->event_handlers_lock);
    l = domain->event_handlers;
    while (l) {
	l->handler(domain, event, l->event_data);
	l = l->next;
    }
    ipmi_unlock(domain->event_handlers_lock);
}

int
ipmi_register_for_events(ipmi_domain_t           *domain,
			 ipmi_event_handler_cb   handler,
			 void                    *event_data,
			 ipmi_event_handler_id_t **id)
{
    ipmi_event_handler_id_t *elem;

    CHECK_DOMAIN_LOCK(domain);

    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem)
	return ENOMEM;
    elem->handler = handler;
    elem->event_data = event_data;

    ipmi_lock(domain->event_handlers_lock);
    add_event_handler(domain, elem);
    ipmi_unlock(domain->event_handlers_lock);

    *id = elem;

    return 0;
}

int
ipmi_deregister_for_events(ipmi_domain_t           *domain,
			   ipmi_event_handler_id_t *id)
{
    int        rv;

    CHECK_DOMAIN_LOCK(domain);

    ipmi_lock(domain->event_handlers_lock);
    rv = remove_event_handler(domain, id);
    ipmi_unlock(domain->event_handlers_lock);

    return rv;
}

int
ipmi_domain_disable_events(ipmi_domain_t *domain)
{
    int rv;
    int return_rv = 0;
    int i;

    CHECK_DOMAIN_LOCK(domain);

    for (i=0; i<MAX_CONS; i++) {
	if (! domain->ll_event_id[i])
	    continue;

	rv = domain->conn[i]->deregister_for_events(domain->conn[i],
						    domain->ll_event_id[i]);
	if (!rv)
	    domain->ll_event_id[i] = NULL;
	else if (!return_rv)
	    return_rv = rv;
    }
    return return_rv;
}

int
ipmi_domain_enable_events(ipmi_domain_t *domain)
{
    int return_rv = 0;
    int rv;
    int i;

    CHECK_DOMAIN_LOCK(domain);

    for (i=0; i<MAX_CONS; i++) {
	if (domain->ll_event_id[i])
	    continue;

	if (! domain->conn[i])
	    continue;

	rv = domain->conn[i]->register_for_events(domain->conn[i],
						  ll_event_handler,
						  NULL, domain,
						  &(domain->ll_event_id[i]));
	if (!return_rv)
	    return_rv = rv;
    }
    return return_rv;
}

/***********************************************************************
 *
 * SEL handling
 *
 **********************************************************************/

typedef struct del_event_info_s
{
    ipmi_domain_t  *domain;
    ipmi_event_t   *event;
    ipmi_domain_cb done_handler;
    void           *cb_data;
    int            rv;
} del_event_info_t;

static void
mc_del_event_done(ipmi_mc_t *mc, int err, void *cb_data)
{
    del_event_info_t *info = cb_data;

    if (info->done_handler)
	info->done_handler(info->domain, err, info->cb_data);
    ipmi_mem_free(info);
}

static void
del_event_handler(ipmi_mc_t *mc, void *cb_data)
{
    del_event_info_t *info = cb_data;
    int              rv;

    rv = _ipmi_mc_del_event(mc, info->event, mc_del_event_done, info);
    if (rv) {
	if (info->done_handler)
	    info->done_handler(info->domain, rv, info->cb_data);
	ipmi_mem_free(info);
    }
}

int
ipmi_domain_del_event(ipmi_domain_t  *domain,
		      ipmi_event_t   *event,
		      ipmi_domain_cb done_handler,
		      void           *cb_data)
{
    int              rv;
    del_event_info_t *info;

    CHECK_DOMAIN_LOCK(domain);

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->domain = domain;
    info->event = event;
    info->done_handler = done_handler;
    info->cb_data = cb_data;
    info->rv = 0;
    rv = _ipmi_mc_pointer_cb(event->mcid, del_event_handler, info);
    if (rv) {
	ipmi_mem_free(info);
	return rv;
    }
    return rv;
}

typedef struct next_event_handler_info_s
{
    int          rv;
    ipmi_event_t *event;
    int          found_curr_mc;
    int          do_prev; /* If going backwards, this will be 1. */
} next_event_handler_info_t;

static void
next_event_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    next_event_handler_info_t *info = cb_data;
    ipmi_mcid_t               mcid = _ipmi_mc_convert_to_id(mc);

    if (!info->rv)
	/* We've found an event already, just return. */
	return;

    if (info->do_prev) {
	if (info->found_curr_mc)
	    /* We've found the MC that had the event, but it didn't have
	       any more events.  Look for last events now. */
	    info->rv = _ipmi_mc_last_event(mc, info->event);
	else if (_ipmi_cmp_mc_id(info->event->mcid, mcid) == 0) {
	    info->found_curr_mc = 1;
	    info->rv = _ipmi_mc_prev_event(mc, info->event);
	}
    } else {
	if (info->found_curr_mc)
	    /* We've found the MC that had the event, but it didn't have
	       any more events.  Look for first events now. */
	    info->rv = _ipmi_mc_first_event(mc, info->event);
	else if (_ipmi_cmp_mc_id(info->event->mcid, mcid) == 0) {
	    info->found_curr_mc = 1;
	    info->rv = _ipmi_mc_next_event(mc, info->event);
	}
    }
}

int
ipmi_domain_first_event(ipmi_domain_t *domain, ipmi_event_t *event)
{
    int                       rv;
    next_event_handler_info_t info;

    CHECK_DOMAIN_LOCK(domain);

    info.rv = ENODEV;
    info.event = event;
    info.found_curr_mc = 1;
    info.do_prev = 0;
    rv = ipmi_domain_iterate_mcs(domain, next_event_handler, &info);
    if (!rv)
	rv = info.rv;

    return rv;
}

int
ipmi_domain_last_event(ipmi_domain_t *domain, ipmi_event_t *event)
{
    int                       rv;
    next_event_handler_info_t info;

    CHECK_DOMAIN_LOCK(domain);

    info.rv = ENODEV;
    info.event = event;
    info.found_curr_mc = 1;
    info.do_prev = 1;
    rv = ipmi_domain_iterate_mcs_rev(domain, next_event_handler, &info);
    if (!rv)
	rv = info.rv;

    return rv;
}

int
ipmi_domain_next_event(ipmi_domain_t *domain, ipmi_event_t *event)
{
    int                       rv;
    next_event_handler_info_t info;

    CHECK_DOMAIN_LOCK(domain);

    info.rv = ENODEV;
    info.event = event;
    info.found_curr_mc = 0;
    info.do_prev = 0;
    rv = ipmi_domain_iterate_mcs(domain, next_event_handler, &info);
    if (!rv)
	rv = info.rv;

    return rv;
}

int
ipmi_domain_prev_event(ipmi_domain_t *domain, ipmi_event_t *event)
{
    int                       rv;
    next_event_handler_info_t info;

    CHECK_DOMAIN_LOCK(domain);

    info.rv = ENODEV;
    info.event = event;
    info.found_curr_mc = 0;
    info.do_prev = 1;
    rv = ipmi_domain_iterate_mcs_rev(domain, next_event_handler, &info);
    if (!rv)
	rv = info.rv;

    return rv;
}

static void
sel_count_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    int *count = cb_data;

    *count += _ipmi_mc_sel_count(mc);
}

int
ipmi_domain_sel_count(ipmi_domain_t *domain,
		      unsigned int  *count)
{
    CHECK_DOMAIN_LOCK(domain);

    *count = 0;
    ipmi_domain_iterate_mcs(domain, sel_count_handler, count);
    return 0;
}

static void
sel_entries_used_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    int *count = cb_data;

    *count += _ipmi_mc_sel_entries_used(mc);
}

int ipmi_domain_sel_entries_used(ipmi_domain_t *domain,
				 unsigned int  *count)
{
    CHECK_DOMAIN_LOCK(domain);

    *count = 0;
    ipmi_domain_iterate_mcs(domain, sel_entries_used_handler, count);
    return 0;
}

static void
set_sel_rescan_time(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    ipmi_mc_set_sel_rescan_time(mc, domain->default_sel_rescan_time);
}

void
ipmi_domain_set_sel_rescan_time(ipmi_domain_t *domain,
				unsigned int  seconds)
{
    CHECK_DOMAIN_LOCK(domain);

    domain->default_sel_rescan_time = seconds;
    ipmi_domain_iterate_mcs(domain, set_sel_rescan_time, NULL);
}

unsigned int
ipmi_domain_get_sel_rescan_time(ipmi_domain_t *domain)
{
    CHECK_DOMAIN_LOCK(domain);

    return domain->default_sel_rescan_time;
}


/***********************************************************************
 *
 * Generic handling of entities and MCs.
 *
 **********************************************************************/

int
ipmi_detect_domain_presence_changes(ipmi_domain_t *domain, int force)
{
    int rv;

    CHECK_DOMAIN_LOCK(domain);
    
    ipmi_domain_entity_lock(domain);
    rv = ipmi_detect_ents_presence_changes(domain->entities, force);
    ipmi_domain_entity_unlock(domain);
    return rv;
}

os_handler_t *
ipmi_domain_get_os_hnd(ipmi_domain_t *domain)
{
    CHECK_DOMAIN_LOCK(domain);
    return domain->os_hnd;
}

ipmi_entity_info_t *
ipmi_domain_get_entities(ipmi_domain_t *domain)
{
    CHECK_DOMAIN_LOCK(domain);
    return domain->entities;
}

void
_ipmi_get_sdr_sensors(ipmi_domain_t *domain,
		      ipmi_mc_t     *mc,
		      ipmi_sensor_t ***sensors,
		      unsigned int  *count)
{
    if (mc) {
	_ipmi_mc_get_sdr_sensors(mc, sensors, count);
    } else {
	CHECK_DOMAIN_LOCK(domain);
	*sensors = domain->sensors_in_main_sdr;
	*count = domain->sensors_in_main_sdr_count;
    }
}

void
_ipmi_set_sdr_sensors(ipmi_domain_t *domain,
		     ipmi_mc_t     *mc,
		     ipmi_sensor_t **sensors,
		     unsigned int  count)
{
    if (mc) {
	_ipmi_mc_set_sdr_sensors(mc, sensors, count);
    } else {
	CHECK_DOMAIN_LOCK(domain);
	domain->sensors_in_main_sdr = sensors;
	domain->sensors_in_main_sdr_count = count;
    }
}

int
ipmi_domain_set_entity_update_handler(ipmi_domain_t         *domain,
				      ipmi_domain_entity_cb handler,
				      void                  *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    return ipmi_entity_set_update_handler(domain->entities,
					  handler,
					  cb_data);
}

int
ipmi_domain_iterate_entities(ipmi_domain_t                   *domain,
			     ipmi_entities_iterate_entity_cb handler,
			     void                            *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    ipmi_domain_entity_lock(domain);
    ipmi_entities_iterate_entities(domain->entities, handler, cb_data);
    ipmi_domain_entity_unlock(domain);
    return 0;
}

typedef struct iterate_mc_info_s
{
    ipmi_domain_t              *domain;
    ipmi_domain_iterate_mcs_cb handler;
    void                       *cb_data;
} iterate_mc_info_t;

static void
iterate_mcs_handler(ilist_iter_t *iter, void *item, void *cb_data)
{
    iterate_mc_info_t *info = cb_data;
    info->handler(info->domain, item, info->cb_data);
}

int
ipmi_domain_iterate_mcs(ipmi_domain_t              *domain,
			ipmi_domain_iterate_mcs_cb handler,
			void                       *cb_data)
{
    iterate_mc_info_t info = { domain, handler, cb_data };

    CHECK_DOMAIN_LOCK(domain);

    ipmi_lock(domain->mc_list_lock);
    ilist_iter(domain->mc_list, iterate_mcs_handler, &info);
    ipmi_unlock(domain->mc_list_lock);
    return 0;
}

int
ipmi_domain_iterate_mcs_rev(ipmi_domain_t              *domain,
			    ipmi_domain_iterate_mcs_cb handler,
			    void                       *cb_data)
{
    iterate_mc_info_t info = { domain, handler, cb_data };

    CHECK_DOMAIN_LOCK(domain);

    ipmi_lock(domain->mc_list_lock);
    ilist_iter_rev(domain->mc_list, iterate_mcs_handler, &info);
    ipmi_unlock(domain->mc_list_lock);
    return 0;
}

typedef struct sdrs_saved_info_s
{
    ipmi_domain_t  *domain;
    ipmi_domain_cb done;
    void           *cb_data;
} sdrs_saved_info_t;

static void
sdrs_saved(ipmi_sdr_info_t *sdrs, int err, void *cb_data)
{
    sdrs_saved_info_t *info = cb_data;

    info->done(info->domain, err, info->cb_data);
    ipmi_mem_free(info);
}

int
ipmi_domain_store_entities(ipmi_domain_t  *domain,
			   ipmi_domain_cb done,
			   void           *cb_data)
{
    int               rv;
    ipmi_sdr_info_t   *stored_sdrs;
    sdrs_saved_info_t *info;

    /* FIXME - this is certainly broken. */

    CHECK_DOMAIN_LOCK(domain);

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    /* Create an SDR repository to store. */
    rv = ipmi_sdr_info_alloc(domain, NULL, 0, 0, &stored_sdrs);
    if (rv) {
	ipmi_mem_free(info);
	return rv;
    }

    /* Now store a channel SDR in case we are less than 1.5. */
    {
	ipmi_sdr_t sdr;
	int        i;
	
	sdr.major_version = 1;
	sdr.minor_version = 0;
	sdr.type = 0x14; /*  */
	sdr.length = 11;
	for (i=0; i<8; i++) {
	    /* FIXME - what about the LUN and transmit support? */
	    if (domain->chan[i].protocol) {
		sdr.data[i] = (domain->chan[i].protocol
			       | (domain->chan[i].xmit_support << 7)
			       | (domain->chan[i].recv_lun << 4));
	    } else {
		sdr.data[i] = 0;
	    }
	}
	sdr.data[8] = domain->msg_int_type;
	sdr.data[9] = domain->event_msg_int_type;
	sdr.data[10] = 0;

	rv = ipmi_sdr_add(stored_sdrs, &sdr);
	if (rv)
	    goto out_err;
    }

    rv = ipmi_entity_append_to_sdrs(domain->entities, stored_sdrs);
    if (rv)
	goto out_err;

    info->domain = domain;
    info->done = done;
    info->cb_data = cb_data;
    rv = ipmi_sdr_save(stored_sdrs, sdrs_saved, info);

 out_err:
    if (rv)
	ipmi_mem_free(info);
    ipmi_sdr_info_destroy(stored_sdrs, NULL, NULL);
    return rv;
}

/***********************************************************************
 *
 * ID handling
 *
 **********************************************************************/

ipmi_domain_id_t
ipmi_domain_convert_to_id(ipmi_domain_t *domain)
{
    ipmi_domain_id_t val;

    CHECK_DOMAIN_LOCK(domain);

    val.domain = domain;
    return val;
}

int
ipmi_domain_pointer_cb(ipmi_domain_id_t   id,
		       ipmi_domain_ptr_cb handler,
		       void               *cb_data)
{
    int           rv;
    ipmi_domain_t *domain;

    domain = id.domain;

    ipmi_read_lock();
    rv = ipmi_domain_validate(domain);
    if (!rv)
	handler(domain, cb_data);
    ipmi_read_unlock();

    return rv;
}

int
ipmi_cmp_domain_id(ipmi_domain_id_t id1, ipmi_domain_id_t id2)
{
    if (id1.domain > id2.domain)
	return 1;
    if (id1.domain < id2.domain)
	return -1;
    return 0;
}


/***********************************************************************
 *
 * Connection setup and handling
 *
 **********************************************************************/

/* Closing a connection is subtle because of locks.  We schedule it to
   be done in a timer callback, that way we can handle all the locks
   as part of the close. */
typedef struct close_info_s
{
    close_done_t  close_done;
    void          *cb_data;
    ipmi_domain_t *domain;
} close_info_t;

static void
real_close_connection(void *cb_data, os_hnd_timer_id_t *id)
{
    close_info_t  *info = cb_data;
    ipmi_domain_t *domain = info->domain;
    ipmi_con_t    *ipmi[MAX_CONS];
    int           i;

    domain->os_hnd->free_timer(domain->os_hnd, id);

    ipmi_write_lock();

    remove_known_domain(domain);

    for (i=0; i<MAX_CONS; i++)
	ipmi[i] = domain->conn[i];

    ipmi_write_unlock();

    cleanup_domain(domain);

    for (i=0; i<MAX_CONS; i++) {
	if (ipmi[i])
	    ipmi[i]->close_connection(ipmi[i]);
    }

    if (info->close_done)
	info->close_done(info->cb_data);
    ipmi_mem_free(info);
}

int
ipmi_close_connection(ipmi_domain_t *domain,
		      close_done_t  close_done,
		      void          *cb_data)
{
    int               rv;
    close_info_t      *close_info = NULL;
    os_hnd_timer_id_t *timer = NULL;
    struct timeval    timeout;

    CHECK_DOMAIN_LOCK(domain);

    close_info = ipmi_mem_alloc(sizeof(*close_info));
    if (!close_info)
	return ENOMEM;

    rv = domain->os_hnd->alloc_timer(domain->os_hnd, &timer);
    if (rv)
	goto out;

    close_info->domain = domain;
    close_info->close_done = close_done;
    close_info->cb_data = cb_data;

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    rv = domain->os_hnd->start_timer(domain->os_hnd,
				     timer,
				     &timeout,
				     real_close_connection,
				     close_info);
 out:
    if (rv) {
	if (close_info)
	    ipmi_mem_free(close_info);
	if (timer)
	    domain->os_hnd->free_timer(domain->os_hnd, timer);
    } else {
	domain->valid = 0;
    }
    return rv;
}

int
ipmi_domain_add_con_change_handler(ipmi_domain_t            *domain,
				   ipmi_domain_con_cb       handler,
				   void                     *cb_data,
				   ipmi_domain_con_change_t **id)
{
    ipmi_domain_con_change_t *new_id;

    new_id = ipmi_mem_alloc(sizeof(*new_id));
    if (!new_id)
	return ENOMEM;

    new_id->handler = handler;
    new_id->cb_data = cb_data;
    if (! ilist_add_tail(domain->con_change_handlers, new_id, NULL)) {
	ipmi_mem_free(new_id);
	return ENOMEM;
    }

    if (id)
	*id = new_id;

    return 0;
}

void
ipmi_domain_remove_con_change_handler(ipmi_domain_t            *domain,
				      ipmi_domain_con_change_t *id)
{
    ilist_iter_t iter;
    int          rv;

    ilist_init_iter(&iter, domain->con_change_handlers);
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

typedef struct con_change_info_s
{
    ipmi_domain_t *domain;
    int           err;
    unsigned int  conn_num;
    unsigned int  port_num;
    int           still_connected;
} con_change_info_t;

static void
iterate_con_changes(ilist_iter_t *iter, void *item, void *cb_data)
{
    con_change_info_t        *info = cb_data;
    ipmi_domain_con_change_t *id = item;

    id->handler(info->domain, info->err, info->conn_num, info->port_num,
		info->still_connected, id->cb_data);
}

static void
call_con_fails(ipmi_domain_t *domain,
	       int           err,
	       unsigned int  conn_num,
	       unsigned int  port_num,
	       int           still_connected)
{
    con_change_info_t info = {domain, err, conn_num, port_num, still_connected};
    ilist_iter(domain->con_change_handlers, iterate_con_changes, &info);
    domain->connecting = 0;
}

static void
call_con_change(ipmi_domain_t *domain,
		int           err,
		unsigned int  conn_num,
		unsigned int  port_num,
		int           still_connected)
{
    con_change_info_t info = {domain, err, conn_num, port_num, still_connected};
    ilist_iter(domain->con_change_handlers, iterate_con_changes, &info);
}


static void	
con_up_complete(ipmi_domain_t *domain)
{
    int i, j;

    domain->connection_up = 1;

    if (domain->working_conn != -1)
	domain->con_up[domain->working_conn] = 1;

    ipmi_lock(domain->mc_list_lock);
    start_mc_scan(domain);
    ipmi_unlock(domain->mc_list_lock);
    ipmi_detect_ents_presence_changes(domain->entities, 1);

    for (i=0; i<MAX_CONS; i++) {
	for (j=0; j<MAX_PORTS_PER_CON; j++) {
	    if (domain->port_up[j][i] == 1)
		call_con_fails(domain, 0, i, j, 1);
	}
    }

    ipmi_entity_scan_sdrs(domain->entities, domain->main_sdrs);
    ipmi_sensor_handle_sdrs(domain, NULL, domain->main_sdrs);
}

static void
chan_info_rsp_handler(ipmi_mc_t  *mc,
		      ipmi_msg_t *rsp,
		      void       *rsp_data)
{
    int           rv = 0;
    long          curr = (long) rsp_data;
    ipmi_domain_t *domain = ipmi_mc_get_domain(mc);

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
	    domain->chan[0].medium = 1; /* IPMB */
	    domain->chan[0].xmit_support = 1;
	    domain->chan[0].recv_lun = 0;
	    domain->chan[0].protocol = 1; /* IPMB */
	    domain->chan[0].session_support = 0; /* Session-less */
	    domain->chan[0].vendor_id = 0x001bf2;
	    domain->chan[0].aux_info = 0;
	}
	goto chan_info_done;
    }

    /* Get the info from the channel info response. */
    domain->chan[curr].medium = rsp->data[2] & 0x7f;
    domain->chan[curr].xmit_support = rsp->data[2] >> 7;
    domain->chan[curr].recv_lun = (rsp->data[2] >> 4) & 0x7;
    domain->chan[curr].protocol = rsp->data[3] & 0x1f;
    domain->chan[curr].session_support = rsp->data[4] >> 6;
    domain->chan[curr].vendor_id = (rsp->data[5]
				    || (rsp->data[6] << 8)
				    || (rsp->data[7] << 16));
    domain->chan[curr].aux_info = rsp->data[8] | (rsp->data[9] << 8);

    curr++;
    if (curr < MAX_IPMI_USED_CHANNELS) {
	ipmi_msg_t    cmd_msg;
	unsigned char cmd_data[1];

	cmd_msg.netfn = IPMI_APP_NETFN;
	cmd_msg.cmd = IPMI_GET_CHANNEL_INFO_CMD;
	cmd_msg.data = cmd_data;
	cmd_msg.data_len = 1;
	cmd_data[0] = curr;

	rv = ipmi_mc_send_command(mc, 0 ,&cmd_msg, chan_info_rsp_handler,
				  (void *) curr);
    } else {
	goto chan_info_done;
    }

    if (rv) {
	call_con_fails(domain, rv, 0, 0, 0);
	return;
    }

    return;

 chan_info_done:
    domain->msg_int_type = 0xff;
    domain->event_msg_int_type = 0xff;
    con_up_complete(domain);
}

static int 
get_channels(ipmi_domain_t *domain)
{
    int rv;

    if ((domain->major_version > 1)
	|| ((domain->major_version == 1) && (domain->minor_version >= 5)))
    {
	ipmi_msg_t    cmd_msg;
	unsigned char cmd_data[1];

	/* IPMI 1.5 or later, use a get channel command. */
	cmd_msg.netfn = IPMI_APP_NETFN;
	cmd_msg.cmd = IPMI_GET_CHANNEL_INFO_CMD;
	cmd_msg.data = cmd_data;
	cmd_msg.data_len = 1;
	cmd_data[0] = 0;

	rv = ipmi_mc_send_command(domain->si_mc, 0, &cmd_msg,
				  chan_info_rsp_handler, (void *) 0);
    } else {
	ipmi_sdr_t sdr;

	/* Get the channel info record. */
	rv = ipmi_get_sdr_by_type(domain->main_sdrs, 0x14, &sdr);
	if (rv) {
	    /* Add a dummy channel zero and finish. */
	    domain->chan[0].medium = 1; /* IPMB */
	    domain->chan[0].xmit_support = 1;
	    domain->chan[0].recv_lun = 0;
	    domain->chan[0].protocol = 1; /* IPMB */
	    domain->chan[0].session_support = 0; /* Session-less */
	    domain->chan[0].vendor_id = 0x001bf2;
	    domain->chan[0].aux_info = 0;
	    domain->msg_int_type = 0xff;
	    domain->event_msg_int_type = 0xff;
	    domain->msg_int_type = 0xff;
	    domain->event_msg_int_type = 0xff;
	    rv = 0;
	} else {
	    int i;

	    for (i=0; i<MAX_IPMI_USED_CHANNELS; i++) {
		int protocol = sdr.data[i] & 0xf;
		
		if (protocol != 0) {
		    domain->chan[i].medium = 1; /* IPMB */
		    domain->chan[i].xmit_support = 1;
		    domain->chan[i].recv_lun = 0;
		    domain->chan[i].protocol = protocol;
		    domain->chan[i].session_support = 0; /* Session-less */
		    domain->chan[i].vendor_id = 0x001bf2;
		    domain->chan[i].aux_info = 0;
		}
	    }
	    domain->msg_int_type = sdr.data[8];
	    domain->event_msg_int_type = sdr.data[9];
	}

	con_up_complete(domain);
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
    ipmi_domain_t *domain = cb_data;
    int           rv;

    if (err) {
	/* Just report an error, it shouldn't be a big deal if this
           fails. */
	ipmi_log(IPMI_LOG_WARNING, "Could not get main SDRs, error 0x%x", err);
    }

    rv = get_channels(domain);
    if (rv)
	call_con_fails(domain, rv, 0, 0, 0);
}

static int 
get_sdrs(ipmi_domain_t *domain)
{
    return ipmi_sdr_fetch(domain->main_sdrs, sdr_handler, domain);
}

static void
got_dev_id(ipmi_mc_t  *mc,
	   ipmi_msg_t *rsp,
	   void       *rsp_data)
{
    ipmi_domain_t *domain = rsp_data;
    int           rv;

    if ((rsp->data[0] != 0) || (rsp->data_len < 12)) {
	/* At least the get device id has to work. */
	call_con_fails(domain, EINVAL, 0, 0, 0);
	return;
    }

    domain->major_version = rsp->data[5] & 0xf;
    domain->minor_version = (rsp->data[5] >> 4) & 0xf;
    domain->SDR_repository_support = (rsp->data[6] & 0x02) == 0x02;

    ipmi_mc_set_sdr_repository_support(domain->si_mc,
				       domain->SDR_repository_support);

    if (domain->major_version < 1) {
	/* We only support 1.0 and greater. */
	call_con_fails(domain, EINVAL, 0, 0, 0);
	return;
    }

    if (domain->SDR_repository_support) {
	rv = get_sdrs(domain);
    } else {
	rv = get_channels(domain);
    }
    if (rv)
	call_con_fails(domain, rv, 0, 0, 0);
}

static int
start_con_up(ipmi_domain_t *domain)
{
    ipmi_msg_t msg;

    domain->connecting = 1;

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_DEVICE_ID_CMD;
    msg.data_len = 0;
    msg.data = NULL;

    return ipmi_mc_send_command(domain->si_mc, 0, &msg, got_dev_id, domain);
}

static int
get_con_num(ipmi_domain_t *domain, ipmi_con_t *ipmi)
{
    int u;

    for (u=0; u<MAX_CONS; u++) {
	if (ipmi == domain->conn[u])
	    break;
    }

    if (u == MAX_CONS) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "Got a connection change from an invalid domain");
	return -1;
    }

    return u;
}

static int
first_working_con(ipmi_domain_t *domain)
{
    int i;

    for (i=0; i<MAX_CONS; i++)
	if (domain->con_up[i])
	    return i;
    return -1;
}

static void ll_addr_changed(ipmi_con_t   *ipmi,
			    int          err,
			    unsigned int ipmb,
			    int          active,
			    void         *cb_data);

static void
activate_timer_cb(void *cb_data, os_hnd_timer_id_t *id)
{
    activate_timer_info_t *info = cb_data;
    ipmi_domain_t         *domain = info->domain;
    int                   to_activate;
    int                   u;
    int                   rv;

    ipmi_read_lock();
    ipmi_lock(info->lock);
    if (info->cancelled) {
	info->os_hnd->free_timer(info->os_hnd, id);
	ipmi_unlock(info->lock);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	ipmi_read_unlock();
	return;
    }
    info->running = 0;

    rv = ipmi_domain_validate(domain);
    if (rv)
	/* Domain is gone, just give up. */
	goto out_unlock;

    /* If no one is active, activate one. */
    to_activate = -1;
    for (u=0; u<MAX_CONS; u++) {
	if (!domain->conn[u]
	    || !domain->con_up[u])
	{
	    continue;
	}
	if (domain->con_active[u]) {
	    to_activate = u;
	    break;
	}
	to_activate = u;
    }
    u = to_activate;
    if ((u != -1)
	&& ! domain->con_active[u]
	&& domain->conn[u]->set_active_state)
    {
	/* If we didn't find an active connection, but we found a
	   working one, activate it.  Note that we may re-activate
	   the connection that just went inactive if it is the
	   only working connection. */
	domain->conn[u]->set_active_state(
	    domain->conn[u],
	    1,
	    ll_addr_changed,
	    domain);
    }

 out_unlock:
    ipmi_unlock(info->lock);
    ipmi_read_unlock();
}

static void
ll_addr_changed(ipmi_con_t   *ipmi,
		int          err,
		unsigned int ipmb,
		int          active,
		void         *cb_data)
{
    ipmi_domain_t *domain = cb_data;
    int           rv;
    int           u;

    ipmi_read_lock();
    rv = ipmi_domain_validate(domain);
    if (rv)
	/* So the connection failed.  So what, there's nothing to talk to. */
	goto out_unlock;

    if (err)
	goto out_unlock;

    u = get_con_num(domain, ipmi);
    if (u == -1)
	goto out_unlock;

    if (ipmb != domain->con_ipmb_addr[u]) {
	/* First scan the old address to remove it. */
	if (domain->con_ipmb_addr[u] != 0)
	    ipmi_start_ipmb_mc_scan(domain, 0, domain->con_ipmb_addr[u],
				    domain->con_ipmb_addr[u], NULL, NULL);
    }

    domain->con_ipmb_addr[u] = ipmb;

    /* Scan the new address.  Even though the address may not have
       changed, it may have changed modes and need to be rescanned. */
    ipmi_start_ipmb_mc_scan(domain, 0, domain->con_ipmb_addr[u],
			    domain->con_ipmb_addr[u], NULL, NULL);

    if (domain->con_active[u] != active) {
	domain->con_active[u] = active;
	if (active) {
	    /* It was active when it previously was not, switch over
               to it. */
	    if (domain->working_conn != u) {
		reroute_cmds(domain, u);
		domain->working_conn = u;
	    }

	    /* Deactivate all the other connections. */
	    for (u=0; u<MAX_CONS; u++) {
		if (u == domain->working_conn
		    || !domain->conn[u]
		    || !domain->con_up[u])
		{
		    continue;
		}

		if (domain->conn[u]->set_active_state)
		    domain->conn[u]->set_active_state(
			domain->conn[u],
			0,
			ll_addr_changed,
			domain);
	    }
	}
    }

    /* If the activate timer is not running, then start it.  This
       allows some time for other connections to become active before
       we go off and start activating things.  We wait a random amount
       of time so that if we get into a war with another program about
       who is active, someone will eventually win. */
    ipmi_lock(domain->activate_timer_info->lock);
    if (!domain->activate_timer_info->running) {
	struct timeval tv;
	domain->os_hnd->get_random(domain->os_hnd,
				   &tv.tv_sec,
				   sizeof(tv.tv_sec));
	/* Wait a random value between 5 and 15 seconds */
	tv.tv_sec = (tv.tv_sec % 10) + 5;
	tv.tv_usec = 0;
	domain->os_hnd->start_timer(domain->os_hnd,
				    domain->activate_timer,
				    &tv,
				    activate_timer_cb,
				    domain->activate_timer_info);
	domain->activate_timer_info->running = 1;
    }
    ipmi_unlock(domain->activate_timer_info->lock);

 out_unlock:
    ipmi_read_unlock();
}

static void
ll_con_changed(ipmi_con_t   *ipmi,
	       int          err,
	       unsigned int port_num,
	       int          still_connected,
	       void         *cb_data)
{
    ipmi_domain_t   *domain = cb_data;
    int             rv;
    int             u;

    if (port_num >= MAX_PORTS_PER_CON) {
	ipmi_log(IPMI_LOG_SEVERE, "domain.c:ll_con_changed: Got port number %d,"
		 " but %d is the max number of ports",
		 port_num, MAX_PORTS_PER_CON);
	return;
    }

    ipmi_read_lock();
    rv = ipmi_domain_validate(domain);
    if (rv)
	/* So the connection failed.  So what, there's nothing to talk to. */
	goto out_unlock;

    u = get_con_num(domain, ipmi);
    if (u == -1)
	goto out_unlock;

    if (err)
	domain->port_up[port_num][u] = 0;
    else
	domain->port_up[port_num][u] = 1;

    if (still_connected) {
	domain->con_up[u] = 1;
	if (domain->connecting) {
	    /* If we are connecting, don't report anything. */
	} else if (domain->connection_up) {
	    /* We already have a connection, just report this. */
	    call_con_change(domain, err, u, port_num, domain->connection_up);
	} else {
	    /* We don't have a working connection, so start up the
               process. */
	    domain->working_conn = u;

	    /* Set the new connection active, if necessary. */
	    if (domain->conn[u]->set_active_state)
		domain->conn[u]->set_active_state(
		    domain->conn[u],
		    1,
		    ll_addr_changed,
		    domain);

	    /* When a connection comes back up, start the process of
	       getting SDRs, scanning the bus, and the like. */
	    rv = start_con_up(domain);
	    if (rv)
		call_con_fails(domain, rv, u, port_num, domain->connection_up);
	}
    } else {
	/* A connection failed, try to find a working connection and
           activate it, if necessary. */
	domain->con_up[u] = 0;
	domain->con_active[u] = 0;
	domain->working_conn = first_working_con(domain);
	if (domain->working_conn == -1)
	    domain->connection_up = 0;
	else if ((!domain->con_active[domain->working_conn])
		 && (domain->conn[domain->working_conn]->set_active_state))
	{
	    domain->conn[domain->working_conn]->set_active_state(
		domain->conn[domain->working_conn],
		1,
		ll_addr_changed,
		domain);
	} else {
	    reroute_cmds(domain, domain->working_conn);
	}
	call_con_fails(domain, err, u, port_num, domain->connection_up);
    }

 out_unlock:
    ipmi_read_unlock();
}

int
ipmi_init_domain(ipmi_con_t               *con[],
		 unsigned int             num_con,
		 ipmi_domain_con_cb       con_change_handler,
		 void                     *con_change_cb_data,
		 ipmi_domain_con_change_t **con_change_id,
		 ipmi_domain_id_t         *new_domain)
{
    int           rv;
    ipmi_domain_t *domain;
    int           i;

    if ((num_con < 1) || (num_con > MAX_CONS))
	return EINVAL;

    rv = setup_domain(con, num_con, &domain);
    if (rv)
	return rv;

    for (i=0; i<num_con; i++) {
	con[i]->set_con_change_handler(con[i], ll_con_changed, domain);
	con[i]->set_ipmb_addr_handler(con[i], ll_addr_changed, domain);
    }

    ipmi_write_lock();
    add_known_domain(domain);

    if (con_change_handler) {
	rv = ipmi_domain_add_con_change_handler(domain, con_change_handler,
						con_change_cb_data,
						con_change_id);
	if (rv)
	    goto out_err;
    }

    for (i=0; i<num_con; i++)
	rv = con[i]->start_con(con[i]);
    if (rv)
	goto out_err;

    if (new_domain)
	*new_domain = ipmi_domain_convert_to_id(domain);
    
 out:
    ipmi_write_unlock();
    return rv;

 out_err:
    for (i=0; i<num_con; i++)
	con[i]->set_con_change_handler(con[i], NULL, NULL);
    remove_known_domain(domain);
    cleanup_domain(domain);
    goto out;
}

/***********************************************************************
 *
 * Handle misc data about domains.
 *
 **********************************************************************/

int
ipmi_domain_get_num_channels(ipmi_domain_t *domain, int *val)
{
    CHECK_DOMAIN_LOCK(domain);

    *val = MAX_IPMI_USED_CHANNELS;
    return 0;
}

int
ipmi_domain_get_channel(ipmi_domain_t    *domain,
			int              index,
			ipmi_chan_info_t *chan)
{
    CHECK_DOMAIN_LOCK(domain);

    if (index >= MAX_IPMI_USED_CHANNELS)
	return EINVAL;

    *chan = domain->chan[index];
    return 0;
}

int
ipmi_domain_con_up(ipmi_domain_t *domain)
{
    CHECK_DOMAIN_LOCK(domain);
    return domain->connection_up;
}

static void
check_event_rcvr(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    unsigned int *addr = cb_data;
    if ((*addr == 0) && ipmi_mc_sel_device_support(mc))
	*addr = ipmi_mc_get_address(mc);
}

int
ipmi_domain_get_event_rcvr(ipmi_domain_t *domain)
{
    unsigned int addr = 0;

    ipmi_domain_iterate_mcs(domain, check_event_rcvr, &addr);
    return addr;
}

/***********************************************************************
 *
 * Initialization and shutdown
 *
 **********************************************************************/

int
_ipmi_domain_init(void)
{
    return 0;
}

void
_ipmi_domain_shutdown(void)
{
}
