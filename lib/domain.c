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
#include <stdio.h>
#include <stdlib.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_sdr.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_auth.h>

#include <OpenIPMI/internal/locked_list.h>
#include <OpenIPMI/internal/ilist.h>
#include <OpenIPMI/internal/ipmi_event.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/ipmi_oem.h>
#include <OpenIPMI/internal/ipmi_utils.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_entity.h>
#include <OpenIPMI/internal/ipmi_mc.h>

#ifdef DEBUG_EVENTS
static void
dump_hex(const unsigned char *data, int len)
{
    int i;
    for (i=0; i<len; i++) {
	if ((i != 0) && ((i % 16) == 0)) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n  ");
	}
	ipmi_log(IPMI_LOG_DEBUG_CONT, " %2.2x", data[i]);
    }
}
#endif

/* Rescan the bus for MCs every 10 minutes by default. */
#define IPMI_AUDIT_DOMAIN_INTERVAL 600

/* Re-query the SEL every 10 seconds by default. */
#define IPMI_SEL_QUERY_INTERVAL 10

/* Timer structure for rescanning the bus. */
typedef struct audit_domain_info_s
{
    int           cancelled;
    os_handler_t  *os_hnd;
    ipmi_lock_t   *lock;
    ipmi_domain_t *domain;
} audit_domain_info_t;

/* Used to keep a record of a bus scan. */
typedef struct mc_ipmb_scan_info_s mc_ipmb_scan_info_t;
struct mc_ipmb_scan_info_s
{
    ipmi_addr_t         addr;
    unsigned int        addr_len;
    ipmi_domain_t       *domain;
    ipmi_msg_t          msg;
    unsigned int        end_addr;
    ipmi_domain_cb      done_handler;
    void                *cb_data;
    mc_ipmb_scan_info_t *next;
    unsigned int        missed_responses;
    int                 cancelled;
    int                 timer_running;
    os_handler_t        *os_hnd;
    os_hnd_timer_id_t   *timer;
    ipmi_lock_t         *lock;
};

/* This structure tracks messages sent to the domain, it is primarily
   here so messages can be rerouted to other connections when a
   connection fails. */
typedef struct ll_msg_s
{
    ipmi_domain_t                *domain;
    int                          con;

    ipmi_msg_t                   msg;
    unsigned char                msg_data[IPMI_MAX_MSG_LENGTH];

    ipmi_addr_response_handler_t rsp_handler;
    ipmi_msgi_t                  *rsp_item;

    long                         seq;

    int                          side_effects;

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

typedef struct domain_check_oem_s domain_check_oem_t;

typedef struct mc_table_s
{
    unsigned short size;
    unsigned short curr;
    ipmi_mc_t      **mcs;
} mc_table_t;

struct ipmi_domain_s
{
    /* Used for error reporting. We add an extra space at the end, thus
       the +1. */
    char name[IPMI_DOMAIN_NAME_LEN+1];

    /* Used to handle shutdown race conditions. */
    int             valid;
    int             in_shutdown;

    /* Is anyone using this domain? */
    unsigned int    usecount;

    /* Used to handle startup race conditions. */
    int             in_startup;

    /* OS handler to use for domain operations. */
    os_handler_t *os_hnd;

    /* A lock for handling miscellaneous data changes. */
    ipmi_lock_t *domain_lock;

    /* The main set of SDRs on a BMC. */
    ipmi_sdr_info_t *main_sdrs;

    /* The sensors that came from the main SDR. */
    ipmi_sensor_t **sensors_in_main_sdr;
    unsigned int  sensors_in_main_sdr_count;

    /* The entities that came from the device SDR on this MC are
       somehow stored in this data structure. */
    void *entities_in_main_sdr;

    /* OEM data for OEM code. */
    void                            *oem_data;
    ipmi_domain_destroy_oem_data_cb oem_data_destroyer;

    /* The type of domain, defaults to unknown */
    enum ipmi_domain_type domain_type;

    /* Major and minor versions of the connection. */
    unsigned int major_version : 4;
    unsigned int minor_version : 4;
    unsigned int SDR_repository_support : 1;

    /* A special MC used to represent the system interface. */
    ipmi_mc_t *si_mc;

    /* Used for generating unique numbers for a domain. */
    unsigned int uniq_num;

#define IPMB_HASH 32
    mc_table_t ipmb_mcs[IPMB_HASH];
#define MAX_CONS 2
    ipmi_mc_t *sys_intf_mcs[MAX_CONS];
    ipmi_lock_t *mc_lock;

    /* A list of outstanding messages.  We use this so we can reroute
       messages to another connection in case a connection fails. */
    ilist_t     *cmds;
    ipmi_lock_t *cmds_lock;
    long        cmds_seq; /* Sequence number for messages to avoid
			     reuse problems. */
    long        conn_seq[MAX_CONS]; /* Sequence number for connection
				       switchovers to avoid handling
				       old messages. */

    locked_list_t            *event_handlers;
    locked_list_t            *event_handlers_cl;
    ipmi_oem_event_handler_cb oem_event_handler;
    void                      *oem_event_cb_data;

    locked_list_t            *new_sensor_handlers; /* callbacks for
                                             OEM-specific sensors*/

    ipmi_domain_shutdown_cb shutdown_handler;

    /* Are we in the middle of an MC bus scan? */
    int scanning_bus_count;

    ipmi_entity_info_t    *entities;
    ipmi_lock_t           *entities_lock;

    ipmi_lock_t   *con_lock;
    int           working_conn;
    ipmi_con_t    *conn[MAX_CONS];
    int           con_active[MAX_CONS];
    unsigned char con_ipmb_addr[MAX_CONS][MAX_IPMI_USED_CHANNELS];

    int           con_up[MAX_CONS];

    /* A list of connection fail handler, separate from the main one. */
    locked_list_t *con_change_handlers;
    locked_list_t *con_change_cl_handlers;

    /* Are any low-level connections up? */
    int connection_up;

    /* If we got some type of invalid return from the BMC, we mark
       this and retry at audit intervals. */
    int got_invalid_dev_id;

    /* Are we in the process of connecting? */
    int connecting;

#define MAX_PORTS_PER_CON 16
    /* -1 if not valid, 0 if not up, 1 if up. */
    int           port_up[MAX_PORTS_PER_CON][MAX_CONS];

    /* Should I do a full bus scan for devices on the bus? */
    int           do_bus_scan;

    /* Timer for rescanning the bus periodically. */
    unsigned int        audit_domain_interval; /* seconds between checks */
    os_hnd_timer_id_t   *audit_domain_timer;
    audit_domain_info_t *audit_domain_timer_info;

    /* This is a list of all the bus scans currently happening, so
       they can be properly freed. */
    mc_ipmb_scan_info_t *bus_scans_running;

    ipmi_chan_info_t chan[MAX_IPMI_USED_CHANNELS];
    char             chan_set[MAX_IPMI_USED_CHANNELS];
    unsigned char    msg_int_type;
    unsigned char    event_msg_int_type;

    /* A list of handlers to call when an MC is added to the domain. */
    locked_list_t *mc_upd_handlers;
    locked_list_t *mc_upd_cl_handlers;

    /* A list of IPMB addresses to not scan. */
    ilist_t     *ipmb_ignores;
    ipmi_lock_t *ipmb_ignores_lock;

    /* This is a timer that waits a little while before activating a
       connection if all connections are not active.  It avoids race
       conditions with activiation. */
    os_hnd_timer_id_t     *activate_timer;
    activate_timer_info_t *activate_timer_info;

    unsigned int default_sel_rescan_time;

    /* Used to inform the user that the main SDR has been read. */
    ipmi_domain_cb SDRs_read_handler;
    void           *SDRs_read_handler_cb_data;

    /* Used to inform OEM code that the user has been informed that
       the connection is up. */
    ipmi_domain_ptr_cb con_up_handler;
    void               *con_up_handler_cb_data;

    /* Fixups for SDRs. */
    ipmi_domain_oem_fixup_sdrs_cb fixup_sdrs_handler;
    void                          *fixup_sdrs_cb_data;

    unsigned int       fully_up_count;
    ipmi_domain_ptr_cb domain_fully_up;
    void               *domain_fully_up_cb_data;

    /* Used to inform the user that the bus scanning has been done */
    ipmi_domain_cb bus_scan_handler;
    void           *bus_scan_handler_cb_data;

    /* If we are running a domain OEM check, then this will be the
       check that is running.  Otherwise it is NULL. */
    domain_check_oem_t *check;

    int                       close_count;
    ipmi_domain_close_done_cb close_done;
    void                      *close_done_cb_data;

    _ipmi_domain_fru_setup_cb fru_setup_cb;
    void                      *fru_setup_cb_data;

    /* Anonymous attributes for the domain. */
    locked_list_t *attr;

    /* Statistics for the domain. */
    locked_list_t *stats;

    /* Keep a linked-list of these. */
    ipmi_domain_t *next, *prev;

    /* Cruft... */
    struct ipmi_domain_mc_upd_s     *mc_upd_cruft;
    struct ipmi_event_handler_id_s  *event_cruft;
    struct ipmi_domain_con_change_s *con_change_cruft;

    ipmi_domain_entity_cb cruft_entity_update_handler;
    void                  *cruft_entity_update_cb_data;

    ipmi_ll_stat_info_t *con_stat_info;

    /* Option processing */
    unsigned int option_all : 1;
    unsigned int option_SDRs : 1;
    unsigned int option_SEL : 1;
    unsigned int option_FRUs : 1;
    unsigned int option_IPMB_scan : 1;
    unsigned int option_OEM_init : 1;
    unsigned int option_set_event_rcvr : 1;
    unsigned int option_set_sel_time : 1;
    unsigned int option_activate_if_possible : 1;
    unsigned int option_local_only : 1;
    unsigned int option_local_only_set : 1;
    unsigned int option_use_cache : 1;
};

/* A list of all domains in the system. */
static locked_list_t *domains_list;

static void domain_audit(void *cb_data, os_hnd_timer_id_t *id);

static int domain_send_mc_id(ipmi_domain_t *domain);

static void cancel_domain_oem_check(ipmi_domain_t *domain);

static void real_close_connection(ipmi_domain_t *domain);

static void free_domain_cruft(ipmi_domain_t *domain);

static void ll_con_changed(ipmi_con_t   *ipmi,
			   int          err,
			   unsigned int port_num,
			   int          still_connected,
			   void         *cb_data);

static void ll_addr_changed(ipmi_con_t    *ipmi,
			    int           err,
			    const unsigned char ipmb_addr[],
			    unsigned int  num_ipmb_addr,
			    int           active,
			    unsigned int  hacks,
			    void          *cb_data);

/***********************************************************************
 *
 * Some general utilities
 *
 **********************************************************************/

static int
first_working_con(ipmi_domain_t *domain)
{
    int i;

    for (i=0; i<MAX_CONS; i++)
	if (domain->con_up[i])
	    return i;
    return -1;
}

static int
first_active_con(ipmi_domain_t *domain)
{
    int i;

    for (i=0; i<MAX_CONS; i++)
	if (domain->con_up[i] && domain->con_active[i])
	    return i;
    return -1;
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
		 "%sdomain.c(get_con_num): "
		 "Got a connection change from an invalid domain",
		 DOMAIN_NAME(domain));
	return -1;
    }

    return u;
}

static void
deliver_rsp(ipmi_domain_t                *domain, 
	    ipmi_addr_response_handler_t rsp_handler,
	    ipmi_msgi_t                  *rspi)
{
    int used = IPMI_MSG_ITEM_NOT_USED;

    if (rsp_handler)
	used = rsp_handler(domain, rspi);

    if (!used)
	ipmi_free_msg_item(rspi);
}

/***********************************************************************
 *
 * Used for handling detecting when the domain is fully up.
 *
 **********************************************************************/
void
_ipmi_get_domain_fully_up(ipmi_domain_t *domain, char *name)
{
    if (!domain->domain_fully_up)
	return;
    ipmi_lock(domain->domain_lock);
    domain->fully_up_count++;
    ipmi_unlock(domain->domain_lock);
}

void
_ipmi_put_domain_fully_up(ipmi_domain_t *domain, char *name)
{
    if (!domain->domain_fully_up)
	return;
    ipmi_lock(domain->domain_lock);
    domain->fully_up_count--;
    if (domain->fully_up_count == 0) {
	ipmi_domain_ptr_cb domain_fully_up;
	void               *domain_fully_up_cb_data;

	domain_fully_up = domain->domain_fully_up;
	domain_fully_up_cb_data = domain->domain_fully_up_cb_data;
	domain->domain_fully_up = NULL;
	ipmi_unlock(domain->domain_lock);
	domain_fully_up(domain, domain_fully_up_cb_data);
	return;
    }
    ipmi_unlock(domain->domain_lock);
}

int
ipmi_domain_is_fully_up(ipmi_domain_t *domain)
{
    return domain->fully_up_count == 0;
}

/***********************************************************************
 *
 * Domain data structure creation and destruction
 *
 **********************************************************************/

static locked_list_t *domain_change_handlers;

int
ipmi_domain_add_domain_change_handler(ipmi_domain_change_cb handler,
				      void                  *cb_data)
{
    if (locked_list_add(domain_change_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_domain_remove_domain_change_handler(ipmi_domain_change_cb handler,
					 void                  *cb_data)
{
    if (locked_list_remove(domain_change_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

typedef struct domain_change_info_s
{
    enum ipmi_update_e op;
    ipmi_domain_t      *domain;
} domain_change_info_t;

static int
iterate_domain_changes(void *cb_data, void *item1, void *item2)
{
    domain_change_info_t  *info = cb_data;
    ipmi_domain_change_cb handler = item1;

    handler(info->domain, info->op, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_domain_change(ipmi_domain_t      *domain,
		   enum ipmi_update_e op)
{
    domain_change_info_t info = { op, domain };
    locked_list_iterate(domain_change_handlers, iterate_domain_changes, &info);
}

int
_ipmi_domain_in_shutdown(ipmi_domain_t *domain)
{
    return domain->in_shutdown;
}

static void
iterate_cleanup_mc(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    _ipmi_cleanup_mc(mc);
}

void
ipmi_domain_set_oem_shutdown_handler(ipmi_domain_t           *domain,
				     ipmi_domain_shutdown_cb handler)
{
    domain->shutdown_handler = handler;
}

static int destroy_attr(void *cb_data, void *item1, void *item2);
static int destroy_stat(void *cb_data, void *item1, void *item2);
static void call_mc_upd_cl_handlers(ipmi_domain_t         *domain,
				    ipmi_domain_mc_upd_cb handler,
				    void                  *handler_data);
static void call_con_change_cl_handlers(ipmi_domain_t      *domain,
					ipmi_domain_con_cb handler,
					void               *handler_data);
static void call_event_handler_cl_handlers(ipmi_domain_t         *domain,
					   ipmi_event_handler_cb handler,
					   void                 *handler_data);

static int
mc_upds_cleanup(void *cb_data, void *item1, void *item2)
{
    call_mc_upd_cl_handlers(cb_data, item1, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
con_change_cleanup(void *cb_data, void *item1, void *item2)
{
    call_con_change_cl_handlers(cb_data, item1, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
event_handler_cleanup(void *cb_data, void *item1, void *item2)
{
    call_event_handler_cl_handlers(cb_data, item1, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
cleanup_domain(ipmi_domain_t *domain)
{
    unsigned int i;
    int          rv;

    /* This must be first, so that nuking the oustanding messages will
       cause the right thing to happen. */
    cancel_domain_oem_check(domain);

    if (domain->attr) {
	locked_list_iterate(domain->attr, destroy_attr, domain);
	locked_list_destroy(domain->attr);
	domain->attr = NULL;
    }

    if (domain->stats) {
	locked_list_iterate(domain->stats, destroy_stat, domain);
	locked_list_destroy(domain->stats);
	domain->stats = NULL;
    }

    /* Nuke all outstanding messages. */
    if ((domain->cmds_lock) && (domain->cmds)) {
	ll_msg_t     *nmsg;
	int          ok;
	ilist_iter_t iter;

	ipmi_lock(domain->cmds_lock);

	ilist_init_iter(&iter, domain->cmds);
	ok = ilist_first(&iter);
	while (ok) {
	    ipmi_msgi_t *rspi;

	    nmsg = ilist_get(&iter);
	    rspi = nmsg->rsp_item;

	    rspi->msg.netfn = nmsg->msg.netfn | 1;
	    rspi->msg.cmd = nmsg->msg.cmd;
	    rspi->msg.data = rspi->data;
	    rspi->msg.data_len = 1;
	    rspi->msg.data[0] = IPMI_UNKNOWN_ERR_CC;
	    deliver_rsp(domain, nmsg->rsp_handler, rspi);
	    
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

    /* Shutdown code called here. */
    if (domain->shutdown_handler)
	domain->shutdown_handler(domain);

    /* Delete the sensors from the main SDR repository. */
    if (domain->sensors_in_main_sdr) {
	for (i=0; i<domain->sensors_in_main_sdr_count; i++) {
	    _ipmi_domain_entity_lock(domain);
	    if (domain->sensors_in_main_sdr[i]) {
		ipmi_sensor_t *sensor = domain->sensors_in_main_sdr[i];
		ipmi_entity_t *entity = ipmi_sensor_get_entity(sensor);
		ipmi_mc_t     *mc = ipmi_sensor_get_mc(sensor);
		_ipmi_entity_get(entity);
		_ipmi_sensor_get(sensor);
		_ipmi_domain_entity_unlock(domain);
		_ipmi_domain_mc_lock(domain);
		_ipmi_mc_get(mc);
		_ipmi_domain_mc_unlock(domain);
		ipmi_sensor_destroy(domain->sensors_in_main_sdr[i]);
		_ipmi_sensor_put(sensor);
		_ipmi_mc_put(mc);
		_ipmi_entity_put(entity);
	    } else
		_ipmi_domain_entity_unlock(domain);
	}
	ipmi_mem_free(domain->sensors_in_main_sdr);
    }

    if (domain->entities_in_main_sdr) {
	ipmi_sdr_entity_destroy(domain->entities_in_main_sdr);
	domain->entities_in_main_sdr = NULL;
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
    ipmi_domain_iterate_mcs(domain, iterate_cleanup_mc, NULL);
    ipmi_domain_iterate_mcs(domain, iterate_cleanup_mc, NULL);

    if (domain->si_mc) {
	_ipmi_mc_get(domain->si_mc);
	_ipmi_mc_release(domain->si_mc);
	_ipmi_cleanup_mc(domain->si_mc);
	_ipmi_mc_put(domain->si_mc);
    }

    /* Destroy the main SDR repository, if it exists. */
    if (domain->main_sdrs)
	ipmi_sdr_info_destroy(domain->main_sdrs, NULL, NULL);

    if (domain->audit_domain_timer_info) {
	domain->audit_domain_timer_info->cancelled = 1;
	ipmi_lock(domain->audit_domain_timer_info->lock);
	rv = domain->os_hnd->stop_timer(domain->os_hnd,
					domain->audit_domain_timer);
	ipmi_unlock(domain->audit_domain_timer_info->lock);
	if (!rv) {
	    /* If we can stop the timer or it wasn't running, free it
	       and it's info.  If we can't stop the timer, that means
	       that the code is currently in the timer handler, so we
	       let the "cancelled" value do this for us. */
	    if (domain->audit_domain_timer)
		domain->os_hnd->free_timer(domain->os_hnd,
					   domain->audit_domain_timer);
	    if (domain->audit_domain_timer_info->lock)
		ipmi_destroy_lock(domain->audit_domain_timer_info->lock);
	    ipmi_mem_free(domain->audit_domain_timer_info);
	}
    }

    if (domain->event_handlers) {
	locked_list_iterate(domain->event_handlers, event_handler_cleanup,
			    domain);
	locked_list_destroy(domain->event_handlers);
    }
    if (domain->event_handlers_cl)
	locked_list_destroy(domain->event_handlers_cl);

    if (domain->con_change_handlers) {
	locked_list_iterate(domain->con_change_handlers, con_change_cleanup,
			    domain);
	locked_list_destroy(domain->con_change_handlers);
    }
    if (domain->con_change_cl_handlers)
	locked_list_destroy(domain->con_change_cl_handlers);

    if (domain->new_sensor_handlers)
        locked_list_destroy(domain->new_sensor_handlers);

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
	    ipmi_lock(item->lock);
	    if (item->timer_running) {
		if (item->os_hnd->stop_timer(item->os_hnd, item->timer)) {
		    item->cancelled = 1;
		    ipmi_unlock(item->lock);
		    item = NULL;
		}
	    }
	    if (item) {
		ipmi_unlock(item->lock);
		item->os_hnd->free_timer(item->os_hnd, item->timer);
		ipmi_destroy_lock(item->lock);
		ipmi_mem_free(item);
	    }
	}
    }

    /* Destroy the entities last, since sensors and controls may
       refer to them. */
    if (domain->entities)
	ipmi_entity_info_destroy(domain->entities);
    if (domain->entities_lock)
	ipmi_destroy_lock(domain->entities_lock);

    call_domain_change(domain, IPMI_DELETED);

    /* The MC list should no longer have anything in it. */
    if (domain->mc_upd_handlers) {
	locked_list_iterate(domain->mc_upd_handlers, mc_upds_cleanup, domain);
	locked_list_destroy(domain->mc_upd_handlers);
    }
    if (domain->mc_upd_cl_handlers)
	locked_list_destroy(domain->mc_upd_cl_handlers);

    for (i=0; i<IPMB_HASH; i++) {
	if (domain->ipmb_mcs[i].mcs)
	    ipmi_mem_free(domain->ipmb_mcs[i].mcs);
    }

    /* We wait until here to call the OEM data destroyer, the process
       of destroying information that has previously gone on can call
       OEM callbacks, we want the OEM data to hang around until we
       don't need it for sure. */
    if (domain->oem_data && domain->oem_data_destroyer)
	domain->oem_data_destroyer(domain, domain->oem_data);

    if (domain->con_stat_info)
	ipmi_ll_con_free_stat_info(domain->con_stat_info);

    /* Locks must be last, because they can be used by many things. */
    if (domain->ipmb_ignores_lock)
	ipmi_destroy_lock(domain->ipmb_ignores_lock);
    if (domain->mc_lock)
	ipmi_destroy_lock(domain->mc_lock);
    if (domain->con_lock)
	ipmi_destroy_lock(domain->con_lock);
    if (domain->domain_lock)
	ipmi_destroy_lock(domain->domain_lock);

    /* Cruft */
    free_domain_cruft(domain);

    ipmi_mem_free(domain);
}

static int con_register_stat(ipmi_ll_stat_info_t *info,
			     const char          *name,
			     const char          *instance,
			     void                **stat)
{
    ipmi_domain_stat_t *rstat;
    int                rv;
    ipmi_domain_t      *domain = ipmi_ll_con_stat_get_user_data(info);

    rv = ipmi_domain_stat_register(domain, name, instance, &rstat);
    if (!rv)
	*stat = rstat;
    return rv;
}

static void con_add_stat(ipmi_ll_stat_info_t *info,
			 void                *stat,
			 int                 value)
{
    ipmi_domain_stat_add(stat, value);
}

static void con_unregister_stat(ipmi_ll_stat_info_t *info,
				void                *stat)
{
    ipmi_domain_stat_put(stat);
}

static int
process_options(ipmi_domain_t      *domain, 
		ipmi_open_option_t *options,
		unsigned int       num_options)
{
    unsigned int i;

    /* Option processing. */
    for (i=0; i<num_options; i++) {
	switch (options[i].option) {
	case IPMI_OPEN_OPTION_ALL:
	    domain->option_all = options[i].ival != 0;
	    break;
	case IPMI_OPEN_OPTION_SDRS:
	    domain->option_SDRs = options[i].ival != 0;
	    break;
	case IPMI_OPEN_OPTION_FRUS:
	    domain->option_FRUs = options[i].ival != 0;
	    break;
	case IPMI_OPEN_OPTION_SEL:
	    domain->option_SEL = options[i].ival != 0;
	    break;
	case IPMI_OPEN_OPTION_IPMB_SCAN:
	    domain->option_IPMB_scan = options[i].ival != 0;
	    break;
	case IPMI_OPEN_OPTION_OEM_INIT:
	    domain->option_OEM_init = options[i].ival != 0;
	    break;
	case IPMI_OPEN_OPTION_SET_EVENT_RCVR:
	    domain->option_set_event_rcvr = options[i].ival != 0;
	    break;
	case IPMI_OPEN_OPTION_SET_SEL_TIME:
	    domain->option_set_sel_time = options[i].ival != 0;
	    break;
	case IPMI_OPEN_OPTION_USE_CACHE:
	    domain->option_use_cache = options[i].ival != 0;
	    break;
	case IPMI_OPEN_OPTION_ACTIVATE_IF_POSSIBLE:
	    domain->option_activate_if_possible = options[i].ival != 0;
	    break;
	case IPMI_OPEN_OPTION_LOCAL_ONLY:
	    domain->option_local_only = options[i].ival != 0;
	    domain->option_local_only_set = 1;
	    break;
	default:
	    return EINVAL;
	}
    }

    return 0;
}

static int
setup_domain(const char         *name,
	     ipmi_con_t         *ipmi[],
	     int                num_con,
	     ipmi_open_option_t *options,
	     unsigned int       num_options,
	     ipmi_domain_t      **new_domain)
{
    struct timeval               timeout;
    ipmi_domain_t                *domain;
    int                          rv;
    ipmi_system_interface_addr_t si;
    int                          i, j;
    unsigned int                 priv;

    /* Don't allow '(' in the domain name, as that messes up the
       naming.  That is the only restriction. */
    if (strchr(name, '('))
	return EINVAL;

    domain = ipmi_mem_alloc(sizeof(*domain));
    if (!domain)
	return ENOMEM;
    memset(domain, 0, sizeof(*domain));

    domain->in_startup = 1;
    domain->option_all = 1;
    domain->option_set_event_rcvr = 1;
    domain->option_set_sel_time = 1;
    domain->option_activate_if_possible = 1;
    domain->option_local_only = 0;
    domain->option_local_only_set = 0;
    domain->option_use_cache = 1;

    priv = IPMI_PRIVILEGE_ADMIN;
    for (i=0; i<num_con; i++) {
	/* Find the least-common demominator privilege for the
	   connections. */
	if ((ipmi[i]->priv_level != 0) && (ipmi[i]->priv_level < priv))
	    priv = ipmi[i]->priv_level;
    }

    /* Enable setting the event receiver (by default) if the privilege
       is admin or greater. */
    domain->option_set_event_rcvr = (priv >= IPMI_PRIVILEGE_ADMIN);
    domain->option_set_sel_time = (priv >= IPMI_PRIVILEGE_ADMIN);

    if (options)
	process_options(domain, options, num_options);

    strncpy(domain->name, name, sizeof(domain->name)-2);
    i = strlen(domain->name);
    if (i > 0) {
	domain->name[i] = ' ';
	domain->name[i+1] = '\0';
    }

    domain->os_hnd = ipmi[0]->os_hnd;

    domain->valid = 1;
    domain->in_shutdown = 0;
    domain->usecount = 1;

    domain->stats = locked_list_alloc(domain->os_hnd);
    if (!domain->stats) {
	ipmi_mem_free(domain);
	return ENOMEM;
    }

    domain->con_stat_info = ipmi_ll_con_alloc_stat_info();
    if (!domain->con_stat_info) {
	locked_list_destroy(domain->stats);
	ipmi_mem_free(domain);
	return ENOMEM;
    }
    ipmi_ll_con_stat_info_set_register(domain->con_stat_info,
				       con_register_stat);
    ipmi_ll_con_stat_info_set_adder(domain->con_stat_info, con_add_stat);
    ipmi_ll_con_stat_info_set_unregister(domain->con_stat_info,
					 con_unregister_stat);
    ipmi_ll_con_stat_set_user_data(domain->con_stat_info, domain);

    for (i=0; i<num_con; i++) {
	int len1 = strlen(domain->name);
	domain->conn[i] = ipmi[i];
	for (j=0; j<MAX_IPMI_USED_CHANNELS; j++)
	    domain->con_ipmb_addr[i][j] = 0x20;
	domain->con_active[i] = 1;
	domain->con_up[i] = 0;
	ipmi[i]->name = ipmi_mem_alloc(len1 + 11);
	if (ipmi[i]->name)
	    snprintf(ipmi[i]->name, len1 + 11, "%s%d ", domain->name, i);
	ipmi[i]->user_data = domain;

	for (j=0; j<MAX_PORTS_PER_CON; j++)
	    domain->port_up[j][i] = -1;

	if (ipmi[i]->register_stat_handler)
	    ipmi[i]->register_stat_handler(ipmi[i], domain->con_stat_info);
    }

    domain->connection_up = 0;

    /* Create the locks before anything else. */
    domain->default_sel_rescan_time = IPMI_SEL_QUERY_INTERVAL;

    /* Set the default timer intervals. */
    domain->audit_domain_interval = IPMI_AUDIT_DOMAIN_INTERVAL;

    rv = ipmi_create_lock(domain, &domain->mc_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock(domain, &domain->con_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock(domain, &domain->domain_lock);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock(domain, &domain->entities_lock);
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
    domain->activate_timer_info->running = 0;

    rv = ipmi_create_lock(domain, &domain->activate_timer_info->lock);
    if (rv)
	goto out_err;

    rv = domain->os_hnd->alloc_timer(domain->os_hnd,
				     &(domain->activate_timer));
    if (rv)
	goto out_err;

    domain->event_handlers_cl = locked_list_alloc(domain->os_hnd);
    if (!domain->event_handlers_cl) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->event_handlers = locked_list_alloc(domain->os_hnd);
    if (!domain->event_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->attr = locked_list_alloc(domain->os_hnd);
    if (!domain->attr) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->do_bus_scan = 1;

    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = IPMI_BMC_CHANNEL;
    si.lun = 0;
    rv = _ipmi_create_mc(domain,
			 (ipmi_addr_t *) &si, sizeof(si),
			 &domain->si_mc);
    if (rv)
	goto out_err;
    _ipmi_mc_use(domain->si_mc);

    /* Force this one to always be active, so anything that uses it is
       always ready to go.  Since it represents the connection, it
       really can't ever go inactive. */
    _ipmi_mc_force_active(domain->si_mc, 1);

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

    domain->con_change_cl_handlers = locked_list_alloc(domain->os_hnd);
    if (! domain->con_change_cl_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->con_change_handlers = locked_list_alloc(domain->os_hnd);
    if (! domain->con_change_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->mc_upd_cl_handlers = locked_list_alloc(domain->os_hnd);
    if (! domain->mc_upd_cl_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->mc_upd_handlers = locked_list_alloc(domain->os_hnd);
    if (! domain->mc_upd_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->new_sensor_handlers = locked_list_alloc(domain->os_hnd);
    if (! domain->new_sensor_handlers) {
        rv = ENOMEM;
        goto out_err;
    }

    rv = ipmi_create_lock(domain, &domain->ipmb_ignores_lock);
    if (rv)
	goto out_err;

    domain->ipmb_ignores = alloc_ilist();
    if (! domain->ipmb_ignores) {
	rv = ENOMEM;
	goto out_err;
    }

    domain->bus_scans_running = NULL;

    domain->audit_domain_timer_info
	= ipmi_mem_alloc(sizeof(audit_domain_info_t));
    if (!domain->audit_domain_timer_info) {
	rv = ENOMEM;
	goto out_err;
    }
    memset(domain->audit_domain_timer_info, 0, sizeof(audit_domain_info_t));
	
    domain->audit_domain_timer_info->domain = domain;
    domain->audit_domain_timer_info->os_hnd = domain->os_hnd;
    domain->audit_domain_timer_info->cancelled = 0;
    rv = ipmi_create_lock(domain, &domain->audit_domain_timer_info->lock);
    if (rv)
	goto out_err;
    rv = domain->os_hnd->alloc_timer(domain->os_hnd,
				     &(domain->audit_domain_timer));
    if (rv)
	goto out_err;

    timeout.tv_sec = domain->audit_domain_interval;
    timeout.tv_usec = 0;
    domain->os_hnd->start_timer(domain->os_hnd,
				domain->audit_domain_timer,
				&timeout,
				domain_audit,
				domain->audit_domain_timer_info);

    rv = ipmi_entity_info_alloc(domain, &(domain->entities));
    if (rv)
	goto out_err;

    memset(domain->chan, 0, sizeof(domain->chan));

 out_err:
    if (domain->si_mc)
	_ipmi_mc_put(domain->si_mc);

    if (rv) {
	for (i=0; i<num_con; i++) {
	    if (ipmi[i]->register_stat_handler)
		ipmi[i]->unregister_stat_handler(ipmi[i],
						 domain->con_stat_info);
	}
	cleanup_domain(domain);
    } else
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
__ipmi_check_domain_lock(const ipmi_domain_t *domain)
{
    if (!domain)
	return;

    if (!DEBUG_LOCKS)
	return;

    if (domain->usecount == 0)
	ipmi_report_lock_error(domain->os_hnd,
			       "domain not locked when it should have been");
}
#endif

void
_ipmi_domain_entity_lock(ipmi_domain_t *domain)
{

    CHECK_DOMAIN_LOCK(domain);
    ipmi_lock(domain->entities_lock);
}

void
_ipmi_domain_entity_unlock(ipmi_domain_t *domain)
{
    CHECK_DOMAIN_LOCK(domain);
    ipmi_unlock(domain->entities_lock);
}

void
_ipmi_domain_mc_lock(ipmi_domain_t *domain)
{

    CHECK_DOMAIN_LOCK(domain);
    ipmi_lock(domain->mc_lock);
}

void
_ipmi_domain_mc_unlock(ipmi_domain_t *domain)
{
    CHECK_DOMAIN_LOCK(domain);
    ipmi_unlock(domain->mc_lock);
}

/***********************************************************************
 *
 * Domain validation
 *
 **********************************************************************/

/* A open hash table of all the registered domains. */
#define DOMAIN_HASH_SIZE 128
static ipmi_domain_t *domains[DOMAIN_HASH_SIZE];
static ipmi_lock_t *domains_lock;
static int domains_initialized = 0;

static void
add_known_domain(ipmi_domain_t *domain)
{
    unsigned int hash = ipmi_hash_pointer(domain) % DOMAIN_HASH_SIZE;

    ipmi_lock(domains_lock);

    domain->prev = NULL;
    domain->next = domains[hash];
    if (domains[hash])
	domains[hash]->prev = domain;
    domains[hash] = domain;

    ipmi_unlock(domains_lock);
}

static void
remove_known_domain(ipmi_domain_t *domain)
{
    ipmi_lock(domains_lock);

    if (domain->next)
	domain->next->prev = domain->prev;
    if (domain->prev)
	domain->prev->next = domain->next;
    else {
	unsigned int hash = ipmi_hash_pointer(domain) % DOMAIN_HASH_SIZE;
	domains[hash] = domain->next;
    }

    ipmi_unlock(domains_lock);
}

/* Validate that the domain and it's underlying connection is valid
   and increment its use count. */
int
_ipmi_domain_get(ipmi_domain_t *domain)
{
    unsigned int  hash = ipmi_hash_pointer(domain) % DOMAIN_HASH_SIZE;
    ipmi_domain_t *c;
    int           rv = 0;

    if (!domains_initialized)
	    return ECANCELED;

    ipmi_lock(domains_lock);

    c = domains[hash];
    while (c != NULL) {
	if (c == domain)
	    break;
	c = c->next;
    }
    if (c == NULL) {
	rv = EINVAL;
	goto out;
    }

    /* We do this check after we find the domain in the list, because
       want to make sure the pointer is good before we do this. */
    if (!domain->valid) {
	rv = EINVAL;
	goto out;
    }

    domain->usecount++;

 out:
    ipmi_unlock(domains_lock);

    return rv;
}

void
_ipmi_domain_put(ipmi_domain_t *domain)
{
    ipmi_lock(domains_lock);

    if ((domain->usecount == 1) && (domain->in_shutdown)) {
	ipmi_unlock(domains_lock);
	/* The domain has been destroyed, finish the process. */
	real_close_connection(domain);
	return;
    }

    domain->usecount--;

    ipmi_unlock(domains_lock);
}

/***********************************************************************
 *
 * Handle global OEM callbacks new domains.
 *
 **********************************************************************/
typedef struct oem_handlers_s {
    ipmi_domain_oem_check check;
    void                  *cb_data;
} oem_handlers_t;

/* FIXME - do we need a lock?  Probably, add it. */
static ilist_t *oem_handlers;

int
ipmi_register_domain_oem_check(ipmi_domain_oem_check check,
			       void                  *cb_data)
{
    oem_handlers_t *new_item;

    new_item = ipmi_mem_alloc(sizeof(*new_item));
    if (!new_item)
	return ENOMEM;

    new_item->check = check;
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
    oem_handlers_t *cmp = cb_data;

    return ((hndlr->check == cmp->check)
	    && (hndlr->cb_data == cmp->cb_data));
}

int
ipmi_deregister_domain_oem_check(ipmi_domain_oem_check check,
				 void                  *cb_data)
{
    oem_handlers_t *hndlr;
    oem_handlers_t tmp;
    ilist_iter_t   iter;

    tmp.check = check;
    tmp.cb_data = cb_data;
    ilist_init_iter(&iter, oem_handlers);
    ilist_unpositioned(&iter);
    hndlr = ilist_search_iter(&iter, oem_handler_cmp, &tmp);
    if (hndlr) {
	ilist_delete(&iter);
	ipmi_mem_free(hndlr);
	return 0;
    }
    return ENOENT;
}

struct domain_check_oem_s
{
    int                        cancelled;
    ipmi_domain_oem_check_done done;
    void                       *cb_data;
    oem_handlers_t             *curr_handler;
};

static void domain_oem_check_done(ipmi_domain_t *domain,
				  int           err,
				  void          *cb_data);

static void
start_oem_domain_check(ipmi_domain_t      *domain, 
		       domain_check_oem_t *check)
{
    ilist_iter_t     iter;

    ilist_init_iter(&iter, oem_handlers);
    if (!ilist_first(&iter)) {
	/* Empty list, just go on */
	check->done(domain, 0, check->cb_data);
	ipmi_mem_free(check);
	goto out;
    } else {
	oem_handlers_t *h = ilist_get(&iter);
	int            rv = ENOSYS;

	while (rv) {
	    check->curr_handler = h;
	    rv = h->check(domain, domain_oem_check_done, check);
	    if (!rv)
		break;
	    if (rv != ENOSYS)
		break;
	    if (!ilist_next(&iter)) {
		/* End of list, just go on */
		check->done(domain, 0, check->cb_data);
		ipmi_mem_free(check);
		goto out;
	    }
	    h = ilist_get(&iter);
	}
	if (rv) {
	    if (rv == ENOSYS)
		/* This just means that we didn't match anything. */
		rv = 0;

	    /* We didn't get a check to start, just give up. */
	    check->done(domain, rv, check->cb_data);
	    ipmi_mem_free(check);
	}
    }
 out:
    return;
}

static int
oem_handler_cmp2(void *item, void *cb_data)
{
    oem_handlers_t *hndlr = item;
    oem_handlers_t *cmp = cb_data;

    return (hndlr == cmp);
}

static void
next_oem_domain_check(ipmi_domain_t      *domain, 
		      domain_check_oem_t *check)
{
    oem_handlers_t *h;
    ilist_iter_t   iter;

    /* We can't keep an interater in the check, because the list may
       change during execution. */
    ilist_init_iter(&iter, oem_handlers);
    ilist_unpositioned(&iter);
    h = ilist_search_iter(&iter, oem_handler_cmp2, check->curr_handler);
    if (!h) {
	/* The current handler we were working on went away, start over. */
	start_oem_domain_check(domain, check);
    } else {
	int rv = 1;

	while (rv) {
	    if (!ilist_next(&iter)) {
		/* End of list, just go on */
		check->done(domain, 0, check->cb_data);
		ipmi_mem_free(check);
		goto out;
	    }
	    h = ilist_get(&iter);
	    check->curr_handler = h;
	    rv = h->check(domain, domain_oem_check_done, check);
	}
	if (rv) {
	    /* We didn't get a check to start, just give up. */
	    check->done(domain, 0, check->cb_data);
	    ipmi_mem_free(check);
	}
    }
 out:
    return;
}

static void
domain_oem_check_done(ipmi_domain_t *domain,
		      int           err,
		      void          *cb_data)
{
    domain_check_oem_t *check = cb_data;

    if (check->cancelled) {
	check->done(NULL, ECANCELED, check->cb_data);
	ipmi_mem_free(check);
	return;
    }

    if (err != ENOSYS) {
	/* Either we got a success or some error trying to install the
	   OEM handlers. */
	check->done(domain, err, check->cb_data);
	ipmi_mem_free(check);
	return;
    }

    next_oem_domain_check(domain, check);
}

static int
check_oem_handlers(ipmi_domain_t              *domain,
		   ipmi_domain_oem_check_done done,
		   void                       *cb_data)
{
    domain_check_oem_t *check;

    check = ipmi_mem_alloc(sizeof(*check));
    if (!check)
	return ENOMEM;

    check->done = done;
    check->cb_data = cb_data;
    check->cancelled = 0;

    start_oem_domain_check(domain, check);

    return 0;
}

static void
cancel_domain_oem_check(ipmi_domain_t *domain)
{
    if (domain->check)
	domain->check->cancelled = 1;
}

/***********************************************************************
 *
 * FRU data handling
 *
 **********************************************************************/
int _ipmi_domain_fru_set_special_setup(ipmi_domain_t             *domain,
				       _ipmi_domain_fru_setup_cb setup,
				       void                      *cb_data)
{
    domain->fru_setup_cb = setup;
    domain->fru_setup_cb_data = cb_data;
    return 0;
}

int _ipmi_domain_fru_call_special_setup(ipmi_domain_t *domain,
					unsigned char is_logical,
					unsigned char device_address,
					unsigned char device_id,
					unsigned char lun,
					unsigned char private_bus,
					unsigned char channel,
					ipmi_fru_t    *fru)
{
    if (!domain->fru_setup_cb)
	return 0;
    return domain->fru_setup_cb(domain, is_logical, device_address,
				device_id, lun, private_bus, channel,
				fru, domain->fru_setup_cb_data);
}

/***********************************************************************
 *
 * MC handling
 *
 **********************************************************************/

#define HASH_SLAVE_ADDR(x) (((x) >> 1) & (IPMB_HASH-1))

ipmi_mc_t *
_ipmi_find_mc_by_addr(ipmi_domain_t     *domain,
		      const ipmi_addr_t *addr,
		      unsigned int      addr_len)
{
    ipmi_mc_t     *mc = NULL;

    if (addr_len > sizeof(ipmi_addr_t))
	return NULL;

    ipmi_lock(domain->mc_lock);
    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	if (addr->channel == IPMI_BMC_CHANNEL)
	    mc = domain->si_mc;
	else if (addr->channel < MAX_CONS)
	    mc = domain->sys_intf_mcs[addr->channel];
    } else if (addr->addr_type == IPMI_IPMB_ADDR_TYPE) {
	const ipmi_ipmb_addr_t *ipmb = (ipmi_ipmb_addr_t *) addr;
	int                    idx;
	const mc_table_t       *tab;
	ipmi_addr_t            addr2;
	unsigned int           addr2_len;
	int                    i;

	if (addr_len >= sizeof(*ipmb)) {
	    idx = HASH_SLAVE_ADDR(ipmb->slave_addr);
	    tab = &(domain->ipmb_mcs[idx]);
	    for (i=0; i<tab->size; i++) {
		if (tab->mcs[i]) {
		    ipmi_mc_get_ipmi_address(tab->mcs[i], &addr2, &addr2_len);

		    if (ipmi_addr_equal_nolun(addr, addr_len,
					      &addr2, addr2_len))
		    {
			mc = tab->mcs[i];
			break;
		    }
		}
	    }
	}
    }

    /* If we cannot get the MC, it has been destroyed. */
    if (mc) {
	if (_ipmi_mc_get(mc))
	    mc = NULL;
    }
    ipmi_unlock(domain->mc_lock);

    return mc;
}

static int
in_ipmb_ignores(ipmi_domain_t *domain,
		unsigned char channel,
		unsigned char ipmb_addr)
{
    unsigned long addr;
    unsigned char first, last, ichan;
    ilist_iter_t iter;
    int          rv = 0;

    ipmi_lock(domain->ipmb_ignores_lock);
    ilist_init_iter(&iter, domain->ipmb_ignores);
    ilist_unpositioned(&iter);
    while (ilist_next(&iter)) {
	addr = (unsigned long) ilist_get(&iter);
	first = addr & 0xff;
	last = (addr >> 8) & 0xff;
	ichan = (addr >> 16) & 0xff;
	if ((ichan == channel) && (ipmb_addr >= first) && (ipmb_addr <= last))
	    rv = 1;
    }
    ipmi_unlock(domain->ipmb_ignores_lock);

    return rv;
}

int
ipmi_domain_add_ipmb_ignore(ipmi_domain_t *domain,
			    unsigned char channel,
			    unsigned char ipmb_addr)
{
    unsigned long addr = ipmb_addr | (ipmb_addr << 8) | (channel << 16);
    int           rv = 0;

    ipmi_lock(domain->ipmb_ignores_lock);
    if (! ilist_add_tail(domain->ipmb_ignores, (void *) addr, NULL))
	rv = ENOMEM;
    ipmi_unlock(domain->ipmb_ignores_lock);

    return rv;
}

int
ipmi_domain_add_ipmb_ignore_range(ipmi_domain_t *domain,
				  unsigned char channel,
				  unsigned char first_ipmb_addr,
				  unsigned char last_ipmb_addr)
{
    unsigned long addr = (first_ipmb_addr | (last_ipmb_addr << 8)
			  | (channel << 16));
    int           rv = 0;

    ipmi_lock(domain->ipmb_ignores_lock);
    if (! ilist_add_tail(domain->ipmb_ignores, (void *) addr, NULL))
	return ENOMEM;
    ipmi_unlock(domain->ipmb_ignores_lock);

    return rv;
}

typedef struct mc_upd_info_s
{
    enum ipmi_update_e op;
    ipmi_domain_t      *domain;
    ipmi_mc_t          *mc;
} mc_upd_info_t;

static int
iterate_mc_upds(void *cb_data, void *item1, void *item2)
{
    mc_upd_info_t         *info = cb_data;
    ipmi_domain_mc_upd_cb handler = item1;

    handler(info->op, info->domain, info->mc, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
add_mc_to_domain(ipmi_domain_t *domain, ipmi_mc_t *mc)
{
    char         addr_data[sizeof(ipmi_addr_t)];
    ipmi_addr_t  *addr = (ipmi_addr_t *) addr_data;
    unsigned int addr_len;
    int          rv = 0;

    CHECK_DOMAIN_LOCK(domain);
    CHECK_MC_LOCK(mc);

    ipmi_mc_get_ipmi_address(mc, addr, &addr_len);
    
    ipmi_lock(domain->mc_lock);

    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	if (addr->channel >= MAX_CONS)
	    rv = EINVAL;
	else
	    domain->sys_intf_mcs[addr->channel] = mc;
    } else if (addr->addr_type == IPMI_IPMB_ADDR_TYPE) {
	ipmi_ipmb_addr_t *ipmb = (ipmi_ipmb_addr_t *) addr;
	int              idx;
	mc_table_t       *tab;
	int              i;

	idx = HASH_SLAVE_ADDR(ipmb->slave_addr);
	tab = &(domain->ipmb_mcs[idx]);
	if (tab->size == tab->curr) {
	    ipmi_mc_t **nmcs;

	    nmcs = ipmi_mem_alloc(sizeof(ipmi_mc_t *) * (tab->size+5));
	    if (!nmcs) {
		rv = ENOMEM;
		goto out_unlock;
	    }
	    if (tab->mcs) {
		memcpy(nmcs, tab->mcs, sizeof(ipmi_mc_t *) * tab->size);
		ipmi_mem_free(tab->mcs);
	    }
	    memset(nmcs+tab->size, 0, sizeof(ipmi_mc_t *) * 5);
	    tab->size += 5;
	    tab->mcs = nmcs;
	}
	for (i=0; i<tab->size; i++) {
	    if (!tab->mcs[i]) {
		tab->mcs[i] = mc;
		tab->curr++;
		break;
	    }
	}
    }

out_unlock:
    ipmi_unlock(domain->mc_lock);

    return rv;
}

static void
call_mc_upd_handlers(ipmi_domain_t      *domain,
		     ipmi_mc_t          *mc,
		     enum ipmi_update_e op)
{
    mc_upd_info_t info;

    CHECK_DOMAIN_LOCK(domain);
    CHECK_MC_LOCK(mc);

    info.domain = domain;
    info.op = op;
    info.mc = mc;
    locked_list_iterate(domain->mc_upd_handlers, iterate_mc_upds, &info);
}

int
ipmi_domain_add_mc_updated_handler(ipmi_domain_t         *domain,
				   ipmi_domain_mc_upd_cb handler,
				   void                  *cb_data)
{
    if (locked_list_add(domain->mc_upd_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

typedef struct mc_upd_cl_info_s
{
    ipmi_domain_mc_upd_cb handler;
    void                  *handler_data;
} mc_upd_cl_info_t;


static int
iterate_mc_upds_cl(void *cb_data, void *item1, void *item2)
{
    mc_upd_cl_info_t         *info = cb_data;
    ipmi_domain_mc_upd_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_mc_upd_cl_handlers(ipmi_domain_t         *domain,
			ipmi_domain_mc_upd_cb handler,
			void                  *handler_data)
{
    mc_upd_cl_info_t info;

    info.handler = handler;
    info.handler_data = handler_data;
    locked_list_iterate(domain->mc_upd_cl_handlers, iterate_mc_upds_cl, &info);
}

int
ipmi_domain_remove_mc_updated_handler(ipmi_domain_t        *domain,
				      ipmi_domain_mc_upd_cb handler,
				      void                  *cb_data)
{
    if (locked_list_remove(domain->mc_upd_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_domain_add_mc_updated_handler_cl(ipmi_domain_t            *domain,
				      ipmi_domain_mc_upd_cl_cb handler,
				      void                     *cb_data)
{
    if (locked_list_add(domain->mc_upd_cl_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_domain_remove_mc_updated_handler_cl(ipmi_domain_t            *domain,
					 ipmi_domain_mc_upd_cl_cb handler,
					 void                     *cb_data)
{
    if (locked_list_remove(domain->mc_upd_cl_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

/* Must be called with the domain MC lock held.  It will be
   released. */
int
_ipmi_remove_mc_from_domain(ipmi_domain_t *domain, ipmi_mc_t *mc)
{
    char         addr_data[sizeof(ipmi_addr_t)];
    ipmi_addr_t  *addr = (ipmi_addr_t *) addr_data;
    unsigned int addr_len;
    int          found = 0;

    ipmi_mc_get_ipmi_address(mc, addr, &addr_len);
    
    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	if ((addr->channel < MAX_CONS)
	    && (mc == domain->sys_intf_mcs[addr->channel]))
	{
	    domain->sys_intf_mcs[addr->channel] = NULL;
	    found = 1;
	}
    } else if (addr->addr_type == IPMI_IPMB_ADDR_TYPE) {
	ipmi_ipmb_addr_t *ipmb = (ipmi_ipmb_addr_t *) addr;
	int              idx;
	mc_table_t       *tab;
	int              i;

	idx = HASH_SLAVE_ADDR(ipmb->slave_addr);
	tab = &(domain->ipmb_mcs[idx]);
	for (i=0; i<tab->size; i++) {
	    if (tab->mcs[i] == mc) {
		tab->curr--;
		tab->mcs[i] = NULL;
		found = 1;
	    }
	}
    }

    ipmi_unlock(domain->mc_lock);

    if (found) {
	call_mc_upd_handlers(domain, mc, IPMI_DELETED);
	return 0;
    } else
	return ENOENT;
}

int
_ipmi_find_or_create_mc_by_slave_addr(ipmi_domain_t *domain,
				      unsigned int  channel,
				      unsigned int  slave_addr,
				      ipmi_mc_t     **new_mc)
{
    ipmi_mc_t   *mc;
    char        addr_data[sizeof(ipmi_addr_t)];
    ipmi_addr_t *addr = (ipmi_addr_t *) addr_data;
    int         addr_size;
    int         rv;

    if (channel == IPMI_BMC_CHANNEL) {
	ipmi_system_interface_addr_t *saddr = (void *) addr;
	saddr->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	saddr->channel = slave_addr;
	saddr->lun = 0;
	addr_size = sizeof(*saddr);
    } else {
	ipmi_ipmb_addr_t *iaddr = (void *) addr;
	iaddr->addr_type = IPMI_IPMB_ADDR_TYPE;
	iaddr->channel = channel;
	iaddr->lun = 0;
	iaddr->slave_addr = slave_addr;
	addr_size = sizeof(*iaddr);
    }

    mc = _ipmi_find_mc_by_addr(domain, addr, addr_size);
    if (mc) {
	if (new_mc)
	    *new_mc = mc;
	return 0;
    }

    rv = _ipmi_create_mc(domain, addr, addr_size, &mc);
    if (rv)
	return rv;

    /* If we find an MC in the SDRs that we don't know about yet,
       attempt to scan it. */
    if (ipmi_option_IPMB_scan(domain))
	ipmi_start_ipmb_mc_scan(domain, channel, slave_addr, slave_addr,
				NULL, NULL);

    rv = add_mc_to_domain(domain, mc);
    if (rv) {
	_ipmi_cleanup_mc(mc);
	_ipmi_mc_put(mc);
	return rv;
    }
    call_mc_upd_handlers(domain, mc, IPMI_ADDED);

    if (new_mc)
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

/* Must be called with the cmds_lock held. */
static int
find_and_remove_msg(ipmi_domain_t *domain, ll_msg_t *nmsg, long seq)
{
    ilist_iter_t iter;
    int          rv = 0;

    ilist_init_iter(&iter, domain->cmds);
    ilist_unpositioned(&iter);
    if ((ilist_search_iter(&iter, cmp_nmsg, nmsg) != NULL)
	&& (nmsg->seq == seq))
    {
	ilist_delete(&iter);
	rv = 1;
    }
    return rv;
}

static int
ll_rsp_handler(ipmi_con_t   *ipmi,
	       ipmi_msgi_t  *orspi)
{
    ipmi_msgi_t   *rspi;
    ipmi_domain_t *domain = orspi->data1;
    ll_msg_t      *nmsg = orspi->data2;
    long          seq = (long) orspi->data3;
    long          conn_seq = (long) orspi->data4;
    int           rv;

    rv = _ipmi_domain_get(domain);
    if (rv)
	/* No need to report these to the upper layer, they have
	   already been delivered in the cleanup code. */
	return IPMI_MSG_ITEM_NOT_USED;

    ipmi_lock(domain->cmds_lock);
    if (conn_seq != domain->conn_seq[nmsg->con]) {
	/* The message has been rerouted, just ignore this response. */
	ipmi_unlock(domain->cmds_lock);
	goto out_unlock;
    }

    if (!find_and_remove_msg(domain, nmsg, seq)) {
	ipmi_unlock(domain->cmds_lock);
	goto out_unlock;
    }
    ipmi_unlock(domain->cmds_lock);

    rspi = nmsg->rsp_item;
    if (nmsg->rsp_handler) {
	ipmi_move_msg_item(rspi, orspi);
	memcpy(&rspi->addr, &orspi->addr, orspi->addr_len);
	rspi->addr_len = orspi->addr_len;
	deliver_rsp(domain, nmsg->rsp_handler, rspi);
    } else
	ipmi_free_msg_item(rspi);
    ipmi_mem_free(nmsg);
 out_unlock:
    _ipmi_domain_put(domain);
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
ll_si_rsp_handler(ipmi_con_t *ipmi, ipmi_msgi_t *orspi)
{
    ipmi_msgi_t                  *rspi;
    ipmi_domain_t                *domain = orspi->data1;
    ll_msg_t                     *nmsg = orspi->data2;
    int                          rv;

    rspi = nmsg->rsp_item;

    rv = _ipmi_domain_get(domain);
    if (rv) {
	/* Note that since we don't track SI messages, we must report
	   them to the upper layer through this interface when the
	   domain goes away. */
	deliver_rsp(NULL, nmsg->rsp_handler, rspi);
	return IPMI_MSG_ITEM_NOT_USED;
    }

    if (nmsg->rsp_handler) {
	ipmi_move_msg_item(rspi, orspi);
	/* Set the LUN from the response message. */
	ipmi_addr_set_lun(&rspi->addr, ipmi_addr_get_lun(&rspi->addr));
	deliver_rsp(domain, nmsg->rsp_handler, rspi);
    } else
	ipmi_free_msg_item(rspi);
    ipmi_mem_free(nmsg);

    _ipmi_domain_put(domain);
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
matching_domain_sysaddr(ipmi_domain_t *domain, const ipmi_addr_t *addr,
			ipmi_system_interface_addr_t *si)
{
    if (addr->addr_type == IPMI_IPMB_ADDR_TYPE) {
	ipmi_ipmb_addr_t *ipmb = (ipmi_ipmb_addr_t *) addr;
	int              i;

	if (ipmb->channel >= MAX_IPMI_USED_CHANNELS)
	    return 0;

	if (domain->chan[ipmb->channel].medium != IPMI_CHANNEL_MEDIUM_IPMB)
	    return 0;

	for (i=0; i<MAX_CONS; i++) {
	    if (domain->con_active[i]
		&& domain->con_up[i]
		&& (domain->con_ipmb_addr[i][ipmb->channel]==ipmb->slave_addr)
		&& domain->sys_intf_mcs[i])
	    {
		si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
		si->channel = i;
		si->lun = ipmb->lun;
		return 1;
	    }
	}
    }

    return 0;
}

static int
send_command_option(ipmi_domain_t           *domain,
		    int                     conn,
		    const ipmi_addr_t       *addr,
		    unsigned int            addr_len,
		    const ipmi_msg_t        *msg,
		    const ipmi_con_option_t *options,
		    ipmi_ll_rsp_handler_t   handler,
		    void		    *handler_data)
{
    if (domain->conn[conn]->send_command_option)
	return domain->conn[conn]->send_command_option(domain->conn[conn],
						       addr, addr_len,
						       msg,
						       options,
						       handler,
						       handler_data);
    else
	return domain->conn[conn]->send_command(domain->conn[conn],
						addr, addr_len,
						msg,
						handler,
						handler_data);
}

static int
send_command_addr(ipmi_domain_t                *domain,
		  const ipmi_addr_t            *addr,
		  unsigned int                 addr_len,
		  const ipmi_msg_t             *msg,
		  ipmi_addr_response_handler_t rsp_handler,
		  void                         *rsp_data1,
		  void                         *rsp_data2,
		  int			       side_effects)
{
    int                          rv;
    int                          u;
    ll_msg_t                     *nmsg;
    ipmi_system_interface_addr_t si;
    ipmi_ll_rsp_handler_t        handler;
    void                         *data4 = NULL;
    int                          is_ipmb = 0;
    ipmi_msgi_t                  *rspi;
    ipmi_con_option_t            opt_data[2];
    ipmi_con_option_t		 *options = NULL;

    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    if (msg->data_len > IPMI_MAX_MSG_LENGTH)
	return EINVAL;

    if (domain->in_shutdown)
	return EINVAL;

    if (side_effects) {
	options = opt_data;
	options[0].option = IPMI_CON_MSG_OPTION_SIDE_EFFECTS;
	options[0].ival = 1;
	options[1].option = IPMI_CON_OPTION_LIST_END;
    }

    CHECK_DOMAIN_LOCK(domain);

    nmsg = ipmi_mem_alloc(sizeof(*nmsg));
    if (!nmsg)
	return ENOMEM;
    nmsg->rsp_item = ipmi_alloc_msg_item();
    if (!nmsg->rsp_item) {
	ipmi_mem_free(nmsg);
	return ENOMEM;
    }

    /* Copy the address here because where we send it may change.  But
       we want the response address to match what we sent. */
    memcpy(&nmsg->rsp_item->addr, addr, addr_len);
    nmsg->rsp_item->addr_len = addr_len;

    if (matching_domain_sysaddr(domain, addr, &si)) {
	/* We have a direct connection to this BMC and it is up and
	   operational, so talk directly to it. */
	u = si.channel;
	si.channel = IPMI_BMC_CHANNEL;
	addr = (ipmi_addr_t *) &si;
	addr_len = sizeof(si);
	handler = ll_si_rsp_handler;
    } else if ((addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE)
	&& (addr->channel != IPMI_BMC_CHANNEL))
    {
	u = addr->channel;

	/* Messages to system interface addresses use the channel to
           choose which system address to message. */
	if ((u < 0) || (u >= MAX_CONS)) {
	    rv = EINVAL;
	    goto out;
	}
	if (!domain->conn[u]) {
	    rv = EINVAL;
	    goto out;
	}

	si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si.channel = IPMI_BMC_CHANNEL;
	si.lun = ((ipmi_system_interface_addr_t *) addr)->lun;
	addr = (ipmi_addr_t *) &si;
	addr_len = sizeof(si);
	handler = ll_si_rsp_handler;
    } else {
	u = domain->working_conn;

	/* If we don't have any working connection, just use connection
	   zero. */
	if (u == -1)
	    u = 0;
	handler = ll_rsp_handler;
	is_ipmb = 1;
    }

    nmsg->domain = domain;
    nmsg->con = u;

    memcpy(&nmsg->msg, msg, sizeof(nmsg->msg));
    nmsg->msg.data = nmsg->msg_data;
    nmsg->msg.data_len = msg->data_len;
    memcpy(nmsg->msg.data, msg->data, msg->data_len);

    nmsg->rsp_handler = rsp_handler;
    nmsg->rsp_item->data1 = rsp_data1;
    nmsg->rsp_item->data2 = rsp_data2;

    nmsg->side_effects = side_effects;

    ipmi_lock(domain->cmds_lock);
    nmsg->seq = domain->cmds_seq;
    domain->cmds_seq++;

    /* Have to delay this to here so we are holding the lock. */
    if (is_ipmb)
	data4 = (void *) (long) domain->conn_seq[u];

    rspi = ipmi_alloc_msg_item();
    if (!rspi) {
	rv = ENOMEM;
	goto out_unlock;
    }

    rspi->data1 = domain;
    rspi->data2 = nmsg;
    rspi->data3 = (void *) nmsg->seq;
    rspi->data4 = data4;
    rv = send_command_option(domain, u, addr, addr_len,
			     msg, options, handler, rspi);

    if (rv) {
	ipmi_free_msg_item(rspi);
	goto out_unlock;
    } else if (is_ipmb) {
	/* If it's a system interface we don't add it to the list of
	   commands running, because it will never need to be
	   rerouted. */
	ilist_add_tail(domain->cmds, nmsg, &nmsg->link);
    }
 out_unlock:
    ipmi_unlock(domain->cmds_lock);

 out:
    if (rv) {
	ipmi_free_msg_item(nmsg->rsp_item);
	ipmi_mem_free(nmsg);
    }
    return rv;
}

int
ipmi_send_command_addr(ipmi_domain_t                *domain,
		       const ipmi_addr_t	    *addr,
		       unsigned int                 addr_len,
		       const ipmi_msg_t             *msg,
		       ipmi_addr_response_handler_t rsp_handler,
		       void                         *rsp_data1,
		       void                         *rsp_data2)
{
    return send_command_addr(domain, addr, addr_len, msg, rsp_handler,
			     rsp_data1, rsp_data2, 0);
}

int
ipmi_send_command_addr_sideeff(ipmi_domain_t                *domain,
			       const ipmi_addr_t	    *addr,
			       unsigned int                 addr_len,
			       const ipmi_msg_t             *msg,
			       ipmi_addr_response_handler_t rsp_handler,
			       void                         *rsp_data1,
			       void                         *rsp_data2)
{
    return send_command_addr(domain, addr, addr_len, msg, rsp_handler,
			     rsp_data1, rsp_data2, 1);
}

/* Take all the commands for any inactive or down connection and
   resend them on another connection.  */
static void
reroute_cmds(ipmi_domain_t *domain, int old_con, int new_con)
{
    ilist_iter_t iter;
    int          rv;
    ll_msg_t     *nmsg;

    ipmi_lock(domain->cmds_lock);
    ilist_init_iter(&iter, domain->cmds);
    rv = ilist_first(&iter);
    (domain->conn_seq[old_con])++;
    while (rv) {
	nmsg = ilist_get(&iter);
	if (nmsg->con == old_con) {
	    ipmi_msgi_t       *rspi;
	    ipmi_con_option_t opt_data[2];
	    ipmi_con_option_t *options = NULL;

	    nmsg->seq = domain->cmds_seq;
	    domain->cmds_seq++; /* Make the message unique so a
                                   response from the other connection
                                   will not match. */
	    nmsg->con = new_con;

	    rspi = ipmi_alloc_msg_item();
	    if (!rspi)
		goto send_err;

	    if (nmsg->side_effects) {
		options = opt_data;
		options[0].option = IPMI_CON_MSG_OPTION_SIDE_EFFECTS;
		options[0].ival = 1;
		options[1].option = IPMI_CON_OPTION_LIST_END;
	    }

	    rspi->data1 = domain;
	    rspi->data2 = nmsg;
	    rspi->data3 = (void *) nmsg->seq;
	    rspi->data4 = (void *) domain->conn_seq[new_con];
	    rv = send_command_option(domain, new_con,
				     &nmsg->rsp_item->addr,
				     nmsg->rsp_item->addr_len,
				     &nmsg->msg,
				     options,
				     ll_rsp_handler,
				     rspi);
	    if (rv) {
		ipmi_free_msg_item(rspi);
	    send_err:
		/* Couldn't send the message, just fail it. */
		if (nmsg->rsp_handler) {
		    rspi = nmsg->rsp_item;
		    rspi->msg.netfn = nmsg->msg.netfn | 1;
		    rspi->msg.cmd = nmsg->msg.cmd;
		    rspi->msg.data = rspi->data;
		    rspi->msg.data_len = 1;
		    rspi->data[0] = IPMI_UNKNOWN_ERR_CC;
		    deliver_rsp(domain, nmsg->rsp_handler, rspi);
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
    int            rv;
    struct timeval timeout;

    CHECK_DOMAIN_LOCK(domain);

    ipmi_lock(domain->audit_domain_timer_info->lock);
    domain->audit_domain_interval = seconds;
    rv = domain->os_hnd->stop_timer(domain->os_hnd,
				    domain->audit_domain_timer);
    if (rv) {
	/* If we can't stop the timer, that's ok, the timer is in the
	   wakeup and will handle the restart for us. */
	ipmi_unlock(domain->audit_domain_timer_info->lock);
	return;
    }
    timeout.tv_sec = domain->audit_domain_interval;
    timeout.tv_usec = 0;
    domain->os_hnd->start_timer(domain->os_hnd,
				domain->audit_domain_timer,
				&timeout,
				domain_audit,
				domain->audit_domain_timer_info);
    ipmi_unlock(domain->audit_domain_timer_info->lock);
}

unsigned int
ipmi_domain_get_ipmb_rescan_time(ipmi_domain_t *domain)
{
    CHECK_DOMAIN_LOCK(domain);

    return domain->audit_domain_interval;
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

static int devid_bc_rsp_handler(ipmi_domain_t *domain, ipmi_msgi_t *rspi);

static void
rescan_timeout_handler(void *cb_data, os_hnd_timer_id_t *id)
{
    mc_ipmb_scan_info_t *info = cb_data;
    int                 rv;
    ipmi_ipmb_addr_t    *ipmb;
    ipmi_domain_t       *domain;

    ipmi_lock(info->lock);
    if (info->cancelled) {
	ipmi_unlock(info->lock);
	info->os_hnd->free_timer(info->os_hnd, info->timer);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	return;
    }
    info->timer_running = 0;
    ipmi_unlock(info->lock);

    domain = info->domain;
    rv = _ipmi_domain_get(domain);
    if (rv) {
	ipmi_log(IPMI_LOG_INFO,
		 "%sdomain.c(rescan_timeout_handler): "
		 "BMC went away while scanning for MCs",
		 DOMAIN_NAME(domain));
	return;
    }

    goto retry_addr;

 next_addr_nolock:
    ipmb = (ipmi_ipmb_addr_t *) &info->addr;
    if ((info->addr.addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE)
	|| (ipmb->slave_addr >= info->end_addr)) {
	/* We've hit the end, we can quit now. */
	if (info->done_handler)
	    info->done_handler(domain, 0, info->cb_data);
	remove_bus_scans_running(domain, info);
	info->os_hnd->free_timer(info->os_hnd, info->timer);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	goto out;
    }
    ipmb->slave_addr += 2;
    info->missed_responses = 0;
    if (in_ipmb_ignores(domain, ipmb->channel, ipmb->slave_addr))
	goto next_addr_nolock;

 retry_addr:
    rv = ipmi_send_command_addr(domain,
				&(info->addr),
				info->addr_len,
				&(info->msg),
				devid_bc_rsp_handler,
				info, NULL);
    if (rv)
	goto next_addr_nolock;

 out:
    _ipmi_domain_put(domain);
}

static int
devid_bc_rsp_handler(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_msg_t          *msg = &rspi->msg;
    ipmi_addr_t         *addr = &rspi->addr;
    unsigned int        addr_len = rspi->addr_len;
    mc_ipmb_scan_info_t *info = rspi->data1;
    int                 rv;
    ipmi_mc_t           *mc = NULL;
    ipmi_ipmb_addr_t    *ipmb;
    int                 mc_added = 0;
    int                 mc_changed = 0;


    rv = _ipmi_domain_get(domain);
    if (rv) {
	ipmi_log(IPMI_LOG_INFO,
		 "%sdomain.c(devid_bc_rsp_handler): "
		 "BMC went away while scanning for MCs",
		 DOMAIN_NAME(domain));
	return IPMI_MSG_ITEM_NOT_USED;
    }

    mc = _ipmi_find_mc_by_addr(domain, addr, addr_len);
    if (msg->data[0] == 0) {
	if (mc && ipmi_mc_is_active(mc)
	    && !_ipmi_mc_device_data_compares(mc, msg))
	{
	    /* The MC was replaced with a new one, so clear the old
               one and add a new one. */
	    _ipmi_cleanup_mc(mc);
	    _ipmi_mc_put(mc);
	    mc = _ipmi_find_mc_by_addr(domain, addr, addr_len);
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
		    if (info->done_handler)
			info->done_handler(domain, 0, info->cb_data);
		    remove_bus_scans_running(domain, info);
		    info->os_hnd->free_timer(info->os_hnd, info->timer);
		    ipmi_destroy_lock(info->lock);
		    ipmi_mem_free(info);
		    goto out;
		}

		rv = add_mc_to_domain(domain, mc);
		if (rv) {
		    _ipmi_cleanup_mc(mc);
		    goto next_addr;
		}

		rv = _ipmi_mc_get_device_id_data_from_rsp(mc, msg);
		if (rv) {
		    /* If we couldn't handle the device data, just clean
		       it up */
		    _ipmi_cleanup_mc(mc);
		    goto out;
		}

		/* In this case, the use count is defined to be 1, so
		   it will always be set up properly and the previous
		   function will not return EAGAIN, no need to
		   check. */

		mc_added = 1;
		_ipmi_mc_handle_new(mc);
	    } else {
		/* It was inactive, activate it. */
		rv = _ipmi_mc_get_device_id_data_from_rsp(mc, msg);
		if (rv == EAGAIN) {
		    /* The MC is in use, so we cannot handle it right
		       now.  We wait until the MC is released to do
		       that and cue off the pending new MC field in
		       the MC. */
		} else if (rv) {
		    /* If we couldn't handle the device data, just clean
		       it up. */
		    _ipmi_cleanup_mc(mc);
		} else {
		    mc_changed = 1;
		    _ipmi_mc_handle_new(mc);
		}
	    }
	} else {
	    /* Periodically check the MCs. */
	    _ipmi_mc_check_mc(mc);
	}
    } else if (mc && ipmi_mc_is_active(mc)) {
	/* Didn't get a response.  Maybe the MC has gone away? */
	info->missed_responses++;

	/* We fail system interface addresses immediately, since they
           shouldn't be a timeout problem. */
	if ((info->addr.addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE)
	    || (info->missed_responses >= MAX_MC_MISSED_RESPONSES))
	{
	    _ipmi_cleanup_mc(mc);
	    goto next_addr;
	} else {
	    /* Try again after a second. */
	    struct timeval timeout;

	    if (msg->data[0] == IPMI_TIMEOUT_CC)
		/* If we timed out, then no need to time, since a
		   second has gone by already. */
		goto retry_addr;

	    ipmi_lock(info->lock);
	    timeout.tv_sec = 1;
	    timeout.tv_usec = 0;
	    info->timer_running = 1;
	    info->os_hnd->start_timer(info->os_hnd,
				      info->timer,
				      &timeout,
				      rescan_timeout_handler,
				      info);
	    ipmi_unlock(info->lock);
	    goto out;
	}
    }

 next_addr:
    if (mc_added)
	call_mc_upd_handlers(domain, mc, IPMI_ADDED);
    else if (mc_changed)
	call_mc_upd_handlers(domain, mc, IPMI_CHANGED);

 next_addr_nolock:
    ipmb = (ipmi_ipmb_addr_t *) &info->addr;
    if ((info->addr.addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE)
	|| (ipmb->slave_addr >= info->end_addr)) {
	/* We've hit the end, we can quit now. */
	if (info->done_handler)
	    info->done_handler(domain, 0, info->cb_data);
	remove_bus_scans_running(domain, info);
	info->os_hnd->free_timer(info->os_hnd, info->timer);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	goto out;
    }
    ipmb->slave_addr += 2;
    info->missed_responses = 0;
    if (in_ipmb_ignores(domain, ipmb->channel, ipmb->slave_addr))
	goto next_addr_nolock;

 retry_addr:
    rv = ipmi_send_command_addr(domain,
				&(info->addr),
				info->addr_len,
				&(info->msg),
				devid_bc_rsp_handler,
				info, NULL);
    if (rv)
	goto next_addr_nolock;

 out:
    if (mc)
	_ipmi_mc_put(mc);
    _ipmi_domain_put(domain);
    return IPMI_MSG_ITEM_NOT_USED;
}

int
ipmi_start_ipmb_mc_scan(ipmi_domain_t  *domain,
	       		int            channel,
	       		unsigned int   start_addr,
			unsigned int   end_addr,
			ipmi_domain_cb done_handler,
			void           *cb_data)
{
    mc_ipmb_scan_info_t *info;
    int                 rv;
    ipmi_ipmb_addr_t    *ipmb;

    CHECK_DOMAIN_LOCK(domain);

    if (channel > MAX_IPMI_USED_CHANNELS)
	return EINVAL;

    if ((domain->chan[channel].medium != 1)
	&& !(start_addr == 0x20 || end_addr == 0x20))
	/* Make sure it is IPMB, or the BMC address. */
	return ENOSYS;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));

    info->domain = domain;
    ipmb = (ipmi_ipmb_addr_t *) &info->addr;
    ipmb->addr_type = IPMI_IPMB_BROADCAST_ADDR_TYPE;
    ipmb->channel = channel;
    ipmb->slave_addr = start_addr;
    ipmb->lun = 0;
    info->addr_len = sizeof(*ipmb);
    info->msg.netfn = IPMI_APP_NETFN;
    info->msg.cmd = IPMI_GET_DEVICE_ID_CMD;
    info->msg.data = NULL;
    info->msg.data_len = 0;
    info->end_addr = end_addr;
    info->done_handler = done_handler;
    info->cb_data = cb_data;
    info->missed_responses = 0;
    info->os_hnd = domain->os_hnd;
    rv = info->os_hnd->alloc_timer(info->os_hnd, &info->timer);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock(domain, &info->lock);
    if (rv)
	goto out_err;

    rv = ENOSYS; /* Return err if no scans done */

    /* Skip addresses we must ignore. */
    while (in_ipmb_ignores(domain, ipmb->channel, ipmb->slave_addr)) {
	/* ipmb->slave_addr is 8 bits, so we can't do a <= comparison as it
	   will overflow after 254. */
	if (ipmb->slave_addr == end_addr)
	    goto out_err;
	ipmb->slave_addr += 2;
    }
    while (rv) {
	rv = ipmi_send_command_addr(domain,
				    &info->addr,
				    info->addr_len,
				    &(info->msg),
				    devid_bc_rsp_handler,
				    info, NULL);
	if (rv) {
	    if (ipmb->slave_addr == end_addr)
		goto out_err;
	    ipmb->slave_addr += 2;
	}
    }

    if (rv)
	goto out_err;
    else
	add_bus_scans_running(domain, info);
    return 0;

 out_err:
    if (info->timer)
	info->os_hnd->free_timer(info->os_hnd, info->timer);
    if (info->lock)
	ipmi_destroy_lock(info->lock);
    ipmi_mem_free(info);
    return 0; /* Since the done handler is always called, always
		 return true.  Bus scans always succeed. */
}

int
ipmi_start_si_scan(ipmi_domain_t  *domain,
		   int            si_num,
		   ipmi_domain_cb done_handler,
		   void           *cb_data)
{
    mc_ipmb_scan_info_t          *info;
    ipmi_system_interface_addr_t *si;
    int                          rv;

    info = ipmi_mem_alloc(sizeof(mc_ipmb_scan_info_t));
    if (!info) 
	return ENOMEM;
    memset(info, 0, sizeof(*info));

    info->domain = domain;
    si = (void *) &info->addr;
    si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si->channel = si_num;
    si->lun = 0;
    info->addr_len = sizeof(*si);
    info->msg.netfn = IPMI_APP_NETFN;
    info->msg.cmd = IPMI_GET_DEVICE_ID_CMD;
    info->msg.data = NULL;
    info->msg.data_len = 0;
    info->done_handler = done_handler;
    info->cb_data = cb_data;
    info->missed_responses = 0;
    info->os_hnd = domain->os_hnd;
    rv = info->os_hnd->alloc_timer(info->os_hnd, &info->timer);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock(domain, &info->lock);
    if (rv)
	goto out_err;

    rv = ipmi_send_command_addr(domain,
				&info->addr,
				info->addr_len,
				&(info->msg),
				devid_bc_rsp_handler,
				info, NULL);
    if (rv)
	goto out_err;
    else
	add_bus_scans_running(domain, info);
    return 0;

 out_err:
    if (info->timer)
	info->os_hnd->free_timer(info->os_hnd, info->timer);
    if (info->lock)
	ipmi_destroy_lock(info->lock);
    ipmi_mem_free(info);
    return rv;
}

static void
mc_scan_done(ipmi_domain_t *domain, int err, void *cb_data)
{
    ipmi_domain_cb bus_scan_handler;
    void           *bus_scan_handler_cb_data;

    ipmi_lock(domain->mc_lock);
    domain->scanning_bus_count--;
    if (domain->scanning_bus_count) {
	_ipmi_put_domain_fully_up(domain, "mc_scan_done");
	ipmi_unlock(domain->mc_lock);
	return;
    }

    bus_scan_handler = domain->bus_scan_handler;
    bus_scan_handler_cb_data = domain->bus_scan_handler_cb_data;
    ipmi_unlock(domain->mc_lock);
    if (bus_scan_handler)
	bus_scan_handler(domain, 0,
			 bus_scan_handler_cb_data);
    _ipmi_put_domain_fully_up(domain, "mc_scan_done");
}

void
_ipmi_start_mc_scan_one(ipmi_domain_t *domain, int chan, int first, int last)
{
    int rv;

    _ipmi_get_domain_fully_up(domain, "_ipmi_start_mc_scan_one");
    domain->scanning_bus_count++;
    rv = ipmi_start_ipmb_mc_scan(domain, chan, first, last,
				 mc_scan_done, NULL);
    if (rv) {
	domain->scanning_bus_count--;
	_ipmi_put_domain_fully_up(domain, "_ipmi_start_mc_scan_one");
    }
}

static int
cmp_int(const void *v1, const void *v2)
{
    const int *i1 = v1;
    const int *i2 = v2;
    if (*i1 < *i2)
	return -1;
    else if (*i1 > *i2)
	return 1;
    else
	return 0;
}

void
ipmi_domain_start_full_ipmb_scan(ipmi_domain_t *domain)
{
    int i, j;
    int rv;
    int got_bmc = 0;

    if (domain->in_shutdown)
	return;

    ipmi_lock(domain->mc_lock);
    if (!domain->do_bus_scan || (!ipmi_option_IPMB_scan(domain))) {
	/* Always scan the local BMC(s). */
	for (i=0; i<MAX_CONS; i++) {
	    if (!domain->conn[i])
		continue;
	    for (j=0; j<MAX_IPMI_USED_CHANNELS; j++) {
		if (domain->chan[j].medium != IPMI_CHANNEL_MEDIUM_IPMB)
		    continue;
		_ipmi_start_mc_scan_one(domain, j,
					domain->con_ipmb_addr[i][j],
					domain->con_ipmb_addr[i][j]);
		break;
	    }
	    if (j == MAX_IPMI_USED_CHANNELS) {
		/* Didn't find a valid channel, just scan 0 to get one. */
		_ipmi_start_mc_scan_one(domain, 0,
					domain->con_ipmb_addr[i][0],
					domain->con_ipmb_addr[i][0]);
	    }
	}
	ipmi_unlock(domain->mc_lock);
	return;
    }

    if (domain->scanning_bus_count) {
	ipmi_unlock(domain->mc_lock);
	return;
    }

    /* If a connections supports sysaddress scanning, then scan the
       system address for that connection. */
    for (i=0; i<MAX_CONS; i++) {
	if ((domain->con_up[i]) && domain->conn[i]->scan_sysaddr) {
	    _ipmi_get_domain_fully_up(domain,
				      "ipmi_domain_start_full_ipmb_scan");
	    domain->scanning_bus_count++;
	    rv = ipmi_start_si_scan(domain, i, mc_scan_done, NULL);
	    if (rv) {
		domain->scanning_bus_count--;
		_ipmi_put_domain_fully_up(domain,
					  "ipmi_domain_start_full_ipmb_scan");
	    }
	}
    }

    /* Now start the IPMB scans. */
    for (i=0; i<MAX_IPMI_USED_CHANNELS; i++) {
	if (domain->chan[i].medium == IPMI_CHANNEL_MEDIUM_IPMB) {
	    if (!got_bmc) {
		got_bmc = 1;
		/* Always scan the normal BMC first. */
		_ipmi_start_mc_scan_one(domain, i, 0x20, 0x20);
		_ipmi_start_mc_scan_one(domain, i, 0x10, 0xf0);
	    } else {
		/* This is unfortunately complicated.  We only want
		   the BMC to show up in one place, so we only scan
		   the BMC's address on the first one.  If we have a
		   system with two connections (two BMCs), we want to
		   make sure they don't show up on each others lists.
		   So except for the first IPMB, we ignore all BMC
		   IPMB addresses. */
		int ignore_addr[MAX_CONS];
		int num_ignore = 0;
		int cstart = 0x10;
		for (j=0; j<MAX_CONS; j++) {
		    if (! domain->conn[j])
			continue;
		    ignore_addr[num_ignore] = domain->con_ipmb_addr[j][i];
		    num_ignore++;
		}
		qsort(ignore_addr, num_ignore, sizeof(int), cmp_int);
		for (j=0; j<num_ignore; j++) {
		    _ipmi_start_mc_scan_one(domain, i,
					    cstart, ignore_addr[j]-1);
		    cstart = ignore_addr[j]+1;
		}
		if (cstart <= 0xf0)
		    _ipmi_start_mc_scan_one(domain, i, cstart, 0xf0);
	    }
	}
    }
    ipmi_unlock(domain->mc_lock);
}

static void
refetch_sdr_handler(ipmi_sdr_info_t *sdrs,
		    int             err,
		    int             changed,
		    unsigned int    count,
		    void            *cb_data)
{
    ipmi_domain_t *domain = cb_data;

    if (changed) {
	ipmi_entity_scan_sdrs(domain, NULL,
			      domain->entities, domain->main_sdrs);
	ipmi_sensor_handle_sdrs(domain, NULL, domain->main_sdrs);
	ipmi_detect_ents_presence_changes(domain->entities, 1);
    }
}

static void
check_main_sdrs(ipmi_domain_t *domain)
{
    if (ipmi_option_SDRs(domain))
	ipmi_sdr_fetch(domain->main_sdrs, refetch_sdr_handler, domain);
}

static void
domain_audit(void *cb_data, os_hnd_timer_id_t *id)
{
    struct timeval      timeout;
    audit_domain_info_t *info = cb_data;
    ipmi_domain_t       *domain = info->domain;
    int                 rv;

    ipmi_lock(info->lock);
    if (info->cancelled) {
	ipmi_unlock(info->lock);
	info->os_hnd->free_timer(info->os_hnd, id);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	return;
    }

    rv = _ipmi_domain_get(domain);
    if (rv)
	goto out;

    if (domain->got_invalid_dev_id) {
	/* Failure getting device id, just try again. */
	domain_send_mc_id(domain);
	goto out_start_timer;
    }

    /* Only operate if we know a connection is up. */
    if (! domain->connection_up)
	goto out_start_timer;

    /* Rescan all the presence sensors to make sure they are valid. */
    ipmi_detect_domain_presence_changes(domain, 1);
    
    ipmi_domain_start_full_ipmb_scan(domain);

    /* Also check to see if the SDRs have changed. */
    check_main_sdrs(domain);

 out_start_timer:
    timeout.tv_sec = domain->audit_domain_interval;
    timeout.tv_usec = 0;
    domain->os_hnd->start_timer(domain->os_hnd,
				id,
				&timeout,
				domain_audit,
				info);
    _ipmi_domain_put(domain);
 out:
    ipmi_unlock(info->lock);
}

/***********************************************************************
 *
 * Incoming event handling.
 *
 **********************************************************************/

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
				  ipmi_mc_t     *ev_mc,
				  ipmi_event_t  *event)
{
    int          rv = 1;
    ipmi_time_t  timestamp = ipmi_event_get_timestamp(event);
    unsigned int type = ipmi_event_get_type(event);

    /* We do not need any locking to assure that events are delivered
       in order (from the same SEL).  Indeed, locking here wouldn't
       help.  But the event-fetching mechanisms are guaranteed to be
       single-threaded, so ordering is always preserved there. */

    if (DEBUG_EVENTS) {
	ipmi_mcid_t         mcid = ipmi_event_get_mcid(event);
	unsigned int        record_id = ipmi_event_get_record_id(event);
	unsigned int        data_len = ipmi_event_get_data_len(event);
	const unsigned char *data;

	ipmi_log(IPMI_LOG_DEBUG_START,
		 "Event recid mc (0x%x):%4.4x type:%2.2x timestamp %lld:",
		 mcid.mc_num, record_id, type, (long long) timestamp);
	if (data_len) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n  ");
	    data = ipmi_event_get_data_ptr(event);
	    dump_hex(data, data_len);
	}
	ipmi_log(IPMI_LOG_DEBUG_END, " ");
    }

    /* Let the OEM handler for the MC that the message came from have
       a go at it first.  Note that OEM handlers must look at the time
       themselves. */
    if (_ipmi_mc_check_sel_oem_event_handler(ev_mc, event))
	return;

    /* It's a system event record from an MC, and the timestamp is
       later than our startup timestamp. */
    if ((type == 0x02) && !ipmi_event_is_old(event)) {
	/* It's a standard IPMI event. */
	ipmi_mc_t           *mc;
	ipmi_sensor_id_t    id;
	event_sensor_info_t info;
	const unsigned char *data;

	mc = _ipmi_event_get_generating_mc(domain, ev_mc, event);
	if (!mc)
	    goto out;

	/* Let the OEM handler for the MC that sent the event try
	   next. */
	if (_ipmi_mc_check_oem_event_handler(mc, event)) {
	    _ipmi_mc_put(mc);
	    return;
	}

	/* The OEM code didn't handle it. */
	data = ipmi_event_get_data_ptr(event);
	id.mcid = ipmi_mc_convert_to_id(mc);
	id.lun = data[5] & 0x3;
	id.sensor_num = data[8];

	info.event = event;

	rv = ipmi_sensor_pointer_cb(id, event_sensor_cb, &info);
	if (!rv)
	    rv = info.err;

	_ipmi_mc_put(mc);
    }

 out:
    /* It's an event from system software, or the info couldn't be found. */
    if (rv)
	ipmi_handle_unhandled_event(domain, event);
}

static void
ll_event_handler(ipmi_con_t        *ipmi,
		 const ipmi_addr_t *addr,
		 unsigned int      addr_len,
		 ipmi_event_t      *event,
		 void              *cb_data)
{
    ipmi_domain_t                *domain = cb_data;
    ipmi_mc_t                    *mc;
    int                          rv;
    ipmi_system_interface_addr_t si;

    rv = _ipmi_domain_get(domain);
    if (rv)
	return;

    /* Convert the address to the proper one if it comes from a
       specific connection. */
    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	int i;

	for (i=0; i<MAX_CONS; i++) {
	    if (domain->conn[i] == ipmi)
		break;
	}
	if (i == MAX_CONS)
	    goto out;
	addr = (ipmi_addr_t *) &si;
	si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si.channel = i;
	si.lun = 0;
	addr_len = sizeof(si);
    }

    /* It came from an MC, so find the MC. */
    mc = _ipmi_find_mc_by_addr(domain, addr, addr_len);
    if (!mc)
	goto out;
    ipmi_event_set_mcid(event, ipmi_mc_convert_to_id(mc));

    if (event == NULL) {
	/* The incoming event didn't carry the full event information.
	   Just scan for events in the MC's SEL. */
	ipmi_mc_reread_sel(mc, NULL, NULL);
    } else {
	/* Add it to the mc's event log. */
	rv = _ipmi_mc_sel_event_add(mc, event);

	if (rv != EEXIST)
	    /* Call the handler on it if it wasn't already in there. */
	    _ipmi_domain_system_event_handler(domain, mc, event);
    }
    _ipmi_mc_put(mc);

 out:
    _ipmi_domain_put(domain);
}

typedef struct call_event_handler_s
{
    ipmi_domain_t *domain;
    ipmi_event_t  *event;
} call_event_handler_t;

static int
call_event_handler(void *cb_data, void *item1, void *item2)
{
    call_event_handler_t  *info = cb_data;
    ipmi_event_handler_cb handler = item1;

    handler(info->domain, info->event, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_handle_unhandled_event(ipmi_domain_t *domain, ipmi_event_t *event)
{
    call_event_handler_t info;

    info.domain = domain;
    info.event = event;
    locked_list_iterate(domain->event_handlers, call_event_handler, &info);
}

int
ipmi_domain_add_event_handler(ipmi_domain_t           *domain,
			      ipmi_event_handler_cb   handler,
			      void                    *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    if (locked_list_add(domain->event_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_domain_remove_event_handler(ipmi_domain_t           *domain,
				 ipmi_event_handler_cb   handler,
				 void                    *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    if (locked_list_remove(domain->event_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

typedef struct event_handler_cl_info_s
{
    ipmi_event_handler_cb handler;
    void                  *handler_data;
} event_handler_cl_info_t;


static int
iterate_event_handler_cl(void *cb_data, void *item1, void *item2)
{
    event_handler_cl_info_t  *info = cb_data;
    ipmi_event_handler_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_event_handler_cl_handlers(ipmi_domain_t         *domain,
			       ipmi_event_handler_cb handler,
			       void                  *handler_data)
{
    event_handler_cl_info_t info;

    info.handler = handler;
    info.handler_data = handler_data;
    locked_list_iterate(domain->event_handlers_cl, iterate_event_handler_cl,
			&info);
}

int
ipmi_domain_add_event_handler_cl(ipmi_domain_t            *domain,
				 ipmi_event_handler_cl_cb handler,
				 void                     *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    if (locked_list_add(domain->event_handlers_cl, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_domain_remove_event_handler_cl(ipmi_domain_t            *domain,
				    ipmi_event_handler_cl_cb handler,
				    void                     *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    if (locked_list_remove(domain->event_handlers_cl, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_domain_disable_events(ipmi_domain_t *domain)
{
    int rv;
    int return_rv = 0;
    int i;

    CHECK_DOMAIN_LOCK(domain);

    for (i=0; i<MAX_CONS; i++) {
	rv = domain->conn[i]->remove_event_handler(domain->conn[i],
						   ll_event_handler,
						   domain);
	if (!return_rv)
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
	if (! domain->conn[i])
	    continue;

	rv = domain->conn[i]->add_event_handler(domain->conn[i],
						ll_event_handler,
						domain);
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

int
ipmi_domain_del_event(ipmi_domain_t  *domain,
		      ipmi_event_t   *event,
		      ipmi_domain_cb done_handler,
		      void           *cb_data)
{
    return ipmi_event_delete(event, done_handler, cb_data);
}

typedef struct next_event_handler_info_s
{
    ipmi_event_t       *rv;
    const ipmi_event_t *event;
    ipmi_mcid_t        event_mcid;
    int                found_curr_mc;
    int                do_prev; /* If going backwards, this will be 1. */
} next_event_handler_info_t;

static void
next_event_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    next_event_handler_info_t *info = cb_data;
    ipmi_mcid_t               mcid = ipmi_mc_convert_to_id(mc);

    if (info->rv)
	/* We've found an event already, just return. */
	return;

    if (info->do_prev) {
	if (info->found_curr_mc)
	    /* We've found the MC that had the event, but it didn't have
	       any more events.  Look for last events now. */
	    info->rv = ipmi_mc_last_event(mc);
	else if (ipmi_cmp_mc_id(info->event_mcid, mcid) == 0) {
	    info->found_curr_mc = 1;
	    info->rv = ipmi_mc_prev_event(mc, info->event);
	}
    } else {
	if (info->found_curr_mc)
	    /* We've found the MC that had the event, but it didn't have
	       any more events.  Look for first events now. */
	    info->rv = ipmi_mc_first_event(mc);
	else if (ipmi_cmp_mc_id(info->event_mcid, mcid) == 0) {
	    info->found_curr_mc = 1;
	    info->rv = ipmi_mc_next_event(mc, info->event);
	}
    }
}

ipmi_event_t *
ipmi_domain_first_event(ipmi_domain_t *domain)
{
    next_event_handler_info_t info;

    CHECK_DOMAIN_LOCK(domain);

    info.rv = NULL;
    info.event = NULL;
    info.found_curr_mc = 1;
    info.do_prev = 0;
    ipmi_domain_iterate_mcs(domain, next_event_handler, &info);

    return info.rv;
}

ipmi_event_t *
ipmi_domain_last_event(ipmi_domain_t *domain)
{
    next_event_handler_info_t info;

    CHECK_DOMAIN_LOCK(domain);

    info.rv = NULL;
    info.event = NULL;
    info.found_curr_mc = 1;
    info.do_prev = 1;
    ipmi_domain_iterate_mcs_rev(domain, next_event_handler, &info);

    return info.rv;
}

ipmi_event_t *
ipmi_domain_next_event(ipmi_domain_t *domain, const ipmi_event_t *event)
{
    next_event_handler_info_t info;

    CHECK_DOMAIN_LOCK(domain);

    info.rv = NULL;
    info.event = event;
    info.found_curr_mc = 0;
    info.do_prev = 0;
    info.event_mcid = ipmi_event_get_mcid(event);
    ipmi_domain_iterate_mcs(domain, next_event_handler, &info);

    return info.rv;
}

ipmi_event_t *
ipmi_domain_prev_event(ipmi_domain_t *domain, const ipmi_event_t *event)
{
    next_event_handler_info_t info;

    CHECK_DOMAIN_LOCK(domain);

    info.rv = NULL;
    info.event = event;
    info.found_curr_mc = 0;
    info.do_prev = 1;
    info.event_mcid = ipmi_event_get_mcid(event);
    ipmi_domain_iterate_mcs_rev(domain, next_event_handler, &info);

    return info.rv;
}

static void
sel_count_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    int *count = cb_data;

    *count += ipmi_mc_sel_count(mc);
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

    *count += ipmi_mc_sel_entries_used(mc);
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

/* Code to explicitly reread all the SELs in the domain. */
typedef struct sels_reread_s
{
    /* The number of pending requests. */
    int         count;

    /* The actual number of MCs we tried to request from .*/
    int         tried;

    /* This is the last error that occurred. */
    int         err;

    ipmi_domain_cb handler;
    void           *cb_data;

    /* We may have multiple threads going at the data from multiple
       SEL reads, so we need to protect the data. */
    ipmi_lock_t *lock;

    ipmi_domain_t *domain;
} sels_reread_t;

static void
reread_sel_handler(ipmi_mc_t *mc, int err, void *cb_data)
{
    sels_reread_t *info = cb_data;
    int           count;
    int           rv;

    ipmi_lock(info->lock);
    info->count--;
    count = info->count;
    if (err)
	info->err = err;
    ipmi_unlock(info->lock);
    if (count == 0) {
	/* We were the last one, call the main handler. */

	/* First validate the domain. */
	rv = _ipmi_domain_get(info->domain);
	if (rv)
	    info->domain = NULL;

	if (info->handler)
	    info->handler(info->domain, info->err, info->cb_data);
	ipmi_destroy_lock(info->lock);
	if (info->domain)
	    _ipmi_domain_put(info->domain);
	ipmi_mem_free(info);
    }
}

static void
reread_sels_handler(ipmi_domain_t *domain,
		    ipmi_mc_t     *mc,
		    void          *cb_data)
{
    sels_reread_t *info = cb_data;
    int           rv;

    if (ipmi_mc_sel_device_support(mc)) {
	info->tried++;
	rv = ipmi_mc_reread_sel(mc, reread_sel_handler, info);
	if (rv)
	    info->err = rv;
	else
	    info->count++;
    }
}

int
ipmi_domain_reread_sels(ipmi_domain_t  *domain,
			ipmi_domain_cb handler,
			void           *cb_data)
{
    sels_reread_t *info;
    int           rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    rv = ipmi_create_lock(domain, &info->lock);
    if (rv) {
	ipmi_mem_free(info);
	return rv;
    }
    info->count = 0;
    info->tried = 0;
    info->err = 0;
    info->domain = domain;
    info->handler = handler;
    info->cb_data = cb_data;
    ipmi_lock(info->lock);
    rv = ipmi_domain_iterate_mcs(domain, reread_sels_handler, info);
    if (rv) {
	ipmi_unlock(info->lock);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	return rv;
    }
    if ((info->tried > 0) && (info->count == 0)) {
	/* We tried to do an SEL fetch, but failed to actually
	   accomplish any.  Return an error. */
	rv = info->err;
	ipmi_unlock(info->lock);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	return rv;
    }

    if (info->count == 0) {
	/* No requests, so return an error. */
	ipmi_unlock(info->lock);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	return ENOSYS;
    }
    ipmi_unlock(info->lock);

    return 0;
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
    
    rv = ipmi_detect_ents_presence_changes(domain->entities, force);
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

void *
_ipmi_get_sdr_entities(ipmi_domain_t *domain,
		       ipmi_mc_t     *mc)
{
    if (mc) {
	return _ipmi_mc_get_sdr_entities(mc);
    } else {
	CHECK_DOMAIN_LOCK(domain);
	return domain->entities_in_main_sdr;
    }
}

void
_ipmi_set_sdr_entities(ipmi_domain_t *domain,
		       ipmi_mc_t     *mc,
		       void          *entities)
{
    if (mc) {
	_ipmi_mc_set_sdr_entities(mc, entities);
    } else {
	CHECK_DOMAIN_LOCK(domain);
	domain->entities_in_main_sdr = entities;
    }
}

int
ipmi_domain_add_entity_update_handler(ipmi_domain_t         *domain,
				      ipmi_domain_entity_cb handler,
				      void                  *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    return ipmi_entity_info_add_update_handler(domain->entities,
					       handler,
					       cb_data);
}

int
ipmi_domain_remove_entity_update_handler(ipmi_domain_t         *domain,
					 ipmi_domain_entity_cb handler,
					 void                  *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    return ipmi_entity_info_remove_update_handler(domain->entities,
						  handler,
						  cb_data);
}

int
ipmi_domain_add_entity_update_handler_cl(ipmi_domain_t            *domain,
					 ipmi_domain_entity_cl_cb handler,
					 void                     *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    return ipmi_entity_info_add_update_handler_cl(domain->entities,
						  handler,
						  cb_data);
}

int
ipmi_domain_remove_entity_update_handler_cl(ipmi_domain_t            *domain,
					    ipmi_domain_entity_cl_cb handler,
					    void                     *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    return ipmi_entity_info_remove_update_handler_cl(domain->entities,
						     handler,
						     cb_data);
}

int
ipmi_domain_iterate_entities(ipmi_domain_t      *domain,
			     ipmi_entity_ptr_cb handler,
			     void               *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    ipmi_entities_iterate_entities(domain->entities, handler, cb_data);
    return 0;
}

int
ipmi_domain_iterate_mcs(ipmi_domain_t              *domain,
			ipmi_domain_iterate_mcs_cb handler,
			void                       *cb_data)
{
    int i, j;

    CHECK_DOMAIN_LOCK(domain);

    ipmi_lock(domain->mc_lock);
    for (i=0; i<MAX_CONS; i++) {
	ipmi_mc_t *mc = domain->sys_intf_mcs[i];
	if (mc && !_ipmi_mc_get(mc)) {
	    ipmi_unlock(domain->mc_lock);
	    handler(domain, mc, cb_data);
	    _ipmi_mc_put(mc);
	    ipmi_lock(domain->mc_lock);
	}
    }
    for (i=0; i<IPMB_HASH; i++) {
	mc_table_t *tab = &(domain->ipmb_mcs[i]);

	for (j=0; j<tab->size; j++) {
	    ipmi_mc_t *mc = tab->mcs[j];
	    if (mc && !_ipmi_mc_get(mc)) {
		ipmi_unlock(domain->mc_lock);
		handler(domain, mc, cb_data);
		_ipmi_mc_put(mc);
		ipmi_lock(domain->mc_lock);
	    }
	}
    }
    ipmi_unlock(domain->mc_lock);
    return 0;
}

int
ipmi_domain_iterate_mcs_rev(ipmi_domain_t              *domain,
			    ipmi_domain_iterate_mcs_cb handler,
			    void                       *cb_data)
{
    int i, j;

    CHECK_DOMAIN_LOCK(domain);

    ipmi_lock(domain->mc_lock);
    for (i=IPMB_HASH-1; i>=0; i--) {
	mc_table_t *tab = &(domain->ipmb_mcs[i]);

	for (j=tab->size-1; j>=0; j--) {
	    ipmi_mc_t *mc = tab->mcs[j];
	    if (mc && !_ipmi_mc_get(mc)) {
		ipmi_unlock(domain->mc_lock);
		handler(domain, mc, cb_data);
		_ipmi_mc_put(mc);
		ipmi_lock(domain->mc_lock);
	    }
	}
    }
    for (i=MAX_CONS-1; i>=0; i--) {
	ipmi_mc_t *mc = domain->sys_intf_mcs[i];
	if (mc && !_ipmi_mc_get(mc)) {
	    ipmi_unlock(domain->mc_lock);
	    handler(domain, mc, cb_data);
	    _ipmi_mc_put(mc);
	    ipmi_lock(domain->mc_lock);
	}
    }
    ipmi_unlock(domain->mc_lock);
    return 0;
}

#if SAVE_SDR_CODE_ENABLE
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
#endif

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

    rv = _ipmi_domain_get(domain);
    if (!rv) {
	handler(domain, cb_data);
	_ipmi_domain_put(domain);
    }

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

void
ipmi_domain_id_set_invalid(ipmi_domain_id_t *id)
{
    id->domain = NULL;
}

int
ipmi_domain_id_is_invalid(const ipmi_domain_id_t *id)
{
    return (id->domain == NULL);
}

/***********************************************************************
 *
 * Handle global OEM callbacks for new domain MCs.
 *
 **********************************************************************/

typedef struct mc_oem_handlers_s {
    unsigned int                 manufacturer_id;
    unsigned int                 first_product_id;
    unsigned int                 last_product_id;
    ipmi_oem_domain_match_handler_cb handler;
    ipmi_oem_domain_shutdown_handler_cb shutdown;
    void                         *cb_data;
} mc_oem_handlers_t;

static locked_list_t *mc_oem_handlers;

int
ipmi_domain_register_oem_handler(unsigned int                 manufacturer_id,
				 unsigned int                 product_id,
				 ipmi_oem_domain_match_handler_cb handler,
				 ipmi_oem_domain_shutdown_handler_cb shutdown,
				 void                         *cb_data)
{
    mc_oem_handlers_t *new_item;
    int               rv;

    /* This might be called before initialization, so be 100% sure. */
    rv = _ipmi_domain_init();
    if (rv)
	return rv;

    new_item = ipmi_mem_alloc(sizeof(*new_item));
    if (!new_item)
	return ENOMEM;

    new_item->manufacturer_id = manufacturer_id;
    new_item->first_product_id = product_id;
    new_item->last_product_id = product_id;
    new_item->handler = handler;
    new_item->shutdown = shutdown;
    new_item->cb_data = cb_data;

    if (! locked_list_add(mc_oem_handlers, new_item, NULL)) {
	ipmi_mem_free(new_item);
	return ENOMEM;
    }

    return 0;
}

int
ipmi_domain_register_oem_handler_range(unsigned int           manufacturer_id,
				       unsigned int           first_product_id,
				       unsigned int           last_product_id,
				       ipmi_oem_domain_match_handler_cb handler,
				       ipmi_oem_domain_shutdown_handler_cb shutdown,
				       void                         *cb_data)
{
    mc_oem_handlers_t *new_item;
    int               rv;

    /* This might be called before initialization, so be 100% sure. */
    rv = _ipmi_mc_init();
    if (rv)
	return rv;

    new_item = ipmi_mem_alloc(sizeof(*new_item));
    if (!new_item)
	return ENOMEM;

    new_item->manufacturer_id = manufacturer_id;
    new_item->first_product_id = first_product_id;
    new_item->last_product_id = last_product_id;
    new_item->handler = handler;
    new_item->shutdown = shutdown;
    new_item->cb_data = cb_data;

    if (! locked_list_add(mc_oem_handlers, new_item, NULL)) {
	ipmi_mem_free(new_item);
	return ENOMEM;
    }

    return 0;
}

typedef struct handler_cmp_s
{
    int           rv;
    unsigned int  manufacturer_id;
    unsigned int  first_product_id;
    unsigned int  last_product_id;
    ipmi_domain_t *domain;
} handler_cmp_t;

static int
mc_oem_handler_cmp_dereg(void *cb_data, void *item1, void *item2)
{
    mc_oem_handlers_t *hndlr = item1;
    handler_cmp_t     *cmp = cb_data;

    if ((hndlr->manufacturer_id == cmp->manufacturer_id)
	&& (hndlr->first_product_id <= cmp->first_product_id)
	&& (hndlr->last_product_id >= cmp->last_product_id))
    {
	cmp->rv = 0;
	locked_list_remove(mc_oem_handlers, item1, item2);
	ipmi_mem_free(hndlr);
	return LOCKED_LIST_ITER_STOP;
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

int
ipmi_domain_deregister_oem_handler(unsigned int manufacturer_id,
				   unsigned int product_id)
{
    handler_cmp_t  tmp;

    tmp.rv = ENOENT;
    tmp.manufacturer_id = manufacturer_id;
    tmp.first_product_id = product_id;
    tmp.last_product_id = product_id;
    locked_list_iterate(mc_oem_handlers, mc_oem_handler_cmp_dereg, &tmp);
    return tmp.rv;
}

int
ipmi_domain_deregister_oem_handler_range(unsigned int manufacturer_id,
					 unsigned int first_product_id,
					 unsigned int last_product_id)
{
    handler_cmp_t  tmp;

    tmp.rv = ENOENT;
    tmp.manufacturer_id = manufacturer_id;
    tmp.first_product_id = first_product_id;
    tmp.last_product_id = last_product_id;
    locked_list_iterate(mc_oem_handlers, mc_oem_handler_cmp_dereg, &tmp);
    return tmp.rv;
}

static int
mc_oem_handler_call(void *cb_data, void *item1, void *item2)
{
    mc_oem_handlers_t *hndlr = item1;
    handler_cmp_t     *cmp = cb_data;

    if ((hndlr->manufacturer_id == cmp->manufacturer_id)
	&& (hndlr->first_product_id <= cmp->first_product_id)
	&& (hndlr->last_product_id >= cmp->last_product_id))
    {
	cmp->rv = hndlr->handler(cmp->domain, hndlr->cb_data);
	return LOCKED_LIST_ITER_STOP;
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
check_mc_oem_handlers(ipmi_domain_t *domain)
{
    handler_cmp_t  tmp;

    tmp.rv = 0;
    tmp.manufacturer_id = ipmi_mc_manufacturer_id(domain->si_mc);
    tmp.first_product_id = ipmi_mc_product_id(domain->si_mc);
    tmp.last_product_id = tmp.first_product_id;
    tmp.domain = domain;
    locked_list_iterate(mc_oem_handlers, mc_oem_handler_call, &tmp);
    return tmp.rv;
}

int
ipmi_domain_set_sdrs_fixup_handler(ipmi_domain_t                 *domain,
				   ipmi_domain_oem_fixup_sdrs_cb handler,
				   void                          *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);
    domain->fixup_sdrs_handler = handler;
    domain->fixup_sdrs_cb_data = cb_data;
    return 0;
}


/***********************************************************************
 *
 * Connection setup and handling
 *
 **********************************************************************/

int
ipmi_domain_set_main_SDRs_read_handler(ipmi_domain_t  *domain,
				       ipmi_domain_cb handler,
				       void           *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    ipmi_lock(domain->domain_lock);
    domain->SDRs_read_handler = handler;
    domain->SDRs_read_handler_cb_data = cb_data;
    ipmi_unlock(domain->domain_lock);
    return 0;
}

int
ipmi_domain_set_con_up_handler(ipmi_domain_t      *domain,
			       ipmi_domain_ptr_cb handler,
			       void               *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    ipmi_lock(domain->domain_lock);
    domain->con_up_handler = handler;
    domain->con_up_handler_cb_data = cb_data;
    ipmi_unlock(domain->domain_lock);
    return 0;
}

int
ipmi_domain_set_bus_scan_handler(ipmi_domain_t  *domain,
				 ipmi_domain_cb handler,
				 void           *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    ipmi_lock(domain->mc_lock);
    domain->bus_scan_handler = handler;
    domain->bus_scan_handler_cb_data = cb_data;
    ipmi_unlock(domain->mc_lock);
    return 0;
}

static void
conn_close(ipmi_con_t *ipmi, void *cb_data)
{
    ipmi_domain_close_done_cb close_done;
    void                      *my_cb_data;
    ipmi_domain_t             *domain = cb_data;
    int                       done = 0;

    ipmi_lock(domain->domain_lock);
    domain->close_count--;
    done = domain->close_count <= 0;
    ipmi_unlock(domain->domain_lock);

    if (!done)
	return;

    remove_known_domain(domain);

    close_done = domain->close_done;
    my_cb_data = domain->close_done_cb_data;

    cleanup_domain(domain);

    if (close_done)
	close_done(my_cb_data);
}

static void
real_close_connection(ipmi_domain_t *domain)
{
    ipmi_con_t                *ipmi[MAX_CONS];
    int                       i;

    for (i=0; i<MAX_CONS; i++) {
	ipmi[i] = domain->conn[i];

	if (!ipmi[i])
	    continue;

	/* Remove all the handlers. */
	domain->conn[i]->remove_event_handler(domain->conn[i],
					      ll_event_handler,
					      domain);
	domain->conn[i]->remove_con_change_handler(domain->conn[i],
						   ll_con_changed,
						   domain);
	domain->conn[i]->remove_ipmb_addr_handler(domain->conn[i],
						  ll_addr_changed,
						  domain);
	domain->conn[i] = NULL;
    }

    /* No lock needed here, this is single threaded until we start
       actually closing the connections. */
    domain->close_count = 0;
    for (i=0; i<MAX_CONS; i++) {
	if (ipmi[i])
	    domain->close_count++;
    }
    for (i=0; i<MAX_CONS; i++) {
	if (ipmi[i]) {
	    if (ipmi[i]->register_stat_handler)
		ipmi[i]->unregister_stat_handler(ipmi[i],
						 domain->con_stat_info);
	    ipmi[i]->close_connection_done(ipmi[i], conn_close, domain);
	}
    }
}

int
ipmi_domain_close(ipmi_domain_t             *domain,
		  ipmi_domain_close_done_cb close_done,
		  void                      *cb_data)
{
    CHECK_DOMAIN_LOCK(domain);

    if (domain->in_shutdown)
	return EINVAL;

    domain->in_shutdown = 1;
    domain->close_done = close_done;
    domain->close_done_cb_data = cb_data;

    locked_list_remove(domains_list, domain, NULL);

    /* We don't actually do the destroy here, since the domain should
       be in use.  We wait until the usecount goes to zero. */

    return 0;
}

int
ipmi_domain_add_connect_change_handler(ipmi_domain_t      *domain,
				       ipmi_domain_con_cb handler,
				       void               *cb_data)
{
    if (locked_list_add(domain->con_change_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_domain_remove_connect_change_handler(ipmi_domain_t      *domain,
					  ipmi_domain_con_cb handler,
					  void               *cb_data)
{
    if (locked_list_remove(domain->con_change_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

typedef struct con_change_cl_info_s
{
    ipmi_domain_con_cb handler;
    void               *handler_data;
} con_change_cl_info_t;

static int
iterate_con_change_cl(void *cb_data, void *item1, void *item2)
{
    con_change_cl_info_t  *info = cb_data;
    ipmi_domain_con_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_con_change_cl_handlers(ipmi_domain_t      *domain,
			    ipmi_domain_con_cb handler,
			    void               *handler_data)
{
    con_change_cl_info_t info;

    info.handler = handler;
    info.handler_data = handler_data;
    locked_list_iterate(domain->con_change_cl_handlers, iterate_con_change_cl,
			&info);
}

int
ipmi_domain_add_connect_change_handler_cl(ipmi_domain_t         *domain,
					  ipmi_domain_con_cl_cb handler,
					  void                  *cb_data)
{
    if (locked_list_add(domain->con_change_cl_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_domain_remove_connect_change_handler_cl(ipmi_domain_t         *domain,
					     ipmi_domain_con_cl_cb handler,
					     void                  *cb_data)
{
    if (locked_list_remove(domain->con_change_cl_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

typedef struct con_change_info_s
{
    ipmi_domain_t *domain;
    int           err;
    unsigned int  conn_num;
    unsigned int  port_num;
    int           still_connected;
} con_change_info_t;

static int
iterate_con_changes(void *cb_data, void *item1, void *item2)
{
    con_change_info_t  *info = cb_data;
    ipmi_domain_con_cb handler = item1;

    handler(info->domain, info->err, info->conn_num, info->port_num,
	    info->still_connected, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_con_change(ipmi_domain_t *domain,
		int           err,
		unsigned int  conn_num,
		unsigned int  port_num,
		int           still_connected)
{
    con_change_info_t info = {domain, err, conn_num, port_num,
			      still_connected};
    locked_list_iterate(domain->con_change_handlers, iterate_con_changes,
			&info);
}

static void
call_con_fails(ipmi_domain_t *domain,
	       int           err,
	       unsigned int  conn_num,
	       unsigned int  port_num,
	       int           still_connected)
{
    ipmi_lock(domain->con_lock);
    domain->connecting = 0;
    if (err) {
	/* Nothing really to do, can't start anything up, just report it. */
	ipmi_unlock(domain->con_lock);
    } else if (domain->in_startup) {
	domain->in_startup = 0;
	ipmi_unlock(domain->con_lock);
    } else
	ipmi_unlock(domain->con_lock);

    call_con_change(domain, err, conn_num, port_num, still_connected);
}

static void	
con_up_complete(ipmi_domain_t *domain)
{
    int                i, j;
    ipmi_domain_ptr_cb con_up_handler;
    void               *con_up_handler_cb_data;
    ipmi_domain_cb     SDRs_read_handler;
    void               *SDRs_read_handler_cb_data;

    if (domain->in_shutdown)
	return;

    /* This is an unusual looking piece of code, but is required for
       systems that do not implement the get channel command.  For
       those, it is required that channel 0 be an IPMB channel.
       Basically, if all of the channel info commands failed, set
       channel 0 to IPMB. */
    for (i=0; i<MAX_IPMI_USED_CHANNELS; i++) {
	if (domain->chan_set[i])
	    break;
    }
    if (i == MAX_IPMI_USED_CHANNELS) {
	domain->chan[0].medium = IPMI_CHANNEL_MEDIUM_IPMB;
	domain->chan[0].xmit_support = 1;
	domain->chan[0].recv_lun = 0;
	domain->chan[0].protocol = IPMI_CHANNEL_PROTOCOL_IPMB;
	domain->chan[0].session_support = IPMI_CHANNEL_SESSION_LESS;
	domain->chan[0].vendor_id = IPMI_ENTERPRISE_NUMBER;
	domain->chan[0].aux_info = 0;
    }

    domain->connection_up = 1;

    if (domain->working_conn != -1)
	domain->con_up[domain->working_conn] = 1;

    for (i=0; i<MAX_CONS; i++) {
	for (j=0; j<MAX_PORTS_PER_CON; j++) {
	    if (domain->port_up[j][i] == 1)
		call_con_fails(domain, 0, i, j, 1);
	}
    }

    ipmi_lock(domain->domain_lock);
    con_up_handler = domain->con_up_handler;
    con_up_handler_cb_data = domain->con_up_handler_cb_data;
    ipmi_unlock(domain->domain_lock);
    if (con_up_handler)
	con_up_handler(domain, con_up_handler_cb_data);

    ipmi_domain_start_full_ipmb_scan(domain);

    ipmi_detect_ents_presence_changes(domain->entities, 1);

    ipmi_entity_scan_sdrs(domain, NULL, domain->entities, domain->main_sdrs);
    ipmi_sensor_handle_sdrs(domain, NULL, domain->main_sdrs);
    ipmi_lock(domain->domain_lock);
    SDRs_read_handler = domain->SDRs_read_handler;
    SDRs_read_handler_cb_data = domain->SDRs_read_handler_cb_data;
    ipmi_unlock(domain->domain_lock);
    if (SDRs_read_handler)
	SDRs_read_handler(domain, 0, SDRs_read_handler_cb_data);
    _ipmi_put_domain_fully_up(domain, "con_up_complete");
}

static void
chan_info_rsp_handler(ipmi_mc_t  *mc,
		      ipmi_msg_t *rsp,
		      void       *rsp_data)
{
    int           rv = 0;
    long          curr = (long) rsp_data;
    ipmi_domain_t *domain;

    if (!mc)
	return;

    domain = ipmi_mc_get_domain(mc);

    if (rsp->data[0] != 0) {
	rv = IPMI_IPMI_ERR_VAL(rsp->data[0]);
    } else if (rsp->data_len < 8) {
	rv = EINVAL;
    }

    if (rv) {
	/* Got an error, invalidate the channel.  IPMI requires that
	   1.5 systems implement this command if they have
	   channels. */
	memset(&domain->chan[curr], 0, sizeof(domain->chan[curr]));
	/* Keep going, there may be more channels. */
    } else {
	domain->chan_set[curr] = 1;

        /* Get the info from the channel info response. */
        domain->chan[curr].medium = rsp->data[2] & 0x7f;
	domain->chan[curr].xmit_support = rsp->data[2] >> 7;
	domain->chan[curr].recv_lun = (rsp->data[2] >> 4) & 0x7;
	domain->chan[curr].protocol = rsp->data[3] & 0x1f;
	domain->chan[curr].session_support = rsp->data[4] >> 6;
	domain->chan[curr].vendor_id = (rsp->data[5]
					| (rsp->data[6] << 8)
					| (rsp->data[7] << 16));
	domain->chan[curr].aux_info = rsp->data[8] | (rsp->data[9] << 8);
    }

    curr++;
    if (curr < MAX_IPMI_USED_CHANNELS) {
	ipmi_msg_t    cmd_msg;
	unsigned char cmd_data[1];

	cmd_msg.netfn = IPMI_APP_NETFN;
	cmd_msg.cmd = IPMI_GET_CHANNEL_INFO_CMD;
	cmd_msg.data = cmd_data;
	cmd_msg.data_len = 1;
	cmd_data[0] = curr;

	rv = ipmi_mc_send_command(mc, 0, &cmd_msg, chan_info_rsp_handler,
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

    if (domain->in_shutdown)
	return ECANCELED;

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

	_ipmi_mc_get(domain->si_mc);
	rv = ipmi_mc_send_command(domain->si_mc, 0, &cmd_msg,
				  chan_info_rsp_handler, (void *) 0);
	_ipmi_mc_put(domain->si_mc);
    } else {
	ipmi_sdr_t sdr;

	/* Get the channel info record. */
	rv = ipmi_get_sdr_by_type(domain->main_sdrs, 0x14, &sdr);
	if (rv) {
	    domain->chan_set[0] = 1;

	    /* Add a dummy channel zero and finish. */
	    domain->chan[0].medium = IPMI_CHANNEL_MEDIUM_IPMB;
	    domain->chan[0].xmit_support = 1;
	    domain->chan[0].recv_lun = 0;
	    domain->chan[0].protocol = IPMI_CHANNEL_PROTOCOL_IPMB;
	    domain->chan[0].session_support = IPMI_CHANNEL_SESSION_LESS;
	    domain->chan[0].vendor_id = IPMI_ENTERPRISE_NUMBER;
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
		    domain->chan_set[i] = 1;

		    domain->chan[i].medium = IPMI_CHANNEL_MEDIUM_IPMB;
		    domain->chan[i].xmit_support = 1;
		    domain->chan[i].recv_lun = 0;
		    domain->chan[i].protocol = protocol;
		    domain->chan[i].session_support= IPMI_CHANNEL_SESSION_LESS;
		    domain->chan[i].vendor_id = IPMI_ENTERPRISE_NUMBER;
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
	ipmi_log(IPMI_LOG_WARNING,
		 "%sdomain.c(sdr_handler): "
		 "Could not get main SDRs, error 0x%x",
		 DOMAIN_NAME(domain), err);
    }

    if (domain->fixup_sdrs_handler)
	domain->fixup_sdrs_handler(domain, domain->main_sdrs,
				   domain->fixup_sdrs_cb_data);

    rv = get_channels(domain);
    if (rv)
	call_con_fails(domain, rv, 0, 0, 0);
}

static void
got_guid(ipmi_mc_t  *mc,
	 ipmi_msg_t *rsp,
	 void       *rsp_data)
{
    ipmi_domain_t *domain = rsp_data;
    int           rv;

    if (!mc)
	return; /* domain went away while processing. */

    if ((rsp->data[0] == 0) && (rsp->data_len >= 17)) {
	/* We have a GUID, save it */
	ipmi_mc_set_guid(mc, rsp->data+1);
    }

    if (domain->SDR_repository_support && ipmi_option_SDRs(domain)) {
	rv = ipmi_sdr_fetch(domain->main_sdrs, sdr_handler, domain);
    } else {
	rv = get_channels(domain);
    }
    if (rv)
	call_con_fails(domain, rv, 0, 0, 0);
}

static void
domain_oem_handlers_checked(ipmi_domain_t *domain, int err, void *cb_data)
{
    ipmi_msg_t msg;
    int        rv;

    /* FIXME - handle errors setting up OEM comain information. */

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_SYSTEM_GUID_CMD;
    msg.data_len = 0;
    msg.data = NULL;

    _ipmi_mc_get(domain->si_mc);
    rv = ipmi_mc_send_command(domain->si_mc, 0, &msg, got_guid, domain);
    _ipmi_mc_put(domain->si_mc);
    if (rv)
	call_con_fails(domain, rv, 0, 0, 0);
}

static void
got_dev_id(ipmi_mc_t  *mc,
	   ipmi_msg_t *rsp,
	   void       *rsp_data)
{
    ipmi_domain_t *domain = rsp_data;
    int           rv;

    if (!mc)
	return; /* domain went away while processing. */

    rv = _ipmi_mc_get_device_id_data_from_rsp(mc, rsp);
    if (rv) {
	/* At least the get device id has to work. */
	if ((rsp->data[0] == 0) && (rsp->data_len >= 6)) {
	    int major_version = rsp->data[5] & 0xf;
	    int minor_version = (rsp->data[5] >> 4) & 0xf;

	    if (major_version < 1) {
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "%sdomain.c(got_dev_id): "
			 "IPMI version of the BMC is %d.%d, which is older"
			 " than OpenIPMI supports",
			 DOMAIN_NAME(domain), major_version, minor_version);
		domain->got_invalid_dev_id = 1;
		call_con_fails(domain, ENOSYS, 0, 0, 0);
		return;
	    }
	}
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sdomain.c(got_dev_id): "
		 "Invalid return from IPMI Get Device ID, something is"
		 " seriously wrong with the BMC",
		 DOMAIN_NAME(domain));
	domain->got_invalid_dev_id = 1;
	call_con_fails(domain, rv, 0, 0, 0);
	return;
    }

    domain->got_invalid_dev_id = 0;

    /* Get the information from the MC, not the message, since it may have
       been fixed up. */
    domain->major_version = ipmi_mc_major_version(mc);
    domain->minor_version = ipmi_mc_minor_version(mc);
    domain->SDR_repository_support = ipmi_mc_sdr_repository_support(mc);

    if (((domain->major_version < 1) || (domain->major_version > 2))
	|| ((domain->major_version == 1)
	    && (domain->minor_version != 5)
	    && (domain->minor_version != 0))
	|| ((domain->major_version == 2)
	    && (domain->minor_version != 0)))
    {
	ipmi_log(IPMI_LOG_WARNING,
		 "%sdomain.c(got_dev_id): "
		 "IPMI version of the BMC is %d.%d, which is not directly"
		 " supported by OpenIPMI.  It may work, but there may be"
		 " issues.",
		 DOMAIN_NAME(domain),
		 domain->major_version, domain->minor_version);
    }

    if (domain->major_version < 1) {
	/* We only support 1.0 and greater. */
	domain->got_invalid_dev_id = 0;
	call_con_fails(domain, EINVAL, 0, 0, 0);
	return;
    }

    if (ipmi_option_OEM_init(domain)) {
	rv = check_oem_handlers(domain, domain_oem_handlers_checked, NULL);
	if (rv)
	    call_con_fails(domain, rv, 0, 0, 0);
	rv = check_mc_oem_handlers(domain);
	if (rv)
	    call_con_fails(domain, rv, 0, 0, 0);
    } else {
	domain_oem_handlers_checked(domain, 0, NULL);
    }
}

static int
domain_send_mc_id(ipmi_domain_t *domain)
{
    ipmi_msg_t msg;
    int        rv;

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_DEVICE_ID_CMD;
    msg.data_len = 0;
    msg.data = NULL;

    _ipmi_mc_get(domain->si_mc);
    rv = ipmi_mc_send_command(domain->si_mc, 0, &msg, got_dev_id, domain);
    _ipmi_mc_put(domain->si_mc);

    return rv;
}

static int
start_con_up(ipmi_domain_t *domain)
{
    ipmi_lock(domain->con_lock);
    if (domain->connecting || domain->connection_up) {
	ipmi_unlock(domain->con_lock);
	return 0;
    }
    domain->connecting = 1;
    ipmi_unlock(domain->con_lock);

    return domain_send_mc_id(domain);
}

static void start_activate_timer(ipmi_domain_t *domain);

static void
initial_ipmb_addr_cb(ipmi_con_t    *ipmi,
		     int           err,
		     const unsigned char ipmb_addr[],
		     unsigned int  num_ipmb_addr,
		     int           active,
		     unsigned int  hacks,
		     void          *cb_data)
{
    ipmi_domain_t *domain = cb_data;
    int           u;
    int           rv;

    rv = _ipmi_domain_get(domain);
    if (rv)
	/* So the connection failed.  So what, there's nothing to talk to. */
	return;

    u = get_con_num(domain, ipmi);
    if (u == -1)
	goto out_unlock;

    if (err) {
	call_con_fails(domain, err, u, 0, domain->connection_up);
	goto out_unlock;
    }

    /* If we are not activating connections, just use whatever we get
       and don't worry if it is active or not. */
    if (! domain->option_activate_if_possible)
	active = 1;

    if (active) {
        domain->working_conn = u;
	rv = start_con_up(domain);
	if (rv)
	    call_con_fails(domain, rv, u, 0, domain->connection_up);
    } else {
	/* Start the timer to activate the connection, if necessary. */
	start_activate_timer(domain);
    }

 out_unlock:
    _ipmi_domain_put(domain);
}

static void
activate_timer_cb(void *cb_data, os_hnd_timer_id_t *id)
{
    activate_timer_info_t *info = cb_data;
    ipmi_domain_t         *domain = info->domain;
    int                   to_activate;
    int                   u;
    int                   rv;

    ipmi_lock(info->lock);
    if (info->cancelled) {
	info->os_hnd->free_timer(info->os_hnd, id);
	ipmi_unlock(info->lock);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	return;
    }
    info->running = 0;

    rv = _ipmi_domain_get(domain);
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
	&& domain->option_activate_if_possible
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

    _ipmi_domain_put(domain);

 out_unlock:
    ipmi_unlock(info->lock);
}

int
ipmi_domain_activate_connection(ipmi_domain_t *domain, unsigned int connection)
{
    CHECK_DOMAIN_LOCK(domain);

    if ((connection >= MAX_CONS) || !domain->conn[connection])
	return EINVAL;

    if (!domain->conn[connection]->set_active_state
	|| !domain->option_activate_if_possible)
	return ENOSYS;

    domain->conn[connection]->set_active_state(domain->conn[connection], 1, 
					       ll_addr_changed, domain);

    /* The other connections will be deactivated when this one
       activates, if that is required. */
    return 0;
}

int
ipmi_domain_is_connection_active(ipmi_domain_t *domain,
				 unsigned int  connection,
				 unsigned int  *active)
{
    CHECK_DOMAIN_LOCK(domain);

    if ((connection >= MAX_CONS) || !domain->conn[connection])
	return EINVAL;

    *active = domain->con_active[connection];
    return 0;
}

int
ipmi_domain_is_connection_up(ipmi_domain_t *domain,
			     unsigned int  connection,
			     unsigned int  *up)
{
    int          port;
    unsigned int val;

    CHECK_DOMAIN_LOCK(domain);

    if ((connection >= MAX_CONS) || !domain->conn[connection])
	return EINVAL;

    val = 0;
    for (port=0; port<MAX_PORTS_PER_CON; port++) {
	if (domain->port_up[port][connection] == 1)
	    val = 1;
    }

    *up = val;
    return 0;
}

int
ipmi_domain_num_connection_ports(ipmi_domain_t *domain,
				 unsigned int  connection,
				 unsigned int  *ports)
{
    int          port;
    unsigned int val = 0;

    CHECK_DOMAIN_LOCK(domain);

    if ((connection >= MAX_CONS) || !domain->conn[connection])
	return EINVAL;

    for (port=0; port<MAX_PORTS_PER_CON; port++) {
	if (domain->port_up[port][connection] != -1)
	    val = port+1;
    }

    *ports = val;
    return 0;
}

int
ipmi_domain_is_connection_port_up(ipmi_domain_t *domain,
				  unsigned int  connection,
				  unsigned int  port,
				  unsigned int  *up)
{
    CHECK_DOMAIN_LOCK(domain);

    if ((connection >= MAX_CONS) || !domain->conn[connection])
	return EINVAL;

    if (port >= MAX_PORTS_PER_CON)
	return EINVAL;

    if (domain->port_up[port][connection] == -1)
	return ENOSYS;

    *up = domain->port_up[port][connection];

    return 0;
}

int
ipmi_domain_get_port_info(ipmi_domain_t *domain,
			  unsigned int  connection,
			  unsigned int  port,
			  char          *info,
			  int           *info_len)
{
    CHECK_DOMAIN_LOCK(domain);

    if ((connection >= MAX_CONS) || !domain->conn[connection])
	return EINVAL;

    if (port >= MAX_PORTS_PER_CON)
	return EINVAL;

    if (!domain->conn[connection]->get_port_info)
	return ENOSYS;

    return domain->conn[connection]->get_port_info(domain->conn[connection],
						   port, info, info_len);
}

int
_ipmi_domain_get_connection(ipmi_domain_t *domain,
			    int           con_num,
			    ipmi_con_t    **con)
{
    if (con_num >= MAX_CONS)
	return EINVAL;
    *con = domain->conn[con_num];
    return 0;
}

void
ipmi_domain_iterate_connections(ipmi_domain_t          *domain,
				ipmi_connection_ptr_cb handler,
				void                   *cb_data)
{
    int i;

    CHECK_DOMAIN_LOCK(domain);

    for (i=0; i<MAX_CONS; i++) {
	if (domain->conn[i])
	    handler(domain, i, cb_data);
    }
}

ipmi_args_t *
ipmi_domain_get_connection_args(ipmi_domain_t *domain,
				unsigned int  con)
{
    CHECK_DOMAIN_LOCK(domain);

    if (con >= MAX_CONS)
	return NULL;

    if (!domain->conn[con])
	return NULL;

    if (! domain->conn[con]->get_startup_args)
	return NULL;

    return domain->conn[con]->get_startup_args(domain->conn[con]);
}

char *
ipmi_domain_get_connection_type(ipmi_domain_t *domain,
				unsigned int  connection)
{
    CHECK_DOMAIN_LOCK(domain);

    if (connection >= MAX_CONS)
	return NULL;

    if (!domain->conn[connection])
	return NULL;

    return domain->conn[connection]->con_type;
}

ipmi_con_t *
ipmi_domain_get_connection(ipmi_domain_t *domain,
			   unsigned int  connection)
{
    CHECK_DOMAIN_LOCK(domain);

    if (connection >= MAX_CONS)
	return NULL;

    if (!domain->conn[connection])
	return NULL;

    if (! domain->conn[connection]->use_connection)
	return NULL;

    domain->conn[connection]->use_connection(domain->conn[connection]);
    return domain->conn[connection];
}

/* If the activate timer is not running, then start it.  This
   allows some time for other connections to become active before
   we go off and start activating things.  We wait a random amount
   of time so that if we get into a war with another program about
   who is active, someone will eventually win. */
static void
start_activate_timer(ipmi_domain_t *domain)
{
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
}

static void
ll_addr_changed(ipmi_con_t    *ipmi,
		int           err,
		const unsigned char ipmb_addr[],
		unsigned int  num_ipmb_addr,
		int           active,
		unsigned int  hacks,
		void          *cb_data)
{
    ipmi_domain_t *domain = cb_data;
    int           rv;
    int           u;
    int           start_connection;
    unsigned char old_addr[MAX_IPMI_USED_CHANNELS];
    unsigned int  i;

    rv = _ipmi_domain_get(domain);
    if (rv)
	/* So the connection failed.  So what, there's nothing to talk to. */
	return;

    if (err)
	goto out_unlock;

    u = get_con_num(domain, ipmi);
    if (u == -1)
	goto out_unlock;

    memcpy(old_addr, domain->con_ipmb_addr[u], sizeof(old_addr));

    for (i=0; i<num_ipmb_addr && i<MAX_IPMI_USED_CHANNELS; i++) {
	if (! ipmb_addr[i])
	    continue;
	domain->con_ipmb_addr[u][i] = ipmb_addr[i];
    }

    if (!domain->in_startup) {
	/* Only scan the IPMBs if we are not in startup.  Otherwise things
	   get reported before we are ready. */
	for (i=0; i<num_ipmb_addr && i<MAX_IPMI_USED_CHANNELS; i++) {
	    if (! ipmb_addr[i])
		continue;
	    if (ipmb_addr[i] != old_addr[i]) {
		/* First scan the old address to remove it. */
		if (domain->con_ipmb_addr[u] != 0)
		    ipmi_start_ipmb_mc_scan(domain, i,
					    old_addr[i], old_addr[i],
					    NULL, NULL);
	    }

	    /* Scan the new address.  Even though the address may not have
	       changed, it may have changed modes and need to be rescanned. */
	    ipmi_start_ipmb_mc_scan(domain, i, ipmb_addr[i], ipmb_addr[i],
				    NULL, NULL);
	}
    }

    /* If we are not activating connections, just use whatever we get
       and don't worry if it is active or not. */
    if (! domain->option_activate_if_possible)
	active = 1;

    start_connection = (active && (first_active_con(domain) == -1));

    if (domain->con_active[u] != active) {
	domain->con_active[u] = active;
	if (active) {
	    /* Deactivate all the other connections, if they support
	       it. */
	    for (u=0; u<MAX_CONS; u++) {
		if (u == domain->working_conn
		    || !domain->conn[u]
		    || !domain->con_up[u])
		{
		    continue;
		}

		if (domain->conn[u]->set_active_state
		    && domain->option_activate_if_possible)
		{
		    domain->conn[u]->set_active_state(
			domain->conn[u],
			0,
			ll_addr_changed,
			domain);
		}
	    }
	} else {
	    /* The connection went inactive, route message from it to
	       the current working connection. */
	    reroute_cmds(domain, u, domain->working_conn);
	}
    } else if (active) {
        /* Always pick the last working active connection to use. */
	domain->working_conn = u;
    } else if (domain->conn[u]->set_active_state
	       && domain->option_activate_if_possible)
    {
        /* Start the timer to activate the connection, if necessary. */
	start_activate_timer(domain);
    }

    if (start_connection) {
	/* We now have an active connection and we didn't before,
           attempt to start up the connection. */
	rv = start_con_up(domain);
	if (rv)
	    call_con_fails(domain, rv, u, 0, domain->connection_up);
    }

 out_unlock:
    _ipmi_domain_put(domain);
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
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sdomain.c(ll_con_changed): Got port number %d,"
		 " but %d is the max number of ports",
		 DOMAIN_NAME(domain), port_num, MAX_PORTS_PER_CON);
	return;
    }

    rv = _ipmi_domain_get(domain);
    if (rv)
	/* So the connection failed.  So what, there's nothing to talk to. */
	return;

    u = get_con_num(domain, ipmi);
    if (u == -1)
	goto out_unlock;

    if (err == ENOENT)
	domain->port_up[port_num][u] = -1;
    else if (err)
	domain->port_up[port_num][u] = 0;
    else
	domain->port_up[port_num][u] = 1;

    /* If we are not starting up, if we gain or lose a connection
       then scan the address. */
    if ((!domain->in_startup) && (ipmi->scan_sysaddr))
    	ipmi_start_si_scan(domain, u, NULL, NULL);

    if (still_connected) {
	domain->con_up[u] = 1;
	if (domain->connecting) {
	    /* If we are connecting, don't report it, it will be
	       reported when the connection is finished. */
	} else if (domain->connection_up) {
	    /* We already have a connection, just report this. */
	    call_con_change(domain, err, u, port_num, domain->connection_up);
	} else {
	    /* We don't have a working connection, so start up the
               process. */
	    domain->working_conn = u;

	    if (domain->conn[u]->get_ipmb_addr)
		/* If we can fetch the IPMB address, see if this is an
                   active connection first. */
		rv = domain->conn[u]->get_ipmb_addr(domain->conn[u],
						    initial_ipmb_addr_cb,
						    domain);
	    else
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
	domain->working_conn = first_working_con(domain);
	if (domain->working_conn == -1)
	    domain->connection_up = 0;
	else if ((!domain->con_active[domain->working_conn])
		 && (domain->conn[domain->working_conn]->set_active_state)
		 && domain->option_activate_if_possible)
	{
	    domain->conn[domain->working_conn]->set_active_state(
		domain->conn[domain->working_conn],
		1,
		ll_addr_changed,
		domain);
	} else {
	    reroute_cmds(domain, u, domain->working_conn);
	}
	call_con_fails(domain, err, u, port_num, domain->connection_up);
    }

 out_unlock:
    _ipmi_domain_put(domain);
}

int
ipmi_option_SDRs(ipmi_domain_t *domain)
{
    return domain->option_all || domain->option_SDRs;
}

int
ipmi_option_SEL(ipmi_domain_t *domain)
{
    return domain->option_all || domain->option_SEL;
}

int
ipmi_option_FRUs(ipmi_domain_t *domain)
{
    return domain->option_all || domain->option_FRUs;
}

int
ipmi_option_IPMB_scan(ipmi_domain_t *domain)
{
    if (domain->option_local_only)
	return 0;
    return domain->option_all || domain->option_IPMB_scan;
}

int
ipmi_option_OEM_init(ipmi_domain_t *domain)
{
    return domain->option_all || domain->option_OEM_init;
}

int
ipmi_option_set_event_rcvr(ipmi_domain_t *domain)
{
    if (domain->option_local_only)
	return 0;
    return domain->option_set_event_rcvr;
}

int
ipmi_option_set_sel_time(ipmi_domain_t *domain)
{
    return domain->option_set_sel_time;
}

int
ipmi_option_use_cache(ipmi_domain_t *domain)
{
    return domain->option_use_cache;
}

int
ipmi_option_activate_if_possible(ipmi_domain_t *domain)
{
    return domain->option_activate_if_possible;
}

int
ipmi_option_local_only(ipmi_domain_t *domain)
{
    return domain->option_local_only;
}

void
_ipmi_option_set_local_only_if_not_specified(ipmi_domain_t *domain, int val)
{
    if (domain->option_local_only_set)
	return;
    domain->option_local_only = val != 0;
}


int
ipmi_open_domain(const char         *name,
		 ipmi_con_t         *con[],
		 unsigned int       num_con,
		 ipmi_domain_con_cb con_change_handler,
		 void               *con_change_cb_data,
		 ipmi_domain_ptr_cb domain_fully_up,
		 void               *domain_fully_up_cb_data,
		 ipmi_open_option_t *options,
		 unsigned int       num_options,
		 ipmi_domain_id_t   *new_domain)
{
    int           rv;
    ipmi_domain_t *domain = NULL;
    unsigned int  i;

    if ((num_con < 1) || (num_con > MAX_CONS))
	return EINVAL;

    rv = setup_domain(name, con, num_con, options, num_options, &domain);
    if (rv)
	return rv;

    domain->domain_fully_up = domain_fully_up;
    domain->domain_fully_up_cb_data = domain_fully_up_cb_data;
    domain->fully_up_count = 1;

    for (i=0; i<num_con; i++) {
	rv = con[i]->add_con_change_handler(con[i], ll_con_changed, domain);
	if (rv)
	    goto out_err;
	rv = con[i]->add_ipmb_addr_handler(con[i], ll_addr_changed, domain);
	if (rv)
	    goto out_err;
    }

    add_known_domain(domain);

    if (con_change_handler) {
	rv = ipmi_domain_add_connect_change_handler(domain,
						    con_change_handler,
						    con_change_cb_data);
	if (rv)
	    goto out_err;
    }

    for (i=0; i<num_con; i++) {
	/* Set the ports that we will have valid and unconnected. */
	if (con[i]->get_num_ports) {
	    int m = con[i]->get_num_ports(con[i]);
	    int j;
	    for (j=0; j<m; j++)
		domain->port_up[j][i] = 0;
	} else
	    /* Only one port 0 */
	    domain->port_up[0][i] = 0;
	rv = con[i]->start_con(con[i]);
	if (rv)
	    break;
    }
    if (rv)
	goto out_err;

    if (new_domain)
	*new_domain = ipmi_domain_convert_to_id(domain);
    
    if (! locked_list_add(domains_list, domain, NULL)) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sdomain.c(sdr_handler): "
		 "Out of memory, could not add domain to the domains list",
		 DOMAIN_NAME(domain));
    }

    call_domain_change(domain, IPMI_ADDED);

    _ipmi_domain_put(domain);
    return rv;

 out_err:
    for (i=0; i<num_con; i++) {
	con[i]->remove_con_change_handler(con[i], ll_con_changed, domain);
	con[i]->remove_ipmb_addr_handler(con[i], ll_addr_changed, domain);
	if (con[i]->register_stat_handler)
	    con[i]->unregister_stat_handler(con[i],
					    domain->con_stat_info);
    }
    remove_known_domain(domain);
    cleanup_domain(domain);
    return rv;
}

/***********************************************************************
 *
 * Handle misc data about domains.
 *
 **********************************************************************/

typedef struct domains_iter_s
{
    ipmi_domain_ptr_cb handler;
    void               *cb_data;
} domains_iter_t;

static int
iterate_domains(void *cb_data, void *item1, void *item2)
{
    domains_iter_t *info = cb_data;
    ipmi_domain_t  *domain = item1;
    int            rv;
    
    rv = _ipmi_domain_get(domain);
    if (!rv) {
	info->handler(item1, info->cb_data);
	_ipmi_domain_put(domain);
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_domain_iterate_domains(ipmi_domain_ptr_cb handler,
			    void               *cb_data)
{
    domains_iter_t info;

    if (!handler)
	return;
    if (!domains_list)
	return;

    info.handler = handler;
    info.cb_data = cb_data;
    locked_list_iterate(domains_list, iterate_domains, &info);
}

ipmi_sdr_info_t *
ipmi_domain_get_main_sdrs(ipmi_domain_t *domain)
{
    return domain->main_sdrs;
}

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
ipmi_domain_get_guid(ipmi_domain_t *domain, unsigned char *guid)
{
    int rv;
    _ipmi_mc_get(domain->si_mc);
    rv = ipmi_mc_get_guid(domain->si_mc, guid);
    _ipmi_mc_put(domain->si_mc);
    return rv;
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
    if (*addr)
	return;
    if (!ipmi_mc_ipmb_event_receiver_support(mc))
	return;
    if (ipmi_mc_get_channel(mc) == IPMI_BMC_CHANNEL)
	return;
    *addr = ipmi_mc_get_address(mc);
}

int
ipmi_domain_get_event_rcvr(ipmi_domain_t *domain)
{
    unsigned int addr = 0;

    ipmi_domain_iterate_mcs(domain, check_event_rcvr, &addr);
    return addr;
}

const char *
_ipmi_domain_name(const ipmi_domain_t *domain)
{
    return domain->name;
}

int
ipmi_domain_get_name(ipmi_domain_t *domain, char *name, int length)
{
    int  slen;

    if (length <= 0)
	return 0;

    /* Never changes, no lock needed. */
    slen = strlen(domain->name);
    if (slen == 0) {
	if (name)
	    *name = '\0';
	goto out;
    }

    slen -= 1; /* Remove the trailing ' ' */
    if (slen >= length) {
	slen = length - 1;
    }

    if (name) {
	memcpy(name, domain->name, slen);
	name[slen] = '\0';
    }
 out:
    return slen;
}

void
ipmi_domain_set_oem_data(ipmi_domain_t                   *domain,
			 void                            *oem_data,
			 ipmi_domain_destroy_oem_data_cb destroyer)
{
    domain->oem_data = oem_data;
    domain->oem_data_destroyer = destroyer;
}

void *
ipmi_domain_get_oem_data(ipmi_domain_t *domain)
{
    return domain->oem_data;
}

enum ipmi_domain_type
ipmi_domain_get_type(ipmi_domain_t *domain)
{
    return domain->domain_type;
}

void
ipmi_domain_set_type(ipmi_domain_t *domain, enum ipmi_domain_type dtype)
{
    domain->domain_type = dtype;
}

unsigned int
ipmi_domain_get_unique_num(ipmi_domain_t *domain)
{
    unsigned int rv;

    ipmi_lock(domain->domain_lock);
    rv = domain->uniq_num;
    domain->uniq_num++;
    ipmi_unlock(domain->domain_lock);
    return rv;
}


/*OEM-specific sensors handling*/
int
ipmi_domain_add_new_sensor_handler(ipmi_domain_t         *domain,
                                   ipmi_domain_sensor_cb handler,
                                   void                  *cb_data)
{
    if (locked_list_add(domain->new_sensor_handlers, handler, cb_data))
        return 0;
    else
        return ENOMEM;
}

int
ipmi_domain_remove_new_sensor_handler(ipmi_domain_t        *domain,
                                      ipmi_domain_sensor_cb handler,
                                       void                *cb_data)
{
    if (locked_list_remove(domain->new_sensor_handlers, handler, cb_data))
        return 0;
    else
        return EINVAL;
}

typedef struct new_sensor_handler_info_s
{
    ipmi_domain_t *domain;
    ipmi_sensor_t *sensor;
} new_sensor_handler_info_t;

static int
call_new_sensor_handler(void *cb_data, void *item1, void *item2)
{
    new_sensor_handler_info_t *info = cb_data;
    ipmi_domain_sensor_cb     handler = item1;

    handler(info->domain, info->sensor, item2);
    return 0;
}

int
_call_new_sensor_handlers(ipmi_domain_t *domain,
                         ipmi_sensor_t *sensor)
{
    new_sensor_handler_info_t info;

    info.domain = domain;
    info.sensor = sensor;

    locked_list_iterate(domain->new_sensor_handlers, call_new_sensor_handler,
		        &info);
    return 0;
}

/***********************************************************************
 *
 * Handling anonmymous attributes for domains
 *
 **********************************************************************/

struct ipmi_domain_attr_s
{
    char *name;
    void *data;

    ipmi_lock_t *lock;
    unsigned int refcount;

    ipmi_domain_attr_kill_cb destroy;
    void                     *cb_data;
};

static int
destroy_attr(void *cb_data, void *item1, void *item2)
{
    ipmi_domain_t      *domain = cb_data;
    ipmi_domain_attr_t *attr = item1;

    locked_list_remove(domain->attr, item1, item2);
    ipmi_domain_attr_put(attr);
    return LOCKED_LIST_ITER_CONTINUE;
}

typedef struct domain_attr_cmp_s
{
    char               *name;
    ipmi_domain_attr_t *attr;
} domain_attr_cmp_t;

static int
domain_attr_cmp(void *cb_data, void *item1, void *item2)
{
    domain_attr_cmp_t  *info = cb_data;
    ipmi_domain_attr_t *attr = item1;

    if (strcmp(info->name, attr->name) == 0) {
	info->attr = attr;
	return LOCKED_LIST_ITER_STOP;
    }

    return LOCKED_LIST_ITER_CONTINUE;
}

int
ipmi_domain_register_attribute(ipmi_domain_t            *domain,
			       char                     *name,
			       ipmi_domain_attr_init_cb init,
			       ipmi_domain_attr_kill_cb destroy,
			       void                     *cb_data,
			       ipmi_domain_attr_t       **attr)
{
    ipmi_domain_attr_t  *val = NULL;
    domain_attr_cmp_t   info;
    int                 rv = 0;
    locked_list_entry_t *entry;

    info.name = name;
    info.attr = NULL;
    locked_list_lock(domain->attr);
    locked_list_iterate_nolock(domain->attr, domain_attr_cmp, &info);
    if (info.attr) {
	ipmi_lock(info.attr->lock);
	info.attr->refcount++;
	ipmi_unlock(info.attr->lock);
	*attr = info.attr;
	goto out_unlock;
    }

    val = ipmi_mem_alloc(sizeof(*val));
    if (!val) {
	rv = ENOMEM;
	goto out_unlock;
    }

    val->name = ipmi_strdup(name);
    if (!val->name) {
	ipmi_mem_free(val);
	rv = ENOMEM;
	goto out_unlock;
    }

    entry = locked_list_alloc_entry();
    if (!entry) {
	ipmi_mem_free(val->name);
	ipmi_mem_free(val);
	rv = ENOMEM;
	goto out_unlock;
    }

    rv = ipmi_create_lock(domain, &val->lock);
    if (rv) {
	locked_list_free_entry(entry);
	ipmi_mem_free(val->name);
	ipmi_mem_free(val);
	goto out_unlock;
    }

    val->refcount = 2;
    val->destroy = destroy;
    val->cb_data = cb_data;
    val->data = NULL;

    if (init) {
	rv = init(domain, cb_data, &val->data);
	if (rv) {
	    ipmi_destroy_lock(val->lock);
	    locked_list_free_entry(entry);
	    ipmi_mem_free(val->name);
	    ipmi_mem_free(val);
	    rv = ENOMEM;
	    goto out_unlock;
	}
    }

    locked_list_add_entry_nolock(domain->attr, val, NULL, entry);

    *attr = val;

 out_unlock:
    locked_list_unlock(domain->attr);
    return rv;
}
			       
int
ipmi_domain_find_attribute(ipmi_domain_t      *domain,
			   char               *name,
			   ipmi_domain_attr_t **attr)
{
    domain_attr_cmp_t info;

    if (!domain->attr)
	return EINVAL;

    /* Attributes are immutable, no lock is required. */
    info.name = name;
    info.attr = NULL;
    locked_list_iterate(domain->attr, domain_attr_cmp, &info);
    if (info.attr) {
	ipmi_lock(info.attr->lock);
	info.attr->refcount++;
	ipmi_unlock(info.attr->lock);
	*attr = info.attr;
	return 0;
    }
    return EINVAL;
}

void *
ipmi_domain_attr_get_data(ipmi_domain_attr_t *attr)
{
    return attr->data;
}

void
ipmi_domain_attr_put(ipmi_domain_attr_t *attr)
{
    ipmi_lock(attr->lock);
    attr->refcount--;
    if (attr->refcount > 0) {
	ipmi_unlock(attr->lock);
	return;
    }
    ipmi_unlock(attr->lock);
    if (attr->destroy)
	attr->destroy(attr->cb_data, attr->data);
    ipmi_destroy_lock(attr->lock);
    ipmi_mem_free(attr->name);
    ipmi_mem_free(attr);
}
			       
typedef struct find_attr_s
{
    char               *name;
    ipmi_domain_attr_t **attr;
    int                rv;
} find_attr_t;

static void
find_attr_2(ipmi_domain_t *domain, void *cb_data)
{
    find_attr_t *info = cb_data;

    info->rv = ipmi_domain_find_attribute(domain, info->name, info->attr);
}

int
ipmi_domain_id_find_attribute(ipmi_domain_id_t   domain_id,
			      char               *name,
			      ipmi_domain_attr_t **attr)
{
    find_attr_t info = { name, attr, 0 };
    int  rv;

    rv = ipmi_domain_pointer_cb(domain_id, find_attr_2, &info);
    if (!rv)
	rv = info.rv;
    return rv;
}

/***********************************************************************
 *
 * Statistics
 *
 **********************************************************************/

struct ipmi_domain_stat_s
{
    char               *name;
    char               *instance;
    ipmi_lock_t        *lock;
    unsigned int       count;
    ipmi_domain_stat_t *stat;
    unsigned int       refcount;
};

static int
destroy_stat(void *cb_data, void *item1, void *item2)
{
    ipmi_domain_t      *domain = cb_data;
    ipmi_domain_stat_t *stat = item1;

    locked_list_remove(domain->stats, item1, item2);
    ipmi_domain_stat_put(stat);
    return LOCKED_LIST_ITER_CONTINUE;
}

typedef struct domain_stat_cmp_s
{
    const char         *name;
    const char         *instance;
    ipmi_domain_stat_t *stat;
} domain_stat_cmp_t;

static int
domain_stat_cmp(void *cb_data, void *item1, void *item2)
{
    domain_stat_cmp_t  *info = cb_data;
    ipmi_domain_stat_t *stat = item1;

    if ((strcmp(info->name, stat->name) == 0)
	&& (strcmp(info->instance, stat->instance) == 0))
    {
	info->stat = stat;
	return LOCKED_LIST_ITER_STOP;
    }

    return LOCKED_LIST_ITER_CONTINUE;
}

int
ipmi_domain_stat_register(ipmi_domain_t      *domain,
			  const char         *name,
			  const char         *instance,
			  ipmi_domain_stat_t **stat)
{
    ipmi_domain_stat_t  *val = NULL;
    domain_stat_cmp_t   info;
    int                 rv = 0;
    locked_list_entry_t *entry;

    info.name = name;
    info.instance = instance;
    info.stat = NULL;
    locked_list_lock(domain->stats);
    locked_list_iterate_nolock(domain->stats, domain_stat_cmp, &info);
    if (info.stat) {
	ipmi_lock(info.stat->lock);
	info.stat->refcount++;
	ipmi_unlock(info.stat->lock);
	*stat = info.stat;
	goto out_unlock;
    }

    val = ipmi_mem_alloc(sizeof(*val));
    if (!val) {
	rv = ENOMEM;
	goto out_unlock;
    }

    val->name = ipmi_strdup(name);
    if (!val->name) {
	ipmi_mem_free(val);
	rv = ENOMEM;
	goto out_unlock;
    }

    val->instance = ipmi_strdup(instance);
    if (!val->instance) {
	ipmi_mem_free(val->name);
	ipmi_mem_free(val);
	rv = ENOMEM;
	goto out_unlock;
    }

    entry = locked_list_alloc_entry();
    if (!entry) {
	ipmi_mem_free(val->instance);
	ipmi_mem_free(val->name);
	ipmi_mem_free(val);
	rv = ENOMEM;
	goto out_unlock;
    }

    rv = ipmi_create_lock(domain, &val->lock);
    if (rv) {
	locked_list_free_entry(entry);
	ipmi_mem_free(val->instance);
	ipmi_mem_free(val->name);
	ipmi_mem_free(val);
	goto out_unlock;
    }

    val->refcount = 2;
    val->count = 0;

    locked_list_add_entry_nolock(domain->stats, val, NULL, entry);

    *stat = val;

 out_unlock:    
    locked_list_unlock(domain->stats);
    return 0;
}

int
ipmi_domain_find_stat(ipmi_domain_t      *domain,
		      const char         *name,
		      const char         *instance,
		      ipmi_domain_stat_t **stat)
{
    domain_stat_cmp_t   info;
    int                 rv = ENOENT;

    info.name = name;
    info.instance = instance;
    info.stat = NULL;
    locked_list_lock(domain->stats);
    locked_list_iterate_nolock(domain->stats, domain_stat_cmp, &info);
    if (info.stat) {
	ipmi_lock(info.stat->lock);
	info.stat->refcount++;
	ipmi_unlock(info.stat->lock);
	*stat = info.stat;
	rv = 0;
    }
    locked_list_unlock(domain->stats);

    return rv;
}

void
ipmi_domain_stat_put(ipmi_domain_stat_t *stat)
{
    ipmi_lock(stat->lock);
    stat->refcount--;
    if (stat->refcount > 0) {
	ipmi_unlock(stat->lock);
	return;
    }
    ipmi_unlock(stat->lock);
    ipmi_destroy_lock(stat->lock);
    ipmi_mem_free(stat->name);
    ipmi_mem_free(stat->instance);
    ipmi_mem_free(stat);
}

void
ipmi_domain_stat_add(ipmi_domain_stat_t *stat, int amount)
{
    ipmi_lock(stat->lock);
    stat->count += amount;
    ipmi_unlock(stat->lock);
}

unsigned int
ipmi_domain_stat_get(ipmi_domain_stat_t *stat)
{
    unsigned int rv;
    ipmi_lock(stat->lock);
    rv = stat->count;
    ipmi_unlock(stat->lock);
    return rv;
}

unsigned int
ipmi_domain_stat_get_and_zero(ipmi_domain_stat_t *stat)
{
    unsigned int rv;
    ipmi_lock(stat->lock);
    rv = stat->count;
    stat->count = 0;
    ipmi_unlock(stat->lock);
    return rv;
}

const char *
ipmi_domain_stat_get_name(ipmi_domain_stat_t *stat)
{
    return stat->name;
}

const char *
ipmi_domain_stat_get_instance(ipmi_domain_stat_t *stat)
{
    return stat->instance;
}

typedef struct stat_iterate_s
{
    ipmi_domain_t *domain;
    const char    *name;
    const char    *instance;
    ipmi_stat_cb  handler;
    void          *cb_data;
} stat_iterate_t;

static int
domain_stat_iter_pre(void *cb_data, void *item1, void *item2)
{
    stat_iterate_t     *info = cb_data;
    ipmi_domain_stat_t *stat = item1;

    if (info->name && (strcmp(info->name, stat->name) != 0))
	return LOCKED_LIST_ITER_SKIP;
    if (info->instance && (strcmp(info->instance, stat->instance) != 0))
	return LOCKED_LIST_ITER_SKIP;

    ipmi_lock(stat->lock);
    stat->refcount++;
    ipmi_unlock(stat->lock);

    return LOCKED_LIST_ITER_CONTINUE;
}

static int
domain_stat_iter(void *cb_data, void *item1, void *item2)
{
    stat_iterate_t     *info = cb_data;
    ipmi_domain_stat_t *stat = item1;

    /* Prefunc already matched, this is a good one. */
    info->handler(info->domain, stat, info->cb_data);
    ipmi_domain_stat_put(stat);

    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_domain_stat_iterate(ipmi_domain_t *domain,
			 const char    *name,
			 const char    *instance,
			 ipmi_stat_cb  handler,
			 void          *cb_data)
{
    stat_iterate_t info;

    info.domain = domain;
    info.name = name;
    info.instance = instance;
    info.handler = handler;
    info.cb_data = cb_data;
    locked_list_iterate_prefunc(domain->stats, domain_stat_iter_pre,
				domain_stat_iter, &info);
}

/***********************************************************************
 *
 * Initialization and shutdown
 *
 **********************************************************************/

int
_ipmi_domain_init(void)
{
    int rv;

    if (domains_initialized)
	return 0;

    mc_oem_handlers = locked_list_alloc(ipmi_get_global_os_handler());
    if (!mc_oem_handlers)
	return ENOMEM;

    domain_change_handlers = locked_list_alloc(ipmi_get_global_os_handler());
    if (!domain_change_handlers)
	return ENOMEM;

    domains_list = locked_list_alloc(ipmi_get_global_os_handler());
    if (!domains_list) {
	locked_list_destroy(domain_change_handlers);
	return ENOMEM;
    }

    oem_handlers = alloc_ilist();
    if (!oem_handlers) {
	locked_list_destroy(domain_change_handlers);
	locked_list_destroy(domains_list);
	domains_list = NULL;
	return ENOMEM;
    }

    rv = ipmi_create_global_lock(&domains_lock);
    if (rv) {
	locked_list_destroy(domain_change_handlers);
	locked_list_destroy(domains_list);
	domains_list = NULL;
	free_ilist(oem_handlers);
	oem_handlers = NULL;
	return rv;
    }

    domains_initialized = 1;

    return 0;
}

void
_ipmi_domain_shutdown(void)
{
    domains_initialized = 0;

    locked_list_destroy(domain_change_handlers);
    locked_list_destroy(mc_oem_handlers);
    locked_list_destroy(domains_list);
    domains_list = NULL;
    free_ilist(oem_handlers);
    oem_handlers = NULL;
    ipmi_destroy_lock(domains_lock);
    domains_lock = NULL;
}


/***********************************************************************
 *
 * Cruft
 *
 **********************************************************************/

struct ipmi_domain_mc_upd_s
{
    ipmi_domain_mc_upd_cb handler;
    void                  *cb_data;
    struct ipmi_domain_mc_upd_s *next, *prev;
};

int
ipmi_domain_register_mc_update_handler(ipmi_domain_t         *domain,
				       ipmi_domain_mc_upd_cb handler,
				       void                  *cb_data,
				       struct ipmi_domain_mc_upd_s **id)
{
    struct ipmi_domain_mc_upd_s *info;
    int                         rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    rv = ipmi_domain_add_mc_updated_handler(domain, handler, cb_data);
    if (rv) {
	ipmi_mem_free(info);
    } else {
	info->handler = handler;
	info->cb_data = cb_data;
	ipmi_lock(domain->domain_lock);
	info->next = domain->mc_upd_cruft;
	info->prev = NULL;
	domain->mc_upd_cruft = info;
	ipmi_unlock(domain->domain_lock);

	if (id)
	    *id = info;
    }

    return rv;
}

void
ipmi_domain_remove_mc_update_handler(ipmi_domain_t               *domain,
				     struct ipmi_domain_mc_upd_s *id)
{
    ipmi_domain_remove_mc_updated_handler(domain, id->handler, id->cb_data);
    ipmi_lock(domain->domain_lock);
    if (id->next)
	id->next->prev = id->prev;
    if (id->prev)
	id->prev->next = id->next;
    else
	domain->mc_upd_cruft = id->next;
    ipmi_unlock(domain->domain_lock);
    ipmi_mem_free(id);
}

struct ipmi_event_handler_id_s
{
    ipmi_event_handler_cb   handler;
    void                    *event_data;
    struct ipmi_event_handler_id_s *next, *prev;
};

int
ipmi_register_for_events(ipmi_domain_t                  *domain,
			 ipmi_event_handler_cb          handler,
			 void                           *event_data,
			 struct ipmi_event_handler_id_s **id)
{
    struct ipmi_event_handler_id_s *info;
    int                            rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    rv = ipmi_domain_add_event_handler(domain, handler, event_data);
    if (rv) {
	ipmi_mem_free(info);
    } else {
	info->handler = handler;
	info->event_data = event_data;
	ipmi_lock(domain->domain_lock);
	info->next = domain->event_cruft;
	info->prev = NULL;
	domain->event_cruft = info;
	ipmi_unlock(domain->domain_lock);

	if (id)
	    *id = info;
    }

    return rv;
}

int
ipmi_deregister_for_events(ipmi_domain_t                  *domain,
			   struct ipmi_event_handler_id_s *id)
{
    int rv;
    rv = ipmi_domain_remove_event_handler(domain, id->handler, id->event_data);
    ipmi_lock(domain->domain_lock);
    if (id->next)
	id->next->prev = id->prev;
    if (id->prev)
	id->prev->next = id->next;
    else
	domain->event_cruft = id->next;
    ipmi_unlock(domain->domain_lock);
    ipmi_mem_free(id);
    return rv;
}

struct ipmi_domain_con_change_s
{
    ipmi_domain_con_cb              handler;
    void                            *cb_data;
    struct ipmi_domain_con_change_s *next, *prev;
};

static int
ipmi_domain_add_con_change_handler_nd(ipmi_domain_t                   *domain,
				      ipmi_domain_con_cb              handler,
				      void                            *cb_data,
				      struct ipmi_domain_con_change_s **id)
{
    struct ipmi_domain_con_change_s *info;
    int                             rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    rv = ipmi_domain_add_connect_change_handler(domain, handler, cb_data);
    if (rv) {
	ipmi_mem_free(info);
    } else {
	info->handler = handler;
	info->cb_data = cb_data;
	ipmi_lock(domain->domain_lock);
	info->next = domain->con_change_cruft;
	info->prev = NULL;
	domain->con_change_cruft = info;
	ipmi_unlock(domain->domain_lock);

	if (id)
	    *id = info;
    }

    return rv;
}

int
ipmi_domain_add_con_change_handler(ipmi_domain_t                   *domain,
				   ipmi_domain_con_cb              handler,
				   void                            *cb_data,
				   struct ipmi_domain_con_change_s **id)
{
    return ipmi_domain_add_con_change_handler_nd(domain,
						 handler,
						 cb_data,
						 id);
}

void
ipmi_domain_remove_con_change_handler(ipmi_domain_t                   *domain,
				      struct ipmi_domain_con_change_s *id)
{
    ipmi_domain_remove_connect_change_handler(domain, id->handler,
					      id->cb_data);
    ipmi_lock(domain->domain_lock);
    if (id->next)
	id->next->prev = id->prev;
    if (id->prev)
	id->prev->next = id->next;
    else
	domain->con_change_cruft = id->next;
    ipmi_unlock(domain->domain_lock);
    ipmi_mem_free(id);
}

int
ipmi_init_domain(ipmi_con_t               *con[],
		 unsigned int             num_con,
		 ipmi_domain_con_cb       con_change_handler,
		 void                     *con_change_cb_data,
		 struct ipmi_domain_con_change_s **con_change_id,
		 ipmi_domain_id_t         *new_domain)
{
    int           rv;
    ipmi_domain_t *domain;
    unsigned int  i;

    if ((num_con < 1) || (num_con > MAX_CONS))
	return EINVAL;

    rv = setup_domain("", con, num_con, NULL, 0, &domain);
    if (rv)
	return rv;

    domain->in_startup = 1;
    for (i=0; i<num_con; i++) {
	rv = con[i]->add_con_change_handler(con[i], ll_con_changed, domain);
	if (rv)
	    return rv;
	rv = con[i]->add_ipmb_addr_handler(con[i], ll_addr_changed, domain);
	if (rv)
	    return rv;
    }

    add_known_domain(domain);

    if (con_change_handler) {
	rv = ipmi_domain_add_con_change_handler_nd(domain, con_change_handler,
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
    
    if (! locked_list_add(domains_list, domain, NULL)) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%sdomain.c(sdr_handler): "
		 "Out of memory, could not add domain to the domains list",
		 DOMAIN_NAME(domain));
    }

 out:
    _ipmi_domain_put(domain);
    return rv;

 out_err:
    for (i=0; i<num_con; i++) {
	con[i]->remove_con_change_handler(con[i], ll_con_changed, domain);
	con[i]->remove_ipmb_addr_handler(con[i], ll_addr_changed, domain);
	if (con[i]->register_stat_handler)
	    con[i]->unregister_stat_handler(con[i],
					    domain->con_stat_info);
    }
    remove_known_domain(domain);
    cleanup_domain(domain);
    goto out;
}

int
ipmi_domain_set_entity_update_handler(ipmi_domain_t         *domain,
				      ipmi_domain_entity_cb handler,
				      void                  *cb_data)
{
    int rv = 0;

    CHECK_DOMAIN_LOCK(domain);

    ipmi_lock(domain->domain_lock);
    if (domain->cruft_entity_update_handler)
	ipmi_entity_info_remove_update_handler
	    (domain->entities,
	     domain->cruft_entity_update_handler,
	     domain->cruft_entity_update_cb_data);

    domain->cruft_entity_update_handler = handler;
    domain->cruft_entity_update_cb_data = cb_data;
    if (handler)
	rv = ipmi_entity_info_add_update_handler(domain->entities,
						 handler,
						 cb_data);
    ipmi_unlock(domain->domain_lock);
    return rv;
}

int
ipmi_close_connection(ipmi_domain_t             *domain,
		      ipmi_domain_close_done_cb close_done,
		      void                      *cb_data)
{
    return ipmi_domain_close(domain, close_done, cb_data);
}

static void
free_domain_cruft(ipmi_domain_t *domain)
{
    while (domain->mc_upd_cruft) {
	struct ipmi_domain_mc_upd_s *to_free;
	to_free = domain->mc_upd_cruft;
	domain->mc_upd_cruft = to_free->next;
	ipmi_mem_free(to_free);
    }

    while (domain->event_cruft) {
	struct ipmi_event_handler_id_s *to_free;
	to_free = domain->event_cruft;
	domain->event_cruft = to_free->next;
	ipmi_mem_free(to_free);
    }

    while (domain->con_change_cruft) {
	struct ipmi_domain_con_change_s *to_free;
	to_free = domain->con_change_cruft;
	domain->con_change_cruft = to_free->next;
	ipmi_mem_free(to_free);
    }
}
