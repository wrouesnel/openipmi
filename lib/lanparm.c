/*
 * lanparm.c
 *
 * MontaVista IPMI code for configuring IPMI LAN connections
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

#include <string.h>
#include <math.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_lanparm.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ilist.h>
#include <OpenIPMI/opq.h>

struct ipmi_lanparm_s
{
    ipmi_mcid_t mc;
    unsigned char channel;

    unsigned int destroyed : 1;
    unsigned int in_destroy : 1;

    /* Something to call when the destroy is complete. */
    ipmi_lanparm_done_cb destroy_handler;
    void                 *destroy_cb_data;

    os_hnd_lock_t *lanparm_lock;

    os_handler_t *os_hnd;

    /* We serialize operations through here, since we are dealing with
       a locked resource. */
    opq_t *opq;
};

static void
lanparm_lock(ipmi_lanparm_t *lanparm)
{
    if (lanparm->os_hnd->lock)
	lanparm->os_hnd->lock(lanparm->os_hnd, lanparm->lanparm_lock);
}

static void
lanparm_unlock(ipmi_lanparm_t *lanparm)
{
    if (lanparm->os_hnd->lock)
	lanparm->os_hnd->unlock(lanparm->os_hnd, lanparm->lanparm_lock);
}

static int
check_lanparm_response_param(ipmi_lanparm_t *lanparm,
			     ipmi_mc_t      *mc,
			     ipmi_msg_t     *rsp,
			     int	    len,
			     char	    *func_name)
{
    if (lanparm->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%s: "
		 "LANPARM was destroyed while an operation was in progress",
		 func_name);
	return ECANCELED;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%s: MC went away while LANPARM op was in progress",
		 func_name);
	return ENXIO;
    }

    if (rsp->data[0] != 0) {
	/* We ignore 0x80, since that may be a valid error return for an
	   unsupported parameter. */
	if (rsp->data[0] != 0x80)
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%s: IPMI error from LANPARM capabilities fetch: %x",
		     func_name,
		     rsp->data[0]);
	return IPMI_IPMI_ERR_VAL(rsp->data[0]);
    }

    if (rsp->data_len < len) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		"%s: LANPARM capabilities too short",
		func_name);
	return EINVAL;
    }
    return 0;
}

int
ipmi_lanparm_alloc(ipmi_mc_t      *mc,
		   unsigned int   channel,
		   ipmi_lanparm_t **new_lanparm)
{
    ipmi_lanparm_t *lanparm = NULL;
    int            rv = 0;
    ipmi_domain_t  *domain;

    CHECK_MC_LOCK(mc);

    lanparm = ipmi_mem_alloc(sizeof(*lanparm));
    if (!lanparm) {
	rv = ENOMEM;
	goto out;
    }
    memset(lanparm, 0, sizeof(*lanparm));

    lanparm->mc = ipmi_mc_convert_to_id(mc);
    domain = ipmi_mc_get_domain(mc);
    lanparm->os_hnd = ipmi_domain_get_os_hnd(domain);
    lanparm->lanparm_lock = NULL;
    lanparm->channel = channel & 0xf;

    lanparm->opq = opq_alloc(lanparm->os_hnd);
    if (!lanparm->opq) {
	rv = ENOMEM;
	goto out;
    }

    if (lanparm->os_hnd->create_lock) {
	rv = lanparm->os_hnd->create_lock(lanparm->os_hnd,
					  &lanparm->lanparm_lock);
	if (rv)
	    goto out;
    }

 out:
    if (rv) {
	if (lanparm) {
	    if (lanparm->opq)
		opq_destroy(lanparm->opq);
	    if (lanparm->lanparm_lock)
		lanparm->os_hnd->destroy_lock(lanparm->os_hnd,
					      lanparm->lanparm_lock);
	    ipmi_mem_free(lanparm);
	}
    } else {
	*new_lanparm = lanparm;
    }
    return rv;
}

static void
internal_destroy_lanparm(ipmi_lanparm_t *lanparm)
{
    lanparm->in_destroy = 1;

    /* We don't have to have a valid ipmi to destroy an SEL, the are
       designed to live after the ipmi has been destroyed. */
    lanparm_unlock(lanparm);

    if (lanparm->opq)
	opq_destroy(lanparm->opq);

    if (lanparm->lanparm_lock)
	lanparm->os_hnd->destroy_lock(lanparm->os_hnd, lanparm->lanparm_lock);

    /* Do this after we have gotten rid of all external dependencies,
       but before it is free. */
    if (lanparm->destroy_handler)
	lanparm->destroy_handler(lanparm, 0, lanparm->destroy_cb_data);

    ipmi_mem_free(lanparm);
}

int
ipmi_lanparm_destroy(ipmi_lanparm_t       *lanparm,
		     ipmi_lanparm_done_cb handler,
		     void                 *cb_data)
{
    /* We don't need the read lock, because the lanparm are stand-alone
       after they are created (except for fetching SELs, of course). */
    lanparm_lock(lanparm);
    if (lanparm->destroyed) {
	lanparm_unlock(lanparm);
	return EINVAL;
    }
    lanparm->destroyed = 1;
    lanparm->destroy_handler = handler;
    lanparm->destroy_cb_data = cb_data;
    if (opq_stuff_in_progress(lanparm->opq)) {
	/* It's currently doing something with callbacks, so let it be
           destroyed in the handler, since we can't cancel the handler
           or operation. */
	lanparm_unlock(lanparm);
	return 0;
    }

    /* This unlocks the lock. */
    internal_destroy_lanparm(lanparm);
    return 0;
}

typedef struct lanparm_fetch_handler_s
{
    ipmi_lanparm_t 	*lanparm;
    unsigned char       parm;
    unsigned char       set;
    unsigned char       block;
    ipmi_lanparm_get_cb handler;
    void                *cb_data;
    unsigned char       *data;
    unsigned int        data_len;
    int                 rv;
} lanparm_fetch_handler_t;

/* This should be called with the lanparm locked.  It will unlock the lanparm
   before returning. */
static void
fetch_complete(ipmi_lanparm_t *lanparm, int err, lanparm_fetch_handler_t *elem)
{
    if (lanparm->in_destroy)
	goto out;

    if (elem->handler)
	elem->handler(lanparm, err, elem->data, elem->data_len, elem->cb_data);

    ipmi_mem_free(elem);

    if (lanparm->destroyed) {
	internal_destroy_lanparm(lanparm);
	return;
    }

    opq_op_done(lanparm->opq);

 out:
    lanparm_unlock(lanparm);
}


static void
lanparm_config_fetched(ipmi_mc_t  *mc,
		       ipmi_msg_t *rsp,
		       void       *rsp_data)
{
    lanparm_fetch_handler_t *elem = rsp_data;
    ipmi_lanparm_t          *lanparm = elem->lanparm;
    int                 rv;

    rv = check_lanparm_response_param(lanparm, mc, rsp, 2,
				      "lanparm_config_fetched");

    /* Skip over the completion code. */
    elem->data = rsp->data + 1;
    elem->data_len = rsp->data_len - 1;

    lanparm_lock(lanparm);
    fetch_complete(lanparm, rv, elem);
}

static void
start_config_fetch_cb(ipmi_mc_t *mc, void *cb_data)
{
    lanparm_fetch_handler_t *elem = cb_data;
    ipmi_lanparm_t          *lanparm = elem->lanparm;
    unsigned char           data[4];
    ipmi_msg_t              msg;
    int                     rv;

    lanparm_lock(lanparm);
    if (lanparm->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_fetch: "
		 "LANPARM was destroyed while an operation was in progress");
	fetch_complete(lanparm, ECANCELED, elem);
	goto out;
    }

    msg.data = data;
    msg.netfn = IPMI_TRANSPORT_NETFN;
    msg.cmd = IPMI_GET_LAN_CONFIG_PARMS_CMD;
    data[0] = lanparm->channel;
    data[1] = elem->parm;
    data[2] = elem->set;
    data[3] = elem->block;
    msg.data_len = 4;
    rv = ipmi_mc_send_command(mc, 0, &msg, lanparm_config_fetched, elem);

    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "LANPARM start_config_fetch: could not send cmd: %x",
		 rv);
	fetch_complete(lanparm, ECANCELED, elem);
	goto out;
    }

    lanparm_unlock(lanparm);
 out:
    return;
}

static void
start_config_fetch(void *cb_data, int shutdown)
{
    lanparm_fetch_handler_t *elem = cb_data;
    int                 rv;

    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_fetch: "
		 "LANPARM was destroyed while an operation was in progress");
	lanparm_lock(elem->lanparm);
	fetch_complete(elem->lanparm, ECANCELED, elem);
	return;
    }

    /* The read lock must be claimed before the lanparm lock to avoid
       deadlock. */
    rv = ipmi_mc_pointer_cb(elem->lanparm->mc, start_config_fetch_cb, elem);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO, "start_fetch: LANPARM's MC is not valid");
	lanparm_lock(elem->lanparm);
	fetch_complete(elem->lanparm, rv, elem);
    }
}

int
ipmi_lanparm_get_parm(ipmi_lanparm_t      *lanparm,
		      unsigned int	  parm,
		      unsigned int	  set,
		      unsigned int	  block,
		      ipmi_lanparm_get_cb done,
		      void                *cb_data)
{
    lanparm_fetch_handler_t *elem;
    int                 rv = 0;

    if (lanparm->destroyed)
	return EINVAL;

    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lanparm_get: could not allocate the lanparm element");
	return ENOMEM;
    }

    elem->handler = done;
    elem->cb_data = cb_data;
    elem->lanparm = lanparm;
    elem->parm = parm;
    elem->set = set;
    elem->block = block;
    elem->rv = 0;

    lanparm_lock(lanparm);

    if (!opq_new_op(lanparm->opq, start_config_fetch, elem, 0))
	rv = ENOMEM;

    lanparm_unlock(lanparm);

    return rv;
}

typedef struct lanparm_set_handler_s
{
    ipmi_lanparm_t 	 *lanparm;
    ipmi_lanparm_done_cb handler;
    void                 *cb_data;
    unsigned char        data[MAX_IPMI_DATA_SIZE];
    unsigned int         data_len;
    int                  rv;
} lanparm_set_handler_t;

/* This should be called with the lanparm locked.  It will unlock the lanparm
   before returning. */
static void
set_complete(ipmi_lanparm_t *lanparm, int err, lanparm_set_handler_t *elem)
{
    if (lanparm->in_destroy)
	goto out;

    if (elem->handler)
	elem->handler(lanparm, err, elem->cb_data);

    ipmi_mem_free(elem);

    if (lanparm->destroyed) {
	internal_destroy_lanparm(lanparm);
	return;
    }

    opq_op_done(lanparm->opq);

 out:
    lanparm_unlock(lanparm);
}

static void
lanparm_config_set(ipmi_mc_t  *mc,
	       ipmi_msg_t *rsp,
	       void       *rsp_data)
{
    lanparm_set_handler_t *elem = rsp_data;
    ipmi_lanparm_t        *lanparm = elem->lanparm;
    int               rv;

    rv = check_lanparm_response_param(lanparm, mc, rsp, 1, "lanparm_config_set");

    lanparm_lock(lanparm);
    set_complete(lanparm, rv, elem);
}

static void
start_config_set_cb(ipmi_mc_t *mc, void *cb_data)
{
    lanparm_set_handler_t *elem = cb_data;
    ipmi_lanparm_t        *lanparm = elem->lanparm;
    ipmi_msg_t        msg;
    int               rv;

    lanparm_lock(lanparm);
    if (lanparm->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_set: "
		 "LANPARM was destroyed while an operation was in progress");
	set_complete(lanparm, ECANCELED, elem);
	goto out;
    }

    msg.netfn = IPMI_TRANSPORT_NETFN;
    msg.cmd = IPMI_SET_LAN_CONFIG_PARMS_CMD;
    msg.data = elem->data;
    msg.data_len = elem->data_len;
    rv = ipmi_mc_send_command(mc, 0, &msg, lanparm_config_set, elem);

    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "LANPARM start_config_set: could not send cmd: %x",
		 rv);
	set_complete(lanparm, ECANCELED, elem);
	goto out;
    }

    lanparm_unlock(lanparm);
 out:
    return;
}

static void
start_config_set(void *cb_data, int shutdown)
{
    lanparm_set_handler_t *elem = cb_data;
    int               rv;

    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_config_set: "
		 "LANPARM was destroyed while an operation was in progress");
	lanparm_lock(elem->lanparm);
	set_complete(elem->lanparm, ECANCELED, elem);
	return;
    }

    /* The read lock must be claimed before the lanparm lock to avoid
       deadlock. */
    rv = ipmi_mc_pointer_cb(elem->lanparm->mc, start_config_set_cb, elem);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_config_set: LANPARM's MC is not valid");
	lanparm_lock(elem->lanparm);
	set_complete(elem->lanparm, rv, elem);
    }
}

int
ipmi_lanparm_set_parm(ipmi_lanparm_t       *lanparm,
		      unsigned int         parm,
		      unsigned char        *data,
		      unsigned int         data_len,
		      ipmi_lanparm_done_cb done,
		      void                 *cb_data)
{
    lanparm_set_handler_t *elem;
    int               rv = 0;

    if (lanparm->destroyed)
	return EINVAL;

    if (data_len > MAX_IPMI_DATA_SIZE-2)
	return EINVAL;

    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lanparm_get: could not allocate the lanparm element");
	return ENOMEM;
    }

    elem->handler = done;
    elem->cb_data = cb_data;
    elem->lanparm = lanparm;
    elem->data[0] = lanparm->channel;
    elem->data[1] = parm;
    memcpy(elem->data+2, data, data_len);
    elem->data_len = data_len + 2;
    elem->rv = 0;

    lanparm_lock(lanparm);

    if (!opq_new_op(lanparm->opq, start_config_set, elem, 0))
	rv = ENOMEM;

    lanparm_unlock(lanparm);

    return rv;
}

typedef struct authtypes_s
{
    unsigned int oem : 1;
    unsigned int straight : 1;
    unsigned int md5 : 1;
    unsigned int md2 : 1;
    unsigned int none : 1;
} authtypes_t;

typedef struct alert_dest_type_s
{
    unsigned int alert_ack : 1;
    unsigned int dest_type : 3;
    unsigned int alert_retry_interval : 8;
    unsigned int max_alert_retries : 3;
} alert_dest_type_t;

typedef struct alert_dest_addr_s
{
    unsigned char dest_format;
    unsigned char gw_to_use;
    unsigned char dest_ip_addr[4];
    unsigned char dest_mac_addr[6];
} alert_dest_addr_t;

struct ipmi_lan_config_s
{
    /* Stuff for getting/setting the values. */
    int curr_parm;
    int curr_sel;

    /* Not used for access, just for checking validity. */
    ipmi_lanparm_t *my_lan;

    /* Does this config hold the external LAN "set in progress" lock? */
    int lan_locked;

    /* Does the LAN config support locking? */
    int lock_supported;

    /* Used for deferred errors. */
    int err;

    ipmi_lanparm_done_cb   set_done;
    ipmi_lan_get_config_cb done;
    void                   *cb_data;

    authtypes_t auth_support;
    authtypes_t auth_enable[5];
    unsigned char ip_addr[4];
    unsigned char ip_addr_source;
    unsigned char mac_addr[6];
    unsigned char subnet_mask[4];
    unsigned char ipv4_ttl;
    unsigned char ipv4_flags;
    unsigned char ipv4_precedence;
    unsigned char ipv4_tos;
    unsigned char ipv4_header_parms_supported;
    unsigned char primary_rmcp_port[2];
    unsigned char primary_rmcp_port_supported;
    unsigned char secondary_rmcp_port[2];
    unsigned char secondary_rmcp_port_supported;
    unsigned char bmc_generated_arps;
    unsigned char bmc_generated_garps;
    unsigned char arp_control_supported;
    unsigned char garp_interval;
    unsigned char garp_interval_supported;
    unsigned char default_gateway_ip_addr[4];
    unsigned char default_gateway_mac_addr[6];
    unsigned char default_gateway_mac_addr_supported;
    unsigned char backup_gateway_ip_addr[4];
    unsigned char backup_gateway_ip_addr_supported;
    unsigned char backup_gateway_mac_addr[6];
    unsigned char backup_gateway_mac_addr_supported;
    unsigned char community_string[18];

    unsigned char num_alert_destinations;
    alert_dest_type_t *alert_dest_type;
    alert_dest_addr_t *alert_dest_addr;
};

typedef struct lanparms_s lanparms_t;
struct lanparms_s
{
    unsigned int valid : 1;
    unsigned int optional_offset : 8;
    unsigned int length : 8;
    unsigned int offset : 8;
    /* Returns err. */
    int (*get_handler)(ipmi_lan_config_t *lanc, lanparms_t *lp, int err,
		       unsigned char *data);
    /* NULL if parameter is read-only */
    void (*set_handler)(ipmi_lan_config_t *lanc, lanparms_t *lp,
			unsigned char *data);
};

/* Byte array */
static int gba(ipmi_lan_config_t *lanc, lanparms_t *lp, int err,
	       unsigned char *data)
{
    unsigned char *opt = NULL;

    if (lp->optional_offset)
	opt = ((unsigned char *) lanc) + lp->optional_offset;

    if (err) {
	if (opt && (err == IPMI_IPMI_ERR_VAL(0x80))) {
	    *opt = 0;
	    return 0;
	}
	return err;
    }

    data++; /* Skip over the revision byte. */

    if (opt)
	*opt = 1;

    memcpy(((unsigned char *) lanc)+lp->offset, data, lp->length);
    return 0;
}

static void sba(ipmi_lan_config_t *lanc, lanparms_t *lp, unsigned char *data)
{
    memcpy(data, ((unsigned char *) lanc)+lp->offset, lp->length);
}

#define GETAUTH(d, v) \
	(d)->oem = (((v) >> 5) & 1); \
	(d)->straight = (((v) >> 4) & 1); \
	(d)->md5 = (((v) >> 2) & 1); \
	(d)->md2 = (((v) >> 1) & 1); \
	(d)->none = (((v) >> 0) & 1);

#define SETAUTH(d) \
	(((d)->oem << 5) \
	 | ((d)->straight << 4) \
	 | ((d)->md5 << 2) \
	 | ((d)->md2 << 1) \
	 | (d)->none)

/* Authentication Support */
static int gas(ipmi_lan_config_t *lanc, lanparms_t *lp, int err,
	       unsigned char *data)
{
    if (err)
	return err;

    data++; /* Skip over the revision byte. */

    GETAUTH(&lanc->auth_support, *data);
    return 0;
}

/* Authentication Enables */
static int gae(ipmi_lan_config_t *lanc, lanparms_t *lp, int err,
	       unsigned char *data)
{
    int i;

    if (err)
	return err;

    data++; /* Skip over the revision byte. */

    for (i=0; i<5; i++)
	GETAUTH(&(lanc->auth_enable[i]), data[i]);
    return 0;
}

static void sae(ipmi_lan_config_t *lanc, lanparms_t *lp, unsigned char *data)
{
    int i;

    for (i=0; i<5; i++)
	data[i] = SETAUTH(&(lanc->auth_enable[i]));
}

/* IPV4 Header Parms */
static int ghp(ipmi_lan_config_t *lanc, lanparms_t *lp, int err,
	       unsigned char *data)
{
    unsigned char *opt = NULL;

    if (lp->optional_offset)
	opt = ((unsigned char *) lanc) + lp->optional_offset;

    if (err) {
	if (opt && (err == IPMI_IPMI_ERR_VAL(0x80))) {
	    *opt = 0;
	    return 0;
	}
	return err;
    }

    data++; /* Skip over the revision byte. */

    if (opt)
	*opt = 1;

    lanc->ipv4_ttl = data[0];
    lanc->ipv4_flags = (data[1] >> 5) & 0x7;
    lanc->ipv4_precedence = (data[2] >> 5) & 0x7;
    lanc->ipv4_tos = (data[2] >> 1) & 0xf;
    return 0;
}

static void shp(ipmi_lan_config_t *lanc, lanparms_t *lp, unsigned char *data)
{
    data[0] = lanc->ipv4_ttl;
    data[1] = lanc->ipv4_flags << 5;
    data[2] = (lanc->ipv4_precedence << 5) | (lanc->ipv4_tos << 1);
}

/* Generated ARP control */
static int gga(ipmi_lan_config_t *lanc, lanparms_t *lp, int err,
	       unsigned char *data)
{
    unsigned char *opt = NULL;

    if (lp->optional_offset)
	opt = ((unsigned char *) lanc) + lp->optional_offset;

    if (err) {
	if (opt && (err == IPMI_IPMI_ERR_VAL(0x80))) {
	    *opt = 0;
	    return 0;
	}
	return err;
    }

    data++; /* Skip over the revision byte. */

    if (opt)
	*opt = 1;

    lanc->bmc_generated_arps = (data[0] >> 1) & 1;
    lanc->bmc_generated_garps = (data[0] >> 0) & 1;
    return 0;
}

static void sga(ipmi_lan_config_t *lanc, lanparms_t *lp, unsigned char *data)
{
    data[0] = (lanc->bmc_generated_arps << 1) | lanc->bmc_generated_garps;
}

/* Number of Destinations */
static int gnd(ipmi_lan_config_t *lanc, lanparms_t *lp, int err,
	       unsigned char *data)
{
    unsigned int num;

    if (err)
	return err;

    data++; /* Skip over the revision byte. */

    lanc->num_alert_destinations = 0;
    num = data[0] & 0xf;
    if (lanc->alert_dest_type != NULL)
	ipmi_mem_free(lanc->alert_dest_type);
    lanc->alert_dest_type = NULL;
    if (lanc->alert_dest_addr != NULL)
	ipmi_mem_free(lanc->alert_dest_addr);
    lanc->alert_dest_addr = NULL;

    if (num == 0)
	return 0;

    lanc->alert_dest_type = ipmi_mem_alloc(sizeof(alert_dest_type_t) * num);
    if (!lanc->alert_dest_type)
	return ENOMEM;

    lanc->alert_dest_addr = ipmi_mem_alloc(sizeof(alert_dest_addr_t) * num);
    if (!lanc->alert_dest_addr)
	return ENOMEM;

    lanc->num_alert_destinations = num;

    return 0;
}

/* LAN Destination Type */
static int gdt(ipmi_lan_config_t *lanc, lanparms_t *lp, int err,
	       unsigned char *data)
{
    int               sel;
    alert_dest_type_t *dt;

    if (err)
	return err;

    data++; /* Skip over the revision byte. */

    sel = data[0] & 0xf;
    if (sel > lanc->num_alert_destinations)
	return 0; /* Another error check will get this later. */

    dt = lanc->alert_dest_type + sel;
    dt->alert_ack = (data[1] >> 7) & 0x1;
    dt->dest_type = data[1] & 0x7;
    dt->alert_retry_interval = data[2];
    dt->max_alert_retries = data[3] & 0x7;
    
    return 0;
}

/* This one is special, the sel is in data[0]. */
static void sdt(ipmi_lan_config_t *lanc, lanparms_t *lp, unsigned char *data)
{
    int               sel;
    alert_dest_type_t *dt;

    sel = data[0] & 0xf;
    dt = lanc->alert_dest_type + sel;

    data[1] = (dt->alert_ack << 7) | dt->dest_type;
    data[2] = dt->alert_retry_interval;
    data[3] = dt->max_alert_retries;
}

/* LAN Destination Address */
static int gda(ipmi_lan_config_t *lanc, lanparms_t *lp, int err,
	       unsigned char *data)
{
    int               sel;
    alert_dest_addr_t *da;

    if (err)
	return err;

    data++; /* Skip over the revision byte. */

    sel = data[0] & 0xf;
    if (sel > lanc->num_alert_destinations)
	return 0; /* Another error check will get this later. */

    da = lanc->alert_dest_addr + sel;
    da->dest_format = (data[1] >> 4) & 0xf;
    da->gw_to_use = data[2] & 1;
    memcpy(da->dest_ip_addr, data+3, 4);
    memcpy(da->dest_mac_addr, data+7, 6);
    
    return 0;
}

/* This one is special, the sel is in data[0]. */
static void sda(ipmi_lan_config_t *lanc, lanparms_t *lp, unsigned char *data)
{
    int               sel;
    alert_dest_addr_t *da;

    sel = data[0] & 0xf;
    da = lanc->alert_dest_addr + sel;

    data[1] = da->dest_format << 4;
    data[2] = da->gw_to_use;
    memcpy(data+3, da->dest_ip_addr, 4);
    memcpy(data+7, da->dest_mac_addr, 6);
}

#define OFFSET_OF(x) (((unsigned char *) &(((ipmi_lan_config_t *) NULL)->x)) \
                      - ((unsigned char *) NULL))

#define NUM_LANPARMS 20
static lanparms_t lanparms[NUM_LANPARMS] =
{
    { 0, 0, 0, 0, NULL, NULL }, /* IPMI_LANPARM_SET_IN_PROGRESS		     */
    { 1, 0, 1, 0, gas,  NULL }, /* IPMI_LANPARM_AUTH_TYPE_SUPPORT	     */
    { 1, 0, 5, 0, gae,  sae  }, /* IPMI_LANPARM_AUTH_TYPE_ENABLES	     */
#undef F
#define F OFFSET_OF(ip_addr)
    { 1, 0, 4, F, gba,  sba  }, /* IPMI_LANPARM_IP_ADDRESS		     */
#undef F
#define F OFFSET_OF(ip_addr_source)
    { 1, 0, 1, F, gba,  sba  }, /* IPMI_LANPARM_IP_ADDRESS_SRC		     */
#undef F
#define F OFFSET_OF(mac_addr)
    { 1, 0, 6, F, gba,  sba  }, /* IPMI_LANPARM_MAX_ADDRESS		     */
#undef F
#define F OFFSET_OF(subnet_mask)
    { 1, 0, 4, F, gba,  sba  }, /* IPMI_LANPARM_SUBNET_MASK		     */
#undef S
#define S OFFSET_OF(ipv4_header_parms_supported)
    { 1, S, 3, 0, ghp,  shp  }, /* IPMI_LANPARM_IPV4_HDR_PARMS		     */
#undef F
#define F OFFSET_OF(primary_rmcp_port)
#undef S
#define S OFFSET_OF(primary_rmcp_port_supported)
    { 1, S, 2, F, gba,  sba  }, /* IPMI_LANPARM_PRIMARY_RMCP_PORT	     */
#undef F
#define F OFFSET_OF(secondary_rmcp_port)
#undef S
#define S OFFSET_OF(secondary_rmcp_port_supported)
    { 1, S, 2, F, gba,  sba  }, /* IPMI_LANPARM_SECONDARY_RMCP_PORT	     */
#undef S
#define S OFFSET_OF(arp_control_supported)
    { 1, S, 1, 0, gga,  sga  }, /* IPMI_LANPARM_BMC_GENERATED_ARP_CNTL	     */
#undef F
#define F OFFSET_OF(garp_interval)
#undef S
#define S OFFSET_OF(garp_interval_supported)
    { 1, S, 1, F, gba,  sba  }, /* IPMI_LANPARM_GRATUIDOUS_ARP_INTERVAL      */
#undef F
#define F OFFSET_OF(default_gateway_ip_addr)
    { 1, 0, 4, F, gba,  sba  }, /* IPMI_LANPARM_DEFAULT_GATEWAY_ADDR	     */
#undef F
#define F OFFSET_OF(default_gateway_mac_addr)
#undef S
#define S OFFSET_OF(default_gateway_mac_addr_supported)
    { 1, S, 6, F, gba,  sba  }, /* IPMI_LANPARM_DEFAULT_GATEWAY_MAC_ADDR     */
#undef F
#define F OFFSET_OF(backup_gateway_ip_addr)
#undef S
#define S OFFSET_OF(backup_gateway_ip_addr_supported)
    { 1, S, 4, F, gba,  sba  }, /* IPMI_LANPARM_BACKUP_GATEWAY_ADDR	     */
#undef F
#define F OFFSET_OF(backup_gateway_mac_addr)
#undef S
#define S OFFSET_OF(backup_gateway_mac_addr_supported)
    { 1, S, 6, F, gba,  sba  }, /* IPMI_LANPARM_BACKUP_GATEWAY_MAC_ADDR      */
#undef F
#define F OFFSET_OF(community_string)
    { 1, 0, 18, F, gba, sba  }, /* IPMI_LANPARM_COMMUNITY_STRING	     */
    { 1, 0, 1, 0, gnd,  NULL }, /* IPMI_LANPARM_NUM_DESTINATIONS	     */
    { 1, 0, 4, 0, gdt,  sdt  }, /* IPMI_LANPARM_DEST_TYPE		     */
    { 1, 0, 13, 0, gda, sda  }, /* IPMI_LANPARM_DEST_ADDR		     */
};

static void
err_lock_cleared(ipmi_lanparm_t *lanparm,
		 int            err,
		 void           *cb_data)
{
    ipmi_lan_config_t *lanc = cb_data;

    lanc->done(lanparm, lanc->err, NULL, lanc->cb_data);
    ipmi_lan_free_config(lanc);
}

static void
got_parm(ipmi_lanparm_t    *lanparm,
	 int               err,
	 unsigned char     *data,
	 unsigned int      data_len,
	 void              *cb_data)
{
    ipmi_lan_config_t *lanc = cb_data;
    lanparms_t        *lp = &(lanparms[lanc->curr_parm]);

    /* Check the length, and don't forget the revision byte must be added. */
    if ((!err) && (data_len < (lp->length+1))) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lanparm_got_parm:"
		 " Invalid data length on parm %d was %d, should have been %d",
		 lanc->curr_parm, data_len, lp->length+1);
	err = EINVAL;
	goto done;
    }

    err = lp->get_handler(lanc, lp, err, data);
    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lanparm_got_parm: Error fetching parm %d: %x",
		 lanc->curr_parm, err);
	goto done;
    }

 next_parm:
    switch (lanc->curr_parm) {
    case IPMI_LANPARM_NUM_DESTINATIONS:
	lanc->curr_parm++;
	if (lanc->num_alert_destinations == 0)
	    goto done;
	lanc->curr_sel = 0;
	break;

    case IPMI_LANPARM_DEST_TYPE:
	if ((data[1] & 0xf) != lanc->curr_sel) {
	    /* Yikes, wrong selector came back! */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "ipmi_lanparm_got_parm: Error fetching dest type %d,"
		     " wrong selector came back, expecting %d, was %d",
		     lanc->curr_parm, lanc->curr_sel, data[1] & 0xf);
	    err = EINVAL;
	    goto done;
	}
	lanc->curr_sel++;
	if (lanc->curr_sel >= lanc->num_alert_destinations) {
	    lanc->curr_parm++;
	    lanc->curr_sel = 0;
	}
	break;

    case IPMI_LANPARM_DEST_ADDR:
	if ((data[1] & 0xf) != lanc->curr_sel) {
	    /* Yikes, wrong selector came back! */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "ipmi_lanparm_got_parm: Error fetching dest addr %d,"
		     " wrong selector came back, expecting %d, was %d",
		     lanc->curr_parm, lanc->curr_sel, data[1] & 0xf);
	    err = EINVAL;
	    goto done;
	}
	lanc->curr_sel++;
	if (lanc->curr_sel >= lanc->num_alert_destinations)
	    goto done;
	break;

    default:
	lanc->curr_parm++;
    }

    lp = &(lanparms[lanc->curr_parm]);
    if (!lp->valid)
	goto next_parm;

    err = ipmi_lanparm_get_parm(lanparm, lanc->curr_parm, lanc->curr_sel, 0,
				got_parm, lanc);
    if (err)
	goto done;

    return;

 done:
    if (err) {
	unsigned char data[1];

	ipmi_log(IPMI_LOG_ERR_INFO,
		 "lanparm.c(got_parm): Error trying to get parm %d: %x",
		 lanc->curr_parm, err);
	lanc->err = err;
	/* Clear the lock */
	data[0] = 0;
	err = ipmi_lanparm_set_parm(lanparm, 0, data, 1,
				    err_lock_cleared, lanc);
	if (err) {
	    ipmi_lan_free_config(lanc);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "lan.c(got_parm): Error trying to clear lock: %x",
		     err);
	    lanc->done(lanparm, lanc->err, NULL, lanc->cb_data);
	    ipmi_lan_free_config(lanc);
	}
    } else
	lanc->done(lanparm, 0, lanc, lanc->cb_data);
}

static void 
lock_done(ipmi_lanparm_t *lanparm,
	  int            err,
	  void           *cb_data)
{
    ipmi_lan_config_t *lanc = cb_data;
    int               rv;

    if (err == IPMI_IPMI_ERR_VAL(0x80)) {
	/* Lock is not supported, just mark it and go on. */
	lanc->lock_supported = 0;
    } else if (err == IPMI_IPMI_ERR_VAL(0x81)) {
	/* Someone else has the lock, return EAGAIN. */
	lanc->done(lanparm, err, NULL, lanc->cb_data);
	ipmi_lan_free_config(lanc);
	return;
    } else if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "lan.c(lock_done): Error trying to lock the LAN"
		 " parms: %x",
		 err);
	lanc->done(lanparm, err, NULL, lanc->cb_data);
	ipmi_lan_free_config(lanc);
	return;
    }

    lanc->lan_locked = 1;

    rv = ipmi_lanparm_get_parm(lanparm, lanc->curr_parm, lanc->curr_sel, 0,
			       got_parm, lanc);
    if (rv) {
	unsigned char data[1];
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "lan.c(lock_done): Error trying to get parms: %x",
		 err);

	lanc->err = rv;
	/* Clear the lock */
	data[0] = 0;
	rv = ipmi_lanparm_set_parm(lanparm, 0, data, 1,
				   err_lock_cleared, lanc);
	if (rv) {
	    ipmi_lan_free_config(lanc);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "lan.c(lock_done): Error trying to clear lock: %x",
		     err);
	    lanc->done(lanparm, lanc->err, NULL, lanc->cb_data);
	    ipmi_lan_free_config(lanc);
	}
    }
}

int ipmi_lan_get_config(ipmi_lanparm_t         *lanparm,
			ipmi_lan_get_config_cb done,
			void                   *cb_data)
{
    ipmi_lan_config_t *lanc;
    int               rv;
    unsigned char     data[1];

    lanc = ipmi_mem_alloc(sizeof(*lanc));
    if (!lanc)
	return ENOMEM;
    memset(lanc, 0, sizeof(*lanc));

    lanc->curr_parm = 1;
    lanc->curr_sel = 0;
    lanc->done = done;
    lanc->cb_data = cb_data;

    /* First grab the lock */
    data[0] = 1; /* Set in progress. */
    rv = ipmi_lanparm_set_parm(lanparm, 0, data, 1, lock_done, lanc);
    if (rv)
	ipmi_lan_free_config(lanc);

    return rv;
}

static void 
set_clear(ipmi_lanparm_t *lanparm,
	 int            err,
	 void           *cb_data)
{
    ipmi_lan_config_t *lanc = cb_data;

    if (lanc->err)
	err = lanc->err;
    lanc->set_done(lanparm, err, lanc->cb_data);
    ipmi_lan_free_config(lanc);
}

static void 
commit_done(ipmi_lanparm_t *lanparm,
	    int            err,
	    void           *cb_data)
{
    ipmi_lan_config_t *lanc = cb_data;
    unsigned char     data[1];
    int               rv;

    /* Note that we ignore the error.  The commit done is optional,
       and must return an error if it is optional, so we just ignore
       the error and clear the field here. */

    /* Commit is done.  The IPMI spec says that it goes into the
       set-in-progress state after this, so we need to clear it. */

    data[0] = 0;
    rv = ipmi_lanparm_set_parm(lanparm, 0, data, 1, set_clear, lanc);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "ipmi_lanparm_commit_done: Error trying to clear the set in"
		 " progress: %x",
		 rv);
	set_clear(lanparm, err, lanc);
    }
}

static void 
set_done(ipmi_lanparm_t *lanparm,
	 int            err,
	 void           *cb_data)
{
    ipmi_lan_config_t *lanc = cb_data;
    unsigned char     data[MAX_IPMI_DATA_SIZE];
    lanparms_t        *lp = &(lanparms[lanc->curr_parm]);

    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Error setting lan parm %d: %x", lanc->curr_parm, err);
	goto done;
    }

 next_parm:
    switch (lanc->curr_parm) {
    case IPMI_LANPARM_NUM_DESTINATIONS:
	lanc->curr_parm++;
	if (lanc->num_alert_destinations == 0)
	    goto done;
	lanc->curr_sel = 0;
	data[0] = lanc->curr_sel;
	break;

    case IPMI_LANPARM_DEST_TYPE:
	lanc->curr_sel++;
	if (lanc->curr_sel >= lanc->num_alert_destinations) {
	    lanc->curr_parm++;
	    lanc->curr_sel = 0;
	}
	data[0] = lanc->curr_sel;
	break;

    case IPMI_LANPARM_DEST_ADDR:
	if ((data[0] & 0xf) != lanc->curr_sel) {
	    /* Yikes, wrong selector came back! */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "ipmi_lanparm_got_parm: Error fetching dest addr %d,"
		     " wrong selector came back, expecting %d, was %d",
		     lanc->curr_parm, lanc->curr_sel, data[0] & 0xf);
	}
	lanc->curr_sel++;
	if (lanc->curr_sel >= lanc->num_alert_destinations)
	    goto done;
	data[0] = lanc->curr_sel;
	break;

    default:
	lanc->curr_parm++;
    }

    lp = &(lanparms[lanc->curr_parm]);
    if ((!lp->valid) || (!lp->set_handler)
	|| (lp->optional_offset
	    && !(((unsigned char *) lanc)[lp->optional_offset])))
    {
	/* The parameter is read-only or not supported, just go on. */
	goto next_parm;
    }

    lp->set_handler(lanc, lp, data);
    err = ipmi_lanparm_set_parm(lanparm, lanc->curr_parm,
				data, lp->length, set_done, lanc);
    if (err)
	goto done;

    return;

 done:
    if (err) {
	data[0] = 0; /* Don't commit the parameters. */
	lanc->err = err;
	err = ipmi_lanparm_set_parm(lanparm, 0, data, 1, set_clear, lanc);
    } else {
	data[0] = 2; /* Commit the parameters. */
	err = ipmi_lanparm_set_parm(lanparm, 0, data, 1, commit_done, lanc);
    }
    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "ipmi_lanparm_got_parm: Error trying to clear the set in"
		 " progress: %x",
		 err);
	set_clear(lanparm, err, lanc);
    }
}

int
ipmi_lan_set_config(ipmi_lanparm_t       *lanparm,
		    ipmi_lan_config_t    *olanc,
		    ipmi_lanparm_done_cb done,
		    void                 *cb_data)
{
    ipmi_lan_config_t *lanc;
    unsigned char     data[1];
    lanparms_t        *lp;
    int               rv;

    if (olanc->my_lan != lanparm)
	return EINVAL;

    if (!olanc->lan_locked)
	return EINVAL;

    lanc = ipmi_mem_alloc(sizeof(*lanc));
    if (!lanc)
	return ENOMEM;

    *lanc = *olanc;
    lanc->alert_dest_type = NULL;
    lanc->alert_dest_addr = NULL;
    lanc->err = 0;
    lanc->lan_locked = 0; /* Set this here, since we will unlock it,
			     but we don't want the free operation to
			     attempt an unlock */

    if (lanc->num_alert_destinations) {
	lanc->alert_dest_type
	    = ipmi_mem_alloc(sizeof(alert_dest_type_t)
			     * lanc->num_alert_destinations);
	if (!lanc->alert_dest_type) {
	    rv = ENOMEM;
	    goto out;
	}
	memcpy(lanc->alert_dest_type, olanc->alert_dest_type, 
	       sizeof(alert_dest_type_t) * lanc->num_alert_destinations);

	lanc->alert_dest_addr
	    = ipmi_mem_alloc(sizeof(alert_dest_addr_t)
			     * lanc->num_alert_destinations);
	if (!lanc->alert_dest_addr) {
	    rv = ENOMEM;
	    goto out;
	}
	memcpy(lanc->alert_dest_addr, olanc->alert_dest_addr, 
	       sizeof(alert_dest_type_t) * lanc->num_alert_destinations);
    }

    lanc->curr_parm = 0;
    lanc->curr_sel = 0;
    lanc->set_done = done;
    lanc->cb_data = cb_data;

    lp = &(lanparms[lanc->curr_parm]);
    lp->set_handler(lanc, lp, data);
    rv = ipmi_lanparm_set_parm(lanparm, lanc->curr_parm,
				data, lp->length, set_done, lanc);
 out:
    if (rv) {
	ipmi_lan_free_config(lanc);
    } else {
	/* The old config no longer holds the lock. */
	olanc->lan_locked = 0;
    }
    return rv;
}

typedef struct clear_lock_s
{
    ipmi_lanparm_done_cb done;
    void                 *cb_data;
    
} clear_lock_t;

static void 
lock_cleared(ipmi_lanparm_t *lanparm,
	     int            err,
	     void           *cb_data)
{
    clear_lock_t *cl = cb_data;

    cl->done(lanparm, err, cl->cb_data);

    ipmi_mem_free(cl);
}

int
ipmi_lan_clear_lock(ipmi_lanparm_t       *lanparm,
		    ipmi_lan_config_t    *lanc,
		    ipmi_lanparm_done_cb done,
		    void                 *cb_data)
{
    unsigned char data[1];
    int           rv;
    clear_lock_t  *cl;

    if (lanc) {
	if (lanc->my_lan != lanparm)
	    return EINVAL;

	if (!lanc->lan_locked)
	    return EINVAL;
    }

    cl = ipmi_mem_alloc(sizeof(*cl));
    if (!cl)
	return ENOMEM;

    data[0] = 0; /* Clear the lock. */
    rv = ipmi_lanparm_set_parm(lanparm, 0, data, 1, lock_cleared, cl);
    if (rv) {
	ipmi_mem_free(cl);
    } else if (lanc) {
	lanc->lan_locked = 0;
    }

    return rv;
}

void
ipmi_lan_free_config(ipmi_lan_config_t *lanc)
{
    if (lanc->alert_dest_type != NULL)
	ipmi_mem_free(lanc->alert_dest_type);
    if (lanc->alert_dest_addr != NULL)
	ipmi_mem_free(lanc->alert_dest_addr);
    ipmi_mem_free(lanc);
}

#define AUTH_SUP(n) \
unsigned int \
ipmi_lanconfig_get_support_auth_ ## n(ipmi_lan_config_t *lanc) \
{ \
    return lanc->auth_support.n; \
}

AUTH_SUP(oem)
AUTH_SUP(straight)
AUTH_SUP(md5)
AUTH_SUP(md2)
AUTH_SUP(none)

#define AUTH_ENAB(n) \
int \
ipmi_lanconfig_get_enable_auth_ ## n(ipmi_lan_config_t *lanc, \
				     unsigned int user, \
				     unsigned int *val) \
{ \
    if (user >= 5) \
	return EINVAL; \
    *val = lanc->auth_support.n; \
    return 0; \
} \
int \
ipmi_lanconfig_set_enable_auth_ ## n(ipmi_lan_config_t *lanc, \
				     unsigned int user, \
				     unsigned int val) \
{ \
    if (user >= 5) \
	return EINVAL; \
    lanc->auth_support.n = (val != 0); \
    return 0; \
}

AUTH_ENAB(oem)
AUTH_ENAB(straight)
AUTH_ENAB(md5)
AUTH_ENAB(md2)
AUTH_ENAB(none)

#define LP_BYTE_PARM(n) \
unsigned int \
ipmi_lanconfig_get_ ## n(ipmi_lan_config_t *lanc) \
{ \
    return lanc->n; \
} \
int \
ipmi_lanconfig_set_ ## n(ipmi_lan_config_t *lanc, \
			 unsigned int      val) \
{ \
    lanc->n = val; \
    return 0; \
}

#define LP_ARRAY_PARM(n, l) \
int \
ipmi_lanconfig_get_ ## n(ipmi_lan_config_t *lanc, \
			 unsigned char     *data, \
			 unsigned int      *data_len) \
{ \
    if (*data_len < l) \
        return EMSGSIZE; \
    memcpy(data, lanc->n, l); \
    *data_len = l; \
    return 0; \
} \
int \
ipmi_lanconfig_set_ ## n(ipmi_lan_config_t *lanc, \
			 unsigned char     *data, \
			 unsigned int      data_len) \
{ \
    if (data_len != l) \
        return EMSGSIZE; \
    memcpy(lanc->n, data, l); \
    return 0; \
}

LP_ARRAY_PARM(ip_addr, 4)
LP_BYTE_PARM(ip_addr_source);
LP_ARRAY_PARM(mac_addr, 6)
LP_ARRAY_PARM(subnet_mask, 4)
LP_ARRAY_PARM(default_gateway_ip_addr, 4)
LP_ARRAY_PARM(community_string, 18)

#define LP_ARRAY_PARM_SUP(n, l) \
int \
ipmi_lanconfig_get_ ## n(ipmi_lan_config_t *lanc, \
			 unsigned char     *data, \
			 unsigned int      *data_len) \
{ \
    if (! lanc->n ## _supported) \
        return ENOTSUP; \
    if (*data_len < l) \
        return EMSGSIZE; \
    memcpy(data, lanc->n, l); \
    *data_len = l; \
    return 0; \
} \
int \
ipmi_lanconfig_set_ ## n(ipmi_lan_config_t *lanc, \
			 unsigned char     *data, \
			 unsigned int      data_len) \
{ \
    if (! lanc->n ## _supported) \
        return ENOTSUP; \
    if (data_len != l) \
        return EMSGSIZE; \
    memcpy(lanc->n, data, l); \
    return 0; \
}

LP_ARRAY_PARM_SUP(primary_rmcp_port, 4)
LP_ARRAY_PARM_SUP(secondary_rmcp_port, 4)
LP_ARRAY_PARM_SUP(default_gateway_mac_addr, 6)
LP_ARRAY_PARM_SUP(backup_gateway_ip_addr, 4)
LP_ARRAY_PARM_SUP(backup_gateway_mac_addr, 6)

#define LP_BYTE_PARM_SUP(n, s) \
int \
ipmi_lanconfig_get_ ## n(ipmi_lan_config_t *lanc, \
			 unsigned int      *data) \
{ \
    if (! lanc->s) \
        return ENOTSUP; \
    *data = lanc->n; \
    return 0; \
} \
int \
ipmi_lanconfig_set_ ## n(ipmi_lan_config_t *lanc, \
			 unsigned int      data) \
{ \
    if (! lanc->s) \
        return ENOTSUP; \
    lanc->n = data; \
    return 0; \
}

LP_BYTE_PARM_SUP(ipv4_ttl, ipv4_header_parms_supported);
LP_BYTE_PARM_SUP(ipv4_flags, ipv4_header_parms_supported);
LP_BYTE_PARM_SUP(ipv4_precedence, ipv4_header_parms_supported);
LP_BYTE_PARM_SUP(ipv4_tos, ipv4_header_parms_supported);
LP_BYTE_PARM_SUP(bmc_generated_arps, arp_control_supported)
LP_BYTE_PARM_SUP(bmc_generated_garps, arp_control_supported)
LP_BYTE_PARM_SUP(garp_interval, garp_interval_supported)

unsigned int
ipmi_lanconfig_get_num_alert_destinations(ipmi_lan_config_t *lanc)
{
    return lanc->num_alert_destinations;
}

#define LP_BYTE_TAB(s, n) \
int \
ipmi_lanconfig_get_## n(ipmi_lan_config_t *lanc, \
			unsigned int      set, \
			unsigned int      *val) \
{ \
    if (set > lanc->num_alert_destinations) \
	return EINVAL; \
    *val = lanc->s[set].n; \
    return 0; \
} \
int \
ipmi_lanconfig_set_## n(ipmi_lan_config_t *lanc, \
			unsigned int      set, \
			unsigned int      val) \
{ \
    if (set > lanc->num_alert_destinations) \
	return EINVAL; \
    lanc->s[set].n = val; \
    return 0; \
}

#define LP_ARRAY_TAB(s, n, l) \
int \
ipmi_lanconfig_get_## n(ipmi_lan_config_t *lanc, \
			unsigned int      set, \
			unsigned char     *data, \
			unsigned int      *data_len) \
{ \
    if (set > lanc->num_alert_destinations) \
	return EINVAL; \
    if (*data_len < l) \
        return EMSGSIZE; \
    memcpy(data, lanc->s[set].n, l); \
    *data_len = l; \
    return 0; \
} \
int \
ipmi_lanconfig_set_## n(ipmi_lan_config_t *lanc, \
			unsigned int      set, \
			unsigned char     *data, \
			unsigned int      data_len) \
{ \
    if (set > lanc->num_alert_destinations) \
	return EINVAL; \
    if (data_len != l) \
        return EMSGSIZE; \
    memcpy(lanc->s[set].n, data, l); \
    return 0; \
}

LP_BYTE_TAB(alert_dest_type, alert_ack)
LP_BYTE_TAB(alert_dest_type, dest_type)
LP_BYTE_TAB(alert_dest_type, alert_retry_interval)
LP_BYTE_TAB(alert_dest_type, max_alert_retries)

LP_BYTE_TAB(alert_dest_addr, dest_format)
LP_BYTE_TAB(alert_dest_addr, gw_to_use)
LP_ARRAY_TAB(alert_dest_addr, dest_ip_addr, 4)
LP_ARRAY_TAB(alert_dest_addr, dest_mac_addr, 6)
