/*
 * solparm.c
 *
 * MontaVista IPMI code for configuring SoL data
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2006 MontaVista Software Inc.
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
#include <stdio.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_solparm.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_err.h>

#include <OpenIPMI/internal/opq.h>
#include <OpenIPMI/internal/locked_list.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_mc.h>
#include <OpenIPMI/internal/ipmi_int.h>

#define IPMI_SOLPARM_ATTR_NAME "ipmi_solparm"

struct ipmi_solparm_s
{
    ipmi_mcid_t      mc;
    ipmi_domain_id_t domain;
    unsigned char    channel;

    int refcount;

    char name[IPMI_SOLPARM_NAME_LEN];

    unsigned int destroyed : 1;
    unsigned int in_destroy : 1;
    unsigned int locked : 1;
    unsigned int in_list : 1;

    /* Something to call when the destroy is complete. */
    ipmi_solparm_done_cb destroy_handler;
    void                 *destroy_cb_data;

    os_hnd_lock_t *solparm_lock;

    os_handler_t *os_hnd;

    /* We serialize operations through here, since we are dealing with
       a locked resource. */
    opq_t *opq;
};

static int
solparm_attr_init(ipmi_domain_t *domain, void *cb_data, void **data)
{
    locked_list_t *solparml;
    
    solparml = locked_list_alloc(ipmi_domain_get_os_hnd(domain));
    if (!solparml)
	return ENOMEM;

    *data = solparml;
    return 0;
}

static void
solparm_lock(ipmi_solparm_t *solparm)
{
    if (solparm->os_hnd->lock)
	solparm->os_hnd->lock(solparm->os_hnd, solparm->solparm_lock);
}

static void
solparm_unlock(ipmi_solparm_t *solparm)
{
    if (solparm->os_hnd->lock)
	solparm->os_hnd->unlock(solparm->os_hnd, solparm->solparm_lock);
}

static void
solparm_get(ipmi_solparm_t *solparm)
{
    solparm_lock(solparm);
    solparm->refcount++;
    solparm_unlock(solparm);
}

static void internal_destroy_solparm(ipmi_solparm_t *solparm);

static void
solparm_put(ipmi_solparm_t *solparm)
{
    solparm_lock(solparm);
    solparm->refcount--;
    if (solparm->refcount == 0) {
	internal_destroy_solparm(solparm);
	return;
    }
    solparm_unlock(solparm);
}

void
ipmi_solparm_ref(ipmi_solparm_t *solparm)
{
    solparm_get(solparm);
}

void
ipmi_solparm_deref(ipmi_solparm_t *solparm)
{
    solparm_put(solparm);
}

static int
destroy_solparm(void *cb_data, void *item1, void *item2)
{
    ipmi_solparm_t *solparm = item1;

    solparm_lock(solparm);
    solparm->in_list = 1;
    solparm_unlock(solparm);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
solparm_attr_destroy(void *cb_data, void *data)
{
    locked_list_t *solparml = data;

    locked_list_iterate(solparml, destroy_solparm, NULL);
    locked_list_destroy(solparml);
}

typedef struct iterate_solparms_info_s
{
    ipmi_solparm_ptr_cb handler;
    void                *cb_data;
} iterate_solparms_info_t;

static int
solparms_handler(void *cb_data, void *item1, void *item2)
{
    iterate_solparms_info_t *info = cb_data;
    info->handler(item1, info->cb_data);
    solparm_put(item1);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
solparms_prefunc(void *cb_data, void *item1, void *item2)
{
    ipmi_solparm_t *solparm = item1;
    solparm_get(solparm);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_solparm_iterate_solparms(ipmi_domain_t       *domain,
			      ipmi_solparm_ptr_cb handler,
			      void                *cb_data)
{
    iterate_solparms_info_t info;
    ipmi_domain_attr_t      *attr;
    locked_list_t           *solparms;
    int                     rv;

    rv = ipmi_domain_find_attribute(domain, IPMI_SOLPARM_ATTR_NAME,
				    &attr);
    if (rv)
	return;
    solparms = ipmi_domain_attr_get_data(attr);

    info.handler = handler;
    info.cb_data = cb_data;
    locked_list_iterate_prefunc(solparms, solparms_prefunc,
				solparms_handler, &info);
    ipmi_domain_attr_put(attr);
}

ipmi_mcid_t
ipmi_solparm_get_mc_id(ipmi_solparm_t *solparm)
{
    return solparm->mc;
}

unsigned int
ipmi_solparm_get_channel(ipmi_solparm_t *solparm)
{
    return solparm->channel;
}

int
ipmi_solparm_get_name(ipmi_solparm_t *solparm, char *name, int length)
{
    int  slen;

    if (length <= 0)
	return 0;

    /* Never changes, no lock needed. */
    slen = strlen(solparm->name);
    if (slen == 0) {
	if (name)
	    *name = '\0';
	goto out;
    }

    if (name) {
	memcpy(name, solparm->name, slen);
	name[slen] = '\0';
    }
 out:
    return slen;
}

static int
check_solparm_response_param(ipmi_solparm_t *solparm,
			     ipmi_mc_t      *mc,
			     ipmi_msg_t     *rsp,
			     int	    len,
			     char	    *func_name)
{
    if (solparm->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssolparm.c(%s): "
		 "SOLPARM was destroyed while an operation was in progress",
		 MC_NAME(mc), func_name);
	return ECANCELED;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssolparm.c(%s): "
		 "MC went away while SOLPARM op was in progress",
		 MC_NAME(mc), func_name);
	return ECANCELED;
    }

    if (rsp->data[0] != 0) {
#if 0
	/* Sometimes this comes in and is valid (like when writing
	   parm 0 to value 2), just ignore it. */
	/* We ignore 0x80, since that may be a valid error return for an
	   unsupported parameter.  We also ignore 0x82, just to avoid
	   extraneous errors. */
	if ((rsp->data[0] != 0x80) && (rsp->data[0] != 0x82))
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%ssolparm.c(%s): "
		     "IPMI error from SOLPARM capabilities fetch: %x",
		     MC_NAME(mc), func_name, rsp->data[0]);
#endif
	return IPMI_IPMI_ERR_VAL(rsp->data[0]);
    }

    if (rsp->data_len < len) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		"%ssolparm.c(%s): SOLPARM capabilities too short",
		 MC_NAME(mc), func_name);
	return EINVAL;
    }
    return 0;
}

int
ipmi_solparm_alloc(ipmi_mc_t      *mc,
		   unsigned int   channel,
		   ipmi_solparm_t **new_solparm)
{
    ipmi_solparm_t     *solparm = NULL;
    int                rv = 0;
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    int                p, len;
    locked_list_t      *solparml;
    ipmi_domain_attr_t *attr;

    CHECK_MC_LOCK(mc);

    rv = ipmi_domain_register_attribute(domain, IPMI_SOLPARM_ATTR_NAME,
					solparm_attr_init,
					solparm_attr_destroy,
					NULL,
					&attr);
    if (rv)
	return rv;
    solparml = ipmi_domain_attr_get_data(attr);

    solparm = ipmi_mem_alloc(sizeof(*solparm));
    if (!solparm) {
	rv = ENOMEM;
	goto out;
    }
    memset(solparm, 0, sizeof(*solparm));

    solparm->refcount = 1;
    solparm->in_list = 1;
    solparm->mc = ipmi_mc_convert_to_id(mc);
    solparm->domain = ipmi_domain_convert_to_id(domain);
    len = sizeof(solparm->name);
    p = ipmi_domain_get_name(domain, solparm->name, len);
    len -= p;
    snprintf(solparm->name+p, len, ".%d", ipmi_domain_get_unique_num(domain));
    solparm->os_hnd = ipmi_domain_get_os_hnd(domain);
    solparm->solparm_lock = NULL;
    solparm->channel = channel & 0xf;

    solparm->opq = opq_alloc(solparm->os_hnd);
    if (!solparm->opq) {
	rv = ENOMEM;
	goto out;
    }

    if (solparm->os_hnd->create_lock) {
	rv = solparm->os_hnd->create_lock(solparm->os_hnd,
					  &solparm->solparm_lock);
	if (rv)
	    goto out;
    }

    if (! locked_list_add(solparml, solparm, NULL)) {
	rv = ENOMEM;
	goto out;
    }

 out:
    if (rv) {
	if (solparm) {
	    if (solparm->opq)
		opq_destroy(solparm->opq);
	    if (solparm->solparm_lock)
		solparm->os_hnd->destroy_lock(solparm->os_hnd,
					      solparm->solparm_lock);
	    ipmi_mem_free(solparm);
	}
    } else {
	*new_solparm = solparm;
    }
    ipmi_domain_attr_put(attr);
    return rv;
}

static void
internal_destroy_solparm(ipmi_solparm_t *solparm)
{
    solparm->in_destroy = 1;

    /* We don't have to have a valid ipmi to destroy a solparm, they
       are designed to live after the ipmi has been destroyed. */

    if (solparm->in_list) {
	int                rv;
	ipmi_domain_attr_t *attr;
	locked_list_t      *solparml;

	rv = ipmi_domain_id_find_attribute(solparm->domain,
					   IPMI_SOLPARM_ATTR_NAME,
					   &attr);
	if (!rv) {
	    solparm->refcount++;
	    solparm->in_list = 0;
	    solparm_unlock(solparm);
	    solparml = ipmi_domain_attr_get_data(attr);

	    locked_list_remove(solparml, solparm, NULL);
	    ipmi_domain_attr_put(attr);
	    solparm_lock(solparm);
	    /* While we were unlocked, someone may have come in and
	       grabbed the solparm by iterating the list of solparms.
	       That's ok, we just let them handle the destruction
	       since this code will not be entered again. */
	    if (solparm->refcount != 1) {
		solparm->refcount--;
		solparm_unlock(solparm);
		return;
	    }
	}
    }
    solparm_unlock(solparm);

    if (solparm->opq)
	opq_destroy(solparm->opq);

    if (solparm->solparm_lock)
	solparm->os_hnd->destroy_lock(solparm->os_hnd, solparm->solparm_lock);

    /* Do this after we have gotten rid of all external dependencies,
       but before it is free. */
    if (solparm->destroy_handler)
	solparm->destroy_handler(solparm, 0, solparm->destroy_cb_data);

    ipmi_mem_free(solparm);
}

int
ipmi_solparm_destroy(ipmi_solparm_t       *solparm,
		     ipmi_solparm_done_cb done,
		     void                 *cb_data)

{
    solparm_lock(solparm);
    if (solparm->in_list) {
	int                rv;
	ipmi_domain_attr_t *attr;
	locked_list_t      *solparml;

	solparm->in_list = 0;
	rv = ipmi_domain_id_find_attribute(solparm->domain,
					   IPMI_SOLPARM_ATTR_NAME,
					   &attr);
	if (!rv) {
	    solparm_unlock(solparm);
	    solparml = ipmi_domain_attr_get_data(attr);

	    locked_list_remove(solparml, solparm, NULL);
	    ipmi_domain_attr_put(attr);
	    solparm_lock(solparm);
	}
    }

    if (solparm->destroyed) {
	solparm_unlock(solparm);
	return EINVAL;
    }
    solparm->destroyed = 1;
    solparm_unlock(solparm);
    solparm->destroy_handler = done;
    solparm->destroy_cb_data = cb_data;

    solparm_put(solparm);
    return 0;
}

typedef struct solparm_fetch_handler_s
{
    ipmi_solparm_t 	*solparm;
    unsigned char       parm;
    unsigned char       set;
    unsigned char       block;
    ipmi_solparm_get_cb handler;
    void                *cb_data;
    unsigned char       *data;
    unsigned int        data_len;
    int                 rv;
} solparm_fetch_handler_t;

/* This should be called with the solparm locked.  It will unlock the solparm
   before returning. */
static void
fetch_complete(ipmi_solparm_t *solparm, int err, solparm_fetch_handler_t *elem)
{
    if (solparm->in_destroy)
	goto out;

    solparm_unlock(solparm);

    if (elem->handler)
	elem->handler(solparm, err, elem->data, elem->data_len, elem->cb_data);

    ipmi_mem_free(elem);

    if (!solparm->destroyed)
	opq_op_done(solparm->opq);

    solparm_put(solparm);
    return;

 out:
    solparm_unlock(solparm);
    solparm_put(solparm);
}


static void
solparm_config_fetched(ipmi_mc_t  *mc,
		       ipmi_msg_t *rsp,
		       void       *rsp_data)
{
    solparm_fetch_handler_t *elem = rsp_data;
    ipmi_solparm_t          *solparm = elem->solparm;
    int                 rv;

    rv = check_solparm_response_param(solparm, mc, rsp, 2,
				      "solparm_config_fetched");

    /* Skip over the completion code. */
    elem->data = rsp->data + 1;
    elem->data_len = rsp->data_len - 1;

    solparm_lock(solparm);
    fetch_complete(solparm, rv, elem);
}

static void
start_config_fetch_cb(ipmi_mc_t *mc, void *cb_data)
{
    solparm_fetch_handler_t *elem = cb_data;
    ipmi_solparm_t          *solparm = elem->solparm;
    unsigned char           data[4];
    ipmi_msg_t              msg;
    int                     rv;

    solparm_lock(solparm);
    if (solparm->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssolparm.c(start_config_fetch_cb): "
		 "SOLPARM was destroyed while an operation was in progress",
		 MC_NAME(mc));
	fetch_complete(solparm, ECANCELED, elem);
	goto out;
    }

    msg.data = data;
    msg.netfn = IPMI_TRANSPORT_NETFN;
    msg.cmd = IPMI_GET_SOL_CONFIGURATION_PARAMETERS;
    data[0] = solparm->channel;
    data[1] = elem->parm;
    data[2] = elem->set;
    data[3] = elem->block;
    msg.data_len = 4;
    rv = ipmi_mc_send_command(mc, 0, &msg, solparm_config_fetched, elem);

    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssolparm.c(start_config_fetch_cb): "
		 "SOLPARM start_config_fetch: could not send cmd: %x",
		 MC_NAME(mc), rv);
	fetch_complete(solparm, ECANCELED, elem);
	goto out;
    }

    solparm_unlock(solparm);
 out:
    return;
}

static int
start_config_fetch(void *cb_data, int shutdown)
{
    solparm_fetch_handler_t *elem = cb_data;
    int                 rv;

    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(start_config_fetch): "
		 "SOLPARM was destroyed while an operation was in progress");
	solparm_lock(elem->solparm);
	fetch_complete(elem->solparm, ECANCELED, elem);
	return OPQ_HANDLER_STARTED;
    }

    /* The read lock must be claimed before the solparm lock to avoid
       deadlock. */
    rv = ipmi_mc_pointer_cb(elem->solparm->mc, start_config_fetch_cb, elem);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(start_config_fetch): "
		 "SOLPARM's MC is not valid");
	solparm_lock(elem->solparm);
	fetch_complete(elem->solparm, rv, elem);
    }
    return OPQ_HANDLER_STARTED;
}

int
ipmi_solparm_get_parm(ipmi_solparm_t      *solparm,
		      unsigned int	  parm,
		      unsigned int	  set,
		      unsigned int	  block,
		      ipmi_solparm_get_cb done,
		      void                *cb_data)
{
    solparm_fetch_handler_t *elem;
    int                 rv = 0;

    if (solparm->destroyed)
	return EINVAL;

    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(ipmi_solparm_get_parm): "
		 "could not allocate the solparm element");
	return ENOMEM;
    }

    elem->handler = done;
    elem->cb_data = cb_data;
    elem->solparm = solparm;
    elem->parm = parm;
    elem->set = set;
    elem->block = block;
    elem->rv = 0;

    if (!opq_new_op(solparm->opq, start_config_fetch, elem, 0))
	rv = ENOMEM;

    if (rv)
	ipmi_mem_free(elem);
    else
	solparm_get(solparm);

    return rv;
}

typedef struct solparm_set_handler_s
{
    ipmi_solparm_t 	 *solparm;
    ipmi_solparm_done_cb handler;
    void                 *cb_data;
    unsigned char        data[MAX_IPMI_DATA_SIZE];
    unsigned int         data_len;
    int                  rv;
} solparm_set_handler_t;

/* This should be called with the solparm locked.  It will unlock the solparm
   before returning. */
static void
set_complete(ipmi_solparm_t *solparm, int err, solparm_set_handler_t *elem)
{
    if (solparm->in_destroy)
	goto out;

    solparm_unlock(solparm);

    if (elem->handler)
	elem->handler(solparm, err, elem->cb_data);

    ipmi_mem_free(elem);

    solparm_lock(solparm);
    if (!solparm->destroyed) {
	solparm_unlock(solparm);
	opq_op_done(solparm->opq);
    } else {
	solparm_unlock(solparm);
    }

    solparm_put(solparm);
    return;

 out:
    solparm_unlock(solparm);
    solparm_put(solparm);
}

static void
solparm_config_set(ipmi_mc_t  *mc,
		   ipmi_msg_t *rsp,
		   void       *rsp_data)
{
    solparm_set_handler_t *elem = rsp_data;
    ipmi_solparm_t        *solparm = elem->solparm;
    int               rv;

    rv = check_solparm_response_param(solparm, mc, rsp, 1,
				      "solparm_config_set");

    solparm_lock(solparm);
    set_complete(solparm, rv, elem);
}

static void
start_config_set_cb(ipmi_mc_t *mc, void *cb_data)
{
    solparm_set_handler_t *elem = cb_data;
    ipmi_solparm_t        *solparm = elem->solparm;
    ipmi_msg_t        msg;
    int               rv;

    solparm_lock(solparm);
    if (solparm->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssolparm.c(start_config_set_cb): "
		 "SOLPARM was destroyed while an operation was in progress",
		 MC_NAME(mc));
	set_complete(solparm, ECANCELED, elem);
	goto out;
    }

    msg.netfn = IPMI_TRANSPORT_NETFN;
    msg.cmd = IPMI_SET_SOL_CONFIGURATION_PARAMETERS;
    msg.data = elem->data;
    msg.data_len = elem->data_len;
    rv = ipmi_mc_send_command(mc, 0, &msg, solparm_config_set, elem);

    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%ssolparm.c(start_config_set_cb): "
		 "SOLPARM start_config_set: could not send cmd: %x",
		 MC_NAME(mc), rv);
	set_complete(solparm, ECANCELED, elem);
	goto out;
    }

    solparm_unlock(solparm);
 out:
    return;
}

static int
start_config_set(void *cb_data, int shutdown)
{
    solparm_set_handler_t *elem = cb_data;
    int                   rv;

    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(start_config_set): "
		 "SOLPARM was destroyed while an operation was in progress");
	solparm_lock(elem->solparm);
	set_complete(elem->solparm, ECANCELED, elem);
	return OPQ_HANDLER_STARTED;
    }

    /* The read lock must be claimed before the solparm lock to avoid
       deadlock. */
    rv = ipmi_mc_pointer_cb(elem->solparm->mc, start_config_set_cb, elem);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(start_config_set): "
		 "SOLPARM's MC is not valid");
	solparm_lock(elem->solparm);
	set_complete(elem->solparm, rv, elem);
    }
    return OPQ_HANDLER_STARTED;
}

int
ipmi_solparm_set_parm(ipmi_solparm_t       *solparm,
		      unsigned int         parm,
		      unsigned char        *data,
		      unsigned int         data_len,
		      ipmi_solparm_done_cb done,
		      void                 *cb_data)
{
    solparm_set_handler_t *elem;
    int               rv = 0;

    if (solparm->destroyed)
	return EINVAL;

    if (data_len > MAX_IPMI_DATA_SIZE-2)
	return EINVAL;

    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(ipmi_solparm_set_parm): "
		 "could not allocate the solparm element");
	return ENOMEM;
    }

    elem->handler = done;
    elem->cb_data = cb_data;
    elem->solparm = solparm;
    elem->data[0] = solparm->channel;
    elem->data[1] = parm;
    memcpy(elem->data+2, data, data_len);
    elem->data_len = data_len + 2;
    elem->rv = 0;

    if (!opq_new_op(solparm->opq, start_config_set, elem, 0))
	rv = ENOMEM;

    if (rv)
	ipmi_mem_free(elem);
    else
	solparm_get(solparm);

    return rv;
}

struct ipmi_sol_config_s
{
    /* Stuff for getting/setting the values. */
    int curr_parm;
    int curr_sel;

    /* Not used for access, just for checking validity. */
    ipmi_solparm_t *my_sol;

    /* Does this config hold the external SOL "set in progress" lock? */
    int sol_locked;

    /* Does the SOL config support locking? */
    int lock_supported;

    /* Used for deferred errors. */
    int err;

    ipmi_solparm_done_cb   set_done;
    ipmi_sol_get_config_cb done;
    void                   *cb_data;

    unsigned int enable : 1;
    unsigned int force_payload_encryption : 1;
    unsigned int force_payload_authentication : 1;
    unsigned int privilege_level : 4;
    unsigned int retry_count : 3;
    unsigned char payload_channel_supported;
    unsigned char payload_channel;
    unsigned char char_accumulation_interval;
    unsigned char char_send_threshold;
    unsigned char non_volatile_bitrate;
    unsigned char volatile_bitrate;
    unsigned char retry_interval;
    unsigned char port_number_supported;
    unsigned int port_number;
};

typedef struct solparms_s solparms_t;
struct solparms_s
{
    unsigned int valid : 1;
    unsigned int optional_offset : 8;
    unsigned int length : 8;
    unsigned int offset : 8;
    /* Returns err. */
    int (*get_handler)(ipmi_sol_config_t *solc, solparms_t *lp, int err,
		       unsigned char *data);
    /* NULL if parameter is read-only */
    void (*set_handler)(ipmi_sol_config_t *solc, solparms_t *lp,
			unsigned char *data);
};

/* SoL Enable */
static int gse(ipmi_sol_config_t *solc, solparms_t *lp, int err,
	       unsigned char *data)
{
    if (err)
	return err;

    data++; /* Skip over the revision byte. */
    solc->enable = data[0] & 0x1;
    return 0;
}

static void sse(ipmi_sol_config_t *solc, solparms_t *lp, unsigned char *data)
{
    data[0] = solc->enable;
}

/* Authentication */
static int gsa(ipmi_sol_config_t *solc, solparms_t *lp, int err,
	       unsigned char *data)
{
    if (err)
	return err;

    data++; /* Skip over the revision byte. */
    solc->force_payload_encryption = (data[0] >> 7) & 0x1;
    solc->force_payload_authentication = (data[0] >> 6) & 0x1;
    solc->privilege_level = data[0] & 0xf;
    return 0;
}

static void ssa(ipmi_sol_config_t *solc, solparms_t *lp, unsigned char *data)
{
    data[0] = ((solc->force_payload_encryption << 7)
	       | (solc->force_payload_authentication << 6)
	       | solc->privilege_level);
}

/* char settings */
static int gcs(ipmi_sol_config_t *solc, solparms_t *lp, int err,
	       unsigned char *data)
{
    if (err)
	return err;

    data++; /* Skip over the revision byte. */
    solc->char_accumulation_interval = data[0];
    solc->char_send_threshold = data[1];
    return 0;
}

static void scs(ipmi_sol_config_t *solc, solparms_t *lp, unsigned char *data)
{
    data[0] = solc->char_accumulation_interval;
    data[1] = solc->char_send_threshold;
}

/* retry */
static int gsr(ipmi_sol_config_t *solc, solparms_t *lp, int err,
	       unsigned char *data)
{
    if (err)
	return err;

    data++; /* Skip over the revision byte. */
    solc->retry_count = data[0] & 0x7;
    solc->retry_interval = data[1];
    return 0;
}

static void ssr(ipmi_sol_config_t *solc, solparms_t *lp, unsigned char *data)
{
    data[0] = solc->retry_count;
    data[1] = solc->retry_interval;
}

/* bitrate */
static int gbr(ipmi_sol_config_t *solc, solparms_t *lp, int err,
	       unsigned char *data)
{
    unsigned char *ptr;

    if (err)
	return err;

    ptr = ((unsigned char *) solc) + lp->offset;

    data++; /* Skip over the revision byte. */
    *ptr = data[0] & 0xf;
    return 0;
}

static void sbr(ipmi_sol_config_t *solc, solparms_t *lp, unsigned char *data)
{
    unsigned char *ptr = ((unsigned char *) solc) + lp->offset;
    data[0] = *ptr & 0xf;
}

/* payload channel */
static int gpc(ipmi_sol_config_t *solc, solparms_t *lp, int err,
	       unsigned char *data)
{
    if (err) {
	if (err == IPMI_IPMI_ERR_VAL(0x80)) {
	    solc->payload_channel_supported = 0;
	    return 0;
	}
	return err;
    }

    data++; /* Skip over the revision byte. */
    solc->payload_channel_supported = 1;
    solc->payload_channel = data[0] & 0xf;
    return 0;
}

/* port number */
static int gpn(ipmi_sol_config_t *solc, solparms_t *lp, int err,
	       unsigned char *data)
{
    if (err) {
	if (err == IPMI_IPMI_ERR_VAL(0x80)) {
	    solc->port_number_supported = 0;
	    return 0;
	}
	return err;
    }

    data++; /* Skip over the revision byte. */
    solc->port_number = ipmi_get_uint16(data);
    return 0;
}

static void spn(ipmi_sol_config_t *solc, solparms_t *lp, unsigned char *data)
{
    ipmi_set_uint16(data, solc->port_number);
}


#define OFFSET_OF(x) (((unsigned char *) &(((ipmi_sol_config_t *) NULL)->x)) \
                      - ((unsigned char *) NULL))

#define NUM_SOLPARMS 26
static solparms_t solparms[NUM_SOLPARMS] =
{
    { 0, 0, 0, 0, NULL, NULL }, /* IPMI_SOLPARM_SET_IN_PROGRESS		     */
    { 1, 0, 1, 0, gse,  sse  }, /* IPMI_SOLPARM_ENABLE			     */
    { 1, 0, 1, 0, gsa,  ssa  }, /* IPMI_SOLPARM_AUTHENTICATION		     */
    { 1, 0, 2, 0, gcs,  scs  }, /* IPMI_SOLPARM_CHAR_SETTINGS		     */
    { 1, 0, 2, 0, gsr,  ssr  }, /* IPMI_SOLPARM_RETRY			     */
#define F OFFSET_OF(non_volatile_bitrate)
    { 1, 0, 1, F, gbr,  sbr  }, /* IPMI_SOLPARM_NONVOLATILE_BITRATE	     */
#undef F
#define F OFFSET_OF(volatile_bitrate)
    { 1, 0, 1, F, gbr,  sbr  }, /* IPMI_SOLPARM_VOLATILE_BITRATE	     */
#undef F
#define S OFFSET_OF(payload_channel_supported)
    { 1, S, 1, 0, gpc,  NULL }, /* IPMI_SOLPARM_PAYLOAD_CHANNEL		     */
#undef S
#define S OFFSET_OF(port_number_supported)
    { 1, S, 2, 0, gpn,  spn  }, /* IPMI_SOLPARM_PORT_NUMBER		     */
#undef S
};

static void
err_lock_cleared(ipmi_solparm_t *solparm,
		 int            err,
		 void           *cb_data)
{
    ipmi_sol_config_t *solc = cb_data;

    if (solc->done)
	solc->done(solparm, solc->err, NULL, solc->cb_data);
    ipmi_sol_free_config(solc);
    solparm->locked = 0;
    solparm_put(solparm);
}

static void
got_parm(ipmi_solparm_t    *solparm,
	 int               err,
	 unsigned char     *data,
	 unsigned int      data_len,
	 void              *cb_data)
{
    ipmi_sol_config_t *solc = cb_data;
    solparms_t        *lp = &(solparms[solc->curr_parm]);

    /* Check the length, and don't forget the revision byte must be added. */
    if ((!err) && (data_len < (unsigned int) (lp->length+1))) {
	if ((data_len == 1) && (lp->optional_offset)) {
	    /* Some systems return zero-length data for optional parms. */
	    unsigned char *opt = ((unsigned char *)solc) + lp->optional_offset;
	    *opt = 0;
	    goto next_parm;
	}
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(got_parm): "
		 " Invalid data length on parm %d was %d, should have been %d",
		 solc->curr_parm, data_len, lp->length+1);
	err = EINVAL;
	goto done;
    }

    err = lp->get_handler(solc, lp, err, data);
    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(got_parm): "
		 "Error fetching parm %d: %x",
		 solc->curr_parm, err);
	goto done;
    }

 next_parm:
    switch (solc->curr_parm) {
    case IPMI_SOLPARM_PAYLOAD_PORT_NUMBER:
	goto done;
    default:
	solc->curr_parm++;
    }

    lp = &(solparms[solc->curr_parm]);
    if (!lp->valid)
	goto next_parm;

    err = ipmi_solparm_get_parm(solparm, solc->curr_parm, solc->curr_sel, 0,
				got_parm, solc);
    if (err)
	goto done;

    return;

 done:
    if (err) {
	unsigned char data[1];

	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(got_parm): Error trying to get parm %d: %x",
		 solc->curr_parm, err);
	solc->err = err;
	/* Clear the lock */
	data[0] = 0;
	err = ipmi_solparm_set_parm(solparm, 0, data, 1,
				    err_lock_cleared, solc);
	if (err) {
	    ipmi_sol_free_config(solc);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "solparm.c(got_parm): Error trying to clear lock: %x",
		     err);
	    solc->done(solparm, solc->err, NULL, solc->cb_data);
	    ipmi_sol_free_config(solc);
	    solparm->locked = 0;
	    solparm_put(solparm);
	}
    } else {
	solc->done(solparm, 0, solc, solc->cb_data);
	solparm_put(solparm);
    }
}

static void 
lock_done(ipmi_solparm_t *solparm,
	  int            err,
	  void           *cb_data)
{
    ipmi_sol_config_t *solc = cb_data;
    int               rv;

    if (err == IPMI_IPMI_ERR_VAL(0x80)) {
	/* Lock is not supported, just mark it and go on. */
	solc->lock_supported = 0;
    } else if (err == IPMI_IPMI_ERR_VAL(0x81)) {
	/* Someone else has the lock, return EAGAIN. */
	solc->done(solparm, EAGAIN, NULL, solc->cb_data);
	ipmi_sol_free_config(solc);
	solparm_put(solparm);
	return;
    } else if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(lock_done): Error trying to lock the SOL"
		 " parms: %x",
		 err);
	solc->done(solparm, err, NULL, solc->cb_data);
	ipmi_sol_free_config(solc);
	solparm_put(solparm);
	return;
    } else {
	solc->sol_locked = 1;
	solparm->locked = 1;
    }

    rv = ipmi_solparm_get_parm(solparm, solc->curr_parm, solc->curr_sel, 0,
			       got_parm, solc);
    if (rv) {
	unsigned char data[1];
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(lock_done): Error trying to get parms: %x",
		 err);

	solc->err = rv;
	/* Clear the lock */
	data[0] = 0;
	rv = ipmi_solparm_set_parm(solparm, 0, data, 1,
				   err_lock_cleared, solc);
	if (rv) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "solparm.c(lock_done): Error trying to clear lock: %x",
		     err);
	    solc->done(solparm, solc->err, NULL, solc->cb_data);
	    ipmi_sol_free_config(solc);
	    solparm->locked = 0;
	    solparm_put(solparm);
	}
    }
}

int ipmi_sol_get_config(ipmi_solparm_t         *solparm,
			ipmi_sol_get_config_cb done,
			void                   *cb_data)
{
    ipmi_sol_config_t *solc;
    int               rv;
    unsigned char     data[1];

    solc = ipmi_mem_alloc(sizeof(*solc));
    if (!solc)
	return ENOMEM;
    memset(solc, 0, sizeof(*solc));

    solc->curr_parm = 1;
    solc->curr_sel = 0;
    solc->done = done;
    solc->cb_data = cb_data;
    solc->my_sol = solparm;
    solc->lock_supported = 1; /* Assume it works */

    solparm_get(solparm);

    /* First grab the lock */
    data[0] = 1; /* Set in progress. */
    rv = ipmi_solparm_set_parm(solparm, 0, data, 1, lock_done, solc);
    if (rv) {
	ipmi_sol_free_config(solc);
	solparm_put(solparm);
    }

    return rv;
}

static void 
set_clear(ipmi_solparm_t *solparm,
	 int            err,
	 void           *cb_data)
{
    ipmi_sol_config_t *solc = cb_data;

    if (solc->err)
	err = solc->err;
    if (solc->set_done)
	solc->set_done(solparm, err, solc->cb_data);
    ipmi_sol_free_config(solc);
    solparm->locked = 0;
    solparm_put(solparm);
}

static void 
commit_done(ipmi_solparm_t *solparm,
	    int            err,
	    void           *cb_data)
{
    ipmi_sol_config_t *solc = cb_data;
    unsigned char     data[1];
    int               rv;

    /* Note that we ignore the error.  The commit done is optional,
       and must return an error if it is optional, so we just ignore
       the error and clear the field here. */

    /* Commit is done.  The IPMI spec says that it goes into the
       set-in-progress state after this, so we need to clear it. */

    data[0] = 0;
    rv = ipmi_solparm_set_parm(solparm, 0, data, 1, set_clear, solc);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "solparm.c(commit_done): Error trying to clear the set in"
		 " progress: %x",
		 rv);
	set_clear(solparm, err, solc);
    }
}

static void 
set_done(ipmi_solparm_t *solparm,
	 int            err,
	 void           *cb_data)
{
    ipmi_sol_config_t *solc = cb_data;
    unsigned char     data[MAX_IPMI_DATA_SIZE];
    solparms_t        *lp = &(solparms[solc->curr_parm]);

    if (err == IPMI_IPMI_ERR_VAL(0x82)) {
	/* We attempted to write a read-only parameter that is not
	   marked by the spec as read-only.  Just ignore it. */
	err = 0;
    }

    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "solparm.c(set_done): Error setting sol parm %d sel %d: %x",
		 solc->curr_parm, solc->curr_sel, err);
	goto done;
    }

 next_parm:
    switch (solc->curr_parm) {
    case IPMI_SOLPARM_PAYLOAD_PORT_NUMBER:
	goto done;
    default:
	solc->curr_parm++;
    }

    lp = &(solparms[solc->curr_parm]);
    if ((!lp->valid) || (!lp->set_handler)
	|| (lp->optional_offset
	    && !(((unsigned char *) solc)[lp->optional_offset])))
    {
	/* The parameter is read-only or not supported, just go on. */
	goto next_parm;
    }

    lp->set_handler(solc, lp, data);
    err = ipmi_solparm_set_parm(solparm, solc->curr_parm,
				data, lp->length, set_done, solc);
    if (err)
	goto done;

    return;

 done:
    if (!solc->lock_supported) {
	/* No lock support, just finish the operation. */
	set_clear(solparm, err, solc);
	return;
    }
    else if (err) {
	data[0] = 0; /* Don't commit the parameters. */
	solc->err = err;
	err = ipmi_solparm_set_parm(solparm, 0, data, 1, set_clear, solc);
    } else {
	data[0] = 2; /* Commit the parameters. */
	err = ipmi_solparm_set_parm(solparm, 0, data, 1, commit_done, solc);
    }
    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "solparm.c(set_done): Error trying to clear the set in"
		 " progress: %x",
		 err);
	set_clear(solparm, err, solc);
    }
}

int
ipmi_sol_set_config(ipmi_solparm_t       *solparm,
		    ipmi_sol_config_t    *osolc,
		    ipmi_solparm_done_cb done,
		    void                 *cb_data)
{
    ipmi_sol_config_t *solc;
    unsigned char     data[MAX_IPMI_DATA_SIZE];
    solparms_t        *lp;
    int               rv;

    if (osolc->my_sol != solparm)
	return EINVAL;

    if (!osolc->sol_locked)
	return EINVAL;

    solc = ipmi_mem_alloc(sizeof(*solc));
    if (!solc)
	return ENOMEM;

    *solc = *osolc;
    solc->err = 0;
    solc->sol_locked = 0; /* Set this here, since we will unlock it,
			     but we don't want the free operation to
			     attempt an unlock */

    solc->curr_parm = 1;
    solc->curr_sel = 0;
    solc->set_done = done;
    solc->cb_data = cb_data;

    /* Parm 1 is known good for writing. */
    lp = &(solparms[solc->curr_parm]);
    lp->set_handler(solc, lp, data);
    rv = ipmi_solparm_set_parm(solparm, solc->curr_parm,
			       data, lp->length, set_done, solc);
    if (rv) {
	ipmi_sol_free_config(solc);
    } else {
	/* The old config no longer holds the lock. */
	osolc->sol_locked = 0;
	solparm_get(solparm);
    }
    return rv;
}

typedef struct clear_lock_s
{
    ipmi_solparm_done_cb done;
    void                 *cb_data;
    
} clear_lock_t;

static void 
lock_cleared(ipmi_solparm_t *solparm,
	     int            err,
	     void           *cb_data)
{
    clear_lock_t *cl = cb_data;

    cl->done(solparm, err, cl->cb_data);

    ipmi_mem_free(cl);
    solparm->locked = 0;
    solparm_put(solparm);
}

int
ipmi_sol_clear_lock(ipmi_solparm_t       *solparm,
		    ipmi_sol_config_t    *solc,
		    ipmi_solparm_done_cb done,
		    void                 *cb_data)
{
    unsigned char data[1];
    int           rv;
    clear_lock_t  *cl;

    if (solc) {
	if (solc->my_sol != solparm)
	    return EINVAL;

	if (!solc->sol_locked)
	    return EINVAL;
    }

    cl = ipmi_mem_alloc(sizeof(*cl));
    if (!cl)
	return ENOMEM;
    cl->done = done;
    cl->cb_data = cb_data;

    data[0] = 0; /* Clear the lock. */
    rv = ipmi_solparm_set_parm(solparm, 0, data, 1, lock_cleared, cl);
    if (rv) {
	ipmi_mem_free(cl);
    } else {
	if (solc)
	    solc->sol_locked = 0;
	solparm_get(solparm);
    }

    return rv;
}

void
ipmi_sol_free_config(ipmi_sol_config_t *solc)
{
    ipmi_mem_free(solc);
}


#define LP_INT_PARM(n) \
unsigned int \
ipmi_solconfig_get_ ## n(ipmi_sol_config_t *solc) \
{ \
    return solc->n; \
} \
int \
ipmi_solconfig_set_ ## n(ipmi_sol_config_t *solc, \
			 unsigned int      val) \
{ \
    solc->n = val; \
    return 0; \
}


LP_INT_PARM(enable)
LP_INT_PARM(force_payload_encryption)
LP_INT_PARM(force_payload_authentication)
LP_INT_PARM(privilege_level)
LP_INT_PARM(char_accumulation_interval)
LP_INT_PARM(char_send_threshold)
LP_INT_PARM(retry_count)
LP_INT_PARM(retry_interval)
LP_INT_PARM(non_volatile_bitrate)
LP_INT_PARM(volatile_bitrate)


#define LP_INT_PARM_SUP(n, s) \
int \
ipmi_solconfig_get_ ## n(ipmi_sol_config_t *solc, \
			 unsigned int      *data) \
{ \
    if (! solc->s) \
        return ENOSYS; \
    *data = solc->n; \
    return 0; \
} \
int \
ipmi_solconfig_set_ ## n(ipmi_sol_config_t *solc, \
			 unsigned int      data) \
{ \
    if (! solc->s) \
        return ENOSYS; \
    solc->n = data; \
    return 0; \
}

LP_INT_PARM_SUP(payload_channel, payload_channel_supported);
LP_INT_PARM_SUP(port_number, port_number_supported)


typedef struct solparm_gendata_s
{
    enum ipmi_solconf_val_type_e datatype;
    char *fname;

    union {
	struct {
	    unsigned int (*gval)(ipmi_sol_config_t *solc);
	    int (*gval_v)(ipmi_sol_config_t *solc, unsigned int *val);
	    int (*gval_iv)(ipmi_sol_config_t *solc, unsigned int idx,
			   unsigned int *val);
	    int (*sval)(ipmi_sol_config_t *solc, unsigned int val);
	    int (*sval_v)(ipmi_sol_config_t *solc, unsigned int val);
	    int (*sval_iv)(ipmi_sol_config_t *solc, unsigned int idx,
			   unsigned int val);
	} ival;
	struct {
	    int (*gval_v)(ipmi_sol_config_t *solc, unsigned char *data,
			  unsigned int *data_len);
	    int (*gval_iv)(ipmi_sol_config_t *solc, unsigned int idx,
			   unsigned char *data, unsigned int *data_len);
	    int (*sval_v)(ipmi_sol_config_t *solc, unsigned char *data,
			  unsigned int data_len);
	    int (*sval_iv)(ipmi_sol_config_t *solc, unsigned int idx,
			   unsigned char *data, unsigned int data_len);
	} dval;
    } u;
    unsigned int (*iv_cnt)(ipmi_sol_config_t *solc);
} solparm_gendata_t;

#define F_BOOL(name) \
	{ .datatype = IPMI_SOLCONFIG_BOOL, .fname = #name, \
	  .u = { .ival = { .gval = ipmi_solconfig_get_ ## name, \
			   .sval = ipmi_solconfig_set_ ## name }}}
#define F_INT(name) \
	{ .datatype = IPMI_SOLCONFIG_INT, .fname = #name, \
	  .u = { .ival = { .gval = ipmi_solconfig_get_ ## name, \
			   .sval = ipmi_solconfig_set_ ## name }}}
#define F_INTV(name) \
	{ .datatype = IPMI_SOLCONFIG_INT, .fname = #name, \
	  .u = { .ival = { .gval_v = ipmi_solconfig_get_ ## name, \
			   .sval_v = ipmi_solconfig_set_ ## name }}}

static solparm_gendata_t gdata[] =
{
    F_BOOL(enable),				/* 0 */
    F_BOOL(force_payload_encryption),
    F_BOOL(force_payload_authentication),
    F_INT(privilege_level),
    F_INT(retry_count),
    F_INT(retry_interval),			/* 5 */
    F_INT(char_accumulation_interval),
    F_INT(char_send_threshold),
    F_INT(non_volatile_bitrate),
    F_INT(volatile_bitrate),
    F_INTV(payload_channel),			/* 10 */
    F_INTV(port_number),
};
#define NUM_GDATA_ENTRIES (sizeof(gdata) / sizeof(solparm_gendata_t))

int
ipmi_solconfig_enum_val(unsigned int parm, int val, int *nval,
			const char **sval)
{
    char *rval;
    int  rnval;

    switch (parm) {
    case 3: /* privilege level */
	if (val < 2) {
	    if (nval)
		*nval = 2;
	    return EINVAL;
	}

	switch (val) {
	case 2:
	    rval = "user";
	    rnval = 3;
	    break;
	case 3:
	    rval = "operator";
	    rnval = 4;
	    break;
	case 4:
	    rval = "admin";
	    rnval = 5;
	    break;
	case 5:
	    rval = "oem";
	    rnval = -1;
	    break;
	default:
	    if (*nval)
		*nval = -1;
	    return EINVAL;
	}
	break;

    case 8: case 9:
	if (val < 6) {
	    if (nval)
		*nval = 6;
	    return EINVAL;
	}

	switch (val) {
	case 6:
	    rval = "9600";
	    rnval = 7;
	    break;
	case 7:
	    rval = "19.2K";
	    rnval = 8;
	    break;
	case 8:
	    rval = "38.4K";
	    rnval = 9;
	    break;
	case 9:
	    rval = "57.6K";
	    rnval = 10;
	    break;
	case 10:
	    rval = "115.2K";
	    rnval = -1;
	    break;
	default:
	    if (*nval)
		*nval = -1;
	    return EINVAL;
	}
	break;

    default:
	return ENOSYS;
    }


    if (sval)
	*sval = rval;
    if (nval)
	*nval = rnval;
    return 0;
}

int
ipmi_solconfig_enum_idx(unsigned int parm, int idx, const char **sval)
{
    return ENOSYS;
}

int
ipmi_solconfig_get_val(ipmi_sol_config_t *solc,
		       unsigned int      parm,
		       const char        **name,
		       int               *index,
		       enum ipmi_solconf_val_type_e *valtype,
		       unsigned int      *ival,
		       unsigned char     **dval,
		       unsigned int      *dval_len)
{
    unsigned int  curr = *index;
    unsigned int  count;
    int           rv = 0;
    unsigned char *data;
    unsigned int  data_len;

    if (parm >= NUM_GDATA_ENTRIES)
	return EINVAL;
    if (valtype)
	*valtype = gdata[parm].datatype;
    if (name)
	*name = gdata[parm].fname;

    if (gdata[parm].iv_cnt) {
	count = gdata[parm].iv_cnt(solc);
	if (curr >= count) {
	    *index = -1;
	    return E2BIG;
	}

	if (curr+1 == count)
	    *index = -1;
	else
	    *index = curr+1;
    }

    switch (gdata[parm].datatype) {
    case IPMI_SOLCONFIG_INT:
    case IPMI_SOLCONFIG_BOOL:
	if (!ival)
	    break;
	if (gdata[parm].u.ival.gval)
	    *ival = gdata[parm].u.ival.gval(solc);
	else if (gdata[parm].u.ival.gval_v)
	    rv = gdata[parm].u.ival.gval_v(solc, ival);
	else if (gdata[parm].u.ival.gval_iv)
	    rv = gdata[parm].u.ival.gval_iv(solc, curr, ival);
	else
	    rv = ENOSYS;
	break;

    case IPMI_SOLCONFIG_DATA:
    case IPMI_SOLCONFIG_IP:
    case IPMI_SOLCONFIG_MAC:
	data_len = 0;
	if (gdata[parm].u.dval.gval_v)
	    rv = gdata[parm].u.dval.gval_v(solc, NULL, &data_len);
	else if (gdata[parm].u.dval.gval_iv)
	    rv = gdata[parm].u.dval.gval_iv(solc, curr, NULL, &data_len);
	else
	    rv = ENOSYS;
	if (rv && (rv != EBADF))
	    break;
	if (data_len == 0)
	    data = ipmi_mem_alloc(1);
	else
	    data = ipmi_mem_alloc(data_len);
	if (gdata[parm].u.dval.gval_v)
	    rv = gdata[parm].u.dval.gval_v(solc, data, &data_len);
	else if (gdata[parm].u.dval.gval_iv)
	    rv = gdata[parm].u.dval.gval_iv(solc, curr, data, &data_len);
	if (rv) {
	    ipmi_mem_free(data);
	    break;
	}
	if (dval)
	    *dval = data;
	if (dval_len)
	    *dval_len = data_len;
	break;
    }

    return rv;
}

int
ipmi_solconfig_set_val(ipmi_sol_config_t *solc,
		       unsigned int      parm,
		       int               index,
		       unsigned int      ival,
		       unsigned char     *dval,
		       unsigned int      dval_len)
{
    unsigned int  count;
    int           rv = 0;

    if (parm >= NUM_GDATA_ENTRIES)
	return EINVAL;

    if (gdata[parm].iv_cnt) {
	count = gdata[parm].iv_cnt(solc);
	if (index >= (int) count)
	    return E2BIG;
    }

    switch (gdata[parm].datatype) {
    case IPMI_SOLCONFIG_INT:
    case IPMI_SOLCONFIG_BOOL:
	if (gdata[parm].u.ival.sval)

	    rv = gdata[parm].u.ival.sval(solc, ival);
	else if (gdata[parm].u.ival.sval_v)
	    rv = gdata[parm].u.ival.sval_v(solc, ival);
	else if (gdata[parm].u.ival.sval_iv)
	    rv = gdata[parm].u.ival.sval_iv(solc, index, ival);
	else
	    rv = ENOSYS;
	break;

    case IPMI_SOLCONFIG_DATA:
    case IPMI_SOLCONFIG_IP:
    case IPMI_SOLCONFIG_MAC:
	if (gdata[parm].u.dval.sval_v)
	    rv = gdata[parm].u.dval.sval_v(solc, dval, dval_len);
	else if (gdata[parm].u.dval.sval_iv)
	    rv = gdata[parm].u.dval.sval_iv(solc, index, dval, dval_len);
	else
	    rv = ENOSYS;
	break;
    }

    return rv;
}


void
ipmi_solconfig_data_free(void *data)
{
    ipmi_mem_free(data);
}

unsigned int
ipmi_solconfig_str_to_parm(char *name)
{
    unsigned int i;
    for (i=0; i<NUM_GDATA_ENTRIES; i++) {
	if (strcmp(name, gdata[i].fname) == 0)
	    return i;
    }
    return -1;
}

const char *
ipmi_solconfig_parm_to_str(unsigned int parm)
{
    if (parm >= NUM_GDATA_ENTRIES)
	return NULL;
    return gdata[parm].fname;
}

int
ipmi_solconfig_parm_to_type(unsigned int                 parm,
			    enum ipmi_solconf_val_type_e *valtype)
{
    if (parm >= NUM_GDATA_ENTRIES)
	return EINVAL;
    *valtype = gdata[parm].datatype;
    return 0;
}
