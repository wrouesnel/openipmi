/*
 * pef.c
 *
 * OpenIPMI code for handling Platform Event Filters
 *
 * Author: Intel Corporation
 *         Jeff Zheng <Jeff.Zheng@Intel.com>
 *
 * Copyright 2002,2003 Intel Corporation.
 *
 * Mostly rewritten by: MontaVista Software, Inc.
 *                      Corey Minyard <minyard@mvista.com>
 *                      source@mvista.com
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

/* I rewrote this because I needed access to individual data items,
   not just a full configuration. -Corey */

#include <string.h>
#include <math.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_pef.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ilist.h>
#include <OpenIPMI/opq.h>

struct ipmi_pef_s
{
    ipmi_mcid_t mc;

    /* Is the PEF ready (the capabilities have been checked)? */
    unsigned int ready : 1;

    /* Does the MC have a usable PEF? */
    unsigned int valid : 1;

    /* Information from the get PEF capability command. */
    unsigned int can_diagnostic_interrupt : 1;
    unsigned int can_oem_action : 1;
    unsigned int can_power_cycle : 1;
    unsigned int can_reset : 1;
    unsigned int can_power_down : 1;
    unsigned int can_alert : 1;
    unsigned int major_version : 4;
    unsigned int minor_version : 4;

    unsigned char num_eft_entries;

    /* Used to inform the user when the PEF is ready. */
    ipmi_pef_done_cb ready_cb;
    void             *ready_cb_data;

    unsigned int destroyed : 1;
    unsigned int in_destroy : 1;

    /* Something to call when the destroy is complete. */
    ipmi_pef_done_cb destroy_handler;
    void             *destroy_cb_data;

    os_hnd_lock_t *pef_lock;

    os_handler_t *os_hnd;

    /* We serialize operations through here, since we are dealing with
       a locked resource. */
    opq_t *opq;
};

static void
pef_lock(ipmi_pef_t *pef)
{
    if (pef->os_hnd->lock)
	pef->os_hnd->lock(pef->os_hnd, pef->pef_lock);
}

static void
pef_unlock(ipmi_pef_t *pef)
{
    if (pef->os_hnd->lock)
	pef->os_hnd->unlock(pef->os_hnd, pef->pef_lock);
}

static int
check_pef_response_param(ipmi_pef_t *pef,
			 ipmi_mc_t  *mc,
			 ipmi_msg_t *rsp,
			 int	    len,
			 char	    *func_name)
{
    if (pef->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%s: "
		 "PEF was destroyed while an operation was in progress",
		 func_name);
	return ECANCELED;
    }

    if (!mc) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%s: MC went away while PEF op was in progress",
		 func_name);
	return ENXIO;
    }

    if (rsp->data[0] != 0) {
	/* Allow optional parameters to return errors without complaining. */
	if (rsp->data[0] != 0x80)
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%s: IPMI error from PEF capabilities fetch: %x",
		     func_name,
		     rsp->data[0]);
	return IPMI_IPMI_ERR_VAL(rsp->data[0]);
    }

    if (rsp->data_len < len) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		"%s: PEF capabilities too short",
		func_name);
	return EINVAL;
    }
    return 0;
}

static void
handle_pef_capabilities(ipmi_mc_t  *mc,
			ipmi_msg_t *rsp,
			void       *rsp_data)
{
    ipmi_pef_t *pef = rsp_data;
    int        rv;

    rv = check_pef_response_param(pef, mc, rsp, 4, "handle_pef_capabilities");
    if (rv)
	goto out;

    pef_lock(pef);

    pef->valid = 1;

    /* Pull pertinant info from the response. */
    pef->major_version = rsp->data[1] & 0xf;
    pef->minor_version = (rsp->data[1] >> 4) & 0xf;
    pef->can_alert = (rsp->data[2] & 0x01) == 0x01;
    pef->can_power_down = (rsp->data[2] & 0x02) == 0x02;
    pef->can_reset = (rsp->data[2] & 0x04) == 0x04;
    pef->can_power_cycle = (rsp->data[2] & 0x08) == 0x08;
    pef->can_oem_action = (rsp->data[2] & 0x10) == 0x10;
    pef->can_diagnostic_interrupt = (rsp->data[2] & 0x20) == 0x20;
    pef->num_eft_entries = rsp->data[3];

    pef_unlock(pef);

 out:
    pef->ready = 1;

    if (pef->ready_cb)
	pef->ready_cb(pef, rv, pef->ready_cb_data);
}

static int
pef_start_capability_fetch(ipmi_pef_t *pef, ipmi_mc_t *mc)
{
    ipmi_msg_t msg;
    int        rv;

    msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    msg.cmd = IPMI_GET_PEF_CAPABILITIES_CMD;
    msg.data_len = 0;
    msg.data = NULL;
    rv = ipmi_mc_send_command(mc, 0,
			      &msg, handle_pef_capabilities, pef);
    if (rv)
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "pef_start_capability_fetch: could not send cmd: %x",
		 rv);

    return rv;
}

int
ipmi_pef_alloc(ipmi_mc_t        *mc,
	       ipmi_pef_done_cb done,
	       void             *cb_data,
	       ipmi_pef_t       **new_pef)
{
    ipmi_pef_t    *pef = NULL;
    int           rv = 0;
    ipmi_domain_t *domain;

    CHECK_MC_LOCK(mc);

    pef = ipmi_mem_alloc(sizeof(*pef));
    if (!pef) {
	rv = ENOMEM;
	goto out;
    }
    memset(pef, 0, sizeof(*pef));

    pef->mc = ipmi_mc_convert_to_id(mc);
    domain = ipmi_mc_get_domain(mc);
    pef->os_hnd = ipmi_domain_get_os_hnd(domain);
    pef->pef_lock = NULL;
    pef->ready_cb = done;
    pef->ready_cb_data = cb_data;

    pef->opq = opq_alloc(pef->os_hnd);
    if (!pef->opq) {
	rv = ENOMEM;
	goto out;
    }

    if (pef->os_hnd->create_lock) {
	rv = pef->os_hnd->create_lock(pef->os_hnd, &pef->pef_lock);
	if (rv)
	    goto out;
    }

 out:
    if (!rv)
	rv = pef_start_capability_fetch(pef, mc);

    if (rv) {
	if (pef) {
	    if (pef->opq)
		opq_destroy(pef->opq);
	    if (pef->pef_lock)
		pef->os_hnd->destroy_lock(pef->os_hnd, pef->pef_lock);
	    ipmi_mem_free(pef);
	}
    } else {
	if (new_pef)
	    *new_pef = pef;
    }
    return rv;
}

static void
internal_destroy_pef(ipmi_pef_t *pef)
{
    pef->in_destroy = 1;

    /* We don't have to have a valid ipmi to destroy an SEL, the are
       designed to live after the ipmi has been destroyed. */
    pef_unlock(pef);

    if (pef->opq)
	opq_destroy(pef->opq);

    if (pef->pef_lock)
	pef->os_hnd->destroy_lock(pef->os_hnd, pef->pef_lock);

    /* Do this after we have gotten rid of all external dependencies,
       but before it is free. */
    if (pef->destroy_handler)
	pef->destroy_handler(pef, 0, pef->destroy_cb_data);

    ipmi_mem_free(pef);
}

int
ipmi_pef_destroy(ipmi_pef_t       *pef,
		 ipmi_pef_done_cb handler,
		 void             *cb_data)
{
    /* We don't need the read lock, because the pef are stand-alone
       after they are created (except for fetching SELs, of course). */
    pef_lock(pef);
    if (pef->destroyed) {
	pef_unlock(pef);
	return EINVAL;
    }
    pef->destroyed = 1;
    pef->destroy_handler = handler;
    pef->destroy_cb_data = cb_data;
    if (opq_stuff_in_progress(pef->opq)) {
	/* It's currently doing something with callbacks, so let it be
           destroyed in the handler, since we can't cancel the handler
           or operation. */
	pef_unlock(pef);
	return 0;
    }

    /* This unlocks the lock. */
    internal_destroy_pef(pef);
    return 0;
}

typedef struct pef_fetch_handler_s
{
    ipmi_pef_t 		*pef;
    unsigned char       parm;
    unsigned char       set;
    unsigned char       block;
    ipmi_pef_get_cb 	handler;
    void                *cb_data;
    unsigned char       *data;
    unsigned int        data_len;
    int                 rv;
} pef_fetch_handler_t;

/* This should be called with the pef locked.  It will unlock the pef
   before returning. */
static void
fetch_complete(ipmi_pef_t *pef, int err, pef_fetch_handler_t *elem)
{
    if (pef->in_destroy)
	goto out;

    if (elem->handler)
	elem->handler(pef, err, elem->data, elem->data_len, elem->cb_data);

    ipmi_mem_free(elem);

    if (pef->destroyed) {
	internal_destroy_pef(pef);
	return;
    }

    opq_op_done(pef->opq);

 out:
    pef_unlock(pef);
}


static void
pef_config_fetched(ipmi_mc_t  *mc,
		   ipmi_msg_t *rsp,
		   void       *rsp_data)
{
    pef_fetch_handler_t *elem = rsp_data;
    ipmi_pef_t          *pef = elem->pef;
    int                 rv;

    rv = check_pef_response_param(pef, mc, rsp, 2, "pef_config_fetched");

    /* Skip the revision number. */
    elem->data = rsp->data + 2;
    elem->data_len = rsp->data_len - 2;

    pef_lock(pef);
    fetch_complete(pef, rv, elem);
}

static void
start_config_fetch_cb(ipmi_mc_t *mc, void *cb_data)
{
    pef_fetch_handler_t *elem = cb_data;
    ipmi_pef_t          *pef = elem->pef;
    unsigned char       data[3];
    ipmi_msg_t          msg;
    int                 rv;

    pef_lock(pef);
    if (pef->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_fetch: "
		 "PEF was destroyed while an operation was in progress");
	fetch_complete(pef, ECANCELED, elem);
	goto out;
    }

    msg.data = data;
    msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    msg.cmd = IPMI_GET_PEF_CONFIG_PARMS_CMD;
    data[0] = elem->parm;
    data[1] = elem->set;
    data[2] = elem->block;
    msg.data_len = 3;
    rv = ipmi_mc_send_command(mc, 0, &msg, pef_config_fetched, elem);

    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "PEF start_config_fetch: could not send cmd: %x",
		 rv);
	fetch_complete(pef, ECANCELED, elem);
	goto out;
    }

    pef_unlock(pef);
 out:
    return;
}

static void
start_config_fetch(void *cb_data, int shutdown)
{
    pef_fetch_handler_t *elem = cb_data;
    int                 rv;

    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_fetch: "
		 "PEF was destroyed while an operation was in progress");
	pef_lock(elem->pef);
	fetch_complete(elem->pef, ECANCELED, elem);
	return;
    }

    /* The read lock must be claimed before the pef lock to avoid
       deadlock. */
    rv = ipmi_mc_pointer_cb(elem->pef->mc, start_config_fetch_cb, elem);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO, "start_fetch: PEF's MC is not valid");
	pef_lock(elem->pef);
	fetch_complete(elem->pef, rv, elem);
    }
}

int
ipmi_pef_get_parm(ipmi_pef_t      *pef,
		  unsigned int    parm,
		  unsigned int    set,
		  unsigned int    block,
		  ipmi_pef_get_cb done,
		  void            *cb_data)
{
    pef_fetch_handler_t *elem;
    int                 rv = 0;

    if (pef->destroyed)
	return EINVAL;

    if (!pef->valid)
	return EINVAL;
	
    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_pef_get: could not allocate the pef element");
	return ENOMEM;
    }

    elem->handler = done;
    elem->cb_data = cb_data;
    elem->pef = pef;
    elem->parm = parm;
    elem->set = set;
    elem->block = block;
    elem->rv = 0;

    pef_lock(pef);

    if (!opq_new_op(pef->opq, start_config_fetch, elem, 0))
	rv = ENOMEM;

    pef_unlock(pef);

    return rv;
}

typedef struct pef_set_handler_s
{
    ipmi_pef_t 		*pef;
    ipmi_pef_done_cb 	handler;
    void                *cb_data;
    unsigned char       data[MAX_IPMI_DATA_SIZE];
    unsigned int        data_len;
    int                 rv;
} pef_set_handler_t;

/* This should be called with the pef locked.  It will unlock the pef
   before returning. */
static void
set_complete(ipmi_pef_t *pef, int err, pef_set_handler_t *elem)
{
    if (pef->in_destroy)
	goto out;

    if (elem->handler)
	elem->handler(pef, err, elem->cb_data);

    ipmi_mem_free(elem);

    if (pef->destroyed) {
	internal_destroy_pef(pef);
	return;
    }

    opq_op_done(pef->opq);

 out:
    pef_unlock(pef);
}

static void
pef_config_set(ipmi_mc_t  *mc,
	       ipmi_msg_t *rsp,
	       void       *rsp_data)
{
    pef_set_handler_t *elem = rsp_data;
    ipmi_pef_t        *pef = elem->pef;
    int               rv;

    rv = check_pef_response_param(pef, mc, rsp, 1, "pef_config_set");

    pef_lock(pef);
    set_complete(pef, rv, elem);
}

static void
start_config_set_cb(ipmi_mc_t *mc, void *cb_data)
{
    pef_set_handler_t *elem = cb_data;
    ipmi_pef_t        *pef = elem->pef;
    ipmi_msg_t        msg;
    int               rv;

    pef_lock(pef);
    if (pef->destroyed) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_set: "
		 "PEF was destroyed while an operation was in progress");
	set_complete(pef, ECANCELED, elem);
	goto out;
    }

    msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    msg.cmd = IPMI_SET_PEF_CONFIG_PARMS_CMD;
    msg.data = elem->data;
    msg.data_len = elem->data_len;
    rv = ipmi_mc_send_command(mc, 0, &msg, pef_config_set, elem);

    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "PEF start_config_set: could not send cmd: %x",
		 rv);
	set_complete(pef, ECANCELED, elem);
	goto out;
    }

    pef_unlock(pef);
 out:
    return;
}

static void
start_config_set(void *cb_data, int shutdown)
{
    pef_set_handler_t *elem = cb_data;
    int               rv;

    if (shutdown) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "start_config_set: "
		 "PEF was destroyed while an operation was in progress");
	pef_lock(elem->pef);
	set_complete(elem->pef, ECANCELED, elem);
	return;
    }

    /* The read lock must be claimed before the pef lock to avoid
       deadlock. */
    rv = ipmi_mc_pointer_cb(elem->pef->mc, start_config_set_cb, elem);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO, "start_config_set: PEF's MC is not valid");
	pef_lock(elem->pef);
	set_complete(elem->pef, rv, elem);
    }
}

int
ipmi_pef_set_parm(ipmi_pef_t       *pef,
		  unsigned int     parm,
		  unsigned char    *data,
		  unsigned int     data_len,
		  ipmi_pef_done_cb done,
		  void             *cb_data)
{
    pef_set_handler_t *elem;
    int               rv = 0;

    if (pef->destroyed)
	return EINVAL;

    if (!pef->valid)
	return EINVAL;
	
    if (data_len > MAX_IPMI_DATA_SIZE-1)
	return EINVAL;

    elem = ipmi_mem_alloc(sizeof(*elem));
    if (!elem) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_pef_get: could not allocate the pef element");
	return ENOMEM;
    }

    elem->handler = done;
    elem->cb_data = cb_data;
    elem->pef = pef;
    elem->data[0] = parm;
    memcpy(elem->data+1, data, data_len);
    elem->data_len = data_len + 1;
    elem->rv = 0;

    pef_lock(pef);

    if (!opq_new_op(pef->opq, start_config_set, elem, 0))
	rv = ENOMEM;

    pef_unlock(pef);

    return rv;
}

int
ipmi_pef_valid(ipmi_pef_t *pef)
{
    return pef->valid;
}

int
ipmi_pef_supports_diagnostic_interrupt(ipmi_pef_t *pef)
{
    return pef->can_diagnostic_interrupt;
}

int
ipmi_pef_supports_oem_action(ipmi_pef_t *pef)
{
    return pef->can_oem_action;
}

int
ipmi_pef_supports_power_cycle(ipmi_pef_t *pef)
{
    return pef->can_power_cycle;
}

int
ipmi_pef_supports_reset(ipmi_pef_t *pef)
{
    return pef->can_reset;
}

int
ipmi_pef_supports_power_down(ipmi_pef_t *pef)
{
    return pef->can_power_down;
}

int
ipmi_pef_supports_alert(ipmi_pef_t *pef)
{
    return pef->can_alert;
}

unsigned int
ipmi_pef_major_version(ipmi_pef_t *pef)
{
    return pef->major_version;
}

unsigned int
ipmi_pef_minor_version(ipmi_pef_t *pef)
{
    return pef->minor_version;
}

unsigned int
num_event_filter_table_entries(ipmi_pef_t *pef)
{
    return pef->num_eft_entries;
}

ipmi_mcid_t
ipmi_pef_get_mc(ipmi_pef_t *pef)
{
    return pef->mc;
}

typedef struct ipmi_eft_s
{
    unsigned int enable_filter : 1;
    unsigned int filter_type : 2;

    /* Byte 2: Event Filter Action */
    unsigned int diagnostic_interrupt : 1;
    unsigned int oem_action : 1;
    unsigned int power_cycle : 1;
    unsigned int reset : 1;
    unsigned int power_down : 1;
    unsigned int alert : 1;

    /* Byte 3: Alert Policy Number */
    unsigned char alert_policy_number;

    /* Byte 4: Event Severity */
    unsigned char event_severity;

    /* Byte 5 : Generator ID Byte 1 */
    unsigned char generator_id_addr;

    /* Byte 6 : Generator ID Byte 2 */
    unsigned char generator_id_channel_lun;

    /* Byte 7 : Sensor Type */
    unsigned char sensor_type;

    /* Byte 8 : Sensor Number */
    unsigned char sensor_number;

    /* Byte 9 : Event trigger (Event/Reading Type) */
    unsigned char event_trigger;

    /* Byte 10 - 20 : Event data process */
    unsigned short data1_offset_mask; /* byte 10, 11 */
    unsigned char data1_mask;
    unsigned char data1_compare1;
    unsigned char data1_compare2;
    unsigned char data2_mask;
    unsigned char data2_compare1;
    unsigned char data2_compare2;
    unsigned char data3_mask;
    unsigned char data3_compare1;
    unsigned char data3_compare2;
} ipmi_eft_t;

typedef struct ipmi_apt_s
{
    unsigned int policy_num : 4;
    unsigned int enabled : 1;
    unsigned int policy : 3;
    unsigned int channel : 4;
    unsigned int destination_selector : 4;
    unsigned int alert_string_event_specific : 1;
    unsigned int alert_string_selector : 7;
} ipmi_apt_t;

typedef struct ipmi_ask_s
{
    unsigned int event_filter : 4;
    unsigned int alert_string_set : 4;
} ipmi_ask_t;

struct ipmi_pef_config_s
{
    int curr_parm;
    int curr_sel;
    int curr_block;

    ipmi_pef_get_config_cb done;
    void                   *cb_data;

    /* PEF Control */
    unsigned int alert_startup_delay_enabled : 1;
    unsigned int startup_delay_enabled : 1;
    unsigned int event_messages_enabled : 1;
    unsigned int pef_enabled : 1;

    /* PEF Action global control */
    unsigned char diagnostic_interrupt_enabled : 1;
    unsigned char oem_action_enabled : 1;
    unsigned char power_cycle_enabled : 1;
    unsigned char reset_enabled : 1;
    unsigned char power_down_enabled : 1;
    unsigned char alert_enabled : 1;

    unsigned char startup_delay;	/* PEF Startup Delay */
    unsigned char startup_delay_supported;

    unsigned char alert_startup_delay;	/* PEF Alert Startup Delay */
    unsigned char alert_startup_delay_supported;

    unsigned char guid[16];		/* System GUID */
    unsigned char guid_enabled;

    unsigned char num_event_filters;	/* Number of Event Filters */
    ipmi_eft_t	  *efts;		/* Event Filter Table */

    unsigned char num_alert_policies;	/* Number of alert policy entries */
    ipmi_apt_t    *apts;		/* Alert Policy Table */

    unsigned char num_alert_strings;	/* Number of alert strings */
    ipmi_ask_t	  *asks;		/* Alert String Key Table */
    unsigned char **alert_strings;	/* Alert strings */
};


typedef struct pefparms_s pefparms_t;
struct pefparms_s
{
    unsigned int valid : 1;
    unsigned int optional_offset : 8;
    unsigned int offset : 8;
    unsigned int length : 8;
    /* Returns err. */
    int (*get_handler)(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
		       unsigned char *data, unsigned int data_len);
    /* NULL if parameter is read-only */
    void (*set_handler)(ipmi_pef_config_t *pefc, pefparms_t *lp,
			unsigned char *data, unsigned int *data_len);
};

/* Control */
static int gctl(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
		unsigned char *data, unsigned int data_len)
{
    if (err)
	return err;

    pefc->alert_startup_delay_enabled = (data[0] >> 3) & 1;
    pefc->startup_delay_enabled = (data[0] >> 2) & 1;
    pefc->event_messages_enabled = (data[0] >> 2) & 1;
    pefc->pef_enabled = (data[0] >> 0) & 1;

    return 0;
}

static void sctl(ipmi_pef_config_t *pefc, pefparms_t *lp, unsigned char *data,
		 unsigned int *data_len)
{
    data[0] = ((pefc->alert_startup_delay_enabled << 3)
	       || (pefc->startup_delay_enabled << 2)
	       || (pefc->event_messages_enabled << 1)
	       || pefc->pef_enabled);
}

/* Action Global Control */
static int gagc(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
		unsigned char *data, unsigned int data_len)
{
    if (err)
	return err;

    pefc->diagnostic_interrupt_enabled = (data[0] >> 5) & 1;
    pefc->oem_action_enabled = (data[0] >> 4) & 1;
    pefc->power_cycle_enabled = (data[0] >> 3) & 1;
    pefc->reset_enabled = (data[0] >> 2) & 1;
    pefc->power_down_enabled = (data[0] >> 1) & 1;
    pefc->alert_enabled = (data[0] >> 0) & 1;

    return 0;
}

static void sagc(ipmi_pef_config_t *pefc, pefparms_t *lp, unsigned char *data,
		 unsigned int *data_len)
{
    data[0] = ((pefc->diagnostic_interrupt_enabled << 5)
	       | (pefc->oem_action_enabled << 4)
	       | (pefc->power_cycle_enabled << 3)
	       | (pefc->reset_enabled << 2)
	       | (pefc->power_down_enabled << 1)
	       | (pefc->alert_enabled << 0));
}

/* Startup Delay */
static int gsd(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
	       unsigned char *data, unsigned int data_len)
{
    if (err) {
	pefc->startup_delay_supported = 0;
	return 0;
    }

    pefc->startup_delay_supported = 1;
    pefc->startup_delay = data[0] & 0x7f;

    return 0;
}

static void ssd(ipmi_pef_config_t *pefc, pefparms_t *lp, unsigned char *data,
		unsigned int *data_len)
{
    data[0] = pefc->startup_delay;
}

/* Alert Startup Delay */
static int gasd(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
		unsigned char *data, unsigned int data_len)
{
    if (err) {
	pefc->alert_startup_delay_supported = 0;
	return 0;
    }

    pefc->alert_startup_delay_supported = 1;
    pefc->alert_startup_delay = data[0] & 0x7f;

    return 0;
}

static void sasd(ipmi_pef_config_t *pefc, pefparms_t *lp, unsigned char *data,
		 unsigned int *data_len)
{
    data[0] = pefc->alert_startup_delay;
}

/* Number of Event Filters */
static int gnef(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
		unsigned char *data, unsigned int data_len)
{
    int num;

    if (err)
	return err;

    pefc->num_event_filters = 0;
    num = data[0] & 0x7f;
    if (pefc->efts)
	ipmi_mem_free(pefc->efts);
    pefc->efts = NULL;

    if (num == 0)
	return 0;

    pefc->efts = ipmi_mem_alloc(sizeof(ipmi_eft_t) * (num+1));
    if (!pefc->efts)
	return ENOMEM;

    pefc->num_event_filters = num;
    
    return 0;
}

/* Event Filter Table */
static int geft(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
		unsigned char *data, unsigned int data_len)
{
    int        pos = data[0] & 0x7f;
    ipmi_eft_t *t;

    if (err)
	return err;
    if (pos > pefc->num_event_filters)
	return 0; /* Another error check will get this later. */

    t = &(pefc->efts[pos]);
    t->enable_filter = (data[1] >> 7) & 0x1;
    t->filter_type = (data[1] >> 5) & 0x3;
    t->diagnostic_interrupt = (data[2] >> 5) & 1;
    t->oem_action = (data[2] >> 4) & 1;
    t->power_cycle = (data[2] >> 3) & 1;
    t->reset = (data[2] >> 2) & 1;
    t->power_down = (data[2] >> 1) & 1;
    t->alert = (data[2] >> 0) & 1;
    t->alert_policy_number = data[3] & 0xf;
    t->event_severity = data[4];
    t->generator_id_addr = data[5];
    t->generator_id_channel_lun = data[6];
    t->sensor_type = data[7];
    t->sensor_number = data[8];
    t->event_trigger = data[9];
    t->data1_offset_mask = data[10] | (data[11] << 8);
    t->data1_mask = data[12];
    t->data1_compare1 = data[13];
    t->data1_compare2 = data[14];
    t->data2_mask = data[15];
    t->data2_compare1 = data[16];
    t->data2_compare2 = data[17];
    t->data3_mask = data[18];
    t->data3_compare1 = data[19];
    t->data3_compare2 = data[20];
    
    return 0;
}

/* Comes in with position in data[0]. */
static void seft(ipmi_pef_config_t *pefc, pefparms_t *lp, unsigned char *data,
		 unsigned int *data_len)
{
    int        pos = data[0] & 0x7f;
    ipmi_eft_t *t = &(pefc->efts[pos]);

    data[1] = (t->enable_filter << 7) | (t->filter_type << 5);
    data[2] = ((t->diagnostic_interrupt << 5)
	       | (t->oem_action << 4)
	       | (t->power_cycle << 3)
	       | (t->reset << 2)
	       | (t->power_down << 1)
	       | t->alert);
    data[3] = t->alert_policy_number;
    data[4] = t->event_severity;
    data[5] = t->generator_id_addr;
    data[6] = t->generator_id_channel_lun;
    data[7] = t->sensor_type;
    data[8] = t->sensor_number;
    data[9] = t->event_trigger;
    data[10] = t->data1_offset_mask & 0xff;
    data[11] = (t->data1_offset_mask >> 8) & 0xff;
    data[12] = t->data1_mask;
    data[13] = t->data1_compare1;
    data[14] = t->data1_compare2;
    data[15] = t->data2_mask;
    data[16] = t->data2_compare1;
    data[17] = t->data2_compare2;
    data[18] = t->data3_mask;
    data[19] = t->data3_compare1;
    data[20] = t->data3_compare2;
}

/* Number of Alert Policies */
static int gnap(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
		unsigned char *data, unsigned int data_len)
{
    int num;

    if (err)
	return err;

    pefc->num_alert_policies = 0;
    num = data[0] & 0x7f;
    if (pefc->apts)
	ipmi_mem_free(pefc->apts);
    pefc->apts = NULL;

    if (num == 0)
	return 0;

    pefc->apts = ipmi_mem_alloc(sizeof(ipmi_apt_t) * (num + 1));
    if (!pefc->apts)
	return ENOMEM;

    pefc->num_alert_policies = num;
    
    return 0;
}

/* Alert Policy Table */
static int gapt(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
		unsigned char *data, unsigned int data_len)
{
    int        pos = data[0] & 0x7f;
    ipmi_apt_t *t;

    if (err)
	return err;
    if (pos > pefc->num_alert_policies)
	return 0; /* Another error check will get this later. */

    t = &(pefc->apts[pos]);
    t->policy_num = (data[1] >> 4) & 0xf;
    t->enabled = (data[1] >> 3) & 0x1;
    t->policy = (data[1] >> 0) & 0x7;
    t->channel = (data[2] >> 4) & 0xf;
    t->destination_selector = data[2] & 0xf;
    t->alert_string_event_specific = (data[3] >> 7) & 1;
    t->alert_string_selector = data[3] & 0x7f;

    return 0;
}

/* Comes in with position in data[0]. */
static void sapt(ipmi_pef_config_t *pefc, pefparms_t *lp, unsigned char *data,
		 unsigned int *data_len)
{
    int        pos = data[0] & 0x7f;
    ipmi_apt_t *t = &(pefc->apts[pos]);

    data[1] = ((t->policy_num << 4)
	       | (t->enabled << 3)
	       | t->policy);
    data[2] = (t->channel << 4) | t->destination_selector;
    data[3] = (t->alert_string_event_specific << 7) | t->alert_string_selector;
}

/* System GUID */
static int gsg(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
	       unsigned char *data, unsigned int data_len)
{
    if (err)
	return err;

    pefc->guid_enabled = data[0] & 1;
    memcpy(pefc->guid, data+1, 16);

    return 0;
}

static void ssg(ipmi_pef_config_t *pefc, pefparms_t *lp, unsigned char *data,
		unsigned int *data_len)
{
    data[0] = pefc->guid_enabled;
    memcpy(data+1, pefc->guid, 16);
}

/* Number of Alert Strings */
static int gnas(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
		unsigned char *data, unsigned int data_len)
{
    int           num = pefc->num_alert_strings;
    int           i;
    unsigned char ddata[1];

    if (err == IPMI_IPMI_ERR_VAL(0x80)) {
	/* If it's unsupported, then just set it to zero. */
	data = ddata;
	data[0] = 0;
    } else if (err)
	return err;

    if (pefc->asks)
	ipmi_mem_free(pefc->asks);
    if (pefc->alert_strings) {
	for (i=0; i<num; i++) {
	    if (pefc->alert_strings[i])
		ipmi_mem_free(pefc->alert_strings[i]);
	}
	ipmi_mem_free(pefc->alert_strings);
    }
    pefc->asks = NULL;
    pefc->alert_strings = NULL;

    pefc->num_alert_strings = 0;
    num = data[0] & 0x7f;

    if (num == 0)
	return 0;

    pefc->asks = ipmi_mem_alloc(sizeof(ipmi_ask_t) * num);
    if (!pefc->asks)
	return ENOMEM;

    pefc->alert_strings = ipmi_mem_alloc(sizeof(unsigned char *) * num);
    if (!pefc->alert_strings) {
	ipmi_mem_free(pefc->asks);
	pefc->asks = NULL;
	return ENOMEM;
    }

    pefc->num_alert_strings = num;
    
    return 0;
}

/* Alert String Keys */
static int gask(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
		unsigned char *data, unsigned int data_len)
{
    int        pos = data[0] & 0x7f;
    ipmi_ask_t *t = &(pefc->asks[pos]);

    if (err)
	return err;
    if (pos > pefc->num_alert_strings)
	return 0; /* Another error check will get this later. */

    t->event_filter = data[1] & 0x7f;
    t->alert_string_set = data[2] & 0x7f;

    return 0;
}

/* Comes in with position in data[0]. */
static void sask(ipmi_pef_config_t *pefc, pefparms_t *lp, unsigned char *data,
		 unsigned int *data_len)
{
    int        pos = data[0] & 0x7f;
    ipmi_ask_t *t = &(pefc->asks[pos]);

    data[1] = t->event_filter;
    data[2] = t->alert_string_set;
}

/* Alert Strings */
static int gas(ipmi_pef_config_t *pefc, pefparms_t *lp, int err,
	       unsigned char *data, unsigned int data_len)
{
    int           pos = data[0] & 0x7f;
    unsigned char **t = &(pefc->alert_strings[pos]);
    unsigned char *s1, *s2;
    int           len;

    if (err)
	return err;
    if (pos > pefc->num_alert_strings)
	return 0; /* Another error check will get this later. */
    if (data_len-2 == 0)
	return 0;

    data += 2;
    data_len -= 2;

    /* We fetch the blocks successively, so just appending is all that
       is necessary.  The string in nil terminated (per the spec), so
       no worries about zeros, either. */
    s1 = *t;
    if (s1)
	len = strlen(s1);
    else
	len = 0;
    s2 = ipmi_mem_alloc(len + data_len + 1);
    if (!s2)
	return ENOMEM;

    if (s1)
	memcpy(s2, s1, len);
    memcpy(s2+len, data, data_len);
    s2[len+data_len] = '\0';

    *t = s2;
    ipmi_mem_free(s1);
    
    return 0;
}

/* Comes in with position in data[0], block in data[1]. */
static void sas(ipmi_pef_config_t *pefc, pefparms_t *lp, unsigned char *data,
		unsigned int *data_len)
{
    int           pos = data[0] & 0x7f;
    int           block = data[1];
    unsigned char *t = pefc->alert_strings[pos];
    int           len;

    if (!t) {
	data[2] = '\0';
	*data_len = 3;
	return;
    }

    t += (block * 16);
    len = strlen(t);
    if (len >= 16) {
	memcpy(data+2, t, 16);
	*data_len = 18;
    } else {
	memcpy(data+2, t, len+1); /* Make sure to include the nil */
	*data_len = len + 2 + 1;
    }
}

#define OFFSET_OF(x) (((unsigned char *) &(((ipmi_pef_config_t *) NULL)->x)) \
                      - ((unsigned char *) NULL))

#define NUM_PEFPARMS 20
static pefparms_t pefparms[NUM_PEFPARMS] =
{
    { 0, 0, 0,  0, NULL, NULL }, /* IPMI_PEFPARM_SET_IN_PROGRESS	     */
    { 1, 0, 0,  1, gctl, sctl }, /* IPMI_PERPARM_CONTROL		     */
    { 1, 0, 0,  1, gagc, sagc }, /* IPMI_PEFPARM_ACTION_GLOBAL_CONTROL	     */
#undef S
#define S OFFSET_OF(startup_delay_supported)
    { 1, S, 0,  1, gsd,  ssd  }, /* IPMI_PEFPARM_STARTUP_DELAY		     */
#undef S
#define S OFFSET_OF(startup_delay_supported)
    { 1, S, 0,  1, gasd, sasd }, /* IPMI_PEFPARM_ALERT_STARTUP_DELAY	     */
    { 1, 0, 0,  1, gnef, NULL }, /* IPMI_PEFPARM_NUM_EVENT_FILTERS	     */
    { 1, 0, 0, 21, geft, seft }, /* IPMI_PEFPARM_EVENT_FILTER_TABLE	     */
    { 0, 0, 0,  0, NULL, NULL }, /* IPMI_PEFPARM_EVENT_FILTER_TABLE_DATA1    */
    { 1, 0, 0,  1, gnap, NULL }, /* IPMI_PEFPARM_NUM_ALERT_POLICIES	     */
    { 1, 0, 0,  4, gapt, sapt }, /* IPMI_PEFPARM_ALERT_POLICY_TABLE	     */
    { 1, 0, 0, 17, gsg,  ssg  }, /* IPMI_PEFPARM_SYSTEM_GUID		     */
    { 1, 0, 0,  1, gnas, NULL }, /* IPMI_PEFPARM_NUM_ALERT_STRINGS	     */
    { 1, 0, 0,  3, gask, sask }, /* IPMI_PEFPARM_ALERT_STRING_KEY	     */
    { 1, 0, 0, 18, gas,  sas  }, /* IPMI_PEFPARM_ALERT_STRING		     */
};

static void
got_parm(ipmi_pef_t     *pef,
	 int            err,
	 unsigned char  *data,
	 unsigned int   data_len,
	 void           *cb_data)
{
    ipmi_pef_config_t *pefc = cb_data;
    pefparms_t        *lp = &(pefparms[pefc->curr_parm]);

    if ((!err) && data_len < lp->length) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_pefparm_got_parm:"
		 " Invalid data length on parm %d was %d, should have been %d",
		 pefc->curr_parm, data_len, lp->length);
	err = EINVAL;
	goto done;
    }

    err = lp->get_handler(pefc, lp, err, data, data_len);
    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_pefparm_got_parm: Error fetching parm %d: %x",
		 pefc->curr_parm, err);
	goto done;
    }

 next_parm:
    switch (pefc->curr_parm) {
    case IPMI_PEFPARM_NUM_EVENT_FILTERS:
	pefc->curr_parm++;
	if (pefc->num_event_filters == 0)
	    pefc->curr_parm = IPMI_PEFPARM_NUM_ALERT_POLICIES;
	else
	    pefc->curr_sel = 1;
	break;

    case IPMI_PEFPARM_EVENT_FILTER_TABLE:
	if ((data[0] & 0x7f) != pefc->curr_sel) {
	    /* Yikes, wrong selector came back! */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "ipmi_pefparm_got_parm: Error fetching eft %d,"
		     " wrong selector came back, expecting %d, was %d",
		     pefc->curr_parm, pefc->curr_sel, data[0] & 0x7f);
	    err = EINVAL;
	    goto done;
	}
	pefc->curr_sel++;
	if (pefc->curr_sel > pefc->num_event_filters) {
	    pefc->curr_parm++;
	    pefc->curr_sel = 0;
	}
	break;

    case IPMI_PEFPARM_NUM_ALERT_POLICIES:
	pefc->curr_parm++;
	if (pefc->num_alert_policies == 0)
	    pefc->curr_parm = IPMI_PEFPARM_NUM_ALERT_STRINGS;
	else
	    pefc->curr_sel = 1;
	break;

    case IPMI_PEFPARM_ALERT_POLICY_TABLE:
	if ((data[0] & 0x7f) != pefc->curr_sel) {
	    /* Yikes, wrong selector came back! */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "ipmi_pefparm_got_parm: Error fetching apt %d,"
		     " wrong selector came back, expecting %d, was %d",
		     pefc->curr_parm, pefc->curr_sel, data[0] & 0x7f);
	    err = EINVAL;
	    goto done;
	}
	pefc->curr_sel++;
	if (pefc->curr_sel > pefc->num_alert_policies) {
	    pefc->curr_parm++;
	    pefc->curr_sel = 0;
	}
	break;

    case IPMI_PEFPARM_NUM_ALERT_STRINGS:
	pefc->curr_parm++;
	if (pefc->num_alert_strings == 0)
	    goto done;
	pefc->curr_sel = 0;
	break;

    case IPMI_PEFPARM_ALERT_STRING_KEY:
	if ((data[0] & 0x7f) != pefc->curr_sel) {
	    /* Yikes, wrong selector came back! */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "ipmi_pefparm_got_parm: Error fetching ask %d,"
		     " wrong selector came back, expecting %d, was %d",
		     pefc->curr_parm, pefc->curr_sel, data[0] & 0x7f);
	    err = EINVAL;
	    goto done;
	}
	pefc->curr_sel++;
	if (pefc->curr_sel >= pefc->num_alert_strings) {
	    pefc->curr_parm++;
	    pefc->curr_sel = 0;
	    pefc->curr_block = 0;
	}
	break;

    case IPMI_PEFPARM_ALERT_STRING:
	if ((data[0] & 0x7f) != pefc->curr_sel) {
	    /* Yikes, wrong selector came back! */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "ipmi_pefparm_got_parm: Error fetching ask %d,"
		     " wrong selector came back, expecting %d, was %d",
		     pefc->curr_parm, pefc->curr_sel, data[0] & 0x7f);
	    err = EINVAL;
	    goto done;
	}
	if (data[1] != pefc->curr_block) {
	    /* Yikes, wrong block came back! */
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "ipmi_pefparm_got_parm: Error fetching ask %d,"
		     " wrong block came back, expecting %d, was %d",
		     pefc->curr_parm, pefc->curr_block, data[1]);
	    err = EINVAL;
	    goto done;
	}
	if ((data_len < 18) ||
	    (memchr(data+2, '\0', data_len-2)))
	{
	    /* End of string, either a subsize-block or a nil
	       character in the data. */
	    pefc->curr_sel++;
	    if (pefc->curr_sel >= pefc->num_alert_strings)
		goto done;
	} else {
	    /* Not at the end yet. */
	    pefc->curr_block++;
	}
	break;

    default:
	pefc->curr_parm++;
    }

    lp = &(pefparms[pefc->curr_parm]);
    if (!lp->valid)
	goto next_parm;

    err = ipmi_pef_get_parm(pef, pefc->curr_parm, pefc->curr_sel, 0,
			    got_parm, pefc);
    if (err)
	goto done;

    return;

 done:
    if (err) {
	pefc->done(pef, err, NULL, pefc->cb_data);
	ipmi_pef_free_config(pefc);
    } else
	pefc->done(pef, 0, pefc, pefc->cb_data);
}

int ipmi_pef_get_config(ipmi_pef_t             *pefparm,
			ipmi_pef_get_config_cb done,
			void                   *cb_data)
{
    ipmi_pef_config_t *pefc;
    int               rv;

    pefc = ipmi_mem_alloc(sizeof(*pefc));
    if (!pefc)
	return ENOMEM;
    memset(pefc, 0, sizeof(*pefc));

    pefc->curr_parm = 1;
    pefc->curr_sel = 0;
    pefc->done = done;
    pefc->cb_data = cb_data;

    rv = ipmi_pef_get_parm(pefparm, pefc->curr_parm, pefc->curr_sel, 0,
			   got_parm, pefc);
    if (rv)
	ipmi_pef_free_config(pefc);

    return rv;
}

typedef struct setconfig_s
{
    int               err;
    ipmi_pef_done_cb  done;
    void              *cb_data;
    ipmi_pef_config_t *pefc;
} setconfig_t;

static void 
set_clear(ipmi_pef_t *pefparm,
	 int         err,
	 void        *cb_data)
{
    setconfig_t *sc = cb_data;

    if (sc->err)
	err = sc->err;
    sc->done(pefparm, err, sc->cb_data);
    ipmi_mem_free(sc);
}

static void 
commit_done(ipmi_pef_t *pefparm,
	    int        err,
	    void       *cb_data)
{
    setconfig_t   *sc = cb_data;
    unsigned char data[1];
    int           rv;

    /* Note that we ignore the error.  The commit done is optional,
       and must return an error if it is optional, so we just ignore
       the error and clear the field here. */

    /* Commit is done.  The IPMI spec doesn't say if you should set
       the "set in progress" value back to 0 or if it is automatic, so
       we go ahead and do it to be sure. */

    data[0] = 0;
    rv = ipmi_pef_set_parm(pefparm, 0, data, 1, set_clear, sc);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "ipmi_pefparm_commit_done: Error trying to clear the set in"
		 " progress: %x",
		 rv);
	sc->done(pefparm, rv, sc->cb_data);
	ipmi_mem_free(sc);
    }
}

static void 
set_done(ipmi_pef_t *pefparm,
	 int        err,
	 void       *cb_data)
{
    setconfig_t       *sc = cb_data;
    ipmi_pef_config_t *pefc = sc->pefc;
    unsigned char     data[MAX_IPMI_DATA_SIZE];
    pefparms_t        *lp = &(pefparms[pefc->curr_parm]);
    unsigned int      length;

    if (err)
	goto done;

 next_parm:
    switch (pefc->curr_parm) {
    case IPMI_PEFPARM_NUM_EVENT_FILTERS:
	pefc->curr_parm++;
	if (pefc->num_event_filters == 0)
	    pefc->curr_parm = IPMI_PEFPARM_NUM_ALERT_POLICIES;
	else {
	    pefc->curr_sel = 0;
	    data[0] = pefc->curr_sel;
	}
	break;

    case IPMI_PEFPARM_EVENT_FILTER_TABLE:
	pefc->curr_sel++;
	if (pefc->curr_sel >= pefc->num_event_filters) {
	    pefc->curr_parm++;
	    pefc->curr_sel = 0;
	}
	data[0] = pefc->curr_sel;
	break;

    case IPMI_PEFPARM_NUM_ALERT_POLICIES:
	pefc->curr_parm++;
	if (pefc->num_event_filters == 0)
	    pefc->curr_parm = IPMI_PEFPARM_NUM_ALERT_STRINGS;
	else {
	    pefc->curr_sel = 0;
	    data[0] = pefc->curr_sel;
	}
	break;

    case IPMI_PEFPARM_ALERT_POLICY_TABLE:
	pefc->curr_sel++;
	if (pefc->curr_sel >= pefc->num_alert_policies) {
	    pefc->curr_parm++;
	    pefc->curr_sel = 0;
	}
	data[0] = pefc->curr_sel;
	break;

    case IPMI_PEFPARM_NUM_ALERT_STRINGS:
	pefc->curr_parm++;
	if (pefc->num_event_filters == 0)
	    goto done;
	pefc->curr_sel = 0;
	data[0] = pefc->curr_sel;
	break;

    case IPMI_PEFPARM_ALERT_STRING_KEY:
	pefc->curr_sel++;
	if (pefc->curr_sel >= pefc->num_alert_strings) {
	    pefc->curr_parm++;
	    pefc->curr_sel = 0;
	    pefc->curr_block = 0;
	}
	data[0] = pefc->curr_sel;
	data[1] = pefc->curr_block;
	break;

    case IPMI_PEFPARM_ALERT_STRING:
	/* curr_sel increment is done write after the send formatting,
	   because we don't know until there if it's the end of the
	   string. */
	if (pefc->curr_sel >= pefc->num_alert_strings)
	    goto done;
	data[0] = pefc->curr_sel;
	data[1] = pefc->curr_block;
	break;

    default:
	pefc->curr_parm++;
    }

    lp = &(pefparms[pefc->curr_parm]);
    if ((!lp->valid) || (lp->set_handler == NULL)
	|| (lp->optional_offset
	    && !(((unsigned char *) pefc)[lp->optional_offset])))
    {
	/* The parameter is read-only or not supported, just go on. */
	goto next_parm;
    }

    length = lp->length;
    lp->set_handler(pefc, lp, data, &length);
    err = ipmi_pef_set_parm(pefparm, pefc->curr_parm,
			    data, length, set_done, sc);
    if (err)
	goto done;

    if (pefc->curr_parm == IPMI_PEFPARM_ALERT_STRING) {
	/* Special handling for blocks of an alert string */
	if ((length < 18) ||
	    (memchr(data+2, '\0', length)))
	{
	    /* End of string, either a subsize-block or a nil
	       character in the data. */
	    pefc->curr_sel++;
	    pefc->curr_block = 0;
	} else {
	    pefc->curr_block++;
	}
    }
    return;

 done:
    ipmi_pef_free_config(pefc);
    sc->pefc = NULL;
    if (err) {
	data[0] = 0; /* Don't commit the parameters. */
	sc->err = err;
	err = ipmi_pef_set_parm(pefparm, 0, data, 1, set_clear, sc);
    } else {
	data[0] = 3; /* Commit the parameters. */
	err = ipmi_pef_set_parm(pefparm, 0, data, 1, commit_done, sc);
    }
    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "ipmi_pefparm_got_parm: Error trying to clear the set in"
		 " progress: %x",
		 err);
	sc->done(pefparm, err, sc->cb_data);
	ipmi_mem_free(sc);
    }
}

int
ipmi_pef_set_config(ipmi_pef_t        *pef,
		    ipmi_pef_config_t *pefc,
		    ipmi_pef_done_cb  done,
		    void              *cb_data)
{
    setconfig_t   *sc;
    unsigned char data[1];
    int           rv;
    int           i;

    sc = ipmi_mem_alloc(sizeof(*sc));
    if (!sc)
	return ENOMEM;

    sc->pefc = ipmi_mem_alloc(sizeof(*pefc));
    if (!sc->pefc) {
	ipmi_mem_free(sc);
	return ENOMEM;
    }

    *sc->pefc = *pefc;
    sc->pefc->efts = NULL;
    sc->pefc->apts = NULL;
    sc->pefc->asks = NULL;
    sc->pefc->alert_strings = NULL;

    if (pefc->num_event_filters) {
	sc->pefc->efts = ipmi_mem_alloc(sizeof(ipmi_eft_t)
					* (pefc->num_event_filters+1));
	if (!sc->pefc->efts) {
	    rv = ENOMEM;
	    goto out;
	}
	memcpy(sc->pefc->efts, pefc->efts,
	       sizeof(ipmi_eft_t) * (pefc->num_event_filters + 1));
    }

    if (pefc->num_alert_policies) {
	sc->pefc->apts = ipmi_mem_alloc(sizeof(ipmi_apt_t)
					* (pefc->num_alert_policies + 1));
	if (!sc->pefc->apts) {
	    rv = ENOMEM;
	    goto out;
	}
	memcpy(sc->pefc->apts, pefc->apts,
	       sizeof(ipmi_apt_t) * (pefc->num_alert_policies + 1));
    }

    if (pefc->num_alert_strings) {
	sc->pefc->asks = ipmi_mem_alloc(sizeof(ipmi_ask_t)
					* pefc->num_alert_strings);
	if (!sc->pefc->asks) {
	    rv = ENOMEM;
	    goto out;
	}
	memcpy(sc->pefc->asks, pefc->asks,
	       sizeof(ipmi_ask_t) * pefc->num_alert_strings);

	sc->pefc->alert_strings = ipmi_mem_alloc(sizeof(unsigned char *)
						 * pefc->num_alert_strings);
	if (!sc->pefc->alert_strings) {
	    rv = ENOMEM;
	    goto out;
	}
	memset(sc->pefc->asks, 0,
	       sizeof(unsigned char *) * pefc->num_alert_strings);
	
	for (i=0; i<pefc->num_alert_strings; i++) {
	    sc->pefc->alert_strings[i] = ipmi_strdup(pefc->alert_strings[i]);
	    if (!sc->pefc->alert_strings[i]) {
		rv = ENOMEM;
		goto out;
	    }
	}
    }

    sc->pefc->curr_parm = 0;
    sc->pefc->curr_sel = 0;
    sc->pefc->curr_block = 0;
    sc->done = done;
    sc->cb_data = cb_data;

    data[0] = 1; /* Set in progress. */
    rv = ipmi_pef_set_parm(pef, sc->pefc->curr_parm, data, 1,
			   set_done, sc);
 out:
    if (rv) {
	ipmi_pef_free_config(sc->pefc);
	ipmi_mem_free(sc);
    }
    return rv;
}

void
ipmi_pef_free_config(ipmi_pef_config_t *pefc)
{
    int i;

    if (pefc->efts)
	ipmi_mem_free(pefc->efts);
    if (pefc->apts)
	ipmi_mem_free(pefc->apts);
    if (pefc->asks)
	ipmi_mem_free(pefc->asks);
    if (pefc->alert_strings) {
	for (i=0; i<pefc->num_alert_strings; i++) {
	    if (pefc->alert_strings[i])
		ipmi_mem_free(pefc->alert_strings[i]);
	}
	ipmi_mem_free(pefc->alert_strings);
    }
    ipmi_mem_free(pefc);
}

#define PEF_BIT(n) \
unsigned int \
ipmi_pefconfig_get_ ## n(ipmi_pef_config_t *pefc) \
{ \
    return pefc->n; \
} \
int \
ipmi_pefconfig_set_ ## n(ipmi_pef_config_t *pefc, unsigned int val) \
{ \
    pefc->n = (val != 0); \
    return 0; \
}

PEF_BIT(alert_startup_delay_enabled)
PEF_BIT(startup_delay_enabled)
PEF_BIT(event_messages_enabled)
PEF_BIT(pef_enabled)
PEF_BIT(diagnostic_interrupt_enabled)
PEF_BIT(oem_action_enabled)
PEF_BIT(power_cycle_enabled)
PEF_BIT(reset_enabled)
PEF_BIT(power_down_enabled)
PEF_BIT(alert_enabled)

#define PEF_BYTE_SUPPORT(n) \
int \
ipmi_pefconfig_get_ ## n(ipmi_pef_config_t *pefc, unsigned int *val) \
{ \
    if (!pefc->n ## _supported) \
	return ENOTSUP; \
    *val = pefc->n; \
    return 0; \
} \
int \
ipmi_pefconfig_set_ ## n(ipmi_pef_config_t *pefc, unsigned int val) \
{ \
    if (!pefc->n ## _supported) \
	return ENOTSUP; \
    pefc->n = val; \
    return 0; \
}

PEF_BYTE_SUPPORT(startup_delay);
PEF_BYTE_SUPPORT(alert_startup_delay);

int
ipmi_pefconfig_get_guid(ipmi_pef_config_t *pefc,
			unsigned int      *enabled,
			unsigned char     *data,
			unsigned int      *data_len)
{
    if (*data_len <= 16)
        return EINVAL;
    memcpy(data, pefc->guid, 16);
    *enabled = pefc->guid_enabled;
    *data_len = 16;
    return 0;
}

int
ipmi_pefconfig_set_guid(ipmi_pef_config_t *pefc, unsigned int enabled,
			unsigned char *data, unsigned int data_len)
{
    if (data_len != 16)
	return EINVAL;
    pefc->guid_enabled = enabled;
    memcpy(pefc->guid, data, 16);
    return 0;
}

unsigned int
ipmi_pefconfig_get_num_event_filters(ipmi_pef_config_t *pefc)
{
    return pefc->num_event_filters;
}
unsigned int
ipmi_pefconfig_get_num_alert_policies(ipmi_pef_config_t *pefc)
{
    return pefc->num_alert_policies;
}
unsigned int
ipmi_pefconfig_get_num_alert_strings(ipmi_pef_config_t *pefc)
{
    return pefc->num_alert_strings;
}

#define PEF_SUB_BIT(t, c, n) \
int \
ipmi_pefconfig_get_ ## n(ipmi_pef_config_t *pefc, unsigned int sel, \
			 unsigned int *val) \
{ \
    if (sel >= pefc->c) \
	return EINVAL; \
    *val = pefc->t[sel].n; \
    return 0; \
} \
int \
ipmi_pefconfig_set_ ## n(ipmi_pef_config_t *pefc, unsigned int sel, \
			 unsigned int val) \
{ \
    if (sel >= pefc->c) \
	return EINVAL; \
    pefc->t[sel].n = (val != 0); \
    return 0; \
}

#define PEF_SUB_BYTE(t, c, n) \
int \
ipmi_pefconfig_get_ ## n(ipmi_pef_config_t *pefc, unsigned int sel, \
			 unsigned int *val) \
{ \
    if (sel >= pefc->c) \
	return EINVAL; \
    *val = pefc->t[sel].n; \
    return 0; \
} \
int \
ipmi_pefconfig_set_ ## n(ipmi_pef_config_t *pefc, unsigned int sel, \
			 unsigned int val) \
{ \
    if (sel >= pefc->c) \
	return EINVAL; \
    pefc->t[sel].n = val; \
    return 0; \
}

PEF_SUB_BIT(efts, num_event_filters, enable_filter);
PEF_SUB_BYTE(efts, num_event_filters, filter_type);
PEF_SUB_BIT(efts, num_event_filters, diagnostic_interrupt);
PEF_SUB_BIT(efts, num_event_filters, oem_action);
PEF_SUB_BIT(efts, num_event_filters, power_cycle);
PEF_SUB_BIT(efts, num_event_filters, reset);
PEF_SUB_BIT(efts, num_event_filters, power_down);
PEF_SUB_BIT(efts, num_event_filters, alert);
PEF_SUB_BYTE(efts, num_event_filters, alert_policy_number);
PEF_SUB_BYTE(efts, num_event_filters, event_severity);
PEF_SUB_BYTE(efts, num_event_filters, generator_id_addr);
PEF_SUB_BYTE(efts, num_event_filters, generator_id_channel_lun);
PEF_SUB_BYTE(efts, num_event_filters, sensor_type);
PEF_SUB_BYTE(efts, num_event_filters, sensor_number);
PEF_SUB_BYTE(efts, num_event_filters, event_trigger);
PEF_SUB_BYTE(efts, num_event_filters, data1_offset_mask);
PEF_SUB_BYTE(efts, num_event_filters, data1_mask);
PEF_SUB_BYTE(efts, num_event_filters, data1_compare1);
PEF_SUB_BYTE(efts, num_event_filters, data1_compare2);
PEF_SUB_BYTE(efts, num_event_filters, data2_mask);
PEF_SUB_BYTE(efts, num_event_filters, data2_compare1);
PEF_SUB_BYTE(efts, num_event_filters, data2_compare2);
PEF_SUB_BYTE(efts, num_event_filters, data3_mask);
PEF_SUB_BYTE(efts, num_event_filters, data3_compare1);
PEF_SUB_BYTE(efts, num_event_filters, data3_compare2);

PEF_SUB_BYTE(apts, num_alert_policies, policy_num);
PEF_SUB_BIT(apts, num_alert_policies, enabled);
PEF_SUB_BYTE(apts, num_alert_policies, policy);
PEF_SUB_BYTE(apts, num_alert_policies, channel);
PEF_SUB_BYTE(apts, num_alert_policies, destination_selector);
PEF_SUB_BIT(apts, num_alert_policies, alert_string_event_specific);
PEF_SUB_BYTE(apts, num_alert_policies, alert_string_selector);

PEF_SUB_BYTE(asks, num_alert_strings, event_filter);
PEF_SUB_BYTE(asks, num_alert_strings, alert_string_set);

int
ipmi_pefconfig_get_alert_string(ipmi_pef_config_t *pefc, unsigned int sel,
				unsigned char *val, unsigned int len)
{
    if (sel >= pefc->num_alert_strings)
	return EINVAL;
    if (len == 0)
	return EINVAL;
    if (! pefc->alert_strings[sel]) {
	*val = '\0';
	return 0;
    }
    if (strlen((char *) pefc->alert_strings[sel])+1 < len)
	return EAGAIN;
    strcpy(val, pefc->alert_strings[sel]);
    return 0;
}

int
ipmi_pefconfig_set_alert_string(ipmi_pef_config_t *pefc, unsigned int sel,
				unsigned char *val)
{
    unsigned char *s;

    if (sel >= pefc->num_alert_strings)
	return EINVAL;
    s = pefc->alert_strings[sel];
    pefc->alert_strings[sel] = ipmi_strdup((char *) val);
    if (! pefc->alert_strings[sel]) {
	pefc->alert_strings[sel] = s;
	return ENOMEM;
    }
    if (s)
	ipmi_mem_free(s);
    return 0;
}
