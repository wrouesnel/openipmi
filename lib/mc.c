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

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_sdr.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_user.h>
#include <OpenIPMI/ipmi_mc.h>

#include <OpenIPMI/internal/locked_list.h>
#include <OpenIPMI/internal/opq.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_mc.h>
#include <OpenIPMI/internal/ipmi_sel.h>
#include <OpenIPMI/internal/ipmi_oem.h>
#include <OpenIPMI/internal/ipmi_int.h>

#define MAX_SEL_TIME_SET_RETRIES 10

#undef DEBUG_INFO_TRACKING

/* Timer structure for rereading the SEL. */
typedef struct mc_reread_sel_s
{
    char                name[IPMI_MC_NAME_LEN+1];
    int                 timer_running;
    ipmi_lock_t         *lock;
    int                 cancelled;
    ipmi_mc_t           *mc;
    ipmi_mcid_t         mc_id;
    ipmi_sels_fetched_t handler;
    void                *cb_data;
    os_handler_t        *os_hnd;
    os_hnd_timer_id_t   *sel_timer;

    int                 timer_should_run;
    unsigned int        retries;
    int                 sel_time_set;
    int                 processing;

    ipmi_mc_ptr_cb sels_first_read_handler;
    void           *sels_first_read_cb_data;

#ifdef DEBUG_INFO_TRACKING
#define DIT_SIZE 100
#define DIT_LAST (DIT_SIZE-1)
    struct {
	int            line;
	const char     *filename;
	const char     *function;
    } last[DIT_SIZE];
#define DEBUG_INFO(info) (memcpy(info->last, info->last+1,	\
				 sizeof(info->last[0]) * (DIT_LAST)),	\
			  info->last[DIT_LAST].filename = __FILE__,	\
			  info->last[DIT_LAST].line = __LINE__,	\
			  info->last[DIT_LAST].function = __FUNCTION__)
#else
#define DEBUG_INFO(info)
#endif
} mc_reread_sel_t;


typedef struct mc_devid_data_s
{    
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
} mc_devid_data_t;

/*
 * The MC follows a state machine for it's status to keep reporting of
 * active/inactive/fully up sane.  It is driven by the following inputs:
 *
 * _ipmi_mc_handle_new - function call from domain code when MC is detected
 * _ipmi_cleanup_mc - function call from domain code when MC removal is
 *	detected
 * put_done - When the _ipmi_mc_put() calls cause the count to go to 0
 * startup_get - When a startup operation starts
 * startup_done - When a startup operation completes
 *
 * It has the following states:
 *
 * MC_INACTIVE - startup state
 *  _ipmi_mc_handle_new
 *	state = MC_INACTIVE_PEND_STARTUP
 *  _ipmi_cleanup_mc
 *	nil
 *  put_done
 *	nil
 *  startup_get
 *	nil
 *  startup_done
 *	nil
 *
 * MC_INACTIVE_PEND_STARTUP - A startup has been requested.  Wait for the
 * mc to be put_done and start up the MC.
 *  _ipmi_mc_handle_new
 *	nil
 *  _ipmi_cleanup_mc
 *	state = MC_INACTIVE
 *  put_done
 *	state = MC_ACTIVE_IN_STARTUP
 *	startup MC
 *      startup_count = 1
 *      startup_called = False
 *      active = 1
 *      call active handlers
 *  startup_get
 *	nil
 *  startup_done
 *	nil
 *
 * MC_ACTIVE_IN_STARTUP - MC is startup up
 *  _ipmi_mc_handle_new
 *	nil
 *  _ipmi_cleanup_mc
 *	state = MC_ACTIVE_PENDING_CLEANUP
 *  put_done
 *	nil
 *  startup_get
 *	startup_count++
 *  startup_done
 *	startup_count--
 *      if (startup_count == 0 and NOT startup_called)
 *        startup_called = True
 *	  state = MC_ACTIVE_PENDING_FULLY_UP
 *
 * MC_ACTIVE_PEND_FULLY_UP - We have gone fully up, waiting for
 * put_done to go to active and report fully up
 *  _ipmi_mc_handle_new
 *	nil
 *  _ipmi_cleanup_mc
 *	state = MC_ACTIVE_PENDING_CLEANUP
 *  put_done
 *	state = MC_ACTIVE
 *      call fully up handlers
 *  startup_get
 *	nil
 *  startup_done
 *	nil
 *
 * MC_ACTIVE - MC is fully operational
 *  _ipmi_mc_handle_new
 *	nil
 *  _ipmi_cleanup_mc
 *	state = MC_ACTIVE_PENDING_CLEANUP
 *  put_done
 *	nil
 *  startup_get
 *	nil
 *  startup_done
 *	nil
 *
 * MC_ACTIVE_PEND_CLEANUP - A cleanup has been requested, pending for
 * the startup_count to go to zero in a put_done.
 *  _ipmi_mc_handle_new
 *	state = MC_ACTIVE_PEND_CLEANUP_PEND_STARTUP
 *  _ipmi_cleanup_mc
 *	nil
 *  put_done
 *	if (startup_count == 0)
 *        state = MC_INACTIVE
 *	  active = 0
 *	  cleanup MC
 *        call active handlers
 *  startup_get
 *	startup_count++
 *  startup_done
 *	startup_count--
 *
 * MC_ACTIVE_PEND_CLEANUP_PEND_STARTUP - When we were pending close, an
 * _ipmi_mc_handle_new event came in.  We need to finish cleaning up
 * before we restart the MC.
 *  _ipmi_mc_handle_new
 *	nil
 *  _ipmi_cleanup_mc
 *	state = MC_ACTIVE_PENDING_CLEANUP
 *  put_done
 *	if (startup_count == 0)
 *        state = MC_INACTIVE
 *	  active = 0
 *	  cleanup MC
 *        call active handlers
 *        state = MC_ACTIVE_IN_STARTUP
 *	  active = 0
 *	  startup MC
 *        startup_count = True
 *        startup_called = False
 *        active = 1
 *        call active handlers
 *  startup_get
 *	startup_count++
 *  startup_done
 *	startup_count--
 *
 * A few notes:
 *
 * We don't do anything in the startup_get and startup_put operations
 * because the caller must be holding an mc and we want to wait until
 * the put operation to do anything.
 *
 * Same with the handle_new and cleanup calls
 *
 * For the user, you will never get a fully_up call while the MC is
 * inactive.
 */
typedef enum {
    MC_INACTIVE,
    MC_INACTIVE_PEND_STARTUP,
    MC_ACTIVE_IN_STARTUP,
    MC_ACTIVE_PEND_FULLY_UP,
    MC_ACTIVE,
    MC_ACTIVE_PEND_CLEANUP,
    MC_ACTIVE_PEND_CLEANUP_PEND_STARTUP
} mc_state_e;

struct ipmi_mc_s
{
    unsigned int usecount;
    ipmi_lock_t *lock;

    int           in_destroy;

    ipmi_domain_t *domain;
    long          seq;
    ipmi_addr_t   addr;
    int           addr_len;

    mc_state_e state;

    /* How many startup items are pending? */
    unsigned int startup_count;
    int startup_reported;

    /* If we have any external users that do not have direct
       references, we increment the usercount.  This is primarily the
       internal uses in the active_handlers list, but we cannot use
       that list being empty because it also may have external
       users. */
    int usercount;

    /* If the MC is known to be good in the system, then active is
       true.  If active is false, that means that there are sensors
       that refer to this MC, but the MC is not currently in the
       system. */
    int active;

    /* Used to generate unique numbers for the MC. */
    unsigned int uniq_num;

    /* The device SDRs on the MC. */
    ipmi_sdr_info_t *sdrs;

    /* The sensors that came from the device SDR on this MC. */
    ipmi_sensor_t **sensors_in_my_sdr;
    unsigned int  sensors_in_my_sdr_count;

    /* The entities that came from the device SDR on this MC are
       somehow stored in this data structure. */
    void *entities_in_my_sdr;

    /* Sensors that this MC owns (you message this MC to talk to this
       sensor, and events report the MC as the owner. */
    ipmi_sensor_info_t  *sensors;

    ipmi_control_info_t *controls;

    unsigned int in_domain_list : 1; /* Tells if we are in the list of
					our domain yet. */

    /* The system event log, for querying and storing events. */
    ipmi_sel_info_t *sel;

    /* The handler to call for add/delete event operations.  This is NULL
       normally and is only used if the MC has a special delete event
       handler. */
    ipmi_mc_del_event_cb sel_del_event_handler;
    ipmi_mc_add_event_cb sel_add_event_handler;
    ipmi_mc_del_event_cb sel_clear_handler;

    /* Timer for rescanning the sel periodically. */
    mc_reread_sel_t   *sel_timer_info;
    unsigned int      sel_scan_interval; /* seconds between SEL scans */

    /* Is the global events enable for the MC enabled? */
    int events_enabled;

    /* The SEL time when the connection first came up.  Only used at
       startup, after the SEL has been read the first time this will
       be set to zero. */
    ipmi_time_t startup_SEL_time;

    /* The MC's GUID. */
    unsigned int  guid_set : 1;
    unsigned char guid[16];

    void *oem_data;

    ipmi_mc_oem_fixup_sdrs_cb fixup_sdrs_handler;
    void                      *fixup_sdrs_cb_data;

    ipmi_mc_oem_new_sensor_cb new_sensor_handler;
    void                      *new_sensor_cb_data;

    ipmi_oem_event_handler_cb oem_event_handler;
    void                      *oem_event_cb_data;

    ipmi_oem_event_handler_cb sel_oem_event_handler;
    void                      *sel_oem_event_cb_data;

    ipmi_mc_ptr_cb sdrs_first_read_handler;
    void           *sdrs_first_read_cb_data;

    /* Call these when the MC is destroyed. */
    locked_list_t *removed_handlers;

    /* Call these when the MC changes from active to inactive. */
    locked_list_t *active_handlers, *active_handlers_cl;

    /* Called after going active when the MC is fully up. */
    locked_list_t *fully_up_handlers, *fully_up_handlers_cl;

    /* Set if we are treating main SDRs like device SDRs. */
    int treat_main_as_device_sdrs;

    /* The rest is the actual data from the get device id and SDRs.
       There's the normal version, the pending version, and the
       version.  The real version is the one from the get device id
       response, and normal version may have been adjusted by the OEM
       code.  The pending version is used to hold the data until the
       usecount goes to 0; we don't change the user data until no one
       else is using it. */

    mc_devid_data_t devid;
    mc_devid_data_t real_devid;
    mc_devid_data_t pending_devid;
    int pending_devid_data;
    int pending_new_mc;

    /* Name used for reporting.  We add a ' ' onto the end, thus
       the +1. */
    char name[IPMI_MC_NAME_LEN+1];
};

/* Cna the MC do normal operations like check SDRs, fetch the SEL,
   etc?  Must be called with the MC lock held. */
#define mc_op_ready(mc) \
    (((mc)->state == MC_ACTIVE_IN_STARTUP) \
     || ((mc)->state == MC_ACTIVE_PEND_FULLY_UP) \
     || ((mc)->state == MC_ACTIVE))

static void mc_sel_new_event_handler(ipmi_sel_info_t *sel,
				     ipmi_mc_t       *mc,
				     ipmi_event_t    *event,
				     void            *cb_data);

static void sels_start_timer(mc_reread_sel_t *info);
static void start_sel_time_set(ipmi_mc_t *mc, mc_reread_sel_t *info);

static void call_active_handlers(ipmi_mc_t *mc);
static void call_fully_up_handlers(ipmi_mc_t *mc);

/***********************************************************************
 *
 * Routines for creating and destructing MCs.
 *
 **********************************************************************/

static void
mc_set_name(ipmi_mc_t *mc)
{
    int         length;
    ipmi_mcid_t id = ipmi_mc_convert_to_id(mc);

    ipmi_lock(mc->lock);
    length = ipmi_domain_get_name(mc->domain, mc->name, sizeof(mc->name)-3);
    mc->name[length] = '(';
    length++;
    length += snprintf(mc->name+length, IPMI_MC_NAME_LEN-length-3, "%x.%x",
		       id.channel, id.mc_num);
    mc->name[length] = ')';
    length++;
    mc->name[length] = ' ';
    length++;
    mc->name[length] = '\0';
    length++;
    ipmi_unlock(mc->lock);
}

int
ipmi_mc_get_name(ipmi_mc_t *mc, char *name, int length)
{
    int  slen;

    if (length <= 0)
	return 0;

    /* Never changes, no lock needed. */
    slen = strlen(mc->name);
    if (slen == 0) {
	if (name)
	    *name = '\0';
	goto out;
    }

    slen -= 1; /* Remove the trailing ' ' */
    if (slen >= length)
	slen = length - 1;

    if (name) {
	memcpy(name, mc->name, slen);
	name[slen] = '\0';
    }
 out:
    return slen;
}

const char *
_ipmi_mc_name(const ipmi_mc_t *mc)
{
    return mc->name;
}

static os_handler_t *
mc_get_os_hnd(ipmi_mc_t *mc)
{
    ipmi_domain_t *domain = mc->domain;
    return ipmi_domain_get_os_hnd(domain);
}

typedef struct fully_up_cl_info_s
{
    ipmi_mc_ptr_cb handler;
    void           *handler_data;
} fully_up_cl_info_t;

static int
iterate_fully_up_cl(void *cb_data, void *item1, void *item2)
{
    fully_up_cl_info_t     *info = cb_data;
    ipmi_mc_fully_up_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
fully_up_cleanup(void *cb_data, void *item1, void *item2)
{
    ipmi_mc_t *mc = cb_data;
    fully_up_cl_info_t info;

    info.handler = item1;
    info.handler_data = item2;
    locked_list_iterate(mc->fully_up_handlers_cl, iterate_fully_up_cl, &info);
    return LOCKED_LIST_ITER_CONTINUE;
}

typedef struct active_cl_info_s
{
    ipmi_mc_active_cb handler;
    void              *handler_data;
} active_cl_info_t;

static int
iterate_active_cl(void *cb_data, void *item1, void *item2)
{
    active_cl_info_t     *info = cb_data;
    ipmi_mc_active_cl_cb handler = item1;

    handler(info->handler, info->handler_data, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
active_cleanup(void *cb_data, void *item1, void *item2)
{
    ipmi_mc_t *mc = cb_data;
    active_cl_info_t info;

    info.handler = item1;
    info.handler_data = item2;
    locked_list_iterate(mc->active_handlers_cl, iterate_active_cl, &info);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
check_mc_destroy(ipmi_mc_t *mc)
{
    ipmi_domain_t *domain = mc->domain;
    os_handler_t  *os_hnd = mc_get_os_hnd(mc);
    int           rv;

    if ((mc->state == MC_INACTIVE)
	&& (ipmi_controls_get_count(mc->controls) == 0)
	&& (ipmi_sensors_get_count(mc->sensors) == 0)
	&& (mc->usercount == 0))
    {
	mc->in_destroy = 1;
	ipmi_unlock(mc->lock);

	/* There are no sensors associated with this MC, so it's safe
           to delete it.  If there are sensors that still reference
           this MC (such as from another MC's SDR repository, or the
           main SDR repository) we have to leave it inactive but not
           delete it.  The active handlers come from MCDLR and FRUDLR
           SDRs that monitor the MC. */
	_ipmi_remove_mc_from_domain(domain, mc);

	if (mc->sel_timer_info) {
	    if (mc->sel_timer_info->lock) {
		ipmi_lock(mc->sel_timer_info->lock);
		if (mc->sel_timer_info->timer_running) {
		    mc->sel_timer_info->cancelled = 1;
		    rv = os_hnd->stop_timer(os_hnd,
					    mc->sel_timer_info->sel_timer);
		    ipmi_unlock(mc->sel_timer_info->lock);
		    if (!rv) {
			/* If we can stop the timer, free it and it's info.
			   If we can't stop the timer, that means that the
			   code is currently in the timer handler, so we let
			   the "cancelled" value do this for us. */
			ipmi_destroy_lock(mc->sel_timer_info->lock);
			os_hnd->free_timer(os_hnd,
					   mc->sel_timer_info->sel_timer);
			ipmi_mem_free(mc->sel_timer_info);
		    }
		} else {
		    ipmi_unlock(mc->sel_timer_info->lock);
		    ipmi_destroy_lock(mc->sel_timer_info->lock);
		    os_hnd->free_timer(os_hnd, mc->sel_timer_info->sel_timer);
		    ipmi_mem_free(mc->sel_timer_info);
		}
	    } else {
		/* Timer wasn't completely created. */
		if (mc->sel_timer_info->sel_timer)
		    os_hnd->free_timer(os_hnd, mc->sel_timer_info->sel_timer);
		ipmi_mem_free(mc->sel_timer_info);
	    }
	}

	if (mc->removed_handlers)
	    locked_list_destroy(mc->removed_handlers);
    	if (mc->active_handlers) {
	    locked_list_iterate(mc->active_handlers, active_cleanup, mc);
	    locked_list_destroy(mc->active_handlers);
	}
    	if (mc->active_handlers_cl)
	    locked_list_destroy(mc->active_handlers_cl);
    	if (mc->fully_up_handlers) {
	    locked_list_iterate(mc->fully_up_handlers, fully_up_cleanup, mc);
	    locked_list_destroy(mc->fully_up_handlers);
	}
    	if (mc->fully_up_handlers_cl)
	    locked_list_destroy(mc->fully_up_handlers_cl);
	if (mc->sensors)
	    ipmi_sensors_destroy(mc->sensors);
	if (mc->controls)
	    ipmi_controls_destroy(mc->controls);
	if (mc->sdrs)
	    ipmi_sdr_info_destroy(mc->sdrs, NULL, NULL);
	if (mc->sel)
	    ipmi_sel_destroy(mc->sel, NULL, NULL);
	if (mc->lock)
	    ipmi_destroy_lock(mc->lock);

	ipmi_mem_free(mc);
	return 1;
    }
    return 0;
}

int
_ipmi_create_mc(ipmi_domain_t *domain,
		ipmi_addr_t   *addr,
		unsigned int  addr_len,
		ipmi_mc_t     **new_mc)
{
    ipmi_mc_t    *mc;
    int          rv = 0;
    os_handler_t *os_hnd = ipmi_domain_get_os_hnd(domain);

    if (addr_len > sizeof(ipmi_addr_t))
	return EINVAL;

    mc = ipmi_mem_alloc(sizeof(*mc));
    if (!mc)
	return ENOMEM;
    memset(mc, 0, sizeof(*mc));

    mc->state = MC_INACTIVE;

    mc->usecount = 1; /* Require a release */

    mc->domain = domain;

    mc->seq = ipmi_get_seq();

    mc->events_enabled = 1;

    mc->active = 0; /* Start assuming inactive. */

    mc->sensors = NULL;
    mc->sensors_in_my_sdr = NULL;
    mc->sensors_in_my_sdr_count = 0;
    mc->entities_in_my_sdr = NULL;
    mc->controls = NULL;
    mc->new_sensor_handler = NULL;
    rv = ipmi_create_lock(domain, &mc->lock);
    if (rv)
	goto out_err;
    mc->removed_handlers = locked_list_alloc(os_hnd);
    if (!mc->removed_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    mc->active_handlers_cl = locked_list_alloc(os_hnd);
    if (!mc->active_handlers_cl) {
	rv = ENOMEM;
	goto out_err;
    }

    mc->active_handlers = locked_list_alloc(os_hnd);
    if (!mc->active_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    mc->fully_up_handlers_cl = locked_list_alloc(os_hnd);
    if (!mc->fully_up_handlers_cl) {
	rv = ENOMEM;
	goto out_err;
    }
    mc->fully_up_handlers = locked_list_alloc(os_hnd);
    if (!mc->fully_up_handlers) {
	rv = ENOMEM;
	goto out_err;
    }

    mc->sel = NULL;
    mc->sel_scan_interval = ipmi_domain_get_sel_rescan_time(domain);

    memcpy(&(mc->addr), addr, addr_len);
    mc->addr_len = addr_len;
    mc->sdrs = NULL;

    rv = ipmi_sensors_alloc(mc, &(mc->sensors));
    if (rv)
	goto out_err;

    rv = ipmi_controls_alloc(mc, &(mc->controls));
    if (rv)
	goto out_err;

    mc_set_name(mc);

    rv = ipmi_sel_alloc(mc, 0, &(mc->sel));
    if (rv)
	goto out_err;

    mc->sel_timer_info = ipmi_mem_alloc(sizeof(*mc->sel_timer_info));
    if (!mc->sel_timer_info) {
	rv = ENOMEM;
	goto out_err;
    }
    memset(mc->sel_timer_info, 0, sizeof(*mc->sel_timer_info));
    strncpy(mc->sel_timer_info->name, mc->name,
	    sizeof(mc->sel_timer_info->name));
    mc->sel_timer_info->mc_id = ipmi_mc_convert_to_id(mc);
    mc->sel_timer_info->mc = mc;
    mc->sel_timer_info->os_hnd = os_hnd;
    rv = os_hnd->alloc_timer(os_hnd, &mc->sel_timer_info->sel_timer);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock(domain, &mc->sel_timer_info->lock);
    if (rv)
	goto out_err;

    rv = ipmi_sdr_info_alloc(domain, mc, 0, 1, &(mc->sdrs));
    if (rv)
	goto out_err;

    /* When we get new logs, handle them. */
    ipmi_sel_set_new_event_handler(mc->sel,
				   mc_sel_new_event_handler,
				   domain);

 out_err:
    if (rv)
	check_mc_destroy(mc);
    else
	*new_mc = mc;

    return rv;
}

static int
call_removed_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_mc_oem_removed_cb handler = item1;
    ipmi_mc_t              *mc = cb_data;

    ipmi_mc_remove_oem_removed_handler(mc, handler, item2);
    handler(mc->domain, mc, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

/* Must be called with the mc lock held. */
static void
mc_stop_timer(ipmi_mc_t *mc)
{
    os_handler_t *os_hnd = mc_get_os_hnd(mc);
    int          rv;

    /* Make sure the timer stops. */
    ipmi_lock(mc->sel_timer_info->lock);
    mc->sel_timer_info->timer_should_run = 0;
    if (mc->sel_timer_info->timer_running) {
	rv = os_hnd->stop_timer(os_hnd, mc->sel_timer_info->sel_timer);
	if (!rv) {
	    mc->sel_timer_info->timer_running = 0;
	    mc->sel_timer_info->processing = 0;
	}
    }
    if ((mc->startup_count > 0) && !mc->sel_timer_info->processing)
	/* Hack: If we are processing, we will fail the processing or
	   it will complete later and finish.  If we were not
	   processing, then we were just waiting on the timer that was
	   just cancelled.  We decrement if we were waiting on the
	   timer. */
	mc->startup_count--;
    ipmi_unlock(mc->sel_timer_info->lock);
}

static void
mc_cleanup(ipmi_mc_t *mc)
{
    unsigned int  i;
    ipmi_domain_t *domain = mc->domain;

    /* Call the OEM handlers for removal, if it has been registered. */
    locked_list_iterate(mc->removed_handlers, call_removed_handler, mc);
    
    /* First the device SDR sensors, since they can be there for any
       MC. */
    if (mc->sensors_in_my_sdr) {
	for (i=0; i<mc->sensors_in_my_sdr_count; i++) {
	    ipmi_sensor_t *sensor;
	    _ipmi_domain_entity_lock(domain);
	    sensor = mc->sensors_in_my_sdr[i];
	    if (sensor) {
		ipmi_entity_t *entity = ipmi_sensor_get_entity(sensor);
		_ipmi_entity_get(entity);
		_ipmi_sensor_get(sensor);
		_ipmi_domain_entity_unlock(domain);
		ipmi_sensor_destroy(mc->sensors_in_my_sdr[i]);
		_ipmi_sensor_put(sensor);
		_ipmi_entity_put(entity);
	    } else {
		_ipmi_domain_entity_unlock(domain);
	    }
	}
	ipmi_mem_free(mc->sensors_in_my_sdr);
	mc->sensors_in_my_sdr = NULL;
    }

    if (mc->entities_in_my_sdr) {
	ipmi_sdr_entity_destroy(mc->entities_in_my_sdr);
	mc->entities_in_my_sdr = NULL;
    }

    if (mc->sdrs)
	ipmi_sdr_clean_out_sdrs(mc->sdrs);
}

/***********************************************************************
 *
 * Reset routines for MCs.
 *
 **********************************************************************/

typedef struct mc_reset_info_s
{
    ipmi_mc_done_cb done;
    void            *cb_data;
} mc_reset_info_t;

static void
mc_reset_done(ipmi_mc_t  *mc,
	      ipmi_msg_t *rsp,
	      void       *rsp_data)
{
    int             err = 0;
    mc_reset_info_t *info = rsp_data;

    if (rsp->data[0] != 0)
	err = IPMI_IPMI_ERR_VAL(rsp->data[0]);

    if (info->done)
	info->done(mc, err, info->cb_data);

    ipmi_mem_free(info);
}

int
ipmi_mc_reset(ipmi_mc_t       *mc,
	      int             reset_type,
	      ipmi_mc_done_cb done,
	      void            *cb_data)
{
    int             rv;
    ipmi_msg_t      msg;
    mc_reset_info_t *info;

    CHECK_MC_LOCK(mc);

    if (reset_type == IPMI_MC_RESET_COLD)
	msg.cmd = IPMI_COLD_RESET_CMD;
    else if (reset_type == IPMI_MC_RESET_WARM)
	msg.cmd = IPMI_WARM_RESET_CMD;
    else
	return EINVAL;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    info->done = done;
    info->cb_data = cb_data;

    msg.netfn = IPMI_APP_NETFN;
    msg.data = NULL;
    msg.data_len = 0;
    rv = ipmi_mc_send_command(mc, 0, &msg, mc_reset_done, info);
    if (rv)
	ipmi_mem_free(info);

    return rv;
}

/***********************************************************************
 *
 * Event handling.
 *
 **********************************************************************/

/* Got a new event in the system event log that we didn't have before. */
static void
mc_sel_new_event_handler(ipmi_sel_info_t *sel,
			 ipmi_mc_t       *mc,
			 ipmi_event_t    *event,
			 void            *cb_data)
{
    _ipmi_domain_system_event_handler(cb_data, mc, event);
}

int
_ipmi_mc_check_oem_event_handler(ipmi_mc_t *mc, ipmi_event_t *event)
{
    if (mc->oem_event_handler)
	return (mc->oem_event_handler(mc, event, mc->oem_event_cb_data));
    else
	return 0;
}

int
_ipmi_mc_check_sel_oem_event_handler(ipmi_mc_t *mc, ipmi_event_t *event)
{
    if (mc->sel_oem_event_handler)
	return (mc->sel_oem_event_handler(mc, event,
					  mc->sel_oem_event_cb_data));
    else
	return 0;
}


/***********************************************************************
 *
 * SEL handling.
 *
 **********************************************************************/

int
_ipmi_mc_sel_event_add(ipmi_mc_t *mc, ipmi_event_t *event)
{
    return ipmi_sel_event_add(mc->sel, event);
}

ipmi_time_t
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

void
ipmi_mc_set_add_event_handler(ipmi_mc_t            *mc,
			      ipmi_mc_add_event_cb handler)
{
    mc->sel_add_event_handler = handler;
}

void
ipmi_mc_set_sel_clear_handler(ipmi_mc_t            *mc,
			      ipmi_mc_del_event_cb handler)
{
    mc->sel_clear_handler = handler;
}

void
ipmi_mc_set_sel_rescan_time(ipmi_mc_t *mc, unsigned int seconds)
{
    unsigned int old_time;
    CHECK_MC_LOCK(mc);

    if (mc->sel_scan_interval == seconds)
	return;

    old_time = mc->sel_scan_interval;

    mc->sel_scan_interval = seconds;
    if (old_time == 0) {
	/* The old time was zero, so we must restart the timer. */
	ipmi_lock(mc->sel_timer_info->lock);
	sels_start_timer(mc->sel_timer_info);
	ipmi_unlock(mc->sel_timer_info->lock);
    }
}

unsigned int
ipmi_mc_get_sel_rescan_time(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);

    return mc->sel_scan_interval;
}

typedef struct sel_op_done_info_s
{
    ipmi_mc_t       *mc;
    ipmi_mc_done_cb done;
    void            *cb_data;
} sel_op_done_info_t;

static void
sel_op_done(ipmi_sel_info_t *sel,
	    void            *cb_data,
	    int             err)
{
    sel_op_done_info_t *info = cb_data;

    /* No need to refcount, the domain/mc should already be locked. */
    if (info->done)
        info->done(info->mc, err, info->cb_data);
    ipmi_mem_free(info);
}

int
ipmi_mc_del_event(ipmi_mc_t                 *mc,
		  ipmi_event_t              *event, 
		  ipmi_mc_del_event_done_cb handler,
		  void                      *cb_data)
{
    sel_op_done_info_t *sel_info;
    int                rv;

    if (!mc->devid.SEL_device_support)
	return EINVAL;

    /* If we have an OEM handler, call it instead. */
    if (mc->sel_del_event_handler) {
	rv = mc->sel_del_event_handler(mc, event, handler, cb_data);
	return rv;
    }

    sel_info = ipmi_mem_alloc(sizeof(*sel_info));
    if (!sel_info)
	return ENOMEM;

    sel_info->mc = mc;
    sel_info->done = handler;
    sel_info->cb_data = cb_data;

    rv = ipmi_sel_del_event(mc->sel, event, sel_op_done, sel_info);
    if (rv)
	ipmi_mem_free(sel_info);

    return rv;
}

int
ipmi_mc_sel_clear(ipmi_mc_t                 *mc,
		  ipmi_event_t              *last_event, 
		  ipmi_mc_del_event_done_cb handler,
		  void                      *cb_data)
{
    sel_op_done_info_t *sel_info;
    int                rv;

    if (!mc->devid.SEL_device_support)
	return EINVAL;

    /* If we have an OEM handler, call it instead. */
    if (mc->sel_clear_handler) {
	rv = mc->sel_clear_handler(mc, last_event, handler, cb_data);
	return rv;
    }

    sel_info = ipmi_mem_alloc(sizeof(*sel_info));
    if (!sel_info)
	return ENOMEM;

    sel_info->mc = mc;
    sel_info->done = handler;
    sel_info->cb_data = cb_data;

    rv = ipmi_sel_clear(mc->sel, last_event, sel_op_done, sel_info);
    if (rv)
	ipmi_mem_free(sel_info);

    return rv;
}

typedef struct sel_add_op_done_info_s
{
    ipmi_mc_t                 *mc;
    ipmi_mc_add_event_done_cb done;
    void                      *cb_data;
} sel_add_op_done_info_t;

static void sel_add_op_done(ipmi_sel_info_t *sel,
			    void            *cb_data,
			    int             err,
			    unsigned int    record_id)
{
    sel_add_op_done_info_t *info = cb_data;

    /* No need to lock, the domain/mc should already be locked. */
    if (info->done)
        info->done(info->mc, record_id, err, info->cb_data);
    ipmi_mem_free(info);
}

int
ipmi_mc_add_event_to_sel(ipmi_mc_t                 *mc,
			 ipmi_event_t              *event,
			 ipmi_mc_add_event_done_cb handler,
			 void                      *cb_data)
{
    sel_add_op_done_info_t *sel_info;
    int                    rv;

    if (!mc->devid.SEL_device_support)
	return EINVAL;

    /* If we have an OEM handler, call it instead. */
    if (mc->sel_add_event_handler) {
	rv = mc->sel_add_event_handler(mc, event, handler, cb_data);
	return rv;
    }

    sel_info = ipmi_mem_alloc(sizeof(*sel_info));
    if (!sel_info)
	return ENOMEM;

    sel_info->mc = mc;
    sel_info->done = handler;
    sel_info->cb_data = cb_data;

    rv = ipmi_sel_add_event_to_sel(mc->sel, event, sel_add_op_done, sel_info);
    if (rv)
	ipmi_mem_free(sel_info);

    return rv;
}

ipmi_event_t *
ipmi_mc_next_event(ipmi_mc_t *mc, const ipmi_event_t *event)
{
    return ipmi_sel_get_next_event(mc->sel, event);
}

ipmi_event_t *
ipmi_mc_prev_event(ipmi_mc_t *mc, const ipmi_event_t *event)
{
    return ipmi_sel_get_prev_event(mc->sel, event);
}

ipmi_event_t *
ipmi_mc_last_event(ipmi_mc_t *mc)
{
    return ipmi_sel_get_last_event(mc->sel);
}

ipmi_event_t *
ipmi_mc_first_event(ipmi_mc_t *mc)
{
    return ipmi_sel_get_first_event(mc->sel);
}

ipmi_event_t *
ipmi_mc_event_by_recid(ipmi_mc_t    *mc,
                       unsigned int record_id)
{
    return ipmi_sel_get_event_by_recid(mc->sel, record_id);
}

int
ipmi_mc_sel_count(ipmi_mc_t *mc)
{
    unsigned int val = 0;

    ipmi_get_sel_count(mc->sel, &val);
    return val;
}

int
ipmi_mc_sel_entries_used(ipmi_mc_t *mc)
{
    unsigned int val = 0;

    ipmi_get_sel_entries_used(mc->sel, &val);
    return val;
}

int
ipmi_mc_sel_get_major_version(ipmi_mc_t *mc)
{
    int val = 0;

    ipmi_sel_get_major_version(mc->sel, &val);
    return val;
}

int 
ipmi_mc_sel_get_minor_version(ipmi_mc_t *mc)
{
    int val = 0;

    ipmi_sel_get_minor_version(mc->sel, &val);
    return val;
}

int
ipmi_mc_sel_get_num_entries(ipmi_mc_t *mc)
{
    int val = 0;
    
    ipmi_sel_get_num_entries(mc->sel, &val);
    return val;
}

int
ipmi_mc_sel_get_free_bytes(ipmi_mc_t *mc)
{
    int val = 0;
    
    ipmi_sel_get_free_bytes(mc->sel, &val);
    return val;
}

int 
ipmi_mc_sel_get_overflow(ipmi_mc_t *mc)
{
    int val = 0;
    
    ipmi_sel_get_overflow(mc->sel, &val);
    return val;
}

int
ipmi_mc_sel_get_supports_delete_sel(ipmi_mc_t *mc)
{
    int val = 0;
    
    ipmi_sel_get_supports_delete_sel(mc->sel, &val);
    return val;
}

int
ipmi_mc_sel_get_supports_partial_add_sel(ipmi_mc_t *mc)
{
    int val = 0;

    ipmi_sel_get_supports_partial_add_sel(mc->sel, &val);
    return val;
}

int
ipmi_mc_sel_get_supports_reserve_sel(ipmi_mc_t *mc)
{
    int val = 0;

    ipmi_sel_get_supports_reserve_sel(mc->sel, &val);
    return val;
}

int 
ipmi_mc_sel_get_supports_get_sel_allocation(ipmi_mc_t *mc)
{
    int val = 0;

    ipmi_sel_get_supports_get_sel_allocation(mc->sel, &val);
    return val;
}

int
ipmi_mc_sel_get_last_addition_timestamp(ipmi_mc_t *mc)
{
    int val = 0;

    ipmi_sel_get_last_addition_timestamp(mc->sel, &val);
    return val;
}

int
ipmi_mc_set_oem_event_handler(ipmi_mc_t                 *mc,
			      ipmi_oem_event_handler_cb handler,
			      void                      *cb_data)
{
    mc->oem_event_handler = handler;
    mc->oem_event_cb_data = cb_data;
    return 0;
}

int
ipmi_mc_set_sel_oem_event_handler(ipmi_mc_t                 *mc,
				  ipmi_oem_event_handler_cb handler,
				  void                      *cb_data)
{
    mc->sel_oem_event_handler = handler;
    mc->sel_oem_event_cb_data = cb_data;
    return 0;
}

static void mc_reread_sel_timeout(void *cb_data, os_hnd_timer_id_t *id);

/* Must be called with the info lock held. */
static void
sels_start_timer(mc_reread_sel_t *info)
{
    DEBUG_INFO(info);
    info->processing = 0;
    if (info->mc->sel_scan_interval != 0) {
	os_handler_t   *os_hnd = info->os_hnd;
	struct timeval timeout;

	timeout.tv_sec = info->mc->sel_scan_interval;
	timeout.tv_usec = 0;
	info->timer_running = 1;
	os_hnd->start_timer(os_hnd,
			    info->sel_timer,
			    &timeout,
			    mc_reread_sel_timeout,
			    info);
    } else {
	info->timer_running = 0;
    }
}

/* Must be called with the info lock held, will release the lock. */
static void
sels_fetched_call_handler(mc_reread_sel_t *info, int err, int changed,
			  int count)
{
    ipmi_sels_fetched_t handler = NULL;
    void                *cb_data = NULL;
    ipmi_mc_ptr_cb      handler2 = NULL;
    void                *cb_data2 = NULL;

    DEBUG_INFO(info);
    if (info->handler) {
	handler = info->handler;
	cb_data = info->cb_data;
	info->handler = NULL;
    }
    if (info->sels_first_read_handler) {
	handler2 = info->sels_first_read_handler;
	cb_data2 = info->sels_first_read_cb_data;
	info->sels_first_read_handler = NULL;
    }
    ipmi_unlock(info->lock);

    if (handler2)
	handler2(info->mc, cb_data2);

    if (handler)
	handler(info->mc->sel, err, changed, count, cb_data);
}

static void
sels_restart(mc_reread_sel_t *info)
{
    /* After the first SEL fetch, disable looking at the timestamp, in
       case someone messes with the SEL time. */
    DEBUG_INFO(info);
    info->mc->startup_SEL_time = 0;
    info->sel_time_set = 1;

    sels_start_timer(info);
}

static void
sels_fetched_start_timer(ipmi_sel_info_t *sel,
			 int             err,
			 int             changed,
			 unsigned int    count,
			 void            *cb_data)
{
    mc_reread_sel_t *info = cb_data;

    ipmi_lock(info->lock);
    DEBUG_INFO(info);
    if (info->cancelled) {
	DEBUG_INFO(info);
	ipmi_unlock(info->lock);
	info->os_hnd->free_timer(info->os_hnd, info->sel_timer);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	return;
    } else if (! info->timer_should_run) {
	DEBUG_INFO(info);
	info->processing = 0;
	info->timer_running = 0;
	sels_fetched_call_handler(info, ECANCELED, 0, 0);
	return;
    }

    /* After the first SEL fetch, disable looking at the timestamp, in
       case someone messes with the SEL time. */
    info->mc->startup_SEL_time = 0;

    sels_start_timer(info);
    sels_fetched_call_handler(info, err, changed, count);
}

static void
mc_reread_sel_timeout_cb(ipmi_mc_t *mc, void *cb_data)
{
    mc_reread_sel_t *info = cb_data;
    int             rv = EINVAL;

    DEBUG_INFO(info);
    info->processing = 1;
    if (! info->sel_time_set) {
	DEBUG_INFO(mc->sel_timer_info);
	start_sel_time_set(mc, info);
    } else {
	/* Only fetch the SEL if we know the connection is up. */
	if (ipmi_domain_con_up(mc->domain)) {
	    DEBUG_INFO(mc->sel_timer_info);
	    rv = ipmi_sel_get(mc->sel, sels_fetched_start_timer, info);
	}

	/* If we couldn't run the SEL get, then restart the timer now. */
	if (rv) {
	    DEBUG_INFO(mc->sel_timer_info);
	    sels_start_timer(info);
	}
    }

    /* Have to unlock here, because the MC put processing may claim
       this lock. */
    ipmi_unlock(info->lock);
}

static void
mc_reread_sel_timeout(void *cb_data, os_hnd_timer_id_t *id)
{
    mc_reread_sel_t *info = cb_data;
    ipmi_mcid_t     mc_id;
    int             rv;

    ipmi_lock(info->lock);
    DEBUG_INFO(info);
    if (info->cancelled) {
	DEBUG_INFO(info);
	ipmi_unlock(info->lock);
	info->os_hnd->free_timer(info->os_hnd, info->sel_timer);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	return;
    } else if (! info->timer_should_run) {
	DEBUG_INFO(info);
	info->processing = 0;
	info->timer_running = 0;
	sels_fetched_call_handler(info, ECANCELED, 0, 0);
	return;
    }

    mc_id = info->mc_id;

    rv = ipmi_mc_pointer_cb(mc_id, mc_reread_sel_timeout_cb, info);
    if (rv) {
	/* Strange, but correct.  If we get here but the MC no longer
	   exists, we raced with it's destroy.  We still hold the info
	   lock, so just don't start the timer and everything should
	   be happy. */
	DEBUG_INFO(info);
	info->processing = 0;
	info->timer_running = 0;
	ipmi_unlock(info->lock);
    }
}

typedef struct sel_reread_s
{
    ipmi_mc_done_cb handler;
    void            *cb_data;
    ipmi_mcid_t     mcid;
    int             err;
} sel_reread_t;

static void
mc_reread_sel_cb(ipmi_mc_t *mc, void *cb_data)
{
    sel_reread_t *info = cb_data;

    info->handler(mc, info->err, info->cb_data);
}

static void
reread_sel_done(ipmi_sel_info_t *sel,
		int             err,
		int             changed,
		unsigned int    count,
		void            *cb_data)
{
    sel_reread_t *info = cb_data;
    int          rv;

    if (info->handler) {
	if (!sel) {
	    info->handler(NULL, ECANCELED, info->cb_data);
	    goto out;
	}

	rv = ipmi_mc_pointer_cb(info->mcid, mc_reread_sel_cb, info);
	if (rv) {
	    info->handler(NULL, ECANCELED, info->cb_data);
	    goto out;
	}
    }
 out:
    ipmi_mem_free(info);
}

static int start_sel_ops(ipmi_mc_t           *mc,
			 int                 fail_if_down,
			 ipmi_sels_fetched_t handler,
			 void                *cb_data);

int
ipmi_mc_reread_sel(ipmi_mc_t       *mc,
		   ipmi_mc_done_cb handler,
		   void            *cb_data)
{
    sel_reread_t        *info = NULL;
    ipmi_sels_fetched_t cb = NULL;
    int                 rv;

    if (handler) {
	info = ipmi_mem_alloc(sizeof(*info));
	if (!info)
	    return ENOMEM;

	info->handler = handler;
	info->cb_data = cb_data;
	info->mcid = ipmi_mc_convert_to_id(mc);
	info->err = 0;
	cb = reread_sel_done;
    }

    ipmi_lock(mc->lock);
    if (! mc_op_ready(mc)) {
	rv = ECANCELED;
    } else if (mc->sel_timer_info) {
	/* SEL is already set up, just do a request. */
	rv = ipmi_sel_get(mc->sel, cb, info);
    } else {
	/* SEL is not set up, start it. */
	rv = start_sel_ops(mc, 1, cb, info);
    }
    ipmi_unlock(mc->lock);

    if (rv && info) {
	ipmi_mem_free(info);
    }

    return rv;
}

typedef struct sel_get_time_s
{
    sel_get_time_cb handler;
    void            *cb_data;
    char            name[IPMI_MC_NAME_LEN];
} sel_get_time_t;

static void
get_sel_time(ipmi_mc_t  *mc,
	     ipmi_msg_t *rsp,
	     void       *rsp_data)
{
    sel_get_time_t *info = rsp_data;

    if (!mc) {
	/* The MC went away, deliver an error. */
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(get_sel_time): "
		 "MC went away during SEL time fetch.",
		 info->name);
	if (info->handler)
	    info->handler(mc, ECANCELED, 0, info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	/* Error setting the event receiver, report it. */
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(get_sel_time): "
		 "Could not get SEL time for MC at 0x%x",
		 mc->name, ipmi_addr_get_slave_addr(&mc->addr));
	if (info->handler)
	    info->handler(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), 0,
			  info->cb_data);
	goto out;
    }

    if (rsp->data_len < 5) {
	/* Not enough data? */
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(get_sel_time): "
		 "Get SEL time response too short for MC at 0x%x",
		 mc->name, ipmi_addr_get_slave_addr(&mc->addr));
	if (info->handler)
	    info->handler(mc, EINVAL, 0, info->cb_data);
	goto out;
    }

    if (info->handler)
	info->handler(mc, 0, ipmi_get_uint32(rsp->data+1), info->cb_data);

 out:
    ipmi_mem_free(info);
}

int
ipmi_mc_get_current_sel_time(ipmi_mc_t       *mc,
			     sel_get_time_cb handler,
			     void            *cb_data)
{
    ipmi_msg_t     msg;
    sel_get_time_t *info;
    int            rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->handler = handler;
    info->cb_data = cb_data;
    strncpy(info->name, mc->name, sizeof(info->name));

    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_GET_SEL_TIME_CMD;
    msg.data = NULL;
    msg.data_len = 0;
    rv = ipmi_mc_send_command(mc, 0, &msg, get_sel_time, info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

typedef struct set_sel_time_s
{
    ipmi_mc_done_cb handler;
    void            *cb_data;
    char            name[IPMI_MC_NAME_LEN];
} set_sel_time_t;

static void
set_sel_time(ipmi_mc_t  *mc,
	     ipmi_msg_t *rsp,
	     void       *rsp_data)
{
    set_sel_time_t *info = rsp_data;

    if (!mc) {
	/* The MC went away, deliver an error. */
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(set_sel_time): "
		 "MC went away during SEL time fetch.",
		 info->name);
	if (info->handler)
	    info->handler(mc, ECANCELED, info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	/* Error setting the event receiver, report it. */
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(set_sel_time): "
		 "Could not get SEL time for MC at 0x%x",
		 mc->name, ipmi_addr_get_slave_addr(&mc->addr));
	if (info->handler)
	    info->handler(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), info->cb_data);
	goto out;
    }

    if (info->handler)
	info->handler(mc, 0, info->cb_data);

 out:
    ipmi_mem_free(info);
}

int
ipmi_mc_set_current_sel_time(ipmi_mc_t             *mc,
			     const struct timeval  *time,
			     ipmi_mc_done_cb       handler,
			     void                  *cb_data)
{
    ipmi_msg_t     msg;
    int            rv;
    unsigned char  data[4];
    set_sel_time_t *info;


    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->handler = handler;
    info->cb_data = cb_data;
    strncpy(info->name, mc->name, sizeof(info->name));

    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_SET_SEL_TIME_CMD;
    msg.data = data;
    msg.data_len = 4;
    ipmi_set_uint32(data, time->tv_sec);
    rv = ipmi_mc_send_command(mc, 0, &msg, set_sel_time, info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}


/***********************************************************************
 *
 * Handling startup of a new MC
 *
 **********************************************************************/

typedef struct set_event_rcvr_info_s
{
    ipmi_mc_done_cb done;
    void            *cb_data;
} set_event_rcvr_info_t;

static void
set_event_rcvr_done(ipmi_mc_t  *mc,
		    ipmi_msg_t *rsp,
		    void       *rsp_data)
{
    ipmi_mc_done_cb done = NULL;
    void            *cb_data = NULL;
    int             rv = 0;

    if (rsp_data) {
	set_event_rcvr_info_t *info = rsp_data;
	done = info->done;
	cb_data = info->cb_data;
	ipmi_mem_free(info);
    }

    if (!mc) {
	rv = ECANCELED;
	goto out; /* The MC went away, no big deal. */
    }

    if (rsp->data[0] != 0) {
	/* Error setting the event receiver, report it. */
	ipmi_log(IPMI_LOG_WARNING,
		 "%smc.c(set_event_rcvr_done): "
		 "Could not set event receiver for MC at 0x%x",
		 mc->name, ipmi_addr_get_slave_addr(&mc->addr));
	rv = IPMI_IPMI_ERR_VAL(rsp->data[0]);
    }

 out:
    if (done)
	done(mc, rv, cb_data);
}

static int
send_set_event_rcvr(ipmi_mc_t       *mc,
		    unsigned int    addr,
		    ipmi_mc_done_cb done,
		    void            *cb_data)
{
    ipmi_msg_t            msg;
    unsigned char         data[2];
    set_event_rcvr_info_t *info = NULL;

    if (done) {
	info = ipmi_mem_alloc(sizeof(*info));
	if (!info)
	    return ENOMEM;
	info->done = done;
	info->cb_data = cb_data;
    }
    
    msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    msg.cmd = IPMI_SET_EVENT_RECEIVER_CMD;
    msg.data = data;
    msg.data_len = 2;
    data[0] = addr;
    data[1] = 0; /* LUN is 0 per the spec (section 7.2 of 1.5 spec). */
    return ipmi_mc_send_command(mc, 0, &msg, set_event_rcvr_done, info);
    /* No care about return values, if this fails it will be done
       again later. */
}

static void
get_event_rcvr_done(ipmi_mc_t  *mc,
		    ipmi_msg_t *rsp,
		    void       *rsp_data)
{
    if (!mc)
	return; /* The MC went away, no big deal. */

    if (rsp->data[0] != 0) {
	/* Error getting the event receiver, report it. */
	ipmi_log(IPMI_LOG_WARNING,
		 "%smc.c(get_event_rcvr_done): "
		 "Could not get event receiver for MC at 0x%x",
		 mc->name, ipmi_addr_get_slave_addr(&mc->addr));
    } else if (rsp->data_len < 2) {
	ipmi_log(IPMI_LOG_WARNING,
		 "%smc.c(get_event_rcvr_done): "
		 "Get event receiver length invalid for MC at 0x%x",
		 mc->name, ipmi_addr_get_slave_addr(&mc->addr));
    } else if ((rsp->data[1] == 0) && (!mc->events_enabled))  {
	/* Nothing to do, our event receiver is disabled. */
    } else {
	ipmi_domain_t    *domain = ipmi_mc_get_domain(mc);
	ipmi_mc_t        *destmc;
	ipmi_ipmb_addr_t ipmb;

	ipmb.addr_type = IPMI_IPMB_ADDR_TYPE;
	ipmb.channel = ipmi_mc_get_channel(mc);
	ipmb.slave_addr = rsp->data[1];
	ipmb.lun = 0;

	if (mc->events_enabled) {
	    destmc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &ipmb,
					   sizeof(ipmb));
	    if (!destmc || !ipmi_mc_ipmb_event_receiver_support(destmc)) {
		/* The current event receiver doesn't exist or cannot
		   receive events, change it. */
		unsigned int event_rcvr = ipmi_domain_get_event_rcvr(mc->domain);
		if (event_rcvr)
		    send_set_event_rcvr(mc, event_rcvr, NULL, NULL);
	    }
	    if (destmc)
		_ipmi_mc_put(destmc);
	} else {
	    send_set_event_rcvr(mc, 0, NULL, NULL);
	}
    }
}

static void
send_get_event_rcvr(ipmi_mc_t *mc)
{
    ipmi_msg_t    msg;
    
    msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    msg.cmd = IPMI_GET_EVENT_RECEIVER_CMD;
    msg.data = NULL;
    msg.data_len = 0;
    ipmi_mc_send_command(mc, 0, &msg, get_event_rcvr_done, NULL);
    /* No care about return values, if this fails it will be done
       again later. */
}

void
_ipmi_mc_check_event_rcvr(ipmi_mc_t *mc)
{
    if (mc && mc->devid.IPMB_event_generator_support
	&& ipmi_option_set_event_rcvr(mc->domain))
    {
	/* We have an MC that is live (or still live) and generates
	   events, make sure the event receiver is set properly. */
	unsigned int event_rcvr = ipmi_domain_get_event_rcvr(mc->domain);

	/* Don't bother if we have no possible event receivers.*/
	if (event_rcvr) {
	    send_get_event_rcvr(mc);
	}
    }
}

static void
startup_set_sel_time(ipmi_mc_t  *mc,
		     ipmi_msg_t *rsp,
		     void       *rsp_data)
{
    mc_reread_sel_t *info = rsp_data;
    int             rv;

    ipmi_lock(info->lock);
    DEBUG_INFO(info);
    if (info->cancelled) {
	DEBUG_INFO(info);
	ipmi_unlock(info->lock);
	info->os_hnd->free_timer(info->os_hnd, info->sel_timer);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	return;
    } else if (! info->timer_should_run) {
	DEBUG_INFO(info);
	info->processing = 0;
	info->timer_running = 0;
	sels_fetched_call_handler(info, ECANCELED, 0, 0);
	return;
    }

    mc = info->mc;

    if (rsp->data[0] != 0) {
	info->retries++;
	if (info->retries > MAX_SEL_TIME_SET_RETRIES) {
	    DEBUG_INFO(mc->sel_timer_info);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%smc.c(startup_set_sel_time): "
		     "Unable to set the SEL time due to error: %x, aborting",
		     mc->name, rsp->data[0]);
	    mc->startup_SEL_time = 0;
	    info->sel_time_set = 1;
	    sels_restart(info);
	} else {
	    DEBUG_INFO(mc->sel_timer_info);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%smc.c(startup_set_sel_time): "
		     "Unable to set the SEL time due to error: %x, retrying",
		     mc->name, rsp->data[0]);
	    sels_start_timer(info);
	}
	goto out;
    }

    info->sel_time_set = 1;

    rv = ipmi_sel_get(mc->sel, sels_fetched_start_timer, mc->sel_timer_info);
    if (rv) {
	DEBUG_INFO(mc->sel_timer_info);
	ipmi_log(IPMI_LOG_WARNING,
		 "%smc.c(startup_set_sel_time): "
		 "Unable to start an SEL get due to error: %x",
		 mc->name, rsp->data[0]);
	sels_restart(info);
    }

 out:
    ipmi_unlock(info->lock);
}

static void
do_sel_time_set(ipmi_mc_t *mc, mc_reread_sel_t *info)
{
    ipmi_msg_t     msg;
    int            rv;
    unsigned char  data[4];
    struct timeval now;

    DEBUG_INFO(info);
    /* Set the current system event log time.  We do this here so
       we can be sure that the entities are all there before
       reporting events. */
    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_SET_SEL_TIME_CMD;
    msg.data = data;
    msg.data_len = 4;
    gettimeofday(&now, NULL);
    ipmi_set_uint32(data, now.tv_sec);
    mc->startup_SEL_time = ipmi_seconds_to_time(now.tv_sec);
    rv = ipmi_mc_send_command(mc, 0, &msg, startup_set_sel_time, info);
    if (rv) {
	info->retries++;
	if (info->retries > MAX_SEL_TIME_SET_RETRIES) {
	    DEBUG_INFO(mc->sel_timer_info);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%smc.c(first_sel_op): "
		     "Unable to start SEL time set due to error: %x, aborting",
		     mc->name, rv);
	    mc->startup_SEL_time = 0;
	    sels_restart(info);
	} else {
	    DEBUG_INFO(mc->sel_timer_info);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%smc.c(first_sel_op): "
		     "Unable to start SEL time set due to error: %x, retrying",
		     mc->name, rv);
	    sels_start_timer(info);
	}
    }
}

static void
startup_got_sel_time(ipmi_mc_t  *mc,
		     ipmi_msg_t *rsp,
		     void       *rsp_data)
{
    mc_reread_sel_t *info = rsp_data;
    struct timeval  now;
    uint32_t        time;
    int             rv;

    ipmi_lock(info->lock);
    DEBUG_INFO(info);
    if (info->cancelled) {
	DEBUG_INFO(info);
	ipmi_unlock(info->lock);
	info->os_hnd->free_timer(info->os_hnd, info->sel_timer);
	ipmi_destroy_lock(info->lock);
	ipmi_mem_free(info);
	return;
    } else if (! info->timer_should_run) {
	DEBUG_INFO(info);
	info->processing = 0;
	info->timer_running = 0;
	sels_fetched_call_handler(info, ECANCELED, 0, 0);
	return;
    }

    /* MC must be valid if we are not cancelled. */
    mc = info->mc;
    
    if (rsp->data[0] != 0) {
	info->retries++;
	if (info->retries > MAX_SEL_TIME_SET_RETRIES) {
	    DEBUG_INFO(mc->sel_timer_info);
	    ipmi_log(IPMI_LOG_WARNING,
		     "%smc.c(startup_set_sel_time): "
		     "Unable to get the SEL time due to error: %x, aborting",
		     mc->name, rsp->data[0]);
	    mc->startup_SEL_time = 0;
	    sels_restart(info);
	} else {
	    DEBUG_INFO(mc->sel_timer_info);
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%smc.c(startup_set_sel_time): "
		     "Unable to get the SEL time due to error: %x, retrying",
		     mc->name, rsp->data[0]);
	    sels_start_timer(info);
	}
	goto out;
    }

    if (rsp->data_len < 5) {
	info->retries++;
	if (info->retries > MAX_SEL_TIME_SET_RETRIES) {
	    DEBUG_INFO(mc->sel_timer_info);
	    ipmi_log(IPMI_LOG_WARNING,
		     "%smc.c(startup_got_sel_time): "
		     "Get SEL time response too short for MC at 0x%x,"
		     " aborting",
		     mc->name, ipmi_addr_get_slave_addr(&mc->addr));
	    mc->startup_SEL_time = 0;
	    sels_restart(info);
	} else {
	    DEBUG_INFO(mc->sel_timer_info);
	    ipmi_log(IPMI_LOG_WARNING,
		     "%smc.c(startup_got_sel_time): "
		     "Get SEL time response too short for MC at 0x%x,"
		     " retrying",
		     mc->name, ipmi_addr_get_slave_addr(&mc->addr));
	    sels_start_timer(info);
	}
	goto out;
    }

    gettimeofday(&now, NULL);
    time = ipmi_get_uint32(rsp->data+1);

    if ((time < (uint32_t)now.tv_sec) && ipmi_option_set_sel_time(mc->domain)) {
	/* Time is in the past and setting time is requested, move it
	   forward. */
	DEBUG_INFO(mc->sel_timer_info);
	do_sel_time_set(mc, info);
    } else {
	struct timeval tv;
	/* Time is current or in the future, don't move it backwards
	   as that may mess other things up. */
	DEBUG_INFO(mc->sel_timer_info);
	tv.tv_sec = time;
	tv.tv_usec = 0;
	mc->startup_SEL_time = ipmi_timeval_to_time(tv);
	info->sel_time_set = 1;

	rv = ipmi_sel_get(mc->sel, sels_fetched_start_timer,
			  mc->sel_timer_info);
	if (rv) {
	    DEBUG_INFO(mc->sel_timer_info);
	    ipmi_log(IPMI_LOG_WARNING,
		     "%smc.c(startup_got_sel_time): "
		     "Unable to start SEL fetch due to error 0x%x",
		     mc->name, rv);
	    sels_restart(info);
	}
    }

 out:
    ipmi_unlock(info->lock);
}

static void
start_sel_time_set(ipmi_mc_t *mc, mc_reread_sel_t *info)
{
    ipmi_msg_t      msg;
    int             rv;

    DEBUG_INFO(info);
    /* Set the current system event log time.  We do this here so we
       can be sure that the entities are all there before reporting
       events.  But first we fetch it to make sure it needs to be
       changed. */
    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_GET_SEL_TIME_CMD;
    msg.data = NULL;
    msg.data_len = 0;
    rv = ipmi_mc_send_command(mc, 0, &msg, startup_got_sel_time, info);
    if (rv) {
	DEBUG_INFO(mc->sel_timer_info);
	info->retries++;
	if (info->retries > MAX_SEL_TIME_SET_RETRIES) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "%smc.c(start_sel_time_set): "
		     "Unable to start SEL time set due to error: %x, aborting",
		     mc->name, rv);
	    sels_restart(info);
	} else {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%smc.c(start_sel_time_set): "
		     "Unable to start SEL time set due to error: %x, retrying",
		     mc->name, rv);
	    sels_start_timer(info);
	}
    }
}

static int
start_sel_ops(ipmi_mc_t           *mc,
	      int                 fail_if_down,
	      ipmi_sels_fetched_t handler,
	      void                *cb_data)
{
    ipmi_domain_t   *domain = ipmi_mc_get_domain(mc);
    mc_reread_sel_t *info = mc->sel_timer_info;
    int             rv = 0;

    ipmi_lock(info->lock);
    DEBUG_INFO(info);
    if (info->timer_should_run) {
	DEBUG_INFO(info);
	ipmi_unlock(info->lock);
	return EBUSY; /* Already started. */
    }

    info->timer_should_run = 1;
    info->retries = 0;
    info->sel_time_set = 0;

    info->handler = handler;
    info->cb_data = cb_data;

    if (ipmi_domain_con_up(domain)) {
	/* The domain is already up, just start the process. */
	DEBUG_INFO(info);
	info->processing = 1;
	start_sel_time_set(mc, info);
	ipmi_unlock(info->lock);
    } else if (fail_if_down) {
	ipmi_mc_ptr_cb  handler2 = NULL;
	void            *cb_data2 = NULL;
	DEBUG_INFO(info);
	rv = EAGAIN;
	info->timer_should_run = 0;
	info->processing = 0;
	/* SELs not started, just call the handler. */
	if (mc->sel_timer_info->sels_first_read_handler) {
	    handler2 = mc->sel_timer_info->sels_first_read_handler;
	    cb_data2 = mc->sel_timer_info->sels_first_read_cb_data;
	    mc->sel_timer_info->sels_first_read_handler = NULL;
	}
	ipmi_unlock(info->lock);

	if (handler2)
	    handler2(info->mc, cb_data2);
    } else {
	/* The domain is not up yet, wait for it to come up then start
           the process. */
	DEBUG_INFO(info);
	sels_start_timer(info);
	ipmi_unlock(info->lock);
    }
    return rv;
}

void
_ipmi_mc_startup_get(ipmi_mc_t *mc, char *name)
{
    ipmi_lock(mc->lock);
    mc->startup_count++;
    ipmi_unlock(mc->lock);
}

void
_ipmi_mc_startup_put(ipmi_mc_t *mc, char *name)
{
    ipmi_lock(mc->lock);
    DEBUG_INFO(mc->sel_timer_info);
    mc->sel_timer_info->processing = 0;
    mc->startup_count--;
    if (mc->startup_reported || (mc->startup_count > 0)) {
	ipmi_unlock(mc->lock);
	return;
    }
    mc->startup_reported = 1;
    if (mc->state == MC_ACTIVE_IN_STARTUP)
	mc->state = MC_ACTIVE_PEND_FULLY_UP;
    ipmi_unlock(mc->lock);
    _ipmi_put_domain_fully_up(mc->domain, "_ipmi_mc_startup_put");
}

static void
mc_first_sels_read(ipmi_sel_info_t *sel,
		   int             err,
		   int             changed,
		   unsigned int    count,
		   void            *cb_data)
{
    ipmi_mc_t *mc = cb_data;

    _ipmi_mc_startup_put(mc, "mc_first_sels_read");
}

/* This is called after the first sensor scan for the MC, we start up
   timers and things like that here. */
static void
sensors_reread(ipmi_mc_t *mc, int err, void *cb_data)
{
    unsigned int event_rcvr = 0;

    if (!mc) {
	/* MC data is still valid, but the MC is not good any more.
	   We saved it in rsp_data. */
        mc = cb_data;
	DEBUG_INFO(mc->sel_timer_info);
	_ipmi_mc_startup_put(mc, "sensors_reread(3)");
	return; /* domain went away while processing. */
    }

    DEBUG_INFO(mc->sel_timer_info);
    /* See if any presence has changed with the new sensors. */ 
    ipmi_detect_domain_presence_changes(mc->domain, 0);

    /* We set the event receiver here, so that we know all the SDRs
       are installed.  That way any incoming events from the device
       will have the proper sensor set. */
    if (mc->devid.IPMB_event_generator_support
	&& ipmi_option_set_event_rcvr(mc->domain))
    {
	event_rcvr = ipmi_domain_get_event_rcvr(mc->domain);
    }

    if (event_rcvr)
	send_set_event_rcvr(mc, event_rcvr, NULL, NULL);

    ipmi_lock(mc->lock);
    if (mc->sdrs_first_read_handler) {
	ipmi_mc_ptr_cb handler = mc->sdrs_first_read_handler;
	void           *cb_data = mc->sdrs_first_read_cb_data;
	mc->sdrs_first_read_handler = NULL;
	ipmi_unlock(mc->lock);
	handler(mc, cb_data);
    } else
	ipmi_unlock(mc->lock);

    if (mc->devid.SEL_device_support && ipmi_option_SEL(mc->domain)) {
	int rv;
	/* If the MC supports an SEL, start scanning its SEL. */
	DEBUG_INFO(mc->sel_timer_info);
	ipmi_lock(mc->lock);
	rv = start_sel_ops(mc, 0, mc_first_sels_read, mc);
	ipmi_unlock(mc->lock);
	if (rv) {
	    DEBUG_INFO(mc->sel_timer_info);
	    _ipmi_mc_startup_put(mc, "sensors_reread(2)");
	}
    } else {
	DEBUG_INFO(mc->sel_timer_info);
	_ipmi_mc_startup_put(mc, "sensors_reread");
    }
}

static void
got_guid(ipmi_mc_t  *mc,
	 ipmi_msg_t *rsp,
	 void       *rsp_data)
{
    int rv;

    if (!mc) {
	/* MC data is still valid, but the MC is not good any more.
	   We saved it in rsp_data. */
        mc = rsp_data;
	_ipmi_mc_startup_put(mc, "got_guid");
	return; /* domain went away while processing. */
    }

    DEBUG_INFO(mc->sel_timer_info);
    if ((rsp->data[0] == 0) && (rsp->data_len >= 17)) {
	/* We have a GUID, save it */
	ipmi_mc_set_guid(mc, rsp->data+1);
    }

    if (((mc->devid.provides_device_sdrs) || (mc->treat_main_as_device_sdrs))
	&& ipmi_option_SDRs(ipmi_mc_get_domain(mc)))
    {
	DEBUG_INFO(mc->sel_timer_info);
	rv = ipmi_mc_reread_sensors(mc, sensors_reread, mc);
	if (rv) {
	    DEBUG_INFO(mc->sel_timer_info);
	    sensors_reread(mc, 0, NULL);
	}
    } else {
	DEBUG_INFO(mc->sel_timer_info);
	sensors_reread(mc, 0, NULL);
    }
}

static void
mc_startup(ipmi_mc_t *mc)
{
    ipmi_msg_t msg;
    int        rv = 0;

    DEBUG_INFO(mc->sel_timer_info);
    mc->sel_timer_info->processing = 1;
    mc->startup_count = 1;
    mc->startup_reported = 0;

    if (mc->devid.chassis_support && (ipmi_mc_get_address(mc) == 0x20)) {
        rv = _ipmi_chassis_create_controls(mc);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "%smc.c(ipmi_mc_setup_new): "
		     "Unable to create chassis controls.",
		     mc->name);
	    _ipmi_mc_startup_put(mc, "mc_startup(2)");
	    return;
	}
    }

    /* FIXME - handle errors setting up OEM comain information.
       Handle errors so they get retried. */

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_DEVICE_GUID_CMD;
    msg.data_len = 0;
    msg.data = NULL;

    rv = ipmi_mc_send_command(mc, 0, &msg, got_guid, mc);
    if (rv) {
	DEBUG_INFO(mc->sel_timer_info);
	ipmi_log(IPMI_LOG_SEVERE,
		 "%smc.c(ipmi_mc_setup_new): "
		 "Unable to send get guid command.",
		 mc->name);
	_ipmi_mc_startup_put(mc, "mc_startup");
    }
}

/***********************************************************************
 *
 * MC ID and state handling
 *
 **********************************************************************/

void
_ipmi_mc_use(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    mc->usercount++;
}

void
_ipmi_mc_release(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    mc->usercount--;
}

/* Must be holding the domain->mc_lock to call these. */
int
_ipmi_mc_get(ipmi_mc_t *mc)
{
    mc->usecount++;
    return 0;
}

static void
mc_apply_pending(ipmi_mc_t *mc)
{
    if (mc->pending_devid_data) {
	mc->devid = mc->pending_devid;
	mc->pending_devid_data = 0;
	if (mc->pending_new_mc) {
	    _ipmi_mc_handle_new(mc);
	    mc->pending_new_mc = 0;
	}
    }
}

void
_ipmi_mc_put(ipmi_mc_t *mc)
{
    _ipmi_domain_mc_lock(mc->domain);
    if (mc->usecount == 1) {
	/* Make sure this code cannot run when we release the lock. */
	mc->usecount++;
	ipmi_lock(mc->lock);
	switch (mc->state) {
	case MC_INACTIVE_PEND_STARTUP:
	    mc->state = MC_ACTIVE_IN_STARTUP;
	    mc->active = 1;
	    mc_apply_pending(mc);
	    ipmi_unlock(mc->lock);
	    _ipmi_domain_mc_unlock(mc->domain);
	    mc_startup(mc);
	    call_active_handlers(mc);
	    _ipmi_domain_mc_lock(mc->domain);
	    break;

	case MC_ACTIVE_PEND_FULLY_UP:
	    mc->state = MC_ACTIVE;
	    ipmi_unlock(mc->lock);
	    _ipmi_domain_mc_unlock(mc->domain);
	    call_fully_up_handlers(mc);
	    _ipmi_domain_mc_lock(mc->domain);
	    break;

	case MC_ACTIVE_PEND_CLEANUP:
	    mc_stop_timer(mc);
	    if (mc->startup_count > 0) {
		ipmi_unlock(mc->lock);
		goto still_in_startup;
	    }
	    mc->state = MC_INACTIVE;
	    mc->active = 0;
	    ipmi_unlock(mc->lock);
	    _ipmi_domain_mc_unlock(mc->domain);
	    mc_cleanup(mc);
	    call_active_handlers(mc);
	    _ipmi_domain_mc_lock(mc->domain);
	    break;

	case MC_ACTIVE_PEND_CLEANUP_PEND_STARTUP:
	    mc_stop_timer(mc);
	    if (mc->startup_count > 0) {
		ipmi_unlock(mc->lock);
		goto still_in_startup;
	    }
	    mc->state = MC_INACTIVE;
	    mc->active = 0;
	    ipmi_unlock(mc->lock);
	    _ipmi_domain_mc_unlock(mc->domain);
	    mc_cleanup(mc);
	    call_active_handlers(mc);
	    _ipmi_domain_mc_lock(mc->domain);
	    ipmi_lock(mc->lock);
	    mc->state = MC_ACTIVE_IN_STARTUP;
	    mc->active = 1;
	    mc_apply_pending(mc);
	    ipmi_unlock(mc->lock);
	    _ipmi_domain_mc_unlock(mc->domain);
	    mc_startup(mc);
	    call_active_handlers(mc);
	    _ipmi_domain_mc_lock(mc->domain);
	    break;

	default:
	    ipmi_unlock(mc->lock);
	    break;
	}
    still_in_startup:
	mc->usecount--;

	/* Only attempt the destroy if no one else has gotten the MC
	   while we were holding it. */
	if (mc->usecount == 1) {
	    ipmi_lock(mc->lock);
	    if (check_mc_destroy(mc))
		return;
	    ipmi_unlock(mc->lock);
	}
    }
    mc->usecount--;
    _ipmi_domain_mc_unlock(mc->domain);
}

int
_ipmi_mc_handle_new(ipmi_mc_t *mc)
{
    ipmi_lock(mc->lock);
    switch (mc->state) {
    case MC_INACTIVE:
	_ipmi_get_domain_fully_up(mc->domain, "_ipmi_mc_handle_new");
	mc->state = MC_INACTIVE_PEND_STARTUP;
	break;
    case MC_ACTIVE_PEND_CLEANUP:
	_ipmi_get_domain_fully_up(mc->domain, "_ipmi_mc_handle_new");
	mc->state = MC_ACTIVE_PEND_CLEANUP_PEND_STARTUP;
	break;
    default:
	break;
    }
    ipmi_unlock(mc->lock);
    return 0;
}

void
_ipmi_cleanup_mc(ipmi_mc_t *mc)
{
    ipmi_lock(mc->lock);
    switch (mc->state) {
    case MC_INACTIVE_PEND_STARTUP:
	_ipmi_put_domain_fully_up(mc->domain, "_ipmi_cleanup_mc");
	mc->state = MC_INACTIVE;
	break;
    case MC_ACTIVE_IN_STARTUP:
	mc->state = MC_ACTIVE_PEND_CLEANUP;
	ipmi_unlock(mc->lock);
	ipmi_sdr_cleanout_timer(mc->sdrs);
	/* FIXME - shut down startup code */
	goto out;
    case MC_ACTIVE:
    case MC_ACTIVE_PEND_FULLY_UP:
	mc->state = MC_ACTIVE_PEND_CLEANUP;
	ipmi_unlock(mc->lock);
	ipmi_sdr_cleanout_timer(mc->sdrs);
	goto out;
    case MC_ACTIVE_PEND_CLEANUP_PEND_STARTUP:
	_ipmi_put_domain_fully_up(mc->domain, "_ipmi_cleanup_mc");
	mc->state = MC_ACTIVE_PEND_CLEANUP;
	break;
    default:
	break;
    }
    ipmi_unlock(mc->lock);
 out:
    return;
}

ipmi_mcid_t
ipmi_mc_convert_to_id(ipmi_mc_t *mc)
{
    ipmi_mcid_t val;

    CHECK_MC_LOCK(mc);

    val.domain_id = ipmi_domain_convert_to_id(mc->domain);
    val.mc_num = ipmi_mc_get_address(mc);
    val.channel = ipmi_mc_get_channel(mc);
    val.seq = mc->seq;
    return val;
}

typedef struct mc_ptr_info_s
{
    int            err;
    int            cmp_seq;
    ipmi_mcid_t    id;
    ipmi_mc_ptr_cb handler;
    void           *cb_data;
} mc_ptr_info_t;

static void
mc_ptr_cb(ipmi_domain_t *domain, void *cb_data)
{
    mc_ptr_info_t *info = cb_data;
    ipmi_addr_t   addr;
    unsigned int  addr_len;
    ipmi_mc_t     *mc;

    if (info->id.channel == IPMI_BMC_CHANNEL) {
	ipmi_system_interface_addr_t *si = (void *) &addr;

	si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si->channel = info->id.mc_num;
	si->lun = 0;
	addr_len = sizeof(*si);
    } else {
	ipmi_ipmb_addr_t *ipmb = (void *) &addr;

	ipmb->addr_type = IPMI_IPMB_ADDR_TYPE;
	ipmb->channel = info->id.channel;
	ipmb->slave_addr = info->id.mc_num;
	ipmb->lun = 0;
	addr_len = sizeof(*ipmb);
    }

    mc = _ipmi_find_mc_by_addr(domain, &addr, addr_len);
    if (mc) {
	if (info->cmp_seq && (mc->seq != info->id.seq)) {
	    _ipmi_mc_put(mc);
	    return;
	}

	info->err = 0;
	info->handler(mc, info->cb_data);
	_ipmi_mc_put(mc);
    }
}

int
ipmi_mc_pointer_cb(ipmi_mcid_t id, ipmi_mc_ptr_cb handler, void *cb_data)
{
    int           rv;
    mc_ptr_info_t info;

    info.err = EINVAL;
    info.id = id;
    info.handler = handler;
    info.cb_data = cb_data;
    info.cmp_seq = 1;
    rv = ipmi_domain_pointer_cb(id.domain_id, mc_ptr_cb, &info);
    if (!rv)
	rv = info.err;
    return rv;
}

int
ipmi_mc_pointer_noseq_cb(ipmi_mcid_t    id,
			 ipmi_mc_ptr_cb handler,
			 void           *cb_data)
{
    int           rv;
    mc_ptr_info_t info;

    info.err = EINVAL;
    info.id = id;
    info.handler = handler;
    info.cb_data = cb_data;
    info.cmp_seq = 0;
    rv = ipmi_domain_pointer_cb(id.domain_id, mc_ptr_cb, &info);
    if (!rv)
	rv = info.err;
    return rv;
}

int
ipmi_cmp_mc_id_noseq(ipmi_mcid_t id1, ipmi_mcid_t id2)
{
    int d;

    d = ipmi_cmp_domain_id(id1.domain_id, id2.domain_id);
    if (d)
	return d;

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

int
ipmi_cmp_mc_id(ipmi_mcid_t id1, ipmi_mcid_t id2)
{
    int d;

    d = ipmi_cmp_mc_id_noseq(id1, id2);
    if (d)
	return d;

    if (id1.seq > id2.seq)
	return 1;
    if (id1.seq < id2.seq)
	return -1;
    return 0;
}

void
ipmi_mc_id_set_invalid(ipmi_mcid_t *id)
{
    memset(id, 0, sizeof(*id));
}

int
ipmi_mc_id_is_invalid(ipmi_mcid_t *id)
{
    return (id->domain_id.domain == NULL);
}

/***********************************************************************
 *
 * Handle sending commands and getting responses.
 *
 **********************************************************************/

static int
addr_rsp_handler(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_addr_t                *addr = &rspi->addr;
    unsigned int               addr_len = rspi->addr_len;
    ipmi_msg_t                 *msg = &rspi->msg;
    ipmi_mc_response_handler_t rsp_handler = rspi->data2;
    ipmi_mc_t                  *mc;

    if (rsp_handler) {
	if (domain)
	    mc = _ipmi_find_mc_by_addr(domain, addr, addr_len);
	else
	    mc = NULL;
	rsp_handler(mc, msg, rspi->data1);
	if (mc)
	    _ipmi_mc_put(mc);
    }
    return IPMI_MSG_ITEM_NOT_USED;
}

int
ipmi_mc_send_command(ipmi_mc_t                  *mc,
		     unsigned int               lun,
		     const ipmi_msg_t           *msg,
		     ipmi_mc_response_handler_t rsp_handler,
		     void                       *rsp_data)
{
    int           rv;
    ipmi_addr_t   addr = mc->addr;
    ipmi_domain_t *domain;

    CHECK_MC_LOCK(mc);

    rv = ipmi_addr_set_lun(&addr, lun);
    if (rv)
	return rv;

    domain = ipmi_mc_get_domain(mc);

    rv = ipmi_send_command_addr(domain,
				&addr, mc->addr_len,
				msg,
				addr_rsp_handler,
				rsp_data,
				rsp_handler);
    return rv;
}

int
ipmi_mc_send_command_sideeff(ipmi_mc_t                  *mc,
			     unsigned int               lun,
			     const ipmi_msg_t           *msg,
			     ipmi_mc_response_handler_t rsp_handler,
			     void                       *rsp_data)
{
    int           rv;
    ipmi_addr_t   addr = mc->addr;
    ipmi_domain_t *domain;

    CHECK_MC_LOCK(mc);

    rv = ipmi_addr_set_lun(&addr, lun);
    if (rv)
	return rv;

    domain = ipmi_mc_get_domain(mc);

    rv = ipmi_send_command_addr_sideeff(domain,
					&addr, mc->addr_len,
					msg,
					addr_rsp_handler,
					rsp_data,
					rsp_handler);
    return rv;
}

/***********************************************************************
 *
 * Handle global OEM callbacks for new MCs.
 *
 **********************************************************************/

typedef struct oem_handlers_s {
    unsigned int                 manufacturer_id;
    unsigned int                 first_product_id;
    unsigned int                 last_product_id;
    ipmi_oem_mc_match_handler_cb handler;
    ipmi_oem_shutdown_handler_cb shutdown;
    void                         *cb_data;
} oem_handlers_t;

static locked_list_t *oem_handlers;

int
ipmi_register_oem_handler(unsigned int                 manufacturer_id,
			  unsigned int                 product_id,
			  ipmi_oem_mc_match_handler_cb handler,
			  ipmi_oem_shutdown_handler_cb shutdown,
			  void                         *cb_data)
{
    oem_handlers_t *new_item;
    int            rv;

    /* This might be called before initialization, so be 100% sure. */
    rv = _ipmi_mc_init();
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

    if (! locked_list_add(oem_handlers, new_item, NULL)) {
	ipmi_mem_free(new_item);
	return ENOMEM;
    }

    return 0;
}

int
ipmi_register_oem_handler_range(unsigned int                 manufacturer_id,
				unsigned int                 first_product_id,
				unsigned int                 last_product_id,
				ipmi_oem_mc_match_handler_cb handler,
				ipmi_oem_shutdown_handler_cb shutdown,
				void                         *cb_data)
{
    oem_handlers_t *new_item;
    int            rv;

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

    if (! locked_list_add(oem_handlers, new_item, NULL)) {
	ipmi_mem_free(new_item);
	return ENOMEM;
    }

    return 0;
}

typedef struct handler_cmp_s
{
    int          rv;
    unsigned int manufacturer_id;
    unsigned int first_product_id;
    unsigned int last_product_id;
    ipmi_mc_t    *mc;
} handler_cmp_t;

static int
oem_handler_cmp_dereg(void *cb_data, void *item1, void *item2)
{
    oem_handlers_t *hndlr = item1;
    handler_cmp_t  *cmp = cb_data;

    if ((hndlr->manufacturer_id == cmp->manufacturer_id)
	&& (hndlr->first_product_id <= cmp->first_product_id)
	&& (hndlr->last_product_id >= cmp->last_product_id))
    {
	cmp->rv = 0;
	locked_list_remove(oem_handlers, item1, item2);
	ipmi_mem_free(hndlr);
	return LOCKED_LIST_ITER_STOP;
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

int
ipmi_deregister_oem_handler(unsigned int manufacturer_id,
			    unsigned int product_id)
{
    handler_cmp_t  tmp;

    tmp.rv = ENOENT;
    tmp.manufacturer_id = manufacturer_id;
    tmp.first_product_id = product_id;
    tmp.last_product_id = product_id;
    locked_list_iterate(oem_handlers, oem_handler_cmp_dereg, &tmp);
    return tmp.rv;
}

int
ipmi_deregister_oem_handler_range(unsigned int manufacturer_id,
				  unsigned int first_product_id,
				  unsigned int last_product_id)
{
    handler_cmp_t  tmp;

    tmp.rv = ENOENT;
    tmp.manufacturer_id = manufacturer_id;
    tmp.first_product_id = first_product_id;
    tmp.last_product_id = last_product_id;
    locked_list_iterate(oem_handlers, oem_handler_cmp_dereg, &tmp);
    return tmp.rv;
}

static int
oem_handler_call(void *cb_data, void *item1, void *item2)
{
    oem_handlers_t *hndlr = item1;
    handler_cmp_t  *cmp = cb_data;

    if ((hndlr->manufacturer_id == cmp->manufacturer_id)
	&& (hndlr->first_product_id <= cmp->first_product_id)
	&& (hndlr->last_product_id >= cmp->last_product_id))
    {
	cmp->rv = hndlr->handler(cmp->mc, hndlr->cb_data);
	return LOCKED_LIST_ITER_STOP;
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
check_oem_handlers(ipmi_mc_t *mc)
{
    handler_cmp_t  tmp;

    tmp.rv = 0;
    tmp.manufacturer_id = mc->pending_devid.manufacturer_id;
    tmp.first_product_id = mc->pending_devid.product_id;
    tmp.last_product_id = mc->pending_devid.product_id;
    tmp.mc = mc;
    locked_list_iterate(oem_handlers, oem_handler_call, &tmp);
    return tmp.rv;
}


/***********************************************************************
 *
 * device SDR handling.
 *
 **********************************************************************/

typedef struct sdr_fetch_info_s
{
    ipmi_domain_t    *domain;
    ipmi_mcid_t      source_mc; /* This is used to scan the SDRs. */
    ipmi_mc_done_cb  done;
    void             *done_data;
    int              err;
    int              changed;
    ipmi_sdr_info_t  *sdrs;
} sdr_fetch_info_t;

int
ipmi_mc_set_main_sdrs_as_device(ipmi_mc_t *mc)
{
    int             rv;
    ipmi_sdr_info_t *new_sdrs;

    rv = ipmi_sdr_info_alloc(ipmi_mc_get_domain(mc), mc, 0, 0, &new_sdrs);
    if (rv)
	return rv;

    mc->treat_main_as_device_sdrs = 1;
    if (mc->sdrs)
	ipmi_sdr_info_destroy(mc->sdrs, NULL, NULL);
    mc->sdrs = new_sdrs;

    /* Note that we don't reread the sensors, so this must be done
       before the sensor read operation. */
    return 0;
}

static void
sdr_reread_done(sdr_fetch_info_t *info, ipmi_mc_t *mc, int err)
{
    if (info->done)
	info->done(mc, err, info->done_data);
    ipmi_mem_free(info);
}

static void
sdrs_fetched_mc_cb(ipmi_mc_t *mc, void *cb_data)
{
    sdr_fetch_info_t *info = (sdr_fetch_info_t *) cb_data;
    int              rv = 0;

    if (info->err) {
	sdr_reread_done(info, mc, info->err);
	return;
    }

    if (mc->fixup_sdrs_handler)
	mc->fixup_sdrs_handler(mc, info->sdrs, mc->fixup_sdrs_cb_data);

    if (info->changed) {
	ipmi_entity_scan_sdrs(info->domain, mc,
			      ipmi_domain_get_entities(info->domain),
			      info->sdrs);
	rv = ipmi_sensor_handle_sdrs(info->domain, mc, info->sdrs);

	if (!rv)
	    ipmi_detect_domain_presence_changes(info->domain, 0);
    }

    sdr_reread_done(info, mc, rv);
}

static void
sdrs_fetched(ipmi_sdr_info_t *sdrs,
	     int             err,
	     int             changed,
	     unsigned int    count,
	     void            *cb_data)
{
    sdr_fetch_info_t *info = (sdr_fetch_info_t *) cb_data;
    int              rv = 0;

    info->err = err;
    info->changed = changed;
    info->sdrs = sdrs;
    rv = ipmi_mc_pointer_cb(info->source_mc, sdrs_fetched_mc_cb, info);
    if (rv)
	sdr_reread_done(info, NULL, ECANCELED);
}

int
ipmi_mc_reread_sensors(ipmi_mc_t       *mc,
		       ipmi_mc_done_cb done,
		       void            *done_data)
{
    sdr_fetch_info_t   *info;
    int                rv = 0;
    ipmi_sensor_info_t *sensors;

    CHECK_MC_LOCK(mc);

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    sensors = _ipmi_mc_get_sensors(mc);

    info->source_mc = ipmi_mc_convert_to_id(mc);
    info->domain = ipmi_mc_get_domain(mc);
    info->done = done;
    info->done_data = done_data;

    ipmi_lock(mc->lock);
    if (! mc_op_ready(mc)) {
	ipmi_unlock(mc->lock);
	rv = ECANCELED;
    } else {
	ipmi_unlock(mc->lock);
	rv = ipmi_sdr_fetch(ipmi_mc_get_sdrs(mc), sdrs_fetched, info);
    }
    if (rv)
	ipmi_mem_free(info);

    return rv;
}

/***********************************************************************
 *
 * Checking for the validity and currentness of MC data.
 *
 **********************************************************************/

/* Check the MC, we reread the SDRs and check the event receiver. */
void
_ipmi_mc_check_mc(ipmi_mc_t *mc)
{
    if ((mc->devid.provides_device_sdrs) || (mc->treat_main_as_device_sdrs))
	ipmi_mc_reread_sensors(mc, NULL, NULL);
    _ipmi_mc_check_event_rcvr(mc);
}



/***********************************************************************
 *
 * Handle the boatloads of information from a get device id.
 *
 **********************************************************************/

int
_ipmi_mc_get_device_id_data_from_rsp(ipmi_mc_t *mc, ipmi_msg_t *rsp)
{
    unsigned char *rsp_data = rsp->data;
    int           rv = 0;

    if (rsp_data[0] != 0) {
	return IPMI_IPMI_ERR_VAL(rsp_data[0]);
    }

    if (rsp->data_len < 12) {
	if ((rsp->data[0] == 0) && (rsp->data_len >= 6)) {
	    int major_version = rsp->data[5] & 0xf;
	    int minor_version = (rsp->data[5] >> 4) & 0xf;

	    if (major_version < 1) {
		ipmi_log(IPMI_LOG_ERR_INFO,
			 "%smc.c(_ipmi_mc_get_device_id_data_from_rsp): "
			 "IPMI version of the MC at address 0x%2.2x is %d.%d,"
			 " which is older than OpenIPMI supports",
			 mc->name, ipmi_addr_get_slave_addr(&mc->addr),
			 major_version, minor_version);
		return EINVAL;
	    }
	}
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(_ipmi_mc_get_device_id_data_from_rsp): "
		 "Invalid return from IPMI Get Device ID from address 0x%2.2x,"
		 " something is seriously wrong with the MC, length is %d",
		 mc->name, ipmi_addr_get_slave_addr(&mc->addr), rsp->data_len);
	return EINVAL;
    }

    ipmi_lock(mc->lock);

    /* Pend these to be installed when nobody is using them. */
    mc->pending_devid.device_id = rsp_data[1];
    mc->pending_devid.device_revision = rsp_data[2] & 0xf;
    mc->pending_devid.provides_device_sdrs = (rsp_data[2] & 0x80) == 0x80;
    mc->pending_devid.device_available = (rsp_data[3] & 0x80) == 0x80;
    mc->pending_devid.major_fw_revision = rsp_data[3] & 0x7f;
    mc->pending_devid.minor_fw_revision = rsp_data[4];
    mc->pending_devid.major_version = rsp_data[5] & 0xf;
    mc->pending_devid.minor_version = (rsp_data[5] >> 4) & 0xf;
    mc->pending_devid.chassis_support = (rsp_data[6] & 0x80) == 0x80;
    mc->pending_devid.bridge_support = (rsp_data[6] & 0x40) == 0x40;
    mc->pending_devid.IPMB_event_generator_support
	= (rsp_data[6] & 0x20) == 0x20;
    mc->pending_devid.IPMB_event_receiver_support
	= (rsp_data[6] & 0x10) == 0x10;
    mc->pending_devid.FRU_inventory_support = (rsp_data[6] & 0x08) == 0x08;
    mc->pending_devid.SEL_device_support = (rsp_data[6] & 0x04) == 0x04;
    mc->pending_devid.SDR_repository_support = (rsp_data[6] & 0x02) == 0x02;
    mc->pending_devid.sensor_device_support = (rsp_data[6] & 0x01) == 0x01;
    mc->pending_devid.manufacturer_id = (rsp_data[7]
				 | (rsp_data[8] << 8)
				 | (rsp_data[9] << 16));
    mc->pending_devid.product_id = rsp_data[10] | (rsp_data[11] << 8);

    if (rsp->data_len < 16) {
	/* no aux revision. */
	memset(mc->pending_devid.aux_fw_revision, 0, 4);
    } else {
	memcpy(mc->pending_devid.aux_fw_revision, rsp_data + 12, 4);
    }

    /* Copy these to the version we use for comparison. */
    mc->real_devid = mc->pending_devid;

    /* Either copy it or mark it to be copied. */
    if (mc->usecount == 1) {
	mc->devid = mc->pending_devid;
	mc->pending_devid_data = 0;
	mc->pending_new_mc = 0;
	ipmi_unlock(mc->lock);

	/* OEM handlers set the pending data. */
	rv = check_oem_handlers(mc);
    } else {
	mc->pending_devid_data = 1;
	mc->pending_new_mc = 1;
	rv = EAGAIN; /* Tell the user that they must call the OEM
			handlers check later when the MC is
			released. */
	ipmi_unlock(mc->lock);
    }

    return rv;
}

int
_ipmi_mc_device_data_compares(ipmi_mc_t  *mc,
			      ipmi_msg_t *rsp)
{
    unsigned char *rsp_data = rsp->data;

    if (rsp->data_len < 12) {
	return EINVAL;
    }

    if (mc->real_devid.device_id != rsp_data[1])
	return 0;

    if (mc->real_devid.device_revision != (rsp_data[2] & 0xf))
	return 0;
    
    if (mc->real_devid.provides_device_sdrs != ((rsp_data[2] & 0x80) == 0x80))
	return 0;

    if (mc->real_devid.device_available != ((rsp_data[3] & 0x80) == 0x80))
	return 0;

    if (mc->real_devid.major_fw_revision != (rsp_data[3] & 0x7f))
	return 0;

    if (mc->real_devid.minor_fw_revision != (rsp_data[4]))
	return 0;

    if (mc->real_devid.major_version != (rsp_data[5] & 0xf))
	return 0;

    if (mc->real_devid.minor_version != ((rsp_data[5] >> 4) & 0xf))
	return 0;

    if (mc->real_devid.chassis_support != ((rsp_data[6] & 0x80) == 0x80))
	return 0;

    if (mc->real_devid.bridge_support != ((rsp_data[6] & 0x40) == 0x40))
	return 0;

    if (mc->real_devid.IPMB_event_generator_support
	!= ((rsp_data[6] & 0x20)==0x20))
	return 0;

    if (mc->real_devid.IPMB_event_receiver_support
	!= ((rsp_data[6] & 0x10) == 0x10))
	return 0;

    if (mc->real_devid.FRU_inventory_support != ((rsp_data[6] & 0x08) == 0x08))
	return 0;

    if (mc->real_devid.SEL_device_support != ((rsp_data[6] & 0x04) == 0x04))
	return 0;

    if (mc->real_devid.SDR_repository_support
	!= ((rsp_data[6] & 0x02) == 0x02))
	return 0;

    if (mc->real_devid.sensor_device_support != ((rsp_data[6] & 0x01) == 0x01))
	return 0;

    if (mc->real_devid.manufacturer_id != (uint32_t) (rsp_data[7]
						      | (rsp_data[8] << 8)
						      | (rsp_data[9] << 16)))
	return 0;

    if (mc->real_devid.product_id != (rsp_data[10] | (rsp_data[11] << 8)))
	return 0;

    if (rsp->data_len < 16) {
	/* no aux revision, it should be all zeros. */
	if ((mc->real_devid.aux_fw_revision[0] != 0)
	    || (mc->real_devid.aux_fw_revision[1] != 0)
	    || (mc->real_devid.aux_fw_revision[2] != 0)
	    || (mc->real_devid.aux_fw_revision[3] != 0))
	    return 0;
    } else {
	if (memcmp(mc->real_devid.aux_fw_revision, rsp_data + 12, 4) != 0)
	    return 0;
    }

    /* Everything's the same. */
    return 1;
}

/***********************************************************************
 *
 * Get/set the information for an MC.
 *
 **********************************************************************/

void
_ipmi_mc_get_sdr_sensors(ipmi_mc_t     *mc,
			 ipmi_sensor_t ***sensors,
			 unsigned int  *count)
{
    *sensors = mc->sensors_in_my_sdr;
    *count = mc->sensors_in_my_sdr_count;
}

void
_ipmi_mc_set_sdr_sensors(ipmi_mc_t     *mc,
			 ipmi_sensor_t **sensors,
			 unsigned int  count)
{
    mc->sensors_in_my_sdr = sensors;
    mc->sensors_in_my_sdr_count = count;
}

void *
_ipmi_mc_get_sdr_entities(ipmi_mc_t *mc)
{
    return mc->entities_in_my_sdr;
}

void
_ipmi_mc_set_sdr_entities(ipmi_mc_t *mc, void *entities)
{
    mc->entities_in_my_sdr = entities;
}

int
ipmi_mc_provides_device_sdrs(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.provides_device_sdrs;
}

int
ipmi_mc_set_sdrs_first_read_handler(ipmi_mc_t      *mc,
				    ipmi_mc_ptr_cb handler,
				    void           *cb_data)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->lock);
    mc->sdrs_first_read_handler = handler;
    mc->sdrs_first_read_cb_data = cb_data;
    ipmi_unlock(mc->lock);
    return 0;
}

int ipmi_mc_set_sels_first_read_handler(ipmi_mc_t      *mc,
					ipmi_mc_ptr_cb handler,
					void           *cb_data)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->sel_timer_info->lock);
    mc->sel_timer_info->sels_first_read_handler = handler;
    mc->sel_timer_info->sels_first_read_cb_data = cb_data;
    ipmi_unlock(mc->sel_timer_info->lock);
    return 0;
}

static int
call_active_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_mc_active_cb handler = item1;
    ipmi_mc_t         *mc = cb_data;

    handler(mc, mc->active, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_active_handlers(ipmi_mc_t *mc)
{
    locked_list_iterate(mc->active_handlers, call_active_handler, mc);
}

int
ipmi_mc_add_active_handler(ipmi_mc_t         *mc,
			   ipmi_mc_active_cb handler,
			   void              *cb_data)
{
    CHECK_MC_LOCK(mc);

    if (locked_list_add(mc->active_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_mc_remove_active_handler(ipmi_mc_t         *mc,
			      ipmi_mc_active_cb handler,
			      void              *cb_data)
{
    CHECK_MC_LOCK(mc);

    if (locked_list_remove(mc->active_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_mc_add_active_handler_cl(ipmi_mc_t            *mc,
			      ipmi_mc_active_cl_cb handler,
			      void                 *cb_data)
{
    CHECK_MC_LOCK(mc);

    if (locked_list_add(mc->active_handlers_cl, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_mc_remove_active_handler_cl(ipmi_mc_t            *mc,
				 ipmi_mc_active_cl_cb handler,
				 void                 *cb_data)
{
    CHECK_MC_LOCK(mc);

    if (locked_list_remove(mc->active_handlers_cl, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_mc_is_active(ipmi_mc_t *mc)
{
    return mc->active;
}

void
_ipmi_mc_force_active(ipmi_mc_t *mc, int val)
{
    ipmi_lock(mc->lock);
    mc->active = val;
    ipmi_unlock(mc->lock);
}

static int
call_fully_up_handler(void *cb_data, void *item1, void *item2)
{
    ipmi_mc_ptr_cb handler = item1;
    ipmi_mc_t      *mc = cb_data;

    handler(mc, item2);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
call_fully_up_handlers(ipmi_mc_t *mc)
{
    locked_list_iterate(mc->fully_up_handlers, call_fully_up_handler, mc);
}

int
ipmi_mc_add_fully_up_handler(ipmi_mc_t      *mc,
			     ipmi_mc_ptr_cb handler,
			     void           *cb_data)
{
    CHECK_MC_LOCK(mc);

    if (locked_list_add(mc->fully_up_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_mc_remove_fully_up_handler(ipmi_mc_t      *mc,
				ipmi_mc_ptr_cb handler,
				void           *cb_data)
{
    CHECK_MC_LOCK(mc);

    if (locked_list_remove(mc->fully_up_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_mc_add_fully_up_handler_cl(ipmi_mc_t              *mc,
				ipmi_mc_fully_up_cl_cb handler,
				void                   *cb_data)
{
    CHECK_MC_LOCK(mc);

    if (locked_list_add(mc->fully_up_handlers_cl, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_mc_remove_fully_up_handler_cl(ipmi_mc_t              *mc,
				   ipmi_mc_fully_up_cl_cb handler,
				   void                   *cb_data)
{
    CHECK_MC_LOCK(mc);

    if (locked_list_remove(mc->fully_up_handlers_cl, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

void
ipmi_mc_set_provides_device_sdrs(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->lock);
    mc->pending_devid.provides_device_sdrs = val;
    mc->pending_devid_data = 1;
    ipmi_unlock(mc->lock);
}

int
ipmi_mc_device_available(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.device_available;
}

void
ipmi_mc_set_device_available(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->lock);
    mc->pending_devid.device_available = val;
    mc->pending_devid_data = 1;
    ipmi_unlock(mc->lock);
}

int
ipmi_mc_chassis_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.chassis_support;
}

void
ipmi_mc_set_chassis_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->lock);
    mc->pending_devid.chassis_support = val;
    mc->pending_devid_data = 1;
    ipmi_unlock(mc->lock);
}

int
ipmi_mc_bridge_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.bridge_support;
}

void
ipmi_mc_set_bridge_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->lock);
    mc->pending_devid.bridge_support = val;
    mc->pending_devid_data = 1;
    ipmi_unlock(mc->lock);
}

int
ipmi_mc_ipmb_event_generator_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.IPMB_event_generator_support;
}

void
ipmi_mc_set_ipmb_event_generator_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->lock);
    mc->pending_devid.IPMB_event_generator_support = val;
    mc->pending_devid_data = 1;
    ipmi_unlock(mc->lock);
}

int
ipmi_mc_ipmb_event_receiver_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.IPMB_event_receiver_support;
}

void
ipmi_mc_set_ipmb_event_receiver_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->lock);
    mc->pending_devid.IPMB_event_receiver_support = val;
    mc->pending_devid_data = 1;
    ipmi_unlock(mc->lock);
}

int
ipmi_mc_fru_inventory_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.FRU_inventory_support;
}

void
ipmi_mc_set_fru_inventory_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->lock);
    mc->pending_devid.FRU_inventory_support = val;
    mc->pending_devid_data = 1;
    ipmi_unlock(mc->lock);
}

int
ipmi_mc_sel_device_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.SEL_device_support;
}

void
ipmi_mc_set_sel_device_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->lock);
    mc->pending_devid.SEL_device_support = val;
    mc->pending_devid_data = 1;
    ipmi_unlock(mc->lock);
}

int
ipmi_mc_sdr_repository_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.SDR_repository_support;
}

void
ipmi_mc_set_sdr_repository_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->lock);
    mc->pending_devid.SDR_repository_support = val;
    mc->pending_devid_data = 1;
    ipmi_unlock(mc->lock);
}

int
ipmi_mc_sensor_device_support(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.sensor_device_support;
}

void
ipmi_mc_set_sensor_device_support(ipmi_mc_t *mc, int val)
{
    CHECK_MC_LOCK(mc);
    ipmi_lock(mc->lock);
    mc->pending_devid.sensor_device_support = val;
    mc->pending_devid_data = 1;
    ipmi_unlock(mc->lock);
}

int
ipmi_mc_device_id(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.device_id;
}

int
ipmi_mc_device_revision(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.device_revision;
}

int
ipmi_mc_major_fw_revision(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.major_fw_revision;
}

int
ipmi_mc_minor_fw_revision(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.minor_fw_revision;
}

int
ipmi_mc_major_version(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.major_version;
}

int
ipmi_mc_minor_version(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.minor_version;
}

int
ipmi_mc_manufacturer_id(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.manufacturer_id;
}

int
ipmi_mc_product_id(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->devid.product_id;
}

void
ipmi_mc_aux_fw_revision(ipmi_mc_t *mc, unsigned char val[])
{
    CHECK_MC_LOCK(mc);
    memcpy(val, mc->devid.aux_fw_revision, sizeof(mc->devid.aux_fw_revision));
}

int
ipmi_mc_get_guid(ipmi_mc_t *mc, unsigned char *guid)
{
    CHECK_MC_LOCK(mc);
    if (!mc->guid_set)
	return ENOSYS;
    memcpy(guid, mc->guid, 16);
    return 0;
}

void
ipmi_mc_set_guid(ipmi_mc_t *mc, unsigned char *data)
{
    memcpy(mc->guid, data, 16);
    mc->guid_set = 1;
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

ipmi_sensor_info_t *
_ipmi_mc_get_sensors(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->sensors;
}

ipmi_control_info_t *
_ipmi_mc_get_controls(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    return mc->controls;
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
	ipmi_ipmb_addr_t *ipmb = (ipmi_ipmb_addr_t *) &(mc->addr);
	return ipmb->slave_addr;
    } else if (mc->addr.addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	ipmi_system_interface_addr_t *si = (void *) &(mc->addr);
	return si->channel;
    }

    /* Address is ignore for other types. */
    return 0;
}

void
ipmi_mc_get_ipmi_address(ipmi_mc_t    *mc,
			 ipmi_addr_t  *addr,
			 unsigned int *addr_len)
{
    /* We don't check the lock here because this is used as part of
       the lock grabbing. */
    if (addr)
	memcpy(addr, &mc->addr, mc->addr_len);
    if (addr_len)
	*addr_len = mc->addr_len;
}

unsigned int
ipmi_mc_get_channel(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);
    if (mc->addr.addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE)
	return IPMI_BMC_CHANNEL;
    else
	return mc->addr.channel;
}

ipmi_domain_t *ipmi_mc_get_domain(ipmi_mc_t *mc)
{
    return mc->domain;
}

unsigned int
ipmi_mc_get_unique_num(ipmi_mc_t *mc)
{
    unsigned int rv;

    ipmi_lock(mc->lock);
    rv = mc->uniq_num;
    mc->uniq_num++;
    ipmi_unlock(mc->lock);
    return rv;
}

int
_ipmi_mc_new_sensor(ipmi_mc_t     *mc,
		    ipmi_entity_t *ent,
		    ipmi_sensor_t *sensor,
		    void          *link)
{
    int rv = 0;

    CHECK_MC_LOCK(mc);

    if (mc->new_sensor_handler)
	rv = mc->new_sensor_handler(mc, ent, sensor, link,
				    mc->new_sensor_cb_data);
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

int
ipmi_mc_set_sdrs_fixup_handler(ipmi_mc_t                 *mc,
			       ipmi_mc_oem_fixup_sdrs_cb handler,
			       void                      *cb_data)
{
    CHECK_MC_LOCK(mc);
    mc->fixup_sdrs_handler = handler;
    mc->fixup_sdrs_cb_data = cb_data;
    return 0;
}

int
ipmi_mc_add_oem_removed_handler(ipmi_mc_t              *mc,
				ipmi_mc_oem_removed_cb handler,
				void                   *cb_data)
{
    CHECK_MC_LOCK(mc);

    if (locked_list_add(mc->removed_handlers, handler, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_mc_remove_oem_removed_handler(ipmi_mc_t              *mc,
				   ipmi_mc_oem_removed_cb handler,
				   void                   *cb_data)
{
    CHECK_MC_LOCK(mc);

    if (locked_list_remove(mc->removed_handlers, handler, cb_data))
	return 0;
    else
	return EINVAL;
}

int
ipmi_mc_get_events_enable(ipmi_mc_t *mc)
{
    CHECK_MC_LOCK(mc);

    return mc->events_enabled;
}

int
ipmi_mc_set_events_enable(ipmi_mc_t       *mc,
			  int             val,
			  ipmi_mc_done_cb done,
			  void            *cb_data)
{
    int rv;

    CHECK_MC_LOCK(mc);

    if (!ipmi_mc_ipmb_event_generator_support(mc))
	return ENOSYS;

    val = val != 0;

    ipmi_lock(mc->lock);
    if (val == mc->events_enabled) {
	/* Didn't changed, just finish the operation. */
	ipmi_unlock(mc->lock);
	if (done)
	    done(mc, 0, cb_data);
	return 0;
    }

    mc->events_enabled = val;
    
    if (val) {
	unsigned int event_rcvr = ipmi_domain_get_event_rcvr(mc->domain);
	rv = send_set_event_rcvr(mc, event_rcvr, done, cb_data);
    } else {
	rv = send_set_event_rcvr(mc, 0, done, cb_data);
    }
    ipmi_unlock(mc->lock);

    return rv;
}

typedef struct ipmi_get_event_log_info_s
{
    ipmi_mc_data_done_cb done;
    void                 *cb_data;
} ipmi_get_event_log_info_t;

static void
got_event_log_enable(ipmi_mc_t  *mc,
		     ipmi_msg_t *rsp,
		     void       *cb_data)
{
    ipmi_get_event_log_info_t *info = cb_data;

    if (rsp->data[0] != 0) {
	info->done(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), 0, info->cb_data);
	goto out;
    }

    if (rsp->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(got_event_log_enable): response too small",
		 mc->name);
	info->done(mc, EINVAL, 0, info->cb_data);
	goto out;
    }

    info->done(mc, 0, (rsp->data[1] >> 3) & 1, info->cb_data);

 out:
    ipmi_mem_free(info);
}

int
ipmi_mc_get_event_log_enable(ipmi_mc_t            *mc,
			     ipmi_mc_data_done_cb done,
			     void                 *cb_data)
{
    int                       rv;
    ipmi_msg_t                msg;
    ipmi_get_event_log_info_t *info;

    info = ipmi_mem_alloc(sizeof(*info));
    if(!info)
	return ENOMEM;

    info->done = done;
    info->cb_data = cb_data;

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_BMC_GLOBAL_ENABLES_CMD;
    msg.data = NULL;
    msg.data_len = 0;

    rv = ipmi_mc_send_command(mc, 0, &msg, got_event_log_enable, info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

typedef struct ipmi_set_event_log_info_s
{
    ipmi_mc_done_cb done;
    void            *cb_data;
    int             val;
} ipmi_set_event_log_info_t;

static void
set_event_log_enable_2(ipmi_mc_t  *mc,
		       ipmi_msg_t *rsp,
		       void       *cb_data)
{
    ipmi_set_event_log_info_t *info = cb_data;


    if (rsp->data[0] != 0) {
	if (info->done)
	    info->done(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), info->cb_data);
	goto out;
    }

    if (info->done)
	info->done(mc, 0, info->cb_data);
 out:
    ipmi_mem_free(info);
}

static void
set_event_log_enable(ipmi_mc_t  *mc,
		     ipmi_msg_t *rsp,
		     void       *cb_data)
{
    ipmi_set_event_log_info_t *info = cb_data;
    int                       rv;
    ipmi_msg_t                msg;
    unsigned char             data[1];


    if (rsp->data[0] != 0) {
	if (info->done)
	    info->done(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), info->cb_data);
	goto out_err;
    }

    if (rsp->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(set_event_log_enable): response too small",
		 mc->name);
	if (info->done)
	    info->done(mc, EINVAL, info->cb_data);
	goto out_err;
    }

    data[0] = (rsp->data[1] & ~0x08) | (info->val << 3);
    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_SET_BMC_GLOBAL_ENABLES_CMD;
    msg.data = data;
    msg.data_len = 1;

    rv = ipmi_mc_send_command(mc, 0, &msg, set_event_log_enable_2, info);
    if (rv) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(set_event_log_enable): Can't send set: 0x%x",
		 mc->name, rv);
	if (info->done)
	    info->done(mc, rv, info->cb_data);
	goto out_err;
    }
    return;

 out_err:
    ipmi_mem_free(info);
}

int
ipmi_mc_set_event_log_enable(ipmi_mc_t       *mc,
			     int             val,
			     ipmi_mc_done_cb done,
			     void            *cb_data)
{
    int                       rv;
    ipmi_msg_t                msg;
    ipmi_set_event_log_info_t *info;

    info = ipmi_mem_alloc(sizeof(*info));
    if(!info)
	return ENOMEM;

    info->done = done;
    info->cb_data = cb_data;
    info->val = val != 0;

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_BMC_GLOBAL_ENABLES_CMD;
    msg.data = NULL;
    msg.data_len = 0;

    rv = ipmi_mc_send_command(mc, 0, &msg, set_event_log_enable, info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

/***********************************************************************
 *
 * Global initialization and shutdown
 *
 **********************************************************************/

static int mc_initialized = 0;

int
_ipmi_mc_init(void)
{
    if (mc_initialized)
	return 0;

    oem_handlers = locked_list_alloc(ipmi_get_global_os_handler());
    if (!oem_handlers)
	return ENOMEM;

    mc_initialized = 1;

    return 0;
}

static int
oem_handler_free(void *cb_data, void *item1, void *item2)
{
    oem_handlers_t *hndlr = item1;

    locked_list_remove(oem_handlers, item1, item2);
    ipmi_mem_free(hndlr);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
_ipmi_mc_shutdown(void)
{
    if (mc_initialized) {
	/* Destroy the members of the OEM list. */
	locked_list_iterate(oem_handlers, oem_handler_free, NULL);
	locked_list_destroy(oem_handlers);
	oem_handlers = NULL;
	mc_initialized = 0;
    }
}

/***********************************************************************
 *
 * Lock checking
 *
 **********************************************************************/

void
__ipmi_check_mc_lock(const ipmi_mc_t *mc)
{
    if (!mc)
	return;

    if (!DEBUG_LOCKS)
	return;

    if (mc->usecount == 0)
	ipmi_report_lock_error(ipmi_domain_get_os_hnd(mc->domain),
			       "MC not locked when it should have been");
	
}

/***********************************************************************
 *
 * Channel handling
 *
 **********************************************************************/

struct ipmi_channel_info_s
{
    unsigned int channel : 4;
    unsigned int medium : 7;
    unsigned int protocol : 5;
    unsigned int session_support : 2;
    unsigned char vendor_id[3];
    unsigned char aux_info[2];

    ipmi_channel_info_cb handler;
    void                 *cb_data;
};

static void
got_chan_info(ipmi_mc_t  *mc,
	      ipmi_msg_t *rsp,
	      void       *cb_data)
{
    ipmi_channel_info_t *info = cb_data;

    if (rsp->data[0] != 0) {
	info->handler(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), info,
		      info->cb_data);
	goto out;
    }

    if (rsp->data_len < 10) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(got_chan_info): Channel info response too small",
		 mc->name);
	info->handler(mc, EINVAL, info, info->cb_data);
	goto out;
    }

    info->channel = rsp->data[1] & 0xf;
    info->medium = rsp->data[2] & 0x7f;
    info->protocol = rsp->data[3] & 0x1f;
    info->session_support = rsp->data[4] >> 6;
    memcpy(info->vendor_id, rsp->data+5, 3);
    memcpy(info->aux_info, rsp->data+8, 2);
    info->handler(mc, 0, info, info->cb_data);

 out:
    ipmi_mem_free(info);
}

int
ipmi_mc_channel_get_info(ipmi_mc_t            *mc,
			 unsigned int         channel,
			 ipmi_channel_info_cb handler,
			 void                 *cb_data)
{
    int                 rv;
    ipmi_msg_t          msg;
    unsigned char       data[1];
    ipmi_channel_info_t *info;

    if (channel > 15)
	return EINVAL;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));

    info->handler = handler;
    info->cb_data = cb_data;

    data[0] = channel & 0xf;
    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_CHANNEL_INFO_CMD;
    msg.data = data;
    msg.data_len = 1;

    rv = ipmi_mc_send_command(mc, 0, &msg, got_chan_info, info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

ipmi_channel_info_t *
ipmi_channel_info_copy(ipmi_channel_info_t *info)
{
    ipmi_channel_info_t *rv = ipmi_mem_alloc(sizeof(*rv));
    if (!rv)
	return NULL;
    memcpy(rv, info, sizeof(*rv));
    return rv;
}

void
ipmi_channel_info_free(ipmi_channel_info_t *info)
{
    ipmi_mem_free(info);
}

int
ipmi_channel_info_get_channel(ipmi_channel_info_t *info,
			      unsigned int        *channel)
{
    *channel = info->channel;
    return 0;
}

int
ipmi_channel_info_get_medium(ipmi_channel_info_t *info,
			     unsigned int        *medium)
{
    *medium = info->medium;
    return 0;
}

int
ipmi_channel_info_get_protocol_type(ipmi_channel_info_t *info,
				    unsigned int        *prot_type)
{
    *prot_type = info->protocol;
    return 0;
}

int
ipmi_channel_info_get_session_support(ipmi_channel_info_t *info,
				      unsigned int        *sup)
{
    *sup = info->session_support;
    return 0;
}

int
ipmi_channel_info_get_vendor_id(ipmi_channel_info_t *info,
				unsigned char       *data)
{
    memcpy(data, info->vendor_id, 3);
    return 0;
}

int
ipmi_channel_info_get_aux_info(ipmi_channel_info_t *info,
			       unsigned char *data)
{
    memcpy(data, info->aux_info, 2);
    return 0;
}

struct ipmi_channel_access_s
{
    unsigned int channel : 4;
    unsigned int alert_set : 1;
    unsigned int alert_val : 1;
    unsigned int msg_auth_set : 1;
    unsigned int msg_auth_val : 1;
    unsigned int user_auth_set : 1;
    unsigned int user_auth_val : 1;
    unsigned int access_mode_set : 1;
    unsigned int access_mode_val : 3;
    unsigned int privilege_set : 1;
    unsigned int privilege_val : 4;

    ipmi_channel_access_cb handler;
    ipmi_mc_done_cb        done;
    void                   *cb_data;
};

static void
got_chan_access(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *cb_data)
{
    ipmi_channel_access_t *info = cb_data;

    if (rsp->data[0] != 0) {
	info->handler(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), info,
		      info->cb_data);
	goto out;
    }

    if (rsp->data_len < 3) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(got_chan_info): Channel access response too small",
		 mc->name);
	info->handler(mc, EINVAL, info, info->cb_data);
	goto out;
    }

    /* For these, the values in the message are the inverse of their
       boolean value. */
    info->alert_val = !((rsp->data[1] >> 5) & 1);
    info->msg_auth_val = !((rsp->data[1] >> 4) & 1);
    info->user_auth_val = !((rsp->data[1] >> 3) & 1);

    info->access_mode_val = rsp->data[1] & 0x7;
    info->privilege_val = rsp->data[2] & 0xf;
    info->handler(mc, 0, info, info->cb_data);
 out:
    ipmi_mem_free(info);
}

int
ipmi_mc_channel_get_access(ipmi_mc_t              *mc,
			   unsigned int           channel,
			   enum ipmi_set_dest_e   dest,
			   ipmi_channel_access_cb handler,
			   void                   *cb_data)
{
    int                   rv;
    ipmi_msg_t            msg;
    unsigned char         data[2];
    ipmi_channel_access_t *info;

    if (channel > 15)
	return EINVAL;
    if ((dest < IPMI_SET_DEST_NON_VOLATILE) || (dest > IPMI_SET_DEST_VOLATILE))
	return EINVAL;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));

    info->channel = channel;
    info->handler = handler;
    info->cb_data = cb_data;

    data[0] = channel & 0xf;
    data[1] = dest << 6;
    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_CHANNEL_ACCESS_CMD;
    msg.data = data;
    msg.data_len = 2;

    rv = ipmi_mc_send_command(mc, 0, &msg, got_chan_access, info);
    if (rv)
	ipmi_mem_free(info);
    return rv;
}

static void
set_chan_access(ipmi_mc_t  *mc,
		ipmi_msg_t *rsp,
		void       *cb_data)
{
    ipmi_channel_access_t *info = cb_data;

    if (rsp->data[0] != 0) {
	if (info->done)
	    info->done(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), info->cb_data);
	goto out;
    }

    if (info->done)
	info->done(mc, 0, info->cb_data);

 out:
    ipmi_mem_free(info);
}

int
ipmi_mc_channel_set_access(ipmi_mc_t             *mc,
			   unsigned int           channel,
			   enum ipmi_set_dest_e  dest,
			   ipmi_channel_access_t *access,
			   ipmi_mc_done_cb       handler,
			   void                  *cb_data)
{
    ipmi_channel_access_t *info;
    ipmi_msg_t            msg;
    unsigned char         data[3];
    int                   rv;


    if (channel > 15)
	return EINVAL;
    if ((dest < IPMI_SET_DEST_NON_VOLATILE) || (dest > IPMI_SET_DEST_VOLATILE))
	return EINVAL;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return EINVAL;

    memcpy(info, access, sizeof(*info));
    info->channel = channel;
    info->done = handler;
    info->cb_data = cb_data;

    data[0] = channel & 0xf;

    data[1] = ((!info->alert_val << 5)
	       | (!info->msg_auth_val << 4)
	       | (!info->user_auth_val << 3)
	       | info->access_mode_val);
    if (info->alert_set || info->msg_auth_set || info->user_auth_set
	|| info->access_mode_set)
    {
	data[1] |= dest << 6;
    }

    data[2] = info->privilege_val;
    if (info->privilege_set)
	data[2] |= dest << 6;

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_SET_CHANNEL_ACCESS_CMD;
    msg.data = data;
    msg.data_len = 3;

    rv = ipmi_mc_send_command(mc, 0, &msg, set_chan_access, info);
    if (rv)
	ipmi_mem_free(info);

    return rv;
}

ipmi_channel_access_t *
ipmi_channel_access_copy(ipmi_channel_access_t *access)
{
    ipmi_channel_access_t *rv = ipmi_mem_alloc(sizeof(*rv));
    if (!rv)
	return NULL;
    memcpy(rv, access, sizeof(*rv));
    return rv;
}

void
ipmi_channel_access_free(ipmi_channel_access_t *access)
{
    ipmi_mem_free(access);
}

int
ipmi_channel_access_get_channel(ipmi_channel_access_t *info,
				unsigned int          *channel)
{
    *channel = info->channel;
    return 0;
}

int
ipmi_channel_access_get_alerting_enabled(ipmi_channel_access_t *info,
					 unsigned int          *enab)
{
    *enab = info->alert_val;
    return 0;
}

int
ipmi_channel_access_set_alerting_enabled(ipmi_channel_access_t *info,
					 unsigned int          enab)
{
    info->alert_val = enab;
    info->alert_set = 1;
    return 0;
}

int
ipmi_channel_access_get_per_msg_auth(ipmi_channel_access_t *info,
				     unsigned int          *msg_auth)
{
    *msg_auth = info->msg_auth_val;
    return 0;
}

int
ipmi_channel_access_set_per_msg_auth(ipmi_channel_access_t *info,
				     unsigned int          msg_auth)
{
    info->msg_auth_val = msg_auth;
    info->msg_auth_set = 1;
    return 0;
}

int
ipmi_channel_access_get_user_auth(ipmi_channel_access_t *info,
				  unsigned int          *user_auth)
{
    *user_auth = info->user_auth_val;
    return 0;
}

int
ipmi_channel_access_set_user_auth(ipmi_channel_access_t *info,
				  unsigned int          user_auth)
{
    info->user_auth_val = user_auth;
    info->user_auth_set = 1;
    return 0;
}

int
ipmi_channel_access_get_access_mode(ipmi_channel_access_t *info,
				    unsigned int          *access_mode)
{
    *access_mode = info->access_mode_val;
    return 0;
}

int
ipmi_channel_access_set_access_mode(ipmi_channel_access_t *info,
				    unsigned int          access_mode)
{
    info->access_mode_val = access_mode;
    info->access_mode_set = 1;
    return 0;
}

int
ipmi_channel_access_get_priv_limit(ipmi_channel_access_t *info,
				   unsigned int          *priv_limit)
{
    *priv_limit = info->privilege_val;
    return 0;
}

int
ipmi_channel_access_set_priv_limit(ipmi_channel_access_t *info,
				   unsigned int          priv_limit)
{
    info->privilege_val = priv_limit;
    info->privilege_set = 1;
    return 0;
}

int
ipmi_channel_access_setall(ipmi_channel_access_t *info)
{
    info->alert_set = 1;
    info->msg_auth_set = 1;
    info->user_auth_set = 1;
    info->access_mode_set = 1;
    info->privilege_set = 1;
    return 0;
}

/***********************************************************************
 *
 * User management
 *
 **********************************************************************/

struct ipmi_user_s
{
    int  num;
    unsigned int link_enabled_set : 1;
    unsigned int link_enabled : 1;
    unsigned int msg_enabled_set : 1;
    unsigned int msg_enabled : 1;
    unsigned int privilege_limit_set : 1;
    unsigned int privilege_limit : 4;
    unsigned int cb_only_set : 1;
    unsigned int cb_only : 1;
    unsigned int session_limit_set : 1;
    unsigned int session_limit_read : 1;
    unsigned int session_limit : 4;
    unsigned int enable_set : 1;
    unsigned int enable_read : 1;
    unsigned int enable : 4;
    unsigned int name_set : 1;
    char name[17];
    unsigned int pw_set : 1;
    unsigned int pw2_set : 1;
    unsigned int can_use_pw2 : 1;
    char pw[20];

    unsigned int channel : 4;
    ipmi_mc_done_cb handler;
    void            *cb_data;
};

struct ipmi_user_list_s
{
    unsigned int      channel;
    unsigned int      curr;
    unsigned int      idx;
    unsigned int      max;
    unsigned int      enabled;
    unsigned int      fixed;
    ipmi_user_t       *users;
    int               supports_rmcpp;

    ipmi_user_list_cb handler;
    void              *cb_data;
};

ipmi_user_list_t *
ipmi_user_list_copy(ipmi_user_list_t *list)
{
    ipmi_user_list_t *rv;

    rv = ipmi_mem_alloc(sizeof(*rv));
    if (!rv)
	return NULL;
    memcpy(rv, list, sizeof(*rv));
    rv->users = ipmi_mem_alloc(sizeof(ipmi_user_t) * list->idx);
    if (!rv->users) {
	ipmi_mem_free(rv);
	return NULL;
    }
    memcpy(rv->users, list->users, sizeof(ipmi_user_t) * list->idx);
    return rv;
}

void
ipmi_user_list_free(ipmi_user_list_t *list)
{
    if (list->users)
	ipmi_mem_free(list->users);
    ipmi_mem_free(list);
}

unsigned int
ipmi_user_list_get_user_count(ipmi_user_list_t *list)
{
  return list->idx;
}

ipmi_user_t *
ipmi_user_list_get_user(ipmi_user_list_t *list,
			unsigned int     idx)
{
  if (idx >= list->idx)
      return NULL;
  return ipmi_user_copy(&list->users[idx]);
}

int
ipmi_user_list_get_channel(ipmi_user_list_t *list, unsigned int *channel)
{
    *channel = list->channel;
    return 0;
}

int
ipmi_user_list_get_max_user(ipmi_user_list_t *list, unsigned int *max)
{
    *max = list->max;
    return 0;
}

int
ipmi_user_list_get_enabled_users(ipmi_user_list_t *list, unsigned int *e)
{
    *e = list->enabled;
    return 0;
}

int
ipmi_user_list_get_fixed_users(ipmi_user_list_t *list, unsigned int *f)
{
    *f = list->fixed;
    return 0;
}


static int list_next_user(ipmi_mc_t *mc, ipmi_user_list_t *list);

static void
user_list_done(ipmi_mc_t *mc, ipmi_user_list_t *list)
{
    list->handler(mc, 0, list, list->cb_data);
    ipmi_user_list_free(list);
}

static void
got_user2(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    ipmi_user_list_t *list = cb_data;
    int              rv;

    if (rsp->data[0] != 0) {
	list->handler(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), list,
		      list->cb_data);
	goto out_err;
    }

    if (rsp->data_len < 17) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(got_chan_info): user name response too small",
		 mc->name);
	list->handler(mc, EINVAL, list, list->cb_data);
	goto out_err;
    }

    memcpy(list->users[list->idx].name, rsp->data+1, 16);
    list->users[list->idx].name[16] = '\0';
    list->idx++;

    if (list->curr >= list->max)
	user_list_done(mc, list);
    else {
	list->curr++;
	rv = list_next_user(mc, list);
	if (rv) {
	    list->handler(mc, rv, list, list->cb_data);
	    goto out_err;
	}
    }
    return;

 out_err:
    ipmi_user_list_free(list);
}

static void
got_user1(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    ipmi_user_list_t *list = cb_data;
    int              rv;
    int              idx;
    ipmi_msg_t       msg;
    unsigned char    data[1];


    if (rsp->data[0] != 0) {
	list->handler(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), list,
		      list->cb_data);
	goto out_err;
    }

    if (rsp->data_len < 5) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%smc.c(got_chan_info): user access response too small",
		 mc->name);
	list->handler(mc, EINVAL, list, list->cb_data);
	goto out_err;
    }

    if (! list->users) {
	if (list->max == 0) {
	    list->max = rsp->data[1] & 0x3f;
	    list->enabled = rsp->data[2] & 0x3f;
	    list->fixed = rsp->data[3] & 0x3f;
	}
	if (list->max < 1) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%smc.c(got_chan_info): user access num uses is < 1",
		     mc->name);
	    list->handler(mc, EINVAL, list, list->cb_data);
	    goto out_err;
	}
	list->users = ipmi_mem_alloc(sizeof(ipmi_user_t)
				     * (list->max - list->curr + 1));
	if (!list->users) {
	    list->handler(mc, EINVAL, list, list->cb_data);
	    goto out_err;
	}
	memset(list->users, 0,
	       sizeof(ipmi_user_t) * (list->max - list->curr + 1));
    }

    idx = list->idx;
    list->users[idx].num = list->curr;
    list->users[idx].cb_only = (rsp->data[4] >> 6) & 1;
    list->users[idx].link_enabled = (rsp->data[4] >> 5) & 1;
    list->users[idx].msg_enabled = (rsp->data[4] >> 4) & 1;
    list->users[idx].privilege_limit = rsp->data[4] & 0x0f;
    list->users[idx].channel = list->channel;
    list->users[idx].can_use_pw2 = list->supports_rmcpp;

    if (list->curr == 1) {
	/* User 1 does not have a name, don't try to fetch it. */
	memset(list->users[list->idx].name, 0, 17);
	list->idx++;
	if (list->curr >= list->max) {
	    user_list_done(mc, list);
	    rv = 0;
	} else {
	    list->curr++;
	    rv = list_next_user(mc, list);
	}
    } else {
	msg.netfn = IPMI_APP_NETFN;
	msg.cmd = IPMI_GET_USER_NAME_CMD;
	msg.data = data;
	msg.data_len = 1;
	data[0] = list->curr;

	rv = ipmi_mc_send_command(mc, 0, &msg, got_user2, list);
    }
    if (rv) {
	list->handler(mc, rv, list, list->cb_data);
	goto out_err;
    }
    
    return;

 out_err:
    ipmi_user_list_free(list);
}

static int
list_next_user(ipmi_mc_t *mc, ipmi_user_list_t *info)
{
    ipmi_msg_t      msg;
    unsigned char   data[2];

    if ((info->curr > 0x3f) || (info->curr < 1))
	return EINVAL;

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_USER_ACCESS_CMD;
    msg.data = data;
    msg.data_len = 2;
    data[0] = info->channel & 0xf;
    data[1] = info->curr;

    return ipmi_mc_send_command(mc, 0, &msg, got_user1, info);
}

static void
got_user0(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    ipmi_user_list_t *list = cb_data;
    int              rv;

    if (rsp->data[0] != 0) {
	/* We possibly have 2.0 support. */
	 list->supports_rmcpp
	     = ((rsp->data[2] & (1 << 7)) /* Supports 2.0 capabilities */
		&& (rsp->data[4] & (1 << 1))); /* 2.0 connection support */
    }

    rv = list_next_user(mc, list);
    if (rv) {
	list->handler(mc, rv, list, list->cb_data);
	ipmi_mem_free(list);
    }
}

int
ipmi_mc_get_users(ipmi_mc_t         *mc,
		  unsigned int      channel,
		  unsigned int      user,
		  ipmi_user_list_cb handler,
		  void              *cb_data)
{
    int              rv;
    ipmi_user_list_t *list = NULL;
    ipmi_msg_t       msg;
    unsigned char    data[2];

    if (channel > 15)
	return EINVAL;
    if (user > 0x3f)
	return EINVAL;

    list = ipmi_mem_alloc(sizeof(*list));
    if (!list)
	return ENOMEM;
    memset(list, 0, sizeof(*list));

    list->channel = channel;
    list->handler = handler;
    list->cb_data = cb_data;
    if (user) {
	list->curr = user;
	list->max = user;
    } else {
	list->curr = 1;
	list->max = 0;
    }

    /* First determine if we have 2.0 (RMCP+) support. */
    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_CHANNEL_AUTH_CAPABILITIES_CMD;
    msg.data = data;
    msg.data_len = 2;
    data[0] = (channel & 0xf) | (1 << 7); /* Request IPMI 2.0 data */
    data[1] = 2; /* Request user level access */

    rv = ipmi_mc_send_command(mc, 0, &msg, got_user0, list);
    if (rv)
	ipmi_mem_free(list);
    return rv;
}

ipmi_user_t *
ipmi_user_copy(ipmi_user_t *user)
{
    ipmi_user_t *rv;

    rv = ipmi_mem_alloc(sizeof(*rv));
    if (rv)
	memcpy(rv, user, sizeof(*rv));
    return rv;
}

void
ipmi_user_free(ipmi_user_t *user)
{
    ipmi_mem_free(user);
}

static void
set_user_done(ipmi_mc_t *mc, int err, ipmi_user_t *user)
{
    if (user->handler)
	user->handler(mc, err, user->cb_data);
    ipmi_user_free(user);
}

static void
set_user5(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    ipmi_user_t     *user = cb_data;

    if (rsp->data[0] != 0) {
	set_user_done(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), user);
	return;
    }

    set_user_done(mc, 0, user);
}

static int set_enable(ipmi_mc_t *mc, ipmi_user_t *user)
{
    ipmi_msg_t      msg;
    unsigned char   data[2];

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_SET_USER_PASSWORD_CMD;
    msg.data = data;
    msg.data_len = 2;


    data[0] = user->num;
    if (user->enable)
	data[1] = 0x01; /* enable */
    else
	data[1] = 0x00; /* disable */
	
    return ipmi_mc_send_command(mc, 0, &msg, set_user5, user);
}

static void
set_user4(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    ipmi_user_t *user = cb_data;
    int         rv = 0;

    if (rsp->data[0] != 0) {
	set_user_done(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), user);
	return;
    }

    if (user->enable_set)
	rv = set_enable(mc, user);
    else
	set_user_done(mc, 0, user);

    if (rv)
	set_user_done(mc, rv, user);
}

static int set_pw(ipmi_mc_t *mc, ipmi_user_t *user)
{
    ipmi_msg_t      msg;
    unsigned char   data[22];

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_SET_USER_PASSWORD_CMD;
    msg.data = data;


    data[0] = user->num;
    data[1] = 0x02; /* set password */
    if (user->pw2_set) {
	msg.data_len = 22;
	memcpy(data+2, user->pw, 20);
	data[0] |= 0x80;
    } else {
	msg.data_len = 18;
	memcpy(data+2, user->pw, 16);
    }
	
    return ipmi_mc_send_command(mc, 0, &msg, set_user4, user);
}

static void
set_user3(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    ipmi_user_t     *user = cb_data;
    int             rv = 0;

    if (rsp->data[0] != 0) {
	set_user_done(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), user);
	return;
    }

    if (user->pw_set || user->pw2_set)
	rv = set_pw(mc, user);
    else if (user->enable_set)
	rv = set_enable(mc, user);
    else
	set_user_done(mc, 0, user);

    if (rv)
	set_user_done(mc, rv, user);
}

static int set_name(ipmi_mc_t *mc, ipmi_user_t *user)
{
    ipmi_msg_t      msg;
    unsigned char   data[17];

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_SET_USER_NAME_CMD;
    msg.data = data;
    msg.data_len = 17;


    data[0] = user->num;
    memcpy(data+1, user->name, 16);
	
    return ipmi_mc_send_command(mc, 0, &msg, set_user3, user);
}

static void
set_user2(ipmi_mc_t  *mc,
	  ipmi_msg_t *rsp,
	  void       *cb_data)
{
    ipmi_user_t     *user = cb_data;
    int             rv = 0;

    if (rsp->data[0] != 0) {
	set_user_done(mc, IPMI_IPMI_ERR_VAL(rsp->data[0]), user);
	return;
    }

    if (user->name_set)
	rv = set_name(mc, user);
    else if (user->pw_set || user->pw2_set)
	rv = set_pw(mc, user);
    else if (user->enable_set)
	rv = set_enable(mc, user);
    else
	set_user_done(mc, 0, user);

    if (rv)
	set_user_done(mc, rv, user);
}

static int
set_user_access(ipmi_mc_t *mc, ipmi_user_t *user)
{
    ipmi_msg_t      msg;
    unsigned char   data[4];

    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_SET_USER_ACCESS_CMD;
    msg.data = data;
    msg.data_len = 3;

    data[0] = user->channel;
    if (user->cb_only_set || user->link_enabled_set || user->msg_enabled_set) {
	data[0] |= user->channel;
	data[0] |= user->cb_only << 6;
	data[0] |= user->link_enabled << 5;
	data[0] |= user->msg_enabled << 4;
	data[0] |= 0x80;
    }
    data[1] = user->num;
    data[2] = user->privilege_limit;
    if (user->session_limit_set) {
	/* Optional value, afaict there is no way to get this value. */
	data[3] = user->session_limit;
	msg.data_len++;
    }
	
    return ipmi_mc_send_command(mc, 0, &msg, set_user2, user);
}

int
ipmi_mc_set_user(ipmi_mc_t       *mc,
		 unsigned int    channel,
		 unsigned int    num,
		 ipmi_user_t     *iuser,
		 ipmi_mc_done_cb handler,
		 void            *cb_data)
{
    int             rv = 0;
    ipmi_user_t     *user;

    if (channel > 15)
	return EINVAL;
    if (num > 0x3f)
	return EINVAL;

    user = ipmi_user_copy(iuser);
    if (!user)
	return ENOMEM;
    user->num = num;
    user->channel = channel;
    user->handler = handler;
    user->cb_data = cb_data;

    if (user->cb_only_set || user->link_enabled_set || user->msg_enabled_set
	|| user->privilege_limit_set || user->session_limit_set)
    	rv = set_user_access(mc, user);
    else if (user->name_set)
	rv = set_name(mc, user);
    else if (user->pw_set || user->pw2_set)
	rv = set_pw(mc, user);
    else if (user->enable_set)
	rv = set_enable(mc, user);
    else {
	/* Nothing to do. */
	if (handler)
	    handler(mc, 0, cb_data);
	ipmi_user_free(user);
    }

    if (rv)
	ipmi_user_free(user);

    return rv;
}

int
ipmi_user_get_channel(ipmi_user_t *user, unsigned int *channel)
{
    *channel = user->channel;
    return 0;
}

int
ipmi_user_get_num(ipmi_user_t *user, unsigned int *num)
{
    *num = user->num;
    return 0;
}

int
ipmi_user_set_num(ipmi_user_t *user, unsigned int num)
{
    if (num > 0x3f)
	return EINVAL;
    user->num = num;
    return 0;
}

int
ipmi_user_get_name_len(ipmi_user_t *user, unsigned int *len)
{
    *len = 16;
    return 0;
}

int
ipmi_user_get_name(ipmi_user_t *user, char *name, unsigned int *len)
{
    if (*len > 17)
	*len = 17;
    memcpy(name, user->name, *len);
    return 0;
}

int
ipmi_user_set_name(ipmi_user_t *user, char *name, unsigned int len)
{
    if (len > 16)
	return EINVAL;
    memcpy(user->name, name, len);
    user->name_set = 1;
    return 0;
}

int
ipmi_user_set_password(ipmi_user_t *user, char *pw, unsigned int len)
{
    if (len > 16)
	return EINVAL;
    memcpy(user->pw, pw, len);
    user->pw_set = 1;
    return 0;
}

int
ipmi_user_set_password2(ipmi_user_t *user, char *pw, unsigned int len)
{
    if (! user->can_use_pw2)
	return ENOSYS;
    if (len > 20)
	return EINVAL;
    memcpy(user->pw, pw, len);
    user->pw2_set = 1;
    return 0;
}

int
ipmi_user_get_link_auth_enabled(ipmi_user_t *user, unsigned int *val)
{
    *val = user->link_enabled;
    return 0;
}

int
ipmi_user_set_link_auth_enabled(ipmi_user_t *user, unsigned int val)
{
    user->link_enabled = val;
    user->link_enabled_set = 1;
    return 0;
}

int
ipmi_user_get_msg_auth_enabled(ipmi_user_t *user, unsigned int *val)
{
    *val = user->msg_enabled;
    return 0;
}

int
ipmi_user_set_msg_auth_enabled(ipmi_user_t *user, unsigned int val)
{
    user->msg_enabled = val;
    user->msg_enabled_set = 1;
    return 0;
}

int
ipmi_user_get_access_cb_only(ipmi_user_t *user, unsigned int *val)
{
    *val = user->cb_only;
    return 0;
}

int
ipmi_user_set_access_cb_only(ipmi_user_t *user, unsigned int val)
{
    user->cb_only = val;
    user->cb_only_set = 1;
    return 0;
}

int
ipmi_user_get_privilege_limit(ipmi_user_t *user, unsigned int *val)
{
    *val = user->privilege_limit;
    return 0;
}

int
ipmi_user_set_privilege_limit(ipmi_user_t *user, unsigned int val)
{
    user->privilege_limit = val;
    user->privilege_limit_set = 1;
    return 0;
}

int
ipmi_user_get_session_limit(ipmi_user_t *user, unsigned int *val)
{
    if (!user->session_limit_read)
	return ENOSYS;
    *val = user->session_limit;
    return 0;
}

int
ipmi_user_set_session_limit(ipmi_user_t *user, unsigned int val)
{
    user->session_limit = val;
    user->session_limit_set = 1;
    user->session_limit_read = 1;
    return 0;
}

int
ipmi_user_get_enable(ipmi_user_t *user, unsigned int *val)
{
    if (!user->enable_read)
	return ENOSYS;
    *val = user->enable;
    return 0;
}

int
ipmi_user_set_enable(ipmi_user_t *user, unsigned int val)
{
    user->enable = val;
    user->enable_set = 1;
    user->enable_read = 1;
    return 0;
}

int
ipmi_user_set_all(ipmi_user_t *user)
{
    user->cb_only_set = 1;
    user->link_enabled_set = 1;
    user->msg_enabled_set = 1;
    user->privilege_limit_set = 1;
    user->session_limit_set = user->session_limit_read;
    user->enable_set = user->enable_read;
    user->name_set = 1;
    return 0;
}

