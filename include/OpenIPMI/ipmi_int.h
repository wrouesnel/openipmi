/*
 * ipmi_int.h
 *
 * MontaVista IPMI interface, internal information.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
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

#ifndef _IPMI_INT_H
#define _IPMI_INT_H

/* Stuff used internally in the IPMI code, and possibly by OEM code. */

#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_addr.h>

/* There is a global read/write lock that protects the addition and
   removal of MCs and high-level information that doesn't change very
   much.  Grabbing the read lock keep anything from adding or removing
   MCs.  Grabbing the write lock give exclusive access to the MCs.  It's
   also used for protecting a few other things, too. */
void ipmi_read_lock(void);
void ipmi_read_unlock(void);
void ipmi_write_lock(void);
void ipmi_write_unlock(void);

/* This is a generic lock used by the IPMI code. */
typedef struct ipmi_lock_s ipmi_lock_t;

/* Create a lock, using the OS handlers for the given MC. */
int ipmi_create_lock(ipmi_mc_t *mc, ipmi_lock_t **lock);

/* Create a lock using the main os handler registered with ipmi_init(). */
int ipmi_create_global_lock(ipmi_lock_t **new_lock);

/* Create a lock but us your own OS handlers. */
int ipmi_create_lock_os_hnd(os_handler_t *os_hnd, ipmi_lock_t **lock);

/* Destroy a lock. */
void ipmi_destroy_lock(ipmi_lock_t *lock);

/* Lock the lock.  Locks are recursive, so the same thread can claim
   the same lock multiple times, and must release it the same number
   of times. */
void ipmi_lock(ipmi_lock_t *lock);

/* Release the lock. */
void ipmi_unlock(ipmi_lock_t *lock);

/* The sensor code calls the MC code with this when it finds a new
   sensor.  If this returns 1, the sensor will NOT be added to the
   list of sensors in then entity.  This will call the OEM code if it
   has registered for this. */
int ipmi_bmc_oem_new_sensor(ipmi_mc_t     *mc,
			    ipmi_entity_t *ent,
			    ipmi_sensor_t *sensor,
			    void          *link);

/* This is called by the entity code when a new entity is created.
   Entity creation cannot be stopped.  This will call the OEM code if
   it has registered for this. */
void ipmi_bmc_oem_new_entity(ipmi_mc_t *bmc, ipmi_entity_t *ent);

/* The event state data structure. */
struct ipmi_event_state_s
{
    unsigned int status;
    /* Pay no attention to the implementation. */
    unsigned int __assertion_events;
    unsigned int __deassertion_events;
};

struct ipmi_thresholds_s
{
    /* Pay no attention to the implementation here. */
    struct {
	unsigned int status; /* Is this threshold enabled? */
	double       val;
    } vals[6];
};

struct ipmi_states_s
{
    int          __event_messages_disabled;
    int          __sensor_scanning_disabled;
    int          __initial_update_in_progress;
    unsigned int __states;
};


/* IPMI uses this for memory allocation, so it can easily be
   substituted, etc. */
void *ipmi_mem_alloc(size_t size);
void ipmi_mem_free(void *data);

/* If you have debug allocations on, then you should call this to
   check for data you haven't freed (after you have freed all the
   data, of course).  It's safe to call even if malloc debugging is
   turned off. */
void ipmi_debug_malloc_cleanup(void);


/* Various logging stuff (mostly for debugging) */
extern unsigned int __ipmi_log_mask;

/* Log normal IPMI messages, but not low-level protocol messages. */
#define DEBUG_MSG_BIT		(1 << 0)

/* Log all messages. */
#define DEBUG_RAWMSG_BIT	(1 << 1)

/* Attempt to detect locking errors and report them. */
#define DEBUG_LOCKS_BIT		(1 << 2)

/* Log events that are received. */
#define DEBUG_EVENTS_BIT	(1 << 3)

/* Force the given connection to no longer work */
#define DEBUG_CON0_FAIL_BIT	(1 << 4)
#define DEBUG_CON1_FAIL_BIT	(1 << 5)
#define DEBUG_CON2_FAIL_BIT	(1 << 6)
#define DEBUG_CON3_FAIL_BIT	(1 << 7)

/* Debug mallocs.  This should only be set at startup (before
   ipmi_mem_alloc() is called), and cannot be cleared after that. */
#define DEBUG_MALLOC_BIT	(1 << 8)

#define DEBUG_MSG	(__ipmi_log_mask & DEBUG_MSG_BIT)
#define DEBUG_MSG_ENABLE() __ipmi_log_mask |= DEBUG_MSG_BIT
#define DEBUG_MSG_DISABLE() __ipmi_log_mask &= ~DEBUG_MSG_BIT

#define DEBUG_RAWMSG	(__ipmi_log_mask & DEBUG_RAWMSG_BIT)
#define DEBUG_RAWMSG_ENABLE() __ipmi_log_mask |= DEBUG_RAWMSG_BIT
#define DEBUG_RAWMSG_DISABLE() __ipmi_log_mask &= ~DEBUG_RAWMSG_BIT

#define DEBUG_LOCKS	(__ipmi_log_mask & DEBUG_LOCKS_BIT)
#define DEBUG_LOCKS_ENABLE() __ipmi_log_mask |= DEBUG_LOCKS_BIT
#define DEBUG_LOCKS_DISABLE() __ipmi_log_mask &= ~DEBUG_LOCKS_BIT

#define DEBUG_EVENTS	(__ipmi_log_mask & DEBUG_EVENTS_BIT)
#define DEBUG_EVENTS_ENABLE() __ipmi_log_mask |= DEBUG_EVENTS_BIT
#define DEBUG_EVENTS_DISABLE() __ipmi_log_mask &= ~DEBUG_EVENTS_BIT

#define DEBUG_CON_FAIL(con)    (__ipmi_log_mask & (DEBUG_CON0_FAIL_BIT << con))
#define DEBUG_CON_FAIL_ENABLE(con) \
	__ipmi_log_mask |= (DEBUG_CON0_FAIL_BIT << con)
#define DEBUG_CON_FAIL_DISABLE(con) \
	__ipmi_log_mask &= ~(DEBUG_CON0_FAIL_BIT << con)

#define DEBUG_MALLOC	(__ipmi_log_mask & DEBUG_MALLOC_BIT)
#define DEBUG_MALLOC_ENABLE() __ipmi_log_mask |= DEBUG_MALLOC_BIT

#ifdef IPMI_CHECK_LOCKS
/* Various lock-checking information. */
void __ipmi_check_mc_lock(ipmi_mc_t *mc);
#define CHECK_MC_LOCK(mc) __ipmi_check_mc_lock(mc)
void __ipmi_check_entity_lock(ipmi_entity_t *entity);
#define CHECK_ENTITY_LOCK(entity) __ipmi_check_entity_lock(entity)
void __ipmi_check_mc_entity_lock(ipmi_mc_t *mc);
#define CHECK_MC_ENTITY_LOCK(entity) __ipmi_check_mc_entity_lock(mc)
void __ipmi_check_sensor_lock(ipmi_sensor_t *sensor);
#define CHECK_SENSOR_LOCK(sensor) __ipmi_check_sensor_lock(sensor)
void __ipmi_check_control_lock(ipmi_control_t *control);
#define CHECK_CONTROL_LOCK(control) __ipmi_check_control_lock(control)
void ipmi_report_lock_error(os_handler_t *handler, char *str);
#define IPMI_REPORT_LOCK_ERROR(handler, str) ipmi_report_lock_error(handler, \
								    str)
void ipmi_check_lock(ipmi_lock_t *lock, char *str);
#else
#define CHECK_MC_LOCK(mc) do {} while (0)
#define CHECK_ENTITY_LOCK(entity) do {} while (0)
#define CHECK_MC_ENTITY_LOCK(entity) do {} while (0)
#define CHECK_SENSOR_LOCK(sensor) do {} while (0)
#define CHECK_CONTROL_LOCK(control) do {} while (0)
#define IPMI_REPORT_LOCK_ERROR(handler, str) do {} while (0)
#endif

#endif /* _IPMI_INT_H */
