/*
 * ipmi_int.h
 *
 * MontaVista IPMI interface, internal information.
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
int ipmi_create_lock(ipmi_domain_t *mc, ipmi_lock_t **lock);

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

/* Get a globally unique sequence number. */
long ipmi_get_seq(void);

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
    int          __event_messages_enabled;
    int          __sensor_scanning_enabled;
    int          __initial_update_in_progress;
    unsigned int __states;
};

/* Called by connections to see if they have any special OEM handling
   to do. */
int ipmi_check_oem_conn_handlers(ipmi_con_t   *conn,
				 unsigned int manufacturer_id,
				 unsigned int product_id);

/* IPMI data handling. */

/* Extract a 32-bit integer from the data, IPMI (little-endian) style. */
unsigned int ipmi_get_uint32(unsigned char *data);

/* Extract a 16-bit integer from the data, IPMI (little-endian) style. */
unsigned int ipmi_get_uint16(unsigned char *data);

/* Add a 32-bit integer to the data, IPMI (little-endian) style. */
void ipmi_set_uint32(unsigned char *data, int val);

/* Add a 16-bit integer to the data, IPMI (little-endian) style. */
void ipmi_set_uint16(unsigned char *data, int val);

/* If we have a 6-bit field, we can have up to 63 items, and with BCD
   there may be 2 characters per byte, so 126 max. */
#define IPMI_MAX_STR_LEN 126

/* Fetch an IPMI device string as defined in section 37.14 of the IPMI
   version 1.5 manual.  The in_len is the number of input bytes in the
   string, including the type/length byte.  The max_out_len is the
   maximum number of characters to output, including the nil.  The
   type will be set to either unicode or ASCII.  The number of bytes
   put into the output string is returned. */
unsigned int ipmi_get_device_string(unsigned char        *input,
				    unsigned int         in_len,
				    char                 *output,
				    int                  force_unicode,
				    enum ipmi_str_type_e *type,
				    unsigned int         max_out_len);

/* Store an IPMI device string in the most compact form possible.
   input is the input string (nil terminated), output is where to
   place the output (including the type/length byte) and out_len is a
   pointer to the max size of output (including the type/length byte).
   Upon return, out_len will be set to the actual output length. */
void ipmi_set_device_string(char                 *input,
			    enum ipmi_str_type_e type,
			    unsigned int         in_len,
			    unsigned char        *output,
			    int                  force_unicode,
			    int                  *out_len);


/* IPMI uses this for memory allocation, so it can easily be
   substituted, etc. */
void *ipmi_mem_alloc(int size);
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

/* Lock/unlock the entities for the given domain. */
void ipmi_domain_entity_lock(ipmi_domain_t *domain);
void ipmi_domain_entity_unlock(ipmi_domain_t *domain);

#ifdef IPMI_CHECK_LOCKS
/* Various lock-checking information. */
/* Nothing for now. */
#define CHECK_MC_LOCK(mc) do {} while (0)

void __ipmi_check_domain_lock(ipmi_domain_t *domain);
#define CHECK_DOMAIN_LOCK(domain) __ipmi_check_domain_lock(domain)
void __ipmi_check_entity_lock(ipmi_entity_t *entity);
#define CHECK_ENTITY_LOCK(entity) __ipmi_check_entity_lock(entity)
void __ipmi_check_domain_entity_lock(ipmi_domain_t *domain);
#define CHECK_DOMAIN_ENTITY_LOCK(domain) __ipmi_check_domain_entity_lock(domain)
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
#define CHECK_DOMAIN_LOCK(domain) do {} while (0)
#define CHECK_ENTITY_LOCK(entity) do {} while (0)
#define CHECK_DOMAIN_ENTITY_LOCK(domain) do {} while (0)
#define CHECK_SENSOR_LOCK(sensor) do {} while (0)
#define CHECK_CONTROL_LOCK(control) do {} while (0)
#define IPMI_REPORT_LOCK_ERROR(handler, str) do {} while (0)
#endif

#endif /* _IPMI_INT_H */
