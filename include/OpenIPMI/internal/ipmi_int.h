/*
 * ipmi_int.h
 *
 * MontaVista IPMI interface, internal information.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004 MontaVista Software Inc.
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
#include <OpenIPMI/ipmi_types.h>
#include <OpenIPMI/ipmi_bits.h>
#include <OpenIPMI/ipmi_log.h>

#include <OpenIPMI/internal/ipmi_malloc.h>
#include <OpenIPMI/internal/ipmi_locks.h>

/* Get the "global" OS handlers used for non-domain operations. */
os_handler_t *ipmi_get_global_os_handler(void);

/* There is a global read/write lock that protects the addition and
   removal of MCs and high-level information that doesn't change very
   much.  Grabbing the read lock keep anything from adding or removing
   MCs.  Grabbing the write lock give exclusive access to the MCs.  It's
   also used for protecting a few other things, too. */
void ipmi_read_lock(void);
void ipmi_read_unlock(void);
void ipmi_write_lock(void);
void ipmi_write_unlock(void);

/* Create a lock, using the OS handlers for the given MC. */
int ipmi_create_lock(ipmi_domain_t *mc, ipmi_lock_t **lock);

/* Create a lock using the main os handler registered with ipmi_init(). */
int ipmi_create_global_lock(ipmi_lock_t **new_lock);

int ipmi_create_global_rwlock(ipmi_rwlock_t **new_lock);
int ipmi_create_rwlock(ipmi_domain_t *domain, ipmi_rwlock_t **new_lock);

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


/* Generate a log.  Note that logs should not end in a newline, that
   will be automatically added as needed to the log.  */
void ipmi_log(enum ipmi_log_type_e log_type, char *format, ...)
#ifdef __GNUC__
     __attribute__ ((__format__ (__printf__, 2, 3)))
#endif
;

/* Internal function to get the name of a domain. */
char *_ipmi_domain_name(ipmi_domain_t *domain);
char *_ipmi_mc_name(ipmi_mc_t *mc);
char *_ipmi_sensor_name(ipmi_sensor_t *sensor);
char *_ipmi_control_name(ipmi_control_t *control);
char *_ipmi_entity_name(ipmi_entity_t *entity);
char *_ipmi_entity_id_name(ipmi_entity_id_t entity_id);
#define DOMAIN_NAME(d) ((d) ? _ipmi_domain_name(d) : "")
#define MC_NAME(m) ((m) ? _ipmi_mc_name(m) : "")
#define ENTITY_NAME(e) ((e) ? _ipmi_entity_name(e) : "")
#define ENTITY_ID_NAME(e) (_ipmi_entity_id_name(e))
#define SENSOR_NAME(s) ((s) ? _ipmi_sensor_name(s) : "")
#define CONTROL_NAME(c) ((c) ? _ipmi_control_name(c) : "")

#include <OpenIPMI/ipmi_debug.h>

/* Lock/unlock the entities/mcs for the given domain. */
void _ipmi_domain_entity_lock(ipmi_domain_t *domain);
void _ipmi_domain_entity_unlock(ipmi_domain_t *domain);
void _ipmi_domain_mc_lock(ipmi_domain_t *domain);
void _ipmi_domain_mc_unlock(ipmi_domain_t *domain);

#ifdef IPMI_CHECK_LOCKS
/* Various lock-checking information. */
/* Nothing for now. */
void __ipmi_check_mc_lock(ipmi_mc_t *mc);
#define CHECK_MC_LOCK(mc) __ipmi_check_mc_lock(mc)

void __ipmi_check_domain_lock(ipmi_domain_t *domain);
#define CHECK_DOMAIN_LOCK(domain) __ipmi_check_domain_lock(domain)
void __ipmi_check_entity_lock(ipmi_entity_t *entity);
#define CHECK_ENTITY_LOCK(entity) __ipmi_check_entity_lock(entity)
void __ipmi_check_sensor_lock(ipmi_sensor_t *sensor);
#define CHECK_SENSOR_LOCK(sensor) __ipmi_check_sensor_lock(sensor)
void __ipmi_check_control_lock(ipmi_control_t *control);
#define CHECK_CONTROL_LOCK(control) __ipmi_check_control_lock(control)

void ipmi_check_lock(ipmi_lock_t *lock, char *str);
#else
#define CHECK_MC_LOCK(mc) do {} while (0)
#define CHECK_DOMAIN_LOCK(domain) do {} while (0)
#define CHECK_ENTITY_LOCK(entity) do {} while (0)
#define CHECK_DOMAIN_ENTITY_LOCK(domain) do {} while (0)
#define CHECK_SENSOR_LOCK(sensor) do {} while (0)
#define CHECK_CONTROL_LOCK(control) do {} while (0)
#endif

#define ipmi_seconds_to_time(x) (((ipmi_time_t) (x)) * 1000000000)
#define ipmi_timeval_to_time(x) ((((ipmi_time_t) (x).tv_sec) * 1000000000) \
				 + (((ipmi_time_t) (x).tv_usec) * 1000))

#endif /* _IPMI_INT_H */
