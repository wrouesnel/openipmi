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
#include <OpenIPMI/ipmiif.h> /* for ipmi_args_t, sigh */

#include <OpenIPMI/internal/ipmi_malloc.h>
#include <OpenIPMI/internal/ipmi_locks.h>

/* Get the "global" OS handlers used for non-domain operations. */
os_handler_t *ipmi_get_global_os_handler(void);

/* Create a lock, using the OS handlers for the given MC. */
int ipmi_create_lock(ipmi_domain_t *mc, ipmi_lock_t **lock);

/* Create a lock using the main os handler registered with ipmi_init(). */
int ipmi_create_global_lock(ipmi_lock_t **new_lock);

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
unsigned int ipmi_get_uint32(const unsigned char *data);

/* Extract a 16-bit integer from the data, IPMI (little-endian) style. */
unsigned int ipmi_get_uint16(const unsigned char *data);

/* Add a 32-bit integer to the data, IPMI (little-endian) style. */
void ipmi_set_uint32(unsigned char *data, int val);

/* Add a 16-bit integer to the data, IPMI (little-endian) style. */
void ipmi_set_uint16(unsigned char *data, int val);

/* If we have a 6-bit field, we can have up to 63 items, and with BCD
   there may be 2 characters per byte, so 126 max. */
#define IPMI_MAX_STR_LEN 126

/* Fetch an IPMI device string as defined in section 37.14 of the IPMI
   version 1.5 manual.  The in_len is the number of input bytes in the
   string, including the type/length byte.  It may be longer than the
   actual length.  The max_out_len is the maximum number of characters
   to output, including the nil.  The type will be set to either
   unicode or ASCII.  The number of bytes put into the output string
   is returned in out_len.  The input pointer will be updated to point
   to the character after the used data.  This returns a standard
   error value. */
#define IPMI_STR_SDR_SEMANTICS	0
#define IPMI_STR_FRU_SEMANTICS	1
int ipmi_get_device_string(unsigned char        **input,
			   unsigned int         in_len,
			   char                 *output,
			   int                  semantics,
			   int                  force_unicode,
			   enum ipmi_str_type_e *type,
			   unsigned int         max_out_len,
			   unsigned int         *out_len);

/* Store an IPMI device string in the most compact form possible.
   input is the input string (nil terminated), output is where to
   place the output (including the type/length byte) and out_len is a
   pointer to the max size of output (including the type/length byte).
   Upon return, out_len will be set to the actual output length. */
void ipmi_set_device_string(const char           *input,
			    enum ipmi_str_type_e type,
			    unsigned int         in_len,
			    unsigned char        *output,
			    int                  force_unicode,
			    unsigned int         *out_len);

/* Like ipmi_set_device_string, but include options.  See ipmi_bits.h
   for IPMI_STRING_OPTION_xxx. */
void ipmi_set_device_string2(const char           *input,
			     enum ipmi_str_type_e type,
			     unsigned int         in_len,
			     unsigned char        *output,
			     int                  force_unicode,
			     unsigned int         *out_len,
			     unsigned int         options);

/* Generate a log.  Note that logs should not end in a newline, that
   will be automatically added as needed to the log.  */
void ipmi_log(enum ipmi_log_type_e log_type, const char *format, ...)
#ifdef __GNUC__
     __attribute__ ((__format__ (__printf__, 2, 3)))
#endif
;

/* Information for connection handlers. */
typedef struct ipmi_con_setup_s ipmi_con_setup_t;
typedef int (*ipmi_con_parse_args_cb)(int         *curr_arg,
				      int         arg_count,
				      char        * const *args,
				      ipmi_args_t **iargs);
typedef const char *(*ipmi_con_get_help_cb)(void);
typedef ipmi_args_t *(*ipmi_con_alloc_args_cb)(void);
ipmi_con_setup_t *_ipmi_alloc_con_setup(ipmi_con_parse_args_cb parse,
					ipmi_con_get_help_cb   help,
					ipmi_con_alloc_args_cb alloc);
void _ipmi_free_con_setup(ipmi_con_setup_t *v);

int _ipmi_register_con_type(const char *name, ipmi_con_setup_t *setup);
int _ipmi_unregister_con_type(const char *name, ipmi_con_setup_t *setup);

typedef void (*ipmi_args_free_cb)(ipmi_args_t *args);
typedef int (*ipmi_args_connect_cb)(ipmi_args_t  *args,
				    os_handler_t *handler,
				    void         *user_data,
				    ipmi_con_t   **new_con);
typedef int (*ipmi_args_get_val_cb)(ipmi_args_t  *args,
				    unsigned int argnum,
				    const char   **name,
				    const char   **type,
				    const char   **help,
				    char         **value,
				    const char   ***range);
typedef int (*ipmi_args_set_val_cb)(ipmi_args_t  *args,
				    unsigned int argnum,
				    const char   *name,
				    const char   *value);
typedef ipmi_args_t *(*ipmi_args_copy_cb)(ipmi_args_t *args);
typedef int (*ipmi_args_validate_cb)(ipmi_args_t *args, int *argnum);
typedef void (*ipmi_args_free_val_cb)(ipmi_args_t *args, char *value);
typedef const char *(*ipmi_args_get_type_cb)(ipmi_args_t *args);
ipmi_args_t *_ipmi_args_alloc(ipmi_args_free_cb     free,
			      ipmi_args_connect_cb  connect,
			      ipmi_args_get_val_cb  get_val,
			      ipmi_args_set_val_cb  set_val,
			      ipmi_args_copy_cb     copy,
			      ipmi_args_validate_cb validate,
			      ipmi_args_free_val_cb free_val,
			      ipmi_args_get_type_cb get_type,
			      unsigned int          extra_data_len);
void *_ipmi_args_get_extra_data(ipmi_args_t *args);


/* Internal function to get the name of a domain. */
const char *_ipmi_domain_name(const ipmi_domain_t *domain);
const char *_ipmi_mc_name(const ipmi_mc_t *mc);
const char *_ipmi_sensor_name(const ipmi_sensor_t *sensor);
const char *_ipmi_control_name(const ipmi_control_t *control);
const char *_ipmi_entity_name(const ipmi_entity_t *entity);
const char *_ipmi_entity_id_name(const ipmi_entity_id_t entity_id);
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
void __ipmi_check_mc_lock(const ipmi_mc_t *mc);
#define CHECK_MC_LOCK(mc) __ipmi_check_mc_lock(mc)

void __ipmi_check_domain_lock(const ipmi_domain_t *domain);
#define CHECK_DOMAIN_LOCK(domain) __ipmi_check_domain_lock(domain)
void __ipmi_check_entity_lock(const ipmi_entity_t *entity);
#define CHECK_ENTITY_LOCK(entity) __ipmi_check_entity_lock(entity)
void __ipmi_check_sensor_lock(const ipmi_sensor_t *sensor);
#define CHECK_SENSOR_LOCK(sensor) __ipmi_check_sensor_lock(sensor)
void __ipmi_check_control_lock(const ipmi_control_t *control);
#define CHECK_CONTROL_LOCK(control) __ipmi_check_control_lock(control)

void ipmi_check_lock(const ipmi_lock_t *lock, const char *str);
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
