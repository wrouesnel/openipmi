/*
 * ipmi.c
 *
 * MontaVista IPMI generic code
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
#include <netdb.h>

#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_oem.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/mxp.h>

static os_hnd_rwlock_t *global_lock;
static os_handler_t *ipmi_os_handler;

unsigned int __ipmi_log_mask = 0;

void ipmi_read_lock(void)
{
    if (global_lock)
	ipmi_os_handler->read_lock(ipmi_os_handler, global_lock);
}

void ipmi_read_unlock(void)
{
    if (global_lock)
	ipmi_os_handler->read_unlock(ipmi_os_handler, global_lock);
}

void ipmi_write_lock(void)
{
    if (global_lock)
	ipmi_os_handler->write_lock(ipmi_os_handler, global_lock);
}

void ipmi_write_unlock(void)
{
    if (global_lock)
	ipmi_os_handler->write_unlock(ipmi_os_handler, global_lock);
}

struct ipmi_lock_s
{
    os_hnd_lock_t *ll_lock;
    os_handler_t  *os_hnd;
};
    
int
ipmi_create_lock_os_hnd(os_handler_t *os_hnd, ipmi_lock_t **new_lock)
{
    ipmi_lock_t *lock;
    int         rv;

    lock = ipmi_mem_alloc(sizeof(*lock));
    if (!lock)
	return ENOMEM;

    lock->os_hnd = os_hnd;
    if (lock->os_hnd && lock->os_hnd->create_lock) {
	rv = lock->os_hnd->create_lock(lock->os_hnd, &(lock->ll_lock));
	if (rv) {
	    ipmi_mem_free(lock);
	    return rv;
	}
    } else {
	lock->ll_lock = NULL;
    }

    *new_lock = lock;

    return 0;
}

int
ipmi_create_global_lock(ipmi_lock_t **new_lock)
{
    ipmi_lock_t *lock;
    int         rv;

    lock = ipmi_mem_alloc(sizeof(*lock));
    if (!lock)
	return ENOMEM;

    lock->os_hnd = ipmi_os_handler;
    if (lock->os_hnd && lock->os_hnd->create_lock) {
	rv = lock->os_hnd->create_lock(lock->os_hnd, &(lock->ll_lock));
	if (rv) {
	    ipmi_mem_free(lock);
	    return rv;
	}
    } else {
	lock->ll_lock = NULL;
    }

    *new_lock = lock;

    return 0;
}

int
ipmi_create_lock(ipmi_domain_t *domain, ipmi_lock_t **new_lock)
{
    return ipmi_create_lock_os_hnd(ipmi_domain_get_os_hnd(domain), new_lock);
}

void ipmi_destroy_lock(ipmi_lock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->destroy_lock(lock->os_hnd, lock->ll_lock);
    ipmi_mem_free(lock);
}

void ipmi_lock(ipmi_lock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->lock(lock->os_hnd, lock->ll_lock);
}

void ipmi_unlock(ipmi_lock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->unlock(lock->os_hnd, lock->ll_lock);
}

void
ipmi_log(enum ipmi_log_type_e log_type, char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    if (ipmi_os_handler->vlog)
	ipmi_os_handler->vlog(ipmi_os_handler, log_type, format, ap);
    else
	vfprintf(stderr, format, ap);
    va_end(ap);
}

static ll_ipmi_t *ipmi_ll = NULL;

void
ipmi_register_ll(ll_ipmi_t *ll)
{
    if (ll->registered)
	return;

    ipmi_write_lock();
    if (! ll->registered) {
	ll->registered = 1;
	ll->next = ipmi_ll;
	ipmi_ll = ll;
    }
    ipmi_write_unlock();
}

/* Must be called with the read or write lock held. */
int
__ipmi_validate(ipmi_con_t *ipmi)
{
    ll_ipmi_t *elem;

    elem = ipmi_ll;
    while (elem) {
	if (elem->valid_ipmi(ipmi)) {
	    return 0;
	}
	elem = elem->next;
    }

    return EINVAL;
}

static unsigned int
ipmi_get_unicode(int len,
		 unsigned char *d, int in_len,
		 char *out, int out_len)
{
    if (out_len < len)
	len = out_len;

    memcpy(out, d, len);
    return len;
}

static unsigned int
ipmi_get_bcd_plus(int len,
		  unsigned char *d, int in_len,
		  char *out, int out_len)
{
    static char table[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', ' ', '-', '.', ':', ',', '_'
    };
    int pos;
    int bo;
    int val = 0;
    int i;
    int real_length;
    char *out_s = out;

    real_length = (in_len * 8) / 6;
    if (len > real_length)
	len = real_length;
    
    if (len > out_len)
	len = out_len;

    bo = 0;
    pos = 0;
    for (i=0; i<len; i++) {
	switch (bo) {
	    case 0:
		val = *d & 0xf;
		bo = 4;
		break;
	    case 4:
		val = (*d >> 4) & 0xf;
		d++;
		bo = 0;
		break;
	}
	*out = table[val];
	out++;
    }
    return out - out_s;
}

static unsigned int
ipmi_get_6_bit_ascii(int len,
		     unsigned char *d, int in_len,
		     char *out, int out_len)
{
    static char table[64] = {
	' ', '!', '"', '#', '$', '%', '&', '\'',
	'(', ')', '*', '+', ',', '-', '.', '/', 
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', ':', ';', '<', '=', '>', '?',
	'&', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	'X', 'Y', 'Z', '[', '\\', ']', '^', '_' 
    };
    int pos;
    int bo;
    int val = 0;
    int i;
    int real_length;
    char *out_s = out;

    real_length = (in_len * 8) / 6;
    if (len > real_length)
	len = real_length;
    
    if (len > out_len)
	len = out_len;

    bo = 0;
    pos = 0;
    for (i=0; i<len; i++) {
	switch (bo) {
	    case 0:
		val = *d & 0x3f;
		bo = 6;
		break;
	    case 2:
		val = (*d >> 2) & 3;
		d++;
		val |= (*d & 0xf) << 2;
		bo = 0;
		break;
	    case 4:
		val = (*d >> 4) & 0xf;
		d++;
		val |= (*d & 0x3) << 4;
		bo = 2;
		break;
	    case 6:
		val = (*d >> 6) & 0x3;
		d++;
		val |= (*d & 0xf) << 2;
		bo = 4;
		break;
	}
	*out = table[val];
	out++;
    }

    return out - out_s;
}

static unsigned int
ipmi_get_8_bit_ascii(int len,
		     unsigned char *d, int in_len,
		     char *out, int out_len)
{
    int j;

    
    if (len > in_len)
	len = in_len;

    if (len > out_len)
	len = out_len;

    for (j=0; j<len; j++) {
	*out = *d;
	out++;
	d++;
    }
    return len;
};

unsigned int
ipmi_get_device_string(unsigned char        *input,
		       unsigned int         in_len,
		       char                 *output,
		       int                  force_unicode,
		       enum ipmi_str_type_e *stype,
		       unsigned int         max_out_len)
{
    int          type;
    int          len;
    unsigned int olen;

    if (max_out_len == 0)
	return 0;

    if (in_len < 2) {
	*output = '\0';
	return 0;
    }

    type = (*input >> 6) & 3;

    /* Special case for FRU data, type 3 is unicode if the language is
       non-english. */
    if ((force_unicode) && (type == 3))
	type = 0;

    len = *input & 0x3f;
    input++;
    in_len--;
    *stype = IPMI_ASCII_STR;
    switch (type)
    {
	case 0: /* Unicode */
	    olen = ipmi_get_unicode(len, input, in_len, output, max_out_len);
	    *stype = IPMI_UNICODE_STR;
	    break;
	case 1: /* BCD Plus */
	    olen = ipmi_get_bcd_plus(len, input, in_len, output, max_out_len);
	    break;
	case 2: /* 6-bit ASCII */
	    olen=ipmi_get_6_bit_ascii(len, input, in_len, output, max_out_len);
	    break;
	case 3: /* 8-bit ASCII */
	    olen=ipmi_get_8_bit_ascii(len, input, in_len, output, max_out_len);
	    break;
        default:
	    olen = 0;
    }

    return olen;
}

/* Element will be zero if not present, n-1 if present. */
static char table_4_bit[256] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0f, 0x0c, 0x0d, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Element will be zero if not present, n-1 if present. */
static char table_6_bit[256] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x21, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x00, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static void
ipmi_set_bcdplus(char          *input,
		 unsigned char *output,
		 int           *out_len)
{
    int  len = *out_len;
    char *s = input;
    int  pos = 0;
    int  bit = 0;
    int  count = 0;

    while (*s != '\0') {
	if (pos >= len) {
	    output[0] = (0x01 << 6) | count;
	    return;
	}
	switch(bit) {
	    case 0:
		pos++;
		output[pos] = table_4_bit[(int) *s];
		bit = 4;
		break;

	    case 4:
		output[pos] |= table_4_bit[(int) *s] << 4;
		bit = 0;
		break;
	}
	count++;
    }
    output[0] = (0x01 << 6) | count;
    *out_len = pos+1;
}

static void
ipmi_set_6_bit_ascii(char          *input,
		     unsigned char *output,
		     int           *out_len)
{
    int  len = *out_len;
    char *s = input+1;
    int  pos = 0;
    int  bit = 0;
    int  count = 0;
    int  cval;

    while (*s != '\0') {
	if (pos >= len) {
	    output[0] = (0x02 << 6) | count;
	    return;
	}
	cval = *s;
	switch(bit) {
	    case 0:
		pos++;
		output[pos] = table_6_bit[cval];
		bit = 6;
		break;

	    case 2:
		output[pos] |= (table_6_bit[cval] << 2);
		bit = 0;
		break;

	    case 4:
		output[pos] |= table_4_bit[cval] << 4;
		pos++;
		output[pos] = (table_4_bit[cval] >> 4) & 0x3;
		bit = 2;
		break;

	    case 6:
		output[pos] |= table_4_bit[cval] << 6;
		pos++;
		output[pos] = (table_4_bit[cval] >> 2) & 0xf;
		bit = 4;
		break;
	}
	count++;
    }
    output[0] = (0x02 << 6) | count;
    *out_len = pos+1;
}

static void
ipmi_set_8_bit_ascii(char          *input,
		     unsigned char *output,
		     int           *out_len)
{
    int len = strlen(input+1);
    if (len > (*out_len - 1))
	len = *out_len - 1;
    else
	*out_len = len + 1;
    strncpy(input, output+1, len);
    output[0] = (0x02 << 6) | len;
}

static void
ipmi_set_8_bit_ascii_to_unicode(char          *input,
				unsigned char *output,
				int           *out_len)
{
    /* FIXME - this is not implemented yet. */
    *out_len = 0;
}

void
ipmi_set_device_string(char                 *input,
		       enum ipmi_str_type_e type,
		       unsigned int         in_len,
		       unsigned char        *output,
		       int                  force_unicode,
		       int                  *out_len)
{
    char *s = input+1;
    int  bsize = 0; /* Start with 4-bit. */

    /* Max size is 63 (62 bytes + the type byte). */
    if (*out_len > 63)
	*out_len = 63;

    if (type == IPMI_ASCII_STR) {
	while (*s != '\0') {
	    if (table_4_bit[(int) *s] == 0)
		bsize |= 1;
	    else if (table_6_bit[(int) *s] == 0) {
		bsize |= 2;
		break;
	    }
	}
	if (bsize == 0) {
	    /* We can encode it in 4-bit BCD+ */
	    ipmi_set_bcdplus(input, output, out_len);
	} else if (bsize == 1) {
	    /* We can encode it in 6-bit ASCII. */
	    ipmi_set_6_bit_ascii(input, output, out_len);
	} else {
	    /* Hack for FRU information, if the language is
	       non-english and the type is ascii, it's unicode. */
	    if (force_unicode) {
		/* The input is ASCII and the output is unicode. */
		ipmi_set_8_bit_ascii_to_unicode(input, output, out_len);
	    } else {
		/* 8-bit ASCII is required. */
		ipmi_set_8_bit_ascii(input, output, out_len);
	    }
	}
    } else {
	/* The input and output are unicode. */
	if (in_len > *out_len-1)
	    in_len = *out_len-1;
	*output = in_len;
	memcpy(output+1, input, in_len);
	*out_len = in_len + 1;
    }
}

static long seq = 0;
static os_hnd_lock_t *seq_lock;
long
ipmi_get_seq(void)
{
    long rv;

    if (seq_lock)
	ipmi_os_handler->lock(ipmi_os_handler, seq_lock);
    rv = seq;
    seq++;
    if (seq_lock)
	ipmi_os_handler->unlock(ipmi_os_handler, seq_lock);

    return rv;
}

void
ipmi_event_state_init(ipmi_event_state_t *events)
{
    events->status = 0;
    events->__assertion_events = 0;
    events->__deassertion_events = 0;
}

void
ipmi_threshold_event_clear(ipmi_event_state_t          *events,
			   enum ipmi_thresh_e          type,
			   enum ipmi_event_value_dir_e value_dir,
			   enum ipmi_event_dir_e       dir)
{
    if (dir == IPMI_ASSERTION) {
	events->__assertion_events &= ~(1 << (type*2+value_dir));
    } else {
	events->__deassertion_events &= ~(1 << (type*2+value_dir));
    }
}

void
ipmi_threshold_event_set(ipmi_event_state_t          *events,
			 enum ipmi_thresh_e          type,
			 enum ipmi_event_value_dir_e value_dir,
			 enum ipmi_event_dir_e       dir)
{
    if (dir == IPMI_ASSERTION) {
	events->__assertion_events |= 1 << (type*2+value_dir);
    } else {
	events->__deassertion_events |= 1 << (type*2+value_dir);
    }
}

int
ipmi_is_threshold_event_set(ipmi_event_state_t          *events,
			    enum ipmi_thresh_e          type,
			    enum ipmi_event_value_dir_e value_dir,
			    enum ipmi_event_dir_e       dir)
{
    if (dir == IPMI_ASSERTION) {
	return (events->__assertion_events & (1 << (type*2+value_dir))) != 0;
    } else {
	return (events->__deassertion_events & (1 << (type*2+value_dir))) != 0;
    }
}

void
ipmi_discrete_event_clear(ipmi_event_state_t    *events,
			  int                   event_offset,
			  enum ipmi_event_dir_e dir)
{
    if (dir == IPMI_ASSERTION) {
	events->__assertion_events &= ~(1 << event_offset);
    } else {
	events->__deassertion_events &= ~(1 << event_offset);
    }
}

void
ipmi_discrete_event_set(ipmi_event_state_t    *events,
			int                   event_offset,
			enum ipmi_event_dir_e dir)
{
    if (dir == IPMI_ASSERTION) {
	events->__assertion_events |= 1 << event_offset;
    } else {
	events->__deassertion_events |= 1 << event_offset;
    }
}

int
ipmi_is_discrete_event_set(ipmi_event_state_t    *events,
			   int                   event_offset,
			   enum ipmi_event_dir_e dir)
{
    if (dir == IPMI_ASSERTION) {
	return (events->__assertion_events & (1 << event_offset)) != 0;
    } else {
	return (events->__deassertion_events & (1 << event_offset)) != 0;
    }
}

#define IPMI_SENSOR_EVENTS_ENABLED	0x80
#define IPMI_SENSOR_SCANNING_ENABLED	0x40
#define IPMI_SENSOR_BUSY		0x20

unsigned int ipmi_event_state_size(void)
{
    return sizeof(ipmi_event_state_t);
}

void
ipmi_copy_event_state(ipmi_event_state_t *dest, ipmi_event_state_t *src)
{
    *dest = *src;
}

void
ipmi_event_state_set_events_enabled(ipmi_event_state_t *events, int val)
{
    if (val)
	events->status |= IPMI_SENSOR_EVENTS_ENABLED;
    else
	events->status &= ~IPMI_SENSOR_EVENTS_ENABLED;
}

int
ipmi_event_state_get_events_enabled(ipmi_event_state_t *events)
{
    return (events->status >> 7) & 1;
}

void
ipmi_event_state_set_scanning_enabled(ipmi_event_state_t *events, int val)
{
    if (val)
	events->status |= IPMI_SENSOR_SCANNING_ENABLED;
    else
	events->status &= ~IPMI_SENSOR_SCANNING_ENABLED;
}

int
ipmi_event_state_get_scanning_enabled(ipmi_event_state_t *events)
{
    return (events->status >> 6) & 1;
}

void
ipmi_event_state_set_busy(ipmi_event_state_t *events, int val)
{
    if (val)
	events->status |= IPMI_SENSOR_BUSY;
    else
	events->status &= ~IPMI_SENSOR_BUSY;
}

int
ipmi_event_state_get_busy(ipmi_event_state_t *events)
{
    return (events->status >> 5) & 1;
}

unsigned int ipmi_thresholds_size(void)
{
    return sizeof(ipmi_thresholds_t);
}

void
ipmi_copy_thresholds(ipmi_thresholds_t *dest, ipmi_thresholds_t *src)
{
    *dest = *src;
}

int ipmi_thresholds_init(ipmi_thresholds_t *th)
{
    int i;
    for (i=0; i<6; i++)
	th->vals[i].status = 0;
    return 0;
}

int ipmi_threshold_set(ipmi_thresholds_t  *th,
		       ipmi_sensor_t      *sensor,
		       enum ipmi_thresh_e threshold,
		       double             value)
{
    int rv = 0;

    if (threshold > IPMI_UPPER_NON_RECOVERABLE)
	return EINVAL;

    if (sensor) {
	int val;
	rv = ipmi_sensor_threshold_settable(sensor, threshold, &val);
	if (rv)
	    return rv;
	if (!val)
	    return ENOTSUP;
    }

    th->vals[threshold].status = 1;
    th->vals[threshold].val = value;
    return 0;
}

int ipmi_threshold_get(ipmi_thresholds_t  *th,
		       enum ipmi_thresh_e threshold,
		       double             *value)
{
    if (threshold > IPMI_UPPER_NON_RECOVERABLE)
	return EINVAL;

    if (th->vals[threshold].status) {
	*value = th->vals[threshold].val;
	return 0;
    } else {
	return ENOTSUP;
    }
}

unsigned int ipmi_states_size(void)
{
    return sizeof(ipmi_states_t);
}

void
ipmi_copy_states(ipmi_states_t *dest, ipmi_states_t *src)
{
    *dest = *src;
}

void
ipmi_init_states(ipmi_states_t *states)
{
    states->__event_messages_enabled = 0;
    states->__sensor_scanning_enabled = 0;
    states->__initial_update_in_progress = 0;
    states->__states = 0;
}

int
ipmi_is_event_messages_enabled(ipmi_states_t *states)
{
    return states->__event_messages_enabled;
}

void
ipmi_set_event_messages_enabled(ipmi_states_t *states, int val)
{
    states->__event_messages_enabled = val;
}

int
ipmi_is_sensor_scanning_enabled(ipmi_states_t *states)
{
    return states->__sensor_scanning_enabled;
}

void
ipmi_set_sensor_scanning_enabled(ipmi_states_t *states, int val)
{
    states->__sensor_scanning_enabled = val;
}

int
ipmi_is_initial_update_in_progress(ipmi_states_t *states)
{
    return states->__initial_update_in_progress;
}

void
ipmi_set_initial_update_in_progress(ipmi_states_t *states, int val)
{
    states->__initial_update_in_progress = val;
}

int
ipmi_is_state_set(ipmi_states_t *states,
		  int           state_num)
{
    return (states->__states & (1 << state_num)) != 0;
}

void
ipmi_set_state(ipmi_states_t *states,
	       int           state_num,
	       int           val)
{
    if (val)
	states->__states |= 1 << state_num;
    else
	states->__states &= ~(1 << state_num);
}

int
ipmi_is_threshold_out_of_range(ipmi_states_t      *states,
			       enum ipmi_thresh_e thresh)
{
    return (states->__states & (1 << thresh)) != 0;
}

void
ipmi_set_threshold_out_of_range(ipmi_states_t      *states,
				enum ipmi_thresh_e thresh,
				int                val)
{
    if (val)
	states->__states |= 1 << thresh;
    else
	states->__states &= ~(1 << thresh);
}

#ifdef IPMI_CHECK_LOCKS
/* Set a breakpoint here to detect locking errors. */
void
ipmi_report_lock_error(os_handler_t *handler, char *str)
{
    handler->log(handler, IPMI_LOG_WARNING, "%s", str);
}

void
ipmi_check_lock(ipmi_lock_t *lock, char *str)
{
    if ((!DEBUG_LOCKS) || (!lock) || (!lock->ll_lock))
	return;

    if (! lock->os_hnd->is_locked(lock->os_hnd, lock->ll_lock))
	IPMI_REPORT_LOCK_ERROR(lock->os_hnd, str);
}
#endif

void ipmi_oem_force_conn_init(void);
int ipmi_oem_motorola_mxp_init(void);

int
ipmi_init(os_handler_t *handler)
{
    int rv;

    rv = _ipmi_conn_init();
    if (rv)
	return rv;

    if (handler->create_rwlock) {
	rv = handler->create_rwlock(handler, &global_lock);
	if (rv)
	    return rv;
    } else {
	global_lock = NULL;
    }

    if (handler->create_lock) {
	rv = handler->create_lock(handler, &seq_lock);
	if (rv)
	    goto out_err;
    } else {
	seq_lock = NULL;
    }
    ipmi_os_handler = handler;
    _ipmi_domain_init();
    _ipmi_mc_init();

    /* Call the OEM handlers. */
    ipmi_oem_force_conn_init();
    ipmi_oem_motorola_mxp_init();

    return 0;

 out_err:
    if (global_lock)
	handler->destroy_rwlock(ipmi_os_handler, global_lock);
    if (seq_lock)
	handler->destroy_lock(ipmi_os_handler, seq_lock);
    return rv;
}

void
ipmi_shutdown(void)
{
    _ipmi_conn_shutdown();
    _ipmi_domain_shutdown();
    _ipmi_mc_shutdown();
    if (global_lock)
	ipmi_os_handler->destroy_rwlock(ipmi_os_handler, global_lock);
    if (seq_lock)
	ipmi_os_handler->destroy_lock(ipmi_os_handler, seq_lock);
    global_lock = NULL;
}

char *
ipmi_strdup(char *str)
{
    char *rv = ipmi_mem_alloc(strlen(str)+1);

    if (!rv)
	return NULL;

    strcpy(rv, str);
    return rv;
}

enum con_type_e { SMI, LAN, MXP };

struct ipmi_args_s
{
    enum con_type_e con_type;

    int             smi_intf;

    char            *str_addr[2];
    char            *str_port[2];
    int             num_addr;
    int             authtype;
    int             privilege;
    char            username[17];
    char            password[17];

    unsigned char   swid;
    struct in_addr  lan_addr[2];
    int             lan_port[2];
};

#define CHECK_ARG \
    do { \
        if (*curr_arg >= arg_count) { \
	    rv = EINVAL; \
	    goto out_err; \
        } \
    } while(0)

int
ipmi_parse_args(int *curr_arg, int arg_count, char *args[],
		ipmi_args_t **iargs)
{
    ipmi_args_t *p;
    int rv;
    
    p = ipmi_mem_alloc(sizeof(*p));
    if (!p)
	return ENOMEM;
    memset(p, 0, sizeof(*p));

    CHECK_ARG;

    if (strcmp(args[*curr_arg], "smi") == 0) {
	(*curr_arg)++; CHECK_ARG;

	p->con_type = SMI;

	p->smi_intf = atoi(args[*curr_arg]);
	(*curr_arg)++;
    } else if (strcmp(args[*curr_arg], "lan") == 0) {
	(*curr_arg)++; CHECK_ARG;

	p->con_type = LAN;
	p->num_addr = 1;

	p->str_addr[0] = ipmi_strdup(args[*curr_arg]);
	if (p->str_addr[0] == NULL) {
	    rv = ENOMEM;
	    goto out_err;
	}
	(*curr_arg)++; CHECK_ARG;
	p->str_port[0] = ipmi_strdup(args[*curr_arg]);
	if (p->str_port[0] == NULL) {
	    rv = ENOMEM;
	    goto out_err;
	}
	(*curr_arg)++; CHECK_ARG;

    doauth:
	if (strcmp(args[*curr_arg], "none") == 0) {
	    p->authtype = IPMI_AUTHTYPE_NONE;
	} else if (strcmp(args[*curr_arg], "md2") == 0) {
	    p->authtype = IPMI_AUTHTYPE_MD2;
	} else if (strcmp(args[*curr_arg], "md5") == 0) {
	    p->authtype = IPMI_AUTHTYPE_MD5;
	} else if (strcmp(args[*curr_arg], "straight") == 0) {
	    p->authtype = IPMI_AUTHTYPE_STRAIGHT;
	} else if (p->num_addr == 1) {
	    p->num_addr++;
	    p->str_addr[1] = ipmi_strdup(args[*curr_arg]);
	    if (p->str_addr[1] == NULL) {
		rv = ENOMEM;
		goto out_err;
	    }
	    (*curr_arg)++; CHECK_ARG;
	    p->str_port[1] = ipmi_strdup(args[*curr_arg]);
	    if (p->str_port[1] == NULL) {
		rv = ENOMEM;
		goto out_err;
	    }
	    (*curr_arg)++; CHECK_ARG;
	    goto doauth;
	} else {
	    rv = EINVAL;
	    goto out_err;
	}
	(*curr_arg)++; CHECK_ARG;

	if (strcmp(args[*curr_arg], "callback") == 0) {
	    p->privilege = IPMI_PRIVILEGE_CALLBACK;
	} else if (strcmp(args[*curr_arg], "user") == 0) {
	    p->privilege = IPMI_PRIVILEGE_USER;
	} else if (strcmp(args[*curr_arg], "operator") == 0) {
	    p->privilege = IPMI_PRIVILEGE_OPERATOR;
	} else if (strcmp(args[*curr_arg], "admin") == 0) {
	    p->privilege = IPMI_PRIVILEGE_ADMIN;
	} else if (strcmp(args[*curr_arg], "oem") == 0) {
	    p->privilege = IPMI_PRIVILEGE_OEM;
	} else {
	    rv = EINVAL;
	    goto out_err;
	}
	(*curr_arg)++; CHECK_ARG;

	memset(p->username, 0, sizeof(p->username));
	memset(p->password, 0, sizeof(p->password));
	strncpy(p->username, args[*curr_arg], 16);
	p->username[16] = '\0';
	(*curr_arg)++; CHECK_ARG;
	strncpy(p->password, args[*curr_arg], 16);
	p->password[16] = '\0';
	(*curr_arg)++;
    } else if (strcmp(args[*curr_arg], "mxp") == 0) {
	struct hostent *ent;

	(*curr_arg)++; CHECK_ARG;

	p->con_type = MXP;
	p->num_addr = 1;

	ent = gethostbyname(args[*curr_arg]);
	if (!ent) {
	    rv = h_errno;
	    goto out_err;
	}
	memcpy(&p->lan_addr[0],
	       ent->h_addr_list[0],
	       ent->h_length);
	(*curr_arg)++; CHECK_ARG;
	p->lan_port[0] = atoi(args[*curr_arg]);
	(*curr_arg)++; CHECK_ARG;

    doauth_mxp:
	if (strcmp(args[*curr_arg], "none") == 0) {
	    p->authtype = IPMI_AUTHTYPE_NONE;
	} else if (strcmp(args[*curr_arg], "md2") == 0) {
	    p->authtype = IPMI_AUTHTYPE_MD2;
	} else if (strcmp(args[*curr_arg], "md5") == 0) {
	    p->authtype = IPMI_AUTHTYPE_MD5;
	} else if (strcmp(args[*curr_arg], "straight") == 0) {
	    p->authtype = IPMI_AUTHTYPE_STRAIGHT;
	} else if (p->num_addr == 1) {
	    p->num_addr++;
	    ent = gethostbyname(args[*curr_arg]);
	    if (!ent) {
		rv = h_errno;
		goto out_err;
	    }
	    memcpy(&p->lan_addr[1],
		   ent->h_addr_list[0],
		   ent->h_length);
	    (*curr_arg)++; CHECK_ARG;
	    p->lan_port[1] = atoi(args[*curr_arg]);
	    (*curr_arg)++; CHECK_ARG;

	    goto doauth_mxp;
	} else {
	    rv = EINVAL;
	    goto out_err;
	}
	(*curr_arg)++; CHECK_ARG;

	if (strcmp(args[*curr_arg], "callback") == 0) {
	    p->privilege = IPMI_PRIVILEGE_CALLBACK;
	} else if (strcmp(args[*curr_arg], "user") == 0) {
	    p->privilege = IPMI_PRIVILEGE_USER;
	} else if (strcmp(args[*curr_arg], "operator") == 0) {
	    p->privilege = IPMI_PRIVILEGE_OPERATOR;
	} else if (strcmp(args[*curr_arg], "admin") == 0) {
	    p->privilege = IPMI_PRIVILEGE_ADMIN;
	} else if (strcmp(args[*curr_arg], "oem") == 0) {
	    p->privilege = IPMI_PRIVILEGE_OEM;
	} else {
	    rv = EINVAL;
	    goto out_err;
	}
	(*curr_arg)++; CHECK_ARG;

	memset(p->username, 0, sizeof(p->username));
	memset(p->password, 0, sizeof(p->password));
	strncpy(p->username, args[*curr_arg], 16);
	p->username[16] = '\0';
	(*curr_arg)++; CHECK_ARG;
	strncpy(p->password, args[*curr_arg], 16);
	p->password[16] = '\0';
	(*curr_arg)++; CHECK_ARG;

	p->swid = strtoul(args[*curr_arg], NULL, 0);
	(*curr_arg)++;
    } else {
	rv = EINVAL;
	goto out_err;
    }

    *iargs = p;
    return 0;

 out_err:
    ipmi_free_args(p);
    return rv;
}

void
ipmi_free_args(ipmi_args_t *args)
{
    if (args->str_addr[0])
	ipmi_mem_free(args->str_addr[0]);
    if (args->str_addr[1])
	ipmi_mem_free(args->str_addr[1]);
    if (args->str_port[0])
	ipmi_mem_free(args->str_port[0]);
    if (args->str_port[1])
	ipmi_mem_free(args->str_port[1]);
    ipmi_mem_free(args);
}

int
ipmi_args_setup_con(ipmi_args_t  *args,
		    os_handler_t *handlers,
		    void         *user_data,
		    ipmi_con_t   **con)
{
    switch(args->con_type) {
    case SMI:
	return ipmi_smi_setup_con(args->smi_intf, handlers, user_data, con);

    case LAN:
	return ipmi_ip_setup_con(args->str_addr,
				 args->str_port,
				 args->num_addr,
				 args->authtype,
				 args->privilege,
				 args->username,
				 strlen(args->username),
				 args->password,
				 strlen(args->password),
				 handlers, user_data,
				 con);

    case MXP:
	return mxp_lan_setup_con(args->lan_addr,
				 args->lan_port,
				 args->num_addr,
				 args->authtype,
				 args->privilege,
				 args->username,
				 strlen(args->username),
				 args->password,
				 strlen(args->password),
				 handlers, user_data,
				 args->swid,
				 con);

    default:
	return EINVAL;
    }
}
