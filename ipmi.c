/*
 * ipmi.c
 *
 * MontaVista IPMI generic code
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

#include <malloc.h>
#include <string.h>

#include <ipmi/os_handler.h>
#include <ipmi/ipmi_mc.h>
#include <ipmi/ipmi_int.h>
#include <ipmi/ipmi_conn.h>
#include <ipmi/ipmi_auth.h>
#include <ipmi/ipmi_err.h>
#include "md2.h"
#include "md5.h"

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

    lock = malloc(sizeof(*lock));
    if (!lock)
	return ENOMEM;

    lock->os_hnd = os_hnd;
    if (lock->os_hnd->create_lock) {
	rv = lock->os_hnd->create_lock(lock->os_hnd, &(lock->ll_lock));
	if (rv) {
	    free(lock);
	    return rv;
	}
    } else {
	lock->ll_lock = NULL;
    }

    *new_lock = lock;

    return 0;
}

int
ipmi_create_lock(ipmi_mc_t *mc, ipmi_lock_t **new_lock)
{
    return ipmi_create_lock_os_hnd(ipmi_mc_get_os_hnd(mc), new_lock);
}

void ipmi_destroy_lock(ipmi_lock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->destroy_lock(lock->os_hnd, lock->ll_lock);
    free(lock);
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
ipmi_log(char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    ipmi_os_handler->vlog(ipmi_os_handler, format, ap);
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

static void
ipmi_get_unicode(int len,
		 unsigned char *d, int in_len,
		 char *out, int out_len)
{
    /* FIXME - no unicode handling. */
    *out = '\0';
}

static void
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
    *out = '\0';
}

static void
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
    *out = '\0';
}

static void
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
    *out = '\0';
};

void
ipmi_get_device_string(unsigned char *input,
		       int           in_len,
		       char          *output,
		       int           max_out_len)
{
    int type;
    int len;

    if (max_out_len <= 0)
	return;

    if (in_len < 2) {
	*output = '\0';
	return;
    }

    /* Remove the nil from the length. */
    max_out_len--;

    type = (*input >> 6) & 3;
    len = *input & 0x1f;
    input++;
    in_len--;
    switch (type)
    {
	case 0: /* Unicode */
	    ipmi_get_unicode(len, input, in_len, output, max_out_len);
	    break;
	case 1: /* BCD Plus */
	    ipmi_get_bcd_plus(len, input, in_len, output, max_out_len);
	    break;
	case 2: /* 6-bit ASCII */
	    ipmi_get_6_bit_ascii(len, input, in_len, output, max_out_len);
	    break;
	case 3: /* 8-bit ASCII */
	    ipmi_get_8_bit_ascii(len, input, in_len, output, max_out_len);
	    break;
    }
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

void
ipmi_set_device_string(char          *input,
		       unsigned char *output,
		       int           *out_len)
{
    char *s = input+1;
    int  bsize = 0; /* Start with 4-bit. */

    /* Max size is 30. */
    if (*out_len > 30)
	*out_len = 30;

    while (*s != '\0') {
	if ((bsize == 0) && (table_4_bit[(int) *s] == 0))
	    bsize = 1;
	if ((bsize == 1) && (table_6_bit[(int) *s] == 0)) {
	    bsize = 2;
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
	/* 8-bit ASCII is required. */
	ipmi_set_8_bit_ascii(input, output, out_len);
    }
}

static int
pw_authcode_init(unsigned char *password, ipmi_authdata_t *handle)
{
    unsigned char *data;

    data = malloc(16);
    if (!data)
	return ENOMEM;

    memcpy(data, password, 16);
    *handle = (ipmi_authdata_t) data;
    return 0;
}

static int
pw_authcode_gen(ipmi_authdata_t handle, ipmi_auth_sg_t data[], void *output)
{
    memcpy(output, handle, 16);
    return 0;
}

static int
pw_authcode_check(ipmi_authdata_t handle, ipmi_auth_sg_t data[], void *code)
{
    if (strncmp((unsigned char *) handle, code, 16) != 0)
	return EINVAL;
    return 0;
}

static void
pw_authcode_cleanup(ipmi_authdata_t handle)
{
    free(handle);
}

static int
no_authcode_init(unsigned char *password, ipmi_authdata_t *handle)
{
    return 0;
}

static int
no_authcode_gen(ipmi_authdata_t handle, ipmi_auth_sg_t data[], void *output)
{
    memset(output, 0, 16);
    return 0;
}

static int
no_authcode_check(ipmi_authdata_t handle, ipmi_auth_sg_t data[], void *code)
{
    return 0;
}

static void
no_authcode_cleanup(ipmi_authdata_t handle)
{
}


ipmi_auth_t ipmi_auths[MAX_IPMI_AUTHS] =
{
    { no_authcode_init,  no_authcode_gen,
      no_authcode_check, no_authcode_cleanup },
    { ipmi_md2_authcode_init,  ipmi_md2_authcode_gen,
      ipmi_md2_authcode_check, ipmi_md2_authcode_cleanup },
    { ipmi_md5_authcode_init,  ipmi_md5_authcode_gen,
      ipmi_md5_authcode_check, ipmi_md5_authcode_cleanup },
    { NULL, NULL, NULL, NULL },
    { pw_authcode_init,  pw_authcode_gen,
      pw_authcode_check, pw_authcode_cleanup },
    { NULL, NULL, NULL, NULL },
};

int
ipmi_init(os_handler_t *handler)
{
    int rv;

    if (handler->create_rwlock) {
	rv = handler->create_rwlock(handler, &global_lock);
	if (rv)
	    return rv;
    } else {
	global_lock = NULL;
    }
    ipmi_os_handler = handler;
    ipmi_mc_init();
    return 0;
}

int ipmi_addr_equal(ipmi_addr_t *addr1,
		    int         addr1_len,
		    ipmi_addr_t *addr2,
		    int         addr2_len)
{
    if (addr1_len != addr2_len)
	return 0;

    if (addr1->addr_type != addr2->addr_type)
	return 0;

    if (addr1->channel != addr2->channel)
	return 0;

    switch (addr1->addr_type)
    {
	case IPMI_IPMB_ADDR_TYPE:
	{
	    ipmi_ipmb_addr_t *iaddr1 = (ipmi_ipmb_addr_t *) addr1;
	    ipmi_ipmb_addr_t *iaddr2 = (ipmi_ipmb_addr_t *) addr2;

	    return ((iaddr1->slave_addr == iaddr2->slave_addr)
		    && (iaddr1->lun == iaddr2->lun));
	}

	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
	{
	    ipmi_system_interface_addr_t *iaddr1
		= (ipmi_system_interface_addr_t *) addr1;
	    ipmi_system_interface_addr_t *iaddr2
		= (ipmi_system_interface_addr_t *) addr2;
	    return (iaddr1->lun == iaddr2->lun);
	}

	default:
	    return 0;
    }
}

unsigned int ipmi_addr_get_lun(ipmi_addr_t *addr)
{
    switch (addr->addr_type)
    {
	case IPMI_IPMB_ADDR_TYPE:
	{
	    ipmi_ipmb_addr_t *iaddr = (ipmi_ipmb_addr_t *) addr;

	    return iaddr->lun;
	}

	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
	{
	    ipmi_system_interface_addr_t *iaddr
		= (ipmi_system_interface_addr_t *) addr;

	    return iaddr->lun;
	}

	default:
	    return 0;
    }
}

int ipmi_addr_set_lun(ipmi_addr_t *addr, unsigned int lun)
{
    if (lun >= 4)
	return EINVAL;

    switch (addr->addr_type)
    {
	case IPMI_IPMB_ADDR_TYPE:
	{
	    ipmi_ipmb_addr_t *iaddr = (ipmi_ipmb_addr_t *) addr;

	    iaddr->lun = lun;
	    break;
	}

	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
	{
	    ipmi_system_interface_addr_t *iaddr
		= (ipmi_system_interface_addr_t *) addr;

	    iaddr->lun = lun;
	    break;
	}

	default:
	    return EINVAL;
    }

    return 0;
}
