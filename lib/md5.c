/*
 * md5.c
 *
 * MontaVista RMCP+ code for doing MD5 without HMAC.
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

#include <config.h>

/* Not strictly necessary, but ths is pointless if we don't have ssl */
#ifdef HAVE_OPENSSL

#include <errno.h>
#include <string.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/internal/ipmi_malloc.h>

/* We use our own internal vesion of MD5 over openssl's because ours
   does scatter/gather. */
#include <OpenIPMI/internal/md5.h>

typedef struct md5_info_s
{
    ipmi_authdata_t authdata;
} md5_info_t;

static void *
auth_alloc(void *info, int size)
{
    return ipmi_mem_alloc(size);
}

static void
auth_free(void *info, void *data)
{
    ipmi_mem_free(data);
}

static int
md5_init(ipmi_con_t       *ipmi,
	 ipmi_rmcpp_auth_t *ainfo,
	 void              **integ_data)
{
    md5_info_t          *info;
    unsigned int        klen;
    const unsigned char *k;
    int                 rv;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    k = ipmi_rmcpp_auth_get_password(ainfo, &klen);
    if (klen < 20)
	return EINVAL;

    rv = ipmi_md5_authcode_initl(k, 20, &info->authdata, NULL,
				 auth_alloc, auth_free);
    if (rv) {
	ipmi_mem_free(info);
	return rv;
    }

    *integ_data = info;
    return 0;
}

static void
md5_free(ipmi_con_t *ipmi,
	  void       *integ_data)
{
    md5_info_t *info = integ_data;

    ipmi_md5_authcode_cleanup(info->authdata);
    ipmi_mem_free(integ_data);
}

static int
md5_pad(ipmi_con_t    *ipmi,
	void          *integ_data,
	unsigned char *payload,
	unsigned int  *payload_len,
	unsigned int  max_payload_len)
{
    unsigned char  *p = payload;
    unsigned int   l = *payload_len;
    unsigned int   count = 0;

    /* Pad so that when we add two bytes (the pad length and the next
       header) the result is on a multiple of 4 boundary. */
    while (((l+2) % 4) != 0) {
	if (l == max_payload_len)
	    return E2BIG;
	p[l] = 0xff;
	l++;
	count++;
    }

    /* Add the padding length.  The next header gets added later. */
    if (l == max_payload_len)
	return E2BIG;
    p[l] = count;
    l++;

    *payload_len = l;
    return 0;
}

static int
md5_add(ipmi_con_t    *ipmi,
	void          *integ_data,
	unsigned char *payload,
	unsigned int  *payload_len,
	unsigned int  max_payload_len)
{
    md5_info_t     *info = integ_data;
    unsigned char  *p = payload;
    unsigned int   l = *payload_len;
    ipmi_auth_sg_t data[2];
    int            rv;

    if (l+17 > max_payload_len)
	return E2BIG;

    if (l < 4)
	return E2BIG;

    p[l] = 0x07; /* Next header */
    l++;

    data[0].data = p+4;
    data[0].len = l-4;
    data[1].data = NULL;
    rv = ipmi_md5_authcode_gen(info->authdata, data, p+l);
    if (rv)
	return rv;
    l += 16;

    *payload_len = l;
    return 0;
}

static int
md5_check(ipmi_con_t    *ipmi,
	   void          *integ_data,
	   unsigned char *payload,
	   unsigned int  payload_len,
	   unsigned int  total_len)
{
    md5_info_t     *info = integ_data;
    unsigned char  *p = payload;
    unsigned int   l = payload_len;
    ipmi_auth_sg_t data[2];
    int            rv;

    /* We don't authenticate this part of the header. */
    p += 4;
    l -= 4;

    if ((total_len - payload_len) < 17)
	return EINVAL;

    /* We add 1 to the length because we also check the next header
       field. */
    data[0].data = p;
    data[0].len = l+1;
    data[1].data = NULL;
    rv = ipmi_md5_authcode_check(info->authdata, data, p+l+1);
    if (rv)
	return rv;

    return 0;
}

static ipmi_rmcpp_integrity_t md5_integ =
{
    .integ_init = md5_init,
    .integ_free = md5_free,
    .integ_pad = md5_pad,
    .integ_add = md5_add,
    .integ_check = md5_check
};

#endif /* HAVE_OPENSSL */

int
_ipmi_md5_init(void)
{
#ifdef HAVE_OPENSSL
    int rv = 0;

    rv = ipmi_rmcpp_register_integrity
	(IPMI_LANP_INTEGRITY_ALGORITHM_MD5_128, &md5_integ);
    if (rv)
	return rv;
#endif

    return 0;
}

void
_ipmi_md5_shutdown(void)
{
#ifdef HAVE_OPENSSL
    ipmi_rmcpp_register_integrity
	(IPMI_LANP_INTEGRITY_ALGORITHM_MD5_128, NULL);
#endif
}
