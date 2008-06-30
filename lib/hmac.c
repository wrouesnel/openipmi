/*
 * hmac.c
 *
 * MontaVista RMCP+ code for doing HMAC, both SHA1 and MD5
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

#ifdef HAVE_OPENSSL

#include <errno.h>
#include <string.h>
#include <openssl/hmac.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/internal/ipmi_malloc.h>

typedef struct hmac_info_s
{
    const EVP_MD *evp_md;
    unsigned int  klen;
    unsigned int  ilen;
    unsigned char k[20];
} hmac_info_t;

static int
hmac_sha1_init(ipmi_con_t       *ipmi,
	       ipmi_rmcpp_auth_t *ainfo,
	       void             **integ_data)
{
    hmac_info_t         *info;
    const unsigned char *k;
    unsigned int        klen;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    if (ipmi_rmcpp_auth_get_sik_len(ainfo) < 20)
	return EINVAL;

    if (ipmi->hacks & IPMI_CONN_HACK_RMCPP_INTEG_SIK)
	k = ipmi_rmcpp_auth_get_sik(ainfo, &klen);
    else
	k = ipmi_rmcpp_auth_get_k1(ainfo, &klen);
    if (klen < 20)
	return EINVAL;

    memcpy(info->k, k, 20);
    info->klen = 20;
    info->ilen = 12;

    info->evp_md = EVP_sha1();
    *integ_data = info;
    return 0;
}

static int
hmac_md5_init(ipmi_con_t       *ipmi,
	      ipmi_rmcpp_auth_t *ainfo,
	      void             **integ_data)
{
    hmac_info_t         *info;
    const unsigned char *k;
    unsigned int        klen;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    if (ipmi_rmcpp_auth_get_sik_len(ainfo) < 16)
	return EINVAL;

    k = ipmi_rmcpp_auth_get_sik(ainfo, &klen);
    if (klen < 16)
	return EINVAL;

    memcpy(info->k, k, 16);
    info->klen = 16;
    info->ilen = 16;

    info->evp_md = EVP_md5();
    *integ_data = info;
    return 0;
}

static void
hmac_free(ipmi_con_t *ipmi,
	  void       *integ_data)
{
    hmac_info_t *info = integ_data;

    memset(info->k, 0, sizeof(info->k));
    ipmi_mem_free(integ_data);
}

static int
hmac_pad(ipmi_con_t    *ipmi,
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
hmac_add(ipmi_con_t    *ipmi,
	 void          *integ_data,
	 unsigned char *payload,
	 unsigned int  *payload_len,
	 unsigned int  max_payload_len)
{
    hmac_info_t   *info = integ_data;
    unsigned char *p = payload;
    unsigned int  l = *payload_len;
    unsigned int  ilen;
    unsigned char integ[20];

    if (l+info->ilen+1 > max_payload_len)
	return E2BIG;

    if (l < 4)
	return E2BIG;

    p[l] = 0x07; /* Add the next header */
    l++;

    HMAC(info->evp_md, info->k, info->klen, p+4, l-4, integ, &ilen);
    memcpy(p+l, integ, ilen);
    l += info->ilen;

    *payload_len = l;
    return 0;
}

static int
hmac_check(ipmi_con_t    *ipmi,
	   void          *integ_data,
	   unsigned char *payload,
	   unsigned int  payload_len,
	   unsigned int  total_len)
{
    hmac_info_t   *info = integ_data;
    unsigned char *p = payload;
    unsigned int  l = payload_len;
    unsigned int  ilen;
    unsigned char new_integ[20];

    /* We don't authenticate this part of the header. */
    p += 4;
    l -= 4;

    if ((total_len - payload_len) < info->ilen+1)
	return EINVAL;

    /* We add 1 to the length because we also check the next header
       field. */
    HMAC(info->evp_md, info->k, info->klen, p, l+1, new_integ, &ilen);
    if (memcmp(new_integ, p+l+1, info->ilen) != 0)
	return EINVAL;

    return 0;
}

static ipmi_rmcpp_integrity_t hmac_sha1_integ =
{
    .integ_init = hmac_sha1_init,
    .integ_free = hmac_free,
    .integ_pad = hmac_pad,
    .integ_add = hmac_add,
    .integ_check = hmac_check
};

static ipmi_rmcpp_integrity_t hmac_md5_integ =
{
    .integ_init = hmac_md5_init,
    .integ_free = hmac_free,
    .integ_pad = hmac_pad,
    .integ_add = hmac_add,
    .integ_check = hmac_check
};
#endif /* HAVE_OPENSSL */

void
_ipmi_hmac_shutdown(void)
{
#ifdef HAVE_OPENSSL
    ipmi_rmcpp_register_integrity
	(IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_SHA1_96, NULL);
    ipmi_rmcpp_register_integrity
	(IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_MD5_128, NULL);
#endif
}

int
_ipmi_hmac_init(void)
{
#ifdef HAVE_OPENSSL
    int rv = 0;

    rv = ipmi_rmcpp_register_integrity
	(IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_SHA1_96, &hmac_sha1_integ);
    if (rv)
	return rv;

    rv = ipmi_rmcpp_register_integrity
	(IPMI_LANP_INTEGRITY_ALGORITHM_HMAC_MD5_128, &hmac_md5_integ);
    if (rv) {
	_ipmi_hmac_shutdown();
	return rv;
    }
#endif

    return 0;
}
