/*
 * aes_cbc.c
 *
 * MontaVista RMCP+ code for doing AES-CBC-128
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

#ifdef HAVE_OPENSSL

#include <errno.h>
#include <string.h>
#include <openssl/evp.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/internal/ipmi_malloc.h>

typedef struct aes_cbc_info_s
{
    unsigned char k2[16];
} aes_cbc_info_t;

static int
aes_cbc_init(ipmi_con_t *ipmi, ipmi_rmcpp_auth_t *ainfo, void **conf_data)
{
    aes_cbc_info_t *info;
    unsigned int   k2len;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    if (ipmi_rmcpp_auth_get_k2_len(ainfo) < 16)
	return EINVAL;
    
    memcpy(info->k2, ipmi_rmcpp_auth_get_k2(ainfo, &k2len), 16);
    *conf_data = info;
    return 0;
}

static void
aes_cbc_free(ipmi_con_t *ipmi, void *conf_data)
{
    aes_cbc_info_t *info = conf_data;

    memset(info->k2, 0, 16);
    ipmi_mem_free(info);
}

static int
aes_cbc_encrypt(ipmi_con_t    *ipmi,
		void          *conf_data,
		unsigned char **payload,
		unsigned int  *header_len,
		unsigned int  *payload_len,
		unsigned int  max_payload_len)
{
    aes_cbc_info_t *info = conf_data;
    unsigned char  *p;
    unsigned int   l = *payload_len;
    unsigned int   e;
    int            i;
    unsigned char  *d;
    EVP_CIPHER_CTX ctx;
    unsigned int   tmplen;
    int            rv;
    unsigned int   outlen;

    if (*header_len < 16)
	return E2BIG;

    /* Calculate the number of padding bytes -> e.  Note that the pad
       length byte is included, thus the +1. */
    e = 16 -((l+1) % 16);
    if (e == 16)
	e = 0;
    l += e+1;
    if (l > max_payload_len)
	return E2BIG;

    /* We store the unencrypted data here, then crypt into the real
       data. */
    d = ipmi_mem_alloc(l+16);
    if (!d)
	return ENOMEM;

    rv = ipmi->os_hnd->get_random(ipmi->os_hnd, d, 16);
    if (rv) {
	ipmi_mem_free(d);
	return rv;
    }

    memcpy(d+16, *payload, *payload_len);

    /* Add the padding bytes. */
    p = d + *payload_len + 16;
    for (i=0; i<e; i++, p++)
	*p = i;
    *p = e; /* length byte */
    *payload_len += e + 1;

    /* Ok, we're set to do the crypt operation. */
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, info->k2, d);
    if (!EVP_EncryptUpdate(&ctx, *payload, &outlen, d+16, l)) {
	ipmi_mem_free(d);
	return ENOMEM; /* right? */
    }

    if (!EVP_EncryptFinal_ex(&ctx, (*payload)+outlen, &tmplen)) {
	ipmi_mem_free(d);
	return ENOMEM; /* right? */
    }

    outlen += tmplen;

    *payload -= 16;
    memcpy(*payload, d, 16);
    *payload_len = outlen + 16;
    ipmi_mem_free(d);
    return 0;
}

static int
aes_cbc_decrypt(ipmi_con_t    *ipmi,
		void          *conf_data,
		unsigned char **payload,
		unsigned int  *payload_len)
{
    aes_cbc_info_t *info = conf_data;
    unsigned char  *p;
    unsigned int   l = *payload_len;
    unsigned char  *d;
    EVP_CIPHER_CTX ctx;
    unsigned int   tmplen;
    unsigned int   outlen;

    l = *payload_len;
    if (l < 32)
	/* Not possible with this algorithm. */
	return EINVAL;

    l -= 16;
    /* We store the encrypted data here, then decrypt into the real
       data. */
    d = ipmi_mem_alloc(l);
    if (!d)
	return ENOMEM;

    p = *payload;
    p += 16;

    memcpy(d, p, l);

    /* Ok, we're set to do the decrypt operation. */
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, info->k2, *payload);
    if (!EVP_DecryptUpdate(&ctx, p, &outlen, d, l)) {
	ipmi_mem_free(d);
	return ENOMEM; /* right? */
    }

    if (!EVP_DecryptFinal_ex(&ctx, p+outlen, &tmplen)) {
	ipmi_mem_free(d);
	return ENOMEM; /* right? */
    }

    outlen += tmplen;
    if (outlen < 16)
	return EINVAL;

    if (p[outlen-1] > 15)
	return EINVAL;

    outlen -= p[outlen-1];

    *payload += 16;
    *payload_len = outlen;
    ipmi_mem_free(d);
    return 0;
}

static ipmi_rmcpp_confidentiality_t aes_conf =
{
    .conf_init = aes_cbc_init,
    .conf_free = aes_cbc_free,
    .conf_encrypt = aes_cbc_encrypt,
    .conf_decrypt = aes_cbc_decrypt
};

#endif /* HAVE_OPENSSL */

int
_ipmi_aes_cbc_init(void)
{
#ifdef HAVE_OPENSSL
    int rv = 0;

    rv = ipmi_rmcpp_register_confidentiality
	(IPMI_LANP_CONFIDENTIALITY_ALGORITHM_AES_CBC_128, &aes_conf);
    if (rv)
	return rv;
#endif

    return 0;
}
