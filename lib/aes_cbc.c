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

static void
dump_data(const unsigned char *d, int l, const char *n)
{
    int i;
    printf("%s:", n);
    for (i=0; i<l; i++) {
	if ((i%16) == 0)
	    printf("\n ");
	printf(" %2.2x", d[i]);
    }
    printf("\n");
}


static int
aes_cbc_encrypt(ipmi_con_t    *ipmi,
		void          *conf_data,
		unsigned char **payload,
		unsigned int  *header_len,
		unsigned int  *payload_len,
		unsigned int  *max_payload_len)
{
    aes_cbc_info_t *info = conf_data;
    unsigned char  *iv;
    unsigned int   l = *payload_len;
    unsigned int   e;
    unsigned char  *d;
    EVP_CIPHER_CTX ctx;
    int            rv;
    unsigned int   outlen;
    unsigned int   tmplen;

    if (*header_len < 16)
	return E2BIG;

    /* Calculate the number of padding bytes -> e.  Note that the pad
       length byte is included, thus the +1.  We assume AES does the
       padding, but we need to know how much. */
    e = 16 -((l+1) % 16);
    if (e == 16)
	e = 0;
    l += e+1;
    if (l > *max_payload_len)
	return E2BIG;

    /* We store the unencrypted data here, then crypt into the real
       data. */
    d = ipmi_mem_alloc(*payload_len);
    if (!d)
	return ENOMEM;
    iv = (*payload)-16;

    rv = ipmi->os_hnd->get_random(ipmi->os_hnd, iv, 16);
    if (rv) {
	ipmi_mem_free(d);
	return rv;
    }

    memcpy(d, *payload, *payload_len);

    /* Make room for the initialization vector. */
    *header_len -= 16;
    *max_payload_len += 16;

    /* Ok, we're set to do the crypt operation. */
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, info->k2, iv);
    if (!EVP_EncryptUpdate(&ctx, *payload, &outlen, d, *payload_len)) {
	ipmi_mem_free(d);
	return ENOMEM; /* right? */
    }
    if (!EVP_EncryptFinal(&ctx, (*payload)+outlen, &tmplen)) {
	free(d);
	return ENOMEM; /* right? */
    }
    outlen += tmplen;

    *payload = iv;
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
    unsigned int   l = *payload_len;
    unsigned char  *d;
    unsigned char  *p;
    EVP_CIPHER_CTX ctx;
    unsigned int   outlen;
    unsigned int   tmplen;

    if (l < 32)
	/* Not possible with this algorithm. */
	return EINVAL;

    l -= 16;
    /* We store the encrypted data here, then decrypt into the real
       data. */
    d = ipmi_mem_alloc(l);
    if (!d)
	return ENOMEM;

    p = (*payload)+16;

    memcpy(d, p, l);

    /* Ok, we're set to do the decrypt operation. */
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, info->k2, *payload);
    if (!EVP_DecryptUpdate(&ctx, p, &outlen, d, l)) {
	ipmi_mem_free(d);
	return ENOMEM; /* right? */
    }
    if (!EVP_DecryptFinal(&ctx, p+outlen, &tmplen)) {
	ipmi_mem_free(d);
	return ENOMEM; /* right? */
    }
    outlen += tmplen;

    *payload = p;
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
