/* md2.c - MD2 Message-Digest Algorithm
 * Copyright (C) 2002,2003 MontaVista Software.
 * Corey Minyard <cminyard@mvista.com>
 *
 * This file is part of the IPMI Interface (IPMIIF).
 *
 * This is the MD2 algorithm, as defined by RFC1319.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * Lesser General Public License (GPL) Version 2 or the modified BSD
 * license below.  The following disclamer applies to both licenses:
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
 * GNU Lesser General Public Licence
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Modified BSD Licence
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *   3. The name of the author may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <OpenIPMI/internal/md2.h>

typedef uint32_t u32;
typedef uint8_t  byte;

typedef struct {
    byte buf[48];
    byte inbuf[16];
    byte checksum[16];
    int  count;
    byte l;
} MD2_CONTEXT;

static void
md2_init( MD2_CONTEXT *ctx )
{
    memset(ctx->buf, 0, 16);
    memset(ctx->checksum, 0, 16);
    ctx->count = 0;
    ctx->l = 0;
}

/* The "Bytes of PI" defined by the algorithm. */
static byte s[256] =
{
   41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161, 236, 240,   6,  19,
   98, 167,   5, 243, 192, 199, 115, 140, 152, 147,  43, 217, 188,  76, 130, 202,
   30, 155,  87,  60, 253, 212, 224,  22, 103,  66, 111,  24, 138,  23, 229,  18,
  190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142, 187,  47, 238, 122,
  169, 104, 121, 145,  21, 178,   7,  63, 148, 194,  16, 137,  11,  34,  95,  33,
  128, 127,  93, 154,  90, 144,  50,  39,  53,  62, 204, 231, 191, 247, 151,   3,
  255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42, 172,  86, 170, 198,
   79, 184,  56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116,   4, 241,
   69, 157, 112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,
   27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126,  15,
   85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197, 234,  38,
   44,  83,  13, 110, 133,  40, 132,  9,  211, 223, 205, 244,  65, 129,  77,  82,
  106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,  12, 189, 177,  74,
  120, 136, 149, 139, 227,  99, 232, 109, 233, 203, 213, 254,  59,   0,  29,  57,
  242, 239, 183,  14, 102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
   49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51, 159,  17, 131,  20
};

static void
checksum( MD2_CONTEXT *ctx )
{
    int j;

    for (j=0; j<16; j++) {
	ctx->checksum[j] ^= s[ctx->inbuf[j] ^ ctx->l];
	ctx->l = ctx->checksum[j];
    }
}

/****************
 * transform 16 bytes
 */
static void
transform( MD2_CONTEXT *ctx )
{
    int j, k;
    int t;

    for (j=0; j<16; j++) {
	ctx->buf[j+16] = ctx->inbuf[j];
	ctx->buf[j+32] = ctx->inbuf[j] ^ ctx->buf[j];
    }

    t = 0;
    for (j=0; j<18; j++) {
	for (k=0; k<48; k++) {
	    t = ctx->buf[k] ^ s[t];
	    ctx->buf[k] = t;
	}
	t = (t + j) % 256;
    }
}


/* The routine updates the message-digest context to
 * account for the presence of each of the characters inBuf[0..inLen-1]
 * in the message whose digest is being computed.
 */
static void
md2_write( MD2_CONTEXT *ctx, byte *inbuf, size_t inlen )
{
    int cnt;

    if( !inbuf )
	return;

    if (ctx->count+inlen > 16)
	cnt = 16-ctx->count;
    else
	cnt = inlen;

    memcpy(ctx->inbuf+ctx->count, inbuf, cnt);
    inbuf += cnt;
    inlen -= cnt;
    ctx->count += cnt;

    while (ctx->count == 16) {
	checksum(ctx);
	transform(ctx);

	if (inlen > 16)
	    cnt = 16;
	else
	    cnt = inlen;

	memcpy(ctx->inbuf, inbuf, cnt);
	inbuf += cnt;
	inlen -= cnt;
	ctx->count = cnt;
    }
}


/* The routine final terminates the message-digest computation and
 * ends with the desired message digest in mdContext->digest[0...15].
 * The handle is prepared for a new MD2 cycle.
 * Returns 16 bytes representing the digest.
 */

static void
md2_final( MD2_CONTEXT *ctx )
{
    int i, cnt;

    cnt = 16 - ctx->count;
    for (i=ctx->count; i<16; i++)
	ctx->inbuf[i] = cnt;

    checksum(ctx);
    transform(ctx);

    memcpy(ctx->inbuf, ctx->checksum, 16);

    transform(ctx);
}

static byte *
md2_read( MD2_CONTEXT *hd )
{
    return hd->buf;
}

struct ipmi_authdata_s
{
    void          *info;
    void          *(*mem_alloc)(void *info, int size);
    void          (*mem_free)(void *info, void *data);
    unsigned char data[16];
};

/* External functions for the IPMI authcode algorithms. */
int
ipmi_md2_authcode_init(unsigned char   *password,
		       ipmi_authdata_t *handle,
		       void            *info,
		       void            *(*mem_alloc)(void *info, int size),
		       void            (*mem_free)(void *info, void *data))
{
    struct ipmi_authdata_s *data;

    data = mem_alloc(info, sizeof(*data));
    if (!data)
	return ENOMEM;

    data->info = info;
    data->mem_alloc = mem_alloc;
    data->mem_free = mem_free;

    memcpy(data->data, password, 16);
    *handle = data;
    return 0;
}

int
ipmi_md2_authcode_gen(ipmi_authdata_t handle,
		      ipmi_auth_sg_t  data[],
		      void            *output)
{
    MD2_CONTEXT ctx;
    int         i;

    md2_init(&ctx);
    md2_write(&ctx, handle->data, 16);
    for (i=0; data[i].data != NULL; i++) {
	md2_write(&ctx, data[i].data, data[i].len);
    }
    md2_write(&ctx, handle->data, 16);
    md2_final(&ctx);
    memcpy(output, md2_read(&ctx), 16);
    return 0;
}

int
ipmi_md2_authcode_check(ipmi_authdata_t handle,
			ipmi_auth_sg_t  data[],
			void            *code)
{
    MD2_CONTEXT ctx;
    int         i;

    md2_init(&ctx);
    md2_write(&ctx, handle->data, 16);
    for (i=0; data[i].data != NULL; i++) {
	md2_write(&ctx, data[i].data, data[i].len);
    }
    md2_write(&ctx, handle->data, 16);
    md2_final(&ctx);
    if (memcmp(code, md2_read(&ctx), 16) != 0)
	return EINVAL;
    return 0;
}

void
ipmi_md2_authcode_cleanup(ipmi_authdata_t handle)
{
    memset(handle->data, 0, sizeof(handle->data));
    handle->mem_free(handle->info, handle);
    handle = NULL;
}

/* The stuff below is libgcrypt-specific, and does not apply to IPMI.  The
   stuff above is generic.  Nice separation, thank you :-).
   -Corey Minyard
*/
#if 0
/****************
 * Return some information about the algorithm.  We need algo here to
 * distinguish different flavors of the algorithm.
 * Returns: A pointer to string describing the algorithm or NULL if
 *	    the ALGO is invalid.
 */
static const char *
md2_get_info( int algo, size_t *contextsize,
	       byte **r_asnoid, int *r_asnlen, int *r_mdlen,
	       void (**r_init)( void *c ),
	       void (**r_write)( void *c, byte *buf, size_t nbytes ),
	       void (**r_final)( void *c ),
	       byte *(**r_read)( void *c )
	     )
{
    static byte asn[18] = /* Object ID is 1.2.840.113549.2.5 */
		    { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,0x48,
		      0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };

    if( algo != 1 )
	return NULL;

    *contextsize = sizeof(MD2_CONTEXT);
    *r_asnoid = asn;
    *r_asnlen = DIM(asn);
    *r_mdlen = 16;
    *(void  (**)(MD2_CONTEXT *))r_init		       = md2_init;
    *(void  (**)(MD2_CONTEXT *, byte*, size_t))r_write = md2_write;
    *(void  (**)(MD2_CONTEXT *))r_final 	       = md2_final;
    *(byte *(**)(MD2_CONTEXT *))r_read		       = md2_read;

    return "MD2";
}


#ifndef IS_MODULE
static
#endif
const char * const gnupgext_version = "MD2 ($Revision: 1.4 $)";

static struct {
    int class;
    int version;
    int  value;
    void (*func)(void);
} func_table[] = {
    { 10, 1, 0, (void(*)(void))md2_get_info },
    { 11, 1, 1 },
};


#ifndef IS_MODULE
static
#endif
void *
gnupgext_enum_func( int what, int *sequence, int *class, int *vers )
{
    void *ret;
    int i = *sequence;

    do {
	if( i >= DIM(func_table) || i < 0 )
	    return NULL;
	*class = func_table[i].class;
	*vers  = func_table[i].version;
	switch( *class ) {
	  case 11: case 21: case 31: ret = &func_table[i].value; break;
	  default:		     ret = func_table[i].func; break;
	}
	i++;
    } while( what && what != *class );

    *sequence = i;
    return ret;
}




#ifndef IS_MODULE
void
_gcry_md2_constructor(void)
{
    _gcry_register_internal_cipher_extension( gnupgext_version, gnupgext_enum_func );
}
#endif
#endif
/* end of file */
