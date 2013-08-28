/* string.c - IPMI string handling
 * Copyright (C) 2012 MontaVista Software.
 * Corey Minyard <cminyard@mvista.com>
 *
 * This file is part of the IPMI Interface (IPMIIF).
 *
 * This is for handling strings in SDRs and FRU data.
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

#include <string.h>
#include <errno.h>

#include <OpenIPMI/ipmi_string.h>

static int
ipmi_get_unicode(unsigned int len,
		 unsigned char **d, unsigned int in_len,
		 char *out, unsigned int out_len)
{
    if (in_len < len)
	return -1;
    if (out_len < len)
	return -1;

    memcpy(out, *d, len);
    *d += len;
    return len;
}

static int
ipmi_get_bcd_plus(unsigned int len,
		  unsigned char **d, unsigned int in_len,
		  char *out, unsigned int out_len)
{
    static char table[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', ' ', '-', '.', ':', ',', '_'
    };
    unsigned int bo;
    unsigned int val = 0;
    unsigned int i;
    unsigned int real_length;
    char         *out_s = out;

    real_length = (in_len * 8) / 4;
    if (len > real_length)
	return -1;
    if (len > out_len)
	return -1;

    bo = 0;
    for (i=0; i<len; i++) {
	switch (bo) {
	case 0:
	    val = **d & 0xf;
	    bo = 4;
	    break;
	case 4:
	    val = (**d >> 4) & 0xf;
	    (*d)++;
	    bo = 0;
	    break;
	}
	*out = table[val];
	out++;
    }

    if (bo != 0)
	(*d)++;

    return out - out_s;
}

static int
ipmi_get_6_bit_ascii(unsigned int len,
		     unsigned char **d, unsigned int in_len,
		     char *out, unsigned int out_len)
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
    unsigned int bo;
    unsigned int val = 0;
    unsigned int i;
    unsigned int real_length;
    char         *out_s = out;

    real_length = (in_len * 8) / 6;
    if (len > real_length)
	return -1;
    if (len > out_len)
	return -1;

    bo = 0;
    for (i=0; i<len; i++) {
	switch (bo) {
	case 0:
	    val = **d & 0x3f;
	    bo = 6;
	    break;
	case 2:
	    val = (**d >> 2) & 0x3f;
	    (*d)++;
	    bo = 0;
	    break;
	case 4:
	    val = (**d >> 4) & 0xf;
	    (*d)++;
	    val |= (**d & 0x3) << 4;
	    bo = 2;
	    break;
	case 6:
	    val = (**d >> 6) & 0x3;
	    (*d)++;
	    val |= (**d & 0xf) << 2;
	    bo = 4;
	    break;
	}
	*out = table[val];
	out++;
    }

    if (bo != 0)
	(*d)++;

    return out - out_s;
}

static int
ipmi_get_8_bit_ascii(unsigned int len,
		     unsigned char **d, unsigned int in_len,
		     char *out, unsigned int out_len)
{
    unsigned int j;
    
    if (len > in_len)
	return -1;
    if (len > out_len)
	return -1;

    for (j=0; j<len; j++) {
	*out = **d;
	out++;
	(*d)++;
    }
    return len;
};

int
ipmi_get_device_string(unsigned char        ** const pinput,
		       unsigned int         in_len,
		       char                 *output,
		       int                  semantics,
		       int                  force_unicode,
		       enum ipmi_str_type_e *stype,
		       unsigned int         max_out_len,
		       unsigned int         *out_len)
{
    int type;
    int len;
    int olen;

    if (max_out_len == 0)
	return 0;

    if (in_len <= 0) {
	*output = '\0';
	return 0;
    }

#if 0
    /* Note that this is technically correct, but commonly ignored.
       0xc1 is invalid, but some FRU and SDR data still uses it.  Grr.
       The FRU stuff has to handle the end-of-area marker c1 itself,
       anyway, so this is relatively safe.  In a "correct" system you
       should never see a 0xc1 here, anyway. */
    if (**pinput == 0xc1) {
	*output = '\0';
	(*pinput)++;
	return 0;
    }
#endif

    type = (**pinput >> 6) & 3;

    /* Special case for FRU data, type 3 is unicode if the language is
       non-english. */
    if ((force_unicode) && (type == 3)) {
	type = 0;
	force_unicode = 0;
    }

    len = **pinput & 0x3f;
    (*pinput)++;
    in_len--;
    *stype = IPMI_ASCII_STR;
    switch (type)
    {
	case 0: /* Unicode */
	    olen = ipmi_get_unicode(len, pinput, in_len, output, max_out_len);
	    if (semantics == IPMI_STR_FRU_SEMANTICS)
		*stype = IPMI_BINARY_STR;
	    else
		*stype = IPMI_UNICODE_STR;
	    break;
	case 1: /* BCD Plus */
	    olen = ipmi_get_bcd_plus(len, pinput, in_len, output, max_out_len);
	    break;
	case 2: /* 6-bit ASCII */
	    olen=ipmi_get_6_bit_ascii(len, pinput, in_len, output, max_out_len);
	    break;
	case 3: /* 8-bit ASCII */
	    olen=ipmi_get_8_bit_ascii(len, pinput, in_len, output, max_out_len);
	    break;
        default:
	    olen = 0;
    }

    if (olen < 0)
	return EINVAL;

    *out_len = olen;
    return 0;
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
ipmi_set_bcdplus(const char    *input,
		 unsigned int  in_len,
		 unsigned char *output,
		 unsigned int  *out_len)
{
    unsigned int len = *out_len;
    const char   *s = input;
    unsigned int pos = 0;
    unsigned int bit = 0;
    unsigned int count = 0;

    while (in_len > 0) {
	switch(bit) {
	    case 0:
		pos++;
		if (pos >= len)
		    goto out_overflow;
		output[pos] = table_4_bit[(int) *s] - 1;
		bit = 4;
		break;

	    case 4:
		output[pos] |= (table_4_bit[(int) *s] - 1) << 4;
		bit = 0;
		break;
	}
	count++;
	in_len--;
	s++;
    }
    pos++;
 out_overflow:
    output[0] = (0x01 << 6) | count;
    *out_len = pos;
}

static void
ipmi_set_6_bit_ascii(const char    *input,
		     unsigned int  in_len,
		     unsigned char *output,
		     unsigned int  *out_len)
{
    unsigned int len = *out_len;
    const char   *s = input;
    unsigned int pos = 0;
    unsigned int bit = 0;
    unsigned int count = 0;
    unsigned int cval;
    unsigned int oval;

    while (in_len > 0) {
	cval = *s;
	s++;
	oval = table_6_bit[cval] - 1;
	switch(bit) {
	case 0:
	    pos++;
	    if (pos >= len) 
		goto out_overflow;
	    output[pos] = oval;
	    bit = 6;
	    break;

	case 2:
	    output[pos] |= oval << 2;
	    bit = 0;
	    break;

	case 4:
	    output[pos] |= oval << 4;
	    pos++;
	    if (pos >= len) 
		goto out_overflow;
	    output[pos] = (oval >> 4) & 0x3;
	    bit = 2;
	    break;

	case 6:
	    output[pos] |= oval << 6;
	    pos++;
	    if (pos >= len) 
		goto out_overflow;
	    output[pos] = (oval >> 2) & 0xf;
	    bit = 4;
	    break;
	}
	count++;
	in_len--;
    }
    pos++;
 out_overflow:
    output[0] = (0x02 << 6) | count;
    *out_len = pos;
}

static void
ipmi_set_8_bit_ascii(const char    *input,
		     unsigned int  in_len,
		     unsigned char *output,
		     unsigned int  *out_len)
{
    char tmp[2];
    /* truncate if necessary. */
    if (in_len > (*out_len - 1))
	in_len = *out_len - 1;

    /* A length of 1 is invalid, make it 2 with a nil char */
    if (in_len == 1) {
	tmp[0] = input[0];
	tmp[1] = '\0';
	input = tmp;
	in_len++;
    }

    *out_len = in_len + 1;

    memcpy(output+1, input, in_len);
    output[0] = (0x03 << 6) | in_len;
}

void
ipmi_set_device_string2(const char           *input,
			enum ipmi_str_type_e type,
			unsigned int         in_len,
			unsigned char        *output,
			int                  force_unicode,
			unsigned int         *out_len,
			unsigned int         options)
{
    const char   *s = input;
    int          bsize = 0; /* Start with 4-bit. */
    unsigned int i;

    /* Max size is 64 (63 bytes + the type byte). */
    if (*out_len > 64)
	*out_len = 64;
    /* Truncate */
    if (in_len > 63)
	in_len = 63;

    if (type == IPMI_ASCII_STR) {
	if (options && IPMI_STRING_OPTION_8BIT_ONLY)
	    bsize = 2;
	else {
	    for (i=0; i<in_len; i++) {
		if (table_4_bit[(int) *s] == 0) {
		    bsize |= 1;
		    if (table_6_bit[(int) *s] == 0) {
			bsize |= 2;
			break;
		    }
		}
		s++;
	    }
	}
	if (bsize == 0) {
	    /* We can encode it in 4-bit BCD+ */
	    ipmi_set_bcdplus(input, in_len, output, out_len);
	} else if (bsize == 1) {
	    /* We can encode it in 6-bit ASCII. */
	    ipmi_set_6_bit_ascii(input, in_len, output, out_len);
	} else {
	    ipmi_set_8_bit_ascii(input, in_len, output, out_len);
	}
    } else {
	/* The input and output are unicode. */
	if (in_len > *out_len-1)
	    in_len = *out_len-1;
	if ((force_unicode) && (type == IPMI_UNICODE_STR))
	    *output = (0x3 << 6) | in_len;
	else
	    *output = in_len;
	memcpy(output+1, input, in_len);
	*out_len = in_len + 1;
    }
}

void
ipmi_set_device_string(const char           *input,
		       enum ipmi_str_type_e type,
		       unsigned int         in_len,
		       unsigned char        *output,
		       int                  force_unicode,
		       unsigned int         *out_len)
{
    ipmi_set_device_string2(input, type, in_len, output, force_unicode,
			    out_len, IPMI_STRING_OPTION_NONE);
}
