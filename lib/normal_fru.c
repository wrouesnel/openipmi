/*
 * normal_fru.c
 *
 * "normal" (IPMI-specified) fru handling
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
 *
 * Note that this file was originally written by Thomas Kanngieser
 * <thomas.kanngieser@fci.com> of FORCE Computers, but I've pretty
 * much gutted it and rewritten it, nothing really remained the same.
 * Thomas' code was helpful, though and many thanks go to him.
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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>

#include <OpenIPMI/internal/locked_list.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/ipmi_utils.h>
#include <OpenIPMI/internal/ipmi_oem.h>
#include <OpenIPMI/internal/ipmi_fru.h>

#define IPMI_LANG_CODE_ENGLISH	25

/***********************************************************************
 *
 * Normal fru info.
 *
 **********************************************************************/

/* Records used to hold the FRU. */
typedef struct ipmi_fru_record_s ipmi_fru_record_t;

typedef struct fru_string_s
{
    enum ipmi_str_type_e type;
    unsigned int         length;
    char                 *str;

    /* The raw offset from the start of the area, and the raw length
       of this string.  This is the offset and length in the raw FRU
       data. */
    unsigned short       offset;
    unsigned short       raw_len;
    unsigned char        *raw_data;

    /* Has this value been changed locally since it has been read?
       Use to know that this needs to be written. */
    char                 changed;
} fru_string_t;

typedef struct fru_variable_s
{
    unsigned short len;
    unsigned short next;
    fru_string_t   *strings;
} fru_variable_t;

typedef struct fru_area_info_s {
    unsigned short num_fixed_fields;
    unsigned short field_start;
    unsigned short empty_length;
    fru_variable_t *(*get_fields)(ipmi_fru_record_t *rec);
    void (*free)(ipmi_fru_record_t *rec);
    unsigned short extra_len;
    int (*decode)(ipmi_fru_t        *fru,
		  unsigned char     *data,
		  unsigned int      data_len,
		  ipmi_fru_record_t **rrec);
    int (*encode)(ipmi_fru_t *fru, unsigned char *data);
    int (*setup_new)(ipmi_fru_record_t *rec, int full_init);
} fru_area_info_t;

/* Forward declaration */
static fru_area_info_t fru_area_info[IPMI_FRU_FTR_NUMBER];

struct ipmi_fru_record_s
{
    fru_area_info_t       *handlers;
    void                  *data;


    /* Where does this area start in the FRU and how much memory is
       available? */
    unsigned int          offset;
    unsigned int          length;

    /* How much of the area is currently used? */
    unsigned int          used_length;

    /* Length of the used length in the  */
    unsigned int          orig_used_length;

    /* Has this value been changed locally since it has been read?
       Use to know that something in the record needs to be written,
       the header needs to be rewritten, and the checksum needs to be
       recalculated. */
    char                  changed;

    /* Does the whole area require a rewrite?  This would be true if
       the position changed or the length was increased. */
    char                 rewrite;
};

static void fru_record_destroy(ipmi_fru_record_t *rec);

typedef struct normal_fru_rec_data_s
{
    int               version;

    /* Has an offset changed (thus causing the header to need to be
       rewritten)? */
    int               header_changed;

    ipmi_fru_record_t *recs[IPMI_FRU_FTR_NUMBER];
} normal_fru_rec_data_t;

static normal_fru_rec_data_t *setup_normal_fru(ipmi_fru_t    *fru,
					       unsigned char version);

static ipmi_fru_record_t **
normal_fru_get_recs(ipmi_fru_t *fru)
{
    normal_fru_rec_data_t *info = _ipmi_fru_get_rec_data(fru);
    return info->recs;
}

/***********************************************************************
 *
 * Normal fru data formatting.
 *
 **********************************************************************/

static unsigned char
checksum(unsigned char *data, unsigned int length)
{
    unsigned char sum = 0;

    while (length) {
	sum += *data;
	data++;
	length--;
    }

    return sum;
}

/* 820476000 is seconds between 1970.01.01 00:00:00 and 1996.01.01 00:00:00 */
#define FRU_TIME_TO_UNIX_TIME(t) (((t) * 60) + 820476000)
#define UNIX_TIME_TO_FRU_TIME(t) ((((t) - 820476000) + 30) / 60)

static int
read_fru_time(unsigned char **data,
	      unsigned int  *len,
	      time_t        *time)
{
    unsigned int  t;
    unsigned char *d = *data;

    if (*len < 3)
	return EBADF;

    t = *d++;
    t += *d++ * 256;
    t += *d++ * 256 * 256;

    *len -= 3;
    *data += 3;

    *time = FRU_TIME_TO_UNIX_TIME(t);
    return 0;
}

static void
write_fru_time(unsigned char *d, time_t time)
{
    unsigned int t;

    t = UNIX_TIME_TO_FRU_TIME(time);

    *d++ = t & 0xff;
    t >>= 8;
    *d++ = t & 0xff;
    t >>= 8;
    *d++ = t & 0xff;
    t >>= 8;
}

static int
fru_encode_fields(ipmi_fru_t        *fru,
		  ipmi_fru_record_t *rec,
		  fru_variable_t    *v,
		  unsigned char     *data,
		  unsigned int      offset)
{
    int i;
    int rv;

    for (i=0; i<v->next; i++) {
	fru_string_t *s = v->strings + i;
	unsigned int len;

	if (offset != s->offset) {
	    /* Bug in the FRU code.  Return a unique error code so it
	       can be identified, but don't pass it to the user. */
	    return EBADF;
	}

	if (s->raw_data) {
	    memcpy(data+offset, s->raw_data, s->raw_len);
	    len = s->raw_len;
	} else if (s->str) {
	    len = IPMI_MAX_STR_LEN;
	    ipmi_set_device_string2(s->str, s->type, s->length,
				    data+offset, 1, &len,
				    ipmi_fru_get_options(fru));
	} else {
	    data[offset] = 0xc0;
	    len = 1;
	}
	if (s->changed && !rec->rewrite) {
	    rv = _ipmi_fru_new_update_record(fru, offset+rec->offset, len);
	    if (rv)
		return rv;
	}
	offset += len;
    }
    /* Now the end marker */
    data[offset] = 0xc1;
    /* If the record changed, put out the end marker */
    if (rec->changed && !rec->rewrite) {
	rv = _ipmi_fru_new_update_record(fru, offset+rec->offset, 1);
	if (rv)
	    return rv;
    }
    offset++;
    /* We are not adding the checksum, so remove it from the check */
    if (offset != (rec->used_length-1)) {
	return EBADF;
    }
    return 0;
}

/***********************************************************************
 *
 * Custom field handling for FRUs.  This is a variable-length array
 * of strings.
 *
 **********************************************************************/

static int
fru_setup_min_field(ipmi_fru_record_t *rec, int area, int changed)
{
    unsigned int   i;
    unsigned int   min;
    unsigned int   start_offset;
    fru_variable_t *v;

    if (!fru_area_info[area].get_fields)
	return 0;

    v = fru_area_info[area].get_fields(rec);
    min = fru_area_info[area].num_fixed_fields;
    start_offset = fru_area_info[area].field_start;

    if (min == 0)
	return 0;

    v->strings = ipmi_mem_alloc(min * sizeof(fru_string_t));
    if (!v->strings)
	return ENOMEM;
    memset(v->strings, 0, min * sizeof(fru_string_t));
    for (i=0; i<min; i++) {
	v->strings[i].changed = changed;
	v->strings[i].offset = start_offset;
	start_offset++;
	v->strings[i].raw_len = 1;
    }
    v->len = min;
    v->next = min;
    return 0;
}

static int
fru_string_set(ipmi_fru_t           *fru,
	       enum ipmi_str_type_e type,
	       char                 *str,
	       unsigned int         len,
	       ipmi_fru_record_t    *rec,
	       fru_variable_t       *vals,
	       unsigned int         num,
	       int                  is_custom)
{
    char         *newval;
    fru_string_t *val = vals->strings + num;
    unsigned char tstr[IPMI_MAX_STR_LEN+1];
    unsigned int  raw_len = sizeof(tstr);
    int           raw_diff;
    int           i;

    if (str) {
	/* First calculate if it will fit into the record area. */

	/* Truncate if too long. */
	if (len > 63)
	    len = 63;
	ipmi_set_device_string2(str, type, len, tstr, 1, &raw_len,
				ipmi_fru_get_options(fru));
	raw_diff = raw_len - val->raw_len;
	if ((raw_diff > 0) && (rec->used_length+raw_diff > rec->length))
	    return ENOSPC;
	if (len == 0)
	    newval = ipmi_mem_alloc(1);
	else
	    newval = ipmi_mem_alloc(len);
	if (!newval)
	    return ENOMEM;
	memcpy(newval, str, len);
    } else {
	newval = NULL;
	len = 0;
	raw_diff = 1 - val->raw_len;
    }

    if (val->str)
	ipmi_mem_free(val->str);
    if (val->raw_data) {
	ipmi_mem_free(val->raw_data);
	val->raw_data = NULL;
    }

    if (!is_custom || newval) {
	/* Either it's not a custom value (and thus is always there)
	   or there is a value to put in.  Modify the length and
	   reduce the offset of all the following strings. */
	val->str = newval;
	val->length = len;
	val->type = type;
	val->raw_len += raw_diff;
	val->changed = 1;
	if (raw_diff) {
	    for (i=num+1; i<vals->next; i++) {
		vals->strings[i].offset += raw_diff;
		vals->strings[i].changed = 1;
	    }
	}
    } else {
	/* A custom value that is being cleared.  Nuke it by moving
	   all the strings following this back. */
	raw_diff = -val->raw_len;
	vals->next--;
	for (i=num; i<vals->next; i++) {
	    vals->strings[i] = vals->strings[i+1];
	    vals->strings[i].offset += raw_diff;
	    vals->strings[i].changed = 1;
	}
    }

    rec->used_length += raw_diff;
    rec->changed |= 1;

    return 0;
}

static int
fru_decode_string(ipmi_fru_t     *fru,
		  unsigned char  *start_pos,
		  unsigned char  **in,
		  unsigned int   *in_len,
		  int            lang_code,
		  int            force_english,
		  fru_variable_t *strs,
		  unsigned int   num)
{
    char          str[IPMI_MAX_STR_LEN+1];
    int           force_unicode;
    fru_string_t  *out = strs->strings + num;
    unsigned char *in_start;
    int           rv;

    out->offset = *in - start_pos;
    in_start = *in;
    force_unicode = !force_english && (lang_code != IPMI_LANG_CODE_ENGLISH);
    rv = ipmi_get_device_string(in, *in_len, str,
				IPMI_STR_FRU_SEMANTICS, force_unicode,
				&out->type, sizeof(str), &out->length);
    if (rv)
	return rv;
    out->raw_len = *in - in_start;
    *in_len -= out->raw_len;
    out->raw_data = ipmi_mem_alloc(out->raw_len);
    if (!out->raw_data)
	return ENOMEM;
    memcpy(out->raw_data, in_start, out->raw_len);

    if (out->length != 0) {
	out->str = ipmi_mem_alloc(out->length);
	if (!out->str) {
	    ipmi_mem_free(out->raw_data);
	    return ENOMEM;
	}
	memcpy(out->str, str, out->length);
    } else {
	out->str = ipmi_mem_alloc(1);
	if (!out->str) {
	    ipmi_mem_free(out->raw_data);
	    return ENOMEM;
	}
    }
    return 0;
}

static int
fru_string_to_out(char *out, unsigned int *length, fru_string_t *in)
{
    unsigned int clen;

    if (!in->str)
	return ENOSYS;

    if (in->length > *length)
	clen = *length;
    else
	clen = in->length;
    memcpy(out, in->str, clen);

    if (in->type == IPMI_ASCII_STR) {
	/* NIL terminate the ASCII string. */
	if (clen == *length)
	    clen--;

	out[clen] = '\0';
    }

    *length = clen;

    return 0;
}

static void
fru_free_string(fru_string_t *str)
{
    if (str->str)
	ipmi_mem_free(str->str);
    if (str->raw_data)
	ipmi_mem_free(str->raw_data);
}


static int
fru_variable_string_set(ipmi_fru_t           *fru,
			ipmi_fru_record_t    *rec,
			fru_variable_t       *val,
			unsigned int         first_custom,
			unsigned int         num,
			enum ipmi_str_type_e type,
			char                 *str,
			unsigned int         len,
			int                  is_custom)
{
    int rv;

    if (is_custom) {
	/* Renumber to get the custom fields.  We do this a little
	   strangly to avoid overflows if the user passes in MAX_INT
	   for the num. */
	if (num > val->next - first_custom)
	    num = val->next;
	else
	    num += first_custom;
    }
    if (num >= val->next) {
	if (len == 0) {
	    /* Don't expand if we are deleting an invalid field,
	       return an error. */
	    return EINVAL;
	}
	num = val->next;
	/* If not enough room, expand the array by a set amount (to
	   keep from thrashing memory when adding lots of things). */
	if (val->next >= val->len) {
	    fru_string_t *newval;
	    unsigned int alloc_num = val->len + 16;

	    newval = ipmi_mem_alloc(sizeof(fru_string_t) * alloc_num);
	    if (!newval)
		return ENOMEM;
	    memset(newval, 0, sizeof(fru_string_t) * alloc_num);
	    if (val->strings) {
		memcpy(newval, val->strings, sizeof(fru_string_t) * val->next);
		ipmi_mem_free(val->strings);
	    }
	    val->strings = newval;
	    val->len = alloc_num;
	}
	val->strings[num].str = NULL;
	val->strings[num].raw_data = NULL;
	/* Subtract 2 below because of the end marker and the checksum. */
	val->strings[num].offset = rec->used_length-2;
	val->strings[num].length = 0;
	val->strings[num].raw_len = 0;
	val->next++;
    }

    rv = fru_string_set(fru, type, str, len, rec, val, num, is_custom);
    return rv;
}

static int
fru_variable_string_ins(ipmi_fru_t           *fru,
			ipmi_fru_record_t    *rec,
			fru_variable_t       *val,
			unsigned int         first_custom,
			unsigned int         num,
			enum ipmi_str_type_e type,
			char                 *str,
			unsigned int         len)
{
    int rv;
    int i;
    int offset;

    /* Renumber to get the custom fields.  We do this a little
       strangly to avoid overflows if the user passes in MAX_INT
       for the num. */
    if (num > val->next - first_custom)
	num = val->next;
    else
	num += first_custom;

    if (num > val->next)
	return EINVAL;

    if (!str)
	return EINVAL;

    if ((rec->used_length + 1) > rec->length)
	return ENOSPC;

    /* If not enough room, expand the array by a set amount (to
       keep from thrashing memory when adding lots of things). */
    if (val->next >= val->len) {
	fru_string_t *newval;
	unsigned int alloc_num = val->len + 16;

	newval = ipmi_mem_alloc(sizeof(fru_string_t) * alloc_num);
	if (!newval)
	    return ENOMEM;
	memset(newval, 0, sizeof(fru_string_t) * alloc_num);
	if (val->strings) {
	    memcpy(newval, val->strings, sizeof(fru_string_t) * val->next);
	    ipmi_mem_free(val->strings);
	}
	val->strings = newval;
	val->len = alloc_num;
    }

    if (num == val->next)
	/* Subtract 2 below because of the end marker and the checksum. */
	offset = rec->used_length-2;
    else
	offset = val->strings[num].offset;

    for (i=val->next; i>(int)num; i--) {
	val->strings[i] = val->strings[i-1];
	val->strings[i].changed = 1;
    }

    val->strings[num].str = NULL;
    val->strings[num].raw_data = NULL;
    val->strings[num].offset = offset;
    val->strings[num].length = 0;
    val->strings[num].raw_len = 0;
    val->next++;

    rv = fru_string_set(fru, type, str, len, rec, val, num, 1);
    return rv;
}

static int
fru_decode_variable_string(ipmi_fru_t     *fru,
			   unsigned char  *start_pos,
			   unsigned char  **in,
			   unsigned int   *in_len,
			   int            lang_code,
			   fru_variable_t *v)
{
    int err;

    if (v->next == v->len) {
#define FRU_STR_ALLOC_INCREMENT	5
	fru_string_t *n;
	int          n_len = v->len + FRU_STR_ALLOC_INCREMENT;

	n = ipmi_mem_alloc(sizeof(fru_string_t) * n_len);
	if (!n)
	    return ENOMEM;

	if (v->strings) {
	    memcpy(n, v->strings, sizeof(fru_string_t) * v->len);
	    ipmi_mem_free(v->strings);
	}
	memset(n + v->len, 0,
	       sizeof(fru_string_t) * FRU_STR_ALLOC_INCREMENT);
	v->strings = n;
	v->len = n_len;
    }

    err = fru_decode_string(fru, start_pos, in, in_len, lang_code, 0,
			    v, v->next);
    if (!err)
	v->next++;
    return err;
}

static int
fru_variable_string_to_out(fru_variable_t *in,
			   unsigned int   num,
			   char           *out,
			   unsigned int   *length)
{
    if (num >= in->next)
	return E2BIG;

    return fru_string_to_out(out, length, &in->strings[num]);
}

static int
fru_variable_string_length(fru_variable_t *in,
			   unsigned int   num,
			   unsigned int   *length)
{
    if (num >= in->next)
	return E2BIG;

    if (in->strings[num].type == IPMI_ASCII_STR)
	*length = in->strings[num].length + 1;
    else
	*length = in->strings[num].length;
    return 0;
}

static int
fru_variable_string_type(fru_variable_t       *in,
			 unsigned int         num,
			 enum ipmi_str_type_e *type)
{
    if (num >= in->next)
	return E2BIG;

    *type = in->strings[num].type;
    return 0;
}

static void
fru_free_variable_string(fru_variable_t *v)
{
    int i;

    for (i=0; i<v->next; i++)
	fru_free_string(&v->strings[i]);

    if (v->strings)
	ipmi_mem_free(v->strings);
}


/***********************************************************************
 *
 * Here is the basic FRU handling.
 *
 **********************************************************************/

static ipmi_fru_record_t *
fru_record_alloc(int area, int full_init, unsigned int length)
{
    ipmi_fru_record_t *rec;
    unsigned short    extra_len = fru_area_info[area].extra_len;

    rec = ipmi_mem_alloc(sizeof(ipmi_fru_record_t) + extra_len);
    if (!rec)
	return NULL;

    memset(rec, 0, sizeof(ipmi_fru_record_t)+extra_len);

    rec->handlers = fru_area_info + area;
    rec->data = ((char *) rec) + sizeof(ipmi_fru_record_t);
    rec->length = length;

    if (fru_area_info[area].setup_new) {
	int rv;
	rv = fru_area_info[area].setup_new(rec, full_init);
	if (rv) {
	    ipmi_mem_free(rec);
	    rec = NULL;
	}
    }

    return rec;
}

static void *
fru_record_get_data(ipmi_fru_record_t *rec)
{
    return rec->data;
}

static void
fru_record_free(ipmi_fru_record_t *rec)
{
    ipmi_mem_free(rec);
}


/***********************************************************************
 *
 * Various macros for common handling.
 *
 **********************************************************************/

#define HANDLE_STR_DECODE(ucname, fname, force_english) \
    err = fru_decode_string(fru, orig_data, &data, &data_len, u->lang_code, \
			    force_english, &u->fields,		\
			    ucname ## _ ## fname);		\
    if (err)							\
	goto out_err

#define HANDLE_CUSTOM_DECODE(ucname) \
do {									\
    while ((data_len > 0) && (*data != 0xc1)) {				\
	err = fru_decode_variable_string(fru, orig_data, &data, &data_len, \
					 u->lang_code,			\
					 &u->fields);			\
	if (err)							\
	    goto out_err;						\
    }									\
} while (0)

#define GET_DATA_PREFIX(lcname, ucname) \
    ipmi_fru_ ## lcname ## _area_t *u;				\
    ipmi_fru_record_t              **recs;			\
    ipmi_fru_record_t              *rec;			\
    if (!_ipmi_fru_is_normal_fru(fru))				\
	return ENOSYS;						\
    _ipmi_fru_lock(fru);					\
    recs = normal_fru_get_recs(fru);				\
    rec = recs[IPMI_FRU_FTR_## ucname ## _AREA];		\
    if (!rec) {							\
	_ipmi_fru_unlock(fru);					\
	return ENOSYS;						\
    }								\
    u = fru_record_get_data(rec);

#define GET_DATA_STR(lcname, ucname, fname) \
int									\
ipmi_fru_get_ ## lcname ## _ ## fname ## _len(ipmi_fru_t   *fru,	\
					      unsigned int *length)	\
{									\
    int rv;								\
    GET_DATA_PREFIX(lcname, ucname);					\
    rv = fru_variable_string_length(&u->fields,				\
				    ucname ## _ ## fname,		\
                                    length);				\
    _ipmi_fru_unlock(fru);						\
    return rv;								\
}									\
int									\
ipmi_fru_get_ ## lcname ## _ ## fname ## _type(ipmi_fru_t           *fru,\
					       enum ipmi_str_type_e *type)\
{									\
    int rv;								\
    GET_DATA_PREFIX(lcname, ucname);					\
    rv = fru_variable_string_type(&u->fields,				\
				  ucname ## _ ## fname,			\
                                  type);				\
    _ipmi_fru_unlock(fru);						\
    return rv;								\
}									\
int									\
ipmi_fru_get_ ## lcname ## _ ## fname(ipmi_fru_t	*fru,		\
				      char              *str,		\
				      unsigned int      *strlen)	\
{									\
    int rv;								\
    GET_DATA_PREFIX(lcname, ucname);					\
    rv = fru_variable_string_to_out(&u->fields,				\
				    ucname ## _ ## fname,		\
                                    str, strlen);			\
    _ipmi_fru_unlock(fru);						\
    return rv;								\
}									\
int									\
ipmi_fru_set_ ## lcname ## _ ## fname(ipmi_fru_t	   *fru,	\
				      enum ipmi_str_type_e type,	\
				      char                 *str,	\
				      unsigned int         len)		\
{									\
    int rv;								\
    GET_DATA_PREFIX(lcname, ucname);					\
    rv = fru_variable_string_set(fru, rec,				\
				 &u->fields,				\
				 0, ucname ## _ ## fname,		\
                                 type, str, len, 0);			\
    _ipmi_fru_unlock(fru);						\
    return rv;								\
}

#define GET_CUSTOM_STR(lcname, ucname) \
int									\
ipmi_fru_get_ ## lcname ## _ ## custom ## _len(ipmi_fru_t   *fru,	\
					       unsigned int num,	\
					       unsigned int *length)	\
{									\
    int rv;								\
    GET_DATA_PREFIX(lcname, ucname);					\
    rv = fru_variable_string_length(&u->fields,				\
				    ucname ## _ ## custom_start + num,	\
                                    length);				\
    _ipmi_fru_unlock(fru);						\
    return rv;								\
}									\
int									\
ipmi_fru_get_ ## lcname ## _ ## custom ## _type(ipmi_fru_t   *fru,	\
					        unsigned int num,	\
					        enum ipmi_str_type_e *type) \
{									\
    int rv;								\
    GET_DATA_PREFIX(lcname, ucname);					\
    rv = fru_variable_string_type(&u->fields,				\
				  ucname ## _ ## custom_start + num,	\
                                  type);				\
    _ipmi_fru_unlock(fru);						\
    return rv;								\
}									\
int									\
ipmi_fru_get_ ## lcname ## _ ## custom(ipmi_fru_t	 *fru,		\
				       unsigned int      num,		\
				       char              *str,		\
				       unsigned int      *strlen)	\
{									\
    int rv;								\
    GET_DATA_PREFIX(lcname, ucname);					\
    rv = fru_variable_string_to_out(&u->fields,				\
				    ucname ## _ ## custom_start + num,	\
                                    str, strlen);			\
    _ipmi_fru_unlock(fru);						\
    return rv;								\
}									\
int									\
ipmi_fru_set_ ## lcname ## _ ## custom(ipmi_fru_t	    *fru,	\
				       unsigned int         num,	\
				       enum ipmi_str_type_e type,	\
				       char                 *str,	\
				       unsigned int         len)	\
{									\
    int rv;								\
    GET_DATA_PREFIX(lcname, ucname);					\
    rv = fru_variable_string_set(fru, rec,				\
				 &u->fields,				\
				 ucname ## _ ## custom_start, num,	\
                                 type, str, len, 1);			\
    _ipmi_fru_unlock(fru);						\
    return rv;								\
}									\
int									\
ipmi_fru_ins_ ## lcname ## _ ## custom(ipmi_fru_t	    *fru,	\
				       unsigned int         num,	\
				       enum ipmi_str_type_e type,	\
				       char                 *str,	\
				       unsigned int         len)	\
{									\
    int rv;								\
    GET_DATA_PREFIX(lcname, ucname);					\
    rv = fru_variable_string_ins(fru, rec,				\
				 &u->fields,				\
				 ucname ## _ ## custom_start, num,	\
                                 type, str, len);			\
    _ipmi_fru_unlock(fru);						\
    return rv;								\
}

/***********************************************************************
 *
 * Handling for FRU internal use areas.
 *
 **********************************************************************/

typedef struct ipmi_fru_internal_use_area_s
{
    /* version bit 7-4 reserved (0000), bit 3-0 == 0001 */
    unsigned char  version;
    unsigned short length;
    unsigned char  *data;
} ipmi_fru_internal_use_area_t;


static void
internal_use_area_free(ipmi_fru_record_t *rec)
{
    ipmi_fru_internal_use_area_t *u = fru_record_get_data(rec);

    ipmi_mem_free(u->data);
    fru_record_free(rec);
}

static int
internal_use_area_setup(ipmi_fru_record_t *rec, int full_setup)
{
    ipmi_fru_internal_use_area_t *u = fru_record_get_data(rec);

    u->version = 1;
    if (full_setup) {
	u->length = rec->length - 1;
	u->data = ipmi_mem_alloc(u->length);
	if (!u->data)
	    return ENOMEM;
	memset(u->data, 0, u->length);
    }
    return 0;
}

static int
fru_decode_internal_use_area(ipmi_fru_t        *fru,
			     unsigned char     *data,
			     unsigned int      data_len,
			     ipmi_fru_record_t **rrec)
{
    ipmi_fru_internal_use_area_t *u;
    ipmi_fru_record_t            *rec;

    rec = fru_record_alloc(IPMI_FRU_FTR_INTERNAL_USE_AREA, 0, data_len);
    if (!rec)
	return ENOMEM;

    rec->used_length = data_len;
    rec->orig_used_length = data_len;

    u = fru_record_get_data(rec);

    u->version = *data;
    u->length = data_len-1;
    u->data = ipmi_mem_alloc(u->length);
    if (!u->data) {
	ipmi_mem_free(rec);
	return ENOMEM;
    }

    memcpy(u->data, data+1, u->length);

    *rrec = rec;

    return 0;
}

int 
ipmi_fru_get_internal_use_version(ipmi_fru_t    *fru,
				  unsigned char *version)
{
    GET_DATA_PREFIX(internal_use, INTERNAL_USE);

    *version = u->version;

    _ipmi_fru_unlock(fru);

    return 0;
}

static int
ipmi_fru_set_internal_use_version(ipmi_fru_t *fru, unsigned char data)
{
    return EPERM;
}

int 
ipmi_fru_get_internal_use_len(ipmi_fru_t   *fru,
			      unsigned int *length)
{
    GET_DATA_PREFIX(internal_use, INTERNAL_USE);

    *length = u->length;

    _ipmi_fru_unlock(fru);

    return 0;
}


int 
ipmi_fru_get_internal_use(ipmi_fru_t    *fru,
			  unsigned char *data,
			  unsigned int  *max_len)
{
    int l;
    GET_DATA_PREFIX(internal_use, INTERNAL_USE);

    l = *max_len;

    if (l > u->length)
	l = u->length;

    memcpy(data, u->data, l);

    *max_len = l;

    _ipmi_fru_unlock(fru);

    return 0;
}

int
ipmi_fru_set_internal_use(ipmi_fru_t *fru, unsigned char *data,
			  unsigned int len)
{
    unsigned char *new_val;

    GET_DATA_PREFIX(internal_use, INTERNAL_USE);

    if (len > rec->length-1) {
	_ipmi_fru_unlock(fru);
	return E2BIG;
    }

    new_val = ipmi_mem_alloc(len);
    if (!new_val) {
	_ipmi_fru_unlock(fru);
	return ENOMEM;
    }
    if (u->data)
	ipmi_mem_free(u->data);
    u->data = new_val;
    memcpy(u->data, data, len);
    u->length = len;
    rec->changed = 1;
    rec->used_length = len + 1;
    rec->orig_used_length = rec->used_length;
    
    _ipmi_fru_unlock(fru);

    return 0;
}

static int
fru_encode_internal_use_area(ipmi_fru_t *fru, unsigned char *data)
{
    ipmi_fru_record_t **recs = normal_fru_get_recs(fru);
    ipmi_fru_record_t *rec = recs[IPMI_FRU_FTR_INTERNAL_USE_AREA];
    ipmi_fru_internal_use_area_t *u;
    int               rv;

    if (!rec)
	return 0;

    u = fru_record_get_data(rec);
    data += rec->offset;
    memset(data, 0, rec->length);
    data[0] = 1; /* Version */
    memcpy(data+1, u->data, u->length);
    if (rec->changed && !rec->rewrite) {
	rv = _ipmi_fru_new_update_record(fru, rec->offset, u->length+1);
	if (rv)
	    return rv;
    }
    return 0;
}

/***********************************************************************
 *
 * Handling for FRU chassis info areas
 *
 **********************************************************************/

#define CHASSIS_INFO_part_number	0
#define CHASSIS_INFO_serial_number	1
#define CHASSIS_INFO_custom_start	2

typedef struct ipmi_fru_chassis_info_area_s
{
    /* version bit 7-4 reserved (0000), bit 3-0 == 0001 */
    unsigned char  version;
    unsigned char  type;  /* chassis type CT_xxxx */
    unsigned char  lang_code;
    fru_variable_t fields;
} ipmi_fru_chassis_info_area_t;

static void
chassis_info_area_free(ipmi_fru_record_t *rec)
{
    ipmi_fru_chassis_info_area_t *u = fru_record_get_data(rec);

    fru_free_variable_string(&u->fields);
    fru_record_free(rec);
}

static int
chassis_info_area_setup(ipmi_fru_record_t *rec, int full_init)
{
    ipmi_fru_chassis_info_area_t *u = fru_record_get_data(rec);

    u->version = 1;
    if (full_init) {
	u->type = 0;
	u->lang_code = 0;
    }
    return 0;
}

static fru_variable_t *
chassis_info_get_fields(ipmi_fru_record_t *rec)
{
    ipmi_fru_chassis_info_area_t *u;
    u = fru_record_get_data(rec);
    return &u->fields;
}

static int
fru_decode_chassis_info_area(ipmi_fru_t        *fru,
			     unsigned char     *data,
			     unsigned int      data_len,
			     ipmi_fru_record_t **rrec)
{
    ipmi_fru_chassis_info_area_t *u;
    ipmi_fru_record_t            *rec;
    int                          err;
    unsigned char                version;
    unsigned char                length;
    unsigned char                *orig_data = data;

    version = *data;
    length = (*(data+1)) * 8;
    if ((length == 0) || (length > data_len)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%snormal_fru.c(fru_decode_chassis_info_area):"
		 " FRU string goes past data length",
		 _ipmi_fru_get_iname(fru));
	return EBADF;
    }

    if (checksum(data, length) != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%snormal_fru.c(fru_decode_chassis_info_area):"
		 " FRU string checksum failed",
		 _ipmi_fru_get_iname(fru));
	return EBADF;
    }

    data_len--; /* remove the checksum */

    rec = fru_record_alloc(IPMI_FRU_FTR_CHASSIS_INFO_AREA, 0, length);
    if (!rec)
	return ENOMEM;

    err = fru_setup_min_field(rec, IPMI_FRU_FTR_CHASSIS_INFO_AREA, 0);
    if (err)
	goto out_err;

    u = fru_record_get_data(rec);

    u->version = version;
    data += 2;
    data_len -= 2;
    u->type = *data;
    data++;
    data_len--;
    u->lang_code = IPMI_LANG_CODE_ENGLISH;
    HANDLE_STR_DECODE(CHASSIS_INFO, part_number, 1);
    HANDLE_STR_DECODE(CHASSIS_INFO, serial_number, 1);
    HANDLE_CUSTOM_DECODE(CHASSIS_INFO);
    rec->used_length = data - orig_data + 2; /* add 1 for the checksum, 1 for term */
    rec->orig_used_length = rec->used_length;

    *rrec = rec;

    return 0;

 out_err:
    chassis_info_area_free(rec);
    return err;
}

int 
ipmi_fru_get_chassis_info_version(ipmi_fru_t    *fru,
				  unsigned char *version)
{
    GET_DATA_PREFIX(chassis_info, CHASSIS_INFO);
    
    *version = u->version;

    _ipmi_fru_unlock(fru);

    return 0;
}

static int
ipmi_fru_set_chassis_info_version(ipmi_fru_t *fru, unsigned char data)
{
    return EPERM;
}

int 
ipmi_fru_get_chassis_info_type(ipmi_fru_t    *fru,
			       unsigned char *type)
{
    GET_DATA_PREFIX(chassis_info, CHASSIS_INFO);
    
    *type = u->type;

    _ipmi_fru_unlock(fru);

    return 0;
}

int 
ipmi_fru_set_chassis_info_type(ipmi_fru_t    *fru,
			       unsigned char type)
{
    GET_DATA_PREFIX(chassis_info, CHASSIS_INFO);

    rec->changed |= u->type != type;
    u->type = type;

    _ipmi_fru_unlock(fru);

    return 0;
}

GET_DATA_STR(chassis_info, CHASSIS_INFO, part_number)
GET_DATA_STR(chassis_info, CHASSIS_INFO, serial_number)
GET_CUSTOM_STR(chassis_info, CHASSIS_INFO)

static int
fru_encode_chassis_info_area(ipmi_fru_t *fru, unsigned char *data)
{
    ipmi_fru_record_t **recs = normal_fru_get_recs(fru);
    ipmi_fru_record_t *rec = recs[IPMI_FRU_FTR_CHASSIS_INFO_AREA];
    ipmi_fru_chassis_info_area_t *u;
    int               rv;

    if (!rec)
	return 0;

    u = fru_record_get_data(rec);
    data += rec->offset;
    memset(data, 0, rec->length);
    data[0] = 1; /* Version */
    data[1] = rec->length / 8;
    data[2] = u->type;
    if (rec->changed && !rec->rewrite) {
	rv = _ipmi_fru_new_update_record(fru, rec->offset, 3);
	if (rv)
	    return rv;
    }
    rv = fru_encode_fields(fru, rec, &u->fields, data, 3);
    if (rv)
	return rv;
    data[rec->length-1] = -checksum(data, rec->length-1);
    if (rec->changed && !rec->rewrite) {
	/* Write any zeros that need to be written if the data got
	   shorter. */
	if (rec->used_length < rec->orig_used_length) {
	    rv = _ipmi_fru_new_update_record(fru,
					     rec->offset + rec->used_length - 1,
					     (rec->orig_used_length
					      - rec->used_length));
	    if (rv)
		return rv;
	}
	/* Write the checksum */
	rv = _ipmi_fru_new_update_record(fru, rec->offset+rec->length-1, 1);
	if (rv)
	    return rv;
    }
    return 0;
}

/***********************************************************************
 *
 * Handling for FRU board info areas
 *
 **********************************************************************/

#define BOARD_INFO_board_manufacturer	0
#define BOARD_INFO_board_product_name	1
#define BOARD_INFO_board_serial_number	2
#define BOARD_INFO_board_part_number	3
#define BOARD_INFO_fru_file_id		4
#define BOARD_INFO_custom_start		5

typedef struct ipmi_fru_board_info_area_s
{
    /* version bit 7-4 reserved (0000), bit 3-0 == 0001 */
    unsigned char  version;
    unsigned char  lang_code;
    time_t         mfg_time;
    fru_variable_t fields;
} ipmi_fru_board_info_area_t;

static void
board_info_area_free(ipmi_fru_record_t *rec)
{
    ipmi_fru_board_info_area_t *u = fru_record_get_data(rec);

    fru_free_variable_string(&u->fields);
    fru_record_free(rec);
}

static int
board_info_area_setup(ipmi_fru_record_t *rec, int full_init)
{
    ipmi_fru_board_info_area_t *u = fru_record_get_data(rec);

    u->version = 1;
    if (full_init) {
	u->lang_code = 0;
	u->mfg_time = 0;
    }
    return 0;
}

static fru_variable_t *
board_info_get_fields(ipmi_fru_record_t *rec)
{
    ipmi_fru_board_info_area_t *u;
    u = fru_record_get_data(rec);
    return &u->fields;
}

static int
fru_decode_board_info_area(ipmi_fru_t        *fru,
			   unsigned char     *data,
			   unsigned int      data_len,
			   ipmi_fru_record_t **rrec)
{
    ipmi_fru_board_info_area_t *u;
    ipmi_fru_record_t          *rec;
    int                        err;
    unsigned char              version;
    unsigned int               length;
    unsigned char              *orig_data = data;

    version = *data;
    length = (*(data+1)) * 8;
    if ((length == 0) || (length > data_len)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%snormal_fru.c(fru_decode_board_info_area):"
		 " FRU string goes past data length",
		 _ipmi_fru_get_iname(fru));
	return EBADF;
    }

    if (checksum(data, length) != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%snormal_fru.c(fru_decode_board_info_area):"
		 " FRU string checksum failed",
		 _ipmi_fru_get_iname(fru));
	return EBADF;
    }

    data_len--; /* remove the checksum */

    rec = fru_record_alloc(IPMI_FRU_FTR_BOARD_INFO_AREA, 0, length);
    if (!rec)
	return ENOMEM;

    err = fru_setup_min_field(rec, IPMI_FRU_FTR_BOARD_INFO_AREA, 0);
    if (err)
	goto out_err;

    u = fru_record_get_data(rec);

    u->version = version;
    data += 2;
    data_len -= 2;
    u->lang_code = *data;
    if (u->lang_code == 0)
	u->lang_code = IPMI_LANG_CODE_ENGLISH;
    data++;
    data_len--;

    err = read_fru_time(&data, &data_len, &u->mfg_time);
    if (err)
	goto out_err;

    HANDLE_STR_DECODE(BOARD_INFO, board_manufacturer, 0);
    HANDLE_STR_DECODE(BOARD_INFO, board_product_name, 0);
    HANDLE_STR_DECODE(BOARD_INFO, board_serial_number, 1);
    HANDLE_STR_DECODE(BOARD_INFO, board_part_number, 1);
    HANDLE_STR_DECODE(BOARD_INFO, fru_file_id, 1);
    HANDLE_CUSTOM_DECODE(BOARD_INFO);
    rec->used_length = data - orig_data + 2; /* add 1 for the checksum, 1 for term */
    rec->orig_used_length = rec->used_length;

    *rrec = rec;

    return 0;

 out_err:
    board_info_area_free(rec);
    return err;
}

int 
ipmi_fru_get_board_info_version(ipmi_fru_t    *fru,
				unsigned char *version)
{
    GET_DATA_PREFIX(board_info, BOARD_INFO);
    
    *version = u->version;

    _ipmi_fru_unlock(fru);

    return 0;
}

static int
ipmi_fru_set_board_info_version(ipmi_fru_t *fru, unsigned char data)
{
    return EPERM;
}

int 
ipmi_fru_get_board_info_lang_code(ipmi_fru_t    *fru,
				  unsigned char *type)
{
    GET_DATA_PREFIX(board_info, BOARD_INFO);
    
    *type = u->lang_code;

    _ipmi_fru_unlock(fru);

    return 0;
}

int 
ipmi_fru_set_board_info_lang_code(ipmi_fru_t    *fru,
				  unsigned char lang)
{
    GET_DATA_PREFIX(board_info, BOARD_INFO);

    rec->changed |= u->lang_code != lang;
    u->lang_code = lang;

    _ipmi_fru_unlock(fru);

    return 0;
}

int 
ipmi_fru_get_board_info_mfg_time(ipmi_fru_t *fru,
				 time_t     *time)
{
    GET_DATA_PREFIX(board_info, BOARD_INFO);
    
    *time = u->mfg_time;

    _ipmi_fru_unlock(fru);

    return 0;
}

int 
ipmi_fru_set_board_info_mfg_time(ipmi_fru_t *fru,
				 time_t     time)
{
    GET_DATA_PREFIX(board_info, BOARD_INFO);
    
    rec->changed |= u->mfg_time != time;
    u->mfg_time = time;

    _ipmi_fru_unlock(fru);

    return 0;
}

GET_DATA_STR(board_info, BOARD_INFO, board_manufacturer)
GET_DATA_STR(board_info, BOARD_INFO, board_product_name)
GET_DATA_STR(board_info, BOARD_INFO, board_serial_number)
GET_DATA_STR(board_info, BOARD_INFO, board_part_number)
GET_DATA_STR(board_info, BOARD_INFO, fru_file_id)
GET_CUSTOM_STR(board_info, BOARD_INFO)

static int
fru_encode_board_info_area(ipmi_fru_t *fru, unsigned char *data)
{
    ipmi_fru_record_t **recs = normal_fru_get_recs(fru);
    ipmi_fru_record_t *rec = recs[IPMI_FRU_FTR_BOARD_INFO_AREA];
    ipmi_fru_board_info_area_t *u;
    int               rv;

    if (!rec)
	return 0;

    u = fru_record_get_data(rec);
    data += rec->offset;
    data[0] = 1; /* Version */
    data[1] = rec->length / 8;
    data[2] = u->lang_code;
    write_fru_time(data+3, u->mfg_time);
    
    if (rec->changed && !rec->rewrite) {
	rv = _ipmi_fru_new_update_record(fru, rec->offset, 6);
	if (rv)
	    return rv;
    }
    rv = fru_encode_fields(fru, rec, &u->fields, data, 6);
    if (rv)
	return rv;
    data[rec->length-1] = -checksum(data, rec->length-1);
    if (rec->changed && !rec->rewrite) {
	/* Write any zeros that need to be written if the data got
	   shorter.  Subtract off 1 for the checksum since it is in
	   the used length */
	if (rec->used_length < rec->orig_used_length) {
	    rv = _ipmi_fru_new_update_record(fru,
					     rec->offset + rec->used_length - 1,
					     (rec->orig_used_length
					      - rec->used_length));
	    if (rv)
		return rv;
	}
	/* Write the checksum */
	rv = _ipmi_fru_new_update_record(fru, rec->offset+rec->length-1, 1);
	if (rv)
	    return rv;
    }
    return 0;
}

/***********************************************************************
 *
 * Handling for FRU product info areas
 *
 **********************************************************************/

#define PRODUCT_INFO_manufacturer_name		0
#define PRODUCT_INFO_product_name		1
#define PRODUCT_INFO_product_part_model_number	2
#define PRODUCT_INFO_product_version		3
#define PRODUCT_INFO_product_serial_number	4
#define PRODUCT_INFO_asset_tag			5
#define PRODUCT_INFO_fru_file_id		6
#define PRODUCT_INFO_custom_start		7

typedef struct ipmi_fru_product_info_area_s
{
    /* version bit 7-4 reserved (0000), bit 3-0 == 0001 */
    unsigned char  version;
    unsigned char  lang_code;
    fru_variable_t fields;
} ipmi_fru_product_info_area_t;

static void
product_info_area_free(ipmi_fru_record_t *rec)
{
    ipmi_fru_product_info_area_t *u = fru_record_get_data(rec);

    fru_free_variable_string(&u->fields);
    fru_record_free(rec);
}

static int
product_info_area_setup(ipmi_fru_record_t *rec, int full_init)
{
    ipmi_fru_product_info_area_t *u = fru_record_get_data(rec);

    u->version = 1;
    if (full_init) {
	u->lang_code = 0;
    }
    return 0;
}

static fru_variable_t *
product_info_get_fields(ipmi_fru_record_t *rec)
{
    ipmi_fru_product_info_area_t *u;
    u = fru_record_get_data(rec);
    return &u->fields;
}

static int
fru_decode_product_info_area(ipmi_fru_t        *fru,
			     unsigned char     *data,
			     unsigned int      data_len,
			     ipmi_fru_record_t **rrec)
{
    ipmi_fru_product_info_area_t *u;
    ipmi_fru_record_t            *rec;
    int                          err;
    unsigned char                version;
    unsigned int                 length;
    unsigned char                *orig_data = data;

    version = *data;
    length = (*(data+1)) * 8;
    if ((length == 0) || (length > data_len)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%snormal_fru.c(fru_decode_product_info_area):"
		 " FRU string goes past data length",
		 _ipmi_fru_get_iname(fru));
	return EBADF;
    }

    if (checksum(data, length) != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%snormal_fru.c(fru_decode_product_info_area):"
		 " FRU string checksum failed",
		 _ipmi_fru_get_iname(fru));
	return EBADF;
    }

    data_len--; /* remove the checksum */

    rec = fru_record_alloc(IPMI_FRU_FTR_PRODUCT_INFO_AREA, 0, length);
    if (!rec)
	return ENOMEM;

    err = fru_setup_min_field(rec, IPMI_FRU_FTR_PRODUCT_INFO_AREA, 0);
    if (err)
	goto out_err;

    u = fru_record_get_data(rec);

    u->version = version;
    data += 2;
    data_len -= 2;
    u->lang_code = *data;
    if (u->lang_code == 0)
	u->lang_code = IPMI_LANG_CODE_ENGLISH;
    data++;
    data_len--;
    HANDLE_STR_DECODE(PRODUCT_INFO, manufacturer_name, 0);
    HANDLE_STR_DECODE(PRODUCT_INFO, product_name, 0);
    HANDLE_STR_DECODE(PRODUCT_INFO, product_part_model_number, 0);
    HANDLE_STR_DECODE(PRODUCT_INFO, product_version, 0);
    HANDLE_STR_DECODE(PRODUCT_INFO, product_serial_number, 1);
    HANDLE_STR_DECODE(PRODUCT_INFO, asset_tag, 0);
    HANDLE_STR_DECODE(PRODUCT_INFO, fru_file_id, 1);
    HANDLE_CUSTOM_DECODE(PRODUCT_INFO);
    rec->used_length = data - orig_data + 2; /* add 1 for the checksum, 1 for term */
    rec->orig_used_length = rec->used_length;

    *rrec = rec;

    return 0;

 out_err:
    product_info_area_free(rec);
    return err;
}

int 
ipmi_fru_get_product_info_version(ipmi_fru_t    *fru,
				  unsigned char *version)
{
    GET_DATA_PREFIX(product_info, PRODUCT_INFO);
    
    *version = u->version;

    _ipmi_fru_unlock(fru);

    return 0;
}

static int
ipmi_fru_set_product_info_version(ipmi_fru_t *fru, unsigned char data)
{
    return EPERM;
}

int 
ipmi_fru_get_product_info_lang_code(ipmi_fru_t    *fru,
				    unsigned char *type)
{
    GET_DATA_PREFIX(product_info, PRODUCT_INFO);
    
    *type = u->lang_code;

    _ipmi_fru_unlock(fru);

    return 0;
}

int 
ipmi_fru_set_product_info_lang_code(ipmi_fru_t    *fru,
				    unsigned char lang)
{
    GET_DATA_PREFIX(product_info, PRODUCT_INFO);
    
    rec->changed |= u->lang_code != lang;
    u->lang_code = lang;

    _ipmi_fru_unlock(fru);

    return 0;
}

GET_DATA_STR(product_info, PRODUCT_INFO, manufacturer_name)
GET_DATA_STR(product_info, PRODUCT_INFO, product_name)
GET_DATA_STR(product_info, PRODUCT_INFO, product_part_model_number)
GET_DATA_STR(product_info, PRODUCT_INFO, product_version)
GET_DATA_STR(product_info, PRODUCT_INFO, product_serial_number)
GET_DATA_STR(product_info, PRODUCT_INFO, asset_tag)
GET_DATA_STR(product_info, PRODUCT_INFO, fru_file_id)
GET_CUSTOM_STR(product_info, PRODUCT_INFO)

static int
fru_encode_product_info_area(ipmi_fru_t *fru, unsigned char *data)
{
    ipmi_fru_record_t **recs = normal_fru_get_recs(fru);
    ipmi_fru_record_t *rec = recs[IPMI_FRU_FTR_PRODUCT_INFO_AREA];
    ipmi_fru_product_info_area_t *u;
    int               rv;

    if (!rec)
	return 0;

    u = fru_record_get_data(rec);
    data += rec->offset;
    memset(data, 0, rec->length);
    data[0] = 1; /* Version */
    data[1] = rec->length / 8;
    data[2] = u->lang_code;
    
    if (rec->changed && !rec->rewrite) {
	rv = _ipmi_fru_new_update_record(fru, rec->offset, 3);
	if (rv)
	    return rv;
    }
    rv = fru_encode_fields(fru, rec, &u->fields, data, 3);
    if (rv)
	return rv;
	/* Write any zeros that need to be written if the data got
	   shorter. */
    data[rec->length-1] = -checksum(data, rec->length-1);
    if (rec->changed && !rec->rewrite) {
	if (rec->used_length < rec->orig_used_length) {
	    rv = _ipmi_fru_new_update_record(fru,
					     rec->offset + rec->used_length - 1,
					     (rec->orig_used_length
					      - rec->used_length));
	    if (rv)
		return rv;
	}
	/* Write the checksum */
	rv = _ipmi_fru_new_update_record(fru, rec->offset+rec->length-1, 1);
	if (rv)
	    return rv;
    }
    return 0;
}

/***********************************************************************
 *
 * Handling for FRU multi-records
 *
 **********************************************************************/
typedef struct ipmi_fru_record_elem_s
{
    /* Where relative to the beginning of the record area does this
       record start? */
    unsigned int  offset;

    /* Has this record been changed (needs to be written)? */
    char          changed;

    unsigned char type;
    unsigned char format_version;
    unsigned char length;
    unsigned char *data;
} ipmi_fru_record_elem_t;

typedef struct ipmi_fru_multi_record_s
{
    /* Actual length of the array. */
    unsigned int           rec_len;

    /* Number of used elements in the array */
    unsigned int           num_records;
    ipmi_fru_record_elem_t *records;

    /* Dummy field to keep the macros happy */
    int                    version;
} ipmi_fru_multi_record_area_t;

static void
multi_record_area_free(ipmi_fru_record_t *rec)
{
    ipmi_fru_multi_record_area_t *u = fru_record_get_data(rec);
    unsigned int                 i;

    if (u->records) {
	for (i=0; i<u->num_records; i++) {
	    if (u->records[i].data)
		ipmi_mem_free(u->records[i].data);
	}
	ipmi_mem_free(u->records);
    }
    fru_record_free(rec);
}

static int
fru_decode_multi_record_area(ipmi_fru_t        *fru,
			     unsigned char     *data,
			     unsigned int      data_len,
			     ipmi_fru_record_t **rrec)
{
    ipmi_fru_record_t       *rec;
    int                     err;
    unsigned int            i;
    unsigned int            num_records;
    unsigned char           *orig_data = data;
    unsigned int            orig_data_len = data_len;
    ipmi_fru_multi_record_area_t *u;
    ipmi_fru_record_elem_t  *r;
    unsigned char           sum;
    unsigned int            length;
    unsigned int            start_offset = 0;
    unsigned int            left = data_len;

    /* First scan for the number of records. */
    num_records = 0;
    for (;;) {
	unsigned char eol;

	if (left < 5) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%snormal_fru.c(fru_decode_multi_record_area):"
		     " Data not long enough for multi record",
		     _ipmi_fru_get_iname(fru));
	    return EBADF;
	}

	if (checksum(data, 5) != 0) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%snormal_fru.c(fru_decode_multi_record_area):"
		     " Header checksum for record %d failed",
		     _ipmi_fru_get_iname(fru), num_records+1);
	    return EBADF;
	}

	length = data[2];
	if ((length + 5) > left) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%snormal_fru.c(fru_decode_multi_record_area):"
		     " Record went past end of data",
		     _ipmi_fru_get_iname(fru));
	    return EBADF;
	}

	sum = checksum(data+5, length) + data[3];
	if (sum != 0) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%snormal_fru.c(fru_decode_multi_record_area):"
		     " Data checksum for record %d failed",
		     _ipmi_fru_get_iname(fru), num_records+1);
	    return EBADF;
	}

	num_records++;

	eol = data[1] & 0x80;

	data += length + 5;
	left -= length + 5;

	if (eol)
	    /* End of list */
	    break;
    }

    rec = fru_record_alloc(IPMI_FRU_FTR_MULTI_RECORD_AREA, 0, data_len);
    if (!rec)
	return ENOMEM;

    rec->used_length = data - orig_data;
    rec->orig_used_length = rec->used_length;

    u = fru_record_get_data(rec);
    u->num_records = num_records;
    u->rec_len = num_records;
    u->records = ipmi_mem_alloc(sizeof(ipmi_fru_record_elem_t) * num_records);
    if (!u->records) {
	err = ENOMEM;
	goto out_err;
    }
    memset(u->records, 0, sizeof(ipmi_fru_record_elem_t) * num_records);

    data = orig_data;
    data_len = orig_data_len;
    for (i=0; i<num_records; i++) {
	/* No checks required, they've already been done above. */
	length = data[2];
	r = u->records + i;
	if (length == 0)
	    r->data = ipmi_mem_alloc(1);
	else
	    r->data = ipmi_mem_alloc(length);
	if (!r->data) {
	    err = ENOMEM;
	    goto out_err;
	}

	memcpy(r->data, data+5, length);
	r->length = length;
	r->type = data[0];
	r->format_version = data[1] & 0xf;
	r->offset = start_offset;

	data += length + 5;
	start_offset += length + 5;
    }

    *rrec = rec;

    return 0;

 out_err:
    multi_record_area_free(rec);
    return err;
}

unsigned int
ipmi_fru_get_num_multi_records(ipmi_fru_t *fru)
{
    ipmi_fru_record_t            **recs;
    ipmi_fru_multi_record_area_t *u;
    unsigned int                 num;

    if (!_ipmi_fru_is_normal_fru(fru))
	return 0;

    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    if (!recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]) {
	_ipmi_fru_unlock(fru);
	return 0;
    }

    u = fru_record_get_data(recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]);
    num = u->num_records;
    _ipmi_fru_unlock(fru);
    return num;
}

static int
validate_and_lock_multi_record(ipmi_fru_t                   *fru,
			       unsigned int                 num,
			       ipmi_fru_multi_record_area_t **ru,
			       ipmi_fru_record_t            **rrec)
{
    ipmi_fru_record_t            **recs;
    ipmi_fru_multi_record_area_t *u;

    if (!_ipmi_fru_is_normal_fru(fru))
	return ENOSYS;

    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    if (!recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]) {
	_ipmi_fru_unlock(fru);
	return ENOSYS;
    }
    u = fru_record_get_data(recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]);
    if (num >= u->num_records) {
	_ipmi_fru_unlock(fru);
	return E2BIG;
    }
    *ru = u;
    if (rrec)
	*rrec = recs[IPMI_FRU_FTR_MULTI_RECORD_AREA];
    return 0;
}

int
ipmi_fru_get_multi_record_type(ipmi_fru_t    *fru,
			       unsigned int  num,
			       unsigned char *type)
{
    ipmi_fru_multi_record_area_t *u;
    int                          rv;

    rv = validate_and_lock_multi_record(fru, num, &u, NULL);
    if (rv)
	return rv;
    *type = u->records[num].type;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_set_multi_record_type(ipmi_fru_t    *fru,
			       unsigned int  num,
			       unsigned char type)
{
    ipmi_fru_multi_record_area_t *u;
    int                          rv;

    rv = validate_and_lock_multi_record(fru, num, &u, NULL);
    if (rv)
	return rv;
    u->records[num].type = type;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_get_multi_record_format_version(ipmi_fru_t    *fru,
					 unsigned int  num,
					 unsigned char *ver)
{
    ipmi_fru_multi_record_area_t *u;
    int                          rv;

    rv = validate_and_lock_multi_record(fru, num, &u, NULL);
    if (rv)
	return rv;
    *ver = u->records[num].format_version;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_get_multi_record_data_len(ipmi_fru_t   *fru,
				   unsigned int num,
				   unsigned int *len)
{
    ipmi_fru_multi_record_area_t *u;
    int                          rv;

    rv = validate_and_lock_multi_record(fru, num, &u, NULL);
    if (rv)
	return rv;
    *len = u->records[num].length;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_get_multi_record_data(ipmi_fru_t    *fru,
			       unsigned int  num,
			       unsigned char *data,
			       unsigned int  *length)
{
    ipmi_fru_multi_record_area_t *u;
    int                          rv;

    rv = validate_and_lock_multi_record(fru, num, &u, NULL);
    if (rv)
	return rv;
    if (*length < u->records[num].length) {
	_ipmi_fru_unlock(fru);
	return EINVAL;
    }
    memcpy(data, u->records[num].data, u->records[num].length);
    *length = u->records[num].length;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_get_multi_record_slice(ipmi_fru_t    *fru,
				unsigned int  num,
				unsigned int  offset,
				unsigned int  length,
				unsigned char *data)
{
    ipmi_fru_multi_record_area_t *u;
    int                          rv;

    rv = validate_and_lock_multi_record(fru, num, &u, NULL);
    if (rv)
	return rv;

    if ((offset + length) > u->records[num].length) {
	_ipmi_fru_unlock(fru);
	return EINVAL;
    }

    memcpy(data, u->records[num].data+offset, length);
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_set_multi_record_data(ipmi_fru_t    *fru,
			       unsigned int  num,
			       unsigned char *data,
			       unsigned int  length)
{
    ipmi_fru_multi_record_area_t *u;
    ipmi_fru_record_t            *rec;
    int                          raw_diff;
    unsigned int                 i;
    unsigned char                *new_data;
    int                          rv;

    if (length > 255)
	return EINVAL;

    rv = validate_and_lock_multi_record(fru, num, &u, &rec);
    if (rv)
	return rv;

    raw_diff = length - u->records[num].length;

    /* Is there enough space? */
    if ((rec->used_length + raw_diff) > rec->length)
	return ENOSPC;

    /* Modifying the record. */
    if (length == 0)
	new_data = ipmi_mem_alloc(1);
    else
	new_data = ipmi_mem_alloc(length);
    if (!new_data) {
	_ipmi_fru_unlock(fru);
	return ENOMEM;
    }
    memcpy(new_data, data, length);
    if (u->records[num].data)
	ipmi_mem_free(u->records[num].data);
    u->records[num].data = new_data;
    u->records[num].length = length;
    if (raw_diff) {
	for (i=num+1; i<u->num_records; i++) {
	    u->records[i].offset += raw_diff;
	    u->records[i].changed = 1;
	}
    }

    rec->used_length += raw_diff;
    rec->changed |= 1;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_set_multi_record(ipmi_fru_t    *fru,
			  unsigned int  num,
			  unsigned char type,
			  unsigned char version,
			  unsigned char *data,
			  unsigned int  length)
{
    normal_fru_rec_data_t        *info = _ipmi_fru_get_rec_data(fru);
    ipmi_fru_record_t            **recs;
    ipmi_fru_multi_record_area_t *u;
    unsigned char                *new_data;
    ipmi_fru_record_t            *rec;
    int                          raw_diff = 0;
    unsigned int                 i;

    if (data && version != 2)
	return EINVAL;

    if (length > 255)
	return EINVAL;

    if (!_ipmi_fru_is_normal_fru(fru))
	return ENOSYS;

    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    rec = recs[IPMI_FRU_FTR_MULTI_RECORD_AREA];
    if (!rec) {
	_ipmi_fru_unlock(fru);
	return ENOSYS;
    }

    u = fru_record_get_data(rec);

    if (num >= u->num_records) {
	if (!data) {
	    /* Don't expand if we are deleting an invalid field,
	       return an error. */
	    _ipmi_fru_unlock(fru);
	    return EINVAL;
	}

	num = u->num_records;
	/* If not enough room, expand the array by a set amount (to
	   keep from thrashing memory when adding lots of things). */
	if (u->num_records >= u->rec_len) {
	    unsigned int           new_len = u->rec_len + 16;
	    ipmi_fru_record_elem_t *new_recs;

	    new_recs = ipmi_mem_alloc(new_len * sizeof(*new_recs));
	    if (!new_recs) {
		_ipmi_fru_unlock(fru);
		return ENOMEM;
	    }
	    memset(new_recs, 0, new_len * sizeof(*new_recs));
	    if (u->records) {
		memcpy(new_recs, u->records, u->rec_len * sizeof(*new_recs));
		ipmi_mem_free(u->records);
	    }
	    u->records = new_recs;
	    u->rec_len = new_len;
	}
	if (u->num_records == 0)
	    info->header_changed = 1;
	u->num_records++;
	u->records[num].offset = rec->used_length;
	u->records[num].length = 0;
	u->records[num].changed = 1;
	u->records[num].data = NULL;
	raw_diff = 5; /* Header size */
    }

    if (data) {
	raw_diff += length - u->records[num].length;

	/* Is there enough space? */
	if ((rec->used_length + raw_diff) > rec->length)
	    return ENOSPC;

	/* Modifying the record. */
	if (length == 0)
	    new_data = ipmi_mem_alloc(1);
	else
	    new_data = ipmi_mem_alloc(length);
	if (!new_data) {
	    _ipmi_fru_unlock(fru);
	    return ENOMEM;
	}
	memcpy(new_data, data, length);
	if (u->records[num].data)
	    ipmi_mem_free(u->records[num].data);
	u->records[num].data = new_data;
	u->records[num].type = type;
	u->records[num].format_version = version;
	u->records[num].length = length;
	if (raw_diff) {
	    for (i=num+1; i<u->num_records; i++) {
		u->records[i].offset += raw_diff;
		u->records[i].changed = 1;
	    }
	}
    } else {
	/* Deleting the record. */
	if (u->records[num].data)
	    ipmi_mem_free(u->records[num].data);
	u->num_records--;
	raw_diff = - (5 + u->records[num].length);
	for (i=num; i<u->num_records; i++) {
	    u->records[i] = u->records[i+1];
	    u->records[i].offset += raw_diff;
	    u->records[i].changed = 1;
	}
	if (u->num_records == 0)
	    /* Need to write "0" for the multi-records. */
	    info->header_changed = 1;
    }

    rec->used_length += raw_diff;
    rec->changed |= 1;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_ins_multi_record(ipmi_fru_t    *fru,
			  unsigned int  num,
			  unsigned char type,
			  unsigned char version,
			  unsigned char *data,
			  unsigned int  length)
{
    normal_fru_rec_data_t        *info = _ipmi_fru_get_rec_data(fru);
    ipmi_fru_record_t            **recs;
    ipmi_fru_multi_record_area_t *u;
    unsigned char                *new_data;
    ipmi_fru_record_t            *rec;
    int                          raw_diff = 0;
    unsigned int                 i;
    int                          offset;

    if (data && version != 2)
	return EINVAL;

    if (length > 255)
	return EINVAL;

    if (!_ipmi_fru_is_normal_fru(fru))
	return ENOSYS;

    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    rec = recs[IPMI_FRU_FTR_MULTI_RECORD_AREA];
    if (!rec) {
	_ipmi_fru_unlock(fru);
	return ENOSYS;
    }

    u = fru_record_get_data(rec);

    if (num >= u->num_records) {
	num = u->num_records;
	/* If not enough room, expand the array by a set amount (to
	   keep from thrashing memory when adding lots of things). */
	if (u->num_records >= u->rec_len) {
	    unsigned int           new_len = u->rec_len + 16;
	    ipmi_fru_record_elem_t *new_recs;

	    new_recs = ipmi_mem_alloc(new_len * sizeof(*new_recs));
	    if (!new_recs) {
		_ipmi_fru_unlock(fru);
		return ENOMEM;
	    }
	    memset(new_recs, 0, new_len * sizeof(*new_recs));
	    if (u->records) {
		memcpy(new_recs, u->records, u->rec_len * sizeof(*new_recs));
		ipmi_mem_free(u->records);
	    }
	    u->records = new_recs;
	    u->rec_len = new_len;
	}
    }

    raw_diff = 5 + length;

    /* Is there enough space? */
    if ((rec->used_length + raw_diff) > rec->length)
	return ENOSPC;

    /* Modifying the record. */
    if (length == 0)
	new_data = ipmi_mem_alloc(1);
    else
	new_data = ipmi_mem_alloc(length);
    if (!new_data) {
	_ipmi_fru_unlock(fru);
	return ENOMEM;
    }
    memcpy(new_data, data, length);

    if (num == u->num_records)
	offset = rec->used_length;
    else
	offset = u->records[num].offset;

    for (i=u->num_records; i>num; i--) {
	u->records[i] = u->records[i-1];
	u->records[i].offset += raw_diff;
	u->records[i].changed = 1;
    }

    if (u->num_records == 0)
	info->header_changed = 1;
    u->num_records++;
    u->records[num].offset = offset;
    u->records[num].changed = 1;
    u->records[num].data = new_data;
    u->records[num].type = type;
    u->records[num].format_version = version;
    u->records[num].length = length;

    rec->used_length += raw_diff;
    rec->changed |= 1;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_ovw_multi_record_data(ipmi_fru_t    *fru,
			       unsigned int  num,
			       unsigned char *data,
			       unsigned int  offset,
			       unsigned int  length)
{
    ipmi_fru_multi_record_area_t *u;
    ipmi_fru_record_t            *rec;
    int                          rv;

    rv = validate_and_lock_multi_record(fru, num, &u, &rec);
    if (rv)
	return rv;

    if ((offset + length) > u->records[num].length) {
	_ipmi_fru_unlock(fru);
	return EINVAL;
    }

    memcpy(u->records[num].data+offset, data, length);
    rec->changed |= 1;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_ins_multi_record_data(ipmi_fru_t    *fru,
			       unsigned int  num,
			       unsigned char *data,
			       unsigned int  offset,
			       unsigned int  length)
{
    ipmi_fru_multi_record_area_t *u;
    ipmi_fru_record_t            *rec;
    int                          new_length;
    unsigned int                 i;
    unsigned char                *new_data;
    int                          rv;

    rv = validate_and_lock_multi_record(fru, num, &u, &rec);
    if (rv)
	return rv;

    if (offset > u->records[num].length) {
	_ipmi_fru_unlock(fru);
	return EINVAL;
    }

    new_length = length + u->records[num].length;
    if (new_length > 255) {
	_ipmi_fru_unlock(fru);
	return EINVAL;
    }

    /* Is there enough space? */
    if ((rec->used_length + length) > rec->length) {
	_ipmi_fru_unlock(fru);
	return ENOSPC;
    }

    /* Modifying the record. */
    if (length == 0)
	new_data = ipmi_mem_alloc(1);
    else
	new_data = ipmi_mem_alloc(new_length);
    if (!new_data) {
	_ipmi_fru_unlock(fru);
	return ENOMEM;
    }
    if (u->records[num].data) {
	memcpy(new_data, u->records[num].data, offset);
	memcpy(new_data+offset+length, u->records[num].data+offset,
	       u->records[num].length-offset);
	ipmi_mem_free(u->records[num].data);
    }
    memcpy(new_data+offset, data, length);
    u->records[num].data = new_data;
    u->records[num].length = new_length;
    u->records[num].changed = 1;
    if (length) {
	for (i=num+1; i<u->num_records; i++) {
	    u->records[i].offset += length;
	    u->records[i].changed = 1;
	}
    }

    rec->used_length += length;
    rec->changed |= 1;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_del_multi_record_data(ipmi_fru_t    *fru,
			       unsigned int  num,
			       unsigned int  offset,
			       unsigned int  length)
{
    ipmi_fru_multi_record_area_t *u;
    ipmi_fru_record_t            *rec;
    int                          new_length;
    unsigned int                 i;
    unsigned char                *new_data;
    int                          rv;

    rv = validate_and_lock_multi_record(fru, num, &u, &rec);
    if (rv)
	return rv;

    if ((offset + length) > u->records[num].length) {
	_ipmi_fru_unlock(fru);
	return EINVAL;
    }

    new_length = u->records[num].length - length;
    if (new_length < 0) {
	_ipmi_fru_unlock(fru);
	return EINVAL;
    }

    /* Modifying the record. */
    if (new_length == 0)
	new_data = ipmi_mem_alloc(1);
    else
	new_data = ipmi_mem_alloc(new_length);
    if (!new_data) {
	_ipmi_fru_unlock(fru);
	return ENOMEM;
    }
    if (u->records[num].data) {
	memcpy(new_data, u->records[num].data, offset);
	memcpy(new_data+offset, u->records[num].data+offset+length,
	       u->records[num].length-offset-length);
	ipmi_mem_free(u->records[num].data);
    }

    u->records[num].data = new_data;
    u->records[num].length = new_length;
    if (length) {
	for (i=num+1; i<u->num_records; i++) {
	    u->records[i].offset -= length;
	    u->records[i].changed = 1;
	}
    }

    rec->used_length -= length;
    rec->changed |= 1;
    _ipmi_fru_unlock(fru);
    return 0;
}

static int
fru_encode_multi_record(ipmi_fru_t             *fru,
			ipmi_fru_record_t      *rec,
			ipmi_fru_multi_record_area_t *u,
			unsigned int           idx,
			unsigned char          *data,
			unsigned int           *offset)
{
    unsigned int           o = *offset;
    ipmi_fru_record_elem_t *elem = u->records + idx;
    int                    rv;

    if (o != elem->offset)
	return EBADF;

    data += o;
    data[0] = elem->type;
    data[1] = 2; /* Version */
    if (idx+1 == u->num_records)
	data[1] |= 0x80; /* Last record */
    data[2] = elem->length;
    data[3] = -checksum(elem->data, elem->length);
    data[4] = -checksum(data, 4);
    memcpy(data+5, elem->data, elem->length);

    if (rec->changed && !rec->rewrite) {
	rv = _ipmi_fru_new_update_record(fru, rec->offset+elem->offset,
					 elem->length+5);
	if (rv)
	    return rv;
    }

    *offset = o + elem->length + 5;
    return 0;
}

static int
fru_encode_multi_record_area(ipmi_fru_t *fru, unsigned char *data)
{
    ipmi_fru_record_t **recs = normal_fru_get_recs(fru);
    ipmi_fru_record_t *rec = recs[IPMI_FRU_FTR_MULTI_RECORD_AREA];
    ipmi_fru_multi_record_area_t *u;
    int               rv;
    unsigned int      i;
    unsigned int      offset;

    if (!rec)
	return 0;

    u = fru_record_get_data(rec);
    data += rec->offset;
    memset(data, 0, rec->length);

    if (u->num_records == 0)
	return 0;
    
    offset = 0;
    for (i=0; i<u->num_records; i++) {
	rv = fru_encode_multi_record(fru, rec, u, i, data, &offset);
	if (rv)
	    return rv;
    }
    return 0;
}


/***********************************************************************
 *
 * Area processing
 *
 **********************************************************************/

static fru_area_info_t fru_area_info[IPMI_FRU_FTR_NUMBER] = 
{
    { 0, 0,  1, NULL,                    internal_use_area_free,
      sizeof(ipmi_fru_internal_use_area_t),
      fru_decode_internal_use_area, fru_encode_internal_use_area,
      internal_use_area_setup },
    { 2, 3,  7, chassis_info_get_fields, chassis_info_area_free,
      sizeof(ipmi_fru_chassis_info_area_t),
      fru_decode_chassis_info_area, fru_encode_chassis_info_area,
      chassis_info_area_setup },
    { 5, 6, 13, board_info_get_fields,   board_info_area_free,
      sizeof(ipmi_fru_board_info_area_t),
      fru_decode_board_info_area, fru_encode_board_info_area,
      board_info_area_setup },
    { 7, 3, 12, product_info_get_fields, product_info_area_free,
      sizeof(ipmi_fru_product_info_area_t),
      fru_decode_product_info_area, fru_encode_product_info_area,
      product_info_area_setup },
    { 0, 0,  0, NULL,                    multi_record_area_free,
      sizeof(ipmi_fru_multi_record_area_t),
      fru_decode_multi_record_area, fru_encode_multi_record_area,
      NULL },
};

static int
check_rec_position(ipmi_fru_t   *fru,
		   int          recn,
		   unsigned int offset,
		   unsigned int length)
{
    ipmi_fru_record_t **recs = normal_fru_get_recs(fru);
    int               pos;
    unsigned int      data_len = _ipmi_fru_get_data_len(fru);
    unsigned int      max_start = data_len - 8;

    /* Zero is invalid, and it must be a multiple of 8. */
    if ((offset == 0) || ((offset % 8) != 0))
	return EINVAL;

    /* Make sure the used area still fits. */
    if (recs[recn] && (length < recs[recn]->used_length))
	return E2BIG;

    /* FRU data record starts cannot exceed 2040 bytes.  The offsets
       are in multiples of 8 and the sizes are 8-bits, thus 8 *
       255.  The end of the data can go till the end of the FRU. */
    if (max_start > 2040)
	max_start = 2040;
    if ((offset > max_start) || ((offset + length) > data_len))
	return EINVAL;

    /* Check that this is not in the previous record's space. */
    pos = recn - 1;
    while ((pos >= 0) && !recs[pos])
	pos--;
    if (pos >= 0) {
	if (offset < (recs[pos]->offset + recs[pos]->length))
	    return EINVAL;
    }

    /* Check that this is not in the next record's space. */
    pos = recn + 1;
    while ((pos < IPMI_FRU_FTR_NUMBER) && !recs[pos])
	pos++;
    if (pos < IPMI_FRU_FTR_NUMBER) {
	if ((offset + length) > recs[pos]->offset)
	    return EINVAL;
    }

    return 0;
}

int
ipmi_fru_add_area(ipmi_fru_t   *fru,
		  unsigned int area,
		  unsigned int offset,
		  unsigned int length)
{
    normal_fru_rec_data_t *info = _ipmi_fru_get_rec_data(fru);
    ipmi_fru_record_t     **recs;
    ipmi_fru_record_t     *rec;
    int                   rv;

    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;

    if (!_ipmi_fru_is_normal_fru(fru)) {
	/* This was not a normal FRU.  Convert it over to a normal one. */
	info = setup_normal_fru(fru, 1);
	if (!info)
	    return ENOMEM;
    }

    if (length == 0)
	length = fru_area_info[area].empty_length;

    /* Round up the length to a multiple of 8. */
    length = (length + 7) & ~(8-1);

    if (length < fru_area_info[area].empty_length)
	return EINVAL;

    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    if (recs[area]) {
	_ipmi_fru_unlock(fru);
	return EEXIST;
    }

    rv = check_rec_position(fru, area, offset, length);
    if (rv) {
	_ipmi_fru_unlock(fru);
	return rv;
    }

    rec = fru_record_alloc(area, 1, length);
    if (!rec) {
	_ipmi_fru_unlock(fru);
	return ENOMEM;
    }
    rec->changed = 1;
    rec->rewrite = 1;
    rec->used_length = fru_area_info[area].empty_length;
    rec->orig_used_length = rec->used_length;
    rec->offset = offset;
    info->header_changed = 1;

    rv = fru_setup_min_field(rec, area, 1);
    if (rv) {
	_ipmi_fru_unlock(fru);
	return rv;
    }

    recs[area] = rec;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_delete_area(ipmi_fru_t *fru, int area)
{
    ipmi_fru_record_t **recs;

    if (!_ipmi_fru_is_normal_fru(fru))
	return ENOSYS;

    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;

    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    fru_record_destroy(recs[area]); 
    recs[area] = NULL;
    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_area_get_offset(ipmi_fru_t   *fru,
			 unsigned int area,
			 unsigned int *offset)
{
    ipmi_fru_record_t **recs;

    if (!_ipmi_fru_is_normal_fru(fru))
	return ENOSYS;

    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;
    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    if (!recs[area]) {
	_ipmi_fru_unlock(fru);
	return ENOENT;
    }

    *offset = recs[area]->offset;

    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_area_get_length(ipmi_fru_t   *fru,
			 unsigned int area,
			 unsigned int *length)
{
    ipmi_fru_record_t **recs;

    if (!_ipmi_fru_is_normal_fru(fru))
	return ENOSYS;

    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;

    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    if (!recs[area]) {
	_ipmi_fru_unlock(fru);
	return ENOENT;
    }

    *length = recs[area]->length;

    _ipmi_fru_unlock(fru);
    return 0;
}

int
ipmi_fru_area_set_offset(ipmi_fru_t   *fru,
			 unsigned int area,
			 unsigned int offset)
{
    normal_fru_rec_data_t *info = _ipmi_fru_get_rec_data(fru);
    ipmi_fru_record_t     **recs;
    int                   rv;

    if (!_ipmi_fru_is_normal_fru(fru))
	return ENOSYS;

    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;

    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    if (!recs[area]) {
	_ipmi_fru_unlock(fru);
	return ENOENT;
    }

    if (recs[area]->offset == offset) {
	_ipmi_fru_unlock(fru);
	return 0;
    }

    if (area == IPMI_FRU_FTR_MULTI_RECORD_AREA) {
	/* Multi-record lengths are not defined, but just goto the end.
	   So adjust the length for comparison here. */
	int newlength = (recs[area]->length
			 + recs[area]->offset - offset);
	rv = check_rec_position(fru, area, offset, newlength);
    } else {
	rv = check_rec_position(fru, area, offset, recs[area]->length);
    }
    if (!rv) {
	if (area == IPMI_FRU_FTR_MULTI_RECORD_AREA)
	    recs[area]->length += recs[area]->offset - offset;
	recs[area]->offset = offset;
	recs[area]->changed = 1;
	recs[area]->rewrite = 1;
	info->header_changed = 1;
    }

    _ipmi_fru_unlock(fru);
    return rv;
}

int
ipmi_fru_area_set_length(ipmi_fru_t   *fru,
			 unsigned int area,
			 unsigned int length)
{
    ipmi_fru_record_t **recs;
    int               rv;

    if (!_ipmi_fru_is_normal_fru(fru))
	return ENOSYS;

    /* Truncate the length to a multiple of 8. */
    length = length & ~(8-1);

    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;
    if (length == 0)
	return EINVAL;
    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    if (!recs[area]) {
	_ipmi_fru_unlock(fru);
	return ENOENT;
    }

    if (recs[area]->length == length) {
	_ipmi_fru_unlock(fru);
	return 0;
    }

    rv = check_rec_position(fru, area, recs[area]->offset, length);
    if (!rv) {
	if (length > recs[area]->length)
	    /* Only need to rewrite the whole record (to get the zeroes
	       into the unused area) if we increase the length. */
	    recs[area]->rewrite = 1;
	recs[area]->length = length;
	recs[area]->changed = 1;
    }

    _ipmi_fru_unlock(fru);
    return rv;
}

#define AREA_GENERIC(n1, n2) \
static int								      \
ipmi_fru_get_ ## n1 ## _offset(ipmi_fru_t *fru, int *offset)		      \
{									      \
    unsigned int v;							      \
    int          rv;							      \
    rv = ipmi_fru_area_get_offset(fru, IPMI_FRU_FTR_ ## n2 ##_AREA, &v);      \
    if (rv == ENOENT) {							      \
	rv = 0;								      \
	*offset = 0;							      \
    } else if (!rv)							      \
	*offset = v;							      \
    return rv;								      \
}									      \
static int								      \
ipmi_fru_set_ ## n1 ## _offset(ipmi_fru_t *fru, int offset)		      \
{									      \
    int rv;								      \
    if (offset == 0) {							      \
	rv = ipmi_fru_delete_area(fru, IPMI_FRU_FTR_ ## n2 ##_AREA);	      \
	return rv;							      \
    }									      \
    rv = ipmi_fru_area_set_offset(fru, IPMI_FRU_FTR_ ## n2 ##_AREA, offset);  \
    if (rv == ENOENT)							      \
	rv = ipmi_fru_add_area(fru, IPMI_FRU_FTR_ ## n2 ##_AREA, offset, 0);  \
    return rv;								      \
}									      \
static int								      \
ipmi_fru_get_ ## n1 ## _length(ipmi_fru_t *fru, int *length)		      \
{									      \
    unsigned int v;							      \
    int          rv;							      \
    rv = ipmi_fru_area_get_length(fru, IPMI_FRU_FTR_ ## n2 ##_AREA, &v);      \
    if (rv == ENOENT) {							      \
	rv = 0;								      \
	*length = 0;							      \
    } else if (!rv)							      \
	*length = v;							      \
    return rv;								      \
}									      \
static int								      \
ipmi_fru_set_ ## n1 ## _length(ipmi_fru_t *fru, int length)		      \
{									      \
    return ipmi_fru_area_set_length(fru, IPMI_FRU_FTR_ ## n2 ##_AREA, length);\
}

AREA_GENERIC(internal_use2, INTERNAL_USE)
AREA_GENERIC(chassis_info, CHASSIS_INFO)
AREA_GENERIC(board_info, BOARD_INFO)
AREA_GENERIC(product_info, PRODUCT_INFO)
AREA_GENERIC(multi_record, MULTI_RECORD)

static int
ipmi_fru_get_fru_length(ipmi_fru_t *fru, int *length)
{
    *length = ipmi_fru_get_data_length(fru);
    return 0;
}

static int
ipmi_fru_set_fru_length(ipmi_fru_t *fru, int length)
{
    return ENOSYS;
}

int
ipmi_fru_area_get_used_length(ipmi_fru_t *fru,
			      unsigned int area,
			      unsigned int *used_length)
{
    ipmi_fru_record_t **recs;

    if (!_ipmi_fru_is_normal_fru(fru))
	return ENOSYS;

    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;

    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    if (!recs[area]) {
	_ipmi_fru_unlock(fru);
	return ENOENT;
    }

    *used_length = recs[area]->used_length;

    _ipmi_fru_unlock(fru);
    return 0;
}

/***********************************************************************
 *
 * Handling for FRU generic interface.
 *
 **********************************************************************/

typedef struct fru_data_rep_s
{
    char                      *name;
    enum ipmi_fru_data_type_e type;
    unsigned int              hasnum : 1;
    unsigned int              settable : 1;

    union {
	struct {
	    int (*fetch_uchar)(ipmi_fru_t *fru, unsigned char *data);
	    int (*set_uchar)(ipmi_fru_t *fru, unsigned char data);
	    int (*fetch_int)(ipmi_fru_t *fru, int *data);
	    int (*set_int)(ipmi_fru_t *fru, int data);
	} inttype;

	struct {
	    int (*fetch_uchar)(ipmi_fru_t *fru, unsigned int num,
			       unsigned char *data);
	    int (*set_uchar)(ipmi_fru_t *fru, unsigned int num,
			     unsigned char data);
	} intnumtype;

	struct {
	    int (*fetch)(ipmi_fru_t *fru, double *data);
	    int (*set)(ipmi_fru_t *fru, double data);
	} floattype;

	struct {
	    int (*fetch)(ipmi_fru_t *fru, unsigned int num, double *data);
	    int (*set)(ipmi_fru_t *fru, unsigned int num, double data);
	} floatnumtype;

	struct {
	    int (*fetch)(ipmi_fru_t *fru, time_t *data);
	    int (*set)(ipmi_fru_t *fru, time_t data);
	} timetype;

	struct {
	    int (*fetch)(ipmi_fru_t *fru, unsigned int num,
			 time_t *data);
	    int (*set)(ipmi_fru_t *fru, unsigned int num,
		       time_t data);
	} timenumtype;

	struct {
	    int (*fetch_len)(ipmi_fru_t *fru, unsigned int *len);
	    int (*fetch_type)(ipmi_fru_t *fru, enum ipmi_str_type_e *type);
	    int (*fetch_data)(ipmi_fru_t *fru, char *data,
			      unsigned int *max_len);
	    int (*set)(ipmi_fru_t *fru, enum ipmi_str_type_e type,
		       char *data, unsigned int len);
	} strtype;

	struct {
	    int (*fetch_len)(ipmi_fru_t *fru, unsigned int num,
			     unsigned int *len);
	    int (*fetch_type)(ipmi_fru_t *fru, unsigned int num,
			      enum ipmi_str_type_e *type);
	    int (*fetch_data)(ipmi_fru_t *fru, unsigned int num,
			      char *data, unsigned int *max_len);
	    int (*set)(ipmi_fru_t *fru, unsigned int num,
		       enum ipmi_str_type_e type, char *data,
		       unsigned int len);
	    int (*ins)(ipmi_fru_t *fru, unsigned int num,
		       enum ipmi_str_type_e type, char *data,
		       unsigned int len);
	} strnumtype;

	struct {
	    int (*fetch_len)(ipmi_fru_t *fru, unsigned int *len);
	    int (*fetch_data)(ipmi_fru_t *fru, unsigned char *data,
			      unsigned int *max_len);
	    int (*set)(ipmi_fru_t *fru, unsigned char *data,
		       unsigned int len);
	} bintype;

	struct {
	    int (*fetch_len)(ipmi_fru_t *fru, unsigned int num,
			     unsigned int *len);
	    int (*fetch_data)(ipmi_fru_t *fru, unsigned intnum,
			      unsigned char *data, unsigned int *max_len);
	    int (*set)(ipmi_fru_t *fru, unsigned int num,
		       unsigned char *data, unsigned int len);
	    int (*ins)(ipmi_fru_t *fru, unsigned int num,
		       unsigned char *data, unsigned int len);
	} binnumtype;
    } u;
} fru_data_rep_t;

#define F_UCHAR(x,s) { .name = #x, .type = IPMI_FRU_DATA_INT,		     \
		       .hasnum = 0, .settable = s,			     \
		       .u = { .inttype = { .fetch_uchar = ipmi_fru_get_ ## x,\
					   .set_uchar = ipmi_fru_set_ ## x }}}
#define F_INT(x,s) { .name = #x, .type = IPMI_FRU_DATA_INT,		     \
		     .hasnum = 0, .settable = s,			     \
		     .u = { .inttype = { .fetch_int = ipmi_fru_get_ ## x,\
					 .set_int = ipmi_fru_set_ ## x }}}
#define F_NUM_UCHAR(x,s) { .name = #x, .type = IPMI_FRU_DATA_INT,	     \
			   .hasnum = 1, .settable = s,			     \
			   .u = { .intnumtype = {			     \
				  .fetch_uchar = ipmi_fru_get_ ## x,	     \
				  .set_uchar = ipmi_fru_set_ ## x }}}
#define F_TIME(x,s) { .name = #x, .type = IPMI_FRU_DATA_TIME,		     \
		      .hasnum = 0, .settable = s,			     \
		      .u = { .timetype = { .fetch = ipmi_fru_get_ ## x,      \
					 .set = ipmi_fru_set_ ## x }}}
#define F_NUM_TIME(x,s) { .name = #x, .type = IPMI_FRU_DATA_TIME,	     \
			  .hasnum = 1, .settable = s,			     \
		          .u = { .timenumtype = { .fetch = ipmi_fru_get_ ## x,\
					          .set = ipmi_fru_set_ ## x }}}
#define F_STR(x,s) { .name = #x, .type = IPMI_FRU_DATA_ASCII,		     \
		     .hasnum = 0, .settable = s,			     \
		     .u = { .strtype = {				     \
			    .fetch_len = ipmi_fru_get_ ## x ## _len,	     \
		            .fetch_type = ipmi_fru_get_ ## x ## _type,	     \
		            .fetch_data = ipmi_fru_get_ ## x,		     \
			    .set = ipmi_fru_set_ ## x }}}
#define F_NUM_STR(x,s) { .name = #x, .type = IPMI_FRU_DATA_ASCII,	     \
			 .hasnum = 1, .settable = s,			     \
		         .u = { .strnumtype = {                              \
			        .fetch_len = ipmi_fru_get_ ## x ## _len,     \
		                .fetch_type = ipmi_fru_get_ ## x ## _type,   \
		                .fetch_data = ipmi_fru_get_ ## x,            \
			        .set = ipmi_fru_set_ ## x,		     \
				.ins = ipmi_fru_ins_ ## x }}}
#define F_BIN(x,s) { .name = #x, .type = IPMI_FRU_DATA_BINARY,		     \
		     .hasnum = 0, .settable = s,			     \
		     .u = { .bintype = {				     \
			    .fetch_len = ipmi_fru_get_ ## x ## _len,	     \
		   	    .fetch_data = ipmi_fru_get_ ## x,		     \
			    .set = ipmi_fru_set_ ## x }}}
#define F_NUM_BIN(x,s) { .name = #x, .type = IPMI_FRU_DATA_BINARY,	     \
			 .hasnum = 1, .settable = s,			     \
		         .u = { .binnumtype = {				     \
			        .fetch_len = ipmi_fru_get_ ## x ## _len,     \
		       	        .fetch_data = ipmi_fru_get_ ## x,	     \
			        .set = ipmi_fru_set_ ## x,		     \
			        .ins = ipmi_fru_ins_ ## x }}}
static fru_data_rep_t frul[] =
{
    F_UCHAR(internal_use_version, 0),
    F_BIN(internal_use, 1),
    F_UCHAR(chassis_info_version, 0),
    F_UCHAR(chassis_info_type, 1),
    F_STR(chassis_info_part_number, 1),
    F_STR(chassis_info_serial_number, 1),
    F_NUM_STR(chassis_info_custom, 1),
    F_UCHAR(board_info_version, 0),
    F_UCHAR(board_info_lang_code, 1),
    F_TIME(board_info_mfg_time, 1),
    F_STR(board_info_board_manufacturer, 1),
    F_STR(board_info_board_product_name, 1),
    F_STR(board_info_board_serial_number, 1),
    F_STR(board_info_board_part_number, 1),
    F_STR(board_info_fru_file_id, 1),
    F_NUM_STR(board_info_custom, 1),
    F_UCHAR(product_info_version, 0),
    F_UCHAR(product_info_lang_code, 1),
    F_STR(product_info_manufacturer_name, 1),
    F_STR(product_info_product_name, 1),
    F_STR(product_info_product_part_model_number, 1),
    F_STR(product_info_product_version, 1),
    F_STR(product_info_product_serial_number, 1),
    F_STR(product_info_asset_tag, 1),
    F_STR(product_info_fru_file_id, 1),
    F_NUM_STR(product_info_custom, 1),
    F_INT(fru_length, 0),
    { .name = "internal_use_offset", .type = IPMI_FRU_DATA_INT,
      .hasnum = 0, .settable = 1,
      .u = { .inttype = { .fetch_int = ipmi_fru_get_internal_use2_offset,
			  .set_int = ipmi_fru_set_internal_use2_offset }}},
    { .name = "internal_use_length", .type = IPMI_FRU_DATA_INT,
      .hasnum = 0, .settable = 1,
      .u = { .inttype = { .fetch_int = ipmi_fru_get_internal_use2_length,
			  .set_int = ipmi_fru_set_internal_use2_length }}},
    F_INT(chassis_info_offset, 1),
    F_INT(chassis_info_length, 1),
    F_INT(board_info_offset, 1),
    F_INT(board_info_length, 1),
    F_INT(product_info_offset, 1),
    F_INT(product_info_length, 1),
    F_INT(multi_record_offset, 1),
    F_INT(multi_record_length, 1),
};
#define NUM_FRUL_ENTRIES (sizeof(frul) / sizeof(fru_data_rep_t))

int
ipmi_fru_str_to_index(char *name)
{
    unsigned int i;
    for (i=0; i<NUM_FRUL_ENTRIES; i++) {
	if (strcmp(name, frul[i].name) == 0)
	    return i;
    }
    return -1;
}

char *
ipmi_fru_index_to_str(int index)
{
    if ((index < 0) || (index >= (int) NUM_FRUL_ENTRIES))
	return NULL;

    return frul[index].name;
}

int
ipmi_fru_get(ipmi_fru_t                *fru,
	     int                       index,
	     const char                **name,
	     int                       *num,
	     enum ipmi_fru_data_type_e *dtype,
	     int                       *intval,
	     time_t                    *time,
	     char                      **data,
	     unsigned int              *data_len)
{
    fru_data_rep_t *p;
    unsigned char  ucval, dummy_ucval;
    unsigned int   dummy_uint;
    time_t         dummy_time;
    int            rv = 0, rv2 = 0;
    unsigned int   len;
    char           *dval = NULL;
    enum ipmi_fru_data_type_e rdtype;
    enum ipmi_str_type_e stype;
    

    if ((index < 0) || (index >= (int) NUM_FRUL_ENTRIES))
	return EINVAL;

    p = frul + index;

    if (name)
	*name = p->name;

    rdtype = p->type;

    switch (p->type) {
    case IPMI_FRU_DATA_INT:
	if (intval) {
	    if (! p->hasnum) {
		if (p->u.inttype.fetch_uchar) {
		    rv = p->u.inttype.fetch_uchar(fru, &ucval);
		    if (!rv)
			*intval = ucval;
		} else
		    rv = p->u.inttype.fetch_int(fru, intval);
	    } else {
		rv = p->u.intnumtype.fetch_uchar(fru, *num, &ucval);
		rv2 = p->u.intnumtype.fetch_uchar(fru, (*num)+1, &dummy_ucval);
		if (!rv)
		    *intval = ucval;
	    }
	}
	break;

    case IPMI_FRU_DATA_TIME:
	if (time) {
	    if (! p->hasnum) {
		rv = p->u.timetype.fetch(fru, time);
	    } else {
		rv = p->u.timenumtype.fetch(fru, *num, time);
		rv2 = p->u.timenumtype.fetch(fru, (*num)+1, &dummy_time);
	    }
	}
	break;

    case IPMI_FRU_DATA_ASCII:
	if (dtype) {
	    if (! p->hasnum) {
		rv = p->u.strtype.fetch_type(fru, &stype);
	    } else {
		rv = p->u.strnumtype.fetch_type(fru, *num, &stype);
	    }
	    if (rv) {
		break;
	    } else {
		switch (stype) {
		case IPMI_UNICODE_STR: rdtype = IPMI_FRU_DATA_UNICODE; break;
		case IPMI_BINARY_STR: rdtype = IPMI_FRU_DATA_BINARY; break;
		case IPMI_ASCII_STR: break;
		}
	    }
	}

	if (data_len || data) {
	    if (! p->hasnum) {
		rv = p->u.strtype.fetch_len(fru, &len);
	    } else {
		rv = p->u.strnumtype.fetch_len(fru, *num, &len);
	    }
	    if (rv)
		break;

	    if (data) {
		dval = ipmi_mem_alloc(len);
		if (!dval) {
		    rv = ENOMEM;
		    break;
		}
		if (! p->hasnum) {
		    rv = p->u.strtype.fetch_data(fru, dval, &len);
		} else {
		    rv = p->u.strnumtype.fetch_data(fru, *num, dval, &len);
		}
		if (rv)
		    break;
		*data = dval;
	    }

	    if (data_len)
		*data_len = len;
	}

	if (p->hasnum)
	    rv2 = p->u.strnumtype.fetch_len(fru, (*num)+1, &dummy_uint);
	break;

    case IPMI_FRU_DATA_BINARY:
	if (data_len || data) {
	    if (! p->hasnum) {
		rv = p->u.bintype.fetch_len(fru, &len);
	    } else {
		rv = p->u.binnumtype.fetch_len(fru, *num, &len);
	    }
	    if (rv)
		break;

	    if (data) {
		dval = ipmi_mem_alloc(len);
		if (!dval) {
		    rv = ENOMEM;
		    break;
		}
		if (! p->hasnum) {
		    rv = p->u.bintype.fetch_data(fru, (unsigned char *) dval,
						 &len);
		} else {
		    rv = p->u.binnumtype.fetch_data(fru, *num,
						    (unsigned char *) dval,
						    &len);
		}
		if (rv)
		    break;
		*data = dval;
	    }

	    if (data_len)
		*data_len = len;
	}

	if (p->hasnum)
	    rv2 = p->u.binnumtype.fetch_len(fru, (*num)+1, &dummy_uint);
	break;

    default:
	break;
    }

    if (rv) {
	if (dval)
	    ipmi_mem_free(dval);
	return rv;
    }

    if (p->hasnum) {
	if (rv2)
	    *num = -1;
	else
	    *num = (*num) + 1;
    }

    if (dtype)
	*dtype = rdtype;

    return 0;
}

int
ipmi_fru_set_int_val(ipmi_fru_t *fru,
		     int        index,
		     int        num,
		     int        val)
{
    fru_data_rep_t *p;
    int            rv;

    if ((index < 0) || (index >= (int) NUM_FRUL_ENTRIES))
	return EINVAL;

    p = frul + index;

    if (p->type != IPMI_FRU_DATA_INT)
	return EINVAL;

    if (! p->hasnum) {
	if (p->u.inttype.set_uchar)
	    rv = p->u.inttype.set_uchar(fru, val);
	else
	    rv = p->u.inttype.set_int(fru, val);
    } else {
	rv = p->u.intnumtype.set_uchar(fru, num, val);
    }

    return rv;
}

int
ipmi_fru_set_float_val(ipmi_fru_t *fru,
		       int        index,
		       int        num,
		       double     val)
{
    fru_data_rep_t *p;
    int            rv;

    if ((index < 0) || (index >= (int) NUM_FRUL_ENTRIES))
	return EINVAL;

    p = frul + index;

    if (p->type != IPMI_FRU_DATA_FLOAT)
	return EINVAL;

    if (! p->hasnum) {
	rv = p->u.floattype.set(fru, val);
    } else {
	rv = p->u.floatnumtype.set(fru, num, val);
    }

    return rv;
}

int
ipmi_fru_set_time_val(ipmi_fru_t *fru,
		      int        index,
		      int        num,
		      time_t     val)
{
    fru_data_rep_t *p;
    int            rv;
    

    if ((index < 0) || (index >= (int) NUM_FRUL_ENTRIES))
	return EINVAL;

    p = frul + index;

    if (p->type != IPMI_FRU_DATA_TIME)
	return EINVAL;

    if (! p->hasnum) {
	rv = p->u.timetype.set(fru, val);
    } else {
	rv = p->u.timenumtype.set(fru, num, val);
    }

    return rv;
}

int
ipmi_fru_set_data_val(ipmi_fru_t                *fru,
		      int                       index,
		      int                       num,
		      enum ipmi_fru_data_type_e dtype,
		      char                      *data,
		      unsigned int              len)
{
    fru_data_rep_t       *p;
    int                  rv;
    enum ipmi_str_type_e stype;
    

    if ((index < 0) || (index >= (int) NUM_FRUL_ENTRIES))
	return EINVAL;

    p = frul + index;

    switch (dtype) {
    case IPMI_FRU_DATA_UNICODE: stype = IPMI_UNICODE_STR; break;
    case IPMI_FRU_DATA_BINARY: stype = IPMI_BINARY_STR; break;
    case IPMI_FRU_DATA_ASCII: stype = IPMI_ASCII_STR; break;
    default:
	return EINVAL;
    }

    switch (p->type)
    {
    case IPMI_FRU_DATA_UNICODE:
    case IPMI_FRU_DATA_ASCII:
	if (! p->hasnum) {
	    rv = p->u.strtype.set(fru, stype, data, len);
	} else {
	    rv = p->u.strnumtype.set(fru, num, stype, data, len);
	}
	break;

    case IPMI_FRU_DATA_BINARY:
	if (! p->hasnum) {
	    rv = p->u.bintype.set(fru, (unsigned char *) data, len);
	} else {
	    rv = p->u.binnumtype.set(fru, num, (unsigned char *) data, len);
	}
	break;

    default:
	return EINVAL;
    }

    return rv;
}

int
ipmi_fru_ins_data_val(ipmi_fru_t                *fru,
		      int                       index,
		      int                       num,
		      enum ipmi_fru_data_type_e dtype,
		      char                      *data,
		      unsigned int              len)
{
    fru_data_rep_t       *p;
    int                  rv;
    enum ipmi_str_type_e stype;
    
    if ((index < 0) || (index >= (int) NUM_FRUL_ENTRIES))
	return EINVAL;

    p = frul + index;

    switch (dtype) {
    case IPMI_FRU_DATA_UNICODE: stype = IPMI_UNICODE_STR; break;
    case IPMI_FRU_DATA_BINARY: stype = IPMI_BINARY_STR; break;
    case IPMI_FRU_DATA_ASCII: stype = IPMI_ASCII_STR; break;
    default:
	return EINVAL;
    }

    switch (p->type)
    {
    case IPMI_FRU_DATA_UNICODE:
    case IPMI_FRU_DATA_ASCII:
	if (! p->hasnum)
	    return ENOSYS;
	rv = p->u.strnumtype.ins(fru, num, stype, data, len);
	break;

    case IPMI_FRU_DATA_BINARY:
	if (! p->hasnum)
	    return ENOSYS;
	rv = p->u.binnumtype.ins(fru, num, (unsigned char *) data, len);
	break;

    default:
	return EINVAL;
    }

    return rv;
}

/***********************************************************************
 *
 * FRU node handling
 *
 **********************************************************************/
static void
fru_node_destroy(ipmi_fru_node_t *node)
{
    ipmi_fru_t *fru = _ipmi_fru_node_get_data(node);

    ipmi_fru_deref(fru);
}

typedef struct fru_mr_array_idx_s
{
    int             index;
    const char      *name;
    ipmi_fru_node_t *mr_node;
    ipmi_fru_t      *fru;
} fru_mr_array_idx_t;

static void
fru_mr_array_idx_destroy(ipmi_fru_node_t *node)
{
    fru_mr_array_idx_t *info = _ipmi_fru_node_get_data(node);
    ipmi_fru_t         *fru = info->fru;

    ipmi_fru_deref(fru);
    if (info->mr_node)
	ipmi_fru_put_node(info->mr_node);
    ipmi_mem_free(info);
}

static int
fru_mr_array_idx_set_field(ipmi_fru_node_t           *pnode,
			   unsigned int              index,
			   enum ipmi_fru_data_type_e dtype,
			   int                       intval,
			   time_t                    time,
			   double                    floatval,
			   char                      *data,
			   unsigned int              data_len)
{
    fru_mr_array_idx_t *info = _ipmi_fru_node_get_data(pnode);

    switch (index) {
    case 0:
	if (dtype != IPMI_FRU_DATA_INT)
	    return EINVAL;
	return ipmi_fru_set_multi_record_type(info->fru, info->index, intval);

    case 2:
	if (dtype != IPMI_FRU_DATA_BINARY)
	    return EINVAL;
	return ipmi_fru_set_multi_record_data(info->fru, info->index,
					      (unsigned char *) data,
					      data_len);

    case 1:
    case 3:
	return EPERM;
    default:
	return EINVAL;
    }
    return 0;
}

static int
fru_mr_array_idx_settable(ipmi_fru_node_t *pnode,
			  unsigned int    index)
{
    switch (index) {
    case 0:
    case 2:
	return 0;
    case 1:
    case 3:
	return EPERM;
    default:
	return EINVAL;
    }
}

static int
fru_mr_array_idx_get_field(ipmi_fru_node_t           *pnode,
			   unsigned int              index,
			   const char                **name,
			   enum ipmi_fru_data_type_e *dtype,
			   int                       *intval,
			   time_t                    *time,
			   double                    *floatval,
			   char                      **data,
			   unsigned int              *data_len,
			   ipmi_fru_node_t           **sub_node)
{
    fru_mr_array_idx_t *info = _ipmi_fru_node_get_data(pnode);
    int                rv;
    unsigned int       rlen;
    char               *rdata;

    if (index == 0) {
	/* Record type */
	unsigned char type;

	rv = ipmi_fru_get_multi_record_type(info->fru, info->index, &type);
	if (rv)
	    return rv;
	if (intval)
	    *intval = type;
	if (dtype)
	    *dtype = IPMI_FRU_DATA_INT;
	if (name)
	    *name = "type";
	return 0;
    } else if (index == 1) {
	/* Record format version */
	unsigned char ver;

	rv = ipmi_fru_get_multi_record_format_version(info->fru, info->index,
						      &ver);
	if (rv)
	    return rv;
	if (intval)
	    *intval = ver;
	if (dtype)
	    *dtype = IPMI_FRU_DATA_INT;
	if (name)
	    *name = "format version";
	return 0;
    } else if (index == 2) {
	/* Raw FRU data */
	rv = ipmi_fru_get_multi_record_data_len(info->fru, info->index, &rlen);
	if (rv)
	    return rv;
	if (data) {
	    rdata = ipmi_mem_alloc(rlen);
	    if (!rdata)
		return ENOMEM;
	    rv = ipmi_fru_get_multi_record_data(info->fru, info->index,
						(unsigned char *) rdata,
						&rlen);
	    if (rv) {
		ipmi_mem_free(rdata);
		return rv;
	    }
	    *data = rdata;
	}

	if (data_len)
	    *data_len = rlen;

	if (dtype)
	    *dtype = IPMI_FRU_DATA_BINARY;

	if (name)
	    *name = "raw-data";

	return 0;
    } else if (index == 3) {
	/* FRU node itself. */
	if (info->mr_node == NULL)
	    return EINVAL;

	if (intval)
	    *intval = -1;
	if (name)
	    *name = info->name;
	if (dtype)
	    *dtype = IPMI_FRU_DATA_SUB_NODE;
	if (sub_node) {
	    ipmi_fru_get_node(info->mr_node);
	    *sub_node = info->mr_node;
	}
	return 0;
    } else
	return EINVAL;
}

static int
fru_mr_array_get_field(ipmi_fru_node_t           *pnode,
		       unsigned int              index,
		       const char                **name,
		       enum ipmi_fru_data_type_e *dtype,
		       int                       *intval,
		       time_t                    *time,
		       double                    *floatval,
		       char                      **data,
		       unsigned int              *data_len,
		       ipmi_fru_node_t           **sub_node)
{
    fru_mr_array_idx_t *info;
    ipmi_fru_t         *fru = _ipmi_fru_node_get_data(pnode);
    ipmi_fru_node_t    *node;
    ipmi_fru_node_t    *snode;
    const char         *sname;
    int                rv;

    if (index >= ipmi_fru_get_num_multi_records(fru))
	return EINVAL;

    if (name)
	*name = NULL;
    if (dtype)
	*dtype = IPMI_FRU_DATA_SUB_NODE;
    if (intval)
	*intval = -1;
    if (sub_node) {
	node = _ipmi_fru_node_alloc(fru);
	if (!node)
	    return ENOMEM;
	info = ipmi_mem_alloc(sizeof(*info));
	if (!info) {
	    ipmi_fru_put_node(node);
	    return ENOMEM;
	}
	memset(info, 0, sizeof(*info));
	info->index = index;
	info->fru = fru;
	ipmi_fru_ref(fru);
	_ipmi_fru_node_set_data(node, info);

	rv = ipmi_fru_multi_record_get_root_node(fru, index, &sname, &snode);
	if (rv) {
	    /* No decode data, just do a "raw" node. */
	    info->mr_node = NULL;
	    info->name = "multirecord";
	} else {
	    info->mr_node = snode;
	    info->name = sname;
	}
	_ipmi_fru_node_set_get_field(node, fru_mr_array_idx_get_field);
	_ipmi_fru_node_set_set_field(node, fru_mr_array_idx_set_field);
	_ipmi_fru_node_set_settable(node, fru_mr_array_idx_settable);
	_ipmi_fru_node_set_destructor(node, fru_mr_array_idx_destroy);

	*sub_node = node;
    }

    /* We always succeed if we can get the memory, even if we don't
       have a decoder. */
    return 0;
}

static int
fru_mr_array_get_subtype(ipmi_fru_node_t           *pnode,
			 enum ipmi_fru_data_type_e *dtype)
{
    *dtype = IPMI_FRU_DATA_SUB_NODE;
    return 0;
}

static int
fru_mr_array_set_field(ipmi_fru_node_t           *pnode,
		       unsigned int              index,
		       enum ipmi_fru_data_type_e dtype,
		       int                       intval,
		       time_t                    time,
		       double                    floatval,
		       char                      *data,
		       unsigned int              data_len)
{
    ipmi_fru_t    *fru = _ipmi_fru_node_get_data(pnode);
    unsigned char type = 0, version = 2;

    if (dtype != IPMI_FRU_DATA_SUB_NODE)
	return EINVAL;

    if (data) {
	if (data_len >= 1) {
	    type = data[0];
	    data++;
	    data_len--;
	}
	if (data_len >= 1) {
	    version = data[0];
	    data++;
	    data_len--;
	}
	/* First two bytes are the type and version */
	return ipmi_fru_set_multi_record(fru, index, type, version,
					 (unsigned char *) data, data_len);
    } else
	return ipmi_fru_set_multi_record(fru, index, 0, 0, NULL, 0);
}

static int
fru_mr_array_settable(ipmi_fru_node_t           *node,
		      unsigned int              index)
{
    /* Array elements are not. */
    return EPERM;
}

typedef struct fru_array_s
{
    int        index;
    ipmi_fru_t *fru;
} fru_array_t;

static void
fru_array_idx_destroy(ipmi_fru_node_t *node)
{
    fru_array_t *info = _ipmi_fru_node_get_data(node);
    ipmi_fru_t  *fru = info->fru;

    ipmi_fru_deref(fru);
    ipmi_mem_free(info);
}

static int
fru_array_idx_get_field(ipmi_fru_node_t           *pnode,
			unsigned int              index,
			const char                **name,
			enum ipmi_fru_data_type_e *dtype,
			int                       *intval,
			time_t                    *time,
			double                    *floatval,
			char                      **data,
			unsigned int              *data_len,
			ipmi_fru_node_t           **sub_node)
{
    fru_array_t *info = _ipmi_fru_node_get_data(pnode);
    int         num = index;
    int         rv;

    if (name)
	*name = NULL;

    rv = ipmi_fru_get(info->fru, info->index, NULL, &num, dtype,
		      intval, time, data, data_len);
    if ((rv == E2BIG) || (rv == ENOSYS))
	rv = EINVAL;
    return rv;
}

static int
fru_array_idx_set_field(ipmi_fru_node_t           *pnode,
			unsigned int              index,
			enum ipmi_fru_data_type_e dtype,
			int                       intval,
			time_t                    time,
			double                    floatval,
			char                      *data,
			unsigned int              data_len)
{
    fru_array_t *info = _ipmi_fru_node_get_data(pnode);

    return ipmi_fru_set_data_val(info->fru, info->index, index,
				 dtype, data, data_len);
}

static int
fru_array_get_subtype(ipmi_fru_node_t           *pnode,
		      enum ipmi_fru_data_type_e *dtype)
{
    *dtype = IPMI_FRU_DATA_ASCII;
    return 0;
}

static int
fru_node_get_field(ipmi_fru_node_t           *pnode,
		   unsigned int              index,
		   const char                **name,
		   enum ipmi_fru_data_type_e *dtype,
		   int                       *intval,
		   time_t                    *time,
		   double                    *floatval,
		   char                      **data,
		   unsigned int              *data_len,
		   ipmi_fru_node_t           **sub_node)
{
    ipmi_fru_record_t            **recs;
    ipmi_fru_multi_record_area_t *u;
    ipmi_fru_t                   *fru = _ipmi_fru_node_get_data(pnode);
    ipmi_fru_node_t              *node;
    int                          rv;
    int                          num;
    int                          len;

    if ((index >= 0) && (index < NUM_FRUL_ENTRIES)) {
	num = 0;
	rv = ipmi_fru_get(fru, index, name, &num, NULL, NULL, NULL, NULL,
			  NULL);
	if (rv)
	    return rv;

	if (num != 0) {
	    fru_array_t               *info;
	    enum ipmi_fru_data_type_e ldtype;
	    int                       num2 = 0;

	    /* Determine if the value exists or if the array is empty. */
	    num2 = 0;
	    rv = ipmi_fru_get(fru, index, name, &num2, &ldtype, NULL, NULL,
			      NULL, NULL);
	    if (rv) {
		if (rv != E2BIG)
		    /* No support for this field. */
		    return rv;
		else if (rv == E2BIG)
		    len = 0;
	    }
	    else
		len = 1;

	    /* name is set by the previous call */
	    if (dtype)
		*dtype = IPMI_FRU_DATA_SUB_NODE;
	    if (intval) {
		/* Get the length of the array by searching. */
		while (num != -1) {
		    len++;
		    rv = ipmi_fru_get(fru, index, NULL, &num, NULL, NULL,
				      NULL, NULL, NULL);
		    if (rv)
			return rv;
		}
		*intval = len;
	    }
	    if (sub_node) {
		node = _ipmi_fru_node_alloc(fru);
		if (!node)
		    return ENOMEM;
		info = ipmi_mem_alloc(sizeof(*info));
		if (!info) {
		    ipmi_fru_put_node(node);
		    return ENOMEM;
		}
		info->index = index;
		info->fru = fru;
		_ipmi_fru_node_set_data(node, info);
		_ipmi_fru_node_set_get_field(node, fru_array_idx_get_field);
		_ipmi_fru_node_set_set_field(node, fru_array_idx_set_field);
		_ipmi_fru_node_set_get_subtype(node, fru_array_get_subtype);
		_ipmi_fru_node_set_destructor(node, fru_array_idx_destroy);
		ipmi_fru_ref(fru);

		*sub_node = node;
	    }
	    return 0;
	} else
	    /* Not an array, everything is ok. */
	    return ipmi_fru_get(fru, index, name, NULL, dtype, intval, time,
				data, data_len);

    } else if (index == NUM_FRUL_ENTRIES) {
	/* Handle multi-records. */
	_ipmi_fru_lock(fru);
	recs = normal_fru_get_recs(fru);
	if (!recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]) {
	    _ipmi_fru_unlock(fru);
	    return ENOSYS;
	}
	if (intval) {
	    u = fru_record_get_data(recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]);
	    *intval = u->num_records;
	}
	_ipmi_fru_unlock(fru);

	if (name)
	    *name = "multirecords";
	if (dtype)
	    *dtype = IPMI_FRU_DATA_SUB_NODE;
	if (sub_node) {
	    node = _ipmi_fru_node_alloc(fru);
	    if (!node)
		return ENOMEM;
	    _ipmi_fru_node_set_data(node, fru);
	    _ipmi_fru_node_set_get_field(node, fru_mr_array_get_field);
	    _ipmi_fru_node_set_set_field(node, fru_mr_array_set_field);
	    _ipmi_fru_node_set_get_subtype(node, fru_mr_array_get_subtype);
	    _ipmi_fru_node_set_settable(node, fru_mr_array_settable);
	    _ipmi_fru_node_set_destructor(node, fru_node_destroy);
	    ipmi_fru_ref(fru);

	    *sub_node = node;
	}
	return 0;
    } else
	return EINVAL;
}

static int
fru_node_set_field(ipmi_fru_node_t           *pnode,
		   unsigned int              index,
		   enum ipmi_fru_data_type_e dtype,
		   int                       intval,
		   time_t                    time,
		   double                    floatval,
		   char                      *data,
		   unsigned int              data_len)
{
    ipmi_fru_t     *fru = _ipmi_fru_node_get_data(pnode);
    fru_data_rep_t *p;

    if ((index < 0) || (index > (int) NUM_FRUL_ENTRIES))
	return EINVAL;

    p = frul + index;
    if ((index >= 0) && (index < NUM_FRUL_ENTRIES)) {
	if (p->hasnum) {
	    /* Insert/delete array indexes. */
	    if (intval >= 0) {
		if (!data) {
		    data = "";
		    data_len = 0;
		}
		return ipmi_fru_ins_data_val(fru, index, intval,
					     IPMI_FRU_DATA_ASCII, data,
					     data_len);
	    } else {
		intval = (-intval) - 1;
		data = NULL;
		data_len = 0;
		return ipmi_fru_set_data_val(fru, index, intval,
					     IPMI_FRU_DATA_ASCII, data,
					     data_len);
	    }
	}

	switch (dtype) {
	case IPMI_FRU_DATA_INT:
	    return ipmi_fru_set_int_val(fru, index, 0, intval);
	case IPMI_FRU_DATA_FLOAT:
	    return ipmi_fru_set_float_val(fru, index, 0, floatval);
	case IPMI_FRU_DATA_TIME:
	    return ipmi_fru_set_time_val(fru, index, 0, time);
	default:
	    return ipmi_fru_set_data_val(fru, index, 0, dtype, data, data_len);
	}
    } else if (index == (int) NUM_FRUL_ENTRIES) {
	/* Insert/delete multirecords. */
	unsigned char type = 0, version = 2;

	if (data) {
	    /* First two bytes are the type and version */
	    if (data_len >= 1) {
		type = data[0];
		data++;
		data_len--;
	    }
	    if (data_len >= 1) {
		version = data[0];
		data++;
		data_len--;
	    }
	}

	if (intval >= 0) {
	    if (!data) {
		data = "";
		data_len = 0;
	    }
	    return ipmi_fru_ins_multi_record(fru, intval, type, version,
					     (unsigned char *) data, data_len);
	} else {
	    intval = (-intval) - 1;
	    return ipmi_fru_set_multi_record(fru, intval, 0, 0, NULL, 0);
	}
    } else
	return EINVAL;
}

static int
fru_node_settable(ipmi_fru_node_t           *node,
		  unsigned int              index)
{
    fru_data_rep_t *p;

    if ((index >= 0) && (index < (int) NUM_FRUL_ENTRIES)) {
	p = frul + index;
	if (p->settable)
	    return 0;
	else
	    return EPERM;
    } else if (index == (int) NUM_FRUL_ENTRIES)
	/* The multirecord array is settable. */
	return 0;
    else
	return EINVAL;
}

/***********************************************************************
 *
 * Normal-fru-specific processing
 *
 **********************************************************************/
static void
fru_record_destroy(ipmi_fru_record_t *rec)
{
    if (rec)
	rec->handlers->free(rec);
}

static void
fru_cleanup_recs(ipmi_fru_t *fru)
{
    normal_fru_rec_data_t *info = _ipmi_fru_get_rec_data(fru);
    int                   i;

    if (!info)
	return;

    for (i=0; i<IPMI_FRU_FTR_NUMBER; i++)
	fru_record_destroy(info->recs[i]);

    ipmi_mem_free(info);
}

static void
fru_write_complete(ipmi_fru_t *fru)
{
    ipmi_fru_record_t **recs = normal_fru_get_recs(fru);
    int               i;

    for (i=0; i<IPMI_FRU_FTR_NUMBER; i++) {
	ipmi_fru_record_t *rec = recs[i];
	if (rec) {
	    rec->rewrite = 0;
	    rec->changed = 0;
	    rec->orig_used_length = rec->used_length;
	    if (rec->handlers->get_fields) {
		fru_variable_t *f = rec->handlers->get_fields(rec);
		int j;
		for (j=0; j<f->next; j++)
		    f->strings[i].changed = 0;
	    }
	}
    }
}

static int
fru_write(ipmi_fru_t *fru)
{
    normal_fru_rec_data_t *info = _ipmi_fru_get_rec_data(fru);
    ipmi_fru_record_t     **recs = normal_fru_get_recs(fru);
    int                   i;
    int                   rv;
    unsigned char         *data = _ipmi_fru_get_data_ptr(fru);

    data[0] = 1; /* Version */
    for (i=0; i<IPMI_FRU_FTR_MULTI_RECORD_AREA; i++) {
	if (recs[i])
	    data[i+1] = recs[i]->offset / 8;
	else
	    data[i+1] = 0;
    }
    if (recs[i] && recs[i]->used_length)
	data[i+1] = recs[i]->offset / 8;
    else
	data[i+1] = 0;
    data[6] = 0;
    data[7] = -checksum(data, 7);

    if (info->header_changed) {
	rv = _ipmi_fru_new_update_record(fru, 0, 8);
	if (rv)
	    return rv;
    }

    for (i=0; i<IPMI_FRU_FTR_NUMBER; i++) {
	ipmi_fru_record_t *rec = recs[i];
	unsigned int      length;

	if (rec) {
	    rv = rec->handlers->encode(fru, data);
	    if (rv)
		return rv;
	    if (rec->rewrite) {
		if (i == IPMI_FRU_FTR_MULTI_RECORD_AREA)
		    length = rec->used_length;
		else
		    length = rec->length;
		if (length == 0)
		    continue;
		rv = _ipmi_fru_new_update_record(fru, rec->offset, length);
		if (rv)
		    return rv;
	    }
	}
    }    

    return 0;
}

static int
fru_get_root_node(ipmi_fru_t *fru, const char **name, ipmi_fru_node_t **rnode)
{
    ipmi_fru_node_t *node;

    if (name)
	*name = "standard FRU";
    if (rnode) {
	node = _ipmi_fru_node_alloc(fru);
	if (!node)
	    return ENOMEM;
	_ipmi_fru_node_set_data(node, fru);
	_ipmi_fru_node_set_get_field(node, fru_node_get_field);
	_ipmi_fru_node_set_set_field(node, fru_node_set_field);
	_ipmi_fru_node_set_settable(node, fru_node_settable);
	_ipmi_fru_node_set_destructor(node, fru_node_destroy);
	ipmi_fru_ref(fru);
	*rnode = node;
    }
    return 0;
}

/************************************************************************
 *
 * For OEM-specific FRU multi-record decode and field get
 *
 ************************************************************************/

static locked_list_t *fru_multi_record_oem_handlers;

typedef struct fru_multi_record_oem_handlers_s {
    unsigned int                               manufacturer_id;
    unsigned char                              record_type_id;
    ipmi_fru_oem_multi_record_get_root_node_cb get_root;
    void                                       *cb_data;
} fru_multi_record_oem_handlers_t;

int
_ipmi_fru_register_multi_record_oem_handler
(unsigned int                               manufacturer_id,
 unsigned char                              record_type_id,
 ipmi_fru_oem_multi_record_get_root_node_cb get_root,
 void                                       *cb_data)
{
    fru_multi_record_oem_handlers_t *new_item;

    new_item = ipmi_mem_alloc(sizeof(*new_item));
    if (!new_item)
	return ENOMEM;

    new_item->manufacturer_id = manufacturer_id;
    new_item->record_type_id = record_type_id;
    new_item->get_root = get_root;
    new_item->cb_data = cb_data;

    if (!locked_list_add(fru_multi_record_oem_handlers, new_item, NULL)) {
        ipmi_mem_free(new_item);
	return ENOMEM;
    }
    return 0;
}

static int
fru_multi_record_oem_handler_cmp_dereg(void *cb_data, void *item1, void *item2)
{
    fru_multi_record_oem_handlers_t *hndlr = item1;
    fru_multi_record_oem_handlers_t *cmp = cb_data;

    if ((hndlr->manufacturer_id == cmp->manufacturer_id)
	&& (hndlr->record_type_id == cmp->record_type_id))
    {
	/* We re-use the cb_data as a marker to tell we found it. */
        cmp->cb_data = cmp;
        locked_list_remove(fru_multi_record_oem_handlers, item1, item2);
        ipmi_mem_free(hndlr);
	return LOCKED_LIST_ITER_STOP;
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

int
_ipmi_fru_deregister_multi_record_oem_handler(unsigned int manufacturer_id,
					      unsigned char record_type_id)
{
    fru_multi_record_oem_handlers_t tmp;

    tmp.manufacturer_id = manufacturer_id;
    tmp.record_type_id = record_type_id;
    tmp.cb_data = NULL;
    locked_list_iterate(fru_multi_record_oem_handlers,
                        fru_multi_record_oem_handler_cmp_dereg,
                        &tmp);
    if (!tmp.cb_data)
	return ENOENT;
    return 0;
}

typedef struct oem_search_node_s
{
    unsigned int    mr_rec_num;
    unsigned int    manufacturer_id;
    unsigned char   record_type_id;
    ipmi_fru_t      *fru;
    ipmi_fru_node_t *node;
    unsigned char   *mr_data;
    unsigned char   mr_data_len;
    const char      *name;
    int             rv;
} oem_search_node_t;

static int
get_root_node(void *cb_data, void *item1, void *item2)
{
    fru_multi_record_oem_handlers_t *hndlr = item1;
    oem_search_node_t               *cmp = cb_data;

    if ((hndlr->record_type_id == cmp->record_type_id)
	&& ((hndlr->record_type_id < 0xc0)
	    || (hndlr->manufacturer_id == cmp->manufacturer_id)))
    {
	cmp->rv = hndlr->get_root(cmp->fru, cmp->mr_rec_num,
				  cmp->manufacturer_id,
				  cmp->record_type_id,
				  cmp->mr_data, cmp->mr_data_len,
				  hndlr->cb_data, &cmp->name, &cmp->node);
	
	return LOCKED_LIST_ITER_STOP;
    } else {
        cmp->rv = EINVAL;
    }
    return LOCKED_LIST_ITER_CONTINUE;
}

int
ipmi_fru_multi_record_get_root_node(ipmi_fru_t      *fru,
				    unsigned int    record_num,
				    const char      **name,
				    ipmi_fru_node_t **node)
{
    ipmi_fru_record_t            **recs;
    ipmi_fru_multi_record_area_t *u;
    unsigned char                *d;
    oem_search_node_t            cmp;

    if (!_ipmi_fru_is_normal_fru(fru))
	return ENOSYS;

    _ipmi_fru_lock(fru);
    recs = normal_fru_get_recs(fru);
    if (!recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]) {
	_ipmi_fru_unlock(fru);
	return ENOSYS;
    }
    u = fru_record_get_data(recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]);
    if (record_num >= u->num_records) {
	_ipmi_fru_unlock(fru);
	return E2BIG;
    }
    if (u->records[record_num].length < 3) {
	_ipmi_fru_unlock(fru);
	return EINVAL;
    }
    d = ipmi_mem_alloc(u->records[record_num].length);
    if (!d) {
	_ipmi_fru_unlock(fru);
	return ENOMEM;
    }

    memcpy(d, u->records[record_num].data, u->records[record_num].length);
    cmp.mr_rec_num = record_num;
    cmp.manufacturer_id = d[0] | (d[1] << 8) | (d[2] << 16);
    cmp.record_type_id = u->records[record_num].type;
    cmp.fru = fru;
    cmp.node = NULL;
    cmp.mr_data = d;
    cmp.mr_data_len = u->records[record_num].length;
    cmp.name = NULL;
    cmp.rv = 0;
    _ipmi_fru_unlock(fru);

    locked_list_iterate(fru_multi_record_oem_handlers, get_root_node, &cmp);
    ipmi_mem_free(d);
    if (cmp.rv)
	return cmp.rv;
    if (node)
	*node = cmp.node;
    else
	ipmi_fru_put_node(cmp.node);
    if (name)
	*name = cmp.name;
    return 0;
}

/************************************************************************
 *
 * Standard multi-record handlers.
 *
 ************************************************************************/

static ipmi_mr_floattab_item_t pow_supply_intfloat =
{
    .count = 4,
    .defval = 0.0,
    .table = { {  11.9,  12.0,  12.1, "12.0" },
	       { -12.1, -12.0, -11.9, "-12.0" },
	       {   4.9,   5.0,   5.1, "5.0" },
	       {   3.2,   3.3,   3.4, "3.3" } }
};
static ipmi_mr_item_layout_t pow_supply_items[] = {
    { .name = "overall capacity", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 2,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "peak VA", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 2, .length = 2,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "inrush current", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 4, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "inrush current", .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 5, .length = 1,
      .u = { .multiplier = 0.001 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "low input voltage 1", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 6, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "high input voltage 1", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 8, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "low input voltage 2", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 10, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "high input voltage 2", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 12, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "low frequency", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 14, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "high frequency", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 15, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "A/C dropout tolerance", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 16, .length = 1,
      .u = { .multiplier = 0.001 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "tach pulses per rotation", .dtype = IPMI_FRU_DATA_BOOLEAN,
      .settable = 1,
      .start = 140, .length = 1,
      .set_field = ipmi_mr_bitint_set_field,
      .get_field = ipmi_mr_bitint_get_field },
    { .name = "hot swap support", .dtype = IPMI_FRU_DATA_BOOLEAN,
      .settable = 1,
      .start = 139, .length = 1,
      .set_field = ipmi_mr_bitint_set_field,
      .get_field = ipmi_mr_bitint_get_field },
    { .name = "autoswitch", .dtype = IPMI_FRU_DATA_BOOLEAN,
      .settable = 1,
      .start = 138, .length = 1,
      .set_field = ipmi_mr_bitint_set_field,
      .get_field = ipmi_mr_bitint_get_field },
    { .name = "power factor correction", .dtype = IPMI_FRU_DATA_BOOLEAN,
      .settable = 1,
      .start = 137, .length = 1,
      .set_field = ipmi_mr_bitint_set_field,
      .get_field = ipmi_mr_bitint_get_field },
    { .name = "predictive fail support", .dtype = IPMI_FRU_DATA_BOOLEAN,
      .settable = 1,
      .start = 136, .length = 1,
      .set_field = ipmi_mr_bitint_set_field,
      .get_field = ipmi_mr_bitint_get_field },
    { .name = "peak capacity hold up time", .dtype = IPMI_FRU_DATA_INT,
      .settable = 1,
      .start = 156, .length = 4,
      .set_field = ipmi_mr_bitint_set_field,
      .get_field = ipmi_mr_bitint_get_field },
    { .name = "peak capacity", .dtype = IPMI_FRU_DATA_INT,
      .settable = 1,
      .start = 144, .length = 12,
      .set_field = ipmi_mr_bitint_set_field,
      .get_field = ipmi_mr_bitint_get_field },
    { .name = "combined wattage voltage 1", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 164, .length = 4,
      .u = { .tab_data = &pow_supply_intfloat },
      .set_field = ipmi_mr_bitfloatvaltab_set_field,
      .get_field = ipmi_mr_bitfloatvaltab_get_field,
      .get_enum  = ipmi_mr_bitfloatvaltab_get_enum },
    { .name = "combined wattage voltage 2", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 160, .length = 4,
      .u = { .tab_data = &pow_supply_intfloat },
      .set_field = ipmi_mr_bitfloatvaltab_set_field,
      .get_field = ipmi_mr_bitfloatvaltab_get_field,
      .get_enum  = ipmi_mr_bitfloatvaltab_get_enum },
    { .name = "combined wattage", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 21, .length = 2,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "predictive fail tack low threshold", .dtype = IPMI_FRU_DATA_INT,
      .settable = 1,
      .start = 23, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_struct_layout_t pow_supply = {
    .name = "Power Supply Information", .length = 24,
    .item_count = 22, .items = pow_supply_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};

static ipmi_mr_item_layout_t dc_output_items[] = {
    { .name = "output number", .dtype = IPMI_FRU_DATA_INT,
      .settable = 1,
      .start = 0, .length = 4,
      .set_field = ipmi_mr_bitint_set_field,
      .get_field = ipmi_mr_bitint_get_field },
    { .name = "standby", .dtype = IPMI_FRU_DATA_BOOLEAN,
      .settable = 1,
      .start = 7, .length = 1,
      .set_field = ipmi_mr_bitint_set_field,
      .get_field = ipmi_mr_bitint_get_field },
    { .name = "nominal voltage", .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 1, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "max negative voltage deviation",
      .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 3, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "max positive voltage deviation",
      .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 5, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "ripple", .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 7, .length = 2,
      .u = { .multiplier = 0.001 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "min current", .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 9, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "max current", .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 11, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
};
static ipmi_mr_struct_layout_t dc_output = {
    .name = "DC Output", .length = 13,
    .item_count = 8, .items = dc_output_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};

static ipmi_mr_item_layout_t dc_load_items[] = {
    { .name = "output number", .dtype = IPMI_FRU_DATA_INT,
      .settable = 1,
      .start = 0, .length = 4,
      .set_field = ipmi_mr_bitint_set_field,
      .get_field = ipmi_mr_bitint_get_field },
    { .name = "nominal voltage", .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 1, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "min voltage",
      .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 3, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "max voltage",
      .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 5, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "ripple", .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 7, .length = 2,
      .u = { .multiplier = 0.001 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "min current", .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 9, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "max current", .dtype = IPMI_FRU_DATA_FLOAT, .settable = 1,
      .start = 11, .length = 2,
      .u = { .multiplier = 0.01 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
};
static ipmi_mr_struct_layout_t dc_load = {
    .name = "DC Load", .length = 13,
    .item_count = 7, .items = dc_load_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};

static int
std_get_mr_root(ipmi_fru_t          *fru,
		unsigned int	    mr_rec_num,
		unsigned int        manufacturer_id,
		unsigned char       record_type_id,
		unsigned char       *mr_data,
		unsigned int        mr_data_len,
		void                *cb_data,
		const char          **name,
		ipmi_fru_node_t     **node)
{
    switch (record_type_id) {
    case 0x00:
	return ipmi_mr_struct_root(fru, mr_rec_num, mr_data, mr_data_len,
				   &pow_supply,
				   name, node);
    case 0x01:
	return ipmi_mr_struct_root(fru, mr_rec_num, mr_data, mr_data_len,
				   &dc_output,
				   name, node);
    case 0x02:
	return ipmi_mr_struct_root(fru, mr_rec_num, mr_data, mr_data_len,
				   &dc_load,
				   name, node);
    default:
	return EINVAL;
    }
}

/***********************************************************************
 *
 * FRU decoding
 *
 **********************************************************************/

typedef struct fru_offset_s
{
    int          type;
    unsigned int offset;
} fru_offset_t;

static normal_fru_rec_data_t *
setup_normal_fru(ipmi_fru_t *fru, unsigned char version)
{
    normal_fru_rec_data_t *info;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return NULL;
    memset(info, 0, sizeof(*info));

    _ipmi_fru_set_rec_data(fru, info);

    info->version = version;

    _ipmi_fru_set_op_cleanup_recs(fru, fru_cleanup_recs);
    _ipmi_fru_set_op_write_complete(fru, fru_write_complete);
    _ipmi_fru_set_op_write(fru, fru_write);
    _ipmi_fru_set_op_get_root_node(fru, fru_get_root_node);

    _ipmi_fru_set_is_normal_fru(fru, 1);
    return info;
}

static int
process_fru_info(ipmi_fru_t *fru)
{
    normal_fru_rec_data_t *info;
    ipmi_fru_record_t **recs;
    unsigned char     *data = _ipmi_fru_get_data_ptr(fru);
    unsigned int      data_len = _ipmi_fru_get_data_len(fru);
    fru_offset_t      foff[IPMI_FRU_FTR_NUMBER];
    int               i, j;
    int               err = 0;
    unsigned char     version;

    if (checksum(data, 8) != 0)
	return EBADF;

    version = *data;
    if ((version != 1) && (version != 2))
	/* Only support version 1 */
	/* The IPMI 0.9 to IPMI 1.0 Change Summary and Porting Considerations
	 * from October 1, 1998 mention under FRU changes (Pg. 4)
	 * "The FRU format version has been updated to 02h from 01h"
	 * Unfortunately, some companies (such as Fujitsu Siemens Computers)
	 * used this information for production tools.
	 */
	return EBADF;

    for (i=0; i<IPMI_FRU_FTR_NUMBER; i++) {
	foff[i].type = i;
	if (! (_ipmi_fru_get_fetch_mask(fru) & (1 << i))) {
	    foff[i].offset = 0;
	    continue;
	}
	foff[i].offset = data[i+1] * 8;
	if (foff[i].offset >= data_len) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%snormal_fru.c(process_fru_info):"
		     " FRU offset exceeds data length",
		     _ipmi_fru_get_iname(fru));
	    return EBADF;
	}
    }

    /* Fields are *supposed* to occur in the specified order.  Verify
       this. */
    for (i=0, j=1; j<IPMI_FRU_FTR_NUMBER; i=j, j++) {
	if (foff[i].offset == 0)
	    continue;
	while (foff[j].offset == 0) {
	    j++;
	    if (j >= IPMI_FRU_FTR_NUMBER)
	        goto check_done;
	}
	if (foff[i].offset >= foff[j].offset) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "%snormal_fru.c(process_fru_info):"
		     " FRU fields did not occur in the correct order",
		     _ipmi_fru_get_iname(fru));
	}
    }
 check_done:

    info = setup_normal_fru(fru, version);
    if (!info)
	return ENOMEM;

    recs = info->recs;
    for (i=0; i<IPMI_FRU_FTR_NUMBER; i++) {
	int plen, next_off, offset;

	offset = foff[i].offset;
	if (offset == 0)
	    continue;

	for (j=i+1; j<IPMI_FRU_FTR_NUMBER; j++) {
	    if (foff[j].offset)
		break;
	}
	
	if (j >= IPMI_FRU_FTR_NUMBER)
	    next_off = data_len;
	else
	    next_off = foff[j].offset;
	plen = next_off - offset;

	err = fru_area_info[i].decode(fru, data+offset, plen, &recs[i]);
	if (err)
	    goto out_err;

	if (recs[i])
	    recs[i]->offset = offset;
    }

    return 0;

 out_err:
    /* Clear out the FRU information. */
    _ipmi_fru_set_op_cleanup_recs(fru, NULL);
    _ipmi_fru_set_op_write_complete(fru, NULL);
    _ipmi_fru_set_op_write(fru, NULL);
    _ipmi_fru_set_op_get_root_node(fru, NULL);

    /* This must be after setting cleanup_recs() */
    fru_cleanup_recs(fru);
    _ipmi_fru_set_rec_data(fru, NULL);

    _ipmi_fru_set_is_normal_fru(fru, 0);

    return err;
}

/************************************************************************
 *
 * Init/shutdown
 *
 ************************************************************************/

static int fru_initialized;

int
_ipmi_normal_fru_init(void)
{
    int rv;

    if (fru_initialized)
	return 0;

    fru_multi_record_oem_handlers = locked_list_alloc
	(ipmi_get_global_os_handler());
    if (!fru_multi_record_oem_handlers)
        return ENOMEM;

    rv = _ipmi_fru_register_multi_record_oem_handler(0,
						     0x00,
						     std_get_mr_root,
						     NULL);
    if (rv) {
	locked_list_destroy(fru_multi_record_oem_handlers);
	fru_multi_record_oem_handlers = NULL;
	return rv;
    }

    rv = _ipmi_fru_register_multi_record_oem_handler(0,
						     0x01,
						     std_get_mr_root,
						     NULL);
    if (rv) {
	_ipmi_fru_deregister_multi_record_oem_handler(0, 0x00);
	locked_list_destroy(fru_multi_record_oem_handlers);
	fru_multi_record_oem_handlers = NULL;
	return rv;
    }

    rv = _ipmi_fru_register_multi_record_oem_handler(0,
						     0x02,
						     std_get_mr_root,
						     NULL);
    if (rv) {
	_ipmi_fru_deregister_multi_record_oem_handler(0, 0x01);
	_ipmi_fru_deregister_multi_record_oem_handler(0, 0x00);
	locked_list_destroy(fru_multi_record_oem_handlers);
	fru_multi_record_oem_handlers = NULL;
	return rv;
    }

    rv = _ipmi_fru_register_decoder(process_fru_info);
    if (rv) {
	_ipmi_fru_deregister_multi_record_oem_handler(0, 0x02);
	_ipmi_fru_deregister_multi_record_oem_handler(0, 0x01);
	_ipmi_fru_deregister_multi_record_oem_handler(0, 0x00);
	locked_list_destroy(fru_multi_record_oem_handlers);
	fru_multi_record_oem_handlers = NULL;
	return rv;
    }

    fru_initialized = 1;

    return 0;
}

void
_ipmi_normal_fru_shutdown(void)
{
    if (fru_initialized) {
	_ipmi_fru_deregister_decoder(process_fru_info);
	_ipmi_fru_deregister_multi_record_oem_handler(0, 0x00);
	_ipmi_fru_deregister_multi_record_oem_handler(0, 0x01);
	_ipmi_fru_deregister_multi_record_oem_handler(0, 0x02);
	locked_list_destroy(fru_multi_record_oem_handlers);
	fru_multi_record_oem_handlers = NULL;
	fru_initialized = 0;
    }
}

/***********************************************************************
 *
 * Table-driven data engine for handling multirecord fru info.
 *
 **********************************************************************/
static int ipmi_mr_node_struct_get_field(ipmi_fru_node_t           *node,
					 unsigned int              index,
					 const char                **name,
					 enum ipmi_fru_data_type_e *dtype,
					 int                       *intval,
					 time_t                    *time,
					 double                    *floatval,
					 char                      **data,
					 unsigned int              *data_len,
					 ipmi_fru_node_t           **sub_node);
static int ipmi_mr_node_struct_get_enum(ipmi_fru_node_t *node,
					unsigned int    index,
					int             *pos,
					int             *nextpos,
					const char      **data);
static int ipmi_mr_node_struct_set_field(ipmi_fru_node_t           *node,
					 unsigned int              index,
					 enum ipmi_fru_data_type_e dtype,
					 int                       intval,
					 time_t                    time,
					 double                    floatval,
					 char                      *data,
					 unsigned int              data_len);
static int ipmi_mr_node_struct_settable(ipmi_fru_node_t *node,
					unsigned int    index);

uint8_t
ipmi_mr_full_offset(ipmi_mr_offset_t *o)
{
    uint8_t rv = 0;

    while (o) {
	rv += o->offset;
	o = o->parent;
    }
    return rv;
}

void
ipmi_mr_adjust_len(ipmi_mr_offset_t *o, int len)
{
    while (o) {
	ipmi_mr_offset_t *l = o->next;
	while (l) {
	    l->offset += len;
	    l = l->next;
	}
	o->length += len;
	o = o->parent;
    }
}

void
ipmi_mr_struct_cleanup(ipmi_mr_struct_info_t *rec)
{
    unsigned int i;

    if (rec->data)
	ipmi_mem_free(rec->data);
    if (rec->arrays) {
	ipmi_mr_struct_layout_t *layout = rec->layout;
	for (i=0; i<layout->array_count; i++) {
	    if (rec->arrays[i].layout)
		rec->arrays[i].layout->cleanup(rec->arrays+i);
	}
	ipmi_mem_free(rec->arrays);
    }
    ipmi_mem_free(rec);
}

void
ipmi_mr_item_cleanup(ipmi_mr_item_info_t *rec)
{
    if (rec->data)
	ipmi_mem_free(rec->data);
    ipmi_mem_free(rec);
}

static void
ipmi_mr_struct_root_destroy(ipmi_fru_node_t *node)
{
    ipmi_mr_struct_info_t *rec      = _ipmi_fru_node_get_data(node);
    ipmi_mr_fru_info_t    *finfo    = _ipmi_fru_node_get_data2(node);
    ipmi_mr_struct_layout_t *layout = rec->layout;
    ipmi_fru_deref(finfo->fru);
    layout->cleanup(rec);
    ipmi_mem_free(finfo);
}

static void
ipmi_mr_sub_destroy(ipmi_fru_node_t *node)
{
    ipmi_fru_node_t *root_node = _ipmi_fru_node_get_data2(node);
    ipmi_fru_put_node(root_node);
}

static int
ins_array_item(ipmi_mr_array_info_t *arec,
	       ipmi_mr_fru_info_t   *finfo,
	       ipmi_mr_offset_t     *poff,
	       int                  index,
	       char                 *data,
	       unsigned int         data_len,
	       unsigned char        **rdata)
{
    ipmi_mr_offset_t **newa;
    ipmi_mr_offset_t **olda;
    unsigned char    *sdata;
    int              i, j;
    int              rv;
    int              no;

    /* insert a new entry */
    if (index > arec->count)
	index = arec->count;

    if (arec->count >= 255)
	return E2BIG;

    newa = ipmi_mem_alloc(sizeof(*newa) * (arec->count+1));
    if (!newa)
	return ENOMEM;
    sdata = ipmi_mem_alloc(arec->layout->min_elem_size);
    if (!sdata) {
	ipmi_mem_free(newa);
	return ENOMEM;
    }
    memset(sdata, 0, arec->layout->min_elem_size);
    if (data) {
	if (data_len > arec->layout->min_elem_size)
	    memcpy(sdata, data, arec->layout->min_elem_size);
	else
	    memcpy(sdata, data, data_len);
    }

    poff->parent = &arec->offset;
    poff->length = arec->layout->min_elem_size;
    if (index == arec->count) {
	poff->offset = arec->offset.length;
	poff->next = NULL;
    } else {
	ipmi_mr_offset_t *o = arec->items[index];
	poff->offset = o->offset;
	poff->next = o;
    }

    rv = ipmi_fru_ins_multi_record_data(finfo->fru, finfo->mr_rec_num,
					sdata,
					ipmi_mr_full_offset(poff),
					arec->layout->min_elem_size);
    if (rv) {
	ipmi_mem_free(sdata);
	ipmi_mem_free(newa);
	return rv;
    }

    if (index > 0) {
	ipmi_mr_offset_t *o = arec->items[index-1];
	o->next = poff;
    }
    ipmi_mr_adjust_len(&arec->offset, arec->layout->min_elem_size);

    if (arec->items) {
	no = 0;
	for (i=0, j=0; i<(int)arec->count; j++) {
	    ipmi_mr_offset_t *o = arec->items[i];
	    if (j == (int) index) {
		no = arec->layout->min_elem_size;
		continue;
	    }
	    newa[j] = o;
	    o->offset += no;
	    i++;
	}
    }
    newa[index] = poff;
	
    no = arec->layout->min_elem_size;

    arec->count += 1;

    /* Adjust the arrays that come after me in the record. */
    for (j=0; j<arec->nr_after; j++) {
	ipmi_mr_array_info_t *ai = arec + j + 1;
	
	ai->offset.offset += no;
	for (i=0; i<(int)ai->count; i++) {
	    ipmi_mr_offset_t *o = ai->items[i];
	    o->offset += no;
	}
    }

    olda = arec->items;
    arec->items = newa;
    if (arec->layout->has_count)
	ipmi_fru_ovw_multi_record_data(finfo->fru, finfo->mr_rec_num,
				       &arec->count,
				       ipmi_mr_full_offset(&arec->offset), 1);
    if (olda)
	ipmi_mem_free(olda);

    *rdata = sdata;
    return 0;
}

static int
del_array_item(ipmi_mr_array_info_t *arec,
	       ipmi_mr_fru_info_t   *finfo,
	       int                  index,
	       ipmi_mr_offset_t     **delitem)
{
    ipmi_mr_offset_t **newa;
    ipmi_mr_offset_t **olda;
    int              i, j;
    int              rv;
    int              no;
    ipmi_mr_offset_t *poff;

    index = (-index) - 1;
    if (index > arec->count)
	return EINVAL;

    poff = arec->items[index];

    newa = ipmi_mem_alloc(sizeof(*newa) * (arec->count-1));
    if (!newa)
	return ENOMEM;
    rv = ipmi_fru_del_multi_record_data(finfo->fru, finfo->mr_rec_num,
					ipmi_mr_full_offset(poff),
					poff->length);
    if (rv) {
	ipmi_mem_free(newa);
	return rv;
    }

    if (index > 0) {
	ipmi_mr_offset_t *o = arec->items[index-1];
	o->next = poff->next;
    }

    ipmi_mr_adjust_len(&arec->offset, - (int) poff->length);

    no = 0;
    for (i=0, j=0; j<(int)arec->count; j++) {
	ipmi_mr_offset_t *o = arec->items[j];
	if (j == (int) index) {
	    no = - poff->length;
	    continue;
	}
	newa[i] = o;
	o->offset += no;
	i++;
    }
    no = - poff->length;

    arec->count -= 1;

    /* Adjust the arrays that come after me in the record. */
    for (j=0; j<arec->nr_after; j++) {
	ipmi_mr_array_info_t *ai = arec + j + 1;
	
	ai->offset.offset += no;
	for (i=0; i<(int)ai->count; i++) {
	    ipmi_mr_offset_t *o = ai->items[i];
	    o->offset += no;
	}
    }

    olda = arec->items;
    arec->items = newa;
    if (arec->layout->has_count)
	ipmi_fru_ovw_multi_record_data(finfo->fru, finfo->mr_rec_num,
				       &arec->count,
				       ipmi_mr_full_offset(&arec->offset), 1);
    if (olda)
	ipmi_mem_free(olda);

    *delitem = poff;

    return 0;
}

void
ipmi_mr_array_array_cleanup(ipmi_mr_array_info_t *arec)
{
    int i;

    if (arec->items) {
	for (i=0; i<arec->count; i++) {
	    if (arec->items[i]) {
		ipmi_mr_array_layout_t *layout = arec->layout->elem_layout;
		layout->cleanup((void *) arec->items[i]);
	    }
	}
	ipmi_mem_free(arec->items);
    }
}

void
ipmi_mr_item_array_cleanup(ipmi_mr_array_info_t *arec)
{
    int i;

    if (arec->items) {
	for (i=0; i<arec->count; i++) {
	    if (arec->items[i]) {
		ipmi_mr_item_info_t *irec = (void *) arec->items[i];
		if (irec->data)
		    ipmi_mem_free(irec->data);
		ipmi_mem_free(irec);
	    }
	}
	ipmi_mem_free(arec->items);
    }
}

static int
ipmi_mr_node_item_array_set_field(ipmi_fru_node_t           *node,
				  unsigned int              index,
				  enum ipmi_fru_data_type_e dtype,
				  int                       intval,
				  time_t                    time,
				  double                    floatval,
				  char                      *data,
				  unsigned int              data_len)
{
    ipmi_mr_array_info_t  *arec = _ipmi_fru_node_get_data(node);
    ipmi_fru_node_t       *rnode = _ipmi_fru_node_get_data2(node);
    ipmi_mr_item_info_t   *info;
    ipmi_mr_item_layout_t *layout = arec->layout->elem_layout;
    ipmi_mr_fru_info_t    *finfo =_ipmi_fru_node_get_data2(rnode);
    ipmi_mr_getset_t      gs = { layout, NULL, NULL, finfo };
    int                   rv = EINVAL;

    _ipmi_fru_lock(finfo->fru);
    if (index >= arec->count) {
	rv = EINVAL;
	goto out;
    }

    info = (void *) arec->items[index];
    gs.rdata = info->data;
    gs.offset = arec->items[index];
    rv = layout->set_field(&gs,
			   dtype, intval, time, floatval, data, data_len);
 out:
    _ipmi_fru_unlock(finfo->fru);
    return rv;
}

static int
ipmi_mr_node_item_array_get_subtype(ipmi_fru_node_t           *node,
				    enum ipmi_fru_data_type_e *dtype)
{
    ipmi_mr_array_info_t  *arec = _ipmi_fru_node_get_data(node);
    ipmi_mr_item_layout_t *layout = arec->layout->elem_layout;

    *dtype = layout->dtype;
    return 0;
}

static int
ipmi_mr_node_item_array_settable(ipmi_fru_node_t *node,
				 unsigned int    index)
{
    ipmi_mr_array_info_t  *arec = _ipmi_fru_node_get_data(node);
    ipmi_mr_item_layout_t *layout = arec->layout->elem_layout;

    if (layout->settable)
	return 0;
    else
	return EPERM;
}

static int
ipmi_mr_node_item_array_get_field(ipmi_fru_node_t           *node,
				  unsigned int              index,
				  const char                **name,
				  enum ipmi_fru_data_type_e *dtype,
				  int                       *intval,
				  time_t                    *time,
				  double                    *floatval,
				  char                      **data,
				  unsigned int              *data_len,
				  ipmi_fru_node_t           **sub_node)
{
    ipmi_mr_array_info_t  *arec = _ipmi_fru_node_get_data(node);
    ipmi_mr_item_layout_t *layout = arec->layout->elem_layout;
    ipmi_mr_item_info_t   *info;
    ipmi_fru_node_t       *rnode =_ipmi_fru_node_get_data2(node);
    ipmi_mr_fru_info_t    *finfo =_ipmi_fru_node_get_data2(rnode);
    ipmi_mr_getset_t      gs = { layout, NULL, NULL, finfo };
    int                   rv = EINVAL;

    _ipmi_fru_lock(finfo->fru);
    if (index >= arec->count) {
	rv = EINVAL;
	goto out;
    }

    info = (void *) arec->items[index];
    gs.rdata = info->data;
    gs.offset = arec->items[index];
    rv = layout->get_field(&gs,
			   dtype, intval, time, floatval, data, data_len);
 out:
    _ipmi_fru_unlock(finfo->fru);
    return rv;
}

static int
ipmi_mr_node_item_array_get_enum(ipmi_fru_node_t *node,
				 unsigned int    index,
				 int             *pos,
				 int             *nextpos,
				 const char      **data)
{
    ipmi_mr_array_info_t  *arec = _ipmi_fru_node_get_data(node);
    ipmi_mr_item_layout_t *layout = arec->layout->elem_layout;
    ipmi_mr_item_info_t   *info;
    ipmi_fru_node_t       *rnode =_ipmi_fru_node_get_data2(node);
    ipmi_mr_fru_info_t    *finfo =_ipmi_fru_node_get_data2(rnode);
    ipmi_mr_getset_t      gs = { layout, NULL, NULL, finfo };
    int                   rv;

    _ipmi_fru_lock(finfo->fru);
    if (index >= arec->count) {
	rv = EINVAL;
	goto out;
    }

    if (!layout->get_enum) {
	rv = ENOSYS;
	goto out;
    }

    info = (void *) arec->items[index];
    gs.rdata = info->data;
    gs.offset = arec->items[index];
    rv = layout->get_enum(&gs, pos, nextpos, data);
 out:
    _ipmi_fru_unlock(finfo->fru);
    return rv;
}

int
ipmi_mr_item_array_set_field(ipmi_mr_array_info_t      *arec,
			     ipmi_mr_fru_info_t        *finfo,
			     enum ipmi_fru_data_type_e dtype,
			     int                       intval,
			     time_t                    time,
			     double                    floatval,
			     char                      *data,
			     unsigned int              data_len)
{
    int index = intval;
    int rv;

    if (index >= 0) {
	ipmi_mr_item_info_t *newv;

	newv = ipmi_mem_alloc(sizeof(*newv));
	if (!newv)
	    return ENOMEM;
	memset(newv, 0, sizeof(*newv));
	newv->layout = arec->layout->elem_layout;

	rv = ins_array_item(arec, finfo, &newv->offset, index, data, data_len,
			    &newv->data);
	if (rv)
	    ipmi_mem_free(newv);
    } else {
	ipmi_mr_offset_t      *delo;
	ipmi_mr_item_info_t *delv;

	rv = del_array_item(arec, finfo, index, &delo);
	if (!rv) {
	    delv = (void *) delo;
	    if (delv->data)
		ipmi_mem_free(delv->data);
	    ipmi_mem_free(delv);
	}
    }

    return rv;
}

int
ipmi_mr_item_array_get_field(ipmi_mr_array_info_t      *arec,
			     ipmi_fru_node_t           *rnode,
			     enum ipmi_fru_data_type_e *dtype,
			     int                       *intval,
			     time_t                    *time,
			     double                    *floatval,
			     char                      **data,
			     unsigned int              *data_len,
			     ipmi_fru_node_t           **sub_node)
{
    ipmi_fru_node_t    *node;
    ipmi_mr_fru_info_t *finfo = _ipmi_fru_node_get_data2(rnode);

    if (dtype)
	*dtype = IPMI_FRU_DATA_SUB_NODE;
    if (intval)
	*intval = arec->count;
    if (sub_node) {
	node = _ipmi_fru_node_alloc(finfo->fru);
	if (!node)
	    return ENOMEM;
	ipmi_fru_get_node(rnode);
	_ipmi_fru_node_set_data(node, arec);
	_ipmi_fru_node_set_data2(node, rnode);
	_ipmi_fru_node_set_get_field(node,
				     ipmi_mr_node_item_array_get_field);
	_ipmi_fru_node_set_get_enum(node, 
				    ipmi_mr_node_item_array_get_enum);
	_ipmi_fru_node_set_set_field(node,
				     ipmi_mr_node_item_array_set_field);
	_ipmi_fru_node_set_settable(node, ipmi_mr_node_item_array_settable);
	_ipmi_fru_node_set_get_subtype(node,
				       ipmi_mr_node_item_array_get_subtype);
	_ipmi_fru_node_set_destructor(node, ipmi_mr_sub_destroy);
	*sub_node = node;
    }
    return 0;
}

void
ipmi_mr_struct_array_cleanup(ipmi_mr_array_info_t *arec)
{
    int i;

    if (arec->items) {
	for (i=0; i<arec->count; i++) {
	    if (arec->items[i]) {
		ipmi_mr_struct_layout_t *layout = arec->layout->elem_layout;
		layout->cleanup((void *) arec->items[i]);
	    }
	}
	ipmi_mem_free(arec->items);
    }
}

static int
ipmi_mr_node_struct_array_set_field(ipmi_fru_node_t           *node,
				    unsigned int              index,
				    enum ipmi_fru_data_type_e dtype,
				    int                       intval,
				    time_t                    time,
				    double                    floatval,
				    char                      *data,
				    unsigned int              data_len)
{
    return EPERM;
}

static int
ipmi_mr_node_struct_array_get_subtype(ipmi_fru_node_t           *node,
				      enum ipmi_fru_data_type_e *dtype)
{
    *dtype = IPMI_FRU_DATA_SUB_NODE;
    return 0;
}

static int
ipmi_mr_node_struct_array_settable(ipmi_fru_node_t *node,
				   unsigned int    index)
{
    return EPERM;
}

static int
ipmi_mr_node_struct_array_get_field(ipmi_fru_node_t           *node,
				    unsigned int              index,
				    const char                **name,
				    enum ipmi_fru_data_type_e *dtype,
				    int                       *intval,
				    time_t                    *time,
				    double                    *floatval,
				    char                      **data,
				    unsigned int              *data_len,
				    ipmi_fru_node_t           **sub_node)
{
    ipmi_mr_array_info_t *arec = _ipmi_fru_node_get_data(node);
    ipmi_fru_node_t      *rnode = _ipmi_fru_node_get_data2(node);
    ipmi_mr_fru_info_t   *finfo = _ipmi_fru_node_get_data2(rnode);
    int                  rv = 0;

    _ipmi_fru_lock(finfo->fru);
    if (index >= arec->count) {
	rv = EINVAL;
	goto out;
    }

    if (name)
	*name = NULL; /* We are an array */
    if (dtype)
	*dtype = IPMI_FRU_DATA_SUB_NODE;
    if (intval)
	*intval = -1; /* Sub element is not an array */
    if (sub_node) {
	node = _ipmi_fru_node_alloc(finfo->fru);
	if (!node) {
	    rv = ENOMEM;
	    goto out;
	}

	ipmi_fru_get_node(rnode);
	_ipmi_fru_node_set_data(node, arec->items[index]);
	_ipmi_fru_node_set_data2(node, rnode);
	_ipmi_fru_node_set_get_field(node, ipmi_mr_node_struct_get_field);
	_ipmi_fru_node_set_get_enum(node, ipmi_mr_node_struct_get_enum);
	_ipmi_fru_node_set_set_field(node, ipmi_mr_node_struct_set_field);
	_ipmi_fru_node_set_settable(node, ipmi_mr_node_struct_settable);
	_ipmi_fru_node_set_destructor(node, ipmi_mr_sub_destroy);

	*sub_node = node;
    }

 out:
    _ipmi_fru_unlock(finfo->fru);
    return rv;
}

int
ipmi_mr_struct_array_set_field(ipmi_mr_array_info_t      *arec,
			       ipmi_mr_fru_info_t        *finfo,
			       enum ipmi_fru_data_type_e dtype,
			       int                       intval,
			       time_t                    time,
			       double                    floatval,
			       char                      *data,
			       unsigned int              data_len)
{
    int index = intval;
    int rv;

    if (index >= 0) {
	ipmi_mr_struct_info_t *newv;

	newv = ipmi_mem_alloc(sizeof(*newv));
	if (!newv)
	    return ENOMEM;
	memset(newv, 0, sizeof(*newv));
	newv->layout = arec->layout->elem_layout;

	rv = ins_array_item(arec, finfo, &newv->offset, index, data, data_len,
			    &newv->data);
	if (rv)
	    ipmi_mem_free(newv);
    } else {
	ipmi_mr_offset_t      *delo;
	ipmi_mr_struct_info_t *delv;

	rv = del_array_item(arec, finfo, index, &delo);
	if (!rv) {
	    delv = (void *) delo;
	    delv->layout->cleanup(delv);
	}
    }

    return rv;
}

int
ipmi_mr_struct_array_get_field(ipmi_mr_array_info_t      *arec,
			       ipmi_fru_node_t           *rnode,
			       enum ipmi_fru_data_type_e *dtype,
			       int                       *intval,
			       time_t                    *time,
			       double                    *floatval,
			       char                      **data,
			       unsigned int              *data_len,
			       ipmi_fru_node_t           **sub_node)
{
    ipmi_fru_node_t    *node;
    ipmi_mr_fru_info_t *finfo = _ipmi_fru_node_get_data2(rnode);

    if (dtype)
	*dtype = IPMI_FRU_DATA_SUB_NODE;
    if (intval)
	*intval = arec->count;
    if (sub_node) {
	node = _ipmi_fru_node_alloc(finfo->fru);
	if (!node)
	    return ENOMEM;
	ipmi_fru_get_node(rnode);
	_ipmi_fru_node_set_data(node, arec);
	_ipmi_fru_node_set_data2(node, rnode);
	_ipmi_fru_node_set_get_field(node,
				     ipmi_mr_node_struct_array_get_field);
	_ipmi_fru_node_set_set_field(node,
				     ipmi_mr_node_struct_array_set_field);
	_ipmi_fru_node_set_settable(node, ipmi_mr_node_struct_array_settable);
	_ipmi_fru_node_set_get_subtype(node,
				       ipmi_mr_node_struct_array_get_subtype);
	_ipmi_fru_node_set_destructor(node, ipmi_mr_sub_destroy);
	*sub_node = node;
    }
    return 0;
}

static int
ipmi_mr_node_struct_set_field(ipmi_fru_node_t           *node,
			      unsigned int              index,
			      enum ipmi_fru_data_type_e dtype,
			      int                       intval,
			      time_t                    time,
			      double                    floatval,
			      char                      *data,
			      unsigned int              data_len)
{
    ipmi_mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    ipmi_fru_node_t         *rnode = _ipmi_fru_node_get_data2(node);
    ipmi_mr_struct_layout_t *layout = rec->layout;
    ipmi_mr_fru_info_t      *finfo = _ipmi_fru_node_get_data2(rnode);
    int                     rv = EINVAL;

    _ipmi_fru_lock(finfo->fru);
    if (index < layout->item_count) {
	ipmi_mr_item_layout_t *ilayout = layout->items+index;
	ipmi_mr_getset_t      gs = { ilayout, &rec->offset,
				     rec->data, finfo };
	if (!layout->items[index].set_field)
	    rv = EPERM;
	else
	    rv = layout->items[index].set_field(&gs,
						dtype, intval, time, floatval,
						data, data_len);
    } else {
	index -= layout->item_count;
	if (index < layout->array_count)
	    rv = layout->arrays[index].set_field(rec->arrays+index, finfo,
						 dtype, intval, time,
						 floatval, data, data_len);
    }
    _ipmi_fru_unlock(finfo->fru);

    return rv;
}

static int
ipmi_mr_root_node_struct_set_field(ipmi_fru_node_t           *node,
				   unsigned int              index,
				   enum ipmi_fru_data_type_e dtype,
				   int                       intval,
				   time_t                    time,
				   double                    floatval,
				   char                      *data,
				   unsigned int              data_len)
{
    ipmi_mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    ipmi_mr_struct_layout_t *layout = rec->layout;
    ipmi_mr_fru_info_t      *finfo = _ipmi_fru_node_get_data2(node);
    int                     rv = EINVAL;

    _ipmi_fru_lock(finfo->fru);
    if (index < layout->item_count) {
	ipmi_mr_getset_t gs = { layout->items+index, &rec->offset,
				rec->data, finfo };
	rv = layout->items[index].set_field(&gs,
					    dtype, intval, time, floatval,
					    data, data_len);
    } else {
	index -= layout->item_count;
	if (index < layout->array_count)
	    rv = layout->arrays[index].set_field(rec->arrays+index, finfo,
						 dtype, intval, time, floatval,
						 data, data_len);
    }
    _ipmi_fru_unlock(finfo->fru);

    return rv;
}

static int
ipmi_mr_node_struct_settable(ipmi_fru_node_t *node,
			     unsigned int    index)
{
    ipmi_mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    ipmi_mr_struct_layout_t *layout = rec->layout;
    ipmi_fru_node_t         *rnode =_ipmi_fru_node_get_data2(node);
    ipmi_mr_fru_info_t      *finfo =_ipmi_fru_node_get_data2(rnode);
    int                     rv = EINVAL;

    _ipmi_fru_lock(finfo->fru);
    if (index < layout->item_count) {
	if (layout->items[index].settable)
	    rv = 0;
	else
	    rv = EPERM;
    } else {
	index -= layout->item_count;
	if (index < layout->array_count) {
	    if (layout->arrays[index].settable)
		rv = 0;
	    else
		rv = EPERM;
	}
    }
    _ipmi_fru_unlock(finfo->fru);

    return rv;
}

static int
ipmi_mr_root_node_struct_settable(ipmi_fru_node_t *node,
				  unsigned int    index)
{
    ipmi_mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    ipmi_mr_struct_layout_t *layout = rec->layout;
    ipmi_mr_fru_info_t      *finfo =_ipmi_fru_node_get_data2(node);
    int                     rv = EINVAL;

    _ipmi_fru_lock(finfo->fru);
    if (index < layout->item_count) {
	if (layout->items[index].settable)
	    rv = 0;
	else
	    rv = EPERM;
    } else {
	index -= layout->item_count;
	if (index < layout->array_count) {
	    if (layout->arrays[index].settable)
		rv = 0;
	    else
		rv = EPERM;
	}
    }
    _ipmi_fru_unlock(finfo->fru);

    return rv;
}

static int
ipmi_mr_node_struct_get_enum(ipmi_fru_node_t *node,
			     unsigned int    index,
			     int             *pos,
			     int             *nextpos,
			     const char      **data)
{
    ipmi_mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    ipmi_mr_struct_layout_t *layout = rec->layout;
    ipmi_fru_node_t         *rnode =_ipmi_fru_node_get_data2(node);
    ipmi_mr_fru_info_t      *finfo =_ipmi_fru_node_get_data2(rnode);
    int                     rv = EINVAL;

    _ipmi_fru_lock(finfo->fru);
    if (index < layout->item_count) {
	ipmi_mr_getset_t gs = { layout->items+index, &rec->offset,
				rec->data, finfo };
	if (! layout->items[index].get_enum)
	    rv = ENOSYS;
	else
	    rv = layout->items[index].get_enum(&gs, pos, nextpos, data);
    } else {
	index -= layout->item_count;
	if (index < layout->array_count)
	    rv = ENOSYS;
    }
    _ipmi_fru_unlock(finfo->fru);

    return rv;
}

static int
ipmi_mr_node_struct_get_field(ipmi_fru_node_t           *node,
			      unsigned int              index,
			      const char                **name,
			      enum ipmi_fru_data_type_e *dtype,
			      int                       *intval,
			      time_t                    *time,
			      double                    *floatval,
			      char                      **data,
			      unsigned int              *data_len,
			      ipmi_fru_node_t           **sub_node)
{
    ipmi_mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    ipmi_mr_struct_layout_t *layout = rec->layout;
    ipmi_fru_node_t         *rnode =_ipmi_fru_node_get_data2(node);
    ipmi_mr_fru_info_t      *finfo =_ipmi_fru_node_get_data2(rnode);
    int                     rv = EINVAL;

    _ipmi_fru_lock(finfo->fru);
    if (index < layout->item_count) {
	ipmi_mr_getset_t gs = { layout->items+index, &rec->offset,
				rec->data, finfo };
	if (name)
	    *name = layout->items[index].name;
	rv = layout->items[index].get_field(&gs, dtype,
					    intval, time, floatval,
					    data, data_len);
    } else {
	index -= layout->item_count;
	if (index < layout->array_count) {
	    if (name)
		*name = layout->arrays[index].name;
	    
	    rv = layout->arrays[index].get_field(rec->arrays+index, rnode,
						 dtype, intval, time, floatval,
						 data, data_len, sub_node);
	}
    }
    _ipmi_fru_unlock(finfo->fru);

    return rv;
}

static int
ipmi_mr_root_node_struct_get_field(ipmi_fru_node_t           *node,
				   unsigned int              index,
				   const char                **name,
				   enum ipmi_fru_data_type_e *dtype,
				   int                       *intval,
				   time_t                    *time,
				   double                    *floatval,
				   char                      **data,
				   unsigned int              *data_len,
				   ipmi_fru_node_t           **sub_node)
{
    ipmi_mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    ipmi_mr_struct_layout_t *layout = rec->layout;
    ipmi_mr_fru_info_t      *finfo =_ipmi_fru_node_get_data2(node);
    int                     rv = EINVAL;

    _ipmi_fru_lock(finfo->fru);
    if (index < layout->item_count) {
	ipmi_mr_getset_t gs = { layout->items+index, &rec->offset,
				rec->data, finfo };
	if (name)
	    *name = layout->items[index].name;
	rv = layout->items[index].get_field(&gs, dtype,
					    intval, time, floatval,
					    data, data_len);
    } else {
	index -= layout->item_count;
	if (index < layout->array_count) {
	    if (name)
		*name = layout->arrays[index].name;

	    rv = layout->arrays[index].get_field(rec->arrays+index,
						 node, dtype,
						 intval, time, floatval,
						 data, data_len, sub_node);
	}
    }
    _ipmi_fru_unlock(finfo->fru);

    return rv;
}

static int
ipmi_mr_root_node_struct_get_enum(ipmi_fru_node_t *node,
				  unsigned int    index,
				  int             *pos,
				  int             *nextpos,
				  const char      **data)
{
    ipmi_mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    ipmi_mr_struct_layout_t *layout = rec->layout;
    ipmi_mr_fru_info_t      *finfo =_ipmi_fru_node_get_data2(node);
    int                     rv = EINVAL;

    _ipmi_fru_lock(finfo->fru);
    if (index < layout->item_count) {
	ipmi_mr_getset_t gs = { layout->items+index, &rec->offset,
				rec->data, finfo };
	if (! layout->items[index].get_enum)
	    rv = ENOSYS;
	else
	    rv = layout->items[index].get_enum(&gs, pos, nextpos, data);
    } else {
	index -= layout->item_count;
	if (index < layout->array_count)
	    rv = ENOSYS;
    }
    _ipmi_fru_unlock(finfo->fru);

    return rv;
}

int
ipmi_mr_struct_elem_check(void          *vlayout,
			  unsigned char **rmr_data,
			  unsigned int  *rmr_data_len)
{
    ipmi_mr_struct_layout_t *layout = vlayout;
    unsigned char           *mr_data = *rmr_data;
    unsigned int            mr_data_len = *rmr_data_len;
    int                     i, j;
    int                     rv;

    if (mr_data_len < layout->length)
	return EINVAL;

    mr_data += layout->length;
    mr_data_len -= layout->length;

    for (i=0; i<(int)layout->array_count; i++) {
	ipmi_mr_array_layout_t *al = layout->arrays + i;
	unsigned int           count;

	if (al->has_count) {
	    if (mr_data_len < 1)
		return EINVAL;
	    count = *mr_data;
	    mr_data++;
	    mr_data_len--;
	    for (j=0; j<(int)count; j++) {
		rv = al->elem_check(al->elem_layout, &mr_data, &mr_data_len);
		if (rv)
		    return rv;
	    }
	} else {
	    count = 0;
	    while (mr_data_len > 0) {
		rv = al->elem_check(al->elem_layout, &mr_data, &mr_data_len);
		if (rv)
		    return rv;
		count++;
	    }
	}
    }

    *rmr_data = mr_data;
    *rmr_data_len = mr_data_len;

    return 0;
}

int
ipmi_mr_struct_decode(void             *vlayout,
		      unsigned int     offset,
		      ipmi_mr_offset_t *offset_parent,
		      ipmi_mr_offset_t **rrec,
		      unsigned char    **rmr_data,
		      unsigned int     *rmr_data_len)
{
    unsigned char           *mr_data = *rmr_data;
    unsigned int            mr_data_len = *rmr_data_len;
    int                     i, j;
    ipmi_mr_struct_layout_t *layout = vlayout;
    int                     rv;
    ipmi_mr_struct_info_t   *rec;
    ipmi_mr_array_info_t    *ap;

    if (mr_data_len < layout->length)
	return EINVAL;

    rec = ipmi_mem_alloc(sizeof(*rec));
    if (!rec)
	return ENOMEM;
    memset(rec, 0, sizeof(*rec));

    rec->offset.offset = offset;
    rec->offset.parent = offset_parent;
    rec->offset.next = NULL;
    rec->layout = layout;

    if (layout->length > 0) {
	rec->data = ipmi_mem_alloc(layout->length);
	if (!rec->data) {
	    rv = ENOMEM;
	    goto out_err;
	}
	memcpy(rec->data, mr_data, layout->length);
	mr_data += layout->length;
	mr_data_len -= layout->length;
    }

    if (layout->array_count > 0) {
	rec->arrays = ipmi_mem_alloc(sizeof(*(rec->arrays))
				     * layout->array_count);
	if (!rec->arrays) {
	    rv = ENOMEM;
	    goto out_err;
	}
	memset(rec->arrays, 0, sizeof(*(rec->arrays)) * layout->array_count);
    }

    ap = NULL;
    for (i=0; i<(int)layout->array_count; i++) {
	ipmi_mr_array_layout_t *al = layout->arrays + i;
	ipmi_mr_array_info_t   *ai = rec->arrays + i;
	unsigned int           count;
	unsigned char          *astart_mr_data = mr_data;

	ai->offset.offset = mr_data - *rmr_data;
	ai->offset.parent = &(rec->offset);
	ai->offset.next = NULL;
	if (ap)
	    ap->offset.next = &ai->offset;

	ai->nr_after = layout->array_count - i - 1;
	ai->layout = al;
	if (al->has_count) {
	    if (mr_data_len < 1) {
		rv = EINVAL;
		goto out_err;
	    }
	    count = *mr_data;
	    mr_data++;
	    mr_data_len--;
	} else {
	    unsigned char *d = mr_data;
	    unsigned int  l = mr_data_len;

	    count = 0;
	    while (l > 0) {
		rv = al->elem_check(al->elem_layout, &d, &l);
		if (rv)
		    goto out_err;
		count++;
	    }
	}
	if (count > 0) {
	    ipmi_mr_offset_t *p;

	    ai->count = count;
	    ai->items = ipmi_mem_alloc(sizeof(*(ai->items)) * count);
	    if (!ai->items)
		return ENOMEM;
	    memset(ai->items, 0, sizeof(*(ai->items)) * count);
	    p = NULL;
	    for (j=0; j<(int)count; j++) {
		ipmi_mr_offset_t *r;

		rv = al->elem_decode(al->elem_layout,
				     mr_data - astart_mr_data,
				     &ai->offset,
				     &r,
				     &mr_data,
				     &mr_data_len);
		if (rv)
		    goto out_err;

		if (p)
		    p->next = r;
		ai->items[j] = r;
		p = r;
	    }
	}
	ai->offset.length = mr_data - astart_mr_data;
	ap = ai;
    }

    rec->offset.length = mr_data - *rmr_data;
    *rmr_data = mr_data;
    *rmr_data_len = mr_data_len;
    *rrec = &rec->offset;

    return 0;

 out_err:
    ipmi_mr_struct_cleanup(rec);
    return rv;
}

int
ipmi_mr_item_elem_check(void          *vlayout,
			unsigned char **rmr_data,
			unsigned int  *rmr_data_len)
{
    ipmi_mr_item_layout_t *layout = vlayout;
    unsigned char         *mr_data = *rmr_data;
    unsigned int          mr_data_len = *rmr_data_len;

    if (mr_data_len < layout->length)
	return EINVAL;

    mr_data += layout->length;
    mr_data_len -= layout->length;

    *rmr_data = mr_data;
    *rmr_data_len = mr_data_len;

    return 0;
}

int
ipmi_mr_item_decode(void             *vlayout,
		    unsigned int     offset,
		    ipmi_mr_offset_t *offset_parent,
		    ipmi_mr_offset_t **rrec,
		    unsigned char    **rmr_data,
		    unsigned int     *rmr_data_len)
{
    unsigned char         *mr_data = *rmr_data;
    unsigned int          mr_data_len = *rmr_data_len;
    ipmi_mr_item_layout_t *layout = vlayout;
    int                   rv;
    ipmi_mr_item_info_t   *rec;

    if (mr_data_len < layout->length)
	return EINVAL;

    rec = ipmi_mem_alloc(sizeof(*rec));
    if (!rec)
	return ENOMEM;
    memset(rec, 0, sizeof(*rec));

    rec->offset.offset = offset;
    rec->offset.parent = offset_parent;
    rec->offset.next = NULL;
    rec->layout = layout;

    if (layout->length > 0) {
	rec->data = ipmi_mem_alloc(layout->length);
	if (!rec->data) {
	    rv = ENOMEM;
	    goto out_err;
	}
	memcpy(rec->data, mr_data, layout->length);
	mr_data += layout->length;
	mr_data_len -= layout->length;
    }

    rec->offset.length = mr_data - *rmr_data;
    *rmr_data = mr_data;
    *rmr_data_len = mr_data_len;

    *rrec = &rec->offset;

    return 0;

 out_err:
    ipmi_mr_item_cleanup(rec);
    return rv;
}

int
ipmi_mr_struct_root(ipmi_fru_t              *fru,
		    unsigned int            mr_rec_num,
		    unsigned char           *rmr_data,
		    unsigned int            rmr_data_len,
		    ipmi_mr_struct_layout_t *layout,
		    const char              **name,
		    ipmi_fru_node_t         **rnode)
{
    unsigned char         *mr_data = rmr_data;
    unsigned int          mr_data_len = rmr_data_len;
    ipmi_mr_offset_t      *orec;
    ipmi_fru_node_t       *node;
    ipmi_mr_fru_info_t    *finfo = NULL;
    int                   rv;

    if (mr_data_len == 0)
	return EINVAL;
    
    _ipmi_fru_lock(fru);
    rv = ipmi_mr_struct_decode(layout, 4, NULL, &orec, &mr_data, &mr_data_len);
    if (rv) {
        _ipmi_fru_unlock(fru);
	return rv;
    }

    finfo = ipmi_mem_alloc(sizeof(*finfo));
    if (!finfo)
	goto out_no_mem;
    _ipmi_fru_ref_nolock(fru);
    finfo->fru = fru;
    finfo->mr_rec_num = mr_rec_num;

    node = _ipmi_fru_node_alloc(fru);
    if (!node)
	goto out_no_mem;

    _ipmi_fru_node_set_data(node, orec);
    _ipmi_fru_node_set_data2(node, finfo);
    _ipmi_fru_node_set_get_field(node, ipmi_mr_root_node_struct_get_field);
    _ipmi_fru_node_set_get_enum(node, ipmi_mr_root_node_struct_get_enum);
    _ipmi_fru_node_set_set_field(node, ipmi_mr_root_node_struct_set_field);
    _ipmi_fru_node_set_settable(node, ipmi_mr_root_node_struct_settable);
    _ipmi_fru_node_set_destructor(node, ipmi_mr_struct_root_destroy);

    *rnode = node;

    if (name)
	*name = layout->name;
    _ipmi_fru_unlock(fru);

    return 0;

 out_no_mem:
    _ipmi_fru_unlock(fru);
    rv = ENOMEM;

    if (finfo) {
	ipmi_fru_deref(fru);
	ipmi_mem_free(finfo);
    }
    ipmi_mr_struct_cleanup((void *) orec);
    return rv;
}


/***********************************************************************
 *
 * Generic field encoders and decoders.
 *
 **********************************************************************/

int
ipmi_mr_int_set_field(ipmi_mr_getset_t          *getset,
		      enum ipmi_fru_data_type_e dtype,
		      int                       intval,
		      time_t                    time,
		      double                    floatval,
		      char                      *data,
		      unsigned int              data_len)
{
    unsigned char *c = getset->rdata + getset->layout->start;
    unsigned int  val = intval;
    int           i;

    if (dtype != getset->layout->dtype)
	return EINVAL;

    if (dtype == IPMI_FRU_DATA_BOOLEAN)
	val = !!val;

    for (i=0; i<getset->layout->length; i++) {
	*c = val & 0xff;
	val >>= 8;
	c++;
    }
    c = getset->rdata + getset->layout->start;
    ipmi_fru_ovw_multi_record_data(getset->finfo->fru,
				   getset->finfo->mr_rec_num, c,
				   (ipmi_mr_full_offset(getset->offset)
				    +getset->layout->start),
				   getset->layout->length);
    return 0;
}

int
ipmi_mr_int_get_field(ipmi_mr_getset_t          *getset,
		      enum ipmi_fru_data_type_e *dtype,
		      int                       *intval,
		      time_t                    *time,
		      double                    *floatval,
		      char                      **data,
		      unsigned int              *data_len)
{
    unsigned char *c = getset->rdata + getset->layout->start;
    int           val = 0;
    int           shift = 0;
    int           i;

    if (dtype)
	*dtype = getset->layout->dtype;
    if (intval) {
	for (i=0; i<getset->layout->length; i++) {
	    val |= ((int) *c) << shift;
	    c++;
	    shift += 8;
	}
	*intval = val;
    }
    return 0;
}

int
ipmi_mr_intfloat_set_field(ipmi_mr_getset_t          *getset,
			   enum ipmi_fru_data_type_e dtype,
			   int                       intval,
			   time_t                    time,
			   double                    floatval,
			   char                      *data,
			   unsigned int              data_len)
{
    unsigned char *c = getset->rdata + getset->layout->start;
    unsigned int  val;
    int           i;

    if (dtype != IPMI_FRU_DATA_FLOAT)
	return EINVAL;

    val = (unsigned int) ((floatval / getset->layout->u.multiplier) + 0.5);

    for (i=0; i<getset->layout->length; i++) {
	*c = val & 0xff;
	val >>= 8;
	c++;
    }
    c = getset->rdata + getset->layout->start;
    ipmi_fru_ovw_multi_record_data(getset->finfo->fru, getset->finfo->mr_rec_num,
				   c, ipmi_mr_full_offset(getset->offset)+getset->layout->start,
				   getset->layout->length);
    return 0;
}

int
ipmi_mr_intfloat_get_field(ipmi_mr_getset_t          *getset,
			   enum ipmi_fru_data_type_e *dtype,
			   int                       *intval,
			   time_t                    *time,
			   double                    *floatval,
			   char                      **data,
			   unsigned int              *data_len)
{
    unsigned char *c = getset->rdata + getset->layout->start;
    int           val = 0;
    int           shift = 0;
    int           i;

    if (dtype)
	*dtype = IPMI_FRU_DATA_FLOAT;
    if (floatval) {
	for (i=0; i<getset->layout->length; i++) {
	    val |= ((int) *c) << shift;
	    c++;
	    shift += 8;
	}
	*floatval = ((double) val) * getset->layout->u.multiplier;
    }
    return 0;
}

int
ipmi_mr_bitint_set_field(ipmi_mr_getset_t          *getset,
			 enum ipmi_fru_data_type_e dtype,
			 int                       intval,
			 time_t                    time,
			 double                    floatval,
			 char                      *data,
			 unsigned int              data_len)
{
    unsigned char *c = getset->rdata + getset->layout->start / 8;
    unsigned char *end = getset->rdata + (getset->layout->start
					  + getset->layout->length) / 8;
    int           val = intval;
    int           shift = getset->layout->start % 8;
    int           offset = 8 - shift;
    unsigned char mask1 = (~0) << shift;
    unsigned char mask2 = (~0) << ((getset->layout->start
				    + getset->layout->length) % 8);

    if (dtype != getset->layout->dtype)
	return EINVAL;

    if (dtype == IPMI_FRU_DATA_BOOLEAN)
	val = !!val;

    while (c != end) {
	*c = (*c & ~mask1) | (val << shift);
	val >>= offset;
	mask1 = 0xff;
	shift = 0;
	offset = 8;
	c++;
    }
    mask1 = ~mask1 | mask2;
    *c = (*c & mask1 ) | ((val << shift) & ~mask1);

    c = getset->rdata + getset->layout->start / 8;
    ipmi_fru_ovw_multi_record_data(getset->finfo->fru,
				   getset->finfo->mr_rec_num, c,
				   (ipmi_mr_full_offset(getset->offset)
				    + (c - getset->rdata)),
				   end - c + 1);
    return 0;
}

int
ipmi_mr_bitint_get_field(ipmi_mr_getset_t          *getset,
			 enum ipmi_fru_data_type_e *dtype,
			 int                       *intval,
			 time_t                    *time,
			 double                    *floatval,
			 char                      **data,
			 unsigned int              *data_len)
{
    unsigned char *c = getset->rdata + getset->layout->start / 8;
    unsigned char *end = getset->rdata + (getset->layout->start
					  + getset->layout->length) / 8;
    int           val = 0;
    int           offset = getset->layout->start % 8;
    int           shift = 8 - offset;
    unsigned int  mask = (~0) << getset->layout->length;

    if (dtype)
	*dtype = getset->layout->dtype;

    if (intval) {
	val = *c >> offset;
	while (c != end) {
	    c++;
	    val |= ((int) *c) << shift;
	    shift += 8;
	}
	val &= ~mask;

	*intval = val;
    }
    return 0;
}

int
ipmi_mr_bitvaltab_set_field(ipmi_mr_getset_t          *getset,
			    enum ipmi_fru_data_type_e dtype,
			    int                       intval,
			    time_t                    time,
			    double                    floatval,
			    char                      *data,
			    unsigned int              data_len)
{
    unsigned char      *c = getset->rdata + getset->layout->start / 8;
    unsigned char      *end = getset->rdata + (getset->layout->start
					       + getset->layout->length) / 8;
    int                val;
    int                shift = getset->layout->start % 8;
    int                offset = 8 - shift;
    unsigned char      mask1 = (~0) << shift;
    unsigned char      mask2 = (~0) << ((getset->layout->start
					 + getset->layout->length) % 8);
    ipmi_mr_tab_item_t *tab = getset->layout->u.tab_data;

    if (dtype != getset->layout->dtype)
	return EINVAL;

    for (val=0; val<(int)tab->count; val++) {
	if (!tab->table[val])
	    continue;
	if (strcasecmp(data, tab->table[val]) == 0)
	    break;
    }
    if (val == (int)tab->count)
	return EINVAL;

    while (c != end) {
	*c = (*c & ~mask1) | (val << shift);
	val >>= offset;
	mask1 = 0xff;
	shift = 0;
	offset = 8;
	c++;
    }
    mask1 = ~mask1 | mask2;
    *c = (*c & mask1 ) | ((val << shift) & ~mask1);

    c = getset->rdata + getset->layout->start / 8;
    ipmi_fru_ovw_multi_record_data(getset->finfo->fru,
				   getset->finfo->mr_rec_num, c,
				   (ipmi_mr_full_offset(getset->offset)
				    + (c - getset->rdata)),
				   end - c + 1);
    return 0;
}

int
ipmi_mr_bitvaltab_get_field(ipmi_mr_getset_t          *getset,
			    enum ipmi_fru_data_type_e *dtype,
			    int                       *intval,
			    time_t                    *time,
			    double                    *floatval,
			    char                      **data,
			    unsigned int              *data_len)
{
    unsigned char      *c = getset->rdata + getset->layout->start / 8;
    unsigned char      *end = getset->rdata + (getset->layout->start
					       + getset->layout->length) / 8;
    int                val = 0;
    int                offset = getset->layout->start % 8;
    int                shift = 8 - offset;
    unsigned int       mask = (~0) << getset->layout->length;
    const char         *str;
    ipmi_mr_tab_item_t *tab = getset->layout->u.tab_data;

    if (dtype)
	*dtype = getset->layout->dtype;

    val = *c >> offset;
    while (c != end) {
	c++;
	val |= ((int) *c) << shift;
	shift += 8;
    }
    val &= ~mask;

    if (val >= (int)tab->count)
	str = "?";
    else if (!tab->table[val])
	str = "?";
    else
	str = tab->table[val];
    if (data_len)
	*data_len = strlen(str);
    if (data) {
	*data = ipmi_strdup(str);
	if (!(*data))
	    return ENOMEM;
    }
    return 0;
}

int
ipmi_mr_bitvaltab_get_enum(ipmi_mr_getset_t *getset,
			   int              *pos,
			   int              *nextpos,
			   const char       **data)
{
    ipmi_mr_tab_item_t *tab = getset->layout->u.tab_data;
    int                p = *pos;

    if (p < 0) {
	p = 0;
	while ((p < (int) tab->count) && !tab->table[p])
	    p++;
    }

    if (p > (int) tab->count)
	return EINVAL;

    if (data) {
	if (!tab->table[p])
	    *data = "?";
	else
	    *data = tab->table[p];
    }
    *pos = p;

    if (nextpos) {
	p++;
	while ((p < (int) tab->count) && !tab->table[p])
	    p++;
	if (p >= (int) tab->count)
	    *nextpos = -1;
	else
	    *nextpos = p;
    }

    return 0;
}

int
ipmi_mr_bitfloatvaltab_set_field(ipmi_mr_getset_t          *getset,
				 enum ipmi_fru_data_type_e dtype,
				 int                       intval,
				 time_t                    time,
				 double                    floatval,
				 char                      *data,
				 unsigned int              data_len)
{
    unsigned char           *c = getset->rdata + getset->layout->start / 8;
    unsigned char           *end = getset->rdata + (getset->layout->start
						 + getset->layout->length) / 8;
    int                     val;
    int                     shift = getset->layout->start % 8;
    int                     offset = 8 - shift;
    unsigned char           mask1 = (~0) << shift;
    unsigned char           mask2 = (~0) << ((getset->layout->start
					      + getset->layout->length) % 8);
    ipmi_mr_floattab_item_t *tab = getset->layout->u.tab_data;

    if (dtype != getset->layout->dtype)
	return EINVAL;

    for (val=0; val<(int)tab->count; val++) {
	if ((floatval >= tab->table[val].low)
	    && (floatval <= tab->table[val].high))
	    break;
    }
    if (val == (int)tab->count)
	return EINVAL;

    while (c != end) {
	*c = (*c & ~mask1) | (val << shift);
	val >>= offset;
	mask1 = 0xff;
	shift = 0;
	offset = 8;
	c++;
    }
    mask1 = ~mask1 | mask2;
    *c = (*c & mask1 ) | ((val << shift) & ~mask1);

    c = getset->rdata + getset->layout->start / 8;
    ipmi_fru_ovw_multi_record_data(getset->finfo->fru,
				   getset->finfo->mr_rec_num, c,
				   (ipmi_mr_full_offset(getset->offset)
				    + (c - getset->rdata)),
				   end - c + 1);
    return 0;
}

int
ipmi_mr_bitfloatvaltab_get_field(ipmi_mr_getset_t          *getset,
				 enum ipmi_fru_data_type_e *dtype,
				 int                       *intval,
				 time_t                    *time,
				 double                    *floatval,
				 char                      **data,
				 unsigned int              *data_len)
{
    unsigned char           *c = getset->rdata + getset->layout->start / 8;
    unsigned char           *end = getset->rdata + (getset->layout->start
						 + getset->layout->length) / 8;
    int                     val = 0;
    int                     offset = getset->layout->start % 8;
    int                     shift = 8 - offset;
    unsigned int            mask = (~0) << getset->layout->length;
    ipmi_mr_floattab_item_t *tab = getset->layout->u.tab_data;

    if (dtype)
	*dtype = getset->layout->dtype;

    if (floatval) {
	val = *c >> offset;
	while (c != end) {
	    c++;
	    val |= ((int) *c) << shift;
	    shift += 8;
	}
	val &= ~mask;

	if (val >= (int)tab->count)
	    *floatval = tab->defval;
	else
	    *floatval = tab->table[val].nominal;
    }
    return 0;
}

int
ipmi_mr_bitfloatvaltab_get_enum(ipmi_mr_getset_t *getset,
				int              *pos,
				int              *nextpos,
				const char       **data)
{
    ipmi_mr_floattab_item_t *tab = getset->layout->u.tab_data;
    int                     p = *pos;

    if (p < 0) {
	p = 0;
	while ((p < (int) tab->count) && !tab->table[p].nominal_str)
	    p++;
    }

    if (p > (int) tab->count)
	return EINVAL;

    if (data) {
	if (!tab->table[p].nominal_str)
	    *data = "?";
	else
	    *data = tab->table[p].nominal_str;
    }

    if (nextpos) {
	p++;
	while ((p < (int) tab->count) && !tab->table[p].nominal_str)
	    p++;
	if (p >= (int) tab->count)
	    *nextpos = -1;
	else
	    *nextpos = p;
    }
    return 0;
}

int
ipmi_mr_str_set_field(ipmi_mr_getset_t          *getset,
		      enum ipmi_fru_data_type_e dtype,
		      int                       intval,
		      time_t                    time,
		      double                    floatval,
		      char                      *data,
		      unsigned int              data_len)
{
    unsigned char        *c = getset->rdata + getset->layout->start;
    enum ipmi_str_type_e stype;
    unsigned int         len;

    if (!data)
	return ENOSYS;
    switch (dtype) {
    case IPMI_FRU_DATA_ASCII: stype = IPMI_ASCII_STR; break;
    case IPMI_FRU_DATA_BINARY: stype = IPMI_UNICODE_STR; break;
    case IPMI_FRU_DATA_UNICODE: stype = IPMI_BINARY_STR; break;
    default:
	return EINVAL;
    }
    memset(c, 0, getset->layout->length);
    len = getset->layout->length;
    ipmi_set_device_string2(data, stype, data_len, c, 0, &len,
			    ipmi_fru_get_options(getset->finfo->fru));
    ipmi_fru_ovw_multi_record_data(getset->finfo->fru,
				   getset->finfo->mr_rec_num, c,
				   (ipmi_mr_full_offset(getset->offset)
				    + getset->layout->start),
				   getset->layout->length);
    return 0;
}

int
ipmi_mr_str_get_field(ipmi_mr_getset_t          *getset,
		      enum ipmi_fru_data_type_e *dtype,
		      int                       *intval,
		      time_t                    *time,
		      double                    *floatval,
		      char                      **data,
		      unsigned int              *data_len)
{
    unsigned char        *c = getset->rdata + getset->layout->start;
    char                 str[64];
    unsigned int         len;
    enum ipmi_str_type_e type;
    int                  rv;

    rv = ipmi_get_device_string(&c, getset->layout->length, str,
				IPMI_STR_FRU_SEMANTICS, 0,
				&type, sizeof(str), &len);
    if (rv)
	return rv;

    if (dtype) {
	switch (type) {
	case IPMI_ASCII_STR: *dtype = IPMI_FRU_DATA_ASCII; break;
	case IPMI_UNICODE_STR: *dtype = IPMI_FRU_DATA_UNICODE; break;
	case IPMI_BINARY_STR: *dtype = IPMI_FRU_DATA_BINARY; break;
	}
    }
    if (data_len)
	*data_len = len;
    if (data) {
	if (type == IPMI_ASCII_STR)
	    len += 1;
	else if (len == 0)
	    len = 1;
	*data = ipmi_mem_alloc(len);
	if (!(*data))
	    return ENOMEM;
	if (type == IPMI_ASCII_STR) {
	    memcpy(*data, str, len-1);
	    (*data)[len-1] = '\0';
	} else
	    memcpy(*data, str, len);
    }
    return 0;
}

int
ipmi_mr_binary_set_field(ipmi_mr_getset_t          *getset,
			 enum ipmi_fru_data_type_e dtype,
			 int                       intval,
			 time_t                    time,
			 double                    floatval,
			 char                      *data,
			 unsigned int              data_len)
{
    unsigned char        *c = getset->rdata + getset->layout->start;

    if (!data)
	return ENOSYS;
    if (dtype != getset->layout->dtype)
	return EINVAL;
    if (data_len > getset->layout->length)
	return EINVAL;

    memcpy(c, data, data_len);
    ipmi_fru_ovw_multi_record_data(getset->finfo->fru,
				   getset->finfo->mr_rec_num, c,
				   (ipmi_mr_full_offset(getset->offset)
				    + getset->layout->start),
				   data_len);
    return 0;
}

int
ipmi_mr_binary_get_field(ipmi_mr_getset_t          *getset,
			 enum ipmi_fru_data_type_e *dtype,
			 int                       *intval,
			 time_t                    *time,
			 double                    *floatval,
			 char                      **data,
			 unsigned int              *data_len)
{
    unsigned char *c = getset->rdata + getset->layout->start;

    if (dtype)
	*dtype = IPMI_FRU_DATA_BINARY;
    if (data_len)
	*data_len = getset->layout->length;
    if (data) {
	*data = ipmi_mem_alloc(getset->layout->length);
	if (!(*data))
	    return ENOMEM;
	memcpy(*data, c, getset->layout->length);
    }
    return 0;
}

int
ipmi_mr_ip_set_field(ipmi_mr_getset_t          *getset,
		     enum ipmi_fru_data_type_e dtype,
		     int                       intval,
		     time_t                    time,
		     double                    floatval,
		     char                      *data,
		     unsigned int              data_len)
{
    unsigned char  *c = getset->rdata + getset->layout->start;
    void           *addr;
    int            addr_len;
    int            af;
    struct in_addr ip_addr;
    int            rv;

    if (dtype != IPMI_FRU_DATA_ASCII)
	return EINVAL;

    if (strncmp(data, "ip:", 3) == 0) {
	af = AF_INET;
	data += 3;
	addr = &ip_addr;
	addr_len = sizeof(ip_addr);
    } else
	return EINVAL;

    rv = inet_pton(af, data, addr);
    if (rv <= 0)
	return EINVAL;
    memcpy(c, addr, addr_len);
    ipmi_fru_ovw_multi_record_data(getset->finfo->fru,
				   getset->finfo->mr_rec_num, c,
				   (ipmi_mr_full_offset(getset->offset)
				    + getset->layout->start),
				   addr_len);

    return 0;
}

int
ipmi_mr_ip_get_field(ipmi_mr_getset_t          *getset,
		     enum ipmi_fru_data_type_e *dtype,
		     int                       *intval,
		     time_t                    *time,
		     double                    *floatval,
		     char                      **data,
		     unsigned int              *data_len)
{
    unsigned char *c = getset->rdata + getset->layout->start;
    char          ipstr[19]; /* worst case size */
    int           len;

    sprintf(ipstr, "ip:%d.%d.%d.%d", c[0], c[1], c[2], c[3]);
    len = strlen(ipstr);
    if (dtype)
	*dtype = IPMI_FRU_DATA_ASCII;
    if (data_len)
	*data_len = len;
    if (data) {
	*data = ipmi_strdup(ipstr);
	if (!(*data))
	    return ENOMEM;
    }
    return 0;
}

/************************************************************************
 *
 * Cruft
 *
 ************************************************************************/

int 
ipmi_fru_get_internal_use_data(ipmi_fru_t    *fru,
			       unsigned char *data,
			       unsigned int  *max_len)
{
    return ipmi_fru_get_internal_use(fru, data, max_len);
}

int 
ipmi_fru_get_internal_use_length(ipmi_fru_t   *fru,
				 unsigned int *length)
{
    return ipmi_fru_get_internal_use_len(fru, length);
}
