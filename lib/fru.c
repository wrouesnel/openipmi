/*
 * fru.c
 *
 * IPMI code for handling FRUs based on sdr.c
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
#include <time.h>
#include <stdint.h>
#include <errno.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>

#include <OpenIPMI/internal/locked_list.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/ipmi_utils.h>

#define IPMI_LANG_CODE_ENGLISH	25

#define MAX_FRU_DATA_FETCH 32
#define FRU_DATA_FETCH_DECR 8
#define MIN_FRU_DATA_FETCH 16

#define MAX_FRU_DATA_WRITE 16
#define MAX_FRU_WRITE_RETRIES 30

#define IPMI_FRU_ATTR_NAME "ipmi_fru"

/*
 * A note of FRUs, fru attributes, and locking.
 *
 * Because we keep a list of FRUs, that makes locking a lot more
 * complicated.  While we are deleting a FRU another thread can come
 * along and iterate and find it.  The lock on the locked list is used
 * along with the FRU lock to prevent this from happening.  Since in
 * this situation, the locked list lock is held when the FRU is
 * referenced, when we destroy the FRU we make sure that it wasn't
 * resurrected after being deleted from this list.
 */

/* Records used to hold the FRU. */
typedef struct ipmi_fru_record_s ipmi_fru_record_t;

typedef struct fru_string_s
{
    enum ipmi_str_type_e type;
    unsigned short       length;
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
    void (*setup_new)(ipmi_fru_record_t *rec);
} fru_area_info_t;

extern fru_area_info_t fru_area_info[IPMI_FRU_FTR_NUMBER];

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

/* Record used for FRU writing. */
typedef struct fru_update_s fru_update_t;
struct fru_update_s
{
    unsigned short offset;
    unsigned short length;
    fru_update_t   *next;
};

struct ipmi_fru_s
{
    char name[IPMI_FRU_NAME_LEN+1];
    int deleted;

    unsigned int refcount;

    /* Is the FRU being read or written? */
    int in_use;

    ipmi_lock_t *lock;

    ipmi_domain_id_t     domain_id;
    unsigned char        is_logical;
    unsigned char        device_address;
    unsigned char        device_id;
    unsigned char        lun;
    unsigned char        private_bus;
    unsigned char        channel;

    ipmi_fru_fetched_cb fetched_handler;
    ipmi_fru_cb         domain_fetched_handler;
    void                *fetched_cb_data;

    ipmi_fru_destroyed_cb destroy_handler;
    void                  *destroy_cb_data;

    int           access_by_words;
    unsigned char *data;
    unsigned int  data_len;
    unsigned int  curr_pos;

    int           fetch_size;

    /* Is this in the list of FRUs? */
    int in_frulist;

    unsigned char version;

    /* Has an offset changed (thus causing the header to need to be
       rewritten)? */
    char header_changed;

    /* The records for writing. */
    fru_update_t *update_recs;
    fru_update_t *update_recs_tail;

    /* The last send command for writing */
    unsigned char last_cmd[MAX_FRU_DATA_WRITE+4];
    unsigned int  last_cmd_len;
    unsigned int  retry_count;

    ipmi_fru_record_t *recs[IPMI_FRU_FTR_NUMBER];

    char iname[IPMI_FRU_NAME_LEN+1];
};

static void fru_record_destroy(ipmi_fru_record_t *rec);

#define FRU_DOMAIN_NAME(fru) (fru ? fru->iname : "")

static void final_fru_destroy(ipmi_fru_t *fru);

/***********************************************************************
 *
 * general utilities
 *
 **********************************************************************/
static void
fru_lock(ipmi_fru_t *fru)
{
    ipmi_lock(fru->lock);
}

static void
fru_unlock(ipmi_fru_t *fru)
{
    ipmi_unlock(fru->lock);
}

/*
 * Must already be holding the FRU lock to call this.
 */
static void
fru_get(ipmi_fru_t *fru)
{
    fru->refcount++;
}

static void
fru_put(ipmi_fru_t *fru)
{
    fru_lock(fru);
    fru->refcount--;
    if (fru->refcount == 0) {
	final_fru_destroy(fru);
	return;
    }
    fru_unlock(fru);
}

void
ipmi_fru_ref(ipmi_fru_t *fru)
{
    fru_lock(fru);
    fru_get(fru);
    fru_unlock(fru);
}

void
ipmi_fru_deref(ipmi_fru_t *fru)
{
    fru_put(fru);
}

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

    t = *d++ * 256 * 256;
    t += *d++ * 256;
    t += *d++;

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
fru_new_update_rec(ipmi_fru_t *fru, unsigned int offset, unsigned int length)
{
    fru_update_t *urec;

    urec = ipmi_mem_alloc(sizeof(*urec));
    if (!urec)
	return ENOMEM;
    if (fru->access_by_words) {
	/* This handled the (really stupid) word access mode.  If the
	   address is odd, back it up one.  If the length is odd,
	   increment by one. */
	if (offset & 1) {
	    offset -= 1;
	    length += 1;
	}
	urec->offset = offset;
	if (length & 1) {
	    length += 1;
	}
	urec->length = length;
    } else {
	urec->offset = offset;
	urec->length = length;
    }
    urec->next = NULL;
    if (fru->update_recs)
	fru->update_recs_tail->next = urec;
    else
	fru->update_recs = urec;
    fru->update_recs_tail = urec;
    return 0;
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
	int          len;

	if (offset != s->offset) {
	    /* Bug in the FRU code.  Return a unique error code so it
	       can be identified, but don't pass it to the user. */
	    return EBADF;
	}

	if (s->changed) {
	    len = IPMI_MAX_STR_LEN;
	    ipmi_set_device_string(s->str, s->type, s->length,
				   data+offset, 1, &len);
	    if (s->raw_data) {
		ipmi_mem_free(s->raw_data);
		s->raw_data = NULL;
	    }
	} else if (s->raw_data) {
	    memcpy(data+offset, s->raw_data, s->raw_len);
	    len = s->raw_len;
	} else if (s->str) {
	    len = IPMI_MAX_STR_LEN;
	    ipmi_set_device_string(s->str, s->type, s->length,
				   data+offset, 1, &len);
	} else {
	    data[offset] = 0xc0;
	    len = 1;
	}
	if (s->changed && !rec->rewrite) {
	    rv = fru_new_update_rec(fru, offset+rec->offset, len);
	    if (rv)
		return rv;
	}
	offset += len;
    }
    /* Now the end marker */
    data[offset] = 0xc1;
    /* If the record changed, put out the end marker */
    if (rec->changed && !rec->rewrite) {
	rv = fru_new_update_rec(fru, offset+rec->offset, 1);
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
    int            i;
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
fru_string_set(enum ipmi_str_type_e type,
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
    int           raw_len = sizeof(tstr);
    int           raw_diff;
    int           i;

    if (str) {
	/* First calculate if it will fit into the record area. */

	/* Truncate if too long. */
	if (len > 63)
	    len = 63;
	ipmi_set_device_string(str, type, len, tstr, 1, &raw_len);
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
    unsigned char str[IPMI_MAX_STR_LEN+1];
    int           force_unicode;
    fru_string_t  *out = strs->strings + num;
    unsigned char *in_start;

    out->offset = *in - start_pos;
    in_start = *in;
    force_unicode = !force_english && (lang_code != IPMI_LANG_CODE_ENGLISH);
    out->length = ipmi_get_device_string(in, *in_len, str,
					 IPMI_STR_FRU_SEMANTICS, force_unicode,
					 &out->type, sizeof(str));
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
    int clen;

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
fru_variable_string_set(ipmi_fru_record_t    *rec,
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

    rv = fru_string_set(type, str, len, rec, val, num, is_custom);
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
	fru_string_t *n;
	int          n_len = v->len + 5;

	n = ipmi_mem_alloc(sizeof(fru_string_t) * n_len);
	if (!n)
	    return ENOMEM;

	if (v->strings) {
	    memcpy(n, v->strings, sizeof(fru_string_t) * v->len);
	    ipmi_mem_free(v->strings);
	}
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
fru_record_alloc(int area)
{
    ipmi_fru_record_t *rec;
    unsigned short    extra_len = fru_area_info[area].extra_len;

    rec = ipmi_mem_alloc(sizeof(ipmi_fru_record_t) + extra_len);
    if (!rec)
	return NULL;

    memset(rec, 0, sizeof(ipmi_fru_record_t)+extra_len);

    rec->handlers = fru_area_info + area;
    rec->data = ((char *) rec) + sizeof(ipmi_fru_record_t);

    if (fru_area_info[area].setup_new)
	fru_area_info[area].setup_new(rec);

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
    ipmi_fru_record_t              *rec;			\
    fru_lock(fru);						\
    rec = fru->recs[IPMI_FRU_FTR_## ucname ## _AREA];		\
    if (!rec) {							\
	fru_unlock(fru);					\
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
    fru_unlock(fru);							\
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
    fru_unlock(fru);							\
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
    fru_unlock(fru);							\
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
    rv = fru_variable_string_set(rec,					\
				 &u->fields,				\
				 0, ucname ## _ ## fname,		\
                                 type, str, len, 0);			\
    fru_unlock(fru);							\
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
    fru_unlock(fru);							\
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
    fru_unlock(fru);							\
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
    fru_unlock(fru);							\
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
    rv = fru_variable_string_set(rec,					\
				 &u->fields,				\
				 ucname ## _ ## custom_start, num,	\
                                 type, str, len, 1);			\
    fru_unlock(fru);							\
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

static void
internal_use_area_setup(ipmi_fru_record_t *rec)
{
    ipmi_fru_internal_use_area_t *u = fru_record_get_data(rec);

    u->version = 1;
}

static int
fru_decode_internal_use_area(ipmi_fru_t        *fru,
			     unsigned char     *data,
			     unsigned int      data_len,
			     ipmi_fru_record_t **rrec)
{
    ipmi_fru_internal_use_area_t *u;
    ipmi_fru_record_t            *rec;

    rec = fru_record_alloc(IPMI_FRU_FTR_INTERNAL_USE_AREA);
    if (!rec)
	return ENOMEM;

    rec->length = data_len;
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

    fru_unlock(fru);

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

    fru_unlock(fru);

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

    fru_unlock(fru);

    return 0;
}

int
ipmi_fru_set_internal_use(ipmi_fru_t *fru, unsigned char *data,
			  unsigned int len)
{
    unsigned char *new_val;

    GET_DATA_PREFIX(internal_use, INTERNAL_USE);

    if (len > rec->length-1) {
	fru_unlock(fru);
	return E2BIG;
    }

    new_val = ipmi_mem_alloc(len);
    if (!new_val) {
	fru_unlock(fru);
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
    
    fru_unlock(fru);

    return 0;
}

static int
fru_encode_internal_use_area(ipmi_fru_t *fru, unsigned char *data)
{
    ipmi_fru_record_t *rec = fru->recs[IPMI_FRU_FTR_INTERNAL_USE_AREA];
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
	rv = fru_new_update_rec(fru, rec->offset, u->length+1);
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

static void
chassis_info_area_setup(ipmi_fru_record_t *rec)
{
    ipmi_fru_internal_use_area_t *u = fru_record_get_data(rec);

    u->version = 1;
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
		 "%sfru.c(fru_decode_chassis_info_area):"
		 " FRU string goes past data length",
		 FRU_DOMAIN_NAME(fru));
	return EBADF;
    }

    if (checksum(data, length) != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_decode_chassis_info_area):"
		 " FRU string checksum failed",
		 FRU_DOMAIN_NAME(fru));
	return EBADF;
    }

    data_len--; /* remove the checksum */

    rec = fru_record_alloc(IPMI_FRU_FTR_CHASSIS_INFO_AREA);
    if (!rec)
	return ENOMEM;

    err = fru_setup_min_field(rec, IPMI_FRU_FTR_CHASSIS_INFO_AREA, 0);
    if (err)
	goto out_err;

    rec->length = length; /* add 1 for the checksum */

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

    fru_unlock(fru);

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

    fru_unlock(fru);

    return 0;
}

int 
ipmi_fru_set_chassis_info_type(ipmi_fru_t    *fru,
			       unsigned char type)
{
    GET_DATA_PREFIX(chassis_info, CHASSIS_INFO);

    rec->changed |= u->type != type;
    u->type = type;

    fru_unlock(fru);

    return 0;
}

GET_DATA_STR(chassis_info, CHASSIS_INFO, part_number)
GET_DATA_STR(chassis_info, CHASSIS_INFO, serial_number)
GET_CUSTOM_STR(chassis_info, CHASSIS_INFO)

static int
fru_encode_chassis_info_area(ipmi_fru_t *fru, unsigned char *data)
{
    ipmi_fru_record_t *rec = fru->recs[IPMI_FRU_FTR_CHASSIS_INFO_AREA];
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
	rv = fru_new_update_rec(fru, rec->offset, 3);
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
	    rv = fru_new_update_rec(fru, rec->offset + rec->used_length - 1,
				    rec->orig_used_length - rec->used_length);
	    if (rv)
		return rv;
	}
	/* Write the checksum */
	rv = fru_new_update_rec(fru, rec->offset+rec->length-1, 1);
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

static void
board_info_area_setup(ipmi_fru_record_t *rec)
{
    ipmi_fru_internal_use_area_t *u = fru_record_get_data(rec);

    u->version = 1;
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
    unsigned char              length;
    unsigned char              *orig_data = data;

    version = *data;
    length = (*(data+1)) * 8;
    if ((length == 0) || (length > data_len)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_decode_board_info_area):"
		 " FRU string goes past data length",
		 FRU_DOMAIN_NAME(fru));
	return EBADF;
    }

    if (checksum(data, length) != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_decode_board_info_area):"
		 " FRU string checksum failed",
		 FRU_DOMAIN_NAME(fru));
	return EBADF;
    }

    data_len--; /* remove the checksum */

    rec = fru_record_alloc(IPMI_FRU_FTR_BOARD_INFO_AREA);
    if (!rec)
	return ENOMEM;

    err = fru_setup_min_field(rec, IPMI_FRU_FTR_BOARD_INFO_AREA, 0);
    if (err)
	goto out_err;

    rec->length = length;

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

    fru_unlock(fru);

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

    fru_unlock(fru);

    return 0;
}

int 
ipmi_fru_set_board_info_lang_code(ipmi_fru_t    *fru,
				  unsigned char lang)
{
    GET_DATA_PREFIX(board_info, BOARD_INFO);

    rec->changed |= u->lang_code != lang;
    u->lang_code = lang;

    fru_unlock(fru);

    return 0;
}

int 
ipmi_fru_get_board_info_mfg_time(ipmi_fru_t *fru,
				 time_t     *time)
{
    GET_DATA_PREFIX(board_info, BOARD_INFO);
    
    *time = u->mfg_time;

    fru_unlock(fru);

    return 0;
}

int 
ipmi_fru_set_board_info_mfg_time(ipmi_fru_t *fru,
				 time_t     time)
{
    GET_DATA_PREFIX(board_info, BOARD_INFO);
    
    rec->changed |= u->mfg_time != time;
    u->mfg_time = time;

    fru_unlock(fru);

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
    ipmi_fru_record_t *rec = fru->recs[IPMI_FRU_FTR_BOARD_INFO_AREA];
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
	rv = fru_new_update_rec(fru, rec->offset, 6);
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
	    rv = fru_new_update_rec(fru, rec->offset + rec->used_length - 1,
				    rec->orig_used_length - rec->used_length);
	    if (rv)
		return rv;
	}
	/* Write the checksum */
	rv = fru_new_update_rec(fru, rec->offset+rec->length-1, 1);
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

static void
product_info_area_setup(ipmi_fru_record_t *rec)
{
    ipmi_fru_internal_use_area_t *u = fru_record_get_data(rec);

    u->version = 1;
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
		 "%sfru.c(fru_decode_product_info_area):"
		 " FRU string goes past data length",
		 FRU_DOMAIN_NAME(fru));
	return EBADF;
    }

    if (checksum(data, length) != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_decode_product_info_area):"
		 " FRU string checksum failed",
		 FRU_DOMAIN_NAME(fru));
	return EBADF;
    }

    data_len--; /* remove the checksum */

    rec = fru_record_alloc(IPMI_FRU_FTR_PRODUCT_INFO_AREA);
    if (!rec)
	return ENOMEM;

    err = fru_setup_min_field(rec, IPMI_FRU_FTR_PRODUCT_INFO_AREA, 0);
    if (err)
	goto out_err;

    rec->length = length;

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

    fru_unlock(fru);

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

    fru_unlock(fru);

    return 0;
}

int 
ipmi_fru_set_product_info_lang_code(ipmi_fru_t    *fru,
				    unsigned char lang)
{
    GET_DATA_PREFIX(product_info, PRODUCT_INFO);
    
    rec->changed |= u->lang_code != lang;
    u->lang_code = lang;

    fru_unlock(fru);

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
    ipmi_fru_record_t *rec = fru->recs[IPMI_FRU_FTR_PRODUCT_INFO_AREA];
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
	rv = fru_new_update_rec(fru, rec->offset, 3);
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
	    rv = fru_new_update_rec(fru, rec->offset + rec->used_length - 1,
				    rec->orig_used_length - rec->used_length);
	    if (rv)
		return rv;
	}
	/* Write the checksum */
	rv = fru_new_update_rec(fru, rec->offset+rec->length-1, 1);
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
    int                          i;

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
    int                     i;
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
		     "%sfru.c(fru_decode_multi_record_area):"
		     " Data not long enough for multi record",
		     FRU_DOMAIN_NAME(fru));
	    return EBADF;
	}

	if (checksum(data, 5) != 0) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sfru.c(fru_decode_multi_record_area):"
		     " Header checksum for record %d failed",
		     FRU_DOMAIN_NAME(fru), num_records+1);
	    return EBADF;
	}

	length = data[2];
	if ((length + 5) > left) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sfru.c(fru_decode_multi_record_area):"
		     " Record went past end of data",
		     FRU_DOMAIN_NAME(fru));
	    return EBADF;
	}

	sum = checksum(data+5, length) + data[3];
	if (sum != 0) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sfru.c(fru_decode_multi_record_area):"
		     " Data checksum for record %d failed",
		     FRU_DOMAIN_NAME(fru), num_records+1);
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

    rec = fru_record_alloc(IPMI_FRU_FTR_MULTI_RECORD_AREA);
    if (!rec)
	return ENOMEM;

    rec->length = data_len;
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
    ipmi_fru_multi_record_area_t *u;
    unsigned int                 num;

    fru_lock(fru);
    if (!fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]) {
	fru_unlock(fru);
	return 0;
    }

    u = fru_record_get_data(fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]);
    num = u->num_records;
    fru_unlock(fru);
    return num;
}

int
ipmi_fru_get_multi_record_type(ipmi_fru_t    *fru,
			       unsigned int  num,
			       unsigned char *type)
{
    ipmi_fru_multi_record_area_t *u;

    fru_lock(fru);
    if (!fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]) {
	fru_unlock(fru);
	return ENOSYS;
    }
    u = fru_record_get_data(fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]);
    if (num >= u->num_records) {
	fru_unlock(fru);
	return E2BIG;
    }
    *type = u->records[num].type;
    fru_unlock(fru);
    return 0;
}

int
ipmi_fru_get_multi_record_format_version(ipmi_fru_t    *fru,
					 unsigned int  num,
					 unsigned char *ver)
{
    ipmi_fru_multi_record_area_t *u;

    fru_lock(fru);
    if (!fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]) {
	fru_unlock(fru);
	return ENOSYS;
    }
    u = fru_record_get_data(fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]);
    if (num >= u->num_records) {
	fru_unlock(fru);
	return E2BIG;
    }
    *ver = u->records[num].format_version;
    fru_unlock(fru);
    return 0;
}

int
ipmi_fru_get_multi_record_data_len(ipmi_fru_t   *fru,
				   unsigned int num,
				   unsigned int *len)
{
    ipmi_fru_multi_record_area_t *u;

    fru_lock(fru);
    if (!fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]) {
	fru_unlock(fru);
	return ENOSYS;
    }
    u = fru_record_get_data(fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]);
    if (num >= u->num_records) {
	fru_unlock(fru);
	return E2BIG;
    }
    *len = u->records[num].length;
    fru_unlock(fru);
    return 0;
}

int
ipmi_fru_get_multi_record_data(ipmi_fru_t    *fru,
			       unsigned int  num,
			       unsigned char *data,
			       unsigned int  *length)
{
    ipmi_fru_multi_record_area_t *u;

    fru_lock(fru);
    if (!fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]) {
	fru_unlock(fru);
	return ENOSYS;
    }
    u = fru_record_get_data(fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA]);
    if (num >= u->num_records) {
	fru_unlock(fru);
	return E2BIG;
    }
    if (*length < u->records[num].length) {
	fru_unlock(fru);
	return EINVAL;
    }
    memcpy(data, u->records[num].data, u->records[num].length);
    *length = u->records[num].length;
    fru_unlock(fru);
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
    ipmi_fru_multi_record_area_t *u;
    unsigned char                *new_data;
    ipmi_fru_record_t            *rec;
    int                          raw_diff = 0;
    int                          i;

    fru_lock(fru);
    rec = fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA];
    if (!rec) {
	fru_unlock(fru);
	return ENOSYS;
    }

    u = fru_record_get_data(rec);

    if (num >= u->num_records) {
	if (!data) {
	    /* Don't expand if we are deleting an invalid field,
	       return an error. */
	    fru_unlock(fru);
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
		fru_unlock(fru);
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
	    fru->header_changed = 1;
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
	    fru_unlock(fru);
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
	    fru->header_changed = 1;
    }

    rec->used_length += raw_diff;
    rec->changed |= 1;
    fru_unlock(fru);
    return 0;
}

static int
fru_encode_multi_record(ipmi_fru_t             *fru,
			ipmi_fru_record_t      *rec,
			ipmi_fru_multi_record_area_t *u,
			int                    idx,
			unsigned char          *data,
			unsigned int           *offset)
{
    unsigned int           o = *offset;
    ipmi_fru_record_elem_t *elem = u->records + idx;
    int                    rv;

    if (o != elem->offset) {
	return EBADF;
    }

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
	rv = fru_new_update_rec(fru, rec->offset+elem->offset, elem->length+5);
	if (rv)
	    return rv;
    }

    *offset = o + elem->length + 5;
    return 0;
}

static int
fru_encode_multi_record_area(ipmi_fru_t *fru, unsigned char *data)
{
    ipmi_fru_record_t *rec = fru->recs[IPMI_FRU_FTR_MULTI_RECORD_AREA];
    ipmi_fru_multi_record_area_t *u;
    int               rv;
    int               i;
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
    int pos;
    int max_start = fru->data_len - 8;

    /* Zero is invalid, and it must be a multiple of 8. */
    if ((offset == 0) || ((offset % 8) != 0))
	return EINVAL;

    /* Make sure the used area still fits. */
    if (fru->recs[recn] && (length < fru->recs[recn]->used_length))
	return E2BIG;

    /* FRU data record starts cannot exceed 2040 bytes.  The offsets
       are in multiples of 8 and the sizes are 8-bits, thus 8 *
       255.  The end of the data can go till the end of the FRU. */
    if (max_start > 2040)
	max_start = 2040;
    if ((offset > max_start) || ((offset + length) > fru->data_len))
	return EINVAL;

    /* Check that this is not in the previous record's space. */
    pos = recn - 1;
    while ((pos >= 0) && !fru->recs[pos])
	pos--;
    if (pos >= 0) {
	if (offset < (fru->recs[pos]->offset + fru->recs[pos]->length))
	    return EINVAL;
    }

    /* Check that this is not in the next record's space. */
    pos = recn + 1;
    while ((pos < IPMI_FRU_FTR_NUMBER) && !fru->recs[pos])
	pos++;
    if (pos < IPMI_FRU_FTR_NUMBER) {
	if ((offset + length) > fru->recs[pos]->offset)
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
    ipmi_fru_record_t  *rec;
    int                rv;

    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;

    /* Truncate the length to a multiple of 8. */
    length = length & ~(8-1);

    fru_lock(fru);
    if (fru->recs[area]) {
	fru_unlock(fru);
	return EEXIST;
    }

    rv = check_rec_position(fru, area, offset, length);
    if (rv) {
	fru_unlock(fru);
	return rv;
    }

    rec = fru_record_alloc(area);
    if (!rec) {
	fru_unlock(fru);
	return ENOMEM;
    }
    rec->changed = 1;
    rec->rewrite = 1;
    rec->used_length = fru_area_info[area].empty_length;
    rec->orig_used_length = rec->used_length;
    rec->offset = offset;
    rec->length = length;
    fru->header_changed = 1;

    rv = fru_setup_min_field(rec, area, 1);
    if (rv) {
	fru_unlock(fru);
	return rv;
    }

    fru->recs[area] = rec;
    fru_unlock(fru);
    return 0;
}

int
ipmi_fru_delete_area(ipmi_fru_t *fru, int area)
{
    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;

    fru_lock(fru);
    fru_record_destroy(fru->recs[area]); 
    fru->recs[area] = NULL;
    fru_unlock(fru);
    return 0;
}

int
ipmi_fru_area_get_offset(ipmi_fru_t   *fru,
			 unsigned int area,
			 unsigned int *offset)
{
    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;
    fru_lock(fru);
    if (!fru->recs[area]) {
	fru_unlock(fru);
	return ENOENT;
    }

    *offset = fru->recs[area]->offset;

    fru_unlock(fru);
    return 0;
}

int
ipmi_fru_area_get_length(ipmi_fru_t   *fru,
			 unsigned int area,
			 unsigned int *length)
{
    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;
    fru_lock(fru);
    if (!fru->recs[area]) {
	fru_unlock(fru);
	return ENOENT;
    }

    *length = fru->recs[area]->length;

    fru_unlock(fru);
    return 0;
}

int
ipmi_fru_area_set_offset(ipmi_fru_t   *fru,
			 unsigned int area,
			 unsigned int offset)
{
    int rv;

    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;
    fru_lock(fru);
    if (!fru->recs[area]) {
	fru_unlock(fru);
	return ENOENT;
    }

    if (fru->recs[area]->offset == offset) {
	fru_unlock(fru);
	return 0;
    }

    if (area == IPMI_FRU_FTR_MULTI_RECORD_AREA) {
	/* Multi-record lengths are not defined, but just goto the end.
	   So adjust the length for comparison here. */
	int newlength = (fru->recs[area]->length
			 + fru->recs[area]->offset - offset);
	rv = check_rec_position(fru, area, offset, newlength);
    } else {
	rv = check_rec_position(fru, area, offset, fru->recs[area]->length);
    }
    if (!rv) {
	if (area == IPMI_FRU_FTR_MULTI_RECORD_AREA)
	    fru->recs[area]->length += fru->recs[area]->offset - offset;
	fru->recs[area]->offset = offset;
	fru->recs[area]->changed = 1;
	fru->recs[area]->rewrite = 1;
	fru->header_changed = 1;
    }

    fru_unlock(fru);
    return rv;
}

int
ipmi_fru_area_set_length(ipmi_fru_t   *fru,
			 unsigned int area,
			 unsigned int length)
{
    int rv;

    /* Truncate the length to a multiple of 8. */
    length = length & ~(8-1);

    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;
    if (length == 0)
	return EINVAL;
    fru_lock(fru);
    if (!fru->recs[area]) {
	fru_unlock(fru);
	return ENOENT;
    }

    if (fru->recs[area]->length == length) {
	fru_unlock(fru);
	return 0;
    }

    rv = check_rec_position(fru, area, fru->recs[area]->offset, length);
    if (!rv) {
	if (length > fru->recs[area]->length)
	    /* Only need to rewrite the whole record (to get the zeroes
	       into the unused area) if we increase the length. */
	    fru->recs[area]->rewrite = 1;
	fru->recs[area]->length = length;
	fru->recs[area]->changed = 1;
    }

    fru_unlock(fru);
    return rv;
}

int
ipmi_fru_area_get_used_length(ipmi_fru_t *fru,
			      unsigned int area,
			      unsigned int *used_length)
{
    if (area >= IPMI_FRU_FTR_NUMBER)
	return EINVAL;
    fru_lock(fru);
    if (!fru->recs[area]) {
	fru_unlock(fru);
	return ENOENT;
    }

    *used_length = fru->recs[area]->used_length;

    fru_unlock(fru);
    return 0;
}


/***********************************************************************
 *
 * FRU allocation and destruction
 *
 **********************************************************************/
static void
fru_record_destroy(ipmi_fru_record_t *rec)
{
    if (rec)
	rec->handlers->free(rec);
}

static void
final_fru_destroy(ipmi_fru_t *fru)
{
    int i;

    if (fru->in_frulist) {
	int                rv;
	ipmi_domain_attr_t *attr;
	locked_list_t      *frul;

	fru->in_frulist = 0;
	rv = ipmi_domain_id_find_attribute(fru->domain_id, IPMI_FRU_ATTR_NAME,
					   &attr);
	if (!rv) {
	    fru->refcount++;
	    fru_unlock(fru);
	    frul = ipmi_domain_attr_get_data(attr);
	    locked_list_remove(frul, fru, NULL);
	    ipmi_domain_attr_put(attr);
	    fru_lock(fru);
	    /* While we were unlocked, someone may have come in and
	       grabbed the FRU by iterating the list of FRUs.  That's
	       ok, we just let them handle the destruction since this
	       code will not be entered again. */
	    if (fru->refcount != 1) {
		fru->refcount--;
		fru_unlock(fru);
		return;
	    }
	}
    }
    fru_unlock(fru);

    /* No one else can be referencing this here, so it is safe to
       release the lock now. */

    if (fru->destroy_handler)
	fru->destroy_handler(fru, fru->destroy_cb_data);

    for (i=0; i<IPMI_FRU_FTR_NUMBER; i++)
	fru_record_destroy(fru->recs[i]);
    while (fru->update_recs) {
	fru_update_t *to_free = fru->update_recs;
	fru->update_recs = to_free->next;
	ipmi_mem_free(to_free);
    }
    ipmi_destroy_lock(fru->lock);
    ipmi_mem_free(fru);
}

int
ipmi_fru_destroy_internal(ipmi_fru_t            *fru,
			  ipmi_fru_destroyed_cb handler,
			  void                  *cb_data)
{
    if (fru->in_frulist)
	return EPERM;

    fru_lock(fru);
    fru->destroy_handler = handler;
    fru->destroy_cb_data = cb_data;
    fru->deleted = 1;
    fru_unlock(fru);

    fru_put(fru);
    return 0;
}

int
ipmi_fru_destroy(ipmi_fru_t            *fru,
		 ipmi_fru_destroyed_cb handler,
		 void                  *cb_data)
{
    ipmi_domain_attr_t *attr;
    locked_list_t      *frul;
    int                rv;

    fru_lock(fru);
    if (fru->in_frulist) {
	rv = ipmi_domain_id_find_attribute(fru->domain_id, IPMI_FRU_ATTR_NAME,
					   &attr);
	if (rv) {
	    fru_unlock(fru);
	    return rv;
	}
	fru->in_frulist = 0;
	fru_unlock(fru);

	frul = ipmi_domain_attr_get_data(attr);
	if (! locked_list_remove(frul, fru, NULL)) {
	    /* Not in the list, it's already been removed. */
	    ipmi_domain_attr_put(attr);
	    fru_unlock(fru);
	    return EINVAL;
	}
	ipmi_domain_attr_put(attr);
	fru_put(fru); /* It's not in the list any more. */
    } else {
	/* User can't destroy FRUs he didn't allocate. */
	fru_unlock(fru);
	return EPERM;
    }

    return ipmi_fru_destroy_internal(fru, handler, cb_data);
}

static int start_logical_fru_fetch(ipmi_domain_t *domain, ipmi_fru_t *fru);
static int start_physical_fru_fetch(ipmi_domain_t *domain, ipmi_fru_t *fru);

static int
destroy_fru(void *cb_data, void *item1, void *item2)
{
    ipmi_fru_t *fru = item1;

    /* Users are responsible for handling their own FRUs, we don't
       delete here, just mark not in the list. */
    fru_lock(fru);
    fru->in_frulist = 0;
    fru_unlock(fru);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
fru_attr_destroy(void *cb_data, void *data)
{
    locked_list_t *frul = data;

    locked_list_iterate(frul, destroy_fru, NULL);
    locked_list_destroy(frul);
}

static int
fru_attr_init(ipmi_domain_t *domain, void *cb_data, void **data)
{
    locked_list_t *frul;
    
    frul = locked_list_alloc(ipmi_domain_get_os_hnd(domain));
    if (!frul)
	return ENOMEM;

    *data = frul;
    return 0;
}

static int
ipmi_fru_alloc_internal(ipmi_domain_t       *domain,
			unsigned char       is_logical,
			unsigned char       device_address,
			unsigned char       device_id,
			unsigned char       lun,
			unsigned char       private_bus,
			unsigned char       channel,
			ipmi_fru_fetched_cb fetched_handler,
			void                *fetched_cb_data,
			ipmi_fru_t          **new_fru)
{
    ipmi_fru_t    *fru;
    int           err;
    int           len, p;

    fru = ipmi_mem_alloc(sizeof(*fru));
    if (!fru)
	return ENOMEM;
    memset(fru, 0, sizeof(*fru));

    err = ipmi_create_lock(domain, &fru->lock);
    if (err) {
	ipmi_mem_free(fru);
	return err;
    }

    /* Refcount starts at 2 because we start a fetch immediately. */
    fru->refcount = 2;
    fru->in_use = 1;

    fru->domain_id = ipmi_domain_convert_to_id(domain);
    fru->is_logical = is_logical;
    fru->device_address = device_address;
    fru->device_id = device_id;
    fru->lun = lun;
    fru->private_bus = private_bus;
    fru->channel = channel;
    fru->fetch_size = MAX_FRU_DATA_FETCH;

    len = sizeof(fru->name);
    p = ipmi_domain_get_name(domain, fru->name, len);
    len -= p;
    snprintf(fru->name+p, len, ".%d", ipmi_domain_get_unique_num(domain));

    snprintf(fru->iname, sizeof(fru->iname), "%s.%d.%x.%d.%d.%d.%d ",
	     DOMAIN_NAME(domain), is_logical, device_address, device_id, lun,
	     private_bus, channel);

    fru->fetched_handler = fetched_handler;
    fru->fetched_cb_data = fetched_cb_data;

    fru->deleted = 0;

    fru_lock(fru);
    if (fru->is_logical)
	err = start_logical_fru_fetch(domain, fru);
    else
	err = start_physical_fru_fetch(domain, fru);
    if (err) {
	fru_unlock(fru);
	ipmi_destroy_lock(fru->lock);
	ipmi_mem_free(fru);
	return err;
    }

    *new_fru = fru;
    return 0;
}

int
ipmi_domain_fru_alloc(ipmi_domain_t *domain,
		      unsigned char is_logical,
		      unsigned char device_address,
		      unsigned char device_id,
		      unsigned char lun,
		      unsigned char private_bus,
		      unsigned char channel,
		      ipmi_fru_cb   fetched_handler,
		      void          *fetched_cb_data,
		      ipmi_fru_t    **new_fru)
{
    ipmi_fru_t         *nfru;
    int                rv;
    ipmi_domain_attr_t *attr;
    locked_list_t      *frul;

    rv = ipmi_domain_register_attribute(domain, IPMI_FRU_ATTR_NAME,
					fru_attr_init,
					fru_attr_destroy,
					NULL,
					&attr);
    if (rv)
	return rv;
    frul = ipmi_domain_attr_get_data(attr);

    /* Be careful with locking, a FRU fetch is already going on when
       the alloc_internal function returns. */
    locked_list_lock(frul);
    rv = ipmi_fru_alloc_internal(domain, is_logical, device_address,
				 device_id, lun, private_bus, channel,
				 NULL, NULL, &nfru);
    if (rv) {
	locked_list_unlock(frul);
	ipmi_domain_attr_put(attr);
	return rv;
    }

    nfru->in_frulist = 1;

    if (! locked_list_add_nolock(frul, nfru, NULL)) {
	locked_list_unlock(frul);
	nfru->fetched_handler = NULL;
	ipmi_fru_destroy(nfru, NULL, NULL);
	ipmi_domain_attr_put(attr);
	return ENOMEM;
    }
    nfru->domain_fetched_handler = fetched_handler;
    nfru->fetched_cb_data = fetched_cb_data;
    fru_unlock(nfru);
    locked_list_unlock(frul);
    ipmi_domain_attr_put(attr);

    if (new_fru)
	*new_fru = nfru;
    return 0;
}

int
ipmi_fru_alloc(ipmi_domain_t       *domain,
	       unsigned char       is_logical,
	       unsigned char       device_address,
	       unsigned char       device_id,
	       unsigned char       lun,
	       unsigned char       private_bus,
	       unsigned char       channel,
	       ipmi_fru_fetched_cb fetched_handler,
	       void                *fetched_cb_data,
	       ipmi_fru_t          **new_fru)
{
    ipmi_fru_t         *nfru;
    int                rv;
    ipmi_domain_attr_t *attr;
    locked_list_t      *frul;

    rv = ipmi_domain_register_attribute(domain, IPMI_FRU_ATTR_NAME,
					fru_attr_init,
					fru_attr_destroy,
					NULL,
					&attr);
    if (rv)
	return rv;
    frul = ipmi_domain_attr_get_data(attr);

    /* Be careful with locking, a FRU fetch is already going on when
       the alloc_internal function returns. */
    locked_list_lock(frul);
    rv = ipmi_fru_alloc_internal(domain, is_logical, device_address,
				 device_id, lun, private_bus, channel,
				 fetched_handler, fetched_cb_data, &nfru);
    if (rv) {
	ipmi_domain_attr_put(attr);
	locked_list_unlock(frul);
	return rv;
    }

    nfru->in_frulist = 1;

    if (! locked_list_add_nolock(frul, nfru, NULL)) {
	locked_list_unlock(frul);
	nfru->fetched_handler = NULL;
	ipmi_fru_destroy(nfru, NULL, NULL);
	ipmi_domain_attr_put(attr);
	return ENOMEM;
    }
    fru_unlock(nfru);
    locked_list_unlock(frul);
    ipmi_domain_attr_put(attr);

    if (new_fru)
	*new_fru = nfru;
    return 0;
}

int
ipmi_fru_alloc_notrack(ipmi_domain_t *domain,
		       unsigned char is_logical,
		       unsigned char device_address,
		       unsigned char device_id,
		       unsigned char lun,
		       unsigned char private_bus,
		       unsigned char channel,
		       ipmi_ifru_cb  fetched_handler,
		       void          *fetched_cb_data,
		       ipmi_fru_t    **new_fru)
{
    ipmi_fru_t *nfru;
    int        rv;

    rv = ipmi_fru_alloc_internal(domain, is_logical, device_address,
				 device_id, lun, private_bus, channel,
				 NULL, NULL, &nfru);
    if (rv)
	return rv;
    nfru->domain_fetched_handler = fetched_handler;
    nfru->fetched_cb_data = fetched_cb_data;
    fru_unlock(nfru);

    if (new_fru)
	*new_fru = nfru;
    return 0;
}

/***********************************************************************
 *
 * FRU reading
 *
 **********************************************************************/
typedef struct fru_offset_s
{
    int type;
    int offset;
} fru_offset_t;

static int
process_fru_info(ipmi_fru_t *fru)
{
    unsigned char *data = fru->data;
    unsigned int  data_len = fru->data_len;
    fru_offset_t  foff[IPMI_FRU_FTR_NUMBER];
    int           i, j;
    int           err = 0;

    if (checksum(data, 8) != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(process_fru_info):"
		 " FRU checksum failed",
		 FRU_DOMAIN_NAME(fru));
	return EBADF;
    }

    fru->version = *data;

    for (i=0; i<IPMI_FRU_FTR_NUMBER; i++) {
	foff[i].type = i;
	foff[i].offset = data[i+1] * 8;
	if (foff[i].offset >= data_len) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sfru.c(process_fru_info):"
		     " FRU offset exceeds data length",
		     FRU_DOMAIN_NAME(fru));
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
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sfru.c(process_fru_info):"
		     " FRU fields did not occur in the correct order",
		     FRU_DOMAIN_NAME(fru));
	    return EBADF;
	}
    }
 check_done:

    for (i=0; i<IPMI_FRU_FTR_NUMBER; i++) {
	int plen, next_off, offset;
	ipmi_fru_record_t *rec;

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

	rec = NULL;
	err = fru_area_info[i].decode(fru, data+offset, plen, &fru->recs[i]);
	if (err)
	    goto out_err;

	if (fru->recs[i])
	    fru->recs[i]->offset = offset;
    }

    return 0;

 out_err:
    return err;
}

void
fetch_complete(ipmi_domain_t *domain, ipmi_fru_t *fru, int err)
{
    if (!err)
	err = process_fru_info(fru);

    if (fru->data)
	ipmi_mem_free(fru->data);
    fru->data = NULL;

    fru->in_use = 0;
    fru_unlock(fru);

    if (fru->fetched_handler)
	fru->fetched_handler(fru, err, fru->fetched_cb_data);
    else if (fru->domain_fetched_handler)
	fru->domain_fetched_handler(domain, fru, err, fru->fetched_cb_data);

    fru_put(fru);
}

static int request_next_data(ipmi_domain_t *domain,
			     ipmi_fru_t    *fru,
			     ipmi_addr_t   *addr,
			     unsigned int  addr_len);

static int
fru_data_handler(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_addr_t   *addr = &rspi->addr;
    unsigned int  addr_len = rspi->addr_len;
    ipmi_msg_t    *msg = &rspi->msg;
    ipmi_fru_t    *fru = rspi->data1;
    unsigned char *data = msg->data;
    int           count;
    int           err;

    fru_lock(fru);

    if (fru->deleted) {
	fetch_complete(domain, fru, ECANCELED);
	goto out;
    }

    /* The timeout and unknown errors should not be necessary, but
       some broken systems just don't return anything if the response
       is too big. */
    if (((data[0] == IPMI_CANNOT_RETURN_REQ_LENGTH_CC)
	 || (data[0] == IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC)
	 || (data[0] == IPMI_REQUEST_DATA_LENGTH_INVALID_CC)
	 || (data[0] == IPMI_TIMEOUT_CC)
	 || (data[0] == IPMI_UNKNOWN_ERR_CC))
	&& (fru->fetch_size > MIN_FRU_DATA_FETCH))
    {
	/* System couldn't support the given size, try decreasing and
	   starting again. */
	fru->fetch_size -= FRU_DATA_FETCH_DECR;
	err = request_next_data(domain, fru, addr, addr_len);
	if (err) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sfru.c(fru_data_handler): "
		     "Error requesting next FRU data (2)",
		     FRU_DOMAIN_NAME(fru));
	    fetch_complete(domain, fru, err);
	    goto out;
	}
	goto out_unlock;
    }

    if (data[0] != 0) {
	if (fru->curr_pos >= 8) {
	    /* Some screwy cards give more size in the info than they
	       really have, if we have enough, try to process it. */
	    ipmi_log(IPMI_LOG_WARNING,
		     "%sfru.c(fru_data_handler): "
		     "IPMI error getting FRU data: %x",
		     FRU_DOMAIN_NAME(fru), data[0]);
	    fru->data_len = fru->curr_pos;
	    fetch_complete(domain, fru, 0);
	} else {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sfru.c(fru_data_handler): "
		     "IPMI error getting FRU data: %x",
		     FRU_DOMAIN_NAME(fru), data[0]);
	    fetch_complete(domain, fru, IPMI_IPMI_ERR_VAL(data[0]));
	}
	goto out;
    }

    if (msg->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_data_handler): "
		 "FRU data response too small",
		 FRU_DOMAIN_NAME(fru));
	fetch_complete(domain, fru, EINVAL);
	goto out;
    }

    count = data[1] << fru->access_by_words;

    if (count == 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_data_handler): "
		 "FRU got zero-sized data, must make progress!",
		 FRU_DOMAIN_NAME(fru));
	fetch_complete(domain, fru, EINVAL);
	goto out;
    }

    if (count > msg->data_len-2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_data_handler): "
		 "FRU data count mismatch",
		 FRU_DOMAIN_NAME(fru));
	fetch_complete(domain, fru, EINVAL);
	goto out;
    }

    memcpy(fru->data+fru->curr_pos, data+2, count);
    fru->curr_pos += count;

    if (fru->curr_pos < fru->data_len) {
	/* More to fetch. */
	err = request_next_data(domain, fru, addr, addr_len);
	if (err) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sfru.c(fru_data_handler): "
		     "Error requesting next FRU data",
		     FRU_DOMAIN_NAME(fru));
	    fetch_complete(domain, fru, err);
	    goto out;
	}
    } else {
	fetch_complete(domain, fru, 0);
	goto out;
    }

 out_unlock:
    fru_unlock(fru);
 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
request_next_data(ipmi_domain_t *domain,
		  ipmi_fru_t    *fru,
		  ipmi_addr_t   *addr,
		  unsigned int  addr_len)
{
    unsigned char cmd_data[4];
    ipmi_msg_t    msg;
    int           to_read;

    /* We only request as much as we have to.  Don't always reqeust
       the maximum amount, some machines don't like this. */
    to_read = fru->data_len - fru->curr_pos;
    if (to_read > fru->fetch_size)
	to_read = fru->fetch_size;

    cmd_data[0] = fru->device_id;
    ipmi_set_uint16(cmd_data+1, fru->curr_pos >> fru->access_by_words);
    cmd_data[3] = to_read >> fru->access_by_words;
    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_READ_FRU_DATA_CMD;
    msg.data = cmd_data;
    msg.data_len = 4;

    return ipmi_send_command_addr(domain,
				  addr, addr_len,
				  &msg,
				  fru_data_handler,
				  fru,
				  NULL);
}

static int
fru_inventory_area_handler(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_addr_t   *addr = &rspi->addr;
    unsigned int  addr_len = rspi->addr_len;
    ipmi_msg_t    *msg = &rspi->msg;
    ipmi_fru_t    *fru = rspi->data1;
    unsigned char *data = msg->data;
    int           err;

    fru_lock(fru);

    if (fru->deleted) {
	fetch_complete(domain, fru, ECANCELED);
	goto out;
    }

    if (data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_inventory_area_handler): "
		 "IPMI error getting FRU inventory area: %x",
		 FRU_DOMAIN_NAME(fru), data[0]);
	fetch_complete(domain, fru, IPMI_IPMI_ERR_VAL(data[0]));
	goto out;
    }

    if (msg->data_len < 4) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_inventory_area_handler): "
		 "FRU inventory area too small",
		 FRU_DOMAIN_NAME(fru));
	fetch_complete(domain, fru, EINVAL);
	goto out;
    }

    fru->data_len = ipmi_get_uint16(data+1);
    fru->access_by_words = data[3] & 1;

    if (fru->data_len < 8) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_inventory_area_handler): "
		 "FRU space less than the header",
		 FRU_DOMAIN_NAME(fru));
	fetch_complete(domain, fru, EMSGSIZE);
	goto out;
    }

    fru->data = ipmi_mem_alloc(fru->data_len);
    if (!fru->data) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_inventory_area_handler): "
		 "Error allocating FRU data",
		 FRU_DOMAIN_NAME(fru));
	fetch_complete(domain, fru, ENOMEM);
	goto out;
    }

    err = request_next_data(domain, fru, addr, addr_len);
    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_inventory_area_handler): "
		 "Error requesting next FRU data",
		 FRU_DOMAIN_NAME(fru));
	fetch_complete(domain, fru, err);
	goto out;
    }

    fru_unlock(fru);
 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
start_logical_fru_fetch(ipmi_domain_t *domain, ipmi_fru_t *fru)
{
    unsigned char    cmd_data[1];
    ipmi_ipmb_addr_t ipmb;
    ipmi_msg_t       msg;

    ipmb.addr_type = IPMI_IPMB_ADDR_TYPE;
    ipmb.channel = fru->channel;
    ipmb.slave_addr = fru->device_address;
    ipmb.lun = fru->lun;

    cmd_data[0] = fru->device_id;
    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_GET_FRU_INVENTORY_AREA_INFO_CMD;
    msg.data = cmd_data;
    msg.data_len = 1;

    return ipmi_send_command_addr(domain,
				  (ipmi_addr_t *) &ipmb,
				  sizeof(ipmb),
				  &msg,
				  fru_inventory_area_handler,
				  fru,
				  NULL);
}

static int
start_physical_fru_fetch(ipmi_domain_t *domain, ipmi_fru_t *fru)
{
    /* FIXME - this is going to suck, but needs to be implemented. */
    return ENOSYS;
}

/***********************************************************************
 *
 * FRU writing
 *
 **********************************************************************/

static int next_fru_write(ipmi_domain_t *domain, ipmi_fru_t *fru,
			  ipmi_addr_t *addr, unsigned int addr_len);

void
write_complete(ipmi_domain_t *domain, ipmi_fru_t *fru, int err)
{
    int i;

    if (!err) {
	/* If we succeed, set everything unchanged. */
	for (i=0; i<IPMI_FRU_FTR_NUMBER; i++) {
	    ipmi_fru_record_t *rec = fru->recs[i];
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
    if (fru->data)
	ipmi_mem_free(fru->data);
    fru->data = NULL;

    fru->in_use = 0;
    fru_unlock(fru);

    if (fru->domain_fetched_handler)
	fru->domain_fetched_handler(domain, fru, err, fru->fetched_cb_data);

    fru_put(fru);
}

static int
fru_write_handler(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_addr_t   *addr = &rspi->addr;
    unsigned int  addr_len = rspi->addr_len;
    ipmi_msg_t    *msg = &rspi->msg;
    ipmi_fru_t    *fru = rspi->data1;
    unsigned char *data = msg->data;
    int           rv;

    fru_lock(fru);

    /* Note that for safety, we do not stop a fru write on deletion. */

    if (data[0] == 0x81) {
	ipmi_msg_t msg;
	/* Got a busy response.  Try again if we haven't run out of
	   retries. */
	if (fru->retry_count >= MAX_FRU_WRITE_RETRIES) {
	    write_complete(domain, fru, IPMI_IPMI_ERR_VAL(data[0]));
	    goto out;
	}
	fru->retry_count++;
	msg.netfn = IPMI_STORAGE_NETFN;
	msg.cmd = IPMI_WRITE_FRU_DATA_CMD;
	msg.data = fru->last_cmd;
	msg.data_len = fru->last_cmd_len;
	rv = ipmi_send_command_addr(domain,
				    addr, addr_len,
				    &msg,
				    fru_data_handler,
				    fru,
				    NULL);
	if (rv) {
	    write_complete(domain, fru, rv);
	    goto out;
	}
	goto out_cmd;
    } else if (data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_write_handler): "
		 "IPMI error writing FRU data: %x",
		 FRU_DOMAIN_NAME(fru), data[0]);
	write_complete(domain, fru, IPMI_IPMI_ERR_VAL(data[0]));
	goto out;
    }

    if (msg->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_write_handler): "
		 "FRU write response too small",
		 FRU_DOMAIN_NAME(fru));
	write_complete(domain, fru, EINVAL);
	goto out;
    }

    if ((data[1] << fru->access_by_words) != (fru->last_cmd_len - 3)) {
	/* Write was incomplete for some reason.  Just go on but issue
	   a warning. */
	ipmi_log(IPMI_LOG_WARNING,
		 "%sfru.c(fru_write_handler): "
		 "Incomplete writing FRU data, write %d, expected %d",
		 FRU_DOMAIN_NAME(fru),
		 data[1] << fru->access_by_words, fru->last_cmd_len-3);
    }

    if (fru->update_recs) {
	/* More to do. */
	rv = next_fru_write(domain, fru, addr, addr_len);
	if (rv) {
	    write_complete(domain, fru, rv);
	    goto out;
	}
    } else {
	write_complete(domain, fru, 0);
	goto out;
    }

 out_cmd:
    fru_unlock(fru);
 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
next_fru_write(ipmi_domain_t *domain,
	       ipmi_fru_t    *fru,
	       ipmi_addr_t   *addr,
	       unsigned int  addr_len)
{
    unsigned char *data = fru->last_cmd;
    int           offset, length = 0, left, noff, tlen;
    ipmi_msg_t    msg;

    noff = fru->update_recs->offset;
    offset = noff;
    left = MAX_FRU_DATA_WRITE;
    while (fru->update_recs
	   && (left > 0)
	   && (noff == fru->update_recs->offset))
    {
	if (left < fru->update_recs->length)
	    tlen = left;
	else
	    tlen = fru->update_recs->length;

	noff += tlen;
	length += tlen;
	left -= tlen;
	fru->update_recs->length -= tlen;
	if (fru->update_recs->length > 0) {
	    fru->update_recs->offset += tlen;
	} else {
	    fru_update_t *to_free = fru->update_recs;
	    fru->update_recs = to_free->next;
	    ipmi_mem_free(to_free);
	}
    }

    fru->retry_count = 0;
    data[0] = fru->device_id;
    ipmi_set_uint16(data+1, offset >> fru->access_by_words);
    memcpy(data+3, fru->data+offset, length);
    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_WRITE_FRU_DATA_CMD;
    msg.data = data;
    msg.data_len = length + 3;
    fru->last_cmd_len = msg.data_len;

    return ipmi_send_command_addr(domain,
				  addr, addr_len,
				  &msg,
				  fru_write_handler,
				  fru,
				  NULL);
}

typedef struct start_domain_fru_write_s
{
    ipmi_fru_t *fru;
    int        rv;
} start_domain_fru_write_t;

static void
start_domain_fru_write(ipmi_domain_t *domain, void *cb_data)
{
    start_domain_fru_write_t *info = cb_data;
    ipmi_ipmb_addr_t         ipmb;
    int                      rv;
    int                      i;
    ipmi_fru_t               *fru = info->fru;

    /* We allocate and format the entire FRU data.  We do this because
       of the stupid word access capability, which means we cannot
       necessarily do byte-aligned writes.  Because of that, we might
       have to have the byte before or after the actual one being
       written, and it may come from a different data field. */
    fru->data = ipmi_mem_alloc(fru->data_len);
    memset(fru->data, 0, fru->data_len);
    fru->data[0] = 1; /* Version */
    for (i=0; i<IPMI_FRU_FTR_MULTI_RECORD_AREA; i++) {
	if (fru->recs[i])
	    fru->data[i+1] = fru->recs[i]->offset / 8;
	else
	    fru->data[i+1] = 0;
    }
    if (fru->recs[i] && fru->recs[i]->used_length)
	fru->data[i+1] = fru->recs[i]->offset / 8;
    else
	fru->data[i+1] = 0;
    fru->data[6] = 0;
    fru->data[7] = -checksum(fru->data, 7);

    if (fru->header_changed) {
	rv = fru_new_update_rec(fru, 0, 8);
	if (rv)
	    goto out_err;
    }

    for (i=0; i<IPMI_FRU_FTR_NUMBER; i++) {
	ipmi_fru_record_t *rec = fru->recs[i];

	if (rec) {
	    rv = rec->handlers->encode(fru, fru->data);
	    if (rv)
		goto out_err;
	    if (rec->rewrite) {
		if (i == IPMI_FRU_FTR_MULTI_RECORD_AREA)
		    rv = fru_new_update_rec(fru, rec->offset,
					    rec->used_length);
		else
		    rv = fru_new_update_rec(fru, rec->offset, rec->length);
		if (rv)
		    goto out_err;
		
	    }
	}
    }    

    if (!fru->update_recs) {
	/* No data changed, no write is needed. */
	ipmi_mem_free(fru->data);
	fru->data = NULL;
	fru_unlock(fru);

	if (fru->domain_fetched_handler)
	    fru->domain_fetched_handler(domain, fru, 0, fru->fetched_cb_data);
	return;
    }

    ipmb.addr_type = IPMI_IPMB_ADDR_TYPE;
    ipmb.channel = info->fru->channel;
    ipmb.slave_addr = info->fru->device_address;
    ipmb.lun = info->fru->lun;

    /* Data is fully encoded and the update records are in place.
       Start the write process. */
    rv = next_fru_write(domain, fru,
			(ipmi_addr_t *) &ipmb, sizeof(ipmb));
    if (rv)
	goto out_err;

    fru_get(fru);
    fru_unlock(fru);
    return;

 out_err:
    while (fru->update_recs) {
	fru_update_t *to_free = fru->update_recs;
	fru->update_recs = to_free->next;
	ipmi_mem_free(to_free);
    }
    ipmi_mem_free(fru->data);
    fru->data = NULL;
    fru->in_use = 0;
    fru_unlock(fru);
    info->rv = rv;
}

int
ipmi_fru_write(ipmi_fru_t *fru, ipmi_fru_cb done, void *cb_data)
{
    int                      rv;
    start_domain_fru_write_t info = {fru, 0};

    fru_lock(fru);
    if (fru->in_use) {
	/* Something else is happening with the FRU, error this
	   operation. */
	fru_unlock(fru);
	return EAGAIN;
    }
    fru->in_use = 1;

    fru->domain_fetched_handler = done;
    fru->fetched_cb_data = cb_data;

    /* Data is fully encoded and the update records are in place.
       Start the write process. */
    rv = ipmi_domain_pointer_cb(fru->domain_id, start_domain_fru_write, &info);
    if (!rv)
	rv = info.rv;
    else
	fru_unlock(fru);

    return rv;
}

/***********************************************************************
 *
 * Misc stuff.
 *
 **********************************************************************/
ipmi_domain_id_t
ipmi_fru_get_domain_id(ipmi_fru_t *fru)
{
    return fru->domain_id;
}

void
ipmi_fru_data_free(char *data)
{
    ipmi_mem_free(data);
}

unsigned int
ipmi_fru_get_data_length(ipmi_fru_t *fru)
{
    return fru->data_len;
}

int
ipmi_fru_get_name(ipmi_fru_t *fru, char *name, int length)
{
    int  slen;

    if (length <= 0)
	return 0;

    /* Never changes, no lock needed. */
    slen = strlen(fru->name);
    if (slen == 0) {
	if (name)
	    *name = '\0';
	goto out;
    }

    if (name) {
	memcpy(name, fru->name, slen);
	name[slen] = '\0';
    }
 out:
    return slen;
}

typedef struct iterate_frus_info_s
{
    ipmi_fru_ptr_cb handler;
    void            *cb_data;
} iterate_frus_info_t;

static int
frus_handler(void *cb_data, void *item1, void *item2)
{
    iterate_frus_info_t *info = cb_data;
    info->handler(item1, info->cb_data);
    fru_put(item1);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
frus_prefunc(void *cb_data, void *item1, void *item2)
{
    ipmi_fru_t *fru = item1;
    ipmi_lock(fru->lock);
    fru_get(fru);
    ipmi_unlock(fru->lock);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_fru_iterate_frus(ipmi_domain_t   *domain,
		      ipmi_fru_ptr_cb handler,
		      void            *cb_data)
{
    iterate_frus_info_t info;
    ipmi_domain_attr_t  *attr;
    locked_list_t       *frus;
    int                 rv;

    rv = ipmi_domain_find_attribute(domain, IPMI_FRU_ATTR_NAME,
				    &attr);
    if (rv)
	return;
    frus = ipmi_domain_attr_get_data(attr);

    info.handler = handler;
    info.cb_data = cb_data;
    locked_list_iterate_prefunc(frus, frus_prefunc, frus_handler, &info);
    ipmi_domain_attr_put(attr);
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
    int                       hasnum;

    union {
	struct {
	    int (*fetch_uchar)(ipmi_fru_t *fru, unsigned char *data);
	    int (*set_uchar)(ipmi_fru_t *fru, unsigned char data);
	} inttype;

	struct {
	    int (*fetch_uchar)(ipmi_fru_t *fru, unsigned int num,
			       unsigned char *data);
	    int (*set_uchar)(ipmi_fru_t *fru, unsigned int num,
			     unsigned char data);
	} intnumtype;

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
	} binnumtype;
    } u;
} fru_data_rep_t;

#define F_UCHAR(x) { .name = #x, .type = IPMI_FRU_DATA_INT, .hasnum = 0, \
		     .u = { .inttype = { .fetch_uchar = ipmi_fru_get_ ## x, \
					 .set_uchar = ipmi_fru_set_ ## x }}}
#define F_NUM_UCHAR(x) { .name = #x, .type = IPMI_FRU_DATA_INT, .hasnum = 1, \
		         .u = { .intnumtype = {				     \
				 .fetch_uchar = ipmi_fru_get_ ## x,	     \
				 .set_uchar = ipmi_fru_set_ ## x }}}
#define F_TIME(x) { .name = #x, .type = IPMI_FRU_DATA_TIME, .hasnum = 0, \
		    .u = { .timetype = { .fetch = ipmi_fru_get_ ## x,    \
					 .set = ipmi_fru_set_ ## x }}}
#define F_NUM_TIME(x) { .name = #x, .type = IPMI_FRU_DATA_TIME, .hasnum = 1, \
		        .u = { .timenumtype = { .fetch = ipmi_fru_get_ ## x, \
					        .set = ipmi_fru_set_ ## x }}}
#define F_STR(x) { .name = #x, .type = IPMI_FRU_DATA_ASCII, .hasnum = 0, \
		   .u = { .strtype = {					     \
			  .fetch_len = ipmi_fru_get_ ## x ## _len, \
		          .fetch_type = ipmi_fru_get_ ## x ## _type, \
		          .fetch_data = ipmi_fru_get_ ## x, \
			  .set = ipmi_fru_set_ ## x }}}
#define F_NUM_STR(x) { .name = #x, .type = IPMI_FRU_DATA_ASCII, .hasnum = 1, \
		       .u = { .strnumtype = {                                \
			      .fetch_len = ipmi_fru_get_ ## x ## _len, \
		              .fetch_type = ipmi_fru_get_ ## x ## _type,\
		              .fetch_data = ipmi_fru_get_ ## x, \
			      .set = ipmi_fru_set_ ## x }}}
#define F_BIN(x) { .name = #x, .type = IPMI_FRU_DATA_BINARY, .hasnum = 0, \
		   .u = { .bintype = {					     \
			  .fetch_len = ipmi_fru_get_ ## x ## _len, \
		   	  .fetch_data = ipmi_fru_get_ ## x, \
			  .set = ipmi_fru_set_ ## x }}}
#define F_NUM_BIN(x) { .name = #x, .type = IPMI_FRU_DATA_BINARY, .hasnum = 1, \
		       .u = { .binnumtype = {				      \
			      .fetch_len = ipmi_fru_get_ ## x ## _len, \
		       	      .fetch_data = ipmi_fru_get_ ## x, \
			      .set = ipmi_fru_set_ ## x }}}
static fru_data_rep_t frul[] =
{
    F_UCHAR(internal_use_version),
    F_BIN(internal_use),
    F_UCHAR(chassis_info_version),
    F_UCHAR(chassis_info_type),
    F_STR(chassis_info_part_number),
    F_STR(chassis_info_serial_number),
    F_NUM_STR(chassis_info_custom),
    F_UCHAR(board_info_version),
    F_UCHAR(board_info_lang_code),
    F_TIME(board_info_mfg_time),
    F_STR(board_info_board_manufacturer),
    F_STR(board_info_board_product_name),
    F_STR(board_info_board_serial_number),
    F_STR(board_info_board_part_number),
    F_STR(board_info_fru_file_id),
    F_NUM_STR(board_info_custom),
    F_UCHAR(product_info_version),
    F_UCHAR(product_info_lang_code),
    F_STR(product_info_manufacturer_name),
    F_STR(product_info_product_name),
    F_STR(product_info_product_part_model_number),
    F_STR(product_info_product_version),
    F_STR(product_info_product_serial_number),
    F_STR(product_info_asset_tag),
    F_STR(product_info_fru_file_id),
    F_NUM_STR(product_info_custom),
};
#define NUM_FRUL_ENTRIES (sizeof(frul) / sizeof(fru_data_rep_t))

int
ipmi_fru_str_to_index(char *name)
{
    int i;
    for (i=0; i<NUM_FRUL_ENTRIES; i++) {
	if (strcmp(name, frul[i].name) == 0)
	    return i;
    }
    return -1;
}

char *
ipmi_fru_index_to_str(int index)
{
    if ((index < 0) || (index >= NUM_FRUL_ENTRIES))
	return NULL;

    return frul[index].name;
}

int
ipmi_fru_get(ipmi_fru_t                *fru,
	     int                       index,
	     char                      **name,
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
    

    if ((index < 0) || (index >= NUM_FRUL_ENTRIES))
	return EINVAL;

    p = frul + index;

    if (name)
	*name = p->name;

    rdtype = p->type;

    switch (p->type) {
    case IPMI_FRU_DATA_INT:
	if (intval) {
	    if (! p->hasnum) {
		rv = p->u.inttype.fetch_uchar(fru, &ucval);
	    } else {
		rv = p->u.intnumtype.fetch_uchar(fru, *num, &ucval);
		rv2 = p->u.intnumtype.fetch_uchar(fru, (*num)+1, &dummy_ucval);
	    }
	    if (!rv)
		*intval = ucval;
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
		    rv = p->u.bintype.fetch_data(fru, (char *) dval, &len);
		} else {
		    rv = p->u.binnumtype.fetch_data(fru, *num, (char *) dval,
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

    if ((index < 0) || (index >= NUM_FRUL_ENTRIES))
	return EINVAL;

    p = frul + index;

    if (p->type != IPMI_FRU_DATA_INT)
	return EINVAL;

    if (! p->hasnum) {
	rv = p->u.inttype.set_uchar(fru, val);
    } else {
	rv = p->u.intnumtype.set_uchar(fru, num, val);
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
    

    if ((index < 0) || (index >= NUM_FRUL_ENTRIES))
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
    

    if ((index < 0) || (index >= NUM_FRUL_ENTRIES))
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
	    rv = p->u.bintype.set(fru, data, len);
	} else {
	    rv = p->u.binnumtype.set(fru, num, data, len);
	}
	break;

    default:
	return EINVAL;
    }

    return rv;
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
