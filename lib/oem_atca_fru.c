/*
 * oem_atca_fru.c
 *
 * FRU Multirecord decoding for ATCA multirecords.
 *
 *  (C) 2005 MontaVista Software, Inc.
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
#include <stdio.h> /* for sprintf */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <OpenIPMI/internal/ipmi_fru.h>
#include <OpenIPMI/internal/ipmi_int.h>


/***********************************************************************
 *
 * Table-driven data engine for handling multirecord fru info.
 *
 **********************************************************************/

typedef struct mr_struct_layout_s mr_struct_layout_t;
typedef struct mr_struct_info_s mr_struct_info_t;
typedef struct mr_item_layout_s mr_item_layout_t;
typedef struct mr_array_layout_s mr_array_layout_t;
typedef struct mr_array_info_s mr_array_info_t;
typedef struct mr_offset_s mr_offset_t;

struct mr_offset_s {
    uint8_t     offset;
    uint8_t     length;
    mr_offset_t *parent;
};

static uint8_t full_offset(mr_offset_t *o)
{
    uint8_t rv = 0;

    while (o) {
	rv += o->offset;
	o = o->parent;
    }
    return rv;
}

static void adjust_len(mr_offset_t *o, int len)
{
    while (o) {
	o->length += len;
	o = o->parent;
    }
}

typedef struct mr_fru_info_s {
    ipmi_fru_t   *fru;
    unsigned int mr_rec_num;
} mr_fru_info_t;

struct mr_array_info_s {
    uint8_t           count;
    uint8_t           nr_after; /* Number of arrays after me. */
    mr_offset_t       offset;
    mr_array_layout_t *layout;
    mr_struct_info_t  **items;
};

struct mr_struct_info_s
{
    uint8_t            len;
    mr_offset_t        offset;
    mr_struct_layout_t *layout;
    unsigned char      *data;
    mr_array_info_t    *arrays;
};

typedef struct mr_tab_item_s {
    unsigned int count;
    char         *table[];
} mr_tab_item_t;

struct mr_item_layout_s
{
    char                      *name;
    enum ipmi_fru_data_type_e dtype;

    uint8_t settable;

    uint16_t start;
    uint16_t length;

    float multiplier;
    mr_tab_item_t *tab;

    int (*set_field)(mr_item_layout_t          *layout,
		     mr_struct_info_t          *rec,
		     mr_fru_info_t             *finfo,
		     enum ipmi_fru_data_type_e dtype,
		     int                       intval,
		     time_t                    time,
		     double                    floatval,
		     char                      *data,
		     unsigned int              data_len);
    int (*get_field)(mr_item_layout_t          *layout,
		     mr_struct_info_t          *rec,
		     enum ipmi_fru_data_type_e *dtype,
		     int                       *intval,
		     time_t                    *time,
		     double                    *floatval,
		     char                      **data,
		     unsigned int              *data_len);
};

struct mr_array_layout_s
{
    char    *name;
    uint8_t has_count;
    uint8_t min_elem_size;
    mr_struct_layout_t *elem_layout;
    int (*elem_check)(mr_struct_layout_t *layout,
		      unsigned char **mr_data,
		      unsigned int  *mr_data_len);
    int (*elem_decode)(mr_struct_info_t   *rec,
		       unsigned char      **mr_data,
		       unsigned int       *mr_data_len);
    void (*cleanup)(mr_array_info_t *arec);
    int (*get_field)(mr_array_info_t           *arec,
		     ipmi_fru_node_t           *rnode,
		     enum ipmi_fru_data_type_e *dtype,
		     int                       *intval,
		     time_t                    *time,
		     double                    *floatval,
		     char                      **data,
		     unsigned int              *data_len,
		     ipmi_fru_node_t           **sub_node);
};

struct mr_struct_layout_s
{
    char              *name;
    uint8_t           length; /* Excluding arrays. */
    unsigned int      item_count;
    mr_item_layout_t  *items;
    unsigned int      array_count;
    mr_array_layout_t *arrays;

    void (*cleanup)(mr_struct_info_t *rec);
};

static int mr_node_struct_get_field(ipmi_fru_node_t           *node,
				    unsigned int              index,
				    const char                **name,
				    enum ipmi_fru_data_type_e *dtype,
				    int                       *intval,
				    time_t                    *time,
				    double                    *floatval,
				    char                      **data,
				    unsigned int              *data_len,
				    ipmi_fru_node_t           **sub_node);
static int mr_node_struct_set_field(ipmi_fru_node_t           *node,
				    unsigned int              index,
				    enum ipmi_fru_data_type_e dtype,
				    int                       intval,
				    time_t                    time,
				    double                    floatval,
				    char                      *data,
				    unsigned int              data_len);
static int mr_node_struct_settable(ipmi_fru_node_t *node,
				   unsigned int    index);


static void
mr_array_cleanup(mr_array_info_t *arec)
{
    int i;

    if (arec->items) {
	for (i=0; i<arec->count; i++) {
	    if (arec->items[i])
		arec->items[i]->layout->cleanup(arec->items[i]);
	}
	ipmi_mem_free(arec->items);
    }
}

static void
mr_struct_cleanup(mr_struct_info_t *rec)
{
    unsigned int i;

    if (rec->data)
	ipmi_mem_free(rec->data);
    if (rec->arrays) {
	for (i=0; i<rec->layout->array_count; i++) {
	    if (rec->arrays[i].layout)
		rec->arrays[i].layout->cleanup(rec->arrays+i);
	}
	ipmi_mem_free(rec->arrays);
    }
    ipmi_mem_free(rec);
}

static void
mr_struct_root_destroy(ipmi_fru_node_t *node)
{
    mr_struct_info_t *rec = _ipmi_fru_node_get_data(node);
    mr_fru_info_t    *finfo = _ipmi_fru_node_get_data2(node);
    ipmi_fru_deref(finfo->fru);
    rec->layout->cleanup(rec);
    ipmi_mem_free(finfo);
}

static void
mr_sub_destroy(ipmi_fru_node_t *node)
{
    ipmi_fru_node_t *root_node = _ipmi_fru_node_get_data2(node);
    ipmi_fru_put_node(root_node);
}

static int
mr_node_array_set_field(ipmi_fru_node_t           *node,
			unsigned int              index,
			enum ipmi_fru_data_type_e dtype,
			int                       intval,
			time_t                    time,
			double                    floatval,
			char                      *data,
			unsigned int              data_len)
{
    mr_array_info_t  *arec = _ipmi_fru_node_get_data(node);
    ipmi_fru_node_t  *rnode = _ipmi_fru_node_get_data2(node);
    mr_fru_info_t    *finfo = _ipmi_fru_node_get_data2(rnode);
    mr_struct_info_t **newa;
    mr_struct_info_t **olda;
    mr_struct_info_t *newv;
    int              i, j, no;
    int              rv;
    unsigned char    *sdata;
    uint8_t          offset;

    if (index > arec->count)
	index = arec->count;

    if (data) {
	/* insert a new entry */

	if (arec->count >= 255)
	    return E2BIG;

	newa = ipmi_mem_alloc(sizeof(*newa) * (arec->count+1));
	if (!newa)
	    return ENOMEM;
	newv = ipmi_mem_alloc(sizeof(*newv));
	if (!newv) {
	    ipmi_mem_free(newa);
	    return ENOMEM;
	}
	memset(newv, 0, sizeof(*newv));
	sdata = ipmi_mem_alloc(arec->layout->min_elem_size);
	if (!sdata) {
	    ipmi_mem_free(newa);
	    ipmi_mem_free(newv);
	    return ENOMEM;
	}
	memset(sdata, 0, arec->layout->min_elem_size);
	if (data) {
	    if (data_len > arec->layout->min_elem_size)
		memcpy(sdata, data, arec->layout->min_elem_size);
	    else
		memcpy(sdata, data, data_len);
	}

	if (index == arec->count)
	    offset = arec->offset.length;
	else
	    offset = arec->items[index]->offset.offset;
	newv->offset.offset = offset;
	newv->offset.parent = &arec->offset;

	rv = ipmi_fru_ins_multi_record_data(finfo->fru, finfo->mr_rec_num,
					    sdata,
					    full_offset(&newv->offset),
					    arec->layout->min_elem_size);
	if (rv) {
	    ipmi_mem_free(sdata);
	    ipmi_mem_free(newa);
	    ipmi_mem_free(newv);
	    return rv;
	}
	adjust_len(&arec->offset, arec->layout->min_elem_size);

	if (arec->items) {
	    no = 0;
	    for (i=0, j=0; i<(int)arec->count; j++) {
		if (j == (int) index) {
		    no = arec->layout->min_elem_size;
		    continue;
		}
		newa[j] = arec->items[i];
		newa[j]->offset.offset += no;
		i++;
	    }
	}
	newa[index] = newv;
	newv->len = arec->layout->min_elem_size;
	newv->data = sdata;
	newv->layout = arec->layout->elem_layout;
	
	no = arec->layout->min_elem_size;
	i = 1;
    } else {
	/* Delete an entry */
	mr_struct_info_t *cr;

	if (index > arec->count)
	    return EINVAL;

	cr = arec->items[index];

	newa = ipmi_mem_alloc(sizeof(*newa) * (arec->count-1));
	if (!newa)
	    return ENOMEM;
	rv = ipmi_fru_del_multi_record_data(finfo->fru, finfo->mr_rec_num,
					    full_offset(&cr->offset),
					    cr->offset.length);
	if (rv) {
	    ipmi_mem_free(newa);
	    return rv;
	}

	adjust_len(&arec->offset, - (int) cr->offset.length);

	no = 0;
	for (i=0, j=0; j<(int)arec->count; j++) {
	    if (j == (int) index) {
		no = -3;
		continue;
	    }
	    newa[i] = arec->items[j];
	    newa[i]->offset.offset += no;
	    i++;
	}
	no = cr->offset.length;
	cr->layout->cleanup(cr);
	i = -1;
    }

    arec->count += i;

    /* Adjust the arrays that come after me in the record. */
    for (j=0; j<arec->nr_after; j++) {
	mr_array_info_t *ai = arec + j + 1;
	
	ai->offset.offset += no;
	for (i=0; i<(int)ai->count; i++)
	    ai->items[i]->offset.offset += no;
    }

    olda = arec->items;
    arec->items = newa;
    if (arec->layout->has_count)
	ipmi_fru_ovw_multi_record_data(finfo->fru, finfo->mr_rec_num,
				       &arec->count,
				       full_offset(&arec->offset), 1);
    if (olda)
	ipmi_mem_free(olda);

    return 0;
}

static int
mr_node_array_get_subtype(ipmi_fru_node_t           *node,
			  enum ipmi_fru_data_type_e *dtype)
{
    *dtype = IPMI_FRU_DATA_SUB_NODE;
    return 0;
}

static int
mr_node_array_settable(ipmi_fru_node_t *node,
		       unsigned int    index)
{
    return EPERM;
}

static int
mr_node_array_get_field(ipmi_fru_node_t           *node,
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
    mr_array_info_t    *arec = _ipmi_fru_node_get_data(node);
    ipmi_fru_node_t    *rnode = _ipmi_fru_node_get_data2(node);
    mr_fru_info_t      *finfo = _ipmi_fru_node_get_data2(rnode);

    if (index >= arec->count)
	return EINVAL;

    if (name)
	*name = NULL; /* We are an array */
    if (dtype)
	*dtype = IPMI_FRU_DATA_SUB_NODE;
    if (intval)
	*intval = -1; /* Sub element is not an array */
    if (sub_node) {
	node = _ipmi_fru_node_alloc(finfo->fru);
	if (!node)
	    return ENOMEM;

	ipmi_fru_get_node(rnode);
	_ipmi_fru_node_set_data(node, arec->items[index]);
	_ipmi_fru_node_set_data2(node, rnode);
	_ipmi_fru_node_set_get_field(node, mr_node_struct_get_field);
	_ipmi_fru_node_set_set_field(node, mr_node_struct_set_field);
	_ipmi_fru_node_set_settable(node, mr_node_struct_settable);
	_ipmi_fru_node_set_destructor(node, mr_sub_destroy);

	*sub_node = node;
    }
    return 0;
}

static int
mr_array_get_field(mr_array_info_t           *arec,
		   ipmi_fru_node_t           *rnode,
		   enum ipmi_fru_data_type_e *dtype,
		   int                       *intval,
		   time_t                    *time,
		   double                    *floatval,
		   char                      **data,
		   unsigned int              *data_len,
		   ipmi_fru_node_t           **sub_node)
{
    ipmi_fru_node_t *node;
    mr_fru_info_t   *finfo = _ipmi_fru_node_get_data2(rnode);

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
	_ipmi_fru_node_set_get_field(node, mr_node_array_get_field);
	_ipmi_fru_node_set_set_field(node, mr_node_array_set_field);
	_ipmi_fru_node_set_settable(node, mr_node_array_settable);
	_ipmi_fru_node_set_get_subtype(node, mr_node_array_get_subtype);
	_ipmi_fru_node_set_destructor(node, mr_sub_destroy);
	*sub_node = node;
    }
    return 0;
}

static int
mr_node_struct_set_field(ipmi_fru_node_t           *node,
			 unsigned int              index,
			 enum ipmi_fru_data_type_e dtype,
			 int                       intval,
			 time_t                    time,
			 double                    floatval,
			 char                      *data,
			 unsigned int              data_len)
{
    mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    ipmi_fru_node_t    *rnode = _ipmi_fru_node_get_data2(node);
    mr_struct_layout_t *layout = rec->layout;
    mr_fru_info_t      *finfo = _ipmi_fru_node_get_data2(rnode);

    if (index < layout->item_count) {
	if (!layout->items[index].set_field)
	    return EPERM;
	return layout->items[index].set_field(layout->items+index, rec, finfo,
					      dtype, intval, time, floatval,
					      data, data_len);
    }

    index -= layout->item_count;
    if (index < layout->array_count) {
	/* Cannot directly set arrays this way. */
	return EPERM;
    }

    return EINVAL;
}

static int
mr_root_node_struct_set_field(ipmi_fru_node_t           *node,
			      unsigned int              index,
			      enum ipmi_fru_data_type_e dtype,
			      int                       intval,
			      time_t                    time,
			      double                    floatval,
			      char                      *data,
			      unsigned int              data_len)
{
    mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    mr_struct_layout_t *layout = rec->layout;
    mr_fru_info_t      *finfo = _ipmi_fru_node_get_data2(node);

    if (index < layout->item_count) {
	return layout->items[index].set_field(layout->items+index, rec, finfo,
					      dtype, intval, time, floatval,
					      data, data_len);
    }

    index -= layout->item_count;
    if (index < layout->array_count) {
	/* Cannot directly set arrays this way. */
	return EPERM;
    }

    return EINVAL;
}

static int
mr_node_struct_settable(ipmi_fru_node_t *node,
			unsigned int    index)
{
    mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    mr_struct_layout_t *layout = rec->layout;

    if (index < layout->item_count) {
	if (layout->items[index].settable)
	    return 0;
	else
	    return EPERM;
    }

    index -= layout->item_count;
    if (index < layout->array_count) {
	/* All our arrays are settable. */
	return 0;
    }

    return EINVAL;
}

static int
mr_node_struct_get_field(ipmi_fru_node_t           *node,
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
    mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    mr_struct_layout_t *layout = rec->layout;

    if (index < layout->item_count) {
	if (name)
	    *name = layout->items[index].name;
	return layout->items[index].get_field(layout->items+index, rec, dtype,
					      intval, time, floatval,
					      data, data_len);
    }

    index -= layout->item_count;
    if (index < layout->array_count) {
	if (name)
	    *name = layout->arrays[index].name;

	return layout->arrays[index].get_field(rec->arrays+index,
					       _ipmi_fru_node_get_data2(node),
					       dtype, intval, time, floatval,
					       data, data_len, sub_node);
    }

    return EINVAL;
}

static int
mr_root_node_struct_get_field(ipmi_fru_node_t           *node,
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
    mr_struct_info_t   *rec = _ipmi_fru_node_get_data(node);
    mr_struct_layout_t *layout = rec->layout;

    if (index < layout->item_count) {
	if (name)
	    *name = layout->items[index].name;
	return layout->items[index].get_field(layout->items+index, rec, dtype,
					      intval, time, floatval,
					      data, data_len);
    }

    index -= layout->item_count;
    if (index < layout->array_count) {
	if (name)
	    *name = layout->arrays[index].name;

	return layout->arrays[index].get_field(rec->arrays+index, node, dtype,
					       intval, time, floatval,
					       data, data_len, sub_node);
    }

    return EINVAL;
}

static int
mr_struct_elem_check(mr_struct_layout_t *layout,
		     unsigned char      **rmr_data,
		     unsigned int       *rmr_data_len)
{
    unsigned char      *mr_data = *rmr_data;
    unsigned int       mr_data_len = *rmr_data_len;
    int                i, j;
    int                rv;

    if (mr_data_len < layout->length)
	return EINVAL;

    mr_data += layout->length;
    mr_data_len -= layout->length;

    for (i=0; i<(int)layout->array_count; i++) {
	mr_array_layout_t *al = layout->arrays + i;
	unsigned int      count;

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

static int
mr_struct_decode(mr_struct_info_t   *rec,
		 unsigned char      **rmr_data,
		 unsigned int       *rmr_data_len)
{
    unsigned char      *mr_data = *rmr_data;
    unsigned int       mr_data_len = *rmr_data_len;
    int                i, j;
    mr_struct_layout_t *layout = rec->layout;
    int                rv;

    if (mr_data_len < layout->length)
	return EINVAL;

    if (layout->length > 0) {
	rec->data = ipmi_mem_alloc(layout->length);
	if (!rec->data)
	    return ENOMEM;
	memcpy(rec->data, mr_data, layout->length);
	mr_data += layout->length;
	mr_data_len -= layout->length;
    }

    if (layout->array_count > 0) {
	rec->arrays = ipmi_mem_alloc(sizeof(*(rec->arrays))
				     * layout->array_count);
	if (!rec->arrays)
	    return ENOMEM;
	memset(rec->arrays, 0, sizeof(*(rec->arrays)) * layout->array_count);
    }

    for (i=0; i<(int)layout->array_count; i++) {
	mr_array_layout_t *al = layout->arrays + i;
	mr_array_info_t   *ai = rec->arrays + i;
	unsigned int      count;
	unsigned char     *astart_mr_data = mr_data;

	ai->offset.offset = mr_data - *rmr_data;
	ai->offset.parent = &(rec->offset);
	ai->nr_after = layout->array_count - i - 1;
	ai->layout = al;
	if (al->has_count) {
	    if (mr_data_len < 1)
		return EINVAL;
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
		    return rv;
		count++;
	    }
	}
	if (count > 0) {
	    ai->count = count;
	    ai->items = ipmi_mem_alloc(sizeof(*(ai->items)) * count);
	    if (!ai->items)
		return ENOMEM;
	    memset(ai->items, 0, sizeof(*(ai->items)) * count);
	    for (j=0; j<(int)count; j++) {
		ai->items[j] = ipmi_mem_alloc(sizeof(*(ai->items[j])));
		if (!ai->items[j])
		    return ENOMEM;
		memset(ai->items[j], 0, sizeof(*(ai->items[j])));
		ai->items[j]->offset.offset = mr_data - astart_mr_data;
		ai->items[j]->offset.parent = &(ai->offset);
		ai->items[j]->layout = al->elem_layout;
		rv = al->elem_decode(ai->items[j], &mr_data, &mr_data_len);
		if (rv)
		    return rv;
	    }
	}
	ai->offset.length = mr_data - astart_mr_data;
    }

    rec->offset.length = mr_data - *rmr_data;
    *rmr_data = mr_data;
    *rmr_data_len = mr_data_len;

    return 0;
}

static int
mr_root(ipmi_fru_t         *fru,
	unsigned int       mr_rec_num,
	unsigned char      *rmr_data,
	unsigned int       rmr_data_len,
	mr_struct_layout_t *layout,
	const char         **name,
	ipmi_fru_node_t    **rnode)
{
    unsigned char      *mr_data = rmr_data;
    unsigned int       mr_data_len = rmr_data_len;
    mr_struct_info_t   *rec;
    ipmi_fru_node_t    *node;
    mr_fru_info_t      *finfo = NULL;
    int                rv;

    if (mr_data_len == 0)
	return EINVAL;
    
    rec = ipmi_mem_alloc(sizeof(*rec));
    if (!rec)
	return ENOMEM;
    memset(rec, 0, sizeof(*rec));

    finfo = ipmi_mem_alloc(sizeof(*finfo));
    if (!finfo)
	goto out_no_mem;
    ipmi_fru_ref(fru);
    finfo->fru = fru;
    finfo->mr_rec_num = mr_rec_num;

    rec->layout = layout;
    rec->offset.offset = 4;
    rec->offset.parent = NULL;

    rv = mr_struct_decode(rec, &mr_data, &mr_data_len);
    if (rv)
	goto out_cleanup;
    rec->offset.length = mr_data - rmr_data;

    node = _ipmi_fru_node_alloc(fru);
    if (!node)
	goto out_no_mem;

    _ipmi_fru_node_set_data(node, rec);
    _ipmi_fru_node_set_data2(node, finfo);
    _ipmi_fru_node_set_get_field(node, mr_root_node_struct_get_field);
    _ipmi_fru_node_set_set_field(node, mr_root_node_struct_set_field);
    _ipmi_fru_node_set_settable(node, mr_node_struct_settable);
    _ipmi_fru_node_set_destructor(node, mr_struct_root_destroy);

    *rnode = node;

    if (name)
	*name = layout->name;

    return 0;

 out_no_mem:
    rv = ENOMEM;

 out_cleanup:
    if (finfo) {
	ipmi_fru_deref(fru);
	ipmi_mem_free(finfo);
    }
    mr_struct_cleanup(rec);
    return rv;
}


/***********************************************************************
 *
 * Generic field encoders and decoders.
 *
 **********************************************************************/

static int mr_int_set_field(mr_item_layout_t          *layout,
			    mr_struct_info_t          *rec,
			    mr_fru_info_t             *finfo,
			    enum ipmi_fru_data_type_e dtype,
			    int                       intval,
			    time_t                    time,
			    double                    floatval,
			    char                      *data,
			    unsigned int              data_len)
{
    unsigned char *c = rec->data + layout->start;
    unsigned int  val = intval;
    int           i;

    if (dtype != layout->dtype)
	return EINVAL;

    if (dtype == IPMI_FRU_DATA_BOOLEAN)
	val = !!val;

    for (i=0; i<layout->length; i++) {
	*c = val & 0xff;
	val >>= 8;
	c++;
    }
    c = rec->data + layout->start;
    ipmi_fru_ovw_multi_record_data(finfo->fru, finfo->mr_rec_num,
				   c, full_offset(&rec->offset)+layout->start,
				   layout->length);
    return 0;
}

static int mr_int_get_field(mr_item_layout_t          *layout,
			    mr_struct_info_t          *rec,
			    enum ipmi_fru_data_type_e *dtype,
			    int                       *intval,
			    time_t                    *time,
			    double                    *floatval,
			    char                      **data,
			    unsigned int              *data_len)
{
    unsigned char *c = rec->data + layout->start;
    int           val = 0;
    int           shift = 0;
    int           i;

    if (dtype)
	*dtype = layout->dtype;
    if (intval) {
	for (i=0; i<layout->length; i++) {
	    val |= ((int) *c) << shift;
	    c++;
	    shift += 8;
	}
	*intval = val;
    }
    return 0;
}

static int mr_intfloat_set_field(mr_item_layout_t          *layout,
				 mr_struct_info_t          *rec,
				 mr_fru_info_t             *finfo,
				 enum ipmi_fru_data_type_e dtype,
				 int                       intval,
				 time_t                    time,
				 double                    floatval,
				 char                      *data,
				 unsigned int              data_len)
{
    unsigned char *c = rec->data + layout->start;
    unsigned int  val;
    int           i;

    if (dtype != IPMI_FRU_DATA_FLOAT)
	return EINVAL;

    val = (unsigned int) ((floatval / layout->multiplier) + 0.5);

    for (i=0; i<layout->length; i++) {
	*c = val & 0xff;
	val >>= 8;
	c++;
    }
    c = rec->data + layout->start;
    ipmi_fru_ovw_multi_record_data(finfo->fru, finfo->mr_rec_num,
				   c, full_offset(&rec->offset)+layout->start,
				   layout->length);
    return 0;
}

static int mr_intfloat_get_field(mr_item_layout_t          *layout,
				 mr_struct_info_t          *rec,
				 enum ipmi_fru_data_type_e *dtype,
				 int                       *intval,
				 time_t                    *time,
				 double                    *floatval,
				 char                      **data,
				 unsigned int              *data_len)
{
    unsigned char *c = rec->data + layout->start;
    int           val = 0;
    int           shift = 0;
    int           i;

    if (dtype)
	*dtype = IPMI_FRU_DATA_FLOAT;
    if (floatval) {
	for (i=0; i<layout->length; i++) {
	    val |= ((int) *c) << shift;
	    c++;
	    shift += 8;
	}
	*floatval = ((double) val) * layout->multiplier;
    }
    return 0;
}

static int mr_bitint_set_field(mr_item_layout_t          *layout,
			       mr_struct_info_t          *rec,
			       mr_fru_info_t             *finfo,
			       enum ipmi_fru_data_type_e dtype,
			       int                       intval,
			       time_t                    time,
			       double                    floatval,
			       char                      *data,
			       unsigned int              data_len)
{
    unsigned char *c = rec->data + layout->start / 8;
    unsigned char *end = rec->data + (layout->start + layout->length) / 8;
    int           val = intval;
    int           shift = layout->start % 8;
    int           offset = 8 - shift;
    unsigned char mask1 = (~0) << shift;
    unsigned char mask2 = (~0) << ((layout->start + layout->length) % 8);

    if (dtype != layout->dtype)
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

    c = rec->data + layout->start / 8;
    ipmi_fru_ovw_multi_record_data(finfo->fru, finfo->mr_rec_num,
				   c,
				   full_offset(&rec->offset) + (c - rec->data),
				   end - c + 1);
    return 0;
}

static int mr_bitint_get_field(mr_item_layout_t          *layout,
			       mr_struct_info_t          *rec,
			       enum ipmi_fru_data_type_e *dtype,
			       int                       *intval,
			       time_t                    *time,
			       double                    *floatval,
			       char                      **data,
			       unsigned int              *data_len)
{
    unsigned char *c = rec->data + layout->start / 8;
    unsigned char *end = rec->data + (layout->start + layout->length) / 8;
    int           val = 0;
    int           offset = layout->start % 8;
    int           shift = 8 - offset;
    unsigned int  mask = (~0) << layout->length;

    if (dtype)
	*dtype = layout->dtype;

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

static int mr_bitvaltab_set_field(mr_item_layout_t          *layout,
				  mr_struct_info_t          *rec,
				  mr_fru_info_t             *finfo,
				  enum ipmi_fru_data_type_e dtype,
				  int                       intval,
				  time_t                    time,
				  double                    floatval,
				  char                      *data,
				  unsigned int              data_len)
{
    unsigned char *c = rec->data + layout->start / 8;
    unsigned char *end = rec->data + (layout->start + layout->length) / 8;
    int           val;
    int           shift = layout->start % 8;
    int           offset = 8 - shift;
    unsigned char mask1 = (~0) << shift;
    unsigned char mask2 = (~0) << ((layout->start + layout->length) % 8);

    if (dtype != layout->dtype)
	return EINVAL;

    for (val=0; val<(int)layout->tab->count; val++) {
	if (strcasecmp(data, layout->tab->table[val]) == 0)
	    break;
    }
    if (val == (int)layout->tab->count)
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

    c = rec->data + layout->start / 8;
    ipmi_fru_ovw_multi_record_data(finfo->fru, finfo->mr_rec_num,
				   c,
				   full_offset(&rec->offset) + (c - rec->data),
				   end - c + 1);
    return 0;
}

static int mr_bitvaltab_get_field(mr_item_layout_t          *layout,
				  mr_struct_info_t          *rec,
				  enum ipmi_fru_data_type_e *dtype,
				  int                       *intval,
				  time_t                    *time,
				  double                    *floatval,
				  char                      **data,
				  unsigned int              *data_len)
{
    unsigned char *c = rec->data + layout->start / 8;
    unsigned char *end = rec->data + (layout->start + layout->length) / 8;
    int           val = 0;
    int           offset = layout->start % 8;
    int           shift = 8 - offset;
    unsigned int  mask = (~0) << layout->length;
    char          *str;

    if (dtype)
	*dtype = layout->dtype;

    val = *c >> offset;
    while (c != end) {
	c++;
	val |= ((int) *c) << shift;
	shift += 8;
    }
    val &= ~mask;

    if (val >= (int)layout->tab->count)
	str = "?";
    else
	str = layout->tab->table[val];
    if (data_len)
	*data_len = strlen(str);
    if (data) {
	*data = ipmi_strdup(str);
	if (!(*data))
	    return ENOMEM;
    }
    return 0;
}

static int mr_str_set_field(mr_item_layout_t          *layout,
			    mr_struct_info_t          *rec,
			    mr_fru_info_t             *finfo,
			    enum ipmi_fru_data_type_e dtype,
			    int                       intval,
			    time_t                    time,
			    double                    floatval,
			    char                      *data,
			    unsigned int              data_len)
{
    unsigned char        *c = rec->data + layout->start;
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
    memset(c, 0, layout->length);
    len = layout->length;
    ipmi_set_device_string(data, stype, data_len, c, 0, &len);
    ipmi_fru_ovw_multi_record_data(finfo->fru, finfo->mr_rec_num, c,
				   full_offset(&rec->offset)+layout->start,
				   layout->length);
    return 0;
}

static int mr_str_get_field(mr_item_layout_t          *layout,
			    mr_struct_info_t          *rec,
			    enum ipmi_fru_data_type_e *dtype,
			    int                       *intval,
			    time_t                    *time,
			    double                    *floatval,
			    char                      **data,
			    unsigned int              *data_len)
{
    unsigned char        *c = rec->data + layout->start;
    char                 str[64];
    unsigned int         len;
    enum ipmi_str_type_e type;
    int                  rv;

    rv = ipmi_get_device_string(&c, layout->length, str,
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

static int mr_binary_set_field(mr_item_layout_t          *layout,
			       mr_struct_info_t          *rec,
			       mr_fru_info_t             *finfo,
			       enum ipmi_fru_data_type_e dtype,
			       int                       intval,
			       time_t                    time,
			       double                    floatval,
			       char                      *data,
			       unsigned int              data_len)
{
    unsigned char        *c = rec->data + layout->start;

    if (!data)
	return ENOSYS;
    if (dtype != layout->dtype)
	return EINVAL;
    if (data_len > layout->length)
	return EINVAL;

    memcpy(c, data, data_len);
    ipmi_fru_ovw_multi_record_data(finfo->fru, finfo->mr_rec_num, c,
				   full_offset(&rec->offset)+layout->start,
				   data_len);
    return 0;
}

static int mr_binary_get_field(mr_item_layout_t          *layout,
			       mr_struct_info_t          *rec,
			       enum ipmi_fru_data_type_e *dtype,
			       int                       *intval,
			       time_t                    *time,
			       double                    *floatval,
			       char                      **data,
			       unsigned int              *data_len)
{
    unsigned char *c = rec->data + layout->start;

    if (dtype)
	*dtype = IPMI_FRU_DATA_BINARY;
    if (data_len)
	*data_len = layout->length;
    if (data) {
	*data = ipmi_mem_alloc(layout->length);
	if (!(*data))
	    return ENOMEM;
	memcpy(*data, c, layout->length);
    }
    return 0;
}

static int mr_ip_set_field(mr_item_layout_t          *layout,
			   mr_struct_info_t          *rec,
			   mr_fru_info_t             *finfo,
			   enum ipmi_fru_data_type_e dtype,
			   int                       intval,
			   time_t                    time,
			   double                    floatval,
			   char                      *data,
			   unsigned int              data_len)
{
    unsigned char  *c = rec->data + layout->start;
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
    ipmi_fru_ovw_multi_record_data(finfo->fru, finfo->mr_rec_num, c,
				   full_offset(&rec->offset)+layout->start,
				   addr_len);

    return 0;
}

static int mr_ip_get_field(mr_item_layout_t          *layout,
			   mr_struct_info_t          *rec,
			   enum ipmi_fru_data_type_e *dtype,
			   int                       *intval,
			   time_t                    *time,
			   double                    *floatval,
			   char                      **data,
			   unsigned int              *data_len)
{
    unsigned char *c = rec->data + layout->start;
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


/***********************************************************************
 *
 * Point-to-point connectivity record
 *
 **********************************************************************/

static mr_item_layout_t p2p_cr_desc_ent_items[] = {
    { .name = "remote slot", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 8,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field },
    { .name = "remote channel", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 8, .length = 5,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field },
    { .name = "local channel ", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 13, .length = 5,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field }
};
static mr_struct_layout_t p2p_cr_desc_ent = {
    .name = NULL, .length = 3,
    .item_count = 3, .items = p2p_cr_desc_ent_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = mr_struct_cleanup
};
static mr_item_layout_t p2p_cr_desc_items[] = {
    { .name = "channel type", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "slot address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field }
};
static mr_array_layout_t p2p_cr_desc_arys[] = {
    { .name = "channels", .has_count = 1, .min_elem_size = 3,
      .elem_layout = &p2p_cr_desc_ent,
      .elem_check = mr_struct_elem_check, .elem_decode = mr_struct_decode,
      .cleanup = mr_array_cleanup, .get_field = mr_array_get_field }
};
static mr_struct_layout_t p2p_cr_desc = {
    .name = NULL, .length = 2,
    .item_count = 2, .items = p2p_cr_desc_items,
    .array_count = 1, .arrays = p2p_cr_desc_arys,
    .cleanup = mr_struct_cleanup
};
static mr_item_layout_t p2p_cr_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = mr_int_get_field }
};
static mr_array_layout_t p2p_cr_arys[] = {
    { .name = "descriptors", .has_count = 0, .min_elem_size = 3,
      .elem_layout = &p2p_cr_desc,
      .elem_check = mr_struct_elem_check, .elem_decode = mr_struct_decode,
      .cleanup = mr_array_cleanup, .get_field = mr_array_get_field }
};
static mr_struct_layout_t p2p_cr = {
    .name = "Point-to-Point Connectivity Record", .length = 1,
    .item_count = 1, .items = p2p_cr_items,
    .array_count = 1, .arrays = p2p_cr_arys,
    .cleanup = mr_struct_cleanup
};


/***********************************************************************
 *
 * Address table descriptor record
 *
 **********************************************************************/

static mr_item_layout_t addr_tab_ent[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "site_number", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "site_type", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 2, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field }
};
static mr_struct_layout_t addr_tab_ents = {
    .name = NULL, .length = 3,
    .item_count = 3, .items = addr_tab_ent,
    .array_count = 0, .arrays = NULL,
    .cleanup = mr_struct_cleanup
};
static mr_item_layout_t addr_tab_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = mr_int_get_field },
    { .name = "shelf address", .dtype = IPMI_FRU_DATA_ASCII, .settable = 1,
      .start = 1, .length = 21,
      .set_field = mr_str_set_field, .get_field = mr_str_get_field },
};
static mr_array_layout_t addr_tab_arys[] = {
    { .name = "addresses", .has_count = 1, .min_elem_size = 3,
      .elem_layout = &addr_tab_ents,
      .elem_check = mr_struct_elem_check, .elem_decode = mr_struct_decode,
      .cleanup = mr_array_cleanup, .get_field = mr_array_get_field }
};
static mr_struct_layout_t addr_tab = {
    .name = "Address Table", .length = 22,
    .item_count = 2, .items = addr_tab_items,
    .array_count = 1, .arrays = addr_tab_arys,
    .cleanup = mr_struct_cleanup
};


/***********************************************************************
 *
 * Shelf power distribution record
 *
 **********************************************************************/

static mr_item_layout_t pow_dist_f2f_items[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "FRU device id", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field }
};
static mr_struct_layout_t pow_dist_f2f = {
    .name = NULL, .length = 2,
    .item_count = 2, .items = pow_dist_f2f_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = mr_struct_cleanup
};
static mr_item_layout_t pow_dist_maps_items[] = {
    { .name = "max extern avail current", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 0, .length = 2,
      .multiplier = 0.1,
      .set_field = mr_intfloat_set_field, .get_field = mr_intfloat_get_field },
    { .name = "max internal current", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 2, .length = 2,
      .multiplier = 0.1,
      .set_field = mr_intfloat_set_field, .get_field = mr_intfloat_get_field },
    { .name = "min operating voltage", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 2, .length = 2,
      .multiplier = 0.5,
      .set_field = mr_intfloat_set_field, .get_field = mr_intfloat_get_field }
};
static mr_array_layout_t pow_dist_maps_arys[] = {
    { .name = "feed to frus", .has_count = 1, .min_elem_size = 6,
      .elem_layout = &pow_dist_f2f,
      .elem_check = mr_struct_elem_check, .elem_decode = mr_struct_decode,
      .cleanup = mr_array_cleanup, .get_field = mr_array_get_field }
};
static mr_struct_layout_t pow_dist_maps = {
    .name = NULL, .length = 5,
    .item_count = 3, .items = pow_dist_maps_items,
    .array_count = 1, .arrays = pow_dist_maps_arys,
    .cleanup = mr_struct_cleanup
};
static mr_item_layout_t pow_dist_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = mr_int_get_field }
};
static mr_array_layout_t pow_dist_arys[] = {
    { .name = "power feeds", .has_count = 1, .min_elem_size = 3,
      .elem_layout = &pow_dist_maps,
      .elem_check = mr_struct_elem_check, .elem_decode = mr_struct_decode,
      .cleanup = mr_array_cleanup, .get_field = mr_array_get_field }
};
static mr_struct_layout_t pow_dist = {
    .name = "Shelf Power Distribution", .length = 1,
    .item_count = 1, .items = pow_dist_items,
    .array_count = 1, .arrays = pow_dist_arys,
    .cleanup = mr_struct_cleanup
};


/***********************************************************************
 *
 * Shelf activation and power management record
 *
 **********************************************************************/

static mr_item_layout_t act_pm_desc[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "FRU device id", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "max FRU power", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 2, .length = 2,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "shelf manager activation", .dtype = IPMI_FRU_DATA_BOOLEAN,
      .settable = 1,
      .start = 38, .length = 1,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field },
    { .name = "delay before next power on", .dtype = IPMI_FRU_DATA_INT,
      .settable = 1,
      .start = 32, .length = 6,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field }
};
static mr_struct_layout_t act_pm_descs = {
    .name = NULL, .length = 5,
    .item_count = 5, .items = act_pm_desc,
    .array_count = 0, .arrays = NULL,
    .cleanup = mr_struct_cleanup
};
static mr_item_layout_t act_pm_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = mr_int_get_field },
    { .name = "allowance for activation readiness", .dtype = IPMI_FRU_DATA_INT,
      .settable = 1,
      .start = 1, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field }
};
static mr_array_layout_t act_pm_arys[] = {
    { .name = "activation power descriptors", .has_count = 1,
      .min_elem_size = 5,
      .elem_layout = &act_pm_descs,
      .elem_check = mr_struct_elem_check, .elem_decode = mr_struct_decode,
      .cleanup = mr_array_cleanup, .get_field = mr_array_get_field }
};
static mr_struct_layout_t act_pm = {
    .name = "Shelf Activation and Power Management", .length = 2,
    .item_count = 1, .items = act_pm_items,
    .array_count = 1, .arrays = act_pm_arys,
    .cleanup = mr_struct_cleanup
};


/***********************************************************************
 *
 * Shelf manager IP connection record
 *
 **********************************************************************/

static mr_item_layout_t ip_conn0_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = mr_int_get_field },
    { .name = "ip address", .dtype = IPMI_FRU_DATA_ASCII,
      .settable = 1,
      .start = 1, .length = 4,
      .set_field = mr_ip_set_field, .get_field = mr_ip_get_field }
};
static mr_struct_layout_t ip_conn0 = {
    .name = "Shelf Manager IP Connection", .length = 5,
    .item_count = 2, .items = ip_conn0_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = mr_struct_cleanup
};

static mr_item_layout_t ip_conn1_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = mr_int_get_field },
    { .name = "ip address", .dtype = IPMI_FRU_DATA_ASCII,
      .settable = 1,
      .start = 1, .length = 4,
      .set_field = mr_ip_set_field, .get_field = mr_ip_get_field },
    { .name = "gateway address", .dtype = IPMI_FRU_DATA_ASCII,
      .settable = 1,
      .start = 5, .length = 4,
      .set_field = mr_ip_set_field, .get_field = mr_ip_get_field },
    { .name = "subnet mask", .dtype = IPMI_FRU_DATA_ASCII,
      .settable = 1,
      .start = 9, .length = 4,
      .set_field = mr_ip_set_field, .get_field = mr_ip_get_field }
};
static mr_struct_layout_t ip_conn1 = {
    .name = "Shelf Manager IP Connection", .length = 13,
    .item_count = 4, .items = ip_conn1_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = mr_struct_cleanup
};

static int
atca_root_mr_shelf_mgr_ip_conn(ipmi_fru_t          *fru,
			       unsigned int        mr_rec_num,
			       unsigned char       *mr_data,
			       unsigned int        mr_data_len,
			       const char          **name,
			       ipmi_fru_node_t     **node)
{
    mr_struct_layout_t *layout;

    if (mr_data_len < 5)
	return EINVAL;
    switch (mr_data[4]) {
    case 0: layout = &ip_conn0; break;
    case 1: layout = &ip_conn1; break;
    default:
	return EINVAL;
    }
    return mr_root(fru, mr_rec_num, mr_data+4, mr_data_len-4, layout,
		   name, node);
}

/***********************************************************************
 *
 * Board point-to-point Connectivity record
 *
 **********************************************************************/

static mr_item_layout_t guid_elem[] = {
    { .name = "GUID", .dtype = IPMI_FRU_DATA_BINARY, .settable = 1,
      .start = 0, .length = 16,
      .set_field = mr_binary_set_field, .get_field = mr_binary_get_field }
};
static mr_struct_layout_t guid_elems = {
    .name = NULL, .length = 16,
    .item_count = 1, .items = guid_elem,
    .array_count = 0, .arrays = NULL,
    .cleanup = mr_struct_cleanup
};
static mr_tab_item_t link_if_tab = {
    .count = 3,
    .table = { "base", "fabric", "update channel" }
};
static mr_item_layout_t link_desc[] = {
    { .name = "link grouping id", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 24, .length = 8,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field },
    { .name = "link type extension", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 20, .length = 4,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field },
    { .name = "link type", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 12, .length = 8,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field },
    { .name = "port 3 included", .dtype = IPMI_FRU_DATA_BOOLEAN, .settable = 1,
      .start = 11, .length = 1,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field },
    { .name = "port 2 included", .dtype = IPMI_FRU_DATA_BOOLEAN, .settable = 1,
      .start = 10, .length = 1,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field },
    { .name = "port 1 included", .dtype = IPMI_FRU_DATA_BOOLEAN, .settable = 1,
      .start = 9, .length = 1,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field },
    { .name = "port 0 included", .dtype = IPMI_FRU_DATA_BOOLEAN, .settable = 1,
      .start = 8, .length = 1,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field },
    { .name = "interface", .dtype = IPMI_FRU_DATA_ASCII, .settable = 1,
      .start = 6, .length = 2,
      .tab = &link_if_tab,
      .set_field = mr_bitvaltab_set_field,
      .get_field = mr_bitvaltab_get_field },
    { .name = "channel number", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 6,
      .set_field = mr_bitint_set_field, .get_field = mr_bitint_get_field }
};
static mr_struct_layout_t link_descs = {
    .name = NULL, .length = 4,
    .item_count = 9, .items = link_desc,
    .array_count = 0, .arrays = NULL,
    .cleanup = mr_struct_cleanup
};
static mr_item_layout_t bp2p_conn_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = mr_int_get_field }
};
static mr_array_layout_t bp2p_conn_arys[] = {
    { .name = "OEM GUIDs", .has_count = 1,
      .min_elem_size = 16,
      .elem_layout = &guid_elems,
      .elem_check = mr_struct_elem_check, .elem_decode = mr_struct_decode,
      .cleanup = mr_array_cleanup, .get_field = mr_array_get_field },
    { .name = "Link Descriptors", .has_count = 0,
      .min_elem_size = 4,
      .elem_layout = &link_descs,
      .elem_check = mr_struct_elem_check, .elem_decode = mr_struct_decode,
      .cleanup = mr_array_cleanup, .get_field = mr_array_get_field }
};
static mr_struct_layout_t bp2p_conn = {
    .name = "Board P2P Connectivity", .length = 1,
    .item_count = 1, .items = bp2p_conn_items,
    .array_count = 2, .arrays = bp2p_conn_arys,
    .cleanup = mr_struct_cleanup
};


/***********************************************************************
 *
 * Radial IPMB-0 Link Mapping
 *
 **********************************************************************/

static mr_item_layout_t ipmb_link_mapping[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "IPMB-0 link entry", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field }
};
static mr_struct_layout_t ipmb_link_mappings = {
    .name = NULL, .length = 2,
    .item_count = 2, .items = ipmb_link_mapping,
    .array_count = 0, .arrays = NULL,
    .cleanup = mr_struct_cleanup
};
static mr_tab_item_t hub_info_if_tab = {
    .count = 4,
    .table = { "?", "IPMB-A only", "IPMB-B only", "IPMB-A and IPMB-B" }
};
static mr_item_layout_t hub_desc_items[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "bus coverage", .dtype = IPMI_FRU_DATA_ASCII, .settable = 1,
      .start = 8, .length = 2,
      .tab = &hub_info_if_tab,
      .set_field = mr_bitvaltab_set_field,
      .get_field = mr_bitvaltab_get_field }
};
static mr_array_layout_t hub_desc_arys[] = {
    { .name = "IPMB-0 link mappings", .has_count = 1,
      .min_elem_size = 4,
      .elem_layout = &ipmb_link_mappings,
      .elem_check = mr_struct_elem_check, .elem_decode = mr_struct_decode,
      .cleanup = mr_array_cleanup, .get_field = mr_array_get_field }
};
static mr_struct_layout_t hub_descs = {
    .name = NULL, .length = 2,
    .item_count = 2, .items = hub_desc_items,
    .array_count = 1, .arrays = hub_desc_arys,
    .cleanup = mr_struct_cleanup
};
static mr_item_layout_t rad_ipmb_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = mr_int_get_field },
    { .name = "connecter definer", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 3,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "connecter version", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 4, .length = 2,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field }
};
static mr_array_layout_t rad_ipmb_arys[] = {
    { .name = "hub descriptors", .has_count = 1,
      .min_elem_size = 4,
      .elem_layout = &hub_descs,
      .elem_check = mr_struct_elem_check, .elem_decode = mr_struct_decode,
      .cleanup = mr_array_cleanup, .get_field = mr_array_get_field }
};
static mr_struct_layout_t rad_ipmb = {
    .name = "Radial IPMB-0 Link Mapping", .length = 6,
    .item_count = 3, .items = rad_ipmb_items,
    .array_count = 1, .arrays = rad_ipmb_arys,
    .cleanup = mr_struct_cleanup
};

/***********************************************************************
 *
 * Shelf fan geography record
 *
 **********************************************************************/

static mr_item_layout_t fan_to_frus_items[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "FRU device id", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "site number", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 2, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field },
    { .name = "site type", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 3, .length = 1,
      .set_field = mr_int_set_field, .get_field = mr_int_get_field }
};
static mr_struct_layout_t fan_to_frus = {
    .name = NULL, .length = 4,
    .item_count = 4, .items = fan_to_frus_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = mr_struct_cleanup
};
static mr_item_layout_t fan_geog_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = mr_int_get_field }
};
static mr_array_layout_t fan_geog_arys[] = {
    { .name = "fan to frus", .has_count = 1,
      .min_elem_size = 4,
      .elem_layout = &fan_to_frus,
      .elem_check = mr_struct_elem_check, .elem_decode = mr_struct_decode,
      .cleanup = mr_array_cleanup, .get_field = mr_array_get_field }
};
static mr_struct_layout_t fan_geog = {
    .name = "Shelf Fan Geography", .length = 1,
    .item_count = 1, .items = fan_geog_items,
    .array_count = 1, .arrays = fan_geog_arys,
    .cleanup = mr_struct_cleanup
};


/***********************************************************************
 *
 * Initialization code
 *
 **********************************************************************/

int
_ipmi_atca_fru_get_mr_root(ipmi_fru_t          *fru,
			   unsigned int        mr_rec_num,
			   unsigned int        manufacturer_id,
			   unsigned char       record_type_id,
			   unsigned char       *mr_data,
			   unsigned int        mr_data_len,
			   void                *cb_data,
			   const char          **name,
			   ipmi_fru_node_t     **node)
{
    /* A record type and version number. */
    if (mr_data_len < 5)
	return EINVAL;

    switch (mr_data[3]) {
    case 4: /* backplane point-to-point connectivity record */
	if (mr_data[4] != 0)
	    return EINVAL;
	return mr_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
		       &p2p_cr,
		       name, node);

    case 0x10: /* shelf address table */
	if (mr_data[4] != 0)
	    return EINVAL;
	return mr_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
		       &addr_tab,
		       name, node);

    case 0x11: /* Shelf power distribution */
	if (mr_data[4] != 0)
	    return EINVAL;
	return mr_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
		       &pow_dist,
		       name, node);

    case 0x12: /* Shelf activation and power mgmt */
	if (mr_data[4] != 0)
	    return EINVAL;
	return mr_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
		       &act_pm,
		       name, node);

    case 0x13: /* Shelf Manager IP Connection Record */
	return atca_root_mr_shelf_mgr_ip_conn(fru, mr_rec_num,
					      mr_data, mr_data_len,
					      name, node);

    case 0x14: /* Board p2p connectivity record */
	if (mr_data[4] != 0)
	    return EINVAL;
	return mr_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
		       &bp2p_conn,
		       name, node);

    case 0x15: /* radial ipmb0 link mapping */
	if (mr_data[4] != 0)
	    return EINVAL;
	return mr_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
		       &rad_ipmb,
		       name, node);

    case 0x1b: /* Shelf fan geography record */
	if (mr_data[4] != 0)
	    return EINVAL;
	return mr_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
		       &fan_geog,
		       name, node);

    default:
	return ENOSYS;
    }
}
