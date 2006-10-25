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
#include <OpenIPMI/internal/ipmi_fru.h>
#include <OpenIPMI/internal/ipmi_int.h>

/***********************************************************************
 *
 * FRU Multi-record decoding
 *
 **********************************************************************/

static int
convert_int_to_fru_int(const char                *name,
		       int                       val,
		       const char                **rname,
		       enum ipmi_fru_data_type_e *dtype,
		       int                       *intval)
{
    if (rname)
	*rname = name;
    if (dtype)
	*dtype = IPMI_FRU_DATA_INT;
    if (intval)
	*intval = val;
    return 0;
}

static int
convert_int_to_fru_float(const char                *name,
			 int                       val,
			 float                     multiplier,
			 const char                **rname,
			 enum ipmi_fru_data_type_e *dtype,
			 double                    *floatval)
{
    if (rname)
	*rname = name;
    if (dtype)
	*dtype = IPMI_FRU_DATA_FLOAT;
    if (floatval)
	*floatval = ((double) val) * multiplier;
    return 0;
}

static int
convert_str_to_fru_str(const char                *name,
		       enum ipmi_str_type_e      type,
		       unsigned int              len,
		       char                      *raw_data,
		       const char                **rname,
		       enum ipmi_fru_data_type_e *dtype,
		       int                       *intval,
		       char                      **data)
{
    if (rname)
	*rname = name;
    if (dtype) {
	switch (type) {
	case IPMI_ASCII_STR: *dtype = IPMI_FRU_DATA_ASCII; break;
	case IPMI_UNICODE_STR: *dtype = IPMI_FRU_DATA_BINARY; break;
	case IPMI_BINARY_STR: *dtype = IPMI_FRU_DATA_UNICODE; break;
	}
    }
    if (intval)
	*intval = len;
    if (data) {
	if (type == IPMI_ASCII_STR)
	    len += 1;
	else if (len == 0)
	    len = 1;
	*data = ipmi_mem_alloc(len);
	if (!(*data))
	    return ENOMEM;
	if (type == IPMI_ASCII_STR) {
	    memcpy(*data, raw_data, len-1);
	    (*data)[len-1] = '\0';
	} else
	    memcpy(*data, raw_data, len);
    }
    return 0;
}

typedef struct atca_p2p_cr_desc_s
{
    unsigned char channel_type;
    unsigned char slot_address;
    unsigned char channel_count;
    uint32_t      *chans;
} atca_p2p_cr_desc_t;

typedef struct atca_p2p_cr_s
{
    unsigned char      version;
    unsigned int       desc_count;
    atca_p2p_cr_desc_t *descs;
    ipmi_fru_t         *fru;
} atca_p2p_cr_t;

static void atca_p2p_cleanup_rec(atca_p2p_cr_t *rec)
{
    unsigned int i;

    if (rec->descs) {
	for (i=0; i<rec->desc_count; i++) {
	    if (rec->descs[i].chans)
		ipmi_mem_free(rec->descs[i].chans);
	}
	ipmi_mem_free(rec->descs);
    }
    ipmi_mem_free(rec);
}

static void
atca_p2p_root_destroy(ipmi_fru_node_t *node)
{
    atca_p2p_cr_t *rec = _ipmi_fru_node_get_data(node);
    ipmi_fru_deref(rec->fru);
    atca_p2p_cleanup_rec(rec);
}

static void
atca_p2p_sub_destroy(ipmi_fru_node_t *node)
{
    ipmi_fru_node_t *root_node = _ipmi_fru_node_get_data2(node);
    ipmi_fru_put_node(root_node);
}

static int
atca_p2p_desc_entry_get_field(ipmi_fru_node_t           *pnode,
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
    uint32_t rec = *((uint32_t *) _ipmi_fru_node_get_data(pnode));
    int      rv = 0;

    switch(index) {
    case 0:
	rv = convert_int_to_fru_int("remote slot", rec & 0xff,
				    name, dtype, intval);
	break;

    case 1:
	rv = convert_int_to_fru_int("remote channel", (rec >> 8) & 0x1f,
				    name, dtype, intval);
	break;

    case 2:
	rv = convert_int_to_fru_int("local channel", (rec >> 13) & 0x1f,
				    name, dtype, intval);
	break;

    default:
	rv = EINVAL;
    }

    return rv;
}

static int
atca_p2p_desc_entry_array_get_field(ipmi_fru_node_t           *pnode,
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
    atca_p2p_cr_desc_t *rec = _ipmi_fru_node_get_data(pnode);
    ipmi_fru_node_t    *rnode = _ipmi_fru_node_get_data2(pnode);
    atca_p2p_cr_t      *rrec = _ipmi_fru_node_get_data(rnode);
    ipmi_fru_node_t    *node;

    if (index >= rec->channel_count)
	return EINVAL;

    if (name)
	*name = NULL; /* We are an array */
    if (dtype)
	*dtype = IPMI_FRU_DATA_SUB_NODE;
    if (intval)
	*intval = -1; /* Sub element is not an array */
    if (sub_node) {
	node = _ipmi_fru_node_alloc(rrec->fru);
	if (!node)
	    return ENOMEM;

	ipmi_fru_get_node(rnode);
	_ipmi_fru_node_set_data(node, rec->chans + index);
	_ipmi_fru_node_set_data2(node, rnode);
	_ipmi_fru_node_set_get_field(node, atca_p2p_desc_entry_get_field);
	_ipmi_fru_node_set_destructor(node, atca_p2p_sub_destroy);

	*sub_node = node;
    }
    return 0;
}


static int
atca_p2p_desc_get_field(ipmi_fru_node_t           *pnode,
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
    atca_p2p_cr_desc_t *rec = _ipmi_fru_node_get_data(pnode);
    ipmi_fru_node_t    *rnode = _ipmi_fru_node_get_data2(pnode);
    atca_p2p_cr_t      *rrec = _ipmi_fru_node_get_data(rnode);
    ipmi_fru_node_t    *node;
    int                rv = 0;

    switch(index) {
    case 0:
	rv = convert_int_to_fru_int("channel type", rec->channel_type,
				    name, dtype, intval);
	break;

    case 1:
	rv = convert_int_to_fru_int("slot address", rec->slot_address,
				    name, dtype, intval);
	break;

    case 2:
	if (name)
	    *name = "channels";
	if (dtype)
	    *dtype = IPMI_FRU_DATA_SUB_NODE;
	if (intval)
	    *intval = rec->channel_count;
	if (sub_node) {
	    node = _ipmi_fru_node_alloc(rrec->fru);
	    if (!node)
		return ENOMEM;
	    ipmi_fru_get_node(rnode);
	    _ipmi_fru_node_set_data(node, rec);
	    _ipmi_fru_node_set_data2(node, rnode);
	    _ipmi_fru_node_set_get_field(node,
					 atca_p2p_desc_entry_array_get_field);
	    _ipmi_fru_node_set_destructor(node, atca_p2p_sub_destroy);
	    *sub_node = node;
	}
	break;

    default:
	rv = EINVAL;
    }

    return rv;
}

static int
atca_p2p_desc_array_get_field(ipmi_fru_node_t           *pnode,
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
    atca_p2p_cr_t   *rec = _ipmi_fru_node_get_data(pnode);
    ipmi_fru_node_t *rnode = _ipmi_fru_node_get_data2(pnode);
    atca_p2p_cr_t   *rrec = _ipmi_fru_node_get_data(rnode);
    ipmi_fru_node_t *node;

    if (index >= rec->desc_count)
	return EINVAL;

    if (name)
	*name = NULL; /* We are an array */
    if (dtype)
	*dtype = IPMI_FRU_DATA_SUB_NODE;
    if (intval)
	*intval = -1; /* Sub element is not an array */
    if (sub_node) {
	node = _ipmi_fru_node_alloc(rrec->fru);
	if (!node)
	    return ENOMEM;

	ipmi_fru_get_node(rnode);
	_ipmi_fru_node_set_data(node, rec->descs + index);
	_ipmi_fru_node_set_data2(node, rnode);
	_ipmi_fru_node_set_get_field(node, atca_p2p_desc_get_field);
	_ipmi_fru_node_set_destructor(node, atca_p2p_sub_destroy);

	*sub_node = node;
    }
    return 0;
}

static int
atca_p2p_root_get_field(ipmi_fru_node_t           *rnode,
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
    atca_p2p_cr_t   *rec = _ipmi_fru_node_get_data(rnode);
    ipmi_fru_node_t *node;
    int             rv = 0;

    switch(index) {
    case 0:
	rv = convert_int_to_fru_int("version", rec->version,
				    name, dtype, intval);
	break;

    case 1:
	if (name)
	    *name = "descriptors";
	if (dtype)
	    *dtype = IPMI_FRU_DATA_SUB_NODE;
	if (intval)
	    *intval = rec->desc_count;
	if (sub_node) {
	    node = _ipmi_fru_node_alloc(rec->fru);
	    if (!node)
		return ENOMEM;
	    ipmi_fru_get_node(rnode);
	    _ipmi_fru_node_set_data(node, rec);
	    _ipmi_fru_node_set_data2(node, rnode);
	    _ipmi_fru_node_set_get_field(node, atca_p2p_desc_array_get_field);
	    _ipmi_fru_node_set_destructor(node, atca_p2p_sub_destroy);
	    *sub_node = node;
	}
	break;

    default:
	rv = EINVAL;
    }

    return rv;
}

static int
atca_root_mr_p2p_cr(ipmi_fru_t          *fru,
		    unsigned char       *mr_data,
		    unsigned int        mr_data_len,
		    const char          **name,
		    ipmi_fru_node_t     **rnode)
{
    atca_p2p_cr_t      *rec;
    atca_p2p_cr_desc_t *drec;
    unsigned int       left;
    unsigned char      *p;
    int                i, j;
    ipmi_fru_node_t    *node;
    int                rv;

    mr_data += 4;
    mr_data_len -= 4;

    if (mr_data_len == 0)
	return EINVAL;
    
    if (mr_data[0] != 0) /* Only support version 0 */
	return ENOSYS;

    rec = ipmi_mem_alloc(sizeof(*rec));
    if (!rec)
	return ENOMEM;
    memset(rec, 0, sizeof(*rec));

    rec->version = mr_data[0];
    mr_data++;
    mr_data_len--;

    left = mr_data_len;
    p = mr_data;
    while (left > 0) {
	if (left < 3)
	    goto out_invalid;
	left -= 3;
	if ((unsigned int) (p[2] * 3) > left)
	    goto out_invalid;
	left -= p[2] * 3;
	p += 3 + (p[2] * 3);
	(rec->desc_count)++;
    }
    rec->descs = ipmi_mem_alloc(sizeof(atca_p2p_cr_desc_t) * rec->desc_count);
    if (!rec->descs)
	goto out_no_mem;
    memset(rec->descs, 0, sizeof(atca_p2p_cr_desc_t) * rec->desc_count);

    left = mr_data_len;
    p = mr_data;
    i = 0;
    while (left > 0) {
	drec = &(rec->descs[i]);
	drec->channel_type = p[0];
	drec->slot_address = p[1];
	drec->channel_count = p[2];
	drec->chans = ipmi_mem_alloc(sizeof(uint32_t) * p[2]);
	if (!drec->chans)
	    goto out_no_mem;
	p += 3;
	left -= 3;
	for (j=0; j<drec->channel_count; j++) {
	    drec->chans[j] = p[0] | (p[1] << 8) | (p[2] << 16);
	    p += 3;
	    left -= 3;
	}
	i++;
    }

    node = _ipmi_fru_node_alloc(fru);
    if (!node)
      goto out_no_mem;

    rec->fru = fru;
    ipmi_fru_ref(fru);

    _ipmi_fru_node_set_data(node, rec);
    _ipmi_fru_node_set_get_field(node, atca_p2p_root_get_field);
    _ipmi_fru_node_set_destructor(node, atca_p2p_root_destroy);

    *rnode = node;

    if (name)
	*name = "Point-to-Point Connectivity Record";

    return 0;

 out_invalid:
    rv = EINVAL;
    goto out_cleanup;

 out_no_mem:
    rv = ENOMEM;
    goto out_cleanup;

 out_cleanup:
    atca_p2p_cleanup_rec(rec);
    return rv;
}

typedef struct atca_addr_tab_desc_s
{
    unsigned char hw_addr;
    unsigned char site_number;
    unsigned char site_type;
} atca_addr_tab_desc_t;

typedef struct atca_addr_tab_s
{
    unsigned char        version;
    unsigned int         shelf_addr_len;
    enum ipmi_str_type_e shelf_addr_type;
    char                 shelf_addr[64];
    unsigned char        addr_count;
    atca_addr_tab_desc_t *addrs;
    ipmi_fru_t           *fru;
} atca_addr_tab_t;

static void atca_addr_tab_cleanup_rec(atca_addr_tab_t *rec)
{
    if (rec->addrs)
	ipmi_mem_free(rec->addrs);
    ipmi_mem_free(rec);
}

static void
atca_addr_tab_root_destroy(ipmi_fru_node_t *node)
{
    atca_addr_tab_t *rec = _ipmi_fru_node_get_data(node);
    ipmi_fru_deref(rec->fru);
    atca_addr_tab_cleanup_rec(rec);
}

static void
atca_addr_tab_sub_destroy(ipmi_fru_node_t *node)
{
    ipmi_fru_node_t *root_node = _ipmi_fru_node_get_data2(node);
    ipmi_fru_put_node(root_node);
}

static int
atca_addr_tab_desc_get_field(ipmi_fru_node_t           *pnode,
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
    atca_addr_tab_desc_t *rec = _ipmi_fru_node_get_data(pnode);
    int                  rv = 0;

    switch(index) {
    case 0:
	rv = convert_int_to_fru_int("hardware address", rec->hw_addr,
				    name, dtype, intval);
	break;

    case 1:
	rv = convert_int_to_fru_int("site number", rec->site_number,
				    name, dtype, intval);
	break;

    case 2:
	rv = convert_int_to_fru_int("site type", rec->site_type,
				    name, dtype, intval);
	break;

    default:
	rv = EINVAL;
    }

    return rv;
}

static int
atca_addr_tab_desc_array_get_field(ipmi_fru_node_t           *pnode,
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
    atca_addr_tab_t *rec = _ipmi_fru_node_get_data(pnode);
    ipmi_fru_node_t *rnode = _ipmi_fru_node_get_data2(pnode);
    atca_addr_tab_t *rrec = _ipmi_fru_node_get_data(rnode);
    ipmi_fru_node_t *node;

    if (index >= rec->addr_count)
	return EINVAL;

    if (name)
	*name = NULL; /* We are an array */
    if (dtype)
	*dtype = IPMI_FRU_DATA_SUB_NODE;
    if (intval)
	*intval = -1; /* Sub element is not an array */
    if (sub_node) {
	node = _ipmi_fru_node_alloc(rrec->fru);
	if (!node)
	    return ENOMEM;

	ipmi_fru_get_node(rnode);
	_ipmi_fru_node_set_data(node, rec->addrs + index);
	_ipmi_fru_node_set_data2(node, rnode);
	_ipmi_fru_node_set_get_field(node, atca_addr_tab_desc_get_field);
	_ipmi_fru_node_set_destructor(node, atca_addr_tab_sub_destroy);
	*sub_node = node;
    }
    return 0;
}

static int
atca_addr_tab_root_get_field(ipmi_fru_node_t           *rnode,
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
    atca_addr_tab_t *rec = _ipmi_fru_node_get_data(rnode);
    ipmi_fru_node_t *node;
    int             rv = 0;

    switch(index) {
    case 0:
	rv = convert_int_to_fru_int("version", rec->version,
				    name, dtype, intval);
	break;

    case 1:
	rv = convert_str_to_fru_str("shelf address", rec->shelf_addr_type,
				    rec->shelf_addr_len,
				    rec->shelf_addr,
				    name, dtype, intval, data);
	break;

    case 2:
	if (name)
	    *name = "addresses";
	if (dtype)
	    *dtype = IPMI_FRU_DATA_SUB_NODE;
	if (intval)
	    *intval = rec->addr_count;
	if (sub_node) {
	    node = _ipmi_fru_node_alloc(rec->fru);
	    if (!node)
		return ENOMEM;
	    ipmi_fru_get_node(rnode);
	    _ipmi_fru_node_set_data(node, rec);
	    _ipmi_fru_node_set_data2(node, rnode);
	    _ipmi_fru_node_set_get_field(node,
					 atca_addr_tab_desc_array_get_field);
	    _ipmi_fru_node_set_destructor(node, atca_addr_tab_sub_destroy);
	    *sub_node = node;
	}
	break;

    default:
	rv = EINVAL;
    }

    return rv;
}

static int
atca_root_mr_addr_tab(ipmi_fru_t          *fru,
		      unsigned char       *mr_data,
		      unsigned int        mr_data_len,
		      const char          **name,
		      ipmi_fru_node_t     **rnode)
{
    atca_addr_tab_t      *rec;
    unsigned char        *p;
    int                  i;
    ipmi_fru_node_t      *node;
    int                  rv;

    mr_data += 4;
    mr_data_len -= 4;

    /* Room for the version, shelf address, and address table entry count */
    if (mr_data_len < 23)
	return EINVAL;
    
    if (mr_data[0] != 0) /* Only support version 0 */
	return ENOSYS;

    rec = ipmi_mem_alloc(sizeof(*rec));
    if (!rec)
	return ENOMEM;
    memset(rec, 0, sizeof(*rec));

    rec->version = mr_data[0];
    mr_data++;
    mr_data_len--;

    p = mr_data;
    rv = ipmi_get_device_string(&p, mr_data_len,
				rec->shelf_addr,
				IPMI_STR_FRU_SEMANTICS, 0,
				&rec->shelf_addr_type,
				sizeof(rec->shelf_addr),
				&rec->shelf_addr_len);
    if (rv)
	return rv;
    if ((p - mr_data) > 21)
	return EINVAL;
    mr_data += 21;
    mr_data_len -= 21;

    rec->addr_count = mr_data[0];
    mr_data++;
    mr_data_len--;

    if ((unsigned int) (rec->addr_count * 3) > mr_data_len)
	goto out_invalid;

    rec->addrs = ipmi_mem_alloc(sizeof(*(rec->addrs)) * rec->addr_count);
    if (!rec->addrs)
	goto out_no_mem;

    for (i=0; i<rec->addr_count; i++) {
	rec->addrs[i].hw_addr = mr_data[0];
	rec->addrs[i].site_number = mr_data[1];
	rec->addrs[i].site_type = mr_data[2];
	mr_data += 3;
	mr_data_len -= 3;
    }

    node = _ipmi_fru_node_alloc(fru);
    if (!node)
	goto out_no_mem;

    rec->fru = fru;
    ipmi_fru_ref(fru);

    _ipmi_fru_node_set_data(node, rec);
    _ipmi_fru_node_set_get_field(node, atca_addr_tab_root_get_field);
    _ipmi_fru_node_set_destructor(node, atca_addr_tab_root_destroy);
    *rnode = node;

    if (name)
	*name = "Address Table";

    return 0;

 out_invalid:
    rv = EINVAL;
    goto out_cleanup;

 out_no_mem:
    rv = ENOMEM;
    goto out_cleanup;

 out_cleanup:
    atca_addr_tab_cleanup_rec(rec);
    return rv;
}

typedef struct atca_feed_to_frus
{
    uint8_t hw_address;
    uint8_t fru_device_id;
} atca_feed_to_fru_t;

typedef struct atca_power_dist_map_s
{
    uint16_t           max_extern_avail_current;
    uint16_t           max_internal_current;
    uint16_t           min_operating_voltage;
    uint16_t           feed_to_fru_count;
    atca_feed_to_fru_t *feed_to_frus;
} atca_power_dist_map_t;

typedef struct atca_shelf_power_dist_s
{
    unsigned char         version;
    unsigned int          nr_power_feeds;
    atca_power_dist_map_t *power_feeds;
    ipmi_fru_t            *fru;
} atca_shelf_power_dist_t;

static void
atca_shelf_power_dist_cleanup_rec(atca_shelf_power_dist_t *rec)
{
    unsigned int i;

    if (!rec)
	return;

    if (rec->power_feeds) {
	for (i=0; i<rec->nr_power_feeds; i++) {
	    atca_power_dist_map_t *f = &(rec->power_feeds[i]);

	    if (f->feed_to_frus)
		ipmi_mem_free(f->feed_to_frus);
	}
	ipmi_mem_free(rec->power_feeds);
    }

    ipmi_mem_free(rec);
}

static void
atca_shelf_power_dist_root_destroy(ipmi_fru_node_t *node)
{
    atca_shelf_power_dist_t *rec = _ipmi_fru_node_get_data(node);
    ipmi_fru_deref(rec->fru);
    atca_shelf_power_dist_cleanup_rec(rec);
}

static void
atca_shelf_power_dist_sub_destroy(ipmi_fru_node_t *node)
{
    ipmi_fru_node_t *root_node = _ipmi_fru_node_get_data2(node);
    ipmi_fru_put_node(root_node);
}

static int
atca_feed_to_fru_get_field(ipmi_fru_node_t           *rnode,
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
    atca_feed_to_fru_t *rec = _ipmi_fru_node_get_data(rnode);
    int                rv = 0;

    switch(index) {
    case 0:
	rv = convert_int_to_fru_int("hardware_address", rec->hw_address,
				    name, dtype, intval);
	break;

    case 1:
	rv = convert_int_to_fru_int("fru_device_id", rec->fru_device_id,
				    name, dtype, intval);
	break;

    default:
	rv = EINVAL;
    }

    return rv;
}

static int
atca_feed_to_fru_array_get_field(ipmi_fru_node_t           *pnode,
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
    atca_power_dist_map_t   *rec = _ipmi_fru_node_get_data(pnode);
    ipmi_fru_node_t         *rnode = _ipmi_fru_node_get_data2(pnode);
    atca_shelf_power_dist_t *rrec = _ipmi_fru_node_get_data(rnode);
    ipmi_fru_node_t         *node;

    if (index >= rec->feed_to_fru_count)
	return EINVAL;

    if (name)
	*name = NULL; /* We are an array */
    if (dtype)
	*dtype = IPMI_FRU_DATA_SUB_NODE;
    if (intval)
	*intval = -1; /* Sub element is not an array */
    if (sub_node) {
	node = _ipmi_fru_node_alloc(rrec->fru);
	if (!node)
	    return ENOMEM;

	ipmi_fru_get_node(rnode);
	_ipmi_fru_node_set_data(node, rec->feed_to_frus + index);
	_ipmi_fru_node_set_data2(node, rnode);
	_ipmi_fru_node_set_get_field(node, atca_feed_to_fru_get_field);
	_ipmi_fru_node_set_destructor(node, atca_shelf_power_dist_sub_destroy);
	*sub_node = node;
    }
    return 0;
}

static int
atca_power_feed_get_field(ipmi_fru_node_t           *pnode,
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
    atca_power_dist_map_t   *rec = _ipmi_fru_node_get_data(pnode);
    ipmi_fru_node_t         *rnode = _ipmi_fru_node_get_data2(pnode);
    atca_shelf_power_dist_t *rrec = _ipmi_fru_node_get_data(rnode);
    ipmi_fru_node_t         *node;
    int                     rv = 0;

    switch(index) {
    case 0:
	rv = convert_int_to_fru_float("max_extern_avail_current",
				      rec->max_extern_avail_current, 0.1,
				      name, dtype, floatval);
	break;

    case 1:
	rv = convert_int_to_fru_float("max_internal_current",
				      rec->max_internal_current, 0.1,
				      name, dtype, floatval);
	break;

    case 2:
	rv = convert_int_to_fru_float("min_operating_voltage",
				      rec->min_operating_voltage, 0.5,
				      name, dtype, floatval);
	break;

    case 3:
	if (name)
	    *name = "feed_to_frus";
	if (dtype)
	    *dtype = IPMI_FRU_DATA_SUB_NODE;
	if (intval)
	    *intval = rec->feed_to_fru_count;
	if (sub_node) {
	    node = _ipmi_fru_node_alloc(rrec->fru);
	    if (!node)
		return ENOMEM;
	    ipmi_fru_get_node(rnode);
	    _ipmi_fru_node_set_data(node, rec);
	    _ipmi_fru_node_set_data2(node, rnode);
	    _ipmi_fru_node_set_get_field(node,
					 atca_feed_to_fru_array_get_field);
	    _ipmi_fru_node_set_destructor(node,
					  atca_shelf_power_dist_sub_destroy);
	    *sub_node = node;
	}
	break;

    default:
	rv = EINVAL;
    }

    return rv;
}

static int
atca_power_feed_array_get_field(ipmi_fru_node_t           *pnode,
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
    atca_shelf_power_dist_t *rec = _ipmi_fru_node_get_data(pnode);
    ipmi_fru_node_t         *rnode = _ipmi_fru_node_get_data2(pnode);
    atca_shelf_power_dist_t *rrec = _ipmi_fru_node_get_data(rnode);
    ipmi_fru_node_t         *node;

    if (index >= rec->nr_power_feeds)
	return EINVAL;

    if (name)
	*name = NULL; /* We are an array */
    if (dtype)
	*dtype = IPMI_FRU_DATA_SUB_NODE;
    if (intval)
	*intval = -1; /* Sub element is not an array */
    if (sub_node) {
	node = _ipmi_fru_node_alloc(rrec->fru);
	if (!node)
	    return ENOMEM;

	ipmi_fru_get_node(rnode);
	_ipmi_fru_node_set_data(node, rec->power_feeds + index);
	_ipmi_fru_node_set_data2(node, rnode);
	_ipmi_fru_node_set_get_field(node, atca_power_feed_get_field);
	_ipmi_fru_node_set_destructor(node, atca_shelf_power_dist_sub_destroy);
	*sub_node = node;
    }
    return 0;
}

static int
atca_shelf_power_dist_root_get_field(ipmi_fru_node_t           *rnode,
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
    atca_shelf_power_dist_t *rec = _ipmi_fru_node_get_data(rnode);
    ipmi_fru_node_t         *node;
    int                     rv = 0;

    switch(index) {
    case 0:
	rv = convert_int_to_fru_int("version", rec->version,
				    name, dtype, intval);
	break;

    case 1:
	if (name)
	    *name = "power_feeds";
	if (dtype)
	    *dtype = IPMI_FRU_DATA_SUB_NODE;
	if (intval)
	    *intval = rec->nr_power_feeds;
	if (sub_node) {
	    node = _ipmi_fru_node_alloc(rec->fru);
	    if (!node)
		return ENOMEM;
	    ipmi_fru_get_node(rnode);
	    _ipmi_fru_node_set_data(node, rec);
	    _ipmi_fru_node_set_data2(node, rnode);
	    _ipmi_fru_node_set_get_field(node,
					 atca_power_feed_array_get_field);
	    _ipmi_fru_node_set_destructor(node,
					  atca_shelf_power_dist_sub_destroy);
	    *sub_node = node;
	}
	break;

    default:
	rv = EINVAL;
    }

    return rv;
}

static int
atca_root_mr_shelf_power_dist(ipmi_fru_t          *fru,
			      unsigned char       *mr_data,
			      unsigned int        mr_data_len,
			      const char          **name,
			      ipmi_fru_node_t     **rnode)
{
    atca_shelf_power_dist_t *rec;
    unsigned int            i, j;
    ipmi_fru_node_t         *node;
    int                     rv;

    mr_data += 4;
    mr_data_len -= 4;

    if (mr_data_len < 11)
	return EINVAL;
    
    if (mr_data[0] != 0) /* Only support version 0 */
	return ENOSYS;

    rec = ipmi_mem_alloc(sizeof(*rec));
    if (!rec)
	return ENOMEM;
    memset(rec, 0, sizeof(*rec));

    rec->version = mr_data[0];
    mr_data++;
    mr_data_len--;

    rec->nr_power_feeds = mr_data[0];
    mr_data++;
    mr_data_len--;

    rec->power_feeds = ipmi_mem_alloc(rec->nr_power_feeds
				      * sizeof(atca_shelf_power_dist_t));
    if (!rec->power_feeds) {
	rv = ENOMEM;
	goto out_cleanup;
    }

    for (i=0; i<rec->nr_power_feeds; i++) {
	atca_power_dist_map_t *f;

	if (mr_data_len < 6) {
	    rv = EINVAL;
	    goto out_cleanup;
	}

	f = &(rec->power_feeds[i]);
	f->max_extern_avail_current = ipmi_get_uint16(mr_data);
	f->max_internal_current = ipmi_get_uint16(mr_data+2);
	f->min_operating_voltage = mr_data[4];
	f->feed_to_fru_count = mr_data[5];
	mr_data += 6;
	mr_data_len -= 6;

	if (mr_data_len < (unsigned int) (2 * f->feed_to_fru_count)) {
	    rv = EINVAL;
	    goto out_cleanup;
	}
	f->feed_to_frus = ipmi_mem_alloc(f->feed_to_fru_count
					 * sizeof(atca_feed_to_fru_t));
	if (!f->feed_to_frus) {
	    rv = ENOMEM;
	    goto out_cleanup;
	}
	for (j=0; j<f->feed_to_fru_count; j++) {
	    f->feed_to_frus[j].hw_address = mr_data[0];
	    f->feed_to_frus[j].fru_device_id = mr_data[1];
	    mr_data += 2;
	    mr_data_len -= 2;
	}
    }

    node = _ipmi_fru_node_alloc(fru);
    if (!node)
	goto out_no_mem;

    rec->fru = fru;
    ipmi_fru_ref(fru);

    _ipmi_fru_node_set_data(node, rec);
    _ipmi_fru_node_set_get_field(node, atca_shelf_power_dist_root_get_field);
    _ipmi_fru_node_set_destructor(node, atca_shelf_power_dist_root_destroy);
    *rnode = node;

    if (name)
	*name = "Shelf Power Distribution";

    return 0;

 out_no_mem:
    rv = ENOMEM;
    goto out_cleanup;

 out_cleanup:
    atca_shelf_power_dist_cleanup_rec(rec);
    return rv;
}

int
_ipmi_atca_fru_get_mr_root(ipmi_fru_t          *fru,
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
	return atca_root_mr_p2p_cr(fru, mr_data, mr_data_len, name, node);

    case 0x10: /* shelf address table */
	return atca_root_mr_addr_tab(fru, mr_data, mr_data_len, name, node);

    case 0x11: /* Shelf power distribution */
	return atca_root_mr_shelf_power_dist(fru, mr_data, mr_data_len,
					     name, node);

    case 0x12: /* Shelf activation and power mgmt */
    case 0x13: /* Shelf Manager IP Connection Record */
    case 0x14: /* Board ptp connectivity record */
    case 0x15: /* radial ipmb0 link mapping */
    case 0x1b: /* Shelf fan geography record */
    default:
	return ENOSYS;
    }
}
