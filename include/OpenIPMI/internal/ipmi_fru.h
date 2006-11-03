/*
 * ipmi_fru.h
 *
 * internal IPMI interface for FRUs
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2003 MontaVista Software Inc.
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

#ifndef _IPMI_FRU_INTERNAL_H
#define _IPMI_FRU_INTERNAL_H

#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/os_handler.h>

os_handler_t *_ipmi_fru_get_os_handler(ipmi_fru_t *fru);

/* The callbacks for FRU multi-record OEM handler, to decode the multi-record 
   and get individual field.
   ipmi_fru_multi_record_oem_decoder_cb(): record is the raw binary multi-record
      record_len is the length of this raw binary multi-record,
      the doceded OEM FRU information is outputted and stored in *explain_data_p.
   ipmi_fru_get_multi_record_oem_field_handler_cb(): this callback is called
      when user call ipmi_fru_multi_record_get_field(). Please refer to the 
      comments for ipmi_fru_multi_record_get_field().
   ipmi_fru_multi_record_free_explain_data_cb(): this callback is used to free
   the OEM FRU specific data structures.

*/

/* Free the data in the node. */
typedef void (*ipmi_fru_oem_node_cb)(ipmi_fru_node_t *node);

typedef int (*ipmi_fru_oem_node_get_field_cb)
     (ipmi_fru_node_t           *node,
      unsigned int              index,
      const char                **name,
      enum ipmi_fru_data_type_e *dtype,
      int                       *intval,
      time_t                    *time,
      double                    *floatval,
      char                      **data,
      unsigned int              *data_len,
      ipmi_fru_node_t           **sub_node);

typedef int (*ipmi_fru_oem_node_set_field_cb)
     (ipmi_fru_node_t           *node,
      unsigned int              index,
      enum ipmi_fru_data_type_e dtype,
      int                       intval,
      time_t                    time,
      double                    floatval,
      char                      *data,
      unsigned int              data_len);

typedef int (*ipmi_fru_oem_node_settable_cb)
     (ipmi_fru_node_t           *node,
      unsigned int              index);

typedef int (*ipmi_fru_oem_node_subtype_cb)
     (ipmi_fru_node_t           *node,
      enum ipmi_fru_data_type_e *dtype);

ipmi_fru_node_t *_ipmi_fru_node_alloc(ipmi_fru_t *fru);

void *_ipmi_fru_node_get_data(ipmi_fru_node_t *node);
void _ipmi_fru_node_set_data(ipmi_fru_node_t *node, void *data);
void *_ipmi_fru_node_get_data2(ipmi_fru_node_t *node);
void _ipmi_fru_node_set_data2(ipmi_fru_node_t *node, void *data2);

void _ipmi_fru_node_set_destructor(ipmi_fru_node_t      *node,
				   ipmi_fru_oem_node_cb destroy);
void _ipmi_fru_node_set_get_field(ipmi_fru_node_t                *node,
				  ipmi_fru_oem_node_get_field_cb get_field);
void _ipmi_fru_node_set_set_field(ipmi_fru_node_t                *node,
				  ipmi_fru_oem_node_set_field_cb set_field);
void _ipmi_fru_node_set_settable(ipmi_fru_node_t               *node,
				 ipmi_fru_oem_node_settable_cb settable);
void _ipmi_fru_node_set_get_subtype(ipmi_fru_node_t              *node,
				    ipmi_fru_oem_node_subtype_cb get_subtype);

/* Get the root node of a multi-record.  Note that the root record
   must not be an array.  Note that you cannot keep a copy of the fru
   pointer around after this call returns; it will be unlocked and
   could go away after this returns. */
typedef int (*ipmi_fru_oem_multi_record_get_root_node_cb)
     (ipmi_fru_t          *fru,
      unsigned int        mr_rec_num,
      unsigned int        manufacturer_id,
      unsigned char       record_type_id,
      unsigned char       *mr_data,
      unsigned int        mr_data_len,
      void                *cb_data,
      const char          **name,
      ipmi_fru_node_t     **node);

/* Register/deregister a multi-record handler.  Note that if the
   record type id is < 0xc0 (not OEM) then the manufacturer id does
   not matter. */
int _ipmi_fru_register_multi_record_oem_handler
(unsigned int                               manufacturer_id,
 unsigned char                              record_type_id,
 ipmi_fru_oem_multi_record_get_root_node_cb get_root,
 void                                       *cb_data);

int _ipmi_fru_deregister_multi_record_oem_handler
(unsigned int  manufacturer_id,
 unsigned char record_type_id);

void _ipmi_fru_lock(ipmi_fru_t *fru);
void _ipmi_fru_unlock(ipmi_fru_t *fru);

/*
 * Some specialized FRU data repositories have protection against
 * multiple readers/writers to keep them from colliding.  The model
 * here is similar to the other parts of IPMI.  You have a timestamp
 * that tells the last time the repository changed.  On reading, the
 * code will check the timestamp before and after to make sure the
 * data hasn't changed while being written.  There is a lock for
 * writers.  The code will lock (prepare to write), check the
 * timestamp to make sure another writer has not modified, then write,
 * then unlock and commit (write complete).  Note that you can have
 * the reader timestamp without the lock, or the lock without the
 * timestamp.
 *
 * You can also override the function that sends the write message.
 * this function will get the data as formatted for a normal FRU
 * write.
 */
typedef void (*_ipmi_fru_timestamp_cb)(ipmi_fru_t    *fru,
				       ipmi_domain_t *domain,
				       int           err,
				       uint32_t      timestamp);
typedef void (*_ipmi_fru_op_cb)(ipmi_fru_t    *fru,
				ipmi_domain_t *domain,
				int           err);

typedef int (*_ipmi_fru_get_timestamp_cb)(ipmi_fru_t             *fru,
					  ipmi_domain_t          *domain,
					  _ipmi_fru_timestamp_cb handler);
typedef int (*_ipmi_fru_prepare_write_cb)(ipmi_fru_t      *fru,
					  ipmi_domain_t   *domain,
					  uint32_t        timestamp,
					  _ipmi_fru_op_cb done);
typedef int (*_ipmi_fru_write_cb)(ipmi_fru_t      *fru,
				  ipmi_domain_t   *domain,
				  unsigned char   *data,
				  unsigned int    data_len,
				  _ipmi_fru_op_cb done);
typedef int (*_ipmi_fru_complete_write_cb)(ipmi_fru_t      *fru,
					   ipmi_domain_t   *domain,
					   int             abort,
					   uint32_t        timestamp,
					   _ipmi_fru_op_cb done);

int _ipmi_fru_set_get_timestamp_handler(ipmi_fru_t                 *fru,
					_ipmi_fru_get_timestamp_cb handler);
int _ipmi_fru_set_prepare_write_handler(ipmi_fru_t                 *fru,
					_ipmi_fru_prepare_write_cb handler);
int _ipmi_fru_set_write_handler(ipmi_fru_t         *fru,
				_ipmi_fru_write_cb handler);
int _ipmi_fru_set_complete_write_handler(ipmi_fru_t                  *fru,
					 _ipmi_fru_complete_write_cb handler);

typedef void (*_ipmi_fru_setup_data_clean_cb)(ipmi_fru_t *fru, void *data);
void _ipmi_fru_set_setup_data(ipmi_fru_t                    *fru,
			      void                          *data,
			      _ipmi_fru_setup_data_clean_cb cleanup);
void *_ipmi_fru_get_setup_data(ipmi_fru_t *fru);

void _ipmi_fru_get_addr(ipmi_fru_t   *fru,
			ipmi_addr_t  *addr,
			unsigned int *addr_len);


/* Add a record telling that a specific area of the FRU data needs to
   be written.  Called from the write handler. */
int _ipmi_fru_new_update_record(ipmi_fru_t   *fru,
				unsigned int offset,
				unsigned int length);

/* Get/set the fru-type secific data.  Note that the cleanup_recs
   function will be called on any rec_data.  The right way to set this
   data is to set the rec data then set your ops. */
void *_ipmi_fru_get_rec_data(ipmi_fru_t *fru);
void _ipmi_fru_set_rec_data(ipmi_fru_t *fru, void *rec_data);

/* Get a pointer to the fru data and the length.  Only valid during
   decoding and writing. */
void *_ipmi_fru_get_data_ptr(ipmi_fru_t *fru);
unsigned int _ipmi_fru_get_data_len(ipmi_fru_t *fru);

/* Get a debug name for the FRU */ 
char *_ipmi_fru_get_iname(ipmi_fru_t *fru);

/* Misc data about the FRU. */
unsigned int _ipmi_fru_get_fetch_mask(ipmi_fru_t *fru);
int _ipmi_fru_is_normal_fru(ipmi_fru_t *fru);
void _ipmi_fru_set_is_normal_fru(ipmi_fru_t *fru, int val);

/*
 * Interface between the generic FRU code and the specific FRU
 * decoders.
 */

typedef void (*ipmi_fru_void_op)(ipmi_fru_t *fru);
typedef int (*ipmi_fru_err_op)(ipmi_fru_t *fru);
typedef int (*ipmi_fru_get_root_node_op)(ipmi_fru_t      *fru,
					 const char      **name,
					 ipmi_fru_node_t **rnode);

/* Add a function to cleanup the FRU record data (free all the memory)
   as the FRU is destroyed. */
void _ipmi_fru_set_op_cleanup_recs(ipmi_fru_t *fru, ipmi_fru_void_op op);

/* Called when a write operations completes successfully, to clear out
   all the write information. */
void _ipmi_fru_set_op_write_complete(ipmi_fru_t *fru, ipmi_fru_void_op op);

/* Called to copy all the changed data into the FRU block of data and
   add update records for the changed data. */
void _ipmi_fru_set_op_write(ipmi_fru_t *fru, ipmi_fru_err_op op);

/* Get the root node for the user to decode. */
void _ipmi_fru_set_op_get_root_node(ipmi_fru_t                *fru,
				    ipmi_fru_get_root_node_op op);

/* Register a decoder for FRU data.  The provided function should
   return success if the FRU is supported and can be decoded properly,
   ENOSYS if the FRU information doesn't match the format, or anything
   else for invalid FRU data.  It should register the nodes  */
int _ipmi_fru_register_decoder(ipmi_fru_err_op op);
int _ipmi_fru_deregister_decoder(ipmi_fru_err_op op);

/* Table-driven multirecord FRU handling. */
typedef struct ipmi_mr_struct_layout_s ipmi_mr_struct_layout_t;
typedef struct ipmi_mr_struct_info_s ipmi_mr_struct_info_t;
typedef struct ipmi_mr_item_layout_s ipmi_mr_item_layout_t;
typedef struct ipmi_mr_array_layout_s ipmi_mr_array_layout_t;
typedef struct ipmi_mr_array_info_s ipmi_mr_array_info_t;
typedef struct ipmi_mr_offset_s ipmi_mr_offset_t;

struct ipmi_mr_offset_s {
    uint8_t          offset;
    uint8_t          length;
    ipmi_mr_offset_t *parent;
};

typedef struct ipmi_mr_fru_info_s {
    ipmi_fru_t   *fru;
    unsigned int mr_rec_num;
} ipmi_mr_fru_info_t;

struct ipmi_mr_array_info_s {
    uint8_t                count;
    uint8_t                nr_after; /* Number of arrays after me. */
    ipmi_mr_offset_t       offset;
    ipmi_mr_array_layout_t *layout;
    ipmi_mr_struct_info_t  **items;
};

struct ipmi_mr_struct_info_s
{
    uint8_t                 len;
    ipmi_mr_offset_t        offset;
    ipmi_mr_struct_layout_t *layout;
    unsigned char           *data;
    ipmi_mr_array_info_t    *arrays;
};

typedef struct ipmi_mr_tab_item_s {
    unsigned int count;
    char         *table[];
} ipmi_mr_tab_item_t;

typedef struct ipmi_mr_floattab_item_s {
    unsigned int count;
    double       defval;
    struct {
	float low;
	float nominal;
	float high;
    } table[];
} ipmi_mr_floattab_item_t;

struct ipmi_mr_item_layout_s
{
    char                      *name;
    enum ipmi_fru_data_type_e dtype;

    uint8_t settable;

    uint16_t start;
    uint16_t length;

    float multiplier;
    void *tab_data;

    int (*set_field)(ipmi_mr_item_layout_t     *layout,
		     ipmi_mr_struct_info_t     *rec,
		     ipmi_mr_fru_info_t        *finfo,
		     enum ipmi_fru_data_type_e dtype,
		     int                       intval,
		     time_t                    time,
		     double                    floatval,
		     char                      *data,
		     unsigned int              data_len);
    int (*get_field)(ipmi_mr_item_layout_t     *layout,
		     ipmi_mr_struct_info_t     *rec,
		     enum ipmi_fru_data_type_e *dtype,
		     int                       *intval,
		     time_t                    *time,
		     double                    *floatval,
		     char                      **data,
		     unsigned int              *data_len);
};

struct ipmi_mr_array_layout_s
{
    char    *name;
    uint8_t has_count;
    uint8_t min_elem_size;
    ipmi_mr_struct_layout_t *elem_layout;
    int (*elem_check)(ipmi_mr_struct_layout_t *layout,
		      unsigned char **mr_data,
		      unsigned int  *mr_data_len);
    int (*elem_decode)(ipmi_mr_struct_info_t   *rec,
		       unsigned char      **mr_data,
		       unsigned int       *mr_data_len);
    void (*cleanup)(ipmi_mr_array_info_t *arec);
    int (*get_field)(ipmi_mr_array_info_t      *arec,
		     ipmi_fru_node_t           *rnode,
		     enum ipmi_fru_data_type_e *dtype,
		     int                       *intval,
		     time_t                    *time,
		     double                    *floatval,
		     char                      **data,
		     unsigned int              *data_len,
		     ipmi_fru_node_t           **sub_node);
};

struct ipmi_mr_struct_layout_s
{
    char                   *name;
    uint8_t                length; /* Excluding arrays. */
    unsigned int           item_count;
    ipmi_mr_item_layout_t  *items;
    unsigned int           array_count;
    ipmi_mr_array_layout_t *arrays;

    void (*cleanup)(ipmi_mr_struct_info_t *rec);
};

uint8_t ipmi_mr_full_offset(ipmi_mr_offset_t *o);
void ipmi_mr_adjust_len(ipmi_mr_offset_t *o, int len);

void ipmi_mr_array_cleanup(ipmi_mr_array_info_t *arec);
void ipmi_mr_struct_cleanup(ipmi_mr_struct_info_t *rec);
void ipmi_mr_struct_root_destroy(ipmi_fru_node_t *node);
void ipmi_mr_sub_destroy(ipmi_fru_node_t *node);
int ipmi_mr_node_array_set_field(ipmi_fru_node_t           *node,
				 unsigned int              index,
				 enum ipmi_fru_data_type_e dtype,
				 int                       intval,
				 time_t                    time,
				 double                    floatval,
				 char                      *data,
				 unsigned int              data_len);
int ipmi_mr_node_array_get_subtype(ipmi_fru_node_t           *node,
				   enum ipmi_fru_data_type_e *dtype);
int ipmi_mr_node_array_settable(ipmi_fru_node_t *node,
				unsigned int    index);
int ipmi_mr_node_array_get_field(ipmi_fru_node_t           *node,
				 unsigned int              index,
				 const char                **name,
				 enum ipmi_fru_data_type_e *dtype,
				 int                       *intval,
				 time_t                    *time,
				 double                    *floatval,
				 char                      **data,
				 unsigned int              *data_len,
				 ipmi_fru_node_t           **sub_node);
int ipmi_mr_array_get_field(ipmi_mr_array_info_t      *arec,
			    ipmi_fru_node_t           *rnode,
			    enum ipmi_fru_data_type_e *dtype,
			    int                       *intval,
			    time_t                    *time,
			    double                    *floatval,
			    char                      **data,
			    unsigned int              *data_len,
			    ipmi_fru_node_t           **sub_node);
int ipmi_mr_node_struct_set_field(ipmi_fru_node_t           *node,
				  unsigned int              index,
				  enum ipmi_fru_data_type_e dtype,
				  int                       intval,
				  time_t                    time,
				  double                    floatval,
				  char                      *data,
				  unsigned int              data_len);
int ipmi_mr_root_node_struct_set_field(ipmi_fru_node_t           *node,
				       unsigned int              index,
				       enum ipmi_fru_data_type_e dtype,
				       int                       intval,
				       time_t                    time,
				       double                    floatval,
				       char                      *data,
				       unsigned int              data_len);
int ipmi_mr_node_struct_settable(ipmi_fru_node_t *node,
				 unsigned int    index);
int ipmi_mr_node_struct_get_field(ipmi_fru_node_t           *node,
				  unsigned int              index,
				  const char                **name,
				  enum ipmi_fru_data_type_e *dtype,
				  int                       *intval,
				  time_t                    *time,
				  double                    *floatval,
				  char                      **data,
				  unsigned int              *data_len,
				  ipmi_fru_node_t           **sub_node);
int ipmi_mr_root_node_struct_get_field(ipmi_fru_node_t           *node,
				       unsigned int              index,
				       const char                **name,
				       enum ipmi_fru_data_type_e *dtype,
				       int                       *intval,
				       time_t                    *time,
				       double                    *floatval,
				       char                      **data,
				       unsigned int              *data_len,
				       ipmi_fru_node_t           **sub_node);
int ipmi_mr_struct_elem_check(ipmi_mr_struct_layout_t *layout,
			      unsigned char           **rmr_data,
			      unsigned int            *rmr_data_len);
int ipmi_mr_struct_decode(ipmi_mr_struct_info_t *rec,
			  unsigned char         **rmr_data,
			  unsigned int          *rmr_data_len);
int ipmi_mr_root(ipmi_fru_t              *fru,
		 unsigned int            mr_rec_num,
		 unsigned char           *rmr_data,
		 unsigned int            rmr_data_len,
		 ipmi_mr_struct_layout_t *layout,
		 const char              **name,
		 ipmi_fru_node_t         **rnode);

/***********************************************************************
 *
 * Generic field encoders and decoders.
 *
 **********************************************************************/

int ipmi_mr_int_set_field(ipmi_mr_item_layout_t     *layout,
			  ipmi_mr_struct_info_t     *rec,
			  ipmi_mr_fru_info_t        *finfo,
			  enum ipmi_fru_data_type_e dtype,
			  int                       intval,
			  time_t                    time,
			  double                    floatval,
			  char                      *data,
			  unsigned int              data_len);
int ipmi_mr_int_get_field(ipmi_mr_item_layout_t     *layout,
			  ipmi_mr_struct_info_t     *rec,
			  enum ipmi_fru_data_type_e *dtype,
			  int                       *intval,
			  time_t                    *time,
			  double                    *floatval,
			  char                      **data,
			  unsigned int              *data_len);
int ipmi_mr_intfloat_set_field(ipmi_mr_item_layout_t     *layout,
			       ipmi_mr_struct_info_t     *rec,
			       ipmi_mr_fru_info_t        *finfo,
			       enum ipmi_fru_data_type_e dtype,
			       int                       intval,
			       time_t                    time,
			       double                    floatval,
			       char                      *data,
			       unsigned int              data_len);
int ipmi_mr_intfloat_get_field(ipmi_mr_item_layout_t     *layout,
			       ipmi_mr_struct_info_t     *rec,
			       enum ipmi_fru_data_type_e *dtype,
			       int                       *intval,
			       time_t                    *time,
			       double                    *floatval,
			       char                      **data,
			       unsigned int              *data_len);
int ipmi_mr_bitint_set_field(ipmi_mr_item_layout_t     *layout,
			     ipmi_mr_struct_info_t     *rec,
			     ipmi_mr_fru_info_t        *finfo,
			     enum ipmi_fru_data_type_e dtype,
			     int                       intval,
			     time_t                    time,
			     double                    floatval,
			     char                      *data,
			     unsigned int              data_len);
int ipmi_mr_bitint_get_field(ipmi_mr_item_layout_t     *layout,
			     ipmi_mr_struct_info_t     *rec,
			     enum ipmi_fru_data_type_e *dtype,
			     int                       *intval,
			     time_t                    *time,
			     double                    *floatval,
			     char                      **data,
			     unsigned int              *data_len);
int ipmi_mr_bitvaltab_set_field(ipmi_mr_item_layout_t     *layout,
				ipmi_mr_struct_info_t     *rec,
				ipmi_mr_fru_info_t        *finfo,
				enum ipmi_fru_data_type_e dtype,
				int                       intval,
				time_t                    time,
				double                    floatval,
				char                      *data,
				unsigned int              data_len);
int ipmi_mr_bitvaltab_get_field(ipmi_mr_item_layout_t     *layout,
				ipmi_mr_struct_info_t     *rec,
				enum ipmi_fru_data_type_e *dtype,
				int                       *intval,
				time_t                    *time,
				double                    *floatval,
				char                      **data,
				unsigned int              *data_len);
int ipmi_mr_bitfloatvaltab_set_field(ipmi_mr_item_layout_t     *layout,
				     ipmi_mr_struct_info_t     *rec,
				     ipmi_mr_fru_info_t        *finfo,
				     enum ipmi_fru_data_type_e dtype,
				     int                       intval,
				     time_t                    time,
				     double                    floatval,
				     char                      *data,
				     unsigned int              data_len);
int ipmi_mr_bitfloatvaltab_get_field(ipmi_mr_item_layout_t     *layout,
				     ipmi_mr_struct_info_t     *rec,
				     enum ipmi_fru_data_type_e *dtype,
				     int                       *intval,
				     time_t                    *time,
				     double                    *floatval,
				     char                      **data,
				     unsigned int              *data_len);
int ipmi_mr_str_set_field(ipmi_mr_item_layout_t     *layout,
			  ipmi_mr_struct_info_t     *rec,
			  ipmi_mr_fru_info_t        *finfo,
			  enum ipmi_fru_data_type_e dtype,
			  int                       intval,
			  time_t                    time,
			  double                    floatval,
			  char                      *data,
			  unsigned int              data_len);
int ipmi_mr_str_get_field(ipmi_mr_item_layout_t     *layout,
			  ipmi_mr_struct_info_t     *rec,
			  enum ipmi_fru_data_type_e *dtype,
			  int                       *intval,
			  time_t                    *time,
			  double                    *floatval,
			  char                      **data,
			  unsigned int              *data_len);
int ipmi_mr_binary_set_field(ipmi_mr_item_layout_t     *layout,
			     ipmi_mr_struct_info_t     *rec,
			     ipmi_mr_fru_info_t        *finfo,
			     enum ipmi_fru_data_type_e dtype,
			     int                       intval,
			     time_t                    time,
			     double                    floatval,
			     char                      *data,
			     unsigned int              data_len);
int ipmi_mr_binary_get_field(ipmi_mr_item_layout_t     *layout,
			     ipmi_mr_struct_info_t     *rec,
			     enum ipmi_fru_data_type_e *dtype,
			     int                       *intval,
			     time_t                    *time,
			     double                    *floatval,
			     char                      **data,
			     unsigned int              *data_len);
int ipmi_mr_ip_set_field(ipmi_mr_item_layout_t     *layout,
			 ipmi_mr_struct_info_t     *rec,
			 ipmi_mr_fru_info_t        *finfo,
			 enum ipmi_fru_data_type_e dtype,
			 int                       intval,
			 time_t                    time,
			 double                    floatval,
			 char                      *data,
			 unsigned int              data_len);
int ipmi_mr_ip_get_field(ipmi_mr_item_layout_t     *layout,
			 ipmi_mr_struct_info_t     *rec,
			 enum ipmi_fru_data_type_e *dtype,
			 int                       *intval,
			 time_t                    *time,
			 double                    *floatval,
			 char                      **data,
			 unsigned int              *data_len);

#endif /* _IPMI_FRU_INTERNAL_H */
