/*
 * ipmi_fru.h
 *
 * IPMI interface for FRUs
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

#ifndef _IPMI_FRU_H
#define _IPMI_FRU_H

#include <OpenIPMI/ipmi_types.h>

/* The following functions get boatloads of information from the FRU.
   These all will return ENOSYS if the information is not available.
   All these function return error, not lengths.

   The string return functions allow you to fetch the type and length.
   The length returns for ASCII strings does include the nil
   character, and it will be put on to the end of the get string.
   Also, when fetching the string, you must set the max_len variable
   to the maximum length of the returned data.  The actual length
   copied into the output string is returned in max_len. */
int ipmi_fru_get_internal_use_version(ipmi_fru_t    *fru,
				      unsigned char *version);
int ipmi_fru_get_internal_use_len(ipmi_fru_t   *fru,
				  unsigned int *length);
int ipmi_fru_get_internal_use(ipmi_fru_t    *fru,
			      unsigned char *data,
			      unsigned int  *max_len);

int ipmi_fru_get_chassis_info_version(ipmi_fru_t    *fru,
				      unsigned char *version);
int ipmi_fru_get_chassis_info_type(ipmi_fru_t    *fru,
				   unsigned char *type);

int ipmi_fru_get_chassis_info_part_number_len(ipmi_fru_t   *fru,
					      unsigned int *length);
int ipmi_fru_get_chassis_info_part_number_type(ipmi_fru_t           *fru,
					       enum ipmi_str_type_e *type);
int ipmi_fru_get_chassis_info_part_number(ipmi_fru_t   *fru,
					  char         *str,
					  unsigned int *strlen);
int ipmi_fru_get_chassis_info_serial_number_len(ipmi_fru_t   *fru,
						unsigned int *length);
int ipmi_fru_get_chassis_info_serial_number_type(ipmi_fru_t           *fru,
						 enum ipmi_str_type_e *type);
int ipmi_fru_get_chassis_info_serial_number(ipmi_fru_t   *fru,
					    char         *str,
					    unsigned int *strlen);
int ipmi_fru_get_chassis_info_custom_len(ipmi_fru_t   *fru,
					 unsigned int num,
					 unsigned int *length);
int ipmi_fru_get_chassis_info_custom_type(ipmi_fru_t           *fru,
					  unsigned int         num,
					  enum ipmi_str_type_e *type);
int ipmi_fru_get_chassis_info_custom(ipmi_fru_t   *fru,
				     unsigned int num,
				     char         *str,
				     unsigned int *strlen);

int ipmi_fru_get_board_info_version(ipmi_fru_t    *fru,
				    unsigned char *version);
int ipmi_fru_get_board_info_lang_code(ipmi_fru_t    *fru,
				      unsigned char *type);
int ipmi_fru_get_board_info_mfg_time(ipmi_fru_t   *fru,
				     time_t *time);
int ipmi_fru_get_board_info_board_manufacturer_len(ipmi_fru_t   *fru,
						   unsigned int *length);
int ipmi_fru_get_board_info_board_manufacturer_type(ipmi_fru_t           *fru,
						    enum ipmi_str_type_e *type);
int ipmi_fru_get_board_info_board_manufacturer(ipmi_fru_t   *fru,
					       char         *str,
					       unsigned int *strlen);
int ipmi_fru_get_board_info_board_product_name_len(ipmi_fru_t   *fru,
						   unsigned int *length);
int ipmi_fru_get_board_info_board_product_name_type(ipmi_fru_t           *fru,
						    enum ipmi_str_type_e *type);
int ipmi_fru_get_board_info_board_product_name(ipmi_fru_t   *fru,
					       char         *str,
					       unsigned int *strlen);
int ipmi_fru_get_board_info_board_serial_number_len(ipmi_fru_t   *fru,
						    unsigned int *length);
int ipmi_fru_get_board_info_board_serial_number_type(ipmi_fru_t           *fru,
						     enum ipmi_str_type_e *type);
int ipmi_fru_get_board_info_board_serial_number(ipmi_fru_t   *fru,
						char         *str,
						unsigned int *strlen);
int ipmi_fru_get_board_info_board_part_number_len(ipmi_fru_t   *fru,
						  unsigned int *length);
int ipmi_fru_get_board_info_board_part_number_type(ipmi_fru_t           *fru,
						   enum ipmi_str_type_e *type);
int ipmi_fru_get_board_info_board_part_number(ipmi_fru_t   *fru,
					      char         *str,
					      unsigned int *strlen);
int ipmi_fru_get_board_info_fru_file_id_len(ipmi_fru_t   *fru,
					    unsigned int *length);
int ipmi_fru_get_board_info_fru_file_id_type(ipmi_fru_t           *fru,
					     enum ipmi_str_type_e *type);
int ipmi_fru_get_board_info_fru_file_id(ipmi_fru_t   *fru,
					char         *str,
					unsigned int *strlen);
int ipmi_fru_get_board_info_custom_len(ipmi_fru_t   *fru,
				       unsigned int num,
				       unsigned int *length);
int ipmi_fru_get_board_info_custom_type(ipmi_fru_t           *fru,
					unsigned int         num,
					enum ipmi_str_type_e *type);
int ipmi_fru_get_board_info_custom(ipmi_fru_t   *fru,
				   unsigned int num,
				   char         *str,
				   unsigned int *strlen);

int ipmi_fru_get_product_info_version(ipmi_fru_t    *fru,
				      unsigned char *version);
int ipmi_fru_get_product_info_lang_code(ipmi_fru_t    *fru,
					unsigned char *type);
int ipmi_fru_get_product_info_manufacturer_name_len(ipmi_fru_t   *fru,
						    unsigned int *length);
int ipmi_fru_get_product_info_manufacturer_name_type(ipmi_fru_t           *fru,
						     enum ipmi_str_type_e *type);
int ipmi_fru_get_product_info_manufacturer_name(ipmi_fru_t   *fru,
						char         *str,
						unsigned int *strlen);
int ipmi_fru_get_product_info_product_name_len(ipmi_fru_t   *fru,
					       unsigned int *length);
int ipmi_fru_get_product_info_product_name_type(ipmi_fru_t           *fru,
						enum ipmi_str_type_e *type);
int ipmi_fru_get_product_info_product_name(ipmi_fru_t   *fru,
					   char         *str,
					   unsigned int *strlen);
int ipmi_fru_get_product_info_product_part_model_number_len(ipmi_fru_t   *fru,
							    unsigned int *length);
int ipmi_fru_get_product_info_product_part_model_number_type(ipmi_fru_t           *fru,
							     enum ipmi_str_type_e *type);
int ipmi_fru_get_product_info_product_part_model_number(ipmi_fru_t   *fru,
							char         *str,
							unsigned int *strlen);
int ipmi_fru_get_product_info_product_version_len(ipmi_fru_t   *fru,
						  unsigned int *length);
int ipmi_fru_get_product_info_product_version_type(ipmi_fru_t           *fru,
						   enum ipmi_str_type_e *type);
int ipmi_fru_get_product_info_product_version(ipmi_fru_t   *fru,
					      char         *str,
					      unsigned int *strlen);
int ipmi_fru_get_product_info_product_serial_number_len(ipmi_fru_t   *fru,
							unsigned int *length);
int ipmi_fru_get_product_info_product_serial_number_type(ipmi_fru_t           *fru,
							 enum ipmi_str_type_e *type);
int ipmi_fru_get_product_info_product_serial_number(ipmi_fru_t   *fru,
						    char         *str,
						    unsigned int *strlen);
int ipmi_fru_get_product_info_asset_tag_len(ipmi_fru_t   *fru,
					    unsigned int *length);
int ipmi_fru_get_product_info_asset_tag_type(ipmi_fru_t           *fru,
					     enum ipmi_str_type_e *type);
int ipmi_fru_get_product_info_asset_tag(ipmi_fru_t   *fru,
					char         *str,
					unsigned int *strlen);
int ipmi_fru_get_product_info_fru_file_id_len(ipmi_fru_t   *fru,
					      unsigned int *length);
int ipmi_fru_get_product_info_fru_file_id_type(ipmi_fru_t           *fru,
					       enum ipmi_str_type_e *type);
int ipmi_fru_get_product_info_fru_file_id(ipmi_fru_t   *fru,
					  char         *str,
					  unsigned int *strlen);
int ipmi_fru_get_product_info_custom_len(ipmi_fru_t   *fru,
					 unsigned int num,
					 unsigned int *length);
int ipmi_fru_get_product_info_custom_type(ipmi_fru_t           *fru,
					  unsigned int         num,
					  enum ipmi_str_type_e *type);
int ipmi_fru_get_product_info_custom(ipmi_fru_t   *fru,
				     unsigned int num,
				     char         *str,
				     unsigned int *strlen);

unsigned int ipmi_fru_get_num_multi_records(ipmi_fru_t *fru);
int ipmi_fru_get_multi_record_type(ipmi_fru_t    *fru,
				   unsigned int  num,
				   unsigned char *type);
int ipmi_fru_get_multi_record_format_version(ipmi_fru_t    *fru,
					     unsigned int  num,
					     unsigned char *ver);
int ipmi_fru_get_multi_record_data_len(ipmi_fru_t   *fru,
				       unsigned int num,
				       unsigned int *len);
/* Note that length is a in/out parameter, you must set the length to
   the length of the buffer and the function will set it to the actual
   length. */
int ipmi_fru_get_multi_record_data(ipmi_fru_t    *fru,
				   unsigned int  num,
				   unsigned char *data,
				   unsigned int  *length);

/* Get the start offset in the FRU of the multi-record data.  This
   includes the multi-record header.  This is here to allow the
   offsets of data in multi-record areas to be computed so that values
   can be modified. */
int ipmi_fru_get_multi_record_data_offset(ipmi_fru_t    *fru,
					  unsigned int  num,
					  unsigned int  *offset);


/*
 * This interface lets you get the FRU data by name.
 */

enum ipmi_fru_data_type_e
{
    IPMI_FRU_DATA_INT,
    IPMI_FRU_DATA_TIME,
    IPMI_FRU_DATA_ASCII,
    IPMI_FRU_DATA_BINARY,
    IPMI_FRU_DATA_UNICODE,
};

/*
 * Find the index number for the given string.  Returns -1 if the string
 * is invalid.
 */
int ipmi_fru_str_to_index(char *name);

/*
 * Get the FRU information by index.  This is a rather complex
 * function, but gives probably the simplest possible way to iterate
 * through the FRU data.  The index is a contiguous range from zero
 * that holds every FRU data item.  So you can iterate through the
 * indexes from 0 until it returns EINVAL to find all the names.
 *
 * name returns the string name for the index.  Note that the
 * indexes may change between release, so don't rely on absolute
 * numbers.  The names will remain the same, so you can rely on
 * those.
 *
 * The number is a pointer to an integer with the number of the item
 * to get within the field.  Some fields (custom records,
 * multi-records) have multiple items in them.  The first item will be
 * zero, and the integer here will be updated to reference the next
 * item.  When the last item is reached, the field will be updated
 * to -1.  For fields that don't have multiple items, this will
 * not modify the value num points to.
 *
 * The dtype field will be set to the data type.  If it is an integer
 * value, then intval will be set to whatever the value is.  If it is
 * a time value, then the time field will be filled in.  If it is not,
 * then a block of data will be allocated to hold the field and placed
 * into data, the length of the data will be in data_len.  You must
 * free the data when you are done with ipmi_fru_data_free().
 *
 * Returns EINVAL if the index is out of range, ENOSYS if the
 * particular index is not supported, or E2BIG if the num is
 * too big.
 *
 * Any of the return values may be passed NULL to ignore the data.
 *
 * This does *not* include the multi-records.
 */
int ipmi_fru_get(ipmi_fru_t                *fru,
		 int                       index,
		 char                      **name,
		 int                       *num,
		 enum ipmi_fru_data_type_e *dtype,
		 int                       *intval,
		 time_t                    *time,
		 char                      **data,
		 unsigned int              *data_len);

/* Free data that comes from ipmi_fru_get if the data return is
   non-NULL. */
int ipmi_fru_data_free(char *data);


/* More internal stuff.  The average user will not need to be able
   to use the following functions, but they are here just in case. */

/* FIXME - for OEM code (if ever necessary) add a way to create an
   empty FRU, fill it with data, and put it into an entity. */

/* The the domain the FRU uses.  For internal use only. */
ipmi_domain_t *ipmi_fru_get_domain(ipmi_fru_t *fru);

typedef void (*ipmi_fru_fetched_cb)(ipmi_fru_t *fru, int err, void *cb_data);
int ipmi_fru_alloc(ipmi_domain_t       *domain,
		   unsigned char       is_logical,
		   unsigned char       device_address,
		   unsigned char       device_id,
		   unsigned char       lun,
		   unsigned char       private_bus,
		   unsigned char       channel,
		   ipmi_fru_fetched_cb fetched_handler,
		   void                *fetched_cb_data,
		   ipmi_fru_t          **new_fru);

/* Destroy an FRU.  Note that if the FRU is currently fetching SDRs,
   the destroy cannot complete immediatly, it will be marked for
   destruction later.  You can supply a callback that, if not NULL,
   will be called when the sdr is destroyed. */
typedef void (*ipmi_fru_destroyed_cb)(ipmi_fru_t *fru, void *cb_data);
int ipmi_fru_destroy(ipmi_fru_t            *fru,
		     ipmi_fru_destroyed_cb handler,
		     void                  *cb_data);

/************************************************************************
 *
 * Cruft
 *
 ************************************************************************/
int ipmi_fru_get_internal_use_data(ipmi_fru_t    *fru,
				   unsigned char *data,
				   unsigned int  *max_len);

int ipmi_fru_get_internal_use_length(ipmi_fru_t   *fru,
				     unsigned int *length);

#endif /* _IPMI_FRU_H */
