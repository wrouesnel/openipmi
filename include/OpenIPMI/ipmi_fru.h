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
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_types.h>

/* FRU information opaque type. */
typedef struct ipmi_fru_s ipmi_fru_t;

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

/* NOTE! - do not use the functions from portable programs, use the
   entity functions to fetch these. */
int ipmi_fru_get_internal_use_version(ipmi_fru_t    *fru,
				      unsigned char *version);
int ipmi_fru_get_internal_use_length(ipmi_fru_t   *fru,
				     unsigned int *length);
int  ipmi_fru_get_internal_use_data(ipmi_fru_t    *fru,
				    unsigned char *data,
				    unsigned int  *max_len);

int ipmi_fru_get_chassis_info_version(ipmi_fru_t    *fru,
				      unsigned char *version);
int  ipmi_fru_get_chassis_info_type(ipmi_fru_t    *fru,
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
int  ipmi_fru_get_board_info_mfg_time(ipmi_fru_t *fru,
				      time_t     *time);
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
   the length of the buffer and the function will set it tot he actual
   length. */
int ipmi_fru_get_multi_record_data(ipmi_fru_t    *fru,
				   unsigned int  num,
				   unsigned char *data,
				   unsigned int  *length);

/* FIXME - for OEM code (if ever necessary) add a way to create an
   empty FRU, fill it with data, and put it into an entity. */

#endif /* _IPMI_FRU_H */
