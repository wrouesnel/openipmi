/*
 * ipmi_sel.h
 *
 * MontaVista IPMI interface for the system event log
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
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

#ifndef _IPMI_SEL_H
#define _IPMI_SEL_H
#include <ipmi/ipmi_types.h>

/* Maximum amount of data allowed in a SEL. */
#define MAX_SEL_DATA 13

/* Generic information about an SEL. */
typedef struct ipmi_sel_s
{
    unsigned int  record_id;
    unsigned int  type;
    unsigned char data[MAX_SEL_DATA];
} ipmi_sel_t;

/* Opaque type representing a remote SEL repository. */
typedef struct ipmi_sel_info_s ipmi_sel_info_t;

/* Create a local representation of a remote SEL repository.  When
   created, it will not automatically fetch the remote SELs, you need
   to do that.  If "sensor" is true, then this will fetch the "sensor"
   SELs using GET DEVICE SEL.  If not, it will use GET SEL for
   fetching SELs. */
int ipmi_sel_alloc(ipmi_mc_t       *mc,
		   unsigned int    lun,
		   ipmi_sel_info_t **new_sel);

/* Destroy an SEL.  Note that if the SEL is currently fetching events,
   the destroy cannot complete immediatly, it will be marked for
   destruction later.  You can supply a callback that, if not NULL,
   will be called when the sel is destroyed. */
typedef void (*ipmi_sel_destroyed_t)(ipmi_sel_info_t *sel, void *cb_data);
int ipmi_sel_destroy(ipmi_sel_info_t      *sel,
		     ipmi_sel_destroyed_t handler,
		     void                 *cb_data);

/* Fetch the remote SELs, but do not wait until the fetch is complete,
   return immediately.  When the fetch is complete, call the given
   handler. */
typedef void (*ipmi_sels_fetched_t)(ipmi_sel_info_t *sel,
				    int             err,
				    int             changed,
				    unsigned int    count,
				    void            *cb_data);
int ipmi_sel_get(ipmi_sel_info_t     *sel,
		 ipmi_sels_fetched_t handler,
		 void                *cb_data);

int ipmi_get_sel_count(ipmi_sel_info_t *sel,
		       unsigned int    *count);

int ipmi_get_sel_by_recid(ipmi_sel_info_t *sel,
			  unsigned int    recid,
			  ipmi_sel_t      *return_sel);

int ipmi_get_sel_by_type(ipmi_sel_info_t *sel,
			 int             type,
			 ipmi_sel_t      *return_sel);

int ipmi_get_sel_by_index(ipmi_sel_info_t *sel,
			  int             index,
			  ipmi_sel_t      *return_sel);

/* Fetch all the sels.  The array size should point to a value that
   holds the number of elements in the passed in array.  The
   array_size will be set to the actual number of elements put into
   the array.  If the number of SELs is larger than the supplied
   array_size, this will return E2BIG and do nothing. */
int ipmi_get_all_sels(ipmi_sel_info_t *sel,
		      int             *array_size,
		      ipmi_sel_t      *array);

typedef void (*ipmi_sel_op_done_cb_t)(ipmi_sel_info_t *sel,
				      void            *cb_data,
				      int             err);

/* Delete an event log entry by record id. */
int ipmi_del_sel_by_recid(ipmi_sel_info_t       *sel,
			  unsigned int          recid,
			  ipmi_sel_op_done_cb_t handler,
			  void                  *cb_data);

/* Delete an event log entry by index. */
int ipmi_del_sel_by_index(ipmi_sel_info_t       *sel,
			  int                   index,
			  ipmi_sel_op_done_cb_t handler,
			  void                  *cb_data);

/* Get various information from the IPMI SEL info commands. */
int ipmi_sel_get_major_version(ipmi_sel_info_t *sel, int *val);
int ipmi_sel_get_minor_version(ipmi_sel_info_t *sel, int *val);
int ipmi_sel_get_overflow(ipmi_sel_info_t *sel, int *val);
int ipmi_sel_get_supports_delete_sel(ipmi_sel_info_t *sel, int *val);
int ipmi_sel_get_supports_partial_add_sel(ipmi_sel_info_t *sel, int *val);
int ipmi_sel_get_supports_reserve_sel(ipmi_sel_info_t *sel, int *val);
int ipmi_sel_get_supports_get_sel_allocation(ipmi_sel_info_t *sel,
					     int             *val);

#endif /* _IPMI_SEL_H */
