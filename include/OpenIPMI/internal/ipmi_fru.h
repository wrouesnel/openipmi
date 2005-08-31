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

void _ipmi_fru_lock(ipmi_fru_t *fru);
void _ipmi_fru_unlock(ipmi_fru_t *fru);

/* Add a record telling that a specific area of the FRU data needs to
   be written.  Called from the write handler. */
int _ipmi_fru_new_update_record(ipmi_fru_t   *fru,
				unsigned int offset,
				unsigned int length);

/* Get/set the fru-type secific data */
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

/* Operations registered by the decode for a FRU. */
typedef struct ipmi_fru_op_s
{
    /* Called to free all the data associated with fru record data. */
    void (*cleanup_recs)(ipmi_fru_t *fru);

    /* Called when the FRU data has been written, to mark all the data
       as unchanged from the FRU contents. */
    void (*write_complete)(ipmi_fru_t *fru);

    /* Called to write any changed data into the fru and mark what is
       changed. */
    int (*write)(ipmi_fru_t *fru);
} ipmi_fru_op_t;

void _ipmi_fru_set_ops(ipmi_fru_t *fru, ipmi_fru_op_t *ops);

/* Register a decoder for FRU data.  This should return success if the
   FRU is supported and can be decoded properly, ENOSYS if the FRU
   information doesn't match the format, or anything else for invalid
   FRU data. */
typedef struct ipmi_fru_reg_s
{
    int (*decode)(ipmi_fru_t *fru);
} ipmi_fru_reg_t;
int _ipmi_fru_register_decoder(ipmi_fru_reg_t *reg);
int _ipmi_fru_deregister_decoder(ipmi_fru_reg_t *reg);


#endif /* _IPMI_FRU_INTERNAL_H */
