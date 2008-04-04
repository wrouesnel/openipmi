/*
 * fru.c
 *
 * IPMI code for handling FRUs
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

#define MAX_FRU_DATA_FETCH 32
#define FRU_DATA_FETCH_DECR 8
#define MIN_FRU_DATA_FETCH 16

#define MAX_FRU_DATA_WRITE 16
#define MAX_FRU_WRITE_RETRIES 30

#define MAX_FRU_FETCH_RETRIES 5

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

/* Record used for FRU writing. */
typedef struct fru_update_s fru_update_t;
struct fru_update_s
{
    unsigned short offset;
    unsigned short length;
    fru_update_t   *next;
};

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

    /* Get the root node for this FRU. */
    int (*get_root_node)(ipmi_fru_t      *fru,
			 const char      **name,
			 ipmi_fru_node_t **rnode);
} ipmi_fru_op_t;

struct ipmi_fru_s
{
    char name[IPMI_FRU_NAME_LEN+1];
    int deleted;

    unsigned int refcount;

    /* Is the FRU being read or written? */
    int in_use;

    ipmi_lock_t *lock;

    ipmi_addr_t  addr;
    unsigned int addr_len;

    void                          *setup_data;
    _ipmi_fru_setup_data_clean_cb setup_data_cleanup;

    ipmi_domain_id_t     domain_id;
    unsigned char        is_logical;
    unsigned char        device_address;
    unsigned char        device_id;
    unsigned char        lun;
    unsigned char        private_bus;
    unsigned char        channel;

    unsigned int        fetch_mask;

    uint32_t last_timestamp;
    int      fetch_retries;

    ipmi_fru_fetched_cb fetched_handler;
    ipmi_fru_cb         domain_fetched_handler;
    void                *fetched_cb_data;

    ipmi_fru_destroyed_cb destroy_handler;
    void                  *destroy_cb_data;

    int           access_by_words;
    unsigned char *data;
    unsigned int  data_len;
    unsigned int  curr_pos;
    unsigned int  curr_write_len;
    int           write_prepared;
    int           saved_err;

    int           fetch_size;

    /* Is this in the list of FRUs? */
    int in_frulist;

    /* The records for writing. */
    fru_update_t *update_recs;
    fru_update_t *update_recs_tail;

    /* The last send command for writing */
    unsigned int  last_cmd_len;
    unsigned int  retry_count;

    os_handler_t *os_hnd;

    /* If the FRU is a "normal" fru type, for backwards
       compatability. */
    int  normal_fru;

    char *fru_rec_type;
    void *rec_data;
    ipmi_fru_op_t ops;

    /* FRU locking handling */
    _ipmi_fru_get_timestamp_cb  timestamp_cb;
    _ipmi_fru_prepare_write_cb  prepare_write_cb;
    _ipmi_fru_write_cb          write_cb;
    _ipmi_fru_complete_write_cb complete_write_cb;

    char iname[IPMI_FRU_NAME_LEN+1];

    unsigned int options;
};

#define FRU_DOMAIN_NAME(fru) (fru ? fru->iname : "")

static void final_fru_destroy(ipmi_fru_t *fru);
static void fetch_complete(ipmi_domain_t *domain, ipmi_fru_t *fru, int err);

/***********************************************************************
 *
 * general utilities
 *
 **********************************************************************/
void
_ipmi_fru_lock(ipmi_fru_t *fru)
{
    ipmi_lock(fru->lock);
}

void
_ipmi_fru_unlock(ipmi_fru_t *fru)
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

void
_ipmi_fru_ref_nolock(ipmi_fru_t *fru)
{
    fru->refcount++;
}

static void
fru_put(ipmi_fru_t *fru)
{
    _ipmi_fru_lock(fru);
    fru->refcount--;
    if (fru->refcount == 0) {
	final_fru_destroy(fru);
	return;
    }
    _ipmi_fru_unlock(fru);
}

void
ipmi_fru_ref(ipmi_fru_t *fru)
{
    _ipmi_fru_lock(fru);
    fru_get(fru);
    _ipmi_fru_unlock(fru);
}

void
ipmi_fru_deref(ipmi_fru_t *fru)
{
    fru_put(fru);
}

/************************************************************************
 *
 * Decode registration handling
 *
 ************************************************************************/

static locked_list_t *fru_decode_handlers;

int
_ipmi_fru_register_decoder(ipmi_fru_err_op op)
{
    if (!locked_list_add(fru_decode_handlers, op, NULL))
	return ENOMEM;
    return 0;
}

int
_ipmi_fru_deregister_decoder(ipmi_fru_err_op op)
{
    if (!locked_list_remove(fru_decode_handlers, op, NULL))
	return ENODEV;
    return 0;
}

typedef struct fru_decode_s
{
    ipmi_fru_t *fru;
    int        err;
} fru_decode_t;

static int
fru_call_decoder(void *cb_data, void *item1, void *item2)
{
    fru_decode_t    *info = cb_data;
    ipmi_fru_err_op op = item1;
    int             err;

    err = op(info->fru);
    if (!err) {
	info->err = 0;
	return LOCKED_LIST_ITER_STOP;
    } else
	return LOCKED_LIST_ITER_CONTINUE;
}

static int
fru_call_decoders(ipmi_fru_t *fru)
{
    fru_decode_t info;

    info.err = ENOSYS;
    info.fru = fru;
    locked_list_iterate(fru_decode_handlers, fru_call_decoder, &info);
    return info.err;
}

void
_ipmi_fru_set_op_cleanup_recs(ipmi_fru_t *fru, ipmi_fru_void_op op)
{
    fru->ops.cleanup_recs = op;
}

void
_ipmi_fru_set_op_write_complete(ipmi_fru_t *fru, ipmi_fru_void_op op)
{
    fru->ops.write_complete = op;
}

void
_ipmi_fru_set_op_write(ipmi_fru_t *fru, ipmi_fru_err_op op)
{
    fru->ops.write = op;
}

void
_ipmi_fru_set_op_get_root_node(ipmi_fru_t                *fru,
			       ipmi_fru_get_root_node_op op)
{
    fru->ops.get_root_node = op;
}


/***********************************************************************
 *
 * FRU configuration
 *
 **********************************************************************/
int
_ipmi_fru_set_get_timestamp_handler(ipmi_fru_t                 *fru,
				    _ipmi_fru_get_timestamp_cb handler)
{
    fru->timestamp_cb = handler;
    return 0;
}

int
_ipmi_fru_set_prepare_write_handler(ipmi_fru_t                 *fru,
				    _ipmi_fru_prepare_write_cb handler)
{
    fru->prepare_write_cb = handler;
    return 0;
}

int
_ipmi_fru_set_write_handler(ipmi_fru_t         *fru,
			    _ipmi_fru_write_cb handler)
{
    fru->write_cb = handler;
    return 0;
}

int
_ipmi_fru_set_complete_write_handler(ipmi_fru_t                  *fru,
				     _ipmi_fru_complete_write_cb handler)
{
    fru->complete_write_cb = handler;
    return 0;
}

void
_ipmi_fru_get_addr(ipmi_fru_t *fru, ipmi_addr_t *addr, unsigned int *addr_len)
{
    *addr = fru->addr;
    *addr_len = fru->addr_len;
}

void
_ipmi_fru_set_setup_data(ipmi_fru_t                    *fru,
			 void                          *data,
			 _ipmi_fru_setup_data_clean_cb cleanup)
{
    fru->setup_data = data;
    fru->setup_data_cleanup = cleanup;
}

void *
_ipmi_fru_get_setup_data(ipmi_fru_t *fru)
{
    return fru->setup_data;
}

static int
fru_normal_write_done(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_msg_t      *msg = &rspi->msg;
    ipmi_fru_t      *fru = rspi->data1;
    unsigned char   *data = msg->data;
    _ipmi_fru_op_cb cb = rspi->data2;
    int             err = 0;

    if (data[0]) {
	err = IPMI_IPMI_ERR_VAL(data[0]);
	goto out;
    }

    if (msg->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_normal_write_done): "
		 "FRU write response too small",
		 FRU_DOMAIN_NAME(fru));
	err = EINVAL;
	goto out;
    }

    if ((unsigned int) (data[1] << fru->access_by_words)
	!= (fru->last_cmd_len - 3))
    {
	/* Write was incomplete for some reason.  Just go on but issue
	   a warning. */
	ipmi_log(IPMI_LOG_WARNING,
		 "%sfru.c(fru_normal_write_done): "
		 "Incomplete writing FRU data, write %d, expected %d",
		 FRU_DOMAIN_NAME(fru),
		 data[1] << fru->access_by_words, fru->last_cmd_len-3);
    }

 out:
    cb(fru, domain, err);
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
fru_normal_write(ipmi_fru_t      *fru,
		 ipmi_domain_t   *domain,
		 unsigned char   *data,
		 unsigned int    data_len,
		 _ipmi_fru_op_cb done)
{
    ipmi_msg_t msg;

    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_WRITE_FRU_DATA_CMD;
    msg.data = data;
    msg.data_len = data_len;

    return ipmi_send_command_addr(domain,
				  &fru->addr, fru->addr_len,
				  &msg,
				  fru_normal_write_done,
				  fru,
				  done);
}

void
ipmi_fru_set_options(ipmi_fru_t *fru, unsigned int options)
{
    fru->options = options;
}

unsigned int
ipmi_fru_get_options(ipmi_fru_t *fru)
{
    return fru->options;
}

/***********************************************************************
 *
 * FRU allocation and destruction
 *
 **********************************************************************/

static void
final_fru_destroy(ipmi_fru_t *fru)
{
    if (fru->in_frulist) {
	int                rv;
	ipmi_domain_attr_t *attr;
	locked_list_t      *frul;

	fru->in_frulist = 0;
	rv = ipmi_domain_id_find_attribute(fru->domain_id, IPMI_FRU_ATTR_NAME,
					   &attr);
	if (!rv) {
	    fru->refcount++;
	    _ipmi_fru_unlock(fru);
	    frul = ipmi_domain_attr_get_data(attr);
	    locked_list_remove(frul, fru, NULL);
	    ipmi_domain_attr_put(attr);
	    _ipmi_fru_lock(fru);
	    /* While we were unlocked, someone may have come in and
	       grabbed the FRU by iterating the list of FRUs.  That's
	       ok, we just let them handle the destruction since this
	       code will not be entered again. */
	    if (fru->refcount != 1) {
		fru->refcount--;
		_ipmi_fru_unlock(fru);
		return;
	    }
	}
    }
    _ipmi_fru_unlock(fru);

    /* No one else can be referencing this here, so it is safe to
       release the lock now. */

    if (fru->destroy_handler)
	fru->destroy_handler(fru, fru->destroy_cb_data);

    if (fru->ops.cleanup_recs)
	fru->ops.cleanup_recs(fru);

    while (fru->update_recs) {
	fru_update_t *to_free = fru->update_recs;
	fru->update_recs = to_free->next;
	ipmi_mem_free(to_free);
    }
    if (fru->setup_data_cleanup)
	fru->setup_data_cleanup(fru, fru->setup_data);
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

    _ipmi_fru_lock(fru);
    fru->destroy_handler = handler;
    fru->destroy_cb_data = cb_data;
    fru->deleted = 1;
    _ipmi_fru_unlock(fru);

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

    _ipmi_fru_lock(fru);
    if (fru->in_frulist) {
	rv = ipmi_domain_id_find_attribute(fru->domain_id, IPMI_FRU_ATTR_NAME,
					   &attr);
	if (rv) {
	    _ipmi_fru_unlock(fru);
	    return rv;
	}
	fru->in_frulist = 0;
	_ipmi_fru_unlock(fru);

	frul = ipmi_domain_attr_get_data(attr);
	if (! locked_list_remove(frul, fru, NULL)) {
	    /* Not in the list, it's already been removed. */
	    ipmi_domain_attr_put(attr);
	    _ipmi_fru_unlock(fru);
	    return EINVAL;
	}
	ipmi_domain_attr_put(attr);
	fru_put(fru); /* It's not in the list any more. */
    } else {
	/* User can't destroy FRUs he didn't allocate. */
	_ipmi_fru_unlock(fru);
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
    _ipmi_fru_lock(fru);
    fru->in_frulist = 0;
    _ipmi_fru_unlock(fru);
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
start_fru_fetch(ipmi_fru_t *fru, ipmi_domain_t *domain)
{
    int rv;

    fru->curr_pos = 0;

    if (fru->is_logical)
	rv = start_logical_fru_fetch(domain, fru);
    else
	rv = start_physical_fru_fetch(domain, fru);

    return rv;
}

static void
fetch_got_timestamp(ipmi_fru_t    *fru,
		    ipmi_domain_t *domain,
		    int           err,
		    uint32_t      timestamp)
{
    int rv;
    _ipmi_fru_lock(fru);
    if (fru->deleted) {
	fetch_complete(domain, fru, ECANCELED);
	goto out;
    }

    if (err) {
	fetch_complete(domain, fru, err);
	goto out;
    }

    fru->last_timestamp = timestamp;
    rv = start_fru_fetch(fru, domain);
    if (rv) {
	fetch_complete(domain, fru, rv);
	goto out;
    }
    _ipmi_fru_unlock(fru);
 out:
    return;
}

static int
ipmi_fru_alloc_internal(ipmi_domain_t       *domain,
			unsigned char       is_logical,
			unsigned char       device_address,
			unsigned char       device_id,
			unsigned char       lun,
			unsigned char       private_bus,
			unsigned char       channel,
			unsigned char       fetch_mask,
			ipmi_fru_fetched_cb fetched_handler,
			void                *fetched_cb_data,
			ipmi_fru_t          **new_fru)
{
    ipmi_fru_t       *fru;
    int              err;
    int              len, p;
    ipmi_ipmb_addr_t *ipmb;

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
    fru->fetch_mask = fetch_mask;
    fru->fetch_size = MAX_FRU_DATA_FETCH;
    fru->os_hnd = ipmi_domain_get_os_hnd(domain);
    fru->write_cb = fru_normal_write;

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

    ipmb = (ipmi_ipmb_addr_t *) &fru->addr;
    ipmb->addr_type = IPMI_IPMB_ADDR_TYPE;
    ipmb->channel = fru->channel;
    ipmb->slave_addr = fru->device_address;
    ipmb->lun = fru->lun;
    fru->addr_len = sizeof(*ipmb);

    err = _ipmi_domain_fru_call_special_setup(domain, is_logical,
					      device_address, device_id,
					      lun, private_bus, channel,
					      fru);
    if (err)
	goto out_err;

    _ipmi_fru_lock(fru);
    if (fru->timestamp_cb) {
	err = fru->timestamp_cb(fru, domain, fetch_got_timestamp);
	if (err)
	    goto out_err;
    } else {
	err = start_fru_fetch(fru, domain);
	if (err)
	    goto out_err;
    }

    *new_fru = fru;
    return 0;

 out_err:
    _ipmi_fru_unlock(fru);
    ipmi_destroy_lock(fru->lock);
    ipmi_mem_free(fru);
    return err;
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
				 IPMI_FRU_ALL_AREA_MASK, NULL, NULL, &nfru);
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
    _ipmi_fru_unlock(nfru);
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
				 IPMI_FRU_ALL_AREA_MASK,
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
    _ipmi_fru_unlock(nfru);
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
		       unsigned char fetch_mask,
		       ipmi_ifru_cb  fetched_handler,
		       void          *fetched_cb_data,
		       ipmi_fru_t    **new_fru)
{
    ipmi_fru_t *nfru;
    int        rv;

    rv = ipmi_fru_alloc_internal(domain, is_logical, device_address,
				 device_id, lun, private_bus, channel,
				 fetch_mask, NULL, NULL, &nfru);
    if (rv)
	return rv;
    nfru->domain_fetched_handler = fetched_handler;
    nfru->fetched_cb_data = fetched_cb_data;
    _ipmi_fru_unlock(nfru);

    if (new_fru)
	*new_fru = nfru;
    return 0;
}

/***********************************************************************
 *
 * FRU Raw data reading
 *
 **********************************************************************/

static void
fetch_complete(ipmi_domain_t *domain, ipmi_fru_t *fru, int err)
{
    if (!err) {
	_ipmi_fru_unlock(fru);
	err = fru_call_decoders(fru);
	if (err) {
	    ipmi_log(IPMI_LOG_ERR_INFO,
		     "%sfru.c(fetch_complete):"
		     " Unable to decode FRU information",
		     _ipmi_fru_get_iname(fru));
	}
	_ipmi_fru_lock(fru);
    }

    if (fru->data)
	ipmi_mem_free(fru->data);
    fru->data = NULL;
    fru->in_use = 0;
    _ipmi_fru_unlock(fru);

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

static void
end_fru_fetch(ipmi_fru_t    *fru,
	      ipmi_domain_t *domain,
	      int           err,
	      uint32_t      timestamp)
{
    int rv;

    _ipmi_fru_lock(fru);
    if (fru->deleted) {
	fetch_complete(domain, fru, ECANCELED);
	goto out;
    }

    if (err) {
	fetch_complete(domain, fru, err);
	goto out;
    }

    if (fru->last_timestamp != timestamp) {
	fru->fetch_retries++;
	if (fru->fetch_retries > MAX_FRU_FETCH_RETRIES)
	    fetch_complete(domain, fru, EAGAIN);
	else {
	    ipmi_mem_free(fru->data);
	    fru->data = NULL;
	    _ipmi_fru_unlock(fru);
	    fru->last_timestamp = timestamp;
	    rv = start_fru_fetch(fru, domain);
	    if (rv)
		fetch_complete(domain, fru, rv);
	}
    } else
	fetch_complete(domain, fru, 0);

 out:
    return;
}

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

    _ipmi_fru_lock(fru);

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
	    if (fru->timestamp_cb) {
		err = fru->timestamp_cb(fru, domain, end_fru_fetch);
		if (err)
		    fetch_complete(domain, fru, err);
		else
		    goto out_unlock;
	    } else {
		fetch_complete(domain, fru, 0);
	    }
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
	if (fru->timestamp_cb) {
	    err = fru->timestamp_cb(fru, domain, end_fru_fetch);
	    if (err) {
		fetch_complete(domain, fru, err);
		goto out;
	    }
	} else {
	    fetch_complete(domain, fru, 0);
	    goto out;
	}
    }

 out_unlock:
    _ipmi_fru_unlock(fru);
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

    _ipmi_fru_lock(fru);

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

    _ipmi_fru_unlock(fru);
 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
start_logical_fru_fetch(ipmi_domain_t *domain, ipmi_fru_t *fru)
{
    unsigned char    cmd_data[1];
    ipmi_msg_t       msg;

    cmd_data[0] = fru->device_id;
    msg.netfn = IPMI_STORAGE_NETFN;
    msg.cmd = IPMI_GET_FRU_INVENTORY_AREA_INFO_CMD;
    msg.data = cmd_data;
    msg.data_len = 1;

    return ipmi_send_command_addr(domain,
				  &fru->addr, fru->addr_len,
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

int
_ipmi_fru_new_update_record(ipmi_fru_t   *fru,
			    unsigned int offset,
			    unsigned int length)
{
    fru_update_t *urec;

    if (length == 0) {
	ipmi_log(IPMI_LOG_WARNING,
		 "fru.c(_ipmi_fru_new_update_record): "
		 "zero-length update record written");
	return 0;
    }
    urec = ipmi_mem_alloc(sizeof(*urec));
    if (!urec)
	return ENOMEM;
    if (fru->access_by_words) {
	/* This handles the (really stupid) word access mode.  If the
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

static int next_fru_write(ipmi_domain_t *domain, ipmi_fru_t *fru);
void write_complete(ipmi_domain_t *domain, ipmi_fru_t *fru, int err);

void
write_complete2(ipmi_fru_t *fru, ipmi_domain_t *domain, int err)
{
    _ipmi_fru_lock(fru);
    write_complete(domain, fru, err);
}

void
write_complete(ipmi_domain_t *domain, ipmi_fru_t *fru, int err)
{
    if (domain && fru->write_prepared) {
	fru->saved_err = err;
	fru->write_prepared = 0;
	err = fru->complete_write_cb(fru, domain, err, fru->last_timestamp,
				     write_complete2);
	if (!err) {
	    _ipmi_fru_unlock(fru);
	    return;
	}
    }

    if (fru->saved_err) {
	err = fru->saved_err;
	fru->saved_err = 0;
    }

    if (!err) {
	/* If we succeed, set everything unchanged. */
	if (fru->ops.write_complete)
	    fru->ops.write_complete(fru);
    }
    if (fru->data)
	ipmi_mem_free(fru->data);
    fru->data = NULL;

    fru->in_use = 0;
    _ipmi_fru_unlock(fru);

    if (fru->domain_fetched_handler)
	fru->domain_fetched_handler(domain, fru, err, fru->fetched_cb_data);

    fru_put(fru);
}

static void
fru_write_handler(ipmi_fru_t    *fru,
		  ipmi_domain_t *domain,
		  int           err)
{
    int rv;

    _ipmi_fru_lock(fru);

    /* Note that for safety, we do not stop a fru write on deletion. */

    if (err == IPMI_IPMI_ERR_VAL(0x81)) {
	/* Got a busy response.  Try again if we haven't run out of
	   retries. */
	if (fru->retry_count >= MAX_FRU_WRITE_RETRIES) {
	    write_complete(domain, fru, err);
	    goto out;
	}
	fru->retry_count++;
	goto retry_write;
    } else if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%sfru.c(fru_write_handler): "
		 "IPMI error writing FRU data: %x",
		 FRU_DOMAIN_NAME(fru), err);
	write_complete(domain, fru, err);
	goto out;
    }

    fru->update_recs->length -= fru->curr_write_len;
    if (fru->update_recs->length > 0) {
	fru->update_recs->offset += fru->curr_write_len;
    } else {
	fru_update_t *to_free = fru->update_recs;
	fru->update_recs = to_free->next;
	ipmi_mem_free(to_free);
    }

 retry_write:
    if (fru->update_recs) {
	/* More to do. */
	rv = next_fru_write(domain, fru);
	if (rv) {
	    write_complete(domain, fru, rv);
	    goto out;
	}
    } else {
	write_complete(domain, fru, 0);
	goto out;
    }

    _ipmi_fru_unlock(fru);
 out:
    return;
}

static int
next_fru_write(ipmi_domain_t *domain, ipmi_fru_t *fru)
{
    unsigned char data[MAX_FRU_DATA_WRITE+4];
    int           offset, length = 0, left, noff, tlen;

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
	fru->curr_write_len = tlen;
    }

    fru->retry_count = 0;
    data[0] = fru->device_id;
    ipmi_set_uint16(data+1, offset >> fru->access_by_words);
    memcpy(data+3, fru->data+offset, length);
    fru->last_cmd_len = length + 3;
    return fru->write_cb(fru, domain, data, length+3, fru_write_handler);
}

static void
fru_write_timestamp_done(ipmi_fru_t    *fru,
			 ipmi_domain_t *domain,
			 int           err,
			 uint32_t      timestamp)
{
    int rv;

    _ipmi_fru_lock(fru);

    if (fru->deleted) {
	write_complete(domain, fru, ECANCELED);
	goto out;
    }

    if (err) {
	write_complete(domain, fru, err);
	goto out;
    }

    rv = next_fru_write(domain, fru);
    if (rv) {
	write_complete(domain, fru, rv);
	goto out;
    }
    _ipmi_fru_unlock(fru);

 out:
    return;
}

static void
fru_write_start_timestamp_check(ipmi_fru_t    *fru,
				ipmi_domain_t *domain,
				int           err)
{
    int rv;

    _ipmi_fru_lock(fru);

    if (fru->deleted) {
	write_complete(domain, fru, ECANCELED);
	goto out;
    }

    if (err) {
	write_complete(domain, fru, err);
	goto out;
    }

    fru->write_prepared = 1;

    if (fru->timestamp_cb)
	rv = fru->timestamp_cb(fru, domain, fru_write_timestamp_done);
    else
	rv = next_fru_write(domain, fru);
    if (rv) {
	write_complete(domain, fru, rv);
	goto out;
    }
    _ipmi_fru_unlock(fru);

 out:
    return;
}

typedef struct start_domain_fru_write_s
{
    ipmi_fru_t *fru;
    int        rv;
} start_domain_fru_write_t;

void
start_domain_fru_write(ipmi_domain_t *domain, void *cb_data)
{
    start_domain_fru_write_t *info = cb_data;
    ipmi_fru_t               *fru = info->fru;


    /* We allocate and format the entire FRU data.  We do this because
       of the stupid word access capability, which means we cannot
       necessarily do byte-aligned writes.  Because of that, we might
       have to have the byte before or after the actual one being
       written, and it may come from a different data field. */
    fru->data = ipmi_mem_alloc(fru->data_len);
    if (!fru->data) {
	info->rv = ENOMEM;
	goto out_unlock;
    }
    memset(fru->data, 0, fru->data_len);

    info->rv = fru->ops.write(fru);
    if (info->rv)
	goto out_unlock;

    if (!fru->update_recs) {
	/* No data changed, no write is needed. */
	ipmi_mem_free(fru->data);
	fru->data = NULL;
	fru->in_use = 0;
	_ipmi_fru_unlock(fru);

	if (fru->domain_fetched_handler)
	    fru->domain_fetched_handler(domain, fru, 0, fru->fetched_cb_data);
	return;
    }

    fru_get(fru);
    fru->write_prepared = 0;

    if (fru->prepare_write_cb)
	info->rv = fru->prepare_write_cb(fru, domain, fru->last_timestamp,
					 fru_write_start_timestamp_check);
    else if (fru->timestamp_cb)
	info->rv = fru->timestamp_cb(fru, domain, fru_write_timestamp_done);
    else
	info->rv = next_fru_write(domain, fru);

    if (info->rv)
	fru_put(fru);

 out_unlock:
    if (info->rv) {
	if (fru->data) {
	    ipmi_mem_free(fru->data);
	    fru->data = NULL;
	}
	fru->in_use = 0;
    }
    _ipmi_fru_unlock(fru);
}

int
ipmi_fru_write(ipmi_fru_t *fru, ipmi_fru_cb done, void *cb_data)
{
    int                      rv;
    start_domain_fru_write_t info = {fru, 0};

    if (!fru->ops.write)
	return ENOSYS;

    _ipmi_fru_lock(fru);
    if (fru->in_use) {
	/* Something else is happening with the FRU, error this
	   operation. */
	_ipmi_fru_unlock(fru);
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
    else {
	fru->in_use = 0;
	_ipmi_fru_unlock(fru);
    }

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

/************************************************************************
 *
 * FRU node handling
 *
 ************************************************************************/

int
ipmi_fru_get_root_node(ipmi_fru_t      *fru,
		       const char      **name,
		       ipmi_fru_node_t **node)
{
    if (!fru->ops.get_root_node)
	return ENOSYS;
    return fru->ops.get_root_node(fru, name, node);
}

struct ipmi_fru_node_s
{
    ipmi_lock_t                    *lock;
    unsigned int                   refcount;

    void                           *data;
    void                           *data2;
    ipmi_fru_oem_node_get_field_cb get_field;
    ipmi_fru_oem_node_set_field_cb set_field;
    ipmi_fru_oem_node_settable_cb  settable;
    ipmi_fru_oem_node_subtype_cb   get_subtype;
    ipmi_fru_oem_node_enum_val_cb  get_enum;
    ipmi_fru_oem_node_cb           destroy;
};

ipmi_fru_node_t *
_ipmi_fru_node_alloc(ipmi_fru_t *fru)
{
    ipmi_fru_node_t *node = ipmi_mem_alloc(sizeof(*node));
    int             rv;

    if (!node)
	return NULL;
    memset(node, 0, sizeof(*node));

    rv = ipmi_create_lock_os_hnd(fru->os_hnd, &node->lock);
    if (rv) {
	ipmi_mem_free(node);
	return NULL;
    }

    node->refcount = 1;
    return node;
}

void
ipmi_fru_get_node(ipmi_fru_node_t *node)
{
    ipmi_lock(node->lock);
    node->refcount++;
    ipmi_unlock(node->lock);
}

void
ipmi_fru_put_node(ipmi_fru_node_t *node)
{
    ipmi_lock(node->lock);
    if (node->refcount > 1) {
	node->refcount--;
	ipmi_unlock(node->lock);
	return;
    }
    ipmi_unlock(node->lock);

    if (node->destroy)
	node->destroy(node);
    ipmi_destroy_lock(node->lock);
    ipmi_mem_free(node);
}

int
ipmi_fru_node_get_field(ipmi_fru_node_t           *node,
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
    return node->get_field(node, index, name, dtype, intval, time,
			   floatval, data, data_len, sub_node);
}

int
ipmi_fru_node_set_field(ipmi_fru_node_t           *node,
			unsigned int              index,
			enum ipmi_fru_data_type_e dtype,
			int                       intval,
			time_t                    time,
			double                    floatval,
			char                      *data,
			unsigned int              data_len)
{
    if (!node->set_field)
	return ENOSYS;
    return node->set_field(node, index, dtype, intval, time,
			   floatval, data, data_len);
}

int
ipmi_fru_node_settable(ipmi_fru_node_t           *node,
		       unsigned int              index)
{
    if (!node->set_field)
	return ENOSYS;
    if (!node->settable)
	return 0;
    return node->settable(node, index);
}

int
ipmi_fru_node_get_subtype(ipmi_fru_node_t           *node,
			  enum ipmi_fru_data_type_e *dtype)
{
    if (!node->get_subtype)
	return ENOSYS;
    return node->get_subtype(node, dtype);
}

int
ipmi_fru_node_get_enum_val(ipmi_fru_node_t *node,
			   unsigned int    index,
			   int             *pos,
			   int             *nextpos,
			   const char      **data)
{
    if (!node->get_enum)
	return ENOSYS;
    return node->get_enum(node, index, pos, nextpos, data);
}

void *
_ipmi_fru_node_get_data(ipmi_fru_node_t *node)
{
    return node->data;
}

void
_ipmi_fru_node_set_data(ipmi_fru_node_t *node, void *data)
{
    node->data = data;
}

void *
_ipmi_fru_node_get_data2(ipmi_fru_node_t *node)
{
    return node->data2;
}

void
_ipmi_fru_node_set_data2(ipmi_fru_node_t *node, void *data2)
{
    node->data2 = data2;
}

void
_ipmi_fru_node_set_destructor(ipmi_fru_node_t      *node,
			      ipmi_fru_oem_node_cb destroy)
{
    node->destroy = destroy;
}

void
_ipmi_fru_node_set_get_field(ipmi_fru_node_t                *node,
			     ipmi_fru_oem_node_get_field_cb get_field)
{
    node->get_field = get_field;
}

void
_ipmi_fru_node_set_set_field(ipmi_fru_node_t                *node,
			     ipmi_fru_oem_node_set_field_cb set_field)
{
    node->set_field = set_field;
}

void
_ipmi_fru_node_set_settable(ipmi_fru_node_t               *node,
			    ipmi_fru_oem_node_settable_cb settable)
{
    node->settable = settable;
}

void
_ipmi_fru_node_set_get_subtype(ipmi_fru_node_t              *node,
			       ipmi_fru_oem_node_subtype_cb get_subtype)
{
    node->get_subtype = get_subtype;
}

void
_ipmi_fru_node_set_get_enum(ipmi_fru_node_t               *node,
			    ipmi_fru_oem_node_enum_val_cb get_enum)
{
    node->get_enum = get_enum;
}


/************************************************************************
 *
 * Misc external interfaces
 *
 ************************************************************************/

void *
_ipmi_fru_get_rec_data(ipmi_fru_t *fru)
{
    return fru->rec_data;
}

void
_ipmi_fru_set_rec_data(ipmi_fru_t *fru, void *rec_data)
{
    if (fru->rec_data && fru->ops.cleanup_recs)
	fru->ops.cleanup_recs(fru);
    fru->rec_data = rec_data;
}

char *
_ipmi_fru_get_iname(ipmi_fru_t *fru)
{
    return FRU_DOMAIN_NAME(fru);
}

unsigned int
_ipmi_fru_get_fetch_mask(ipmi_fru_t *fru)
{
    return fru->fetch_mask;
}

void *
_ipmi_fru_get_data_ptr(ipmi_fru_t *fru)
{
    return fru->data;
}
unsigned int
_ipmi_fru_get_data_len(ipmi_fru_t *fru)
{
    return fru->data_len;
}

int
_ipmi_fru_is_normal_fru(ipmi_fru_t *fru)
{
    return fru->normal_fru;
}

void
_ipmi_fru_set_is_normal_fru(ipmi_fru_t *fru, int val)
{
    fru->normal_fru = val;
}

/************************************************************************
 *
 * Init/shutdown
 *
 ************************************************************************/

int
_ipmi_fru_init(void)
{
    if (fru_decode_handlers)
	return 0;

    fru_decode_handlers = locked_list_alloc(ipmi_get_global_os_handler());
    if (!fru_decode_handlers)
	return ENOMEM;
    return 0;
}

void
_ipmi_fru_shutdown(void)
{
    if (fru_decode_handlers) {
	locked_list_destroy(fru_decode_handlers);
	fru_decode_handlers = NULL;
    }
}
