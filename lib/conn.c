/*
 * conn.c
 *
 * MontaVista IPMI support for connections
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
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

#include <errno.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_oem.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ilist.h>

/***********************************************************************
 *
 * Handle global OEM callbacks for new MCs.
 *
 **********************************************************************/

typedef struct oem_conn_handlers_s {
    unsigned int             manufacturer_id;
    unsigned int             product_id;
    ipmi_oem_conn_handler_cb handler;
    void                     *cb_data;
} oem_conn_handlers_t;
/* FIXME - do we need a lock?  Probably, add it. */
static ilist_t *oem_conn_handlers = NULL;

int
ipmi_register_oem_conn_handler(unsigned int             manufacturer_id,
			       unsigned int             product_id,
			       ipmi_oem_conn_handler_cb handler,
			       void                     *cb_data)
{
    oem_conn_handlers_t *new_item;
    int                 rv;

    /* This might be called before initialization, so be 100% sure.. */
    rv = _ipmi_conn_init();
    if (rv)
	return rv;

    new_item = ipmi_mem_alloc(sizeof(*new_item));
    if (!new_item)
	return ENOMEM;

    new_item->manufacturer_id = manufacturer_id;
    new_item->product_id = product_id;
    new_item->handler = handler;
    new_item->cb_data = cb_data;

    if (! ilist_add_tail(oem_conn_handlers, new_item, NULL)) {
	ipmi_mem_free(new_item);
	return ENOMEM;
    }

    return 0;
}

static int
oem_conn_handler_cmp(void *item, void *cb_data)
{
    oem_conn_handlers_t *hndlr = item;
    oem_conn_handlers_t *cmp = cb_data;

    return ((hndlr->manufacturer_id == cmp->manufacturer_id)
	    && (hndlr->product_id == cmp->product_id));
}

int
ipmi_deregister_oem_conn_handler(unsigned int manufacturer_id,
				 unsigned int product_id)
{
    oem_conn_handlers_t *hndlr;
    oem_conn_handlers_t tmp;
    ilist_iter_t        iter;

    tmp.manufacturer_id = manufacturer_id;
    tmp.product_id = product_id;
    ilist_init_iter(&iter, oem_conn_handlers);
    ilist_unpositioned(&iter);
    hndlr = ilist_search_iter(&iter, oem_conn_handler_cmp, &tmp);
    if (hndlr) {
	ilist_delete(&iter);
	ipmi_mem_free(hndlr);
	return 0;
    }
    return ENOENT;
}

int
ipmi_check_oem_conn_handlers(ipmi_con_t   *conn,
			     unsigned int manufacturer_id,
			     unsigned int product_id)
{
    oem_conn_handlers_t *hndlr;
    oem_conn_handlers_t tmp;

    tmp.manufacturer_id = manufacturer_id;
    tmp.product_id = product_id;
    hndlr = ilist_search(oem_conn_handlers, oem_conn_handler_cmp, &tmp);
    if (hndlr)
	return hndlr->handler(conn, hndlr->cb_data);
    return 0;
}

/***********************************************************************
 *
 * Handle global OEM callbacks new connections.
 *
 **********************************************************************/

static ipmi_rwlock_t *oem_handlers_lock;
static ilist_t *oem_handlers;

int
ipmi_register_conn_oem_check(ipmi_conn_oem_check check,
			     void                *cb_data)
{
    int rv = 0;

    ipmi_rwlock_write_lock(oem_handlers_lock);
    if (ilist_twoitem_exists(oem_handlers, check, cb_data)) {
	rv = EADDRINUSE;
	goto out_unlock;
    }
    if (! ilist_add_twoitem(oem_handlers, check, cb_data)) {
	rv = ENOMEM;
	goto out_unlock;
    }
 out_unlock:
    ipmi_rwlock_write_unlock(oem_handlers_lock);
    return rv;
}

int
ipmi_deregister_conn_oem_check(ipmi_conn_oem_check check,
			       void                *cb_data)
{
    int rv = 0;

    ipmi_rwlock_write_lock(oem_handlers_lock);
    if (! ilist_remove_twoitem(oem_handlers, check, cb_data))
	rv = ENOENT;
    ipmi_rwlock_write_unlock(oem_handlers_lock);
    return rv;
}

typedef struct conn_check_oem_s
{
    ipmi_con_t               *conn;
    volatile unsigned int    count;
    ipmi_lock_t              *lock;
    ipmi_conn_oem_check_done done;
    void                     *cb_data;
} conn_check_oem_t;

static void
conn_oem_check_done(ipmi_con_t *conn,
		    void       *cb_data)
{
    conn_check_oem_t *check = cb_data;
    int              done = 0;

    ipmi_lock(check->lock);
    check->count--;
    if (check->count == 0) {
	done = 1;
    }
    ipmi_unlock(check->lock);

    if (done) {
	check->done(conn, check->cb_data);
	ipmi_mem_free(check);
    }
}

static void
conn_handler_call(void *data, void *ihandler, void *cb_data)
{
    conn_check_oem_t    *check = data;
    ipmi_conn_oem_check check_cb = ihandler;
    int                 rv;

    rv = check_cb(check->conn, conn_oem_check_done, cb_data);
    if (!rv)
	check->count++;
}

int
ipmi_conn_check_oem_handlers(ipmi_con_t               *conn,
			     ipmi_conn_oem_check_done done,
			     void                     *cb_data)
{
    conn_check_oem_t *check;
    int              rv;
    unsigned int     count = 0;

    check = ipmi_mem_alloc(sizeof(*check));
    if (!check)
	return ENOMEM;

    ipmi_rwlock_read_lock(oem_handlers_lock);
    rv = ipmi_create_lock_os_hnd(conn->os_hnd, &check->lock);
    if (rv)
	goto out_unlock;
    check->count = 0;
    check->conn = conn;
    check->done = done;
    check->cb_data = cb_data;

    ipmi_lock(check->lock);
    ilist_iter_twoitem(oem_handlers, conn_handler_call, check);
    count = check->count;
    ipmi_unlock(check->lock);

    ipmi_rwlock_read_unlock(oem_handlers_lock);

    if (count == 0) {
	check->done(conn, check->cb_data);
	ipmi_mem_free(check);
    }

    return 0;

 out_unlock:
    ipmi_rwlock_read_unlock(oem_handlers_lock);
    return rv;
}

/***********************************************************************
 *
 * Init/shutdown
 *
 **********************************************************************/
int
_ipmi_conn_init(void)
{
    int rv;

    if (!oem_conn_handlers) {
	oem_conn_handlers = alloc_ilist();
	if (!oem_conn_handlers)
	    return ENOMEM;
    }
    if (!oem_handlers) {
	oem_handlers = alloc_ilist();
	if (!oem_handlers)
	    return ENOMEM;
    }
    if (!oem_handlers_lock) {
	rv = ipmi_create_global_rwlock(&oem_handlers_lock);
	if (rv)
	    return rv;
    }
    return 0;
}

void
_ipmi_conn_shutdown(void)
{
    if (oem_conn_handlers) {
	oem_conn_handlers_t *hndlr;
	ilist_iter_t        iter;

	/* Destroy the members of the OEM list. */
	ilist_init_iter(&iter, oem_conn_handlers);
	while (ilist_first(&iter)) {
	    hndlr = ilist_get(&iter);
	    ilist_delete(&iter);
	    ipmi_mem_free(hndlr);
	}

	free_ilist(oem_conn_handlers);
	oem_conn_handlers = NULL;
    }
}

