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
#include <string.h>

#include <OpenIPMI/ipmi_conn.h>

#include <OpenIPMI/internal/locked_list.h>
#include <OpenIPMI/internal/ipmi_oem.h>
#include <OpenIPMI/internal/ipmi_int.h>

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

ipmi_lock_t *oem_conn_handlers_lock = NULL;
static locked_list_t *oem_conn_handlers = NULL;

static int
oem_conn_handler_clean(void *cb_data, void *data1, void *data2)
{
    locked_list_remove(oem_conn_handlers, data1, data2);
    ipmi_mem_free(data1);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
cleanup_oem_conn_handlers(void)
{
    ipmi_lock(oem_conn_handlers_lock);
    locked_list_iterate(oem_conn_handlers, oem_conn_handler_clean, NULL);
    ipmi_unlock(oem_conn_handlers_lock);
}

int
ipmi_register_oem_conn_handler(unsigned int             manufacturer_id,
			       unsigned int             product_id,
			       ipmi_oem_conn_handler_cb handler,
			       void                     *cb_data)
{
    oem_conn_handlers_t *new_item;
    int                 rv;

    /* This might be called before initialization, so be 100% sure.. */
    rv = _ipmi_conn_init(ipmi_get_global_os_handler());
    if (rv)
	return rv;

    new_item = ipmi_mem_alloc(sizeof(*new_item));
    if (!new_item)
	return ENOMEM;

    new_item->manufacturer_id = manufacturer_id;
    new_item->product_id = product_id;
    new_item->handler = handler;
    new_item->cb_data = cb_data;

    if (locked_list_add(oem_conn_handlers, new_item, NULL))
	return 0;
    else {
	ipmi_mem_free(new_item);
	return ENOMEM;
    }

    return 0;
}

static int
oem_conn_handler_rm(void *cb_data, void *data1, void *data2)
{
    oem_conn_handlers_t *hndlr = data1;
    oem_conn_handlers_t *cmp = cb_data;

    if ((hndlr->manufacturer_id == cmp->manufacturer_id)
	&& (hndlr->product_id == cmp->product_id))
    {
	int *found = cmp->cb_data;

	*found = 1;
	locked_list_remove(oem_conn_handlers, data1, data2);
	ipmi_mem_free(data1);
	return LOCKED_LIST_ITER_STOP;
    } else 
	return LOCKED_LIST_ITER_CONTINUE;
}

int
ipmi_deregister_oem_conn_handler(unsigned int manufacturer_id,
				 unsigned int product_id)
{
    oem_conn_handlers_t tmp;
    int                 found = 0;

    tmp.manufacturer_id = manufacturer_id;
    tmp.product_id = product_id;
    tmp.cb_data = &found;
    ipmi_lock(oem_conn_handlers_lock);
    locked_list_iterate(oem_conn_handlers, oem_conn_handler_rm, &tmp);
    ipmi_unlock(oem_conn_handlers_lock);

    if (!found)
	return ENOENT;
    return 0;
}

static int
oem_conn_handler_cmp(void *cb_data, void *data1, void *data2)
{
    oem_conn_handlers_t      *hndlr = data1;
    oem_conn_handlers_t      *cmp = cb_data;
    ipmi_oem_conn_handler_cb handler;
    void                     *rcb_data;
    ipmi_con_t               *conn;
    int                      rv = EINVAL;

    if ((hndlr->manufacturer_id == cmp->manufacturer_id)
	&& (hndlr->product_id == cmp->product_id))
    {
	handler = hndlr->handler;
	rcb_data = hndlr->cb_data;
	conn = cmp->cb_data;
	ipmi_unlock(oem_conn_handlers_lock);
	rv = handler(conn, rcb_data);
	ipmi_lock(oem_conn_handlers_lock);
    }

    if (!rv)
	return LOCKED_LIST_ITER_STOP;
    else 
	return LOCKED_LIST_ITER_CONTINUE;
}

int
ipmi_check_oem_conn_handlers(ipmi_con_t   *conn,
			     unsigned int manufacturer_id,
			     unsigned int product_id)
{
    oem_conn_handlers_t tmp;

    tmp.manufacturer_id = manufacturer_id;
    tmp.product_id = product_id;
    tmp.cb_data = conn;
    ipmi_lock(oem_conn_handlers_lock);
    locked_list_iterate(oem_conn_handlers, oem_conn_handler_cmp, &tmp);
    ipmi_unlock(oem_conn_handlers_lock);
    return 0;
}

/***********************************************************************
 *
 * Handle global OEM callbacks new connections.
 *
 **********************************************************************/

static locked_list_t *oem_handlers;

int
ipmi_register_conn_oem_check(ipmi_conn_oem_check check,
			     void                *cb_data)
{
    if (locked_list_add(oem_handlers, check, cb_data))
	return 0;
    else
	return ENOMEM;
}

int
ipmi_deregister_conn_oem_check(ipmi_conn_oem_check check,
			       void                *cb_data)
{
    if (locked_list_remove(oem_handlers, check, cb_data))
	return 0;
    else
	return EINVAL;
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
    if (check->count == 0)
	done = 1;
    ipmi_unlock(check->lock);

    if (done) {
	ipmi_destroy_lock(check->lock);
	check->done(conn, check->cb_data);
	ipmi_mem_free(check);
    }
}

static int
conn_handler_call(void *cb_data, void *ihandler, void *data2)
{
    conn_check_oem_t    *check = cb_data;
    ipmi_conn_oem_check check_cb = ihandler;
    int                 rv;

    ipmi_lock(check->lock);
    check->count++;
    ipmi_unlock(check->lock);
    rv = check_cb(check->conn, data2, conn_oem_check_done, check);
    if (rv) {
	ipmi_lock(check->lock);
	check->count--;
	ipmi_unlock(check->lock);
    }
    return LOCKED_LIST_ITER_CONTINUE;
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

    rv = ipmi_create_lock_os_hnd(conn->os_hnd, &check->lock);
    if (rv)
	return rv;
    check->count = 1;
    check->conn = conn;
    check->done = done;
    check->cb_data = cb_data;

    locked_list_iterate(oem_handlers, conn_handler_call, check);

    ipmi_lock(check->lock);
    count = check->count;
    ipmi_unlock(check->lock);

    /* Say that this function is done with the check. */
    conn_oem_check_done(conn, check);

    return 0;
}

/***********************************************************************
 *
 * Handling anonmymous attributes for connections
 *
 **********************************************************************/

struct ipmi_con_attr_s
{
    char *name;
    void *data;

    ipmi_lock_t *lock;
    unsigned int refcount;

    ipmi_con_attr_kill_cb destroy;
    void                  *cb_data;
};

static int
destroy_attr(void *cb_data, void *item1, void *item2)
{
    ipmi_con_t      *con = cb_data;
    ipmi_con_attr_t *attr = item1;

    locked_list_remove(con->attr, item1, item2);
    ipmi_con_attr_put(attr);
    return LOCKED_LIST_ITER_CONTINUE;
}

typedef struct con_attr_cmp_s
{
    char            *name;
    ipmi_con_attr_t *attr;
} con_attr_cmp_t;

static int
con_attr_cmp(void *cb_data, void *item1, void *item2)
{
    con_attr_cmp_t  *info = cb_data;
    ipmi_con_attr_t *attr = item1;

    if (strcmp(info->name, attr->name) == 0) {
	info->attr = attr;
	return LOCKED_LIST_ITER_STOP;
    }

    return LOCKED_LIST_ITER_CONTINUE;
}

int
ipmi_con_register_attribute(ipmi_con_t            *con,
			    char                  *name,
			    ipmi_con_attr_init_cb init,
			    ipmi_con_attr_kill_cb destroy,
			    void                  *cb_data,
			    ipmi_con_attr_t       **attr)
{
    ipmi_con_attr_t     *val = NULL;
    con_attr_cmp_t      info;
    int                 rv = 0;
    locked_list_entry_t *entry;

    info.name = name;
    info.attr = NULL;
    locked_list_lock(con->attr);
    locked_list_iterate_nolock(con->attr, con_attr_cmp, &info);
    if (info.attr) {
	ipmi_lock(info.attr->lock);
	info.attr->refcount++;
	ipmi_unlock(info.attr->lock);
	*attr = info.attr;
	goto out_unlock;
    }

    val = ipmi_mem_alloc(sizeof(*val));
    if (!val) {
	rv = ENOMEM;
	goto out_unlock;
    }

    val->name = ipmi_strdup(name);
    if (!val->name) {
	ipmi_mem_free(val);
	rv = ENOMEM;
	goto out_unlock;
    }

    entry = locked_list_alloc_entry();
    if (!entry) {
	ipmi_mem_free(val->name);
	ipmi_mem_free(val);
	rv = ENOMEM;
	goto out_unlock;
    }

    rv = ipmi_create_lock_os_hnd(con->os_hnd, &val->lock);
    if (rv) {
	locked_list_free_entry(entry);
	ipmi_mem_free(val->name);
	ipmi_mem_free(val);
	goto out_unlock;
    }

    val->refcount = 2;
    val->destroy = destroy;
    val->cb_data = cb_data;
    val->data = NULL;

    if (init) {
	rv = init(con, cb_data, &val->data);
	if (rv) {
	    ipmi_destroy_lock(val->lock);
	    locked_list_free_entry(entry);
	    ipmi_mem_free(val->name);
	    ipmi_mem_free(val);
	    rv = ENOMEM;
	    goto out_unlock;
	}
    }

    locked_list_add_entry_nolock(con->attr, val, NULL, entry);

    *attr = val;

 out_unlock:
    locked_list_unlock(con->attr);
    return rv;
}
			       
int
ipmi_con_find_attribute(ipmi_con_t      *con,
			char             *name,
			ipmi_con_attr_t **attr)
{
    con_attr_cmp_t info;

    if (!con->attr)
	return EINVAL;

    /* Attributes are immutable, no lock is required. */
    info.name = name;
    info.attr = NULL;
    locked_list_iterate(con->attr, con_attr_cmp, &info);
    if (info.attr) {
	ipmi_lock(info.attr->lock);
	info.attr->refcount++;
	ipmi_unlock(info.attr->lock);
	*attr = info.attr;
	return 0;
    }
    return EINVAL;
}

void *
ipmi_con_attr_get_data(ipmi_con_attr_t *attr)
{
    return attr->data;
}

void
ipmi_con_attr_put(ipmi_con_attr_t *attr)
{
    ipmi_lock(attr->lock);
    attr->refcount--;
    if (attr->refcount > 0) {
	ipmi_unlock(attr->lock);
	return;
    }
    ipmi_unlock(attr->lock);
    if (attr->destroy)
	attr->destroy(attr->cb_data, attr->data);
    ipmi_destroy_lock(attr->lock);
    ipmi_mem_free(attr->name);
    ipmi_mem_free(attr);
}

int
ipmi_con_attr_init(ipmi_con_t *con)
{
    con->attr = locked_list_alloc(con->os_hnd);
    if (!con->attr)
	return ENOMEM;
    return 0;
}

void
ipmi_con_attr_cleanup(ipmi_con_t *con)
{
    if (con->attr) {
	locked_list_iterate(con->attr, destroy_attr, con);
	locked_list_destroy(con->attr);
	con->attr = NULL;
    }
}

/***********************************************************************
 *
 * Statistics interfaces
 *
 **********************************************************************/
struct ipmi_ll_stat_info_s
{
    ipmi_ll_con_add_stat_cb        adder;
    ipmi_ll_con_register_stat_cb   reg;
    ipmi_ll_con_unregister_stat_cb unreg;
    void                           *user_data;
};

ipmi_ll_stat_info_t *
ipmi_ll_con_alloc_stat_info(void)
{
    return ipmi_mem_alloc(sizeof(ipmi_ll_stat_info_t));
}

void
ipmi_ll_con_free_stat_info(ipmi_ll_stat_info_t *info)
{
    ipmi_mem_free(info);
}

void
ipmi_ll_con_stat_info_set_adder(ipmi_ll_stat_info_t     *info,
				ipmi_ll_con_add_stat_cb adder)
{
    info->adder = adder;
}

void
ipmi_ll_con_stat_info_set_register(ipmi_ll_stat_info_t          *info,
				   ipmi_ll_con_register_stat_cb reg)
{
    info->reg = reg;
}

void
ipmi_ll_con_stat_info_set_unregister(ipmi_ll_stat_info_t            *info,
				     ipmi_ll_con_unregister_stat_cb unreg)
{
    info->unreg = unreg;
}

void
ipmi_ll_con_stat_call_adder(ipmi_ll_stat_info_t *info,
			    void                *stat,
			    int                 count)
{
    info->adder(info, stat, count);
}

int
ipmi_ll_con_stat_call_register(ipmi_ll_stat_info_t *info,
			       const char          *name,
			       const char          *instance,
			       void                **stat)
{
    return info->reg(info, name, instance, stat);
}

void
ipmi_ll_con_stat_call_unregister(ipmi_ll_stat_info_t *info,
				 void                *stat)
{
    info->unreg(info, stat);
}

void
ipmi_ll_con_stat_set_user_data(ipmi_ll_stat_info_t *info,
			       void                *data)
{
    info->user_data = data;
}

void *
ipmi_ll_con_stat_get_user_data(ipmi_ll_stat_info_t *info)
{
    return info->user_data;
}

/***********************************************************************
 *
 * Init/shutdown
 *
 **********************************************************************/
int
_ipmi_conn_init(os_handler_t *os_hnd)
{
    int rv;

    if (!oem_conn_handlers_lock) {
	rv = ipmi_create_global_lock(&oem_conn_handlers_lock);
	if (rv)
	    return rv;
    }

    if (!oem_conn_handlers) {
	oem_conn_handlers = locked_list_alloc(os_hnd);
	if (!oem_conn_handlers)
	    return ENOMEM;
    }
    if (!oem_handlers) {
	oem_handlers = locked_list_alloc(os_hnd);
	if (!oem_handlers)
	    return ENOMEM;
    }
    return 0;
}

void
_ipmi_conn_shutdown(void)
{
    if (oem_conn_handlers) {
	cleanup_oem_conn_handlers();
	locked_list_destroy(oem_conn_handlers);
	oem_conn_handlers = NULL;
    }

    if (oem_handlers) {
	locked_list_destroy(oem_handlers);
	oem_handlers = NULL;
    }

    if (oem_conn_handlers_lock) {
	ipmi_destroy_lock(oem_conn_handlers_lock);
	oem_conn_handlers_lock = NULL;
    }
}
