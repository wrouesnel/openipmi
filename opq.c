/*
 * opq.c
 *
 * Code for handling an operation queue.
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

#include <malloc.h>
#include <OpenIPMI/os_handler.h>
#include "ilist.h"
#include "opq.h"

typedef struct opq_elem_s
{
    int               block;
    opq_handler_cb    handler;
    void              *handler_data;
    opq_done_cb       done;
    void              *done_data;
    struct opq_elem_s *next;
} opq_elem_t;

struct opq_s
{
    ilist_t        *ops;
    os_hnd_lock_t  *lock;
    int            in_handler;
    os_handler_t   *os_hnd;
    opq_done_cb    done_handler;
    void           *done_data;
    int            blocked;
};

static void
opq_lock(opq_t *opq)
{
    if (opq->lock)
	opq->os_hnd->lock(opq->os_hnd, opq->lock);
}

static void
opq_unlock(opq_t *opq)
{
    if (opq->lock)
	opq->os_hnd->unlock(opq->os_hnd, opq->lock);
}

opq_t *
opq_alloc(os_handler_t *os_hnd)
{
    int   rv;
    opq_t *opq;

    opq = malloc(sizeof(*opq));
    if (!opq)
	return NULL;

    opq->os_hnd = os_hnd;
    opq->in_handler = 0;
    opq->ops = alloc_ilist();
    if (!(opq->ops)) {
	free(opq);
	return NULL;
    }

    if (os_hnd->create_lock) {
	rv = os_hnd->create_lock(opq->os_hnd, &(opq->lock));
	if (rv) {
	    free_ilist(opq->ops);
	    free(opq);
	    return NULL;
	}
    } else {
	opq->lock = NULL;
    }

    return opq;
}

static void
opq_destroy_item(ilist_iter_t *iter, void *item, void *cb_data)
{
    opq_elem_t *elem = (opq_elem_t *) item;

    elem->handler(elem->handler_data, 1);
    free(elem);
}

void
opq_destroy(opq_t *opq)
{
    ilist_iter(opq->ops, opq_destroy_item, NULL);
    free_ilist(opq->ops);
    if (opq->lock)
	opq->os_hnd->destroy_lock(opq->os_hnd, opq->lock);
    free(opq);
}

int
opq_new_op(opq_t *opq, opq_handler_cb handler, void *cb_data, int nowait)
{
    opq_elem_t *elem;

    opq_lock(opq);
    if (opq->in_handler) {
	if (nowait) {
	    opq_unlock(opq);
	    return -1;
	}
	elem = malloc(sizeof(*elem));
	if (!elem)
	    goto out_err;
	elem->handler = handler;
	elem->done = NULL;
	elem->handler_data = cb_data;
	elem->block = 1;
	if (! ilist_add_tail(opq->ops, elem, NULL)) {
	    free(elem);
	    goto out_err;
	}
	opq->blocked = 0;
	opq_unlock(opq);
    } else {
	opq->blocked = 0;
	opq->in_handler = 1;
	opq->done_handler = NULL;
	opq_unlock(opq);
	handler(cb_data, 0);
    }

    return 1;

 out_err:
    opq_unlock(opq);
    return 0;
}

int
opq_new_op_with_done(opq_t          *opq,
		     opq_handler_cb handler,
		     void           *handler_data,
		     opq_done_cb    done,
		     void           *done_data)
{
    opq_elem_t *elem;

    opq_lock(opq);
    if (opq->in_handler) {
	elem = malloc(sizeof(*elem));
	if (!elem)
	    goto out_err;
	elem->handler = handler;
	elem->handler_data = handler_data;
	elem->done = done;
	elem->done_data = done_data;
	elem->block = opq->blocked;
	if (! ilist_add_tail(opq->ops, elem, NULL)) {
	    free(elem);
	    goto out_err;
	}
	opq->blocked = 0;
	opq_unlock(opq);
    } else {
	opq->blocked = 0;
	opq->in_handler = 1;
	opq->done_handler = done;
	opq->done_data = done_data;
	opq_unlock(opq);
	handler(handler_data, 0);
    }

    return 1;

 out_err:
    opq_unlock(opq);
    return 0;
}

void
opq_add_block(opq_t *opq)
{
    opq_lock(opq);
    opq->blocked = 1;
    opq_unlock(opq);
}

void
opq_op_done(opq_t *opq)
{
    ilist_iter_t   iter;
    opq_elem_t     *elem;
    opq_elem_t     *list = NULL;
    opq_elem_t     *next;
    opq_elem_t     **list_end = &list;
    opq_done_cb    done_handler;
    void           *done_data;

    /* First check for done handlers. */
    opq_lock(opq);
    ilist_init_iter(&iter, opq->ops);
    ilist_first(&iter);
    elem = ilist_get(&iter);
    while (elem && (!elem->block)) {
	ilist_delete(&iter);
	elem->next = NULL;
	*list_end = elem;
	list_end = &(elem->next);
	elem = ilist_get(&iter);
    }
    done_handler = opq->done_handler;
    done_data = opq->done_data;
    opq->done_handler = NULL;
    if (done_handler || list) {
	/* There are done handlers to call, unlock and call them. */
	opq_unlock(opq);

	if (done_handler)
	    done_handler(done_data, 0);
	while (list) {
	    next = list->next;
	    list->done(list->done_data, 0);
	    free(list);
	    list = next;
	}

	opq_lock(opq);
	/* During the time we were unlocked, handlers may have been
           added. */
	ilist_first(&iter);
	elem = ilist_get(&iter);
    }
    if (elem) {
	ilist_delete(&iter);
	opq->done_handler = elem->done;
	opq->done_data = elem->done_data;
	opq_unlock(opq);
	elem->handler(elem->handler_data, 0);
	free(elem);
    } else {
	/* The list is empty. */
	opq->in_handler = 0;
	opq_unlock(opq);
    }
}

int
opq_stuff_in_progress(opq_t *opq)
{
    return opq->in_handler;
}
