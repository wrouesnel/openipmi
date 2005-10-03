/*
 * locked_list.c
 *
 * Code for building a locked list.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2004,2005 MontaVista Software Inc.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * Lesser General Public License (GPL) Version 2 or the modified BSD
 * license below.  The following disclamer applies to both licenses:
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
 * GNU Lesser General Public Licence
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Modified BSD Licence
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *   3. The name of the author may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 */

#include <string.h>

#include <OpenIPMI/internal/ipmi_locks.h>
#include <OpenIPMI/internal/ipmi_malloc.h>
#include <OpenIPMI/internal/locked_list.h>

#define LOCKED_LIST_ENTRIES_INCREMENT 5

struct locked_list_entry_s
{
    unsigned int destroyed;
    void *item1, *item2;
    locked_list_entry_t *next, *prev;
    locked_list_entry_t *dlist_next;
};

struct locked_list_s
{
    unsigned int        destroyed;
    unsigned int        cb_count;
    locked_list_lock_cb lock, unlock;
    void                *lock_cb_data;
    unsigned int        count;
    locked_list_entry_t head;
    locked_list_entry_t *destroy_list;
};

static void
ll_std_lock(void *cb_data)
{
    ipmi_lock_t *lock = cb_data;

    ipmi_lock(lock);
}

static void
ll_std_unlock(void *cb_data)
{
    ipmi_lock_t *lock = cb_data;

    ipmi_unlock(lock);
}

locked_list_t *
locked_list_alloc(os_handler_t *os_hnd)
{
    locked_list_t *ll;
    int           rv;
    ipmi_lock_t   *lock;

    ll = ipmi_mem_alloc(sizeof(*ll));
    if (!ll)
	return NULL;
    memset(ll, 0, sizeof(*ll));
    rv = ipmi_create_lock_os_hnd(os_hnd, &lock);
    if (rv) {
	ipmi_mem_free(ll);
	return NULL;
    }
    ll->lock = ll_std_lock;
    ll->unlock = ll_std_unlock;
    ll->lock_cb_data = lock;

    ll->destroyed = 0;
    ll->cb_count = 0;
    ll->count = 0;
    ll->destroy_list = NULL;
    ll->head.next = &ll->head;
    ll->head.prev = &ll->head;

    return ll;
}

locked_list_t *
locked_list_alloc_my_lock(locked_list_lock_cb lock_func,
			  locked_list_lock_cb unlock_func,
			  void                *lock_func_cb_data)
{
    locked_list_t *ll;

    ll = ipmi_mem_alloc(sizeof(*ll));
    if (!ll)
	return NULL;
    memset(ll, 0, sizeof(*ll));

    ll->lock = lock_func;
    ll->unlock = unlock_func;
    ll->lock_cb_data = lock_func_cb_data;

    ll->destroyed = 0;
    ll->cb_count = 0;
    ll->count = 0;
    ll->destroy_list = NULL;
    ll->head.next = &ll->head;
    ll->head.prev = &ll->head;

    return ll;
}

void
locked_list_destroy(locked_list_t *ll)
{
    locked_list_entry_t *entry, *next;

    entry = ll->head.next;
    while (entry != &ll->head) {
	next = entry->next;
	ipmi_mem_free(entry);
	entry = next;
    }
    if (ll->lock == ll_std_lock)
	ipmi_destroy_lock(ll->lock_cb_data);
    ipmi_mem_free(ll);
}

static locked_list_entry_t *
internal_find(locked_list_t *ll, void *item1, void *item2)
{
    locked_list_entry_t *entry;

    entry = ll->head.next;
    while (entry != &ll->head) {
	if ((!entry->destroyed)
	    && (entry->item1 == item1)
	    && (entry->item2 == item2))
	{
	    return entry;
	}
	entry = entry->next;
    }

    return NULL;
}

int
locked_list_add_entry(locked_list_t *ll, void *item1, void *item2,
		      locked_list_entry_t *entry)
{
    int rv = 1;
    if (!entry)
	entry = ipmi_mem_alloc(sizeof(*entry));
    if (!entry)
	return 0;

    ll->lock(ll->lock_cb_data);

    /* We don't allow duplicates. */
    if (internal_find(ll, item1, item2)) {
	ipmi_mem_free(entry);
	rv = 2;
	goto out_unlock;
    }

    entry->item1 = item1;
    entry->item2 = item2;
    entry->destroyed = 0;
    entry->next = &ll->head;
    entry->prev = ll->head.prev;
    entry->prev->next = entry;
    entry->next->prev = entry;
    ll->count++;

 out_unlock:
    ll->unlock(ll->lock_cb_data);
    return rv;
}

int
locked_list_add(locked_list_t *ll, void *item1, void *item2)
{
    return locked_list_add_entry(ll, item1, item2, NULL);
}

int
locked_list_add_entry_nolock(locked_list_t *ll, void *item1, void *item2,
			     locked_list_entry_t *entry)
{
    int rv = 1;
    if (!entry)
	entry = ipmi_mem_alloc(sizeof(*entry));
    if (!entry)
	return 0;

    /* We don't allow duplicates. */
    if (internal_find(ll, item1, item2)) {
	ipmi_mem_free(entry);
	rv = 2;
	goto out;
    }

    entry->item1 = item1;
    entry->item2 = item2;
    entry->destroyed = 0;
    entry->next = &ll->head;
    entry->prev = ll->head.prev;
    entry->prev->next = entry;
    entry->next->prev = entry;
    ll->count++;

 out:
    return rv;
}

int
locked_list_add_nolock(locked_list_t *ll, void *item1, void *item2)
{
    return locked_list_add_entry_nolock(ll, item1, item2, NULL);
}

int
locked_list_remove_nolock(locked_list_t *ll, void *item1, void *item2)
{
    int                 rv;
    locked_list_entry_t *entry;

    entry = internal_find(ll, item1, item2);
    if (!entry) {
	rv = 0;
    } else {
	rv = 1;
	ll->count--;
	if (ll->cb_count) {
	    /* We are in callbacks, just mark it destroyed and let the
	       last call back exit clear it up. */
	    entry->destroyed = 1;
	    entry->dlist_next = ll->destroy_list;
	    ll->destroy_list = entry;
	} else {
	    entry->next->prev = entry->prev;
	    entry->prev->next = entry->next;
	    ipmi_mem_free(entry);
	}
    }
    return rv;
}

int
locked_list_remove(locked_list_t *ll, void *item1, void *item2)
{
    int rv;
    ll->lock(ll->lock_cb_data);
    rv = locked_list_remove_nolock(ll, item1, item2);
    ll->unlock(ll->lock_cb_data);
    return rv;
}

void
locked_list_iterate_prefunc_nolock(locked_list_t          *ll,
				   locked_list_handler_cb prefunc,
				   locked_list_handler_cb handler,
				   void                   *cb_data)
{
    int                 rv;
    locked_list_entry_t *entry;

    ll->cb_count++;
    entry = ll->head.next;
    while (entry != &ll->head) {
	if (!entry->destroyed)
	{
	    void *item1, *item2;
	    int  process = 1;

	    item1 = entry->item1;
	    item2 = entry->item2;
	    if (prefunc) {
		rv = prefunc(cb_data, item1, item2);
		if (rv == LOCKED_LIST_ITER_SKIP)
		    process = 0;
		else if (rv)
		    break;
	    }
	    if (process && handler) {
		ll->unlock(ll->lock_cb_data);
		rv = handler(cb_data, item1, item2);
		ll->lock(ll->lock_cb_data);
		if (rv)
		    break;
	    }
	}
	entry = entry->next;
    }
    ll->cb_count--;

    /* If no one else is going through the list, clean up the
       destroyed entries. */
    if (ll->cb_count == 0) {
	while (ll->destroy_list) {
	    entry = ll->destroy_list;
	    ll->destroy_list = entry->dlist_next;
	    entry->next->prev = entry->prev;
	    entry->prev->next = entry->next;
	    ipmi_mem_free(entry);
	}
    }
}

void
locked_list_iterate_prefunc(locked_list_t          *ll,
			    locked_list_handler_cb prefunc,
			    locked_list_handler_cb handler,
			    void                   *cb_data)
{
    ll->lock(ll->lock_cb_data);
    locked_list_iterate_prefunc_nolock(ll, prefunc, handler, cb_data);
    ll->unlock(ll->lock_cb_data);
}

void
locked_list_iterate(locked_list_t          *ll,
		    locked_list_handler_cb handler,
		    void                   *cb_data)
{
    ll->lock(ll->lock_cb_data);
    locked_list_iterate_prefunc_nolock(ll, NULL, handler, cb_data);
    ll->unlock(ll->lock_cb_data);
}

void
locked_list_iterate_nolock(locked_list_t          *ll,
			   locked_list_handler_cb handler,
			   void                   *cb_data)
{
    locked_list_iterate_prefunc_nolock(ll, NULL, handler, cb_data);
}

unsigned int
locked_list_num_entries(locked_list_t *ll)
{
    unsigned int rv;

    ll->lock(ll->lock_cb_data);
    rv = ll->count;
    ll->unlock(ll->lock_cb_data);
    return rv;
}

unsigned int
locked_list_num_entries_nolock(locked_list_t *ll)
{
    return ll->count;
}

locked_list_entry_t *
locked_list_alloc_entry(void)
{
    return ipmi_mem_alloc(sizeof(locked_list_entry_t));
}

void
locked_list_free_entry(locked_list_entry_t *entry)
{
    ipmi_mem_free(entry);
}

void
locked_list_lock(locked_list_t *ll)
{
    ll->lock(ll->lock_cb_data);
}

void
locked_list_unlock(locked_list_t *ll)
{
    ll->unlock(ll->lock_cb_data);
}
