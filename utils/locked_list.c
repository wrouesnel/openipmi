/*
 * locked_list.c
 *
 * Code for building a locked list.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2004 MontaVista Software Inc.
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
    ipmi_lock_t         *lock;
    unsigned int        count;
    locked_list_entry_t head;
    locked_list_entry_t *destroy_list;
};

locked_list_t *
locked_list_alloc(os_handler_t *os_hnd)
{
    locked_list_t *ll;
    int           rv;

    ll = ipmi_mem_alloc(sizeof(*ll));
    rv = ipmi_create_lock_os_hnd(os_hnd, &ll->lock);
    if (rv) {
	ipmi_mem_free(ll);
	return NULL;
    }

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
    ipmi_destroy_lock(ll->lock);
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

    if (!entry)
	entry = ipmi_mem_alloc(sizeof(*entry));
    if (!entry)
	return 0;

    ipmi_lock(ll->lock);

    /* We don't allow duplicates. */
    if (internal_find(ll, item1, item2)) {
	ipmi_mem_free(entry);
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
    ipmi_unlock(ll->lock);
    return 1;
}

int
locked_list_add(locked_list_t *ll, void *item1, void *item2)
{
    locked_list_entry_t *entry = ipmi_mem_alloc(sizeof(*entry));

    if (!entry)
	return 0;
    locked_list_add_entry(ll, item1, item2, entry);
    return 1;
}

int
locked_list_remove(locked_list_t *ll, void *item1, void *item2)
{
    int                 rv;
    locked_list_entry_t *entry;

    ipmi_lock(ll->lock);

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

    ipmi_unlock(ll->lock);
    return rv;
}

void
locked_list_iterate(locked_list_t          *ll,
		    locked_list_handler_cb handler,
		    void                   *cb_data)
{
    int                 rv;
    locked_list_entry_t *entry;

    ipmi_lock(ll->lock);

    ll->cb_count++;
    entry = ll->head.next;
    while (entry != &ll->head) {
	if (!entry->destroyed)
	{
	    void *item1, *item2;

	    item1 = entry->item1;
	    item2 = entry->item2;
	    ipmi_unlock(ll->lock);
	    rv = handler(cb_data, item1, item2);
	    ipmi_lock(ll->lock);
	    if (rv)
		break;
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

    ipmi_unlock(ll->lock);
}

unsigned int
locked_list_num_entries(locked_list_t *ll)
{
    unsigned int rv;

    ipmi_lock(ll->lock);
    rv = ll->count;
    ipmi_unlock(ll->lock);
    return rv;
}

int
locked_list_search(locked_list_t *ll, void *item1, void *item2)
{
    int rv = 1;

    ipmi_lock(ll->lock);
    if (! internal_find(ll, item1, item2))
	rv = 0;
    ipmi_lock(ll->lock);
    return rv;
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
