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
#include <OpenIPMI/ilist.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/locked_list.h>

typedef struct ll_entry_s
{
    int in_use;
    void *item1, *item2;
} ll_entry_t;

typedef struct ll_entries_s
{
    unsigned int size;
    unsigned int curr;
    ll_entry_t *entries;
} ll_entries_t;

struct locked_list_s
{
    os_handler_t *os_hnd;
    ipmi_lock_t  *lock;
    ilist_t      *list;
    ll_entries_t * volatile entries;
};

locked_list_t *
locked_list_alloc(os_handler_t *os_hnd)
{
    locked_list_t *ll;
    int           i;
    int           rv;

    ll = ipmi_mem_alloc(sizeof(*ll));
    rv = ipmi_create_lock_os_hnd(os_hnd, &ll->lock);
    if (rv) {
	ipmi_mem_free(ll);
	return NULL;
    }
    ll->list = alloc_ilist();
    if (!ll->list) {
	ipmi_destroy_lock(ll->lock);
	ipmi_mem_free(ll);
	return NULL;
    }

    ll->entries = ipmi_mem_alloc(sizeof(ll_entries_t));
    if (!ll->entries) {
	ilist_twoitem_destroy(ll->list);
	ipmi_destroy_lock(ll->lock);
	ipmi_mem_free(ll);
	return NULL;
    }

    ll->entries->entries = ipmi_mem_alloc(sizeof(ll_entry_t) * 10);
    if (!ll->entries->entries) {
	ipmi_mem_free(ll->entries);
	ilist_twoitem_destroy(ll->list);
	ipmi_destroy_lock(ll->lock);
	ipmi_mem_free(ll);
	return NULL;
    }

    ll->entries->size = 10;
    ll->entries->curr = 0;

    for (i=0; i<ll->entries->size; i++)
	ll->entries->entries[i].in_use = 0;

    return ll;
}

void
locked_list_destroy(locked_list_t *ll)
{
    ipmi_mem_free(ll->entries->entries);
    ipmi_mem_free(ll->entries);
    ilist_twoitem_destroy(ll->list);
    ipmi_destroy_lock(ll->lock);
    ipmi_mem_free(ll);
}

static int
internal_find(locked_list_t *ll, void *item1, void *item2)
{
    int i;

    for (i=0; i<ll->entries->size; i++) {
	if ((ll->entries->entries[ll->entries->curr].in_use)
	    && (ll->entries->entries[i].item1 == item1)
	    && (ll->entries->entries[i].item2 == item2))
	{
	    return i;
	}
    }

    return -1;
}

int
locked_list_add(locked_list_t *ll, void *item1, void *item2)
{
    int rv = 1;
    int i;

    ipmi_lock(ll->lock);

    /* We don't allow duplicates. */
    if (internal_find(ll, item1, item2) != -1)
	goto out_unlock;

    if (ll->entries->size == ll->entries->curr) {
	/* We have to expand the entries table. */
	ll_entries_t *new_entries;

	new_entries = ipmi_mem_alloc(sizeof(ll_entries_t));
	if (!new_entries) {
	    rv = 0;
	    goto out_unlock;
	}
	new_entries->entries = ipmi_mem_alloc(sizeof(ll_entry_t)
					      * ll->entries->size + 10);
	if (!new_entries->entries) {
	    ipmi_mem_free(new_entries);
	    rv = 0;
	    goto out_unlock;
	}

	new_entries->size = ll->entries->size + 10;
	new_entries->curr = ll->entries->curr;
	memcpy(new_entries->entries, ll->entries->entries,
	       sizeof(ll_entry_t) * ll->entries->size);

	ipmi_mem_free(ll->entries->entries);
	ipmi_mem_free(ll->entries);

	ll->entries = new_entries;

	ll->entries->entries[ll->entries->curr].in_use = 1;
	ll->entries->entries[ll->entries->curr].item1 = item1;
	ll->entries->entries[ll->entries->curr].item2 = item2;
	ll->entries->curr++;

	for (i=ll->entries->curr+1; i<ll->entries->size; i++)
	    ll->entries->entries[i].in_use = 0;
    } else {
	/* Room in the list, find a slot. */
	for (i=0; i<ll->entries->size; i++) {
	    if (! ll->entries->entries[ll->entries->curr].in_use)
		break;
	}

	ll->entries->entries[i].in_use = 1;
	ll->entries->entries[i].item1 = item1;
	ll->entries->entries[i].item2 = item2;
	ll->entries->curr++;
    }

 out_unlock:
    ipmi_unlock(ll->lock);
    return rv;
}

int
locked_list_remove(locked_list_t *ll, void *item1, void *item2)
{
    int i;
    int rv;

    ipmi_lock(ll->lock);

    i = internal_find(ll, item1, item2);
    if (i == -1) {
	rv = 0;
    } else {
	rv = 1;
	ll->entries->curr--;
	ll->entries->entries[i].in_use = 0;
    }

    ipmi_unlock(ll->lock);
    return rv;
}

void
locked_list_iterate(locked_list_t          *ll,
		    locked_list_handler_cb handler,
		    void                   *cb_data)
{
    ll_entries_t *entries;
    int          i;
    int          rv;

    ipmi_lock(ll->lock);

    entries = ll->entries;
    for (i=0; i<entries->size; i++) {
	void *item1, *item2;

	if (! entries->entries[i].in_use)
	    continue;

	item1 = entries->entries[i].item1;
	item2 = entries->entries[i].item2;
	ipmi_unlock(ll->lock);
	rv = handler(cb_data, item1, item2);
	ipmi_lock(ll->lock);
	if (rv)
	    break;
	entries = ll->entries;
    }

    ipmi_unlock(ll->lock);
}
