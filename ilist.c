/*
 * ilist.
 *
 * Generic lists in C.
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
#include <errno.h>
#include "ilist.h"

ilist_t *
alloc_ilist(void)
{
    ilist_t *rv;

    rv = malloc(sizeof(*rv));
    if (!rv)
	return NULL;

    rv->head = malloc(sizeof(*(rv->head)));
    if (!rv->head) {
	free(rv);
	return NULL;
    }

    rv->head->malloced = 1;
    rv->head->next = rv->head;
    rv->head->prev = rv->head;

    return rv;
}

ilist_iter_t *
alloc_ilist_iter(ilist_t *list)
{
    ilist_iter_t *rv;

    rv = malloc(sizeof(*rv));
    if (!rv)
	return NULL;

    rv->list = list;
    rv->curr = list->head;

    return rv;
}

void free_ilist(ilist_t *list)
{
    ilist_item_t *curr, *next;

    curr = list->head->next;
    while (curr != list->head) {
	next = curr->next;
	if (curr->malloced)
	    free(curr);
	curr = next;
    }
    free(list->head);
    free(list);
}

void
free_ilist_iter(ilist_iter_t *iter)
{
    free(iter);
}

static int
add_after(ilist_item_t *pos, void *item, ilist_item_t *entry)
{
    ilist_item_t *new_item;

    if (entry) {
	new_item = entry;
    } else {
	new_item = malloc(sizeof(*new_item));
	if (!new_item)
	    return 0;
	new_item->malloced = 1;
    }

    new_item->item = item;
    new_item->next = pos->next;
    new_item->prev = pos;
    new_item->prev->next = new_item;
    new_item->next->prev = new_item;
    return 1;
}

static int
add_before(ilist_item_t *pos, void *item, ilist_item_t *entry)
{
    ilist_item_t *new_item;

    if (entry) {
	new_item = entry;
    } else {
	new_item = malloc(sizeof(*new_item));
	if (!new_item)
	    return 0;
	new_item->malloced = 1;
    }

    new_item->item = item;
    new_item->next = pos;
    new_item->prev = pos->prev;
    new_item->prev->next = new_item;
    new_item->next->prev = new_item;
    return 1;
}

int
ilist_add_head(ilist_t *list, void *item, ilist_item_t *entry)
{
    return add_after(list->head, item, entry);
}

int
ilist_add_tail(ilist_t *list, void *item, ilist_item_t *entry)
{
    return add_before(list->head, item, entry);
}

int
ilist_add_before(ilist_iter_t *iter, void *item, ilist_item_t *entry)
{
    return add_before(iter->curr, item, entry);
}

int 
ilist_add_after(ilist_iter_t *iter, void *item, ilist_item_t *entry)
{
    return add_after(iter->curr, item, entry);
}

int
ilist_empty(ilist_t *list)
{
    return list->head->next == list->head;
}

int
ilist_first(ilist_iter_t *iter)
{
    iter->curr = iter->list->head->next;
    if (iter->curr == iter->list->head)
	return 0;
    return 1;
}

int
ilist_last(ilist_iter_t *iter)
{
    iter->curr = iter->list->head->prev;
    if (iter->curr == iter->list->head)
	return 0;
    return 1;
}

int
ilist_next(ilist_iter_t *iter)
{
    if (iter->curr->next == iter->list->head)
	return 0;
    iter->curr = iter->curr->next;
    return 1;
}

int
ilist_prev(ilist_iter_t *iter)
{
    if (iter->curr->prev == iter->list->head)
	return 0;
    iter->curr = iter->curr->next;
    return 1;
}

void *
ilist_get(ilist_iter_t *iter)
{
    if (iter->curr == iter->list->head)
	return NULL;
    return iter->curr->item;
}

int
ilist_delete(ilist_iter_t *iter)
{
    ilist_item_t *curr;

    if (ilist_empty(iter->list))
	return 0;
    curr = iter->curr;
    curr->next->prev = curr->prev;
    curr->prev->next = curr->next;
    if (curr->malloced)
	free(curr);
    return 1;
}

void
ilist_unpositioned(ilist_iter_t *iter)
{
    iter->curr = iter->list->head;
}

void *
ilist_search_iter(ilist_iter_t *iter, ilist_search_cb cmp, void *cb_data)
{
    ilist_item_t *curr;

    curr = iter->curr->next;
    while (curr != iter->list->head) {
	if (cmp(curr->item, cb_data)) {
	    iter->curr = curr;
	    return curr->item;
	}
	curr = curr->next;
    }
    return NULL;
}

void *
ilist_search(ilist_t *list, ilist_search_cb cmp, void *cb_data)
{
    ilist_item_t *curr;

    curr = list->head->next;
    while (curr != list->head) {
	if (cmp(curr->item, cb_data)) {
	    return curr->item;
	}
	curr = curr->next;
    }
    return NULL;
}

void
ilist_iter(ilist_t *list, ilist_iter_cb handler, void *cb_data)
{
    ilist_item_t *curr;
    ilist_iter_t iter;

    iter.list = list;
    iter.curr = list->head->next;
    while (iter.curr != list->head) {
	curr = iter.curr;
	handler(&iter, curr->item, cb_data);
	if (iter.curr == curr)
	    iter.curr = curr->next;
    }
}

void
ilist_init_iter(ilist_iter_t *iter, ilist_t *list)
{
    iter->list = list;
    iter->curr = list->head->next;
}

void
ilist_sort(ilist_t *list, ilist_sort_cb cmp)
{
    ilist_item_t *curr, *next;
    int          changed = 1;

    if (ilist_empty(list))
	return;

    /* An improved bubble sort. */
    while (changed) {
	curr = list->head->next;
	changed = 0;
	while (curr->next != list->head) {
	    next = curr->next;
	    if (cmp(curr->item, next->item) > 0) {
		changed = 1;
		/* Swap the places of next and curr. */
		curr->prev->next = next;
		next->next->prev = curr;
		curr->next = next->next;
		next->prev = curr->prev;
		curr->prev = next;
		next->next = curr;
	    } else {
		curr = curr->next;
	    }
	}
    }
}

