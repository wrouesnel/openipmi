/*
 * ilist.c
 *
 * Generic lists in C.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004,2005 MontaVista Software Inc.
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

#include <stdlib.h>
#include <errno.h>

#include <OpenIPMI/internal/ilist.h>

ilist_t *
alloc_ilist(void)
{
    ilist_t *rv;

    rv = ilist_mem_alloc(sizeof(*rv));
    if (!rv)
	return NULL;

    rv->head = ilist_mem_alloc(sizeof(*(rv->head)));
    if (!rv->head) {
	ilist_mem_free(rv);
	return NULL;
    }

    rv->head->malloced = 1;
    rv->head->next = rv->head;
    rv->head->prev = rv->head;
    rv->head->item = NULL;

    return rv;
}

ilist_iter_t *
alloc_ilist_iter(ilist_t *list)
{
    ilist_iter_t *rv;

    rv = ilist_mem_alloc(sizeof(*rv));
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
	    ilist_mem_free(curr);
	curr = next;
    }
    ilist_mem_free(list->head);
    ilist_mem_free(list);
}

void
free_ilist_iter(ilist_iter_t *iter)
{
    ilist_mem_free(iter);
}

static int
add_after(ilist_item_t *pos, void *item, ilist_item_t *entry)
{
    ilist_item_t *new_item;

    if (entry) {
	new_item = entry;
	new_item->malloced = 0;
    } else {
	new_item = ilist_mem_alloc(sizeof(*new_item));
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
	new_item->malloced = 0;
    } else {
	new_item = ilist_mem_alloc(sizeof(*new_item));
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
    iter->curr = iter->curr->prev;
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
    iter->curr = curr->next;
    curr->next->prev = curr->prev;
    curr->prev->next = curr->next;
    if (curr->malloced)
	ilist_mem_free(curr);
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
    ilist_item_t *curr, *next;
    ilist_iter_t iter;

    iter.list = list;
    iter.curr = list->head->next;
    while (iter.curr != list->head) {
	curr = iter.curr;
	next = curr->next;
	handler(&iter, curr->item, cb_data);
	iter.curr = next;
    }
}

void
ilist_iter_rev(ilist_t *list, ilist_iter_cb handler, void *cb_data)
{
    ilist_item_t *curr, *prev;
    ilist_iter_t iter;

    iter.list = list;
    iter.curr = list->head->prev;
    while (iter.curr != list->head) {
	curr = iter.curr;
	prev = curr->prev;
	handler(&iter, curr->item, cb_data);
	iter.curr = prev;
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

void *
ilist_remove_first(ilist_t *list)
{
    ilist_item_t *curr;
    void         *item;

    if (ilist_empty(list))
	return NULL;

    curr = list->head->next;
    curr->next->prev = curr->prev;
    curr->prev->next = curr->next;
    item = curr->item;
    if (curr->malloced)
	ilist_mem_free(curr);
    return item;
}

void *
ilist_remove_last(ilist_t *list)
{
    ilist_item_t *curr;
    void         *item;

    if (ilist_empty(list))
	return NULL;

    curr = list->head->prev;
    curr->next->prev = curr->prev;
    curr->prev->next = curr->next;
    item = curr->item;
    if (curr->malloced)
	ilist_mem_free(curr);
    return item;
}

int
ilist_remove_item_from_list(ilist_t *list, void *item)
{
    ilist_item_t *curr;

    curr = list->head->next;
    while (curr != list->head) {
	if (curr->item == item)
	    break;
	curr = curr->next;
    }
    if (curr == list->head)
	return 0;

    curr->next->prev = curr->prev;
    curr->prev->next = curr->next;
    if (curr->malloced)
	ilist_mem_free(curr);
    return 1;
}

typedef struct ilist_twoitem_entry_s
{
    void         *cb_data1;
    void         *cb_data2;
    ilist_item_t entry;
} ilist_twoitem_entry_t;

static int twoitem_cmp(void *item, void *data)
{
    ilist_twoitem_entry_t *e = item;
    ilist_twoitem_entry_t *c = data;

    return ((e->cb_data1 == c->cb_data1) && (e->cb_data2 == c->cb_data2));
}

static int
find_twoitem(ilist_iter_t *iter, ilist_t *list, void *cb_data1, void *cb_data2)
{
    ilist_twoitem_entry_t *val, tmp = { cb_data1, cb_data2 };

    ilist_init_iter(iter, list);
    ilist_unpositioned(iter);
    val = ilist_search_iter(iter, twoitem_cmp, &tmp);
    return (val != NULL);
}

int
ilist_add_twoitem(ilist_t *list, void *cb_data1, void *cb_data2)
{
    ilist_twoitem_entry_t *entry;

    entry = ilist_mem_alloc(sizeof(*entry));
    if (!entry)
	return 0;
    entry->cb_data1 = cb_data1;
    entry->cb_data2 = cb_data2;

    ilist_add_tail(list, entry, &entry->entry);
    return 1;
}

int
ilist_remove_twoitem(ilist_t *list, void *cb_data1, void *cb_data2)
{
    ilist_iter_t          iter;
    ilist_twoitem_entry_t *entry;

    if (! find_twoitem(&iter, list, cb_data1, cb_data2))
	return 0;

    entry = ilist_get(&iter);
    ilist_delete(&iter);
    ilist_mem_free(entry);
    return 1;
}

int
ilist_twoitem_exists(ilist_t *list, void *cb_data1, void *cb_data2)
{
    ilist_iter_t     iter;

    if (! find_twoitem(&iter, list, cb_data1, cb_data2))
	return 0;

    return 1;
}

typedef struct twoitem_data_s
{
    ilist_twoitem_cb handler;
    void             *data;
} twoitem_data_t;

static void twoitem_iter(ilist_iter_t *iter, void *item, void *cb_data)
{
    ilist_twoitem_entry_t *entry = item;
    twoitem_data_t        *info = cb_data;

    info->handler(info->data, entry->cb_data1, entry->cb_data2);
}

void
ilist_iter_twoitem(ilist_t *list, ilist_twoitem_cb handler, void *data)
{
    twoitem_data_t info = { handler, data };
    ilist_iter(list, twoitem_iter, &info);
}

void
ilist_twoitem_destroy(ilist_t *list)
{
    ilist_iter_t          iter;
    ilist_twoitem_entry_t *entry;

    ilist_init_iter(&iter, list);
    while (ilist_first(&iter)) {
	entry = ilist_get(&iter);
	ilist_delete(&iter);
	ilist_mem_free(entry);
    }
    free_ilist(list);
}
