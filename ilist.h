/*
 * ilist.h
 *
 * Generic lists in C
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

#ifndef _ILIST_H
#define _ILIST_H

typedef struct ilist_s ilist_t;
typedef struct ilist_iter_s ilist_iter_t;

/* This is only so the user can supply their own data chunks for the
   list entries.  This is ugly, but it allows the user to pre-allocate
   (or allocate as part of the entry) the data for the list chunks,
   and avoid having to worry about error returns from the list
   operations. */
typedef struct ilist_item_s ilist_item_t;

/* Returns NULL on failure. */
ilist_t *alloc_ilist(void);
ilist_iter_t *alloc_ilist_iter(ilist_t *list);
void free_ilist(ilist_t *list);
void free_ilist_iter(ilist_iter_t *iter);

/* Returns true if the list is empty, false if not. */
int ilist_empty(ilist_t *list);

/* Return false on failure, true on success.  entry may be NULL,
   meaning you want the ilist code to supply the entry.  If you supply
   an entry, make sure to set the "malloced" flag correctly. */
int ilist_add_head(ilist_t *list, void *item, ilist_item_t *entry);
int ilist_add_tail(ilist_t *list, void *item, ilist_item_t *entry);
int ilist_add_before(ilist_iter_t *iter, void *item, ilist_item_t *entry);
int ilist_add_after(ilist_iter_t *iter, void *item, ilist_item_t *entry);

/* Return false on failure, true on success.  This will return a
   failure (false) if you try to position past the end of the array or
   try to set first or last on an empty array.  In that case it will
   leave the iterator unchanged. */
int ilist_first(ilist_iter_t *iter);
int ilist_last(ilist_iter_t *iter);
int ilist_next(ilist_iter_t *iter);
int ilist_prev(ilist_iter_t *iter);

/* Returns failue (false) if unpositioned. */
int ilist_delete(ilist_iter_t *iter); /* Position on next element after del */

/* Set unpositioned.  Next will go to the first item, prev to the last
   item. */
void ilist_unpositioned(ilist_iter_t *iter);

/* Returns NULL if unpositioned or list empty. */
void *ilist_get(ilist_iter_t *iter);

/* This should return true if the item matches, false if not. */
typedef int (*ilist_search_cb)(void *item, void *cb_data);

/* Search forward (starting at the next item) for something.  Returns
   NULL if not found, the item if found.  iter will be positioned on
   the item, too.  To search from the beginning, set the iterator to
   the "unpositioined" position. */
void *ilist_search_iter(ilist_iter_t *iter, ilist_search_cb cmp, void *cb_data);

/* Search from the beginning, but without an iterator.  This will return
   the first item found. */
void *ilist_search(ilist_t *list, ilist_search_cb cmp, void *cb_data);

/* Called with an iterator positioned on the item. */
typedef void (*ilist_iter_cb)(ilist_iter_t *iter, void *item, void *cb_data);

/* Call the given handler for each item in the list.  You may delete
   the current item the iterator references while this is happening,
   but no other items. */
void ilist_iter(ilist_t *list, ilist_iter_cb handler, void *cb_data);

/* Call the given handler for each item in the list, but run the list
   backwards.  You may delete the current item the iterator references
   while this is happening, but no other items. */
void ilist_iter_rev(ilist_t *list, ilist_iter_cb handler, void *cb_data);

/* Initialize a statically declared iterator. */
void ilist_init_iter(ilist_iter_t *iter, ilist_t *list);

/* Return -1 if item1 < item2, 0 if item1 == item2, and 1 if item1 > item2 */
typedef int (*ilist_sort_cb)(void *item1, void *item2);

void ilist_sort(ilist_t *list, ilist_sort_cb cmp);

/* Internal data structures, DO NOT USE THESE. */

struct ilist_item_s
{
    int malloced;
    ilist_item_t *next, *prev;
    void *item;
};

struct ilist_s
{
    ilist_item_t *head;
};

struct ilist_iter_s
{
    ilist_t      *list;
    ilist_item_t *curr;
};


/* You must define these. */
void *ilist_mem_alloc(size_t size);
void ilist_mem_free(void *data);

#endif /* _ILIST_H */
