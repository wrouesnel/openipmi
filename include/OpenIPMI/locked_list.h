/*
 * locked_list.h
 *
 * A list that handles locking properly. 
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

#ifndef _LOCKED_LIST_H
#define _LOCKED_LIST_H

/*
 * This is a locked list structure that is multi-thread safe.  You can
 * add items and remove items while the list is being iterated, and
 * iterate by multiple threads simultaneously.  The handlers are
 * called without any locks being held.
 */

typedef struct locked_list_s locked_list_t;

/* The callback to the locked list iterator.  If it returns the
   CONTINUE value, iteration will continue.  If it returns the STOP
   value, iteration will not continue. */
#define LOCKED_LIST_ITER_CONTINUE	0
#define LOCKED_LIST_ITER_STOP		1
typedef int (*locked_list_handler_cb)(void *cb_data,
				      void *item1,
				      void *item2);

/* Allocate and free locked lists. */
locked_list_t *locked_list_alloc(os_handler_t *os_hnd);
void locked_list_destroy(locked_list_t *ll);

/* Add an item to the locked list.  If the item is a duplicate, this
   operation will be ignored.  It returns true if successful or false
   if memory could not be allocated. */
int locked_list_add(locked_list_t *ll, void *item1, void *item2);

/* Remove an item from the locked list.  It returns true if the item
   was found on the list and false if not. */
int locked_list_remove(locked_list_t *ll, void *item, void *item2);

/* Iterate over the items of the list. */
void locked_list_iterate(locked_list_t          *ll,
			 locked_list_handler_cb handler,
			 void                   *cb_data);

#endif /* _LOCKED_LIST_H */
