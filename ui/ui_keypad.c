/*
 * ui_keypad.c
 *
 * MontaVista IPMI code, a simple curses UI keypad handler
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
#include "ui_keypad.h"

#include <OpenIPMI/internal/ilist.h>
#include <OpenIPMI/internal/ipmi_malloc.h>

static int search_key(void *item, void *cb_data)
{
    struct key_entry *entry = item;
    int              *val = cb_data;

    return (entry->key == *val);
}

static struct key_entry *
find_key(ilist_iter_t *iter, keypad_t keypad, int key)
{
    int              hash = ((unsigned int) key) % NUM_KEY_ENTRIES;
    struct key_entry *entry;

    ilist_init_iter(iter, keypad->keys[hash]);
    ilist_unpositioned(iter);
    entry = ilist_search_iter(iter, search_key, &key);
    return entry;
}

int
keypad_handle_key(keypad_t keypad, int key, void *cb_data)
{
    ilist_iter_t     iter;
    struct key_entry *entry;

    entry = find_key(&iter, keypad, key);
    if (!entry)
	return ENOENT;

    return entry->handler(key, cb_data);
}

int
keypad_bind_key(keypad_t keypad, int key, key_handler_t handler)
{
    int              hash = ((unsigned int) key) % NUM_KEY_ENTRIES;
    ilist_iter_t     iter;
    struct key_entry *entry;

    if (find_key(&iter, keypad, key))
	return EEXIST;

    entry = ipmi_mem_alloc(sizeof(*entry));
    if (!entry)
	return ENOMEM;

    entry->key = key;
    entry->handler = handler;
    if (!ilist_add_tail(keypad->keys[hash], entry, NULL)) {
	ipmi_mem_free(entry);
	return ENOMEM;
    }

    return 0;
}

int
keypad_unbind_key(keypad_t keypad, int key)
{
    ilist_iter_t     iter;
    struct key_entry *entry;

    entry = find_key(&iter, keypad, key);
    if (!entry)
	return ENOENT;

    ilist_delete(&iter);
    ipmi_mem_free(entry);
    return 0;
}

static void
del_key_entry(ilist_iter_t *iter, void *item, void *cb_data)
{
    ilist_delete(iter);
    ipmi_mem_free(item);
}

void
keypad_free(keypad_t keypad)
{
    int i;

    for (i=0; i<NUM_KEY_ENTRIES; i++) {
	if (keypad->keys[i]) {
	    ilist_iter(keypad->keys[i], del_key_entry, NULL);
	    free_ilist(keypad->keys[i]);
	}
    }
    ipmi_mem_free(keypad);
}

keypad_t
keypad_alloc(void)
{
    keypad_t nv = ipmi_mem_alloc(sizeof(*nv));
    int      i;

    if (nv) {
	memset(nv, 0, sizeof(*nv));
	for (i=0; i<NUM_KEY_ENTRIES; i++) {
	    nv->keys[i] = alloc_ilist();
	    if (!nv->keys[i])
		goto out_err;
	}
    }

    return nv;

 out_err:
    keypad_free(nv);
    return NULL;
}

