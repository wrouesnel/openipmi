
#include <errno.h>
#include <malloc.h>
#include "ui_keypad.h"


static int search_key(void *item, void *cb_data)
{
    struct key_entry *entry = item;
    int              *val = cb_data;

    return (entry->key == *val);
}

static struct key_entry *
find_key(ilist_iter_t *iter, keypad_t keypad, int key)
{
    int              hash = key % NUM_KEY_ENTRIES;
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
    int              hash = key % NUM_KEY_ENTRIES;
    ilist_iter_t     iter;
    struct key_entry *entry;

    if (find_key(&iter, keypad, key))
	return EEXIST;

    entry = malloc(sizeof(*entry));
    if (!entry)
	return ENOMEM;

    entry->key = key;
    entry->handler = handler;
    if (!ilist_add_tail(keypad->keys[hash], entry, NULL)) {
	free(entry);
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
    free(entry);
    return 0;
}

static void
del_key_entry(ilist_iter_t *iter, void *item, void *cb_data)
{
    ilist_delete(iter);
    free(item);
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
    free(keypad);
}

keypad_t
keypad_alloc(void)
{
    keypad_t nv = malloc(sizeof(*nv));
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

