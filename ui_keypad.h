
#ifndef UI_KEYPAD_H
#define UI_KEYPAD_H

#include "ilist.h"

typedef int (*key_handler_t)(int key, void *cb_data);

struct key_entry {
    int           key;
    key_handler_t handler;
};

#define NUM_KEY_ENTRIES 128
typedef struct {
    ilist_t *keys[NUM_KEY_ENTRIES];
} *keypad_t;

int keypad_handle_key(keypad_t keypad, int key, void *cb_data);
int keypad_bind_key(keypad_t keypad, int key, key_handler_t handler);
int keypad_unbind_key(keypad_t keypad, int key);
keypad_t keypad_alloc(void);
void keypad_free(keypad_t keypad);

#endif /* UI_KEYPAD_H */
