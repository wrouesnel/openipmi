/*
 * ui_keypad.h
 *
 * MontaVista IPMI code, a simple curses UI keypad handler
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

#ifndef UI_KEYPAD_H
#define UI_KEYPAD_H

#include <OpenIPMI/internal/ilist.h>

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
