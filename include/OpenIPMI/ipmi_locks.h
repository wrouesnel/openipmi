/*
 * ipmi_locks.h
 *
 * MontaVista IPMI locking abstraction
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004 MontaVista Software Inc.
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

#ifndef _IPMI_LOCKS_H
#define _IPMI_LOCKS_H

#include <OpenIPMI/os_handler.h>

/* This is a generic lock used by the IPMI code. */
typedef struct ipmi_lock_s ipmi_lock_t;

/* Create a lock but us your own OS handlers. */
int ipmi_create_lock_os_hnd(os_handler_t *os_hnd, ipmi_lock_t **lock);

/* Destroy a lock. */
void ipmi_destroy_lock(ipmi_lock_t *lock);

/* Lock the lock.  Locks are recursive, so the same thread can claim
   the same lock multiple times, and must release it the same number
   of times. */
void ipmi_lock(ipmi_lock_t *lock);

/* Release the lock. */
void ipmi_unlock(ipmi_lock_t *lock);

/* Like the above locks, but read/write locks. */
typedef struct ipmi_rwlock_s ipmi_rwlock_t;
int ipmi_create_rwlock_os_hnd(os_handler_t *os_hnd, ipmi_rwlock_t **new_lock);
void ipmi_destroy_rwlock(ipmi_rwlock_t *lock);
void ipmi_rwlock_read_lock(ipmi_rwlock_t *lock);
void ipmi_rwlock_read_unlock(ipmi_rwlock_t *lock);
void ipmi_rwlock_write_lock(ipmi_rwlock_t *lock);
void ipmi_rwlock_write_unlock(ipmi_rwlock_t *lock);

#ifdef IPMI_CHECK_LOCKS
void ipmi_report_lock_error(os_handler_t *handler, char *str);
#define IPMI_REPORT_LOCK_ERROR(handler, str) ipmi_report_lock_error(handler, \
								    str)
#else
#define IPMI_REPORT_LOCK_ERROR(handler, str) do {} while (0)
#endif

extern int __ipmi_debug_locks;
#define DEBUG_LOCKS	(__ipmi_debug_locks)
#define DEBUG_LOCKS_ENABLE() __ipmi_debug_locks = 1
#define DEBUG_LOCKS_DISABLE() __ipmi_debug_locks = 0

#endif /* _IPMI_LOCKS_H */
