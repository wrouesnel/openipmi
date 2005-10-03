/*
 * locks.c
 *
 * Code for abstracting locks in IPMI
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2004,2005 MontaVista Software Inc.
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

#include <OpenIPMI/ipmi_debug.h>

#include <OpenIPMI/internal/ipmi_malloc.h>
#include <OpenIPMI/internal/ipmi_locks.h>

struct ipmi_lock_s
{
    os_hnd_lock_t *ll_lock;
    os_handler_t  *os_hnd;
};

int __ipmi_debug_locks = 0;

int
ipmi_create_lock_os_hnd(os_handler_t *os_hnd, ipmi_lock_t **new_lock)
{
    ipmi_lock_t *lock;
    int         rv;

    lock = ipmi_mem_alloc(sizeof(*lock));
    if (!lock)
	return ENOMEM;

    lock->os_hnd = os_hnd;
    if (lock->os_hnd && lock->os_hnd->create_lock) {
	rv = lock->os_hnd->create_lock(lock->os_hnd, &(lock->ll_lock));
	if (rv) {
	    ipmi_mem_free(lock);
	    return rv;
	}
    } else {
	lock->ll_lock = NULL;
    }

    *new_lock = lock;

    return 0;
}

void ipmi_destroy_lock(ipmi_lock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->destroy_lock(lock->os_hnd, lock->ll_lock);
    ipmi_mem_free(lock);
}

void ipmi_lock(ipmi_lock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->lock(lock->os_hnd, lock->ll_lock);
}

void ipmi_unlock(ipmi_lock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->unlock(lock->os_hnd, lock->ll_lock);
}

struct ipmi_rwlock_s
{
    os_hnd_rwlock_t *ll_lock;
    os_handler_t  *os_hnd;
};

int
ipmi_create_rwlock_os_hnd(os_handler_t *os_hnd, ipmi_rwlock_t **new_lock)
{
    ipmi_rwlock_t *lock;
    int         rv;

    lock = ipmi_mem_alloc(sizeof(*lock));
    if (!lock)
	return ENOMEM;

    lock->os_hnd = os_hnd;
    if (lock->os_hnd && lock->os_hnd->create_lock) {
	rv = lock->os_hnd->create_rwlock(lock->os_hnd, &(lock->ll_lock));
	if (rv) {
	    ipmi_mem_free(lock);
	    return rv;
	}
    } else {
	lock->ll_lock = NULL;
    }

    *new_lock = lock;

    return 0;
}

void ipmi_destroy_rwlock(ipmi_rwlock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->destroy_rwlock(lock->os_hnd, lock->ll_lock);
    ipmi_mem_free(lock);
}

void ipmi_rwlock_read_lock(ipmi_rwlock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->read_lock(lock->os_hnd, lock->ll_lock);
}

void ipmi_rwlock_read_unlock(ipmi_rwlock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->read_unlock(lock->os_hnd, lock->ll_lock);
}

void ipmi_rwlock_write_lock(ipmi_rwlock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->write_lock(lock->os_hnd, lock->ll_lock);
}

void ipmi_rwlock_write_unlock(ipmi_rwlock_t *lock)
{
    if (lock->ll_lock)
	lock->os_hnd->write_unlock(lock->os_hnd, lock->ll_lock);
}

#ifdef IPMI_CHECK_LOCKS
/* Set a breakpoint here to detect locking errors. */
void
ipmi_report_lock_error(os_handler_t *handler, char *str)
{
    handler->log(handler, IPMI_LOG_WARNING, "%s", str);
}

void
ipmi_check_lock(ipmi_lock_t *lock, char *str)
{
    if ((!DEBUG_LOCKS) || (!lock) || (!lock->ll_lock))
	return;

    if (! lock->os_hnd->is_locked(lock->os_hnd, lock->ll_lock))
	IPMI_REPORT_LOCK_ERROR(lock->os_hnd, str);
}
#endif
