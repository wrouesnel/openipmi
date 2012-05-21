/*
 * os_handler.c
 *
 * MontaVista IPMI os handler tools.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2006 MontaVista Software Inc.
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
#include <string.h>
#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/internal/ipmi_malloc.h>
#include <errno.h>


/*
 * This code is subtle, be careful.
 *
 * We handle three basic modes here:
 *
 *   * single-threaded OS handler
 *   * multi-threaded OS handler, multi-threaded (num_threads > 0)
 *   * multi-threaded OS handler, single threaded support (num_threads == 0)
 *     (multi-single mode)
 *
 * Single threaded OS handler is simple.  We just run the event loop
 * until the wait condition is done.
 *
 * Full multi-threaded mode is simple, too.  We allocate threads to
 * run the event loop, then we use condition variables to operate.
 *
 * Multi-single mode is not simple.  You can't just run the event
 * loop.  Another thread may be running the event loop, too, and thus
 * handle the particular operation that frees up our event loop (thus
 * we will still be stuck waiting in our event loop).  We can't have
 * another thread arbitrarily run the event loop, as we need to
 * support single-threaded system.
 *
 * So what we do is allocate a single thread.  It runs the event loop
 * *only when something is waiting*.  Thus we are single-threaded if
 * the app is single threaded.  But since condition variables are used
 * for wakeups, we can support multi-threaded applications properly.
 */


struct os_handler_waiter_factory_s
{
    os_handler_t  *os_hnd;
    unsigned int  num_threads;
    int           thread_priority;
    int           has_threads;

    os_hnd_lock_t *lock;
    os_hnd_cond_t *cond;

    /* Number of currently running threads. */
    unsigned int  thread_count;

    /* Number of wait structures we have out for this factory. */
    unsigned int  num_waiters;

    /* Tells the main thread to stop. */
    volatile int  stop_threads;

    /* Number of single-thread users. */
    unsigned int  single_thread_use_count;
    os_hnd_cond_t *single_thread_cond;
};

struct os_handler_waiter_s
{
    os_handler_waiter_factory_t *factory;

    os_hnd_lock_t *lock;
    os_hnd_cond_t *cond;

    /* Am I using multi-single mode and waiting? */
    int is_single;

    unsigned int count;
};

/* This is a normal event loop thread for full multi-threaded mode. */
static void
waiter_thread(void *data)
{
    os_handler_waiter_factory_t *factory = data;
    os_handler_t                *os_hnd = factory->os_hnd;

    while (!factory->stop_threads) {
	struct timeval tv = { 1, 0 };
	os_hnd->perform_one_op(os_hnd, &tv);
    }

    os_hnd->lock(os_hnd, factory->lock);
    factory->thread_count--;
    if (factory->thread_count == 0)
	os_hnd->cond_wake(os_hnd, factory->cond);
    os_hnd->unlock(os_hnd, factory->lock);
}

/* Event loop thread for multi-single mode.  Subtle, be careful and
   read the comments. */
static void
single_waiter_thread(void *data)
{
    os_handler_waiter_factory_t *factory = data;
    os_handler_t                *os_hnd = factory->os_hnd;

    os_hnd->lock(os_hnd, factory->lock);
    while (!factory->stop_threads) {
	/* While things are waiting, run out thread.  This is subtle
	   here.  If we are truely single-threaded, the thing that
	   releases the wait is going to be running from this thread.
	   This single_thread_use_count will be set to zero before
	   returning from perform_one_op, and we just quit and wait to
	   be woken again and won't call more event loop operations.
	   If we are not single-threaded (the app is multi-threaded)
	   we still run from here, but the app better be ready for
	   multi-threaded operation. */
	while (factory->single_thread_use_count) {
	    struct timeval tv = { 1, 0 };
	    os_hnd->unlock(os_hnd, factory->lock);
	    os_hnd->perform_one_op(os_hnd, &tv);
	    os_hnd->lock(os_hnd, factory->lock);
	}

	/* Wait for someone to tell us there are more event to run */
	os_hnd->cond_wait(os_hnd, factory->single_thread_cond, factory->lock);
    }

    factory->thread_count--;
    if (factory->thread_count == 0)
	os_hnd->cond_wake(os_hnd, factory->cond);
    os_hnd->unlock(os_hnd, factory->lock);
}

extern int ipmi_malloc_init(os_handler_t *os_hnd);

int
os_handler_alloc_waiter_factory(os_handler_t *os_hnd,
				unsigned int num_threads,
				int          thread_priority,
				os_handler_waiter_factory_t **factory)
{
    os_handler_waiter_factory_t *nf;
    int                         rv;
    unsigned int                i;
    int                         has_threads = 0;

    ipmi_malloc_init(os_hnd);

    if (os_hnd->create_lock && os_hnd->create_cond
	&& os_hnd->create_thread)
	has_threads = 1;

    if ((num_threads > 0) && !has_threads) {
	/* Asked for threads, but handler doesn't support them. */
	return ENOSYS;
    }

    nf = ipmi_mem_alloc(sizeof(*nf));
    if (!nf)
	return ENOMEM;
    memset(nf, 0, sizeof(*nf));

    nf->has_threads = has_threads;
    nf->os_hnd = os_hnd;
    nf->thread_priority = thread_priority;
    nf->num_threads = num_threads;

    if (has_threads) {
	rv = os_hnd->create_lock(os_hnd, &nf->lock);
	if (rv) {
	    ipmi_mem_free(nf);
	    return rv;
	}

	rv = os_hnd->create_cond(os_hnd, &nf->cond);
	if (rv) {
	    os_hnd->destroy_lock(os_hnd, nf->lock);
	    ipmi_mem_free(nf);
	    return rv;
	}
    }

    if (num_threads > 0) {
	for (i=0; i<num_threads; i++) {
	    nf->thread_count++;
	    rv = os_hnd->create_thread(os_hnd, thread_priority,
				       waiter_thread, nf);
	    if (rv) {
		nf->thread_count--;
		os_handler_free_waiter_factory(nf);
		return rv;
	    }
	}
    } else if (has_threads) {
	rv = os_hnd->create_cond(os_hnd, &nf->single_thread_cond);
	if (rv) {
	    os_handler_free_waiter_factory(nf);
	    return rv;
	}

	nf->thread_count++;
	rv = os_hnd->create_thread(os_hnd, thread_priority,
				   single_waiter_thread, nf);
	if (rv) {
	    nf->thread_count--;
	    os_handler_free_waiter_factory(nf);
	    return rv;
	}
    }

    *factory = nf;

    return 0;
}

int
os_handler_free_waiter_factory(os_handler_waiter_factory_t *factory)
{
    os_handler_t *os_hnd = factory->os_hnd;

    if (factory->lock)
	os_hnd->lock(os_hnd, factory->lock);

    if (factory->stop_threads)
	return EINVAL;
    if (factory->num_waiters > 0)
	return EAGAIN;

    if (factory->thread_count > 0) {
	factory->stop_threads = 1;
	if (factory->single_thread_cond)
	    os_hnd->cond_wake(os_hnd, factory->single_thread_cond);
	os_hnd->cond_wait(os_hnd, factory->cond, factory->lock);
    }

    if (factory->has_threads) {
	os_hnd->unlock(os_hnd, factory->lock);
	os_hnd->destroy_lock(os_hnd, factory->lock);
	os_hnd->destroy_cond(os_hnd, factory->cond);
    }
    if (factory->single_thread_cond)
	os_hnd->destroy_cond(os_hnd, factory->single_thread_cond);

    ipmi_mem_free(factory);
    return 0;
}

os_handler_waiter_t *
os_handler_alloc_waiter(os_handler_waiter_factory_t *factory)
{
    os_handler_waiter_t *nw;
    os_handler_t        *os_hnd = factory->os_hnd;
    int                 rv;

    nw = ipmi_mem_alloc(sizeof(*nw));
    if (!nw)
	return NULL;
    memset(nw, 0, sizeof(*nw));

    nw->factory = factory;

    if (factory->has_threads) {
	rv = os_hnd->create_lock(os_hnd, &nw->lock);
	if (rv) {
	    ipmi_mem_free(nw);
	    return NULL;
	}

	rv = os_hnd->create_cond(os_hnd, &nw->cond);
	if (rv) {
	    os_hnd->destroy_lock(os_hnd, nw->lock);
	    ipmi_mem_free(nw);
	    return NULL;
	}
    }

    if (factory->lock)
	os_hnd->lock(os_hnd, factory->lock);
    factory->num_waiters++;
    if (factory->lock)
	os_hnd->unlock(os_hnd, factory->lock);

    nw->count = 1;
    return nw;
}

int
os_handler_free_waiter(os_handler_waiter_t *waiter)
{
    os_handler_t *os_hnd = waiter->factory->os_hnd;

    if (waiter->count > 0)
	return EAGAIN;

    if (waiter->factory->lock)
	os_hnd->lock(os_hnd, waiter->factory->lock);
    waiter->factory->num_waiters--;
    if (waiter->factory->lock)
	os_hnd->unlock(os_hnd, waiter->factory->lock);

    if (waiter->lock)
	os_hnd->destroy_lock(os_hnd, waiter->lock);
    if (waiter->cond)
	os_hnd->destroy_cond(os_hnd, waiter->cond);
    ipmi_mem_free(waiter);
    return 0;
}

void
os_handler_waiter_use(os_handler_waiter_t *waiter)
{
    os_handler_t *os_hnd = waiter->factory->os_hnd;

    if (waiter->lock)
	os_hnd->lock(os_hnd, waiter->lock);
    waiter->count++;
    if (waiter->lock)
	os_hnd->unlock(os_hnd, waiter->lock);
}

void
os_handler_waiter_release(os_handler_waiter_t *waiter)
{
    os_handler_t *os_hnd = waiter->factory->os_hnd;

    if (waiter->lock)
	os_hnd->lock(os_hnd, waiter->lock);
    if (waiter->count == 0) {
	os_hnd->log(os_hnd, IPMI_LOG_SEVERE,
		    "os_handler_waiter_release: Got a release when the"
		    " wait count was already zero");
    } else {
	waiter->count--;
	if (waiter->lock && (waiter->count == 0)) {
	    if (waiter->is_single) {
		/* We handle the single thread count here and not in
		   the waiter to avoid a race condition.  See comments
		   at the beginning of this file. */
		os_hnd->lock(os_hnd, waiter->factory->lock);
		waiter->factory->single_thread_use_count--;
		os_hnd->unlock(os_hnd, waiter->factory->lock);
		waiter->is_single = 0;
	    }
	    os_hnd->cond_wake(os_hnd, waiter->cond);
	}
    }
    if (waiter->lock)
	os_hnd->unlock(os_hnd, waiter->lock);
}

int
os_handler_waiter_wait(os_handler_waiter_t *waiter, struct timeval *timeout)
{
    os_handler_waiter_factory_t *factory = waiter->factory;
    os_handler_t *os_hnd = waiter->factory->os_hnd;
    int          rv = 0;

    if (waiter->lock) {
	os_hnd->lock(os_hnd, waiter->lock);
	if (waiter->count > 0) {
	    if (factory->num_threads == 0) {
		/* Threaded, but we don't have a simultaneous running
		   event loop. */
		os_hnd->lock(os_hnd, factory->lock);
		if (factory->single_thread_use_count == 0) {
		    /* Wake the event loop thread. */
		    os_hnd->cond_wake(os_hnd, factory->single_thread_cond);
		}
		factory->single_thread_use_count++;
		os_hnd->unlock(os_hnd, factory->lock);
		waiter->is_single = 1;
	    }

	    rv = os_hnd->cond_timedwait(os_hnd, waiter->cond,
					waiter->lock, timeout);
	    /* single_thread_use_count is decremented by the waker
	       unless it failes to receive the wakeup. */
	    if (rv)
		factory->single_thread_use_count--;
	}
	os_hnd->unlock(os_hnd, waiter->lock);
    } else {
	while (waiter->count > 0)
	    os_hnd->perform_one_op(os_hnd, timeout);
    }

    return rv;
}

