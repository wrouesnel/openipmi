/*
 * ipmi_mc.h
 *
 * MontaVista IPMI interface for management controllers
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

#ifndef __OS_HANDLER_H
#define __OS_HANDLER_H

#include <sys/time.h>

/* An os-independent normal lock. */
typedef struct os_hnd_lock_s os_hnd_lock_t;

/* An os-independent read/write lock. */
typedef struct os_hnd_rwlock_s os_hnd_rwlock_t;

/* An os-independent condition variable. */
typedef struct os_hnd_cond_s os_hnd_cond_t;

/* An os-independent file descriptor holder. */
typedef struct os_hnd_fd_id_s os_hnd_fd_id_t;

/* An os-independent timer. */
typedef struct os_hnd_timer_id_s os_hnd_timer_id_t;

/* This is a structure that defined the os-dependent stuff required by
   threaded code.  In general, return values of these should be zero
   on success, or an errno value on failure.  The errno values will be
   propigated back up to the commands that caused these to be called,
   if possible. */
typedef void (*os_data_ready_t)(int fd, void *cb_data, os_hnd_fd_id_t *id);
typedef void (*os_timed_out_t)(void *cb_data, os_hnd_timer_id_t *id);
typedef struct os_handler_s
{
    /* This is called by the user code to register a callback handler
       to be called when data is ready to be read on the given file
       descriptor.  I know, it's kind of wierd, a callback to register
       a callback, but it's the best way I could think of to do this.
       This call should return an id that can then be used to cancel
       the wait.  The called code should register that whenever data
       is ready to be read from the given file descriptor, data_ready
       should be called with the given cb_data.  If this is NULL, you
       may only call the commands ending in "_wait", the event-driven
       code will return errors.  You also may not receive commands or
       event.  Note that these calls may NOT block. */
    int (*add_fd_to_wait_for)(int             fd,
			      os_data_ready_t data_ready,
			      void            *cb_data,
			      os_hnd_fd_id_t  **id);
    int (*remove_fd_to_wait_for)(os_hnd_fd_id_t *id);

    /* This is called by the user code to register a callback handler
       to be called at the given time or after (absolute time, as seen
       by gettimeofday).  After the given time has passed, the
       "timed_out" should be called with the given cb_data.  This should
       return an identifier in "id" that can be used to cancel the
       timer later.  Note that these calls may NOT block.  If these
       are NULL, you may only call the commands ending in "_wait",
       event-driven code will return errors, and you may not receive
       commands or events. */
    int (*add_timer)(struct timeval    *timeout,
		     os_timed_out_t    timed_out,
		     void              *cb_data,
		     os_hnd_timer_id_t **id);
    /* Cancel the given timer.  If the timer has already been called
       (or is in the process of being called) this should return
       ESRCH, and it may not return ESRCH for any other reason.  In
       other words, if ESRCH is returned, the timer is valid and the
       timeout handler has or will be called.  */
    int (*remove_timer)(os_hnd_timer_id_t *id);
    /* From the context of a timeout, restart the given timer.  This
       can ONLY be called inside a timeout handler for the given id.
       This routine cannot fail. */
    void (*restart_timer)(os_hnd_timer_id_t *id,
			  struct timeval    *timeout);

    /* Used to implement locking primitives for multi-threaded access.
       If these are NULL, then the code will assume that the system is
       single-threaded and doesn't need locking.  Note that these must
       be recursive locks. */
    int (*create_lock)(os_hnd_lock_t **id);
    int (*destroy_lock)(os_hnd_lock_t *id);
    int (*lock)(os_hnd_lock_t *id);
    int (*unlock)(os_hnd_lock_t *id);
    int (*create_rwlock)(os_hnd_rwlock_t **id);
    int (*destroy_rwlock)(os_hnd_rwlock_t *id);
    int (*read_lock)(os_hnd_rwlock_t *id);
    int (*read_unlock)(os_hnd_rwlock_t *id);
    int (*write_lock)(os_hnd_rwlock_t *id);
    int (*write_unlock)(os_hnd_rwlock_t *id);

    /* Condition variables, like in POSIX Threads. */
    int (*create_cond)(os_hnd_cond_t **cond);
    int (*destroy_cond)(os_hnd_cond_t *cond);
    int (*cond_wait)(os_hnd_cond_t *cond, os_hnd_lock_t *lock);
    int (*cond_wake)(os_hnd_cond_t *cond);
    int (*cond_broadcast)(os_hnd_cond_t *cond);

    /* Return "len" bytes of random data into "data". */
    int (*get_random)(void *data, unsigned int len);
} os_handler_t;

#endif /* __OS_HANDLER_H */
