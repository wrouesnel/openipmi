/*
 * os_handler.h
 *
 * MontaVista IPMI os handler interface.
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

#ifndef __OS_HANDLER_H
#define __OS_HANDLER_H

#include <stdarg.h>
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

typedef struct os_handler_s os_handler_t;
struct os_handler_s
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
    int (*add_fd_to_wait_for)(os_handler_t    *handler,
			      int             fd,
			      os_data_ready_t data_ready,
			      void            *cb_data,
			      os_hnd_fd_id_t  **id);
    int (*remove_fd_to_wait_for)(os_handler_t   *handler,
				 os_hnd_fd_id_t *id);

    /* Create a timer.  This will allocate all the data required for
       the timer, so no other timer operations should fail due to lack
       of memory. */
    int (*alloc_timer)(os_handler_t      *handler,
		       os_hnd_timer_id_t **id);
    /* Free the memory for the given timer.  If the timer is running,
       stop it first. */
    int (*free_timer)(os_handler_t      *handler,
		      os_hnd_timer_id_t *id);
    /* This is called to register a callback handler to be called at
       the given time or after (absolute time, as seen by
       gettimeofday).  After the given time has passed, the
       "timed_out" will be called with the given cb_data.  The
       identifier in "id" just be one previously allocated with
       alloc_timer().  Note that timed_out may NOT block. */
    int (*start_timer)(os_handler_t      *handler,
		       os_hnd_timer_id_t *id,
		       struct timeval    *timeout,
		       os_timed_out_t    timed_out,
		       void              *cb_data);
    /* Cancel the given timer.  If the timer has already been called
       (or is in the process of being called) this should return
       ESRCH, and it may not return ESRCH for any other reason.  In
       other words, if ESRCH is returned, the timer is valid and the
       timeout handler has or will be called.  */
    int (*stop_timer)(os_handler_t      *handler,
		      os_hnd_timer_id_t *id);

    /* Used to implement locking primitives for multi-threaded access.
       If these are NULL, then the code will assume that the system is
       single-threaded and doesn't need locking.  Note that these must
       be recursive locks. */
    int (*create_lock)(os_handler_t  *handler,
		       os_hnd_lock_t **id);
    int (*destroy_lock)(os_handler_t  *handler,
			os_hnd_lock_t *id);
    int (*lock)(os_handler_t  *handler,
		os_hnd_lock_t *id);
    int (*unlock)(os_handler_t  *handler,
		  os_hnd_lock_t *id);
    /* Return 1 if locked, 0 if not locked. */
    int (*is_locked)(os_handler_t  *handler,
		     os_hnd_lock_t *id);
    int (*create_rwlock)(os_handler_t  *handler,
			 os_hnd_rwlock_t **id);
    int (*destroy_rwlock)(os_handler_t  *handler,
			  os_hnd_rwlock_t *id);
    int (*read_lock)(os_handler_t  *handler,
		     os_hnd_rwlock_t *id);
    int (*read_unlock)(os_handler_t  *handler,
		       os_hnd_rwlock_t *id);
    int (*write_lock)(os_handler_t  *handler,
		      os_hnd_rwlock_t *id);
    int (*write_unlock)(os_handler_t  *handler,
			os_hnd_rwlock_t *id);
    /* Return 1 if read or write locked, 0 if not locked. */
    int (*is_readlocked)(os_handler_t    *handler,
			 os_hnd_rwlock_t *id);
    /* Return 1 if write locked, 0 if not locked or only read locked. */
    int (*is_writelocked)(os_handler_t    *handler,
			 os_hnd_rwlock_t *id);

    /* Condition variables, like in POSIX Threads. */
    int (*create_cond)(os_handler_t  *handler,
		       os_hnd_cond_t **cond);
    int (*destroy_cond)(os_handler_t  *handler,
			os_hnd_cond_t *cond);
    int (*cond_wait)(os_handler_t  *handler,
		     os_hnd_cond_t *cond,
		     os_hnd_lock_t *lock);
    int (*cond_wake)(os_handler_t  *handler,
		     os_hnd_cond_t *cond);
    int (*cond_broadcast)(os_handler_t  *handler,
			  os_hnd_cond_t *cond);

    /* Return "len" bytes of random data into "data". */
    int (*get_random)(os_handler_t  *handler,
		      void          *data,
		      unsigned int  len);

    /* Report an error. */
    void (*log)(os_handler_t  *handler,
		char          *format,
		...);
    void (*vlog)(os_handler_t  *handler,
		 char          *format,
		 va_list       ap);

    /* The user may use this for whatever they like. */
    void *user_data;
};

#endif /* __OS_HANDLER_H */
