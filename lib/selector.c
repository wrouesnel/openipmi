/*
 * selector.c
 *
 * Code for abstracting select for files and timers.
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

/* This file holds code to abstract the "select" call and make it
   easier to use.  The main thread lives here, the rest of the code
   uses a callback interface.  Basically, other parts of the program
   can register file descriptors with this code, when interesting
   things happen on those file descriptors this code will call
   routines registered with it. */

#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_int.h>

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>

/* The control structure for each file descriptor. */
typedef struct fd_control_s
{
    int              in_use;
    void             *data;		/* Operation-specific data */
    sel_fd_handler_t handle_read;
    sel_fd_handler_t handle_write;
    sel_fd_handler_t handle_except;
} fd_control_t;

typedef struct heap_val_s
{
    /* Set this to the function to call when the timeout occurs. */
    sel_timeout_handler_t handler;

    /* Set this to whatever you like.  You can use this to store your
       own data. */
    void *user_data;

    /* Set this to the time when the timer will go off. */
    struct timeval timeout;

    /* Who owns me? */
    selector_t *sel;

    /* Am I currently running? */
    int in_heap;
} heap_val_t;

typedef struct theap_s theap_t;
#define heap_s theap_s
#define heap_node_s sel_timer_s
#define HEAP_EXPORT_NAME(s) theap_ ## s
#define HEAP_NAMES_LOCAL static
#define HEAP_OUTPUT_PRINTF "(%ld.%7.7ld)"
#define HEAP_OUTPUT_DATA pos->timeout.tv_sec, pos->timeout.tv_usec

static int
cmp_timeval(struct timeval *tv1, struct timeval *tv2)
{
    if (tv1->tv_sec < tv2->tv_sec)
	return -1;

    if (tv1->tv_sec > tv2->tv_sec)
	return 1;

    if (tv1->tv_usec < tv2->tv_usec)
	return -1;

    if (tv1->tv_usec > tv2->tv_usec)
	return 1;

    return 0;
}

static int
heap_cmp_key(heap_val_t *v1, heap_val_t *v2)
{
    return cmp_timeval(&v1->timeout, &v2->timeout);
}

#include "heap.h"

struct selector_s
{
    /* This is an array of all the file descriptors possible.  This is
       moderately wasteful of space, but easy to do.  Hey, memory is
       cheap. */
    volatile fd_control_t fds[FD_SETSIZE];
    
    /* These are the offical fd_sets used to track what file descriptors
       need to be monitored. */
    volatile fd_set read_set;
    volatile fd_set write_set;
    volatile fd_set except_set;

    ipmi_lock_t *fd_lock;

    volatile int maxfd; /* The largest file descriptor registered with
			   this code. */

    /* The timer heap. */
    theap_t timer_heap;

    ipmi_lock_t *timer_lock;

    /* The timeout */
    sel_send_sig_cb send_sig;
    long            thread_id;
    void            *send_sig_cb_data;

    /* This is the memory used to hold the timeout for select
       operation. */
    volatile struct timeval timeout;

    /* If we need to be woken up for an FD or timer head change, this
       will be true. */
    volatile int need_wake_on_change;
};

/* This function will wake the SEL thread.  It must be called with the
   timer lock held, because it messes with timeout.

   The operation is is subtle, but it does work.  The timeout in the
   selector is the data passed in as the timeout to select.  When we
   want to wake the select, we set the timeout to zero first.  That
   way, if the select has calculated the timeout but has not yet
   called select, then this will set it to zero (causing it to wait
   zero time).  If select has already been called, then the signal
   send should wake it up.  We only need to do this after we have
   calculated the timeout, but before we have called select, thus the
   need_wake_on_change is only set in that range. */
static void
wake_sel_thread(selector_t *sel)
{
    if (sel->need_wake_on_change && sel->send_sig) {
	sel->timeout.tv_sec = 0;
	sel->timeout.tv_usec = 0;
	sel->send_sig(sel->thread_id, sel->send_sig_cb_data);
    }
}

static void
wake_sel_thread_lock(selector_t *sel)
{
    ipmi_lock(sel->timer_lock);
    wake_sel_thread(sel);
    ipmi_unlock(sel->timer_lock);
}

/* Initialize a single file descriptor. */
static void
init_fd(fd_control_t *fd)
{
    fd->in_use = 0;
    fd->data = NULL;
    fd->handle_read = NULL;
    fd->handle_write = NULL;
    fd->handle_except = NULL;
}

/* Set the handlers for a file descriptor. */
void
sel_set_fd_handlers(selector_t       *sel,
		    int              fd,
		    void             *data,
		    sel_fd_handler_t read_handler,
		    sel_fd_handler_t write_handler,
		    sel_fd_handler_t except_handler)
{
    fd_control_t *fdc;

    ipmi_lock(sel->fd_lock);
    fdc = (fd_control_t *) &(sel->fds[fd]);
    fdc->in_use = 1;
    fdc->data = data;
    fdc->handle_read = read_handler;
    fdc->handle_write = write_handler;
    fdc->handle_except = except_handler;

    /* Move maxfd up if necessary. */
    if (fd > sel->maxfd) {
	sel->maxfd = fd;
    }

    wake_sel_thread_lock(sel);
    ipmi_unlock(sel->fd_lock);
}

/* Clear the handlers for a file descriptor and remove it from
   select's monitoring. */
void
sel_clear_fd_handlers(selector_t   *sel,
		      int          fd)
{
    ipmi_lock(sel->fd_lock);
    init_fd((fd_control_t *) &(sel->fds[fd]));
    FD_CLR(fd, &sel->read_set);
    FD_CLR(fd, &sel->write_set);
    FD_CLR(fd, &sel->except_set);

    /* Move maxfd down if necessary. */
    if (fd == sel->maxfd) {
	while ((sel->maxfd >= 0) && (! sel->fds[sel->maxfd].in_use)) {
	    sel->maxfd--;
	}
    }

    wake_sel_thread_lock(sel);
    ipmi_unlock(sel->fd_lock);
}

/* Set whether the file descriptor will be monitored for data ready to
   read on the file descriptor. */
void
sel_set_fd_read_handler(selector_t *sel, int fd, int state)
{
    ipmi_lock(sel->fd_lock);
    if (state == SEL_FD_HANDLER_ENABLED) {
	FD_SET(fd, &sel->read_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	FD_CLR(fd, &sel->read_set);
    }
    wake_sel_thread_lock(sel);
    ipmi_unlock(sel->fd_lock);
}

/* Set whether the file descriptor will be monitored for when the file
   descriptor can be written to. */
void
sel_set_fd_write_handler(selector_t *sel, int fd, int state)
{
    ipmi_lock(sel->fd_lock);
    if (state == SEL_FD_HANDLER_ENABLED) {
	FD_SET(fd, &sel->write_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	FD_CLR(fd, &sel->write_set);
    }
    wake_sel_thread_lock(sel);
    ipmi_unlock(sel->fd_lock);
}

/* Set whether the file descriptor will be monitored for exceptions
   on the file descriptor. */
void
sel_set_fd_except_handler(selector_t *sel, int fd, int state)
{
    ipmi_lock(sel->fd_lock);
    if (state == SEL_FD_HANDLER_ENABLED) {
	FD_SET(fd, &sel->except_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	FD_CLR(fd, &sel->except_set);
    }
    wake_sel_thread_lock(sel);
    ipmi_unlock(sel->fd_lock);
}

static void
diff_timeval(struct timeval *dest,
	     struct timeval *left,
	     struct timeval *right)
{
    if (   (left->tv_sec < right->tv_sec)
	|| (   (left->tv_sec == right->tv_sec)
	    && (left->tv_usec < right->tv_usec)))
    {
	/* If left < right, just force to zero, don't allow negative
           numbers. */
	dest->tv_sec = 0;
	dest->tv_usec = 0;
	return;
    }

    dest->tv_sec = left->tv_sec - right->tv_sec;
    dest->tv_usec = left->tv_usec - right->tv_usec;
    while (dest->tv_usec < 0) {
	dest->tv_usec += 1000000;
	dest->tv_sec--;
    }
}

int
sel_alloc_timer(selector_t            *sel,
		sel_timeout_handler_t handler,
		void                  *user_data,
		sel_timer_t           **new_timer)
{
    sel_timer_t *timer;

    timer = ipmi_mem_alloc(sizeof(*timer));
    if (!timer)
	return ENOMEM;

    timer->val.handler = handler;
    timer->val.user_data = user_data;
    timer->val.in_heap = 0;
    timer->val.sel = sel;
    *new_timer = timer;

    return 0;
}

int
sel_free_timer(sel_timer_t *timer)
{
    ipmi_lock(timer->val.sel->timer_lock);
    if (timer->val.in_heap) {
	sel_stop_timer(timer);
    }
    ipmi_unlock(timer->val.sel->timer_lock);
    ipmi_mem_free(timer);

    return 0;
}

int
sel_start_timer(sel_timer_t    *timer,
		struct timeval *timeout)
{
    volatile sel_timer_t *top;

    ipmi_lock(timer->val.sel->timer_lock);
    if (timer->val.in_heap) {
	ipmi_unlock(timer->val.sel->timer_lock);
	return EBUSY;
    }

    top = theap_get_top(&timer->val.sel->timer_heap);

    timer->val.timeout = *timeout;
    theap_add(&timer->val.sel->timer_heap, timer);
    timer->val.in_heap = 1;

    if (timer->val.sel->send_sig
	&& (top != theap_get_top(&timer->val.sel->timer_heap)))
    {
	/* If the top value changed, restart the waiting thread. */
	wake_sel_thread(timer->val.sel);
    }
    ipmi_unlock(timer->val.sel->timer_lock);
    return 0;
}

int
sel_stop_timer(sel_timer_t *timer)
{
    volatile sel_timer_t *top;

    ipmi_lock(timer->val.sel->timer_lock);
    if (!timer->val.in_heap) {
	ipmi_unlock(timer->val.sel->timer_lock);
	return ETIMEDOUT;
    }

    top = theap_get_top(&timer->val.sel->timer_heap);

    theap_remove(&timer->val.sel->timer_heap, timer);
    timer->val.in_heap = 0;

    if (timer->val.sel->send_sig
	&& (top != theap_get_top(&timer->val.sel->timer_heap)))
    {
	/* If the top value changed, restart the waiting thread. */
	wake_sel_thread(timer->val.sel);
    }
    ipmi_unlock(timer->val.sel->timer_lock);

    return 0;
}

/* 
 * Process timers on selector.  The timeout is always set, to a very long
 * value if no timers are waiting.
 */
static void
process_timers(selector_t	*sel,
	       struct timeval   *timeout,
	       int		*num)
{
    struct timeval now;
    sel_timer_t *timer;
    
    ipmi_lock(sel->timer_lock);
    
    *num = 0;
    timer = theap_get_top(&sel->timer_heap);
    gettimeofday(&now, NULL);
    while (timer && cmp_timeval(&now, &timer->val.timeout) >= 0) {
	(*num)++;
	theap_remove(&(sel->timer_heap), timer);
	timer->val.in_heap = 0;
	ipmi_unlock(sel->timer_lock);
	
	timer->val.handler(sel, timer, timer->val.user_data);
	
	ipmi_lock(sel->timer_lock);
	timer = theap_get_top(&sel->timer_heap);
    }

    if (timer) {
	gettimeofday(&now, NULL);   
	diff_timeval((struct timeval *) timeout,
		     (struct timeval *) &timer->val.timeout,
		     &now);
    } else {
	/* No timers, just set a long time. */
	timeout->tv_sec = 100000;
	timeout->tv_usec = 0;
    }
    
    sel->need_wake_on_change = 1;
    ipmi_unlock(sel->timer_lock); 
}

/*
 * return == 0  when timeout
 * 	  >  0  when successful 
 * 	  <  0  when error
 */
static int
process_fds(selector_t	    *sel,
	    sel_send_sig_cb send_sig,
	    long            thread_id,
	    void            *cb_data,
	    struct timeval  *timeout)
{
    fd_set      tmp_read_set;
    fd_set      tmp_write_set;
    fd_set      tmp_except_set;
    int i;
    int err;
    
    ipmi_lock(sel->fd_lock);
    memcpy(&tmp_read_set, (void *) &sel->read_set, sizeof(tmp_read_set));
    memcpy(&tmp_write_set, (void *) &sel->write_set, sizeof(tmp_write_set));
    memcpy(&tmp_except_set, (void *) &sel->except_set, sizeof(tmp_except_set));
    ipmi_unlock(sel->fd_lock);

    err = select(sel->maxfd+1,
		 &tmp_read_set,
		 &tmp_write_set,
		 &tmp_except_set,
		 timeout);
    sel->need_wake_on_change = 0;
    if (err <= 0)
	goto out;
    
    /* We got some I/O. */
    for (i=0; i<=sel->maxfd; i++) {
	if (FD_ISSET(i, &tmp_read_set)) {
	    ipmi_lock(sel->fd_lock);
	    if (sel->fds[i].handle_read == NULL) {
		/* Somehow we don't have a handler for this.
		   Just shut it down. */
		sel_set_fd_read_handler(sel, i, SEL_FD_HANDLER_DISABLED);
	    } else {
		sel->fds[i].handle_read(i, sel->fds[i].data);
	    }
	    ipmi_unlock(sel->fd_lock);
	}
	if (FD_ISSET(i, &tmp_write_set)) {
	    ipmi_lock(sel->fd_lock);
	    if (sel->fds[i].handle_write == NULL) {
		/* Somehow we don't have a handler for this.
                   Just shut it down. */
		sel_set_fd_write_handler(sel, i, SEL_FD_HANDLER_DISABLED);
	    } else {
		sel->fds[i].handle_write(i, sel->fds[i].data);
	    }
	    ipmi_unlock(sel->fd_lock);
	}
	if (FD_ISSET(i, &tmp_except_set)) {
	    ipmi_lock(sel->fd_lock);
	    if (sel->fds[i].handle_except == NULL) {
		/* Somehow we don't have a handler for this.
                   Just shut it down. */
		sel_set_fd_except_handler(sel, i, SEL_FD_HANDLER_DISABLED);
	    } else {
	        sel->fds[i].handle_except(i, sel->fds[i].data);
	    }
	    ipmi_unlock(sel->fd_lock);
	}
    }
out:
    return err;
}

int
sel_select(selector_t      *sel,
	   sel_send_sig_cb send_sig,
	   long            thread_id,
	   void            *cb_data,
	   struct timeval  *timeout)
{
    int            i;
    struct timeval *to_time, loc_timeout;

    process_timers(sel, (struct timeval *)(&loc_timeout), &i);
    if (i) { /* some timer handlers are called */
	return i; 
    }    
    if (timeout) { 
	if (cmp_timeval((struct timeval *)(&loc_timeout), 
			timeout) >= 0)
	    to_time = timeout;
	else
	    to_time = (struct timeval *)&loc_timeout; 
    } else {
	to_time = (struct timeval *)&loc_timeout;
    }

    return process_fds(sel, send_sig, thread_id, cb_data, to_time);
}

/* The main loop for the program.  This will select on the various
   sets, then scan for any available I/O to process.  It also monitors
   the time and call the timeout handlers periodically. */
int
sel_select_loop(selector_t      *sel,
		sel_send_sig_cb send_sig,
		long            thread_id,
		void            *cb_data)
{
    int i;
    int err;

    for (;;) {
	process_timers(sel, (struct timeval *)(&sel->timeout), &i);    
	
	err = process_fds(sel, send_sig, thread_id, cb_data, 
			  (struct timeval *)(&sel->timeout));
    	if ((err < 0) && (errno != EINTR)) {
	    err = errno;
	    /* An error occurred. */
	    /* An error is bad, we need to abort. */
	    syslog(LOG_ERR, "select_loop() - select: %m");
	    return err;
	}
    }
}

/* Initialize the select code. */
int
sel_alloc_selector(selector_t **new_selector)
{
    selector_t *sel;
    int        i;
    int        rv;

    sel = ipmi_mem_alloc(sizeof(*sel));
    if (!sel)
	return ENOMEM;
    memset(sel, 0, sizeof(*sel));

    sel->need_wake_on_change = 0;

    rv = ipmi_create_global_lock(&(sel->timer_lock));
    if (rv)
	goto out_err;

    rv = ipmi_create_global_lock(&(sel->fd_lock));
    if (rv)
	goto out_err;

    FD_ZERO((fd_set *) &sel->read_set);
    FD_ZERO((fd_set *) &sel->write_set);
    FD_ZERO((fd_set *) &sel->except_set);

    for (i=0; i<FD_SETSIZE; i++) {
	init_fd((fd_control_t *) &(sel->fds[i]));
    }

    theap_init(&sel->timer_heap);

    *new_selector = sel;

 out_err:
    if (rv) {
	if (sel->timer_lock)
	    ipmi_destroy_lock(sel->timer_lock);
	if (sel->fd_lock)
	    ipmi_destroy_lock(sel->fd_lock);
	ipmi_mem_free(sel);
    }
    return rv;
}

int
sel_free_selector(selector_t *sel)
{
    sel_timer_t *elem;

    if (sel->timer_lock)
	ipmi_destroy_lock(sel->timer_lock);
    if (sel->fd_lock)
	ipmi_destroy_lock(sel->fd_lock);

    elem = theap_get_top(&(sel->timer_heap));
    while (elem) {
	theap_remove(&(sel->timer_heap), elem);
	ipmi_mem_free(elem);
	elem = theap_get_top(&(sel->timer_heap));
    }
    ipmi_mem_free(sel);

    return 0;
}
