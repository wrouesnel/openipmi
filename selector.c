/*
 * selector.c
 *
 * Code for abstracting select for files and timers.
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

struct sel_timer_s
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

    /* Links for the heap. */
    sel_timer_t *left, *right, *up;
};

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
    volatile sel_timer_t *timer_top, *timer_last;

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

#undef MASSIVE_DEBUG
#ifdef MASSIVE_DEBUG
#include <stdio.h>
FILE **debug_out = &stderr;
static void
print_tree_item(sel_timer_t *pos, int indent)
{
    int i;
    for (i=0; i<indent; i++)
	fprintf(*debug_out, " ");
    fprintf(*debug_out, "  %p: %p %p %p (%ld.%7.7ld)\n", pos, pos->left, pos->right,
	   pos->up, pos->timeout.tv_sec, pos->timeout.tv_usec);
    if (pos->left)
	print_tree_item(pos->left, indent+1);
    if (pos->right)
	print_tree_item(pos->right, indent+1);
}

static void
print_tree(sel_timer_t *top, sel_timer_t *last)
{
    fprintf(*debug_out, "top=%p\n", top);
    if (top)
	print_tree_item(top, 0);
    fprintf(*debug_out, "last=%p\n", last);
    fflush(*debug_out);
}

static void
check_tree_item(sel_timer_t *curr,
		int         *depth,
		int         max_depth,
		sel_timer_t **real_last,
		int         *found_last)
{
    if (! curr->left) {
	if (curr->right) {
	    fprintf(*debug_out, "Tree corrupt B\n");
	    *((int *) NULL) = 0;
	} else if (*depth > max_depth) {
	    fprintf(*debug_out, "Tree corrupt C\n");
	    *((int *) NULL) = 0;
	} else if (*depth < (max_depth - 1)) {
	    fprintf(*debug_out, "Tree corrupt D\n");
	    *((int *) NULL) = 0;
	} else if ((*found_last) && (*depth == max_depth)) {
	    fprintf(*debug_out, "Tree corrupt E\n");
	    *((int *) NULL) = 0;
	} else if (*depth == max_depth) {
	    *real_last = curr;
	} else {
	    *found_last = 1;
	}
    } else {
	if (curr->left->up != curr) {
	    fprintf(*debug_out, "Tree corrupt I\n");
	    *((int *) NULL) = 0;
	}
	if (cmp_timeval(&(curr->left->timeout), &(curr->timeout)) < 0) {
	    fprintf(*debug_out, "Tree corrupt K\n");
	    *((int *) NULL) = 0;
	}
	(*depth)++;
	check_tree_item(curr->left, depth, max_depth, real_last, found_last);
	(*depth)--;

	if (! curr->right) {
	    if (*depth != (max_depth - 1)) {
		fprintf(*debug_out, "Tree corrupt F\n");
		*((int *) NULL) = 0;
	    }
	    if (*found_last) {
		fprintf(*debug_out, "Tree corrupt G\n");
		*((int *) NULL) = 0;
	    }
	    *found_last = 1;
	} else {
	    if (curr->right->up != curr) {
		fprintf(*debug_out, "Tree corrupt H\n");
		*((int *) NULL) = 0;
	    }
	    if (cmp_timeval(&(curr->right->timeout), &(curr->timeout)) < 0) {
		fprintf(*debug_out, "Tree corrupt L\n");
		*((int *) NULL) = 0;
	    }
	    (*depth)++;
	    check_tree_item(curr->right, depth, max_depth, real_last, found_last);
	    (*depth)--;
	}
    }
}

static void
check_tree(sel_timer_t *top, sel_timer_t *last)
{
    unsigned int depth = 0, max_depth = 0;
    int          found_last = 0;
    sel_timer_t  *real_last;

    if (!top) {
	if (last) {
	    fprintf(*debug_out, "Tree corrupt A\n");
	    *((int *) NULL) = 0;
	}
	return;
    }

    real_last = top;
    while (real_last->left) {
	real_last = real_last->left;
	max_depth++;
    }

    real_last = NULL;
    check_tree_item(top, &depth, max_depth, &real_last, &found_last);

    if (real_last != last) {
	fprintf(*debug_out, "Tree corrupt J\n");
	*((int *) NULL) = 0;
    }
    fflush(*debug_out);
}
#endif

static void
find_next_pos(sel_timer_t *curr, sel_timer_t ***next, sel_timer_t **parent)
{
    unsigned int upcount = 0;

    if (curr->up && (curr->up->left == curr)) {
	/* We are a left node, the next node is just my right partner. */
	*next = &(curr->up->right);
	*parent = curr->up;
	return;
    }

    /* While we are a right node, go up. */
    while (curr->up && (curr->up->right == curr)) {
	upcount++;
	curr = curr->up;
    }

    if (curr->up) {
	/* Now we are a left node, trace up then back down. */
	curr = curr->up->right;
	upcount--;
    }
    while (upcount) {
	curr = curr->left;
	upcount--;
    }
    *next = &(curr->left);
    *parent = curr;
}

static void
find_prev_elem(sel_timer_t *curr, sel_timer_t **prev)
{
    unsigned int upcount = 0;

    if (curr->up && (curr->up->right == curr)) {
	/* We are a right node, the previous node is just my left partner. */
	*prev = curr->up->left;
	return;
    }

    /* While we are a left node, go up. */
    while (curr->up && (curr->up->left == curr)) {
	upcount++;
	curr = curr->up;
    }

    if (curr->up) {
	/* Now we are a right node, trace up then back down. */
	curr = curr->up->left;
    } else {
	/* We are going to the previous "row". */
	upcount--;
    }
    while (upcount) {
	curr = curr->right;
	upcount--;
    }
    *prev = curr;
}

static void
send_up(sel_timer_t *elem, sel_timer_t **top, sel_timer_t **last)
{
    sel_timer_t *tmp1, *tmp2, *parent;

    parent = elem->up;
    while (parent && (cmp_timeval(&elem->timeout, &parent->timeout) < 0)) {
	tmp1 = elem->left;
	tmp2 = elem->right;
	if (parent->left == elem) {
	    elem->left = parent;
	    elem->right = parent->right;
	    if (elem->right)
		elem->right->up = elem;
	} else {
	    elem->right = parent;
	    elem->left = parent->left;
	    if (elem->left)
		elem->left->up = elem;
	}
	elem->up = parent->up;

	if (parent->up) {
	    if (parent->up->left == parent) {
		parent->up->left = elem;
	    } else {
		parent->up->right = elem;
	    }
	} else {
	    *top = elem;
	}

	parent->up = elem;
	parent->left = tmp1;
	if (parent->left)
	    parent->left->up = parent;
	parent->right = tmp2;
	if (parent->right)
	    parent->right->up = parent;

	if (*last == elem)
	    *last = parent;

	parent = elem->up;
    }
}

static void
send_down(sel_timer_t *elem, sel_timer_t **top, sel_timer_t **last)
{
    sel_timer_t *tmp1, *tmp2, *left, *right;

    left = elem->left;
    while (left) {
	right = elem->right;
	/* Choose the smaller of the two below me to swap with. */
	if ((right) && (cmp_timeval(&left->timeout, &right->timeout) > 0)) {

	    if (cmp_timeval(&elem->timeout, &right->timeout) > 0) {
		/* Swap with the right element. */
		tmp1 = right->left;
		tmp2 = right->right;
		if (elem->up) {
		    if (elem->up->left == elem) {
			elem->up->left = right;
		    } else {
			elem->up->right = right;
		    }
		} else {
		    *top = right;
		}
		right->up = elem->up;
		elem->up = right;

		right->left = elem->left;
		right->right = elem;
		elem->left = tmp1;
		elem->right = tmp2;
		if (right->left)
		    right->left->up = right;
		if (elem->left)
		    elem->left->up = elem;
		if (elem->right)
		    elem->right->up = elem;

		if (*last == right)
		    *last = elem;
	    } else
		goto done;
	} else {
	    /* The left element is smaller, or the right doesn't exist. */
	    if (cmp_timeval(&elem->timeout, &left->timeout) > 0) {
		/* Swap with the left element. */
		tmp1 = left->left;
		tmp2 = left->right;
		if (elem->up) {
		    if (elem->up->left == elem) {
			elem->up->left = left;
		    } else {
			elem->up->right = left;
		    }
		} else {
		    *top = left;
		}
		left->up = elem->up;
		elem->up = left;

		left->left = elem;
		left->right = elem->right;
		elem->left = tmp1;
		elem->right = tmp2;
		if (left->right)
		    left->right->up = left;
		if (elem->left)
		    elem->left->up = elem;
		if (elem->right)
		    elem->right->up = elem;

		if (*last == left)
		    *last = elem;
	    } else
		goto done;
	}
	left = elem->left;
    }
done:
    return;
}

static void
add_to_heap(sel_timer_t **top, sel_timer_t **last, sel_timer_t *elem)
{
    sel_timer_t **next;
    sel_timer_t *parent;

#ifdef MASSIVE_DEBUG
    fprintf(*debug_out, "add_to_heap entry\n");
    print_tree(*top, *last);
    check_tree(*top, *last);
#endif

    elem->left = NULL;
    elem->right = NULL;
    elem->up = NULL;

    if (*top == NULL) {
	*top = elem;
	*last = elem;
	goto out;
    }

    find_next_pos(*last, &next, &parent);
    *next = elem;
    elem->up = parent;
    *last = elem;
    if (cmp_timeval(&elem->timeout, &parent->timeout) < 0) {
	send_up(elem, top, last);
    }

 out:
#ifdef MASSIVE_DEBUG
    fprintf(*debug_out, "add_to_heap exit\n");
    print_tree(*top, *last);
    check_tree(*top, *last);
#endif
    return;
}

static void
remove_from_heap(sel_timer_t **top, sel_timer_t **last, sel_timer_t *elem)
{
    sel_timer_t *to_insert;

#ifdef MASSIVE_DEBUG
    fprintf(*debug_out, "remove_from_heap entry\n");
    print_tree(*top, *last);
    check_tree(*top, *last);
#endif

    /* First remove the last element from the tree, if it's not what's
       being removed, we will use it for insertion into the removal
       place. */
    to_insert = *last;
    if (! to_insert->up) {
	/* This is the only element in the heap. */
	*top = NULL;
	*last = NULL;
	goto out;
    } else {
	/* Set the new last position, and remove the item we will
           insert. */
	find_prev_elem(to_insert, last);
	if (to_insert->up->left == to_insert) {
	    to_insert->up->left = NULL;
	} else {
	    to_insert->up->right = NULL;
	}
    }

    if (elem == to_insert) {
	/* We got lucky and removed the last element.  We are done. */
	goto out;
    }

    /* Now stick the formerly last element into the removed element's
       position. */
    if (elem->up) {
	if (elem->up->left == elem) {
	    elem->up->left = to_insert;
	} else {
	    elem->up->right = to_insert;
	}
    } else {
	/* The head of the tree is being replaced. */
	*top = to_insert;
    }
    to_insert->up = elem->up;
    if (elem->left)
	elem->left->up = to_insert;
    if (elem->right)
	elem->right->up = to_insert;
    to_insert->left = elem->left;
    to_insert->right = elem->right;

    if (*last == elem)
	*last = to_insert;

    elem = to_insert;

    /* Now propigate it to the right place in the tree. */
    if (elem->up && cmp_timeval(&elem->timeout, &elem->up->timeout) < 0) {
	send_up(elem, top, last);
    } else {
	send_down(elem, top, last);
    }

 out:
#ifdef MASSIVE_DEBUG
    fprintf(*debug_out, "remove_from_head exit\n");
    print_tree(*top, *last);
    check_tree(*top, *last);
#endif
    return;
}

int
sel_alloc_timer(selector_t            *sel,
		sel_timeout_handler_t handler,
		void                  *user_data,
		sel_timer_t           **new_timer)
{
    sel_timer_t *timer;

    timer = malloc(sizeof(*timer));
    if (!timer)
	return ENOMEM;

    timer->handler = handler;
    timer->user_data = user_data;
    timer->in_heap = 0;
    timer->sel = sel;
    *new_timer = timer;

    return 0;
}

int
sel_free_timer(sel_timer_t *timer)
{
    ipmi_lock(timer->sel->timer_lock);
    if (timer->in_heap) {
	sel_stop_timer(timer);
    }
    ipmi_unlock(timer->sel->timer_lock);
    free(timer);

    return 0;
}

int
sel_start_timer(sel_timer_t    *timer,
		struct timeval *timeout)
{
    volatile sel_timer_t *top;

    ipmi_lock(timer->sel->timer_lock);
    if (timer->in_heap) {
	ipmi_unlock(timer->sel->timer_lock);
	return EBUSY;
    }

    top = timer->sel->timer_top;

    timer->timeout = *timeout;
    add_to_heap((sel_timer_t **) &(timer->sel->timer_top),
		(sel_timer_t **) &(timer->sel->timer_last),
		timer);
    timer->in_heap = 1;

    if (timer->sel->send_sig && (top != timer->sel->timer_top))
	wake_sel_thread(timer->sel);
    ipmi_unlock(timer->sel->timer_lock);
    return 0;
}

int
sel_stop_timer(sel_timer_t *timer)
{
    volatile sel_timer_t *top;

    ipmi_lock(timer->sel->timer_lock);
    if (!timer->in_heap) {
	ipmi_unlock(timer->sel->timer_lock);
	return ETIMEDOUT;
    }

    top = timer->sel->timer_top;

    remove_from_heap((sel_timer_t **) &(timer->sel->timer_top),
		     (sel_timer_t **) &(timer->sel->timer_last),
		     timer);
    timer->in_heap = 0;

    if (timer->sel->send_sig && (top != timer->sel->timer_top))
	wake_sel_thread(timer->sel);
    ipmi_unlock(timer->sel->timer_lock);

    return 0;
}

/* The main loop for the program.  This will select on the various
   sets, then scan for any available I/O to process.  It also monitors
   the time and call the timeout handlers periodically. */
void
sel_select_loop(selector_t      *sel,
		sel_send_sig_cb send_sig,
		long            thread_id,
		void            *cb_data)
{
    fd_set      tmp_read_set;
    fd_set      tmp_write_set;
    fd_set      tmp_except_set;
    int         i;
    int         err;
    sel_timer_t *timer;
    volatile struct timeval *to_time = &(sel->timeout);
    struct timeval now;

    for (;;) {
	ipmi_lock(sel->timer_lock);
	timer = (sel_timer_t *) sel->timer_top;
	if (timer) {
	    /* Check for timers to time out. */
	    gettimeofday(&now, NULL);
	    while (cmp_timeval(&now, &timer->timeout) >= 0) {
		remove_from_heap((sel_timer_t **) &(sel->timer_top),
				 (sel_timer_t **) &(sel->timer_last),
				 timer);

		timer->in_heap = 0;
		ipmi_unlock(sel->timer_lock);
		timer->handler(sel, timer, timer->user_data);
		ipmi_lock(sel->timer_lock);

		timer = (sel_timer_t *) sel->timer_top;
		if (!timer) {
		    break;
		}
	    }
	}

	if (timer) {
	    /* Calculate how long to wait now. */
	    gettimeofday(&now, NULL);
	    diff_timeval((struct timeval *) to_time,
			 (struct timeval *) &timer->timeout,
			 &now);
	} else {
	    /* No timers, just set a long time. */
	    to_time->tv_sec = 100000;
	    to_time->tv_usec = 0;
	}
	sel->need_wake_on_change = 1;
	ipmi_unlock(sel->timer_lock);

	ipmi_lock(sel->fd_lock);
	memcpy(&tmp_read_set, (void *) &sel->read_set, sizeof(tmp_read_set));
	memcpy(&tmp_write_set, (void *) &sel->write_set, sizeof(tmp_write_set));
	memcpy(&tmp_except_set, (void *) &sel->except_set, sizeof(tmp_except_set));
	ipmi_unlock(sel->fd_lock);

	err = select(sel->maxfd+1,
		     &tmp_read_set,
		     &tmp_write_set,
		     &tmp_except_set,
		     (struct timeval *) to_time);
	sel->need_wake_on_change = 0;
	if (err == 0) {
	    /* A timeout occurred. */
	} else if (err < 0) {
	    /* An error occurred. */
	    if (errno == EINTR) {
		/* EINTR is ok, just restart the operation. */
	    } else {
		/* An error is bad, we need to abort. */
		syslog(LOG_ERR, "select_loop() - select: %m");
		exit(1);
	    }
	} else {
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

    sel = malloc(sizeof(*sel));
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

    sel->timer_top = NULL;
    sel->timer_last = NULL;

    *new_selector = sel;

 out_err:
    if (rv) {
	if (sel->timer_lock)
	    ipmi_destroy_lock(sel->timer_lock);
	if (sel->fd_lock)
	    ipmi_destroy_lock(sel->fd_lock);
	free(sel);
    }
    return rv;
}

static void
free_heap_element(sel_timer_t *elem)
{
    if (!elem)
	return;

    free_heap_element(elem->left);
    free_heap_element(elem->right);
    free(elem);
}

int
sel_free_selector(selector_t *sel)
{
    sel_timer_t *heap;

    if (sel->timer_lock)
	ipmi_destroy_lock(sel->timer_lock);
    if (sel->fd_lock)
	ipmi_destroy_lock(sel->fd_lock);

    heap = (sel_timer_t *) sel->timer_top;

    free(sel);
    free_heap_element(heap);

    return 0;
}
