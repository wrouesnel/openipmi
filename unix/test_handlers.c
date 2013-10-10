/*
 * test_handlers.c
 *
 * Basic tests for POSIX OS handlers.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <OpenIPMI/ipmi_posix.h>

os_handler_t *test_os_hnd;

static void
err_leave(int err, char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    if (err)
	fprintf(stderr, "error: %s (%d)\n", strerror(err), err);
    va_end(ap);
    exit(1);
}

int expect_log = 0;

static void
my_vlog(os_handler_t         *handler,
	const char           *format,
	enum ipmi_log_type_e log_type,
	va_list              ap)
{
    if (expect_log == 0) {
	int ival;
	char *sval;
	expect_log++;
	if (strcmp(format, "This is a test: %d %s") != 0)
	    err_leave(0, "Wrong format\n");
	if (log_type != IPMI_LOG_FATAL)
	    err_leave(0, "Invalid log type\n");
	ival = va_arg(ap, int);
	if (ival != 47)
	    err_leave(0, "Invalid log int val\n");
	sval = va_arg(ap, char *);
	if (strcmp(sval, "Hello") != 0)
	    err_leave(0, "Invalid log string val\n");
    } else {
	vfprintf(stderr, format, ap);
	err_leave(0, "Unexpected log!\n");
    }
}

static inline void
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

os_handler_waiter_t *timer_waiter;
int expect_timeout = 0;
static void
timeout_handler(void *cb_data, os_hnd_timer_id_t *id)
{
    struct timeval *then = cb_data;
    struct timeval now;
    struct timeval diff;
    int            rv;

    printf("Timeout!\n");
    test_os_hnd->get_monotonic_time(test_os_hnd, &now);
    diff_timeval(&diff, &now, then);
    if (expect_timeout == 0) {
	expect_timeout++;
	if (diff.tv_sec != 1)
	    err_leave(0, "Invalid timeout diff 0: %ld %ld\n",
		      diff.tv_sec, diff.tv_usec);
	diff.tv_sec = 0;
	diff.tv_usec = 500000;
	*then = now;
	rv = test_os_hnd->start_timer(test_os_hnd, id, &diff,
				      timeout_handler, then);
    } else if (expect_timeout == 1) {
	expect_timeout++;
	if (diff.tv_sec != 0)
	    err_leave(0, "Invalid timeout diff 1: %ld %ld\n",
		      diff.tv_sec, diff.tv_usec);
	os_handler_waiter_release(timer_waiter);
    } else {
	err_leave(0, "Unexpected timeout!\n");
    }
}

static void
test_os_handler(os_handler_t *os_hnd, os_handler_waiter_factory_t *factory)
{
    os_hnd_timer_id_t           *timer;
    struct timeval              now;
    struct timeval              tv;
    int                         rv;

    test_os_hnd = os_hnd;

    /* Override the default log handler (so I can catch them). */
    os_hnd->set_log_handler(os_hnd, my_vlog);

    printf("Log test\n");
    os_hnd->log(os_hnd, IPMI_LOG_FATAL, "This is a test: %d %s",
		47, "Hello");

    printf("Timer test\n");
    timer_waiter = os_handler_alloc_waiter(factory);
    if (!timer_waiter)
	err_leave(0, "Unable to allocate waiter\n");

    rv = os_hnd->alloc_timer(os_hnd, &timer);
    if (rv)
	err_leave(rv, "Unable to allocate timer");

    os_hnd->get_monotonic_time(os_hnd, &now);
    tv.tv_sec = 1;
    tv.tv_usec = 500000;
    rv = os_hnd->start_timer(os_hnd, timer, &tv, timeout_handler, &now);

    tv.tv_sec = 3;
    tv.tv_usec = 0;
    os_handler_waiter_wait(timer_waiter, &tv);

    if (expect_timeout != 2)
	err_leave(0, "Error in timers: %d\n", expect_timeout);

    os_handler_free_waiter(timer_waiter);

    rv = os_handler_free_waiter_factory(factory);
    if (rv)
	err_leave(rv, "Error freeing factory\n");

    os_hnd->free_os_handler(os_hnd);
}

static void
reset_tests(void)
{
    expect_log = 0;
    expect_timeout = 0;
}

int ipmi_malloc_init(os_handler_t *os_hnd);

int
main(int argc, char *argv[])
{
    os_handler_waiter_factory_t *factory;
    os_handler_t *os_hnd;
    int          rv;

    printf("*** Testing POSIX OS handler\n");
    reset_tests();
    os_hnd = ipmi_posix_setup_os_handler();
    if (!os_hnd) {
	fprintf(stderr, "ipmi_smi_setup_con: Unable to allocate os handler\n");
	exit(1);
    }
    ipmi_malloc_init(os_hnd);
    rv = os_handler_alloc_waiter_factory(os_hnd, 2, 0, &factory);
    if (rv != ENOSYS)
	err_leave(rv, "Expected ENOSYS allocating threaded factory\n");
    rv = os_handler_alloc_waiter_factory(os_hnd, 0, 0, &factory);
    if (rv)
	err_leave(rv, "Unable to allocate waiter factory\n");
    test_os_handler(os_hnd, factory);

    printf("*** Testing POSIX Threaded OS handler (multithread)\n");
    reset_tests();
    os_hnd = ipmi_posix_thread_setup_os_handler(SIGUSR1);
    if (!os_hnd) {
	fprintf(stderr, "ipmi_smi_setup_con: Unable to allocate os handler\n");
	exit(1);
    }
    ipmi_malloc_init(os_hnd);
    rv = os_handler_alloc_waiter_factory(os_hnd, 2, 0, &factory);
    if (rv)
	err_leave(rv, "Unable to allocate waiter factory\n");
    test_os_handler(os_hnd, factory);

    printf("*** Testing POSIX Threaded OS handler (singlethread)\n");
    reset_tests();
    os_hnd = ipmi_posix_thread_setup_os_handler(SIGUSR1);
    if (!os_hnd) {
	fprintf(stderr, "ipmi_smi_setup_con: Unable to allocate os handler\n");
	exit(1);
    }
    ipmi_malloc_init(os_hnd);
    rv = os_handler_alloc_waiter_factory(os_hnd, 0, 0, &factory);
    if (rv)
	err_leave(rv, "Unable to allocate waiter factory\n");
    test_os_handler(os_hnd, factory);

    return 0;
}
