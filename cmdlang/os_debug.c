/*
 * os_debug.c
 *
 * Debugging OS handler.
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

#include <config.h>

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_debug.h>

/* Internal includes, do not use in your programs */
#include <OpenIPMI/internal/ipmi_malloc.h>

static os_vlog_t log_handler;

#ifdef HAVE_GDBM
#include <gdbm.h>

static char *gdbm_filename;
static GDBM_FILE gdbmf;
#endif


extern selector_t *debug_sel;

#ifdef IPMI_CHECK_LOCKS
static void check_no_locks(os_handler_t *handler);
#define CHECK_NO_LOCKS(handler) check_no_locks(handler)
#else
#define CHECK_NO_LOCKS(handler) do {} while(0)
#endif

struct os_hnd_fd_id_s
{
    int                fd;
    void               *cb_data;
    os_data_ready_t    data_ready;
    os_handler_t       *handler;
    os_fd_data_freed_t freed;
};

static void
fd_handler(int fd, void *data)
{
    os_hnd_fd_id_t *fd_data = (os_hnd_fd_id_t *) data;

    CHECK_NO_LOCKS(fd_data->handler);
    fd_data->data_ready(fd, fd_data->cb_data, fd_data);
    CHECK_NO_LOCKS(fd_data->handler);
}

static void
free_fd_data(int fd, void *data)
{
    os_hnd_fd_id_t *fd_data = data;

    if (fd_data->freed)
        fd_data->freed(fd, fd_data->cb_data);
    ipmi_mem_free(data);
}

static int
add_fd(os_handler_t       *handler,
       int                fd,
       os_data_ready_t    data_ready,
       void               *cb_data,
       os_fd_data_freed_t freed,
       os_hnd_fd_id_t     **id)
{
    os_hnd_fd_id_t *fd_data;
    int            rv;

    fd_data = ipmi_mem_alloc(sizeof(*fd_data));
    if (!fd_data)
	return ENOMEM;

    fd_data->fd = fd;
    fd_data->cb_data = cb_data;
    fd_data->data_ready = data_ready;
    fd_data->handler = handler;
    fd_data->freed = freed;
    rv = sel_set_fd_handlers(debug_sel, fd, fd_data, fd_handler, NULL, NULL,
			     free_fd_data);
    if (rv) {
	ipmi_mem_free(fd_data);
	return rv;
    }
    sel_set_fd_read_handler(debug_sel, fd, SEL_FD_HANDLER_ENABLED);
    sel_set_fd_write_handler(debug_sel, fd, SEL_FD_HANDLER_DISABLED);
    sel_set_fd_except_handler(debug_sel, fd, SEL_FD_HANDLER_DISABLED);

    *id = fd_data;
    return 0;
}

static int
remove_fd(os_handler_t *handler, os_hnd_fd_id_t *fd_data)
{
    sel_set_fd_read_handler(debug_sel, fd_data->fd, SEL_FD_HANDLER_DISABLED);
    sel_clear_fd_handlers(debug_sel, fd_data->fd);
    /* fd_data gets freed in the free_fd_data callback registered at
       set time. */
    return 0;
}

struct os_hnd_timer_id_s
{
    void           *cb_data;
    os_timed_out_t timed_out;
    sel_timer_t    *timer;
    int            running;
    os_handler_t   *handler;
};

static void
timer_handler(selector_t  *sel,
	      sel_timer_t *timer,
	      void        *data)
{
    os_hnd_timer_id_t *timer_data = (os_hnd_timer_id_t *) data;
    /* Make a copy of this, because the handler may delete the timer
       data. */
    os_handler_t      *os_handler = timer_data->handler;
    void              *cb_data;
    os_timed_out_t    timed_out;

    CHECK_NO_LOCKS(os_handler);
    timed_out = timer_data->timed_out;
    cb_data = timer_data->cb_data;
    timer_data->running = 0;
    timed_out(cb_data, timer_data);
    CHECK_NO_LOCKS(os_handler);
}

static int
start_timer(os_handler_t      *handler, 
	    os_hnd_timer_id_t *id,
	    struct timeval    *timeout,
	    os_timed_out_t    timed_out,
	    void              *cb_data)
{
    struct timeval    now;

    if (id->running)
	return EBUSY;

    id->running = 1;
    id->cb_data = cb_data;
    id->timed_out = timed_out;

    handler->get_monotonic_time(handler, &now);
    now.tv_sec += timeout->tv_sec;
    now.tv_usec += timeout->tv_usec;
    while (now.tv_usec >= 1000000) {
	now.tv_usec -= 1000000;
	now.tv_sec += 1;
    }

    return sel_start_timer(id->timer, &now);
}

static int
stop_timer(os_handler_t *handler, os_hnd_timer_id_t *timer_data)
{
    return sel_stop_timer(timer_data->timer);
}

static int
alloc_timer(os_handler_t      *handler, 
	    os_hnd_timer_id_t **id)
{
    os_hnd_timer_id_t *timer_data;
    int               rv;

    timer_data = ipmi_mem_alloc(sizeof(*timer_data));
    if (!timer_data)
	return ENOMEM;

    timer_data->running = 0;
    timer_data->timed_out = NULL;
    timer_data->handler = handler;

    rv = sel_alloc_timer(debug_sel, timer_handler, timer_data,
			 &(timer_data->timer));
    if (rv) {
	ipmi_mem_free(timer_data);
	return rv;
    }

    *id = timer_data;
    return 0;
}

static int
free_timer(os_handler_t *handler, os_hnd_timer_id_t *timer_data)
{
    sel_free_timer(timer_data->timer);
    ipmi_mem_free(timer_data);
    return 0;
}

static int
get_random(os_handler_t *handler, void *data, unsigned int len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    int rv;

    if (fd == -1)
	return errno;

    while (len > 0) {
	rv = read(fd, data, len);
	if (rv < 0) {
	    rv = errno;
	    goto out;
	}
	len -= rv;
    }

    rv = 0;

 out:
    close(fd);
    return rv;
}

extern void debug_vlog(const char *format, enum ipmi_log_type_e log_type,
		       va_list ap);

static void
sdebug_vlog(os_handler_t         *handler,
	    enum ipmi_log_type_e log_type,
	    const char           *format,
	    va_list              ap)
{
    if (log_handler)
	log_handler(handler, format, log_type, ap);
}

static void
sdebug_log(os_handler_t         *handler,
	enum ipmi_log_type_e log_type,
	const char            *format,
	...)
{
    va_list ap;

    va_start(ap, format);
    sdebug_vlog(handler, log_type, format, ap);
    va_end(ap);
}

#ifdef IPMI_CHECK_LOCKS
struct os_hnd_lock_s
{
    os_hnd_lock_t *next, *prev;
    int           lock_count;
};

static os_hnd_lock_t locks = { &locks, &locks, 0 };

static int
create_lock(os_handler_t  *handler,
	    os_hnd_lock_t **id)
{
    os_hnd_lock_t *lock;

    lock = malloc(sizeof(*lock));
    if (!lock)
	return ENOMEM;
    lock->lock_count = 0;
    lock->next = NULL;
    lock->prev = NULL;
    *id = lock;
    return 0;
}

static int
destroy_lock(os_handler_t  *handler,
	     os_hnd_lock_t *id)
{
    if (id->lock_count != 0) {
	IPMI_REPORT_LOCK_ERROR(handler,
			       "Release of lock when count is not zero\n");
	id->next->prev = id->prev;
	id->prev->next = id->next;
    }
    free(id);
    return 0;
}

static int
lock(os_handler_t  *handler,
     os_hnd_lock_t *id)
{
    if (id->lock_count == 0) {
	id->next = locks.next;
	id->prev = &locks;
	id->next->prev = id;
	locks.next = id;
    } else
	IPMI_REPORT_LOCK_ERROR(handler,
			       "lock called recursively\n");

    id->lock_count++;
    return 0;
}

static int
unlock(os_handler_t  *handler,
       os_hnd_lock_t *id)
{
    if (id->lock_count <= 0)
	IPMI_REPORT_LOCK_ERROR(handler,
			       "lock count went negative\n");
    id->lock_count--;
    if (id->lock_count == 0) {
	id->next->prev = id->prev;
	id->prev->next = id->next;
	id->next = NULL;
	id->prev = NULL;
    }
    return 0;
}

static void
check_no_locks(os_handler_t *handler)
{
    if (locks.next != &locks)
	IPMI_REPORT_LOCK_ERROR(handler,
			       "Locks held when all should be free\n");
}
#endif

static int
perform_one_op(os_handler_t   *os_hnd,
	       struct timeval *timeout)
{
    return sel_select(debug_sel, NULL, 0, NULL, timeout);
}

static void
operation_loop(os_handler_t *os_hnd)
{
    sel_select_loop(debug_sel, NULL, 0, NULL);
}

static void
free_os_handler(os_handler_t *os_hnd)
{
}

static void *
debug_malloc(int size)
{
    return malloc(size);
}

static void
debug_free(void *data)
{
    free(data);
}

#ifdef HAVE_GDBM
#define GDBM_FILE ".OpenIPMI_db"

static void
init_gdbm(void)
{
    if (!gdbm_filename) {
	char *home = getenv("HOME");
	if (!home)
	    return;
	gdbm_filename = malloc(strlen(home)+strlen(GDBM_FILE)+2);
	if (!gdbm_filename)
	    return;
	strcpy(gdbm_filename, home);
	strcat(gdbm_filename, "/");
	strcat(gdbm_filename, GDBM_FILE);
    }

    gdbmf = gdbm_open(gdbm_filename, 512, GDBM_WRCREAT, 0600, NULL);
    /* gdbmf will be NULL on error, which is what reports an error. */
}

static int
database_store(os_handler_t  *handler,
	       char          *key,
	       unsigned char *data,
	       unsigned int  data_len)
{
    datum gkey, gdata;
    int   rv;

    if (!gdbmf) {
	init_gdbm();
	if (!gdbmf)
	    return EINVAL;
    }

    gkey.dptr = key;
    gkey.dsize = strlen(key);
    gdata.dptr = (char *) data;
    gdata.dsize = data_len;

    rv = gdbm_store(gdbmf, gkey, gdata, GDBM_REPLACE);
    if (rv)
	return EINVAL;
    return 0;
}

static int
database_find(os_handler_t  *handler,
	      char          *key,
	      unsigned int  *fetch_completed,
	      unsigned char **data,
	      unsigned int  *data_len,
	      void (*got_data)(void          *cb_data,
			       int           err,
			       unsigned char *data,
			       unsigned int  data_len),
	      void *cb_data)
{
    datum gkey, gdata;

    if (!gdbmf) {
	init_gdbm();
	if (!gdbmf)
	    return EINVAL;
    }

    gkey.dptr = key;
    gkey.dsize = strlen(key);
    gdata = gdbm_fetch(gdbmf, gkey);
    if (!gdata.dptr)
	return EINVAL;
    *data = (unsigned char *) gdata.dptr;
    *data_len = gdata.dsize;
    *fetch_completed = 1;
    return 0;
}

static void
database_free(os_handler_t  *handler,
	      unsigned char *data)
{
    free(data);
}

static int
set_gdbm_filename(os_handler_t *os_hnd, char *name)
{
    char *nname;

    nname = strdup(name);
    if (!nname)
	return ENOMEM;
    if (gdbm_filename)
	free(gdbm_filename);
    gdbm_filename = nname;
    return 0;
}
#endif

static void sset_log_handler(os_handler_t *handler,
			     os_vlog_t    rlog_handler)
{
    log_handler = rlog_handler;
}

static int get_posix_time(clockid_t clock,
			  struct timeval *tv)
{
    struct timespec ts;
    int rv;

    rv = clock_gettime(clock, &ts);
    if (rv)
	return rv;
    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = (ts.tv_nsec + 500) / 1000;
    return 0;
}

static int get_monotonic_time(os_handler_t *handler,
			      struct timeval *tv)
{
    return get_posix_time(CLOCK_MONOTONIC, tv);
}

static int get_real_time(os_handler_t *handler,
			 struct timeval *tv)
{
    return get_posix_time(CLOCK_REALTIME, tv);
}

os_handler_t ipmi_debug_os_handlers =
{
    .mem_alloc = debug_malloc,
    .mem_free = debug_free,
    .add_fd_to_wait_for = add_fd,
    .remove_fd_to_wait_for = remove_fd,
    .start_timer = start_timer,
    .stop_timer = stop_timer,
    .alloc_timer = alloc_timer,
    .free_timer = free_timer,
#ifdef IPMI_CHECK_LOCKS
    .create_lock = create_lock,
    .destroy_lock = destroy_lock,
    .lock = lock,
    .unlock = unlock,
#else
    .create_lock = NULL,
    .destroy_lock = NULL,
    .lock = NULL,
    .unlock = NULL,
#endif
    .get_random = get_random,
    .perform_one_op = perform_one_op,
    .operation_loop = operation_loop,
    .free_os_handler = free_os_handler,
    .log = sdebug_log,
    .vlog = sdebug_vlog,
#ifdef HAVE_GDBM
    .database_store = database_store,
    .database_find = database_find,
    .database_free = database_free,
    .database_set_filename = set_gdbm_filename,
#endif
    .set_log_handler = sset_log_handler,
    .get_monotonic_time = get_monotonic_time,
    .get_real_time = get_real_time
};
