/*
 * tcl_os_hnd.c
 *
 * TCL OS-handlers for OpenIPMI
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2006 MontaVista Software Inc.
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

/* Get the rwlocks for GNU. */
#define _GNU_SOURCE

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>

#ifdef HAVE_GDBM
#include <gdbm.h>
#endif

#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/ipmi_tcl.h>

#include <tcl.h>

typedef struct t_os_hnd_data_s
{
    int       priority;
    os_vlog_t log_handler;

#ifdef HAVE_GDBM
    char      *gdbm_filename;
    GDBM_FILE gdbmf;
    Tcl_Mutex gdbm_lock;
#endif
} t_os_hnd_data_t;


struct os_hnd_fd_id_s
{
    int                fd;
    void               *cb_data;
    os_data_ready_t    data_ready;
    os_handler_t       *handler;
    os_fd_data_freed_t freed;
};

static void
fd_handler(ClientData data, int mask)
{
    os_hnd_fd_id_t  *fd_data = (os_hnd_fd_id_t *) data;
    void            *cb_data;
    os_data_ready_t handler;
    int             fd;

    handler = fd_data->data_ready;
    cb_data = fd_data->cb_data;
    fd = fd_data->fd;
    handler(fd, cb_data, fd_data);
}

static int
add_fd(os_handler_t       *handler,
       int                fd,
       os_data_ready_t    data_ready,
       void               *cb_data,
       os_fd_data_freed_t freed,
       os_hnd_fd_id_t     **id)
{
    os_hnd_fd_id_t  *fd_data;

    fd_data = malloc(sizeof(*fd_data));
    if (!fd_data)
	return ENOMEM;
    memset(fd_data, 0, sizeof(*fd_data));

    fd_data->fd = fd;
    fd_data->cb_data = cb_data;
    fd_data->data_ready = data_ready;
    fd_data->handler = handler;
    fd_data->freed = freed;

    Tcl_CreateFileHandler(fd, TCL_READABLE, fd_handler, fd_data);

    *id = fd_data;
    return 0;
}

static int
remove_fd(os_handler_t *handler, os_hnd_fd_id_t *fd_data)
{
    Tcl_DeleteFileHandler(fd_data->fd);
    free(fd_data);
    return 0;
}

struct os_hnd_timer_id_s
{
    void           *cb_data;
    os_timed_out_t timed_out;
    int            running;
    os_handler_t   *handler;
    Tcl_TimerToken token;
};

static void
timer_handler(ClientData data)
{
    os_hnd_timer_id_t *timer_data = (os_hnd_timer_id_t *) data;
    /* Make a copy of this, because the handler may delete the timer
       data. */
    void              *cb_data;
    os_timed_out_t    timed_out;

    timed_out = timer_data->timed_out;
    cb_data = timer_data->cb_data;
    timer_data->running = 0;
    timed_out(cb_data, timer_data);
}

static int
start_timer(os_handler_t      *handler, 
	    os_hnd_timer_id_t *id,
	    struct timeval    *timeout,
	    os_timed_out_t    timed_out,
	    void              *cb_data)
{
    int interval;

    if (id->running)
	return EBUSY;

    id->running = 1;
    id->cb_data = cb_data;
    id->timed_out = timed_out;

    interval = (timeout->tv_sec * 1000) | ((timeout->tv_usec + 999) / 1000);
    id->token = Tcl_CreateTimerHandler(interval, timer_handler, id);
    return 0;
}

static int
stop_timer(os_handler_t *handler, os_hnd_timer_id_t *id)
{
    if (!id->running)
	return EINVAL;

    id->running = 0;
    Tcl_DeleteTimerHandler(id->token);
    return 0;
}

static int
alloc_timer(os_handler_t      *handler, 
	    os_hnd_timer_id_t **id)
{
    os_hnd_timer_id_t *timer_data;

    timer_data = malloc(sizeof(*timer_data));
    if (!timer_data)
	return ENOMEM;

    timer_data->running = 0;
    timer_data->timed_out = NULL;
    timer_data->handler = handler;

    *id = timer_data;
    return 0;
}

static int
free_timer(os_handler_t *handler, os_hnd_timer_id_t *id)
{
    if (id->running)
	return EBUSY;

    free(id);
    return 0;
}


static int
get_random(os_handler_t *handler, void *data, unsigned int len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    int rv = 0;

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

static void
default_vlog(const char           *format,
	     enum ipmi_log_type_e log_type,
	     va_list              ap)
{
    int do_nl = 1;

    switch(log_type)
    {
	case IPMI_LOG_INFO:
	    fprintf(stderr, "INFO: ");
	    break;

	case IPMI_LOG_WARNING:
	    fprintf(stderr, "WARN: ");
	    break;

	case IPMI_LOG_SEVERE:
	    fprintf(stderr, "SEVR: ");
	    break;

	case IPMI_LOG_FATAL:
	    fprintf(stderr, "FATL: ");
	    break;

	case IPMI_LOG_ERR_INFO:
	    fprintf(stderr, "EINF: ");
	    break;

	case IPMI_LOG_DEBUG_START:
	    do_nl = 0;
	    /* FALLTHROUGH */
	case IPMI_LOG_DEBUG:
	    fprintf(stderr, "DEBG: ");
	    break;

	case IPMI_LOG_DEBUG_CONT:
	    do_nl = 0;
	    /* FALLTHROUGH */
	case IPMI_LOG_DEBUG_END:
	    break;
    }

    vfprintf(stderr, format, ap);

    if (do_nl)
	fprintf(stderr, "\n");
}

static void
tcl_vlog(os_handler_t         *handler,
	 enum ipmi_log_type_e log_type,
	 const char           *format,
	 va_list              ap)
{
    t_os_hnd_data_t *info = handler->internal_data;
    os_vlog_t       log_handler = info->log_handler;

    if (log_handler)
	log_handler(handler, format, log_type, ap);
    else
	default_vlog(format, log_type, ap);
}

static void
tcl_log(os_handler_t         *handler,
	enum ipmi_log_type_e log_type,
	const char           *format,
	...)
{
    va_list ap;

    va_start(ap, format);
    tcl_vlog(handler, log_type, format, ap);
    va_end(ap);
}

struct os_hnd_lock_s
{
    Tcl_Mutex mutex;
};

static int
create_lock(os_handler_t  *handler,
	    os_hnd_lock_t **id)
{
    os_hnd_lock_t *lock;

    lock = malloc(sizeof(*lock));
    if (!lock)
	return ENOMEM;
    memset(lock, 0, sizeof(*lock));

    *id = lock;
    return 0;
}

static int
destroy_lock(os_handler_t  *handler,
	     os_hnd_lock_t *id)
{
    Tcl_MutexFinalize(&id->mutex);
    free(id);
    return 0;
}

static int
lock(os_handler_t  *handler,
     os_hnd_lock_t *id)
{
    Tcl_MutexLock(&id->mutex);
    return 0;
}

static int
unlock(os_handler_t  *handler,
       os_hnd_lock_t *id)
{
    Tcl_MutexUnlock(&id->mutex);
    return 0;
}

/*
 * Tcl conditions provide neither an indication of timeout for a timed
 * condition wait nor a broadcast function.  Those have to be simulated
 * and that requires some complexity.
 */
struct os_hnd_cond_s
{
    unsigned int  waiters;
    unsigned int  woken;
    Tcl_Condition cond;
};

static int
create_cond(os_handler_t  *handler,
	    os_hnd_cond_t **new_cond)
{
    os_hnd_cond_t *cond;

    cond = malloc(sizeof(*cond));
    if (!cond)
	return ENOMEM;
    memset(cond, 0, sizeof(*cond));

    *new_cond = cond;
    return 0;
}

static int
destroy_cond(os_handler_t  *handler,
	     os_hnd_cond_t *cond)
{
    if (cond->waiters)
	return EBUSY;
    Tcl_ConditionFinalize(cond->cond);
    free(cond);
    return 0;
}

static int
cond_wait(os_handler_t  *handler,
	  os_hnd_cond_t *cond,
	  os_hnd_lock_t *lock)
{
    while (cond->waiters >= cond->woken) {
	cond->waiters++;
	Tcl_ConditionWait(&cond->cond, &lock->mutex, NULL);
	cond->waiters--;
    }
    cond->woken--;
    return 0;
}

static int
cond_timedwait(os_handler_t   *handler,
	       os_hnd_cond_t  *cond,
	       os_hnd_lock_t  *lock,
	       struct timeval *rtimeout)
{
    Tcl_Time timeout;
    Tcl_Time then;
    Tcl_Time now;

    /* Calculate when the timeout should occur. */
    Tcl_GetTime(&then);
    then.sec += rtimeout->tv_sec;
    then.usec += rtimeout->tv_usec;
    while (then.usec >= 1000000) {
	then.usec -= 1000000;
	then.sec += 1;
    }
    while (then.usec < 0) {
	then.usec += 1000000;
	then.sec -= 1;
    }

    timeout.sec = rtimeout->tv_sec;
    timeout.usec = rtimeout->tv_usec;
    while (cond->waiters >= cond->woken) {
	cond->waiters++;
	Tcl_ConditionWait(&cond->cond, &lock->mutex, &timeout);
	cond->waiters--;
	/* If we are woken, just return. */
	if (cond->waiters < cond->woken)
	    break;

	/* Otherwise, calculate the time left.  If it is <0, then we
	   have timed out. */
	Tcl_GetTime(&now);
	timeout.sec = then.sec - now.sec;
	timeout.usec = then.usec - now.usec;
	while (then.usec < 0) {
	    timeout.usec += 1000000;
	    timeout.sec -= 1;
	}
	if (timeout.sec < 0)
	    return ETIMEDOUT;
    }
    cond->woken--;
    return 0;
}

static int
cond_wake(os_handler_t  *handler,
	  os_hnd_cond_t *cond)
{
    cond->woken++;
    Tcl_ConditionNotify(&cond->cond);
    return 0;
}

static int
cond_broadcast(os_handler_t  *handler,
	       os_hnd_cond_t *cond)
{
    while (cond->waiters > cond->woken) {
	cond->woken++;
	Tcl_ConditionNotify(&cond->cond);
    }
    return 0;
}

#if 0
static int
create_thread(os_handler_t       *handler,
	      int                priority,
	      void               (*startup)(void *data),
	      void               *data)
{
    int rv;

    rv = Tcl_CreateThread(NULL, startup, data, TCL_THREAD_STACK_DEFAULT,
			  TCL_THREAD_NOFLAGS);

    return 0;
}

static int
thread_exit(os_handler_t *handler)
{
    Tcl_ExitThread(0);
    return 0;
}
#endif

static void
timeout_callback(ClientData data)
{
    /* Nothing to do */
}

static int
perform_one_op(os_handler_t   *os_hnd,
	       struct timeval *timeout)
{
    /* Note that this is not technically 100% correct in a
       multi-threaded environment, since another thread may run
       it, but it is pretty close, I guess. */
    int   time_ms;
    Tcl_TimerToken token = NULL;

    if (timeout) {
	time_ms= (timeout->tv_sec * 1000) + ((timeout->tv_usec+500) / 1000);
	token = Tcl_CreateTimerHandler(time_ms, timeout_callback, NULL);
    }
    Tcl_DoOneEvent(TCL_ALL_EVENTS);
    if (token)
	Tcl_DeleteTimerHandler(token);
    return 0;
}

static void
operation_loop(os_handler_t *os_hnd)
{
    for (;;)
	Tcl_DoOneEvent(TCL_ALL_EVENTS);
}

static void
free_os_handler(os_handler_t *os_hnd)
{
    t_os_hnd_data_t *info = os_hnd->internal_data;

#ifdef HAVE_GDBM
    Tcl_MutexFinalize(&info->gdbm_lock);
    if (info->gdbm_filename)
	free(info->gdbm_filename);
    if (info->gdbmf)
	gdbm_close(info->gdbmf);
#endif
    free(info);
    free(os_hnd);
}

static void *
tcl_malloc(int size)
{
    return malloc(size);
}

static void
tcl_free(void *data)
{
    free(data);
}

#ifdef HAVE_GDBM
#define GDBM_FILE ".OpenIPMI_db"

static void
init_gdbm(t_os_hnd_data_t *info)
{
    if (!info->gdbm_filename) {
	char *home = getenv("HOME");
	if (!home)
	    return;
	info->gdbm_filename = malloc(strlen(home)+strlen(GDBM_FILE)+2);
	if (!info->gdbm_filename)
	    return;
	strcpy(info->gdbm_filename, home);
	strcat(info->gdbm_filename, "/");
	strcat(info->gdbm_filename, GDBM_FILE);
    }

    info->gdbmf = gdbm_open(info->gdbm_filename, 512, GDBM_WRCREAT, 0600,
			    NULL);
    /* gdbmf will be NULL on error, which is what reports an error. */
}

static int
database_store(os_handler_t  *handler,
	       char          *key,
	       unsigned char *data,
	       unsigned int  data_len)
{
    t_os_hnd_data_t *info = handler->internal_data;
    datum           gkey, gdata;
    int             rv;

    Tcl_MutexLock(&info->gdbm_lock);
    if (!info->gdbmf) {
	init_gdbm(info);
	if (!info->gdbmf) {
	    Tcl_MutexUnlock(&info->gdbm_lock);
	    return EINVAL;
	}
    }

    gkey.dptr = key;
    gkey.dsize = strlen(key);
    gdata.dptr = (char *) data;
    gdata.dsize = data_len;

    rv = gdbm_store(info->gdbmf, gkey, gdata, GDBM_REPLACE);
    Tcl_MutexUnlock(&info->gdbm_lock);
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
    t_os_hnd_data_t *info = handler->internal_data;
    datum           gkey, gdata;

    Tcl_MutexLock(&info->gdbm_lock);
    if (!info->gdbmf) {
	init_gdbm(info);
	if (!info->gdbmf) {
	    Tcl_MutexUnlock(&info->gdbm_lock);
	    return EINVAL;
	}
    }

    gkey.dptr = key;
    gkey.dsize = strlen(key);
    gdata = gdbm_fetch(info->gdbmf, gkey);
    Tcl_MutexUnlock(&info->gdbm_lock);
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
    t_os_hnd_data_t *info = os_hnd->internal_data;
    char            *nname;

    nname = strdup(name);
    if (!nname)
	return ENOMEM;
    if (info->gdbm_filename)
	free(info->gdbm_filename);
    info->gdbm_filename = nname;
    return 0;
}
#endif

void sset_log_handler(os_handler_t *handler,
		      os_vlog_t    log_handler)
{
    t_os_hnd_data_t *info = handler->internal_data;

    info->log_handler = log_handler;
}

static int get_tcl_time(os_handler_t *handler,
			struct timeval *tv)
{
    Tcl_Time now;
    Tcl_GetTime(&now);
    tv->tv_sec = now.sec;
    tv->tv_usec = now.usec;
    return 0;
}


static os_handler_t ipmi_tcl_os_handler =
{
    .mem_alloc = tcl_malloc,
    .mem_free = tcl_free,

    .add_fd_to_wait_for = add_fd,
    .remove_fd_to_wait_for = remove_fd,

    .start_timer = start_timer,
    .stop_timer = stop_timer,
    .alloc_timer = alloc_timer,
    .free_timer = free_timer,

    .get_random = get_random,
    .log = tcl_log,
    .vlog = tcl_vlog,

    .create_lock = create_lock,
    .destroy_lock = destroy_lock,
    .lock = lock,
    .unlock = unlock,

    .create_cond = create_cond,
    .destroy_cond = destroy_cond,
    .cond_wait = cond_wait,
    .cond_timedwait = cond_timedwait,
    .cond_wake = cond_wake,
    .cond_broadcast = cond_broadcast,

#if 0
    .create_thread = create_thread,
    .thread_exit = thread_exit,
#endif

    .free_os_handler = free_os_handler,

    .perform_one_op = perform_one_op,
    .operation_loop = operation_loop,

#ifdef HAVE_GDBM
    .database_store = database_store,
    .database_find = database_find,
    .database_free = database_free,
    .database_set_filename = set_gdbm_filename,
#endif
    .set_log_handler = sset_log_handler,
    .get_monotonic_time = get_tcl_time,
    .get_real_time = get_tcl_time
};


os_handler_t *
ipmi_tcl_get_os_handler(int priority)
{
    os_handler_t    *rv;
    t_os_hnd_data_t *info;

    rv = malloc(sizeof(*rv));
    if (!rv)
	return NULL;

    memcpy(rv, &ipmi_tcl_os_handler, sizeof(*rv));

    info = malloc(sizeof(*info));
    if (! info) {
	free(rv);
	return NULL;
    }
    memset(info, 0, sizeof(*info));

    info->priority = priority;
    rv->internal_data = info;

    return rv;
}
