/*
 * ui_os.c
 *
 * MontaVista IPMI code, a simple curses UI, the OS interface portion
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


#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <ipmi/os_handler.h>
#include <ipmi/selector.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>

extern selector_t *ui_sel;

struct os_hnd_fd_id_s
{
    int             fd;
    void            *cb_data;
    os_data_ready_t data_ready;
};

static void
fd_handler(int fd, void *data)
{
    os_hnd_fd_id_t *fd_data = (os_hnd_fd_id_t *) data;

    fd_data->data_ready(fd, fd_data->cb_data, fd_data);
}

static int
add_fd(os_handler_t    *handler,
       int             fd,
       os_data_ready_t data_ready,
       void            *cb_data,
       os_hnd_fd_id_t  **id)
{
    os_hnd_fd_id_t *fd_data;

    fd_data = malloc(sizeof(*fd_data));
    if (!fd_data)
	return ENOMEM;

    fd_data->fd = fd;
    fd_data->cb_data = cb_data;
    fd_data->data_ready = data_ready;
    sel_set_fd_handlers(ui_sel, fd, fd_data, fd_handler, NULL, NULL);
    sel_set_fd_read_handler(ui_sel, fd, SEL_FD_HANDLER_ENABLED);
    sel_set_fd_write_handler(ui_sel, fd, SEL_FD_HANDLER_DISABLED);
    sel_set_fd_except_handler(ui_sel, fd, SEL_FD_HANDLER_DISABLED);

    *id = fd_data;
    return 0;
}

static int
remove_fd(os_handler_t *handler, os_hnd_fd_id_t *fd_data)
{
    sel_clear_fd_handlers(ui_sel, fd_data->fd);
    sel_set_fd_read_handler(ui_sel, fd_data->fd, SEL_FD_HANDLER_DISABLED);
    free(fd_data);
    return 0;
}

struct os_hnd_timer_id_s
{
    void           *cb_data;
    os_timed_out_t timed_out;
    sel_timer_t    *timer;
    int            running;
};

static void
free_timer(os_hnd_timer_id_t *timer)
{
    sel_free_timer(timer->timer);
    free(timer);
}

static void
timer_handler(selector_t  *sel,
	      sel_timer_t *timer,
	      void        *data)
{
    os_hnd_timer_id_t *timer_data = (os_hnd_timer_id_t *) data;

    timer_data->running = 0;
    timer_data->timed_out(timer_data->cb_data, timer_data);

    /* The timer might have been restarted. */
    if (!timer_data->running)
	free_timer(timer_data);
}

static int
add_timer(os_handler_t      *handler, 
	  struct timeval    *timeout,
	  os_timed_out_t    timed_out,
	  void              *cb_data,
	  os_hnd_timer_id_t **id)
{
    os_hnd_timer_id_t *timer_data;
    int               rv;
    struct timeval    now;

    timer_data = malloc(sizeof(*timer_data));
    if (!timer_data)
	return ENOMEM;

    timer_data->running = 1;
    timer_data->cb_data = cb_data;
    timer_data->timed_out = timed_out;

    gettimeofday(&now, NULL);
    now.tv_sec += timeout->tv_sec;
    now.tv_usec += timeout->tv_usec;
    while (now.tv_usec >= 1000000) {
	now.tv_usec -= 1000000;
	now.tv_sec += 1;
    }

    rv = sel_alloc_timer(ui_sel, timer_handler, timer_data,
			 &(timer_data->timer));
    if (rv) {
	free(timer_data);
	return rv;
    }

    rv = sel_start_timer(timer_data->timer, &now);
    if (rv) {
	free_timer(timer_data);
	return rv;
    }

    *id = timer_data;
    return 0;
}

static void
restart_timer(os_handler_t      *handler,
	      os_hnd_timer_id_t *id,
	      struct timeval    *timeout)
{
    struct timeval    now;


    gettimeofday(&now, NULL);
    now.tv_sec += timeout->tv_sec;
    now.tv_usec += timeout->tv_usec;
    while (now.tv_usec >= 1000000) {
	now.tv_usec -= 1000000;
	now.tv_sec += 1;
    }

    id->running = 1;

    /* This really can't fail, it can only fail if the timer is already
       running, and that won't be the case here. */
    sel_start_timer(id->timer, &now);
}

static int
remove_timer(os_handler_t *handler, os_hnd_timer_id_t *timer_data)
{
    free_timer(timer_data);
    return 0;
}

static int
get_random(os_handler_t *handler, void *data, unsigned int len)
{
    int fd = open("/dev/random", O_RDONLY);
    int rv;

    if (fd == -1)
	return errno;

    rv = read(fd, data, len);

    close(fd);
    return rv;
}

extern void ui_vlog(char *format, va_list ap);

static void
sui_log(os_handler_t *handler,
	char         *format,
	...)
{
    va_list ap;

    va_start(ap, format);
#if 1
    ui_vlog(format, ap);
#else
    vfprintf(stderr, format, ap);
#endif
    va_end(ap);
}

static void
sui_vlog(os_handler_t *handler,
	 char         *format,
	 va_list      ap)
{
#if 1
    ui_vlog(format, ap);
#else
    vfprintf(stderr, format, ap);
#endif
}

os_handler_t ipmi_ui_cb_handlers =
{
    .add_fd_to_wait_for = add_fd,
    .remove_fd_to_wait_for = remove_fd,
    .add_timer = add_timer,
    .remove_timer = remove_timer,
    .restart_timer = restart_timer,
    .create_lock = NULL,
    .destroy_lock = NULL,
    .lock = NULL,
    .unlock = NULL,
    .get_random = get_random,
    .log = sui_log,
    .vlog = sui_vlog
};
