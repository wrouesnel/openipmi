/*
 * ui.c
 *
 * MontaVista IPMI code, a simple curses UI for IPMI
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004 MontaVista Software Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curses.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>

#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_ui.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_pef.h>
#include <OpenIPMI/ipmi_lanparm.h>
#include <OpenIPMI/ipmi_pet.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_debug.h>
#include <OpenIPMI/internal/ipmi_mc.h>

#include <OpenIPMI/internal/ipmi_malloc.h>
#include <OpenIPMI/internal/ipmi_event.h>

#include "ui_keypad.h"
#include "ui_command.h"

WINDOW *main_win;
WINDOW *cmd_win;
WINDOW *stat_win;
WINDOW *log_pad;
WINDOW *dummy_pad;
WINDOW *display_pad;

selector_t *ui_sel;

int log_pad_top_line;
int display_pad_top_line;

keypad_t keymap;
command_t commands;

ipmi_domain_id_t domain_id;

extern os_handler_t ipmi_ui_cb_handlers;
ipmi_pef_t *pef;
ipmi_pef_config_t *pef_config;
ipmi_lanparm_t *lanparm;
ipmi_lan_config_t *lanparm_config;

static int full_screen;
struct termios old_termios;
int old_flags;

#define STATUS_WIN_LINES 2
#define STATUS_WIN_COLS COLS
#define STATUS_WIN_TOP 0
#define STATUS_WIN_LEFT 0

#define CMD_WIN_LINES 3
#define CMD_WIN_COLS COLS
#define CMD_WIN_LEFT 0
#define CMD_WIN_TOP  (LINES-CMD_WIN_LINES)

#define DISPLAY_WIN_LINES (LINES - STATUS_WIN_LINES - CMD_WIN_LINES - 2)
#define DISPLAY_WIN_COLS (COLS/2-1)
#define DISPLAY_WIN_TOP (STATUS_WIN_LINES+1)
#define DISPLAY_WIN_LEFT 0
#define DISPLAY_WIN_RIGHT (COLS/2-2)
#define DISPLAY_WIN_BOTTOM (CMD_WIN_TOP-2)
#define NUM_DISPLAY_LINES 1024

#define LOG_WIN_LINES (LINES - STATUS_WIN_LINES - CMD_WIN_LINES - 2)
#define LOG_WIN_COLS (COLS-(COLS/2))
#define LOG_WIN_LEFT (COLS/2)
#define LOG_WIN_RIGHT (COLS-1)
#define LOG_WIN_TOP (STATUS_WIN_LINES+1)
#define LOG_WIN_BOTTOM (CMD_WIN_TOP-2)
#define NUM_LOG_LINES 1024

#define TOP_LINE    STATUS_WIN_LINES
#define BOTTOM_LINE (LINES-CMD_WIN_LINES-1)
#define MID_COL (COLS/2-1)
#define MID_LINES (LINES - STATUS_WIN_LINES - CMD_WIN_LINES - 2)

enum scroll_wins_e { LOG_WIN_SCROLL, DISPLAY_WIN_SCROLL };

enum scroll_wins_e curr_win = LOG_WIN_SCROLL;

/* The current thing display in the display pad. */
enum {
    DISPLAY_NONE, DISPLAY_SENSOR, DISPLAY_SENSORS,
    DISPLAY_CONTROLS, DISPLAY_CONTROL, DISPLAY_ENTITIES, DISPLAY_MCS,
    DISPLAY_MC,
    DISPLAY_RSP, DISPLAY_SDRS, HELP, EVENTS, DISPLAY_ENTITY, DISPLAY_FRU
} curr_display_type;
ipmi_sensor_id_t curr_sensor_id;
ipmi_control_id_t curr_control_id;
typedef struct pos_s {int y; int x; } pos_t;
typedef struct thr_pos_s
{
    int   set;
    pos_t value;
    pos_t enabled;
    pos_t oor;
} thr_pos_t;
thr_pos_t threshold_positions[6];

pos_t value_pos;
pos_t enabled_pos;
pos_t scanning_pos;
pos_t discr_assert_enab;
pos_t discr_deassert_enab;

ipmi_entity_id_t curr_entity_id;

static char *line_buffer = NULL;
static int  line_buffer_max = 0;
static int  line_buffer_pos = 0;

sel_timer_t *redisplay_timer;

static void
conv_from_spaces(char *name)
{
    while (*name) {
	if (*name == ' ')
	    *name = '~';
	name++;
    }
}

static void
conv_to_spaces(char *name)
{
    while (*name) {
	if (*name == '~')
	    *name = ' ';
	name++;
    }
}

void
log_pad_refresh(int newlines)
{
    if (full_screen) {
	if (log_pad_top_line < 0)
	    log_pad_top_line = 0;

	if (log_pad_top_line > (NUM_LOG_LINES - LOG_WIN_LINES))
	    log_pad_top_line = NUM_LOG_LINES - LOG_WIN_LINES;

	if (log_pad_top_line != (NUM_LOG_LINES - LOG_WIN_LINES)) {
	    /* We are not at the bottom, so hold the same position. */
	    log_pad_top_line -= newlines;
	}
	prefresh(log_pad,
		 log_pad_top_line, 0,
		 LOG_WIN_TOP, LOG_WIN_LEFT,
		 LOG_WIN_BOTTOM, LOG_WIN_RIGHT);
	wrefresh(cmd_win);
    }
}

void
vlog_pad_out(const char *format, va_list ap)
{
    if (full_screen)
	vw_printw(log_pad, format, ap);
    else
	vprintf(format, ap);
}

void
log_pad_out(char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vlog_pad_out(format, ap);
    va_end(ap);
}

void
display_pad_refresh(void)
{
    if (full_screen) {
	if (display_pad_top_line >= NUM_DISPLAY_LINES)
	    display_pad_top_line = NUM_DISPLAY_LINES;

	if (display_pad_top_line < 0)
	    display_pad_top_line = 0;

	prefresh(display_pad,
		 display_pad_top_line, 0,
		 DISPLAY_WIN_TOP, DISPLAY_WIN_LEFT,
		 DISPLAY_WIN_BOTTOM, DISPLAY_WIN_RIGHT);
	wrefresh(cmd_win);
    }
}

void
display_pad_clear(void)
{
    display_pad_top_line = 0;
    if (full_screen) {
	werase(display_pad);
	wmove(display_pad, 0, 0);
    }
}

void
display_pad_clear_nomove(void)
{
    if (full_screen) {
	werase(display_pad);
	wmove(display_pad, 0, 0);
    }
}

void
display_pad_out(char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    if (full_screen)
	vw_printw(display_pad, format, ap);
    else
	vprintf(format, ap);
    va_end(ap);
}

void
cmd_win_out(char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    if (full_screen)
	vw_printw(cmd_win, format, ap);
    else
	vprintf(format, ap);
    va_end(ap);
}

void
cmd_win_refresh(void)
{
    if (full_screen)
	wrefresh(cmd_win);
    else
	fflush(stdout);
}

static int
get_uchar(char **toks, unsigned char *val, char *errstr)
{
    char *str, *tmpstr;

    str = strtok_r(NULL, " \t\n", toks);
    if (!str) {
	if (errstr)
	    cmd_win_out("No %s given\n", errstr);
	return EINVAL;
    }
    *val = strtoul(str, &tmpstr, 16);
    if (*tmpstr != '\0') {
	if (errstr)
	    cmd_win_out("Invalid %s given\n", errstr);
	return EINVAL;
    }

    return 0;
}

static int
get_uint(char **toks, unsigned int *val, char *errstr)
{
    char *str, *tmpstr;

    str = strtok_r(NULL, " \t\n", toks);
    if (!str) {
	if (errstr)
	    cmd_win_out("No %s given\n", errstr);
	return EINVAL;
    }
    *val = strtoul(str, &tmpstr, 16);
    if (*tmpstr != '\0') {
	if (errstr)
	    cmd_win_out("Invalid %s given\n", errstr);
	return EINVAL;
    }

    return 0;
}

static int
get_ip_addr(char **toks, struct in_addr *ip_addr, char *errstr)
{
    u_int32_t     addr;
    unsigned char val;
    char          *str, *tmpstr, *istr;
    char          *ntok;
    int           i;

    str = strtok_r(NULL, " \t\n", toks);
    if (!str) {
	if (errstr)
	    cmd_win_out("No %s given\n", errstr);
	return EINVAL;
    }

    addr = 0;
    for (i=0; i<4; i++) {
	istr = strtok_r(str, ".", &ntok);
	str = NULL;
	if (!istr) {
	    if (errstr)
		cmd_win_out("%s: invalid IP address\n", errstr);
	    return EINVAL;
	}
	val = strtoul(istr, &tmpstr, 10);
	if (*tmpstr != '\0') {
	    if (errstr)
		cmd_win_out("%s: Invalid IP address\n", errstr);
	    return EINVAL;
	}
	addr = (addr << 8) | val;
    }

    ip_addr->s_addr = htonl(addr);
    return 0;
}

static int
get_mac_addr(char **toks, unsigned char *mac_addr, char *errstr)
{
    char *str, *tmpstr, *istr;
    char *ntok;
    int  i;

    str = strtok_r(NULL, " \t\n", toks);
    if (!str) {
	if (errstr)
	    cmd_win_out("No %s given\n", errstr);
	return EINVAL;
    }

    for (i=0; i<6; i++) {
	istr = strtok_r(str, ":", &ntok);
	str = NULL;
	if (!istr) {
	    if (errstr)
		cmd_win_out("%s: invalid IP address\n", errstr);
	    return EINVAL;
	}
	mac_addr[i] = strtoul(istr, &tmpstr, 16);
	if (*tmpstr != '\0') {
	    if (errstr)
		cmd_win_out("%s: Invalid IP address\n", errstr);
	    return EINVAL;
	}
    }
    return 0;
}

void
draw_lines()
{
    werase(main_win);
    wmove(main_win, TOP_LINE, 0);
    whline(main_win, 0, COLS);
    wmove(main_win, BOTTOM_LINE, 0);
    whline(main_win, 0, COLS);
    wmove(main_win, TOP_LINE, MID_COL);
    wvline(main_win, ACS_TTEE, 1);
    wmove(main_win, TOP_LINE+1, MID_COL);
    wvline(main_win, 0, MID_LINES);
    wmove(main_win, TOP_LINE+1+MID_LINES, MID_COL);
    wvline(main_win, ACS_BTEE, 1);
    wrefresh(main_win);
}    

void
ui_vlog(const char *format, enum ipmi_log_type_e log_type, va_list ap)
{
    int do_nl = 1;
    struct timeval now;

    gettimeofday(&now, NULL);

    if (full_screen) {
	int x = 0, y = 0, old_x = 0, old_y = 0;
	int max_x, max_y, i, j;

	/* Generate the output to the dummy pad to see how many lines we
	   will use. */
	getyx(dummy_pad, old_y, old_x);
	switch(log_type)
	{
	    case IPMI_LOG_INFO:
		wprintw(dummy_pad, "%d.%6.6d: ", now.tv_sec, now.tv_usec);
		wprintw(dummy_pad, "INFO: ");
		break;

	    case IPMI_LOG_WARNING:
		wprintw(dummy_pad, "%d.%6.6d: ", now.tv_sec, now.tv_usec);
		wprintw(dummy_pad, "WARN: ");
		break;

	    case IPMI_LOG_SEVERE:
		wprintw(dummy_pad, "%d.%6.6d: ", now.tv_sec, now.tv_usec);
		wprintw(dummy_pad, "SEVR: ");
		break;

	    case IPMI_LOG_FATAL:
		wprintw(dummy_pad, "%d.%6.6d: ", now.tv_sec, now.tv_usec);
		wprintw(dummy_pad, "FATL: ");
		break;

	    case IPMI_LOG_ERR_INFO:
		wprintw(dummy_pad, "%d.%6.6d: ", now.tv_sec, now.tv_usec);
		wprintw(dummy_pad, "EINF: ");
		break;

	    case IPMI_LOG_DEBUG_START:
		do_nl = 0;
		/* FALLTHROUGH */
	    case IPMI_LOG_DEBUG:
		wprintw(dummy_pad, "%d.%6.6d: ", now.tv_sec, now.tv_usec);
		wprintw(dummy_pad, "DEBG: ");
		break;

	    case IPMI_LOG_DEBUG_CONT:
		do_nl = 0;
		/* FALLTHROUGH */
	    case IPMI_LOG_DEBUG_END:
		break;
	}
	vw_printw(dummy_pad, format, ap);
	if (do_nl)
	    wprintw(dummy_pad, "\n");
	getyx(dummy_pad, y, x);

	if (old_y == y) {
	    for (j=old_x; j<x; j++)
		waddch(log_pad, mvwinch(dummy_pad, y, j));
	} else {
	    getmaxyx(dummy_pad, max_y, max_x);
	    for (j=old_x; j<max_x; j++)
		waddch(log_pad, mvwinch(dummy_pad, old_y, j));
	    for (i=old_y+1; i<y; i++) {
		for (j=0; j<max_x; j++)
		    waddch(log_pad, mvwinch(dummy_pad, i, j));
	    }
	    for (j=0; j<x; j++)
		waddch(log_pad, mvwinch(dummy_pad, y, j));
	}
	y -= old_y;
	wmove(dummy_pad, 0, x);
	log_pad_refresh(y);
    } else {
	switch(log_type)
	{
	    case IPMI_LOG_INFO:
		log_pad_out("%d.%6.6d: ", now.tv_sec, now.tv_usec);
		log_pad_out("INFO: ");
		break;

	    case IPMI_LOG_WARNING:
		log_pad_out("%d.%6.6d: ", now.tv_sec, now.tv_usec);
		log_pad_out("WARN: ");
		break;

	    case IPMI_LOG_SEVERE:
		log_pad_out("%d.%6.6d: ", now.tv_sec, now.tv_usec);
		log_pad_out("SEVR: ");
		break;

	    case IPMI_LOG_FATAL:
		log_pad_out("%d.%6.6d: ", now.tv_sec, now.tv_usec);
		log_pad_out("FATL: ");
		break;

	    case IPMI_LOG_ERR_INFO:
		log_pad_out("%d.%6.6d: ", now.tv_sec, now.tv_usec);
		log_pad_out("EINF: ");
		break;

	    case IPMI_LOG_DEBUG_START:
		do_nl = 0;
		/* FALLTHROUGH */
	    case IPMI_LOG_DEBUG:
		log_pad_out("%d.%6.6d: ", now.tv_sec, now.tv_usec);
		log_pad_out("DEBG: ");
		break;

	    case IPMI_LOG_DEBUG_CONT:
		do_nl = 0;
		/* FALLTHROUGH */
	    case IPMI_LOG_DEBUG_END:
		break;
	}

	vlog_pad_out(format, ap);
	if (do_nl)
	    log_pad_out("\n");
	log_pad_refresh(0);
    }
    cmd_win_refresh();
}

void
ui_log(char *format, ...)
{
    int y = 0, x;
    struct timeval now;
    va_list ap;

    gettimeofday(&now, NULL);

    va_start(ap, format);

    if (full_screen) {
	/* Generate the output to the dummy pad to see how many lines we
	   will use. */
	wprintw(dummy_pad, "%d.%6.6d: ", now.tv_sec, now.tv_usec);
	vw_printw(dummy_pad, format, ap);
	getyx(dummy_pad, y, x);
	wmove(dummy_pad, 0, x);
	va_end(ap);
	va_start(ap, format);
    }

    log_pad_out("%ld.%6.6ld: ", now.tv_sec, now.tv_usec);
    vlog_pad_out(format, ap);
    log_pad_refresh(y);
    cmd_win_refresh();
    va_end(ap);
}

void
leave(int rv, char *format, ...)
{
    va_list ap;

    ipmi_shutdown();

    sel_stop_timer(redisplay_timer);
    sel_free_timer(redisplay_timer);

    if (full_screen) {
	endwin();
	full_screen = 0;
    } else {
	tcsetattr(0, TCSADRAIN, &old_termios);
	fcntl(0, F_SETFL, old_flags);
	tcdrain(0);
    }

    if (pef_config) {
	ipmi_pef_free_config(pef_config);
	pef_config = NULL;
    }
    if (pef) {
	ipmi_pef_destroy(pef, NULL, NULL);
	pef = NULL;
    }
    if (lanparm_config) {
	ipmi_lan_free_config(lanparm_config);
	lanparm_config = NULL;
    }
    if (lanparm) {
	ipmi_lanparm_destroy(lanparm, NULL, NULL);
	lanparm = NULL;
    }

    if (line_buffer) {
	ipmi_mem_free(line_buffer);
    }
    command_free(commands);
    keypad_free(keymap);

    sel_free_selector(ui_sel);

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    ipmi_debug_malloc_cleanup();
    exit(rv);
}

void
leave_err(int err, char *format, ...)
{
    va_list ap;

    if (full_screen)
	endwin();
    else {
	tcsetattr(0, TCSADRAIN, &old_termios);
	fcntl(0, F_SETFL, old_flags);
	tcdrain(0);
    }
    sel_free_selector(ui_sel);

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    if (IPMI_IS_OS_ERR(err)) {
	fprintf(stderr, ": %s\n", strerror(IPMI_GET_OS_ERR(err)));
    } else {
	fprintf(stderr, ": IPMI Error %2.2x\n",	IPMI_GET_IPMI_ERR(err));
    }

    ipmi_debug_malloc_cleanup();
    exit(1);
}

void
recalc_windows(void)
{
    draw_lines();

    mvwin(stat_win, STATUS_WIN_TOP, STATUS_WIN_LEFT);
    wresize(stat_win, STATUS_WIN_LINES, STATUS_WIN_COLS);
    wrefresh(stat_win);
    touchwin(stat_win);

    wresize(display_pad, DISPLAY_WIN_LINES, DISPLAY_WIN_COLS);

    mvwin(cmd_win, CMD_WIN_TOP, CMD_WIN_LEFT);
    wresize(cmd_win, CMD_WIN_LINES, CMD_WIN_COLS);
    wrefresh(cmd_win);
    touchwin(cmd_win);

    wresize(log_pad, NUM_LOG_LINES, LOG_WIN_COLS);
    wresize(dummy_pad, NUM_LOG_LINES, LOG_WIN_COLS);

    doupdate();

    log_pad_refresh(0);
    display_pad_refresh();
}

static
void handle_user_char(int c)
{
    int err = keypad_handle_key(keymap, c, NULL);
    if (err)
	ui_log("Got error on char 0x%x 0%o %d\n", c, c, c);
}

void
user_input_ready(int fd, void *data)
{
    int c;

    if (full_screen) {
	c = wgetch(cmd_win);
	while (c != ERR) {
	    handle_user_char(c);
	    c = wgetch(cmd_win);
	}
    } else {
	char rc;
	int count;

	count = read(0, &rc, 1);
	if (count > 0)
	    handle_user_char(rc);
    }
}

static int
normal_char(int key, void *cb_data)
{
    char out[2];

    if (line_buffer_pos >= line_buffer_max) {
	char *new_line = ipmi_mem_alloc(line_buffer_max+10+1);
	if (!new_line)
	    return ENOMEM;
	line_buffer_max += 10;
	if (line_buffer) {
	    memcpy(new_line, line_buffer, line_buffer_pos);
	    ipmi_mem_free(line_buffer);
	}
	line_buffer = new_line;
    }
    line_buffer[line_buffer_pos] = key;
    line_buffer_pos++;
    out[0] = key;
    out[1] = '\0';
    cmd_win_out(out);
    cmd_win_refresh();
    return 0;
}

static int
end_of_line(int key, void *cb_data)
{
    int err;

    if (!line_buffer)
	return 0;

    line_buffer[line_buffer_pos] = '\0';
    cmd_win_out("\n");
    err = command_handle(commands, line_buffer, NULL);
    if (err)
	cmd_win_out("Invalid command: %s\n> ", line_buffer);
    else
	cmd_win_out("> ");
    line_buffer_pos = 0;
    cmd_win_refresh();
    return 0;
}

static int
backspace(int key, void *cb_data)
{
    if (line_buffer_pos == 0)
	return 0;

    line_buffer_pos--;
    cmd_win_out("\b \b");
    cmd_win_refresh();
    return 0;
}

static int
key_up(int key, void *cb_data)
{
    return 0;
}

static int
key_down(int key, void *cb_data)
{
    return 0;
}

static int
key_right(int key, void *cb_data)
{
    return 0;
}

static int
key_left(int key, void *cb_data)
{
    return 0;
}

static int
key_ppage(int key, void *cb_data)
{
    if (curr_win == LOG_WIN_SCROLL) {
	log_pad_top_line -= (LOG_WIN_LINES-1);
	log_pad_refresh(0);
    } else if (curr_win == DISPLAY_WIN_SCROLL) {
	display_pad_top_line -= (DISPLAY_WIN_LINES-1);
	display_pad_refresh();
    }
    return 0;
}

static int
key_npage(int key, void *cb_data)
{
    if (curr_win == LOG_WIN_SCROLL) {
	log_pad_top_line += (LOG_WIN_LINES-1);
	log_pad_refresh(0);
    } else if (curr_win == DISPLAY_WIN_SCROLL) {
	display_pad_top_line += (DISPLAY_WIN_LINES-1);
	display_pad_refresh();
    }
    return 0;
}

static int leave_count = 0;

static void
final_leave(void *cb_data)
{
    leave_count--;
    if (leave_count == 0)
	leave(0, "");
}

static void
leave_cmder(ipmi_domain_t *domain, void *cb_data)
{
    int rv;

    rv = ipmi_domain_close(domain, final_leave, NULL);
    if (!rv)
	leave_count++;
}

static int
key_leave(int key, void *cb_data)
{
    ipmi_domain_iterate_domains(leave_cmder, NULL);
    if (leave_count == 0)
	leave(0, "");

    return 0;
}

static int
key_resize(int key, void *cb_data)
{
    recalc_windows();
    return 0;
}

static int
key_set_display(int key, void *cb_data)
{
    curr_win = DISPLAY_WIN_SCROLL;
    return 0;
}

static int
key_set_log(int key, void *cb_data)
{
    curr_win = LOG_WIN_SCROLL;
    return 0;
}

/* Includes 3 3-byte fields (entity id, entity instance, and slave
   address) and 1 2-byte field (channel) and three periods and the nil
   char at the end and possible a leading "r" for device-relative. */
#define MAX_ENTITY_LOC_SIZE 16

/* Convert an entity to a locator for the entity.  This is either:
     <num>.<num> for an absolute entity, or
     r<num>.<num>.<num>.<num> for a device-relative entity. */
static char *
get_entity_loc(ipmi_entity_t *entity, char *str, int strlen)
{
    ipmi_entity_id_t id;

    id = ipmi_entity_convert_to_id(entity);
    if (id.entity_instance >= 0x60)
	snprintf(str, strlen, "r%d.%d.%d.%d",
		 id.channel,
		 id.address,
		 id.entity_id,
		 id.entity_instance - 0x60);
    else
	snprintf(str, strlen, "%d.%d",
		 id.entity_id,
		 id.entity_instance);
    return str;
}

static void
entities_handler(ipmi_entity_t *entity,
		 void          *cb_data)
{
    char *present;
    char loc[MAX_ENTITY_LOC_SIZE];
    char name[33];
    enum ipmi_dlr_type_e type;
    static char *ent_types[] = { "unknown", "mc", "fru",
				 "generic", "invalid" };

    type = ipmi_entity_get_type(entity);
    if (type > IPMI_ENTITY_GENERIC)
	type = IPMI_ENTITY_GENERIC + 1;
    curr_entity_id = ipmi_entity_convert_to_id(entity);
    ipmi_entity_get_id(entity, name, 32);
    if (strlen(name) == 0)
	strncpy(name, ipmi_entity_get_entity_id_string(entity), 33);
    if (ipmi_entity_is_present(entity))
	present = "present";
    else
	present = "not present";
    display_pad_out("  %s (%s) %s  %s\n",
		    get_entity_loc(entity, loc, sizeof(loc)),
		    name,
		    ent_types[type], present);
}

static void
entities_cmder(ipmi_domain_t *domain, void *cb_data)
{
    if (cb_data)
	display_pad_clear_nomove();
    else
	display_pad_clear();
    display_pad_out("Entities:\n");
    ipmi_domain_iterate_entities(domain, entities_handler, NULL);
    display_pad_refresh();
}

static int
entities_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    rv = ipmi_domain_pointer_cb(domain_id, entities_cmder, NULL);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
	return 0;
    }
    curr_display_type = DISPLAY_ENTITIES;
    return 0;
}

typedef void (*entity_handler_cb)(ipmi_entity_t *entity,
				  char          **toks,
				  char          **toks2,
				  void          *cb_data);
struct ent_rec {
    int id, instance, found;
    int channel, address;
    entity_handler_cb handler;
    char **toks, **toks2;
    void *cb_data;
};

static void
entity_searcher(ipmi_entity_t *entity,
		void          *cb_data)
{
    struct ent_rec   *info = cb_data;
    ipmi_entity_id_t id;

    id = ipmi_entity_convert_to_id(entity);
    if ((info->id == id.entity_id)
	&& (info->instance == id.entity_instance)
	&& (info->address == id.address)
	&& (info->channel == id.channel))
    {
	info->found = 1;
	info->handler(entity, info->toks, info->toks2, info->cb_data);
    }
}

static void
entity_finder_d(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_domain_iterate_entities(domain, entity_searcher, cb_data);
}

int
entity_finder(char *cmd, char **toks,
	      entity_handler_cb handler,
	      void *cb_data)
{
    struct ent_rec info;
    char           *ent_name;
    char           *id_name, *instance_name, *toks2, *estr;
    int            rv;

    ent_name = strtok_r(NULL, " \t\n", toks);
    if (!ent_name) {
	cmd_win_out("No entity given\n");
	return EINVAL;
    }

    if (ent_name[0] == 'r') {
	/* Device-relative address. */
	char *name;
	name = strtok_r(ent_name+1, ".", &toks2);
	info.channel = strtoul(name, &estr, 0);
	if (*estr != '\0') {
	    cmd_win_out("Invalid entity channel given\n");
	    return EINVAL;
	}

	name = strtok_r(NULL, ".", &toks2);
	info.address = strtoul(name, &estr, 0);
	if (*estr != '\0') {
	    cmd_win_out("Invalid entity address given\n");
	    return EINVAL;
	}

	id_name = strtok_r(NULL, ".", &toks2);
    } else {
	info.address = 0;
	info.channel = 0;
	id_name = strtok_r(ent_name, ".", &toks2);
    }
    instance_name = strtok_r(NULL, ".", &toks2);
    if (!instance_name) {
	cmd_win_out("Invalid entity given\n");
	return EINVAL;
    }
    info.id = strtoul(id_name, &estr, 0);
    if (*estr != '\0') {
	cmd_win_out("Invalid entity id given\n");
	return EINVAL;
    }
    info.instance = strtoul(instance_name, &estr, 0);
    if (*estr != '\0') {
	cmd_win_out("Invalid entity instance given\n");
	return EINVAL;
    }
    if (ent_name[0] == 'r')
	info.instance += 0x60;

    info.found = 0;

    info.handler = handler;
    info.cb_data = cb_data;
    info.toks = toks;
    info.toks2 = &toks2;

    rv = ipmi_domain_pointer_cb(domain_id, entity_finder_d, &info);
    if (!info.found) {
	if (ent_name[0] == 'r')
	    cmd_win_out("Entity r%d.%d.%d.%d not found\n",
			info.channel, info.address, info.id,
			info.instance-0x60);
	else
	    cmd_win_out("Entity %d.%d not found\n", info.id, info.instance);

	return EINVAL;
    }

    return 0;
}

static void
entity_iterate_handler(ipmi_entity_t *o,
		       ipmi_entity_t *entity,
		       void          *cb_data)
{
    char name[33];
    char loc[MAX_ENTITY_LOC_SIZE];

    ipmi_entity_get_id(entity, name, 32);

    display_pad_out("    %s (%s)\n",
		    get_entity_loc(entity, loc, sizeof(loc)),
		    name);
}

static void
entity_handler(ipmi_entity_t *entity,
	       char          **toks,
	       char          **toks2,
	       void          *cb_data)
{
    char *present;
    char name[33];
    char ename[IPMI_ENTITY_NAME_LEN];
    char loc[MAX_ENTITY_LOC_SIZE];
    enum ipmi_dlr_type_e type;
    static char *ent_types[] = { "unknown", "mc", "fru",
				 "generic", "invalid" };

    display_pad_clear();
    type = ipmi_entity_get_type(entity);
    if (type > IPMI_ENTITY_GENERIC)
	type = IPMI_ENTITY_GENERIC + 1;
    curr_entity_id = ipmi_entity_convert_to_id(entity);
    ipmi_entity_get_id(entity, name, 32);
    if (ipmi_entity_is_present(entity))
	present = "present";
    else
	present = "not present";
    display_pad_out("Entity %s (%s)  %s\n", 
		    get_entity_loc(entity, loc, sizeof(loc)),
		    name,  present);

    ipmi_entity_get_name(entity, ename, sizeof(ename));
    display_pad_out("  name = %s\n", ename);

    display_pad_out("  type = %s\n", ent_types[type]);
    display_pad_out("  entity id string = %s\n",
		    ipmi_entity_get_entity_id_string(entity));
    display_pad_out("  is%s fru\n",
		    ipmi_entity_get_is_fru(entity) ? "" : " not");
    display_pad_out("  present sensor%s always there\n",
		    ipmi_entity_get_presence_sensor_always_there(entity)
		    ? "" : " not");
    if (ipmi_entity_get_is_child(entity)) {
	display_pad_out("  Parents:\n");
	ipmi_entity_iterate_parents(entity, entity_iterate_handler, NULL);
    }
    if (ipmi_entity_get_is_parent(entity)) {
	display_pad_out("  Children:\n");
	ipmi_entity_iterate_children(entity, entity_iterate_handler, NULL);
    }

    switch (type) {
    case IPMI_ENTITY_MC:
	display_pad_out("  channel = 0x%x\n", ipmi_entity_get_channel(entity));
	display_pad_out("  lun = 0x%x\n", ipmi_entity_get_lun(entity));
	display_pad_out("  oem = 0x%x\n", ipmi_entity_get_oem(entity));
	display_pad_out("  slave_address = 0x%x\n",
			ipmi_entity_get_slave_address(entity));
	display_pad_out("  ACPI_system_power_notify_required = 0x%x\n",
			ipmi_entity_get_ACPI_system_power_notify_required(entity));
	display_pad_out("  ACPI_device_power_notify_required = 0x%x\n",
			ipmi_entity_get_ACPI_device_power_notify_required(entity));
	display_pad_out("  controller_logs_init_agent_errors = 0x%x\n",
			ipmi_entity_get_controller_logs_init_agent_errors(entity));
	display_pad_out("  log_init_agent_errors_accessing = 0x%x\n",
			ipmi_entity_get_log_init_agent_errors_accessing(entity));
	display_pad_out("  global_init = 0x%x\n",
			ipmi_entity_get_global_init(entity));
	display_pad_out("  chassis_device = 0x%x\n",
			ipmi_entity_get_chassis_device(entity));
	display_pad_out("  bridge = 0x%x\n",
			ipmi_entity_get_bridge(entity));
	display_pad_out("  IPMB_event_generator = 0x%x\n",
			ipmi_entity_get_IPMB_event_generator(entity));
	display_pad_out("  IPMB_event_receiver = 0x%x\n",
			ipmi_entity_get_IPMB_event_receiver(entity));
	display_pad_out("  FRU_inventory_device = 0x%x\n",
			ipmi_entity_get_FRU_inventory_device(entity));
	display_pad_out("  SEL_device = 0x%x\n",
			ipmi_entity_get_SEL_device(entity));
	display_pad_out("  SDR_repository_device = 0x%x\n",
			ipmi_entity_get_SDR_repository_device(entity));
	display_pad_out("  sensor_device = 0x%x\n",
			ipmi_entity_get_sensor_device(entity));
	break;

    case IPMI_ENTITY_FRU:
	display_pad_out("  channel = 0x%x\n", ipmi_entity_get_channel(entity));
	display_pad_out("  lun = 0x%x\n", ipmi_entity_get_lun(entity));
	display_pad_out("  oem = 0x%x\n", ipmi_entity_get_oem(entity));
	display_pad_out("  access_address = 0x%x\n",
			ipmi_entity_get_access_address(entity));
	display_pad_out("  private_bus_id = 0x%x\n",
			ipmi_entity_get_private_bus_id(entity));
	display_pad_out("  device_type = 0x%x\n",
			ipmi_entity_get_device_type(entity));
	display_pad_out("  device_modifier = 0x%x\n",
			ipmi_entity_get_device_modifier(entity));
	display_pad_out("  is_logical_fru = 0x%x\n",
			ipmi_entity_get_is_logical_fru(entity));
	display_pad_out("  fru_device_id = 0x%x\n",
			ipmi_entity_get_fru_device_id(entity));
	break;

    case IPMI_ENTITY_GENERIC:
	display_pad_out("  channel = 0x%x\n", ipmi_entity_get_channel(entity));
	display_pad_out("  lun = 0x%x\n", ipmi_entity_get_lun(entity));
	display_pad_out("  oem = 0x%x\n", ipmi_entity_get_oem(entity));
	display_pad_out("  access_address = 0x%x\n",
			ipmi_entity_get_access_address(entity));
	display_pad_out("  private_bus_id = 0x%x\n",
			ipmi_entity_get_private_bus_id(entity));
	display_pad_out("  device_type = 0x%x\n",
			ipmi_entity_get_device_type(entity));
	display_pad_out("  device_modifier = 0x%x\n",
			ipmi_entity_get_device_modifier(entity));
	display_pad_out("  slave_address = 0x%x\n",
			ipmi_entity_get_slave_address(entity));
	display_pad_out("  address_span = 0x%x\n",
			ipmi_entity_get_address_span(entity));
	break;

    default:
	break;
    }
    display_pad_refresh();
}

int
entity_cmd(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, entity_handler, NULL);
    curr_display_type = DISPLAY_ENTITY;
    return 0;
}


static void
hs_get_act_time_cb(ipmi_entity_t  *ent,
		   int            err,
		   ipmi_timeout_t val,
		   void           *cb_data)
{
    char loc[MAX_ENTITY_LOC_SIZE];

    if (err) {
	ui_log("Could not get hot-swap act time: error 0x%x\n", err);
	return;
    }

    ui_log("Hot-swap activate time for %s is %lld\n",
	   get_entity_loc(ent, loc, sizeof(loc)), val);
}

static void
hs_get_act_time_handler(ipmi_entity_t *entity,
			char          **toks,
			char          **toks2,
			void          *cb_data)
{
    int rv;

    rv = ipmi_entity_get_auto_activate_time(entity, hs_get_act_time_cb, NULL);
    if (rv)
	cmd_win_out("Could not get auto-activate: error 0x%x\n", rv);
}

int
hs_get_act_time(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, hs_get_act_time_handler, NULL);
    return 0;
}

static void
hs_set_act_time_cb(ipmi_entity_t  *ent,
		   int            err,
		   void           *cb_data)
{
    if (err)
	ui_log("Could not get hot-swap act time: error 0x%x\n", err);
    else
	ui_log("hot-swap act time set\n");
}

static void
hs_set_act_time_handler(ipmi_entity_t *entity,
			char          **toks,
			char          **toks2,
			void          *cb_data)
{
    int          rv;
    unsigned int timeout;

    if (get_uint(toks, &timeout, "Hot swap activate time"))
	return;

    rv = ipmi_entity_set_auto_activate_time(entity, timeout,
					    hs_set_act_time_cb, NULL);
    if (rv)
	cmd_win_out("Could not set auto-activate: error 0x%x\n", rv);
}

int
hs_set_act_time(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, hs_set_act_time_handler, NULL);
    return 0;
}

static void
hs_get_deact_time_cb(ipmi_entity_t  *ent,
		     int            err,
		     ipmi_timeout_t val,
		     void           *cb_data)
{
    char loc[MAX_ENTITY_LOC_SIZE];

    if (err) {
	ui_log("Could not get hot-swap deact time: error 0x%x\n", err);
	return;
    }

    ui_log("Hot-swap deactivate time for %s is %lld\n",
	   get_entity_loc(ent, loc, sizeof(loc)), val);
}

static void
hs_get_deact_time_handler(ipmi_entity_t *entity,
			  char          **toks,
			  char          **toks2,
			  void          *cb_data)
{
    int rv;

    rv = ipmi_entity_get_auto_deactivate_time(entity, hs_get_deact_time_cb, NULL);
    if (rv)
	cmd_win_out("Could not get auto-deactivate: error 0x%x\n", rv);
}

int
hs_get_deact_time(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, hs_get_deact_time_handler, NULL);
    return 0;
}

static void
hs_set_deact_time_cb(ipmi_entity_t  *ent,
		     int            err,
		     void           *cb_data)
{
    if (err)
	ui_log("Could not get hot-swap deact time: error 0x%x\n", err);
    else
	ui_log("hot-swap deact time set\n");
}

static void
hs_set_deact_time_handler(ipmi_entity_t *entity,
			  char          **toks,
			  char          **toks2,
			  void          *cb_data)
{
    int rv;
    unsigned int timeout;

    if (get_uint(toks, &timeout, "Hot swap deactivate time"))
	return;

    rv = ipmi_entity_set_auto_deactivate_time(entity, timeout,
					      hs_set_deact_time_cb, NULL);
    if (rv)
	cmd_win_out("Could not set auto-deactivate: error 0x%x\n", rv);
}

int
hs_set_deact_time(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, hs_set_deact_time_handler, NULL);
    return 0;
}

static void
hs_activation_request_cb(ipmi_entity_t  *ent,
			 int            err,
			 void           *cb_data)
{
    if (err)
	ui_log("Could not activate entity: error 0x%x\n", err);
    else
	ui_log("entity activated\n");
}

static void
hs_activation_request_handler(ipmi_entity_t *entity,
			      char          **toks,
			      char          **toks2,
			      void          *cb_data)
{
    int rv;

    rv = ipmi_entity_set_activation_requested(entity,
					      hs_activation_request_cb,
					      NULL);
    if (rv)
	cmd_win_out("Could not set activation requested: error 0x%x\n", rv);
}

static int
hs_activation_request(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, hs_activation_request_handler, NULL);
    return 0;
}

static void
hs_activate_cb(ipmi_entity_t  *ent,
	       int            err,
	       void           *cb_data)
{
    if (err)
	ui_log("Could not activate entity: error 0x%x\n", err);
    else
	ui_log("entity activated\n");
}

static void
hs_activate_handler(ipmi_entity_t *entity,
		    char          **toks,
		    char          **toks2,
		    void          *cb_data)
{
    int rv;

    rv = ipmi_entity_activate(entity, hs_activate_cb, NULL);
    if (rv)
	cmd_win_out("Could not activate entity: error 0x%x\n", rv);
}

int
hs_activate(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, hs_activate_handler, NULL);
    return 0;
}

static void
hs_deactivate_cb(ipmi_entity_t  *ent,
		 int            err,
		 void           *cb_data)
{
    if (err)
	ui_log("Could not deactivate entity: error 0x%x\n", err);
    else
	ui_log("entity deactivated\n");
}

static void
hs_deactivate_handler(ipmi_entity_t *entity,
		      char          **toks,
		      char          **toks2,
		      void          *cb_data)
{
    int rv;

    rv = ipmi_entity_deactivate(entity, hs_deactivate_cb, NULL);
    if (rv)
	cmd_win_out("Could not deactivate entity: error 0x%x\n", rv);
}

int
hs_deactivate(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, hs_deactivate_handler, NULL);
    return 0;
}

static void
hs_state_cb(ipmi_entity_t             *ent,
	    int                       err,
	    enum ipmi_hot_swap_states state,
	    void                      *cb_data)
{
    if (err)
	ui_log("Could not get hot-swap state: error 0x%x\n", err);
    else
	ui_log("Hot-swap state is %s\n", ipmi_hot_swap_state_name(state));
}

static void
hs_state_handler(ipmi_entity_t *entity,
		 char          **toks,
		 char          **toks2,
		 void          *cb_data)
{
    int rv;

    rv = ipmi_entity_get_hot_swap_state(entity, hs_state_cb, NULL);
    if (rv)
	cmd_win_out("Could not get entity state: error 0x%x\n", rv);
}

int
hs_state(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, hs_state_handler, NULL);
    return 0;
}

static void
hs_check_ent(ipmi_entity_t *entity, void *cb_data)
{
    ipmi_entity_check_hot_swap_state(entity);
}

static void
hs_check_cmder(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_domain_iterate_entities(domain, hs_check_ent, NULL);
}

int
hs_check_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    rv = ipmi_domain_pointer_cb(domain_id, hs_check_cmder, NULL);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
	return 0;
    }
    
    return 0;
}



static void
sensors_handler(ipmi_entity_t *entity, ipmi_sensor_t *sensor, void *cb_data)
{
    char name[33];
    char name2[33];
    char loc[MAX_ENTITY_LOC_SIZE];

    ipmi_sensor_get_id(sensor, name, 33);
    strcpy(name2, name);
    conv_from_spaces(name2);
    display_pad_out("  %s.%s - %s\n",
		    get_entity_loc(entity, loc, sizeof(loc)),
		    name2, name);
}

static void
found_entity_for_sensors(ipmi_entity_t *entity,
			 char          **toks,
			 char          **toks2,
			 void          *cb_data)
{
    char loc[MAX_ENTITY_LOC_SIZE];

    curr_display_type = DISPLAY_SENSORS;
    display_pad_clear();
    display_pad_out("Sensors for entity %s:\n",
		    get_entity_loc(entity, loc, sizeof(loc)));
    ipmi_entity_iterate_sensors(entity, sensors_handler, NULL);
    display_pad_refresh();
}

int
sensors_cmd(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, found_entity_for_sensors, NULL);
    return 0;
}

struct sensor_info {
    int  found;
    char *name;
};

/* Has this sensor been displayed yet? */
int sensor_displayed;

/* Decrement whenever the sensor is not displayed and data is
   recevied, when this hits zero it's time to display. */
int sensor_ops_to_read_count;

/* Return value from ipmi_states_get or ipmi_reading_get. */
int sensor_read_err;

/* Values from ipmi_reading_get. */
enum ipmi_value_present_e sensor_value_present;
unsigned int              sensor_raw_val;
double                    sensor_val;

/* Values from ipmi_states_get and ipmi_reading_get. */
ipmi_states_t *sensor_states;

/* Values from ipmi_sensor_event_enables_get. */
int                sensor_event_states_err;
ipmi_event_state_t *sensor_event_states;

/* Values from ipmi_thresholds_get */
int               sensor_read_thresh_err;
ipmi_thresholds_t *sensor_thresholds;

static void
display_sensor(ipmi_entity_t *entity, ipmi_sensor_t *sensor)
{
    char loc[MAX_ENTITY_LOC_SIZE];
    char name[33];
    char sname[IPMI_SENSOR_NAME_LEN];
    int  rv;

    if (sensor_displayed)
	return;

    sensor_ops_to_read_count--;
    if (sensor_ops_to_read_count > 0)
	return;

    sensor_displayed = 1;

    ipmi_sensor_get_name(sensor, sname, sizeof(sname));

    ipmi_sensor_get_id(sensor, name, 33);
    display_pad_clear();

    conv_from_spaces(name);
    display_pad_out("Sensor %s.%s:\n",
		    get_entity_loc(entity, loc, sizeof(loc)),
		    name);
    if (ipmi_sensor_get_ignore_if_no_entity(sensor))
	display_pad_out("  ignore if entity not present\n");
    else
	display_pad_out("  still there if entity not present\n");
    display_pad_out("  name = %s\n", sname);
    display_pad_out("  value = ");
    getyx(display_pad, value_pos.y, value_pos.x);
    if (!ipmi_entity_is_present(entity)
	&& ipmi_sensor_get_ignore_if_no_entity(sensor))
    {
	display_pad_out("not present");
    } else {
	if (sensor_read_err) {
	    display_pad_out("unreadable");
	} else if (ipmi_sensor_get_event_reading_type(sensor)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    if (sensor_value_present == IPMI_BOTH_VALUES_PRESENT)
		display_pad_out("%f (%2.2x)", sensor_val, sensor_raw_val);
	    else if (sensor_value_present == IPMI_RAW_VALUE_PRESENT)
		display_pad_out("0x%x (RAW)", sensor_raw_val);
	    else
		display_pad_out("unreadable");
	} else {
	    int i;
	    for (i=0; i<15; i++) {
		int val;
		val = ipmi_is_state_set(sensor_states, i);
		display_pad_out("%d", val != 0);
	    }    
	}
    }
    display_pad_out("\n  Events = ");
    getyx(display_pad, enabled_pos.y, enabled_pos.x);
    if (sensor_event_states_err)
	display_pad_out("?         ");
    else {
	int global_enable;
	global_enable = ipmi_event_state_get_events_enabled
	    (sensor_event_states);
	if (global_enable)
	    display_pad_out("enabled");
	else
	    display_pad_out("disabled");
    }
    display_pad_out("\n  Scanning = ");
    getyx(display_pad, scanning_pos.y, scanning_pos.x);
    if (sensor_event_states_err)
	display_pad_out("?         ");
    else {
	int scanning_enable;
	scanning_enable = ipmi_event_state_get_scanning_enabled
	    (sensor_event_states);
	if (scanning_enable)
	    display_pad_out("enabled");
	else
	    display_pad_out("disabled");
    }
    display_pad_out("\n  Hysteresis = ");
    switch (ipmi_sensor_get_hysteresis_support(sensor)) {
    case IPMI_HYSTERESIS_SUPPORT_NONE: display_pad_out("none"); break;
    case IPMI_HYSTERESIS_SUPPORT_READABLE: display_pad_out("readable"); break;
    case IPMI_HYSTERESIS_SUPPORT_SETTABLE: display_pad_out("settable"); break;
    case IPMI_HYSTERESIS_SUPPORT_FIXED: display_pad_out("fixed"); break;
    default: display_pad_out("invalid"); break;
    }
    display_pad_out("\n");
    display_pad_out("  sensor type = %s (0x%2.2x)\n",
		    ipmi_sensor_get_sensor_type_string(sensor),
		    ipmi_sensor_get_sensor_type(sensor));
    display_pad_out("  event/reading type = %s (0x%2.2x)\n",
		    ipmi_sensor_get_event_reading_type_string(sensor),
		    ipmi_sensor_get_event_reading_type(sensor));

    if (ipmi_sensor_get_event_reading_type(sensor)
	== IPMI_EVENT_READING_TYPE_THRESHOLD)
    {
	enum ipmi_thresh_e t;
	double val;

	display_pad_out("  units = %s%s",
			ipmi_sensor_get_base_unit_string(sensor),
			ipmi_sensor_get_rate_unit_string(sensor));
	switch(ipmi_sensor_get_modifier_unit_use(sensor)) {
	case IPMI_MODIFIER_UNIT_BASE_DIV_MOD:
	    display_pad_out("/%s",
			    ipmi_sensor_get_modifier_unit_string(sensor));
	    break;
		
	case IPMI_MODIFIER_UNIT_BASE_MULT_MOD:
	    display_pad_out("*%s",
			    ipmi_sensor_get_modifier_unit_string(sensor));
	    break;

	case IPMI_MODIFIER_UNIT_NONE:
	    break;
	}
	display_pad_out("\n");

	rv = ipmi_sensor_get_nominal_reading(sensor, &val);
	if (!rv) display_pad_out("  nominal = %f\n", val);
	
	rv = ipmi_sensor_get_normal_min(sensor, &val);
	if (!rv) display_pad_out("  normal_min = %f\n", val);
	
	rv = ipmi_sensor_get_normal_max(sensor, &val);
	if (!rv) display_pad_out("  normal_max = %f\n", val);
	
	rv = ipmi_sensor_get_sensor_min(sensor, &val);
	if (!rv) display_pad_out("  sensor_min = %f\n", val);
	
	rv = ipmi_sensor_get_sensor_max(sensor, &val);
	if (!rv) display_pad_out("  sensor_max = %f\n", val);
	
	display_pad_out("Thresholds:\n");
	for (t=IPMI_LOWER_NON_CRITICAL; t<=IPMI_UPPER_NON_RECOVERABLE; t++){
	    int settable, readable;
	    int i;
	    int assert_sup[2], deassert_sup[2];
	    int anything_set = 0;
	    
	    ipmi_sensor_threshold_settable(sensor, t, &settable);
	    anything_set |= settable;
	    ipmi_sensor_threshold_readable(sensor, t, &readable);
	    anything_set |= readable;
	    for (i=0; i<=1; i++) {
		ipmi_sensor_threshold_event_supported(
		    sensor, t, i, IPMI_ASSERTION, &(assert_sup[i]));
		anything_set |= assert_sup[i];
		ipmi_sensor_threshold_event_supported(
		    sensor, t, i, IPMI_DEASSERTION, &(deassert_sup[i]));
		anything_set |= deassert_sup[i];
	    }
	    if (anything_set) {
		display_pad_out("  %s:", ipmi_get_threshold_string(t));
		threshold_positions[t].set = 1;
		display_pad_out("\n    available: ");
		if (readable) display_pad_out("R");
		else display_pad_out(" ");
		if (settable) display_pad_out("W");
		else display_pad_out(" ");
		if (assert_sup[0]) display_pad_out("L^");
		else display_pad_out("  ");
		if (deassert_sup[0]) display_pad_out("Lv");
		else display_pad_out("  ");
		if (assert_sup[1]) display_pad_out("H^");
		else display_pad_out("  ");
		if (deassert_sup[1]) display_pad_out("Hv");
		else display_pad_out("  ");
		display_pad_out("\n      enabled: ");
		getyx(display_pad,
		      threshold_positions[t].enabled.y,
		      threshold_positions[t].enabled.x);
		if (sensor_event_states_err)
		    display_pad_out("?         ");
		else {
		    if (ipmi_is_threshold_event_set(sensor_event_states, t,
						    IPMI_GOING_LOW,
						    IPMI_ASSERTION))
			display_pad_out("L^");
		    else
			display_pad_out("  ");
		    if (ipmi_is_threshold_event_set(sensor_event_states, t,
						    IPMI_GOING_LOW,
						    IPMI_DEASSERTION))
			display_pad_out("Lv");
		    else
			display_pad_out("  ");
		    if (ipmi_is_threshold_event_set(sensor_event_states, t,
						    IPMI_GOING_HIGH,
						    IPMI_ASSERTION))
			display_pad_out("H^");
		    else
			display_pad_out("  ");
		    if (ipmi_is_threshold_event_set(sensor_event_states, t,
						    IPMI_GOING_HIGH,
						    IPMI_DEASSERTION))
			display_pad_out("HV");
		    else
			display_pad_out("  ");
		}
		    
		display_pad_out("\n        value: ");
		getyx(display_pad,
		      threshold_positions[t].value.y,
		      threshold_positions[t].value.x);
		if (sensor_read_thresh_err)
		    display_pad_out("?");
		else {
		    double val;
		    rv = ipmi_threshold_get(sensor_thresholds, t, &val);
		    if (rv)
			display_pad_out("?", val);
		    else
			display_pad_out("%f", val);
		}
		display_pad_out("\n out of range: ");
		getyx(display_pad,
		      threshold_positions[t].oor.y,
		      threshold_positions[t].oor.x);
		if (!sensor_read_err) {
		    if (ipmi_is_threshold_out_of_range(sensor_states, t))
			display_pad_out("true ");
		    else
			display_pad_out("false");
		}
		display_pad_out("\n");
	    } else {
		threshold_positions[t].set = 0;
	    }
	}
    } else {
	int val;
	int i;
	
	/* A discrete sensor. */
	display_pad_out("\n  Assertion: ");
	display_pad_out("\n    available: ");
	for (i=0; i<15; i++) {
	    ipmi_sensor_discrete_event_supported(sensor,
						 i,
						 IPMI_ASSERTION,
						 &val);
	    display_pad_out("%d", val != 0);
	}
	display_pad_out("\n      enabled: ");
	getyx(display_pad, discr_assert_enab.y, discr_assert_enab.x);
	if (sensor_event_states_err)
	    display_pad_out("?");
	else {
	    for (i=0; i<15; i++) {
		val = ipmi_is_discrete_event_set(sensor_event_states,
						 i, IPMI_ASSERTION);
		display_pad_out("%d", val != 0);
	    }
	}   

	display_pad_out("\n  Deasertion: ");
	display_pad_out("\n    available: ");
	for (i=0; i<15; i++) {
	    ipmi_sensor_discrete_event_supported(sensor,
						 i,
						 IPMI_DEASSERTION,
						 &val);
	    display_pad_out("%d", val != 0);
	}
	display_pad_out("\n      enabled: ");
	getyx(display_pad, discr_deassert_enab.y, discr_deassert_enab.x);
	if (sensor_event_states_err)
	    display_pad_out("?");
	else {
	    for (i=0; i<15; i++) {
		val = ipmi_is_discrete_event_set(sensor_event_states,
						 i, IPMI_DEASSERTION);
		display_pad_out("%d", val != 0);
	    }
	}
	display_pad_out("\n");
    }

    display_pad_refresh();
}

static void
read_sensor(ipmi_sensor_t             *sensor,
	    int                       err,
	    enum ipmi_value_present_e value_present,
	    unsigned int              raw_val,
	    double                    val,
	    ipmi_states_t             *states,
	    void                      *cb_data)
{
    ipmi_sensor_id_t   sensor_id;
    enum ipmi_thresh_e t;

    if (err) {
	if (sensor_displayed) {
	    wmove(display_pad, value_pos.y, value_pos.x);
	    display_pad_out("unreadable: %x", err);
	    display_pad_refresh();
	} else {
	    curr_display_type = DISPLAY_NONE;
	}
	return;
    }

    sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!((curr_display_type == DISPLAY_SENSOR)
	  && (ipmi_cmp_sensor_id(sensor_id, curr_sensor_id) == 0)))
	return;

    if (sensor_displayed) {
	wmove(display_pad, value_pos.y, value_pos.x);
	if (value_present == IPMI_BOTH_VALUES_PRESENT)
	    display_pad_out("%f (%2.2x)", val, raw_val);
	else if (value_present == IPMI_RAW_VALUE_PRESENT)
	    display_pad_out("0x%x (RAW)", raw_val);
	else
	    display_pad_out("unreadable");

	for (t=IPMI_LOWER_NON_CRITICAL; t<=IPMI_UPPER_NON_RECOVERABLE; t++) {
	    if (threshold_positions[t].set) {
		wmove(display_pad,
		      threshold_positions[t].oor.y,
		      threshold_positions[t].oor.x);
		if (ipmi_is_threshold_out_of_range(states, t))
		    display_pad_out("true ");
		else
		    display_pad_out("false");
	    }
	}    
	display_pad_refresh();
    } else {
	sensor_read_err = err;
	sensor_value_present = value_present;
	sensor_raw_val = raw_val;
	sensor_val = val;
	if (states)
	    ipmi_copy_states(sensor_states, states);
	display_sensor(ipmi_sensor_get_entity(sensor), sensor);
    }
}


static void
read_thresholds(ipmi_sensor_t     *sensor,
		int               err,
		ipmi_thresholds_t *th,
		void              *cb_data)
{
    ipmi_sensor_id_t   sensor_id;
    enum ipmi_thresh_e t;
    double             val;
    int                rv;

    sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!((curr_display_type == DISPLAY_SENSOR)
	  && (ipmi_cmp_sensor_id(sensor_id, curr_sensor_id) == 0)))
	return;

    if (sensor_displayed) {
	if (err) {
	    for (t=IPMI_LOWER_NON_CRITICAL; t<=IPMI_UPPER_NON_RECOVERABLE; t++)
	    {
		if (threshold_positions[t].set) {
		    wmove(display_pad,
			  threshold_positions[t].value.y,
			  threshold_positions[t].value.x);
		    display_pad_out("?");
		}
	    }    
	} else {
	    for (t=IPMI_LOWER_NON_CRITICAL; t<=IPMI_UPPER_NON_RECOVERABLE; t++) {
		if (threshold_positions[t].set) {
		    rv = ipmi_threshold_get(th, t, &val);
		    wmove(display_pad,
			  threshold_positions[t].value.y,
			  threshold_positions[t].value.x);
		    if (rv)
			display_pad_out("?", val);
		    else
			display_pad_out("%f", val);
		}
	    }    
	}
	display_pad_refresh();
    } else {
	sensor_read_thresh_err = err;
	if (th)
	    ipmi_copy_thresholds(sensor_thresholds, th);
	display_sensor(ipmi_sensor_get_entity(sensor), sensor);
    }
}

static void
read_thresh_event_enables(ipmi_sensor_t      *sensor,
			  int                err,
			  ipmi_event_state_t *states,
			  void               *cb_data)
{
    ipmi_sensor_id_t   sensor_id;
    enum ipmi_thresh_e t;
    int                global_enable;
    int                scanning_enable;

    sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!((curr_display_type == DISPLAY_SENSOR)
	  && (ipmi_cmp_sensor_id(sensor_id, curr_sensor_id) == 0)))
	return;

    if (sensor_displayed) {
	if (err)
	    return;

	global_enable = ipmi_event_state_get_events_enabled(states);
	scanning_enable = ipmi_event_state_get_scanning_enabled(states);
	wmove(display_pad, enabled_pos.y, enabled_pos.x);
	if (err)
	    display_pad_out("?         ");
	else if (global_enable)
	    display_pad_out("enabled");
	else
	    display_pad_out("disabled");

	wmove(display_pad, scanning_pos.y, scanning_pos.x);
	if (err)
	    display_pad_out("?         ");
	else if (scanning_enable)
	    display_pad_out("enabled");
	else
	    display_pad_out("disabled");

	if (ipmi_sensor_get_event_support(sensor)
	    != IPMI_EVENT_SUPPORT_PER_STATE)
	    goto out;

	for (t=IPMI_LOWER_NON_CRITICAL; t<=IPMI_UPPER_NON_RECOVERABLE; t++) {
	    if (threshold_positions[t].set) {
		wmove(display_pad,
		      threshold_positions[t].enabled.y,
		      threshold_positions[t].enabled.x);
		if (err) {
		    display_pad_out("?         ");
		    continue;
		}
		display_pad_out("  ");
		if (ipmi_is_threshold_event_set(states, t,
						IPMI_GOING_LOW,
						IPMI_ASSERTION))
		    display_pad_out("L^");
		else
		    display_pad_out("  ");
		if (ipmi_is_threshold_event_set(states, t,
						IPMI_GOING_LOW,
						IPMI_DEASSERTION))
		    display_pad_out("Lv");
		else
		    display_pad_out("  ");
		if (ipmi_is_threshold_event_set(states, t,
						IPMI_GOING_HIGH,
						IPMI_ASSERTION))
		    display_pad_out("H^");
		else
		    display_pad_out("  ");
		if (ipmi_is_threshold_event_set(states, t,
						IPMI_GOING_HIGH,
						IPMI_DEASSERTION))
		    display_pad_out("HV");
		else
		    display_pad_out("  ");
	    }
	}    

    out:
	display_pad_refresh();
    } else {
	sensor_event_states_err = err;
	if (states)
	    ipmi_copy_event_state(sensor_event_states, states);
	display_sensor(ipmi_sensor_get_entity(sensor), sensor);
    }
}

static void
read_discrete_event_enables(ipmi_sensor_t      *sensor,
			    int                err,
			    ipmi_event_state_t *states,
			    void               *cb_data)
{
    ipmi_sensor_id_t sensor_id;
    int              i;
    int              val;
    int              global_enable;
    int              scanning_enable;

    sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!((curr_display_type == DISPLAY_SENSOR)
	  && (ipmi_cmp_sensor_id(sensor_id, curr_sensor_id) == 0)))
	return;

    if (sensor_displayed) {
	global_enable = ipmi_event_state_get_events_enabled(states);
	scanning_enable = ipmi_event_state_get_scanning_enabled(states);
	
	wmove(display_pad, enabled_pos.y, enabled_pos.x);
	if (err)
	    display_pad_out("?         ");
	else if (global_enable)
	    display_pad_out("enabled");
	else
	    display_pad_out("disabled");
	
	wmove(display_pad, scanning_pos.y, scanning_pos.x);
	if (err)
	    display_pad_out("?         ");
	else if (scanning_enable)
	    display_pad_out("enabled");
	else
	    display_pad_out("disabled");
	
	if (ipmi_sensor_get_event_support(sensor)
	    != IPMI_EVENT_SUPPORT_PER_STATE)
	    goto out;
	
	if (err) {
	    wmove(display_pad, discr_assert_enab.y, discr_assert_enab.x);
	    display_pad_out("?");
	    wmove(display_pad, discr_deassert_enab.y, discr_deassert_enab.x);
	    display_pad_out("?");
	} else {
	    wmove(display_pad, discr_assert_enab.y, discr_assert_enab.x);
	    for (i=0; i<15; i++) {
		val = ipmi_is_discrete_event_set(states, i, IPMI_ASSERTION);
		display_pad_out("%d", val != 0);
	    }    
	    wmove(display_pad, discr_deassert_enab.y, discr_deassert_enab.x);
	    for (i=0; i<15; i++) {
		val = ipmi_is_discrete_event_set(states, i, IPMI_DEASSERTION);
		display_pad_out("%d", val != 0);
	    }    
	}
    out:
	display_pad_refresh();
    } else {
	sensor_event_states_err = err;
	if (states)
	    ipmi_copy_event_state(sensor_event_states, states);
	display_sensor(ipmi_sensor_get_entity(sensor), sensor);
    }
}

static void
read_states(ipmi_sensor_t *sensor,
	    int           err,
	    ipmi_states_t *states,
	    void          *cb_data)
{
    ipmi_sensor_id_t sensor_id;
    int              i;
    int              val;

    sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!((curr_display_type == DISPLAY_SENSOR)
	  && (ipmi_cmp_sensor_id(sensor_id, curr_sensor_id) == 0)))
	return;

    if (sensor_displayed) {
	wmove(display_pad, value_pos.y, value_pos.x);
	if (err) {
	    display_pad_out("?");
	} else {
	    for (i=0; i<15; i++) {
		val = ipmi_is_state_set(states, i);
		display_pad_out("%d", val != 0);
	    }    
	}
	display_pad_refresh();
    } else {
	sensor_read_err = err;
	if (states)
	    ipmi_copy_states(sensor_states, states);
	display_sensor(ipmi_sensor_get_entity(sensor), sensor);
    }
}

static void
redisplay_sensor(ipmi_sensor_t *sensor, void *cb_data)
{
    int           rv;
    ipmi_entity_t *entity;

    entity = ipmi_sensor_get_entity(sensor);
    if (!entity)
	return;

    if (!ipmi_entity_is_present(entity)
	&& ipmi_sensor_get_ignore_if_no_entity(sensor))
    {
	wmove(display_pad, value_pos.y, value_pos.x);
	display_pad_out("not present");
	return;
    }

    if (ipmi_sensor_get_event_reading_type(sensor)
	== IPMI_EVENT_READING_TYPE_THRESHOLD)
    {
	rv = ipmi_sensor_get_reading(sensor, read_sensor, NULL);
	if (rv)
	    ui_log("redisplay_sensor: Unable to get sensor reading: 0x%x\n",
		   rv);

	switch (ipmi_sensor_get_threshold_access(sensor))
	{
	case IPMI_THRESHOLD_ACCESS_SUPPORT_READABLE:
	case IPMI_THRESHOLD_ACCESS_SUPPORT_SETTABLE:
	    rv = ipmi_sensor_get_thresholds(sensor, read_thresholds, NULL);
	    if (rv)
		ui_log("Unable to get threshold values: 0x%x\n", rv);
	    break;

	default:
	    break;
	}

	switch (ipmi_sensor_get_event_support(sensor))
	{
	case IPMI_EVENT_SUPPORT_PER_STATE:
	case IPMI_EVENT_SUPPORT_ENTIRE_SENSOR:
	    rv = ipmi_sensor_get_event_enables(sensor,
					       read_thresh_event_enables,
					       NULL);
	    if (rv)
		ui_log("Unable to get event values: 0x%x\n", rv);
	    break;

	default:
	    break;
	}
    } else {
	rv = ipmi_sensor_get_states(sensor, read_states, NULL);
	if (rv)
	    ui_log("Unable to get sensor reading: 0x%x\n", rv);
	
	switch (ipmi_sensor_get_event_support(sensor))
	{
	case IPMI_EVENT_SUPPORT_PER_STATE:
	case IPMI_EVENT_SUPPORT_ENTIRE_SENSOR:
	    rv = ipmi_sensor_get_event_enables(sensor,
					       read_discrete_event_enables,
					       NULL);
	    if (rv)
		ui_log("Unable to get event values: 0x%x\n", rv);
	    break;

	default:
	    break;
	}
    }
}

static void
sensor_handler(ipmi_entity_t *entity, ipmi_sensor_t *sensor, void *cb_data)
{
    char name[33];
    struct sensor_info *sinfo = cb_data;
    int rv;
    int present = 1;

    ipmi_sensor_get_id(sensor, name, 33);
    if (strcmp(name, sinfo->name) == 0) {
	sinfo->found = 1;
	curr_display_type = DISPLAY_SENSOR;
	curr_sensor_id = ipmi_sensor_convert_to_id(sensor);

	sensor_displayed = 0;
	sensor_ops_to_read_count = 1;
	if (! ipmi_entity_is_present(entity)
	    && ipmi_sensor_get_ignore_if_no_entity(sensor))
	{
	    present = 0;
	}
	if (ipmi_sensor_get_event_reading_type(sensor)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    if (present) {
		sensor_ops_to_read_count++;
		rv = ipmi_sensor_get_reading(sensor, read_sensor, NULL);
		if (rv)
		    ui_log("Unable to get sensor reading: 0x%x\n", rv);

		switch (ipmi_sensor_get_threshold_access(sensor))
		{
		case IPMI_THRESHOLD_ACCESS_SUPPORT_READABLE:
		case IPMI_THRESHOLD_ACCESS_SUPPORT_SETTABLE:
		    sensor_ops_to_read_count++;
		    rv = ipmi_sensor_get_thresholds(sensor, read_thresholds,
						    NULL);
		    if (rv)
			ui_log("Unable to get threshold values: 0x%x\n", rv);
		    break;
		    
		default:
		    break;
		}

		switch (ipmi_sensor_get_event_support(sensor))
		{
		case IPMI_EVENT_SUPPORT_PER_STATE:
		case IPMI_EVENT_SUPPORT_ENTIRE_SENSOR:
		    sensor_ops_to_read_count++;
		    rv = ipmi_sensor_get_event_enables
			(sensor,
			 read_thresh_event_enables,
			 NULL);
		    if (rv)
			ui_log("Unable to get event values: 0x%x\n", rv);
		    break;
		    
		default:
		    break;
		}
	    }
	} else {
	    if (present) {
		sensor_ops_to_read_count++;
		rv = ipmi_sensor_get_states(sensor, read_states, NULL);
		if (rv)
		    ui_log("Unable to get sensor reading: 0x%x\n", rv);

		switch (ipmi_sensor_get_event_support(sensor))
		{
		case IPMI_EVENT_SUPPORT_PER_STATE:
		case IPMI_EVENT_SUPPORT_ENTIRE_SENSOR:
		    sensor_ops_to_read_count++;
		    rv = ipmi_sensor_get_event_enables
			(sensor,
			 read_discrete_event_enables,
			 NULL);
		    if (rv)
			ui_log("Unable to get event values: 0x%x\n", rv);
		    break;
		    
		default:
		    break;
		}
	    }
	}
	display_sensor(entity, sensor);

	display_pad_refresh();
    }
}

static void
found_entity_for_sensor(ipmi_entity_t *entity,
			char          **toks,
			char          **toks2,
			void          *cb_data)
{
    struct sensor_info sinfo;

    sinfo.name = strtok_r(NULL, "", toks2);
    if (!sinfo.name) {
	cmd_win_out("Invalid sensor given\n");
	return;
    }
    conv_to_spaces(sinfo.name);
    sinfo.found = 0;

    ipmi_entity_iterate_sensors(entity, sensor_handler, &sinfo);
    if (!sinfo.found) {
	char loc[MAX_ENTITY_LOC_SIZE];

	conv_from_spaces(sinfo.name);
	cmd_win_out("Sensor %s.%s not found\n",
		    get_entity_loc(entity, loc, sizeof(loc)),
		    sinfo.name);
	return;
    }
}

int
sensor_cmd(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, found_entity_for_sensor, NULL);
    return 0;
}

typedef struct events_enable_info_s
{
    ipmi_event_state_t *states;
} events_enable_info_t;

void
events_enable_done(ipmi_sensor_t *sensor,
		   int           err,
		   void          *cb_data)
{
    if (err)
	ui_log("Error setting events enable: 0x%x", err);
}

static void
events_enable(ipmi_sensor_t *sensor, void *cb_data)
{
    events_enable_info_t *info = cb_data;
    int                  rv;

    rv = ipmi_sensor_set_event_enables(sensor, info->states,
				       events_enable_done, NULL);
    if (rv)
	ui_log("Error sending events enable: 0x%x", rv);
    ipmi_mem_free(info);
}

static int
events_enable_cmd(char *cmd, char **toks, void *cb_data)
{
    events_enable_info_t *info;    
    unsigned char        enable;
    int                  i;
    char                 *enptr;
    int                  rv;
    
    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmd_win_out("Out of memory\n");
	return 0;
    }

    info->states = ipmi_mem_alloc(ipmi_event_state_size());
    if (!info->states) {
	ipmi_mem_free(info);
	cmd_win_out("Out of memory\n");
	return 0;
    }

    ipmi_event_state_init(info->states);

    if (get_uchar(toks, &enable, "events"))
	return 0;
    ipmi_event_state_set_events_enabled(info->states, enable);

    if (get_uchar(toks, &enable, "scanning"))
	return 0;
    ipmi_event_state_set_scanning_enabled(info->states, enable);

    enptr = strtok_r(NULL, " \t\n", toks);
    if (!enptr) {
	cmd_win_out("No assertion mask given\n");
	return 0;
    }
    for (i=0; enptr[i]!='\0'; i++) {
	if (enptr[i] == '1')
	    ipmi_discrete_event_set(info->states, i, IPMI_ASSERTION);
	else if (enptr[i] == '0')
	    ipmi_discrete_event_clear(info->states, i, IPMI_ASSERTION);
	else {
	    cmd_win_out("Invalid assertion value\n");
	    return 0;
	}
    }
    
    enptr = strtok_r(NULL, " \t\n", toks);
    if (!enptr) {
	cmd_win_out("No deassertion mask given\n");
	return 0;
    }
    for (i=0; enptr[i]!='\0'; i++) {
	if (enptr[i] == '1')
	    ipmi_discrete_event_set(info->states, i, IPMI_DEASSERTION);
	else if (enptr[i] == '0')
	    ipmi_discrete_event_clear(info->states, i, IPMI_DEASSERTION);
	else {
	    cmd_win_out("Invalid deassertion value\n");
	    return 0;
	}
    }
    
    rv = ipmi_sensor_pointer_cb(curr_sensor_id, events_enable, info);
    if (rv) {
	cmd_win_out("Unable to get sensor pointer: 0x%x\n", rv);
	ipmi_mem_free(info);
    }
    return 0;
}

static void
controls_handler(ipmi_entity_t *entity, ipmi_control_t *control, void *cb_data)
{
    char loc[MAX_ENTITY_LOC_SIZE];
    char name[33];
    char name2[33];

    ipmi_control_get_id(control, name, 33);
    strcpy(name2, name);
    conv_from_spaces(name2);
    display_pad_out("  %s.%s - %s\n",
		    get_entity_loc(entity, loc, sizeof(loc)),
		    name2, name);
}

static void
found_entity_for_controls(ipmi_entity_t *entity,
			  char          **toks,
			  char          **toks2,
			  void          *cb_data)
{
    char loc[MAX_ENTITY_LOC_SIZE];

    curr_display_type = DISPLAY_CONTROLS;
    display_pad_clear();
    display_pad_out("Controls for entity %s:\n",
		    get_entity_loc(entity, loc, sizeof(loc)));
    ipmi_entity_iterate_controls(entity, controls_handler, NULL);
    display_pad_refresh();
}

static int
controls_cmd(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, found_entity_for_controls, NULL);
    return 0;
}

int control_displayed;
int control_ops_to_read_count;
int control_read_err;
int *normal_control_vals;
ipmi_light_setting_t *light_control_val;
int id_control_length;
unsigned char *id_control_vals;

static void
display_control(ipmi_entity_t *entity, ipmi_control_t *control)
{
    char loc[MAX_ENTITY_LOC_SIZE];
    int  control_type;
    char name[33];
    char cname[IPMI_CONTROL_NAME_LEN];
    int  i;
    int  num_vals;

    if (control_displayed)
	return;

    control_ops_to_read_count--;
    if (control_ops_to_read_count > 0)
	return;

    control_displayed = 1;

    ipmi_control_get_id(control, name, 33);
    curr_control_id = ipmi_control_convert_to_id(control);

    display_pad_clear();

    conv_from_spaces(name);
    display_pad_out("Control %s.%s:\n",
		    get_entity_loc(entity, loc, sizeof(loc)),
		    name);
    if (ipmi_control_get_ignore_if_no_entity(control))
	display_pad_out("  ignore if entity not present\n");
    else
	display_pad_out("  still there if entity not present\n");
    ipmi_control_get_name(control, cname, sizeof(cname));
    display_pad_out("  name = %s\n", cname);
    control_type = ipmi_control_get_type(control);
    display_pad_out("  type = %s (%d)\n",
		    ipmi_control_get_type_string(control), control_type);
    num_vals = ipmi_control_get_num_vals(control);
    switch (control_type) {
	case IPMI_CONTROL_LIGHT:
	case IPMI_CONTROL_RELAY:
	case IPMI_CONTROL_ALARM:
	case IPMI_CONTROL_RESET:
	case IPMI_CONTROL_ONE_SHOT_RESET:
	case IPMI_CONTROL_POWER:
	case IPMI_CONTROL_FAN_SPEED:
	case IPMI_CONTROL_OUTPUT:
	case IPMI_CONTROL_ONE_SHOT_OUTPUT:
	    display_pad_out("  num entities = %d\n", num_vals);
	    break;

	case IPMI_CONTROL_DISPLAY:
	case IPMI_CONTROL_IDENTIFIER:
	    break;
    }
    display_pad_out("  value = ");
    getyx(display_pad, value_pos.y, value_pos.x);

    if (! ipmi_control_is_readable(control)) {
	display_pad_out("not readable");
    } else if (control_read_err) {
	/* Nothing to do. */
    } else {
	switch (control_type) {
	    case IPMI_CONTROL_LIGHT:
		if (ipmi_control_light_set_with_setting(control)) {
		    if (light_control_val) {
			ipmi_light_setting_t *setting = light_control_val;
			for (i=0; i<num_vals; ) {
			    int color, on, off, lc;
			    ipmi_light_setting_get_color(setting, i, &color);
			    ipmi_light_setting_get_on_time(setting, i, &on);
			    ipmi_light_setting_get_off_time(setting, i, &off);
			    ipmi_light_setting_in_local_control(setting, i,
								&lc);
			    wmove(display_pad, value_pos.y+i, value_pos.x);
			    display_pad_out("0x%x 0x%x 0x%x %s",
					    color, on, off,
					    lc ? "local cnt": "         ");
			    i++;
			    if (i < num_vals)
				display_pad_out("\n          ");
			}
			ipmi_free_light_settings(light_control_val);
			light_control_val = NULL;
		    } else {
			display_pad_out("error reading values");
		    }
		    break;
		}
		/* FALLTHRU */

	    case IPMI_CONTROL_RELAY:
	    case IPMI_CONTROL_ALARM:
	    case IPMI_CONTROL_RESET:
	    case IPMI_CONTROL_ONE_SHOT_RESET:
	    case IPMI_CONTROL_POWER:
	    case IPMI_CONTROL_FAN_SPEED:
	    case IPMI_CONTROL_OUTPUT:
	    case IPMI_CONTROL_ONE_SHOT_OUTPUT:
		if (normal_control_vals) {
		    for (i=0; i<num_vals; ) {
			display_pad_out("%d (0x%x)", normal_control_vals[i],
					normal_control_vals[i]);
			i++;
			if (i < num_vals)
			    display_pad_out("\n          ");
		    }
		    ipmi_mem_free(normal_control_vals);
		    normal_control_vals = NULL;
		} else {
		    display_pad_out("error reading values");
		}
		break;
		
	    case IPMI_CONTROL_DISPLAY:
		break;
		
	    case IPMI_CONTROL_IDENTIFIER:
		if (id_control_vals) {
		    for (i=0; i<id_control_length;) {
			display_pad_out("0x%2.2x\n", id_control_vals[i]);
			i++;
			if (i < num_vals)
			    display_pad_out("\n          ");
		    }
		    ipmi_mem_free(id_control_vals);
		    id_control_vals = NULL;
		} else {
		    display_pad_out("error reading values");
		}
		break;
	}
    }
    display_pad_out("\n");

    display_pad_refresh();
}

static void
light_control_val_read(ipmi_control_t       *control,
		       int                  err,
		       ipmi_light_setting_t *setting,
		       void                 *cb_data)
{
    ipmi_control_id_t control_id;
    int               num_vals;
    int               i;

    if (control == NULL) {
	/* The control went away, stop the operation. */
	wmove(display_pad, value_pos.y, value_pos.x);
	display_pad_out("invalid");
	curr_display_type = DISPLAY_NONE;
	return;
    }
    control_id = ipmi_control_convert_to_id(control);
    if (!((curr_display_type == DISPLAY_CONTROL)
	  && (ipmi_cmp_control_id(control_id, curr_control_id) == 0)))
	return;

    num_vals = ipmi_control_get_num_vals(control);

    if (control_displayed) {
	if (err) {
	    wmove(display_pad, value_pos.y, value_pos.x);
	    display_pad_out("?");
	} else {
	    for (i=0; i<num_vals; i++) {
		int color, on, off, lc;
		ipmi_light_setting_get_color(setting, i, &color);
		ipmi_light_setting_get_on_time(setting, i, &on);
		ipmi_light_setting_get_off_time(setting, i, &off);
		ipmi_light_setting_in_local_control(setting, i, &lc);
		wmove(display_pad, value_pos.y+i, value_pos.x);
		display_pad_out("0x%x 0x%x 0x%x %s",
				color, on, off,
				lc ? "local cnt": "         ");
	    }
	}
	display_pad_refresh();
    } else {
	if (light_control_val)
	    ipmi_free_light_settings(light_control_val);
	if (err) {
	    light_control_val = NULL;
	} else {
	    light_control_val = ipmi_light_settings_dup(setting);
	}
	display_control(ipmi_control_get_entity(control), control);
    }
}

static void
normal_control_val_read(ipmi_control_t *control,
			int            err,
			int            *val,
			void           *cb_data)
{
    ipmi_control_id_t control_id;
    int               num_vals;
    int               i;

    if (control == NULL) {
	/* The control went away, stop the operation. */
	wmove(display_pad, value_pos.y, value_pos.x);
	display_pad_out("invalid");
	curr_display_type = DISPLAY_NONE;
	return;
    }
    control_id = ipmi_control_convert_to_id(control);
    if (!((curr_display_type == DISPLAY_CONTROL)
	  && (ipmi_cmp_control_id(control_id, curr_control_id) == 0)))
	return;

    num_vals = ipmi_control_get_num_vals(control);

    if (control_displayed) {
	if (err) {
	    wmove(display_pad, value_pos.y, value_pos.x);
	    display_pad_out("?");
	} else {
	    for (i=0; i<num_vals; i++) {
		wmove(display_pad, value_pos.y+i, value_pos.x);
		display_pad_out("%d (0x%x)", val[i], val[i]);
	    }
	}
	display_pad_refresh();
    } else {
	if (err) {
	    if (normal_control_vals)
		ipmi_mem_free(normal_control_vals);
	    normal_control_vals = NULL;
	} else {
	    normal_control_vals = ipmi_mem_alloc(sizeof(int) * num_vals);
	    if (normal_control_vals) {
		memcpy(normal_control_vals, val, sizeof(int) * num_vals);
	    }
	}
	display_control(ipmi_control_get_entity(control), control);
    }
}

static void
identifier_control_val_read(ipmi_control_t *control,
			    int            err,
			    unsigned char  *val,
			    int            length,
			    void           *cb_data)
{
    ipmi_control_id_t control_id;
    int               i;

    if (control == NULL) {
	/* The control went away, stop the operation. */
	wmove(display_pad, value_pos.y, value_pos.x);
	display_pad_out("invalid");
	curr_display_type = DISPLAY_NONE;
	return;
    }

    control_id = ipmi_control_convert_to_id(control);
    if (!((curr_display_type == DISPLAY_CONTROL)
	  && (ipmi_cmp_control_id(control_id, curr_control_id) == 0)))
	return;

    if (control_displayed) {
	if (err) {
	    wmove(display_pad, value_pos.y, value_pos.x);
	    display_pad_out("?");
	} else {
	    wmove(display_pad, value_pos.y, value_pos.x);
	    for (i=0; i<length; i++) {
		display_pad_out("0x%2.2x", val[i]);
		if (i < length)
		    display_pad_out("\n          ");
	    }
	}
	display_pad_refresh();
    } else {
	if (err) {
	    if (id_control_vals)
		ipmi_mem_free(id_control_vals);
	    id_control_vals = NULL;
	} else {
	    id_control_length = length;
	    id_control_vals = ipmi_mem_alloc(sizeof(unsigned char) * length);
	    if (id_control_vals) {
		memcpy(id_control_vals, val, sizeof(unsigned char) * length);
	    }
	    display_control(ipmi_control_get_entity(control), control);
	}
    }
}

static void
redisplay_control(ipmi_control_t *control, void *cb_data)
{
    int           control_type;
    ipmi_entity_t *entity;

    entity = ipmi_control_get_entity(control);
    if (!entity)
	return;

    if (! ipmi_control_is_readable(control)) {
	wmove(display_pad, value_pos.y, value_pos.x);
	display_pad_out("not readable");
	display_pad_refresh();
	return;
    }

    if (!ipmi_entity_is_present(entity)
	&& ipmi_control_get_ignore_if_no_entity(control))
    {
	wmove(display_pad, value_pos.y, value_pos.x);
	display_pad_out("not present");
	display_pad_refresh();
	return;
    }

    control_type = ipmi_control_get_type(control);
    switch (control_type) {
    case IPMI_CONTROL_LIGHT:
	if (ipmi_control_light_set_with_setting(control)) {
	    ipmi_control_get_light(control, light_control_val_read, NULL);
	    break;
	}
	/* FALLTHRU */
    case IPMI_CONTROL_RELAY:
    case IPMI_CONTROL_ALARM:
    case IPMI_CONTROL_RESET:
    case IPMI_CONTROL_ONE_SHOT_RESET:
    case IPMI_CONTROL_POWER:
    case IPMI_CONTROL_FAN_SPEED:
    case IPMI_CONTROL_OUTPUT:
    case IPMI_CONTROL_ONE_SHOT_OUTPUT:
	ipmi_control_get_val(control, normal_control_val_read, NULL);
	break;

    case IPMI_CONTROL_DISPLAY:
	break;

    case IPMI_CONTROL_IDENTIFIER:
	ipmi_control_identifier_get_val(control,
					identifier_control_val_read,
					NULL);
	break;
    }
}

struct control_info {
    int found;
    char *name;
};

static void
control_handler(ipmi_entity_t *entity, ipmi_control_t *control, void *cb_data)
{
    struct control_info *iinfo = cb_data;
    char                name[33];
    int                 control_type;
    int                 rv;


    ipmi_control_get_id(control, name, 33);
    if (strcmp(name, iinfo->name) == 0) {
	iinfo->found = 1;
	curr_display_type = DISPLAY_CONTROL;

	curr_control_id = ipmi_control_convert_to_id(control);

	control_ops_to_read_count = 1;

	control_displayed = 0;

	if (! ipmi_control_is_readable(control)) {
	    /* If the control can't be read, then just display it now. */
	    display_control(entity, control);
	    return;
	}

	control_type = ipmi_control_get_type(control);
	switch (control_type) {
	case IPMI_CONTROL_LIGHT:
	    if (ipmi_control_light_set_with_setting(control)) {
		control_ops_to_read_count++;
		rv = ipmi_control_get_light(control, light_control_val_read,
					    NULL);
		if (rv) {
		    ui_log("Unable to read light control val: 0x%x\n", rv);
		}
		break;
	    }
	    /* FALLTHRU */
	case IPMI_CONTROL_RELAY:
	case IPMI_CONTROL_ALARM:
	case IPMI_CONTROL_RESET:
	case IPMI_CONTROL_ONE_SHOT_RESET:
	case IPMI_CONTROL_POWER:
	case IPMI_CONTROL_FAN_SPEED:
	case IPMI_CONTROL_OUTPUT:
	case IPMI_CONTROL_ONE_SHOT_OUTPUT:
	    control_ops_to_read_count++;
	    rv = ipmi_control_get_val(control, normal_control_val_read, NULL);
	    if (rv) {
		ui_log("Unable to read control val: 0x%x\n", rv);
	    }
	    break;

	case IPMI_CONTROL_DISPLAY:
	    break;

	case IPMI_CONTROL_IDENTIFIER:
	    control_ops_to_read_count++;
	    rv = ipmi_control_identifier_get_val(control,
						 identifier_control_val_read,
						 NULL);
	    if (rv) {
		ui_log("Unable to read control val: 0x%x\n", rv);
	    }
	    break;
	}

	display_control(entity, control);
    }
}

static void
found_entity_for_control(ipmi_entity_t *entity,
			 char          **toks,
			 char          **toks2,
			 void          *cb_data)
{
    struct control_info iinfo;

    iinfo.name = strtok_r(NULL, "", toks2);
    if (!iinfo.name) {
	cmd_win_out("Invalid control given\n");
	return;
    }
    conv_to_spaces(iinfo.name);
    iinfo.found = 0;

    ipmi_entity_iterate_controls(entity, control_handler, &iinfo);
    if (!iinfo.found) {
	char loc[MAX_ENTITY_LOC_SIZE];

	conv_from_spaces(iinfo.name);
	cmd_win_out("Control %s.%s not found\n",
		    get_entity_loc(entity, loc, sizeof(loc)),
		    iinfo.name);
	return;
    }
}

int
control_cmd(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, found_entity_for_control, NULL);
    return 0;
}

typedef struct rearm_info_s
{
    int                global;
    ipmi_event_state_t *states;
} rearm_info_t;

void
rearm_done(ipmi_sensor_t *sensor,
	   int           err,
	   void          *cb_data)
{
    if (err)
	ui_log("Error rearming sensor: 0x%x", err);
}

static void
rearm(ipmi_sensor_t *sensor, void *cb_data)
{
    rearm_info_t *info = cb_data;
    int          rv;

    rv = ipmi_sensor_rearm(sensor, info->global, info->states,
			   rearm_done, NULL);
    if (rv)
	ui_log("Error sending rearm: 0x%x", rv);
    if (info->states)
	ipmi_mem_free(info->states);
    ipmi_mem_free(info);
}

static int
rearm_cmd(char *cmd, char **toks, void *cb_data)
{
    rearm_info_t  *info;    
    unsigned char global;
    int           i;
    char          *enptr;
    int           rv;
    
    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmd_win_out("Out of memory\n");
	return 0;
    }

    info->states = NULL;

    if (get_uchar(toks, &global, "global rearm"))
	goto out_err;
    info->global = global;

    if (!global) {
	info->states = ipmi_mem_alloc(ipmi_event_state_size());
	if (!info->states) {
	    ipmi_mem_free(info);
	    cmd_win_out("Out of memory\n");
	    goto out_err;
	}

	ipmi_event_state_init(info->states);

	enptr = strtok_r(NULL, " \t\n", toks);
	if (!enptr) {
	    cmd_win_out("No assertion mask given\n");
	    goto out_err;
	}
	for (i=0; enptr[i]!='\0'; i++) {
	    if (enptr[i] == '1')
		ipmi_discrete_event_set(info->states, i, IPMI_ASSERTION);
	    else if (enptr[i] == '0')
		ipmi_discrete_event_clear(info->states, i, IPMI_ASSERTION);
	    else {
		cmd_win_out("Invalid assertion value\n");
		goto out_err;
	    }
	}
    
	enptr = strtok_r(NULL, " \t\n", toks);
	if (!enptr) {
	    cmd_win_out("No deassertion mask given\n");
	    return 0;
	}
	for (i=0; enptr[i]!='\0'; i++) {
	    if (enptr[i] == '1')
		ipmi_discrete_event_set(info->states, i, IPMI_DEASSERTION);
	    else if (enptr[i] == '0')
		ipmi_discrete_event_clear(info->states, i, IPMI_DEASSERTION);
	    else {
		cmd_win_out("Invalid deassertion value\n");
		goto out_err;
	    }
	}
    }
    
    rv = ipmi_sensor_pointer_cb(curr_sensor_id, rearm, info);
    if (rv) {
	cmd_win_out("Unable to get sensor pointer: 0x%x\n", rv);
	goto out_err;
    }
    return 0;

 out_err:
    if (info) {
	if (info->states)
	    ipmi_mem_free(info->states);
	ipmi_mem_free(info);
    }
    return 0;
}

void
set_hysteresis_done(ipmi_sensor_t *sensor,
		   int           err,
		   void          *cb_data)
{
    if (err)
	ui_log("Error setting hysteresis: 0x%x", err);
    else
	ui_log("Hysteresis set");
}

static int
set_hysteresis_cmd(char *cmd, char **toks, void *cb_data)
{
    unsigned char physt, nhyst;
    int           rv;
    
    if (get_uchar(toks, &physt, "positive hysteresis value"))
	goto out_err;

    if (get_uchar(toks, &nhyst, "negative hysteresis value"))
	goto out_err;

    rv = ipmi_sensor_id_set_hysteresis(curr_sensor_id, physt, nhyst,
				       set_hysteresis_done, NULL);
    if (rv) {
	cmd_win_out("Unable to set hysteresis: 0x%x\n", rv);
	goto out_err;
    }

 out_err:
    return 0;
}

void
get_hysteresis_done(ipmi_sensor_t *sensor,
		    int           err,
		    unsigned int  positive_hysteresis,
		    unsigned int  negative_hysteresis,
		    void          *cb_data)
{
    if (err)
	ui_log("Error setting hysteresis: 0x%x", err);
    else
	ui_log("Hysteresis values: positive = 0x%x, negative = 0x%x",
	       positive_hysteresis, negative_hysteresis);
}

static int
get_hysteresis_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;
    
    rv = ipmi_sensor_id_get_hysteresis(curr_sensor_id,
				       get_hysteresis_done, NULL);
    if (rv) {
	cmd_win_out("Unable to get hysteresis: 0x%x\n", rv);
	goto out_err;
    }

 out_err:
    return 0;
}

static int
dump_fru_str(ipmi_fru_t *fru,
	     char       *str,
	     int (*glen)(ipmi_fru_t   *fru,
			 unsigned int *length),
	     int (*gtype)(ipmi_fru_t           *fru,
			  enum ipmi_str_type_e *type),
	     int (*gstr)(ipmi_fru_t   *fru,
			 char         *str,
			 unsigned int *strlen))
{
    enum ipmi_str_type_e type;
    int rv;
    char buf[128];
    unsigned int len;

    rv = gtype(fru, &type);
    if (rv) {
	if (rv != ENOSYS)
	    display_pad_out("  Error fetching type for %s: %x\n", str, rv);
	return rv;
    }

    if (type == IPMI_BINARY_STR) {
	display_pad_out("  %s is in binary\n", str);
	return 0;
    } else if (type == IPMI_UNICODE_STR) {
	display_pad_out("  %s is in unicode\n", str);
	return 0;
    } else if (type != IPMI_ASCII_STR) {
	display_pad_out("  %s is in unknown format\n", str);
	return 0;
    }

    len = sizeof(buf);
    rv = gstr(fru, buf, &len);
    if (rv) {
	display_pad_out("  Error fetching string for %s: %x\n", str, rv);
	return rv;
    }

    display_pad_out("  %s: %s\n", str, buf);
    return 0;
}

static int
dump_fru_custom_str(ipmi_fru_t *fru,
		    char       *str,
		    int        num,
		    int (*glen)(ipmi_fru_t   *fru,
				unsigned int num,
				unsigned int *length),
		    int (*gtype)(ipmi_fru_t           *fru,
				 unsigned int         num,
				 enum ipmi_str_type_e *type),
		    int (*gstr)(ipmi_fru_t   *fru,
				unsigned int num,
				char         *str,
				unsigned int *strlen))
{
    enum ipmi_str_type_e type;
    int rv;
    char buf[128];
    unsigned int len;

    rv = gtype(fru, num, &type);
    if (rv)
	return rv;

    if (type == IPMI_BINARY_STR) {
	display_pad_out("  %s custom %d is in binary\n", str, num);
	return 0;
    } else if (type == IPMI_UNICODE_STR) {
	display_pad_out("  %s custom %d is in unicode\n", str, num);
	return 0;
    } else if (type != IPMI_ASCII_STR) {
	display_pad_out("  %s custom %d is in unknown format\n", str, num);
	return 0;
    }

    len = sizeof(buf);
    rv = gstr(fru, num, buf, &len);
    if (rv) {
	display_pad_out("  Error fetching string for %s custom %d: %x\n",
			str, num, rv);
	return rv;
    }

    display_pad_out("  %s custom %d: %s\n", str, num, buf);
    return 0;
}

#define DUMP_FRU_STR(name, str) \
dump_fru_str(fru, str, ipmi_fru_get_ ## name ## _len, \
             ipmi_fru_get_ ## name ## _type, \
             ipmi_fru_get_ ## name)

#define DUMP_FRU_CUSTOM_STR(name, str) \
do {									\
    int i, _rv;								\
    for (i=0; ; i++) {							\
        _rv = dump_fru_custom_str(fru, str, i,				\
				  ipmi_fru_get_ ## name ## _custom_len, \
				  ipmi_fru_get_ ## name ## _custom_type, \
				  ipmi_fru_get_ ## name ## _custom);	\
	if (_rv)							\
	    break;							\
    }									\
} while (0)

static int
traverse_fru_multi_record_tree(ipmi_fru_node_t *node,
			       int             indent)
{
    const char                *name;
    unsigned int              i, k;
    enum ipmi_fru_data_type_e dtype;
    int                       intval, rv;
    double                    floatval;
    time_t                    time;
    char                      *data;
    unsigned int              data_len;
    ipmi_fru_node_t           *sub_node;
    
    for (i=0; ; i++) {
        rv = ipmi_fru_node_get_field(node, i, &name, &dtype, &intval, &time,
				     &floatval, &data, &data_len, &sub_node);
        if ((rv == EINVAL) || (rv == ENOSYS))
            break;
        else if (rv)
            continue;

	if (name)
	    display_pad_out("%*sName: %s \n", indent, "", name);
	else
	    /* An array index. */
	    display_pad_out("%*%d: \n", indent, "", i);
        switch (dtype) {
	case IPMI_FRU_DATA_INT:
	    display_pad_out("%*sType: integer\n", indent, "");
	    display_pad_out("%*sData: %d\n", indent, "", intval);
	    break;

	case IPMI_FRU_DATA_TIME:
	    display_pad_out("%*sType: time\n", indent, "");
	    display_pad_out("%*sData: %ld\n", indent, "", (long)time);
	    break;

	case IPMI_FRU_DATA_BOOLEAN:
	    display_pad_out("%*sType: boolean\n", indent, "");
	    display_pad_out("%*sData: %ls\n", indent, "",
			    intval ? "true" : "false");
	    break;

	case IPMI_FRU_DATA_FLOAT:
	    display_pad_out("%*sType: float\n", indent, "");
	    display_pad_out("%*sData: %lf\n", indent, "", floatval);
	    break;

	case IPMI_FRU_DATA_BINARY:
	    display_pad_out("%*sType: binary\n", indent, "");
	    display_pad_out("%*sData:", indent, "");
	    for(k=0; k<data_len; k++)
		display_pad_out(" %2.2x", data[k]);
	    display_pad_out("\n");
	    break;

	case IPMI_FRU_DATA_ASCII:
	    display_pad_out("%*sType: ascii\n", indent, "");
	    display_pad_out("%*sData: %s\n", indent, "", data);
	    break;

	case IPMI_FRU_DATA_UNICODE:
	    display_pad_out("%*sType: unicode\n", indent, "");
	    display_pad_out("%*sData:", indent, "");
	    for (k=0; k<data_len; k++)
		display_pad_out(" %2.2x", data[k]);
	    display_pad_out("\n");
	    break;

	case IPMI_FRU_DATA_SUB_NODE:
	    if (intval == -1)
		display_pad_out("%*sType: Record\n", indent, "");
	    else
		display_pad_out("%*sType: Array\n", indent, "");
	    traverse_fru_multi_record_tree(sub_node, indent+2);
	    break;
	    
	default:
	    display_pad_out("Type: unknown\n");
	    break;
	}
    }
    
    ipmi_fru_put_node(node);

    return 0;
}

static void
dump_fru_info(ipmi_fru_t *fru)
{
    unsigned char ucval;
    unsigned int  uival;
    time_t        tval;
    int           rv;
    int           i, num_multi;

    rv = ipmi_fru_get_internal_use_version(fru, &ucval);
    if (!rv)
	display_pad_out("  internal area version: 0x%2.2x\n", ucval);

    rv = ipmi_fru_get_internal_use_length(fru, &uival);
    if (!rv)
	display_pad_out("  internal area length: %d\n", uival);

    /* FIXME - dump internal use data. */

    rv = ipmi_fru_get_chassis_info_version(fru, &ucval);
    if (!rv)
	display_pad_out("  chassis info version: 0x%2.2x\n", ucval);

    rv = ipmi_fru_get_chassis_info_type(fru, &ucval);
    if (!rv)
	display_pad_out("  chassis info type: 0x%2.2x\n", ucval);

    DUMP_FRU_STR(chassis_info_part_number, "chassis info part number");
    DUMP_FRU_STR(chassis_info_serial_number, "chassis info serial number");
    DUMP_FRU_CUSTOM_STR(chassis_info, "chassis info");

    rv = ipmi_fru_get_board_info_version(fru, &ucval);
    if (!rv)
	display_pad_out("  board info version: 0x%2.2x\n", ucval);

    rv = ipmi_fru_get_board_info_lang_code(fru, &ucval);
    if (!rv)
	display_pad_out("  board info lang code: 0x%2.2x\n", ucval);

    rv = ipmi_fru_get_board_info_mfg_time(fru, &tval);
    if (!rv)
	display_pad_out("  board info mfg time: %ld\n", (long) tval);

    DUMP_FRU_STR(board_info_board_manufacturer,
		 "board info board manufacturer");
    DUMP_FRU_STR(board_info_board_product_name,
		 "board info board product name");
    DUMP_FRU_STR(board_info_board_serial_number,
		 "board info board serial number");
    DUMP_FRU_STR(board_info_board_part_number,
		 "board info board part number");
    DUMP_FRU_STR(board_info_fru_file_id, "board info fru file id");
    DUMP_FRU_CUSTOM_STR(board_info, "board info");

    rv = ipmi_fru_get_product_info_version(fru, &ucval);
    if (!rv)
	display_pad_out("  product info version: 0x%2.2x\n", ucval);

    rv = ipmi_fru_get_product_info_lang_code(fru, &ucval);
    if (!rv)
	display_pad_out("  product info lang code: 0x%2.2x\n", ucval);

    DUMP_FRU_STR(product_info_manufacturer_name,
		 "product info manufacturer name");
    DUMP_FRU_STR(product_info_product_name, "product info product name");
    DUMP_FRU_STR(product_info_product_part_model_number,
		 "product info product part model number");
    DUMP_FRU_STR(product_info_product_version, "product info product version");
    DUMP_FRU_STR(product_info_product_serial_number,
		 "product info product serial number");
    DUMP_FRU_STR(product_info_asset_tag, "product info asset tag");
    DUMP_FRU_STR(product_info_fru_file_id, "product info fru file id");
    DUMP_FRU_CUSTOM_STR(product_info, "product info");
    num_multi = ipmi_fru_get_num_multi_records(fru);
    for (i=0; i<num_multi; i++) {
	unsigned char   type, ver;
	unsigned int    j;
	unsigned int    len;
	unsigned char   *data;
        ipmi_fru_node_t *node;
	const char      *name;

	rv = ipmi_fru_get_multi_record_type(fru, i, &type);
	if (rv)
	    display_pad_out("  multi-record %d, error getting type: %x\n", rv);
	rv = ipmi_fru_get_multi_record_format_version(fru, i, &ver);
	if (rv)
	    display_pad_out("  multi-record %d, error getting ver: %x\n", rv);

	display_pad_out("  multi-record %d, type 0x%x, format version 0x%x:",
			i, type, ver);
	
	rv = ipmi_fru_get_multi_record_data_len(fru, i, &len);
	if (rv) {
	    display_pad_out("\n  multi-record %d, error getting length: %x\n",
			    rv);
	    continue;
	}
	data = ipmi_mem_alloc(len);
	if (!data) {
	    display_pad_out("\n  multi-record %d, error allocating data\n");
	    continue;
	}
	rv = ipmi_fru_get_multi_record_data(fru, i, data, &len);
	if (rv) {
	    display_pad_out("\n  multi-record %d, error getting data: %x\n",
			    rv);
	} else {
	    for (j=0; j<len; j++) {
		if ((j > 0) && ((j % 16) == 0))
		    display_pad_out("\n     ");
		display_pad_out(" %2.2x", data[j]);
	    }
	    display_pad_out("\n");
            rv = ipmi_fru_multi_record_get_root_node(fru, i, &name, &node);
            if ( !rv ) {
		display_pad_out("Multi-record decode: %s", name);
                traverse_fru_multi_record_tree(node, 2);
            } else if ((rv != ENOSYS) && (rv != EINVAL)) {
                display_pad_out(" multi-record %d, error get root obj: %x\n ",
                                i, rv);
            }
	}
	ipmi_mem_free(data);
    }
}

static void
found_entity_for_fru(ipmi_entity_t *entity,
                     char          **toks,
                     char          **toks2,
                     void          *cb_data)
{
    char loc[MAX_ENTITY_LOC_SIZE];
    ipmi_fru_t *fru = ipmi_entity_get_fru(entity);

    display_pad_clear();

    if (!fru) {
        cmd_win_out("No FRU for entity %s\n",
		    get_entity_loc(entity, loc, sizeof(loc)));
        return;
    }

    display_pad_out("FRU for entity %s\n",
		    get_entity_loc(entity, loc, sizeof(loc)));

    dump_fru_info(fru);

    display_pad_refresh();
}

static int
fru_cmd(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, found_entity_for_fru, NULL);
    curr_display_type = DISPLAY_ENTITY;
    return 0;
}

static void
fru_fetched(ipmi_fru_t *fru, int err, void *cb_data)
{
    display_pad_clear();
    if (err)
	display_pad_out("Error fetching fru: %x\n", err);
    else
	dump_fru_info(fru);
    display_pad_refresh();
    if (err != ECANCELED)
	ipmi_fru_destroy(fru, NULL, NULL);
}

typedef struct fru_rec_s
{
    unsigned char is_logical;
    unsigned char device_address;
    unsigned char device_id;
    unsigned char lun;
    unsigned char private_bus;
    unsigned char channel;
} fru_rec_t;

static void
dump_fru_cmder(ipmi_domain_t *domain, void *cb_data)
{
    fru_rec_t *info = cb_data;
    int       rv;

    rv = ipmi_fru_alloc(domain,
			info->is_logical,
			info->device_address,
			info->device_id,
			info->lun,
			info->private_bus,
			info->channel,
			fru_fetched,
			NULL,
			NULL);
    if (rv)
	cmd_win_out("Unable to allocate fru: %x\n", rv);
}

static int
dump_fru_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;
    fru_rec_t info;

    if (get_uchar(toks, &info.is_logical, "is_logical"))
	return 0;
    if (get_uchar(toks, &info.device_address, "device_address"))
	return 0;
    if (get_uchar(toks, &info.device_id, "device_id"))
	return 0;
    if (get_uchar(toks, &info.lun, "lun"))
	return 0;
    if (get_uchar(toks, &info.private_bus, "private_bus"))
	return 0;
    if (get_uchar(toks, &info.channel, "channel"))
	return 0;

    rv = ipmi_domain_pointer_cb(domain_id, dump_fru_cmder, &info);
    if (rv)
	cmd_win_out("Unable to convert domain id to a pointer\n");
    else 
	curr_display_type = DISPLAY_ENTITY;

    return 0;
}

static char y_or_n(int val)
{
    if (val)
	return 'y';
    else
	return 'n';
}

#define MCCMD_DATA_SIZE 30
typedef struct mccmd_info_s
{
    ipmi_mcid_t   mc_id;
    unsigned char lun;
    ipmi_msg_t    msg;
    int           found;
    unsigned char val;
} mccmd_info_t;

void mc_handler(ipmi_mc_t *mc, void *cb_data)
{
    unsigned char vals[4];
    mccmd_info_t  *info = cb_data;

    curr_display_type = DISPLAY_MC;
    info->found = 1;
    display_pad_clear();
    display_pad_out("MC (%x %x) - %s\n",
		    ipmi_mc_get_channel(mc),
		    ipmi_mc_get_address(mc),
		    ipmi_mc_is_active(mc) ? "active" : "inactive");
    display_pad_out("    provides_device_sdrs: %c\n",
		    y_or_n(ipmi_mc_provides_device_sdrs(mc)));
    display_pad_out("        device_available: %c\n",
		    y_or_n(ipmi_mc_device_available(mc)));
    display_pad_out("         chassis_support: %c\n",
		    y_or_n(ipmi_mc_chassis_support(mc)));
    display_pad_out("          bridge_support: %c\n",
		    y_or_n(ipmi_mc_bridge_support(mc)));
    display_pad_out("    ipmb_event_generator: %c\n",
		    y_or_n(ipmi_mc_ipmb_event_generator_support(mc)));
    display_pad_out("     ipmb_event_receiver: %c\n",
		    y_or_n(ipmi_mc_ipmb_event_receiver_support(mc)));
    display_pad_out("   fru_inventory_support: %c\n",
		    y_or_n(ipmi_mc_fru_inventory_support(mc)));
    display_pad_out("      sel_device_support: %c\n",
		    y_or_n(ipmi_mc_sel_device_support(mc)));
    display_pad_out("  sdr_repository_support: %c\n",
		    y_or_n(ipmi_mc_sdr_repository_support(mc)));
    display_pad_out("   sensor_device_support: %c\n",
		    y_or_n(ipmi_mc_sensor_device_support(mc)));
    display_pad_out("               device_id: %2.2x\n",
		    ipmi_mc_device_id(mc));
    display_pad_out("         device_revision: %1.1x\n",
		    ipmi_mc_device_revision(mc));
    display_pad_out("             fw_revision: %d.%d%d\n",
		    ipmi_mc_major_fw_revision(mc),
		    ipmi_mc_minor_fw_revision(mc)>>4,
		    ipmi_mc_minor_fw_revision(mc)&0xf);
    display_pad_out("                 version: %d.%d\n",
		    ipmi_mc_major_version(mc),
		    ipmi_mc_minor_version(mc));
    display_pad_out("         manufacturer_id: %6.6x\n",
		    ipmi_mc_manufacturer_id(mc));
    display_pad_out("              product_id: %4.4x\n",
		    ipmi_mc_product_id(mc));
    ipmi_mc_aux_fw_revision(mc, vals);
    display_pad_out("         aux_fw_revision: %2.2x %2.2x %2.2x %2.2x\n",
		    vals[0], vals[1], vals[2], vals[3]);

    display_pad_out("               SEL count: %d entries, %d slots used\n",
		    ipmi_mc_sel_count(mc), ipmi_mc_sel_entries_used(mc));
}

int
get_mc_id(char **toks, ipmi_mcid_t *mc_id)
{
    unsigned char val;

    if (get_uchar(toks, &val, "mc channel"))
	return 1;
    mc_id->channel = val;

    if (get_uchar(toks, &val, "MC num"))
	return 1;
    mc_id->mc_num = val;

    mc_id->domain_id = domain_id;
    return 0;
}

int
mc_cmd(char *cmd, char **toks, void *cb_data)
{
    mccmd_info_t  info;
    int           rv;

    if (get_mc_id(toks, &info.mc_id))
	return 0;

    info.found = 0;
    rv = ipmi_mc_pointer_noseq_cb(info.mc_id, mc_handler, &info);
    if (rv) {
	cmd_win_out("Unable to find MC\n");
	return 0;
    }
    if (!info.found) {
	cmd_win_out("Unable to find MC (%d %x)\n",
		    info.mc_id.channel, info.mc_id.mc_num);
    }
    display_pad_refresh();

    return 0;
}

void mcs_handler(ipmi_domain_t *domain,
		 ipmi_mc_t     *mc,
		 void          *cb_data)
{
    int addr;
    int channel;

    addr = ipmi_mc_get_address(mc);
    channel = ipmi_mc_get_channel(mc);
    display_pad_out("  (%x %x) - %s\n", channel, addr,
		    ipmi_mc_is_active(mc) ? "active" : "inactive");
}

static void
mcs_cmder(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_domain_iterate_mcs(domain, mcs_handler, NULL);
}

int
mcs_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    display_pad_clear();
    curr_display_type = DISPLAY_MCS;
    display_pad_out("MCs:\n");
    rv = ipmi_domain_pointer_cb(domain_id, mcs_cmder, NULL);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
	return 0;
    }
    display_pad_refresh();
    return 0;
}

static void
mccmd_rsp_handler(ipmi_mc_t  *src,
		  ipmi_msg_t *msg,
		  void       *rsp_data)
{
    unsigned int  i;
    unsigned char *data;

    display_pad_clear();
    curr_display_type = DISPLAY_RSP;
    display_pad_out("Response:\n");
    display_pad_out("  NetFN = 0x%2.2x\n", msg->netfn);
    display_pad_out("  Command = 0x%2.2x\n", msg->cmd);
    display_pad_out("  Completion code = 0x%2.2x\n", msg->data[0]);
    display_pad_out("  data =");
    data = msg->data + 1;
    for (i=0; i+1<msg->data_len; i++) {
	if ((i != 0) && ((i % 8) == 0))
	    display_pad_out("\n        ");
	display_pad_out(" %2.2x", data[i]);
    }
    display_pad_out("\n");
    display_pad_refresh();
}

void mccmd_handler(ipmi_mc_t *mc,
		   void      *cb_data)
{
    mccmd_info_t *info = cb_data;
    int          rv;

    info->found = 1;
    rv = ipmi_mc_send_command(mc, info->lun, &(info->msg), mccmd_rsp_handler,
			      NULL);
    if (rv)
	cmd_win_out("Send command failure: %x\n", rv);
}

int
mccmd_cmd(char *cmd, char **toks, void *cb_data)
{
    mccmd_info_t  info;
    unsigned char data[MCCMD_DATA_SIZE];
    unsigned int  data_len;
    int           rv;

    
    if (get_mc_id(toks, &info.mc_id))
	return 0;

    if (get_uchar(toks, &info.lun, "LUN"))
	return 0;

    if (get_uchar(toks, &info.msg.netfn, "NetFN"))
	return 0;

    if (get_uchar(toks, &info.msg.cmd, "command"))
	return 0;

    for (data_len=0; ; data_len++) {
	if (get_uchar(toks, data+data_len, NULL))
	    break;
    }

    info.msg.data_len = data_len;
    info.msg.data = data;

    info.found = 0;
    rv = ipmi_mc_pointer_noseq_cb(info.mc_id, mccmd_handler, &info);
    if (rv) {
	cmd_win_out("Unable to convert MC id to a pointer\n");
	return 0;
    }
    if (!info.found) {
	cmd_win_out("Unable to find MC (%d %x)\n",
		    info.mc_id.channel, info.mc_id.mc_num);
    }
    display_pad_refresh();

    return 0;
}

void
mc_events_enable_cb(ipmi_mc_t *mc, int err, void *cb_data)
{
    if (err)
	ui_log("Error setting events enable: 0x%x\n", err);
    else
	ui_log("Events enable set\n");
}

void
mc_events_enable_handler(ipmi_mc_t *mc,
			 void      *cb_data)
{
    mccmd_info_t *info = cb_data;
    int          rv;

    info->found = 1;
    rv = ipmi_mc_set_events_enable(mc, info->val, mc_events_enable_cb, NULL);
    if (rv)
	cmd_win_out("Set events enable failure: %x\n", rv);
}

int
mc_events_enable_cmd(char *cmd, char **toks, void *cb_data)
{
    mccmd_info_t  info;
    int           rv;

    
    if (get_mc_id(toks, &info.mc_id))
	return 0;

    if (get_uchar(toks, &info.val, "enabled"))
	return 0;

    info.found = 0;
    rv = ipmi_mc_pointer_noseq_cb(info.mc_id, mc_events_enable_handler, &info);
    if (rv) {
	cmd_win_out("Unable to convert MC id to a pointer\n");
	return 0;
    }
    if (!info.found) {
	cmd_win_out("Unable to find MC (%d %x)\n",
		    info.mc_id.channel, info.mc_id.mc_num);
    }
    display_pad_refresh();

    return 0;
}

void
mc_events_enabled_handler(ipmi_mc_t *mc,
			  void      *cb_data)
{
    mccmd_info_t *info = cb_data;

    info->found = 1;
    if (ipmi_mc_get_events_enable(mc))
	cmd_win_out("Events enabled\n");
    else
	cmd_win_out("Events not enabled\n");
}

int
mc_events_enabled_cmd(char *cmd, char **toks, void *cb_data)
{
    mccmd_info_t  info;
    int           rv;

    
    if (get_mc_id(toks, &info.mc_id))
	return 0;

    info.found = 0;
    rv = ipmi_mc_pointer_noseq_cb(info.mc_id, mc_events_enabled_handler, &info);
    if (rv) {
	cmd_win_out("Unable to convert MC id to a pointer\n");
	return 0;
    }
    if (!info.found) {
	cmd_win_out("Unable to find MC (%d %x)\n",
		    info.mc_id.channel, info.mc_id.mc_num);
    }
    display_pad_refresh();

    return 0;
}

void
display_pef(void)
{
    if (!pef) {
	display_pad_out("No PEF read, use readpef to fetch one\n");
	return;
    }

    display_pad_out("PEF\n");
    display_pad_out(" Version: %d.%d", ipmi_pef_major_version(pef),
		    ipmi_pef_minor_version(pef));
    display_pad_out(" Supports:");
    if (ipmi_pef_supports_diagnostic_interrupt(pef))
	display_pad_out(" diagnostic_interrupt");
    if (ipmi_pef_supports_oem_action(pef))
	display_pad_out(" oem_action");
    if (ipmi_pef_supports_power_cycle(pef))
	display_pad_out(" power_cycle");
    if (ipmi_pef_supports_reset(pef))
	display_pad_out(" reset");
    if (ipmi_pef_supports_power_down(pef))
	display_pad_out(" power_down");
    if (ipmi_pef_supports_alert(pef))
	display_pad_out(" alert");
    display_pad_out("\n");
    display_pad_out("  Num event filter table entries: %d\n",
		    num_event_filter_table_entries(pef));
}

typedef struct pef_table_s
{
    char *name;
    int (*get)(ipmi_pef_config_t *pefc,
	       unsigned int      sel,
	       unsigned int      *val);
    char *fmt;
} pef_table_t;

#define X(n, f) { #n, ipmi_pefconfig_get_##n, f }
static pef_table_t eft_table[] =
{
    X(enable_filter, "%d"),
    X(filter_type, "%d"),
    X(diagnostic_interrupt, "%d"),
    X(oem_action, "%d"),
    X(power_cycle, "%d"),
    X(reset, "%d"),
    X(power_down, "%d"),
    X(alert, "%d"),
    X(alert_policy_number, "%d"),
    X(event_severity, "0x%x"),
    X(generator_id_addr, "0x%x"),
    X(generator_id_channel_lun, "0x%x"),
    X(sensor_type, "0x%x"),
    X(sensor_number, "0x%x"),
    X(event_trigger, "%d"),
    X(data1_offset_mask, "0x%x"),
    X(data1_mask, "%d"),
    X(data1_compare1, "%d"),
    X(data1_compare2, "%d"),
    X(data2_mask, "%d"),
    X(data2_compare1, "%d"),
    X(data2_compare2, "%d"),
    X(data3_mask, "%d"),
    X(data3_compare1, "%d"),
    X(data3_compare2, "%d"),
    { NULL }
};
static pef_table_t apt_table[] =
{
    X(policy_num, "%d"),
    X(enabled, "%d"),
    X(policy, "%d"),
    X(channel, "0x%x"),
    X(destination_selector, "%d"),
    X(alert_string_event_specific, "%d"),
    X(alert_string_selector, "%d"),
    { NULL }
};
static pef_table_t ask_table[] =
{
    X(event_filter, "%d"),
    X(alert_string_set, "%d"),
    { NULL }
};

void
display_pef_config(void)
{
    unsigned int  i, j;
    unsigned int  val;
    unsigned int  len;
    unsigned char data[128];
    int           rv;
    unsigned int  count;

    if (!pef_config) {
	display_pad_out("No PEF config read, use readpef to fetch one\n");
	return;
    }

    display_pad_out("  alert_startup_delay_enabled: %d\n",
		    ipmi_pefconfig_get_alert_startup_delay_enabled(pef_config));
    display_pad_out("  startup_delay_enabled: %d\n",
		    ipmi_pefconfig_get_startup_delay_enabled(pef_config));
    display_pad_out("  event_messages_enabled: %d\n",
		    ipmi_pefconfig_get_event_messages_enabled(pef_config));
    display_pad_out("  pef_enabled: %d\n",
		    ipmi_pefconfig_get_pef_enabled(pef_config));
    display_pad_out("  diagnostic_interrupt_enabled: %d\n",
		    ipmi_pefconfig_get_diagnostic_interrupt_enabled(pef_config));
    display_pad_out("  oem_action_enabled: %d\n",
		    ipmi_pefconfig_get_oem_action_enabled(pef_config));
    display_pad_out("  power_cycle_enabled: %d\n",
		    ipmi_pefconfig_get_power_cycle_enabled(pef_config));
    display_pad_out("  reset_enabled: %d\n",
		    ipmi_pefconfig_get_reset_enabled(pef_config));
    display_pad_out("  power_down_enabled: %d\n",
		    ipmi_pefconfig_get_power_down_enabled(pef_config));
    display_pad_out("  alert_enabled: %d\n",
		    ipmi_pefconfig_get_alert_enabled(pef_config));

    if (ipmi_pefconfig_get_startup_delay(pef_config, &val) == 0)
	display_pad_out("  startup_delay: %d\n", val);
    if (ipmi_pefconfig_get_alert_startup_delay(pef_config, &val) == 0)
	display_pad_out("  alert_startup_delay: %d\n", val);

    len = sizeof(data);
    rv = ipmi_pefconfig_get_guid(pef_config, &val, data, &len);
    if (!rv) {
	display_pad_out("  guid_enabled: %d\n", val);
	display_pad_out("  guid:", val);
	for (i=0; i<len; i++)
	    display_pad_out(" %2.2x", data[i]);
	display_pad_out("\n");
    }

    count = ipmi_pefconfig_get_num_event_filters(pef_config);
    display_pad_out("  num_event_filters: %d\n", count);
    for (i=0; i<count; i++) {
	display_pad_out("  event filter %d:\n", i+1);
	for (j=0; eft_table[j].name != NULL; j++) {
	    rv = eft_table[j].get(pef_config, i, &val);
	    display_pad_out("    %s: ", eft_table[j].name);
	    if (rv)
		display_pad_out("error %x", rv);
	    else
		display_pad_out(eft_table[j].fmt, val);
	    display_pad_out("\n");
	}
    }

    count = ipmi_pefconfig_get_num_alert_policies(pef_config);
    display_pad_out("  num_alert_policies: %d\n", count);
    for (i=0; i<count; i++) {
	display_pad_out("  alert policy %d:\n", i+1);
	for (j=0; apt_table[j].name != NULL; j++) {
	    rv = apt_table[j].get(pef_config, i, &val);
	    display_pad_out("    %s: ", apt_table[j].name);
	    if (rv)
		display_pad_out("error %x", rv);
	    else
		display_pad_out(apt_table[j].fmt, val);
	    display_pad_out("\n");
	}
    }

    count = ipmi_pefconfig_get_num_alert_strings(pef_config);
    display_pad_out("  num_alert_strings: %d\n", count);
    for (i=0; i<count; i++) {
	display_pad_out("  alert string %d:\n", i);
	for (j=0; ask_table[j].name != NULL; j++) {
	    rv = ask_table[j].get(pef_config, i, &val);
	    display_pad_out("    %s: ", ask_table[j].name);
	    if (rv)
		display_pad_out("error %x", rv);
	    else
		display_pad_out(ask_table[j].fmt, val);
	    display_pad_out("\n");
	}
	len = sizeof(data);
	rv = ipmi_pefconfig_get_alert_string(pef_config, i, data, &len);
	if (rv)
	    display_pad_out("    alert_string: error %x\n", rv);
	else
	    display_pad_out("    alert_string: '%s'\n", data);
    }
}

void
readpef_getconf_handler(ipmi_pef_t        *pef,
			int               err,
			ipmi_pef_config_t *config,
			void              *cb_data)
{
    if (err) {
	ui_log("Error reading PEF config: %x\n", err);
	return;
    }

    pef_config = config;
    display_pef_config();
    display_pad_refresh();
}

void
readpef_alloc_handler(ipmi_pef_t *lpef,
		      int        err,
		      void       *cb_data)
{
    if (err) {
	ui_log("Error allocating PEF: %x\n", err);
	return;
    }

    if (!ipmi_pef_valid(lpef)) {
	display_pad_out("PEF is not valid\n");
	ipmi_pef_destroy(pef, NULL, NULL);
	pef = NULL;
	return;
    }

    pef = lpef;
    display_pad_clear();
    display_pef();

    ipmi_pef_get_config(pef, readpef_getconf_handler, NULL);
}

void
readpef_mc_handler(ipmi_mc_t *mc, void *cb_data)
{
    int          rv;
    mccmd_info_t *info = cb_data;

    info->found = 1;

    if (pef) {
	ipmi_pef_destroy(pef, NULL, NULL);
	pef = NULL;
    }
    if (pef_config) {
	ipmi_pef_free_config(pef_config);
	pef_config = NULL;
    }

    rv = ipmi_pef_alloc(mc, readpef_alloc_handler, NULL, NULL);
    if (rv)
        cmd_win_out("Error allocating PEF");
}

int
readpef_cmd(char *cmd, char **toks, void *cb_data)
{
    mccmd_info_t  info;
    int           rv;

    if (get_mc_id(toks, &info.mc_id))
	return 0;

    info.found = 0;
    rv = ipmi_mc_pointer_noseq_cb(info.mc_id, readpef_mc_handler, &info);
    if (rv) {
	cmd_win_out("Unable to find MC\n");
	return 0;
    }
    if (!info.found) {
	cmd_win_out("Unable to find MC (%d %x)\n",
		    info.mc_id.channel, info.mc_id.mc_num);
    }
    display_pad_refresh();

    return 0;
}

int
viewpef_cmd(char *cmd, char **toks, void *cb_data)
{
    display_pad_clear();
    display_pef();
    display_pef_config();
    display_pad_refresh();
    
    return 0;
}

void writepef_done(ipmi_pef_t *pef,
		   int        err,
		   void       *cb_data)
{
    if (err)
	ui_log("Error writing PEF: %x\n", err);
    else
	ui_log("PEF written\n");
}

int
writepef_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    if (!pef) {
	cmd_win_out("No PEF to write\n");
	return 0;
    }
    if (!pef_config) {
	cmd_win_out("No PEF config to write\n");
	return 0;
    }

    rv = ipmi_pef_set_config(pef, pef_config, writepef_done, NULL);
    if (rv) {
	cmd_win_out("Error writing pef parms: %x\n", rv);
    }
    return 0;
}

void clearpeflock_done(ipmi_pef_t *pef,
		       int        err,
		       void       *cb_data)
{
    if (err)
	ui_log("Error clearing PEF lock: %x\n", err);
    else
	ui_log("PEF lock cleared\n");
}

static void
clearpeflock_rsp_handler(ipmi_mc_t  *src,
			 ipmi_msg_t *msg,
			 void       *rsp_data)
{
    if (msg->data[0])
	ui_log("Error clearing PEF lock: %x\n",
	       IPMI_IPMI_ERR_VAL(msg->data[0]));
    else
	ui_log("PEF lock cleared\n");
}

void
clearpeflock_mc_handler(ipmi_mc_t *mc, void *cb_data)
{
    mccmd_info_t *info = cb_data;
    unsigned char data[2];
    ipmi_msg_t    msg;
    int           rv;

    info->found = 1;

    data[0] = 0;
    data[1] = 0;
    msg.netfn = IPMI_SENSOR_EVENT_NETFN;
    msg.cmd = IPMI_SET_PEF_CONFIG_PARMS_CMD;
    msg.data = data;
    msg.data_len = 2;
    rv = ipmi_mc_send_command(mc, 0, &msg, clearpeflock_rsp_handler,
			      NULL);
    if (rv)
	cmd_win_out("Send PEF clear lock failure: %x\n", rv);
}

int
clearpeflock_cmd(char *cmd, char **toks, void *cb_data)
{
    mccmd_info_t  info;
    int           rv;
    char          *mc_toks;
    char          buf[100];
    char          *ntoks;

    mc_toks = strtok_r(NULL, "", toks);
    if (mc_toks) {
	strncpy(buf+2, mc_toks, sizeof(buf)-2);
	buf[0] = 'a';
	buf[1] = ' ';
	strtok_r(buf, " ", &ntoks);
	if (get_mc_id(&ntoks, &info.mc_id))
	    return 0;

	info.found = 0;
	rv = ipmi_mc_pointer_noseq_cb(info.mc_id, clearpeflock_mc_handler,
				      &info);
	if (rv) {
	    cmd_win_out("Unable to find MC\n");
	    return 0;
	}
	if (!info.found) {
	    cmd_win_out("Unable to find MC (%d %x)\n",
			info.mc_id.channel, info.mc_id.mc_num);
	}
	display_pad_refresh();
    } else {
	if (!pef) {
	    ui_log("No PEF to write\n");
	    return 0;
	}

	ipmi_pef_clear_lock(pef, pef_config, clearpeflock_done, NULL);
    }

    return 0;
}

typedef struct setpef_parm_s
{
    char *name;
    int (*set_val)(ipmi_pef_config_t *, unsigned int);
    int (*set_data)(ipmi_pef_config_t *, unsigned char *, unsigned int);
    int (*set_val_sel)(ipmi_pef_config_t *, unsigned int, unsigned int);
    int (*set_data_sel)(ipmi_pef_config_t *, unsigned int,
			unsigned char *, unsigned int);
} setpef_parm_t;

#define N NULL
#define D(x) #x
#define C(x) D(x)
#define H(x) ipmi_pefconfig_set_ ## x
#define G(x) H(x)
static setpef_parm_t pef_conf[] =
{
#undef V
#define V startup_delay_enabled
    { C(V), G(V),    N,    N,    N },
#undef V
#define V alert_startup_delay_enabled
    { C(V), G(V),    N,    N,    N },
#undef V
#define V event_messages_enabled
    { C(V), G(V),    N,    N,    N },
#undef V
#define V pef_enabled
    { C(V), G(V),    N,    N,    N },
#undef V
#define V diagnostic_interrupt_enabled
    { C(V), G(V),    N,    N,    N },
#undef V
#define V oem_action_enabled
    { C(V), G(V),    N,    N,    N },
#undef V
#define V power_cycle_enabled
    { C(V), G(V),    N,    N,    N },
#undef V
#define V reset_enabled
    { C(V), G(V),    N,    N,    N },
#undef V
#define V power_down_enabled
    { C(V), G(V),    N,    N,    N },
#undef V
#define V alert_enabled
    { C(V), G(V),    N,    N,    N },
#undef V
#define V startup_delay
    { C(V), G(V),    N,    N,    N },
#undef V
#define V alert_startup_delay
    { C(V), G(V),    N,    N,    N },
#undef V
#define V enable_filter
    { C(V),    N,    N, G(V),    N },
#undef V
#define V filter_type
    { C(V),    N,    N, G(V),    N },
#undef V
#define V diagnostic_interrupt
    { C(V),    N,    N, G(V),    N },
#undef V
#define V oem_action
    { C(V),    N,    N, G(V),    N },
#undef V
#define V power_cycle
    { C(V),    N,    N, G(V),    N },
#undef V
#define V reset
    { C(V),    N,    N, G(V),    N },
#undef V
#define V power_down
    { C(V),    N,    N, G(V),    N },
#undef V
#define V alert
    { C(V),    N,    N, G(V),    N },
#undef V
#define V alert_policy_number
    { C(V),    N,    N, G(V),    N },
#undef V
#define V event_severity
    { C(V),    N,    N, G(V),    N },
#undef V
#define V generator_id_addr
    { C(V),    N,    N, G(V),    N },
#undef V
#define V generator_id_channel_lun
    { C(V),    N,    N, G(V),    N },
#undef V
#define V sensor_type
    { C(V),    N,    N, G(V),    N },
#undef V
#define V sensor_number
    { C(V),    N,    N, G(V),    N },
#undef V
#define V event_trigger
    { C(V),    N,    N, G(V),    N },
#undef V
#define V data1_offset_mask
    { C(V),    N,    N, G(V),    N },
#undef V
#define V data1_mask
    { C(V),    N,    N, G(V),    N },
#undef V
#define V data1_compare1
    { C(V),    N,    N, G(V),    N },
#undef V
#define V data1_compare2
    { C(V),    N,    N, G(V),    N },
#undef V
#define V data2_mask
    { C(V),    N,    N, G(V),    N },
#undef V
#define V data2_compare1
    { C(V),    N,    N, G(V),    N },
#undef V
#define V data2_compare2
    { C(V),    N,    N, G(V),    N },
#undef V
#define V data3_mask
    { C(V),    N,    N, G(V),    N },
#undef V
#define V data3_compare1
    { C(V),    N,    N, G(V),    N },
#undef V
#define V data3_compare2
    { C(V),    N,    N, G(V),    N },
#undef V
#define V policy_num
    { C(V),    N,    N, G(V),    N },
#undef V
#define V enabled
    { C(V),    N,    N, G(V),    N },
#undef V
#define V channel
    { C(V),    N,    N, G(V),    N },
#undef V
#define V destination_selector
    { C(V),    N,    N, G(V),    N },
#undef V
#define V alert_string_event_specific
    { C(V),    N,    N, G(V),    N },
#undef V
#define V alert_string_selector
    { C(V),    N,    N, G(V),    N },
#undef V
#define V event_filter
    { C(V),    N,    N, G(V),    N },
#undef V
#define V alert_string_set
    { C(V),    N,    N, G(V),    N },
    { NULL }
};


static int
setpef_cmd(char *cmd, char **toks, void *cb_data)
{
    unsigned int  sel;
    unsigned int  val;
    unsigned char data[30];
    char          *name;
    char          *str;
    unsigned int  i;
    int           rv = 0;

    if (!pef_config) {
	cmd_win_out("No PEF config read, use readpef to fetch one\n");
	return 0;
    }

    name = strtok_r(NULL, " \t\n", toks);
    if (!name) {
	cmd_win_out("No PEF config name given\n");
	return 0;
    }

    for (i=0; pef_conf[i].name != NULL; i++) {
	if (strcmp(pef_conf[i].name, name) == 0)
	    break;
    }

    if (pef_conf[i].name == NULL) {
	if (strcmp(name, "guid") == 0) {
	    for (i=0; i<sizeof(data); i++) {
		if (get_uchar(toks, data+i, NULL))
		    break;
	    }
	    rv = ipmi_pefconfig_set_guid(pef_config, (i != 0), data, i);
	} else if (strcmp(name, "alert_string") == 0) {
	    if (get_uint(toks, &sel, "selector"))
		return 0;
	    str = strtok_r(NULL, "", toks);
	    rv = ipmi_pefconfig_set_alert_string(pef_config, sel,
						 (unsigned char *) str);
	} else {
	    cmd_win_out("Invalid PEF config name: '%s'\n", name);
	    return 0;
	}
    } else if (pef_conf[i].set_val) {
	if (get_uint(toks, &val, "value"))
	    return 0;
	rv = pef_conf[i].set_val(pef_config, val);
    } else if (pef_conf[i].set_data) {
	for (i=0; i<sizeof(data); i++) {
	    if (get_uchar(toks, data+i, NULL))
		break;
	}
	rv = pef_conf[i].set_data(pef_config, data, i);
    } else if (pef_conf[i].set_val_sel) {
	if (get_uint(toks, &sel, "selector"))
	    return 0;
	if (get_uint(toks, &val, "value"))
	    return 0;
	rv = pef_conf[i].set_val_sel(pef_config, sel, val);
    } else if (pef_conf[i].set_data_sel) {
	if (get_uint(toks, &sel, "selector"))
	    return 0;
	for (i=0; i<sizeof(data); i++) {
	    if (get_uchar(toks, data+i, NULL))
		break;
	}
	rv = pef_conf[i].set_data_sel(pef_config, sel, data, i);
    }
    if (rv)
	cmd_win_out("Error setting parm: 0x%x\n", rv);
    return 0;
}

static void
lanparm_out_val(char *name, int rv, char *fmt, unsigned int val)
{
    if (rv == ENOTSUP)
	return;
    display_pad_out("  %s: ", name);
    if (rv)
	display_pad_out("err %x", rv);
    else
	display_pad_out(fmt, val);
    display_pad_out("\n");
}

static void
lanparm_out_data(char *name, int rv, unsigned char *data, int len)
{
    int i;
    if (rv == ENOTSUP)
	return;
    display_pad_out("  %s: ", name);
    if (rv)
	display_pad_out("err %x\n", rv);
    else {
	for (i=0; i<len; i++)
	    display_pad_out("%2.2x", data[i]);
	display_pad_out("\n");
    }
}

void
display_lanparm_config(void)
{
    unsigned int  i;
    unsigned int  val;
    unsigned int  len;
    unsigned char data[128];
    int           rv;
    unsigned int  count;

    if (!lanparm_config) {
	display_pad_out("No LANPARM config read, use readlanparm to fetch one\n");
	return;
    }

    display_pad_out("LAN parameters:");
    display_pad_out("  auth supported:");
    if (ipmi_lanconfig_get_support_auth_oem(lanparm_config))
	display_pad_out(" oem");
    if (ipmi_lanconfig_get_support_auth_straight(lanparm_config))
	display_pad_out(" straight");
    if (ipmi_lanconfig_get_support_auth_md5(lanparm_config))
	display_pad_out(" md5");
    if (ipmi_lanconfig_get_support_auth_md2(lanparm_config))
	display_pad_out(" md2");
    if (ipmi_lanconfig_get_support_auth_none(lanparm_config))
	display_pad_out(" none");
    display_pad_out("\n");

    display_pad_out("  ip_addr_source: %d\n",
		    ipmi_lanconfig_get_ip_addr_source(lanparm_config));
    rv = ipmi_lanconfig_get_ipv4_ttl(lanparm_config, &val);
    lanparm_out_val("ipv4_ttl", rv, "%d", val);
    rv = ipmi_lanconfig_get_ipv4_flags(lanparm_config, &val);
    lanparm_out_val("ipv4_flags", rv, "%d", val);
    rv = ipmi_lanconfig_get_ipv4_precedence(lanparm_config, &val);
    lanparm_out_val("ipv4_precedence", rv, "%d", val);
    rv = ipmi_lanconfig_get_ipv4_tos(lanparm_config, &val);
    lanparm_out_val("ipv4_tos", rv, "%d", val);

    for (i=0; i<5; i++) {
	display_pad_out("  auth enabled (%d):", i);
	rv = ipmi_lanconfig_get_enable_auth_oem(lanparm_config, i, &val);
	if (rv)
	    display_pad_out(" oemerr%x", rv);
	else if (val)
	    display_pad_out(" oem");
	rv = ipmi_lanconfig_get_enable_auth_straight(lanparm_config, i, &val);
	if (rv)
	    display_pad_out(" straighterr%x", rv);
	else if (val)
	    display_pad_out(" straight");
	rv = ipmi_lanconfig_get_enable_auth_md5(lanparm_config, i, &val);
	if (rv)
	    display_pad_out(" md5err%x", rv);
	else if (val)
	    display_pad_out(" md5");
	rv = ipmi_lanconfig_get_enable_auth_md2(lanparm_config, i, &val);
	if (rv)
	    display_pad_out(" md2err%x", rv);
	else if (val)
	    display_pad_out(" md2");
	rv = ipmi_lanconfig_get_enable_auth_none(lanparm_config, i, &val);
	if (rv)
	    display_pad_out(" noneerr%x", rv);
	else if (val)
	    display_pad_out(" none");
	display_pad_out("\n");
    }

    len = 4;
    rv = ipmi_lanconfig_get_ip_addr(lanparm_config, data, &len);
    lanparm_out_data("ip_addr", rv, data, len);
    len = 6;
    rv = ipmi_lanconfig_get_mac_addr(lanparm_config, data, &len);
    lanparm_out_data("mac_addr", rv, data, len);
    len = 4;
    rv = ipmi_lanconfig_get_subnet_mask(lanparm_config, data, &len);
    lanparm_out_data("subnet_mask", rv, data, len);
    len = 2;
    rv = ipmi_lanconfig_get_primary_rmcp_port(lanparm_config, data, &len);
    lanparm_out_data("primary_rmcp_port", rv, data, len);
    len = 2;
    rv = ipmi_lanconfig_get_secondary_rmcp_port(lanparm_config, data, &len);
    lanparm_out_data("secondary_rmcp_port", rv, data, len);

    rv = ipmi_lanconfig_get_bmc_generated_arps(lanparm_config, &val);
    lanparm_out_val("bmc_generated_arps", rv, "%d", val);
    rv = ipmi_lanconfig_get_bmc_generated_garps(lanparm_config, &val);
    lanparm_out_val("bmc_generated_garps", rv, "%d", val);
    rv = ipmi_lanconfig_get_garp_interval(lanparm_config, &val);
    lanparm_out_val("garp_interval", rv, "%d", val);

    len = 4;
    rv = ipmi_lanconfig_get_default_gateway_ip_addr(lanparm_config, data, &len);
    lanparm_out_data("default_gateway_ip_addr", rv, data, len);
    len = 6;
    rv = ipmi_lanconfig_get_default_gateway_mac_addr(lanparm_config, data, &len);
    lanparm_out_data("default_gateway_mac_addr", rv, data, len);
    len = 4;
    rv = ipmi_lanconfig_get_backup_gateway_ip_addr(lanparm_config, data, &len);
    lanparm_out_data("backup_gateway_ip_addr", rv, data, len);
    len = 6;
    rv = ipmi_lanconfig_get_backup_gateway_mac_addr(lanparm_config, data, &len);
    lanparm_out_data("backup_gateway_mac_addr", rv, data, len);

    len = 18;
    rv = ipmi_lanconfig_get_community_string(lanparm_config, data, &len);
    display_pad_out("  community_string: ");
    if (rv)
	display_pad_out("err: %x\n", rv);
    else
	display_pad_out("%s\n", data);

    count = ipmi_lanconfig_get_num_alert_destinations(lanparm_config);
    display_pad_out("  num_alert_destinations: %d\n", count);
    for (i=0; i<count; i++) {
	display_pad_out("  destination %d:\n", i);
	rv = ipmi_lanconfig_get_alert_ack(lanparm_config, i, &val);
	lanparm_out_val("  alert_ack", rv, "%d", val);
	rv = ipmi_lanconfig_get_dest_type(lanparm_config, i, &val);
	lanparm_out_val("  dest_type", rv, "%d", val);
	rv = ipmi_lanconfig_get_alert_retry_interval(lanparm_config, i, &val);
	lanparm_out_val("  alert_retry_interval", rv, "%d", val);
	rv = ipmi_lanconfig_get_max_alert_retries(lanparm_config, i, &val);
	lanparm_out_val("  max_alert_retries", rv, "%d", val);
	rv = ipmi_lanconfig_get_dest_format(lanparm_config, i, &val);
	lanparm_out_val("  dest_format", rv, "%d", val);
	rv = ipmi_lanconfig_get_gw_to_use(lanparm_config, i, &val);
	lanparm_out_val("  gw_to_use", rv, "%d", val);
	len = 4;
	rv = ipmi_lanconfig_get_dest_ip_addr(lanparm_config, i, data, &len);
	lanparm_out_data("  dest_ip_addr", rv, data, len);
	len = 6;
	rv = ipmi_lanconfig_get_dest_mac_addr(lanparm_config, i, data, &len);
	lanparm_out_data("  dest_mac_addr", rv, data, len);
    }
}

typedef struct lanparm_info_s
{
    ipmi_mcid_t   mc_id;
    unsigned char lun;
    unsigned char channel;
    ipmi_msg_t    msg;
    int           found;
} lanparm_info_t;

void
readlanparm_getconf_handler(ipmi_lanparm_t    *lanparm,
			    int               err,
			    ipmi_lan_config_t *config,
			    void              *cb_data)
{
    if (err) {
	ui_log("Error reading LANPARM config: %x\n", err);
	return;
    }

    lanparm_config = config;
    display_pad_clear();
    display_lanparm_config();
    display_pad_refresh();
}

void
readlanparm_mc_handler(ipmi_mc_t *mc, void *cb_data)
{
    int            rv;
    lanparm_info_t *info = cb_data;

    info->found = 1;

    if (lanparm) {
	ipmi_lanparm_destroy(lanparm, NULL, NULL);
	lanparm = NULL;
    }
    if (lanparm_config) {
	ipmi_lan_free_config(lanparm_config);
	lanparm_config = NULL;
    }

    rv = ipmi_lanparm_alloc(mc, info->channel, &lanparm);
    if (rv) {
	cmd_win_out("failed lanparm allocation: %x\n", rv);
	return;
    }

    rv = ipmi_lan_get_config(lanparm, readlanparm_getconf_handler, NULL);
}

int
readlanparm_cmd(char *cmd, char **toks, void *cb_data)
{
    lanparm_info_t info;
    int            rv;
    unsigned char  val;

    if (get_mc_id(toks, &info.mc_id))
	return 0;

    if (get_uchar(toks, &val, "lanparm channel"))
	return 0;
    info.channel = val;

    info.found = 0;
    rv = ipmi_mc_pointer_noseq_cb(info.mc_id, readlanparm_mc_handler, &info);
    if (rv) {
	cmd_win_out("Unable to find MC\n");
	return 0;
    }
    if (!info.found) {
	cmd_win_out("Unable to find MC (%d %x)\n",
		    info.mc_id.channel, info.mc_id.mc_num);
    }
    display_pad_refresh();

    return 0;
}

int
viewlanparm_cmd(char *cmd, char **toks, void *cb_data)
{
    display_pad_clear();
    display_lanparm_config();
    display_pad_refresh();
    
    return 0;
}

void writelanparm_done(ipmi_lanparm_t *lanparm,
		       int            err,
		       void           *cb_data)
{
    if (err)
	ui_log("Error writing LANPARM: %x\n", err);
    else
	ui_log("LANPARM written\n");
}

int
writelanparm_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    if (!lanparm) {
	cmd_win_out("No LANPARM to write\n");
	return 0;
    }
    if (!lanparm_config) {
	cmd_win_out("No LANPARM config to write\n");
	return 0;
    }

    rv = ipmi_lan_set_config(lanparm, lanparm_config, writelanparm_done, NULL);
    if (rv) {
	cmd_win_out("Error writing lan parms: %x\n", rv);
    }
    return 0;
}

void clearlanparmlock_done(ipmi_lanparm_t *lanparm,
			   int            err,
			   void           *cb_data)
{
    if (err)
	ui_log("Error clearing LANPARM lock: %x\n", err);
    else
	ui_log("LANPARM lock cleared\n");
}

static void
clearlanparmlock_rsp_handler(ipmi_mc_t  *src,
			     ipmi_msg_t *msg,
			     void       *rsp_data)
{
    if (msg->data[0])
	ui_log("Error clearing LANPARM lock: %x\n",
	       IPMI_IPMI_ERR_VAL(msg->data[0]));
    else
	ui_log("LANPARM lock cleared\n");
}

void
clearlanparmlock_mc_handler(ipmi_mc_t *mc, void *cb_data)
{
    lanparm_info_t *info = cb_data;
    unsigned char  data[3];
    ipmi_msg_t     msg;
    int            rv;

    info->found = 1;

    data[0] = info->channel;
    data[1] = 0;
    data[2] = 0;
    msg.netfn = IPMI_TRANSPORT_NETFN;
    msg.cmd = IPMI_SET_LAN_CONFIG_PARMS_CMD;
    msg.data = data;
    msg.data_len = 3;
    rv = ipmi_mc_send_command(mc, 0, &msg, clearlanparmlock_rsp_handler,
			      NULL);
    if (rv)
	cmd_win_out("Send LANPARM clear lock failure: %x\n", rv);
}

int
clearlanparmlock_cmd(char *cmd, char **toks, void *cb_data)
{
    lanparm_info_t info;
    int            rv;
    char           *mc_toks;
    char           buf[100];
    char           *ntoks;
    unsigned char  val;

    mc_toks = strtok_r(NULL, "", toks);
    if (mc_toks) {
	strncpy(buf+2, mc_toks, sizeof(buf)-2);
	buf[0] = 'a';
	buf[1] = ' ';
	strtok_r(buf, " ", &ntoks);
	if (get_mc_id(&ntoks, &info.mc_id))
	    return 0;

	if (get_uchar(&ntoks, &val, "lanparm channel"))
	    return 0;
	info.channel = val;

	info.found = 0;
	rv = ipmi_mc_pointer_noseq_cb(info.mc_id, clearlanparmlock_mc_handler,
				      &info);
	if (rv) {
	    cmd_win_out("Unable to find MC\n");
	    return 0;
	}
	if (!info.found) {
	    cmd_win_out("Unable to find MC (%d %x)\n",
			info.mc_id.channel, info.mc_id.mc_num);
	}
	display_pad_refresh();
    } else {
	if (!lanparm) {
	    ui_log("No LANPARM to write\n");
	    return 0;
	}

	ipmi_lan_clear_lock(lanparm, lanparm_config,
			    clearlanparmlock_done, NULL);
    }

    return 0;
}

typedef struct setlan_parm_s
{
    char *name;
    int (*set_val)(ipmi_lan_config_t *, unsigned int);
    int (*set_data)(ipmi_lan_config_t *, unsigned char *, unsigned int);
    int (*set_val_sel)(ipmi_lan_config_t *, unsigned int, unsigned int);
    int (*set_data_sel)(ipmi_lan_config_t *, unsigned int,
			unsigned char *, unsigned int);
} setlan_parm_t;

#undef N
#define N NULL
#undef D
#define D(x) #x
#undef C
#define C(x) D(x)
#undef H
#define H(x) ipmi_lanconfig_set_ ## x
#undef G
#define G(x) H(x)
static setlan_parm_t lan_conf[] =
{
#undef V
#define V ip_addr_source
    { C(V), G(V),    N,    N,    N },
#undef V
#define V ipv4_ttl
    { C(V), G(V),    N,    N,    N },
#undef V
#define V ipv4_flags
    { C(V), G(V),    N,    N,    N },
#undef V
#define V ipv4_precedence
    { C(V), G(V),    N,    N,    N },
#undef V
#define V ipv4_tos
    { C(V), G(V),    N,    N,    N },
#undef V
#define V enable_auth_oem
    { C(V),    N,    N, G(V),    N },
#undef V
#define V enable_auth_straight
    { C(V),    N,    N, G(V),    N },
#undef V
#define V enable_auth_md5
    { C(V),    N,    N, G(V),    N },
#undef V
#define V enable_auth_md2
    { C(V),    N,    N, G(V),    N },
#undef V
#define V enable_auth_none
    { C(V),    N,    N, G(V),    N },
#undef V
#define V ip_addr
    { C(V),    N, G(V),    N,    N },
#undef V
#define V mac_addr
    { C(V),    N, G(V),    N,    N },
#undef V
#define V subnet_mask
    { C(V),    N, G(V),    N,    N },
#undef V
#define V primary_rmcp_port
    { C(V),    N, G(V),    N,    N },
#undef V
#define V secondary_rmcp_port
    { C(V),    N, G(V),    N,    N },
#undef V
#define V bmc_generated_arps
    { C(V), G(V),    N,    N,    N },
#undef V
#define V bmc_generated_garps
    { C(V), G(V),    N,    N,    N },
#undef V
#define V garp_interval
    { C(V), G(V),    N,    N,    N },
#undef V
#define V default_gateway_ip_addr
    { C(V),    N, G(V),    N,    N },
#undef V
#define V default_gateway_mac_addr
    { C(V),    N, G(V),    N,    N },
#undef V
#define V backup_gateway_ip_addr
    { C(V),    N, G(V),    N,    N },
#undef V
#define V backup_gateway_mac_addr
    { C(V),    N, G(V),    N,    N },
#undef V
#define V alert_ack
    { C(V),    N,    N, G(V),    N },
#undef V
#define V dest_type
    { C(V),    N,    N, G(V),    N },
#undef V
#define V alert_retry_interval
    { C(V),    N,    N, G(V),    N },
#undef V
#define V max_alert_retries
    { C(V),    N,    N, G(V),    N },
#undef V
#define V dest_format
    { C(V),    N,    N, G(V),    N },
#undef V
#define V gw_to_use
    { C(V),    N,    N, G(V),    N },
#undef V
#define V dest_ip_addr
    { C(V),    N,    N,    N, G(V) },
#undef V
#define V dest_mac_addr
    { C(V),    N,    N,    N, G(V) },
};


static int
setlanparm_cmd(char *cmd, char **toks, void *cb_data)
{
    unsigned int  sel;
    unsigned int  val;
    unsigned char data[30];
    char          *name;
    char          *str;
    unsigned int  i, j;
    int           rv = 0;

    if (!lanparm_config) {
	cmd_win_out("No LAN config read, use readlan to fetch one\n");
	return 0;
    }

    name = strtok_r(NULL, " \t\n", toks);
    if (!name) {
	cmd_win_out("No LAN config name given\n");
	return 0;
    }

    for (i=0; lan_conf[i].name != NULL; i++) {
	if (strcmp(lan_conf[i].name, name) == 0)
	    break;
    }

    if (lan_conf[i].name == NULL) {
        if (strcmp(name, "community_string") == 0) {
	    if (get_uint(toks, &sel, "selector"))
		return 0;
	    str = strtok_r(NULL, "", toks);
	    rv = ipmi_lanconfig_set_community_string(lanparm_config,
						     (unsigned char *) str,
						     strlen(str));
	} else {
	    cmd_win_out("Invalid LAN config name: '%s'\n", name);
	    return 0;
	}
    } else if (lan_conf[i].set_val) {
	if (get_uint(toks, &val, "value"))
	    return 0;
	rv = lan_conf[i].set_val(lanparm_config, val);
    } else if (lan_conf[i].set_data) {
	for (j=0; j<sizeof(data); j++) {
	    if (get_uchar(toks, data+j, NULL))
		break;
	}
	rv = lan_conf[i].set_data(lanparm_config, data, j);
    } else if (lan_conf[i].set_val_sel) {
	if (get_uint(toks, &sel, "selector"))
	    return 0;
	if (get_uint(toks, &val, "value"))
	    return 0;
	rv = lan_conf[i].set_val_sel(lanparm_config, sel, val);
    } else if (lan_conf[i].set_data_sel) {
	if (get_uint(toks, &sel, "selector"))
	    return 0;
	for (j=0; j<sizeof(data); j++) {
	    if (get_uchar(toks, data+j, NULL))
		break;
	}
	rv = lan_conf[i].set_data_sel(lanparm_config, sel, data, j);
    }
    if (rv)
	cmd_win_out("Error setting parm: 0x%x\n", rv);
    return 0;
}

static ipmi_pet_t *pet;

typedef struct pet_info_s
{
    unsigned int   connection;
    unsigned int   channel;
    struct in_addr ip_addr;
    unsigned char  mac_addr[6];
    unsigned int   eft_sel;
    unsigned int   policy_num;
    unsigned int   apt_sel;
    unsigned int   lan_dest_sel;
} pet_info_t;

static void
pet_done(ipmi_pet_t *pet, int err, void *cb_data)
{
    if (err)
	ui_log("Error setting pet: %x\n", err);
    else
	ui_log("PET set");	
}

static void
pet_domain_cb(ipmi_domain_t *domain, void *cb_data)
{
    pet_info_t *info = cb_data;
    int        rv;

    rv = ipmi_pet_create(domain,
			 info->connection,
			 info->channel,
			 info->ip_addr,
			 info->mac_addr,
			 info->eft_sel,
			 info->policy_num,
			 info->apt_sel,
			 info->lan_dest_sel,
			 pet_done,
			 NULL,
			 &pet);
    if (rv)
	cmd_win_out("Error creating PET: %x\n", rv);
}

static int
pet_cmd(char *cmd, char **toks, void *cb_data)
{
    pet_info_t info;
    int        rv;

    if (pet) {
	ipmi_pet_destroy(pet, NULL, NULL);
	pet = NULL;
    }

    if (get_uint(toks, &info.connection, "connection"))
	return 0;
    if (get_uint(toks, &info.channel, "channel"))
	return 0;
    if (get_ip_addr(toks, &info.ip_addr, "IP address"))
	return 0;
    if (get_mac_addr(toks, info.mac_addr, "MAC address"))
	return 0;
    if (get_uint(toks, &info.eft_sel, "eft selector"))
	return 0;
    if (get_uint(toks, &info.policy_num, "policy_num"))
	return 0;
    if (get_uint(toks, &info.apt_sel, "apt selector"))
	return 0;
    if (get_uint(toks, &info.lan_dest_sel, "LAN dest selector"))
	return 0;

    rv = ipmi_domain_pointer_cb(domain_id, pet_domain_cb, &info);
    if (rv)
	cmd_win_out("Error converting domain");
    return 0;
}

typedef struct msg_cmd_data_s
{
    unsigned char    data[MCCMD_DATA_SIZE];
    unsigned int     data_len;
    ipmi_ipmb_addr_t addr;
    ipmi_msg_t       msg;
} msg_cmd_data_t;

static int
mccmd_addr_rsp_handler(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_msg_t    *msg = &rspi->msg;
    unsigned int  i;
    unsigned char *data;

    display_pad_clear();
    curr_display_type = DISPLAY_RSP;
    display_pad_out("Response:\n");
    display_pad_out("  NetFN = 0x%2.2x\n", msg->netfn);
    display_pad_out("  Command = 0x%2.2x\n", msg->cmd);
    display_pad_out("  Completion code = 0x%2.2x\n", msg->data[0]);
    display_pad_out("  data =");
    data = msg->data + 1;
    for (i=0; i+1<msg->data_len; i++) {
	if ((i != 0) && ((i % 8) == 0))
	    display_pad_out("\n        ");
	display_pad_out(" %2.2x", data[i]);
    }
    display_pad_out("\n");
    display_pad_refresh();
    return IPMI_MSG_ITEM_NOT_USED;
}

static void
msg_cmder(ipmi_domain_t *domain, void *cb_data)
{
    msg_cmd_data_t *info = cb_data;
    int            rv;

    rv = ipmi_send_command_addr(domain,
				(ipmi_addr_t *) &(info->addr),
				sizeof(info->addr),
				&info->msg,
				mccmd_addr_rsp_handler,
				NULL, NULL);
    if (rv)
	cmd_win_out("Send command failure: %x\n", rv);
}

static int
msg_cmd(char *cmd, char **toks, void *cb_data)
{
    msg_cmd_data_t info;
    unsigned int   channel;
    int            rv;
    
    info.addr.addr_type = IPMI_IPMB_ADDR_TYPE;
    if (get_uint(toks, &channel, "channel"))
	return 0;
    info.addr.channel = channel;

    if (get_uchar(toks, &info.addr.slave_addr, "slave address"))
	return 0;

    if (info.addr.slave_addr == 0) {
	info.addr.addr_type = IPMI_IPMB_BROADCAST_ADDR_TYPE;
	if (get_uchar(toks, &info.addr.slave_addr, "slave address"))
	    return 0;
    }

    if (get_uchar(toks, &info.addr.lun, "LUN"))
	return 0;

    if (get_uchar(toks, &info.msg.netfn, "NetFN"))
	return 0;

    if (get_uchar(toks, &info.msg.cmd, "command"))
	return 0;

    for (info.data_len=0; ; info.data_len++) {
	if (get_uchar(toks, info.data+info.data_len, NULL))
	    break;
    }

    info.msg.data_len = info.data_len;
    info.msg.data = info.data;

    rv = ipmi_domain_pointer_cb(domain_id, msg_cmder, &info);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
	return 0;
    }

    display_pad_refresh();

    return 0;
}

static void
set_control(ipmi_control_t *control, void *cb_data)
{
    char          **toks = cb_data;
    int           num_vals;
    int           i;
    int           *vals = NULL;
    unsigned char *cvals = NULL;
    char          *tok;
    char          *estr;
    int           rv;
    int           control_type;

    control_type = ipmi_control_get_type(control);
    switch (control_type) {
	case IPMI_CONTROL_LIGHT:
	    if (ipmi_control_light_set_with_setting(control)) {
		ipmi_light_setting_t *setting;

		num_vals = ipmi_control_get_num_vals(control);
		setting = ipmi_alloc_light_settings(num_vals);
		if (!setting) {
		    cmd_win_out("set_control: out of memory\n");
		    goto out;
		}

		for (i=0; i<num_vals; i++) {
		    unsigned int val;

		    if (get_uint(toks, &val, "light color"))
			goto out_free_light;
		    ipmi_light_setting_set_color(setting, i, val);

		    if (get_uint(toks, &val, "light on time"))
			goto out_free_light;
		    ipmi_light_setting_set_on_time(setting, i, val);

		    if (get_uint(toks, &val, "light off time"))
			goto out_free_light;
		    ipmi_light_setting_set_off_time(setting, i, val);

		    if (get_uint(toks, &val, "local control"))
			goto out_free_light;
		    ipmi_light_setting_set_local_control(setting, i, val);
		}

		rv = ipmi_control_set_light(control, setting, NULL, NULL);
		if (rv) {
		    cmd_win_out("set_control: Returned error 0x%x\n", rv);
		}
	    out_free_light:
		ipmi_free_light_settings(setting);
		break;
	    }
	    /* FALLTHRU */
	case IPMI_CONTROL_RELAY:
	case IPMI_CONTROL_ALARM:
	case IPMI_CONTROL_RESET:
	case IPMI_CONTROL_ONE_SHOT_RESET:
	case IPMI_CONTROL_POWER:
	case IPMI_CONTROL_FAN_SPEED:
	case IPMI_CONTROL_OUTPUT:
	case IPMI_CONTROL_ONE_SHOT_OUTPUT:
	    num_vals = ipmi_control_get_num_vals(control);
	    vals = ipmi_mem_alloc(sizeof(*vals) * num_vals);
	    if (!vals) {
		cmd_win_out("set_control: out of memory\n");
		goto out;
	    }
	
	    for (i=0; i<num_vals; i++) {
		tok = strtok_r(NULL, " \t\n", toks);
		if (!tok) {
		    cmd_win_out("set_control: Value %d is not present\n", i);
		    goto out_bcon;
		}
		vals[i] = strtol(tok, &estr, 0);
		if (*estr != '\0') {
		    cmd_win_out("set_control: Value %d is invalid\n", i);
		    goto out_bcon;
		}
	    }

	    rv = ipmi_control_set_val(control, vals, NULL, NULL);
	    if (rv) {
		cmd_win_out("set_control: Returned error 0x%x\n", rv);
	    }
    out_bcon:
	    break;

	case IPMI_CONTROL_DISPLAY:
	    break;

	case IPMI_CONTROL_IDENTIFIER:
	    num_vals = ipmi_control_identifier_get_max_length(control);
	    cvals = ipmi_mem_alloc(sizeof(*cvals) * num_vals);
	    if (!cvals) {
		cmd_win_out("set_control: out of memory\n");
		goto out;
	    }
	
	    for (i=0; i<num_vals; i++) {
		tok = strtok_r(NULL, " \t\n", toks);
		if (!tok) {
		    cmd_win_out("set_control: Value %d is not present\n", i);
		    goto out;
		}
		cvals[i] = strtol(tok, &estr, 0);
		if (*estr != '\0') {
		    cmd_win_out("set_control: Value %d is invalid\n", i);
		    goto out;
		}
	    }

	    rv = ipmi_control_identifier_set_val(control, cvals, num_vals,
						 NULL, NULL);
	    if (rv) {
		cmd_win_out("set_control: Returned error 0x%x\n", rv);
	    }
	    break;
    }
 out:
    if (vals)
	ipmi_mem_free(vals);
    if (cvals)
	ipmi_mem_free(cvals);
}

static int
set_control_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    if (curr_display_type != DISPLAY_CONTROL) {
	cmd_win_out("The current displayed item is not a control\n");
	goto out;
    }

    rv = ipmi_control_pointer_cb(curr_control_id, set_control, toks);
    if (rv)
	cmd_win_out("set_control: Unable to get control pointer: 0x%x\n", rv);

 out:
    return 0;
}

static void
delevent_cb(ipmi_domain_t *domain, int err, void *cb_data)
{
    if (err)
	ui_log("Error deleting log: %x\n", err);
    else
	ui_log("log deleted\n");
}

typedef struct delevent_info_s
{
    ipmi_mcid_t  mc_id;
    unsigned int record_id;
    int          rv;
} delevent_info_t;

static void
delevent_cmder(ipmi_domain_t *domain, void *cb_data)
{
    int             rv;
    delevent_info_t *info = cb_data;
    ipmi_event_t    *event, *n;
    int             found = 0;

    info->mc_id.domain_id = domain_id;

    event = ipmi_domain_first_event(domain);
    while (event) {
	if ((ipmi_cmp_mc_id_noseq(ipmi_event_get_mcid(event),info->mc_id) == 0)
	    && (ipmi_event_get_record_id(event) == info->record_id))
	{
	    rv = ipmi_domain_del_event(domain, event, delevent_cb, NULL);
	    if (rv)
		cmd_win_out("error deleting log: %x\n", rv);
	    ipmi_event_free(event);
	    found = 1;
	    break;
	} else {
	    n = ipmi_domain_next_event(domain, event);
	    ipmi_event_free(event);
	    event = n;
	}
    }
    if (!found)
	cmd_win_out("log not found\n");
}

static int
delevent_cmd(char *cmd, char **toks, void *cb_data)
{
    delevent_info_t info;
    int             rv;

    if (get_mc_id(toks, &info.mc_id))
	return 0;

    if (get_uint(toks, &info.record_id, "record id"))
	return 0;

    rv = ipmi_domain_pointer_cb(domain_id, delevent_cmder, &info);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
	return 0;
    }
    return 0;
}

static void
addevent_cb(ipmi_mc_t *mc, unsigned int record_id, int err, void *cb_data)
{
    if (err)
	ui_log("Error adding event: %x\n", err);
    else
	ui_log("event 0x%4.4x added\n", record_id);
}

typedef struct addevent_info_s
{
    ipmi_mcid_t   mc_id;
    unsigned int  record_id;
    unsigned int  type;
    ipmi_time_t   timestamp;
    unsigned char data[13];
} addevent_info_t;

static void
addevent_cmder(ipmi_mc_t *mc, void *cb_data)
{
    int             rv;
    addevent_info_t *info = cb_data;
    ipmi_event_t    *event;

    event = ipmi_event_alloc(ipmi_mc_convert_to_id(mc),
			     info->record_id,
			     info->type,
			     info->timestamp,
			     info->data,
			     13);
    if (!event) {
	cmd_win_out("Could not allocate event\n");
	return;
    }
			     
    rv = ipmi_mc_add_event_to_sel(mc, event, addevent_cb, NULL);
    if (rv)
	cmd_win_out("Unable to send add event: %x\n", rv);
    ipmi_event_free(event);
}

static int
addevent_cmd(char *cmd, char **toks, void *cb_data)
{
    addevent_info_t info;
    int             rv;
    int             i;
    struct timeval  time;

    if (get_mc_id(toks, &info.mc_id))
	return 0;

    if (get_uint(toks, &info.record_id, "record id"))
	return 0;

    if (get_uint(toks, &info.type, "record type"))
	return 0;

    for (i=0; i<13; i++) {
	if (get_uchar(toks, &info.data[i], "data"))
	    return 0;
    }

    gettimeofday(&time, NULL);
    info.timestamp = time.tv_sec * 1000000000;

    rv = ipmi_mc_pointer_noseq_cb(info.mc_id, addevent_cmder, &info);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
	return 0;
    }
    return 0;
}

static int
debug_cmd(char *cmd, char **toks, void *cb_data)
{
    char         *type;
    char         *on_off;
    int          val;

    type = strtok_r(NULL, " \t\n", toks);
    if (!type) {
	cmd_win_out("No debug type specified\n");
	goto out;
    }

    on_off = strtok_r(NULL, " \t\n", toks);
    if (!on_off) {
	cmd_win_out("on or off not specified\n");
	goto out;
    } else if (strcmp(on_off, "on") == 0) {
	val = 1;
    } else if (strcmp(on_off, "off") == 0) {
	val = 0;
    } else {
	cmd_win_out("on or off not specified, got '%s'\n", on_off);
	goto out;
    }

    if (strcmp(type, "msg") == 0) {
	if (val) DEBUG_MSG_ENABLE(); else DEBUG_MSG_DISABLE();
    } else if (strcmp(type, "rawmsg") == 0) {
	if (val) DEBUG_RAWMSG_ENABLE(); else DEBUG_RAWMSG_DISABLE();
    } else if (strcmp(type, "locks") == 0) {
	if (val) DEBUG_LOCKS_ENABLE(); else DEBUG_LOCKS_DISABLE();
    } else if (strcmp(type, "events") == 0) {
	if (val) DEBUG_EVENTS_ENABLE(); else DEBUG_EVENTS_DISABLE();
    } else if (strcmp(type, "con0") == 0) {
	if (val) DEBUG_CON_FAIL_ENABLE(0); else DEBUG_CON_FAIL_DISABLE(0);
    } else if (strcmp(type, "con1") == 0) {
	if (val) DEBUG_CON_FAIL_ENABLE(1); else DEBUG_CON_FAIL_DISABLE(1);
    } else if (strcmp(type, "con2") == 0) {
	if (val) DEBUG_CON_FAIL_ENABLE(2); else DEBUG_CON_FAIL_DISABLE(2);
    } else if (strcmp(type, "con3") == 0) {
	if (val) DEBUG_CON_FAIL_ENABLE(3); else DEBUG_CON_FAIL_DISABLE(3);
    } else {
	cmd_win_out("Invalid debug type specified: '%s'\n", type);
	goto out;
    }

 out:
    return 0;
}

static void
clear_sel_cmder(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_event_t *event, *event2;

    event = ipmi_domain_first_event(domain);
    while (event) {
	event2 = event;
	event = ipmi_domain_next_event(domain, event2);
	ipmi_domain_del_event(domain, event2, NULL, NULL);
	ipmi_event_free(event2);
    }
}

static int
clear_sel_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    rv = ipmi_domain_pointer_cb(domain_id, clear_sel_cmder, NULL);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
	return 0;
    }
    return 0;
}

static void
list_sel_cmder(ipmi_domain_t *domain, void *cb_data)
{
    int          rv;
    ipmi_event_t *event, *event2;
    unsigned int count1, count2;

    curr_display_type = EVENTS;
    display_pad_clear();
    rv = ipmi_domain_sel_count(domain, &count1);
    if (rv)
      count1 = -1;
    rv = ipmi_domain_sel_entries_used(domain, &count2);
    if (rv)
      count2 = -1;
    display_pad_out("Event counts: %d entries, %d slots used\n",
		    count1, count2);
    display_pad_out("Events:\n");
    event = ipmi_domain_first_event(domain);
    while (event) {
	ipmi_mcid_t         mcid = ipmi_event_get_mcid(event);
	unsigned int        record_id = ipmi_event_get_record_id(event);
	unsigned int        type = ipmi_event_get_type(event);
	ipmi_time_t         timestamp = ipmi_event_get_timestamp(event);
	unsigned int        data_len = ipmi_event_get_data_len(event);
	const unsigned char *data = ipmi_event_get_data_ptr(event);
	unsigned int        i;

	display_pad_out("  (%x %x) %4.4x:%2.2x %lld:",
			mcid.channel, mcid.mc_num, record_id, type, timestamp);
	for (i=0; i<data_len; i++)
	    display_pad_out(" %2.2x", data[i]);
	display_pad_out("\n");
	event2 = ipmi_domain_next_event(domain, event);
	ipmi_event_free(event);
	event = event2;
    }
    display_pad_refresh();
}

static int
list_sel_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    rv = ipmi_domain_pointer_cb(domain_id, list_sel_cmder, NULL);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
	return 0;
    }
    return 0;
}

void
sel_time_fetched(ipmi_mc_t     *mc,
		 int           err,
		 unsigned long time,
		 void          *cb_data)
{
    if (!mc) {
	display_pad_out("MC went away while fetching SEL time\n");
	goto out;
    }

    if (err) {
	display_pad_out("Error fetching SEL time: %x\n", err);
	goto out;
    }

    display_pad_out("SEL time is 0x%x\n", time);

 out:
    display_pad_refresh();
}

void get_sel_time_handler(ipmi_mc_t *mc, void *cb_data)
{
    mccmd_info_t *info = cb_data;
    int          rv;

    info->found = 1;
    rv = ipmi_mc_get_current_sel_time(mc, sel_time_fetched, NULL);
    if (rv)
	cmd_win_out("Error sending SEL time fetch: %x\n", rv);
}

int
get_sel_time_cmd(char *cmd, char **toks, void *cb_data)
{
    mccmd_info_t  info;
    int           rv;

    if (get_mc_id(toks, &info.mc_id))
	return 0;

    info.found = 0;
    rv = ipmi_mc_pointer_noseq_cb(info.mc_id, get_sel_time_handler, &info);
    if (rv) {
	cmd_win_out("Unable to find MC\n");
	return 0;
    }
    if (!info.found) {
	cmd_win_out("Unable to find MC (%d %x)\n",
		    info.mc_id.channel, info.mc_id.mc_num);
    }
    display_pad_refresh();

    return 0;
}

static void
mc_reset_done(ipmi_mc_t *mc, int err, void *cb_data)
{
    if (err)
	ui_log("Error resetting mc: %x", err);
    else
	ui_log("MC reset");
}

static void
mc_reset_handler(ipmi_mc_t *mc, void *cb_data)
{
    mccmd_info_t *info = cb_data;
    int          rv;

    info->found = 1;
    rv = ipmi_mc_reset(mc, info->msg.cmd, mc_reset_done, NULL);
    if (rv)
	cmd_win_out("Error sending MC reset: %x\n", rv);
}

static int
mc_reset_cmd(char *cmd, char **toks, void *cb_data)
{
    mccmd_info_t  info;
    int           rv;
    char          *type;

    if (get_mc_id(toks, &info.mc_id))
	return 0;

    type = strtok_r(NULL, " \n\t", toks);
    if (!type) {
	cmd_win_out("No reset type given, must be 'cold' or 'warm'\n");
	return 0;
    }

    if (strcmp(type, "warm") == 0) {
	info.msg.cmd = IPMI_MC_RESET_WARM;
    } else if (strcmp(type, "cold") == 0) {
	info.msg.cmd = IPMI_MC_RESET_COLD;
    } else {
	cmd_win_out("Invalid reset type given, must be 'cold' or 'warm'\n");
	return 0;
    }

    info.found = 0;
    rv = ipmi_mc_pointer_noseq_cb(info.mc_id, mc_reset_handler, &info);
    if (rv) {
	cmd_win_out("Unable to find MC\n");
	return 0;
    }
    if (!info.found) {
	cmd_win_out("Unable to find MC (%d %x)\n",
		    info.mc_id.channel, info.mc_id.mc_num);
    }
    display_pad_refresh();

    return 0;
}

typedef struct sdrs_info_s
{
    int           found;
    ipmi_mcid_t   mc_id;
    unsigned char do_sensors;
} sdrs_info_t;

void sdrs_fetched(ipmi_sdr_info_t *sdrs,
		  int             err,
		  int             changed,
		  unsigned int    count,
		  void            *cb_data)
{
    sdrs_info_t  *info = cb_data;
    unsigned int i;
    int          rv;
    int          total_size = 0;

    if (err) {
	ui_log("Error fetching sdrs: %x\n", err);
	goto out;
    }

    if (!sdrs) {
	ui_log("sdrs went away during fetch\n");
	goto out;
    }

    display_pad_clear();
    curr_display_type = DISPLAY_SDRS;

    display_pad_out("%s SDRs for MC (%x %x)\n",
	    info->do_sensors ? "device" : "main",
	    info->mc_id.channel, info->mc_id.mc_num);
    for (i=0; i<count; i++) {
	ipmi_sdr_t sdr;
	int        j;

	rv = ipmi_get_sdr_by_index(sdrs, i, &sdr);
	if (rv) {
	    display_pad_out("*could not get index %d\n", i);
	    continue;
	}
	total_size += sdr.length+5;
	display_pad_out("%4.4x: type %x, version %d.%d",
		sdr.record_id, sdr.type, sdr.major_version, sdr.minor_version);
	for (j=0; j<sdr.length; j++) {
	    if ((j % 8) == 0)
		display_pad_out("\n ");
	    display_pad_out(" %2.2x", sdr.data[j]);
	}
	display_pad_out("\n");
    }
    display_pad_out("total bytes in SDRs: %d\n", total_size);
    display_pad_refresh();

 out:
    ipmi_sdr_info_destroy(sdrs, NULL, NULL);
    ipmi_mem_free(info);
}

void
start_sdr_dump(ipmi_mc_t *mc, sdrs_info_t *info)
{
    ipmi_sdr_info_t *sdrs;
    int             rv;

    rv = ipmi_sdr_info_alloc(ipmi_mc_get_domain(mc),
			     mc, 0, info->do_sensors, &sdrs);
    if (rv) {
	cmd_win_out("Unable to alloc sdr info: %x\n", rv);
	ipmi_mem_free(info);
	return;
    }

    rv = ipmi_sdr_fetch(sdrs, sdrs_fetched, info);
    if (rv) {
	cmd_win_out("Unable to start SDR fetch: %x\n", rv);
	ipmi_sdr_info_destroy(sdrs, NULL, NULL);
	ipmi_mem_free(info);
	return;
    }
}

void
sdrs_mcs_handler(ipmi_mc_t *mc,
		 void      *cb_data)
{
    sdrs_info_t *info = cb_data;

    info->found = 1;
    start_sdr_dump(mc, info);
}

static int
sdrs_cmd(char *cmd, char **toks, void *cb_data)
{
    int           rv;
    sdrs_info_t   *info;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	ui_log("Could not allocate memory for SDR fetch\n");
	return 0;
    }

    if (get_mc_id(toks, &info->mc_id)) {
	ipmi_mem_free(info);
	return 0;
    }

    if (get_uchar(toks, &info->do_sensors, "do_sensors")) {
	ipmi_mem_free(info);
	return 0;
    }

    info->found = 0;

    rv = ipmi_mc_pointer_noseq_cb(info->mc_id, sdrs_mcs_handler, info);
    if (rv) {
	cmd_win_out("Unable to find MC\n");
	ipmi_mem_free(info);
    } else {
	if (!info->found) {
	    cmd_win_out("Unable to find that mc\n");
	    ipmi_mem_free(info);
	}
    }
    return 0;
}

typedef struct scan_cmd_info_s
{
    unsigned char addr;
    unsigned char channel;
} scan_cmd_info_t;

void scan_done(ipmi_domain_t *domain, int err, void *cb_data)
{
    log_pad_out("Bus scan done\n");
}

static void
scan_cmder(ipmi_domain_t *domain, void *cb_data)
{
    scan_cmd_info_t *info = cb_data;

    ipmi_start_ipmb_mc_scan(domain, info->channel,
			    info->addr, info->addr,
			    scan_done, NULL);
}

static int
scan_cmd(char *cmd, char **toks, void *cb_data)
{
    int             rv;
    scan_cmd_info_t info;

    if (get_uchar(toks, &info.channel, "channel"))
	return 0;

    if (get_uchar(toks, &info.addr, "IPMB address"))
	return 0;

    rv = ipmi_domain_pointer_cb(domain_id, scan_cmder, &info);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
    }
    return 0;
}

static void
presence_cmder(ipmi_domain_t *domain, void *cb_data)
{
    int rv;

    rv = ipmi_detect_domain_presence_changes(domain, 1);
    if (rv)
	cmd_win_out("domain presence detect error: %x\n", rv);
}

int
presence_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    rv = ipmi_domain_pointer_cb(domain_id, presence_cmder, NULL);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
	return 0;
    }
    
    return 0;
}

static void
is_con_active_cmder(ipmi_domain_t *domain, void *cb_data)
{
    int          rv;
    unsigned int *connection = cb_data;
    unsigned int val;

    rv = ipmi_domain_is_connection_active(domain, *connection, &val);
    if (rv)
	cmd_win_out("Invalid connection number %d: %x\n", *connection, rv);
    else
	cmd_win_out("Connection %d is%s active\n",
		    *connection, val ? "" : " not");
}

static int
is_con_active_cmd(char *cmd, char **toks, void *cb_data)
{
    int          rv;
    unsigned int connection;

    if (get_uint(toks, &connection, "connection"))
	return 0;

    rv = ipmi_domain_pointer_cb(domain_id, is_con_active_cmder, &connection);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
	return 0;
    }
    
    return 0;
}

static void
activate_con_cmder(ipmi_domain_t *domain, void *cb_data)
{
    int          rv;
    unsigned int *connection = cb_data;

    rv = ipmi_domain_activate_connection(domain, *connection);
    if (rv)
	cmd_win_out("Invalid connection number %d: %x\n", *connection, rv);
}

static int
activate_con_cmd(char *cmd, char **toks, void *cb_data)
{
    int          rv;
    unsigned int connection;

    if (get_uint(toks, &connection, "connection"))
	return 0;

    rv = ipmi_domain_pointer_cb(domain_id, activate_con_cmder, &connection);
    if (rv) {
	cmd_win_out("Unable to convert domain id to a pointer\n");
	return 0;
    }
    
    return 0;
}

static int
quit_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    rv = ipmi_domain_pointer_cb(domain_id, leave_cmder, NULL);
    if (rv) {
	leave(0, "");
    }
    return 0;
}

static int
display_win_cmd(char *cmd, char **toks, void *cb_data)
{
    curr_win = DISPLAY_WIN_SCROLL;
    return 0;
}

static int
log_win_cmd(char *cmd, char **toks, void *cb_data)
{
    curr_win = LOG_WIN_SCROLL;
    return 0;
}

static int
new_domain_cmd(char *cmd, char **toks, void *cb_data)
{
    char         *parms[30];
    int          num_parms;
    int          curr_parm;
    ipmi_args_t  *con_parms[2];
    int          set = 0;
    int          i;
    ipmi_con_t   *con[2];
    int          rv;

    for (num_parms=0; num_parms<30; num_parms++) {
	parms[num_parms] = strtok_r(NULL, " \t\n", toks);
	if (!parms[num_parms])
	    break;
	/* Remove surrounding quotes, if any. */
	if (parms[num_parms][0] == '"') {
	    (parms[num_parms])++;
	    if (parms[num_parms][0])
		parms[num_parms][strlen(parms[num_parms])-1] = '\0';
	}
    }

    if (num_parms < 2) {
	cmd_win_out("Not enough parms given\n");
	return 0;
    }

    curr_parm = 1;
    rv = ipmi_parse_args(&curr_parm, num_parms, parms, &con_parms[set]);
    if (rv) {
	cmd_win_out("First connection parms are invalid\n");
	return 0;
    }
    set++;

    if (curr_parm > num_parms) {
	rv = ipmi_parse_args(&curr_parm, num_parms, parms, &con_parms[set]);
	if (rv) {
	    ipmi_free_args(con_parms[0]);
	    cmd_win_out("Second connection parms are invalid\n");
	    goto out;
	}
	set++;
    }

    for (i=0; i<set; i++) {
	rv = ipmi_args_setup_con(con_parms[i],
				 &ipmi_ui_cb_handlers,
				 ui_sel,
				 &con[i]);
	if (rv) {
	    cmd_win_out("ipmi_ip_setup_con: %s\n", strerror(rv));
	    goto out;
	}
    }

    rv = ipmi_open_domain(parms[0], con, set, ipmi_ui_setup_done,
			  NULL, NULL, NULL, NULL, 0, NULL);
    if (rv) {
	cmd_win_out("ipmi_open_domain: %s\n", strerror(rv));
	for (i=0; i<set; i++)
	    con[i]->close_connection(con[i]);
	goto out;
    }

    cmd_win_out("Domain started\n");
 out:
    for (i=0; i<set; i++)
	ipmi_free_args(con_parms[i]);

    return 0;

}

static void
final_close(void *cb_data)
{
    ui_log("Domain close");
}

typedef struct domain_scan_s
{
    int  err;
    char *name;
} domain_scan_t;

static void
close_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    domain_scan_t *info = cb_data;
    char name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, name, sizeof(name));
    if (strcmp(name, info->name) == 0) {
	/* Found it. */
	info->err = ipmi_domain_close(domain, final_close, NULL);
	if (info->err)
	    cmd_win_out("Could not close connection\n");
    }
}


static int
close_domain_cmd(char *cmd, char **toks, void *cb_data)
{
    domain_scan_t info;

    info.err = ENODEV;
    info.name = strtok_r(NULL, " \t\n", toks);
    if (!info.name) {
	cmd_win_out("No domain given\n");
	return 0;
    }

    ipmi_domain_iterate_domains(close_domain_handler, &info);

    return 0;
}

static void
set_domain_handler(ipmi_domain_t *domain, void *cb_data)
{
    domain_scan_t *info = cb_data;
    char name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, name, sizeof(name));
    if (strcmp(name, info->name) == 0) {
	/* Found it. */
	info->err = 0;
	domain_id = ipmi_domain_convert_to_id(domain);
    }
}

static int
set_domain_cmd(char *cmd, char **toks, void *cb_data)
{
    domain_scan_t info;

    info.err = ENODEV;
    info.name = strtok_r(NULL, " \t\n", toks);
    if (!info.name) {
	cmd_win_out("No domain given\n");
	return 0;
    }

    ipmi_domain_iterate_domains(set_domain_handler, &info);
    if (info.err)
	cmd_win_out("Error setting domain: 0x%x\n", info.err);

    return 0;
}

static void
domains_handler(ipmi_domain_t *domain, void *cb_data)
{
    char name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, name, sizeof(name));
    display_pad_out("  %s\n", name);
}

static int
domains_cmd(char *cmd, char **toks, void *cb_data)
{
    display_pad_clear();
    display_pad_out("Domains:\n");
    ipmi_domain_iterate_domains(domains_handler, NULL);
    display_pad_refresh();
    
    return 0;
}

static int help_cmd(char *cmd, char **toks, void *cb_data);

static struct {
    char          *name;
    cmd_handler_t handler;
    char          *help;
} cmd_list[] =
{
    { "display_win",  display_win_cmd,
      " - Sets the display window (left window) for scrolling" },
    { "log_win",  log_win_cmd,
      " - Sets the log window (right window) for scrolling" },
    { "entities",	entities_cmd,
      " - list all the entities the UI knows about" },
    { "entity",         entity_cmd,
      " <entity name> - list all the info about an entity" },
    { "hs_get_act_time", hs_get_act_time,
      " <entity name>"
      " - Get the host-swap auto-activate time" },
    { "hs_set_act_time", hs_set_act_time,
      " <entity name> <time in nanoseconds>"
      " - Set the host-swap auto-activate time" },
    { "hs_get_deact_time", hs_get_deact_time,
      " <entity name>"
      " - Get the host-swap auto-deactivate time" },
    { "hs_set_deact_time", hs_set_deact_time,
      " <entity name> <time in nanoseconds>"
      " - Set the host-swap auto-deactivate time" },
    { "hs_activation_request", hs_activation_request,
      " <entity name> - Act like a user requested an activation of the"
      " entity.  This is generally equivalent to closing the handle"
      " latch or something like that." },
    { "hs_activate", hs_activate,
      " <entity name> - activate the given entity" },
    { "hs_deactivate", hs_deactivate,
      " <entity name> - deactivate the given entity" },
    { "hs_state", hs_state,
      " <entity name> - Return the current hot-swap state" },
    { "hs_check", hs_check_cmd,
      " - Check all the entities hot-swap states" },
    { "sensors",	sensors_cmd,
      " <entity name> - list all the sensors that monitor the entity" },
    { "sensor",		sensor_cmd,
      " <sensor name> - Pull up all the information on the sensor and start"
      " monitoring it" },
    { "fru",		fru_cmd,
      " <entity name> - dump fru information" },
    { "dump_fru",	dump_fru_cmd,
      " <is_logical> <device_address> <device_id> <lun> <private_bus>"
      "  <channel> - dump a fru given all it's insundry information" },
    { "rearm",		rearm_cmd,
      " - rearm the current sensor" },
    { "set_hysteresis",	set_hysteresis_cmd,
      " <val> - Sets the hysteresis for the current sensor" },
    { "get_hysteresis",	get_hysteresis_cmd,
      " - Gets the hysteresis for the current sensor" },
    { "controls",	controls_cmd,
      " <entity name> - list all the controls attached to the entity" },
    { "control",	control_cmd,
      " <control name> - Pull up all the information on the control and start"
      " monitoring it" },
    { "set_control",	set_control_cmd,
      " <val1> [<val2> ...] - set the value(s) for the control" },
    { "mcs",		mcs_cmd,
      " - List all the management controllers in the system.  They"
      " are listed (<channel>, <mc num>)" },
    { "mc",		mc_cmd,
      " <channel> <mc num>"
      " - Dump info on the given MC"},
    { "mc_reset",	mc_reset_cmd,
      " <channel> <mc num> [warm | cold]"
      " - Do a warm or cold reset on the given MC"},
    { "mccmd",		mccmd_cmd,
      " <channel> <mc num> <LUN> <NetFN> <Cmd> [data...]"
      " - Send the given command"
      " to the management controller and display the response" },
    { "mc_events_enable", mc_events_enable_cmd,
      " <channel> <mc num> <enabled> - set enabled to 0 to disable events,"
      " 1 to enable them.  This is the global event enable on the MC." },
    { "mc_events_enabled", mc_events_enabled_cmd,
      " <channel> <mc num> - Prints out if the events are enabled for"
      " the given MC." },
    { "msg",		msg_cmd,
      " <channel> <IPMB addr> <LUN> <NetFN> <Cmd> [data...] - Send a command"
      " to the given IPMB address on the given channel and display the"
      " response" },
    { "readpef",	readpef_cmd,
      " <channel> <mc num>"
      " - read pef information from an MC" },
    { "clearpeflock",	clearpeflock_cmd,
      " [<channel> <mc num>]"
      " - Clear a PEF lock.  If the MC is given, then the PEF is directly"
      " cleared.  If not given, then the current PEF is cleared" },
    { "viewpef",	viewpef_cmd,
      " - show current pef information " },
    { "writepef",	writepef_cmd,
      " <channel> <mc num>"
      " - write the current PEF information to an MC" },
    { "setpef",		setpef_cmd,
      " <config> [<selector>] <value>"
      " - Set the given config item to the value.  The optional selector"
      " is used for items that take a selector" },
    { "readlanparm",	readlanparm_cmd,
      " <channel> <mc num> <channel>"
      " - read lanparm information from an MC" },
    { "viewlanparm",	viewlanparm_cmd,
      " - show current lanparm information " },
    { "writelanparm",	writelanparm_cmd,
      " <channel> <mc num> <channel>"
      " - write the current LANPARM information to an MC" },
    { "clearlanparmlock",	clearlanparmlock_cmd,
      " [<channel> <mc num> <channel>]"
      " - Clear a LANPARM lock.  If the MC is given, then the LANPARM is"
      " directly"
      " cleared.  If not given, then the current LANPARM is cleared" },
    { "setlanparm",	setlanparm_cmd,
      " <config> [<selector>] <value>"
      " - Set the given config item to the value.  The optional selector"
      " is used for items that take a selector" },
    { "pet",		pet_cmd,
      " <connection> <channel> <ip addr> <mac_addr> <eft selector>"
      " <policy num> <apt selector>"
      " <lan dest selector> - "
      "Set up the domain to send PET traps from the given connection"
      " to the given IP/MAC address over the given channel" },
    { "delevent",	delevent_cmd,
      " <channel> <mc num> <log number> - "
      "Delete the given event number from the SEL" },
    { "addevent",	addevent_cmd,
      " <channel> <mc num> <record id> <type> <13 bytes of data> - "
      "Add the event data to the SEL" },
    { "debug",		debug_cmd,
      " <type> on|off - Turn the given debugging type on or off." },
    { "clear_sel",	clear_sel_cmd,
      " - clear the system event log" },
    { "list_sel",	list_sel_cmd,
      " - list the local copy of the system event log" },
    { "get_sel_time",	get_sel_time_cmd,
      " <channel> <mc num> - Get the time in the SEL for the given MC" },
    { "sdrs",		sdrs_cmd,
      " <channel> <mc num> <do_sensors> - list the SDRs for the mc."
      "  If do_sensors is"
      " 1, then the device SDRs are fetched.  Otherwise the main SDRs are"
      " fetched." },
    { "events_enable",  events_enable_cmd,
      " <events> <scanning> <assertion bitmask> <deassertion bitmask>"
      " - set the events enable data for the sensor" },
    { "scan",  scan_cmd,
      " <ipmb addr> - scan an IPMB to add or remove it" },
    { "is_con_active",  is_con_active_cmd,
      " <connection> - print out if the given connection is active or not" },
    { "activate_con",  activate_con_cmd,
      " <connection> - Activate the given connection" },
    { "quit",  quit_cmd,
      " - leave the program" },
    { "check_presence", presence_cmd,
      " - Check the presence of entities" },
    { "new_domain", new_domain_cmd,
      " <domain name> <parms...> - Open a connection to a new domain" },
    { "close_domain", close_domain_cmd,
      " <num> - close the given domain number" },
    { "set_domain", set_domain_cmd,
      " <num> - Use the given domain number" },
    { "domains", domains_cmd,
      " - List all the domains" },
    { "help",		help_cmd,
      " - This output"},
    { NULL,		NULL}
};
int
init_commands(void)
{
    int err;
    int i;

    commands = command_alloc();
    if (!commands)
	return ENOMEM;

    for (i=0; cmd_list[i].name != NULL; i++) {
	err = command_bind(commands, cmd_list[i].name, cmd_list[i].handler);
	if (err)
	    goto out_err;
    }

    return 0;

 out_err:
    command_free(commands);
    return err;
}

static int
help_cmd(char *cmd, char **toks, void *cb_data)
{
    int i;

    display_pad_clear();
    curr_display_type = HELP;
    display_pad_out("Welcome to the IPMI UI version %s\n", OPENIPMI_VERSION);
    for (i=0; cmd_list[i].name != NULL; i++) {
	display_pad_out("  %s%s\n", cmd_list[i].name, cmd_list[i].help);
    }
    display_pad_refresh();

    return 0;
}

int
init_keypad(void)
{
    int i;
    int err = 0;

    keymap = keypad_alloc();
    if (!keymap)
	return ENOMEM;

    for (i=0x20; i<0x7f; i++) {
	err = keypad_bind_key(keymap, i, normal_char);
	if (err)
	    goto out_err;
    }

    err = keypad_bind_key(keymap, 0x7f, backspace);
    if (!err)
      err = keypad_bind_key(keymap, 9, normal_char);
    if (!err)
      err = keypad_bind_key(keymap, 8, backspace);
    if (!err)
	err = keypad_bind_key(keymap, 4, key_leave);
    if (!err)
	err = keypad_bind_key(keymap, 10, end_of_line);
    if (!err)
	err = keypad_bind_key(keymap, 13, end_of_line);
    if (full_screen) {
	if (!err)
	    err = keypad_bind_key(keymap, KEY_BACKSPACE, backspace);
	if (!err)
	    err = keypad_bind_key(keymap, KEY_DC, backspace);
	if (!err)
	    err = keypad_bind_key(keymap, KEY_UP, key_up);
	if (!err)
	    err = keypad_bind_key(keymap, KEY_DOWN, key_down);
	if (!err)
	    err = keypad_bind_key(keymap, KEY_RIGHT, key_right);
	if (!err)
	    err = keypad_bind_key(keymap, KEY_LEFT, key_left);
	if (!err)
	    err = keypad_bind_key(keymap, KEY_NPAGE, key_npage);
	if (!err)
	    err = keypad_bind_key(keymap, KEY_PPAGE, key_ppage);
	if (!err)
	    err = keypad_bind_key(keymap, KEY_RESIZE, key_resize);
	if (!err)
	    err = keypad_bind_key(keymap, KEY_F(1), key_set_display);
	if (!err)
	    err = keypad_bind_key(keymap, KEY_F(2), key_set_log);
    } else {
	if (!err)
	    err = keypad_bind_key(keymap, -1, key_leave);
    }
    if (err)
	goto out_err;

    return 0;

 out_err:
    keypad_free(keymap);
    return err;
}

int
init_win(void)
{
    main_win = initscr();
    if (!main_win)
	exit(1);

    raw();
    noecho();

    stat_win = newwin(STATUS_WIN_LINES, STATUS_WIN_COLS,
		      STATUS_WIN_TOP, STATUS_WIN_LEFT);
    if (!stat_win)
	leave(1, "Could not allocate stat window\n");

    display_pad = newpad(NUM_DISPLAY_LINES, DISPLAY_WIN_COLS);
    if (!display_pad)
	leave(1, "Could not allocate display window\n");

    log_pad = newpad(NUM_LOG_LINES, LOG_WIN_COLS);
    if (!log_pad)
	leave(1, "Could not allocate log window\n");
    scrollok(log_pad, TRUE);
    wmove(log_pad, NUM_LOG_LINES-1, 0);
    log_pad_top_line = NUM_LOG_LINES-LOG_WIN_LINES;

    dummy_pad = newpad(NUM_LOG_LINES, LOG_WIN_COLS);
    if (!dummy_pad)
	leave(1, "Could not allocate dummy pad\n");
    wmove(dummy_pad, 0, 0);

    cmd_win = newwin(CMD_WIN_LINES, CMD_WIN_COLS, CMD_WIN_TOP, CMD_WIN_LEFT);
    if (!cmd_win)
	leave(1, "Could not allocate command window\n");

    keypad(cmd_win, TRUE);
    meta(cmd_win, TRUE);
    nodelay(cmd_win, TRUE);
    scrollok(cmd_win, TRUE);

    draw_lines();

    display_pad_refresh();

    cmd_win_out("> ");
    cmd_win_refresh();

    return 0;
}

static void
report_error(char *str, int err)
{
    if (IPMI_IS_OS_ERR(err)) {
	ui_log("%s: %s\n", str, strerror(IPMI_GET_OS_ERR(err)));
    } else {
	ui_log("%s: IPMI Error %2.2x\n",
	       str, IPMI_GET_IPMI_ERR(err));
    }
}

static int
sensor_threshold_event_handler(ipmi_sensor_t               *sensor,
			       enum ipmi_event_dir_e       dir,
			       enum ipmi_thresh_e          threshold,
			       enum ipmi_event_value_dir_e high_low,
			       enum ipmi_value_present_e   value_present,
			       unsigned int                raw_value,
			       double                      value,
			       void                        *cb_data,
			       ipmi_event_t                *event)
{
    ipmi_entity_t *entity = ipmi_sensor_get_entity(sensor);
    char          loc[MAX_ENTITY_LOC_SIZE];
    char          name[33];

    ipmi_sensor_get_id(sensor, name, 33);
    ui_log("Sensor %s.%s: %s %s %s\n",
	   get_entity_loc(entity, loc, sizeof(loc)),
	   name,
	   ipmi_get_threshold_string(threshold),
	   ipmi_get_value_dir_string(high_low),
	   ipmi_get_event_dir_string(dir));
    if (value_present == IPMI_BOTH_VALUES_PRESENT) {
	ui_log("  value is %f (%2.2x)\n", value, raw_value);
    } else if (value_present == IPMI_RAW_VALUE_PRESENT) {
	ui_log("  raw value is 0x%x\n", raw_value);
    }
    if (event)
	ui_log("Due to event 0x%4.4x\n", ipmi_event_get_record_id(event));
    return IPMI_EVENT_NOT_HANDLED;
}

static int
sensor_discrete_event_handler(ipmi_sensor_t         *sensor,
			      enum ipmi_event_dir_e dir,
			      int                   offset,
			      int                   severity,
			      int                   prev_severity,
			      void                  *cb_data,
			      ipmi_event_t          *event)
{
    ipmi_entity_t *entity = ipmi_sensor_get_entity(sensor);
    char          loc[MAX_ENTITY_LOC_SIZE];
    char          name[33];

    ipmi_sensor_get_id(sensor, name, 33);
    ui_log("Sensor %s.%s: %d %s\n",
	   get_entity_loc(entity, loc, sizeof(loc)),
	   name,
	   offset,
	   ipmi_get_event_dir_string(dir));
    if (severity != -1)
	ui_log("  severity is %d\n", severity);
    if (prev_severity != -1)
	ui_log("  prev severity is %d\n", prev_severity);
    if (event)
	ui_log("Due to event 0x%4.4x\n", ipmi_event_get_record_id(event));
    return IPMI_EVENT_NOT_HANDLED;
}

static void
sensor_change(enum ipmi_update_e op,
	      ipmi_entity_t      *ent,
	      ipmi_sensor_t      *sensor,
	      void               *cb_data)
{
    ipmi_entity_t *entity = ipmi_sensor_get_entity(sensor);
    char          loc[MAX_ENTITY_LOC_SIZE];
    char          name[33];
    char          name2[33];
    int           rv;

    ipmi_sensor_get_id(sensor, name, 32);
    strcpy(name2, name);
    conv_from_spaces(name2);
    switch (op) {
	case IPMI_ADDED:
	    ui_log("Sensor added: %s.%s (%s)\n",
		   get_entity_loc(entity, loc, sizeof(loc)),
		   name2, name);
	    if (ipmi_sensor_get_event_reading_type(sensor)
		== IPMI_EVENT_READING_TYPE_THRESHOLD)
		rv = ipmi_sensor_add_threshold_event_handler(
		    sensor,
		    sensor_threshold_event_handler,
		    NULL);
	    else
		rv = ipmi_sensor_add_discrete_event_handler(
		    sensor,
		    sensor_discrete_event_handler,
		    NULL);
	    if (rv)
		ui_log("Unable to register sensor event handler: 0x%x\n", rv);
	    break;
	case IPMI_DELETED:
	    ui_log("Sensor deleted: %s.%s (%s)\n",
		   get_entity_loc(entity, loc, sizeof(loc)),
		   name2, name);
	    break;
	case IPMI_CHANGED:
	    ui_log("Sensor changed: %s.%s (%s)\n",
		   get_entity_loc(entity, loc, sizeof(loc)),
		   name2, name);
	    break;
    }
}

static void
control_change(enum ipmi_update_e op,
	       ipmi_entity_t      *ent,
	       ipmi_control_t     *control,
	       void               *cb_data)
{
    ipmi_entity_t *entity = ipmi_control_get_entity(control);
    char          loc[MAX_ENTITY_LOC_SIZE];
    char          name[33];
    char          name2[33];

    ipmi_control_get_id(control, name, 32);
    strcpy(name2, name);
    conv_from_spaces(name2);
    switch (op) {
	case IPMI_ADDED:
	    ui_log("Control added: %s.%s (%s)\n",
		   get_entity_loc(entity, loc, sizeof(loc)),
		   name2, name);
	    break;
	case IPMI_DELETED:
	    ui_log("Control deleted: %s.%s (%s)\n",
		   get_entity_loc(entity, loc, sizeof(loc)),
		   name2, name);
	    break;
	case IPMI_CHANGED:
	    ui_log("Control changed: %s.%s (%s)\n",
		   get_entity_loc(entity, loc, sizeof(loc)),
		   name2, name);
	    break;
    }
}

static int
entity_presence_handler(ipmi_entity_t *entity,
			int           present,
			void          *cb_data,
			ipmi_event_t  *event)
{
    char loc[MAX_ENTITY_LOC_SIZE];

    ui_log("Entity %s, presence is %d\n",
	   get_entity_loc(entity, loc, sizeof(loc)),
	   present);
    if (event)
	ui_log("Due to event 0x%4.4x\n", ipmi_event_get_record_id(event));
    return IPMI_EVENT_NOT_HANDLED;
}

void fru_change(enum ipmi_update_e op,
		ipmi_entity_t      *entity,
		void               *cb_data)
{
    char loc[MAX_ENTITY_LOC_SIZE];

    switch (op) {
	case IPMI_ADDED:
	    ui_log("FRU added for %s\n",
		   get_entity_loc(entity, loc, sizeof(loc)));
	    break;
	case IPMI_DELETED:
	    ui_log("FRU deleted for %s\n",
		   get_entity_loc(entity, loc, sizeof(loc)));
	    break;
	case IPMI_CHANGED:
	    ui_log("FRU changed for %s\n",
		   get_entity_loc(entity, loc, sizeof(loc)));
	    break;
    }
}

static int
entity_hot_swap_handler(ipmi_entity_t             *ent,
			enum ipmi_hot_swap_states last_state,
			enum ipmi_hot_swap_states curr_state,
			void                      *cb_data,
			ipmi_event_t              *event)
{
    char loc[MAX_ENTITY_LOC_SIZE];

    ui_log("Entity hot swap state changed for %s, was %s, now %s\n",
	   get_entity_loc(ent, loc, sizeof(loc)),
	   ipmi_hot_swap_state_name(last_state),
	   ipmi_hot_swap_state_name(curr_state));
    return IPMI_EVENT_NOT_HANDLED;
}

static void
entity_change(enum ipmi_update_e op,
	      ipmi_domain_t      *domain,
	      ipmi_entity_t      *entity,
	      void               *cb_data)
{
    int rv;
    char loc[MAX_ENTITY_LOC_SIZE];

    switch (op) {
	case IPMI_ADDED:
	    ui_log("Entity added: %s\n",
		   get_entity_loc(entity, loc, sizeof(loc)));
	    rv = ipmi_entity_add_sensor_update_handler(entity,
						       sensor_change,
						       entity);
	    if (rv) {
		report_error("ipmi_entity_add_sensor_update_handler", rv);
		break;
	    }
	    rv = ipmi_entity_add_control_update_handler(entity,
							control_change,
							entity);
	    if (rv) {
		report_error("ipmi_entity_add_control_update_handler", rv);
		break;
	    }
	    rv = ipmi_entity_add_fru_update_handler(entity,
						    fru_change,
						    entity);
	    if (rv) {
		report_error("ipmi_entity_add_control_fru_handler", rv);
		break;
	    }
	    rv = ipmi_entity_add_presence_handler(entity,
						  entity_presence_handler,
						  NULL);
	    if (rv) {
		report_error("ipmi_entity_add_presence_handler", rv);
	    }
	    rv = ipmi_entity_add_hot_swap_handler(entity,
						  entity_hot_swap_handler,
						  NULL);
	    if (rv) {
		report_error("ipmi_entity_add_hot_swap_handler", rv);
	    }
	    break;
	case IPMI_DELETED:
	    ui_log("Entity deleted: %s\n",
		   get_entity_loc(entity, loc, sizeof(loc)));
	    break;
	case IPMI_CHANGED:
	    ui_log("Entity changed: %s\n",
		   get_entity_loc(entity, loc, sizeof(loc)));
	    break;
    }

    if (ipmi_entity_hot_swappable(entity))
	ui_log("Entity is hot swappable\n");
    else
	ui_log("Entity is not hot swappable\n");
}

static void
mc_sels_read(ipmi_mc_t *mc, void *cb_data)
{
    int addr = ipmi_mc_get_address(mc);
    int channel = ipmi_mc_get_channel(mc);

    ui_log("MC (%d %x) SELs read\n", channel, addr);
}

static void
mc_sdrs_read(ipmi_mc_t *mc, void *cb_data)
{
    int addr = ipmi_mc_get_address(mc);
    int channel = ipmi_mc_get_channel(mc);

    ui_log("MC (%d %x) SDRs read\n", channel, addr);
}

static void
mc_active(ipmi_mc_t *mc, int active, void *cb_data)
{
    int addr = ipmi_mc_get_address(mc);
    int channel = ipmi_mc_get_channel(mc);

    ui_log("MC is %s: (%d %x)\n",
	   active ? "active" : "inactive",
	   channel, addr);
    ipmi_mc_set_sdrs_first_read_handler(mc, mc_sdrs_read, NULL);
    ipmi_mc_set_sels_first_read_handler(mc, mc_sels_read, NULL);
}

static void
mc_change(enum ipmi_update_e op,
	  ipmi_domain_t      *domain,
	  ipmi_mc_t          *mc,
	  void               *cb_data)
{
    int addr = ipmi_mc_get_address(mc);
    int channel = ipmi_mc_get_channel(mc);
    int rv;

    switch (op) {
	case IPMI_ADDED:
	    rv = ipmi_mc_add_active_handler(mc, mc_active, NULL);
	    if (rv)
		ui_log("Unable to add MC active handler: 0x%x\n", rv);
	    if (ipmi_mc_is_active(mc)) {
		ipmi_mc_set_sdrs_first_read_handler(mc, mc_sdrs_read, NULL);
		ipmi_mc_set_sels_first_read_handler(mc, mc_sels_read, NULL);
		ui_log("MC added: (%d %x) - (active)\n", channel, addr);
	    } else {
		ui_log("MC added: (%d %x) - (inactive)\n", channel, addr);
	    }
	    break;
	case IPMI_DELETED:
	    ui_log("MC deleted: (%d %x)\n", channel, addr);
	    break;
	case IPMI_CHANGED:
	    ui_log("MC changed: (%d %x)\n", channel, addr);
	    break;
    }
}

static void
event_handler(ipmi_domain_t *domain,
	      ipmi_event_t  *event,
	      void          *event_data)
{
    ipmi_mcid_t         mcid = ipmi_event_get_mcid(event);
    unsigned int        record_id = ipmi_event_get_record_id(event);
    unsigned int        type = ipmi_event_get_type(event);
    ipmi_time_t         timestamp = ipmi_event_get_timestamp(event);
    unsigned int        data_len = ipmi_event_get_data_len(event);
    const unsigned char *data = ipmi_event_get_data_ptr(event);
    unsigned int        i;
    char                str[200];
    int                 pos;

    pos = 0;
    for (i=0; i<data_len; i++)
	pos += snprintf(str+pos, 200-pos, " %2.2x", data[i]);

    ui_log("Unknown event from mc (%x %x)\n"
	   "%4.4x:%2.2x %lld: %s\n",
	   mcid.channel, mcid.mc_num, record_id, type, (int64_t) timestamp,
	   str); 
}

static void
redisplay_timeout(selector_t  *sel,
		  sel_timer_t *timer,
		  void        *data)
{
    struct timeval now;
    int            rv;

    if (!full_screen)
	return;

    if (curr_display_type == DISPLAY_ENTITIES) {
	rv = ipmi_domain_pointer_cb(domain_id, entities_cmder, &rv);
	if (rv)
	    ui_log("redisplay_timeout:"
		   " Unable to convert BMC id to a pointer\n");
    } else if (curr_display_type == DISPLAY_SENSOR) {
	rv = ipmi_sensor_pointer_cb(curr_sensor_id, redisplay_sensor, NULL);
	if (rv)
	    ui_log("redisplay_timeout: Unable to get sensor pointer: 0x%x\n",
		   rv);
    } else if (curr_display_type == DISPLAY_CONTROL) {
	rv = ipmi_control_pointer_cb(curr_control_id, redisplay_control, NULL);
	if (rv)
	    ui_log("redisplay_timeout: Unable to get sensor pointer: 0x%x\n",
		   rv);
    }

    gettimeofday(&now, NULL);
    now.tv_sec += 1;
    rv = sel_start_timer(timer, &now);
    if (rv)
	ui_log("Unable to restart redisplay timer: 0x%x\n", rv);
}

void
ipmi_ui_setup_done(ipmi_domain_t *domain,
		   int           err,
		   unsigned int  conn_num,
		   unsigned int  port_num,
		   int           still_connected,
		   void          *cb_data)
{
    int rv;

    if (err)
	ui_log("IPMI connection to con.port %d.%d is down"
	       "  due to error 0x%x\n",
	       conn_num, port_num, err);
    else
	ui_log("IPMI connection to con.port %d.%d is up\n",
	       conn_num, port_num);

    if (!still_connected) {
	ui_log("All IPMI connections down\n");
	return;
    }

    domain_id = ipmi_domain_convert_to_id(domain);

    rv = ipmi_domain_add_event_handler(domain, event_handler, NULL);
    if (rv)
	leave_err(rv, "ipmi_register_for_events");

    rv = ipmi_domain_enable_events(domain);
    if (rv)
	leave_err(rv, "ipmi_domain_enable_events");

    rv = ipmi_domain_add_entity_update_handler(domain, entity_change, domain);
    if (rv)
	leave_err(rv, "ipmi_bmc_set_entity_update_handler");

    rv = ipmi_domain_add_mc_updated_handler(domain, mc_change, domain);
    if (rv)
	leave_err(rv, "ipmi_bmc_set_entity_update_handler");
    pef = NULL;
    lanparm = NULL;
}

void
ipmi_ui_domain_ready(ipmi_domain_t *domain,
		     int           err,
		     unsigned int  conn_num,
		     unsigned int  port_num,
		     int           still_connected,
		     void          *user_data)
{
}

int
ipmi_ui_init(selector_t **selector, int do_full_screen)
{
    int rv;

    full_screen = do_full_screen;

    ipmi_init(&ipmi_ui_cb_handlers);

    rv = sel_alloc_selector(&ipmi_ui_cb_handlers, &ui_sel);
    if (rv) {
	fprintf(stderr, "Could not allocate selector\n");
	exit(1);
    }

    sel_set_fd_handlers(ui_sel, 0, NULL, user_input_ready, NULL, NULL, NULL);
    sel_set_fd_read_handler(ui_sel, 0, SEL_FD_HANDLER_ENABLED);

    /* This is a dummy allocation just to make sure that the malloc
       debugger is working. */
    ipmi_mem_alloc(10);

    sensor_states = ipmi_mem_alloc(ipmi_states_size());
    if (!sensor_states) {
	fprintf(stderr, "Could not allocate sensor states\n");
	exit(1);
    }

    sensor_event_states = ipmi_mem_alloc(ipmi_event_state_size());
    if (!sensor_event_states) {
	fprintf(stderr, "Could not allocate sensor event states\n");
	exit(1);
    }

    sensor_thresholds = ipmi_mem_alloc(ipmi_thresholds_size());
    if (!sensor_thresholds) {
	fprintf(stderr, "Could not allocate sensor thresholds\n");
	exit(1);
    }

    rv = init_commands();
    if (rv) {
	fprintf(stderr, "Could not initialize commands\n");
	exit(1);
    }

    rv = init_keypad();
    if (rv) {
	fprintf(stderr, "Could not initialize keymap\n");
	exit(1);
    }

    if (full_screen) {
	rv = init_win();
	if (rv) {
	    fprintf(stderr, "Could not initialize curses\n");
	    exit(1);
	}
    } else {
	struct termios new_termios;

	tcgetattr(0, &old_termios);
	new_termios = old_termios;
	new_termios.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
			         |INLCR|IGNCR|ICRNL|IXON);
	new_termios.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	tcsetattr(0, TCSADRAIN, &new_termios);
	old_flags = fcntl(0, F_GETFL) & O_ACCMODE;
//	fcntl(0, F_SETFL, old_flags | O_NONBLOCK);
    }

    help_cmd(NULL, NULL, NULL);

    ui_log("Starting setup, wait until complete before entering commands.\n");

    {
	struct timeval now;
	rv = sel_alloc_timer(ui_sel, redisplay_timeout, NULL,
			     &redisplay_timer);
	if (rv)
	    leave_err(rv, "sel_alloc_timer");
	gettimeofday(&now, NULL);
	now.tv_sec += 1;
	rv = sel_start_timer(redisplay_timer, &now);
	if (rv)
	    leave_err(rv, "Unable to restart redisplay timer");
    }

    *selector = ui_sel;

    return 0;
}

void
ipmi_ui_shutdown(void)
{
    ipmi_mem_free(sensor_states);
    sensor_states = NULL;
    ipmi_mem_free(sensor_event_states);
    sensor_event_states = NULL;
    ipmi_mem_free(sensor_thresholds);
    sensor_thresholds = NULL;
    leave(0, "");
}
