/*
 * ui.c
 *
 * MontaVista IPMI code, a simple curses UI for IPMI
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curses.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_ui.h>

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

int bmc_ready = 0;
ipmi_mc_id_t bmc_id;

extern os_handler_t ipmi_ui_cb_handlers;

static int full_screen;
struct termios old_termios;

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
    DISPLAY_RSP, DISPLAY_SDRS, HELP, EVENTS
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
vlog_pad_out(char *format, va_list ap)
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
ui_vlog(char *format, enum ipmi_log_type_e log_type, va_list ap)
{
    int do_nl = 1;

    if (full_screen) {
	int x = 0, y = 0, old_x = 0, old_y = 0;
	int max_x, max_y, i, j;

	/* Generate the output to the dummy pad to see how many lines we
	   will use. */
	getyx(dummy_pad, old_y, old_x);
	switch(log_type)
	{
	    case IPMI_LOG_INFO:
		wprintw(dummy_pad, "INFO: ");
		break;

	    case IPMI_LOG_WARNING:
		wprintw(dummy_pad, "WARN: ");
		break;

	    case IPMI_LOG_SEVERE:
		wprintw(dummy_pad, "SEVR: ");
		break;

	    case IPMI_LOG_FATAL:
		wprintw(dummy_pad, "FATL: ");
		break;

	    case IPMI_LOG_ERR_INFO:
		wprintw(dummy_pad, "EINF: ");
		break;

	    case IPMI_LOG_DEBUG_START:
		do_nl = 0;
		/* FALLTHROUGH */
	    case IPMI_LOG_DEBUG:
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
		log_pad_out("INFO: ");
		break;

	    case IPMI_LOG_WARNING:
		log_pad_out("WARN: ");
		break;

	    case IPMI_LOG_SEVERE:
		log_pad_out("SEVR: ");
		break;

	    case IPMI_LOG_FATAL:
		log_pad_out("FATL: ");
		break;

	    case IPMI_LOG_ERR_INFO:
		log_pad_out("EINF: ");
		break;

	    case IPMI_LOG_DEBUG_START:
		do_nl = 0;
		/* FALLTHROUGH */
	    case IPMI_LOG_DEBUG:
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
    va_list ap;

    va_start(ap, format);

    if (full_screen) {
	/* Generate the output to the dummy pad to see how many lines we
	   will use. */
	vw_printw(dummy_pad, format, ap);
	getyx(dummy_pad, y, x);
	wmove(dummy_pad, 0, x);
	va_end(ap);
	va_start(ap, format);
    }

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
    }
    else
	tcsetattr(0, 0, &old_termios);

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
	while (count > 0) {
	    handle_user_char(rc);
	    count = read(0, &rc, 1);
	}
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
	    strcpy(new_line, line_buffer);
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

static void
final_leave(void *cb_data)
{
    leave(0, "");
}

static void
leave_cmd_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    int rv;

    rv = ipmi_close_connection(bmc, final_leave, NULL);
    if (rv)
	leave(0, "");
}

static int
key_leave(int key, void *cb_data)
{
    int rv;

    if (!bmc_ready) {
	leave(0, "");
    }

    rv = ipmi_mc_pointer_cb(bmc_id, leave_cmd_bmcer, NULL);
    if (rv) {
	leave(0, "");
    }
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

static void
entities_handler(ipmi_entity_t *entity,
		 void          *cb_data)
{
    int  id, instance;
    char *present;
    char name[33];

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    curr_entity_id = ipmi_entity_convert_to_id(entity);
    ipmi_entity_get_id(entity, name, 32);
    if (ipmi_entity_is_present(entity))
	present = "present";
    else
	present = "not present";
    display_pad_out("  %d.%d (%s) %s\n", id, instance, name, present);
}

static void
entities_cmd_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    display_pad_clear();
    display_pad_out("Entities:\n");
    ipmi_bmc_iterate_entities(bmc, entities_handler, NULL);
    display_pad_refresh();
}

static int
entities_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    if (!bmc_ready) {
	cmd_win_out("BMC has not finished setup yet\n");
	return 0;
    }

    rv = ipmi_mc_pointer_cb(bmc_id, entities_cmd_bmcer, NULL);
    if (rv) {
	cmd_win_out("Unable to convert BMC id to a pointer\n");
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
    entity_handler_cb handler;
    char **toks, **toks2;
    void *cb_data;
};

static void
entity_searcher(ipmi_entity_t *entity,
		void          *cb_data)
{
    struct ent_rec *info = cb_data;
    int    id, instance;

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    if ((info->id == id) && (info->instance == instance)) {
	info->found = 1;
	info->handler(entity, info->toks, info->toks2, info->cb_data);
    }
}

static void
entity_finder_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    ipmi_bmc_iterate_entities(bmc, entity_searcher, cb_data);
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

    if (!bmc_ready) {
	cmd_win_out("BMC has not finished setup yet\n");
	return EAGAIN;
    }

    ent_name = strtok_r(NULL, " \t\n", toks);
    if (!ent_name) {
	cmd_win_out("No entity given\n");
	return EINVAL;
    }

    id_name = strtok_r(ent_name, ".", &toks2);
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
    info.found = 0;

    info.handler = handler;
    info.cb_data = cb_data;
    info.toks = toks;
    info.toks2 = &toks2;

    rv = ipmi_mc_pointer_cb(bmc_id, entity_finder_bmcer, &info);
    if (!info.found) {
	cmd_win_out("Entity %d.%d not found\n", info.id, info.instance);
	return EINVAL;
    }

    return 0;
}

static void
sensors_handler(ipmi_entity_t *entity, ipmi_sensor_t *sensor, void *cb_data)
{
    int id, instance;
    char name[33];
    char name2[33];

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    ipmi_sensor_get_id(sensor, name, 33);
    strcpy(name2, name);
    conv_from_spaces(name2);
    display_pad_out("  %d.%d.%s - %s\n", id, instance, name2, name);
}

static void
found_entity_for_sensors(ipmi_entity_t *entity,
			 char          **toks,
			 char          **toks2,
			 void          *cb_data)
{
    int id, instance;

    curr_display_type = DISPLAY_SENSORS;
    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    display_pad_clear();
    display_pad_out("Sensors for entity %d.%d:\n", id, instance);
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
ipmi_states_t sensor_states;

/* Values from ipmi_sensor_event_enables_get. */
int                sensor_event_states_err;
ipmi_event_state_t sensor_event_states;

/* Values from ipmi_thresholds_get */
int               sensor_read_thresh_err;
ipmi_thresholds_t sensor_thresholds;

static void
display_sensor(ipmi_entity_t *entity, ipmi_sensor_t *sensor)
{
    int  id, instance;
    char name[33];
    int  rv;

    if (sensor_displayed)
	return;

    sensor_ops_to_read_count--;
    if (sensor_ops_to_read_count > 0)
	return;

    sensor_displayed = 1;

    ipmi_sensor_get_id(sensor, name, 33);
    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);

    display_pad_clear();

    conv_from_spaces(name);
    display_pad_out("Sensor %d.%d.%s:\n",
		    id, instance, name);
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
		display_pad_out("%f", sensor_val);
	    else if (sensor_value_present == IPMI_RAW_VALUE_PRESENT)
		display_pad_out("0x%x (RAW)", sensor_raw_val);
	    else
		display_pad_out("unreadable");
	} else {
	    int i;
	    for (i=0; i<15; i++) {
		int val;
		val = ipmi_is_state_set(&sensor_states, i);
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
	global_enable = ipmi_event_state_get_events_enabled(
	    &sensor_event_states);
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
	scanning_enable = ipmi_event_state_get_scanning_enabled(
	    &sensor_event_states);
	if (scanning_enable)
	    display_pad_out("enabled");
	else
	    display_pad_out("disabled");
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
	for (t=IPMI_LOWER_NON_CRITICAL; t<IPMI_UPPER_NON_RECOVERABLE; t++){
	    int settable, readable;
	    int i;
	    int assert_sup[2], deassert_sup[2];
	    int anything_set = 0;
	    
	    ipmi_sensor_threshold_settable(sensor, t, &settable);
	    anything_set |= settable;
	    ipmi_sensor_threshold_readable(sensor, t, &readable);
	    anything_set |= readable;
	    for (i=0; i<=1; i++) {
		ipmi_sensor_threshold_assertion_event_supported(
		    sensor, t, i, &(assert_sup[i]));
		anything_set |= assert_sup[i];
		ipmi_sensor_threshold_deassertion_event_supported(
		    sensor, t, i, &(deassert_sup[i]));
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
		    if (ipmi_is_threshold_event_set(&sensor_event_states, t,
						    IPMI_GOING_LOW,
						    IPMI_ASSERTION))
			display_pad_out("L^");
		    else
			display_pad_out("  ");
		    if (ipmi_is_threshold_event_set(&sensor_event_states, t,
						    IPMI_GOING_LOW,
						    IPMI_DEASSERTION))
			display_pad_out("Lv");
		    else
			display_pad_out("  ");
		    if (ipmi_is_threshold_event_set(&sensor_event_states, t,
						    IPMI_GOING_HIGH,
						    IPMI_ASSERTION))
			display_pad_out("H^");
		    else
			display_pad_out("  ");
		    if (ipmi_is_threshold_event_set(&sensor_event_states, t,
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
		    rv = ipmi_threshold_get(&sensor_thresholds, t, &val);
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
		    if (ipmi_is_threshold_out_of_range(&sensor_states, t))
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
	    ipmi_sensor_discrete_assertion_event_supported(sensor,
							   i,
							   &val);
	    display_pad_out("%d", val != 0);
	}
	display_pad_out("\n      enabled: ");
	getyx(display_pad, discr_assert_enab.y, discr_assert_enab.x);
	if (sensor_event_states_err)
	    display_pad_out("?");
	else {
	    for (i=0; i<15; i++) {
		val = ipmi_is_discrete_event_set(&sensor_event_states,
						 i, IPMI_ASSERTION);
		display_pad_out("%d", val != 0);
	    }
	}   

	display_pad_out("\n  Deasertion: ");
	display_pad_out("\n    available: ");
	for (i=0; i<15; i++) {
	    ipmi_sensor_discrete_deassertion_event_supported(sensor,
							     i,
							     &val);
	    display_pad_out("%d", val != 0);
	}
	display_pad_out("\n      enabled: ");
	getyx(display_pad, discr_deassert_enab.y, discr_deassert_enab.x);
	if (sensor_event_states_err)
	    display_pad_out("?");
	else {
	    for (i=0; i<15; i++) {
		val = ipmi_is_discrete_event_set(&sensor_event_states,
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

    sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!((curr_display_type == DISPLAY_SENSOR)
	  && (ipmi_cmp_sensor_id(sensor_id, curr_sensor_id) == 0)))
	return;

    if (sensor_displayed) {
	wmove(display_pad, value_pos.y, value_pos.x);
	if (err) {
	    display_pad_out("unreadable");
	    display_pad_refresh();
	    return;
	}

	if (value_present == IPMI_BOTH_VALUES_PRESENT)
	    display_pad_out("%f", val);
	else if (value_present == IPMI_RAW_VALUE_PRESENT)
	    display_pad_out("0x%x (RAW)", raw_val);
	else
	    display_pad_out("unreadable");

	for (t=IPMI_LOWER_NON_CRITICAL; t<IPMI_UPPER_NON_RECOVERABLE; t++) {
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
	    ipmi_copy_states(&sensor_states, states);
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
	    for (t=IPMI_LOWER_NON_CRITICAL; t<IPMI_UPPER_NON_RECOVERABLE; t++)
	    {
		if (threshold_positions[t].set) {
		    wmove(display_pad,
			  threshold_positions[t].value.y,
			  threshold_positions[t].value.x);
		    display_pad_out("?");
		}
	    }    
	} else {
	    for (t=IPMI_LOWER_NON_CRITICAL; t<IPMI_UPPER_NON_RECOVERABLE; t++) {
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
	    ipmi_copy_thresholds(&sensor_thresholds, th);
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

	for (t=IPMI_LOWER_NON_CRITICAL; t<IPMI_UPPER_NON_RECOVERABLE; t++) {
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
	    ipmi_copy_event_state(&sensor_event_states, states);
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
	    ipmi_copy_event_state(&sensor_event_states, states);
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
	    ipmi_copy_states(&sensor_states, states);
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
	rv = ipmi_reading_get(sensor, read_sensor, NULL);
	if (rv)
	    ui_log("redisplay_sensor: Unable to get sensor reading: 0x%x\n",
		   rv);

	if (ipmi_sensor_get_threshold_access(sensor)
	    != IPMI_THRESHOLD_ACCESS_SUPPORT_NONE)
	{
	    rv = ipmi_thresholds_get(sensor, read_thresholds, NULL);
	    if (rv)
		ui_log("Unable to get threshold values: 0x%x\n", rv);
	}

	if (ipmi_sensor_get_event_support(sensor) != IPMI_EVENT_SUPPORT_NONE) {
	    rv = ipmi_sensor_events_enable_get(sensor,
					       read_thresh_event_enables,
					       NULL);
	    if (rv)
		ui_log("Unable to get event values: 0x%x\n", rv);
	}
    } else {
	rv = ipmi_states_get(sensor, read_states, NULL);
	if (rv)
	    ui_log("Unable to get sensor reading: 0x%x\n", rv);
	
	if (ipmi_sensor_get_event_support(sensor) != IPMI_EVENT_SUPPORT_NONE) {
	    rv = ipmi_sensor_events_enable_get(sensor,
					       read_discrete_event_enables,
					       NULL);
	    if (rv)
		ui_log("Unable to get event values: 0x%x\n", rv);
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
		rv = ipmi_reading_get(sensor, read_sensor, NULL);
		if (rv)
		    ui_log("Unable to get sensor reading: 0x%x\n", rv);

		if (ipmi_sensor_get_threshold_access(sensor)
		    != IPMI_THRESHOLD_ACCESS_SUPPORT_NONE)
		{
		    sensor_ops_to_read_count++;
		    rv = ipmi_thresholds_get(sensor, read_thresholds, NULL);
		    if (rv)
			ui_log("Unable to get threshold values: 0x%x\n", rv);
		}
	    
		if (ipmi_sensor_get_event_support(sensor)
		    != IPMI_EVENT_SUPPORT_NONE)
		{
		    sensor_ops_to_read_count++;
		    rv = ipmi_sensor_events_enable_get(
			sensor,
			read_thresh_event_enables,
			NULL);
		    if (rv)
			ui_log("Unable to get event values: 0x%x\n", rv);
		}
	    }
	} else {
	    if (present) {
		sensor_ops_to_read_count++;
		rv = ipmi_states_get(sensor, read_states, NULL);
		if (rv)
		    ui_log("Unable to get sensor reading: 0x%x\n", rv);

		if (ipmi_sensor_get_event_support(sensor)
		    != IPMI_EVENT_SUPPORT_NONE)
		{
		    sensor_ops_to_read_count++;
		    rv = ipmi_sensor_events_enable_get(
			sensor,
			read_discrete_event_enables,
			NULL);
		    if (rv)
			ui_log("Unable to get event values: 0x%x\n", rv);
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
	int id, instance;

	id = ipmi_entity_get_entity_id(entity);
	instance = ipmi_entity_get_entity_instance(entity);

	conv_from_spaces(sinfo.name);
	cmd_win_out("Sensor %d.%d.%s not found\n",
		id, instance, sinfo.name);
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

    rv = ipmi_sensor_events_enable_set(sensor, info->states,
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
    int id, instance;
    char name[33];
    char name2[33];

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    ipmi_control_get_id(control, name, 33);
    strcpy(name2, name);
    conv_from_spaces(name2);
    display_pad_out("  %d.%d.%s - %s\n", id, instance, name2, name);
}

static void
found_entity_for_controls(ipmi_entity_t *entity,
			  char          **toks,
			  char          **toks2,
			  void          *cb_data)
{
    int id, instance;

    curr_display_type = DISPLAY_CONTROLS;
    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    display_pad_clear();
    display_pad_out("Controls for entity %d.%d:\n", id, instance);
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
int id_control_length;
unsigned char *id_control_vals;

static void
display_control(ipmi_entity_t *entity, ipmi_control_t *control)
{
    int  id, instance;
    int  control_type;
    char name[33];
    int  i;
    int  num_vals;

    if (control_displayed)
	return;

    control_ops_to_read_count--;
    if (control_ops_to_read_count > 0)
	return;

    control_displayed = 1;

    ipmi_control_get_id(control, name, 33);
    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    curr_control_id = ipmi_control_convert_to_id(control);

    display_pad_clear();

    conv_from_spaces(name);
    display_pad_out("Control %d.%d.%s:\n",
		    id, instance, name);
    control_type = ipmi_control_get_type(control);
    display_pad_out("  type = %s (%d)\n",
		    ipmi_control_get_type_string(control), control_type);
    num_vals = ipmi_control_get_num_vals(control);
    switch (control_type) {
	case IPMI_CONTROL_LIGHT:
	case IPMI_CONTROL_RELAY:
	case IPMI_CONTROL_ALARM:
	case IPMI_CONTROL_RESET:
	case IPMI_CONTROL_POWER:
	case IPMI_CONTROL_FAN_SPEED:
	    display_pad_out("  num entities = %d\n", num_vals);
	    break;

	case IPMI_CONTROL_DISPLAY:
	case IPMI_CONTROL_IDENTIFIER:
	    break;
    }
    display_pad_out("  value = ");
    getyx(display_pad, value_pos.y, value_pos.x);

    if (control_read_err) {
	display_pad_out("\n");
    } else {
	switch (control_type) {
	    case IPMI_CONTROL_RELAY:
	    case IPMI_CONTROL_ALARM:
	    case IPMI_CONTROL_RESET:
	    case IPMI_CONTROL_POWER:
	    case IPMI_CONTROL_FAN_SPEED:
	    case IPMI_CONTROL_LIGHT:
		if (normal_control_vals) {
		    for (i=0; i<num_vals; ) {
			display_pad_out("%d (0x%x)", normal_control_vals[i],
					normal_control_vals[i]);
			i++;
			if (i < num_vals)
			    display_pad_out("\n          ");
		    }
		    ipmi_mem_free(normal_control_vals);
		}
		break;
		
	    case IPMI_CONTROL_DISPLAY:
		break;
		
	    case IPMI_CONTROL_IDENTIFIER:
		if (id_control_vals) {
		    for (i=0; i<id_control_length; i++)
			display_pad_out("0x%2.2x", id_control_vals[i]);
		    ipmi_mem_free(id_control_vals);
		}
		break;
	}
    }
    display_pad_out("\n");

    display_pad_refresh();
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
	normal_control_vals = ipmi_mem_alloc(sizeof(int) * num_vals);
	if (normal_control_vals) {
	    memcpy(normal_control_vals, val, sizeof(int) * num_vals);
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

    control_id = ipmi_control_convert_to_id(control);
    if (!((curr_display_type == DISPLAY_CONTROL)
	  && (ipmi_cmp_control_id(control_id, curr_control_id) == 0)))
	return;

    if (control_displayed) {
	if (err) {
	    wmove(display_pad, value_pos.y, value_pos.x);
	    display_pad_out("?");
	} else {
	    for (i=0; i<length; i++) {
		wmove(display_pad, value_pos.y+i, value_pos.x);
		display_pad_out("0x%2.2x", val[i]);
	    }
	}
	display_pad_refresh();
    } else {
	id_control_length = length;
	id_control_vals = ipmi_mem_alloc(sizeof(unsigned char) * length);
	if (id_control_vals) {
	    memcpy(id_control_vals, val, sizeof(unsigned char) * length);
	}
	display_control(ipmi_control_get_entity(control), control);
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
    case IPMI_CONTROL_RELAY:
    case IPMI_CONTROL_ALARM:
    case IPMI_CONTROL_RESET:
    case IPMI_CONTROL_POWER:
    case IPMI_CONTROL_FAN_SPEED:
    case IPMI_CONTROL_LIGHT:
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
    unsigned char *name;
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
	control_displayed = 0;
	control_ops_to_read_count = 1;

	control_type = ipmi_control_get_type(control);
	switch (control_type) {
	case IPMI_CONTROL_RELAY:
	case IPMI_CONTROL_ALARM:
	case IPMI_CONTROL_RESET:
	case IPMI_CONTROL_POWER:
	case IPMI_CONTROL_FAN_SPEED:
	case IPMI_CONTROL_LIGHT:
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
	int id, instance;

	id = ipmi_entity_get_entity_id(entity);
	instance = ipmi_entity_get_entity_instance(entity);

	conv_from_spaces(iinfo.name);
	cmd_win_out("Control %d.%d.%s not found\n",
		id, instance, iinfo.name);
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
	return 0;
    info->global = global;

    if (!global) {
	info->states = ipmi_mem_alloc(ipmi_event_state_size());
	if (!info->states) {
	    ipmi_mem_free(info);
	    cmd_win_out("Out of memory\n");
	    return 0;
	}

	ipmi_event_state_init(info->states);

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
    }
    
    rv = ipmi_sensor_pointer_cb(curr_sensor_id, rearm, info);
    if (rv) {
	cmd_win_out("Unable to get sensor pointer: 0x%x\n", rv);
	ipmi_mem_free(info);
    }
    return 0;
}

void mcs_handler(ipmi_mc_t *bmc,
		 ipmi_mc_t *mc,
		 void      *cb_data)
{
    int addr;
    int channel;

    addr = ipmi_mc_get_address(mc);
    channel = ipmi_mc_get_channel(mc);
    display_pad_out("  (%x %x) - %s\n", channel, addr,
		    ipmi_mc_is_active(mc) ? "active" : "inactive");
}

static void
mcs_cmd_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    ipmi_bmc_iterate_mcs(bmc, mcs_handler, NULL);
}

int
mcs_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    if (!bmc_ready) {
	cmd_win_out("BMC has not finished setup yet\n");
	return 0;
    }

    display_pad_clear();
    curr_display_type = DISPLAY_MCS;
    display_pad_out("MCs:\n");
    display_pad_out("  (f 0) - active\n");
    rv = ipmi_mc_pointer_cb(bmc_id, mcs_cmd_bmcer, NULL);
    if (rv) {
	cmd_win_out("Unable to convert BMC id to a pointer\n");
	return 0;
    }
    display_pad_refresh();
    return 0;
}

#define MCCMD_DATA_SIZE 30
typedef struct mccmd_info_s
{
    ipmi_mc_id_t  mc_id;
    unsigned char lun;
    ipmi_msg_t    msg;
    int           found;
} mccmd_info_t;

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
    for (i=0; i<msg->data_len-1; i++) {
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
    rv = ipmi_send_command(mc, info->lun, &(info->msg), mccmd_rsp_handler,
			   NULL);
    if (rv)
	cmd_win_out("Send command failure: %x\n", rv);
}

static void
mccmd_cmd_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    mccmd_info_t *info = cb_data;

    info->mc_id.bmc = bmc;
    ipmi_mc_pointer_cb(info->mc_id, mccmd_handler, cb_data);
}

int
mccmd_cmd(char *cmd, char **toks, void *cb_data)
{
    mccmd_info_t  info;
    unsigned char data[MCCMD_DATA_SIZE];
    unsigned int  data_len;
    int           rv;
    unsigned char val;

    if (get_uchar(toks, &val, "MC channel"))
	return 0;
    info.mc_id.channel = val;

    if (get_uchar(toks, &val, "MC num"))
	return 0;
    info.mc_id.mc_num = val;

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
    rv = ipmi_mc_pointer_cb(bmc_id, mccmd_cmd_bmcer, &info);
    if (rv) {
	cmd_win_out("Unable to convert BMC id to a pointer\n");
	return 0;
    }
    if (!info.found) {
	cmd_win_out("Unable to find MC (%x %x)\n",
		    info.mc_id.channel, info.mc_id.mc_num);
    }
    display_pad_refresh();

    return 0;
}

typedef struct msg_cmd_data_s
{
    unsigned char    data[MCCMD_DATA_SIZE];
    unsigned int     data_len;
    ipmi_ipmb_addr_t addr;
    ipmi_msg_t       msg;
} msg_cmd_data_t;

static void
msg_cmd_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    msg_cmd_data_t *info = cb_data;
    int            rv;

    rv = ipmi_bmc_send_command_addr(bmc,
				    (ipmi_addr_t *) &(info->addr),
				    sizeof(info->addr),
				    &info->msg,
				    mccmd_rsp_handler,
				    NULL);
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

    rv = ipmi_mc_pointer_cb(bmc_id, msg_cmd_bmcer, &info);
    if (rv) {
	cmd_win_out("Unable to convert BMC id to a pointer\n");
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
    int           *vals;
    unsigned char *cvals;
    char          *tok;
    char          *estr;
    int           rv;
    int           control_type;

    control_type = ipmi_control_get_type(control);
    switch (control_type) {
	case IPMI_CONTROL_RELAY:
	case IPMI_CONTROL_ALARM:
	case IPMI_CONTROL_RESET:
	case IPMI_CONTROL_POWER:
	case IPMI_CONTROL_FAN_SPEED:
	case IPMI_CONTROL_LIGHT:
	    num_vals = ipmi_control_get_num_vals(control);
	    vals = ipmi_mem_alloc(sizeof(*vals) * num_vals);
	    if (!vals) {
		cmd_win_out("set_control: out of memory\n");
		goto out_bcon;
	    }
	
	    for (i=0; i<num_vals; i++) {
		tok = strtok_r(NULL, " \t\n", toks);
		if (!tok) {
		    cmd_win_out("set_control: Value %d is not present\n", i);
		    goto out_bcon;
		}
		vals[i] = strtol(tok, &estr, 0);
		if (*estr != '\0') {
		    ipmi_mem_free(vals);
		    cmd_win_out("set_control: Value %d is invalid\n", i);
		    goto out_bcon;
		}
	    }

	    rv = ipmi_control_set_val(control, vals, NULL, NULL);
	    if (rv) {
		cmd_win_out("set_control: Returned error 0x%x\n", rv);
	    }
    out_bcon:
	    ipmi_mem_free(vals);
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
    return;
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
delevent_cb(ipmi_mc_t *bmc, int err, void *cb_data)
{
    if (err)
	ui_log("Error deleting log: %x\n", err);
    else
	ui_log("log deleted\n");
}

typedef struct delevent_info_s
{
    ipmi_mc_id_t mc_id;
    int          record_id;
    int          rv;
} delevent_info_t;

static void
delevent_cmd_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    int             rv;
    delevent_info_t *info = cb_data;
    ipmi_event_t    event;
    int             found = 0;

    info->mc_id.bmc = bmc;

    rv = ipmi_bmc_first_event(bmc, &event);
    while (!rv && !found) {
	if ((ipmi_cmp_mc_id(event.mc_id, info->mc_id) == 0)
	    && (event.record_id == info->record_id))
	{
	    found = 1;
	    rv = ipmi_bmc_del_event(bmc, &event, delevent_cb, NULL);
	    if (rv)
		cmd_win_out("error deleting log: %x\n", rv);
	} else {
	    rv = ipmi_bmc_next_event(bmc, &event);
	}
    }
    if (!found)
	cmd_win_out("log not found\n", rv);
}

static int
delevent_cmd(char *cmd, char **toks, void *cb_data)
{
    delevent_info_t info;
    int             rv;
    unsigned int    val;

    if (!bmc_ready) {
	cmd_win_out("BMC has not finished setup yet\n");
	return 0;
    }

    if (get_uint(toks, &val, "mc channel"))
	return 0;
    info.mc_id.channel = val;

    if (get_uint(toks, &val, "mc number"))
	return 0;
    info.mc_id.mc_num = val;

    if (get_uint(toks, &info.record_id, "record id"))
	return 0;

    rv = ipmi_mc_pointer_cb(bmc_id, delevent_cmd_bmcer, &info);
    if (rv) {
	cmd_win_out("Unable to convert BMC id to a pointer\n");
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
clear_sel_cmd_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    int          rv;
    ipmi_event_t event, event2;

    rv = ipmi_bmc_first_event(bmc, &event2);
    while (!rv) {
	event = event2;
	rv = ipmi_bmc_next_event(bmc, &event2);
	ipmi_bmc_del_event(bmc, &event, NULL, NULL);
	event = event2;
    }
}

static int
clear_sel_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    rv = ipmi_mc_pointer_cb(bmc_id, clear_sel_cmd_bmcer, NULL);
    if (rv) {
	cmd_win_out("Unable to convert BMC id to a pointer\n");
	return 0;
    }
    return 0;
}

static void
list_sel_cmd_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    int          rv;
    ipmi_event_t event;

    curr_display_type = EVENTS;
    display_pad_clear();
    display_pad_out("Events:\n");
    rv = ipmi_bmc_first_event(bmc, &event);
    while (!rv) {
	display_pad_out("  (%x %x) %4.4x:%2.2x: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x"
			" %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
			event.mc_id.channel, event.mc_id.mc_num,
			event.record_id, event.type,
			event.data[0],
			event.data[1],
			event.data[2],
			event.data[3],
			event.data[4],
			event.data[5],
			event.data[6],
			event.data[7],
			event.data[8],
			event.data[9],
			event.data[10],
			event.data[11],
			event.data[12]);
	rv = ipmi_bmc_next_event(bmc, &event);
    }
    display_pad_refresh();
}

static int
list_sel_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    rv = ipmi_mc_pointer_cb(bmc_id, list_sel_cmd_bmcer, NULL);
    if (rv) {
	cmd_win_out("Unable to convert BMC id to a pointer\n");
	return 0;
    }
    return 0;
}

typedef struct sdrs_info_s
{
    int           found;
    ipmi_mc_id_t  mc_id;
    unsigned char do_sensors;
} sdrs_info_t;

void sdrs_fetched(ipmi_sdr_info_t *sdrs,
		  int             err,
		  int             changed,
		  unsigned int    count,
		  void            *cb_data)
{
    sdrs_info_t *info = cb_data;
    int         i;
    int         rv;

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
	display_pad_out("%4.4x: type %x, version %d.%d",
		sdr.record_id, sdr.type, sdr.major_version, sdr.minor_version);
	for (j=0; j<sdr.length; j++) {
	    if ((j % 8) == 0)
		display_pad_out("\n ");
	    display_pad_out(" %2.2x", sdr.data[j]);
	}
	display_pad_out("\n");
    }
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

    rv = ipmi_sdr_info_alloc(mc, 0, info->do_sensors, &sdrs);
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

static void
sdrs_cmd_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    sdrs_info_t *info = cb_data;

    info->mc_id.bmc = bmc;
    ipmi_mc_pointer_cb(info->mc_id, sdrs_mcs_handler, info);
}

static int
sdrs_cmd(char *cmd, char **toks, void *cb_data)
{
    int           rv;
    sdrs_info_t   *info;
    unsigned char val;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	ui_log("Could not allocate memory for SDR fetch\n");
	return 0;
    }

    if (get_uchar(toks, &val, "MC channel")) {
	ipmi_mem_free(info);
	return 0;
    }
    info->mc_id.channel = val;

    if (get_uchar(toks, &val, "MC num")) {
	ipmi_mem_free(info);
	return 0;
    }
    info->mc_id.mc_num = val;

    if (get_uchar(toks, &info->do_sensors, "do_sensors")) {
	ipmi_mem_free(info);
	return 0;
    }

    info->found = 0;

    rv = ipmi_mc_pointer_cb(bmc_id, sdrs_cmd_bmcer, info);
    if (rv) {
	cmd_win_out("Unable to convert BMC id to a pointer\n");
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

static void
scan_cmd_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    scan_cmd_info_t *info = cb_data;

    ipmi_start_ipmb_mc_scan(bmc, info->channel,
			    info->addr, info->addr,
			    NULL, NULL);
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

    rv = ipmi_mc_pointer_cb(bmc_id, scan_cmd_bmcer, &info);
    if (rv) {
	cmd_win_out("Unable to convert BMC id to a pointer\n");
    }
    return 0;
}

extern void ui_reconnect(void);

static void
disconnect_done(void *cb_data)
{
    ui_reconnect();
}

static void
reconnect_cmd_bmcer(ipmi_mc_t *bmc, void *cb_data)
{
    int rv;

    rv = ipmi_close_connection(bmc, disconnect_done, NULL);
    if (rv)
	cmd_win_out("Could not close connection: %x\n", rv);
}

int
reconnect_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    if (!bmc_ready) {
	cmd_win_out("BMC has not finished setup yet\n");
	return 0;
    }

    rv = ipmi_mc_pointer_cb(bmc_id, reconnect_cmd_bmcer, NULL);
    if (rv) {
	cmd_win_out("Unable to convert BMC id to a pointer\n");
	return 0;
    }
    
    return 0;
}

static int help_cmd(char *cmd, char **toks, void *cb_data);

static struct {
    char          *name;
    cmd_handler_t handler;
    char          *help;
} cmd_list[] =
{
    { "entities",	entities_cmd,
      " - list all the entities the UI knows about" },
    { "sensors",	sensors_cmd,
      " <entity name> - list all the sensors that monitor the entity" },
    { "sensor",		sensor_cmd,
      " <sensor name> - Pull up all the information on the sensor and start"
      " monitoring it" },
    { "rearm",		rearm_cmd,
      " - rearm the current sensor" },
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
    { "mccmd",		mccmd_cmd,
      " <channel> <mc num> <LUN> <NetFN> <Cmd> [data...]"
      " - Send the given command"
      " to the management controller and display the response" },
    { "msg",		msg_cmd,
      " <channel> <IPMB addr> <LUN> <NetFN> <Cmd> [data...] - Send a command"
      " to the given IPMB address on the given channel and display the"
      " response" },
    { "delevent",	delevent_cmd,
      " <channel> <mc num> <log number> - "
      "Delete the given event number from the SEL" },
    { "debug",		debug_cmd,
      " <type> on|off - Turn the given debugging type on or off." },
    { "clear_sel",	clear_sel_cmd,
      " - clear the system event log" },
    { "list_sel",	list_sel_cmd,
      " - list the local copy of the system event log" },
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
    { "reconnect",  reconnect_cmd,
      " - scan an IPMB to add or remove it" },
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
    display_pad_out("Welcome to the IPMI UI\n");
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

static void
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
    int  id, instance;
    char name[33];

    id = ipmi_sensor_get_entity_id(sensor);
    instance = ipmi_sensor_get_entity_instance(sensor);
    ipmi_sensor_get_id(sensor, name, 33);
    ui_log("Sensor %d.%d.%s: %s %s %s\n",
	   id, instance, name,
	   ipmi_get_threshold_string(threshold),
	   ipmi_get_value_dir_string(high_low),
	   ipmi_get_event_dir_string(dir));
    if (value_present == IPMI_BOTH_VALUES_PRESENT) {
	ui_log("  value is %f\n", value);
    } else if (value_present == IPMI_RAW_VALUE_PRESENT) {
	ui_log("  raw value is 0x%x\n", raw_value);
    }
    if (event)
	ui_log("Due to event 0x%4.4x\n", event->record_id);
}

static void
sensor_discrete_event_handler(ipmi_sensor_t         *sensor,
			      enum ipmi_event_dir_e dir,
			      int                   offset,
			      int                   severity,
			      int                   prev_severity,
			      void                  *cb_data,
			      ipmi_event_t          *event)
{
    int  id, instance;
    char name[33];

    id = ipmi_sensor_get_entity_id(sensor);
    instance = ipmi_sensor_get_entity_instance(sensor);
    ipmi_sensor_get_id(sensor, name, 33);
    ui_log("Sensor %d.%d.%s: %d %s\n",
	   id, instance, name,
	   offset,
	   ipmi_get_event_dir_string(dir));
    if (severity != -1)
	ui_log("  severity is %d\n", severity);
    if (prev_severity != -1)
	ui_log("  prev severity is %d\n", prev_severity);
    if (event)
	ui_log("Due to event 0x%4.4x\n", event->record_id);
}

static void
sensor_change(enum ipmi_update_e op,
	      ipmi_entity_t      *ent,
	      ipmi_sensor_t      *sensor,
	      void               *cb_data)
{
    int id, instance;
    char name[33];
    char name2[33];
    int rv;

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_id(sensor, name, 32);
    strcpy(name2, name);
    conv_from_spaces(name2);
    switch (op) {
	case IPMI_ADDED:
	    ui_log("Sensor added: %d.%d.%s (%s)\n",
		   id, instance, name2, name);
	    if (ipmi_sensor_get_event_reading_type(sensor)
		== IPMI_EVENT_READING_TYPE_THRESHOLD)
		rv = ipmi_sensor_threshold_set_event_handler(
		    sensor,
		    sensor_threshold_event_handler,
		    NULL);
	    else
		rv = ipmi_sensor_discrete_set_event_handler(
		    sensor,
		    sensor_discrete_event_handler,
		    NULL);
	    if (rv)
		ui_log("Unable to register sensor event handler: 0x%x\n", rv);
	    break;
	case IPMI_DELETED:
	    ui_log("Sensor deleted: %d.%d.%s (%s)\n",
		   id, instance, name2, name);
	    break;
	case IPMI_CHANGED:
	    ui_log("Sensor changed: %d.%d.%s (%s)\n",
		   id, instance, name2, name);
	    break;
    }
}

static void
control_change(enum ipmi_update_e op,
	       ipmi_entity_t      *ent,
	       ipmi_control_t     *control,
	       void               *cb_data)
{
    int id, instance;
    char name[33];
    char name2[33];

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_control_get_id(control, name, 32);
    strcpy(name2, name);
    conv_from_spaces(name2);
    switch (op) {
	case IPMI_ADDED:
	    ui_log("Control added: %d.%d.%s (%s)\n",
		   id, instance, name2, name);
	    break;
	case IPMI_DELETED:
	    ui_log("Control deleted: %d.%d.%s (%s)\n",
		   id, instance, name2, name);
	    break;
	case IPMI_CHANGED:
	    ui_log("Control changed: %d.%d.%s (%s)\n",
		   id, instance, name2, name);
	    break;
    }
}

static void
entity_presence_handler(ipmi_entity_t *entity,
			int           present,
			void          *cb_data,
			ipmi_event_t  *event)
{
    int id, instance;

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    ui_log("Entity %d.%d, presence is %d\n", id, instance, present);
    if (event)
	ui_log("Due to event 0x%4.4x\n", event->record_id);
}

static void
entity_change(enum ipmi_update_e op,
	      ipmi_mc_t          *bmc,
	      ipmi_entity_t      *entity,
	      void               *cb_data)
{
    int rv;
    int id, instance;

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    switch (op) {
	case IPMI_ADDED:
	    ui_log("Entity added: %d.%d\n", id, instance);
	    rv = ipmi_entity_set_sensor_update_handler(entity,
						       sensor_change,
						       entity);
	    if (rv) {
		report_error("ipmi_entity_set_sensor_update_handler", rv);
		break;
	    }
	    rv = ipmi_entity_set_control_update_handler(entity,
							control_change,
							entity);
	    if (rv) {
		report_error("ipmi_entity_set_control_update_handler", rv);
		break;
	    }
	    rv = ipmi_entity_set_presence_handler(entity,
						  entity_presence_handler,
						  NULL);
	    if (rv) {
		report_error("ipmi_entity_set_presence_handler", rv);
	    }
	    break;
	case IPMI_DELETED:
	    ui_log("Entity deleted: %d.%d\n", id, instance);
	    break;
	case IPMI_CHANGED:
	    ui_log("Entity changed: %d.%d\n", id, instance);
	    break;
    }
}

static ipmi_event_handler_id_t *event_handler_id;

static void
event_handler(ipmi_mc_t    *bmc,
	      ipmi_event_t *event,
	      void         *event_data)
{
    /* FIXME - fill this out. */
    ui_log("Unknown event from mc (%x %x)\n",
	   event->mc_id.channel, event->mc_id.mc_num);
    ui_log("  %4.4x:%2.2x: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x"
	   " %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
	   event->record_id, event->type,
	   event->data[0],
	   event->data[1],
	   event->data[2],
	   event->data[3],
	   event->data[4],
	   event->data[5],
	   event->data[6],
	   event->data[7],
	   event->data[8],
	   event->data[9],
	   event->data[10],
	   event->data[11],
	   event->data[12]);
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
	rv = ipmi_mc_pointer_cb(bmc_id, entities_cmd_bmcer, NULL);
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
ipmi_ui_setup_done(ipmi_mc_t *mc,
		   void      *user_data,
		   int       err)
{
    int             rv;


    if (err)
	leave_err(err, "Could not set up IPMI connection");

    bmc_id = ipmi_mc_convert_to_id(mc);
    bmc_ready = 1;

    ui_log("Completed setup for the IPMI connection\n");

    rv = ipmi_register_for_events(mc, event_handler, NULL, &event_handler_id);
    if (rv)
	leave_err(rv, "ipmi_register_for_events");

    rv = ipmi_bmc_enable_events(mc);
    if (rv)
	leave_err(rv, "ipmi_bmc_enable_events");

    rv = ipmi_bmc_set_entity_update_handler(mc, entity_change, mc);
    if (rv)
	leave_err(rv, "ipmi_bmc_set_entity_update_handler");
}

int
ipmi_ui_init(selector_t **selector, int do_full_screen)
{
    int rv;

    full_screen = do_full_screen;

    rv = sel_alloc_selector(&ui_sel);
    if (rv) {
	fprintf(stderr, "Could not allocate selector\n");
	exit(1);
    }

    sel_set_fd_handlers(ui_sel, 0, NULL, user_input_ready, NULL, NULL);
    sel_set_fd_read_handler(ui_sel, 0, SEL_FD_HANDLER_ENABLED);

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
	tcsetattr(0, 0,&new_termios);
	fcntl(0, F_SETFL, O_NONBLOCK);
    }

    help_cmd(NULL, NULL, NULL);

    ipmi_init(&ipmi_ui_cb_handlers);

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
    leave(0, "");
}
