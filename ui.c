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
#include <ipmi/selector.h>
#include <ipmi/ipmi_err.h>
#include <ipmi/ipmi_mc.h>
#include <ipmi/ipmiif.h>
#include <ipmi/ipmi_int.h>
#include <ipmi/ipmi_ui.h>

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

ipmi_mc_t *bmc = NULL;

extern os_handler_t ipmi_ui_cb_handlers;


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
    DISPLAY_NONE, DISPLAY_SENSOR, DISPLAY_ENTITY, DISPLAY_SENSORS,
    DISPLAY_CONTROLS, DISPLAY_CONTROL, DISPLAY_ENTITIES, DISPLAY_MCS,
    DISPLAY_RSP
} curr_display_type;
ipmi_sensor_id_t curr_sensor_id;
ipmi_control_id_t curr_control_id;
typedef struct pos_s {int y; int x; } pos_t;
typedef struct thr_pos_s
{
    int   set;
    pos_t value;
    pos_t enabled;
} thr_pos_t;
thr_pos_t threshold_positions[6];

pos_t value_pos;
pos_t enabled_pos;
pos_t scanning_pos;
pos_t discr_assert_avail;
pos_t discr_assert_enab;
pos_t discr_deassert_avail;
pos_t discr_deassert_enab;

ipmi_entity_id_t curr_entity_id;

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

static int
get_uchar(char **toks, unsigned char *val, char *errstr)
{
    char *str, *tmpstr;

    str = strtok_r(NULL, " \t\n", toks);
    if (!str) {
	if (errstr)
	    wprintw(cmd_win, "No %s given\n", errstr);
	return EINVAL;
    }
    *val = strtoul(str, &tmpstr, 0);
    if (*tmpstr != '\0') {
	if (errstr)
	    wprintw(cmd_win, "Invalid %s given\n", errstr);
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
	    wprintw(cmd_win, "No %s given\n", errstr);
	return EINVAL;
    }
    *val = strtoul(str, &tmpstr, 0);
    if (*tmpstr != '\0') {
	if (errstr)
	    wprintw(cmd_win, "Invalid %s given\n", errstr);
	return EINVAL;
    }

    return 0;
}

void
log_pad_refresh(int newlines)
{
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

void
display_pad_refresh(void)
{
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
ui_vlog(char *format, va_list ap)
{
    int y, x;

    /* Generate the output to the dummy pad to see how many lines we
       will use. */
    vwprintw(dummy_pad, format, ap);
    getyx(dummy_pad, y, x);
    wmove(dummy_pad, 0, x);

    vwprintw(log_pad, format, ap);
    log_pad_refresh(y);
    wrefresh(cmd_win);
}

void
ui_log(char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    ui_vlog(format, ap);
    va_end(ap);
}

void
leave(int rv, char *format, ...)
{
    va_list ap;

    endwin();
    sel_free_selector(ui_sel);

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    exit(rv);
}

void
leave_err(int err, char *format, ...)
{
    va_list ap;

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

    c = wgetch(cmd_win);
    while (c != ERR) {
	handle_user_char(c);
	c = wgetch(cmd_win);
    }
}

static char *line_buffer = NULL;
static int  line_buffer_max = 0;
static int  line_buffer_pos = 0;

static int
normal_char(int key, void *cb_data)
{
    if (line_buffer_pos >= line_buffer_max) {
	char *new_line = malloc(line_buffer_max+10+1);
	if (!new_line)
	    return ENOMEM;
	line_buffer_max += 10;
	if (line_buffer) {
	    strcpy(new_line, line_buffer);
	    free(line_buffer);
	}
	line_buffer = new_line;
    }
    line_buffer[line_buffer_pos] = key;
    line_buffer_pos++;
    waddch(cmd_win, key);
    return 0;
}

static int
end_of_line(int key, void *cb_data)
{
    int err;

    if (!line_buffer)
	return 0;

    line_buffer[line_buffer_pos] = '\0';
    waddch(cmd_win, '\n');
    err = command_handle(commands, line_buffer, NULL);
    if (err)
	wprintw(cmd_win, "Invalid command: %s\n> ", line_buffer);
    else
	waddstr(cmd_win, "> ");
    line_buffer_pos = 0;
    return 0;
}

static int
backspace(int key, void *cb_data)
{
    if (line_buffer_pos == 0)
	return 0;

    line_buffer_pos--;
    waddstr(cmd_win, "\b \b");
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

static int
key_leave(int key, void *cb_data)
{
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

static void
entities_handler(ipmi_entity_t *entity,
		 void          *cb_data)
{
    int  id, instance;
    char *present;
    char name[33];

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    curr_display_type = DISPLAY_ENTITY;
    curr_entity_id = ipmi_entity_convert_to_id(entity);
    ipmi_entity_get_id(entity, name, 32);
    if (ipmi_entity_is_present(entity))
	present = "present";
    else
	present = "not present";
    wprintw(display_pad, "  %d.%d (%s) %s\n", id, instance, name, present);
}

int
entities_cmd(char *cmd, char **toks, void *cb_data)
{
    if (!bmc) {
	waddstr(cmd_win, "BMC has not finished setup yet\n");
	return 0;
    }

    werase(display_pad);
    wmove(display_pad, 0, 0);
    curr_display_type = DISPLAY_ENTITIES;
    waddstr(display_pad, "Entities:\n");
    ipmi_bmc_iterate_entities(bmc, entities_handler, NULL);
    display_pad_refresh();
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

int
entity_finder(char *cmd, char **toks,
	      entity_handler_cb handler,
	      void *cb_data)
{
    struct ent_rec info;
    char           *ent_name;
    char           *id_name, *instance_name, *toks2, *estr;

    if (!bmc) {
	waddstr(cmd_win, "BMC has not finished setup yet\n");
	return EAGAIN;
    }

    ent_name = strtok_r(NULL, " \t\n", toks);
    if (!ent_name) {
	waddstr(cmd_win, "No entity given\n");
	return EINVAL;
    }

    id_name = strtok_r(ent_name, ".", &toks2);
    instance_name = strtok_r(NULL, ".", &toks2);
    if (!instance_name) {
	waddstr(cmd_win, "Invalid entity given\n");
	return EINVAL;
    }
    info.id = strtoul(id_name, &estr, 0);
    if (*estr != '\0') {
	waddstr(cmd_win, "Invalid entity id given\n");
	return EINVAL;
    }
    info.instance = strtoul(instance_name, &estr, 0);
    if (*estr != '\0') {
	waddstr(cmd_win, "Invalid entity instance given\n");
	return EINVAL;
    }
    info.found = 0;

    info.handler = handler;
    info.cb_data = cb_data;
    info.toks = toks;
    info.toks2 = &toks2;

    ipmi_bmc_iterate_entities(bmc, entity_searcher, &info);
    if (!info.found) {
	wprintw(cmd_win, "Entity %d.%d not found\n", info.id, info.instance);
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
    wprintw(display_pad, "  %d.%d.%s - %s\n", id, instance, name2, name);
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
    werase(display_pad);
    wmove(display_pad, 0, 0);
    wprintw(display_pad, "Sensors for entity %d.%d:\n", id, instance);
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

static void
read_sensor(ipmi_sensor_t *sensor,
	    int           err,
	    int           val_present,
	    double        val,
	    ipmi_states_t *states,
	    void          *cb_data)
{
    ipmi_sensor_id_t sensor_id;

    sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!((curr_display_type == DISPLAY_SENSOR)
	  && (ipmi_cmp_sensor_id(sensor_id, curr_sensor_id) == 0)))
	return;

    wmove(display_pad, value_pos.y, value_pos.x);
    if (err) {
	wprintw(display_pad, "unreadable");
	display_pad_refresh();
	return;
    }

    if (val_present)
	wprintw(display_pad, "%f", val);
    else
	wprintw(display_pad, "unreadable");
    display_pad_refresh();
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

    if (err) {
	for (t=IPMI_LOWER_NON_CRITICAL; t<IPMI_UPPER_NON_RECOVERABLE; t++) {
	    if (threshold_positions[t].set) {
		wmove(display_pad,
		      threshold_positions[t].value.y,
		      threshold_positions[t].value.x);
		wprintw(display_pad, "?");
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
		    wprintw(display_pad, "?", val);
		else
		    wprintw(display_pad, "%f", val);
	    }
	}    
    }
    display_pad_refresh();
}

static void
read_thresh_event_enables(ipmi_sensor_t      *sensor,
			  int                err,
			  int                global_enable,
			  int                scanning_enabled,
			  ipmi_event_state_t *states,
			  void               *cb_data)
{
    ipmi_sensor_id_t   sensor_id;
    enum ipmi_thresh_e t;

    sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!((curr_display_type == DISPLAY_SENSOR)
	  && (ipmi_cmp_sensor_id(sensor_id, curr_sensor_id) == 0)))
	return;

    wmove(display_pad, enabled_pos.y, enabled_pos.x);
    if (err)
	wprintw(display_pad, "?         ");
    else if (global_enable)
	wprintw(display_pad, "enabled");
    else
	wprintw(display_pad, "disabled");

    wmove(display_pad, scanning_pos.y, scanning_pos.x);
    if (err)
	wprintw(display_pad, "?         ");
    else if (scanning_enabled)
	wprintw(display_pad, "enabled");
    else
	wprintw(display_pad, "disabled");

    if (ipmi_sensor_get_event_support(sensor)
	!= IPMI_EVENT_SUPPORT_PER_STATE)
	goto out;

    for (t=IPMI_LOWER_NON_CRITICAL; t<IPMI_UPPER_NON_RECOVERABLE; t++) {
	if (threshold_positions[t].set) {
	    wmove(display_pad,
		  threshold_positions[t].enabled.y,
		  threshold_positions[t].enabled.x);
	    if (err) {
		wprintw(display_pad, "?         ");
		continue;
	    }
	    wprintw(display_pad, "  ");
	    if (ipmi_is_threshold_event_set(states, t,
					    IPMI_GOING_LOW,
					    IPMI_ASSERTION))
		wprintw(display_pad, "L^");
	    else
		wprintw(display_pad, "  ");
	    if (ipmi_is_threshold_event_set(states, t,
					    IPMI_GOING_LOW,
					    IPMI_DEASSERTION))
		wprintw(display_pad, "Lv");
	    else
		wprintw(display_pad, "  ");
	    if (ipmi_is_threshold_event_set(states, t,
					    IPMI_GOING_HIGH,
					    IPMI_ASSERTION))
		wprintw(display_pad, "H^");
	    else
		wprintw(display_pad, "  ");
	    if (ipmi_is_threshold_event_set(states, t,
					    IPMI_GOING_HIGH,
					    IPMI_DEASSERTION))
		wprintw(display_pad, "HV");
	    else
		wprintw(display_pad, "  ");
	}
    }    

 out:
    display_pad_refresh();
}

static void
read_discrete_event_enables(ipmi_sensor_t      *sensor,
			    int                err,
			    int                global_enable,
			    int                scanning_enabled,
			    ipmi_event_state_t *states,
			    void               *cb_data)
{
    ipmi_sensor_id_t sensor_id;
    int              i;
    int              val;

    sensor_id = ipmi_sensor_convert_to_id(sensor);
    if (!((curr_display_type == DISPLAY_SENSOR)
	  && (ipmi_cmp_sensor_id(sensor_id, curr_sensor_id) == 0)))
	return;

    wmove(display_pad, enabled_pos.y, enabled_pos.x);
    if (err)
	wprintw(display_pad, "?         ");
    else if (global_enable)
	wprintw(display_pad, "enabled");
    else
	wprintw(display_pad, "disabled");

    wmove(display_pad, scanning_pos.y, scanning_pos.x);
    if (err)
	wprintw(display_pad, "?         ");
    else if (scanning_enabled)
	wprintw(display_pad, "enabled");
    else
	wprintw(display_pad, "disabled");

    if (ipmi_sensor_get_event_support(sensor)
	!= IPMI_EVENT_SUPPORT_PER_STATE)
	goto out;

    if (err) {
	wmove(display_pad, discr_assert_enab.y, discr_assert_enab.x);
	wprintw(display_pad, "?");
	wmove(display_pad, discr_deassert_enab.y, discr_deassert_enab.x);
	wprintw(display_pad, "?");
    } else {
	wmove(display_pad, discr_assert_enab.y, discr_assert_enab.x);
	for (i=0; i<15; i++) {
	    val = ipmi_is_discrete_event_set(states, i, IPMI_ASSERTION);
	    wprintw(display_pad, "%d", val != 0);
	}    
	wmove(display_pad, discr_deassert_enab.y, discr_deassert_enab.x);
	for (i=0; i<15; i++) {
	    val = ipmi_is_discrete_event_set(states, i, IPMI_DEASSERTION);
	    wprintw(display_pad, "%d", val != 0);
	}    
    }

 out:
    display_pad_refresh();
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

    wmove(display_pad, value_pos.y, value_pos.x);
    if (err) {
	wprintw(display_pad, "?");
    } else {
	for (i=0; i<15; i++) {
	    val = ipmi_is_state_set(states, i);
	    wprintw(display_pad, "%d", val != 0);
	}    
    }
    display_pad_refresh();
}

static void
redisplay_sensor(ipmi_sensor_t *sensor, void *cb_data)
{
    int rv;
    ipmi_entity_t *entity;

    entity = ipmi_sensor_get_entity(sensor);
    if (!entity)
	return;

    if (!ipmi_entity_is_present(entity)
	&& ipmi_sensor_get_ignore_if_no_entity(sensor))
    {
	wmove(display_pad, value_pos.y, value_pos.x);
	wprintw(display_pad, "not present");
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
    int id, instance;
    char name[33];
    struct sensor_info *sinfo = cb_data;
    int rv;
    int present = 1;

    ipmi_sensor_get_id(sensor, name, 33);
    if (strcmp(name, sinfo->name) == 0) {
	sinfo->found = 1;
	curr_display_type = DISPLAY_SENSOR;
	curr_sensor_id = ipmi_sensor_convert_to_id(sensor);

	id = ipmi_entity_get_entity_id(entity);
	instance = ipmi_entity_get_entity_instance(entity);

	werase(display_pad);
	wmove(display_pad, 0, 0);

	conv_from_spaces(name);
	wprintw(display_pad, "Sensor %d.%d.%s - %s:\n",
		id, instance, name, sinfo->name);
	wprintw(display_pad, "  value = ");
	getyx(display_pad, value_pos.y, value_pos.x);
	if (!ipmi_entity_is_present(entity)
	    && ipmi_sensor_get_ignore_if_no_entity(sensor))
	{
	    wprintw(display_pad, "not present");
	    present = 0;
	}
	wprintw(display_pad, "\n  Events = ");
	getyx(display_pad, enabled_pos.y, enabled_pos.x);
	wprintw(display_pad, "\n  Scanning = ");
	getyx(display_pad, scanning_pos.y, scanning_pos.x);
	wprintw(display_pad, "\n");
	wprintw(display_pad, "  sensor type = %s (0x%2.2x)\n",
		ipmi_sensor_get_sensor_type_string(sensor),
		ipmi_sensor_get_sensor_type(sensor));
	wprintw(display_pad, "  event/reading type = %s (0x%2.2x)\n",
		ipmi_sensor_get_event_reading_type_string(sensor),
		ipmi_sensor_get_event_reading_type(sensor));

	if (ipmi_sensor_get_event_reading_type(sensor)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    enum ipmi_thresh_e t;
	    double val;

	    wprintw(display_pad, "  units = %s%s",
		    ipmi_sensor_get_base_unit_string(sensor),
		    ipmi_sensor_get_rate_unit_string(sensor));
	    switch(ipmi_sensor_get_modifier_unit_use(sensor)) {
		case IPMI_MODIFIER_UNIT_BASE_DIV_MOD:
		    wprintw(display_pad, "/%s",
			    ipmi_sensor_get_modifier_unit_string(sensor));
		    break;
		    
		case IPMI_MODIFIER_UNIT_BASE_MULT_MOD:
		    wprintw(display_pad, "*%s",
			    ipmi_sensor_get_modifier_unit_string(sensor));
		    break;
	    }
	    wprintw(display_pad, "\n");

	    rv = ipmi_sensor_get_nominal_reading(sensor, &val);
	    if (!rv) wprintw(display_pad, "  nominal = %f\n", val);

	    rv = ipmi_sensor_get_normal_min(sensor, &val);
	    if (!rv) wprintw(display_pad, "  normal_min = %f\n", val);

	    rv = ipmi_sensor_get_normal_max(sensor, &val);
	    if (!rv) wprintw(display_pad, "  normal_max = %f\n", val);

	    rv = ipmi_sensor_get_sensor_min(sensor, &val);
	    if (!rv) wprintw(display_pad, "  sensor_min = %f\n", val);

	    rv = ipmi_sensor_get_sensor_max(sensor, &val);
	    if (!rv) wprintw(display_pad, "  sensor_max = %f\n", val);

	    wprintw(display_pad, "Thresholds:\n");
	    for (t=IPMI_LOWER_NON_CRITICAL; t<IPMI_UPPER_NON_RECOVERABLE; t++){
		int settable, readable;
		int i;
		int assert_sup[2], deassert_sup[2];
		int anything_set = 0;

		ipmi_sensor_threshold_settable(sensor, t, &settable);
		anything_set |= settable;
		ipmi_sensor_threshold_readable(sensor, t, &readable);
		anything_set |= readable;
		for (i=0; i<1; i++) {
		    ipmi_sensor_threshold_assertion_event_supported(
			sensor, t, i, &(assert_sup[i]));
		    anything_set |= assert_sup[i];
		    ipmi_sensor_threshold_deassertion_event_supported(
			sensor, t, i, &(deassert_sup[i]));
		    anything_set |= deassert_sup[i];
		}
		if (anything_set) {
		    wprintw(display_pad,
			    "  %s:", ipmi_get_threshold_string(t));
		    threshold_positions[t].set = 1;
		    wprintw(display_pad, "\n    available: ");
		    if (readable) wprintw(display_pad, "R");
		    else wprintw(display_pad, " ");
		    if (settable) wprintw(display_pad, "W");
		    else wprintw(display_pad, " ");
		    if (assert_sup[0]) wprintw(display_pad, "L^");
		    else wprintw(display_pad, "  ");
		    if (assert_sup[0]) wprintw(display_pad, "Lv");
		    else wprintw(display_pad, "  ");
		    if (assert_sup[1]) wprintw(display_pad, "H^");
		    else wprintw(display_pad, "  ");
		    if (assert_sup[1]) wprintw(display_pad, "Hv");
		    else wprintw(display_pad, "  ");
		    wprintw(display_pad, "\n      enabled: ");
		    getyx(display_pad,
			  threshold_positions[t].enabled.y,
			  threshold_positions[t].enabled.x);
		    wprintw(display_pad, "\n        value: ");
		    getyx(display_pad,
			  threshold_positions[t].value.y,
			  threshold_positions[t].value.x);
		    wprintw(display_pad, "\n");
		} else {
		    threshold_positions[t].set = 0;
		}
	    }

	    if (present) {
		rv = ipmi_reading_get(sensor, read_sensor, NULL);
		if (rv)
		    ui_log("Unable to get sensor reading: 0x%x\n", rv);

		if (ipmi_sensor_get_threshold_access(sensor)
		    != IPMI_THRESHOLD_ACCESS_SUPPORT_NONE)
		{
		    rv = ipmi_thresholds_get(sensor, read_thresholds, NULL);
		    if (rv)
			ui_log("Unable to get threshold values: 0x%x\n", rv);
		}
	    
		if (ipmi_sensor_get_event_support(sensor)
		    != IPMI_EVENT_SUPPORT_NONE)
		{
		    rv = ipmi_sensor_events_enable_get(
			sensor,
			read_thresh_event_enables,
			NULL);
		    if (rv)
			ui_log("Unable to get event values: 0x%x\n", rv);
		}
	    }
	} else {
	    int val;
	    int i;

	    /* A discrete sensor. */
	    wprintw(display_pad, "\n  Assertion: ");
	    wprintw(display_pad, "\n    available: ");
	    getyx(display_pad, discr_assert_avail.y, discr_assert_avail.x);
	    for (i=0; i<15; i++) {
		ipmi_sensor_discrete_assertion_event_supported(sensor,
							       i,
							       &val);
		wprintw(display_pad, "%d", val != 0);
	    }
	    wprintw(display_pad, "\n      enabled: ");
	    getyx(display_pad, discr_assert_enab.y, discr_assert_enab.x);
	    wprintw(display_pad, "\n  Deasertion: ");
	    wprintw(display_pad, "\n    available: ");
	    getyx(display_pad, discr_deassert_avail.y, discr_deassert_avail.x);
	    for (i=0; i<15; i++) {
		ipmi_sensor_discrete_deassertion_event_supported(sensor,
								 i,
								 &val);
		wprintw(display_pad, "%d", val != 0);
	    }
	    wprintw(display_pad, "\n      enabled: ");
	    getyx(display_pad, discr_deassert_enab.y, discr_deassert_enab.x);

	    if (present) {
		rv = ipmi_states_get(sensor, read_states, NULL);
		if (rv)
		    ui_log("Unable to get sensor reading: 0x%x\n", rv);

		if (ipmi_sensor_get_event_support(sensor)
		    != IPMI_EVENT_SUPPORT_NONE)
		{
		    rv = ipmi_sensor_events_enable_get(
			sensor,
			read_discrete_event_enables,
			NULL);
		    if (rv)
			ui_log("Unable to get event values: 0x%x\n", rv);
		}
	    }
	}

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
	waddstr(cmd_win, "Invalid sensor given\n");
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
	wprintw(cmd_win, "Sensor %d.%d.%s not found\n",
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
    wprintw(display_pad, "  %d.%d.%s - %s\n", id, instance, name2, name);
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
    werase(display_pad);
    wmove(display_pad, 0, 0);
    wprintw(display_pad, "Controls for entity %d.%d:\n", id, instance);
    ipmi_entity_iterate_controls(entity, controls_handler, NULL);
    display_pad_refresh();
}

static int
controls_cmd(char *cmd, char **toks, void *cb_data)
{
    entity_finder(cmd, toks, found_entity_for_controls, NULL);
    return 0;
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

    if (err) {
	wmove(display_pad, value_pos.y, value_pos.x);
	wprintw(display_pad, "?");
    } else {
	for (i=0; i<num_vals; i++) {
	    wmove(display_pad, value_pos.y+i, value_pos.x);
	    wprintw(display_pad, "%d (0x%x)", val[i], val[i]);
	}
    }
    display_pad_refresh();
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

    if (err) {
	wmove(display_pad, value_pos.y, value_pos.x);
	wprintw(display_pad, "?");
    } else {
	for (i=0; i<length; i++) {
	    wmove(display_pad, value_pos.y+i, value_pos.x);
	    wprintw(display_pad, "0x%2.2x", val[i]);
	}
    }
    display_pad_refresh();
}

static void
redisplay_control(ipmi_control_t *control, void *cb_data)
{
    int           control_type;
    ipmi_entity_t *entity;

    entity = ipmi_control_get_entity(control);
    if (!entity)
	return;

    if (!ipmi_entity_is_present(entity)) {
	wmove(display_pad, value_pos.y, value_pos.x);
	wprintw(display_pad, "not present");
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
    int id, instance;
    char name[33];
    struct control_info *iinfo = cb_data;
    int control_type;
    int num_vals;


    ipmi_control_get_id(control, name, 33);
    if (strcmp(name, iinfo->name) == 0) {
	iinfo->found = 1;
	curr_display_type = DISPLAY_CONTROL;

	id = ipmi_entity_get_entity_id(entity);
	instance = ipmi_entity_get_entity_instance(entity);
	curr_control_id = ipmi_control_convert_to_id(control);

	werase(display_pad);
	wmove(display_pad, 0, 0);

	conv_from_spaces(name);
	wprintw(display_pad, "Control %d.%d.%s - %s:\n",
		id, instance, name, iinfo->name);
	control_type = ipmi_control_get_type(control);
	wprintw(display_pad, "  type = %s (%d)\n",
		ipmi_control_get_type_string(control), control_type);
	num_vals = ipmi_control_get_num_vals(control);
	switch (control_type) {
	case IPMI_CONTROL_LIGHT:
	case IPMI_CONTROL_RELAY:
	case IPMI_CONTROL_ALARM:
	case IPMI_CONTROL_RESET:
	case IPMI_CONTROL_POWER:
	case IPMI_CONTROL_FAN_SPEED:
	    wprintw(display_pad, "  num entities = %d\n", num_vals);
	    break;

	case IPMI_CONTROL_DISPLAY:
	case IPMI_CONTROL_IDENTIFIER:
	    break;
	}
	wprintw(display_pad, "  value = ");
	getyx(display_pad, value_pos.y, value_pos.x);

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

	display_pad_refresh();
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
	waddstr(cmd_win, "Invalid control given\n");
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
	wprintw(cmd_win, "Control %d.%d.%s not found\n",
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

int
enable_cmd(char *cmd, char **toks, void *cb_data)
{
    return 0;
}

void mcs_handler(ipmi_mc_t *bmc,
		 ipmi_mc_t *mc,
		 void      *cb_data)
{
    int addr;

    addr = ipmi_mc_get_address(mc);
    wprintw(display_pad, "  0x%x\n", addr);
}

int
mcs_cmd(char *cmd, char **toks, void *cb_data)
{
    if (!bmc) {
	waddstr(cmd_win, "BMC has not finished setup yet\n");
	return 0;
    }

    werase(display_pad);
    wmove(display_pad, 0, 0);
    curr_display_type = DISPLAY_MCS;
    waddstr(display_pad, "MCs:\n");
    waddstr(display_pad, "  0x20\n");
    ipmi_bmc_iterate_mcs(bmc, mcs_handler, NULL);
    display_pad_refresh();
    return 0;
}

#define MCCMD_DATA_SIZE 30
typedef struct mccmd_info_s
{
    unsigned char addr;
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

    werase(display_pad);
    wmove(display_pad, 0, 0);
    curr_display_type = DISPLAY_RSP;
    waddstr(display_pad, "Response:\n");
    wprintw(display_pad, "  NetFN = 0x%2.2x\n", msg->netfn);
    wprintw(display_pad, "  Command = 0x%2.2x\n", msg->cmd);
    wprintw(display_pad, "  Completion code = 0x%2.2x\n", msg->data[0]);
    wprintw(display_pad, "  data =");
    data = msg->data + 1;
    for (i=0; i<msg->data_len-1; i++) {
	if ((i != 0) && ((i % 8) == 0))
	    waddstr(display_pad, "\n        ");
	wprintw(display_pad, " %2.2x", data[i]);
    }
    waddstr(display_pad, "\n");
    display_pad_refresh();
}

void mccmd_handler(ipmi_mc_t *bmc,
		   ipmi_mc_t *mc,
		   void      *cb_data)
{
    mccmd_info_t *info = cb_data;
    int          rv;

    if (info->addr == ipmi_mc_get_address(mc)) {
	info->found = 1;
	rv = ipmi_send_command(mc, info->lun, &(info->msg), mccmd_rsp_handler,
			       NULL);
	if (rv)
	    wprintw(cmd_win, "Send command failure: %x\n", rv);
    }

}

int
mccmd_cmd(char *cmd, char **toks, void *cb_data)
{
    mccmd_info_t  info;
    unsigned char data[MCCMD_DATA_SIZE];
    unsigned int  data_len;

    if (get_uchar(toks, &info.addr, "MC address"))
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
    ipmi_bmc_iterate_mcs(bmc, mccmd_handler, &info);
    if (!info.found) {
	wprintw(cmd_win, "Unable to find MC at address 0x%x\n", info.addr);
    }
    display_pad_refresh();

    return 0;
}

int
msg_cmd(char *cmd, char **toks, void *cb_data)
{
    unsigned char    data[MCCMD_DATA_SIZE];
    unsigned int     data_len;
    ipmi_ipmb_addr_t addr;
    unsigned int     channel;
    ipmi_msg_t       msg;
    int              rv;
    
    addr.addr_type = IPMI_IPMB_ADDR_TYPE;
    if (get_uint(toks, &channel, "channel"))
	return 0;
    addr.channel = channel;

    if (get_uchar(toks, &addr.slave_addr, "slave address"))
	return 0;

    if (addr.slave_addr == 0) {
	addr.addr_type = IPMI_IPMB_BROADCAST_ADDR_TYPE;
	if (get_uchar(toks, &addr.slave_addr, "slave address"))
	    return 0;
    }

    if (get_uchar(toks, &addr.lun, "LUN"))
	return 0;

    if (get_uchar(toks, &msg.netfn, "NetFN"))
	return 0;

    if (get_uchar(toks, &msg.cmd, "command"))
	return 0;

    for (data_len=0; ; data_len++) {
	if (get_uchar(toks, data+data_len, NULL))
	    break;
    }

    msg.data_len = data_len;
    msg.data = data;

    rv = ipmi_bmc_send_command_addr(bmc, (ipmi_addr_t *) &addr, sizeof(addr),
				    &msg, mccmd_rsp_handler, NULL);
    if (rv)
	wprintw(cmd_win, "Send command failure: %x\n", rv);
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
	    vals = malloc(sizeof(*vals) * num_vals);
	    if (!vals) {
		wprintw(cmd_win, "set_control: out of memory\n");
		goto out;
	    }
	
	    for (i=0; i<num_vals; i++) {
		tok = strtok_r(NULL, " \t\n", toks);
		if (!tok) {
		    wprintw(cmd_win,
			    "set_control: Value %d is not present\n",
			    i);
		    goto out;
		}
		vals[i] = strtol(tok, &estr, 0);
		if (*estr != '\0') {
		    wprintw(cmd_win, "set_control: Value %d is invalid\n", i);
		    goto out;
		}
	    }

	    rv = ipmi_control_set_val(control, vals, NULL, NULL);
	    if (rv) {
		wprintw(cmd_win, "set_control: Returned error 0x%x\n", rv);
	    }
	    break;

	case IPMI_CONTROL_DISPLAY:
	    break;

	case IPMI_CONTROL_IDENTIFIER:
	    num_vals = ipmi_control_identifier_get_max_length(control);
	    cvals = malloc(sizeof(*cvals) * num_vals);
	    if (!cvals) {
		wprintw(cmd_win, "set_control: out of memory\n");
		goto out;
	    }
	
	    for (i=0; i<num_vals; i++) {
		tok = strtok_r(NULL, " \t\n", toks);
		if (!tok) {
		    wprintw(cmd_win,
			    "set_control: Value %d is not present\n",
			    i);
		    goto out;
		}
		cvals[i] = strtol(tok, &estr, 0);
		if (*estr != '\0') {
		    wprintw(cmd_win, "set_control: Value %d is invalid\n", i);
		    goto out;
		}
	    }

	    rv = ipmi_control_identifier_set_val(control, cvals, num_vals,
						 NULL, NULL);
	    if (rv) {
		wprintw(cmd_win, "set_control: Returned error 0x%x\n", rv);
	    }
	    break;
	}
 out:
}

static int
set_control_cmd(char *cmd, char **toks, void *cb_data)
{
    int rv;

    if (curr_display_type != DISPLAY_CONTROL) {
	wprintw(cmd_win, "The current displayed item is not a control\n");
	goto out;
    }

    rv = ipmi_control_pointer_cb(curr_control_id, set_control, toks);
    if (rv)
	wprintw(cmd_win,
		"set_control: Unable to get control pointer: 0x%x\n",
		rv);

 out:
    return 0;
}

static void
dellog_cb(ipmi_mc_t *bmc, int err, void *cb_data)
{
    if (err)
	ui_log("Error deleting log: %x\n", err);
    else
	ui_log("log deleted\n");
}

static int
dellog_cmd(char *cmd, char **toks, void *cb_data)
{
    unsigned int record_id;
    int          rv;

    if (!bmc) {
	waddstr(cmd_win, "BMC has not finished setup yet\n");
	return 0;
    }

    if (get_uint(toks, &record_id, "record id"))
	return 0;

    rv = ipmi_bmc_del_log_by_recid(bmc, record_id, dellog_cb, NULL);
    if (rv)
	wprintw(cmd_win, "dellog_cmd: error deleting log: %x\n", rv);

    return 0;
}

static int
debug_cmd(char *cmd, char **toks, void *cb_data)
{
    char         *type;
    char         *on_off;
    int          val;
    unsigned int mask;

    type = strtok_r(NULL, " \t\n", toks);
    if (!type) {
	wprintw(cmd_win, "No debug type specified\n");
	goto out;
    }

    on_off = strtok_r(NULL, " \t\n", toks);
    if (!on_off) {
	wprintw(cmd_win, "on or off not specified\n");
	goto out;
    } else if (strcmp(on_off, "on") == 0) {
	val = 1;
    } else if (strcmp(on_off, "off") == 0) {
	val = 0;
    } else {
	wprintw(cmd_win, "on or off not specified, got '%s'\n", on_off);
	goto out;
    }

    if (strcmp(type, "msg") == 0) {
	mask = DEBUG_MSG_BIT;
    } else {
	wprintw(cmd_win, "Invalid debug type specified: '%s'\n", type);
	goto out;
    }

    if (val)
	__ipmi_log_mask |= mask;
    else
	__ipmi_log_mask &= ~mask;
 out:
    return 0;
}

static struct {
    char          *name;
    cmd_handler_t handler;
} cmd_list[] =
{
    { "entities",			entities_cmd },
    { "sensors",			sensors_cmd },
    { "sensor",				sensor_cmd },
    { "enable",				enable_cmd },
    { "controls",			controls_cmd },
    { "control",			control_cmd },
    { "set_control",			set_control_cmd },
    { "mcs",				mcs_cmd },
    { "mccmd",				mccmd_cmd },
    { "msg",				msg_cmd },
    { "dellog",				dellog_cmd },
    { "debug",				debug_cmd },
    { NULL,				NULL}
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
	err = keypad_bind_key(keymap, 4, key_leave);
    if (!err)
	err = keypad_bind_key(keymap, 10, end_of_line);
    if (!err)
	err = keypad_bind_key(keymap, KEY_RESIZE, key_resize);
    if (!err)
	err = keypad_bind_key(keymap, KEY_F(1), key_set_display);
    if (!err)
	err = keypad_bind_key(keymap, KEY_F(2), key_set_log);

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

    waddstr(display_pad, "Welcome to the IPMI UI");

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

    waddstr(cmd_win, "> ");
    wrefresh(cmd_win);

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
			       int                         value_present,
			       double                      value,
			       void                        *cb_data)
{
    int  id, instance, lun, num;
    char name[33];

    id = ipmi_sensor_get_entity_id(sensor);
    instance = ipmi_sensor_get_entity_instance(sensor);
    ipmi_sensor_get_num(sensor, &lun, &num);
    ipmi_sensor_get_id(sensor, name, 33);
    ui_log("Sensor %d.%d.%d.%d - %s: %s %s %s\n",
	   id, instance, lun, num, name,
	   ipmi_get_threshold_string(threshold),
	   ipmi_get_value_dir_string(high_low),
	   ipmi_get_event_dir_string(dir));
    if (value_present) {
	ui_log("  value is %f\n", value);
    }
}

static void
sensor_discrete_event_handler(ipmi_sensor_t         *sensor,
			      enum ipmi_event_dir_e dir,
			      int                   offset,
			      int                   severity_present,
			      int                   severity,
			      int		    prev_severity_present,
			      int                   prev_severity,
			      void                  *cb_data)
{
    int  id, instance, lun, num;
    char name[33];

    id = ipmi_sensor_get_entity_id(sensor);
    instance = ipmi_sensor_get_entity_instance(sensor);
    ipmi_sensor_get_num(sensor, &lun, &num);
    ipmi_sensor_get_id(sensor, name, 33);
    ui_log("Sensor %d.%d.%d.%d - %s: %d %s\n",
	   id, instance, lun, num, name,
	   offset,
	   ipmi_get_event_dir_string(dir));
    if (severity_present)
	ui_log("  severity is %d\n", severity);
    if (prev_severity_present)
	ui_log("  prev severity is %d\n", prev_severity);
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
	case ADDED:
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
	case DELETED:
	    ui_log("Sensor deleted: %d.%d.%s (%s)\n",
		   id, instance, name2, name);
	    break;
	case CHANGED:
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
	case ADDED:
	    ui_log("Control added: %d.%d.%s (%s)\n",
		   id, instance, name2, name);
	    break;
	case DELETED:
	    ui_log("Control deleted: %d.%d.%s (%s)\n",
		   id, instance, name2, name);
	    break;
	case CHANGED:
	    ui_log("Control changed: %d.%d.%s (%s)\n",
		   id, instance, name2, name);
	    break;
    }
}

static void
entity_presence_handler(ipmi_entity_t *entity,
			int           present,
			void          *cb_data)
{
    int id, instance;

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    ui_log("Entity %d.%d, presence is %d\n", id, instance, present);
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
	case ADDED:
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
	case DELETED:
	    ui_log("Entity deleted: %d.%d\n", id, instance);
	    break;
	case CHANGED:
	    ui_log("Entity changed: %d.%d\n", id, instance);
	    break;
    }
}

static ipmi_event_handler_id_t *event_handler_id;

static void
event_handler(ipmi_mc_t  *bmc,
	      ipmi_log_t *log,
	      void       *event_data)
{
    /* FIXME - fill this out. */
    ui_log("Unknown event\n");
    ui_log("  %4.4x:%2.2x: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x"
	   " %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
	   log->record_id, log->type,
	   log->data[0],
	   log->data[1],
	   log->data[2],
	   log->data[3],
	   log->data[4],
	   log->data[5],
	   log->data[6],
	   log->data[7],
	   log->data[8],
	   log->data[9],
	   log->data[10],
	   log->data[11],
	   log->data[12]);
}

sel_timer_t *redisplay_timer;

static void
redisplay_timeout(selector_t  *sel,
		  sel_timer_t *timer,
		  void        *data)
{
    struct timeval now;
    int            rv;

    if (curr_display_type == DISPLAY_SENSOR) {
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

    bmc = mc;

    ui_log("Completed setup for the IPMI connection\n");

    rv = ipmi_register_for_events(bmc, event_handler, NULL, &event_handler_id);
    if (rv)
	leave_err(rv, "ipmi_register_for_events");

    rv = ipmi_bmc_enable_events(bmc);
    if (rv)
	leave_err(rv, "ipmi_bmc_enable_events");

    rv = ipmi_bmc_set_entity_update_handler(mc, entity_change, mc);
    if (rv)
	leave_err(rv, "ipmi_bmc_set_entity_update_handler");
}

int
ipmi_ui_init(selector_t **selector)
{
    int rv;

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

    rv = init_win();

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
