
#include <stdio.h>
#include <stdlib.h>
#include <curses.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <ipmi/selector.h>
#include <ipmi/ipmi_smi.h>
#include <ipmi/ipmi_lan.h>
#include <ipmi/ipmi_auth.h>
#include <ipmi/ipmi_err.h>
#include <ipmi/ipmiif.h>

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

extern os_handler_t ui_ipmi_cb_handlers;


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
    DISPLAY_NONE, DISPLAY_SENSOR, DISPLAY_ENTITY, DISPLAY_SENSORS
} curr_display_type;
ipmi_sensor_id_t curr_sensor_id;
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

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    curr_display_type = DISPLAY_ENTITY;
    curr_entity_id = ipmi_entity_convert_to_id(entity);
    if (ipmi_entity_is_present(entity))
	present = "present";
    else
	present = "not present";
    wprintw(display_pad, "  %d.%d %s\n", id, instance, present);
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
    waddstr(display_pad, "Entities:\n");
    ipmi_bmc_iterate_entities(bmc, entities_handler, NULL);
    display_pad_refresh();
    return 0;
}

struct ent_rec {
    int id, instance, found;
    void (*handler)(ipmi_entity_t *entity, void *cb_data);
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
	curr_display_type = DISPLAY_SENSORS;
	info->found = 1;
	info->handler(entity, info->cb_data);
    }
}

static void
sensors_handler(ipmi_entity_t *entity, ipmi_sensor_t *sensor, void *cb_data)
{
    int id, instance;
    int lun, num;
    char name[33];

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    ipmi_sensor_get_num(sensor, &lun, &num);
    ipmi_sensor_get_id(sensor, name, 33);
    wprintw(display_pad, "  %d.%d.%d.%d - %s\n", id, instance, lun, num, name);
}

static void
found_entity_for_sensors(ipmi_entity_t *entity,
			 void          *cb_data)
{
    int    id, instance;

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
    struct ent_rec info;
    char           *ent_name;
    char           *id_name, *instance_name, *toks2;

    if (!bmc) {
	waddstr(cmd_win, "BMC has not finished setup yet\n");
	return 0;
    }

    ent_name = strtok_r(NULL, " \t\n", toks);
    if (!ent_name) {
	waddstr(cmd_win, "No entity given\n");
	return 0;
    }

    id_name = strtok_r(ent_name, ".", &toks2);
    instance_name = strtok_r(NULL, "", &toks2);
    if (!instance_name) {
	waddstr(cmd_win, "Invalid entity given\n");
	return 0;
    }
    info.id = strtoul(id_name, &toks2, 0);
    if (*toks2 != '\0') {
	waddstr(cmd_win, "Invalid entity id given\n");
	return 0;
    }
    info.instance = strtoul(instance_name, &toks2, 0);
    if (*toks2 != '\0') {
	waddstr(cmd_win, "Invalid entity instance given\n");
	return 0;
    }
    info.found = 0;

    info.handler = found_entity_for_sensors;
    info.cb_data = &info;

    ipmi_bmc_iterate_entities(bmc, entity_searcher, &info);
    if (!info.found) {
	wprintw(cmd_win, "Entity %d.%d not found\n", info.id, info.instance);
	return 0;
    }

    return 0;
}

struct sensor_info {
    int lun, num, found;
};

static void
read_sensor(ipmi_sensor_t *sensor,
	    int           err,
	    int           val_present,
	    double        val,
	    ipmi_states_t states,
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
			  ipmi_event_state_t states,
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
	    if (ipmi_is_threshold_event_set(&states, t,
					    IPMI_GOING_LOW,
					    IPMI_ASSERTION))
		wprintw(display_pad, "L^");
	    else
		wprintw(display_pad, "  ");
	    if (ipmi_is_threshold_event_set(&states, t,
					    IPMI_GOING_LOW,
					    IPMI_DEASSERTION))
		wprintw(display_pad, "Lv");
	    else
		wprintw(display_pad, "  ");
	    if (ipmi_is_threshold_event_set(&states, t,
					    IPMI_GOING_HIGH,
					    IPMI_ASSERTION))
		wprintw(display_pad, "H^");
	    else
		wprintw(display_pad, "  ");
	    if (ipmi_is_threshold_event_set(&states, t,
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
			    ipmi_event_state_t states,
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
	    val = ipmi_is_discrete_event_set(&states, i, IPMI_ASSERTION);
	    wprintw(display_pad, "%d", val != 0);
	}    
	wmove(display_pad, discr_deassert_enab.y, discr_deassert_enab.x);
	for (i=0; i<15; i++) {
	    val = ipmi_is_discrete_event_set(&states, i, IPMI_DEASSERTION);
	    wprintw(display_pad, "%d", val != 0);
	}    
    }

 out:
    display_pad_refresh();
}

static void
read_states(ipmi_sensor_t *sensor,
	    int           err,
	    ipmi_states_t states,
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
	    val = ipmi_is_state_set(&states, i);
	    wprintw(display_pad, "%d", val != 0);
	}    
    }
    display_pad_refresh();
}

static void
redisplay_sensor(ipmi_sensor_t *sensor, void *cb_data)
{
    int rv;

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
    }

    gettimeofday(&now, NULL);
    now.tv_sec += 1;
    rv = sel_start_timer(timer, &now);
    if (rv)
	ui_log("Unable to restart redisplay timer: 0x%x\n", rv);
}

static void
sensor_handler(ipmi_entity_t *entity, ipmi_sensor_t *sensor, void *cb_data)
{
    int id, instance;
    int lun, num;
    char name[33];
    struct sensor_info *sinfo = cb_data;
    int rv;

    ipmi_sensor_get_num(sensor, &lun, &num);
    if ((lun == sinfo->lun) && (num == sinfo->num)) {
	sinfo->found = 1;
	curr_display_type = DISPLAY_SENSOR;
	curr_sensor_id = ipmi_sensor_convert_to_id(sensor);

	id = ipmi_entity_get_entity_id(entity);
	instance = ipmi_entity_get_entity_instance(entity);
	ipmi_sensor_get_id(sensor, name, 33);

	werase(display_pad);
	wmove(display_pad, 0, 0);

	wprintw(display_pad, "Sensor %d.%d.%d.%d - %s:\n",
		id, instance, lun, num, name);
	wprintw(display_pad, "  value = ");
	getyx(display_pad, value_pos.y, value_pos.x);
	wprintw(display_pad, "\n  Events = ");
	getyx(display_pad, enabled_pos.y, enabled_pos.x);
	wprintw(display_pad, "\n  Scanning = ");
	getyx(display_pad, scanning_pos.y, scanning_pos.x);
	wprintw(display_pad, "\n");
	num = ipmi_sensor_get_sensor_type(sensor);
	wprintw(display_pad, "  sensor type = %s (0x%2.2x)\n",
		ipmi_get_sensor_type_string(num), num);
	num = ipmi_sensor_get_event_reading_type(sensor);
	wprintw(display_pad, "  event/reading type = %s (0x%2.2x)\n",
		ipmi_get_event_reading_type_string(num), num);

	if (ipmi_sensor_get_event_reading_type(sensor)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    enum ipmi_thresh_e t;
	    double val;

	    wprintw(display_pad, "  units = %s%s",
		    ipmi_get_unit_type_string(ipmi_sensor_get_base_unit(sensor)),
		    ipmi_get_rate_unit_string(ipmi_sensor_get_rate_unit(sensor)));
	    switch(ipmi_sensor_get_modifier_unit_use(sensor)) {
		case IPMI_MODIFIER_UNIT_BASE_DIV_MOD:
		    wprintw(display_pad, "/%s",
			    ipmi_get_unit_type_string(
				ipmi_sensor_get_modifier_unit(sensor)));
		    break;
		    
		case IPMI_MODIFIER_UNIT_BASE_MULT_MOD:
		    wprintw(display_pad, "*%s",
			    ipmi_get_unit_type_string(
				ipmi_sensor_get_modifier_unit(sensor)));
		    break;
	    }
	    wprintw(display_pad, "\n");

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
		rv = ipmi_sensor_events_enable_get(sensor,
						   read_thresh_event_enables,
						   NULL);
		if (rv)
		    ui_log("Unable to get event values: 0x%x\n", rv);
	    }
	    
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

	    rv = ipmi_states_get(sensor, read_states, NULL);
	    if (rv)
		ui_log("Unable to get sensor reading: 0x%x\n", rv);

	    if (ipmi_sensor_get_event_support(sensor)
		!= IPMI_EVENT_SUPPORT_NONE)
	    {
		rv = ipmi_sensor_events_enable_get(sensor,
						   read_discrete_event_enables,
						   NULL);
		if (rv)
		    ui_log("Unable to get event values: 0x%x\n", rv);
	    }
	}

	display_pad_refresh();
    }
}

static void
found_entity_for_sensor(ipmi_entity_t *entity,
			void          *cb_data)
{
    ipmi_entity_iterate_sensors(entity, sensor_handler, cb_data);
}

int
sensor_cmd(char *cmd, char **toks, void *cb_data)
{
    struct ent_rec     info;
    struct sensor_info sinfo;
    char               *ent_name;
    char               *id_name, *instance_name, *lun_name, *num_name, *toks2;

    if (!bmc) {
	waddstr(cmd_win, "BMC has not finished setup yet\n");
	return 0;
    }

    ent_name = strtok_r(NULL, " \t\n", toks);
    if (!ent_name) {
	waddstr(cmd_win, "No sensor given\n");
	return 0;
    }

    id_name = strtok_r(ent_name, ".", &toks2);
    instance_name = strtok_r(NULL, ".", &toks2);
    if (!instance_name) {
	waddstr(cmd_win, "Invalid sensor given\n");
	return 0;
    }
    lun_name = strtok_r(NULL, ".", &toks2);
    if (!lun_name) {
	waddstr(cmd_win, "Invalid sensor given\n");
	return 0;
    }
    num_name = strtok_r(NULL, "", &toks2);
    if (!num_name) {
	waddstr(cmd_win, "Invalid sensor given\n");
	return 0;
    }

    info.id = strtoul(id_name, &toks2, 0);
    if (*toks2 != '\0') {
	waddstr(cmd_win, "Invalid entity id given\n");
	return 0;
    }
    info.instance = strtoul(instance_name, &toks2, 0);
    if (*toks2 != '\0') {
	waddstr(cmd_win, "Invalid entity instance given\n");
	return 0;
    }
    sinfo.lun = strtoul(lun_name, &toks2, 0);
    if (*toks2 != '\0') {
	waddstr(cmd_win, "Invalid sensor lun given\n");
	return 0;
    }
    sinfo.num = strtoul(num_name, &toks2, 0);
    if (*toks2 != '\0') {
	waddstr(cmd_win, "Invalid sensor num given\n");
	return 0;
    }
    info.found = 0;
    sinfo.found = 0;

    info.handler = found_entity_for_sensor;
    info.cb_data = &sinfo;

    ipmi_bmc_iterate_entities(bmc, entity_searcher, &info);
    if (!info.found) {
	wprintw(cmd_win, "Entity %d.%d not found\n", info.id, info.instance);
	return 0;
    }
    if (!sinfo.found) {
	wprintw(cmd_win, "Sensor %d.%d.%d.%d not found\n",
		info.id, info.instance, sinfo.lun, sinfo.num);
	return 0;
    }

    return 0;
}

int
enable_cmd(char *cmd, char **toks, void *cb_data)
{
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
    int lun, num;
    char name[33];
    int rv;

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_num(sensor, &lun, &num);
    switch (op) {
	case ADDED:
	    ipmi_sensor_get_id(sensor, name, 33);
	    ui_log("Sensor added: %d.%d.%d.%d (%s)\n",
		   id, instance, lun, num, name);
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
	    ipmi_sensor_get_id(sensor, name, 33);
	    ui_log("Sensor deleted: %d.%d.%d.%d (%s)\n",
		   id, instance, lun, num, name);
	    break;
	case CHANGED:
	    ipmi_sensor_get_id(sensor, name, 33);
	    ui_log("Sensor changed: %d.%d.%d.%d (%s)\n",
		   id, instance, lun, num, name);
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
	      ipmi_msg_t *event,
	      void       *event_data)
{
    /* FIXME - fill this out. */
    ui_log("Unknown event\n");
}

void
setup_done(ipmi_mc_t *mc,
	   void      *user_data,
	   int       err)
{
    int             rv;


    if (err)
	leave_err(err, "Could not set up IPMI connection");

    bmc = mc;

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
main(int argc, char *argv[])
{
    int            err;
    int            rv;


    if (argc < 2) {
	fprintf(stderr, "Not enough arguments\n");
	exit(1);
    }

    err = sel_alloc_selector(&ui_sel);
    if (err) {
	fprintf(stderr, "Could not allocate selector\n");
	exit(1);
    }

    sel_set_fd_handlers(ui_sel, 0, NULL, user_input_ready, NULL, NULL);
    sel_set_fd_read_handler(ui_sel, 0, SEL_FD_HANDLER_ENABLED);

    err = init_commands();
    if (err) {
	fprintf(stderr, "Could not initialize commands\n");
	exit(1);
    }

    err = init_keypad();
    if (err) {
	fprintf(stderr, "Could not initialize keymap\n");
	exit(1);
    }

    err = init_win();

    ipmi_init(&ui_ipmi_cb_handlers);

    if (strcmp(argv[1], "smi") == 0) {
	int smi_intf;

	if (argc < 3)
	    leave(1, "Not enough arguments\n");

	smi_intf = atoi(argv[2]);
	rv = ipmi_smi_setup_con(smi_intf,
				&ui_ipmi_cb_handlers, ui_sel,
				setup_done, NULL);
	if (rv)
	    leave_err(rv, "ipmi_smi_setup_con");

    } else if (strcmp(argv[1], "lan") == 0) {
	struct hostent *ent;
	struct in_addr lan_addr;
	int            lan_port;
	int            authtype = 0;
	int            privilege = 0;
	char           username[17];
	char           password[17];

	if (argc < 8)
	    leave(1, "Not enough arguments\n");

	ent = gethostbyname(argv[2]);
	if (!ent)
	    leave(1, "gethostbyname failed: %s\n", strerror(h_errno));

	memcpy(&lan_addr, ent->h_addr_list[0], ent->h_length);
	lan_port = atoi(argv[3]);

	if (strcmp(argv[4], "none") == 0) {
	    authtype = IPMI_AUTHTYPE_NONE;
	} else if (strcmp(argv[4], "md2") == 0) {
	    authtype = IPMI_AUTHTYPE_MD2;
	} else if (strcmp(argv[4], "md5") == 0) {
	    authtype = IPMI_AUTHTYPE_MD5;
	} else if (strcmp(argv[4], "straight") == 0) {
	    authtype = IPMI_AUTHTYPE_STRAIGHT;
	} else {
	    leave(1, "Invalid authtype: %s\n", argv[4]);
	}

	if (strcmp(argv[5], "callback") == 0) {
	    privilege = IPMI_PRIVILEGE_CALLBACK;
	} else if (strcmp(argv[5], "user") == 0) {
	    privilege = IPMI_PRIVILEGE_USER;
	} else if (strcmp(argv[5], "operator") == 0) {
	    privilege = IPMI_PRIVILEGE_OPERATOR;
	} else if (strcmp(argv[5], "admin") == 0) {
	    privilege = IPMI_PRIVILEGE_ADMIN;
	} else {
	    leave(1, "Invalid privilege: %s\n", argv[5]);
	}

	memset(username, 0, sizeof(username));
	memset(password, 0, sizeof(password));
	strncpy(username, argv[6], 16);
	username[16] = '\0';
	strncpy(password, argv[7], 16);
	password[16] = '\0';

	rv = ipmi_lan_setup_con(lan_addr, lan_port,
				authtype, privilege,
				username, strlen(username),
				password, strlen(password),
				&ui_ipmi_cb_handlers, ui_sel,
				setup_done, NULL);
	if (rv) {
	    leave_err(rv, "ipmi_lan_setup_con");
	}
    } else {
	leave(1, "Invalid mode\n");
    }

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

    sel_select_loop(ui_sel);
    leave(0, "");

    return 0;
}
