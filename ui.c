
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

WINDOW *main_win;
WINDOW *cmd_win;
WINDOW *stat_win;
WINDOW *log_pad;
WINDOW *dummy_pad;
WINDOW *display_win;

selector_t *ui_sel;

int log_pad_top_line;

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

#define LOG_WIN_LINES (LINES - STATUS_WIN_LINES - CMD_WIN_LINES - 2)
#define LOG_WIN_COLS (COLS-(COLS/2))
#define LOG_WIN_LEFT (COLS/2)
#define LOG_WIN_RIGHT (COLS-1)
#define LOG_WIN_TOP (STATUS_WIN_LINES+1)
#define LOG_WIN_BOTTOM (LINES-7)
#define NUM_LOG_LINES 1024

#define TOP_LINE    STATUS_WIN_LINES
#define BOTTOM_LINE (LINES-CMD_WIN_LINES-1)
#define MID_COL (COLS/2-1)
#define MID_LINES (LINES - STATUS_WIN_LINES - CMD_WIN_LINES - 2)

void
log_pad_refresh(int newlines)
{
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
}

void
draw_lines()
{
    werase(main_win);
    wmove(main_win, TOP_LINE, 0);
    whline(main_win, 0, COLS);
    wmove(main_win, BOTTOM_LINE, 0);
    whline(main_win, 0, COLS);
    wmove(main_win, TOP_LINE+1, MID_COL);
    wvline(main_win, 0, MID_LINES);
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

    mvwin(display_win, DISPLAY_WIN_TOP, DISPLAY_WIN_LEFT);
    wresize(display_win, DISPLAY_WIN_LINES, DISPLAY_WIN_COLS);
    wrefresh(display_win);
    touchwin(display_win);

    mvwin(cmd_win, CMD_WIN_TOP, CMD_WIN_LEFT);
    wresize(cmd_win, CMD_WIN_LINES, CMD_WIN_COLS);
    wrefresh(cmd_win);
    touchwin(cmd_win);

    wresize(log_pad, NUM_LOG_LINES, LOG_WIN_COLS);
    wresize(dummy_pad, NUM_LOG_LINES, LOG_WIN_COLS);

    doupdate();

    log_pad_refresh(0);
}

void
user_input_ready(int fd, void *data)
{
    int c;

    c = wgetch(cmd_win);
    while (c != ERR) {
	if (c == 4)
	    leave(0, "");

	if (c == KEY_NPAGE)
	{
	    log_pad_top_line += (LOG_WIN_LINES-1);
	    if (log_pad_top_line > NUM_LOG_LINES - LOG_WIN_LINES)
		log_pad_top_line = NUM_LOG_LINES - LOG_WIN_LINES;
	    log_pad_refresh(0);
	} else if (c == KEY_PPAGE) {
	    log_pad_top_line -= (LOG_WIN_LINES-1);
	    if (log_pad_top_line < 0)
		log_pad_top_line = 0;
	    log_pad_refresh(0);
	} else if (c == KEY_RESIZE) {
	    ui_log("Got resize, lines=%d, cols=%d\n", LINES, COLS);
	    recalc_windows();
	} else if (c > 0xff) {
	    ui_log("Got char 0x%x 0%o (%d)\n", c, c, c);
	    goto next_char;
	} else {
	    waddch(cmd_win, c);
	    if (c == '\n')
		waddstr(cmd_win, "> ");
	}

    next_char:
	c = wgetch(cmd_win);
    }
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

    display_win = newwin(DISPLAY_WIN_LINES, DISPLAY_WIN_COLS,
			 DISPLAY_WIN_TOP, DISPLAY_WIN_LEFT);
    if (!display_win)
	leave(1, "Could not allocate display window\n");

    log_pad = newpad(NUM_LOG_LINES, LOG_WIN_COLS-2);
    if (!log_pad)
	leave(1, "Could not allocate log window\n");
    scrollok(log_pad, TRUE);
    wmove(log_pad, NUM_LOG_LINES-1, 0);
    log_pad_top_line = NUM_LOG_LINES-LOG_WIN_LINES;

    dummy_pad = newpad(NUM_LOG_LINES, LOG_WIN_COLS-2);
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
sensor_change(enum ipmi_update_e op,
	      ipmi_entity_t      *ent,
	      ipmi_sensor_t      *sensor,
	      void               *cb_data)
{
    int id, instance;
    int lun, num;
    char name[33];

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_num(sensor, &lun, &num);
    switch (op) {
	case ADDED:
	    ipmi_sensor_get_id(sensor, name, 33);
	    ui_log("Sensor added: %d.%d.%d.%d (%s)\n",
		   id, instance, lun, num, name);
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

void
setup_done(ipmi_mc_t *mc,
	   void      *user_data,
	   int       err)
{
    int             rv;


    if (err)
	leave_err(err, "Could not set up IPMI connection");

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

    init_win();

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

    sel_select_loop(ui_sel);
    leave(0, "");

    return 0;
}
