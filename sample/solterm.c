/*
 * solterm.c
 *
 * IPMI Serial-over-LAN Terminal application
 *
 * Author: Cyclades Australia Pty. Ltd.
 *         Darius Davis <dariusd@users.sourceforge.net>
 *
 * Copyright 2005 Cyclades Australia Pty. Ltd.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_posix.h>

#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/ipmi_sol.h>
#include <OpenIPMI/ipmi_debug.h>


#undef USE_SUSPEND

/*
 * Usage:
 *
 *	solterm -U username -P password [-Ra auth] [-Ri integ] [-Rc conf] hostname [-e escape_char]
 *		[-notencrypted] [-notauthenticated] [-bitrate (9600|19200|38400|57600|115200)]
 *		[-alerts (succeed|defer|fail)] [-holdoff] [-v] [-q]
 *
 *	-Ra auth	Specify authentication algorithm to use.
 *	-Ri integ	Specify integrity algorithm to use.
 *	-Rc conf	Specify confidentiality algorithm to use.
 *	-e escape_char	The escape character to use (Default: ~).
 *	-notencrypted	Specify that SoL packets should not be encrypted.
 *	-notauthenticated Specify that SoL packets should not be authenticated.
 *	-bitrate xxx	Specify bit rate to use.  BMCs are not required to
 *			support all bit rates.  Make sure this matches the bit
 *			rate at which the baseboard is communicating!
 *	-alerts succeed	Specify that serial/modem alerts are to succeed while SoL is active.
 *	-alerts deferred	Serial/modem alerts are to be deferred for the duration of the SoL session.
 *	-alerts fail	Serial/modem alerts automatically fail during the SoL session.
 *	-holdoff	Specifies that CTS, DTR and DSR are to be deasserted at the start of the SoL session,
 *			so that the configuration may be modified before the handshake is released.
 */


typedef enum {
	condition_running,
	condition_exiting,
	condition_exit_now
} exit_condition_t;

typedef enum {
	escape_waiting_for_CR,
	escape_waiting_for_escape,
	escape_next
} escape_status_t;

char			escape_char = '~';
escape_status_t		escape_status = escape_waiting_for_escape;

struct termios orig_attr;
static const char *progname;

exit_condition_t	exit_condition;
ipmi_sol_conn_t		*active_connection = NULL;
int			connection_up = 0;
int verbosity;

#define INITIAL_VERBOSITY 10

typedef struct {
	int authenticated, encrypted;
	int bit_rate;
	ipmi_sol_serial_alert_behavior alert_behavior;
	int holdoff;
	int ACK_timeout_usec;
	int ACK_retries;
} sol_configuration_t;



static void
my_vlog(os_handler_t *handler, const char *format,
	enum ipmi_log_type_e log_type, va_list ap)
{
    int do_nl = 1;

    switch(log_type)
    {
	case IPMI_LOG_INFO:
		if (verbosity < 3) return;
	    printf("INFO: ");
	    break;

	case IPMI_LOG_WARNING:
		if (verbosity < 1) return;
	    printf("WARN: ");
	    break;

	case IPMI_LOG_SEVERE:
	    printf("SEVR: ");
	    break;

	case IPMI_LOG_FATAL:
	    printf("FATL: ");
	    break;

	case IPMI_LOG_ERR_INFO:
		if (verbosity < 2) return;
	    printf("EINF: ");
	    break;

	case IPMI_LOG_DEBUG_START:
		if (verbosity < 2) return;
	    do_nl = 0;
	    /* FALLTHROUGH */
	case IPMI_LOG_DEBUG:
		if (verbosity < 2) return;
	    printf("DEBG: ");
	    break;

	case IPMI_LOG_DEBUG_CONT:
		if (verbosity < 2) return;
	    do_nl = 0;
	    /* FALLTHROUGH */
	case IPMI_LOG_DEBUG_END:
		if (verbosity < 2) return;
	    break;
    }

    vprintf(format, ap);

    if (do_nl)
	printf("\n");
}

void con_usage(const char *name, const char *help, void *cb_data)
{
    if (strcmp(name, "lan") != 0)
	/* Only supports LAN. */
	return;
    printf("\n%s%s\n", name, help);
}

static void
usage(void)
{
    printf("Usage:\n"
	   "  %s <conparms>\n"
"	[-e escape_char] [-notencrypted] [-notauthenticated]\n"
"	[-bitrate (9600|19200|38400|57600|115200)]\n"
"	[-alerts (succeed|defer|fail)] [-holdoff] [-ack-retries n]\n"
"	[-ack-timeout usec] [-v] [-q]\n\n"
"-e escape_char	The escape character to use.  Default is ~.\n"
"-notencrypted	Specify that SoL packets should not be encrypted.\n"
"-notauthenticated Specify that SoL packets should not be authenticated.\n"
"-bitrate xxx	Specify bit rate to use.  BMCs are not required to support all\n"
"		bit rates.  Make sure this matches the bit rate at which the\n"
"		baseboard is communicating!  Defaults to the BMC's configured\n"
"		nonvolatile bit rate.\n"
"-alerts succeed  Specify that serial/modem alerts are to succeed while\n"
"               SoL is active.\n"
"-alerts deferred  Serial/modem alerts are to be deferred for the duration\n"
"               of the SoL session.\n"
"-alerts fail	Serial/modem alerts automatically fail during the SoL session.\n"
"               This is the default.\n"
"-holdoff	Specifies that CTS, DTR and DSR are to be deasserted at the\n"
"               start of the SoL session,so that the configuration may be\n"
"               modified before the handshake is released.\n"
"-v		Be more verbose.  May be specified multiple times.\n"
"-q		Be quieter.  Opposite of -v.\n"
"\n<conparms> specified connection parameters for solterm.  Note that only\n"
"lan connection are supported for solterm.  These parms are:\n", progname);
    ipmi_parse_args_iter_help(con_usage, NULL);
}

static void show_buffer_text(const void *data, size_t count)
{
	unsigned int i;

	printf("[");
	for (i = 0; i < count; ++i)
	{
		char c = ((unsigned char *)data)[i];
		if (isprint(c))
			putchar(c);
		else
			putchar('.');
	}

	printf("]");
	fflush(stdout);
}

static void show_buffer_hex(const void *data, size_t count)
{
	unsigned int i;

	printf("[");
	for (i = 0; i < count; ++i)
		printf("%02x", ((unsigned char *)data)[i]);

	printf("]");
	fflush(stdout);
}

static int data_received(ipmi_sol_conn_t *conn, const void *data, size_t count, void *user_data)
{
	unsigned int i;
	if (verbosity > 3)
		show_buffer_text(data, count);
	if (verbosity > 5)
		show_buffer_hex(data, count);

	for (i = 0; i < count; ++i)
		printf("%c", ((unsigned char *)data)[i]);
	fflush(stdout);
	return 0;
}


static void break_detected(ipmi_sol_conn_t *conn, void *user_data)
{
	tcsendbreak(1, 0);
}

static void bmc_transmit_overrun(ipmi_sol_conn_t *conn, void *user_data)
{
	if (verbosity < 0)
		return;
	fprintf(stderr, "[BMC-BUFFER-OVERRUN]");
	fflush(stderr);
}

/*typedef enum { ipmi_sol_state_closed, ipmi_sol_state_connecting, ipmi_sol_state_connected,
	ipmi_sol_state_connected_ctu, ipmi_sol_state_closing } ipmi_sol_state;*/
char *state_names[5] = {"Closed", "Connecting", "Connected", "Connected (Char Trans Unavail)", "Closing"};


#define ERROR_STRING_LEN 50
static void connection_state(ipmi_sol_conn_t *conn, ipmi_sol_state state, int error, void *cb_data)
{
	char error_string[ERROR_STRING_LEN];

	ipmi_get_error_string(error,
			error_string,
			ERROR_STRING_LEN);

	if ((verbosity > 2) && (state == ipmi_sol_state_closed))
		printf("===============================================================================\n");

	ipmi_log((error ? IPMI_LOG_SEVERE : IPMI_LOG_INFO),
		"Connection state changed: %s; Reason: %s", state_names[state], error_string);

	if ((verbosity > 2) && (state == ipmi_sol_state_connected || state == ipmi_sol_state_connected_ctu))
		printf("===============================================================================\n");

	if ((state == ipmi_sol_state_connected || state == ipmi_sol_state_connected_ctu) && !connection_up)
	{
		if (verbosity >= 0)
		{
			printf("Connected.  Escape character is %c.  %c? for help; %c. to disconnect.\n", escape_char, escape_char, escape_char);
			fflush(stdout);
		}
		connection_up = 1;
	}

	if (state == ipmi_sol_state_closed)
		exit_condition = condition_exit_now;

	fflush(stdout);
}

static void transmit_complete(ipmi_sol_conn_t *conn, int error, void *user_data)
{
	if (!error)
	{
		if (verbosity > 5)
		{
			printf("[TC]");
			fflush(stdout);
		}
		return;
	}

	if (IPMI_IS_SOL_ERR(error) && (IPMI_GET_SOL_ERR(error) == IPMI_SOL_UNCONFIRMABLE_OPERATION))
	{
		if (verbosity > 1)
			fprintf(stderr, "[Unconfirmable]");
	}
	else
	{
		/*
		 * Transmission failed
		 */
		char buf[50];
		fprintf(stderr, "[Pkt lost: %s]", ipmi_get_error_string(error, buf, 50));
		fflush(stderr);
	}
}

static void flush_complete(ipmi_sol_conn_t *conn, int error, int queues_flushed, void *user_data)
{
	transmit_complete(conn, error, user_data);
}

static void sol_send(const char *text, int count)
{
	int rv;

	if (verbosity > 5)
		show_buffer_hex(text, count);

	rv = ipmi_sol_write(active_connection, text, count, transmit_complete, NULL);

	if (rv)
	{
		char buf[50];
		fprintf(stderr, "[TX err: %s]", ipmi_get_error_string(rv, buf, 50));
	}
}

static void sol_send_break()
{
	int rv = ipmi_sol_send_break(active_connection, transmit_complete, NULL);

	if (rv)
	{
		char buf[50];
		fprintf(stderr, "[TX err: %s]", ipmi_get_error_string(rv, buf, 50));
	}
}

static void sol_do_flush()
{
	int rv = ipmi_sol_flush(active_connection, IPMI_SOL_ALL_QUEUES, flush_complete, NULL);

	if (rv)
	{
		char buf[50];
		fprintf(stderr, "[TX err: %s]", ipmi_get_error_string(rv, buf, 50));
	}
}

static void unconfigure_terminal()
{
	tcsetattr(STDIN_FILENO, TCSANOW, &orig_attr);
	signal(SIGINT, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
}
	
static void signal_handler(int signal)
{
	unconfigure_terminal();
	exit(1);
}

static void configure_terminal()
{
	struct termios attr;
	tcgetattr(STDIN_FILENO, &attr);
	tcgetattr(STDIN_FILENO, &orig_attr);

	attr.c_iflag &= ~(/*IGNBRK|BRKINT|PARMRK|*/ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXANY|IXOFF);
/*	attr.c_oflag &= ~OPOST;*/
	attr.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN | ECHOE | ECHOK);
	attr.c_cflag &= ~(CSIZE|PARENB);
	attr.c_cflag |= CS8;

	tcsetattr(STDIN_FILENO, TCSANOW, &attr);
	signal(SIGINT, signal_handler);
	signal(SIGPIPE, signal_handler);
}

static int configure_sol()
{
	int rv;

	rv = ipmi_sol_register_data_received_callback(active_connection, data_received, NULL);
	if (rv)
		ipmi_log(IPMI_LOG_SEVERE, "Error registering for data_received event: %s.", strerror(rv));

	rv = ipmi_sol_register_break_detected_callback(active_connection, break_detected, NULL);
	if (rv)
		ipmi_log(IPMI_LOG_SEVERE, "Error registering for break_detected event: %s.", strerror(rv));

	rv = ipmi_sol_register_bmc_transmit_overrun_callback(active_connection, bmc_transmit_overrun, NULL);
	if (rv)
		ipmi_log(IPMI_LOG_SEVERE, "Error registering for bmc_transmit_overrun event: %s.", strerror(rv));

	rv = ipmi_sol_register_connection_state_callback(active_connection, connection_state, NULL);
	if (rv)
		ipmi_log(IPMI_LOG_SEVERE, "Error registering for connection_state event: %s.", strerror(rv));

	ipmi_sol_set_ACK_retries(active_connection, 10);
	ipmi_sol_set_ACK_timeout(active_connection, 1000000);

	return 0;
}

static void conn_changed(ipmi_con_t   *ipmi,
		  int          err,
		  unsigned int port_num,
		  int          any_port_up,
		  void         *cb_data)
{
	static int last_any_port_up = -1;

	int rv = err;
	if (any_port_up == last_any_port_up)
		return;

	last_any_port_up = any_port_up;

	if (any_port_up)
	{
		if (verbosity > 2)
			ipmi_log(IPMI_LOG_INFO, "IPMI connection is up.  Bringing up SoL connection.");

		ipmi_sol_open(active_connection);
	}
	else
	{
		char buf[50];
		ipmi_log(IPMI_LOG_SEVERE, "No connection to BMC is available.  %s.", ipmi_get_error_string(rv, buf, 50));
		ipmi_sol_force_close(active_connection);
		exit_condition = condition_exit_now;
	}
}

static void solterm_disconnect()
{
	if (!connection_up)
	{
		exit_condition = condition_exit_now;
	}
	else
	/*
	 * If we aren't already shutting down, do a forcible shut down!
	 */
	if (exit_condition == condition_running)
	{
		exit_condition = condition_exiting;
		ipmi_sol_close(active_connection);
	}
	else
	{
		ipmi_log(IPMI_LOG_WARNING, "Forcing SoL connection closed.");
		exit_condition = condition_exit_now;
	}
}

static void show_escape(unsigned char c)
{
	if (isprint(c))
		printf("[%c%c]", escape_char, c);
	else if ((c >= 1) && (c <= 26))
		printf("[%c^%c]", escape_char, (c | 0x40));
	else
		printf("[%c\\0x%02x]", escape_char, c);
}

static void show_help()
{
	char hostname[80];

	printf("\nThis is solterm");
	if (0 == gethostname(&hostname[0], 80))
	{
		hostname[79] = 0;
		printf(" on \"%s\"", &hostname[0]);
	}

	printf(	".  Supported escape sequences:\n"
		"%c.  - terminate connection\n"
		"%cB  - send a BREAK to the managed baseboard\n"
		"%cF  - flush local and remote buffers\n\n"

		"Baseboard RS232 Control signals:\n"
		"\t%cR/%cr  - ASSERT/deassert RI (Ring Indicator) at managed baseboard\n"
		"\t%cD/%cd  - ASSERT/deassert DCD and DSR at managed baseboard\n"
		"\t%cC/%cc  - CTS PAUSE/place cts under BMC control\n\n",
		escape_char, escape_char, escape_char,
		escape_char, escape_char, escape_char,
		escape_char, escape_char, escape_char
	);

#ifdef USE_SUSPEND
	printf(	"%c^Z - suspend solterm\n", escape_char);
#endif

	printf(	"%c?  - this message\n"
		"%c%c  - send the escape character by typing it twice\n"
		"(Note that escapes are only recognized immediately after newline.)\n",
		escape_char, escape_char, escape_char
	);
}

static int did_handle_escape(unsigned char c)
{
	switch (c)
	{
		case '.':
			/* Disconnect */
			show_escape(c);
			solterm_disconnect();
			return 1;

		case 'b':
		case 'B':
			/* Send Break */
			show_escape(c);
			sol_send_break();
			return 1;

		case 'f':
		case 'F':
			/* Flush everything */
			show_escape(c);
			sol_do_flush();
			return 1;

		case 'R':
		case 'r':
			show_escape(c);
			if (connection_up)
				ipmi_sol_set_RI_asserted(active_connection, (c == 'R'), transmit_complete, NULL);
			return 1;

		case 'D':
		case 'd':
			show_escape(c);
			if (connection_up)
				ipmi_sol_set_DCD_DSR_asserted(active_connection, (c == 'D'), transmit_complete, NULL);
			return 1;

		case 'C':
		case 'c':
			show_escape(c);
			if (connection_up)
				ipmi_sol_set_CTS_assertable(active_connection, (c == 'c'), transmit_complete, NULL);
			return 1;

#ifdef USE_SUSPEND
		case 'Z' & 0x1f: /* ^Z */
			show_escape(c); fflush(stdout);
			unconfigure_terminal();
			kill(getpid(), SIGTSTP);
			configure_terminal();
			printf("Resuming SoL session...\n"); fflush(stdout);

			return 1;
#endif

		case '?':
			show_escape(c);
			show_help();
			return 1;
	}

	return 0;
}


static void stdin_data_avail(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
	struct timeval tv;
	char c;
	fd_set theSet;

	tv.tv_sec = 0;
	tv.tv_usec = 0;

	FD_ZERO(&theSet);
	FD_SET(STDIN_FILENO, &theSet);

	if (!connection_up)
		ipmi_log(IPMI_LOG_WARNING, "Trying to transmit with no active connection!");

	while (select(1, &theSet, NULL, NULL, &tv))
	{
		if (0 == read(STDIN_FILENO, &c, 1))
		{
			solterm_disconnect();
			break;
		}

		else if ((escape_status == escape_next) && (c != escape_char) && did_handle_escape(c))
		{
			/* If it was handled, we just go back to waiting for another escape char.
			 * We should do this so the user can do ~R~r to assert then deassert RI.
			 */
			escape_status = escape_waiting_for_escape;
			fflush(stdout);
		}

		else if ((escape_status == escape_waiting_for_escape) && (escape_char == c))
			escape_status = escape_next;

		else if ((escape_status == escape_waiting_for_CR) && ('\r' == c))
		{
			if (connection_up)
				sol_send(&c, 1);
			escape_status = escape_waiting_for_escape;
		}
		else if (connection_up)
		{
			/* First, send the bottled-up escape char if it wasn't actually used as an escape char! */
			if ((escape_status == escape_next) && (escape_char != c))
				sol_send(&escape_char, 1);

			sol_send(&c, 1);
			if ('\r' == c)
				escape_status = escape_waiting_for_escape;
			else
				escape_status = escape_waiting_for_CR;
		}
	}
}

static os_handler_t *os_hnd;

ipmi_open_option_t domain_open_options = { IPMI_OPEN_OPTION_ALL, { ival: 0 }};

static int parse_sol_bit_rate(char *src, int *bit_rate)
{
	if (0 == strcmp(src, "9600"))
		*bit_rate = IPMI_SOL_BIT_RATE_9600;
	else if (0 == strcmp(src, "19200"))
		*bit_rate = IPMI_SOL_BIT_RATE_19200;
	else if (0 == strcmp(src, "38400"))
		*bit_rate = IPMI_SOL_BIT_RATE_38400;
	else if (0 == strcmp(src, "57600"))
		*bit_rate = IPMI_SOL_BIT_RATE_57600;
	else if (0 == strcmp(src, "115200"))
		*bit_rate = IPMI_SOL_BIT_RATE_115200;
	else
		return 0;

	return 1;
}

static int parse_sol_alerts(char *src, ipmi_sol_serial_alert_behavior *behavior)
{
	if (0 == strcasecmp(src, "fail"))
		*behavior = ipmi_sol_serial_alerts_fail;
	else if (0 == strcasecmp(src, "defer"))
		*behavior = ipmi_sol_serial_alerts_deferred;
	else if (0 == strcasecmp(src, "deferred"))
		*behavior = ipmi_sol_serial_alerts_deferred;
	else if (0 == strcasecmp(src, "succeed"))
		*behavior = ipmi_sol_serial_alerts_succeed;
	else
		return 0;

	return 1;
}

#define ARG (argv[curr_arg])
#define NEXT_ARG \
	{\
		curr_arg++; \
		if (curr_arg >= argc) { \
			ipmi_log(IPMI_LOG_FATAL, "Expected parameter after argument \"%s\"", argv[argc - 1]); \
			exit(1); \
		} \
	}

int main(int argc, char *argv[])
{
	int         rv;
	int         curr_arg = 1;
	ipmi_args_t *args;
	ipmi_con_t  *ipmi;
	char *name = "remote system";
	os_hnd_fd_id_t *stdin_id;
	sol_configuration_t sol_configuration;

	memset(&sol_configuration, 0, sizeof(sol_configuration));

	/* Enable authentication and encryption by default. */
	sol_configuration.authenticated = 1;
	sol_configuration.encrypted = 1;

	exit_condition = condition_running;
	verbosity = INITIAL_VERBOSITY;

	progname = argv[0];

	/* OS handler allocated first. */
	os_hnd = ipmi_posix_setup_os_handler();
	if (!os_hnd) {
		fprintf(stderr, "main: Unable to allocate os handler\n");
		exit(1);
	}
	os_hnd->set_log_handler(os_hnd, my_vlog);

	/* Initialize the OpenIPMI library. */
	ipmi_init(os_hnd);

	if (argc < 2) {
		usage();
		exit(1);
	}

	/* Now we make sure "lan" is the first argument so we get the
	   right connection type... */
	if (strcmp(argv[1], "lan") != 0) {
		fprintf(stderr, "main: %s only supports lan connections\n",
			progname);
		exit(1);
	}

	curr_arg = 1;
	rv = ipmi_parse_args2(&curr_arg, argc, argv, &args);
	if (rv) {
		ipmi_log(IPMI_LOG_FATAL, "Error parsing command arguments, argument %d: %s\n",
			curr_arg, strerror(rv));
		usage();
		exit(1);
	}

	while (curr_arg < argc)
	{
		if (0 == strcmp(ARG, "-notencrypted"))
			sol_configuration.encrypted = 0;
		else if (0 == strcmp(ARG, "-notauthenticated"))
			sol_configuration.authenticated = 0;
		else if (0 == strcmp(ARG, "-holdoff"))
			sol_configuration.holdoff = 1;
		else if (0 == strncmp(ARG, "-bitrate=", 9))
		{
			if (!parse_sol_bit_rate(&ARG[9], &sol_configuration.bit_rate))
				break;
		}
		else if (0 == strcmp(ARG, "-bitrate"))
		{
			NEXT_ARG;
			if (!parse_sol_bit_rate(ARG, &sol_configuration.bit_rate))
				break;
		}
		else if (0 == strncmp(ARG, "-alerts=", 8))
		{
			if (!parse_sol_alerts(&ARG[8], &sol_configuration.alert_behavior))
				break;
		}
		else if (0 == strncmp(ARG, "-alert=", 7))
		{
			if (!parse_sol_alerts(&ARG[7], &sol_configuration.alert_behavior))
				break;
		}
		else if	((0 == strcmp(ARG, "-alerts")) || (0 == strcmp(ARG, "-alert")))
		{
			NEXT_ARG;
			if (!parse_sol_alerts(ARG, &sol_configuration.alert_behavior))
				break;
		}
		else if (0 == strcmp(ARG, "-ack-retries"))
		{
			NEXT_ARG;
		//	if (!parse_int(ARG
		}
		else if (0 == strcmp(ARG, "-e"))
		{
			NEXT_ARG;
			if (strlen(argv[curr_arg]) != 1)
				break;
			escape_char = argv[curr_arg][0];
		}
		else if (0 == strcmp(ARG, "-v"))
			verbosity++;
		else if (0 == strcmp(ARG, "-q"))
			verbosity--;
		else break;

		curr_arg++;
	}

	if (curr_arg < argc)
	{			
		ipmi_log(IPMI_LOG_FATAL, "Unknown arg: %s", argv[curr_arg]);
		usage();
		exit(1);
	}

	if (sol_configuration.encrypted && !sol_configuration.authenticated)
	{
		ipmi_log(IPMI_LOG_FATAL, "Encryption cannot be enabled unless authentication is also enabled.");
		exit(1);
	}

	verbosity -= INITIAL_VERBOSITY;


	rv = ipmi_args_setup_con(args, os_hnd, NULL, &ipmi);
	if (rv) {
	        ipmi_log(IPMI_LOG_FATAL, "ipmi_ip_setup_con: %s", strerror(rv));
		exit(1);
	}

	if (ipmi->name)
		name = ipmi->name;

	rv = ipmi_sol_create(ipmi, &active_connection);
	if (rv)
	{
		ipmi_log(IPMI_LOG_FATAL, "Unable to create sol_conn. Error 0x%08x", rv);
		exit(1);
	}

	rv = configure_sol();
	if (rv)
	{
		ipmi_log(IPMI_LOG_SEVERE, "Unable to configure sol_conn. Error 0x%08x", rv);
	}

	/*
	 * Copy the parsed configuration into the sol_conn
	 */
	ipmi_sol_set_use_encryption(active_connection, sol_configuration.encrypted);
	ipmi_sol_set_use_authentication(active_connection, sol_configuration.authenticated);
	ipmi_sol_set_bit_rate(active_connection, sol_configuration.bit_rate);
	ipmi_sol_set_shared_serial_alert_behavior(active_connection,
		sol_configuration.alert_behavior);
	ipmi_sol_set_deassert_CTS_DCD_DSR_on_connect(active_connection,
		sol_configuration.holdoff);
	

	if (verbosity > 4)
		DEBUG_MSG_ENABLE();
	if (verbosity > 5)
		DEBUG_RAWMSG_ENABLE();

	if (verbosity >= 0)
	{
		printf(	"Connecting to %s...\n", name);
		fflush(stdout);
	}

	configure_terminal();

	rv = ipmi->add_con_change_handler(ipmi, conn_changed, NULL);
	ipmi->start_con(ipmi);

	os_hnd->add_fd_to_wait_for(os_hnd,
		STDIN_FILENO,
		stdin_data_avail, /* os_data_ready_t */
		NULL, /* cb_data */
		NULL, /*os_fd_data_freed_t */
		&stdin_id);

	while (exit_condition != condition_exit_now) {
		os_hnd->perform_one_op(os_hnd, NULL);
	}

	unconfigure_terminal();
	if (active_connection)
	{
		ipmi_sol_force_close(active_connection);
		ipmi_sol_free(active_connection);
	}

	if (connection_up)
		printf("Connection to %s closed.\n", name);

	os_hnd->free_os_handler(os_hnd);

	return 0;
}
