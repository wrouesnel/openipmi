/*
 * eventd.c
 *
 * OpenIPMI event logging daemon
 *
 * This program takes IPMI events and calls an external program to
 * handle them.  See the man page for usage details.
 *
 * Author: Corey Minyard <cminyard@mvista.com>
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>
#include <time.h>
#include <syslog.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_posix.h>

#define STDERR_IPMIERR(err, format, ...) \
    do {								\
	char errstr[128];						\
	ipmi_get_error_string(err, errstr, sizeof(errstr));		\
	fprintf(stderr, "%s: " format ": %s\n", domainname, ##__VA_ARGS__, \
		errstr);						\
    } while(0)

#define SYSLOG_IPMIERR(level, err, format, ...) \
    do {								\
	char errstr[128];						\
	ipmi_get_error_string(err, errstr, sizeof(errstr));		\
	syslog(level, "%s: " format ": %s", domainname, ##__VA_ARGS__, errstr);\
    } while(0)

#define debug_printf(format, ...) \
    do {								\
	if (debug)							\
	    printf(format, ##__VA_ARGS__);				\
    } while(0)

static const char *progname;
static char **prog;
static int num_prog;
static bool progstdio;
static FILE *outfile;
static char *domainname;
static bool domain_up;
static bool delete_events;
static int debug;
static int childpid = -1;

static char *indent_str(const char *instr, const char *indent)
{
    int p, o;
    int ilen = strlen(indent);
    size_t extra = 0;
    char *s;

    for (p = 0; instr[p]; p++) {
	if (instr[p] == '\n')
	    extra += ilen;
    }
    if (extra == 0)
	return (char *) instr;
    s = malloc(strlen(instr) + extra + 1);
    if (!s)
	return NULL;
    for (p = 0, o = 0; instr[p]; p++) {
	s[o++] = instr[p];
	if (instr[p] == '\n') {
	    memcpy(s + o, indent, ilen);
	    o += ilen;
	}
    }
    s[o] = '\0';
    return s;
}

static void con_usage(const char *name, const char *help, void *cb_data)
{
    char *newhelp = indent_str(help, "     ");
    printf("\n %s%s", name, newhelp);
    if (newhelp != help)
	free(newhelp);
}

static void
usage(void)
{
    printf("Usage:\n");
    printf(" %s <domain> <con_parms> [-k] [-i] [-e] [-d] [-b] [-f <filename>] <program> [<parm1> [<parm2> [...]]]\n",
	   progname);
    printf("<domain> is a name given to locally identify the connection.\n");
    printf("Options are:\n");
    printf(" -k, --exec-now - Execute the program at startup and feed it\n");
    printf("    events through stdin.\n");
    printf(" -i, --event-stdin - Execute the program for each event, but\n");
    printf("    feed it input through stdin.\n");
    printf(" -e, --delete-events - Delete each event after processing.\n");
    printf(" -d, --debug - Enable debugging\n");
    printf(" -b, --dont-daemonize - Run the program in foreground.\n");
    printf(" -f, --outfile - Send the output to the given file instead of\n");;
    printf("    spawning another program.\n");
    printf("<con_parms> is:");
    ipmi_parse_args_iter_help(con_usage, NULL);
}

static int
send_parms_to_file(char *type, char **parms1, int num_parms1,
		   char **parms2, int num_parms2)
{
    int i;
    fprintf(outfile, "%s\n", type);
    for (i = 0; i + 1 < num_parms1; i += 2)
	fprintf(outfile, "%s %s\n", parms1[i], parms1[i + 1]);
    for (i = 0; i + 1 < num_parms2; i += 2)
	fprintf(outfile, "%s %s\n", parms2[i], parms2[i + 1]);
    fprintf(outfile, "endevent\n");
    if (fflush(outfile) == -1) {
	syslog(LOG_CRIT, "%s: Destination end of pipe failed: %s\n",
	       domainname, strerror(errno));
	return -1;
    }

    return 0;
}

static int
newpipe(FILE **retfile)
{
    int fds[2];
    FILE *f;

    if (pipe(fds) == -1) {
	syslog(LOG_ERR, "%s: Unable to open pipe to subprogram: %s",
	       domainname, strerror(errno));
	return -1;
    }

    f = fdopen(fds[1], "w");
    if (!f) {
	syslog(LOG_ERR, "%s: Unable to fdopen pipe to subprogram: %s",
	       domainname, strerror(errno));
	close(fds[0]);
	close(fds[1]);
	return -1;
    }

    *retfile = f;
    return fds[0];
}

static void
send_event_to_prog(char         *type,
		   ipmi_event_t *event,
		   char         **parms,
		   int          num_parms)
{
    char typestr[30];
    char timestr[30];
    char datastr[128];
    char *parms2[6];
    int num_parms2 = 0;
    pid_t pid;
    int infd = -1;
    bool handled = false;

    if (event) {
	int pos = 0;
	unsigned int i, len;
	unsigned char eventdata[16];

	parms2[num_parms2++] = "eventtype";
	parms2[num_parms2++] = typestr;
	snprintf(typestr, sizeof(typestr), "0x%x", ipmi_event_get_type(event));

	parms2[num_parms2++] = "eventtime";
	parms2[num_parms2++] = timestr;
	snprintf(timestr, sizeof(timestr), "%lld",
		 (long long) ipmi_event_get_timestamp(event));

	parms2[num_parms2++] = "eventdata";
	parms2[num_parms2++] = datastr;
	datastr[0] = '\0';
	len = ipmi_event_get_data_len(event);
	if (len > sizeof(eventdata))
	    len = sizeof(eventdata);
	ipmi_event_get_data(event, eventdata, 0, len);
	for (i = 0; i < len; i++) {
	    pos += snprintf(datastr + pos, sizeof(datastr) - pos, " 0x%2.2x",
			    eventdata[i]);
	}
    }

    if (!domain_up)
	goto out;

    if (outfile) {
	if (send_parms_to_file(type, parms, num_parms, parms2, num_parms2))
	    /* The remote end is broken, give up. */
	    exit(1);
	handled = true;
	goto out;
    }

    if (progstdio) {
	infd = newpipe(&outfile);
	if (infd == -1)
	    goto out_close;
    }
	
    pid = fork();
    if (pid < 0) {
	syslog(LOG_ERR, "%s: Unable to fork: %s\n", domainname,
	strerror(errno));
    } else if (pid > 0) {
	int rv, status;

	if (outfile) {
	    if (!send_parms_to_file(type, parms, num_parms, parms2, num_parms2))
		handled = true;

	    /*
	     * Close the output here, instead of later, to give a hint to
	     * the program receiving the data that we are done.
	     */
	    fclose(outfile);
	    outfile = NULL;
	}

	/* Wait here so multiple events don't get out of order. */
	rv = waitpid(pid, &status, 0);

	/* If the calling program failed, don't delete the event. */
	if (rv == -1)
	    handled = false;
	else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
	    handled = false;
    } else if (outfile) {
	fclose(outfile);
	close(0);
	if (dup(infd) != 0)
	    exit(1);
	close(infd);
	execv(prog[0], prog);
	syslog(LOG_ERR, "%s: Unable to execute program: %s\n", domainname,
	       strerror(errno));
	exit(1);
    } else {
	char **execvals;
	execvals = malloc((num_parms + num_parms2 + num_prog + 2)
			  * sizeof(char *));
	if (!execvals) {
	    syslog(LOG_ERR, "%s: Out of memory allocating execvals",
		   domainname);
	    goto out_close;
	}

	memcpy(execvals, prog, num_prog * sizeof(char *));
	execvals[num_prog] = type;
	memcpy(execvals + num_prog + 1, parms, num_parms * sizeof(char *));
	memcpy(execvals + num_prog + num_parms + 1, parms2,
	       num_parms2 * sizeof(char *));
	execvals[num_prog + num_parms + num_parms2 + 1] = NULL;

	execv(execvals[0], execvals);
	syslog(LOG_ERR, "%s: Unable to execute program: %s\n", domainname,
	       strerror(errno));
	exit(1);
    }

 out_close:
    if (outfile) {
	fclose(outfile);
	outfile = NULL;
    }
 out:
    if (handled && event && delete_events)
	ipmi_event_delete(event, NULL, NULL);
    return;
}

static void
send_sensor_event_to_prog(ipmi_sensor_t               *sensor,
			  enum ipmi_event_dir_e       dir,
			  ipmi_event_t                *event,
			  char                        *type,
			  char                        **parms,
			  int                         num_parms)
{
    ipmi_entity_t *ent = ipmi_sensor_get_entity(sensor);
    int id, instance, pos;
    char idstr[128];

    
    parms[num_parms++] = "assert";
    parms[num_parms++] = (dir == IPMI_ASSERTION) ? "true" : "false";

    parms[num_parms++] = "id";
    parms[num_parms++] = idstr;
    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    pos = snprintf(idstr, sizeof(idstr), "%d.%d.", id, instance);
    ipmi_sensor_get_id(sensor, idstr + pos, sizeof(idstr) - pos - 1);
    idstr[127] = '\0';

    send_event_to_prog(type, event, parms, num_parms);
}

/*
 * Enough to add the id.
 */
#define MAX_EXTRA_PARMS 4

char *thresh_to_severity[6] = {
    "lower_non_critical",
    "lower_critical",
    "lower_non_recoverable",
    "upper_non_critical",
    "upper_critical",
    "upper_non_recoverable"
};

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
    char *parms[10 + MAX_EXTRA_PARMS];
    int num_parms = 0;
    char valstr[30];
    char rawstr[30];

    debug_printf("threshold event handler\n");

    parms[num_parms++] = "severity";
    parms[num_parms++] = thresh_to_severity[threshold];

    parms[num_parms++] = "direction";
    parms[num_parms++] = high_low == IPMI_GOING_LOW ?
	"going_low" : "going_high";

    if (value_present == IPMI_BOTH_VALUES_PRESENT) {
	parms[num_parms++] = "val";
	parms[num_parms++] = valstr;
	snprintf(valstr, sizeof(valstr), "%f", value);
	parms[num_parms++] = "raw";
	parms[num_parms++] = rawstr;
	snprintf(rawstr, sizeof(rawstr), "0x%2.2x", raw_value);
    } else if (value_present == IPMI_RAW_VALUE_PRESENT) {
	parms[num_parms++] = "raw";
	parms[num_parms++] = rawstr;
	snprintf(rawstr, sizeof(rawstr), "0x%2.2x", raw_value);
    }

    send_sensor_event_to_prog(sensor, dir, event, "threshold",
			      parms, num_parms);

    /* Don't pass this on. */
    return IPMI_EVENT_HANDLED;
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
    char *parms[6 + MAX_EXTRA_PARMS];
    int num_parms = 0;
    char sevstr[30];
    char prevstr[30];
    char offstr[30];

    debug_printf("discrete event handler\n");

    parms[num_parms++] = "offset";
    parms[num_parms++] = offstr;
    snprintf(offstr, sizeof(offstr), "%d", offset);

    if (severity != -1) {
	parms[num_parms++] = "severity";
	parms[num_parms++] = sevstr;
	snprintf(sevstr, sizeof(sevstr), "%d", severity);
    }

    if (prev_severity != -1) {
	parms[num_parms++] = "prevseverity";
	parms[num_parms++] = prevstr;
	snprintf(prevstr, sizeof(prevstr), "%d", prev_severity);
    }

    send_sensor_event_to_prog(sensor, dir, event, "discrete",
			      parms, num_parms);

    /* Don't pass this on. */
    return IPMI_EVENT_HANDLED;
}

static void
default_event_handler(ipmi_domain_t *domain,
		      ipmi_event_t  *event,
		      void          *event_data)
{
    debug_printf("default event handler\n");

    send_event_to_prog("unknown", event, NULL, 0);
}

/* Whenever the status of a sensor changes, the function is called
   We display the information of the sensor if we find a new sensor
*/
static void
sensor_change(enum ipmi_update_e op,
	      ipmi_entity_t      *ent,
	      ipmi_sensor_t      *sensor,
	      void               *cb_data)
{
    int id, instance;
    char name[33];
    int rv;

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_id(sensor, name, 32);
    if (op == IPMI_ADDED) {
	debug_printf("Sensor added: %d.%d.%s\n", id, instance, name);

	if (ipmi_sensor_get_event_reading_type(sensor)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	    rv = ipmi_sensor_add_threshold_event_handler
		(sensor,
		 sensor_threshold_event_handler,
		 NULL);
	else
	    rv = ipmi_sensor_add_discrete_event_handler
		(sensor,
		 sensor_discrete_event_handler,
		 NULL);
	if (rv) {      
	    SYSLOG_IPMIERR(LOG_CRIT, rv, "Unable to add sensor event handler");
	    exit(1);
	}
    }
}

/* Whenever the status of an entity changes, the function is called
   When a new entity is created, we search all sensors that belong 
   to the entity */
static void
entity_change(enum ipmi_update_e op,
	      ipmi_domain_t      *domain,
	      ipmi_entity_t      *entity,
	      void               *cb_data)
{
    int rv;
    int id, instance;

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    if (op == IPMI_ADDED) {
	debug_printf("Entity added: %d.%d\n", id, instance);
	/* Register callback so that when the status of a
	   sensor changes, sensor_change is called */
	rv = ipmi_entity_add_sensor_update_handler(entity,
						   sensor_change,
						   entity);
	if (rv) {
	    SYSLOG_IPMIERR(LOG_CRIT, rv, "Unable to add sensor update handler");
	    exit(1);
	}
    }
}

/* After we have established connection to domain, this function get called
   At this time, we can do whatever things we want to do. Herr we want to
   search all entities in the system */ 
void
setup_done(ipmi_domain_t *domain,
	   int           err,
	   unsigned int  conn_num,
	   unsigned int  port_num,
	   int           still_connected,
	   void          *user_data)
{
    int rv;

    if (err) {
	SYSLOG_IPMIERR(LOG_CRIT, err, "Unable to connect to domain");
	exit(1);
    }

    rv = ipmi_domain_add_event_handler(domain, default_event_handler, NULL);
    if (rv) {      
	SYSLOG_IPMIERR(LOG_CRIT, rv, "Unable to add default event handler");
	exit(1);
    }

    /* Register a callback functin entity_change. When a new entities 
       is created, entity_change is called */
    rv = ipmi_domain_add_entity_update_handler(domain, entity_change, domain);
    if (rv) {      
	SYSLOG_IPMIERR(LOG_CRIT, rv, "Unable to add entity update handler");
	exit(1);
    }
}

static os_handler_t *os_hnd;

static void
handle_openipmi_vlog(os_handler_t         *handler,
		     const char           *format,
		     enum ipmi_log_type_e log_type,
		     va_list              ap)
{
    int level;
    char *newformat;

    switch(log_type)
    {
    case IPMI_LOG_INFO: level = LOG_INFO; break;
    case IPMI_LOG_WARNING: level = LOG_WARNING; break;
    case IPMI_LOG_SEVERE: level = LOG_ERR; break;
    case IPMI_LOG_FATAL: level = LOG_CRIT; break;
    case IPMI_LOG_ERR_INFO: level = LOG_WARNING; break;

    case IPMI_LOG_DEBUG_START:
    case IPMI_LOG_DEBUG:
    case IPMI_LOG_DEBUG_CONT:
    case IPMI_LOG_DEBUG_END:
	level = LOG_DEBUG;
	break;
    default:
	level = LOG_NOTICE;
    }

    newformat = malloc(strlen(format) + strlen(domainname) + 3);
    if (!newformat) {
	vsyslog(level, format, ap);
	return;
    }

    strcpy(newformat, domainname);
    strcat(newformat, ": ");
    strcat(newformat, format);
    vsyslog(level, newformat, ap);
    free(newformat);
}

static void
fully_up(ipmi_domain_t *domain, void *cb_data)
{
    debug_printf("Fully up!\n");
    domain_up = 1;
}

static void
sigchld_handler(int sig)
{
    syslog(LOG_CRIT, "%s: Child process failed\n", domainname);
    exit(1);
}

int
main(int argc, char *argv[])
{
    int         rv;
    int         curr_arg = 2;
    ipmi_args_t *args;
    ipmi_con_t  *con;
    bool        execnow = false;
    bool        daemonize = true;
    char        *outfname = NULL;
    int         syslog_options = 0;

    if (argc < 2) {
	fprintf(stderr, "No domain name given\n");
	exit(1);
    }

    progname = argv[0];
    domainname = argv[1];

    /* OS handler allocated first. */
    os_hnd = ipmi_posix_setup_os_handler();
    if (!os_hnd) {
	fprintf(stderr, "ipmi_smi_setup_con: Unable to allocate os handler\n");
	exit(1);
    }

    /* Override the default log handler. */
    os_hnd->set_log_handler(os_hnd, handle_openipmi_vlog);

    rv = ipmi_init(os_hnd);
    if (rv) {
	STDERR_IPMIERR(rv, "Error in ipmi initialization");
	exit(1);
    }

    rv = ipmi_parse_args2(&curr_arg, argc, argv, &args);
    if (rv) {
	STDERR_IPMIERR(rv, "Error parsing command arguments, argument %d",
		       curr_arg);
	usage();
	exit(1);
    }

    while (curr_arg < argc && argv[curr_arg][0] == '-') {
	int a = curr_arg;
	curr_arg++;
	if (strcmp(argv[a], "--") == 0)
	    break;
	if ((strcmp(argv[a], "-i") == 0) ||
	    (strcmp(argv[a], "--event-stdin") == 0))
	    progstdio = true;
	else if ((strcmp(argv[a], "-k") == 0) ||
		 (strcmp(argv[a], "--exec-now") == 0))
	    execnow = true;
	else if ((strcmp(argv[a], "-e") == 0) ||
		 (strcmp(argv[a], "--delete-events") == 0))
	    delete_events = true;
	else if ((strcmp(argv[a], "-d") == 0) ||
		 (strcmp(argv[a], "--debug") == 0)) {
	    debug++;
	    daemonize = false;
	} else if ((strcmp(argv[a], "-b") == 0) ||
		   (strcmp(argv[a], "--dont-daemonize") == 0))
	    daemonize = false;
	else if ((strcmp(argv[a], "-f") == 0) ||
		 (strcmp(argv[a], "--outfile") == 0)) {
	    if (curr_arg == argc) {
		fprintf(stderr, "-f given, but no filename given\n");
		exit(1);
	    }
	    outfname = argv[curr_arg];
	    curr_arg++;
	} else {
	    fprintf(stderr, "Unknown parameter: %s\n", argv[a]);
	    exit(1);
	}
	    
    }

    prog = argv + curr_arg;
    num_prog = argc - curr_arg;

    if (debug)
	syslog_options |= LOG_PERROR;

    openlog("openipmi_syslog", syslog_options, LOG_DAEMON);

    rv = ipmi_args_setup_con(args, os_hnd, NULL, &con);
    if (rv) {
        STDERR_IPMIERR(rv, "ipmi_ip_setup_con failed");
	exit(1);
    }

    rv = ipmi_open_domain(domainname, &con, 1, setup_done, NULL, fully_up, NULL,
			  NULL, 0, NULL);
    if (rv) {
        STDERR_IPMIERR(rv, "ipmi_open domain failed");
	exit(1);
    }

    if (outfname) {
	if (curr_arg != argc || execnow) {
	    fprintf(stderr, "You can't specify a program or -k"
		    " along with -f\n");
	    exit(1);
	}
	outfile = fopen(outfname, "a");
	if (!outfile) {
	    fprintf(stderr, "Unable to output output file %s: %s\n", outfname,
		    strerror(errno));
	    exit(1);
	}
    } else if (curr_arg == argc) {
	fprintf(stderr, "No program given to execute on an IPMI event\n");
	exit(1);
    }

    if (execnow) {
	/* Only watch for child processes if we keep it around. */
	if (signal(SIGCHLD, sigchld_handler) == SIG_ERR) {
	    fprintf(stderr, "Unable to install sigchld handler: %s\n",
		    strerror(errno));
	    exit(1);
	}
    }

    /*
     * We have to daemonize before we fork or sigchld won't work.
     */
    if (daemonize)
	daemon(0, 0);

    if (execnow) {
	int infd = newpipe(&outfile);

	if (infd == -1) {
	    fprintf(stderr, "Unable to open pipe, see syslog for errors\n");
	    exit(1);
	}
	
	childpid = fork();
	if (childpid < 0) {
	    syslog(LOG_CRIT, "%s: Unable to fork: %s\n", domainname,
		   strerror(errno));
	    exit(1);
	} else if (childpid == 0) {
	    close(0);
	    if (dup(infd) != 0) {
		syslog(LOG_CRIT, "%s: Dup didn't set stdin\n", domainname);
		exit(1);
	    }
	    close(infd);
	    execv(prog[0], prog);
	    syslog(LOG_CRIT, "%s: Unable to exec %s: %s\n", domainname, prog[0],
		    strerror(errno));
	    exit(1);
	}
    }

    /* Let the selector code run the select loop. */
    os_hnd->operation_loop(os_hnd);

    /* Technically, we can't get here, but just to be sure... */
    os_hnd->free_os_handler(os_hnd);
    return 0;
}
