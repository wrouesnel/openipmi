
%module OpenIPMI

%{
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/ipmi_glib.h>

#include "OpenIPMI.h"

os_handler_t *swig_os_hnd;

swig_cb_val swig_log_handler;

void
posix_vlog(char *format, enum ipmi_log_type_e log_type, va_list ap)
{
    char *pfx = "";
    static char log[1024];
    static int curr = 0;
    int  len;
    swig_cb_val handler = swig_log_handler;

    if (! handler)
	return;

    switch(log_type)
    {
    case IPMI_LOG_INFO:
	pfx = "INFO";
	break;

    case IPMI_LOG_WARNING:
	pfx = "WARN";
	break;

    case IPMI_LOG_SEVERE:
	pfx = "SEVR";
	break;

    case IPMI_LOG_FATAL:
	pfx = "FATL";
	break;

    case IPMI_LOG_ERR_INFO:
	pfx = "EINF";
	break;

    case IPMI_LOG_DEBUG:
	pfx = "DEBG";
	break;

    case IPMI_LOG_DEBUG_START:
    case IPMI_LOG_DEBUG_CONT:
	if (curr < sizeof(log))
	    curr += vsnprintf(log+curr, sizeof(log)-curr, format, ap);
	return;

    case IPMI_LOG_DEBUG_END:
	if (curr < sizeof(log))
	    vsnprintf(log+curr, sizeof(log)-curr, format, ap);
	pfx = "DEBG";
	curr = 0;
	goto plog;
    }

    vsnprintf(log, sizeof(log), format, ap);

 plog:
    swig_call_cb(handler, "log", "%s%s", pfx, log);
}

#ifdef HAVE_GLIB
#include <glib.h>
static void
glib_handle_log(const gchar *log_domain,
		GLogLevelFlags log_level,
		const gchar *message,
		gpointer user_data)
{
    char *pfx = "";
    swig_cb_val handler = swig_log_handler;

    if (! handler)
	return;

    if (log_level & G_LOG_LEVEL_ERROR)
	pfx = "FATL";
    else if (log_level & G_LOG_LEVEL_CRITICAL)
	pfx = "SEVR";
    else if (log_level & G_LOG_LEVEL_WARNING)
	pfx = "WARN";
    else if (log_level & G_LOG_LEVEL_MESSAGE)
	pfx = "EINF";
    else if (log_level & G_LOG_LEVEL_INFO)
	pfx = "INFO";
    else if (log_level & G_LOG_LEVEL_DEBUG)
	pfx = "DEBG";

    swig_call_cb(handler, "log", "%s%s", pfx, message);
}
#endif

%}

%nodefault;

%typemap(in) swig_cb {
    if (!SvROK($input))
	croak("Argument $argnum is not a reference.");
    $1 = $input;
}

%typemap(in) char ** {
    AV *tempav;
    I32 len;
    int i;
    SV  **tv;
    if (!SvROK($input))
	croak("Argument $argnum is not a reference.");
    if (SvTYPE(SvRV($input)) != SVt_PVAV)
	croak("Argument $argnum is not an array.");
    tempav = (AV*)SvRV($input);
    len = av_len(tempav);
    $1 = (char **) malloc((len+2)*sizeof(char *));
    for (i = 0; i <= len; i++) {
	tv = av_fetch(tempav, i, 0);
	$1[i] = (char *) SvPV(*tv,PL_na);
    }
    $1[i] = NULL;
};

%typemap(freearg) char ** {
        free($1);
};

%{
static void
handle_domain_cb(ipmi_domain_t *domain, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "domain_cb", "%p", &domain_ref);
    swig_free_ref(domain_ref);
}

static void
domain_con_change(ipmi_domain_t *domain,
		  int           err,
		  unsigned int  conn_num,
		  unsigned int  port_num,
		  int           still_connected,
		  void          *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "conn_change_cb", "%p%d%d%d%d",
		 &domain_ref, err, conn_num, port_num, still_connected);
    swig_free_ref(domain_ref);
}

static void
domain_fully_up(ipmi_domain_t *domain, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "domain_up_cb", "%p", &domain_ref);
    swig_free_ref(domain_ref);
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
domain_close_done(void *cb_data)
{
    swig_cb_val cb = cb_data;

    swig_call_cb(cb, "close_done_cb", "");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
iterate_entities_handler(ipmi_entity_t *entity, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    swig_call_cb(cb, "entity_iter_cb", "%p", &entity_ref);
    swig_free_ref(entity_ref);
}
%}

typedef struct {
} ipmi_domain_t;

typedef struct {
} ipmi_domain_id_t;

typedef struct {
} ipmi_entity_t;

typedef struct {
} ipmi_entity_id_t;

%newobject open_domain;

%inline %{
/*
 * Initialize the OS handler and use the POSIX version.
 */
void
init_posix(void)
{
    swig_os_hnd = ipmi_posix_setup_os_handler();
    ipmi_init(swig_os_hnd);
}

#ifdef HAVE_GLIB
/*
 * Initialize the OS handler with the glib version.
 */
void
init_glib(void)
{
    swig_os_hnd = ipmi_glib_get_os_handler();
    g_thread_init(NULL);
    ipmi_init(swig_os_hnd);
    g_log_set_handler("OpenIPMI",
		      G_LOG_LEVEL_ERROR
		      | G_LOG_LEVEL_CRITICAL
		      | G_LOG_LEVEL_WARNING
		      | G_LOG_LEVEL_MESSAGE
		      | G_LOG_LEVEL_INFO
		      | G_LOG_LEVEL_DEBUG
		      | G_LOG_FLAG_FATAL,
		      glib_handle_log,
		      NULL);
}

/*
 * Initialize the OS handler with the default version.  This is glib
 * if it is present, POSIX if it is not.
 */
void
init(void)
{
#ifdef HAVE_GLIB
    init_glib();
#else
    init_posix();
#endif
}

#endif

/*
 * Create a new domain.  The domain will be named with the first parm,
 * the startup arguments are in a list in the second parm (\@args),
 * the third parm is a callback object whose conn_change_cb method
 * will be called when the domain has connected (but it may not be
 * fully up yet).  The fourth parameter's domain_up_cb method will be
 * called when the domain is completely up.  Note that the done method
 * will be kept around and will continue to be called on connection
 * changes.  If you don't want it any more, it must be deregistered
 * with remove_connect_change_handler.
 * Passing in a reference to an undefined value will cause the handlers
 * to not be called.
 */
ipmi_domain_id_t *
open_domain(char *name, char **args, swig_cb done, swig_cb up)
{
    int                i, j;
    int                len;
    int                num_options = 0;
    ipmi_open_option_t options[10];
    int                set = 0;
    ipmi_args_t        *con_parms[2];
    ipmi_con_t         *con[2];
    ipmi_domain_id_t   *nd;
    int                rv;
    swig_cb_val        done_val = NULL;
    swig_cb_val        up_val = NULL;
    ipmi_domain_con_cb con_change = NULL;
    ipmi_domain_ptr_cb domain_up = NULL;

    for (len=0; args[len]; len++)
	;

    nd = malloc(sizeof(*nd));

    for (i=0; args[i]; i++) {
	if (num_options >= 10) {
	    free(nd);
	    return NULL;
	}

	if (! ipmi_parse_options(options+num_options, args[i]))
	    num_options++;
	else
	    break;
    }

    rv = ipmi_parse_args(&i, len, args, &con_parms[set]);
    if (rv) {
	free(nd);
	return NULL;
    }
    set++;

    if (i < len) {
	rv = ipmi_parse_args(&i, len, args, &con_parms[set]);
	if (rv) {
	    ipmi_free_args(con_parms[0]);
	    free(nd);
	    return NULL;
	}
	set++;
    }

    for (i=0; i<set; i++) {
	rv = ipmi_args_setup_con(con_parms[i],
				 swig_os_hnd,
				 NULL,
				 &con[i]);
	if (rv) {
	    for (j=0; j<set; j++)
		ipmi_free_args(con_parms[j]);
	    free(nd);
	    return NULL;
	}
    }

    if (valid_swig_cb(up)) {
	up_val = ref_swig_cb(up);
	domain_up = domain_fully_up;
    }
    if (valid_swig_cb(done)) {
	done_val = ref_swig_cb(done);
	con_change = domain_con_change;
    }
    rv = ipmi_open_domain(name, con, set, con_change, done_val,
			  domain_up, up_val,
			  options, num_options, nd);
    if (rv) {
	if (valid_swig_cb(up))
	    deref_swig_cb(up);
	if (valid_swig_cb(done))
	    deref_swig_cb(done);
	for (i=0; i<set; i++) {
	    ipmi_free_args(con_parms[i]);
	    con[i]->close_connection(con[i]);
	}
	free(nd);
	return NULL;
    }

    for (i=0; i<set; i++)
	ipmi_free_args(con_parms[i]);

    return nd;
}

/*
 * Perform one operation.  The first parameter is a timeout in
 * milliseconds.
 */
void
wait_io(int timeout)
{
    struct timeval tv = { (timeout / 1000), ((timeout + 999) % 1000) };
    swig_os_hnd->perform_one_op(swig_os_hnd, &tv);
}

/*
 * Set the handler for OpenIPMI logs.  The logs will be sent to the
 * "log" method of the first parameter.  The log method will receive
 * the following parameters: self, log_level (a string), and log (a
 * string).
 */
void
set_log_handler(swig_cb handler)
{
    swig_cb_val old_handler = swig_log_handler;
    if (valid_swig_cb(handler))
	swig_log_handler = ref_swig_cb(handler);
    else
	swig_log_handler = NULL;
    if (old_handler)
	deref_swig_cb_val(old_handler);
}
%}

/*
 * A domain id object.  This object is guaranteed to be valid and
 * can be converted into a domain pointer later.
 */
%extend ipmi_domain_id_t {
    ~ipmi_domain_id_t()
    {
	free(self);
    }

    /*
     * Convert a domain id to a domain pointer.  The "domain_cb" method
     * will be called on the first parameter with the domain as the
     * second parameter.
     */
    char *convert_to_domain(swig_cb handler)
    {
	int rv;

	if (! valid_swig_cb(handler))
	    return NULL;

	rv = ipmi_domain_pointer_cb(*self, handle_domain_cb,
				    get_swig_cb(handler));
	if (rv)
	    return strerror(rv);
	return NULL;
    }
}

/*
 * A domain object.
 */
%extend ipmi_domain_t {
    %newobject get_name;
    /*
     * Get the name of the domain.
     */
    char *get_name()
    {
	char name[IPMI_DOMAIN_NAME_LEN];

	ipmi_domain_get_name(self, name, sizeof(name));
	return strdup(name);
    }

    %newobject get_id;
    /*
     * Get the ID of the domain so you can hold on to the reference.
     */
    ipmi_domain_id_t *get_id()
    {
	ipmi_domain_id_t *rv = malloc(sizeof(*rv));
	if (rv)
	    *rv = ipmi_domain_convert_to_id(self);
	return rv;
    }

    /*
     * Shut down the connections to the domain and free it up.
     * If the parameter given 
     */
    int close(swig_cb handler)
    {
	int         rv;
	swig_cb_val handler_val;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = ref_swig_cb(handler);
	rv = ipmi_domain_close(self, domain_close_done, handler_val);
	if (rv)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Add a handler to be called when the connection changes status.
     * The conn_change_cb method on the first parameter will be
     * called when the connection changes status with the following
     * parameters: self, domain, errorval, connection_number, port_number,
     * still_connected.
     */
    int add_connect_change_handler(swig_cb handler)
    {
	int         rv;
	swig_cb_val handler_val;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = ref_swig_cb(handler);
	rv = ipmi_domain_add_connect_change_handler
	    (self, domain_con_change, handler_val);
	if (rv)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Remove the connection change handler.
     */
    int remove_connect_change_handler(swig_cb handler)
    {
	int         rv;
	swig_cb_val handler_val;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = get_swig_cb(handler);
	rv = ipmi_domain_remove_connect_change_handler
	    (self, domain_con_change, handler_val);
	if (!rv)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Iterate through all the entities in the object.  The
     * entity_iter_cb method will be called on the first parameter for
     * each entity in the domain.  The paramters it receives will be:
     * self, entity.
     */
    int iterate_entities(swig_cb handler)
    {
	swig_cb_val handler_val;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = get_swig_cb(handler);
	ipmi_domain_iterate_entities(self, iterate_entities_handler,
				     handler_val);
	return 0;
    }
}

%extend ipmi_entity_t {
    %newobject get_name;
    /*
     * Get the name of an entity.
     */
    char *get_name()
    {
	char name[IPMI_ENTITY_NAME_LEN];

	ipmi_entity_get_name(self, name, sizeof(name));
	return strdup(name);
    }

    %newobject get_id;
    /*
     * Get the id for the entity.
     */
    ipmi_entity_id_t *get_id()
    {
	ipmi_entity_id_t *rv = malloc(sizeof(*rv));
	if (rv)
	    *rv = ipmi_entity_convert_to_id(self);
	return rv;
    }
}
