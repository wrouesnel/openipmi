
%module OpenIPMI

%{
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_posix.h>

#include "OpenIPMI.h"

os_handler_t *swig_os_hnd;

swig_cb swig_log_handler;

void
posix_vlog(char *format, enum ipmi_log_type_e log_type, va_list ap)
{
    int  do_nl = 1;
    char *pfx = "";
    char log[1024];
    int  len;
    swig_cb handler = swig_log_handler;

    if (!handler)
	return;

    ref_swig_cb(handler);

    switch(log_type)
    {
    case IPMI_LOG_INFO:
	pfx = "INFO: ";
	break;

    case IPMI_LOG_WARNING:
	pfx = "WARN: ";
	break;

    case IPMI_LOG_SEVERE:
	pfx = "SEVR: ";
	break;

    case IPMI_LOG_FATAL:
	pfx = "FATL: ";
	break;

    case IPMI_LOG_ERR_INFO:
	pfx = "EINF: ";
	break;

    case IPMI_LOG_DEBUG_START:
	do_nl = 0;
	/* FALLTHROUGH */
    case IPMI_LOG_DEBUG:
	pfx = "DEBG: ";
	break;

    case IPMI_LOG_DEBUG_CONT:
	do_nl = 0;
	/* FALLTHROUGH */
    case IPMI_LOG_DEBUG_END:
	break;
    }

    len = strlen(pfx);
    memcpy(log, pfx, len);
    len += vsnprintf(log+len, sizeof(log)-len, format, ap);
    if ((len < sizeof(log)-1) && do_nl) {
	log[len] = '\n';
	len++;
	log[len] = '\0';
    }

    swig_call_cb(handler, "log", "%s", log);
}

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
    swig_cb  cb = cb_data;
    swig_ref domain_ref;

    if (!cb)
	return;

    ref_swig_cb(cb);
    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "domain_cb", "%p", domain_ref);
    swig_free_ref(domain_ref);
}

static void
domain_new_done(ipmi_domain_t *domain,
		int           err,
		unsigned int  conn_num,
		unsigned int  port_num,
		int           still_connected,
		void          *cb_data)
{
    swig_cb  cb = cb_data;
    swig_ref domain_ref;

    if (!cb)
	return;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "open_done_cb", "%p%d%d%d%d",
		 domain_ref, err, conn_num, port_num, still_connected);
    swig_free_ref(domain_ref);
}

void
domain_fully_up(ipmi_domain_t *domain, void *cb_data)
{
    swig_cb  cb = cb_data;
    swig_ref domain_ref;

    if (!cb)
	return;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "domain_up_cb", "%p", domain_ref);
    swig_free_ref(domain_ref);
}

static void
iterate_entities_handler(ipmi_entity_t *entity, void *cb_data)
{
    swig_cb  cb = cb_data;
    swig_ref entity_ref;

    if (!cb)
	return;

    ref_swig_cb(cb);
    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    swig_call_cb(cb, "entity_iter_cb", "%p", entity_ref);
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
void
init_posix(void)
{
    swig_os_hnd = ipmi_posix_setup_os_handler();
    ipmi_init(swig_os_hnd);
}

/* FIXME - add GTK, Tk, etc. init version here. */

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

    if (up)
	ref_swig_cb(up);
    if (done)
	ref_swig_cb(done);
    rv = ipmi_open_domain(name, con, set, domain_new_done, done,
			  domain_fully_up, up,
			  options, num_options, nd);
    if (rv) {
	if (up)
	    deref_swig_cb(up);
	if (done)
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

void
wait_io(void)
{
    swig_os_hnd->perform_one_op(swig_os_hnd, NULL);
}

void
set_log_handler(swig_cb handler)
{
    swig_cb old_handler = swig_log_handler;
    ref_swig_cb(handler);
    swig_log_handler = handler;
    if (old_handler)
	deref_swig_cb(old_handler);
}
%}


%extend ipmi_domain_id_t {
    ~ipmi_domain_id_t()
    {
	free(self);
    }

    char *call_pointer(swig_cb handler)
    {
	int rv;
	rv = ipmi_domain_pointer_cb(*self, handle_domain_cb, handler);
	if (rv)
	    return strerror(rv);
	return NULL;
    }
}

%extend ipmi_domain_t {
    %newobject get_name;
    char *get_name()
    {
	char name[IPMI_DOMAIN_NAME_LEN];

	ipmi_domain_get_name(self, name, sizeof(name));
	return strdup(name);
    }

    %newobject get_id;
    ipmi_domain_id_t *get_id()
    {
	ipmi_domain_id_t *rv = malloc(sizeof(*rv));
	if (rv)
	    *rv = ipmi_domain_convert_to_id(self);
	return rv;
    }

    void iterate_entities(swig_cb handler)
    {
	ipmi_domain_iterate_entities(self, iterate_entities_handler, handler);
    }
}

%extend ipmi_entity_t {
    %newobject get_name;
    char *get_name()
    {
	char name[IPMI_ENTITY_NAME_LEN];

	ipmi_entity_get_name(self, name, sizeof(name));
	return strdup(name);
    }

    %newobject get_id;
    ipmi_entity_id_t *get_id()
    {
	ipmi_entity_id_t *rv = malloc(sizeof(*rv));
	if (rv)
	    *rv = ipmi_entity_convert_to_id(self);
	return rv;
    }
}
