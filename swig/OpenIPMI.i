
%module OpenIPMI

%{
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/ipmi_glib.h>
#include <OpenIPMI/ipmi_debug.h>

#include "OpenIPMI.h"

typedef struct intarray
{
    int *val;
    int len;
} intarray;

os_handler_t *swig_os_hnd;

swig_cb_val swig_log_handler;

void
posix_vlog(char *format, enum ipmi_log_type_e log_type, va_list ap)
{
    char *pfx = "";
    static char log[1024];
    static int curr = 0;
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

static int
next_parm(char *s, int *start, int *next)
{
    while (s[*start] && isspace(s[*start]))
	(*start)++;
    if (!s[*start])
	return EINVAL;

    *next = *start;
    while (s[*next] && !isspace(s[*next]))
	(*next)++;
    return 0;
}

static int
next_colon_parm(char *s, int *start, int *next)
{
    while (s[*start] && (s[*start] == ':'))
	(*start)++;
    if (!s[*start])
	return EINVAL;

    *next = *start;
    while (s[*next] && (s[*next] != ':'))
	(*next)++;
    return 0;
}

static int
num_parm(char *s, int len, int *rval)
{
    char numstr[10];
    char *end;
    int  val;

    if (len > 9)
	return EINVAL;
    memcpy(numstr, s, len);
    numstr[len] = '\0';
    val = strtoul(numstr, &end, 0);
    if (*end != '\0')
	return EINVAL;
    *rval = val;
    return 0;
}

static int
parse_ipmi_addr(char *addr, int lun, ipmi_addr_t *i, unsigned int *addr_len)
{
    int start, next;
    int rv;
    int num;
    int len;

    start = 0;
    rv = next_parm(addr, &start, &next);
    if (rv)
	return rv;
    len = next - start;

    if (strncmp(addr+start, "smi", len) == 0) {
	ipmi_system_interface_addr_t *si = (void *) i;

	si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si->lun = lun;
	start = next;
	rv = next_parm(addr, &start, &next);
	if (rv)
	    return rv;
	len = next - start;
	rv = num_parm(addr+start, len, &num);
	if (rv)
	    return rv;
	si->channel = num;
	*addr_len = sizeof(*si);
    } else if (strncmp(addr+start, "ipmb", len) == 0) {
	ipmi_ipmb_addr_t *ipmb = (void *) i;

	ipmb->addr_type = IPMI_IPMB_ADDR_TYPE;
	ipmb->lun = lun;

	start = next;
	rv = next_parm(addr, &start, &next);
	if (rv)
	    return rv;
	len = next - start;
	rv = num_parm(addr+start, len, &num);
	if (rv)
	    return rv;
	ipmb->channel = num;

	start = next;
	rv = next_parm(addr, &start, &next);
	if (rv)
	    return rv;
	len = next - start;
	rv = num_parm(addr+start, len, &num);
	if (rv)
	    return rv;
	ipmb->slave_addr = num;

	*addr_len = sizeof(*ipmb);
    } else {
	return EINVAL;
    }

    return 0;
}

static void
make_ipmi_addr(char *out, int max_len, ipmi_addr_t *addr, int addr_len,
	       int *lun)
{
    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	ipmi_system_interface_addr_t *si = (void *) addr;
	snprintf(out, max_len, "smi %d", si->channel);
	*lun = si->lun;
    } else if (addr->addr_type == IPMI_IPMB_ADDR_TYPE) {
	ipmi_ipmb_addr_t *ipmb = (void *) addr;
	snprintf(out, max_len, "ipmb %d %d", ipmb->channel, ipmb->slave_addr);
	*lun = ipmb->lun;
    } else {
	strncpy(out, "unknown", max_len);
	*lun = 0;
    }
}

static int
parse_ipmi_data(intarray data, unsigned char *odata,
		unsigned int max_len,
		unsigned int *rlen)
{
    int i;
    if (data.len > max_len)
	return E2BIG;
    for (i=0; i<data.len; i++)
	odata[i] = data.val[i];
    *rlen = data.len;
    return 0;
}

%}

%nodefault;

%typemap(in) swig_cb {
    if (!SvROK($input))
	croak("Argument $argnum is not a reference.");
    $1 = $input;
}

%typemap(in) intarray {
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
    $1.val = (int *) malloc((len+2)*sizeof(int));
    $1.len = len + 1;
    
    for (i = 0; i <= len; i++) {
	tv = av_fetch(tempav, i, 0);
	$1.val[i] = SvIV(*tv);
    }
}

%typemap(freearg) intarray {
        free($1.val);
};

%typemap(out) intarray {
    AV *tempav;
    SV **svs;
    int i;

    svs = (SV **) malloc($1.len*sizeof(SV *));
    for (i=0; i<$1.len; i++) {
	svs[i] = sv_newmortal();
	sv_setiv(svs[i], $1.val[i]);
    }
    tempav = av_make($1.len, svs);
    free(svs);
    $result = newRV((SV *) tempav);
    sv_2mortal($result);
    argvi++;
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

#define swig_free_ref_check(r, c) \
	do {								\
	    if (SvREFCNT(SvRV(r.val)) != 1)				\
		warn("***You cannot keep pointers of class %s", c);	\
	    swig_free_ref(r);						\
	} while(0)

static void
handle_domain_cb(ipmi_domain_t *domain, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "domain_cb", "%p", &domain_ref);
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
}

static void
domain_connect_change_handler(ipmi_domain_t *domain,
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
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
}

static void
domain_iterate_connections_handler(ipmi_domain_t *domain, int conn,
				   void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "domain_iter_connection_cb", "%p%d", &domain_ref, conn);
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
}

static void
domain_event_handler(ipmi_domain_t *domain, ipmi_event_t *event, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;
    swig_ref    event_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    event_ref = swig_make_ref_destruct(ipmi_event_dup(event),
				       "OpenIPMI::ipmi_event_t");
    swig_call_cb(cb, "event_cb", "%p%p", &domain_ref, &event_ref);
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
    swig_free_ref(event_ref);
}

static void
domain_mc_updated_handler(enum ipmi_update_e op, ipmi_domain_t *domain,
			  ipmi_mc_t *mc, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;
    swig_ref    mc_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    mc_ref = swig_make_ref(mc, "OpenIPMI::ipmi_mc_t");
    swig_call_cb(cb, "mc_update_cb", "%s%p%p",
		 ipmi_update_e_string(op), &domain_ref, &mc_ref);
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
    swig_free_ref_check(mc_ref, "OpenIPMI::ipmi_mc_t");
}

static void
domain_entity_update_handler(enum ipmi_update_e op, ipmi_domain_t *domain,
			      ipmi_entity_t *entity, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;
    swig_ref    entity_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    swig_call_cb(cb, "entity_update_cb", "%s%p%p",
		 ipmi_update_e_string(op), &domain_ref, &entity_ref);
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
}

static void
domain_fully_up(ipmi_domain_t *domain, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "domain_up_cb", "%p", &domain_ref);
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
domain_close_done(void *cb_data)
{
    swig_cb_val cb = cb_data;

    swig_call_cb(cb, "close_done_cb", " ");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
domain_iterate_entities_handler(ipmi_entity_t *entity, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;
    swig_ref    entity_ref;

    domain_ref = swig_make_ref(ipmi_entity_get_domain(entity),
			       "OpenIPMI::ipmi_domain_t");
    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    swig_call_cb(cb, "entity_iter_cb", "%p%p", &domain_ref, &entity_ref);
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
}

static void
ipmb_mc_scan_handler(ipmi_domain_t *domain, int err, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "ipmb_mc_scan_cb", "%p%i", &domain_ref, err);
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
domain_reread_sels_handler(ipmi_domain_t *domain, int err, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "reread_sels_cb", "%p%i", &domain_ref, err);
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
}

static int
domain_msg_cb(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    swig_cb_val   cb = rspi->data1;
    swig_ref      domain_ref;
    ipmi_msg_t    *msg = &rspi->msg;
    ipmi_addr_t   *addr = &rspi->addr;
    int           addr_len = rspi->addr_len;
    char          addr_str[50];
    int           lun;

    make_ipmi_addr(addr_str, sizeof(addr_str), addr, addr_len, &lun);
    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    swig_call_cb(cb, "addr_cmd_cb", "%p%s%d%d%d%*s", &domain_ref, addr_str,
		 lun, msg->netfn, msg->cmd, msg->data_len, msg->data);
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
    
    return IPMI_MSG_ITEM_NOT_USED;
}

static void
domain_iterate_mcs_handler(ipmi_domain_t *domain, ipmi_mc_t *mc, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    domain_ref;
    swig_ref    mc_ref;

    domain_ref = swig_make_ref(domain, "OpenIPMI::ipmi_domain_t");
    mc_ref = swig_make_ref(mc, "OpenIPMI::ipmi_mc_t");
    swig_call_cb(cb, "domain_iter_mcs_cb", "%p%p", &domain_ref, &mc_ref);
    swig_free_ref_check(domain_ref, "OpenIPMI::ipmi_domain_t");
    swig_free_ref_check(mc_ref, "OpenIPMI::ipmi_mc_t");
}

static void
handle_entity_cb(ipmi_entity_t *entity, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    swig_call_cb(cb, "entity_cb", "%p", &entity_ref);
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
}

static void
entity_iterate_entities_handler(ipmi_entity_t *ent1,
				ipmi_entity_t *ent2,
				void          *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    ent1_ref;
    swig_ref    ent2_ref;

    ent1_ref = swig_make_ref(ent1, "OpenIPMI::ipmi_entity_t");
    ent2_ref = swig_make_ref(ent2, "OpenIPMI::ipmi_entity_t");
    swig_call_cb(cb, "entity_iter_entities_cb", "%p%p", &ent1_ref, &ent2_ref);
    swig_free_ref_check(ent2_ref, "OpenIPMI::ipmi_entity_t");
    swig_free_ref_check(ent1_ref, "OpenIPMI::ipmi_entity_t");
}

static void
entity_iterate_sensors_handler(ipmi_entity_t *entity,
			       ipmi_sensor_t *sensor,
			       void          *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;
    swig_ref    sensor_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    swig_call_cb(cb, "entity_iter_sensors_cb", "%p%p",
		 &entity_ref, &sensor_ref);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
}

static void
entity_iterate_controls_handler(ipmi_entity_t  *entity,
				ipmi_control_t *control,
				void           *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;
    swig_ref    control_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    control_ref = swig_make_ref(control, "OpenIPMI::ipmi_control_t");
    swig_call_cb(cb, "entity_iter_controls_cb", "%p%p",
		 &entity_ref, &control_ref);
    swig_free_ref_check(control_ref, "OpenIPMI::ipmi_control_t");
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
}

static int
entity_presence_handler(ipmi_entity_t *entity,
			int           present,
			void          *cb_data,
			ipmi_event_t  *event)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;
    swig_ref    event_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    event_ref = swig_make_ref_destruct(ipmi_event_dup(event),
				       "OpenIPMI::ipmi_event_t");
    swig_call_cb(cb, "entity_presence_cb", "%p%i%p",
		 &entity_ref, present, &event_ref);
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
    swig_free_ref(event_ref);
    return IPMI_EVENT_NOT_HANDLED;
}

static void
entity_sensor_update_handler(enum ipmi_update_e op,
			     ipmi_entity_t      *entity,
			     ipmi_sensor_t      *sensor,
			     void               *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;
    swig_ref    sensor_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    swig_call_cb(cb, "entity_sensor_cb", "%s%p%p",
		 ipmi_update_e_string(op), &entity_ref, &sensor_ref);
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
}

static void
entity_control_update_handler(enum ipmi_update_e op,
			      ipmi_entity_t      *entity,
			      ipmi_control_t     *control,
			      void               *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;
    swig_ref    control_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    control_ref = swig_make_ref(control, "OpenIPMI::ipmi_control_t");
    swig_call_cb(cb, "entity_control_cb", "%s%p%p",
		 ipmi_update_e_string(op), &entity_ref, &control_ref);
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
    swig_free_ref_check(control_ref, "OpenIPMI::ipmi_control_t");
}

static void
entity_fru_update_handler(enum ipmi_update_e op,
			  ipmi_entity_t      *entity,
			  void               *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;
    swig_ref    fru_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    fru_ref = swig_make_ref(ipmi_entity_get_fru, "OpenIPMI::ipmi_fru_t");
    swig_call_cb(cb, "entity_fru_cb", "%s%p%p",
		 ipmi_update_e_string(op), &entity_ref, &fru_ref);
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
    swig_free_ref_check(fru_ref, "OpenIPMI::ipmi_fru_t");
}

static int
entity_hot_swap_handler(ipmi_entity_t             *entity,
			enum ipmi_hot_swap_states last_state,
			enum ipmi_hot_swap_states curr_state,
			void                      *cb_data,
			ipmi_event_t              *event)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;
    swig_ref    event_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    event_ref = swig_make_ref_destruct(ipmi_event_dup(event),
				       "OpenIPMI::ipmi_event_t");
    swig_call_cb(cb, "entity_hot_swap_update_cb", "%p%s%s%p", &entity_ref,
		 ipmi_hot_swap_state_name(last_state),
		 ipmi_hot_swap_state_name(curr_state),
		 &event_ref);
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
    swig_free_ref(event_ref);
    return IPMI_EVENT_NOT_HANDLED;
}

static void
entity_get_hot_swap_handler(ipmi_entity_t             *entity,
			    int                       err,
			    enum ipmi_hot_swap_states state,
			    void                      *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    swig_call_cb(cb, "entity_hot_swap_update_cb", "%p%i%s", &entity_ref,
		 err, ipmi_hot_swap_state_name(state));
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
entity_get_hot_swap_time_handler(ipmi_entity_t  *entity,
				 int            err,
				 ipmi_timeout_t time,
				 void           *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    swig_call_cb(cb, "entity_hot_swap_get_time_cb", "%p%i%f", &entity_ref,
		 err, ((double) time) / 1000000000.0);
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
entity_set_hot_swap_time_handler(ipmi_entity_t  *entity,
				 int            err,
				 void           *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    swig_call_cb(cb, "entity_hot_swap_set_time_cb", "%p%i", &entity_ref, err);
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
entity_activate_handler(ipmi_entity_t  *entity,
			int            err,
			void           *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    entity_ref;

    entity_ref = swig_make_ref(entity, "OpenIPMI::ipmi_entity_t");
    swig_call_cb(cb, "entity_activate_cb", "%p%i", &entity_ref, err);
    swig_free_ref_check(entity_ref, "OpenIPMI::ipmi_entity_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
handle_mc_cb(ipmi_mc_t *mc, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    mc_ref;

    mc_ref = swig_make_ref(mc, "OpenIPMI::ipmi_mc_t");
    swig_call_cb(cb, "mc_cb", "%p", &mc_ref);
    swig_free_ref_check(mc_ref, "OpenIPMI::ipmi_mc_t");
}

static void
mc_active_handler(ipmi_mc_t  *mc,
		  int        active,
		  void       *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    mc_ref;

    mc_ref = swig_make_ref(mc, "OpenIPMI::ipmi_mc_t");
    swig_call_cb(cb, "mc_active_cb", "%p%i", &mc_ref, active);
    swig_free_ref_check(mc_ref, "OpenIPMI::ipmi_mc_t");
}

static void
mc_msg_cb(ipmi_mc_t  *mc,
	  ipmi_msg_t *msg,
	  void       *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    mc_ref;

    mc_ref = swig_make_ref(mc, "OpenIPMI::ipmi_mc_t");
    swig_call_cb(cb, "mc_cmd_cb", "%p%d%d%*s", &mc_ref,
		 msg->netfn, msg->cmd, msg->data_len, msg->data);
    swig_free_ref_check(mc_ref, "OpenIPMI::ipmi_mc_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
mc_reset_handler(ipmi_mc_t *mc, int err, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    mc_ref;

    mc_ref = swig_make_ref(mc, "OpenIPMI::ipmi_mc_t");
    swig_call_cb(cb, "mc_reset_cb", "%p%d", &mc_ref, err);
    swig_free_ref_check(mc_ref, "OpenIPMI::ipmi_mc_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
mc_events_enable_handler(ipmi_mc_t *mc, int err, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    mc_ref;

    mc_ref = swig_make_ref(mc, "OpenIPMI::ipmi_mc_t");
    swig_call_cb(cb, "mc_events_enable_cb", "%p%d", &mc_ref, err);
    swig_free_ref_check(mc_ref, "OpenIPMI::ipmi_mc_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
mc_reread_sensors_handler(ipmi_mc_t *mc, int err, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    mc_ref;

    mc_ref = swig_make_ref(mc, "OpenIPMI::ipmi_mc_t");
    swig_call_cb(cb, "mc_reread_sensors_cb", "%p%d", &mc_ref, err);
    swig_free_ref_check(mc_ref, "OpenIPMI::ipmi_mc_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
mc_reread_sel_handler(ipmi_mc_t *mc, int err, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    mc_ref;

    mc_ref = swig_make_ref(mc, "OpenIPMI::ipmi_mc_t");
    swig_call_cb(cb, "mc_reread_sel_cb", "%p%d", &mc_ref, err);
    swig_free_ref_check(mc_ref, "OpenIPMI::ipmi_mc_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
mc_sel_get_time_cb(ipmi_mc_t     *mc,
		   int           err,
		   unsigned long time,
		   void          *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    mc_ref;

    mc_ref = swig_make_ref(mc, "OpenIPMI::ipmi_mc_t");
    swig_call_cb(cb, "mc_reread_sel_cb", "%p%d%ld", &mc_ref, err, time);
    swig_free_ref_check(mc_ref, "OpenIPMI::ipmi_mc_t");
    /* One-time call, get rid of the CB. */
    deref_swig_cb_val(cb);
}

static void
handle_sensor_cb(ipmi_sensor_t *sensor, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;

    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    swig_call_cb(cb, "sensor_cb", "%p", &sensor_ref);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
}

static char *
threshold_str(char *s, enum ipmi_thresh_e thresh)
{
    if (thresh == IPMI_UPPER_NON_CRITICAL) {
	*s = 'u'; s++; *s = 'n'; s++;
    } else if (thresh == IPMI_UPPER_CRITICAL) {
	*s = 'u'; s++; *s = 'c'; s++;
    } else if (thresh == IPMI_UPPER_NON_RECOVERABLE) {
	*s = 'u'; s++; *s = 'r'; s++;
    } else if (thresh == IPMI_UPPER_NON_CRITICAL) {
	*s = 'l'; s++; *s = 'n'; s++;
    } else if (thresh == IPMI_UPPER_CRITICAL) {
	*s = 'l'; s++; *s = 'c'; s++;
    } else if (thresh == IPMI_UPPER_NON_RECOVERABLE) {
	*s = 'l'; s++; *s = 'r'; s++;
    }
    return s;
}

static char *
threshold_event_str(char                        *s, 
		    enum ipmi_thresh_e          thresh,
		    enum ipmi_event_value_dir_e value_dir,
		    enum ipmi_event_dir_e       dir)
{
    s = threshold_str(s, thresh);
    if (value_dir == IPMI_GOING_HIGH) {
	*s = 'h'; s++;
    } else {
	*s = 'l'; s++;
    }
    if (dir == IPMI_ASSERTION) {
	*s = 'a'; s++;
    } else {
	*s = 'd'; s++;
    }
    return s;
}

static char *
discrete_event_str(char                   *s, 
		   int                    offset,
		    enum ipmi_event_dir_e dir)
{
    if (offset >= 100)
	offset = 99;
    if (offset < 0)
	offset = 0;
    sprintf(s, "%d", offset);
    s += 2;
    if (dir == IPMI_ASSERTION) {
	*s = 'a'; s++;
    } else {
	*s = 'd'; s++;
    }
    return s;
}

static char *
threshold_event_state_to_str(ipmi_event_state_t *events)
{
    int                         len = 0;
    char                        *str;
    enum ipmi_thresh_e          thresh;
    enum ipmi_event_value_dir_e value_dir;
    enum ipmi_event_dir_e       dir;
    char                        *s;

    if (ipmi_event_state_get_events_enabled(events))
	len += strlen("events ");
    if (ipmi_event_state_get_scanning_enabled(events))
	len += strlen("scanning ");
    if (ipmi_event_state_get_busy(events))
	len += strlen("busy ");

    for (thresh = IPMI_LOWER_NON_CRITICAL;
	 thresh <= IPMI_UPPER_NON_RECOVERABLE; 
	 thresh++)
    {
	for (value_dir = IPMI_GOING_LOW;
	     value_dir <= IPMI_GOING_HIGH;
	     value_dir++)
	{
	    for (dir = IPMI_ASSERTION;
		 dir <= IPMI_DEASSERTION;
		 dir++)
	    {
		if (ipmi_is_threshold_event_set(events,thresh, value_dir, dir))
		    len += 5;
	    }
	}
    }

    str = malloc(len+1);
    
    if (ipmi_event_state_get_events_enabled(events))
	strcat("events ", str);
    if (ipmi_event_state_get_scanning_enabled(events))
	strcat("scanning ", str);
    if (ipmi_event_state_get_busy(events))
	strcat("busy ", str);
    s = str + strlen(str);

    for (thresh = IPMI_LOWER_NON_CRITICAL;
	 thresh <= IPMI_UPPER_NON_RECOVERABLE; 
	 thresh++)
    {
	for (value_dir = IPMI_GOING_LOW;
	     value_dir <= IPMI_GOING_HIGH;
	     value_dir++)
	{
	    for (dir = IPMI_ASSERTION;
		 dir <= IPMI_DEASSERTION;
		 dir++)
	    {
		if (!ipmi_is_threshold_event_set(events,thresh,value_dir,dir))
		    continue;

		s = threshold_event_str(s, thresh, value_dir, dir);
		*s = ' ';
		s++;
	    }
	}
    }

    len = strlen(str);
    if (len > 0)
	str[len-1] = '\0'; /* Remove the final space */

    return str;
}

static int
str_to_threshold_event_state(char               *str,
			     ipmi_event_state_t **events)
{
    enum ipmi_thresh_e          thresh;
    enum ipmi_event_value_dir_e value_dir;
    enum ipmi_event_dir_e       dir;
    ipmi_event_state_t          *e;
    int                         start, next;
    int                         rv;

    e = malloc(ipmi_event_state_size());
    ipmi_event_state_init(e);

    start = 0;
    rv = next_parm(str, &start, &next);
    while (!rv) {
	char *s = str+start;
	int  len = next - start;
	if (strncasecmp(s, "events", len) == 0)
	    ipmi_event_state_set_events_enabled(e, 1);
	else if (strncasecmp(s, "scanning", len) == 0)
	    ipmi_event_state_set_scanning_enabled(e, 1);
	else if (strncasecmp(s, "busy", len) == 0)
	    ipmi_event_state_set_busy(e, 1);
	else if (len != 4)
	    goto out_err;
	else {
	    if (strncasecmp(s, "un", 2) == 0)
		thresh = IPMI_UPPER_NON_CRITICAL;
	    else if (strncasecmp(s, "uc", 2) == 0)
		thresh = IPMI_UPPER_CRITICAL;
	    else if (strncasecmp(s, "ur", 2) == 0)
		thresh = IPMI_UPPER_NON_RECOVERABLE;
	    else if (strncasecmp(s, "ln", 2) == 0)
		thresh = IPMI_LOWER_NON_CRITICAL;
	    else if (strncasecmp(s, "lc", 2) == 0)
		thresh = IPMI_LOWER_CRITICAL;
	    else if (strncasecmp(s, "lr", 2) == 0)
		thresh = IPMI_LOWER_NON_RECOVERABLE;
	    else
		goto out_err;
	    s += 2;
	    if (*s == 'l')
		value_dir = IPMI_GOING_LOW;
	    else if (*s == 'h')
		value_dir = IPMI_GOING_HIGH;
	    else
		goto out_err;
	    s++;
	    if (*s == 'a')
		dir = IPMI_ASSERTION;
	    else if (*s == 'd')
		dir = IPMI_DEASSERTION;
	    else
		goto out_err;
	    ipmi_threshold_event_set(e, thresh, value_dir, dir);
	}
	start = next;
	rv = next_parm(str, &start, &next);
    }

    return 0;

 out_err:
    free(e);
    return EINVAL;
}

static char *
discrete_event_state_to_str(ipmi_event_state_t *events)
{
    int                   len = 0;
    char                  *str;
    int                   offset;
    enum ipmi_event_dir_e dir;
    char                  *s;

    if (ipmi_event_state_get_events_enabled(events))
	len += strlen("events ");
    if (ipmi_event_state_get_scanning_enabled(events))
	len += strlen("scanning ");
    if (ipmi_event_state_get_busy(events))
	len += strlen("busy ");

    for (offset=0; offset<15; offset++) {
	for (dir = IPMI_ASSERTION;
	     dir <= IPMI_DEASSERTION;
	     dir++)
	{
	    if (ipmi_is_discrete_event_set(events, offset, dir))
		    len += 4;
	}
    }

    str = malloc(len+1);
    
    if (ipmi_event_state_get_events_enabled(events))
	strcat("events ", str);
    if (ipmi_event_state_get_scanning_enabled(events))
	strcat("scanning ", str);
    if (ipmi_event_state_get_busy(events))
	strcat("busy ", str);
    s = str + strlen(str);

    for (offset=0; offset<15; offset++) {
	for (dir = IPMI_ASSERTION;
	     dir <= IPMI_DEASSERTION;
	     dir++)
	{
	    if (! ipmi_is_discrete_event_set(events, offset, dir))
		continue;

	    s = discrete_event_str(s, offset, dir);
	    *s = ' ';
	    s++;
	}
    }

    len = strlen(str);
    if (len > 0)
	str[len-1] = '\0'; /* Remove the final space */

    return str;
}

static int
str_to_discrete_event_state(char               *str,
			    ipmi_event_state_t **events)
{
    int                   offset;
    enum ipmi_event_dir_e dir;
    ipmi_event_state_t    *e;
    int                   start, next;
    int                   rv;

    e = malloc(ipmi_event_state_size());
    ipmi_event_state_init(e);

    start = 0;
    rv = next_parm(str, &start, &next);
    while (!rv) {
	char *s = str+start;
	int  len = next - start;
	if (strncasecmp(s, "events", len) == 0)
	    ipmi_event_state_set_events_enabled(e, 1);
	else if (strncasecmp(s, "scanning", len) == 0)
	    ipmi_event_state_set_scanning_enabled(e, 1);
	else if (strncasecmp(s, "busy", len) == 0)
	    ipmi_event_state_set_busy(e, 1);
	else if ((len < 2) || (len > 3))
	    goto out_err;
	else {
	    offset = strtoul(s, &s, 0);
	    if (offset >= 15)
		goto out_err;
	    if (*s == 'a')
		dir = IPMI_ASSERTION;
	    else if (*s == 'd')
		dir = IPMI_DEASSERTION;
	    else
		goto out_err;
	    ipmi_discrete_event_set(e, offset, dir);
	}
	start = next;
	rv = next_parm(str, &start, &next);
    }

    *events = e;
    return 0;

 out_err:
    free(e);
    return EINVAL;
}

static char *
threshold_states_to_str(ipmi_states_t *states)
{
    int                len = 0;
    char               *str;
    enum ipmi_thresh_e thresh;
    char               *s;

    if (ipmi_is_event_messages_enabled(states))
	len += strlen("events ");
    if (ipmi_is_sensor_scanning_enabled(states))
	len += strlen("scanning ");
    if (ipmi_is_initial_update_in_progress(states))
	len += strlen("busy ");

    for (thresh = IPMI_LOWER_NON_CRITICAL;
	 thresh <= IPMI_UPPER_NON_RECOVERABLE; 
	 thresh++)
    {
	if (ipmi_is_threshold_out_of_range(states, thresh))
	    len += 3;
    }

    str = malloc(len+1);
    
    if (ipmi_is_event_messages_enabled(states))
	strcat("events ", str);
    if (ipmi_is_sensor_scanning_enabled(states))
	strcat("scanning ", str);
    if (ipmi_is_initial_update_in_progress(states))
	strcat("busy ", str);
    s = str + strlen(str);

    for (thresh = IPMI_LOWER_NON_CRITICAL;
	 thresh <= IPMI_UPPER_NON_RECOVERABLE; 
	 thresh++)
    {
	if (!ipmi_is_threshold_out_of_range(states, thresh))
	    continue;

	s = threshold_str(s, thresh);
	*s = ' ';
	s++;
    }

    len = strlen(str);
    if (len > 0)
	str[len-1] = '\0'; /* Remove the final space */

    return str;
}

static char *
discrete_states_to_str(ipmi_states_t *states)
{
    int  len = 0;
    char *str;
    int  offset;
    char *s;

    if (ipmi_is_event_messages_enabled(states))
	len += strlen("events ");
    if (ipmi_is_sensor_scanning_enabled(states))
	len += strlen("scanning ");
    if (ipmi_is_initial_update_in_progress(states))
	len += strlen("busy ");

    for (offset=0; offset<15; offset++) {
	if (ipmi_is_state_set(states, offset))
	    len += 3;
    }

    str = malloc(len+1);
    
    if (ipmi_is_event_messages_enabled(states))
	strcat("events ", str);
    if (ipmi_is_sensor_scanning_enabled(states))
	strcat("scanning ", str);
    if (ipmi_is_initial_update_in_progress(states))
	strcat("busy ", str);
    s = str + strlen(str);

    for (offset=0; offset<15; offset++) {
	if (! ipmi_is_state_set(states, offset))
	    continue;

	s += sprintf(s, "%d", offset);
	*s = ' ';
	s++;
    }

    len = strlen(str);
    if (len > 0)
	str[len-1] = '\0'; /* Remove the final space */

    return str;
}

static char *
thresholds_to_str(ipmi_thresholds_t *t)
{
    int                len = 0;
    char               *str;
    enum ipmi_thresh_e thresh;
    char               dummy[3];
    char               *s;
    double             val;

    for (thresh = IPMI_LOWER_NON_CRITICAL;
	 thresh <= IPMI_UPPER_NON_RECOVERABLE; 
	 thresh++)
    {
	if (ipmi_threshold_get(t, thresh, &val) == 0)
	    len += snprintf(dummy, 1, "aa %f:", val);
    }

    str = malloc(len+1);
    s = str;
    
    len = 0;
    for (thresh = IPMI_LOWER_NON_CRITICAL;
	 thresh <= IPMI_UPPER_NON_RECOVERABLE; 
	 thresh++)
    {
	if (ipmi_threshold_get(t, thresh, &val) != 0)
	    continue;

	threshold_str(dummy, thresh);

	s += sprintf(s, "%s %f:", dummy, val);
	*s = ' ';
	s++;
    }

    len = strlen(str);
    if (len > 0)
	str[len-1] = '\0'; /* Remove the final : */

    return str;
}

static int
str_to_thresholds(char              *str,
		  ipmi_thresholds_t **thresholds)
{
    enum ipmi_thresh_e thresh;
    ipmi_thresholds_t  *t;
    int                start, next;
    int                rv;
    double             val;

    t = malloc(ipmi_thresholds_size());
    ipmi_thresholds_init(t);

    start = 0;
    rv = next_colon_parm(str, &start, &next);
    while (!rv) {
	char *s = str+start;
	char *endstr;
	int  len = next - start;
	if (len < 4)
	    goto out_err;

	if (strncasecmp(s, "un ", 3) == 0)
	    thresh = IPMI_UPPER_NON_CRITICAL;
	else if (strncasecmp(s, "uc ", 3) == 0)
	    thresh = IPMI_UPPER_CRITICAL;
	else if (strncasecmp(s, "ur ", 3) == 0)
	    thresh = IPMI_UPPER_NON_RECOVERABLE;
	else if (strncasecmp(s, "ln ", 3) == 0)
	    thresh = IPMI_LOWER_NON_CRITICAL;
	else if (strncasecmp(s, "lc ", 3) == 0)
	    thresh = IPMI_LOWER_CRITICAL;
	else if (strncasecmp(s, "lr ", 3) == 0)
	    thresh = IPMI_LOWER_NON_RECOVERABLE;
	else
	    goto out_err;
	    
	val = strtod(s+3, &endstr);
	if (*endstr != ':')
	    goto out_err;

	start = next;
	rv = next_parm(str, &start, &next);
    }

    *thresholds = t;
    return 0;

 out_err:
    free(t);
    return EINVAL;
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
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;
    char        eventstr[5];
    int         raw_set = 0;
    int         value_set = 0;
    swig_ref    event_ref;

    if (value_present == IPMI_RAW_VALUE_PRESENT)
	raw_set = 1;
    if (value_present == IPMI_BOTH_VALUES_PRESENT) {
	raw_set = 1;
	value_set = 1;
    }
    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    threshold_event_str(eventstr, threshold, high_low, dir);
    event_ref = swig_make_ref_destruct(ipmi_event_dup(event),
				       "OpenIPMI::ipmi_event_t");
    swig_call_cb(cb, "threshold_event_cb", "%p%s%d%d%d%f%p", &sensor_ref,
		 eventstr, raw_set, raw_value, value_set, value, &event_ref);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
    swig_free_ref(event_ref);
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
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;
    char        eventstr[5];
    swig_ref    event_ref;

    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    discrete_event_str(eventstr, offset, dir);
    event_ref = swig_make_ref_destruct(ipmi_event_dup(event),
				       "OpenIPMI::ipmi_event_t");
    swig_call_cb(cb, "threshold_event_cb", "%p%s%d%d%p", &sensor_ref,
		 eventstr, severity, prev_severity, &event_ref);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
    swig_free_ref(event_ref);
    return IPMI_EVENT_NOT_HANDLED;
}

/* A generic callback for a lot of things. */
static void
sensor_event_enable_handler(ipmi_sensor_t *sensor,
			    int           err,
			    void          *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;

    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    swig_call_cb(cb, "sensor_event_enable_cb", "%p%d", &sensor_ref, err);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
}

static void
sensor_get_event_enables_handler(ipmi_sensor_t      *sensor,
				 int                err,
				 ipmi_event_state_t *states,
				 void               *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;
    char        *st;

    if (ipmi_sensor_get_event_reading_type(sensor)
	== IPMI_EVENT_READING_TYPE_THRESHOLD)
    {
	st = threshold_event_state_to_str(states);
    } else {
	st = discrete_event_state_to_str(states);
    }

    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    swig_call_cb(cb, "sensor_get_event_enable_cb", "%p%d%s",
		 &sensor_ref, err, st);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
    free(st);
}

static void
sensor_rearm_handler(ipmi_sensor_t      *sensor,
		     int                err,
		     void               *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;

    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    swig_call_cb(cb, "sensor_rearm_cb", "%p%d", &sensor_ref, err);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
}

static void
sensor_get_hysteresis_handler(ipmi_sensor_t *sensor,
			      int           err,
			      unsigned int  positive_hysteresis,
			      unsigned int  negative_hysteresis,
			      void          *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;

    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    swig_call_cb(cb, "sensor_get_hysteresis_cb", "%p%d%d%d", &sensor_ref, err,
		 positive_hysteresis, negative_hysteresis);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
}

static void
sensor_set_hysteresis_handler(ipmi_sensor_t      *sensor,
			      int                err,
			      void               *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;

    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    swig_call_cb(cb, "sensor_set_hysteresis_cb", "%p%d", &sensor_ref, err);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
}

static void
sensor_set_thresholds_handler(ipmi_sensor_t      *sensor,
			      int                err,
			      void               *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;

    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    swig_call_cb(cb, "sensor_set_thresholds_cb", "%p%d", &sensor_ref, err);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
}

static void sensor_get_thresholds_handler(ipmi_sensor_t     *sensor,
					  int               err,
					  ipmi_thresholds_t *th,
					  void              *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;
    char        *thstr = thresholds_to_str(th);

    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    swig_call_cb(cb, "sensor_get_thresholds_cb", "%p%d%s", &sensor_ref, err,
		 thstr);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
    free(thstr);
}

static void
sensor_get_reading_handler(ipmi_sensor_t             *sensor,
			   int                       err,
			   enum ipmi_value_present_e value_present,
			   unsigned int              raw_value,
			   double                    value,
			   ipmi_states_t             *states,
			   void                      *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;
    int         raw_set = 0;
    int         value_set = 0;
    char        *statestr;

    if (value_present == IPMI_RAW_VALUE_PRESENT)
	raw_set = 1;
    if (value_present == IPMI_BOTH_VALUES_PRESENT) {
	raw_set = 1;
	value_set = 1;
    }
    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    statestr = threshold_states_to_str(states);
    swig_call_cb(cb, "threshold_reading_cb", "%p%d%d%d%f%s", &sensor_ref,
		 raw_set, raw_value, value_set, value, statestr);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
    free(statestr);
}

static void
sensor_get_states_handler(ipmi_sensor_t *sensor,
			  int           err,
			  ipmi_states_t *states,
			  void          *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    sensor_ref;
    char        *statestr;

    sensor_ref = swig_make_ref(sensor, "OpenIPMI::ipmi_sensor_t");
    statestr = discrete_states_to_str(states);
    swig_call_cb(cb, "discrete_states_cb", "%p%d%s", &sensor_ref,
		 err, statestr);
    swig_free_ref_check(sensor_ref, "OpenIPMI::ipmi_sensor_t");
    free(statestr);
}

static void
handle_control_cb(ipmi_control_t *control, void *cb_data)
{
    swig_cb_val cb = cb_data;
    swig_ref    control_ref;

    control_ref = swig_make_ref(control, "OpenIPMI::ipmi_control_t");
    swig_call_cb(cb, "control_cb", "%p", &control_ref);
    swig_free_ref_check(control_ref, "OpenIPMI::ipmi_control_t");
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

typedef struct {
} ipmi_fru_t;

typedef struct {
} ipmi_mc_t;

typedef struct {
} ipmi_mcid_t;

typedef struct {
} ipmi_event_t;

typedef struct {
} ipmi_sensor_t;

typedef struct {
} ipmi_sensor_id_t;

typedef struct {
} ipmi_control_t;

typedef struct {
} ipmi_control_id_t;

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
 * Perform one operation.  The first parameter is a timeout in
 * milliseconds.
 */
void
wait_io(int timeout)
{
    struct timeval tv = { (timeout / 1000), ((timeout + 999) % 1000) };
    swig_os_hnd->perform_one_op(swig_os_hnd, &tv);
}
%}

/*
 * A bug in swig (default parameters not used in inline) causes this
 * to have to not be in an inline and done the hard way.
 */
%{
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
 * The domain_up_cb methods is called with the following parmeters:
 * <domain>
 * The parameters of the connection change handler are defined in
 * the domain->add_connect_change_handler method.
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
	con_change = domain_connect_change_handler;
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
 * Set the handler for OpenIPMI logs.  The logs will be sent to the
 * "log" method of the first parameter.  The log method will receive
 * the following parameters:
 * <self>, <log_level (a string)>, and <log (a string)>.
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

ipmi_domain_id_t *open_domain(char *name, char **args,
			      swig_cb done = NULL, swig_cb up = NULL);
void set_log_handler(swig_cb handler = NULL);


/* These two defines simplify the functions that do addition/removal
   of callbacks.  The type is the object type (domain, entity, etc)
   and the name is the stuff in the middle of the name, ie
   (ipmi_<type>_add_<name>_handler.  The function that will be called
   with the info is <type>_<name>_handler. */
#define cb_add(type, name) \
	int         rv;						\
	swig_cb_val handler_val;				\
	if (! valid_swig_cb(handler))				\
	    return EINVAL;					\
	handler_val = ref_swig_cb(handler);			\
	rv = ipmi_ ## type ## _add_ ## name ## _handler		\
	    (self, type ## _ ## name ## _handler, handler_val);	\
	if (rv)							\
	    deref_swig_cb_val(handler_val);			\
	return rv;
#define cb_rm(type, name) \
	int         rv;						\
	swig_cb_val handler_val;				\
	if (! valid_swig_cb(handler))				\
	    return EINVAL;					\
	handler_val = get_swig_cb(handler);			\
	rv = ipmi_ ## type ## _remove_ ## name ##_handler	\
	    (self, type ## _ ## name ## _handler, handler_val);	\
	if (!rv)						\
	    deref_swig_cb_val(handler_val);			\
	return rv;
    

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
     * will be called on the first parameter with the following parameters:
     * <self> <domain>
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
    int close(swig_cb handler = NULL)
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
     * parameters: <self>, <domain>, <errorval>, <connection_number>,
     * <port_number>, <still_connected>.
     */
    int add_connect_change_handler(swig_cb handler)
    {
	cb_add(domain, connect_change);
    }

    /*
     * Remove the connection change handler.
     */
    int remove_connect_change_handler(swig_cb handler)
    {
	cb_rm(domain, connect_change);
    }

    /*
     * Iterate through all the connections in the object.  The
     * domain_iter_connection_cb method will be called on the first
     * parameter for each connection in the domain.  The parameters it
     * receives will be: <self>, <domain>, <connection (integer)>.
     */
    int iterate_connections(swig_cb handler)
    {
	swig_cb_val handler_val;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = get_swig_cb(handler);
	ipmi_domain_iterate_connections(self,
					domain_iterate_connections_handler,
					handler_val);
	return 0;
    }

    /*
     * Attempt to activate the given connection.
     */
    int activate_connection(int connection)
    {
	return ipmi_domain_activate_connection(self, connection);
    }

    /*
     * Parm 1 is a connection number.  Sets the second parameter to
     * true if the connection is active, false if not.  Returns an
     * error value.
     */
    int is_connection_active(int connection, unsigned int *active)
    {
	return ipmi_domain_is_connection_active(self, connection, active);
    }

    /*
     * Parm 1 is a connection number.  Sets the second parameter to true
     * if the connection is up, false if not.  Returns an error value.
     */
    int is_connection_up(int connection, unsigned int *up)
    {
	return ipmi_domain_is_connection_up(self, connection, up);
    }

    /*
     * Parm 1 is a connection number.  Sets the second parameter to
     * the number of ports in the connection.  A connection may have
     * multiple ports (ie, multiple IP addresses to the same BMC,
     * whereas a separate connection is a connection to a different
     * BMC); these functions let you check their status.  Returns an
     * error value.
     */
    int num_connection_ports(int connection, unsigned int *ports)
    {
	return ipmi_domain_num_connection_ports(self, connection, ports);
    }

    /*
     * Parm 1 is a connection number, parm 2 is a port number.  Sets
     * parm 3 to true if the given port is up, false if not.  Returns
     * an error value.
     */
    int is_connection_port_up(int          connection,
			      int          port,
			      unsigned int *up)
    {
	return ipmi_domain_is_connection_port_up(self, connection, port, up);
    }

    /*
     * Add a handler to be called when an entity is added, updated, or
     * removed. When the entity is updated the entity_updated_cb
     * method on the first parameter will be called with the following
     * parameters: <self>, added|deleted|changed <domain>, <entity>.
     */
    int add_entity_update_handler(swig_cb handler)
    {
	cb_add(domain, entity_update);
    }

    /*
     * Remove the connection change handler.
     */
    int remove_entity_update_handler(swig_cb handler)
    {
	cb_rm(domain, entity_update);
    }

    /*
     * Iterate through all the entities in the object.  The
     * domain_iter_entities_cb method will be called on the first
     * parameter for each entity in the domain.  The parameters it
     * receives will be: <self>, <domain>, <entity>.
     */
    int iterate_entities(swig_cb handler)
    {
	swig_cb_val handler_val;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = get_swig_cb(handler);
	ipmi_domain_iterate_entities(self, domain_iterate_entities_handler,
				     handler_val);
	return 0;
    }

    /*
     * Add a handler to be called when an MC is added, updated, or
     * removed. When the mc is updated the mc_update_cb method on the
     * first parameter will be called with the following parameters:
     * <self>, added|deleted|changed <domain>, <mc>.
     */
    int add_mc_update_handler(swig_cb handler)
    {
	cb_add(domain, mc_updated);
    }

    /*
     * Remove the connection change handler.
     */
    int remove_mc_update_handler(swig_cb handler)
    {
	cb_rm(domain, mc_updated);
    }

    /*
     * Iterate through all the MCs in the object.  The
     * mc_iter_cb method will be called on the first parameter for
     * each mc in the domain.  The parameters it receives will be:
     * <self>, <domain> <mc>.
     */
    int iterate_mcs(swig_cb handler)
    {
	swig_cb_val handler_val;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = get_swig_cb(handler);
	ipmi_domain_iterate_mcs(self, domain_iterate_mcs_handler, handler_val);
	return 0;
    }

    /*
     * Return the type of the domain, either unknown, mxp, or atca.
     * Others may be added later.
     */
    char *get_type()
    {
	return ipmi_domain_get_type_string(ipmi_domain_get_type(self));
    }

    /*
     * Scan all the addresses on the given channel (parm 1) between
     * (and including) start_addr (parm 2) and end_addr (parm 3) and
     * call the "ipmb_mc_scan_cb" method on the handler (parm4) with
     * the following parms:
     * <self>, <domain>, <error val>
     */
    int start_ipmb_mc_scan(int channel, int start_addr, int end_addr,
			   swig_cb handler = NULL)
    {
	int            rv;
	swig_cb_val    handler_val = NULL;
	ipmi_domain_cb domain_cb = NULL;

	if (valid_swig_cb(handler)) {
	    domain_cb = ipmb_mc_scan_handler;
	    handler_val = ref_swig_cb(handler);
	}
	rv = ipmi_start_ipmb_mc_scan(self, channel, start_addr, end_addr,
				     domain_cb, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Send a command to a given address (parm 1) with the given lun
     * (parm 2), netfn (parm 3), command (parm 4).  Parm 5 is the
     * message data in an array reference.  Parm 6 is the handler, it
     * will be called with the response.  The addr_cmd_cb method will
     * be called on the handler handler; its parameters are:
     * <domain> <addr> <lun> <netfn> <cmd> <response data>
     */
    int send_command_addr(char *addr, int lun, int netfn, int cmd,
			  intarray msg_data, swig_cb handler = NULL)
    {
	int                          rv;
	swig_cb_val                  handler_val = NULL;
	ipmi_addr_response_handler_t msg_cb = NULL;
	ipmi_addr_t                  iaddr;
	unsigned int                 addr_len;
	ipmi_msg_t                   msg;
	unsigned char                data[MAX_IPMI_DATA_SIZE];
	unsigned int                 data_len;

	rv = parse_ipmi_addr(addr, lun, &iaddr, &addr_len);
	if (rv)
	    return rv;

	msg.netfn = netfn;
	msg.cmd = cmd;
	msg.data = data;
	rv = parse_ipmi_data(msg_data, data, sizeof(data), &data_len);
	msg.data_len = data_len;
	if (rv)
	    return rv;

	if (valid_swig_cb(handler)) {
	    msg_cb = domain_msg_cb;
	    handler_val = ref_swig_cb(handler);
	}
	rv = ipmi_send_command_addr(self, &iaddr, addr_len, &msg,
				    msg_cb, handler_val, NULL);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Cause the domain to start detecting presence changes.  If parm
     * 1 is supplied, it tells whether to force all entities to have
     * their presence checked (if true) or just detect entity presence
     * for ones that might have changed.
     */
    int detect_presence_changes(int force = 0)
    {
	return ipmi_detect_domain_presence_changes(self, force);
    }

    /*
     * Set the time (in seconds) between SEL rescans for all
     * SELs in the domain
     */
    void set_sel_rescan_time(int seconds)
    {
	return ipmi_domain_set_sel_rescan_time(self, seconds);
    }

    /*
     * Get the default SEL rescan time for the domain.
     */
    int get_sel_rescan_time()
    {
	return ipmi_domain_get_sel_rescan_time(self);
    }

    /*
     * Set the time (in seconds) between IPMB bus rescans for the
     * domain.
     */
    void set_ipmb_rescan_time(int seconds)
    {
	return ipmi_domain_set_ipmb_rescan_time(self, seconds);
    }

    /*
     * Get the default IPMB rescan time for the domain.
     */
    int get_ipmb_rescan_time()
    {
	return ipmi_domain_get_ipmb_rescan_time(self);
    }

    /*
     * Add a handler to be called when a new unhandled event comes
     * into the domain.  When the event comes in, the event_cb method
     * on the first parameter will be called with the following
     * parameters: <self>, <domain>, <event>
     */
    int add_event_handler(swig_cb handler)
    {
	cb_add(domain, event);
    }

    /*
     * Remove the event handler.
     */
    int remove_event_handler(swig_cb handler)
    {
	cb_rm(domain, event);
    }

    %newobject ipmi_domain_first_event;
    /*
     * Retrieve the first event from the domain.  Return NULL (undef)
     * if the event does not exist.
     */
    ipmi_event_t *ipmi_domain_first_event()
    {
	return ipmi_domain_first_event(self);
    }

    %newobject ipmi_domain_last_event;
    /*
     * Retrieve the last event from the domain.
     */
    ipmi_event_t *ipmi_domain_last_event()
    {
	return ipmi_domain_last_event(self);
    }

    %newobject ipmi_domain_next_event;
    /*
     * Retrieve the event after the given event from the domain.
     */
    ipmi_event_t *ipmi_domain_next_event(ipmi_event_t  *event)
    {
	return ipmi_domain_next_event(self, event);
    }

    %newobject ipmi_domain_prev_event;;
    /*
     * Retrieve the event before the given event from the domain.
     */
    ipmi_event_t *ipmi_domain_prev_event(ipmi_event_t  *event)
    {
	return ipmi_domain_prev_event(self, event);
    }

    /*
     * Number of live entries in the local SEL copy.
     */
    int sel_count()
    {
	int          rv;
	unsigned int count;
	rv = ipmi_domain_sel_count(self, &count);
	if (rv)
	    return 0;
	else
	    return count;
    }

    /*
     * Number of entries in the the remote SEL.  If an entry has been
     * deleted in the local copy of the SEL but has not yet finished
     * being deleted in the remote copy, it will be counted here.
     */
    int sel_entries_used()
    {
	int          rv;
	unsigned int count;
	rv = ipmi_domain_sel_entries_used(self, &count);
	if (rv)
	    return 0;
	else
	    return count;
    }

    /*
     * Reread all SELs in the domain.  The callback (if supplied) will
     * be called with the following values:
     * <domain> <error value>
     */
    int domain_reread_sels(swig_cb handler = NULL)
    {
	int            rv;
	swig_cb_val    handler_val = NULL;
	ipmi_domain_cb domain_cb = NULL;

	if (valid_swig_cb(handler)) {
	    domain_cb = domain_reread_sels_handler;
	    handler_val = ref_swig_cb(handler);
	}
	rv = ipmi_domain_reread_sels(self, domain_cb, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }
}

/*
 * A entity id object.  This object is guaranteed to be valid and
 * can be converted into a entity pointer later.
 */
%extend ipmi_entity_id_t {
    ~ipmi_entity_id_t()
    {
	free(self);
    }

    /*
     * Convert a entity id to a entity pointer.  The "entity_cb" method
     * will be called on the first parameter with the following parameters:
     * <self> <entity>
     */
    char *convert_to_entity(swig_cb handler)
    {
	int rv;

	if (! valid_swig_cb(handler))
	    return NULL;

	rv = ipmi_entity_pointer_cb(*self, handle_entity_cb,
				    get_swig_cb(handler));
	if (rv)
	    return strerror(rv);
	return NULL;
    }
}

/*
 * And entity object.
 */
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

    /*
     * Iterate through all the entity's children.  The
     * entity_iter_entities_cb method will be called on the first
     * parameter for each child entity of the parent.  The parameters
     * it receives will be: <self> <parent> <child>.
     */
    int iterate_children(swig_cb handler)
    {
	swig_cb_val handler_val;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = get_swig_cb(handler);
	ipmi_entity_iterate_children(self, entity_iterate_entities_handler,
				     handler_val);
	return 0;
    }

    /*
     * Iterate through all the entity's parents.  The
     * entity_iter_entities_cb method will be called on the first
     * parameter for each parent entity of the child.  The parameters
     * it receives will be: <self> <child> <parent>.
     */
    int iterate_parents(swig_cb handler)
    {
	swig_cb_val handler_val;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = get_swig_cb(handler);
	ipmi_entity_iterate_parents(self, entity_iterate_entities_handler,
				    handler_val);
	return 0;
    }

    /*
     * Iterate through all the entity's sensors.  The
     * entity_iter_sensors_cb method will be called on the first
     * parameter for each sensor of the entity.  The parameters
     * it receives will be: <self> <entity> <sensor>.
     */
    int iterate_sensors(swig_cb handler)
    {
	swig_cb_val handler_val;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = get_swig_cb(handler);
	ipmi_entity_iterate_sensors(self, entity_iterate_sensors_handler,
				    handler_val);
	return 0;
    }

    /*
     * Iterate through all the entity's controls.  The
     * entity_iter_controls_cb method will be called on the first
     * parameter for each control of the entity.  The parameters
     * it receives will be: <self> <entity> <control>.
     */
    int iterate_controls(swig_cb handler)
    {
	swig_cb_val handler_val;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = get_swig_cb(handler);
	ipmi_entity_iterate_controls(self, entity_iterate_controls_handler,
				     handler_val);
	return 0;
    }

    /*
     * Add a handler to be called when an entity's presence
     * changes. When the presence changes the entity_presence_cb
     * method on the first parameter will be called with the following
     * parameters: <self> <entity> <present (boolean integer)> <event>.
     * The event is optional and may not be present.
     */
    int add_presence_handler(swig_cb handler)
    {
	cb_add(entity, presence);
    }

    /*
     * Remove the presence handler.
     */
    int remove_presence_handler(swig_cb handler)
    {
	cb_rm(entity, presence);
    }

    /*
     * Add a handler to be called when a sensor in the entity is added,
     * deleted, or updated.  When the sensor changes the entity_sensor_cb
     * method on the first parameter will be called with the following
     * parameters: <self> added|deleted|changed <entity> <sensor>.
     */
    int add_sensor_update_handler(swig_cb handler)
    {
	cb_add(entity, sensor_update);
    }

    /*
     * Remove the sensor update handler.
     */
    int remove_sensor_update_handler(swig_cb handler)
    {
	cb_rm(entity, sensor_update);
    }

    /*
     * Add a handler to be called when a control in the entity is added,
     * deleted, or updated.  When the control changes the entity_control_cb
     * method on the first parameter will be called with the following
     * parameters: <self> added|deleted|changed <entity> <control>.
     */
    int add_control_update_handler(swig_cb handler)
    {
	cb_add(entity, control_update);
    }

    /*
     * Remove the control update handler.
     */
    int remove_control_update_handler(swig_cb handler)
    {
	cb_rm(entity, control_update);
    }

    /*
     * Add a handler to be called when the FRU data in the entity is added,
     * deleted, or updated.  When the FRU data changes the entity_fru_cb
     * method on the first parameter will be called with the following
     * parameters: <self> added|deleted|changed <entity> <fru>.
     */
    int add_fru_update_handler(swig_cb handler)
    {
	cb_add(entity, fru_update);
    }

    /*
     * Remove the FRU data update handler.
     */
    int remove_fru_update_handler(swig_cb handler)
    {
	cb_rm(entity, fru_update);
    }

    /*
     * Get the entities type, return "mc", "fru", "generic", or "unknown".
     */
    char *get_type()
    {
	switch (ipmi_entity_get_type(self)) {
	case IPMI_ENTITY_MC: return "mc";
	case IPMI_ENTITY_FRU: return "fru";
	case IPMI_ENTITY_GENERIC: return "generic";
	default: return "unknown";
	}
    }

    /*
     * Returns if the entity has FRU data or not.
     */
    int is_fru()
    {
	return ipmi_entity_get_is_fru(self);
    }

    /*
     * Returns the domain for the entity.
     */
    ipmi_domain_t *get_domain()
    {
	return ipmi_entity_get_domain(self);
    }

    /*
     * Get the entity id for the entity
     */
    int get_entity_id()
    {
	return ipmi_entity_get_entity_id(self);
    }

    /*
     * Get the entity instance for the entity
     */
    int get_entity_instance()
    {
	return ipmi_entity_get_entity_instance(self);
    }

    /*
     * Get the channel for the entity.  Only valid if the entity
     * instance is 0x60 or larger.
     */
    int get_entity_device_channel()
    {
	return ipmi_entity_get_device_channel(self);
    }

    /*
     * Get the address for the entity.  Only valid if the entity
     * instance is 0x60 or larger.
     */
    int get_entity_device_address()
    {
	return ipmi_entity_get_device_address(self);
    }

    /*
     * Get the FRU data for the entity.  Note that you cannot hold the
     * FRU data pointer outside the context of where the entity pointer
     * is valid.
     */
    ipmi_fru_t *get_fru()
    {
	return ipmi_entity_get_fru(self);
    }

    /*
     * If this returns true, then the presence sensor is always there
     * for this entity.
     */
    int get_presence_sensor_always_there()
    {
	return ipmi_entity_get_presence_sensor_always_there(self);
    }

    /*
     * Returns if the entity has a parent.
     */
    int is_child()
    {
	return ipmi_entity_get_is_child(self);
    }

    /*
     * Returns if the entity has a child.
     */
    int is_parent()
    {
	return ipmi_entity_get_is_parent(self);
    }

    /*
     * Return the channel from the device locator record.  Valid for
     * all entities except unknown.
     */
    int get_channel()
    {
	return ipmi_entity_get_channel(self);
    }

    /*
     * Return the LUN from the device locator record.  Valid for
     * all entities except unknown.
     */
    int get_lun()
    {
	return ipmi_entity_get_lun(self);
    }

    /*
     * Return the OEM byte from the device locator record.  Valid for
     * all entities except unknown.
     */
    int get_oem()
    {
	return ipmi_entity_get_oem(self);
    }

    /*
     * Return the access address from the device locator record.  Valid for
     * FRU and generic entities.
     */
    int get_access_address()
    {
	return ipmi_entity_get_access_address(self);
    }

    /*
     * Return the private bus id from the device locator record.  Valid for
     * FRU and generic entities.
     */
    int get_private_bus_id()
    {
	return ipmi_entity_get_private_bus_id(self);
    }

    /*
     * Return the device type from the device locator record.  Valid for
     * FRU and generic entities.
     */
    int get_device_type()
    {
	return ipmi_entity_get_device_type(self);
    }

    /*
     * Return the device modifier from the device locator record.
     * Valid for FRU and generic entities.
     */
    int get_device_modifier()
    {
	return ipmi_entity_get_device_modifier(self);
    }

    /*
     * Return the slave address from the device locator record.  Valid for
     * MC and generic entities.
     */
    int get_slave_address()
    {
	return ipmi_entity_get_slave_address(self);
    }


    /*
     * Return if the FRU is logical (from the device locator record).
     * Valid for FRU entities.
     */
    int get_is_logical_fru()
    {
	return ipmi_entity_get_is_logical_fru(self);
    }

    /*
     * Return the device id from the device locator record.  Valid for
     * FRU entities.
     */
    int get_fru_device_id()
    {
	return ipmi_entity_get_fru_device_id(self);
    }

    /*
     * Return the ACPI system power notify required bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_ACPI_system_power_notify_required()
    {
	return ipmi_entity_get_ACPI_system_power_notify_required(self);
    }

    /*
     * Return the ACPI device power notify required bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_ACPI_device_power_notify_required()
    {
	return ipmi_entity_get_ACPI_device_power_notify_required(self);
    }

    /*
     * Return the controller logs init agent errors bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_controller_logs_init_agent_errors()
    {
	return ipmi_entity_get_controller_logs_init_agent_errors(self);
    }

    /*
     * Return the log init agent errors accessing bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_log_init_agent_errors_accessing()
    {
	return ipmi_entity_get_log_init_agent_errors_accessing(self);
    }

    /*
     * Return the global init bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_global_init()
    {
	return ipmi_entity_get_global_init(self);
    }

    /*
     * Return the chassis device bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_chassis_device()
    {
	return ipmi_entity_get_chassis_device(self);
    }

    /*
     * Return the !bridge bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_bridge()
    {
	return ipmi_entity_get_bridge(self);
    }

    /*
     * Return the IPMB event generator bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_IPMB_event_generator()
    {
	return ipmi_entity_get_IPMB_event_generator(self);
    }

    /*
     * Return the IPMB event receiver bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_IPMB_event_receiver()
    {
	return ipmi_entity_get_IPMB_event_receiver(self);
    }

    /*
     * Return the FRU inventory device bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_FRU_inventory_device()
    {
	return ipmi_entity_get_FRU_inventory_device(self);
    }

    /*
     * Return the SEL device bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_SEL_device()
    {
	return ipmi_entity_get_SEL_device(self);
    }

    /*
     * Return the SDR repository device bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_SDR_repository_device()
    {
	return ipmi_entity_get_SDR_repository_device(self);
    }

    /*
     * Return the sensor device bit from the
     * device locator record.  Valid for MC entities.
     */
    int get_sensor_device()
    {
	return ipmi_entity_get_sensor_device(self);
    }

    /*
     * Return the address span from the device locator record.  Valid
     * for generic entities.
     */
    int get_address_span()
    {
	return ipmi_entity_get_address_span(self);
    }

    %newobject get_id;
    /*
     * Return the id string from the DLR.
     */
    char *get_dlr_id()
    {
	/* FIXME - no unicode handling. */
	int len = ipmi_entity_get_id_length(self) + 1;
	char *id = malloc(len);
	ipmi_entity_get_id(self, id, len);
	return id;
    }

    /*
     * Returns true if the entity is present, false if not.
     */
    int is_present()
    {
	return ipmi_entity_is_present(self);
    }

    /*
     * Returns true if the entity is hot-swappable, false if not.
     */
    int is_hot_swappable()
    {
	return ipmi_entity_hot_swappable(self);
    }

    /*
     * Add a handler to be called when the hot-swap state for the
     * entity changes.  When the hot-swap state changes the
     * entity_hot_swap_update_cb method on the first parameter will be
     * called with the following parameters: <self> <entity> <old
     * state> <new state> <event>.  The event is optional and may not
     * be present.
     */
    int add_hot_swap_handler(swig_cb handler)
    {
	cb_add(entity, hot_swap);
    }

    /*
     * Remove the hot-swap update handler.
     */
    int remove_hot_swap_handler(swig_cb handler)
    {
	cb_rm(entity, hot_swap);
    }

    /*
     * Get the current hot-swap state for the entity.  The
     * entity_hot_swap_cb handler will be called with the following
     * parameters: <self> <entity> <err> <state>
     */
    int get_hot_swap_state(swig_cb handler)
    {
	swig_cb_val handler_val;
	int         rv;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = ref_swig_cb(handler);
	rv = ipmi_entity_get_hot_swap_state(self,
					    entity_get_hot_swap_handler,
					    handler_val);
	if (rv)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Get the current hot-swap activation time for the entity.  The
     * entity_hot_swap_time_cb handler will be called with the
     * following parameters: <self> <entity> <err> <time>
     */
    int get_auto_activate_time(swig_cb handler)
    {
	swig_cb_val handler_val;
	int         rv;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = ref_swig_cb(handler);
	rv = ipmi_entity_get_auto_activate_time
	    (self,
	     entity_get_hot_swap_time_handler,
	     handler_val);
	if (rv)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Set the current hot-swap activation time for the entity.  The
     * entity_hot_swap_time_cb handler will be called with the
     * following parameters: <self> <entity> <err>
     */
    int set_auto_activate_time(ipmi_timeout_t auto_act,
			       swig_cb        handler = NULL)
    {
	swig_cb_val    handler_val = NULL;
	ipmi_entity_cb done = NULL;
	int            rv;

	if (valid_swig_cb(handler)) {
	    handler_val = ref_swig_cb(handler);
	    done = entity_set_hot_swap_time_handler;
	}
	rv = ipmi_entity_set_auto_activate_time
	    (self, auto_act, done, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Get the current hot-swap deactivation time for the entity.  The
     * entity_hot_swap_time_cb handler will be called with the
     * following parameters: <self> <entity> <err> <time>
     */
    int get_auto_deactivate_time(swig_cb handler)
    {
	swig_cb_val handler_val;
	int         rv;

	if (! valid_swig_cb(handler))
	    return EINVAL;

	handler_val = ref_swig_cb(handler);
	rv = ipmi_entity_get_auto_deactivate_time
	    (self,
	     entity_get_hot_swap_time_handler,
	     handler_val);
	if (rv)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Set the current hot-swap deactivation time for the entity.  The
     * entity_hot_swap_time_cb handler will be called with the
     * following parameters: <self> <entity> <err>
     */
    int set_auto_deactivate_time(ipmi_timeout_t auto_act,
				 swig_cb        handler = NULL)
    {
	swig_cb_val    handler_val = NULL;
	ipmi_entity_cb done = NULL;
	int            rv;

	if (valid_swig_cb(handler)) {
	    handler_val = ref_swig_cb(handler);
	    done = entity_set_hot_swap_time_handler;
	}
	rv = ipmi_entity_set_auto_deactivate_time
	    (self, auto_act, done, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Cause the entity to move from INACTIVE to ACTIVATION_REQUESTED
     * state, if possible. If the entity does not support this
     * operation, this will return ENOSYS and you can move straight
     * from INACTIVE to ACTIVE state by calling ipmi_entity_activate.
     * After this is done, the entity_activate_cb handler will be
     * called with the following parameters: <self> <entity> <err>
     */
    int set_activation_requested(swig_cb handler = NULL)
    {
	swig_cb_val    handler_val = NULL;
	ipmi_entity_cb done = NULL;
	int            rv;

	if (valid_swig_cb(handler)) {
	    handler_val = ref_swig_cb(handler);
	    done = entity_activate_handler;
	}
	rv = ipmi_entity_set_activation_requested(self, done, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Attempt to activate an entity.  Activate will cause a
     * transition from INACTIVE to ACTIVE (but only if
     * ipmi_entity_set_activation_requested() returns ENOSYS), or from
     * ACTIVATION_REQUESTED to ACTIVE.  After this is done, the
     * entity_activate_cb handler will be called with the following
     * parameters: <self> <entity> <err>
     */
    int activate(swig_cb handler = NULL)
    {
	swig_cb_val    handler_val = NULL;
	ipmi_entity_cb done = NULL;
	int            rv;

	if (valid_swig_cb(handler)) {
	    handler_val = ref_swig_cb(handler);
	    done = entity_activate_handler;
	}
	rv = ipmi_entity_activate(self, done, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Attempt to deactivate an entity.  Deactivate will cause a
     * transition from DEACTIVATION_REQUESTED or ACTIVE to INACTIVE.
     * After this is done, the entity_activate_cb handler will be
     * called with the following parameters: <self> <entity> <err>
     */
    int deactivate(swig_cb handler = NULL)
    {
	swig_cb_val    handler_val = NULL;
	ipmi_entity_cb done = NULL;
	int         rv;

	if (valid_swig_cb(handler)) {
	    handler_val = ref_swig_cb(handler);
	    done = entity_activate_handler;
	}
	rv = ipmi_entity_deactivate(self, done, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Check the state of hot-swap for the entity.  This causes the
     * local state to be audited against the actual state.
     */
    int check_hot_swap_state()
    {
	return ipmi_entity_check_hot_swap_state(self);
    }

}

/*
 * A mc id object.  This object is guaranteed to be valid and
 * can be converted into a mc pointer later.
 */
%extend ipmi_mcid_t {
    ~ipmi_mcid_t()
    {
	free(self);
    }

    /*
     * Convert a mc id to a mc pointer.  The "mc_cb" method
     * will be called on the first parameter with the following parameters:
     * <self> <mc>
     */
    char *convert_to_mc(swig_cb handler)
    {
	int rv;

	if (! valid_swig_cb(handler))
	    return NULL;

	rv = ipmi_mc_pointer_cb(*self, handle_mc_cb,
				get_swig_cb(handler));
	if (rv)
	    return strerror(rv);
	return NULL;
    }
}

/*
 * An MC object
 */
%extend ipmi_mc_t {
    %newobject get_name;
    /*
     * Get the name of an mc.
     */
    char *get_name()
    {
	char name[IPMI_MC_NAME_LEN];

	ipmi_mc_get_name(self, name, sizeof(name));
	return strdup(name);
    }

    %newobject get_id;
    /*
     * Get the id for the mc.
     */
    ipmi_mcid_t *get_id()
    {
	ipmi_mcid_t *rv = malloc(sizeof(*rv));
	if (rv)
	    *rv = ipmi_mc_convert_to_id(self);
	return rv;
    }

    /*
     * Return the domain the MC is in.
     */
    ipmi_domain_t *get_domain()
    {
	return ipmi_mc_get_domain(self);
    }

    /*
     * Get the provides_device_sdrs from the get device id response
     * from the MC.
     */
    int provides_device_sdrs()
    {
	return ipmi_mc_provides_device_sdrs(self);
    }

    /*
     * Get the device_available bit from the get device id response
     * from the MC.
     */
    int device_available()
    {
	return ipmi_mc_device_available(self);
    }

    /*
     * Get the chassis_support bit from the get device id response
     * from the MC.
     */
    int chassis_support()
    {
	return ipmi_mc_chassis_support(self);
    }

    /*
     * Get the bridge_support bit from the get device id response
     * from the MC.
     */
    int bridge_support()
    {
	return ipmi_mc_bridge_support(self);
    }

    /*
     * Get the ipmb_event_generator_support bit from the get device id response
     * from the MC.
     */
    int ipmb_event_generator_support()
    {
	return ipmi_mc_ipmb_event_generator_support(self);
    }

    /*
     * Get the ipmb_event_receiver_support bit from the get device id response
     * from the MC.
     */
    int ipmb_event_receiver_support()
    {
	return ipmi_mc_ipmb_event_receiver_support(self);
    }

    /*
     * Get the fru_inventory_support bit from the get device id response
     * from the MC.
     */
    int fru_inventory_support()
    {
	return ipmi_mc_fru_inventory_support(self);
    }

    /*
     * Get the sel_device_support bit from the get device id response
     * from the MC.
     */
    int sel_device_support()
    {
	return ipmi_mc_sel_device_support(self);
    }

    /*
     * Get the sdr_repository_support bit from the get device id response
     * from the MC.
     */
    int sdr_repository_support()
    {
	return ipmi_mc_sdr_repository_support(self);
    }

    /*
     * Get the sensor_device_support bit from the get device id response
     * from the MC.
     */
    int sensor_device_support()
    {
	return ipmi_mc_sensor_device_support(self);
    }

    /*
     * Get the device_id from the get device id response
     * from the MC.
     */
    int device_id()
    {
	return ipmi_mc_device_id(self);
    }

    /*
     * Get the device_revision from the get device id response
     * from the MC.
     */
    int device_revision()
    {
	return ipmi_mc_device_revision(self);
    }

    /*
     * Get the major_fw_revision from the get device id response
     * from the MC.
     */
    int major_fw_revision()
    {
	return ipmi_mc_major_fw_revision(self);
    }

    /*
     * Get the minor_fw_revision from the get device id response
     * from the MC.
     */
    int minor_fw_revision()
    {
	return ipmi_mc_minor_fw_revision(self);
    }

    /*
     * Get the major_version from the get device id response
     * from the MC.
     */
    int major_version()
    {
	return ipmi_mc_major_version(self);
    }

    /*
     * Get the minor_version from the get device id response
     * from the MC.
     */
    int minor_version()
    {
	return ipmi_mc_minor_version(self);
    }

    /*
     * Get the manufacturer_id from the get device id response
     * from the MC.
     */
    int manufacturer_id()
    {
	return ipmi_mc_manufacturer_id(self);
    }

    /*
     * Get the product_id from the get device id response
     * from the MC.
     */
    int product_id()
    {
	return ipmi_mc_product_id(self);
    }

    /*
     * Get the auxiliary firmware revision.  This returns a string
     * with four bytes set.
     */
    %newobject aux_fw_revision;
    char *aux_fw_revision()
    {
	char *str;
	unsigned char data[4];

	str = malloc(28);
	ipmi_mc_aux_fw_revision(self, data);
	snprintf(str, 28,
		 "0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x",
		 data[0], data[1], data[2], data[3]);
	return str;
    }

    /*
     * Check to see if the MC is operational in the system.  If this
     * is return sfalse, then the MC was referred to by an SDR, but it
     * doesn't really exist (at least not yet).
     */
    int is_active()
    {
	return ipmi_mc_is_active(self);
    }

    /*
     * Add a handler to be called when an mc's active state
     * changes. When the active state changes the mc_active_cb
     * method on the first parameter will be called with the following
     * parameters: <self> <mc> <active (boolean integer)>.
     */
    int add_active_handler(swig_cb handler)
    {
	cb_add(mc, active);
    }

    /*
     * Remove the presence handler.
     */
    int remove_active_handler(swig_cb handler)
    {
	cb_rm(mc, active);
    }

    /*
     * Send a command to a given MC with the given lun
     * (parm 1), netfn (parm 2), command (parm 3).  Parm 4 is the
     * message data in an array reference.  Parm 5 is the handler, it
     * will be called with the response.  The mc_cmd_cb method will
     * be called on the handler handler; its parameters are:
     * <mc> <netfn> <cmd> <response data>
     */
    int ipmi_mc_send_command(int       lun,
			     int       netfn,
			     int       cmd,
			     intarray  msg_data,
			     swig_cb   handler = NULL)
    {
	int                        rv;
	swig_cb_val                handler_val = NULL;
	ipmi_mc_response_handler_t msg_cb = NULL;
	ipmi_msg_t                 msg;
	unsigned char              data[MAX_IPMI_DATA_SIZE];
	unsigned int               data_len;

	msg.netfn = netfn;
	msg.cmd = cmd;
	msg.data = data;
	rv = parse_ipmi_data(msg_data, data, sizeof(data), &data_len);
	msg.data_len = data_len;
	if (rv)
	    return rv;

	if (valid_swig_cb(handler)) {
	    msg_cb = mc_msg_cb;
	    handler_val = ref_swig_cb(handler);
	}
	rv = ipmi_mc_send_command(self, lun, &msg, msg_cb, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

#define IPMI_MC_RESET_COLD 1
#define IPMI_MC_RESET_WARM 2
    /*
     * Reset the MC, either a cold or warm reset depending on the
     * first parm.  Note that the effects of a reset are not defined
     * by IPMI, so this might do wierd things.  Some systems do not
     * support resetting the MC.  This is not a standard control
     * because there is no entity to hang if from and you don't want
     * people messing with it unless they really know what they are
     * doing.  When the reset is complete the mc_reset_cb will
     * be called on the second parameter of this call with the
     * following parameters: <self> <mc> <err>
     */
    int reset(int     reset_type,
	      swig_cb handler = NULL)
    {
	swig_cb_val     handler_val = NULL;
	ipmi_mc_done_cb done = NULL;
	int             rv;

	if (valid_swig_cb(handler)) {
	    handler_val = ref_swig_cb(handler);
	    done = mc_reset_handler;
	}
	rv = ipmi_mc_reset(self, reset_type, done, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /* Get the setting to enable events for the entire MC.  The value
       returned by the get function is a boolean telling whether
       events are enabled. */
    int get_events_enable()
    {
	return ipmi_mc_get_events_enable(self);
    }

    /*
     * Set the setting to enable events for the entire MC.  The "val"
     * passed in as the first parameter is a boolean telling whether
     * to turn events on (true) or off (false).  When the operation
     * completes the mc_events_enable_cb will be called on the handler
     * with the following parameters: <self> <mc> <err>.
     */
    int set_events_enable(int     val,
			  swig_cb handler = NULL)
    {
	swig_cb_val     handler_val = NULL;
	ipmi_mc_done_cb done = NULL;
	int             rv;

	if (valid_swig_cb(handler)) {
	    handler_val = ref_swig_cb(handler);
	    done = mc_events_enable_handler;
	}
	rv = ipmi_mc_set_events_enable(self, val, done, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }


    /*
     * Reread all the sensors for a given mc.  This will request the
     * device SDRs for that mc (And only for that MC) and change the
     * sensors as necessary. */
    int reread_sensors(swig_cb handler = NULL)
    {
	swig_cb_val     handler_val = NULL;
	ipmi_mc_done_cb done = NULL;
	int             rv;

	if (valid_swig_cb(handler)) {
	    handler_val = ref_swig_cb(handler);
	    done = mc_reread_sensors_handler;
	}
	rv = ipmi_mc_reread_sensors(self, done, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Set the time between SEL rescans for the MC (and only that MC).
     * Parm 1 is the time in seconds.
     */
    void ipmi_mc_set_sel_rescan_time(unsigned int seconds)
    {
	ipmi_mc_set_sel_rescan_time(self, seconds);
    }

    /*
     * Return the current SEL rescan time for the MC.
     */
    int get_sel_rescan_time()
    {
	return ipmi_mc_get_sel_rescan_time(self);
    }

    /* Reread the sel for the MC.  When the hander is called, all the
     * events in the SEL have been fetched into the local copy of the SEL
     * (with the obvious caveat that this is a distributed system and
     * other things may have come in after the read has finised).
     * When this completes, the mc_reread_sel_cb method will be called
     * on the handler (parm 1) with the parameters: <self> <mc> <err>. */
    int reread_sel(swig_cb handler = NULL)
    {
	swig_cb_val     handler_val = NULL;
	ipmi_mc_done_cb done = NULL;
	int             rv;

	if (valid_swig_cb(handler)) {
	    handler_val = ref_swig_cb(handler);
	    done = mc_reread_sel_handler;
	}
	rv = ipmi_mc_reread_sel(self, done, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /* Fetch the current time from the SEL. */
    int get_current_sel_time(swig_cb handler)
    {
	swig_cb_val     handler_val = NULL;
	sel_get_time_cb done = NULL;
	int             rv;

	if (valid_swig_cb(handler)) {
	    handler_val = ref_swig_cb(handler);
	    done = mc_sel_get_time_cb;
	}
	rv = ipmi_mc_get_current_sel_time(self, done, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    %newobject first_event;
    /*
     * Retrieve the first event from the MC.  Return NULL (undef)
     * if the event does not exist.
     */
    ipmi_event_t *first_event()
    {
	return ipmi_mc_first_event(self);
    }

    %newobject last_event;
    /*
     * Retrieve the last event from the MC.
     */
    ipmi_event_t *last_event()
    {
	return ipmi_mc_last_event(self);
    }

    %newobject next_event;
    /*
     * Retrieve the next event from the MC.
     */
    ipmi_event_t *next_event(ipmi_mc_t *mc, ipmi_event_t *event)
    {
	return ipmi_mc_next_event(self, event);
    }

    %newobject prev_event;
    /*
     * Retrieve the previous event from the MC.
     */
    ipmi_event_t *prev_event(ipmi_mc_t *mc, ipmi_event_t *event)
    {
	return ipmi_mc_prev_event(self, event);
    }

    %newobject event_by_recid;
    /*
     * Retrieve the event with the given record id from the MC.
     */
    ipmi_event_t *event_by_recid(ipmi_mc_t *mc,
				  int      record_id)
    {
	return ipmi_mc_event_by_recid(self, record_id);
    }

    /*
     * The number of live items in the local copy of the MC's SEL.
     */
    int sel_count()
    {
	return ipmi_mc_sel_count(self);
    }

    /*
     * Number of entries in the the remote SEL.  If an entry has been
     * deleted in the local copy of the SEL but has not yet finished
     * being deleted in the remote copy, it will be counted here.
     */
    int sel_entries_used()
    {
	return ipmi_mc_sel_entries_used(self);
    }

    /*
     * The major version of the MC's SEL.
     */
    int sel_get_major_version()
    {
	return ipmi_mc_sel_get_major_version(self);
    }

    /*
     * The minor version of the MC's SEL.
     */
    int sel_get_minor_version()
    {
	return ipmi_mc_sel_get_minor_version(self);
    }

    /*
     * The number of entries available in the MC's SEL.
     */
    int sel_get_num_entries()
    {
	return ipmi_mc_sel_get_num_entries(self);
    }

    /*
     * The number of free bytes available in the MC's SEL.
     */
    int sel_get_free_bytes()
    {
	return ipmi_mc_sel_get_free_bytes(self);
    }

    /*
     * Has an overflow occurred since the last SEL operation?
     */
    int sel_get_overflow()
    {
	return ipmi_mc_sel_get_overflow(self);
    }

    /*
     * Does the SEL support individual deletes of entries?
     */
    int sel_get_supports_delete_sel()
    {
	return ipmi_mc_sel_get_supports_delete_sel(self);
    }

    /*
     * Does the SEL support partial adds of entries?
     */
    int sel_get_supports_partial_add_sel()
    {
	return ipmi_mc_sel_get_supports_partial_add_sel(self);
    }

    /*
     * Does the SEL support the reserve protocol?
     */
    int sel_get_supports_reserve_sel()
    {
	return ipmi_mc_sel_get_supports_reserve_sel(self);
    }

    /*
     * Does the SEL support getting the SEL allocastion?
     */
    int sel_get_supports_get_sel_allocation()
    {
	return ipmi_mc_sel_get_supports_get_sel_allocation(self);
    }

    /*
     * The timestamp of the last time something was added to the SEL.
     */
    int sel_get_last_addition_timestamp()
    {
	return ipmi_mc_sel_get_last_addition_timestamp(self);
    }
}

/*
 * A sensor id object.  This object is guaranteed to be valid and
 * can be converted into a mc pointer later.
 */
%extend ipmi_sensor_id_t {
    ~ipmi_sensor_id_t()
    {
	free(self);
    }

    /*
     * Convert a sensor id to a sensor pointer.  The "sensor_cb" method
     * will be called on the first parameter with the following parameters:
     * <self> <sensor>
     */
    char *convert_to_sensor(swig_cb handler)
    {
	int rv;

	if (! valid_swig_cb(handler))
	    return NULL;

	rv = ipmi_sensor_pointer_cb(*self, handle_sensor_cb,
				    get_swig_cb(handler));
	if (rv)
	    return strerror(rv);
	return NULL;
    }
}

/*
 * An sensor object.  Sensor operations take several different types
 * of objects.  These are mostly strings that are a list of values.
 *
 * Event states are represented as a string with value separated by
 * spaces.  These value are settings and the events.  The strings
 * "events", "scanning", and "busy" are settings for the full sensor
 * event states.  For threshold sensor, the other values in the string
 * are 4 characters with: 1st character: u for upper or l for lower.
 * 2nd character: n for non-critical, c for critical, and r for
 * non-recoverable.  3rd character: h for going high and l for going
 * low.  4th character: a for assertion and d for deassertion.  For
 * discrete sensors, the other values are a 1 or 2-digit number
 * representing the offset and then a for assertion and d for
 * deassertion.
 *
 * A states structure is similar to event status, but does not have
 * the last two characters (direction and assertion) for thresholds
 * and last chararacter (assertion) for discrete values.
 */
%extend ipmi_sensor_t {
    %newobject get_name;
    /*
     * Get the name of an sensor.
     */
    char *get_name()
    {
	char name[IPMI_SENSOR_NAME_LEN];

	ipmi_sensor_get_name(self, name, sizeof(name));
	return strdup(name);
    }

    %newobject get_id;
    /*
     * Get the id for the sensor.
     */
    ipmi_sensor_id_t *get_id()
    {
	ipmi_sensor_id_t *rv = malloc(sizeof(*rv));
	if (rv)
	    *rv = ipmi_sensor_convert_to_id(self);
	return rv;
    }

    /*
     * Register a handler to be called when an event comes from the
     * sensor.  If the sensor is a threshold sensor, the
     * threshold_event_cb method will be called on the sensor.
     * Otherwise, the sensor is discrete and the discrete_event_cb
     * will be called.  The threshold_event_cb method takes the
     * following parameters:
     * <self> <sensor> <event> <raw_set> <raw> <value_set> <value> <event>
     * The discrete_event_cb method takes the following parameters:
     * <self> <sensor> <event> <severity> <old_severity> <event>
     */
    int add_event_handler(swig_cb handler)
    {
	if (ipmi_sensor_get_event_reading_type(self)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    cb_add(sensor, threshold_event);
	} else {
	    cb_add(sensor, discrete_event);
	}
    }

    /*
     * Remove the event handler from the sensor
     */
    int remove_event_handler(swig_cb handler)
    {
	if (ipmi_sensor_get_event_reading_type(self)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    cb_rm(sensor, threshold_event);
	} else {
	    cb_rm(sensor, discrete_event);
	}
    }

    /* Set the event enables for the given sensor to exactly the event
     * states given in the first parameter.  This will first enable
     * the events/thresholds that are set, then disable the
     * events/thresholds that are not set.  When the operation is
     * done, the sensor_event_enable_cb method on the second parm will
     * be called with the following parameters: <self> <sensor> <err>
     */
    int set_event_enables(char *states, swig_cb handler = NULL)
    {
	int                 rv;
	swig_cb_val         handler_val = NULL;
	ipmi_sensor_done_cb sensor_cb = NULL;
	ipmi_event_state_t  *st;

	if (ipmi_sensor_get_event_reading_type(self)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    rv = str_to_threshold_event_state(states, &st);
	} else {
	    rv = str_to_discrete_event_state(states, &st);
	}
	if (rv)
	    return rv;
	if (valid_swig_cb(handler)) {
	    sensor_cb = sensor_event_enable_handler;
	    handler_val = ref_swig_cb(handler);
	}
	rv = ipmi_sensor_set_event_enables(self, st, sensor_cb, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	free(st);
	return rv;
    }

    /* Enable the event states that are set in the first parameter.  This
     * will *only* enable those states, it will not disable any
     * states.  It will, however, set the "events" flag and the
     * "scanning" flag for the sensor to the value in the states
     * parameter.  When the operation is done, the
     * sensor_event_enable_cb method on the second parm will be called
     * with the following parameters: <self> <sensor> <err>
     */
    int enable_events(char *states, swig_cb handler = NULL)
    {
	int                 rv;
	swig_cb_val         handler_val = NULL;
	ipmi_sensor_done_cb sensor_cb = NULL;
	ipmi_event_state_t  *st;

	if (ipmi_sensor_get_event_reading_type(self)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    rv = str_to_threshold_event_state(states, &st);
	} else {
	    rv = str_to_discrete_event_state(states, &st);
	}
	if (rv)
	    return rv;
	if (valid_swig_cb(handler)) {
	    sensor_cb = sensor_event_enable_handler;
	    handler_val = ref_swig_cb(handler);
	}
	rv = ipmi_sensor_enable_events(self, st, sensor_cb, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	free(st);
	return rv;
    }

    /* Disable the event states that are set in the first parameter.
     * This will *only* disable those states, it will not enable any
     * states.  It will, however, set the "events" flag and the
     * "scanning" flag for the sensor to the value in the states
     * parameter.  When the operation is done, the
     * sensor_event_enable_cb method on the second parm will be called
     * with the following parameters: <self> <sensor> <err>
     */
    int disable_events(char *states, swig_cb handler = NULL)
    {
	int                 rv;
	swig_cb_val         handler_val = NULL;
	ipmi_sensor_done_cb sensor_cb = NULL;
	ipmi_event_state_t  *st;

	if (ipmi_sensor_get_event_reading_type(self)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    rv = str_to_threshold_event_state(states, &st);
	} else {
	    rv = str_to_discrete_event_state(states, &st);
	}
	if (rv)
	    return rv;
	if (valid_swig_cb(handler)) {
	    sensor_cb = sensor_event_enable_handler;
	    handler_val = ref_swig_cb(handler);
	}
	rv = ipmi_sensor_disable_events(self, st, sensor_cb, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	free(st);
	return rv;
    }

    /* Get the event enables for the given sensor.  When done, the
     * sensor_get_event_enable_cb method on the first parameter will
     * be called with the following parameters: <self> <sensor> <err>
     * <event states> */
    int get_event_enables(swig_cb handler)
    {
	int                          rv;
	swig_cb_val                  handler_val = NULL;
	ipmi_sensor_event_enables_cb sensor_cb = NULL;

	if (!valid_swig_cb(handler))
	    return EINVAL;

	sensor_cb = sensor_get_event_enables_handler;
	handler_val = ref_swig_cb(handler);
	rv = ipmi_sensor_get_event_enables(self, sensor_cb, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Rearm the current sensor.  This will cause the sensor to resend
     * it's current event state if it is out of range.  If
     * get_supports_auto_rearm() returns false and you receive an
     * event, you have to rearm a sensor manually to get another event
     * from it.  If global_enable (parm 1) is set, all events are
     * enabled and the state is ignored (and may be NULL).  Otherwise,
     * the events set in the event state (parm 2) are enabled.  When
     * the operation is complete, the sensor_rearm_cb method of the
     * third parameter will be called with the following parameters:
     * <self> <sensor> <err>
     */
    int rearm(int     global_enable,
	      char    *states,
	      swig_cb handler = NULL)
    {
	int                 rv;
	swig_cb_val         handler_val = NULL;
	ipmi_sensor_done_cb sensor_cb = NULL;
	ipmi_event_state_t  *st = NULL;

	if (!global_enable) {
	    if (!states)
		return EINVAL;
	    if (ipmi_sensor_get_event_reading_type(self)
		== IPMI_EVENT_READING_TYPE_THRESHOLD)
	    {
		rv = str_to_threshold_event_state(states, &st);
	    } else {
		rv = str_to_discrete_event_state(states, &st);
	    }
	    if (rv)
		return rv;
	}
	if (valid_swig_cb(handler)) {
	    sensor_cb = sensor_rearm_handler;
	    handler_val = ref_swig_cb(handler);
	}
	rv = ipmi_sensor_rearm(self, global_enable, st,
			       sensor_cb, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	if (st)
	    free(st);
	return rv;
    }

    /*
     * Get the hysteresis values for the given sensor.  These are the
     * raw values, there doesn't seem to be an easy way to calculate
     * the cooked values.  The sensr_get_hysteresis_cb method on the
     * first parameter will be called with the values.  It's
     * parameters are: <self> <sensor> <err> <positive hysteresis>
     * <negative hysteresis>
     */
    int get_hysteresis(swig_cb handler)
    {
	int                       rv;
	swig_cb_val               handler_val = NULL;
	ipmi_sensor_hysteresis_cb sensor_cb = NULL;

	if (!valid_swig_cb(handler))
	    return EINVAL;

	sensor_cb = sensor_get_hysteresis_handler;
	handler_val = ref_swig_cb(handler);
	rv = ipmi_sensor_get_hysteresis(self, sensor_cb, handler_val);
	if (rv)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Set the hysteresis values for the given sensor.  These are the
     * raw values, there doesn't seem to be an easy way to calculate
     * the cooked values.  The positive hysteresis is the first
     * parameter, the negative hystersis is the second.  When the
     * operation completes, the sensor_set_hysteresis_cb will be
     * called on the third parameters with the following parms:
     * <self> <sensor> <err>
     */
    int set_hysteresis(unsigned int positive_hysteresis,
		       unsigned int negative_hysteresis,
		       swig_cb      handler)
    {
	int                 rv;
	swig_cb_val         handler_val = NULL;
	ipmi_sensor_done_cb sensor_cb = NULL;

	if (valid_swig_cb(handler)) {
	    sensor_cb = sensor_set_hysteresis_handler;
	    handler_val = ref_swig_cb(handler);
	}
	rv = ipmi_sensor_set_hysteresis(self, positive_hysteresis,
					negative_hysteresis,
					sensor_cb, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    %newobject get_default_thresholds;
    /* Return the default threshold settings for a sensor. */
    char *get_default_thresholds()
    {
	ipmi_thresholds_t *th = malloc(ipmi_thresholds_size());
	char              *str = NULL;
	int               rv;

	rv = ipmi_get_default_sensor_thresholds(self, th);
	if (!rv) {
	    str = thresholds_to_str(th);
	}
	free(th);
	return str;
    }

    /*
     * Set the thresholds for the given sensor to the threshold values
     * specified in the first parameter.  When the thresholds are set,
     * the sensor_set_thresholds_cb method on the second parm will be
     * called with the following parameters: <self> <sensor> <err>
     */
    int set_thresholds(char    *thresholds,
		       swig_cb handler)
    {
	ipmi_thresholds_t   *th;
	int                 rv;
	swig_cb_val         handler_val = NULL;
	ipmi_sensor_done_cb sensor_cb = NULL;

	rv = str_to_thresholds(thresholds, &th);
	if (rv)
	    return rv;

	if (valid_swig_cb(handler)) {
	    sensor_cb = sensor_set_thresholds_handler;
	    handler_val = ref_swig_cb(handler);
	}
	rv = ipmi_sensor_set_thresholds(self, th, sensor_cb, handler_val);
	if (rv && handler_val)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /*
     * Fetch the thresholds for the given sensor.  When the thresholds
     * are received, the sensor_get_thresholds_cb method on the second
     * parm will be called with the following parameters: <self>
     * <sensor> <err> <thresholds>
     */
    int get_thresholds(swig_cb handler)
    {
	int                       rv;
	swig_cb_val               handler_val = NULL;
	ipmi_sensor_thresholds_cb sensor_cb = NULL;

	if (!valid_swig_cb(handler))
	    return EINVAL;

	sensor_cb = sensor_get_thresholds_handler;
	handler_val = ref_swig_cb(handler);
	rv = ipmi_sensor_get_thresholds(self, sensor_cb, handler_val);
	if (rv)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /* Read the current value of the given sensor.  If this is a
       discrete sensor, the discrete_states_cb method of the first
       parameter will be called with the following parameters: <self>
       <sensor> <err> <states>.  If this is a threshold sensor, the
       threshold_reading_cb method of the first parameter will be
       called with the following parameters: <self> <sensor> <err>
       <raw_set> <raw> <value_set> <value> <states>. */
    int get_value(swig_cb handler)
    {
	int                    rv;
	swig_cb_val            handler_val = NULL;

	if (!valid_swig_cb(handler))
	    return EINVAL;

	handler_val = ref_swig_cb(handler);
	if (ipmi_sensor_get_event_reading_type(self)
	    == IPMI_EVENT_READING_TYPE_THRESHOLD)
	{
	    ipmi_sensor_reading_cb sensor_cb;

	    sensor_cb = sensor_get_reading_handler;
	    rv = ipmi_sensor_get_reading(self, sensor_cb, handler_val);
	} else {
	    ipmi_sensor_states_cb sensor_cb;

	    sensor_cb = sensor_get_states_handler;
	    rv = ipmi_sensor_get_states(self, sensor_cb, handler_val);
	}
	if (rv)
	    deref_swig_cb_val(handler_val);
	return rv;
    }

    /* 
     * Return the LUN for the sensor (with respect to the MC).
     */
    int get_lun()
    {
	int lun = 0;
	ipmi_sensor_get_num(self, &lun, NULL);
	return lun;
    }

    /* 
     * Return the number for the sensor (The number in the MC/LUN).
     */
    int get_num()
    {
	int num = 0;
	ipmi_sensor_get_num(self, NULL, &num);
	return num;
    }

#if 0
    /* Strings for various values for a sensor.  We put them in here, and
       they will be the correct strings even for OEM values. */
    char *get_sensor_type_string()
    {
	return ipmi_sensor_get_sensor_type_string(self);
    }

    char *get_event_reading_type_string()
    {
	return ipmi_sensor_get_event_reading_type_string(self);
    }

    char *get_rate_unit_string()
    {
	return ipmi_sensor_get_rate_unit_string(self);
    }

    char *get_base_unit_string()
    {
	return ipmi_sensor_get_base_unit_string(self);
    }

    char *get_modifier_unit_string()
    {
	return ipmi_sensor_get_modifier_unit_string(self);
    }


/* This call is a little different from the other string calls.  For a
   discrete sensor, you can pass the offset into this call and it will
   return the string associated with the reading.  This way, OEM
   sensors can supply their own strings as necessary for the various
   offsets. */
char *ipmi_sensor_reading_name_string(ipmi_sensor_t *sensor, int offset);

/* Get the entity the sensor is hooked to. */
int ipmi_sensor_get_entity_id(ipmi_sensor_t *sensor);
int ipmi_sensor_get_entity_instance(ipmi_sensor_t *sensor);
ipmi_entity_t *ipmi_sensor_get_entity(ipmi_sensor_t *sensor);

/* Information about a sensor from it's SDR.  These are things that
   are specified by IPMI, see the spec for more details. */
int ipmi_sensor_get_sensor_init_scanning(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_events(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_thresholds(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_hysteresis(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_type(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_pu_events(ipmi_sensor_t *sensor);
int ipmi_sensor_get_sensor_init_pu_scanning(ipmi_sensor_t *sensor);
int ipmi_sensor_get_ignore_if_no_entity(ipmi_sensor_t *sensor);
int ipmi_sensor_get_supports_auto_rearm(ipmi_sensor_t *sensor);

/* Returns IPMI_THRESHOLD_ACCESS_SUPPORT_xxx */
int ipmi_sensor_get_threshold_access(ipmi_sensor_t *sensor);

/* Returns IPMI_HYSTERESIS_SUPPORT_xxx */
int ipmi_sensor_get_hysteresis_support(ipmi_sensor_t *sensor);

/* Returns IPMI_EVENT_SUPPORT_xxx */
int ipmi_sensor_get_event_support(ipmi_sensor_t *sensor);

/* Returns IPMI_SENSOR_TYPE_xxx */
int ipmi_sensor_get_sensor_type(ipmi_sensor_t *sensor);

/* Returns IPMI_EVENT_READING_TYPE_xxx */
int ipmi_sensor_get_event_reading_type(ipmi_sensor_t *sensor);

/* Returns IPMI_SENSOR_DIRECTION_xxx */
int ipmi_sensor_get_sensor_direction(ipmi_sensor_t *sensor);

/* Sets "val" to if an event is supported for this particular sensor. */
int ipmi_sensor_threshold_event_supported(
    ipmi_sensor_t               *sensor,
    enum ipmi_thresh_e          event,
    enum ipmi_event_value_dir_e value_dir,
    enum ipmi_event_dir_e       dir,
    int                         *val);

/* Sets "val" to if a specific threshold can be set. */
int ipmi_sensor_threshold_settable(ipmi_sensor_t      *sensor,
				   enum ipmi_thresh_e threshold,
				   int                *val);

/* Sets "val" to if a specific threshold can be read. */
int ipmi_sensor_threshold_readable(ipmi_sensor_t      *sensor,
				   enum ipmi_thresh_e threshold,
				   int                *val);

/* Sets "val" to if a specific threshold has its reading returned when
   reading the value of the threshold sensor. */
int ipmi_sensor_threshold_reading_supported(ipmi_sensor_t      *sensor,
					    enum ipmi_thresh_e thresh,
					    int                *val);

/* Sets "val" to if the specific event can send an event */
int ipmi_sensor_discrete_event_supported(ipmi_sensor_t         *sensor,
					 int                   offset,
					 enum ipmi_event_dir_e dir,
					 int                   *val);

/* Sets "val" to if the specific event can be read (is supported). */
int ipmi_discrete_event_readable(ipmi_sensor_t *sensor,
				 int           event,
				 int           *val);

/* Returns IPMI_RATE_UNIT_xxx */
enum ipmi_rate_unit_e ipmi_sensor_get_rate_unit(ipmi_sensor_t *sensor);

/* Returns IPMI_MODIFIER_UNIT_xxx */
enum ipmi_modifier_unit_use_e ipmi_sensor_get_modifier_unit_use(
    ipmi_sensor_t *sensor);

/* Returns if the value is a percentage. */
int ipmi_sensor_get_percentage(ipmi_sensor_t *sensor);

/* Returns IPMI_UNIT_TYPE_xxx */
enum ipmi_unit_type_e ipmi_sensor_get_base_unit(ipmi_sensor_t *sensor);

/* Returns IPMI_UNIT_TYPE_xxx */
enum ipmi_unit_type_e ipmi_sensor_get_modifier_unit(ipmi_sensor_t *sensor);

/* Sensor reading information from the SDR. */
int ipmi_sensor_get_tolerance(ipmi_sensor_t *sensor,
			      int           val,
			      double        *tolerance);
int ipmi_sensor_get_accuracy(ipmi_sensor_t *sensor, int val, double *accuracy);
int ipmi_sensor_get_normal_min_specified(ipmi_sensor_t *sensor);
int ipmi_sensor_get_normal_max_specified(ipmi_sensor_t *sensor);
int ipmi_sensor_get_nominal_reading_specified(ipmi_sensor_t *sensor);
int ipmi_sensor_get_nominal_reading(ipmi_sensor_t *sensor,
				    double *nominal_reading);
int ipmi_sensor_get_normal_max(ipmi_sensor_t *sensor, double *normal_max);
int ipmi_sensor_get_normal_min(ipmi_sensor_t *sensor, double *normal_min);
int ipmi_sensor_get_sensor_max(ipmi_sensor_t *sensor, double *sensor_max);
int ipmi_sensor_get_sensor_min(ipmi_sensor_t *sensor, double *sensor_min);

int ipmi_sensor_get_oem1(ipmi_sensor_t *sensor);

/* The ID string from the SDR. */
int ipmi_sensor_get_id_length(ipmi_sensor_t *sensor);
enum ipmi_str_type_e ipmi_sensor_get_id_type(ipmi_sensor_t *sensor);
int ipmi_sensor_get_id(ipmi_sensor_t *sensor, char *id, int length);


#endif
}

/*
 * A control id object.  This object is guaranteed to be valid and
 * can be converted into a mc pointer later.
 */
%extend ipmi_control_id_t {
    ~ipmi_control_id_t()
    {
	free(self);
    }

    /*
     * Convert a control id to a control pointer.  The "control_cb" method
     * will be called on the first parameter with the following parameters:
     * <self> <control>
     */
    char *convert_to_control(swig_cb handler)
    {
	int rv;

	if (! valid_swig_cb(handler))
	    return NULL;

	rv = ipmi_control_pointer_cb(*self, handle_control_cb,
				    get_swig_cb(handler));
	if (rv)
	    return strerror(rv);
	return NULL;
    }
}

/*
 * An control object
 */
%extend ipmi_control_t {
    %newobject get_name;
    /*
     * Get the name of an control.
     */
    char *get_name()
    {
	char name[IPMI_CONTROL_NAME_LEN];

	ipmi_control_get_name(self, name, sizeof(name));
	return strdup(name);
    }

    %newobject get_id;
    /*
     * Get the id for the control.
     */
    ipmi_control_id_t *get_id()
    {
	ipmi_control_id_t *rv = malloc(sizeof(*rv));
	if (rv)
	    *rv = ipmi_control_convert_to_id(self);
	return rv;
    }
}

/*
 * A FRU object
 */
%extend ipmi_fru_t {
}

/*
 * An event object
 */
%extend ipmi_event_t {
    ~ipmi_event_t()
    {
	ipmi_event_free(self);
    }

    %newobject get_mc_id;
    /*
     * Get the MC id the event came from.  Note that the MC may not exist
     * any more.
     */
    ipmi_mcid_t *get_mc_id()
    {
	ipmi_mcid_t *rv = malloc(sizeof(*rv));
	if (rv)
	    *rv = ipmi_event_get_mcid(self);
	return rv;
    }

    /*
     * Get the event's record id
     */
    int get_record_id()
    {
	return ipmi_event_get_record_id(self);
    }

    /*
     * Get the event's type.
     */
    int get_type()
    {
	return ipmi_event_get_type(self);
    }

    /*
     * Get the event's timestamp.  This is in seconds.
     */
    double get_timestamp()
    {
	return ((double) ipmi_event_get_timestamp(self)) / 1000000000.0;
    }

    /*
     * Get the data from the event.  This returns a reference to an
     * array, so you have to reference it like @$val.
     */
    intarray get_data()
    {
	intarray      rv;
	int           i;
	unsigned char *data;
	int           data_len;

	data_len = ipmi_event_get_data_len(self);
	data = malloc(data_len);
	data_len = ipmi_event_get_data(self, data, 0, data_len);
	rv.val = malloc(sizeof(int) * data_len);
	for (i=0; i<data_len; i++)
	    rv.val[i] = data[i];
	free(data);
	rv.len = data_len;
	return rv;
    }
}
