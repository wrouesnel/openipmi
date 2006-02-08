#include <OpenIPMI/ipmi_glib.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <glib.h>

void glib_do_log(const char *pfx, const char *message);

void openipmi_swig_vlog(os_handler_t *os_handler, const char *format,
			enum ipmi_log_type_e log_type, va_list ap);

static void
glib_handle_log(const gchar *log_domain,
		GLogLevelFlags log_level,
		const gchar *message,
		gpointer user_data)
{
    char *pfx = "";
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

    glib_do_log(pfx, message);
}

/*
 * Initialize the OS handler with the glib version.  INITFUN is
 * defined as init_glib_shim or init_glib12_shim in the makefile.
 */
os_handler_t *
INITFUNC(void)
{
    os_handler_t *swig_os_hnd;

    if (!g_thread_supported ())
	g_thread_init(NULL);
    swig_os_hnd = ipmi_glib_get_os_handler();
    swig_os_hnd->set_log_handler(swig_os_hnd, openipmi_swig_vlog);
    ipmi_init(swig_os_hnd);
    ipmi_cmdlang_init(swig_os_hnd);
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
    return swig_os_hnd;
}

