
LIB_VERSION = 0.0.1
LD_VERSION = 0:1:0

AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include

lib_LTLIBRARIES = @GLIB_TARGET@
EXTRA_LTLIBRARIES = libOpenIPMIglib.la

libOpenIPMIglib_la_SOURCES = glib_os_hnd.c
libOpenIPMIglib_la_CFLAGS = $(GLIB_CFLAGS) $(AM_CFLAGS)
libOpenIPMIglib_la_LIBADD = $(GDBM_LIB)
libOpenIPMIglib_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	$(GLIB_LIBS) -rpath $(libdir)
