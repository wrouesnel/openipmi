
LIB_VERSION = 0.0.1
LD_VERSION = 0:1:0

AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include

lib_LTLIBRARIES = @TCL_TARGET@
EXTRA_LTLIBRARIES = libOpenIPMItcl.la

libOpenIPMItcl_la_SOURCES = tcl_os_hnd.c
libOpenIPMItcl_la_CFLAGS = $(TCL_CFLAGS) $(AM_CFLAGS)
libOpenIPMItcl_la_LIBADD = $(GDBM_LIB)
libOpenIPMItcl_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMItcl.map $(TCL_LIBS) -L$(libdir) \
	-rpath $(libdir)

noinst_PROGRAMS = test_handlers

test_handlers_SOURCES = test_handlers.c
test_handlers_CFLAGS = $(TCL_CFLAGS) $(AM_CFLAGS)
test_handlers_LDADD = libOpenIPMItcl.la \
	$(top_builddir)/utils/libOpenIPMIutils.la $(GDBM_LIB) $(TCL_LIBS)

TESTS = test_handlers

CLEANFILES = libOpenIPMItcl.map
