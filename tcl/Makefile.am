
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.1

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))
LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include

lib_LTLIBRARIES = @TCL_TARGET@
EXTRA_LTLIBRARIES = libOpenIPMItcl.la

libOpenIPMItcl_la_SOURCES = tcl_os_hnd.c
libOpenIPMItcl_la_CFLAGS = $(TCL_CFLAGS) $(AM_CFLAGS)
libOpenIPMItcl_la_LIBADD = $(GDBM_LIB)
libOpenIPMItcl_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-rpath $(libdir) \
	-Wl,-Map -Wl,libOpenIPMItcl.map $(TCL_LIBS)

noinst_PROGRAMS = test_handlers

test_handlers_SOURCES = test_handlers.c
test_handlers_LDADD = libOpenIPMItcl.la \
	$(top_builddir)/utils/libOpenIPMIutils.la $(GDBM_LIB) $(TCL_LIBS)

TESTS = test_handlers

CLEANFILES = libOpenIPMItcl.map
