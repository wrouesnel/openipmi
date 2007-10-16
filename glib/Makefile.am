
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.1

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))
LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include

lib_LTLIBRARIES = @GLIB_TARGET@ @GLIB12_TARGET@
EXTRA_LTLIBRARIES = libOpenIPMIglib.la libOpenIPMIglib12.la

libOpenIPMIglib_la_SOURCES = glib_os_hnd.c
libOpenIPMIglib_la_CFLAGS = $(GLIB_CFLAGS) $(AM_CFLAGS)
libOpenIPMIglib_la_LIBADD = $(GDBM_LIB)
libOpenIPMIglib_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-rpath $(libdir) \
	-Wl,-Map -Wl,libOpenIPMIglib.map $(GLIB_LIBS)

libOpenIPMIglib12_la_SOURCES = glib_os_hnd.c
libOpenIPMIglib12_la_CFLAGS = $(GLIB12_CFLAGS) $(AM_CFLAGS)
libOpenIPMIglib12_la_LIBADD = $(GDBM_LIB)
libOpenIPMIglib12_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-rpath $(libdir) \
	-Wl,-Map -Wl,libOpenIPMIglib12.map $(GLIB12_LIBS)

CLEANFILES = libOpenIPMIglib.map libOpenIPMIglib12.map glib12_os_hnd.c
