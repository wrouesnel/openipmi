
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.1

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))
LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

AM_CFLAGS = -Wall -I$(top_srcdir)/include `glib-config --cflags gthread`

lib_LTLIBRARIES = libOpenIPMIglib.la

GLIBLIBS = $(shell glib-config --libs gthread)

libOpenIPMIglib_la_SOURCES = glib_os_hnd.c
libOpenIPMIglib_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMIglib.map $(GLIBLIBS)

clean:
	rm -f *.map
