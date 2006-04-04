
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.1

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))
LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

lib_LTLIBRARIES = libOpenIPMIutils.la

libOpenIPMIutils_la_SOURCES = md5.c md2.c ipmi_auth.c \
			      ipmi_malloc.c ilist.c locks.c hash.c \
			      locked_list.c os_handler.c
libOpenIPMIutils_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMIutils.map

CLEANFILES = libOpenIPMIutils.map
