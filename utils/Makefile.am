
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.1

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))
LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

AM_CFLAGS = -Wall -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

noinst_HEADERS = heap.h

lib_LTLIBRARIES = libOpenIPMIutils.la

libOpenIPMIutils_la_SOURCES = md5.c md2.c ipmi_auth.c selector.c \
			      ipmi_malloc.c ilist.c locks.c hash.c \
			      locked_list.c
libOpenIPMIutils_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMIutils.map

noinst_PROGRAMS = test_heap

test_heap_SOURCES = test_heap.c
test_heap_LDADD = 

TESTS = test_heap

clean:
	rm -f *.map
