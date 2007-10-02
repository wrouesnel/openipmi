
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.1

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))
LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include

lib_LTLIBRARIES = libOpenIPMIposix.la libOpenIPMIpthread.la

libOpenIPMIpthread_la_SOURCES = posix_thread_os_hnd.c selector.c
libOpenIPMIpthread_la_LIBADD = -lpthread $(GDBM_LIB) \
	$(top_builddir)/utils/libOpenIPMIutils.la
libOpenIPMIpthread_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMIpthread.map

libOpenIPMIposix_la_SOURCES = posix_os_hnd.c selector.c
libOpenIPMIposix_la_LIBADD = $(top_builddir)/utils/libOpenIPMIutils.la \
	$(GDBM_LIB)
libOpenIPMIposix_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMIposix.map -R$(libdir)

noinst_HEADERS = heap.h

noinst_PROGRAMS = test_heap test_handlers

test_heap_SOURCES = test_heap.c
test_heap_LDADD = 

test_handlers_SOURCES = test_handlers.c
test_handlers_LDADD = libOpenIPMIposix.la libOpenIPMIpthread.la \
	$(top_builddir)/utils/libOpenIPMIutils.la $(GDBM_LIB)

TESTS = test_heap test_handlers

CLEANFILES = libOpenIPMIposix.map libOpenIPMIpthread.map
