
AM_CFLAGS = -Wall -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

noinst_HEADERS = heap.h

lib_LTLIBRARIES = libOpenIPMIutils.la

libOpenIPMIutils_la_SOURCES = md5.c md2.c ipmi_auth.c selector.c \
			      ipmi_malloc.c ilist.c locks.c hash.c

noinst_PROGRAMS = test_heap

test_heap_SOURCES = test_heap.c
test_heap_LDADD = 

TESTS = test_heap

clean:
	rm -f *.map
