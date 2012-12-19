
LIB_VERSION = 0.0.1
LD_VERSION = 0:1:0

AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

lib_LTLIBRARIES = libOpenIPMIutils.la

libOpenIPMIutils_la_SOURCES = md5.c md2.c ipmi_auth.c \
			      ipmi_malloc.c ilist.c locks.c hash.c \
			      locked_list.c os_handler.c string.c
libOpenIPMIutils_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMIutils.map

CLEANFILES = libOpenIPMIutils.map
