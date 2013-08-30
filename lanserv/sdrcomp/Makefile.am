
AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include \
	-I$(top_srcdir)/lanserv

AM_CPPFLAGS = -DSTATEDIR='"$(localstatedir)"'

bin_PROGRAMS = sdrcomp

sdrcomp_DEPENDENCIES = $(top_srcdir)/lanserv/persist.c
sdrcomp_SOURCES = sdrcomp.c
sdrcomp_LDFLAGS = ../../utils/libOpenIPMIutils.la -lm
