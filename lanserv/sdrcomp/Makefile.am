
AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include \
	-I$(top_srcdir)/lanserv

AM_CPPFLAGS = -DSTATEDIR='"$(localstatedir)"'

bin_PROGRAMS = sdrcomp

noinst_PROGRAMS = sdrcomp_build

sdrcomp_build: sdrcomp.c $(top_srcdir)/utils/string.c
	$(BUILD_CC) $(AM_CFLAGS) -DSTATEDIR="\".\"" \
		-o sdrcomp_build $(srcdir)/sdrcomp.c \
		$(top_srcdir)/utils/string.c -lm

sdrcomp_DEPENDENCIES = $(top_srcdir)/lanserv/persist.c
sdrcomp_SOURCES = sdrcomp.c
sdrcomp_LDFLAGS = ../../utils/libOpenIPMIutils.la -lm
