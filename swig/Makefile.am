
CFLAGS = -g -O2
LDFLAGS = ../lib/.libs/libOpenIPMI.a ../unix/.libs/libOpenIPMIposix.a ../utils/.libs/libOpenIPMIutils.a

AM_CFLAGS = -Wall \
	    -I /usr/lib/perl5/5.8.0/i386-linux-thread-multi/CORE \
	    -I ../include \
	    -D_GNU_SOURCE

lib_LTLIBRARIES = OpenIPMI.so

OpenIPMI_so_SOURCES = OpenIPMI_wrap.c OpenIPMI_perl.c
OpenIPMI_so_LIBS = $(top_builddir)/lib/libOpenIPMI.la \
		   $(top_builddir)/utils/libOpenIPMIutils.la
OpenIPMI_so_LDFLAGS = -shared


OpenIPMI_wrap.c: OpenIPMI.i
	swig -perl5 $<

