
AM_CFLAGS = $(PERL_CFLAGS) \
	    $(GLIB_CFLAGS) \
	    -I $(top_builddir)/include \
	    -I $(top_srcdir)/include \
	    -I $(top_srcdir)/swig/perl

CC = @CC@
CFLAGS = @CFLAGS@
DEFS = @DEFS@

COMPILE = $(CC) $(DEFS) $(AM_CFLAGS) $(CFLAGS)

all: OpenIPMI.so

OpenIPMI_SRC = OpenIPMI_wrap.c OpenIPMI_perl.c
OpenIPMI_OBJ = OpenIPMI_wrap.o OpenIPMI_perl.o

OpenIPMI_LIB = $(top_builddir)/unix/libOpenIPMIposix.la \
	       $(top_builddir)/lib/libOpenIPMI.la \
	       $(top_builddir)/utils/libOpenIPMIutils.la \
	       $(GLIB_LIB) $(GLIB_LIBS)

EXTRA_DIST = OpenIPMI_perl.c

OpenIPMI.so: $(OpenIPMI_OBJ)
	$(LIBTOOL) --mode=link $(CC) -shared -o $@ $^ $(OpenIPMI_LIB)
	rm OpenIPMI.so
	mv .libs/OpenIPMI.so .
	rm -rf .libs

OpenIPMI_wrap.o: OpenIPMI_wrap.c OpenIPMI.h
	$(COMPILE) -c $<

OpenIPMI_perl.o: OpenIPMI_perl.c OpenIPMI.h
	$(COMPILE) -c $<

OpenIPMI_wrap.c OpenIPMI.pm: $(top_srcdir)/swig/OpenIPMI.i
	swig $(DEFS) -perl5 -o $@ $<

CLEANFILES = $(OpenIPMI_OBJ) OpenIPMI.so OpenIPMI_wrap.c