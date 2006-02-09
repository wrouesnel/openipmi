
AM_CFLAGS = $(PERL_CFLAGS) \
	    -I $(top_builddir)/include \
	    -I $(top_srcdir)/include \
	    -I $(top_srcdir)/swig/perl

CC = @CC@ -Wall
CFLAGS = @CFLAGS@ -fPIC -DPERL_HAS_POSIX_THREADS=@PERL_HAS_POSIX_THREADS@
DEFS = @DEFS@

COMPILE = $(CC) $(DEFS) $(AM_CFLAGS) $(CFLAGS)

all: OpenIPMI.so

OpenIPMI_SRC = OpenIPMI_wrap.c OpenIPMI_perl.c
OpenIPMI_OBJ = OpenIPMI_wrap.o OpenIPMI_perl.o

OpenIPMI_LIB = @PERL_POSIX_LIB@ \
	       $(top_builddir)/lib/libOpenIPMI.la \
	       $(top_builddir)/utils/libOpenIPMIutils.la \
	       $(top_builddir)/cmdlang/libOpenIPMIcmdlang.la \
	       $(GLIB_SINGLE_LIB)

OpenIPMI.so: $(OpenIPMI_OBJ)
	$(LIBTOOL) --mode=link $(CC) -shared -o $@ $^ $(OpenIPMI_LIB)
	rm OpenIPMI.so
	mv .libs/OpenIPMI.so .
	rm -rf .libs

OpenIPMI_wrap.o: OpenIPMI_wrap.c OpenIPMI.h
	$(COMPILE) -c $<

OpenIPMI_perl.o: OpenIPMI_perl.c OpenIPMI.h
	$(COMPILE) -c $<

OpenIPMI_wrap.c OpenIPMI.pm: $(top_srcdir)/swig/OpenIPMI.i OpenIPMI_lang.i
	$(SWIG) $(DEFS) -perl5 -o $@ -I$(top_srcdir)/swig/perl $<

CLEANFILES = $(OpenIPMI_OBJ) OpenIPMI.so OpenIPMI_wrap.c OpenIPMI.pm

install-exec-local: OpenIPMI.so OpenIPMI.pm
	$(INSTALL) -d $(DESTDIR)$(PERL_INSTALL_DIR)/auto/OpenIPMI
	$(INSTALL_PROGRAM) OpenIPMI.so $(DESTDIR)$(PERL_INSTALL_DIR)/auto/OpenIPMI
	$(INSTALL_PROGRAM) OpenIPMI.pm $(DESTDIR)$(PERL_INSTALL_DIR)

TEST_LD_LIBRARY_PATH=$(top_builddir)/lib/.libs:$(top_builddir)/utils/.libs:$(top_builddir)/glib/.libs:$(top_builddir)/unix/.libs:$(top_builddir)/cmdlang/.libs

TESTS_ENVIRONMENT = LD_LIBRARY_PATH="$(TEST_LD_LIBRARY_PATH)" PERLLIB="$(top_builddir)/swig/perl:$(srcdir)" top_builddir="$(top_builddir)" srcdir="$(srcdir)"
TESTS = test_fru test_chan test_lanparm test_pet test_pef

EXTRA_DIST = OpenIPMI_perl.c OpenIPMI_lang.i OpenIPMI.h \
	sample ipmi_powerctl $(TESTS) Lanserv.pm lan.conf
