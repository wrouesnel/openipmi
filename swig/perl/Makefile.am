
# Having to -include this is stupid, but perl stupidly have a config.h
# file in it's include directory.
AM_CFLAGS = -include $(top_builddir)/config.h \
	    $(PERL_CFLAGS) \
	    -I $(top_builddir)/include \
	    -I $(top_srcdir)/include \
	    -I $(top_srcdir)/swig/perl

CC = @CC@ -Wall
CFLAGS = @CFLAGS@ -fPIC -DPERL_HAS_POSIX_THREADS=@PERL_HAS_POSIX_THREADS@
DEFS = @DEFS@

COMPILE = $(CC) $(DEFS) $(AM_CFLAGS) $(CFLAGS)

all: OpenIPMI.so dummystuff.so

nodist_OpenIPMI_SRC = OpenIPMI_wrap.c
OpenIPMI_SRC = OpenIPMI_perl.c
OpenIPMI_OBJ = OpenIPMI_wrap.lo OpenIPMI_perl.lo

OpenIPMI.so: $(OpenIPMI_OBJ)
	$(LIBTOOL) --mode=link $(CC) -shared -module -avoid-version -o $(@:.so=.la) $^ $(OPENIPMI_SWIG_LIBS) $(PERL_POSIX_LIB) -rpath $(PERL_INSTALL_DIR)/auto/OpenIPMI
	rm -f OpenIPMI.so
	mv .libs/OpenIPMI.so .
	rm -rf .libs

dummystuff.lo: dummystuff.c
	$(LIBTOOL) --mode=compile $(COMPILE) -c $<

dummystuff.so: dummystuff.lo
	$(LIBTOOL) --mode=link $(CC) -shared -module -avoid-version -o $(@:.so=.la) $^ -rpath /usr/lib

OpenIPMI_wrap.lo: OpenIPMI_wrap.c OpenIPMI.h
	$(LIBTOOL) --mode=compile $(COMPILE) -c $<

OpenIPMI_perl.lo: OpenIPMI_perl.c OpenIPMI.h
	$(LIBTOOL) --mode=compile $(COMPILE) -c $<

OpenIPMI_wrap.c OpenIPMI.pm: $(top_srcdir)/swig/OpenIPMI.i OpenIPMI_lang.i
	$(SWIG) $(DEFS) -perl5 -o OpenIPMI_wrap.c -I$(top_srcdir)/swig/perl $<

CLEANFILES = $(OpenIPMI_OBJ) OpenIPMI_wrap.o OpenIPMI_perl.o OpenIPMI.la \
	OpenIPMI.so OpenIPMI_wrap.c OpenIPMI.pm

install-exec-local: OpenIPMI.so OpenIPMI.pm
	$(INSTALL) -d "$(DESTDIR)$(PERL_INSTALL_DIR)/auto/OpenIPMI"
	$(INSTALL_PROGRAM) OpenIPMI.so "$(DESTDIR)$(PERL_INSTALL_DIR)/auto/OpenIPMI"
	$(INSTALL_DATA) OpenIPMI.pm "$(DESTDIR)$(PERL_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PERL_INSTALL_DIR)/auto/OpenIPMI/OpenIPMI.so"
	rm -f "$(DESTDIR)$(PERL_INSTALL_DIR)/OpenIPMI.pm"
	-rmdir "$(DESTDIR)$(PERL_INSTALL_DIR)/auto/OpenIPMI"

TESTS_ENVIRONMENT = LD_PRELOAD="$(OPENIPMI_SWIG_SO):$(top_builddir)/swig/perl/.libs/dummystuff.so" LD_LIBRARY_PATH=$(top_builddir)/glib/.libs PERLLIB="$(top_builddir)/swig/perl:$(srcdir)" top_builddir="$(top_builddir)" srcdir="$(srcdir)"
TESTS = test_fru test_chan test_lanparm test_pet test_pef

EXTRA_DIST = OpenIPMI_perl.c OpenIPMI_lang.i OpenIPMI.h \
	sample ipmi_powerctl $(TESTS) Lanserv.pm lan.conf dummystuff.c
