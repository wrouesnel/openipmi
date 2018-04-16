
# Having to -include this is stupid, but perl stupidly has a config.h
# file in it's include directory.
AM_CFLAGS = -include $(top_builddir)/config.h \
	    $(PERL_CFLAGS) \
	    -I $(top_builddir)/include \
	    -I $(top_srcdir)/include \
	    -I $(top_srcdir)/swig/perl \
	    -DPERL_HAS_POSIX_THREADS=@PERL_HAS_POSIX_THREADS@

all-local: OpenIPMI.so

noinst_LTLIBRARIES = libOpenIPMI.la

check_LTLIBRARIES = libdummystuff.la

nodist_libOpenIPMI_la_SOURCES = OpenIPMI_wrap.c
libOpenIPMI_la_SOURCES = OpenIPMI_perl.c
libOpenIPMI_la_LDFLAGS = -rpath /nowhere

libdummystuff_la_SOURCES = dummystuff.c
libdummystuff_la_LDFLAGS = -rpath /nowhere

OpenIPMI_wrap.c OpenIPMI.pm: $(top_srcdir)/swig/OpenIPMI.i OpenIPMI_lang.i
	$(SWIG) $(DEFS) -perl5 -o OpenIPMI_wrap.c -I$(top_srcdir)/swig/perl $<

OpenIPMI.so: libOpenIPMI.la
	cp .libs/libOpenIPMI.so $@

CLEANFILES = OpenIPMI.so OpenIPMI.pm OpenIPMI_wrap.c

clean-local:
	rm -rf tmppersist auto

install-exec-local: OpenIPMI.so OpenIPMI.pm
	$(INSTALL) -d "$(DESTDIR)$(PERL_INSTALL_DIR)/auto/OpenIPMI"
	$(INSTALL_PROGRAM) OpenIPMI.so "$(DESTDIR)$(PERL_INSTALL_DIR)/auto/OpenIPMI"
	$(INSTALL_DATA) OpenIPMI.pm "$(DESTDIR)$(PERL_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PERL_INSTALL_DIR)/auto/OpenIPMI/OpenIPMI.so"
	rm -f "$(DESTDIR)$(PERL_INSTALL_DIR)/OpenIPMI.pm"
	-rmdir "$(DESTDIR)$(PERL_INSTALL_DIR)/auto/OpenIPMI"

AM_TESTS_ENVIRONMENT = mkdir -p tmppersist && mkdir -p auto/OpenIPMI && cp OpenIPMI.so auto/OpenIPMI && TEST_LD_PRELOAD="$(OPENIPMI_SWIG_SO):$(top_builddir)/swig/perl/.libs/libdummystuff.so" LD_LIBRARY_PATH=$(top_builddir)/glib/.libs PERL5LIB="$(top_builddir)/swig/perl:$(srcdir)" top_builddir="$(top_builddir)" srcdir="$(srcdir)"
TESTS = test_fru test_chan test_lanparm test_pet test_pef

EXTRA_DIST = OpenIPMI_perl.c OpenIPMI_lang.i OpenIPMI.h \
	sample ipmi_powerctl $(TESTS) Lanserv.pm lan.conf dummystuff.c
