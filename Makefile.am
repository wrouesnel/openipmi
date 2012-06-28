RPM		= rpmbuild
RPMFLAGS	= -ta

SUBDIRS    = include utils lib unix $(GLIB_DIR) $(TCL_DIR) libedit cmdlang \
	     ui lanserv sample doc man $(SWIG_DIR)

DIST_SUBDIRS = include utils lib unix glib tcl libedit cmdlang \
	     ui lanserv sample doc man swig

EXTRA_DIST = FAQ TODO README.Force README.MotorolaMXP OpenIPMI.spec.in \
	     OpenIPMI.spec ipmi.init ipmi.sysconf COPYING.BSD \
	     CONFIGURING_FOR_LAN

PKGCONFIGS = OpenIPMIutils.pc OpenIPMI.pc OpenIPMIui.pc OpenIPMIposix.pc \
	     OpenIPMIpthread.pc OpenIPMIcmdlang.pc $(GLIB_PKGCONF) \
	     $(GLIB12_PKGCONF) $(TCL_PKGCONF)

ACLOCAL_AMFLAGS = -I m4

install-data-local: $(PKGCONFIGS)
	$(mkinstalldirs) $(DESTDIR)$(libdir)/pkgconfig
	$(INSTALL_DATA) $(PKGCONFIGS) $(DESTDIR)$(libdir)/pkgconfig

uninstall-local:
	for i in $(PKGCONFIGS); do \
		rm -f $(DESTDIR)$(libdir)/pkgconfig/$$i; \
	done

rpm: dist
	$(RPM) $(RPMFLAGS) $(distdir).tar.gz < /dev/null

PYPATH=$(top_builddir)/swig/python:$(top_builddir)/swig/python/.libs:$(srcdir)/openipmigui

rungui:
	LD_LIBRARY_PATH=$(top_builddir)/glib/.libs LD_PRELOAD=$(OPENIPMI_SWIG_SO):$(top_builddir)/swig/python/.libs/_OpenIPMI.so PYTHONPATH=$(PYPATH) $(pythonprog) $(top_srcdir)/swig/python/openipmigui.py

DISTCLEANFILES=OpenIPMI.spec OpenIPMIcmdlang.pc OpenIPMI.pc OpenIPMItcl.pc \
	OpenIPMIglib12.pc OpenIPMIposix.pc OpenIPMIui.pc OpenIPMIglib.pc \
	OpenIPMIpthread.pc OpenIPMIutils.pc
