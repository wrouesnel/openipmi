RPM		= rpmbuild
RPMFLAGS	= -ta

SUBDIRS    = include utils lib cmdlang unix ui lanserv sample doc man

EXTRA_DIST = FAQ TODO README.Force README.MotorolaMXP OpenIPMI.spec.in \
	     OpenIPMI.spec

PKGCONFIGS = OpenIPMIutils.pc OpenIPMI.pc OpenIPMIui.pc OpenIPMIposix.pc \
	     OpenIPMIpthread.pc

install-data-local: OpenIPMI.pc OpenIPMIui.pc
	$(mkinstalldirs) $(DESTDIR)$(libdir)/pkgconfig
	$(INSTALL_DATA) $(PKGCONFIGS) $(DESTDIR)$(libdir)/pkgconfig

uninstall-local:
	for i in $(PKGCONFIGS); do \
		rm -f $(DESTDIR)$(libdir)/pkgconfig/$$i; \
	done

rpm: dist
	$(RPM) $(RPMFLAGS) $(distdir).tar.gz < /dev/null
