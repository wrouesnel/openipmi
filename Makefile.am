
SUBDIRS = include utils lib ui lanserv sample doc man

EXTRA_DIST = FAQ TODO README.Force README.MotorolaMXP

PKGCONFIGS = OpenIPMI.pc OpenIPMIui.pc 

install-data-local: OpenIPMI.pc OpenIPMIui.pc
	$(mkinstalldirs) $(DESTDIR)$(libdir)/pkgconfig
	$(INSTALL_DATA) $(PKGCONFIGS) $(DESTDIR)$(libdir)/pkgconfig

uninstall-local:
	for i in $(PKGCONFIGS); do \
		rm -f $(DESTDIR)$(libdir)/pkgconfig/$$i; \
	done
