
SUBDIRS = include utils lib ui lanserv sample doc man

EXTRA_DIST = FAQ TODO README.Force README.MotorolaMXP

install-data-local: OpenIPMI.pc OpenIPMIui.pc
	$(mkinstalldirs) $(DESTDIR)$(libdir)/pkgconfig
	$(INSTALL_DATA) OpenIPMI.pc OpenIPMIui.pc$(DESTDIR)$(libdir)/pkgconfig

uninstall-local:
	rm -f $(DESTDIR)$(libdir)/pkgconfig/OpenIPMI.pc OpenIPMIui.pc
