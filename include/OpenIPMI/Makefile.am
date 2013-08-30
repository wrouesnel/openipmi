
pkginclude_HEADERS = \
	ipmi_addr.h	ipmi_err.h	ipmi_log.h	ipmi_posix.h	\
	mxp.h		ipmi_auth.h	ipmi_msgbits.h	ipmi_sdr.h	\
	os_handler.h	ipmi_bits.h	ipmi_fru.h	ipmi_glib.h	\
	ipmi_smi.h	selector.h	ipmi_mc.h	ipmi_user.h	\
	ipmi_cmdlang.h	ipmiif.h	ipmi_pef.h	ipmi_types.h	\
	ipmi_conn.h	ipmi_lan.h	ipmi_pet.h	ipmi_ui.h	\
	ipmi_debug.h	ipmi_lanparm.h	ipmi_picmg.h	ipmi_string.h	\
	ipmi_sol.h	ipmi_solparm.h	ipmi_tcl.h

SUBDIRS = internal

DISTCLEANFILES = ipmiif.h

uninstall-local:
	-rmdir $(pkgincludedir)
