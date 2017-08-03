
LIB_VERSION = 0.0.1
LD_VERSION = 0:1:0

PVERSION="1.0.13"

BUILD_CC = @BUILD_CC@

SUBDIRS = OpenIPMI sdrcomp @MARVELL_BMC_DIR@
DIST_SUBDIRS = OpenIPMI sdrcomp marvell-bmc

AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS \
	$(OPENSSLINCS) -DPVERSION="\"$(PVERSION)\""

AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -DSTATEDIR='"$(localstatedir)"'

lib_LTLIBRARIES = libIPMIlanserv.la

if HAVE_OPENIPMI_SMI
IPMILAN_PROG = ipmilan
IPMILAN_MAN = ipmilan.8
IPMILAN_NOMAN =
else
IPMILANPROG =
IPMILAN_MAN =
IPMILAN_NOMAN = ipmilan.8
endif

bin_PROGRAMS = ipmi_sim $(IPMILAN_PROG)

noinst_PROGRAMS = ipmi_checksum

noinst_HEADERS = emu.h bmc.h

libIPMIlanserv_la_SOURCES = lanserv_ipmi.c lanserv_asf.c priv_table.c \
	lanserv_oem_force.c lanserv_config.c config.c serv.c serial_ipmi.c \
	persist.c extcmd.c
libIPMIlanserv_la_LIBADD = $(OPENSSLLIBS) -ldl $(RT_LIB)
libIPMIlanserv_la_LDFLAGS = -version-info $(LD_VERSION) \
	../utils/libOpenIPMIutils.la

ipmi_checksum_SOURCES = ipmi_checksum.c

if HAVE_OPENIPMI_SMI
ipmilan_SOURCES = lanserv.c
ipmilan_LDADD = $(POPTLIBS) libIPMIlanserv.la -ldl $(RT_LIB)
ipmilan_LDFLAGS = -rdynamic ../unix/libOpenIPMIposix.la \
	../utils/libOpenIPMIutils.la
endif

ipmi_sim_SOURCES = ipmi_sim.c bmc.c emu_cmd.c sol.c \
	bmc_storage.c bmc_app.c bmc_chassis.c bmc_transport.c \
	bmc_sensor.c bmc_picmg.c
ipmi_sim_LDADD = $(POPTLIBS) libIPMIlanserv.la -lpthread $(RT_LIB)
ipmi_sim_LDFLAGS = -rdynamic ../unix/libOpenIPMIposix.la \
	../utils/libOpenIPMIutils.la $(SOCKETLIB)

man_MANS = $(IPMILAN_MAN) ipmi_lan.5 ipmi_sim.1 ipmi_sim_cmd.5

READMES = README.ipmi_sim README.vm README.design README.yourownbmc
EXTRA_DIST = atca.emu lan.conf ipmisim1.emu ipmisim1.sdrs \
	$(man_MANS) $(IPMILAN_NOMAN) $(READMES)

install-data-local:
	$(INSTALL) -m 755 -d "$(DESTDIR)$(sysconfdir)/ipmi/"; \
	$(INSTALL) -m 644 $(srcdir)/lan.conf "$(DESTDIR)$(sysconfdir)/ipmi/"; 
	$(INSTALL) -m 644 $(srcdir)/ipmisim1.emu "$(DESTDIR)$(sysconfdir)/ipmi/"; 

noinst_DATA = ipmisim1.bsdr

SUFFIXES = .bsdr .sdrs
.sdrs.bsdr:
	sdrcomp/sdrcomp_build -o $@ $<

ipmisim1.bsdr: $(top_srcdir)/lanserv/ipmisim1.sdrs sdrcomp/sdrcomp_build

uninstall-local:
	-rm -f "$(DESTDIR)$(sysconfdir)/ipmi/lan.conf"
	-rm -f "$(DESTDIR)$(sysconfdir)/ipmi/sim.emu"
	-rmdir "$(DESTDIR)$(sysconfdir)/ipmi" 2>/dev/null

CLEANFILES = ipmisim1.bsdr
