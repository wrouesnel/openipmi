
LIB_VERSION = 0.0.1
LD_VERSION = 0:1:0

AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS \
	$(OPENSSLINCS)

lib_LTLIBRARIES = libIPMIlanserv.la

bin_PROGRAMS = ipmilan

noinst_PROGRAMS = ipmi_sim ipmi_checksum

noinst_HEADERS = emu.h

libIPMIlanserv_la_SOURCES = lanserv_ipmi.c lanserv_asf.c priv_table.c \
	lanserv_oem_force.c lanserv_config.c
nodist_libIPMIlanserv_la_SOURCES = ../utils/ipmi_auth.c ../utils/md2.c \
	../utils/md5.c
libIPMIlanserv_la_LIBADD = $(OPENSSLLIBS)
libIPMIlanserv_la_LDFLAGS = -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libIPMIlanserv.map

ipmi_checksum_SOURCES = ipmi_checksum.c

ipmilan_SOURCES = lanserv.c
ipmilan_LDADD = $(POPTLIBS) libIPMIlanserv.la
ipmilan_LDFLAGS = -rdynamic

ipmi_sim_SOURCES = ipmi_sim.c emu.c emu_cmd.c
ipmi_sim_LDADD = $(POPTLIBS) libIPMIlanserv.la
ipmi_sim_LDFLAGS = -rdynamic ../unix/libOpenIPMIposix.la

EXTRA_DIST = atca.emu README.emulator

CLEANFILES = libIPMIlanserv.map

SUBDIRS = OpenIPMI
