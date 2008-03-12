
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.1

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))

AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS \
	$(OPENSSLINCS)

LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

lib_LTLIBRARIES = libIPMIlanserv.la

bin_PROGRAMS = ipmilan

noinst_PROGRAMS = lanserv_emu ipmi_checksum

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

lanserv_emu_SOURCES = lanserv_emu.c emu.c emu_cmd.c
lanserv_emu_LDADD = $(POPTLIBS) libIPMIlanserv.la
lanserv_emu_LDFLAGS = -rdynamic

EXTRA_DIST = atca.emu README.emulator

CLEANFILES = libIPMIlanserv.map

SUBDIRS = OpenIPMI
