
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.1

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))

AM_CFLAGS = -Wall -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

lib_LTLIBRARIES = libIPMIlanserv.la

bin_PROGRAMS = ipmilan

noinst_PROGRAMS = lanserv_emu

libIPMIlanserv_la_SOURCES = lanserv_ipmi.c lanserv_asf.c priv_table.c \
	lanserv_oem_force.c
libIPMIlanserv_la_LIBADD = $(top_builddir)/utils/libIPMIutils.a
libIPMIlanserv_la_LDFLAGS = -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libIPMIlanserv.map

ipmilan_SOURCES = lanserv.c
ipmilan_LDADD = -lpopt libIPMIlanserv.la
ipmilan_LDFLAGS = -rdynamic

lanserv_emu_SOURCES = lanserv_emu.c
lanserv_emu_LDADD = -lpopt libIPMIlanserv.la
lanserv_emu_LDFLAGS = -rdynamic

clean:
	rm -f *.map
