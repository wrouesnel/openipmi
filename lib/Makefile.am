
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.4

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))
LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

AM_CFLAGS = -Wall -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

lib_LTLIBRARIES = libOpenIPMI.la

libOpenIPMI_la_SOURCES = entity.c ipmi.c domain.c mc.c sdr.c \
	control.c ipmi_utils.c conn.c fru.c chassis.c pet.c event.c \
	opq.c sel.c sensor.c pef.c lanparm.c strings.c \
	oem_force_conn.c oem_motorola_mxp.c oem_atca_conn.c oem_atca.c \
	ipmi_smi.c ipmi_lan.c oem_motorola_mxp_intf.c
libOpenIPMI_la_LIBADD = -lm $(top_builddir)/utils/libOpenIPMIutils.la
libOpenIPMI_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMI.map

clean:
	rm -f *.map
