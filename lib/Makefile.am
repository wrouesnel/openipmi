
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.3

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))
LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

AM_CFLAGS = -Wall -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

noinst_HEADERS = heap.h

lib_LTLIBRARIES = libOpenIPMI.la

libOpenIPMI_la_SOURCES = entity.c ipmi.c domain.c mc.c sdr.c selector.c \
	control.c ipmi_utils.c conn.c fru.c chassis.c pet.c event.c \
	ilist.c ipmi_smi.c opq.c sel.c sensor.c pef.c lanparm.c ipmi_lan.c \
	strings.c ipmi_malloc.c oem_force_conn.c \
	oem_motorola_mxp.c oem_motorola_mxp_intf.c oem_atca_conn.c oem_atca.c
libOpenIPMI_la_LIBADD = -lm $(top_builddir)/utils/libIPMIutils.a
libOpenIPMI_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMI.map

noinst_PROGRAMS = test_heap

test_heap_SOURCES = test_heap.c
test_heap_LDADD = 

TESTS = test_heap

clean:
	rm -f *.map
