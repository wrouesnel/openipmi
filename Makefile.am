
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.1

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))

AM_CFLAGS = -Wall -I$(srcdir)/include -DIPMI_CHECK_LOCKS
SUBDIRS = include

noinst_HEADERS = opq.h ilist.h md5.h md2.h ui_keypad.h ui_command.h heap.h

LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

lib_LTLIBRARIES = libOpenIPMI.la libOpenIPMIui.la liblanserv.la

bin_PROGRAMS = ipmi_ui ipmicmd ipmilan

libOpenIPMI_la_SOURCES = entity.c ipmi.c domain.c mc.c sdr.c selector.c \
	control.c ipmi_utils.c conn.c \
	ilist.c ipmi_smi.c opq.c sel.c sensor.c ipmi_lan.c md5.c md2.c \
	strings.c ipmi_malloc.c ipmi_auth.c \
	ipmi_oem_force_conn.c
libOpenIPMI_la_LIBADD = -lm
libOpenIPMI_la_LDFLAGS = -rdynamic -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMI.map

libOpenIPMIui_la_SOURCES = ui.c ui_os.c ui_keypad.c ui_command.c 
libOpenIPMIui_la_LIBADD =
libOpenIPMIui_la_LDFLAGS = -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMIui.map

liblanserv_la_SOURCES = lanserv_ipmi.c lanserv_asf.c priv_table.c \
	lanserv_oem_force.c
liblanserv_la_LIBADD =
liblanserv_la_LDFLAGS = -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,liblanserv.map

noinst_PROGRAMS = test_heap ipmisample lanserv_emu

ipmisample_SOURCES = sample.c
ipmisample_LDADD = libOpenIPMI.la .libs/libOpenIPMIui.a

ipmicmd_SOURCES = ipmicmd.c
ipmicmd_LDADD = -lpopt .libs/libOpenIPMI.a .libs/libOpenIPMIui.a
ipmicmd_LDFLAGS = -rdynamic

ipmilan_SOURCES = lanserv.c
ipmilan_LDADD = -lpopt liblanserv.la .libs/libOpenIPMI.a
ipmilan_LDFLAGS = -rdynamic

lanserv_emu_SOURCES = lanserv_emu.c
lanserv_emu_LDADD = -lpopt liblanserv.la .libs/libOpenIPMI.a
lanserv_emu_LDFLAGS = -rdynamic

test_heap_SOURCES = test_heap.c
test_heap_LDADD = 

ipmi_ui_SOURCES = basic_ui.c
ipmi_ui_LDADD = libOpenIPMIui.la libOpenIPMI.la -lncurses

TESTS = test_heap

info_TEXINFOS = OpenIPMI.texi

man_MANS = ipmi_ui.1 ipmilan.8 ipmicmd.1
EXTRA_DIST = $(man_MANS) FAQ TODO example_oem.c README.Force

clean:
	rm -f *.map
