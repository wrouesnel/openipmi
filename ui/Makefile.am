
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 1.0.1

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))

SNMPLIBS=@SNMPLIBS@

AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

bin_PROGRAMS = ipmi_ui

noinst_HEADERS = ui_keypad.h ui_command.h

LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

lib_LTLIBRARIES = libOpenIPMIui.la

libOpenIPMIui_la_SOURCES = ui.c ui_os.c ui_keypad.c ui_command.c 
libOpenIPMIui_la_LIBADD =
libOpenIPMIui_la_LDFLAGS = -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMIui.map

ipmi_ui_SOURCES = basic_ui.c
ipmi_ui_LDADD = libOpenIPMIui.la $(top_builddir)/utils/libOpenIPMIutils.la $(top_builddir)/lib/libOpenIPMI.la $(top_builddir)/unix/libOpenIPMIposix.la -lncurses $(SNMPLIBS) $(OPENSSLLIBS) $(GDBM_LIB)

CLEANFILES = libOpenIPMIui.map
