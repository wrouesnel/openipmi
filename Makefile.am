
empty:=
space:= $(empty) $(empty)

LIB_VERSION = 0.0.1

SPACE_VERSION = $(subst .,$(space),$(LIB_VERSION))
VERSION_CURRENT = $(wordlist 1, 1, $(SPACE_VERSION))
VERSION_REVISION = $(wordlist 3, 3, $(SPACE_VERSION))
VERSION_AGE = $(wordlist 2, 2, $(SPACE_VERSION))

EXTRA_DIST = 

AM_CFLAGS = -Wall -Werror -Iinclude
SUBDIRS = include

noinst_HEADERS = opq.h ilist.h md5.h md2.h ui_keypad.h ui_command.h

LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

lib_LTLIBRARIES = libOpenIPMI.la libOpenIPMIui.la

bin_PROGRAMS = ipmi_ui

libOpenIPMI_la_SOURCES = entity.c ipmi.c mc.c sdr.c selector.c ind.c \
	ilist.c ipmi_smi.c opq.c sel.c sensor.c ipmi_lan.c md5.c md2.c \
	strings.c
libOpenIPMI_la_LIBADD = -lm
libOpenIPMI_la_LDFLAGS = -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMI.map

libOpenIPMIui_la_SOURCES = ui.c ui_os.c ui_keypad.c ui_command.c 
libOpenIPMIui_la_LIBADD =
libOpenIPMIui_la_LDFLAGS = -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMIui.map

noinst_PROGRAMS = test1

test1_SOURCES = test1.c
test1_LDADD = libOpenIPMI.la

ipmi_ui_SOURCES = basic_ui.c
ipmi_ui_LDADD = libOpenIPMIui.la libOpenIPMI.la -lncurses

TESTS = 

info_TEXINFOS = OpenIPMI.texi

clean:
	rm -f *.map
