
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

noinst_HEADERS = opq.h ilist.h md5.h md2.h

LD_VERSION = $(VERSION_CURRENT):$(VERSION_REVISION):$(VERSION_AGE)

lib_LTLIBRARIES = libOpenIPMI.la

bin_PROGRAMS = 

libOpenIPMI_la_SOURCES = entity.c ipmi.c mc.c sdr.c selector.c ind.c \
	ilist.c ipmi_smi.c opq.c sel.c sensor.c ipmi_lan.c md5.c md2.c
libOpenIPMI_la_LIBADD = -lm
libOpenIPMI_la_LDFLAGS = -version-info $(LD_VERSION) \
	-Wl,-Map -Wl,libOpenIPMI.map

noinst_PROGRAMS = test1

test1_SOURCES = test1.c
test1_LDADD = libOpenIPMI.la

TESTS = 

info_TEXINFOS = OpenIPMI.texi

clean:
	rm -f *.map
