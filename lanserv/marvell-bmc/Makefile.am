
AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/lanserv
pkglib_LTLIBRARIES = marvell_mod.la

marvell_mod_la_SOURCES = marvell_mod.c
marvell_mod_la_LDFLAGS = -module

sdrs.bin: main.sdrs board.sdrs fan.sdrs \
		$(top_builddir)/lanserv/sdrcomp/sdrcomp
	$(top_builddir)/lanserv/sdrcomp/sdrcomp main.sdrs >sdrs.bin

noinst_DATA = sdrs.bin

noinst_HEADERS = wiw.h

EXTRA_DIST = main.sdrs board.sdrs fan.sdrs lan.conf netsrvc
