
AM_CFLAGS = -Wall -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

bin_PROGRAMS = ipmicmd

noinst_PROGRAMS = ipmisample ipmisample2

ipmisample_SOURCES = sample.c
ipmisample_LDADD = $(top_builddir)/utils/libOpenIPMIutils.la \
		$(top_builddir)/lib/libOpenIPMI.la \
		$(top_builddir)/unix/libOpenIPMIposix.la

ipmisample2_SOURCES = sample2.c
ipmisample2_LDADD = $(top_builddir)/utils/libOpenIPMIutils.la \
		$(top_builddir)/lib/libOpenIPMI.la \
		$(top_builddir)/unix/libOpenIPMIposix.la

ipmicmd_SOURCES = ipmicmd.c
ipmicmd_LDADD = -lpopt $(top_builddir)/utils/libOpenIPMIutils.la \
		$(top_builddir)/lib/libOpenIPMI.la \
		$(top_builddir)/unix/libOpenIPMIposix.la
ipmicmd_LDFLAGS = -rdynamic

EXTRA_DIST = example_oem.c
