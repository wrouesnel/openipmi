
AM_CFLAGS = -Wall -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

bin_PROGRAMS = ipmicmd

noinst_PROGRAMS = ipmisample

ipmisample_SOURCES = sample.c
ipmisample_LDADD = $(top_builddir)/lib/libOpenIPMI.la \
		$(top_builddir)/ui/.libs/libOpenIPMIui.a

ipmicmd_SOURCES = ipmicmd.c
ipmicmd_LDADD = -lpopt $(top_builddir)/lib/libOpenIPMI.la \
		$(top_builddir)/ui/.libs/libOpenIPMIui.a
ipmicmd_LDFLAGS = -rdynamic

EXTRA_DIST = example_oem.c
