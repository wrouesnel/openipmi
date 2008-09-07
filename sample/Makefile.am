
AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

bin_PROGRAMS = openipmicmd solterm rmcp_ping

noinst_PROGRAMS = ipmisample ipmisample2 ipmisample3 ipmi_serial_bmc_emu \
		  ipmi_dump_sensors waiter_sample

ipmisample_SOURCES = sample.c
ipmisample_LDADD = $(top_builddir)/utils/libOpenIPMIutils.la \
		$(top_builddir)/lib/libOpenIPMI.la \
		$(top_builddir)/unix/libOpenIPMIposix.la \
		$(OPENSSLLIBS)

ipmisample2_SOURCES = sample2.c
ipmisample2_LDADD = $(top_builddir)/utils/libOpenIPMIutils.la \
		$(top_builddir)/lib/libOpenIPMI.la \
		$(top_builddir)/unix/libOpenIPMIpthread.la \
		-lpthread $(OPENSSLLIBS)

ipmisample3_SOURCES = sample3.c
ipmisample3_LDADD = $(top_builddir)/utils/libOpenIPMIutils.la \
		$(top_builddir)/lib/libOpenIPMI.la \
		$(top_builddir)/unix/libOpenIPMIposix.la \
		$(OPENSSLLIBS)

waiter_sample_SOURCES = waiter_sample.c
waiter_sample_LDADD = $(top_builddir)/utils/libOpenIPMIutils.la \
		$(top_builddir)/lib/libOpenIPMI.la \
		$(top_builddir)/unix/libOpenIPMIposix.la \
		$(OPENSSLLIBS)

ipmi_dump_sensors_SOURCES = dump_sensors.c
ipmi_dump_sensors_LDADD = $(top_builddir)/utils/libOpenIPMIutils.la \
		$(top_builddir)/lib/libOpenIPMI.la \
		$(top_builddir)/unix/libOpenIPMIposix.la \
		$(OPENSSLLIBS)

openipmicmd_SOURCES = ipmicmd.c
openipmicmd_LDADD = $(top_builddir)/utils/libOpenIPMIutils.la \
		$(top_builddir)/lib/libOpenIPMI.la \
		$(top_builddir)/unix/libOpenIPMIposix.la \
		$(OPENSSLLIBS)
openipmicmd_LDFLAGS = -rdynamic

solterm_SOURCES = solterm.c
solterm_LDADD = $(POPTLIBS) $(top_builddir)/utils/libOpenIPMIutils.la \
                $(top_builddir)/lib/libOpenIPMI.la \
                $(top_builddir)/unix/libOpenIPMIposix.la \
                $(OPENSSLLIBS)

rmcp_ping_SOURCES = rmcp_ping.c

ipmi_serial_bmc_emu_SOURCES = ipmi_serial_bmc_emu.c
ipmi_serial_bmc_emu_LDADD = $(top_builddir)/libedit/libedit.a
ipmi_serial_bmc_emu_CFLAGS = -I $(top_srcdir)/libedit

EXTRA_DIST = example_oem.c

# We need to make a link from ipmicmd to openipmicmd for backwards
# compatability.
install-data-local:
	rm -f $(DESTDIR)$(bindir)/ipmicmd
	$(LN_S) openipmicmd $(DESTDIR)$(bindir)/ipmicmd

uninstall-local:
	rm -f $(DESTDIR)$(bindir)/ipmicmd