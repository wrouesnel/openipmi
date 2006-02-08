
SUBDIRS    = . $(PERL_DIR) $(PYTHON_DIR)

EXTRA_DIST = OpenIPMI.i

noinst_LIBRARIES = @GLIB_SHIM@ @GLIB12_SHIM@
EXTRA_LIBRARIES = libglibshim.a libglib12shim.a

AM_CFLAGS = -Wall -I$(top_srcdir)/include

libglibshim_a_SOURCES = glibshim.c
libglibshim_a_CFLAGS = $(GLIB_CFLAGS) $(AM_CFLAGS) -DINITFUNC=init_glib_shim

libglib12shim_a_SOURCES = glibshim.c
libglib12shim_a_CFLAGS = $(GLIB_CFLAGS) $(AM_CFLAGS) -DINITFUNC=init_glib12_shim
