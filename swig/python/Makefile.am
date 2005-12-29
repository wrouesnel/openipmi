
SUBDIRS = . @PYTHON_GUI_DIR@

AM_CFLAGS = $(PYTHON_CFLAGS) \
	    $(GLIB_CFLAGS) \
	    -I $(top_builddir)/include \
	    -I $(top_srcdir)/include \
	    -I $(top_srcdir)/swig/python

CC = @CC@ -Wall
CFLAGS = @CFLAGS@ -fPIC -DPYTHON_HAS_POSIX_THREADS=@PYTHON_HAS_POSIX_THREADS@
DEFS = @DEFS@

COMPILE = $(CC) $(DEFS) $(AM_CFLAGS) $(CFLAGS)

all-local: _OpenIPMI.so

OpenIPMI_SRC = OpenIPMI_wrap.c
OpenIPMI_OBJ = OpenIPMI_wrap.o

OpenIPMI_LIB = @PYTHON_POSIX_LIB@ \
	       $(top_builddir)/lib/libOpenIPMI.la \
	       $(top_builddir)/utils/libOpenIPMIutils.la \
	       $(GLIB_LIB) $(GLIB_LIBS)

EXTRA_DIST = OpenIPMI_lang.i OpenIPMI.h openipmigui.py

_OpenIPMI.so: $(OpenIPMI_OBJ)
	$(LIBTOOL) --mode=link $(CC) -shared -o $@ $^ $(OpenIPMI_LIB)
	rm _OpenIPMI.so
	mv .libs/_OpenIPMI.so .
	rm -rf .libs

OpenIPMI_wrap.o OpenIPMI.py: OpenIPMI_wrap.c OpenIPMI.h
	$(COMPILE) -c $<

OpenIPMI.pyc: OpenIPMI.py _OpenIPMI.so
	-$(pythonprog) -c 'import OpenIPMI.py'

OpenIPMI.pyo: OpenIPMI.py _OpenIPMI.so
	-$(pythonprog) -O -c 'import OpenIPMI.py'

OpenIPMI_wrap.c: $(top_srcdir)/swig/OpenIPMI.i OpenIPMI_lang.i
	$(SWIG) $(DEFS) -python -o $@ -I$(top_srcdir)/swig/python $<

CLEANFILES = $(OpenIPMI_OBJ) _OpenIPMI.so OpenIPMI_wrap.c

install-exec-local: _OpenIPMI.so OpenIPMI.py OpenIPMI.pyc OpenIPMI.pyo
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_PROGRAM) _OpenIPMI.so $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_PROGRAM) OpenIPMI.py $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_PROGRAM) OpenIPMI.pyc $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_PROGRAM) OpenIPMI.pyo $(DESTDIR)$(PYTHON_INSTALL_DIR)
	if test "x$(PYTHON_GUI_DIR)" = "xopenipmigui"; then \
	    $(INSTALL) -d $(DESTDIR)$(bindir); \
	    $(INSTALL_PROGRAM) openipmigui.py $(DESTDIR)$(bindir)/openipmigui;\
	fi

PYPATH=$(top_builddir)/swig/python
PYLDPATH=$(top_builddir)/lib/.libs:$(top_builddir)/utils/.libs:$(top_builddir)/glib/.libs:$(top_builddir)/unix/.libs

rungui:
	LD_LIBRARY_PATH=$(PYLDPATH) PYTHONPATH=$(PYPATH) $(pythonprog) $(top_srcdir)/swig/python/openipmigui.py
