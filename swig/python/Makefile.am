
SUBDIRS = . @PYTHON_GUI_DIR@

AM_CFLAGS = $(PYTHON_CFLAGS) \
	    -I $(top_builddir) \
	    -I $(top_builddir)/include \
	    -I $(top_srcdir)/include \
	    -I $(top_srcdir)/swig/python \
	    -DPYTHON_HAS_POSIX_THREADS=@PYTHON_HAS_POSIX_THREADS@

pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
PYPATH=$(top_builddir)/swig/python:$(top_builddir)/swig/python/.libs:$(srcdir)/openipmigui

pythonlib_LTLIBRARIES = _OpenIPMI.la

nodist__OpenIPMI_la_SOURCES = OpenIPMI_wrap.c
_OpenIPMI_la_LDFLAGS = -module -avoid-version
_OpenIPMI_la_LIBADD = $(OPENIPMI_SWIG_LIBS) $(PYTHON_POSIX_LIB)

EXTRA_DIST = OpenIPMI_lang.i OpenIPMI.h openipmigui.py sample.py sample2.py

OpenIPMI.pyc: OpenIPMI.py _OpenIPMI.la
	-PYTHONPATH=$(PYPATH) $(pythonprog) -c 'import OpenIPMI.py'

OpenIPMI.pyo: OpenIPMI.py _OpenIPMI.la
	-PYTHONPATH=$(PYPATH) $(pythonprog) -O -c 'import OpenIPMI.py'

OpenIPMI_wrap.c OpenIPMI.py: $(top_srcdir)/swig/OpenIPMI.i OpenIPMI_lang.i
	$(SWIG) $(DEFS) -python -o OpenIPMI_wrap.c -I$(top_srcdir)/swig/python $<

CLEANFILES = OpenIPMI_wrap.c OpenIPMI.py OpenIPMI.pyo OpenIPMI.pyc

install-exec-local: _OpenIPMI.la OpenIPMI.py OpenIPMI.pyc OpenIPMI.pyo
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_DATA) OpenIPMI.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"
	$(INSTALL_DATA) OpenIPMI.pyc "$(DESTDIR)$(PYTHON_INSTALL_DIR)"
	$(INSTALL_DATA) OpenIPMI.pyo "$(DESTDIR)$(PYTHON_INSTALL_DIR)"
	if test "x$(PYTHON_GUI_DIR)" = "xopenipmigui"; then \
	    $(INSTALL) -d $(DESTDIR)$(bindir); \
	    $(INSTALL_SCRIPT) $(srcdir)/openipmigui.py "$(DESTDIR)$(bindir)/openipmigui";\
	fi

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_OpenIPMI.so"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/OpenIPMI.py"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/OpenIPMI.pyc"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/OpenIPMI.pyo"
	rm -f "$(DESTDIR)$(bindir)/openipmigui"

rungui:
	LD_LIBRARY_PATH=$(top_builddir)/glib/.libs LD_PRELOAD=$(OPENIPMI_SWIG_SO):$(top_builddir)/swig/python/.libs/_OpenIPMI.so PYTHONPATH=$(PYPATH) $(pythonprog) $(top_srcdir)/swig/python/openipmigui.py
