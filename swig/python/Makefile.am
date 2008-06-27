
SUBDIRS = . @PYTHON_GUI_DIR@

AM_CFLAGS = $(PYTHON_CFLAGS) \
	    -I $(top_builddir) \
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

EXTRA_DIST = OpenIPMI_lang.i OpenIPMI.h openipmigui.py

_OpenIPMI.so: $(OpenIPMI_OBJ)
	$(LIBTOOL) --mode=link $(CC) -shared -o $@ $^ $(OPENIPMI_SWIG_LIBS)
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

CLEANFILES = $(OpenIPMI_OBJ) _OpenIPMI.so OpenIPMI_wrap.c \
	OpenIPMI.py OpenIPMI.pyo OpenIPMI.pyc

install-exec-local: _OpenIPMI.so OpenIPMI.py OpenIPMI.pyc OpenIPMI.pyo
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)
	$(LIBTOOL) --mode=install $(INSTALL_PROGRAM) _OpenIPMI.so "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/"
	$(INSTALL_DATA) OpenIPMI.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"
	$(INSTALL_DATA) OpenIPMI.pyc "$(DESTDIR)$(PYTHON_INSTALL_DIR)"
	$(INSTALL_DATA) OpenIPMI.pyo "$(DESTDIR)$(PYTHON_INSTALL_DIR)"
	if test "x$(PYTHON_GUI_DIR)" = "xopenipmigui"; then \
	    $(INSTALL) -d $(DESTDIR)$(bindir); \
	    $(INSTALL_PROGRAM) openipmigui.py "$(DESTDIR)$(bindir)/openipmigui";\
	fi

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_OpenIPMI.so"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/OpenIPMI.py"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/OpenIPMI.pyc"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/OpenIPMI.pyo"
	rm -f "$(DESTDIR)$(bindir)/openipmigui"

PYPATH=$(top_builddir)/swig/python:$(srcdir)/openipmigui

rungui:
	LD_LIBRARY_PATH=$(top_builddir)/glib/.libs LD_PRELOAD=$(OPENIPMI_SWIG_SO):$(top_builddir)/swig/python/_OpenIPMI.so PYTHONPATH=$(PYPATH) $(pythonprog) $(top_srcdir)/swig/python/openipmigui.py
