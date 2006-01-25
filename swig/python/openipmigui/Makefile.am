
EXTRA_DIST = _control.py _domain.py _entity.py _mc.py _sensor.py \
	_domainDialog.py gui.py __init__.py _saveprefs.py _fru.py \
	_sel.py _oi_logging.py _mc_chan.py _mc_lanparm.py _mc_user.py \
	_conn.py _cmdwin.py _term.py _SoL.py

PYC_FILES = _control.pyc _domain.pyc _entity.pyc _mc.pyc _sensor.pyc \
	_domainDialog.pyc gui.pyc __init__.pyc _saveprefs.pyc _fru.pyc \
	_sel.pyc _oi_logging.pyc _mc_chan.pyc _mc_lanparm.pyc _mc_user.pyc \
	_conn.pyc _cmdwin.pyc _term.pyc _SoL.pyc

PYO_FILES = _control.pyo _domain.pyo _entity.pyo _mc.pyo _sensor.pyo \
	_domainDialog.pyo gui.pyo __init__.pyo _saveprefs.pyo _fru.pyo \
	_sel.pyo _oi_logging.pyo _mc_chan.pyo _mc_lanparm.pyo _mc_user.pyo \
	_conn.pyo _cmdwin.pyo _term.pyo _SoL.pyo

all-local: $(PYC_FILES) $(PYO_FILES)

install-exec-local: $(EXTRA_DIST) $(PYC_FILES) $(PYO_FILES)
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)/openipmigui
	$(INSTALL_PROGRAM) $^ $(DESTDIR)$(PYTHON_INSTALL_DIR)/openipmigui

PYPATH=$(top_builddir)/swig/python
PYLDPATH=$(top_builddir)/lib/.libs:$(top_builddir)/utils/.libs:$(top_builddir)/glib/.libs:$(top_builddir)/unix/.libs:$(top_builddir)/cmdlang/.libs

.py.pyc:
	LD_LIBRARY_PATH=$(PYLDPATH) PYTHONPATH=$(PYPATH) $(pythonprog) -c 'import $*'

.py.pyo:
	LD_LIBRARY_PATH=$(PYLDPATH) PYTHONPATH=$(PYPATH) $(pythonprog) -O -c 'import $*'

CLEANFILES = $(PYC_FILES) $(PYO_FILES)
