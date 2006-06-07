
EXTRA_DIST = _control.py _domain.py _entity.py _mc.py _sensor.py \
	gui_domainDialog.py gui.py __init__.py _saveprefs.py _fru.py \
	_sel.py _oi_logging.py _mc_chan.py _mc_lanparm.py _mc_user.py \
	_conn.py gui_cmdwin.py _term.py gui_SoL.py _mc_solparm.py \
	_mc_pefparm.py gui_errstr.py gui_popup.py gui_setdialog.py \
	gui_lightset.py gui_treelist.py gui_list.py gui_term.py

PYC_FILES = _control.pyc _domain.pyc _entity.pyc _mc.pyc _sensor.pyc \
	gui_domainDialog.pyc gui.pyc __init__.pyc _saveprefs.pyc _fru.pyc \
	_sel.pyc _oi_logging.pyc _mc_chan.pyc _mc_lanparm.pyc _mc_user.pyc \
	_conn.pyc gui_cmdwin.pyc _term.pyc gui_SoL.pyc _mc_solparm.pyc \
	_mc_pefparm.pyc gui_errstr.pyc gui_popup.pyc gui_setdialog.pyc \
	gui_lightset.pyc gui_treelist.pyc gui_list.pyc gui_term.pyc

PYO_FILES = _control.pyo _domain.pyo _entity.pyo _mc.pyo _sensor.pyo \
	gui_domainDialog.pyo gui.pyo __init__.pyo _saveprefs.pyo _fru.pyo \
	_sel.pyo _oi_logging.pyo _mc_chan.pyo _mc_lanparm.pyo _mc_user.pyo \
	_conn.pyo gui_cmdwin.pyo _term.pyo gui_SoL.pyo _mc_solparm.pyo \
	_mc_pefparm.pyo gui_errstr.pyo gui_popup.pyo gui_setdialog.pyo \
	gui_lightset.pyo gui_treelist.pyo gui_list.pyo gui_term.pyo

all-local: $(PYC_FILES) $(PYO_FILES)

install-exec-local: $(EXTRA_DIST) $(PYC_FILES) $(PYO_FILES)
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)/openipmigui
	$(INSTALL_PROGRAM) $^ $(DESTDIR)$(PYTHON_INSTALL_DIR)/openipmigui

PYPATH=$(top_builddir)/swig/python:$(srcdir)
PYLDPATH=$(top_builddir)/lib/.libs:$(top_builddir)/utils/.libs:$(top_builddir)/glib/.libs:$(top_builddir)/unix/.libs:$(top_builddir)/cmdlang/.libs:$(top_builddir)/tcl/.libs

.py.pyc:
	LD_LIBRARY_PATH=$(PYLDPATH) PYTHONPATH=$(PYPATH) $(pythonprog) -c 'import $*'

.py.pyo:
	LD_LIBRARY_PATH=$(PYLDPATH) PYTHONPATH=$(PYPATH) $(pythonprog) -O -c 'import $*'

CLEANFILES = $(PYC_FILES) $(PYO_FILES)
