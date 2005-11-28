
EXTRA_DIST = _control.py _domain.py _entity.py _mc.py _sensor.py \
	_domainDialog.py gui.py __init__.py _saveprefs.py

PYC_FILES = _control.pyc _domain.pyc _entity.pyc _mc.pyc _sensor.pyc \
	_domainDialog.pyc gui.pyc __init__.pyc _saveprefs.pyc

PYO_FILES = _control.pyo _domain.pyo _entity.pyo _mc.pyo _sensor.pyo \
	_domainDialog.pyo gui.pyo __init__.pyo _saveprefs.pyo

all-local: $(PYC_FILES) $(PYO_FILES)

install-exec-local: $(EXTRA_DIST) $(PYC_FILES) $(PYO_FILES)
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)/openipmigui
	$(INSTALL_PROGRAM) $^ $(DESTDIR)$(PYTHON_INSTALL_DIR)/openipmigui

PYPATH=$(top_builddir)/swig/python

.py.pyc:
	PYTHONPATH=$(PYPATH) $(pythonprog) -c 'import $*'

.py.pyo:
	PYTHONPATH=$(PYPATH) $(pythonprog) -O -c 'import $*'

CLEANFILES = $(PYC_FILES) $(PYO_FILES)
