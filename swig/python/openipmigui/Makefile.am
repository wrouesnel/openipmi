
PY_FILES = _control.py _domain.py _entity.py _mc.py _sensor.py \
	gui_domainDialog.py gui.py __init__.py _saveprefs.py _fru.py \
	_sel.py _oi_logging.py _mc_chan.py _mc_lanparm.py _mc_user.py \
	_conn.py gui_cmdwin.py _term.py gui_SoL.py _mc_solparm.py \
	_mc_pefparm.py gui_errstr.py gui_popup.py gui_setdialog.py \
	gui_lightset.py gui_treelist.py gui_list.py gui_term.py \
	_misc.py gui_winsys.py

EXTRA_DIST = $(PY_FILES)

CLEANFILES = $(PY_FILES) *.pyc *.pyo

# Python doesn't have any way to output the compiled files somewhere else,
# and it doesn't work very well for them to be remote, anyway, so maintain
# a local copy of the .py files in the output directory.
localcopy:
	for i in $(EXTRA_DIST); do \
		if ! cmp $(srcdir)/$$i $$i 2>/dev/null; then \
			echo "Copying $$i"; \
			cp $(srcdir)/$$i $$i; \
		fi \
	done

all-local: localcopy

install-exec-local: $(EXTRA_DIST)
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)/openipmigui
	$(INSTALL_DATA) $^ $(DESTDIR)$(PYTHON_INSTALL_DIR)/openipmigui

uninstall-local:
	(for i in $(EXTRA_DIST); do \
		rm -f $(DESTDIR)$(PYTHON_INSTALL_DIR)/openipmigui/$$i; \
	done)
	-rmdir "$(DESTDIR)$(PYTHON_INSTALL_DIR)/openipmigui"

PYPATH=$(top_builddir)/swig/python:$(top_builddir)/swig/python/.libs:$(srcdir)
