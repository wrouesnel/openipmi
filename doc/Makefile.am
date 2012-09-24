
DIA_FILES = BusSystem.dia       ManagementController.dia  SimpleHotSwap.dia \
	    ComplexHotSwap.dia  MgmtIF.dia                Thresh.dia \
	    Hyst.dia            ServerSystem.dia	  SimpleMonitoring.dia

EXTRA_DIST = IPMI.ltx IPMI.pdf ipmi.bib ${DIA_FILES}

EPS_FILES = BusSystem.eps       ManagementController.eps  SimpleHotSwap.eps \
	    ComplexHotSwap.eps  MgmtIF.eps                Thresh.eps \
	    Hyst.eps            ServerSystem.eps	  SimpleMonitoring.eps

IPMI.pdf: IPMI.dvi
	$(DVIPDF) IPMI

IPMI.dvi: $(srcdir)/IPMI.ltx ${EPS_FILES}
	${LATEX} $(srcdir)/IPMI.ltx
	BIBINPUTS=$(srcdir) ${BIBTEX} IPMI
	${LATEX} $(srcdir)/IPMI.ltx
	${LATEX} $(srcdir)/IPMI.ltx

.dia.eps:
	$(DIA) --export=$@ $(DIA_FILTER_NAME)=eps $<

CLEANFILES = ${EPS_FILES} \
	IPMI.aux IPMI.bbl IPMI.blg IPMI.dvi IPMI.log IPMI.pdf IPMI.toc \
	texput.log
