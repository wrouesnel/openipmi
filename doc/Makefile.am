
DIA_FILES = BusSystem.dia       ManagementController.dia  SimpleHotSwap.dia \
	    ComplexHotSwap.dia  MgmtIF.dia                Thresh.dia \
	    Hyst.dia            ServerSystem.dia	  SimpleMonitoring.dia

EXTRA_DIST = IPMI.ltx IPMI.pdf ipmi.bib ${DIA_FILES}

EPS_FILES = $(patsubst %.dia,%.eps,${DIA_FILES})

IPMI.pdf: IPMI.dvi
	$(DVIPDF) IPMI

IPMI.dvi: IPMI.ltx ${EPS_FILES}
	${LATEX} IPMI.ltx
	${BIBTEX} IPMI
	${LATEX} IPMI.ltx
	${LATEX} IPMI.ltx

%.eps : %.dia
	$(DIA) --export=$@ $(DIA_FILTER_NAME)=eps $<

CLEANFILES = BusSystem.eps ComplexHotSwap.eps Hyst.eps MgmtIF.eps \
	ManagementController.eps ServerSystem.eps SimpleHotSwap.eps \
	Thresh.eps SimpleMonitoring.eps \
	IPMI.aux IPMI.bbl IPMI.blg IPMI.dvi IPMI.log IPMI.pdf IPMI.toc \
	texput.log
