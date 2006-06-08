
DIA_FILES = BusSystem.dia       ManagementController.dia  SimpleHotSwap.dia \
	    ComplexHotSwap.dia  MgmtIF.dia                Thresh.dia \
	    Hyst.dia            ServerSystem.dia

EXTRA_DIST = IPMI.ltx IPMI.pdf ipmi.bib ${DIA_FILES}

EPS_FILES = $(patsubst %.dia,%.eps,${DIA_FILES})

IPMI.pdf: IPMI.dvi
	dvipdf IPMI

IPMI.dvi: IPMI.ltx ${EPS_FILES}
	latex IPMI.ltx
	bibtex IPMI
	latex IPMI.ltx
	latex IPMI.ltx

%.eps : %.dia
	dia --export=$@ --filter=eps $<

CLEANFILES = BusSystem.eps ComplexHotSwap.eps Hyst.eps MgmtIF.eps \
	ManagementController.eps ServerSystem.eps SimpleHotSwap.eps \
	Thresh.eps \
	IPMI.aux IPMI.bbl IPMI.blg IPMI.dvi IPMI.log IPMI.pdf IPMI.toc \
	texput.log

