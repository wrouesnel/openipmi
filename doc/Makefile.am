
DIA_FILES = BusSystem.dia       ManagementController.dia  SimpleHotSwap.dia \
	    ComplexHotSwap.dia  MgmtIF.dia                Thresh.dia \
	    Hyst.dia            ServerSystem.dia

EXTRA_DIST = IPMI.ltx IPMI.pdf ipmi.bib ${DIA_FILES}

EPS_FILES = $(patsubst %.dia,%.eps,${DIA_FILES})

IPMI.pdf: IPMI.dvi
	dvipdf IPMI

IPMI.dvi: IPMI.ltx ${EPS_FILES}
	latex IPMI.ltx

%.eps : %.dia
	dia --export=$@ --export-to-format=eps $<