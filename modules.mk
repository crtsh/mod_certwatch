mod_certwatch.la: mod_certwatch.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version mod_certwatch.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_certwatch.la
