# $Id$

include $(top_srcdir)/Makefile.am.common

TESTS = check-gss
check_PROGRAMS = $(TESTS)

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/kdc,g'

check-gss: check-gss.in Makefile
	$(do_subst) < $(srcdir)/check-gss.in > check-gss.tmp
	chmod +x check-gss.tmp
	mv check-gss.tmp check-gss

CLEANFILES= \
	$(TESTS) \
	check-gss.tmp
