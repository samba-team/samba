# $Id$

include $(top_srcdir)/Makefile.am.common

noinst_DATA = krb5.conf mit-pkinit-20070607.cf

check_SCRIPTS = $(SCRIPT_TESTS) test_can

SCRIPT_TESTS = check-can
TESTS = $(SCRIPT_TESTS)

port = 49188

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]port[@],$(port),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/can,g' \
	-e 's,[@]EGREP[@],$(EGREP),g' 

test_can: test_can.in Makefile
	$(do_subst) < $(srcdir)/test_can.in > test_can.tmp
	chmod +x test_can.tmp
	mv test_can.tmp test_can

check-can: check-can.in Makefile
	$(do_subst) < $(srcdir)/check-can.in > check-can.tmp
	chmod +x check-can.tmp
	mv check-can.tmp check-can

krb5.conf: krb5.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5.conf.in > krb5.conf.tmp
	mv krb5.conf.tmp krb5.conf

SUFFIXES += .xf .cf

.xf.cf:
	$(do_subst) < $< > $@.tmp
	mv $@.tmp $@

CLEANFILES= $(TESTS) *.tmp *.xf


EXTRA_DIST = \
	test_can.in \
	check-can.in \
	krb5.conf.in
