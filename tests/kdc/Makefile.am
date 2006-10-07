# $Id$

include $(top_srcdir)/Makefile.am.common

noinst_DATA = krb5.conf

check_PROGRAMS = ap-req
check_SCRIPTS = $(SCRIPT_TESTS) 

SCRIPT_TESTS = check-kdc check-digest
TESTS = $(SCRIPT_TESTS)

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/kdc,g'

LDADD = ../../lib/krb5/libkrb5.la

check-kdc: check-kdc.in Makefile
	$(do_subst) < $(srcdir)/check-kdc.in > check-kdc.tmp
	chmod +x check-kdc.tmp
	mv check-kdc.tmp check-kdc

check-digest: check-digest.in Makefile
	$(do_subst) < $(srcdir)/check-digest.in > check-digest.tmp
	chmod +x check-digest.tmp
	mv check-digest.tmp check-digest

krb5.conf: krb5.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5.conf.in > krb5.conf.tmp
	mv krb5.conf.tmp krb5.conf


CLEANFILES= \
	$(TESTS) \
	check-kdc.tmp \
	check-digest.tmp \
	krb5.conf krb5.conf.tmp \
	digest-reply cdigest-reply o2digest-reply \
	messages.log \
	current-db* \
	foopassword \
	barpassword \
	tempfile \
	server.keytab \
	client-cache
