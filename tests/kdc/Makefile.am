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
	barpassword \
	cache.krb5 \
	cdigest-reply \
	check-digest.tmp \
	check-kdc.tmp \
	client-cache \
	current-db* \
	digest-reply \
	foopassword \
	krb5.conf krb5.conf.tmp \
	messages.log \
	o2cache.krb5 \
	o2digest-reply \
	ocache.krb5 \
	s2digest-reply \
	sdigest-reply \
	server.keytab \
	tempfile


EXTRA_DIST = \
	check-kdc.in \
	check-digest.in \
	krb5.conf.in \
	wait-kdc.sh \
	pki-mapping
