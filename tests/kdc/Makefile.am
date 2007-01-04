# $Id$

include $(top_srcdir)/Makefile.am.common

noinst_DATA = krb5.conf krb5-pkinit.conf

check_PROGRAMS = ap-req
check_SCRIPTS = $(SCRIPT_TESTS) 

SCRIPT_TESTS = check-kdc check-digest check-pkinit
TESTS = $(SCRIPT_TESTS)

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/kdc,g' \
	-e 's,[@]EGREP[@],$(EGREP),g' 

LDADD = ../../lib/krb5/libkrb5.la $(LIB_roken)

check-kdc: check-kdc.in Makefile
	$(do_subst) < $(srcdir)/check-kdc.in > check-kdc.tmp
	chmod +x check-kdc.tmp
	mv check-kdc.tmp check-kdc

check-pkinit: check-pkinit.in Makefile krb5-pkinit.conf
	$(do_subst) < $(srcdir)/check-pkinit.in > check-pkinit.tmp
	chmod +x check-pkinit.tmp
	mv check-pkinit.tmp check-pkinit

check-digest: check-digest.in Makefile
	$(do_subst) < $(srcdir)/check-digest.in > check-digest.tmp
	chmod +x check-digest.tmp
	mv check-digest.tmp check-digest

krb5.conf: krb5.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5.conf.in > krb5.conf.tmp
	mv krb5.conf.tmp krb5.conf

krb5-pkinit.conf: krb5-pkinit.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5-pkinit.conf.in > krb5-pkinit.conf.tmp
	mv krb5-pkinit.conf.tmp krb5-pkinit.conf



CLEANFILES= \
	$(TESTS) \
	barpassword \
	cache.krb5 \
	cdigest-reply \
	check-digest.tmp \
	check-kdc.tmp \
	check-pkinit.tmp \
	client-cache \
	current-db* \
	digest-reply \
	foopassword \
	krb5.conf krb5.conf.tmp \
	krb5-pkinit.conf krb5-pkinit.conf.tmp \
	messages.log \
	o2cache.krb5 \
	o2digest-reply \
	ocache.krb5 \
	s2digest-reply \
	sdigest-reply \
	server.keytab \
	req-pkinit.der \
	req-kdc.der \
	pkinit.crt \
	kdc.crt \
	ca.crt \
	tempfile


EXTRA_DIST = \
	check-kdc.in \
	check-pkinit.in \
	check-digest.in \
	krb5.conf.in \
	krb5-pkinit.conf.in \
	wait-kdc.sh \
	pki-mapping
