# $Id$

include $(top_srcdir)/Makefile.am.common

noinst_DATA = krb5.conf krb5-pkinit.conf krb5-pkinit-win.conf

check_PROGRAMS = ap-req
check_SCRIPTS = $(SCRIPT_TESTS) 

SCRIPT_TESTS = \
	check-digest \
	check-kadmin \
	check-kdc \
	check-pkinit \
	check-referral \
	check-uu

TESTS = $(SCRIPT_TESTS)

port = 49188
admport = 49189

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]port[@],$(port),g' \
	-e 's,[@]admport[@],$(admport),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/kdc,g' \
	-e 's,[@]EGREP[@],$(EGREP),g' 

LDADD = ../../lib/krb5/libkrb5.la $(LIB_roken)

check-kdc: check-kdc.in Makefile
	$(do_subst) < $(srcdir)/check-kdc.in > check-kdc.tmp
	chmod +x check-kdc.tmp
	mv check-kdc.tmp check-kdc

check-kadmin: check-kadmin.in Makefile
	$(do_subst) < $(srcdir)/check-kadmin.in > check-kadmin.tmp
	chmod +x check-kadmin.tmp
	mv check-kadmin.tmp check-kadmin

check-uu: check-uu.in Makefile
	$(do_subst) < $(srcdir)/check-uu.in > check-uu.tmp
	chmod +x check-uu.tmp
	mv check-uu.tmp check-uu

check-pkinit: check-pkinit.in Makefile krb5-pkinit.conf
	$(do_subst) < $(srcdir)/check-pkinit.in > check-pkinit.tmp
	chmod +x check-pkinit.tmp
	mv check-pkinit.tmp check-pkinit

check-digest: check-digest.in Makefile
	$(do_subst) < $(srcdir)/check-digest.in > check-digest.tmp
	chmod +x check-digest.tmp
	mv check-digest.tmp check-digest

check-referral: check-referral.in Makefile
	$(do_subst) < $(srcdir)/check-referral.in > check-referral.tmp
	chmod +x check-referral.tmp
	mv check-referral.tmp check-referral

krb5.conf: krb5.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5.conf.in > krb5.conf.tmp
	mv krb5.conf.tmp krb5.conf

krb5-pkinit.conf: krb5-pkinit.conf.in Makefile
	$(do_subst) -e 's,[@]w2k[@],no,g' < $(srcdir)/krb5-pkinit.conf.in > krb5-pkinit.conf.tmp
	mv krb5-pkinit.conf.tmp krb5-pkinit.conf

krb5-pkinit-win.conf: krb5-pkinit.conf.in Makefile
	$(do_subst) -e 's,[@]w2k[@],yes,g' < $(srcdir)/krb5-pkinit.conf.in > krb5-pkinit-win.conf.tmp
	mv krb5-pkinit-win.conf.tmp krb5-pkinit-win.conf

CLEANFILES= \
	$(TESTS) \
	barpassword \
	cache.krb5 \
	cdigest-reply \
	*.tmp \
	client-cache \
	current-db* \
	digest-reply \
	foopassword \
	krb5.conf \
	krb5-pkinit.conf \
	krb5-pkinit-win.conf \
	messages.log \
	o2cache.krb5 \
	o2digest-reply \
	ocache.krb5 \
	s2digest-reply \
	sdigest-init \
	sdigest-reply \
	server.keytab \
	req-pkinit.der \
	req-pkinit2.der \
	req-kdc.der \
	pkinit.crt \
	pkinit2.crt \
	pkinit3.crt \
	kdc.crt \
	ca.crt \
	uuserver.log \
	tempfile


EXTRA_DIST = \
	check-kadmin.in \
	check-kdc.in \
	check-referral.in \
	check-uu.in \
	check-pkinit.in \
	check-digest.in \
	heimdal.acl \
	krb5.conf.in \
	krb5-pkinit.conf.in \
	wait-kdc.sh \
	pki-mapping \
	ntlm-user-file.txt \
	uuserver.txt
