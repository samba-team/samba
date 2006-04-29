# $Id$

include $(top_srcdir)/Makefile.am.common

noinst_DATA = krb5.conf

check_PROGRAMS = $(TESTS) ap-req

LDADD = ../../lib/krb5/libkrb5.la

TESTS = check-kdc

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/kdc,g'

check-kdc: check-kdc.in Makefile
	$(do_subst) < $(srcdir)/check-kdc.in > check-kdc.tmp
	chmod +x check-kdc.tmp
	mv check-kdc.tmp check-kdc

krb5.conf: krb5.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5.conf.in > krb5.conf.tmp
	mv krb5.conf.tmp krb5.conf


CLEANFILES= \
	$(TESTS) \
	check-kdc.tmp \
	krb5.conf krb5.conf.tmp \
	messages.log \
	current-db* \
	foopassword \
	barpassword \
	tempfile \
	server.keytab \
	client-cache
