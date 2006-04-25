# $Id$

include $(top_srcdir)/Makefile.am.common

noinst_DATA = krb5.conf

TESTS = loaddump-db

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/db,g'

loaddump-db: loaddump-db.in Makefile
	$(do_subst) < $(srcdir)/loaddump-db.in > loaddump-db.tmp
	chmod +x loaddump-db.tmp
	mv loaddump-db.tmp loaddump-db

krb5.conf: krb5.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5.conf.in > krb5.conf.tmp
	mv krb5.conf.tmp krb5.conf


CLEANFILES= \
	$(TESTS) \
	db-dump* \
	current-db* \
	out-text-dump* \
	out-current-* \
	mkey.file* \
	krb5.conf krb5.conf.tmp \
	messages.log
