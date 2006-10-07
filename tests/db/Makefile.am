# $Id$

include $(top_srcdir)/Makefile.am.common

noinst_DATA = krb5.conf

check_SCRIPTS = loaddump-db add-modify-delete

TESTS = loaddump-db add-modify-delete

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/db,g'

loaddump-db: loaddump-db.in Makefile
	$(do_subst) < $(srcdir)/loaddump-db.in > loaddump-db.tmp
	chmod +x loaddump-db.tmp
	mv loaddump-db.tmp loaddump-db

add-modify-delete: add-modify-delete.in Makefile
	$(do_subst) < $(srcdir)/add-modify-delete.in > add-modify-delete.tmp
	chmod +x add-modify-delete.tmp
	mv add-modify-delete.tmp add-modify-delete

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
	tempfile \
	messages.log
