# $Id$

AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = kadm5

noinst_PROGRAMS = bits

INCLUDES=-DHOST=\"@CANONICAL_HOST@\"

foodir = $(includedir)
foo_DATA =					\
	admin.h					\
	base64.h				\
	com_err.h				\
	com_right.h				\
	der.h					\
	des.h					\
	getarg.h				\
	gssapi.h				\
	hdb.h					\
	kafs.h					\
	krb5-protos.h				\
	krb5-types.h				\
	krb5.h					\
	md4.h					\
	md5.h					\
	otp.h					\
	parse_time.h				\
	parse_units.h				\
	resolve.h				\
	roken-common.h				\
	sha.h					\
	sl.h					\
	xdbm.h					\
	@EXTRA_HDRS@

EXTRA_DATA = err.h fnmatch.h glob.h

CLEANFILES = $(foo_DATA) asn1.h asn1_err.h hdb_asn1.h hdb_err.h heim_err.h \
	     krb5_err.h roken.h

krb5-types.h: bits
	./bits krb5-types.h

admin.h:
	$(LN_S) $(top_srcdir)/lib/kadm5/admin.h .
base64.h:
	$(LN_S) $(top_srcdir)/lib/roken/base64.h .
cache.h:
	$(LN_S) $(top_srcdir)/lib/krb5/cache.h .
config_file.h:
	$(LN_S) $(top_srcdir)/lib/krb5/config_file.h .
des.h:
	$(LN_S) $(top_srcdir)/lib/des/des.h .
err.h:
	$(LN_S) $(top_srcdir)/lib/roken/err.h .
com_err.h:
	$(LN_S) $(top_srcdir)/lib/com_err/com_err.h .
com_right.h:
	$(LN_S) $(top_srcdir)/lib/com_err/com_right.h .
fnmatch.h:
	$(LN_S) $(top_srcdir)/lib/roken/fnmatch.h .
getarg.h:
	$(LN_S) $(top_srcdir)/lib/roken/getarg.h .
glob.h:
	$(LN_S) $(top_srcdir)/lib/roken/glob.h .
gssapi.h:
	$(LN_S) $(top_srcdir)/lib/gssapi/gssapi.h .
hdb.h:
	$(LN_S) $(top_srcdir)/lib/hdb/hdb.h .
kafs.h:
	$(LN_S) $(top_srcdir)/lib/kafs/kafs.h .
keytab.h:
	$(LN_S) $(top_srcdir)/lib/krb5/keytab.h .
krb5.h:
	$(LN_S) $(top_srcdir)/lib/krb5/krb5.h .
krb5-protos.h:
	$(LN_S) $(top_srcdir)/lib/krb5/krb5-protos.h .
md4.h:
	$(LN_S) $(top_srcdir)/lib/des/md4.h .
md5.h:
	$(LN_S) $(top_srcdir)/lib/des/md5.h .
otp.h:
	$(LN_S) $(top_srcdir)/lib/otp/otp.h .
parse_time.h:
	$(LN_S) $(top_srcdir)/lib/roken/parse_time.h .
parse_units.h:
	$(LN_S) $(top_srcdir)/lib/roken/parse_units.h .
resolve.h:
	$(LN_S) $(top_srcdir)/lib/roken/resolve.h .
roken-common.h:
	$(LN_S) $(top_srcdir)/lib/roken/roken-common.h .
sha.h:
	$(LN_S) $(top_srcdir)/lib/des/sha.h .
sl.h:
	$(LN_S) $(top_srcdir)/lib/sl/sl.h .
store.h:
	$(LN_S) $(top_srcdir)/lib/krb5/store.h .
der.h:
	$(LN_S) $(top_srcdir)/lib/asn1/der.h .
xdbm.h:
	$(LN_S) $(top_srcdir)/lib/roken/xdbm.h .
