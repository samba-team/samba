# $Id$

AUTOMAKE_OPTIONS = foreign no-dependencies

noinst_PROGRAMS = bits

INCLUDES=-DHOST=\"@CANONICAL_HOST@\"

foodir = $(includedir)
foo_DATA = \
	bits.h cache.h config_file.h des.h error.h \
	getarg.h gssapi.h hdb.h kafs.h \
	keytab.h krb5.h md4.h md5.h otp.h parse_time.h \
	parse_units.h roken.h sha.h sl.h store.h @EXTRA_HDRS@


EXTRA_DATA = err.h

CLEANFILES = $(foo_DATA)

bits.h: bits
	./bits bits.h

cache.h:
	$(LN_S) $(top_srcdir)/lib/krb5/cache.h .
config_file.h:
	$(LN_S) $(top_srcdir)/lib/krb5/config_file.h .
des.h:
	$(LN_S) $(top_srcdir)/lib/des/des.h .
err.h:
	$(LN_S) $(top_srcdir)/lib/roken/err.h .
error.h:
	$(LN_S) $(top_srcdir)/lib/error/error.h .
getarg.h:
	$(LN_S) $(top_srcdir)/lib/roken/getarg.h .
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
roken.h:
	$(LN_S) $(top_srcdir)/lib/roken/roken.h .
sha.h:
	$(LN_S) $(top_srcdir)/lib/des/sha.h .
sl.h:
	$(LN_S) $(top_srcdir)/lib/sl/sl.h .
store.h:
	$(LN_S) $(top_srcdir)/lib/krb5/store.h .
