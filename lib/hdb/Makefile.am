# $Id$

include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += -I../asn1 -I$(srcdir)/../asn1 $(INCLUDE_des)

BUILT_SOURCES = \
	$(gen_files_hdb:.x=.c)	\
	hdb_err.c \
	hdb_err.h

gen_files_hdb = \
	asn1_Salt.x \
	asn1_Key.x \
	asn1_Event.x \
	asn1_HDBFlags.x \
	asn1_GENERATION.x \
	asn1_HDB_Ext_PKINIT_acl.x \
	asn1_HDB_Ext_PKINIT_hash.x \
	asn1_HDB_Ext_Constrained_delegation_acl.x \
	asn1_HDB_Ext_Lan_Manager_OWF.x \
	asn1_HDB_Ext_Password.x \
	asn1_HDB_Ext_Aliases.x \
	asn1_HDB_extension.x \
	asn1_HDB_extensions.x \
	asn1_hdb_entry.x

CLEANFILES = $(BUILT_SOURCES) $(gen_files_hdb) hdb_asn1.h hdb_asn1_files

LDADD = libhdb.la \
	$(LIB_openldap) \
	../krb5/libkrb5.la \
	../asn1/libasn1.la \
	$(LIB_des) \
	$(LIB_roken) \
	$(LIB_ldopen)

if OPENLDAP_MODULE

ldap_so = hdb_ldap.la
hdb_ldap_la_SOURCES = hdb-ldap.c
hdb_ldap_la_LDFLAGS = -module

else

ldap = hdb-ldap.c

endif


lib_LTLIBRARIES = libhdb.la $(ldap_so)
libhdb_la_LDFLAGS = -version-info 9:0:0

dist_libhdb_la_SOURCES =			\
	common.c				\
	db.c					\
	db3.c					\
	ext.c					\
	$(ldap)					\
	hdb.c					\
	hdb_locl.h				\
	hdb-private.h				\
	keys.c					\
	keytab.c				\
	mkey.c					\
	ndbm.c					\
	print.c

nodist_libhdb_la_SOURCES = $(BUILT_SOURCES)

AM_CPPFLAGS += $(INCLUDE_openldap)

include_HEADERS = hdb.h hdb-protos.h
nodist_include_HEADERS =  hdb_err.h hdb_asn1.h

libhdb_la_LIBADD = \
	$(LIB_com_err) \
	../krb5/libkrb5.la \
	../asn1/libasn1.la \
	../roken/libroken.la \
	$(LIB_openldap) \
	$(LIB_dlopen) \
	$(DBLIB) \
	$(LIB_NDBM)

$(libhdb_la_OBJECTS): $(srcdir)/hdb-protos.h $(srcdir)/hdb-private.h

CHECK_SYMBOLS = -lib hdb -asn1compile -com_err \
	hdb_ _hdb HDBFlags2int initialize_hdb_error_table

$(srcdir)/hdb-protos.h:
	cd $(srcdir); perl ../../cf/make-proto.pl -q -P comment -o hdb-protos.h $(dist_libhdb_la_SOURCES) || rm -f hdb-protos.h

$(srcdir)/hdb-private.h:
	cd $(srcdir); perl ../../cf/make-proto.pl -q -P comment -p hdb-private.h $(dist_libhdb_la_SOURCES) || rm -f hdb-private.h

$(gen_files_hdb) hdb_asn1.h: hdb_asn1_files

hdb_asn1_files: ../asn1/asn1_compile$(EXEEXT) $(srcdir)/hdb.asn1
	../asn1/asn1_compile$(EXEEXT) $(srcdir)/hdb.asn1 hdb_asn1

$(libhdb_la_OBJECTS): hdb_asn1.h hdb_err.h

# to help stupid solaris make

hdb_err.h: hdb_err.et

EXTRA_DIST = hdb.asn1 hdb_err.et
