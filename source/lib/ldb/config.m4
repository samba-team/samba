
SMB_MODULE(libldb_tdb,LIBLDB,STATIC,
		[lib/ldb/ldb_tdb/ldb_tdb.o \
		lib/ldb/ldb_tdb/ldb_pack.o \
		lib/ldb/ldb_tdb/ldb_search.o \
		lib/ldb/ldb_tdb/ldb_index.o \
		lib/ldb/ldb_tdb/ldb_match.o])

if test x"$with_ldap_support" = x"yes"; then
	SMB_MODULE_DEFAULT(libldb_ldap,STATIC)
fi
SMB_MODULE(libldb_ldap,LIBLDB,NOT,[lib/ldb/ldb_ldap/ldb_ldap.o])

SMB_SUBSYSTEM(LIBLDB,[lib/ldb/common/ldb.o],
		[lib/ldb/common/ldb_ldif.o \
		lib/ldb/common/ldb_parse.o \
		lib/ldb/common/util.o])
