if test x"$with_ldap_support" = x"yes"; then
    SMB_MODULE_DEFAULT(libldb_ldap,STATIC)
fi

SMB_MODULE(libldb_ldap,LIBLDB,NOT,[lib/ldb/ldb_ldap/ldb_ldap.o])

SMB_MODULE(libldb_tdb,LIBLDB,STATIC,
		[lib/ldb/ldb_tdb/ldb_search.o
		lib/ldb/ldb_tdb/ldb_tdb.o
		lib/ldb/ldb_tdb/ldb_pack.o
		lib/ldb/ldb_tdb/ldb_index.o
		lib/ldb/ldb_tdb/ldb_match.o])

SMB_SUBSYSTEM(LIBLDB,[lib/ldb/common/ldb.o],
		[lib/ldb/common/ldb_ldif.o
		lib/ldb/common/ldb_parse.o
		lib/ldb/common/ldb_msg.o
		lib/ldb/common/util.o])

SMB_BINARY(ldbadd,[LDB],[BIN],lib/ldb/tools/ldbadd.o,
		[],
		[LIBBASIC LIBSMB CONFIG LIBCMDLINE LIBLDB])

SMB_BINARY(ldbdel,[LDB],[BIN],lib/ldb/tools/ldbdel.o,
		[],
		[LIBBASIC LIBSMB CONFIG LIBLDB])

SMB_BINARY(ldbmodify,[LDB],[BIN],lib/ldb/tools/ldbmodify.o,
		[],
		[LIBBASIC LIBSMB CONFIG LIBLDB])

SMB_BINARY(ldbsearch,[LDB],[BIN],lib/ldb/tools/ldbsearch.o,
		[],
		[LIBBASIC LIBSMB CONFIG LIBLDB])

SMB_BINARY(ldbedit,[LDB],[BIN],lib/ldb/tools/ldbedit.o,
		[],
		[LIBBASIC LIBSMB CONFIG LIBLDB])
