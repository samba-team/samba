SMB_SUBSYSTEM(LIBLDB,[lib/ldb/common/ldb.o],
		[lib/ldb/ldb_tdb/ldb_pack.o \
		lib/ldb/common/ldb_ldif.o    lib/ldb/ldb_tdb/ldb_search.o \
		lib/ldb/common/ldb_parse.o   lib/ldb/ldb_tdb/ldb_tdb.o \
		lib/ldb/common/util.o        lib/ldb/ldb_ldap/ldb_ldap.o \  
		lib/ldb/ldb_tdb/ldb_index.o  lib/ldb/ldb_tdb/ldb_match.o],
		lib/ldb/include/ldb.h)
