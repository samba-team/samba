################################################
# Start MODULE libldb_ldap
MODULE_libldb_ldap_INIT_OBJ_FILES = \
		lib/ldb/ldb_ldap/ldb_ldap.o
# End MODULE libldb_tdb
################################################

################################################
# Start MODULE libldb_tdb
MODULE_libldb_tdb_INIT_OBJ_FILES = \
		lib/ldb/ldb_tdb/ldb_tdb.o
MODULE_libldb_tdb_ADD_OBJ_FILES = \
		lib/ldb/ldb_tdb/ldb_search.o \
		lib/ldb/ldb_tdb/ldb_pack.o \
		lib/ldb/ldb_tdb/ldb_index.o \
		lib/ldb/ldb_tdb/ldb_match.o
# End MODULE libldb_tdb
################################################

################################################
# Start SUBSYSTEM LIBLDB
SUBSYSTEM_LIBLDB_INIT_OBJ_FILES = \
		lib/ldb/common/ldb.o
SUBSYSTEM_LIBLDB_ADD_OBJ_FILES = \
		lib/ldb/common/ldb_ldif.o \
		lib/ldb/common/ldb_parse.o \
		lib/ldb/common/ldb_msg.o \
		lib/ldb/common/util.o
# End SUBSYSTEM LIBLDB
################################################

################################################
# Start BINARY ldbadd
BINARY_ldbadd_OBJ_FILES= \
		lib/ldb/tools/ldbadd.o
BINARY_ldbadd_REQUIRED_SUBSYSTEMS = \
		LIBBASIC LIBSMB CONFIG LIBCMDLINE LIBLDB
# End BINARY ldbadd
################################################

################################################
# Start BINARY ldbdel
BINARY_ldbdel_OBJ_FILES= \
		lib/ldb/tools/ldbdel.o
BINARY_ldbdel_REQUIRED_SUBSYSTEMS = \
		LIBBASIC LIBSMB CONFIG LIBCMDLINE LIBLDB
# End BINARY ldbdel
################################################

################################################
# Start BINARY ldbmodify
BINARY_ldbmodify_OBJ_FILES= \
		lib/ldb/tools/ldbmodify.o
BINARY_ldbmodify_REQUIRED_SUBSYSTEMS = \
		LIBBASIC LIBSMB CONFIG LIBCMDLINE LIBLDB
# End BINARY ldbmodify
################################################

################################################
# Start BINARY ldbsearch
BINARY_ldbsearch_OBJ_FILES= \
		lib/ldb/tools/ldbsearch.o
BINARY_ldbsearch_REQUIRED_SUBSYSTEMS = \
		LIBBASIC LIBSMB CONFIG LIBCMDLINE LIBLDB
# End BINARY ldbsearch
################################################

################################################
# Start BINARY ldbedit
BINARY_ldbedit_OBJ_FILES= \
		lib/ldb/tools/ldbedit.o
BINARY_ldbedit_REQUIRED_SUBSYSTEMS = \
		LIBBASIC LIBSMB CONFIG LIBCMDLINE LIBLDB
# End BINARY ldbedit
################################################
