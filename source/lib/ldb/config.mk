################################################
# Start MODULE libldb_timestamps
[MODULE::libldb_timestamps]
SUBSYSTEM = LIBLDB
INIT_OBJ_FILES = \
		lib/ldb/modules/timestamps.o
# End MODULE libldb_timestamps
################################################

################################################
# Start MODULE libldb_schema
[MODULE::libldb_schema]
SUBSYSTEM = LIBLDB
INIT_OBJ_FILES = \
		lib/ldb/modules/schema.o
# End MODULE libldb_schema
################################################

################################################
# Start MODULE libldb_ildap
[MODULE::libldb_ildap]
SUBSYSTEM = LIBLDB
INIT_OBJ_FILES = \
		lib/ldb/ldb_ildap/ldb_ildap.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_LDAP
NOPROTO = YES
# End MODULE libldb_ildap
################################################

################################################
# Start MODULE libldb_sqlite3
[MODULE::libldb_sqlite3]
SUBSYSTEM = LIBLDB
INIT_OBJ_FILES = \
		lib/ldb/ldb_sqlite3/ldb_sqlite3.o
REQUIRED_SUBSYSTEMS = \
		EXT_LIB_SQLITE3
NOPROTO = YES
# End MODULE libldb_sqlite3
################################################

################################################
# Start MODULE libldb_tdb
[MODULE::libldb_tdb]
SUBSYSTEM = LIBLDB
INIT_OBJ_FILES = \
		lib/ldb/ldb_tdb/ldb_tdb.o
ADD_OBJ_FILES = \
		lib/ldb/ldb_tdb/ldb_search.o \
		lib/ldb/ldb_tdb/ldb_pack.o \
		lib/ldb/ldb_tdb/ldb_index.o \
		lib/ldb/ldb_tdb/ldb_match.o \
		lib/ldb/ldb_tdb/ldb_cache.o
REQUIRED_SUBSYSTEMS = \
		LIBTDB
NOPROTO = YES
# End MODULE libldb_tdb
################################################

################################################
# Start SUBSYSTEM LIBLDB
[SUBSYSTEM::LIBLDB]
INIT_OBJ_FILES = \
		lib/ldb/common/ldb.o
ADD_OBJ_FILES = \
		lib/ldb/common/ldb_ldif.o \
		lib/ldb/common/ldb_parse.o \
		lib/ldb/common/ldb_msg.o \
		lib/ldb/common/util.o \
		lib/ldb/common/ldb_utf8.o \
		lib/ldb/common/ldb_debug.o \
		lib/ldb/common/ldb_modules.o \
		lib/ldb/common/ldb_explode_dn.o
REQUIRED_SUBSYSTEMS = \
		LIBREPLACE LIBTALLOC
NOPROTO = YES
#
# End SUBSYSTEM LIBLDB
################################################

################################################
# Start LIBRARY LIBLDB
[LIBRARY::libldb]
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
REQUIRED_SUBSYSTEMS = \
		LIBLDB
#
# End LIBRARY LIBLDB
################################################

################################################
# Start SUBSYSTEM LIBLDB_CMDLINE
[SUBSYSTEM::LIBLDB_CMDLINE]
OBJ_FILES= \
		lib/ldb/tools/cmdline.o
REQUIRED_SUBSYSTEMS = LIBLDB LIBCMDLINE
# End SUBSYSTEM LIBLDB_CMDLINE
################################################

################################################
# Start BINARY ldbadd
[BINARY::ldbadd]
OBJ_FILES= \
		lib/ldb/tools/ldbadd.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
# End BINARY ldbadd
################################################

################################################
# Start BINARY ldbdel
[BINARY::ldbdel]
OBJ_FILES= \
		lib/ldb/tools/ldbdel.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
# End BINARY ldbdel
################################################

################################################
# Start BINARY ldbmodify
[BINARY::ldbmodify]
OBJ_FILES= \
		lib/ldb/tools/ldbmodify.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
# End BINARY ldbmodify
################################################

################################################
# Start BINARY ldbsearch
[BINARY::ldbsearch]
OBJ_FILES= \
		lib/ldb/tools/ldbsearch.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE 
# End BINARY ldbsearch
################################################

################################################
# Start BINARY ldbedit
[BINARY::ldbedit]
OBJ_FILES= \
		lib/ldb/tools/ldbedit.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
# End BINARY ldbedit
################################################

################################################
# Start BINARY ldbrename
[BINARY::ldbrename]
OBJ_FILES= \
		lib/ldb/tools/ldbrename.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
# End BINARY ldbrename
################################################

################################################
# Start BINARY ldbtest
[BINARY::ldbtest]
OBJ_FILES= \
		lib/ldb/tools/ldbtest.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
# End BINARY ldbtest
################################################
