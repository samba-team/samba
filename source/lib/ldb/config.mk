################################################
# Start MODULE libldb_operational
[MODULE::libldb_operational]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		modules/operational.o
# End MODULE libldb_operational
################################################

################################################
# Start MODULE libldb_objectclass
[MODULE::libldb_objectclass]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		modules/objectclass.o
# End MODULE libldb_objectclass
################################################

################################################
# Start MODULE libldb_rdn_name
[MODULE::libldb_rdn_name]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		modules/rdn_name.o
# End MODULE libldb_rdn_name
################################################

################################################
# Start MODULE libldb_schema
[MODULE::libldb_schema]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		modules/schema.o
# End MODULE libldb_schema
################################################

################################################
# Start MODULE libldb_ildap
[MODULE::libldb_ildap]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		ldb_ildap/ldb_ildap.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_LDAP
NOPROTO = YES
# End MODULE libldb_ildap
################################################

################################################
# Start MODULE libldb_map
[MODULE::libldb_map]
SUBSYSTEM = LIBLDB
OBJ_FILES = modules/ldb_map.o
# End MODULE libldb_map
################################################

################################################
# Start MODULE libldb_sqlite3
[MODULE::libldb_sqlite3]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		ldb_sqlite3/ldb_sqlite3.o
REQUIRED_SUBSYSTEMS = \
		EXT_LIB_SQLITE3
NOPROTO = YES
# End MODULE libldb_sqlite3
################################################

################################################
# Start MODULE libldb_tdb
[MODULE::libldb_tdb]
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		ldb_tdb/ldb_tdb.o \
		ldb_tdb/ldb_search.o \
		ldb_tdb/ldb_pack.o \
		ldb_tdb/ldb_index.o \
		ldb_tdb/ldb_cache.o \
		ldb_tdb/ldb_tdb_wrap.o
REQUIRED_SUBSYSTEMS = \
		LIBTDB
NOPROTO = YES
# End MODULE libldb_tdb
################################################

################################################
# Start SUBSYSTEM LIBLDB
[LIBRARY::LIBLDB]
MAJOR_VERSION = 0
MINOR_VERSION = 0
DESCRIPTION = LDAP-like embedded database library
RELEASE_VERSION = 1
OBJ_FILES = \
		common/ldb.o \
		common/ldb_ldif.o \
		common/ldb_parse.o \
		common/ldb_msg.o \
		common/ldb_utf8.o \
		common/ldb_debug.o \
		common/ldb_modules.o \
		common/ldb_match.o \
		common/ldb_attributes.o \
		common/attrib_handlers.o \
		common/ldb_dn.o
REQUIRED_SUBSYSTEMS = \
		LIBREPLACE LIBTALLOC LDBSAMBA
NOPROTO = YES
MANPAGE = man/ldb.3
PUBLIC_HEADERS = include/ldb.h
#
# End SUBSYSTEM LIBLDB
################################################

################################################
# Start SUBSYSTEM LDBSAMBA
[SUBSYSTEM::LDBSAMBA]
OBJ_FILES = \
		samba/ldif_handlers.o
# End SUBSYSTEM LDBSAMBA
################################################

################################################
# Start SUBSYSTEM LIBLDB_CMDLINE
[SUBSYSTEM::LIBLDB_CMDLINE]
OBJ_FILES= \
		tools/cmdline.o
REQUIRED_SUBSYSTEMS = LIBLDB LIBBASIC LIBPOPT POPT_SAMBA POPT_CREDENTIALS
# End SUBSYSTEM LIBLDB_CMDLINE
################################################

################################################
# Start BINARY ldbadd
[BINARY::ldbadd]
INSTALLDIR = BINDIR
OBJ_FILES = \
		tools/ldbadd.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
MANPAGE = man/ldbadd.1
# End BINARY ldbadd
################################################

################################################
# Start BINARY ldbdel
[BINARY::ldbdel]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/ldbdel.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
MANPAGE = man/ldbdel.1
# End BINARY ldbdel
################################################

################################################
# Start BINARY ldbmodify
[BINARY::ldbmodify]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/ldbmodify.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
MANPAGE = man/ldbmodify.1
# End BINARY ldbmodify
################################################

################################################
# Start BINARY ldbsearch
[BINARY::ldbsearch]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/ldbsearch.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE 
MANPAGE = man/ldbsearch.1
# End BINARY ldbsearch
################################################

################################################
# Start BINARY ldbedit
[BINARY::ldbedit]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/ldbedit.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
MANPAGE = man/ldbedit.1
# End BINARY ldbedit
################################################

################################################
# Start BINARY ldbrename
[BINARY::ldbrename]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/ldbrename.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
MANPAGE = man/ldbrename.1
# End BINARY ldbrename
################################################

################################################
# Start BINARY ldbtest
[BINARY::ldbtest]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/ldbtest.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
# End BINARY ldbtest
################################################

################################################
# Start BINARY oLschema2ldif
[BINARY::oLschema2ldif]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/oLschema2ldif.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
# End BINARY oLschema2ldif
################################################
