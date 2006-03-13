################################################
# Start MODULE ldb_asq
[MODULE::ldb_asq]
INIT_FUNCTION = ldb_asq_init
SUBSYSTEM = ldb
OBJ_FILES = \
		modules/asq.o
# End MODULE ldb_asq
################################################

################################################
# Start MODULE ldb_sort
[MODULE::ldb_sort]
INIT_FUNCTION = ldb_sort_init
SUBSYSTEM = ldb
OBJ_FILES = \
		modules/sort.o
# End MODULE ldb_sort
################################################

################################################
# Start MODULE ldb_paged_results
[MODULE::ldb_paged_results]
INIT_FUNCTION = ldb_paged_results_init
SUBSYSTEM = ldb
OBJ_FILES = \
		modules/paged_results.o
# End MODULE ldb_paged_results
################################################

################################################
# Start MODULE ldb_operational
[MODULE::ldb_operational]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_operational_init
OBJ_FILES = \
		modules/operational.o
# End MODULE ldb_operational
################################################

################################################
# Start MODULE ldb_objectclass
[MODULE::ldb_objectclass]
INIT_FUNCTION = ldb_objectclass_init
SUBSYSTEM = ldb
OBJ_FILES = \
		modules/objectclass.o
# End MODULE ldb_objectclass
################################################

################################################
# Start MODULE ldb_rdn_name
[MODULE::ldb_rdn_name]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_rdn_name_init
OBJ_FILES = \
		modules/rdn_name.o
# End MODULE ldb_rdn_name
################################################

################################################
# Start MODULE ldb_schema
[MODULE::ldb_schema]
INIT_FUNCTION = ldb_schema_init
SUBSYSTEM = ldb
OBJ_FILES = \
		modules/schema.o
# End MODULE ldb_schema
################################################

################################################
# Start MODULE ldb_ildap
[MODULE::ldb_ildap]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_ildap_init
OBJ_FILES = \
		ldb_ildap/ldb_ildap.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_LDAP
NOPROTO = YES
# End MODULE ldb_ildap
################################################

################################################
# Start MODULE ldb_map
[MODULE::ldb_map]
SUBSYSTEM = ldb
OBJ_FILES = modules/ldb_map.o
# End MODULE ldb_map
################################################

################################################
# Start MODULE ldb_skel
[MODULE::ldb_skel]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_skel_init
OBJ_FILES = modules/skel.o
# End MODULE ldb_skel
################################################

################################################
# Start MODULE ldb_sqlite3
[MODULE::ldb_sqlite3]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_sqlite3_init
OBJ_FILES = \
		ldb_sqlite3/ldb_sqlite3.o
REQUIRED_SUBSYSTEMS = \
		EXT_LIB_SQLITE3
NOPROTO = YES
# End MODULE ldb_sqlite3
################################################

################################################
# Start MODULE ldb_tdb
[MODULE::ldb_tdb]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_tdb_init
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
# End MODULE ldb_tdb
################################################

################################################
# Start SUBSYSTEM ldb
[LIBRARY::ldb]
VERSION = 0.0.1
SO_VERSION = 0.0.1
DESCRIPTION = LDAP-like embedded database library
INIT_FUNCTION_TYPE = int (*) (void)
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
		common/ldb_dn.o \
		common/ldb_controls.o \
		common/qsort.o
REQUIRED_SUBSYSTEMS = \
		LIBREPLACE LIBTALLOC 
NOPROTO = YES
MANPAGE = man/ldb.3
PUBLIC_HEADERS = include/ldb.h
#
# End SUBSYSTEM ldb
################################################

################################################
# Start SUBSYSTEM LDBSAMBA
[SUBSYSTEM::LDBSAMBA]
PRIVATE_PROTO_HEADER = samba/ldif_handlers.h
REQUIRED_SUBSYSTEMS = LIB_SECURITY SAMDB
OBJ_FILES = \
		samba/ldif_handlers.o
# End SUBSYSTEM LDBSAMBA
################################################

################################################
# Start SUBSYSTEM LIBLDB_CMDLINE
[SUBSYSTEM::LIBLDB_CMDLINE]
NOPROTO = YES
OBJ_FILES= \
		tools/cmdline.o
REQUIRED_SUBSYSTEMS = ldb LIBBASIC LIBPOPT POPT_SAMBA POPT_CREDENTIALS
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
MANPAGE = man/oLschema2ldif.1
OBJ_FILES= \
		tools/oLschema2ldif.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB_CMDLINE
# End BINARY oLschema2ldif
################################################
