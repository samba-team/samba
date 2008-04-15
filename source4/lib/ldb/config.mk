################################################
# Start MODULE ldb_asq
[MODULE::ldb_asq]
PRIVATE_DEPENDENCIES = LIBTALLOC
CFLAGS = -Ilib/ldb/include
INIT_FUNCTION = &ldb_asq_module_ops
SUBSYSTEM = LIBLDB

ldb_asq_OBJ_FILES = lib/ldb/modules/asq.o
# End MODULE ldb_asq
################################################

################################################
# Start MODULE ldb_server_sort
[MODULE::ldb_server_sort]
PRIVATE_DEPENDENCIES = LIBTALLOC
CFLAGS = -Ilib/ldb/include
INIT_FUNCTION = &ldb_server_sort_module_ops
SUBSYSTEM = LIBLDB

# End MODULE ldb_sort
################################################
ldb_server_sort_OBJ_FILES = lib/ldb/modules/sort.o

################################################
# Start MODULE ldb_paged_results
[MODULE::ldb_paged_results]
INIT_FUNCTION = &ldb_paged_results_module_ops
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
# End MODULE ldb_paged_results
################################################

ldb_paged_results_OBJ_FILES = lib/ldb/modules/paged_results.o

################################################
# Start MODULE ldb_paged_results
[MODULE::ldb_paged_searches]
INIT_FUNCTION = &ldb_paged_searches_module_ops
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
# End MODULE ldb_paged_results
################################################

ldb_paged_searches_OBJ_FILES = lib/ldb/modules/paged_searches.o

################################################
# Start MODULE ldb_operational
[MODULE::ldb_operational]
SUBSYSTEM = LIBLDB
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = &ldb_operational_module_ops
# End MODULE ldb_operational
################################################

ldb_operational_OBJ_FILES = lib/ldb/modules/operational.o

################################################
# Start MODULE ldb_rdn_name
[MODULE::ldb_rdn_name]
SUBSYSTEM = LIBLDB
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = &ldb_rdn_name_module_ops
# End MODULE ldb_rdn_name
################################################

ldb_rdn_name_OBJ_FILES = lib/ldb/modules/rdn_name.o

################################################
# Start MODULE ldb_map
[SUBSYSTEM::ldb_map]
PRIVATE_DEPENDENCIES = LIBTALLOC
CFLAGS = -Ilib/ldb/include -Ilib/ldb/ldb_map
# End MODULE ldb_map
################################################

ldb_map_OBJ_FILES = $(addprefix lib/ldb/ldb_map/, ldb_map_inbound.o ldb_map_outbound.o ldb_map.o)

################################################
# Start MODULE ldb_skel
[MODULE::ldb_skel]
SUBSYSTEM = LIBLDB
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = &ldb_skel_module_ops
# End MODULE ldb_skel
################################################

ldb_skel_OBJ_FILES = lib/ldb/modules/skel.o

################################################
# Start MODULE ldb_sqlite3
[MODULE::ldb_sqlite3]
SUBSYSTEM = LIBLDB
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC SQLITE3 LIBTALLOC
# End MODULE ldb_sqlite3
################################################

ldb_sqlite3_OBJ_FILES = lib/ldb/ldb_sqlite3/ldb_sqlite3.o

################################################
# Start MODULE ldb_tdb
[MODULE::ldb_tdb]
SUBSYSTEM = LIBLDB
CFLAGS = -Ilib/ldb/include -Ilib/ldb/ldb_tdb
PRIVATE_DEPENDENCIES = \
		LIBTDB LIBTALLOC
# End MODULE ldb_tdb
################################################

ldb_tdb_OBJ_FILES = $(addprefix lib/ldb/ldb_tdb/, ldb_tdb.o ldb_search.o ldb_pack.o ldb_index.o ldb_cache.o ldb_tdb_wrap.o)


################################################
# Start SUBSYSTEM ldb
[LIBRARY::LIBLDB]
CFLAGS = -Ilib/ldb/include
INIT_FUNCTION_TYPE = extern const struct ldb_module_ops
PUBLIC_DEPENDENCIES = \
		LIBTALLOC
PRIVATE_DEPENDENCIES = \
		SOCKET_WRAPPER

PC_FILES += $(ldbdir)/ldb.pc
#
# End SUBSYSTEM ldb
################################################

LIBLDB_VERSION = 0.0.1
LIBLDB_SOVERSION = 0

LIBLDB_OBJ_FILES = $(addprefix lib/ldb/common/, ldb.o ldb_ldif.o ldb_parse.o ldb_msg.o ldb_utf8.o ldb_debug.o ldb_modules.o ldb_match.o ldb_attributes.o attrib_handlers.o ldb_dn.o ldb_controls.o qsort.o)

PUBLIC_HEADERS += $(ldbdir)/include/ldb.h $(ldbdir)/include/ldb_errors.h

MANPAGES += $(ldbdir)/man/ldb.3

################################################
# Start BINARY ldbtest
[BINARY::ldbtest]
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ldbtest
################################################

ldbtest_OBJ_FILES = lib/ldb/tools/ldbtest.o

################################################
# Start BINARY oLschema2ldif
[BINARY::oLschema2ldif]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY oLschema2ldif
################################################


oLschema2ldif_OBJ_FILES = $(addprefix lib/ldb/tools/, convert.o oLschema2ldif.o)

MANPAGES += $(ldbdir)/man/oLschema2ldif.1

################################################
# Start BINARY  ad2oLschema
[BINARY::ad2oLschema]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ad2oLschema
################################################

ad2oLschema_OBJ_FILES = $(addprefix lib/ldb/tools/, convert.o ad2oLschema.o)

MANPAGES += $(ldbdir)/man/ad2oLschema.1

mkinclude tools/config.mk
mkinclude ldb_ildap/config.mk
