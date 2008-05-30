################################################
# Start MODULE ldb_asq
[MODULE::ldb_asq]
PRIVATE_DEPENDENCIES = LIBTALLOC
CFLAGS = -I$(ldbdir)/include
INIT_FUNCTION = LDB_MODULE(asq)
SUBSYSTEM = LIBLDB

ldb_asq_OBJ_FILES = $(ldbdir)/modules/asq.o
# End MODULE ldb_asq
################################################

################################################
# Start MODULE ldb_server_sort
[MODULE::ldb_server_sort]
PRIVATE_DEPENDENCIES = LIBTALLOC
CFLAGS = -I$(ldbdir)/include
INIT_FUNCTION = LDB_MODULE(server_sort)
SUBSYSTEM = LIBLDB

# End MODULE ldb_sort
################################################
ldb_server_sort_OBJ_FILES = $(ldbdir)/modules/sort.o

################################################
# Start MODULE ldb_paged_results
[MODULE::ldb_paged_results]
INIT_FUNCTION = LDB_MODULE(paged_results)
CFLAGS = -I$(ldbdir)/include
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
# End MODULE ldb_paged_results
################################################

ldb_paged_results_OBJ_FILES = $(ldbdir)/modules/paged_results.o

################################################
# Start MODULE ldb_paged_results
[MODULE::ldb_paged_searches]
INIT_FUNCTION = LDB_MODULE(paged_searches)
CFLAGS = -I$(ldbdir)/include
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
# End MODULE ldb_paged_results
################################################

ldb_paged_searches_OBJ_FILES = $(ldbdir)/modules/paged_searches.o

################################################
# Start MODULE ldb_operational
[MODULE::ldb_operational]
SUBSYSTEM = LIBLDB
CFLAGS = -I$(ldbdir)/include
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = LDB_MODULE(operational)
# End MODULE ldb_operational
################################################

ldb_operational_OBJ_FILES = $(ldbdir)/modules/operational.o

################################################
# Start MODULE ldb_rdn_name
[MODULE::ldb_rdn_name]
SUBSYSTEM = LIBLDB
CFLAGS = -I$(ldbdir)/include
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = LDB_MODULE(rdn_name)
# End MODULE ldb_rdn_name
################################################

ldb_rdn_name_OBJ_FILES = $(ldbdir)/modules/rdn_name.o

ldb_map_OBJ_FILES = $(addprefix $(ldbdir)/ldb_map/, ldb_map_inbound.o ldb_map_outbound.o ldb_map.o)

$(ldb_map_OBJ_FILES): CFLAGS+=-I$(ldbdir)/ldb_map

################################################
# Start MODULE ldb_skel
[MODULE::ldb_skel]
SUBSYSTEM = LIBLDB
CFLAGS = -I$(ldbdir)/include
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = LDB_MODULE(skel)
# End MODULE ldb_skel
################################################

ldb_skel_OBJ_FILES = $(ldbdir)/modules/skel.o

################################################
# Start MODULE ldb_sqlite3
[MODULE::ldb_sqlite3]
SUBSYSTEM = LIBLDB
CFLAGS = -I$(ldbdir)/include
PRIVATE_DEPENDENCIES = LIBTALLOC SQLITE3 LIBTALLOC
# End MODULE ldb_sqlite3
################################################

ldb_sqlite3_OBJ_FILES = $(ldbdir)/ldb_sqlite3/ldb_sqlite3.o

################################################
# Start MODULE ldb_tdb
[MODULE::ldb_tdb]
SUBSYSTEM = LIBLDB
CFLAGS = -I$(ldbdir)/include -I$(ldbdir)/ldb_tdb
PRIVATE_DEPENDENCIES = \
		LIBTDB LIBTALLOC
# End MODULE ldb_tdb
################################################

ldb_tdb_OBJ_FILES = $(addprefix $(ldbdir)/ldb_tdb/, ldb_tdb.o ldb_search.o ldb_pack.o ldb_index.o ldb_cache.o ldb_tdb_wrap.o)


################################################
# Start SUBSYSTEM ldb
[LIBRARY::LIBLDB]
CFLAGS = -I$(ldbdir)/include
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

LIBLDB_OBJ_FILES = $(addprefix $(ldbdir)/common/, ldb.o ldb_ldif.o ldb_parse.o ldb_msg.o ldb_utf8.o ldb_debug.o ldb_modules.o ldb_match.o ldb_attributes.o attrib_handlers.o ldb_dn.o ldb_controls.o qsort.o) $(ldb_map_OBJ_FILES)

$(LIBLDB_OBJ_FILES): CFLAGS+=-I$(ldbdir)/include

PUBLIC_HEADERS += $(ldbdir)/include/ldb.h $(ldbdir)/include/ldb_errors.h

MANPAGES += $(ldbdir)/man/ldb.3

################################################
# Start BINARY ldbtest
[BINARY::ldbtest]
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ldbtest
################################################

ldbtest_OBJ_FILES = $(ldbdir)/tools/ldbtest.o

################################################
# Start BINARY oLschema2ldif
[BINARY::oLschema2ldif]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY oLschema2ldif
################################################


oLschema2ldif_OBJ_FILES = $(addprefix $(ldbdir)/tools/, convert.o oLschema2ldif.o)

MANPAGES += $(ldbdir)/man/oLschema2ldif.1

################################################
# Start BINARY  ad2oLschema
[BINARY::ad2oLschema]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ad2oLschema
################################################

ad2oLschema_OBJ_FILES = $(addprefix $(ldbdir)/tools/, convert.o ad2oLschema.o)

MANPAGES += $(ldbdir)/man/ad2oLschema.1

mkinclude tools/config.mk
mkinclude ldb_ildap/config.mk
