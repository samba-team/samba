################################################
# Start MODULE ldb_objectguid
[MODULE::ldb_objectguid]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = LIBTALLOC LIBNDR NDR_MISC
INIT_FUNCTION = objectguid_module_init
OBJ_FILES = \
		objectguid.o
# End MODULE ldb_objectguid
################################################

################################################
# Start MODULE ldb_repl_mata_data
[MODULE::ldb_repl_meta_data]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC LIBNDR NDR_MISC NDR_DRSUAPI NDR_DRSBLOBS
INIT_FUNCTION = repl_meta_data_module_init
OBJ_FILES = \
		repl_meta_data.o
# End MODULE ldb_repl_meta_data
################################################

################################################
# Start MODULE ldb_dsdb_cache
[MODULE::ldb_dsdb_cache]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = dsdb_cache_module_init
OBJ_FILES = \
		dsdb_cache.o
# End MODULE ldb_dsdb_cache
################################################

################################################
# Start MODULE ldb_schema_fsmo
[MODULE::ldb_schema_fsmo]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = schema_fsmo_module_init
OBJ_FILES = \
		schema_fsmo.o
# End MODULE ldb_schema_fsmo
################################################

################################################
# Start MODULE ldb_naming_fsmo
[MODULE::ldb_naming_fsmo]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = naming_fsmo_module_init
OBJ_FILES = \
		naming_fsmo.o
# End MODULE ldb_naming_fsmo
################################################

################################################
# Start MODULE ldb_pdc_fsmo
[MODULE::ldb_pdc_fsmo]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = pdc_fsmo_module_init
OBJ_FILES = \
		pdc_fsmo.o
# End MODULE ldb_pdc_fsmo
################################################

################################################
# Start MODULE ldb_samldb
[MODULE::ldb_samldb]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = samldb_module_init
OBJ_FILES = \
		samldb.o
#
# End MODULE ldb_samldb
################################################

################################################
# Start MODULE ldb_samba3sam
[MODULE::ldb_samba3sam]
SUBSYSTEM = LIBLDB
INIT_FUNCTION = ldb_samba3sam_module_init
PRIVATE_DEPENDENCIES = LIBTALLOC ldb_map SMBPASSWD
OBJ_FILES = \
		samba3sam.o
#
# End MODULE ldb_samldb
################################################

################################################
# Start MODULE ldb_entryUUID
[MODULE::ldb_entryUUID]
SUBSYSTEM = LIBLDB
INIT_FUNCTION = ldb_entryUUID_module_init
PRIVATE_DEPENDENCIES = LIBTALLOC
ENABLE = YES
OBJ_FILES = \
		entryUUID.o
#
# End MODULE ldb_entryUUID
################################################

# ################################################
# # Start MODULE ldb_proxy
# [MODULE::ldb_proxy]
# SUBSYSTEM = LIBLDB
# INIT_FUNCTION = proxy_module_init
# OBJ_FILES = \
# 		proxy.o
# 
# # End MODULE ldb_proxy
# ################################################


################################################
# Start MODULE ldb_rootdse
[MODULE::ldb_rootdse]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = rootdse_module_init
OBJ_FILES = \
		rootdse.o
#
# End MODULE ldb_rootdse
################################################

################################################
# Start MODULE ldb_password_hash
[MODULE::ldb_password_hash]
SUBSYSTEM = LIBLDB
INIT_FUNCTION = password_hash_module_init
OBJ_FILES = password_hash.o
PRIVATE_DEPENDENCIES = HEIMDAL_HDB_KEYS LIBTALLOC HEIMDAL_KRB5
#
# End MODULE ldb_password_hash
################################################

################################################
# Start MODULE ldb_local_password
[MODULE::ldb_local_password]
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
INIT_FUNCTION = local_password_module_init
OBJ_FILES = local_password.o
#
# End MODULE ldb_local_password
################################################

################################################
# Start MODULE ldb_kludge_acl
[MODULE::ldb_kludge_acl]
PRIVATE_DEPENDENCIES = LIBTALLOC LIBSECURITY
SUBSYSTEM = LIBLDB
INIT_FUNCTION = ldb_kludge_acl_init
OBJ_FILES = \
		kludge_acl.o
#
# End MODULE ldb_kludge_acl
################################################

################################################
# Start MODULE ldb_extended_dn
[MODULE::ldb_extended_dn]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = ldb_extended_dn_init
OBJ_FILES = \
		extended_dn.o
#
# End MODULE ldb_extended_dn
################################################

################################################
# Start MODULE ldb_show_deleted
[MODULE::ldb_show_deleted]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = ldb_show_deleted_init
OBJ_FILES = \
		show_deleted.o
#
# End MODULE ldb_show_deleted
################################################

################################################
# Start MODULE ldb_partition
[MODULE::ldb_partition]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = ldb_partition_init
OBJ_FILES = \
		partition.o
#
# End MODULE ldb_partition
################################################

################################################
# Start MODULE ldb_schema
[MODULE::ldb_schema]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = ldb_schema_init
OBJ_FILES = \
		schema.o schema_syntax.o
#
# End MODULE ldb_schema
################################################

################################################
# Start MODULE ldb_update_kt
[MODULE::ldb_update_kt]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = LIBTALLOC CREDENTIALS_KRB5
#Also depends on credentials, but that would loop
INIT_FUNCTION = ldb_update_kt_init
OBJ_FILES = \
		update_keytab.o 
#
# End MODULE ldb_update_kt
################################################

