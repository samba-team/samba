################################################
# Start MODULE ldb_objectguid
[MODULE::ldb_objectguid]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBNDR NDR_MISC
INIT_FUNCTION = objectguid_module_module_ops
# End MODULE ldb_objectguid
################################################

ldb_objectguid_OBJ_FILES = dsdb/samdb/ldb_modules/objectguid.o

################################################
# Start MODULE ldb_repl_meta_data
[MODULE::ldb_repl_meta_data]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC LIBNDR NDR_MISC NDR_DRSUAPI \
					   NDR_DRSBLOBS LIBNDR
INIT_FUNCTION = repl_meta_data_module_module_ops
# End MODULE ldb_repl_meta_data
################################################

ldb_repl_meta_data_OBJ_FILES = \
		repl_meta_data.o

################################################
# Start MODULE ldb_dsdb_cache
[MODULE::ldb_dsdb_cache]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = dsdb_cache_module_module_ops
# End MODULE ldb_dsdb_cache
################################################

ldb_dsdb_cache_OBJ_FILES = \
		dsdb_cache.o

################################################
# Start MODULE ldb_schema_fsmo
[MODULE::ldb_schema_fsmo]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = schema_fsmo_module_module_ops
# End MODULE ldb_schema_fsmo
################################################

ldb_schema_fsmo_OBJ_FILES = \
		schema_fsmo.o

################################################
# Start MODULE ldb_naming_fsmo
[MODULE::ldb_naming_fsmo]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = naming_fsmo_module_module_ops
# End MODULE ldb_naming_fsmo
################################################

ldb_naming_fsmo_OBJ_FILES = \
		naming_fsmo.o

################################################
# Start MODULE ldb_pdc_fsmo
[MODULE::ldb_pdc_fsmo]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = pdc_fsmo_module_module_ops
# End MODULE ldb_pdc_fsmo
################################################

ldb_pdc_fsmo_OBJ_FILES = \
		pdc_fsmo.o

################################################
# Start MODULE ldb_samldb
[MODULE::ldb_samldb]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LDAP_ENCODE NDR_MISC SAMDB
INIT_FUNCTION = samldb_module_module_ops
#
# End MODULE ldb_samldb
################################################

ldb_samldb_OBJ_FILES = \
		samldb.o

################################################
# Start MODULE ldb_samba3sam
[MODULE::ldb_samba3sam]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
INIT_FUNCTION = &ldb_samba3sam_module_module_ops
PRIVATE_DEPENDENCIES = LIBTALLOC ldb_map SMBPASSWD NSS_WRAPPER LIBSECURITY \
					   NDR_SECURITY
#
# End MODULE ldb_samldb
################################################

ldb_samba3sam_OBJ_FILES = \
		samba3sam.o

################################################
# Start MODULE ldb_simple_ldap_map
[MODULE::ldb_simple_ldap_map]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
INIT_FUNCTION = &ldb_simple_ldap_map_module_module_ops
PRIVATE_DEPENDENCIES = LIBTALLOC ldb_map LIBNDR NDR_MISC
ENABLE = YES
ALIASES = entryuuid nsuniqueid
#
# End MODULE ldb_entryuuid
################################################

ldb_simple_ldap_map_OBJ_FILES = \
		simple_ldap_map.o

# ################################################
# # Start MODULE ldb_proxy
# [MODULE::ldb_proxy]
# SUBSYSTEM = LIBLDB
# INIT_FUNCTION = proxy_module_module_ops
# OBJ_FILES = \
# 		proxy.o
# 
# # End MODULE ldb_proxy
# ################################################


################################################
# Start MODULE ldb_rootdse
[MODULE::ldb_rootdse]
SUBSYSTEM = LIBLDB
PRIVATE_DEPENDENCIES = LIBTALLOC SAMDB
OUTPUT_TYPE = SHARED_LIBRARY
INIT_FUNCTION = rootdse_module_module_ops
# End MODULE ldb_rootdse
################################################

ldb_rootdse_OBJ_FILES = dsdb/samdb/ldb_modules/rootdse.o

################################################
# Start MODULE ldb_password_hash
[MODULE::ldb_password_hash]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
INIT_FUNCTION = password_hash_module_module_ops
PRIVATE_DEPENDENCIES = HEIMDAL_HDB_KEYS LIBTALLOC HEIMDAL_KRB5 LDAP_ENCODE \
					   LIBCLI_AUTH NDR_DRSBLOBS KERBEROS SAMDB
# End MODULE ldb_password_hash
################################################

ldb_password_hash_OBJ_FILES = dsdb/samdb/ldb_modules/password_hash.o

################################################
# Start MODULE ldb_local_password
[MODULE::ldb_local_password]
PRIVATE_DEPENDENCIES = LIBTALLOC LIBNDR SAMDB
OUTPUT_TYPE = SHARED_LIBRARY
SUBSYSTEM = LIBLDB
INIT_FUNCTION = local_password_module_module_ops
# End MODULE ldb_local_password
################################################

ldb_local_password_OBJ_FILES = dsdb/samdb/ldb_modules/local_password.o

################################################
# Start MODULE ldb_kludge_acl
[MODULE::ldb_kludge_acl]
PRIVATE_DEPENDENCIES = LIBTALLOC LIBSECURITY SAMDB
OUTPUT_TYPE = SHARED_LIBRARY
SUBSYSTEM = LIBLDB
INIT_FUNCTION = &ldb_kludge_acl_module_ops

# End MODULE ldb_kludge_acl
################################################

ldb_kludge_acl_OBJ_FILES = dsdb/samdb/ldb_modules/kludge_acl.o

################################################
# Start MODULE ldb_extended_dn
[MODULE::ldb_extended_dn]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBNDR LIBSECURITY SAMDB
INIT_FUNCTION = &ldb_extended_dn_module_ops
# End MODULE ldb_extended_dn
################################################

ldb_extended_dn_OBJ_FILES = dsdb/samdb/ldb_modules/extended_dn.o

################################################
# Start MODULE ldb_show_deleted
[MODULE::ldb_show_deleted]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = &ldb_show_deleted_module_ops
# End MODULE ldb_show_deleted
################################################

ldb_show_deleted_OBJ_FILES = dsdb/samdb/ldb_modules/show_deleted.o

################################################
# Start MODULE ldb_partition
[MODULE::ldb_partition]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC SAMDB
INIT_FUNCTION = &ldb_partition_module_ops
# End MODULE ldb_partition
################################################

ldb_partition_OBJ_FILES = dsdb/samdb/ldb_modules/partition.o

################################################
# Start MODULE ldb_schema
[MODULE::ldb_schema]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBLDB
INIT_FUNCTION = &ldb_schema_module_ops
# End MODULE ldb_schema
################################################

ldb_schema_OBJ_FILES = $(addprefix dsdb/samdb/ldb_modules/, schema.o schema_syntax.o)

################################################
# Start MODULE ldb_update_kt
[MODULE::ldb_update_keytab]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC CREDENTIALS
#Also depends on credentials, but that would loop
INIT_FUNCTION = &ldb_update_kt_module_ops
# End MODULE ldb_update_kt
################################################

ldb_update_keytab_OBJ_FILES = dsdb/samdb/ldb_modules/update_keytab.o 

################################################
# Start MODULE ldb_objectclass
[MODULE::ldb_objectclass]
INIT_FUNCTION = &ldb_objectclass_module_ops
OUTPUT_TYPE = SHARED_LIBRARY
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC LIBSECURITY NDR_SECURITY SAMDB
SUBSYSTEM = LIBLDB
# End MODULE ldb_objectclass
################################################

ldb_objectclass_OBJ_FILES = dsdb/samdb/ldb_modules/objectclass.o

################################################
# Start MODULE ldb_subtree_rename
[MODULE::ldb_subtree_rename]
INIT_FUNCTION = &ldb_subtree_rename_module_ops
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
# End MODULE ldb_subtree_rename
################################################

ldb_subtree_rename_OBJ_FILES = dsdb/samdb/ldb_modules/subtree_rename.o

################################################
# Start MODULE ldb_subtree_rename
[MODULE::ldb_subtree_delete]
INIT_FUNCTION = &ldb_subtree_delete_module_ops
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
# End MODULE ldb_subtree_rename
################################################

ldb_subtree_delete_OBJ_FILES = dsdb/samdb/ldb_modules/subtree_delete.o

################################################
# Start MODULE ldb_linked_attributes
[MODULE::ldb_linked_attributes]
INIT_FUNCTION = &ldb_linked_attributes_module_ops
CFLAGS = -Ilib/ldb/include
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC SAMDB
SUBSYSTEM = LIBLDB
# End MODULE ldb_linked_attributes
################################################

ldb_linked_attributes_OBJ_FILES = dsdb/samdb/ldb_modules/linked_attributes.o

################################################
# Start MODULE ldb_ranged_results
[MODULE::ldb_ranged_results]
INIT_FUNCTION = &ldb_ranged_results_module_ops
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
# End MODULE ldb_ranged_results
################################################

ldb_ranged_results_OBJ_FILES = dsdb/samdb/ldb_modules/ranged_results.o

################################################
# Start MODULE ldb_anr
[MODULE::ldb_anr]
INIT_FUNCTION = &ldb_anr_module_ops
CFLAGS = -Ilib/ldb/include
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBSAMBA-UTIL SAMDB
SUBSYSTEM = LIBLDB
# End MODULE ldb_anr
################################################

ldb_anr_OBJ_FILES = dsdb/samdb/ldb_modules/anr.o

################################################
# Start MODULE ldb_normalise
[MODULE::ldb_normalise]
INIT_FUNCTION = &ldb_normalise_module_ops
CFLAGS = -Ilib/ldb/include
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBSAMBA-UTIL SAMDB
SUBSYSTEM = LIBLDB
# End MODULE ldb_normalise
################################################

ldb_normalise_OBJ_FILES = dsdb/samdb/ldb_modules/normalise.o

################################################
# Start MODULE ldb_instancetype
[MODULE::ldb_instancetype]
INIT_FUNCTION = &ldb_instancetype_module_ops
CFLAGS = -Ilib/ldb/include
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
# End MODULE ldb_instancetype
################################################

ldb_instancetype_OBJ_FILES = dsdb/samdb/ldb_modules/instancetype.o

