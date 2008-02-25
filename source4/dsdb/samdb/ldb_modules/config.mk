################################################
# Start MODULE ldb_objectguid
[MODULE::ldb_objectguid]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBNDR NDR_MISC
INIT_FUNCTION = LDB_MODULE(objectguid)
OBJ_FILES = \
		objectguid.o
# End MODULE ldb_objectguid
################################################

################################################
# Start MODULE ldb_repl_meta_data
[MODULE::ldb_repl_meta_data]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC LIBNDR NDR_MISC NDR_DRSUAPI \
					   NDR_DRSBLOBS LIBNDR
INIT_FUNCTION = LDB_MODULE(repl_meta_data)
OBJ_FILES = \
		repl_meta_data.o
# End MODULE ldb_repl_meta_data
################################################

################################################
# Start MODULE ldb_dsdb_cache
[MODULE::ldb_dsdb_cache]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = LDB_MODULE(dsdb_cache)
OBJ_FILES = \
		dsdb_cache.o
# End MODULE ldb_dsdb_cache
################################################

################################################
# Start MODULE ldb_schema_fsmo
[MODULE::ldb_schema_fsmo]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = LDB_MODULE(schema_fsmo)
OBJ_FILES = \
		schema_fsmo.o
# End MODULE ldb_schema_fsmo
################################################

################################################
# Start MODULE ldb_naming_fsmo
[MODULE::ldb_naming_fsmo]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = LDB_MODULE(naming_fsmo)
OBJ_FILES = \
		naming_fsmo.o
# End MODULE ldb_naming_fsmo
################################################

################################################
# Start MODULE ldb_pdc_fsmo
[MODULE::ldb_pdc_fsmo]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = SAMDB LIBTALLOC
INIT_FUNCTION = LDB_MODULE(pdc_fsmo)
OBJ_FILES = \
		pdc_fsmo.o
# End MODULE ldb_pdc_fsmo
################################################

################################################
# Start MODULE ldb_samldb
[MODULE::ldb_samldb]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LDAP_ENCODE NDR_MISC SAMDB
INIT_FUNCTION = LDB_MODULE(samldb)
OBJ_FILES = \
		samldb.o
#
# End MODULE ldb_samldb
################################################

################################################
# Start MODULE ldb_samba3sam
[MODULE::ldb_samba3sam]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
INIT_FUNCTION = LDB_MODULE(samba3sam)
PRIVATE_DEPENDENCIES = LIBTALLOC ldb_map SMBPASSWD NSS_WRAPPER LIBSECURITY \
					   NDR_SECURITY
OBJ_FILES = \
		samba3sam.o
#
# End MODULE ldb_samldb
################################################

################################################
# Start MODULE ldb_simple_ldap_map
[MODULE::ldb_simple_ldap_map]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
INIT_FUNCTION = LDB_MODULE(simple_ldap_map)
PRIVATE_DEPENDENCIES = LIBTALLOC ldb_map LIBNDR NDR_MISC
ENABLE = YES
ALIASES = entryuuid nsuniqueid
OBJ_FILES = \
		simple_ldap_map.o
#
# End MODULE ldb_entryuuid
################################################

# ################################################
# # Start MODULE ldb_proxy
# [MODULE::ldb_proxy]
# SUBSYSTEM = LIBLDB
# INIT_FUNCTION = LDB_MODULE(proxy)
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
INIT_FUNCTION = LDB_MODULE(rootdse)
OBJ_FILES = \
		rootdse.o
#
# End MODULE ldb_rootdse
################################################

################################################
# Start MODULE ldb_password_hash
[MODULE::ldb_password_hash]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
INIT_FUNCTION = LDB_MODULE(password_hash)
OBJ_FILES = password_hash.o
PRIVATE_DEPENDENCIES = HEIMDAL_HDB_KEYS LIBTALLOC HEIMDAL_KRB5 LDAP_ENCODE \
					   LIBCLI_AUTH NDR_DRSBLOBS KERBEROS SAMDB
#
# End MODULE ldb_password_hash
################################################

################################################
# Start MODULE ldb_local_password
[MODULE::ldb_local_password]
PRIVATE_DEPENDENCIES = LIBTALLOC LIBNDR SAMDB
OUTPUT_TYPE = SHARED_LIBRARY
SUBSYSTEM = LIBLDB
INIT_FUNCTION = LDB_MODULE(local_password)
OBJ_FILES = local_password.o
#
# End MODULE ldb_local_password
################################################

################################################
# Start MODULE ldb_kludge_acl
[MODULE::ldb_kludge_acl]
PRIVATE_DEPENDENCIES = LIBTALLOC LIBSECURITY SAMDB
OUTPUT_TYPE = SHARED_LIBRARY
SUBSYSTEM = LIBLDB
INIT_FUNCTION = LDB_MODULE(kludge_acl)
OBJ_FILES = \
		kludge_acl.o
#
# End MODULE ldb_kludge_acl
################################################

################################################
# Start MODULE ldb_extended_dn
[MODULE::ldb_extended_dn]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBNDR LIBSECURITY SAMDB
INIT_FUNCTION = LDB_MODULE(extended_dn)
OBJ_FILES = \
		extended_dn.o
#
# End MODULE ldb_extended_dn
################################################

################################################
# Start MODULE ldb_show_deleted
[MODULE::ldb_show_deleted]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC
INIT_FUNCTION = LDB_MODULE(show_deleted)
OBJ_FILES = \
		show_deleted.o
#
# End MODULE ldb_show_deleted
################################################

################################################
# Start MODULE ldb_partition
[MODULE::ldb_partition]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC SAMDB
INIT_FUNCTION = LDB_MODULE(partition)
OBJ_FILES = \
		partition.o
#
# End MODULE ldb_partition
################################################

################################################
# Start MODULE ldb_schema
[MODULE::ldb_schema]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBLDB
INIT_FUNCTION = LDB_MODULE(schema)
OBJ_FILES = \
		schema.o schema_syntax.o
#
# End MODULE ldb_schema
################################################

################################################
# Start MODULE ldb_update_kt
[MODULE::ldb_update_keytab]
SUBSYSTEM = LIBLDB
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC CREDENTIALS
#Also depends on credentials, but that would loop
INIT_FUNCTION = LDB_MODULE(update_kt)
OBJ_FILES = \
		update_keytab.o 
#
# End MODULE ldb_update_kt
################################################

################################################
# Start MODULE ldb_objectclass
[MODULE::ldb_objectclass]
INIT_FUNCTION = LDB_MODULE(objectclass)
OUTPUT_TYPE = SHARED_LIBRARY
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC LIBSECURITY NDR_SECURITY SAMDB
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		objectclass.o
# End MODULE ldb_objectclass
################################################

################################################
# Start MODULE ldb_subtree_rename
[MODULE::ldb_subtree_rename]
INIT_FUNCTION = LDB_MODULE(subtree_rename)
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		subtree_rename.o
# End MODULE ldb_subtree_rename
################################################

################################################
# Start MODULE ldb_subtree_rename
[MODULE::ldb_subtree_delete]
INIT_FUNCTION = LDB_MODULE(subtree_delete)
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		subtree_delete.o
# End MODULE ldb_subtree_rename
################################################

################################################
# Start MODULE ldb_linked_attributes
[MODULE::ldb_linked_attributes]
INIT_FUNCTION = LDB_MODULE(linked_attributes)
CFLAGS = -Ilib/ldb/include
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC SAMDB
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		linked_attributes.o
# End MODULE ldb_linked_attributes
################################################

################################################
# Start MODULE ldb_ranged_results
[MODULE::ldb_ranged_results]
INIT_FUNCTION = LDB_MODULE(ranged_results)
CFLAGS = -Ilib/ldb/include
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		ranged_results.o
# End MODULE ldb_ranged_results
################################################

################################################
# Start MODULE ldb_anr
[MODULE::ldb_anr]
INIT_FUNCTION = LDB_MODULE(anr)
CFLAGS = -Ilib/ldb/include
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBSAMBA-UTIL SAMDB
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		anr.o
# End MODULE ldb_anr
################################################

################################################
# Start MODULE ldb_normalise
[MODULE::ldb_normalise]
INIT_FUNCTION = LDB_MODULE(normalise)
CFLAGS = -Ilib/ldb/include
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBSAMBA-UTIL SAMDB
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		normalise.o
# End MODULE ldb_normalise
################################################

################################################
# Start MODULE ldb_instancetype
[MODULE::ldb_instancetype]
INIT_FUNCTION = LDB_MODULE(instancetype)
CFLAGS = -Ilib/ldb/include
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC
SUBSYSTEM = LIBLDB
OBJ_FILES = \
		instancetype.o
# End MODULE ldb_instancetype
################################################

