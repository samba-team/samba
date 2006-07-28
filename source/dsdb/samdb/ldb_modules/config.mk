################################################
# Start MODULE ldb_objectguid
[MODULE::ldb_objectguid]
SUBSYSTEM = ldb
INIT_FUNCTION = objectguid_module_init
OBJ_FILES = \
		objectguid.o
PUBLIC_DEPENDENCIES = \
		LIBNDR NDR_MISC
# End MODULE ldb_objectguid
################################################

################################################
# Start MODULE ldb_samldb
[MODULE::ldb_samldb]
SUBSYSTEM = ldb
INIT_FUNCTION = samldb_module_init
OBJ_FILES = \
		samldb.o
#
# End MODULE ldb_samldb
################################################

################################################
# Start MODULE ldb_samba3sam
[MODULE::ldb_samba3sam]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_samba3sam_module_init
ENABLE = NO
OBJ_FILES = \
		samba3sam.o
#
# End MODULE ldb_samldb
################################################

# ################################################
# # Start MODULE ldb_proxy
# [MODULE::ldb_proxy]
# SUBSYSTEM = ldb
# INIT_FUNCTION = proxy_module_init
# OBJ_FILES = \
# 		proxy.o
# 
# # End MODULE ldb_proxy
# ################################################


################################################
# Start MODULE ldb_rootdse
[MODULE::ldb_rootdse]
SUBSYSTEM = ldb
INIT_FUNCTION = rootdse_module_init
OBJ_FILES = \
		rootdse.o
#
# End MODULE ldb_rootdse
################################################

################################################
# Start MODULE ldb_password_hash
[MODULE::ldb_password_hash]
SUBSYSTEM = ldb
INIT_FUNCTION = password_hash_module_init
OBJ_FILES = password_hash.o
PUBLIC_DEPENDENCIES = HEIMDAL_KRB5
PRIVATE_DEPENDENCIES = HEIMDAL_HDB_KEYS
#
# End MODULE ldb_password_hash
################################################

################################################
# Start MODULE ldb_local_password
[MODULE::ldb_local_password]
SUBSYSTEM = ldb
INIT_FUNCTION = local_password_module_init
OBJ_FILES = local_password.o
#
# End MODULE ldb_local_password
################################################

################################################
# Start MODULE ldb_kludge_acl
[MODULE::ldb_kludge_acl]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_kludge_acl_init
OBJ_FILES = \
		kludge_acl.o
PUBLIC_DEPENDENCIES = \
		LIBSECURITY
#
# End MODULE ldb_kludge_acl
################################################

################################################
# Start MODULE ldb_extended_dn
[MODULE::ldb_extended_dn]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_extended_dn_init
OBJ_FILES = \
		extended_dn.o
#
# End MODULE ldb_extended_dn
################################################

################################################
# Start MODULE ldb_partition
[MODULE::ldb_partition]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_partition_init
OBJ_FILES = \
		partition.o
#
# End MODULE ldb_partition
################################################

