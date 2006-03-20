################################################
# Start MODULE ldb_objectguid
[MODULE::ldb_objectguid]
SUBSYSTEM = ldb
INIT_FUNCTION = objectguid_module_init
OBJ_FILES = \
		objectguid.o
REQUIRED_SUBSYSTEMS = \
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
REQUIRED_SUBSYSTEMS = SAMDB
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

################################################
# Start MODULE ldb_proxy
[MODULE::ldb_proxy]
SUBSYSTEM = ldb
INIT_FUNCTION = proxy_module_init
OBJ_FILES = \
		proxy.o
#
# End MODULE ldb_proxy
################################################


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
OBJ_FILES = \
		password_hash.o
REQUIRED_SUBSYSTEMS = \
		HEIMDAL_HDB HEIMDAL_KRB5
#
# End MODULE ldb_rootdse
################################################

################################################
# Start MODULE ldb_cludge_acl
[MODULE::ldb_kludge_acl]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_kludge_acl_init
OBJ_FILES = \
		kludge_acl.o
REQUIRED_SUBSYSTEMS = \
		LIB_SECURITY
#
# End MODULE ldb_rootdse
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

