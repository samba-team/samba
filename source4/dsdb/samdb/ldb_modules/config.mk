################################################
# Start MODULE libldb_objectguid
[MODULE::libldb_objectguid]
SUBSYSTEM = ldb
INIT_FUNCTION = objectguid_module_init
OBJ_FILES = \
		objectguid.o
REQUIRED_SUBSYSTEMS = \
		LIBNDR NDR_MISC
# End MODULE libldb_objectguid
################################################

################################################
# Start MODULE libldb_samldb
[MODULE::libldb_samldb]
SUBSYSTEM = ldb
INIT_FUNCTION = samldb_module_init
OBJ_FILES = \
		samldb.o
REQUIRED_SUBSYSTEMS = SAMDB
#
# End MODULE libldb_samldb
################################################

################################################
# Start MODULE libldb_samba3sam
[MODULE::libldb_samba3sam]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_samba3sam_module_init
ENABLE = NO
OBJ_FILES = \
		samba3sam.o
#
# End MODULE libldb_samldb
################################################

################################################
# Start MODULE libldb_proxy
[MODULE::libldb_proxy]
SUBSYSTEM = ldb
INIT_FUNCTION = proxy_module_init
OBJ_FILES = \
		proxy.o
#
# End MODULE libldb_proxy
################################################


################################################
# Start MODULE libldb_rootdse
[MODULE::libldb_rootdse]
SUBSYSTEM = ldb
INIT_FUNCTION = rootdse_module_init
OBJ_FILES = \
		rootdse.o
#
# End MODULE libldb_rootdse
################################################

################################################
# Start MODULE libldb_password_hash
[MODULE::libldb_password_hash]
SUBSYSTEM = ldb
INIT_FUNCTION = password_hash_module_init
OBJ_FILES = \
		password_hash.o
REQUIRED_SUBSYSTEMS = \
		HEIMDAL_HDB HEIMDAL_KRB5
#
# End MODULE libldb_rootdse
################################################

################################################
# Start MODULE libldb_cludge_acl
[MODULE::libldb_kludge_acl]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_kludge_acl_init
OBJ_FILES = \
		kludge_acl.o
REQUIRED_SUBSYSTEMS = \
		LIB_SECURITY
#
# End MODULE libldb_rootdse
################################################

################################################
# Start MODULE libldb_extended_dn
[MODULE::libldb_extended_dn]
SUBSYSTEM = ldb
INIT_FUNCTION = ldb_extended_dn_init
OBJ_FILES = \
		extended_dn.o
#
# End MODULE libldb_extended_dn
################################################

