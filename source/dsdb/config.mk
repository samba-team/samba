# Directory Service subsystem

################################################
# Start MODULE libldb_objectguid
[MODULE::libldb_objectguid]
SUBSYSTEM = LIBLDB
INIT_OBJ_FILES = \
		samdb/ldb_modules/objectguid.o
REQUIRED_SUBSYSTEMS = \
		LIBNDR NDR_MISC
# End MODULE libldb_objectguid
################################################

################################################
# Start MODULE libldb_samldb
[MODULE::libldb_samldb]
SUBSYSTEM = LIBLDB
INIT_OBJ_FILES = \
		samdb/ldb_modules/samldb.o
#
# End MODULE libldb_samldb
################################################

################################################
# Start MODULE libldb_samba3sam
[MODULE::libldb_samba3sam]
SUBSYSTEM = LIBLDB
INIT_OBJ_FILES = \
		samdb/ldb_modules/samba3sam.o
#
# End MODULE libldb_samldb
################################################

################################################
# Start MODULE libldb_proxy
[MODULE::libldb_proxy]
SUBSYSTEM = LIBLDB
INIT_OBJ_FILES = \
		samdb/ldb_modules/proxy.o
#
# End MODULE libldb_proxy
################################################

################################################
# Start SUBSYSTEM SAMDB
[SUBSYSTEM::SAMDB]
INIT_OBJ_FILES = \
		samdb/samdb.o
ADD_OBJ_FILES = \
		samdb/samdb_privilege.o \
		samdb/cracknames.o \
		common/flag_mapping.o
REQUIRED_SUBSYSTEMS = \
		DCERPC_COMMON
#
# End SUBSYSTEM SAMDB
################################################
