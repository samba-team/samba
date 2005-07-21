# Directory Service subsystem

################################################
# Start MODULE libldb_objectguid
[MODULE::libldb_objectguid]
SUBSYSTEM = LIBLDB
INIT_OBJ_FILES = \
		dsdb/samdb/ldb_modules/objectguid.o
REQUIRED_SUBSYSTEMS = \
		NDR_RAW NDR_MISC
# End MODULE libldb_objectguid
################################################

################################################
# Start MODULE libldb_samldb
[MODULE::libldb_samldb]
SUBSYSTEM = LIBLDB
INIT_OBJ_FILES = \
		dsdb/samdb/ldb_modules/samldb.o
#
# End MODULE libldb_samldb
################################################

################################################
# Start SUBSYSTEM SAMDB
[SUBSYSTEM::SAMDB]
INIT_OBJ_FILES = \
		dsdb/samdb/samdb.o
ADD_OBJ_FILES = \
		dsdb/samdb/samdb_privilege.o \
		dsdb/common/flag_mapping.o
REQUIRED_SUBSYSTEMS = \
		DCERPC_COMMON
#
# End SUBSYSTEM SAMDB
################################################
