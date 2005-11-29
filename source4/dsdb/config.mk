# Directory Service subsystem

include samdb/ldb_modules/config.mk

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
