# Directory Service subsystem

include samdb/ldb_modules/config.mk

################################################
# Start SUBSYSTEM SAMDB
[SUBSYSTEM::SAMDB]
OBJ_FILES = \
		samdb/samdb.o \
		samdb/samdb_privilege.o \
		samdb/cracknames.o \
		common/flag_mapping.o
REQUIRED_SUBSYSTEMS = \
		DCERPC_COMMON
#
# End SUBSYSTEM SAMDB
################################################
