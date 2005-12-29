# Directory Service subsystem

include samdb/ldb_modules/config.mk

################################################
# Start SUBSYSTEM SAMDB
[SUBSYSTEM::SAMDB]
PRIVATE_PROTO_HEADER = samdb/samdb.h
REQUIRED_SUBSYSTEMS = DB_WRAP
OBJ_FILES = \
		samdb/samdb.o \
		samdb/samdb_privilege.o \
		samdb/cracknames.o \
		common/flag_mapping.o
#
# End SUBSYSTEM SAMDB
################################################
