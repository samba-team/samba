# Directory Service subsystem

include samdb/ldb_modules/config.mk

################################################
# Start SUBSYSTEM SAMDB
[SUBSYSTEM::SAMDB]
PUBLIC_PROTO_HEADER = samdb/samdb_proto.h
PUBLIC_HEADERS = samdb/samdb.h
REQUIRED_SUBSYSTEMS = DB_WRAP LIBCLI_LDAP
OBJ_FILES = \
		samdb/samdb.o \
		samdb/samdb_privilege.o \
		samdb/cracknames.o \
		common/flag_mapping.o
#
# End SUBSYSTEM SAMDB
################################################
