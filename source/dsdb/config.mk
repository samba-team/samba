# Directory Service subsystem

include samdb/ldb_modules/config.mk

################################################
# Start SUBSYSTEM SAMDB
[SUBSYSTEM::SAMDB]
PUBLIC_PROTO_HEADER = samdb/samdb_proto.h
PUBLIC_HEADERS = samdb/samdb.h
PUBLIC_DEPENDENCIES = ldb LIBCLI_LDAP HEIMDAL_KRB5 
OBJ_FILES = \
		samdb/samdb.o \
		samdb/samdb_privilege.o \
		samdb/cracknames.o \
		common/sidmap.o \
		common/flag_mapping.o \
		schema/schema_init.o
#
# End SUBSYSTEM SAMDB
################################################
