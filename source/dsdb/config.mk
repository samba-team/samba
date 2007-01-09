# Directory Service subsystem

include samdb/ldb_modules/config.mk

################################################
# Start SUBSYSTEM SAMDB
[SUBSYSTEM::SAMDB]
PUBLIC_PROTO_HEADER = samdb/samdb_proto.h
PUBLIC_HEADERS = samdb/samdb.h
PUBLIC_DEPENDENCIES = LIBCLI_LDAP HEIMDAL_KRB5 
PRIVATE_DEPENDENCIES = LIBNDR NDR_MISC NDR_DRSUAPI
LDFLAGS = $(LIBRARY_ldb_OUTPUT)
OBJ_FILES = \
		samdb/samdb.o \
		samdb/samdb_privilege.o \
		samdb/cracknames.o \
		common/sidmap.o \
		common/flag_mapping.o \
		schema/schema_init.o \
		schema/schema_syntax.o \
		repl/replicated_objects.o
#
# End SUBSYSTEM SAMDB
################################################
