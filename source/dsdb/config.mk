# Directory Service subsystem

mkinclude samdb/ldb_modules/config.mk

################################################
# Start SUBSYSTEM SAMDB
[SUBSYSTEM::SAMDB]
PRIVATE_PROTO_HEADER = samdb/samdb_proto.h
PUBLIC_DEPENDENCIES = HEIMDAL_KRB5 
PRIVATE_DEPENDENCIES = LIBNDR NDR_MISC NDR_DRSUAPI NDR_DRSBLOBS NSS_WRAPPER \
					   auth_system_session LDAP_ENCODE LIBCLI_AUTH LIBNDR \
					   SAMDB_SCHEMA LDB_WRAP SAMDB_COMMON


SAMDB_OBJ_FILES = $(addprefix dsdb/, \
		samdb/samdb.o \
		samdb/samdb_privilege.o \
		samdb/cracknames.o \
		repl/replicated_objects.o)

PUBLIC_HEADERS += dsdb/samdb/samdb.h

[SUBSYSTEM::SAMDB_COMMON]
PRIVATE_PROTO_HEADER = common/proto.h
PRIVATE_DEPENDENCIES = LIBLDB

SAMDB_COMMON_OBJ_FILES = $(addprefix dsdb/common/, \
		sidmap.o \
		flag_mapping.o \
		util.o)

[SUBSYSTEM::SAMDB_SCHEMA]
PRIVATE_PROTO_HEADER = schema/proto.h
PRIVATE_DEPENDENCIES = SAMDB_COMMON NDR_DRSUAPI NDR_DRSBLOBS

SAMDB_SCHEMA_OBJ_FILES = $(addprefix dsdb/schema/, \
		schema_init.o \
		schema_syntax.o \
		schema_constructed.o)

PUBLIC_HEADERS += dsdb/schema/schema.h

#######################
# Start SUBSYSTEM DREPL_SRV
[MODULE::DREPL_SRV]
INIT_FUNCTION = server_service_drepl_init
SUBSYSTEM = smbd
PRIVATE_PROTO_HEADER = repl/drepl_service_proto.h
PRIVATE_DEPENDENCIES = \
		SAMDB \
		process_model 
# End SUBSYSTEM DREPL_SRV
#######################

DREPL_SRV_OBJ_FILES = $(addprefix dsdb/repl/, \
		drepl_service.o \
		drepl_periodic.o \
		drepl_partitions.o \
		drepl_out_pull.o \
		drepl_out_helpers.o)

