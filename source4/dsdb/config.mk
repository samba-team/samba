# Directory Service subsystem

mkinclude samdb/ldb_modules/config.mk

################################################
# Start SUBSYSTEM SAMDB
[SUBSYSTEM::SAMDB]
PUBLIC_DEPENDENCIES = HEIMDAL_KRB5 
PRIVATE_DEPENDENCIES = LIBNDR NDR_DRSUAPI NDR_DRSBLOBS NSS_WRAPPER \
					   auth_system_session LDAP_ENCODE LIBCLI_AUTH LIBNDR \
					   SAMDB_SCHEMA LDB_WRAP SAMDB_COMMON


SAMDB_OBJ_FILES = $(addprefix $(dsdbsrcdir)/, \
		samdb/samdb.o \
		samdb/samdb_privilege.o \
		samdb/cracknames.o \
		repl/replicated_objects.o)

$(eval $(call proto_header_template,$(dsdbsrcdir)/samdb/samdb_proto.h,$(SAMDB_OBJ_FILES:.o=.c)))
# PUBLIC_HEADERS += dsdb/samdb/samdb.h

[SUBSYSTEM::SAMDB_COMMON]
PRIVATE_DEPENDENCIES = LIBLDB

SAMDB_COMMON_OBJ_FILES = $(addprefix $(dsdbsrcdir)/common/, \
		sidmap.o \
		flag_mapping.o \
		util.o)
$(eval $(call proto_header_template,$(dsdbsrcdir)/common/proto.h,$(SAMDB_COMMON_OBJ_FILES:.o=.c)))

[SUBSYSTEM::SAMDB_SCHEMA]
PRIVATE_DEPENDENCIES = SAMDB_COMMON NDR_DRSUAPI NDR_DRSBLOBS

SAMDB_SCHEMA_OBJ_FILES = $(addprefix $(dsdbsrcdir)/schema/, \
		schema_init.o \
		schema_set.o \
		schema_query.o \
		schema_syntax.o \
		schema_description.o)

$(eval $(call proto_header_template,$(dsdbsrcdir)/schema/proto.h,$(SAMDB_SCHEMA_OBJ_FILES:.o=.c)))
# PUBLIC_HEADERS += dsdb/schema/schema.h

#######################
# Start SUBSYSTEM DREPL_SRV
[MODULE::DREPL_SRV]
INIT_FUNCTION = server_service_drepl_init
SUBSYSTEM = service
PRIVATE_DEPENDENCIES = \
		SAMDB \
		process_model 
# End SUBSYSTEM DREPL_SRV
#######################

DREPL_SRV_OBJ_FILES = $(addprefix $(dsdbsrcdir)/repl/, \
		drepl_service.o \
		drepl_periodic.o \
		drepl_partitions.o \
		drepl_out_pull.o \
		drepl_out_helpers.o)

$(eval $(call proto_header_template,$(dsdbsrcdir)/repl/drepl_service_proto.h,$(DREPL_SRV_OBJ_FILES:.o=.c)))
