# WREPL server subsystem

#######################
# Start SUBSYSTEM WREPL_SRV
[MODULE::WREPL_SRV]
INIT_FUNCTION = server_service_wrepl_init
SUBSYSTEM = service
OBJ_FILES = \
		wrepl_server.o \
		wrepl_in_connection.o \
		wrepl_in_call.o \
		wrepl_apply_records.o \
		wrepl_periodic.o \
		wrepl_scavenging.o \
		wrepl_out_pull.o \
		wrepl_out_push.o \
		wrepl_out_helpers.o
PRIVATE_PROTO_HEADER = wrepl_server_proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_WREPL WINSDB process_model 
# End SUBSYSTEM WREPL_SRV
#######################
