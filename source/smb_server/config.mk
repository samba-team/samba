# SMB server subsystem
#
[MODULE::SERVICE_SMB]
INIT_FUNCTION = server_service_smb_init
SUBSYSTEM = service
OBJ_FILES = smb_server.o
PRIVATE_PROTO_HEADER = service_smb_proto.h
PRIVATE_DEPENDENCIES = SMB_SERVER

#######################
# Start SUBSYSTEM SMB
[SUBSYSTEM::SMB_SERVER]
OBJ_FILES = \
		handle.o \
		tcon.o \
		session.o \
		blob.o \
		management.o
PRIVATE_PROTO_HEADER = smb_server_proto.h
PUBLIC_DEPENDENCIES = \
		share \
		LIBPACKET \
		SMB_PROTOCOL \
		SMB2_PROTOCOL
# End SUBSYSTEM SMB
#######################

include smb/config.mk
include smb2/config.mk
