# SMB server subsystem

#######################
# Start SUBSYSTEM SMB
[MODULE::SMB_SERVER]
INIT_FUNCTION = server_service_smb_init
SUBSYSTEM = service
OBJ_FILES = \
		smb_server.o \
		tcon.o \
		session.o \
		management.o
PRIVATE_PROTO_HEADER = smb_server_proto.h
PUBLIC_DEPENDENCIES = \
		LIBPACKET \
		SMB_PROTOCOL \
		SMB2_PROTOCOL
# End SUBSYSTEM SMB
#######################

include smb/config.mk
include smb2/config.mk
