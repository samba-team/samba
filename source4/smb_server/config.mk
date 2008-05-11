# SMB server subsystem
#
[MODULE::SERVICE_SMB]
INIT_FUNCTION = server_service_smb_init
SUBSYSTEM = smbd
PRIVATE_PROTO_HEADER = service_smb_proto.h
PRIVATE_DEPENDENCIES = SMB_SERVER

SERVICE_SMB_OBJ_FILES = smb_server/smb_server.o

#######################
# Start SUBSYSTEM SMB
[SUBSYSTEM::SMB_SERVER]
PRIVATE_PROTO_HEADER = smb_server_proto.h
PUBLIC_DEPENDENCIES = \
		share \
		LIBPACKET \
		SMB_PROTOCOL \
		SMB2_PROTOCOL
# End SUBSYSTEM SMB
#######################

SMB_SERVER_OBJ_FILES = $(addprefix smb_server/, \
		handle.o \
		tcon.o \
		session.o \
		blob.o \
		management.o)

mkinclude smb/config.mk
mkinclude smb2/config.mk
