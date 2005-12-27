# SMB server subsystem

#######################
# Start SUBSYSTEM SMB
[SUBSYSTEM::SMB]
OBJ_FILES = \
		smb_server.o \
		tcon.o \
		session.o \
		management.o
PRIVATE_PROTO_HEADER = smb_server_proto.h
REQUIRED_SUBSYSTEMS = \
		LIBPACKET \
		SMB_PROTOCOL \
		SMB2_PROTOCOL
# End SUBSYSTEM SMB
#######################

include smb/config.mk
include smb2/config.mk
