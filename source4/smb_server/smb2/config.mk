#######################
# Start SUBSYSTEM SMB2_PROTOCOL
[SUBSYSTEM::SMB2_PROTOCOL]
PRIVATE_PROTO_HEADER = smb2_proto.h
OBJ_FILES = \
		receive.o \
		negprot.o \
		sesssetup.o \
		tcon.o \
		fileio.o \
		keepalive.o
REQUIRED_SUBSYSTEMS = \
		ntvfs LIBPACKET LIBCLI_SMB2
# End SUBSYSTEM SMB2_PROTOCOL
#######################
