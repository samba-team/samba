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
		fileinfo.o \
		find.o \
		keepalive.o
PUBLIC_DEPENDENCIES = \
		ntvfs LIBPACKET LIBCLI_SMB2
LDFLAGS = $(SUBSYSTEM_SMB_SERVER_OUTPUT)
# End SUBSYSTEM SMB2_PROTOCOL
#######################
