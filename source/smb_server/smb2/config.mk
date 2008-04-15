#######################
# Start SUBSYSTEM SMB2_PROTOCOL
[SUBSYSTEM::SMB2_PROTOCOL]
PRIVATE_PROTO_HEADER = smb2_proto.h
PUBLIC_DEPENDENCIES = \
		ntvfs LIBPACKET LIBCLI_SMB2
# End SUBSYSTEM SMB2_PROTOCOL
#######################

SMB2_PROTOCOL_OBJ_FILES = $(addprefix smb_server/smb2/, \
		receive.o \
		negprot.o \
		sesssetup.o \
		tcon.o \
		fileio.o \
		fileinfo.o \
		find.o \
		keepalive.o)

