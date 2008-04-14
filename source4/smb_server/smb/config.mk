#######################
# Start SUBSYSTEM SMB_PROTOCOL
[SUBSYSTEM::SMB_PROTOCOL]
PRIVATE_PROTO_HEADER = smb_proto.h
PUBLIC_DEPENDENCIES = \
		ntvfs LIBPACKET CREDENTIALS
# End SUBSYSTEM SMB_PROTOCOL
#######################

SMB_PROTOCOL_OBJ_FILES = $(addprefix smb_server/smb/, \
		receive.o \
		negprot.o \
		nttrans.o \
		reply.o \
		request.o \
		search.o \
		service.o \
		sesssetup.o \
		srvtime.o \
		trans2.o \
		signing.o)

