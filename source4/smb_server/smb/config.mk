#######################
# Start SUBSYSTEM SMB_PROTOCOL
[SUBSYSTEM::SMB_PROTOCOL]
PRIVATE_PROTO_HEADER = smb_proto.h
OBJ_FILES = \
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
		signing.o
PUBLIC_DEPENDENCIES = \
		ntvfs LIBPACKET
LDFLAGS = $(SUBSYSTEM_SMB_SERVER_OUTPUT)
# End SUBSYSTEM SMB_PROTOCOL
#######################
