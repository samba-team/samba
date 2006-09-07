#################################
# Start SUBSYSTEM LIBCLI_AUTH
[SUBSYSTEM::LIBCLI_AUTH]
PUBLIC_HEADERS = credentials.h
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = credentials.o \
		session.o \
		smbencrypt.o \
		smbdes.o
PUBLIC_DEPENDENCIES = \
		SCHANNELDB MSRPC_PARSE
# End SUBSYSTEM LIBCLI_AUTH
#################################
