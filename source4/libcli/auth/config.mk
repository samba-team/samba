#################################
# Start SUBSYSTEM LIBCLI_AUTH
[SUBSYSTEM::LIBCLI_AUTH]
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = credentials.o \
		session.o \
		smbencrypt.o \
		smbdes.o
PUBLIC_DEPENDENCIES = \
		MSRPC_PARSE \
		LIBSAMBA-CONFIG
# End SUBSYSTEM LIBCLI_AUTH
#################################


PUBLIC_HEADERS += libcli/auth/credentials.h
