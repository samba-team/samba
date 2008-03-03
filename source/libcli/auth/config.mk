#################################
# Start SUBSYSTEM LIBCLI_AUTH
[SUBSYSTEM::LIBCLI_AUTH]
PRIVATE_PROTO_HEADER = proto.h
PUBLIC_DEPENDENCIES = \
		MSRPC_PARSE \
		LIBSAMBA-CONFIG
# End SUBSYSTEM LIBCLI_AUTH
#################################

LIBCLI_AUTH_OBJ_FILES = $(addprefix libcli/auth/, \
		credentials.o \
		session.o \
		smbencrypt.o \
		smbdes.o)

PUBLIC_HEADERS += libcli/auth/credentials.h
