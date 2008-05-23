#################################
# Start SUBSYSTEM LIBCLI_AUTH
[SUBSYSTEM::LIBCLI_AUTH]
PUBLIC_DEPENDENCIES = \
		MSRPC_PARSE \
		LIBSAMBA-HOSTCONFIG
# End SUBSYSTEM LIBCLI_AUTH
#################################

LIBCLI_AUTH_OBJ_FILES = $(addprefix $(libclisrcdir)/auth/, \
		credentials.o \
		session.o \
		smbencrypt.o \
		smbdes.o)

PUBLIC_HEADERS += $(libclisrcdir)/auth/credentials.h
$(eval $(call proto_header_template,$(libclisrcdir)/auth/proto.h,$(LIBCLI_AUTH_OBJ_FILES:.o=.c)))
