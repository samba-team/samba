[SUBSYSTEM::LIBCLI_AUTH]
PUBLIC_DEPENDENCIES = \
		MSRPC_PARSE \
		LIBSAMBA-HOSTCONFIG

LIBCLI_AUTH_OBJ_FILES = $(addprefix $(libclicommonsrcdir)/auth/, \
		credentials.o \
		session.o \
		smbencrypt.o \
		smbdes.o)

PUBLIC_HEADERS += ../libcli/auth/credentials.h
$(eval $(call proto_header_template,$(libclicommonsrcdir)/auth/proto.h,$(LIBCLI_AUTH_OBJ_FILES:.o=.c)))
