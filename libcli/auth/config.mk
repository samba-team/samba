[SUBSYSTEM::ntlm_check]
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL

ntlm_check_OBJ_FILES = $(addprefix $(libclicommonsrcdir)/auth/, ntlm_check.o)

[SUBSYSTEM::MSRPC_PARSE]

MSRPC_PARSE_OBJ_FILES = $(addprefix $(libclicommonsrcdir)/auth/, msrpc_parse.o)

$(eval $(call proto_header_template,$(libclicommonsrcdir)/auth/msrpc_parse.h,$(MSRPC_PARSE_OBJ_FILES:.o=.c)))

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

[SUBSYSTEM::COMMON_SCHANNELDB]
PRIVATE_DEPENDENCIES = LDB_WRAP

COMMON_SCHANNELDB_OBJ_FILES = $(addprefix $(libclicommonsrcdir)/auth/, schannel_state.o)
$(eval $(call proto_header_template,$(libclicommonsrcdir)/auth/schannel_state_proto.h,$(COMMON_SCHANNELDB_OBJ_FILES:.o=.c)))

