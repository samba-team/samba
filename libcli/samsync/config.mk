[SUBSYSTEM::LIBCLI_SAMSYNC]
PUBLIC_DEPENDENCIES = \
		LIBCLI_AUTH

LIBCLI_SAMSYNC_OBJ_FILES = $(addprefix $(libclicommonsrcdir)/samsync/, \
		decrypt.o)

PUBLIC_HEADERS += ../libcli/samsync/samsync.h

$(eval $(call proto_header_template,$(libclicommonsrcdir)/samsync/samsync.h,$(LIBCLI_SAMSYNC_OBJ_FILES:.o=.c)))
