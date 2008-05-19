################################################
# Start SUBSYSTEM CHARSET
[SUBSYSTEM::CHARSET]
PUBLIC_DEPENDENCIES = ICONV
PRIVATE_DEPENDENCIES = DYNCONFIG
# End SUBSYSTEM CHARSET
################################################

CHARSET_OBJ_FILES = $(addprefix $(libcharsetsrcdir)/, iconv.o charcnv.o util_unistr.o)

PUBLIC_HEADERS += $(libcharsetsrcdir)/charset.h

$(eval $(call proto_header_template,$(libcharsetsrcdir)/charset_proto.h,$(CHARSET_OBJ_FILES:.o=.c)))
