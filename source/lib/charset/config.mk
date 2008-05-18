################################################
# Start SUBSYSTEM CHARSET
[SUBSYSTEM::CHARSET]
PRIVATE_PROTO_HEADER = charset_proto.h
PUBLIC_DEPENDENCIES = ICONV
PRIVATE_DEPENDENCIES = DYNCONFIG
# End SUBSYSTEM CHARSET
################################################

CHARSET_OBJ_FILES = $(addprefix $(libcharsetsrcdir)/, iconv.o charcnv.o util_unistr.o)

PUBLIC_HEADERS += $(libcharsetsrcdir)/charset.h
