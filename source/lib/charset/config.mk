################################################
# Start SUBSYSTEM CHARSET
[SUBSYSTEM::CHARSET]
PRIVATE_PROTO_HEADER = charset_proto.h
PUBLIC_DEPENDENCIES = ICONV
PRIVATE_DEPENDENCIES = DYNCONFIG
# End SUBSYSTEM CHARSET
################################################

CHARSET_OBJ_FILES = $(addprefix lib/charset/, iconv.o charcnv.o util_unistr.o)

PUBLIC_HEADERS += lib/charset/charset.h
