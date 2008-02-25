################################################
# Start SUBSYSTEM CHARSET
[SUBSYSTEM::CHARSET]
OBJ_FILES = \
		iconv.o \
		charcnv.o \
		util_unistr.o
PUBLIC_HEADERS = charset.h
PRIVATE_PROTO_HEADER = charset_proto.h
PUBLIC_DEPENDENCIES = ICONV
PRIVATE_DEPENDENCIES = DYNCONFIG
# End SUBSYSTEM CHARSET
################################################
