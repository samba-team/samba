################################################
# Start SUBSYSTEM CHARSET
[SUBSYSTEM::CHARSET]
OBJ_FILES = \
		iconv.o \
		charcnv.o \
		util_unistr.o
PUBLIC_HEADERS = charset.h
PUBLIC_PROTO_HEADER = charset_proto.h
PUBLIC_DEPENDENCIES = ICONV LIBREPLACE
# End SUBSYSTEM CHARSET
################################################
