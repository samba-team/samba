################################################
# Start SUBSYSTEM CHARSET
[SUBSYSTEM::CHARSET]
OBJ_FILES = \
		iconv.o \
		charcnv.o \
		util_unistr.o
PRIVATE_PROTO_HEADER = charset_proto.h
PUBLIC_DEPENDENCIES = ICONV
PRIVATE_DEPENDENCIES = DYNCONFIG
# End SUBSYSTEM CHARSET
################################################


PUBLIC_HEADERS += lib/charset/charset.h
