################################################
# Start SUBSYSTEM CHARSET
[SUBSYSTEM::CHARSET]
OBJ_FILES = \
		iconv.o \
		charcnv.o
PRIVATE_PROTO_HEADER = charset_proto.h
REQUIRED_SUBSYSTEMS = EXT_LIB_ICONV
# End SUBSYSTEM CHARSET
################################################
