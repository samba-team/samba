##############################
# Start SUBSYSTEM LIBCRYPTO
[SUBSYSTEM::LIBCRYPTO]
OBJ_FILES = \
		crc32.o \
		md5.o \
		hmacmd5.o \
		md4.o \
		arcfour.o \
		sha1.o \
		hmacsha1.o
# End SUBSYSTEM LIBCRYPTO
##############################

[MODULE::TORTURE_LIBCRYPTO]
OBJ_FILES = \
		md4test.o \
		md5test.o \
		hmacmd5test.o \
		sha1test.o \
		hmacsha1test.o
SUBSYSTEM = torture
PRIVATE_DEPENDENCIES = LIBCRYPTO
PRIVATE_PROTO_HEADER = test_proto.h


