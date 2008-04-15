##############################
# Start SUBSYSTEM LIBCRYPTO
[SUBSYSTEM::LIBCRYPTO]
# End SUBSYSTEM LIBCRYPTO
##############################

LIBCRYPTO_OBJ_FILES = $(addprefix lib/crypto/, \
					 crc32.o md5.o hmacmd5.o md4.o \
					 arcfour.o sha1.o hmacsha1.o)


[MODULE::TORTURE_LIBCRYPTO]
SUBSYSTEM = torture
PRIVATE_DEPENDENCIES = LIBCRYPTO
PRIVATE_PROTO_HEADER = test_proto.h

TORTURE_LIBCRYPTO_OBJ_FILES = $(addprefix lib/crypto/, \
		md4test.o md5test.o hmacmd5test.o sha1test.o hmacsha1test.o)

