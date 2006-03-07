# LIB BASIC subsystem
include com/config.mk
include samba3/config.mk
include socket/config.mk
include charset/config.mk
include ldb/config.mk
include talloc/config.mk
include tdb/config.mk
include tls/config.mk
include registry/config.mk
include messaging/config.mk
include events/config.mk
include popt/config.mk
include cmdline/config.mk
include socket_wrapper/config.mk
include appweb/config.mk
include replace/config.mk
include stream/config.mk
include util/config.mk
include tdr/config.mk

##############################
# Start SUBSYSTEM LIBNETIF
[SUBSYSTEM::LIBNETIF]
PRIVATE_PROTO_HEADER = netif/proto.h
OBJ_FILES = \
		netif/interface.o \
		netif/netif.o
# End SUBSYSTEM LIBNETIF
##############################

##############################
# Start SUBSYSTEM LIBCRYPTO
[SUBSYSTEM::LIBCRYPTO]
NOPROTO = YES
OBJ_FILES = \
		crypto/crc32.o \
		crypto/md5.o \
		crypto/hmacmd5.o \
		crypto/md4.o \
		crypto/arcfour.o
# End SUBSYSTEM LIBCRYPTO
##############################

################################################
# Start SUBSYSTEM LIBCOMPRESSION
[SUBSYSTEM::LIBCOMPRESSION]
NOPROTO = YES
OBJ_FILES = \
		compression/mszip.o
# End SUBSYSTEM LIBCOMPRESION
################################################

[SUBSYSTEM::GENCACHE]
PRIVATE_PROTO_HEADER = gencache/gencache.h
OBJ_FILES = \
		gencache/gencache.o \

[SUBSYSTEM::DB_WRAP]
PRIVATE_PROTO_HEADER = db_wrap_proto.h
OBJ_FILES = db_wrap.o \
		gendb.o
REQUIRED_SUBSYSTEMS = LIBLDB LIBTDB LDBSAMBA
