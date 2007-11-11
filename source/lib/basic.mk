# LIB BASIC subsystem
include samba3/config.mk
include socket/config.mk
include charset/config.mk
include ldb-samba/config.mk
include tls/config.mk
include registry/config.mk
include policy/config.mk
include messaging/config.mk
include events/config.mk
include cmdline/config.mk
include socket_wrapper/config.mk
include nss_wrapper/config.mk
include appweb/config.mk
include stream/config.mk
include util/config.mk
include tdr/config.mk
include dbwrap/config.mk
include crypto/config.mk

################################################
# Start SUBSYSTEM LIBCOMPRESSION
[SUBSYSTEM::LIBCOMPRESSION]
OBJ_FILES = compression/mszip.o
# End SUBSYSTEM LIBCOMPRESION
################################################

[SUBSYSTEM::GENCACHE]
PRIVATE_PROTO_HEADER = gencache/gencache.h
OBJ_FILES = gencache/gencache.o \

[SUBSYSTEM::DB_WRAP]
PUBLIC_PROTO_HEADER = db_wrap_proto.h
PUBLIC_HEADERS = db_wrap.h
OBJ_FILES = db_wrap.o gendb.o
PUBLIC_DEPENDENCIES = LIBTDB LIBLDB
PRIVATE_DEPENDENCIES = LDBSAMBA
