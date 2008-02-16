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

[SUBSYSTEM::LIBCOMPRESSION]
OBJ_FILES = compression/mszip.o

[SUBSYSTEM::GENCACHE]
PUBLIC_HEADERS = gencache/gencache.h
OBJ_FILES = gencache/gencache.o
PRIVATE_DEPENDENCIES = TDB_WRAP

[SUBSYSTEM::LDB_WRAP]
PUBLIC_HEADERS = ldb_wrap.h
OBJ_FILES = ldb_wrap.o
PUBLIC_DEPENDENCIES = LIBLDB
PRIVATE_DEPENDENCIES = LDBSAMBA UTIL_LDB

[SUBSYSTEM::TDB_WRAP]
PUBLIC_HEADERS = tdb_wrap.h
OBJ_FILES = tdb_wrap.o
PUBLIC_DEPENDENCIES = LIBTDB
