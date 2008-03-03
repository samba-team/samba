# LIB BASIC subsystem
mkinclude samba3/config.mk
mkinclude socket/config.mk
mkinclude charset/config.mk
mkinclude ldb-samba/config.mk
mkinclude tls/config.mk
mkinclude registry/config.mk
mkinclude policy/config.mk
mkinclude messaging/config.mk
mkinclude events/config.mk
mkinclude cmdline/config.mk
mkinclude socket_wrapper/config.mk
mkinclude nss_wrapper/config.mk
mkinclude appweb/config.mk
mkinclude stream/config.mk
mkinclude util/config.mk
mkinclude tdr/config.mk
mkinclude dbwrap/config.mk
mkinclude crypto/config.mk

[SUBSYSTEM::LIBCOMPRESSION]

LIBCOMPRESSION_OBJ_FILES = lib/compression/mszip.o

[SUBSYSTEM::GENCACHE]
PRIVATE_DEPENDENCIES = TDB_WRAP

GENCACHE_OBJ_FILES = gencache/gencache.o

PUBLIC_HEADERS += lib/gencache/gencache.h

[SUBSYSTEM::LDB_WRAP]
PUBLIC_DEPENDENCIES = LIBLDB
PRIVATE_DEPENDENCIES = LDBSAMBA UTIL_LDB

LDB_WRAP_OBJ_FILES = lib/ldb_wrap.o
PUBLIC_HEADERS += lib/ldb_wrap.h

[SUBSYSTEM::TDB_WRAP]
PUBLIC_DEPENDENCIES = LIBTDB

TDB_WRAP_OBJ_FILES = lib/tdb_wrap.o
PUBLIC_HEADERS += lib/tdb_wrap.h
