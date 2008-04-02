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
OBJ_FILES = compression/mszip.o

[SUBSYSTEM::GENCACHE]
OBJ_FILES = gencache/gencache.o
PRIVATE_DEPENDENCIES = TDB_WRAP


# PUBLIC_HEADERS += lib/gencache/gencache.h

[SUBSYSTEM::LDB_WRAP]
OBJ_FILES = ldb_wrap.o
PUBLIC_DEPENDENCIES = LIBLDB
PRIVATE_DEPENDENCIES = LDBSAMBA UTIL_LDB


PUBLIC_HEADERS += lib/ldb_wrap.h

[SUBSYSTEM::TDB_WRAP]
OBJ_FILES = tdb_wrap.o
PUBLIC_DEPENDENCIES = LIBTDB


PUBLIC_HEADERS += lib/tdb_wrap.h
