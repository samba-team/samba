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
