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

##############################
# Start SUBSYSTEM LIBNETIF
[SUBSYSTEM::LIBNETIF]
OBJ_FILES = \
		netif/interface.o \
		netif/netif.o
# End SUBSYSTEM LIBNETIF
##############################

[LIBRARY::TDR]
PUBLIC_HEADERS = tdr/tdr.h
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
DESCRIPTION = Simple marshall/unmarshall library
PRIVATE_PROTO_HEADER = tdr/tdr_proto.h
OBJ_FILES = tdr/tdr.o

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
OBJ_FILES = \
		compression/mszip.o
# End SUBSYSTEM LIBCOMPRESION
################################################

[SUBSYSTEM::GENCACHE]
PRIVATE_PROTO_HEADER = gencache.h
OBJ_FILES = \
		gencache.o \

##############################
# Start SUBSYSTEM LIBBASIC
[SUBSYSTEM::LIBBASIC]
PRIVATE_PROTO_HEADER = basic.h
OBJ_FILES = version.o \
		xfile.o \
		debug.o \
		fault.o \
		signal.o \
		system.o \
		time.o \
		genrand.o \
		dprintf.o \
		util_str.o \
		util_strlist.o \
		util_unistr.o \
		util_file.o \
		data_blob.o \
		util.o \
		util_sock.o \
		substitute.o \
		fsusage.o \
		ms_fnmatch.o \
		select.o \
		mutex.o \
		idtree.o \
		module.o
REQUIRED_SUBSYSTEMS = \
		CHARSET LIBREPLACE LIBNETIF LIBCRYPTO EXT_LIB_DL LIBTALLOC \
		SOCKET_WRAPPER CONFIG
# End SUBSYSTEM LIBBASIC
##############################

[SUBSYSTEM::DB_WRAP]
OBJ_FILES = db_wrap.o \
		gendb.o
REQUIRED_SUBSYSTEMS = LIBLDB LIBTDB

[SUBSYSTEM::PIDFILE]
OBJ_FILES = pidfile.o

[SUBSYSTEM::UNIX_PRIVS]
OBJ_FILES = unix_privs.o
