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
INIT_OBJ_FILES = \
		netif/interface.o
ADD_OBJ_FILES = \
		netif/netif.o
# End SUBSYSTEM LIBNETIF
##############################

[LIBRARY::TDR]
PUBLIC_HEADERS = tdr/tdr.h
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
INIT_OBJ_FILES = tdr/tdr.o

##############################
# Start SUBSYSTEM LIBCRYPTO
[SUBSYSTEM::LIBCRYPTO]
NOPROTO = YES
INIT_OBJ_FILES = \
		crypto/crc32.o
ADD_OBJ_FILES = \
		crypto/md5.o \
		crypto/hmacmd5.o \
		crypto/md4.o \
		crypto/arcfour.o
# End SUBSYSTEM LIBCRYPTO
##############################

################################################
# Start SUBSYSTEM LIBCOMPRESSION
[SUBSYSTEM::LIBCOMPRESSION]
INIT_OBJ_FILES = \
		compression/mszip.o
# End SUBSYSTEM LIBCOMPRESION
################################################

[SUBSYSTEM::GENCACHE]
OBJ_FILES = \
		gencache.o \

##############################
# Start SUBSYSTEM LIBBASIC
[SUBSYSTEM::LIBBASIC]
INIT_OBJ_FILES = version.o
ADD_OBJ_FILES = \
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
		db_wrap.o \
		gendb.o \
		module.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB CHARSET LIBREPLACE LIBNETIF LIBCRYPTO EXT_LIB_DL LIBTALLOC \
		SOCKET_WRAPPER CONFIG
# End SUBSYSTEM LIBBASIC
##############################

[SUBSYSTEM::PIDFILE]
OBJ_FILES = pidfile.o

[SUBSYSTEM::UNIX_PRIVS]
OBJ_FILES = unix_privs.o
