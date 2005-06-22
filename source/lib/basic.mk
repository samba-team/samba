# LIB BASIC subsystem

##############################
# Start SUBSYSTEM LIBNETIF
[SUBSYSTEM::LIBNETIF]
INIT_OBJ_FILES = \
		lib/netif/interface.o
ADD_OBJ_FILES = \
		lib/netif/netif.o
# End SUBSYSTEM LIBNETIF
##############################

##############################
# Start SUBSYSTEM LIBCRYPTO
[SUBSYSTEM::LIBCRYPTO]
NOPROTO = YES
INIT_OBJ_FILES = \
		lib/crypto/crc32.o
ADD_OBJ_FILES = \
		lib/crypto/md5.o \
		lib/crypto/hmacmd5.o \
		lib/crypto/md4.o
# End SUBSYSTEM LIBCRYPTO
##############################

################################################
# Start SUBSYSTEM LIBCOMPRESSION
[SUBSYSTEM::LIBCOMPRESSION]
INIT_OBJ_FILES = \
		lib/compression/mszip.o
# End SUBSYSTEM LIBCOMPRESION
################################################


################################################
# Start SUBSYSTEM LIBSAMBA3
[SUBSYSTEM::LIBSAMBA3]
INIT_OBJ_FILES = \
		lib/samba3/smbpasswd.o
# End SUBSYSTEM LIBSAMBA3
################################################

[SUBSYSTEM::PAM_ERRORS]
OBJ_FILES = lib/pam_errors.o

[SUBSYSTEM::GENCACHE]
OBJ_FILES = \
		lib/gencache.o \

##############################
# Start SUBSYSTEM LIBBASIC
[SUBSYSTEM::LIBBASIC]
INIT_OBJ_FILES = lib/version.o
ADD_OBJ_FILES = \
		lib/xfile.o \
		lib/debug.o \
		lib/fault.o \
		lib/pidfile.o \
		lib/signal.o \
		lib/system.o \
		lib/time.o \
		lib/genrand.o \
		lib/dprintf.o \
		lib/util_str.o \
		lib/util_strlist.o \
		lib/util_unistr.o \
		lib/util_file.o \
		lib/data_blob.o \
		lib/util.o \
		lib/util_sock.o \
		lib/substitute.o \
		lib/fsusage.o \
		lib/ms_fnmatch.o \
		lib/select.o \
		lib/mutex.o \
		lib/idtree.o \
		lib/unix_privs.o \
		lib/db_wrap.o \
		lib/gendb.o \
		lib/credentials.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB CHARSET LIBREPLACE LIBNETIF LIBCRYPTO EXT_LIB_DL LIBTALLOC \
		SOCKET_WRAPPER CONFIG
# End SUBSYSTEM LIBBASIC
##############################

