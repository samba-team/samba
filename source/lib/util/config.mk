[SUBSYSTEM::LIBSAMBA-UTIL]
#VERSION = 0.0.1
#SO_VERSION = 0
PUBLIC_DEPENDENCIES = \
		LIBTALLOC LIBCRYPTO \
		SOCKET_WRAPPER EXT_NSL \
		CHARSET EXECINFO

LIBSAMBA-UTIL_OBJ_FILES = $(addprefix lib/util/, \
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
		util_file.o \
		data_blob.o \
		util.o \
		fsusage.o \
		ms_fnmatch.o \
		mutex.o \
		idtree.o \
		become_daemon.o)

PUBLIC_HEADERS += $(addprefix lib/util/, util.h \
				 attr.h \
				 byteorder.h \
				 data_blob.h \
				 debug.h \
				 mutex.h \
				 safe_string.h \
				 time.h \
				 xfile.h)

[SUBSYSTEM::ASN1_UTIL]
PRIVATE_PROTO_HEADER = asn1_proto.h


ASN1_UTIL_OBJ_FILES = lib/util/asn1.o
PUBLIC_HEADERS += lib/util/asn1.h

[SUBSYSTEM::UNIX_PRIVS]
PRIVATE_PROTO_HEADER = unix_privs.h

UNIX_PRIVS_OBJ_FILES = lib/util/unix_privs.o

################################################
# Start SUBSYSTEM WRAP_XATTR
[SUBSYSTEM::WRAP_XATTR]
PRIVATE_PROTO_HEADER = wrap_xattr.h
PUBLIC_DEPENDENCIES = XATTR
#
# End SUBSYSTEM WRAP_XATTR
################################################

WRAP_XATTR_OBJ_FILES = lib/util/wrap_xattr.o

[SUBSYSTEM::UTIL_TDB]
PRIVATE_PROTO_HEADER = util_tdb.h
PUBLIC_DEPENDENCIES = LIBTDB

UTIL_TDB_OBJ_FILES = lib/util/util_tdb.o

[SUBSYSTEM::UTIL_LDB]
PRIVATE_PROTO_HEADER = util_ldb.h
PUBLIC_DEPENDENCIES = LIBLDB

UTIL_LDB_OBJ_FILES = lib/util/util_ldb.o
