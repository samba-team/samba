[SUBSYSTEM::LIBSAMBA-UTIL]
#VERSION = 0.0.1
#SO_VERSION = 0
#DESCRIPTION = Generic utility functions
PUBLIC_PROTO_HEADER = util_proto.h
PUBLIC_HEADERS = util.h \
				 byteorder.h \
				 debug.h \
				 mutex.h \
				 safe_string.h \
				 xfile.h
OBJ_FILES = xfile.o \
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
		module.o
PUBLIC_DEPENDENCIES = \
		LIBTALLOC LIBCRYPTO \
		SOCKET_WRAPPER EXT_NSL \
		CHARSET

[SUBSYSTEM::UNIX_PRIVS]
PRIVATE_PROTO_HEADER = unix_privs.h
OBJ_FILES = unix_privs.o

################################################
# Start SUBSYSTEM WRAP_XATTR
[SUBSYSTEM::WRAP_XATTR]
PUBLIC_PROTO_HEADER = wrap_xattr.h
OBJ_FILES = \
		wrap_xattr.o
PUBLIC_DEPENDENCIES = XATTR
#
# End SUBSYSTEM WRAP_XATTR
################################################

################################################
# Start SUBSYSTEM UTIL_TDB
[SUBSYSTEM::UTIL_TDB]
PUBLIC_PROTO_HEADER = util_tdb.h
OBJ_FILES = \
		util_tdb.o
PUBLIC_DEPENDENCIES = LIBTDB
# End SUBSYSTEM UTIL_TDB
################################################
