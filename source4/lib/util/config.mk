[LIBRARY::LIBBASIC]
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = Generic utility functions
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
		CHARSET LIBREPLACE LIBCRYPTO EXT_LIB_DL LIBTALLOC \
		SOCKET_WRAPPER CONFIG \
# for the base64 functions
		ldb 

[SUBSYSTEM::PIDFILE]
PRIVATE_PROTO_HEADER = pidfile.h
OBJ_FILES = pidfile.o

[SUBSYSTEM::UNIX_PRIVS]
PRIVATE_PROTO_HEADER = unix_privs.h
OBJ_FILES = unix_privs.o
