[SUBSYSTEM::LIBBASIC]
PRIVATE_PROTO_HEADER = util_proto.h
PUBLIC_HEADERS = util.h
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
		SOCKET_WRAPPER CONFIG

[SUBSYSTEM::PIDFILE]
OBJ_FILES = pidfile.o

[SUBSYSTEM::UNIX_PRIVS]
OBJ_FILES = unix_privs.o
