[LIBRARY::LIBSAMBA-CONFIG]
DESCRIPTION = Reading Samba configuration files
VERSION = 0.0.1
SO_VERSION = 0
OBJ_FILES = loadparm.o \
			params.o \
			generic.o \
			../lib/version.o
REQUIRED_SUBSYSTEMS = LIBSAMBA-UTIL DYNCONFIG
PRIVATE_PROTO_HEADER = proto.h


