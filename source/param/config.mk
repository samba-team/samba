[SUBSYSTEM::CONFIG]
OBJ_FILES = loadparm.o \
			params.o \
			generic.o \
			../lib/version.o
REQUIRED_SUBSYSTEMS = LIBBASIC DYNCONFIG
PRIVATE_PROTO_HEADER = proto.h


