[SUBSYSTEM::CONFIG]
OBJ_FILES = ../dynconfig.o \
				loadparm.o \
				params.o \
				generic.o
REQUIRED_SUBSYSTEMS = LIBBASIC 
PRIVATE_PROTO_HEADER = param.h
