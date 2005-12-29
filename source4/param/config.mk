[SUBSYSTEM::CONFIG]
OBJ_FILES = ../dynconfig.o \
				loadparm.o \
				params.o \
				../passdb/secrets.o \
				generic.o
REQUIRED_SUBSYSTEMS = LIBBASIC DB_WRAP
