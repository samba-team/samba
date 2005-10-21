[SUBSYSTEM::CONFIG]
INIT_OBJ_FILES = ../dynconfig.o
ADD_OBJ_FILES = loadparm.o \
				params.o \
				../passdb/secrets.o \
				generic.o
