[SUBSYSTEM::CONFIG]
OBJ_FILES = ../dynconfig.o \
				loadparm.o \
				params.o \
				generic.o
REQUIRED_SUBSYSTEMS = LIBBASIC 
PRIVATE_PROTO_HEADER = param.h

dynconfig.o: dynconfig.c Makefile
	@echo Compiling $<
	@$(CC) $(CFLAGS) $(PICFLAG) $(PATH_FLAGS) -c $< -o $@
