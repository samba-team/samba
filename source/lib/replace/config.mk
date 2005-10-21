##############################
# Start SUBSYSTEM REPLACE_READDIR
[SUBSYSTEM::REPLACE_READDIR]
ADD_OBJ_FILES = \
		repdir/repdir.o
NOPROTO = YES
# End SUBSYSTEM REPLACE_READDIR
##############################


##############################
# Start SUBSYSTEM LIBREPLACE
[SUBSYSTEM::LIBREPLACE]
INIT_OBJ_FILES = replace.o
ADD_OBJ_FILES = \
		snprintf.o \
		dlfcn.o
NOPROTO = YES
REQUIRED_SUBSYSTEMS = REPLACE_READDIR
# End SUBSYSTEM LIBREPLACE
##############################
