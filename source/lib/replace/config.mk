##############################
# Start SUBSYSTEM REPLACE_READDIR
[SUBSYSTEM::REPLACE_READDIR]
OBJ_FILES = \
		repdir/repdir.o
NOPROTO = YES
# End SUBSYSTEM REPLACE_READDIR
##############################


##############################
# Start SUBSYSTEM LIBREPLACE
[SUBSYSTEM::LIBREPLACE]
OBJ_FILES = replace.o \
		snprintf.o \
		dlfcn.o
NOPROTO = YES
REQUIRED_SUBSYSTEMS = REPLACE_READDIR
# End SUBSYSTEM LIBREPLACE
##############################
