##############################
# Start SUBSYSTEM REPLACE_READDIR
[SUBSYSTEM::REPLACE_READDIR]
ADD_OBJ_FILES = \
		lib/replace/repdir/repdir.o
NOPROTO = YES
# End SUBSYSTEM REPLACE_READDIR
##############################


##############################
# Start SUBSYSTEM LIBREPLACE
[SUBSYSTEM::LIBREPLACE]
INIT_OBJ_FILES = lib/replace/replace.o
ADD_OBJ_FILES = \
		lib/replace/snprintf.o
REQUIRED_SUBSYSTEMS = REPLACE_READDIR
# End SUBSYSTEM LIBREPLACE
##############################
