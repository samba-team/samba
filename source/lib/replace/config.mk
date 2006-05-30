##############################
# Start SUBSYSTEM REPLACE_READDIR
[SUBSYSTEM::REPLACE_READDIR]
OBJ_FILES = \
		repdir/repdir.o
# End SUBSYSTEM REPLACE_READDIR
##############################

##############################
# Start SUBSYSTEM LIBREPLACE
[SUBSYSTEM::LIBREPLACE]
OBJ_FILES = replace.o \
		snprintf.o \
		timegm.o \
		dlfcn.o \
		getpass.o
PUBLIC_DEPENDENCIES = REPLACE_READDIR
# End SUBSYSTEM LIBREPLACE
##############################
