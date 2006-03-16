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
		dlfcn.o \
		getpass.o
REQUIRED_SUBSYSTEMS = REPLACE_READDIR
# End SUBSYSTEM LIBREPLACE
##############################

[SUBSYSTEM::SMBREADLINE]
OBJ_FILES = readline.o
PRIVATE_PROTO_HEADER = readline.h
