# utils subsystem

#################################
# Start BINARY ndrdump
[BINARY::ndrdump]
OBJ_FILES = \
		utils/ndrdump.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC \
		LIBSMB
# End BINARY ndrdump
#################################
