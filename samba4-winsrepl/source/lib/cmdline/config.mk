##############################
# Start SUBSYSTEM LIBCMDLINE_CREDENTIALS
[SUBSYSTEM::LIBCMDLINE_CREDENTIALS]
ADD_OBJ_FILES = lib/cmdline/getsmbpass.o \
		lib/cmdline/credentials.o
REQUIRED_SUBSYSTEMS = CREDENTIALS
# End SUBSYSTEM LIBCMDLINE_CREDENTIALS
##############################
