# utils/net subsystem

#################################
# Start BINARY net
[BINARY::net]
OBJ_FILES = \
		utils/net/net.o \
		utils/net/net_password.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC \
		LIBSMB \
		LIBNET
# End BINARY net
#################################
