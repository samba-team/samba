# client subsystem

#################################
# Start BINARY smbclient
[BINARY::smbclient]
OBJ_FILES = \
		client/client.o \
		client/clitar.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC \
		LIBSMB \
		RPC_NDR_SRVSVC
# End BINARY smbclient
#################################
