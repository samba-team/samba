# client subsystem

#################################
# Start BINARY smbclient
[BINARY::smbclient]
OBJ_FILES = \
		client/client.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC \
		LIBSMB \
		RPC_NDR_SRVSVC \
		LIBCLI_LSA
# End BINARY smbclient
#################################
