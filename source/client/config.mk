# client subsystem

#################################
# Start BINARY smbclient
[BINARY::smbclient]
INSTALLDIR = BINDIR
OBJ_FILES = \
		client.o
REQUIRED_SUBSYSTEMS = \
		CONFIG \
		LIBREADLINE \
		LIBBASIC \
		LIBSMB \
		RPC_NDR_SRVSVC \
		LIBCLI_LSA \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS
# End BINARY smbclient
#################################
