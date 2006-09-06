# client subsystem

#################################
# Start BINARY smbclient
[BINARY::smbclient]
INSTALLDIR = BINDIR
OBJ_FILES = \
		client.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		SMBREADLINE \
		LIBSAMBA-UTIL \
		LIBCLI_SMB \
		RPC_NDR_SRVSVC \
		LIBCLI_LSA \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS
# End BINARY smbclient
#################################

#################################
# Start BINARY cifsdd
[BINARY::cifsdd]
INSTALLDIR = BINDIR
OBJ_FILES = \
		cifsdd.o \
		cifsddio.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG \
		LIBCLI_SMB \
		LIBPOPT \
		POPT_SAMBA \
		POPT_CREDENTIALS
# End BINARY sdd
#################################

