#######################
# Start LIBRARY EJSRPC
[SUBSYSTEM::EJSRPC]
OBJ_FILES = \
		ejsrpc.o
NOPROTO = YES
# End SUBSYSTEM EJSRPC
#######################

#######################
# Start LIBRARY SMBCALLS
[SUBSYSTEM::SMBCALLS]
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		smbcalls.o \
		smbcalls_config.o \
		smbcalls_ldb.o \
		smbcalls_nbt.o \
		smbcalls_cli.o \
		smbcalls_rpc.o \
		smbcalls_auth.o \
		smbcalls_options.o \
		smbcalls_nss.o \
		smbcalls_string.o \
		smbcalls_data.o \
		smbcalls_rand.o \
		smbcalls_sys.o \
		smbcalls_creds.o \
		smbcalls_samba3.o \
		smbcalls_param.o \
		ejsnet.o \
		mprutil.o
REQUIRED_SUBSYSTEMS = \
		auth EJS LIBBASIC \
		EJSRPC MESSAGING LIBSAMBA3 \
		LIBNET LIBSMB LIBPOPT \
		POPT_CREDENTIALS POPT_SAMBA \
		dcerpc \
		NDR_ALL \
		RPC_EJS_SECURITY \
		RPC_EJS_LSA \
		RPC_EJS_ECHO \
		RPC_EJS_WINREG \
		RPC_EJS_DFS \
		RPC_EJS_MISC \
		RPC_EJS_EVENTLOG \
		RPC_EJS_SAMR \
		RPC_EJS_WKSSVC \
		RPC_EJS_SRVSVC \
		RPC_EJS_SVCCTL \
		RPC_EJS_INITSHUTDOWN \
		RPC_EJS_NETLOGON \
		RPC_EJS_DRSUAPI \
		RPC_EJS_IRPC
# End SUBSYSTEM SMBCALLS
#######################

#######################
# Start BINARY SMBSCRIPT
[BINARY::smbscript]
INSTALLDIR = BINDIR
OBJ_FILES = \
		smbscript.o
REQUIRED_SUBSYSTEMS = EJS LIBBASIC SMBCALLS CONFIG 
# End BINARY SMBSCRIPT
#######################
