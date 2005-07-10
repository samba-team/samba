#######################
# Start LIBRARY EJSRPC
[SUBSYSTEM::EJSRPC]
OBJ_FILES = \
		scripting/ejs/ejsrpc.o
REQUIRED_SUBSYSTEMS = RPC_EJS
NOPROTO = YES
# End SUBSYSTEM EJSRPC
#######################

#######################
# Start LIBRARY SMBCALLS
[SUBSYSTEM::SMBCALLS]
OBJ_FILES = \
		scripting/ejs/smbcalls.o \
		scripting/ejs/smbcalls_config.o \
		scripting/ejs/smbcalls_ldb.o \
		scripting/ejs/smbcalls_nbt.o \
		scripting/ejs/smbcalls_cli.o \
		scripting/ejs/smbcalls_rpc.o \
		scripting/ejs/mprutil.o
REQUIRED_SUBSYSTEMS = AUTH EJS LIBBASIC EJSRPC MESSAGING
# End SUBSYSTEM SMBCALLS
#######################

#######################
# Start BINARY SMBSCRIPT
[BINARY::smbscript]
OBJ_FILES = \
		scripting/ejs/smbscript.o
REQUIRED_SUBSYSTEMS = EJS LIBBASIC SMBCALLS CONFIG LIBSMB RPC LIBCMDLINE
# End BINARY SMBSCRIPT
#######################
