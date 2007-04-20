#######################
# Start LIBRARY EJSRPC
[SUBSYSTEM::EJSRPC]
OBJ_FILES = \
		ejsrpc.o
# End SUBSYSTEM EJSRPC
#######################

[MODULE::smbcalls_config]
OBJ_FILES = smbcalls_config.o
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_config

[MODULE::smbcalls_ldb]
OBJ_FILES = smbcalls_ldb.o
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_ldb

[MODULE::smbcalls_nbt]
OBJ_FILES = smbcalls_nbt.o
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_nbt

[MODULE::smbcalls_samba3]
OBJ_FILES = smbcalls_samba3.o
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_samba3
PRIVATE_DEPENDENCIES = LIBSAMBA3 

[MODULE::smbcalls_rand]
OBJ_FILES = smbcalls_rand.o
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_random

[MODULE::smbcalls_nss]
OBJ_FILES = smbcalls_nss.o
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_nss

[MODULE::smbcalls_data]
OBJ_FILES = smbcalls_data.o
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_datablob

[MODULE::smbcalls_auth]
OBJ_FILES = smbcalls_auth.o
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_auth
PRIVATE_DEPENDENCIES = auth

[MODULE::smbcalls_string]
OBJ_FILES = smbcalls_string.o
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_string

[MODULE::smbcalls_sys]
OBJ_FILES = smbcalls_sys.o
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_system

include ejsnet/config.mk

#######################
# Start LIBRARY smbcalls
[LIBRARY::smbcalls]
SO_VERSION = 0
VERSION = 0.0.1
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		smbcalls.o \
		smbcalls_cli.o \
		smbcalls_rpc.o \
		smbcalls_options.o \
		smbcalls_creds.o \
		smbcalls_param.o \
		mprutil.o \
		literal.o
PRIVATE_DEPENDENCIES = \
		EJS LIBSAMBA-UTIL \
		EJSRPC MESSAGING \
		LIBSAMBA-NET LIBCLI_SMB LIBPOPT \
		CREDENTIALS POPT_CREDENTIALS POPT_SAMBA \
		dcerpc \
		NDR_TABLE
# End SUBSYSTEM smbcalls
#######################

#######################
# Start BINARY SMBSCRIPT
[BINARY::smbscript]
INSTALLDIR = BINDIR
OBJ_FILES = \
		smbscript.o
PRIVATE_DEPENDENCIES = EJS LIBSAMBA-UTIL smbcalls LIBSAMBA-CONFIG
# End BINARY SMBSCRIPT
#######################
