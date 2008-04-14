[SUBSYSTEM::EJSRPC]

EJSRPC_OBJ_FILES = scripting/ejs/ejsrpc.o

[MODULE::smbcalls_config]
OUTPUT_TYPE = MERGED_OBJ
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_config

smbcalls_config_OBJ_FILES = scripting/ejs/smbcalls_config.o

[MODULE::smbcalls_ldb]
OUTPUT_TYPE = MERGED_OBJ
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_ldb
PRIVATE_DEPENDENCIES = LIBLDB SAMDB LIBNDR

smbcalls_ldb_OBJ_FILES = scripting/ejs/smbcalls_ldb.o

[MODULE::smbcalls_reg]
SUBSYSTEM = smbcalls
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = smb_setup_ejs_reg
PRIVATE_DEPENDENCIES = registry SAMDB LIBNDR

smbcalls_reg_OBJ_FILES = scripting/ejs/smbcalls_reg.o

[MODULE::smbcalls_nbt]
SUBSYSTEM = smbcalls
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = smb_setup_ejs_nbt

smbcalls_nbt_OBJ_FILES = scripting/ejs/smbcalls_nbt.o

[MODULE::smbcalls_rand]
SUBSYSTEM = smbcalls
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = smb_setup_ejs_random

smbcalls_rand_OBJ_FILES = scripting/ejs/smbcalls_rand.o

[MODULE::smbcalls_nss]
SUBSYSTEM = smbcalls
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = smb_setup_ejs_nss
PRIVATE_DEPENDENCIES = NSS_WRAPPER

smbcalls_nss_OBJ_FILES = scripting/ejs/smbcalls_nss.o

[MODULE::smbcalls_data]
SUBSYSTEM = smbcalls
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = smb_setup_ejs_datablob

smbcalls_data_OBJ_FILES = scripting/ejs/smbcalls_data.o

[MODULE::smbcalls_auth]
OUTPUT_TYPE = MERGED_OBJ
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_auth
PRIVATE_DEPENDENCIES = auth

smbcalls_auth_OBJ_FILES = scripting/ejs/smbcalls_auth.o

[MODULE::smbcalls_string]
SUBSYSTEM = smbcalls
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = smb_setup_ejs_string

smbcalls_string_OBJ_FILES = scripting/ejs/smbcalls_string.o

[MODULE::smbcalls_sys]
SUBSYSTEM = smbcalls
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = smb_setup_ejs_system

smbcalls_sys_OBJ_FILES = scripting/ejs/smbcalls_sys.o

mkinclude ejsnet/config.mk

[SUBSYSTEM::smbcalls]
PRIVATE_PROTO_HEADER = proto.h
PRIVATE_DEPENDENCIES = \
		EJS LIBSAMBA-UTIL \
		EJSRPC MESSAGING \
		LIBSAMBA-NET LIBCLI_SMB LIBPOPT \
		CREDENTIALS POPT_CREDENTIALS POPT_SAMBA \
		dcerpc \
		NDR_TABLE

smbcalls_OBJ_FILES = $(addprefix scripting/ejs/, \
		smbcalls.o \
		smbcalls_cli.o \
		smbcalls_rpc.o \
		smbcalls_options.o \
		smbcalls_creds.o \
		smbcalls_param.o \
		mprutil.o \
		literal.o)

#######################
# Start BINARY SMBSCRIPT
[BINARY::smbscript]
PRIVATE_DEPENDENCIES = EJS LIBSAMBA-UTIL smbcalls LIBSAMBA-HOSTCONFIG
# End BINARY SMBSCRIPT
#######################

smbscript_OBJ_FILES = scripting/ejs/smbscript.o
