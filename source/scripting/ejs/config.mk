[MODULE::smbcalls_config]
OUTPUT_TYPE = MERGED_OBJ
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_config

smbcalls_config_OBJ_FILES = $(ejsscriptsrcdir)/smbcalls_config.o

[MODULE::smbcalls_ldb]
OUTPUT_TYPE = MERGED_OBJ
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_ldb
PRIVATE_DEPENDENCIES = LIBLDB SAMDB LIBNDR

smbcalls_ldb_OBJ_FILES = $(ejsscriptsrcdir)/smbcalls_ldb.o

[MODULE::smbcalls_auth]
OUTPUT_TYPE = MERGED_OBJ
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_auth
PRIVATE_DEPENDENCIES = service_auth

smbcalls_auth_OBJ_FILES = $(ejsscriptsrcdir)/smbcalls_auth.o

smbcalls_auth_OBJ_FILES = $(ejsscriptsrcdir)/smbcalls_auth.o

[MODULE::smbcalls_string]
SUBSYSTEM = smbcalls
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = smb_setup_ejs_string

smbcalls_string_OBJ_FILES = $(ejsscriptsrcdir)/smbcalls_string.o

[MODULE::smbcalls_sys]
SUBSYSTEM = smbcalls
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = smb_setup_ejs_system

smbcalls_sys_OBJ_FILES = $(ejsscriptsrcdir)/smbcalls_sys.o

[SUBSYSTEM::smbcalls]
PRIVATE_DEPENDENCIES = \
		EJS LIBSAMBA-UTIL \
		MESSAGING \
		LIBSAMBA-NET LIBCLI_SMB LIBPOPT \
		CREDENTIALS POPT_CREDENTIALS POPT_SAMBA \
		NDR_TABLE

smbcalls_OBJ_FILES = $(addprefix $(ejsscriptsrcdir)/, \
		smbcalls.o \
		smbcalls_options.o \
		smbcalls_creds.o \
		mprutil.o)

$(eval $(call proto_header_template,$(ejsscriptsrcdir)/proto.h,$(smbcalls_OBJ_FILES:.o=.c)))

#######################
# Start BINARY SMBSCRIPT
[BINARY::smbscript]
PRIVATE_DEPENDENCIES = EJS LIBSAMBA-UTIL smbcalls LIBSAMBA-HOSTCONFIG
# End BINARY SMBSCRIPT
#######################

smbscript_OBJ_FILES = $(ejsscriptsrcdir)/smbscript.o
