[MODULE::smbcalls_net]
OBJ_FILES = \
		net_ctx.o \
		net_user.o \
		mpr_user.o
SUBSYSTEM = smbcalls
INIT_FUNCTION = smb_setup_ejs_net
PRIVATE_PROTO_HEADER = proto.h
PRIVATE_DEPENDENCIES = LIBSAMBA-NET LIBCLI_SMB CREDENTIALS
