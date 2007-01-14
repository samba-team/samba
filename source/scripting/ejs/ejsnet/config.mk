#######################
# Start LIBRARY EJSNET
[LIBRARY::EJSNET]
SO_VERSION = 0
VERSION = 0.0.1
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		net_ctx.o \
		net_user.o \
		mpr_user.o
PUBLIC_DEPENDENCIES = LIBSAMBA-NET LIBCLI_SMB CREDENTIALS
# End SUBSYSTEM ejsnet
#######################
