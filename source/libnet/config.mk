#################################
# Start SUBSYSTEM LIBNET
[SUBSYSTEM::LIBNET]
INIT_OBJ_FILES = \
		libnet/libnet.o
ADD_OBJ_FILES = \
		libnet/libnet_passwd.o \
		libnet/libnet_time.o \
		libnet/libnet_rpc.o \
		libnet/libnet_join.o \
		libnet/libnet_vampire.o \
		libnet/libnet_user.o \
		libnet/libnet_share.o \
		libnet/userinfo.o \
		libnet/userman.o
REQUIRED_SUBSYSTEMS = RPC_NDR_SAMR RPC_NDR_SRVSVC LIBCLI_COMPOSITE LIBSAMBA3
# End SUBSYSTEM LIBNET
#################################
