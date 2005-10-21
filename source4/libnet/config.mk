#################################
# Start SUBSYSTEM LIBNET
[SUBSYSTEM::LIBNET]
INIT_OBJ_FILES = \
		libnet.o
ADD_OBJ_FILES = \
		libnet_passwd.o \
		libnet_time.o \
		libnet_rpc.o \
		libnet_join.o \
		libnet_vampire.o \
		libnet_samdump.o \
		libnet_samsync_ldb.o \
		libnet_user.o \
		libnet_share.o \
		libnet_lookup.o \
		userinfo.o \
		userman.o \
		domain.o 
REQUIRED_SUBSYSTEMS = RPC_NDR_SAMR RPC_NDR_LSA RPC_NDR_SRVSVC RPC_NDR_DRSUAPI LIBCLI_COMPOSITE LIBCLI_RESOLVE LIBSAMBA3 LIBCLI_CLDAP
# End SUBSYSTEM LIBNET
#################################
