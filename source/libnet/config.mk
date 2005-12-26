#################################
# Start SUBSYSTEM LIBNET
[LIBRARY::LIBNET]
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
DESCRIPTION = User-friendly access to Samba interfaces
PUBLIC_HEADERS = libnet.h libnet_join.h libnet_lookup.h libnet_passwd.h \
				 libnet_rpc.h libnet_share.h libnet_time.h libnet_user.h \
				 libnet_vampire.h userinfo.h userman.h
OBJ_FILES = \
		libnet.o \
		libnet_passwd.o \
		libnet_time.o \
		libnet_rpc.o \
		libnet_join.o \
		libnet_vampire.o \
		libnet_samdump.o \
		libnet_samdump_keytab.o \
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
