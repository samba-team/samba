[LIBRARY::LIBSAMBA-NET]
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = Convenient high level access to Samba management interfaces
PRIVATE_PROTO_HEADER = libnet_proto.h
PUBLIC_HEADERS = libnet.h libnet_join.h libnet_lookup.h libnet_passwd.h \
				 libnet_rpc.h libnet_share.h libnet_time.h \
				 libnet_user.h libnet_site.h libnet_vampire.h \
				 userinfo.h userman.h
OBJ_FILES = \
		libnet.o \
		libnet_passwd.o \
		libnet_time.o \
		libnet_rpc.o \
		libnet_join.o \
		libnet_site.o \
		libnet_become_dc.o \
		libnet_unbecome_dc.o \
		libnet_vampire.o \
		libnet_samdump.o \
		libnet_samdump_keytab.o \
		libnet_samsync_ldb.o \
		libnet_user.o \
		libnet_group.o \
		libnet_share.o \
		libnet_lookup.o \
		libnet_domain.o \
		userinfo.o \
		groupinfo.o \
		userman.o \
		prereq_domain.o
PUBLIC_DEPENDENCIES = CREDENTIALS dcerpc dcerpc_samr RPC_NDR_LSA RPC_NDR_SRVSVC RPC_NDR_DRSUAPI LIBCLI_COMPOSITE LIBCLI_RESOLVE LIBCLI_FINDDCS LIBSAMBA3 LIBCLI_CLDAP LIBCLI_FINDDCS gensec_schannel
PRIVATE_DEPENDENCIES = CREDENTIALS_KRB5
