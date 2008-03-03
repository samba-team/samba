[SUBSYSTEM::LIBSAMBA-NET]
PRIVATE_PROTO_HEADER = libnet_proto.h
PUBLIC_DEPENDENCIES = CREDENTIALS dcerpc dcerpc_samr RPC_NDR_LSA RPC_NDR_SRVSVC RPC_NDR_DRSUAPI LIBCLI_COMPOSITE LIBCLI_RESOLVE LIBCLI_FINDDCS LIBCLI_CLDAP LIBCLI_FINDDCS gensec_schannel LIBCLI_AUTH LIBNDR SMBPASSWD

LIBSAMBA-NET_OBJ_FILES = $(addprefix libnet/, \
	libnet.o libnet_passwd.o libnet_time.o libnet_rpc.o \
	libnet_join.o libnet_site.o libnet_become_dc.o libnet_unbecome_dc.o \
	libnet_vampire.o libnet_samdump.o libnet_samdump_keytab.o \
	libnet_samsync_ldb.o libnet_user.o libnet_group.o libnet_share.o \
	libnet_lookup.o libnet_domain.o userinfo.o groupinfo.o userman.o \
	groupman.o prereq_domain.o)

PUBLIC_HEADERS += $(addprefix libnet/, libnet.h libnet_join.h libnet_lookup.h libnet_passwd.h \
				 libnet_rpc.h libnet_share.h libnet_time.h \
				 libnet_user.h libnet_site.h libnet_vampire.h \
				 userinfo.h userman.h)


[PYTHON::swig_net]
PRIVATE_DEPENDENCIES = LIBSAMBA-NET
SWIG_FILE = net.i
