#################################
# Start SUBSYSTEM KERBEROS
[SUBSYSTEM::KERBEROS]
PRIVATE_PROTO_HEADER = proto.h
PUBLIC_DEPENDENCIES = HEIMDAL_KRB5 NDR_KRB5PAC samba-socket LIBCLI_RESOLVE
PRIVATE_DEPENDENCIES = ASN1_UTIL auth_sam_reply LIBPACKET LIBNDR
# End SUBSYSTEM KERBEROS
#################################

KERBEROS_OBJ_FILES = $(addprefix auth/kerberos/, \
	kerberos.o \
	clikrb5.o \
	kerberos_heimdal.o \
	kerberos_pac.o \
	gssapi_parse.o \
	krb5_init_context.o)

