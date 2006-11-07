#################################
# Start SUBSYSTEM KERBEROS
[SUBSYSTEM::KERBEROS]
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = kerberos.o \
			clikrb5.o \
			kerberos_verify.o \
			kerberos_util.o \
			kerberos_pac.o \
			gssapi_parse.o \
			krb5_init_context.o
PUBLIC_DEPENDENCIES = HEIMDAL_KRB5 NDR_KRB5PAC samba-socket LIBCLI_RESOLVE
PRIVATE_DEPENDENCIES = ASN1_UTIL HEIMDAL_ROKEN_ADDRINFO auth_sam CREDENTIALS_KRB5
# End SUBSYSTEM KERBEROS
#################################
