#################################
# Start SUBSYSTEM CREDENTIALS
[SUBSYSTEM::CREDENTIALS]
PUBLIC_PROTO_HEADER = credentials_proto.h
PUBLIC_HEADERS = credentials.h
OBJ_FILES = credentials.o \
		credentials_files.o \
		credentials_ntlm.o
PUBLIC_DEPENDENCIES = \
		LIBCLI_AUTH SECRETS LIBCRYPTO KERBEROS
PRIVATE_DEPENDENCIES = CREDENTIALS_KRB5
# End SUBSYSTEM CREDENTIALS
#################################

#################################
# Start SUBSYSTEM CREDENTIALS
[SUBSYSTEM::CREDENTIALS_KRB5]
PUBLIC_PROTO_HEADER = credentials_krb5_proto.h
PUBLIC_HEADERS = credentials_krb5.h
OBJ_FILES = credentials_krb5.o
PUBLIC_DEPENDENCIES = \
		HEIMDAL_GSSAPI
# End SUBSYSTEM CREDENTIALS
#################################
