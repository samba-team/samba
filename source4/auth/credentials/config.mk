#################################
# Start SUBSYSTEM CREDENTIALS
[SUBSYSTEM::CREDENTIALS]
PRIVATE_PROTO_HEADER = credentials_proto.h
PUBLIC_HEADERS = credentials.h credentials_krb5.h
OBJ_FILES = credentials.o \
		credentials_files.o \
		credentials_ntlm.o \
		credentials_krb5.o \
		../kerberos/kerberos_util.o
PUBLIC_DEPENDENCIES = \
		LIBCLI_AUTH SECRETS LIBCRYPTO KERBEROS UTIL_LDB HEIMDAL_GSSAPI 
PRIVATE_DEPENDENCIES = \
		SECRETS

[PYTHON::swig_credentials]
PUBLIC_DEPENDENCIES = CREDENTIALS LIBCMDLINE_CREDENTIALS
SWIG_FILE = credentials.i
