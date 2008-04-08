#################################
# Start SUBSYSTEM CREDENTIALS
[SUBSYSTEM::CREDENTIALS]
PRIVATE_PROTO_HEADER = credentials_proto.h
PUBLIC_DEPENDENCIES = \
		LIBCLI_AUTH SECRETS LIBCRYPTO KERBEROS UTIL_LDB HEIMDAL_GSSAPI 
PRIVATE_DEPENDENCIES = \
		SECRETS

CREDENTIALS_OBJ_FILES = $(addprefix auth/credentials/, credentials.o credentials_files.o credentials_ntlm.o credentials_krb5.o ../kerberos/kerberos_util.o)

PUBLIC_HEADERS += auth/credentials/credentials.h

[PYTHON::swig_credentials]
PUBLIC_DEPENDENCIES = CREDENTIALS LIBCMDLINE_CREDENTIALS
SWIG_FILE = credentials.i

swig_credentials_OBJ_FILES = auth/credentials/credentials_wrap.o
