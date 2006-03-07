#################################
# Start SUBSYSTEM gensec
[SUBSYSTEM::CREDENTIALS]
PRIVATE_PROTO_HEADER = credentials_proto.h
OBJ_FILES = credentials.o \
		credentials_files.o \
		credentials_krb5.o \
		credentials_ntlm.o
REQUIRED_SUBSYSTEMS = \
		HEIMDAL LIBCLI_AUTH ldb SECRETS
# End SUBSYSTEM CREDENTIALS
#################################

