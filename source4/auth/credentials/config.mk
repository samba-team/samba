#################################
# Start SUBSYSTEM GENSEC
[SUBSYSTEM::CREDENTIALS]
PRIVATE_PROTO_HEADER = credentials_proto.h
OBJ_FILES = credentials.o \
		credentials_files.o \
		credentials_krb5.o \
		credentials_ntlm.o \
		credentials_gensec.o 
REQUIRED_SUBSYSTEMS = \
		HEIMDAL GENSEC LIBCLI_AUTH LIBLDB
# End SUBSYSTEM CREDENTIALS
#################################

