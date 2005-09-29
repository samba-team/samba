#################################
# Start SUBSYSTEM GENSEC
[SUBSYSTEM::CREDENTIALS]
INIT_OBJ_FILES = auth/credentials/credentials.o
ADD_OBJ_FILES = auth/credentials/credentials_files.o \
		auth/credentials/credentials_krb5.o
REQUIRED_SUBSYSTEMS = \
		HEIMDAL
# End SUBSYSTEM GENSEC
#################################

