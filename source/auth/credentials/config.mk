#################################
# Start SUBSYSTEM GENSEC
[SUBSYSTEM::CREDENTIALS]
INIT_OBJ_FILES = credentials.o
ADD_OBJ_FILES = credentials_files.o \
		credentials_krb5.o \
		credentials_ntlm.o
REQUIRED_SUBSYSTEMS = \
		HEIMDAL
# End SUBSYSTEM GENSEC
#################################

