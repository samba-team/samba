#################################
# Start SUBSYSTEM GENSEC
[SUBSYSTEM::CREDENTIALS]
OBJ_FILES = credentials.o \
		credentials_files.o \
		credentials_krb5.o \
		credentials_ntlm.o \
		credentials_gensec.o 
REQUIRED_SUBSYSTEMS = \
		HEIMDAL GENSEC
# End SUBSYSTEM CREDENTIALS
#################################

