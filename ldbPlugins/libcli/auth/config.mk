#################################
# Start SUBSYSTEM GENSEC
[SUBSYSTEM::LIBCLI_AUTH]
ADD_OBJ_FILES = libcli/auth/schannel.o \
		libcli/auth/credentials.o \
		libcli/auth/session.o 
REQUIRED_SUBSYSTEMS = \
		AUTH SCHANNELDB GENSEC
# End SUBSYSTEM LIBCLI_AUTH
#################################
