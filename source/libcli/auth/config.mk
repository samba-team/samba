#################################
# Start SUBSYSTEM LIBCLI_AUTH
[SUBSYSTEM::LIBCLI_AUTH]
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = credentials.o \
		session.o \
		smbencrypt.o 
REQUIRED_SUBSYSTEMS = \
		AUTH SCHANNELDB gensec_ntlmssp
# End SUBSYSTEM LIBCLI_AUTH
#################################
