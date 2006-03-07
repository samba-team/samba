################################################
# Start MODULE gensec_ntlmssp
[MODULE::gensec_ntlmssp]
SUBSYSTEM = gensec
NOPROTO = NO
INIT_FUNCTION = gensec_ntlmssp_init
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = ntlmssp.o \
		ntlmssp_sign.o \
		ntlmssp_client.o \
		ntlmssp_parse.o \
		ntlmssp_server.o
REQUIRED_SUBSYSTEMS = auth
# End MODULE gensec_ntlmssp
################################################
