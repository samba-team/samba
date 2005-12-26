################################################
# Start MODULE gensec_ntlmssp
[MODULE::gensec_ntlmssp]
SUBSYSTEM = GENSEC
INIT_FUNCTION = gensec_ntlmssp_init
OBJ_FILES = ntlmssp.o \
		ntlmssp_parse.o \
		ntlmssp_sign.o \
		ntlmssp_client.o \
		ntlmssp_server.o
REQUIRED_SUBSYSTEMS = AUTH
# End MODULE gensec_ntlmssp
################################################
