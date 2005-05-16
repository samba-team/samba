################################################
# Start MODULE gensec_ntlmssp
[MODULE::gensec_ntlmssp]
SUBSYSTEM = GENSEC
INIT_FUNCTION = gensec_ntlmssp_init
INIT_OBJ_FILES = auth/ntlmssp/ntlmssp.o
ADD_OBJ_FILES = \
		auth/ntlmssp/ntlmssp_parse.o \
		auth/ntlmssp/ntlmssp_sign.o \
		auth/ntlmssp/ntlmssp_client.o \
		auth/ntlmssp/ntlmssp_server.o
REQUIRED_SUBSYSTEMS = AUTH
# End MODULE gensec_ntlmssp
################################################
