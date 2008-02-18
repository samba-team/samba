[SUBSYSTEM::MSRPC_PARSE]
PRIVATE_PROTO_HEADER = msrpc_parse.h
OBJ_FILES = ntlmssp_parse.o

################################################
# Start MODULE gensec_ntlmssp
[MODULE::gensec_ntlmssp]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_ntlmssp_init
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = ntlmssp.o \
		ntlmssp_sign.o \
		ntlmssp_client.o \
		ntlmssp_server.o
PRIVATE_DEPENDENCIES = MSRPC_PARSE CREDENTIALS
OUTPUT_TYPE = MERGED_OBJ
# End MODULE gensec_ntlmssp
################################################
