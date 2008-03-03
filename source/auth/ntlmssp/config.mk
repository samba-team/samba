[SUBSYSTEM::MSRPC_PARSE]
PRIVATE_PROTO_HEADER = msrpc_parse.h

MSRPC_PARSE_OBJ_FILES = $(addprefix auth/ntlmssp/, ntlmssp_parse.o)

################################################
# Start MODULE gensec_ntlmssp
[MODULE::gensec_ntlmssp]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_ntlmssp_init
PRIVATE_PROTO_HEADER = proto.h
PRIVATE_DEPENDENCIES = MSRPC_PARSE CREDENTIALS
OUTPUT_TYPE = MERGED_OBJ
# End MODULE gensec_ntlmssp
################################################

gensec_ntlmssp_OBJ_FILES = $(addprefix auth/ntlmssp/, ntlmssp.o ntlmssp_sign.o ntlmssp_client.o ntlmssp_server.o) 
