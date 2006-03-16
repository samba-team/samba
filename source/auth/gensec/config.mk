#################################
# Start SUBSYSTEM gensec
[LIBRARY::gensec]
VERSION = 0.0.1
SO_VERSION = 0.0.1
DESCRIPTION = Generic Security Library
PUBLIC_HEADERS = gensec.h spnego.h
PUBLIC_PROTO_HEADER = gensec_proto.h
OBJ_FILES = gensec.o
REQUIRED_SUBSYSTEMS = \
		CREDENTIALS
# End SUBSYSTEM gensec
#################################

################################################
# Start MODULE gensec_krb5
[MODULE::gensec_krb5]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_krb5_init
OBJ_FILES = gensec_krb5.o 
REQUIRED_SUBSYSTEMS = KERBEROS auth
# End MODULE gensec_krb5
################################################

################################################
# Start MODULE gensec_gssapi
[MODULE::gensec_gssapi]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_gssapi_init
OBJ_FILES = gensec_gssapi.o 
REQUIRED_SUBSYSTEMS = KERBEROS auth
# End MODULE gensec_gssapi
################################################

################################################
# Start MODULE gensec_spnego
[MODULE::gensec_spnego]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_spnego_init
PRIVATE_PROTO_HEADER = spnego_proto.h
OBJ_FILES = spnego.o \
			spnego_parse.o
# End MODULE gensec_spnego
################################################

################################################
# Start MODULE gensec_schannel
[MODULE::gensec_schannel]
SUBSYSTEM = gensec
PRIVATE_PROTO_HEADER = schannel_proto.h
INIT_FUNCTION = gensec_schannel_init
OBJ_FILES = schannel.o \
			schannel_sign.o
REQUIRED_SUBSYSTEMS = auth SCHANNELDB NDR_SCHANNEL
OUTPUT_TYPE = MERGEDOBJ
# End MODULE gensec_schannel
################################################

################################################
# Start SUBSYSTEM SCHANNELDB
[SUBSYSTEM::SCHANNELDB]
PRIVATE_PROTO_HEADER = schannel_state.h
OBJ_FILES = \
		schannel_state.o
#
# End SUBSYSTEM SCHANNELDB
################################################

