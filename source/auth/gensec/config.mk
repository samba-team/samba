#################################
# Start SUBSYSTEM gensec
[LIBRARY::gensec]
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = Generic Security Library
PUBLIC_HEADERS = gensec.h spnego.h
PUBLIC_PROTO_HEADER = gensec_proto.h
OBJ_FILES = gensec.o
PUBLIC_DEPENDENCIES = \
		CREDENTIALS LIBSAMBA-UTIL LIBCRYPTO ASN1_UTIL
# End SUBSYSTEM gensec
#################################

################################################
# Start MODULE gensec_krb5
[MODULE::gensec_krb5]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_krb5_init
OBJ_FILES = gensec_krb5.o 
PUBLIC_DEPENDENCIES = CREDENTIALS_KRB5 KERBEROS auth auth_sam
# End MODULE gensec_krb5
################################################

################################################
# Start MODULE gensec_gssapi
[MODULE::gensec_gssapi]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_gssapi_init
OBJ_FILES = gensec_gssapi.o 
PUBLIC_DEPENDENCIES = CREDENTIALS_KRB5 KERBEROS auth HEIMDAL_GSSAPI
# End MODULE gensec_gssapi
################################################

################################################
# Start MODULE cyrus_sasl
[MODULE::cyrus_sasl]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_sasl_init
OBJ_FILES = cyrus_sasl.o 
PUBLIC_DEPENDENCIES = CREDENTIALS SASL auth
# End MODULE cyrus_sasl
################################################

################################################
# Start MODULE gensec_spnego
[MODULE::gensec_spnego]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_spnego_init
PRIVATE_PROTO_HEADER = spnego_proto.h
PRIVATE_DEPENDENCIES = ASN1_UTIL GENSEC_SOCKET
PUBLIC_DEPENDENCIES = CREDENTIALS
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
PUBLIC_DEPENDENCIES = auth SCHANNELDB NDR_SCHANNEL CREDENTIALS
OUTPUT_TYPE = INTEGRATED
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

################################################
# Start SUBSYSTEM GENSEC_SOCKET
[SUBSYSTEM::GENSEC_SOCKET]
OBJ_FILES = \
		socket.o
PUBLIC_DEPENDENCIES = samba-socket LIBPACKET
#PUBLIC_DEPENDENCIES =  gensec
#
# End SUBSYSTEM GENSEC_SOCKET
################################################

