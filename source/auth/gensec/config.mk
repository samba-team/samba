#################################
# Start SUBSYSTEM gensec
[LIBRARY::gensec]
PC_FILE = gensec.pc
VERSION = 0.0.1
SO_VERSION = 0
PRIVATE_PROTO_HEADER = gensec_proto.h
OBJ_FILES = gensec.o socket.o
PUBLIC_DEPENDENCIES = \
		CREDENTIALS LIBSAMBA-UTIL LIBCRYPTO ASN1_UTIL samba-socket LIBPACKET
# End SUBSYSTEM gensec
#################################

PUBLIC_HEADERS += auth/gensec/gensec.h

################################################
# Start MODULE gensec_krb5
[MODULE::gensec_krb5]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_krb5_init
OBJ_FILES = gensec_krb5.o 
PRIVATE_DEPENDENCIES = CREDENTIALS KERBEROS auth auth_sam
# End MODULE gensec_krb5
################################################

################################################
# Start MODULE gensec_gssapi
[MODULE::gensec_gssapi]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_gssapi_init
OBJ_FILES = gensec_gssapi.o 
PRIVATE_DEPENDENCIES = HEIMDAL_GSSAPI CREDENTIALS KERBEROS 
# End MODULE gensec_gssapi
################################################

################################################
# Start MODULE cyrus_sasl
[MODULE::cyrus_sasl]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_sasl_init
OBJ_FILES = cyrus_sasl.o 
PRIVATE_DEPENDENCIES = CREDENTIALS SASL 
# End MODULE cyrus_sasl
################################################

################################################
# Start MODULE gensec_spnego
[MODULE::gensec_spnego]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_spnego_init
PRIVATE_PROTO_HEADER = spnego_proto.h
PRIVATE_DEPENDENCIES = ASN1_UTIL CREDENTIALS
OBJ_FILES = spnego.o spnego_parse.o
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
PRIVATE_DEPENDENCIES = SCHANNELDB NDR_SCHANNEL CREDENTIALS LIBNDR
OUTPUT_TYPE = MERGED_OBJ
# End MODULE gensec_schannel
################################################

################################################
# Start SUBSYSTEM SCHANNELDB
[SUBSYSTEM::SCHANNELDB]
PRIVATE_PROTO_HEADER = schannel_state.h
OBJ_FILES = \
		schannel_state.o
PRIVATE_DEPENDENCIES = LDB_WRAP SAMDB
#
# End SUBSYSTEM SCHANNELDB
################################################

