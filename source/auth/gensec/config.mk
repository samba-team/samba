#################################
# Start SUBSYSTEM gensec
[LIBRARY::gensec]
PC_FILE = gensec.pc
VERSION = 0.0.1
SO_VERSION = 0
PRIVATE_PROTO_HEADER = gensec_proto.h
PUBLIC_DEPENDENCIES = \
		CREDENTIALS LIBSAMBA-UTIL LIBCRYPTO ASN1_UTIL samba-socket LIBPACKET
# End SUBSYSTEM gensec
#################################


gensec_OBJ_LIST = $(addprefix auth/, gensec.o socket.o)

PUBLIC_HEADERS += $(addprefix auth/gensec/, gensec.h spnego.h)

################################################
# Start MODULE gensec_krb5
[MODULE::gensec_krb5]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_krb5_init
PRIVATE_DEPENDENCIES = CREDENTIALS KERBEROS auth auth_sam
# End MODULE gensec_krb5
################################################

gensec_krb5_OBJ_FILES = $(addprefix auth/, gensec_krb5.o)

################################################
# Start MODULE gensec_gssapi
[MODULE::gensec_gssapi]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_gssapi_init
PRIVATE_DEPENDENCIES = HEIMDAL_GSSAPI CREDENTIALS KERBEROS 
# End MODULE gensec_gssapi
################################################

gensec_gssapi_OBJ_FILES = $(addprefix auth/, gensec_gssapi.o)

################################################
# Start MODULE cyrus_sasl
[MODULE::cyrus_sasl]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_sasl_init
PRIVATE_DEPENDENCIES = CREDENTIALS SASL 
# End MODULE cyrus_sasl
################################################

cyrus_sasl_OBJ_FILES = $(addprefix auth/gensec/, cyrus_sasl.o)

################################################
# Start MODULE gensec_spnego
[MODULE::gensec_spnego]
SUBSYSTEM = gensec
INIT_FUNCTION = gensec_spnego_init
PRIVATE_PROTO_HEADER = spnego_proto.h
PRIVATE_DEPENDENCIES = ASN1_UTIL CREDENTIALS
# End MODULE gensec_spnego
################################################

gensec_spnego_OBJ_FILES = $(addprefix auth/gensec/, spnego.o spnego_parse.o)

################################################
# Start MODULE gensec_schannel
[MODULE::gensec_schannel]
SUBSYSTEM = gensec
PRIVATE_PROTO_HEADER = schannel_proto.h
INIT_FUNCTION = gensec_schannel_init
PRIVATE_DEPENDENCIES = SCHANNELDB NDR_SCHANNEL CREDENTIALS LIBNDR
OUTPUT_TYPE = MERGED_OBJ
# End MODULE gensec_schannel
################################################

gensec_schannel_OBJ_FILES = $(addprefix auth/gensec/, schannel.o schannel_sign.o)

################################################
# Start SUBSYSTEM SCHANNELDB
[SUBSYSTEM::SCHANNELDB]
PRIVATE_PROTO_HEADER = schannel_state.h
PRIVATE_DEPENDENCIES = LDB_WRAP SAMDB
# End SUBSYSTEM SCHANNELDB
################################################

SCHANNELDB_OBJ_FILES = $(addprefix auth/gensec/, schannel_state.o)

