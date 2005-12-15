#################################
# Start SUBSYSTEM GENSEC
[LIBRARY::GENSEC]
MAJOR_VERSION = 0
MINOR_VERSION = 0
DESCRIPTION = Generic Security Library
RELEASE_VERSION = 1
PUBLIC_HEADERS = gensec.h
INIT_FUNCTION = gensec_init
INIT_OBJ_FILES = gensec.o
REQUIRED_SUBSYSTEMS = \
		SCHANNELDB
# End SUBSYSTEM GENSEC
#################################

################################################
# Start MODULE gensec_krb5
[MODULE::gensec_krb5]
SUBSYSTEM = GENSEC
INIT_FUNCTION = gensec_krb5_init
INIT_OBJ_FILES = gensec_krb5.o 
REQUIRED_SUBSYSTEMS = KERBEROS AUTH
# End MODULE gensec_krb5
################################################

################################################
# Start MODULE gensec_gssapi
[MODULE::gensec_gssapi]
SUBSYSTEM = GENSEC
INIT_FUNCTION = gensec_gssapi_init
INIT_OBJ_FILES = gensec_gssapi.o 
REQUIRED_SUBSYSTEMS = KERBEROS AUTH
# End MODULE gensec_gssapi
################################################

################################################
# Start MODULE gensec_spnego
[MODULE::gensec_spnego]
SUBSYSTEM = GENSEC
INIT_FUNCTION = gensec_spnego_init
INIT_OBJ_FILES = spnego.o
ADD_OBJ_FILES = \
		spnego_parse.o
# End MODULE gensec_spnego
################################################

################################################
# Start MODULE gensec_schannel
[MODULE::gensec_schannel]
SUBSYSTEM = GENSEC
INIT_FUNCTION = gensec_schannel_init
INIT_OBJ_FILES = schannel.o
ADD_OBJ_FILES = \
		schannel_sign.o
REQUIRED_SUBSYSTEMS = AUTH SCHANNELDB
# End MODULE gensec_schannel
################################################

################################################
# Start SUBSYSTEM SCHANNELDB
[SUBSYSTEM::SCHANNELDB]
INIT_OBJ_FILES = \
		schannel_state.o
#
# End SUBSYSTEM SCHANNELDB
################################################

