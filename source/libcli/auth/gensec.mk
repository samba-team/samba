#################################
# Start SUBSYSTEM GENSEC
[SUBSYSTEM::GENSEC]
INIT_FUNCTION = gensec_init
INIT_OBJ_FILES = libcli/auth/gensec.o
REQUIRED_SUBSYSTEMS = \
		SCHANNELDB
# End SUBSYSTEM GENSEC
#################################

################################################
# Start MODULE gensec_krb5
[MODULE::gensec_krb5]
INIT_FUNCTION = gensec_krb5_init
INIT_OBJ_FILES = libcli/auth/gensec_krb5.o 
ADD_OBJ_FILES = \
		libcli/auth/clikrb5.o \
		libcli/auth/kerberos.o \
		libcli/auth/kerberos_verify.o \
		libcli/auth/gssapi_parse.o
REQUIRED_SUBSYSTEMS = GENSEC EXT_LIB_KRB5
# End MODULE gensec_krb5
################################################

################################################
# Start MODULE gensec_spnego
[MODULE::gensec_spnego]
INIT_FUNCTION = gensec_spnego_init
INIT_OBJ_FILES = libcli/auth/spnego.o
ADD_OBJ_FILES = \
		libcli/auth/spnego_parse.o
REQUIRED_SUBSYSTEMS = GENSEC
# End MODULE gensec_spnego
################################################

################################################
# Start MODULE gensec_ntlmssp
[MODULE::gensec_ntlmssp]
INIT_FUNCTION = gensec_ntlmssp_init
INIT_OBJ_FILES = libcli/auth/gensec_ntlmssp.o
ADD_OBJ_FILES = \
		libcli/auth/ntlmssp.o \
		libcli/auth/ntlmssp_parse.o \
		libcli/auth/ntlmssp_sign.o
REQUIRED_SUBSYSTEMS = GENSEC AUTH
# End MODULE gensec_ntlmssp
################################################
