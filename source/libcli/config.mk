#################################
# Start SUBSYSTEM LIBCLI_AUTH
[SUBSYSTEM::LIBCLI_AUTH]
ADD_OBJ_FILES = \
		libcli/auth/spnego.o \
		libcli/auth/spnego_parse.o \
		libcli/auth/ntlmssp.o \
		libcli/auth/ntlmssp_parse.o \
		libcli/auth/ntlmssp_sign.o \
		libcli/auth/schannel.o \
		libcli/auth/credentials.o \
		libcli/auth/session.o \
		libcli/auth/ntlm_check.o \
		libcli/auth/kerberos.o \
		libcli/auth/kerberos_verify.o \
		libcli/auth/clikrb5.o \
		libcli/auth/gensec.o \
		libcli/auth/gensec_ntlmssp.o 
REQUIRED_SUBSYSTEMS = \
		AUTH SCHANNELDB
# End SUBSYSTEM LIBCLI_AUTH
#################################

