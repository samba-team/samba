# auth server subsystem
mkinclude gensec/config.mk
mkinclude kerberos/config.mk
mkinclude ntlmssp/config.mk
mkinclude credentials/config.mk

[SUBSYSTEM::auth_session]
OBJ_FILES = session.o
PUBLIC_PROTO_HEADER = session_proto.h
PUBLIC_DEPENDENCIES = CREDENTIALS

PUBLIC_HEADERS += auth/session.h

[SUBSYSTEM::auth_system_session]
OBJ_FILES = system_session.o
PUBLIC_PROTO_HEADER = system_session_proto.h
PUBLIC_DEPENDENCIES = CREDENTIALS
PRIVATE_DEPENDENCIES = auth_session LIBSAMBA-UTIL LIBSECURITY 

[SUBSYSTEM::auth_sam]
PRIVATE_PROTO_HEADER = auth_sam.h
OBJ_FILES = sam.o ntlm_check.o 
PUBLIC_DEPENDENCIES = SAMDB UTIL_LDB LIBSECURITY
PRIVATE_DEPENDENCIES = LDAP_ENCODE

[SUBSYSTEM::auth_sam_reply]
PRIVATE_PROTO_HEADER = auth_sam_reply.h
OBJ_FILES = auth_sam_reply.o

#######################
# Start MODULE auth_sam
[MODULE::auth_sam_module]
# gensec_krb5 and gensec_gssapi depend on it
INIT_FUNCTION = auth_sam_init
SUBSYSTEM = auth
OBJ_FILES = auth_sam.o
PRIVATE_DEPENDENCIES = \
		SAMDB auth_sam
# End MODULE auth_sam
#######################

#######################
# Start MODULE auth_anonymous
[MODULE::auth_anonymous]
INIT_FUNCTION = auth_anonymous_init
SUBSYSTEM = auth
OBJ_FILES = auth_anonymous.o
# End MODULE auth_anonymous
#######################

#######################
# Start MODULE auth_winbind
[MODULE::auth_winbind]
INIT_FUNCTION = auth_winbind_init
SUBSYSTEM = auth
OBJ_FILES = auth_winbind.o
PRIVATE_DEPENDENCIES = NDR_WINBIND MESSAGING LIBWINBIND-CLIENT
# End MODULE auth_winbind
#######################

#######################
# Start MODULE auth_developer
[MODULE::auth_developer]
INIT_FUNCTION = auth_developer_init
SUBSYSTEM = auth
OBJ_FILES = auth_developer.o
# End MODULE auth_developer
#######################

[MODULE::auth_unix]
INIT_FUNCTION = auth_unix_init
SUBSYSTEM = auth
OBJ_FILES = auth_unix.o
PRIVATE_DEPENDENCIES = CRYPT PAM PAM_ERRORS NSS_WRAPPER

[SUBSYSTEM::PAM_ERRORS]
PRIVATE_PROTO_HEADER = pam_errors.h
OBJ_FILES = pam_errors.o

#######################
# Start SUBSYSTEM auth
[SUBSYSTEM::auth]
#VERSION = 0.0.1
#SO_VERSION = 0
PUBLIC_PROTO_HEADER = auth_proto.h
OBJ_FILES = \
		auth.o \
		auth_util.o \
		auth_simple.o
PUBLIC_DEPENDENCIES = LIBSECURITY SAMDB CREDENTIALS
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL
# End SUBSYSTEM auth
#######################

PUBLIC_HEADERS += auth/auth.h

[PYTHON::swig_auth]
PUBLIC_DEPENDENCIES = auth_system_session
PRIVATE_DEPENDENCIES = SAMDB 
SWIG_FILE = auth.i
