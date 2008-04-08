# auth server subsystem
mkinclude gensec/config.mk
mkinclude kerberos/config.mk
mkinclude ntlmssp/config.mk
mkinclude credentials/config.mk

[SUBSYSTEM::auth_session]
PRIVATE_PROTO_HEADER = session_proto.h
PUBLIC_DEPENDENCIES = CREDENTIALS

# PUBLIC_HEADERS += auth/session.h

auth_session_OBJ_FILES = $(addprefix auth/, session.o)

[SUBSYSTEM::auth_system_session]
PRIVATE_PROTO_HEADER = system_session_proto.h
PUBLIC_DEPENDENCIES = CREDENTIALS
PRIVATE_DEPENDENCIES = auth_session LIBSAMBA-UTIL LIBSECURITY 

auth_system_session_OBJ_FILES = $(addprefix auth/, system_session.o)

[SUBSYSTEM::auth_sam]
PRIVATE_PROTO_HEADER = auth_sam.h
PUBLIC_DEPENDENCIES = SAMDB UTIL_LDB LIBSECURITY
PRIVATE_DEPENDENCIES = LDAP_ENCODE

auth_sam_OBJ_FILES = $(addprefix auth/, sam.o ntlm_check.o)

[SUBSYSTEM::auth_sam_reply]
PRIVATE_PROTO_HEADER = auth_sam_reply.h

auth_sam_reply_OBJ_FILES = $(addprefix auth/, auth_sam_reply.o)

#######################
# Start MODULE auth_sam
[MODULE::auth_sam_module]
# gensec_krb5 and gensec_gssapi depend on it
INIT_FUNCTION = auth_sam_init
SUBSYSTEM = service_auth
PRIVATE_DEPENDENCIES = \
		SAMDB auth_sam
# End MODULE auth_sam
#######################

auth_sam_module_OBJ_FILES = $(addprefix auth/, auth_sam.o)

#######################
# Start MODULE auth_anonymous
[MODULE::auth_anonymous]
INIT_FUNCTION = auth_anonymous_init
SUBSYSTEM = service_auth
# End MODULE auth_anonymous
#######################

auth_anonymous_OBJ_FILES = $(addprefix auth/, auth_anonymous.o)

#######################
# Start MODULE auth_winbind
[MODULE::auth_winbind]
INIT_FUNCTION = auth_winbind_init
SUBSYSTEM = service_auth
PRIVATE_DEPENDENCIES = NDR_WINBIND MESSAGING LIBWINBIND-CLIENT
# End MODULE auth_winbind
#######################

auth_winbind_OBJ_FILES = $(addprefix auth/, auth_winbind.o)

#######################
# Start MODULE auth_developer
[MODULE::auth_developer]
INIT_FUNCTION = auth_developer_init
SUBSYSTEM = service_auth
# End MODULE auth_developer
#######################

auth_developer_OBJ_FILES = $(addprefix auth/, auth_developer.o)

[MODULE::auth_unix]
INIT_FUNCTION = auth_unix_init
SUBSYSTEM = service_auth
PRIVATE_DEPENDENCIES = CRYPT PAM PAM_ERRORS NSS_WRAPPER

auth_unix_OBJ_FILES = $(addprefix auth/, auth_unix.o)

[SUBSYSTEM::PAM_ERRORS]
PRIVATE_PROTO_HEADER = pam_errors.h

PAM_ERRORS_OBJ_FILES = $(addprefix auth/, pam_errors.o)

[MODULE::service_auth]
INIT_FUNCTION = server_service_auth_init
SUBSYSTEM = smbd
PRIVATE_PROTO_HEADER = auth_proto.h
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL LIBSECURITY SAMDB CREDENTIALS 

service_auth_OBJ_FILES = $(addprefix auth/, auth.o auth_util.o auth_simple.o)

# PUBLIC_HEADERS += auth/auth.h

[PYTHON::swig_auth]
PUBLIC_DEPENDENCIES = auth_system_session
PRIVATE_DEPENDENCIES = SAMDB 
SWIG_FILE = auth.i

swig_auth_OBJ_FILES = auth/auth_wrap.o
