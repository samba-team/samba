# auth server subsystem
gensecsrcdir := $(authsrcdir)/gensec
mkinclude gensec/config.mk
mkinclude kerberos/config.mk
mkinclude ntlmssp/config.mk
mkinclude ntlm/config.mk
mkinclude credentials/config.mk

[SUBSYSTEM::auth_session]
PRIVATE_PROTO_HEADER = session_proto.h
PUBLIC_DEPENDENCIES = CREDENTIALS

PUBLIC_HEADERS += $(authsrcdir)/session.h

auth_session_OBJ_FILES = $(addprefix $(authsrcdir)/, session.o)

[SUBSYSTEM::auth_system_session]
PRIVATE_PROTO_HEADER = system_session_proto.h
PUBLIC_DEPENDENCIES = CREDENTIALS
PRIVATE_DEPENDENCIES = auth_session LIBSAMBA-UTIL LIBSECURITY 

auth_system_session_OBJ_FILES = $(addprefix $(authsrcdir)/, system_session.o)

[SUBSYSTEM::auth_sam]
PRIVATE_PROTO_HEADER = auth_sam.h
PUBLIC_DEPENDENCIES = SAMDB UTIL_LDB LIBSECURITY
PRIVATE_DEPENDENCIES = LDAP_ENCODE

auth_sam_OBJ_FILES = $(addprefix $(authsrcdir)/, sam.o)

[SUBSYSTEM::auth_sam_reply]
PRIVATE_PROTO_HEADER = auth_sam_reply.h

auth_sam_reply_OBJ_FILES = $(addprefix $(authsrcdir)/, auth_sam_reply.o)

[PYTHON::swig_auth]
PUBLIC_DEPENDENCIES = auth_system_session
PRIVATE_DEPENDENCIES = SAMDB 
SWIG_FILE = auth.i

swig_auth_OBJ_FILES = $(authsrcdir)/auth_wrap.o
