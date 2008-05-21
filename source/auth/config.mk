# auth server subsystem
gensecsrcdir := $(authsrcdir)/gensec
mkinclude gensec/config.mk
mkinclude kerberos/config.mk
mkinclude ntlmssp/config.mk
mkinclude ntlm/config.mk
mkinclude credentials/config.mk

[SUBSYSTEM::auth_session]
PUBLIC_DEPENDENCIES = CREDENTIALS

PUBLIC_HEADERS += $(authsrcdir)/session.h

auth_session_OBJ_FILES = $(addprefix $(authsrcdir)/, session.o)

$(eval $(call proto_header_template,$(authsrcdir)/session_proto.h,$(auth_session_OBJ_FILES:.o=.c)))

[SUBSYSTEM::auth_system_session]
PUBLIC_DEPENDENCIES = CREDENTIALS
PRIVATE_DEPENDENCIES = auth_session LIBSAMBA-UTIL LIBSECURITY 

auth_system_session_OBJ_FILES = $(addprefix $(authsrcdir)/, system_session.o)
$(eval $(call proto_header_template,$(authsrcdir)/system_session_proto.h,$(auth_system_session_OBJ_FILES:.o=.c)))

[SUBSYSTEM::auth_sam]
PUBLIC_DEPENDENCIES = SAMDB UTIL_LDB LIBSECURITY
PRIVATE_DEPENDENCIES = LDAP_ENCODE

auth_sam_OBJ_FILES = $(addprefix $(authsrcdir)/, sam.o)

$(eval $(call proto_header_template,$(authsrcdir)/auth_sam.h,$(auth_sam_OBJ_FILES:.o=.c)))

[SUBSYSTEM::auth_sam_reply]

auth_sam_reply_OBJ_FILES = $(addprefix $(authsrcdir)/, auth_sam_reply.o)

$(eval $(call proto_header_template,$(authsrcdir)/auth_sam_reply.h,$(auth_sam_reply_OBJ_FILES:.o=.c)))

[PYTHON::swig_auth]
PUBLIC_DEPENDENCIES = auth_system_session
PRIVATE_DEPENDENCIES = SAMDB 
SWIG_FILE = auth.i

$(eval $(call python_py_module_template,auth.py,$(authsrcdir)/auth.py))

swig_auth_OBJ_FILES = $(authsrcdir)/auth_wrap.o
