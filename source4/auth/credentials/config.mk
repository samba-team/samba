#################################
# Start SUBSYSTEM CREDENTIALS
[SUBSYSTEM::CREDENTIALS]
PUBLIC_DEPENDENCIES = \
		LIBCLI_AUTH SECRETS LIBCRYPTO KERBEROS UTIL_LDB HEIMDAL_GSSAPI 
PRIVATE_DEPENDENCIES = \
		SECRETS


CREDENTIALS_OBJ_FILES = $(addprefix $(authsrcdir)/credentials/, credentials.o credentials_files.o credentials_ntlm.o credentials_krb5.o ../kerberos/kerberos_util.o)

$(eval $(call proto_header_template,$(authsrcdir)/credentials/credentials_proto.h,$(CREDENTIALS_OBJ_FILES:.o=.c)))

PUBLIC_HEADERS += $(authsrcdir)/credentials/credentials.h

[PYTHON::swig_credentials]
LIBRARY_REALNAME = samba/_credentials.$(SHLIBEXT)
PUBLIC_DEPENDENCIES = CREDENTIALS LIBCMDLINE_CREDENTIALS

$(eval $(call python_py_module_template,samba/credentials.py,$(authsrcdir)/credentials/credentials.py))

swig_credentials_OBJ_FILES = $(authsrcdir)/credentials/credentials_wrap.o

$(swig_credentials_OBJ_FILES): CFLAGS+=$(CFLAG_NO_UNUSED_MACROS) $(CFLAG_NO_CAST_QUAL)
