[SUBSYSTEM::LIBSECURITY]
PUBLIC_DEPENDENCIES = LIBNDR

LIBSECURITY_OBJ_FILES = $(addprefix $(libclisrcdir)/security/, \
					   security_token.o security_descriptor.o \
					   dom_sid.o access_check.o privilege.o sddl.o)

$(eval $(call proto_header_template,$(libclisrcdir)/security/proto.h,$(LIBSECURITY_OBJ_FILES:.o=.c)))

[PYTHON::swig_security]
LIBRARY_REALNAME = samba/_security.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = LIBSECURITY

swig_security_OBJ_FILES = $(libclisrcdir)/security/security_wrap.o

$(eval $(call python_py_module_template,samba/security.py,$(libclisrcdir)/security/security.py))

$(swig_security_OBJ_FILES): CFLAGS+=$(CFLAG_NO_UNUSED_MACROS) $(CFLAG_NO_CAST_QUAL)
