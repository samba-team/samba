[SUBSYSTEM::LIBSECURITY]
PUBLIC_DEPENDENCIES = NDR_MISC LIBNDR

LIBSECURITY_OBJ_FILES = $(addprefix $(libclisrcdir)/security/, \
					   security_token.o security_descriptor.o \
					   dom_sid.o access_check.o privilege.o sddl.o)

$(eval $(call proto_header_template,$(libclisrcdir)/security/proto.h,$(LIBSECURITY_OBJ_FILES:.o=.c)))

[PYTHON::swig_security]
SWIG_FILE = security.i
PRIVATE_DEPENDENCIES = LIBSECURITY

swig_security_OBJ_FILES = $(libclisrcdir)/security/security_wrap.o
