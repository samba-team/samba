[SUBSYSTEM::LIBSECURITY]
PRIVATE_PROTO_HEADER = proto.h
PUBLIC_DEPENDENCIES = NDR_MISC LIBNDR

LIBSECURITY_OBJ_FILES = $(addprefix libcli/security/, \
					   security_token.o security_descriptor.o \
					   dom_sid.o access_check.o privilege.o sddl.o)


[PYTHON::swig_security]
SWIG_FILE = security.i
PRIVATE_DEPENDENCIES = LIBSECURITY

swig_security_OBJ_FILES = libcli/security/security_wrap.o
