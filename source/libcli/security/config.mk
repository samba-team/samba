#################################
# Start SUBSYSTEM LIBSECURITY
[SUBSYSTEM::LIBSECURITY]
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = security_token.o \
		security_descriptor.o \
		dom_sid.o \
		access_check.o \
		privilege.o \
		sddl.o
PUBLIC_DEPENDENCIES = NDR_MISC
# End SUBSYSTEM LIBSECURITY
#################################
