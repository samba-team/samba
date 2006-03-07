#################################
# Start SUBSYSTEM LIB_SECURITY
[SUBSYSTEM::LIB_SECURITY]
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = security_token.o \
		security_descriptor.o \
		dom_sid.o \
		access_check.o \
		privilege.o \
		sddl.o
REQUIRED_SUBSYSTEMS = NDR_SECURITY
# End SUBSYSTEM LIB_SECURITY
#################################
