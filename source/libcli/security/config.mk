#################################
# Start SUBSYSTEM LIB_SECURITY_NDR_HELPER
[SUBSYSTEM::LIB_SECURITY_NDR_HELPER]
ADD_OBJ_FILES = ../../librpc/ndr/ndr_sec_helper.o
# End SUBSYSTEM LIB_SECURITY_NDR_HELPER
#################################

#################################
# Start SUBSYSTEM LIB_SECURITY_NDR
[SUBSYSTEM::LIB_SECURITY_NDR]
ADD_OBJ_FILES = ../../librpc/gen_ndr/ndr_security.o
NOPROTO = YES
REQUIRED_SUBSYSTEMS = LIB_SECURITY_NDR_HELPER
# End SUBSYSTEM LIB_SECURITY_NDR
#################################

#################################
# Start SUBSYSTEM LIB_SECURITY
[SUBSYSTEM::LIB_SECURITY]
ADD_OBJ_FILES = security_token.o \
		security_descriptor.o \
		dom_sid.o \
		access_check.o \
		privilege.o \
		sddl.o \
		../../librpc/ndr/ndr_sec.o
REQUIRED_SUBSYSTEMS = LIB_SECURITY_NDR
# End SUBSYSTEM LIB_SECURITY
#################################
