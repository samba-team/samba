#################################
# Start SUBSYSTEM LIB_SECURITY_NDR
[SUBSYSTEM::LIB_SECURITY_NDR]
ADD_OBJ_FILES = librpc/gen_ndr/ndr_security.o
NOPROTO = YES
# End SUBSYSTEM LIB_SECURITY_NDR
#################################

#################################
# Start SUBSYSTEM LIB_SECURITY
[SUBSYSTEM::LIB_SECURITY]
ADD_OBJ_FILES = libcli/security/security_token.o \
		libcli/security/security_descriptor.o \
		libcli/security/dom_sid.o \
		libcli/security/access_check.o \
		libcli/security/privilege.o \
		librpc/ndr/ndr_sec.o
REQUIRED_SUBSYSTEMS = LIB_SECURITY_NDR
# End SUBSYSTEM LIB_SECURITY
#################################
