
#################################
# Start SUBSYSTEM TORTURE_SMB2
[SUBSYSTEM::TORTURE_SMB2]
ADD_OBJ_FILES = \
		connect.o \
		scan.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_SMB2
# End SUBSYSTEM TORTURE_SMB2
#################################
