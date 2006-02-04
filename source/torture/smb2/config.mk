
#################################
# Start SUBSYSTEM TORTURE_SMB2
[SUBSYSTEM::TORTURE_SMB2]
PRIVATE_PROTO_HEADER = \
		proto.h
OBJ_FILES = \
		connect.o \
		scan.o \
		util.o \
		getinfo.o \
		setinfo.o \
		find.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_SMB2
# End SUBSYSTEM TORTURE_SMB2
#################################
