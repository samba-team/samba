#######################
# Start SUBSYSTEM SMB2_PROTOCOL
[SUBSYSTEM::SMB2_PROTOCOL]
INIT_OBJ_FILES = \
		receive.o
ADD_OBJ_FILES = \
		negprot.o \
		sesssetup.o \
		tcon.o \
		fileio.o
REQUIRED_SUBSYSTEMS = \
		NTVFS LIBPACKET LIBCLI_SMB2
# End SUBSYSTEM SMB2_PROTOCOL
#######################
