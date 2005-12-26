#######################
# Start SUBSYSTEM SMB2_PROTOCOL
[SUBSYSTEM::SMB2_PROTOCOL]
OBJ_FILES = \
		receive.o \
		negprot.o \
		sesssetup.o \
		tcon.o \
		fileio.o \
		keepalive.o
REQUIRED_SUBSYSTEMS = \
		NTVFS LIBPACKET LIBCLI_SMB2
# End SUBSYSTEM SMB2_PROTOCOL
#######################
