[SUBSYSTEM::LIBCLI_SMB2]
OBJ_FILES = \
	transport.o \
	request.o \
	negprot.o \
	session.o
REQUIRED_SUBSYSTEMS = LIBCLI_RAW LIBPACKET
