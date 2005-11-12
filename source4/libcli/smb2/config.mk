[SUBSYSTEM::LIBCLI_SMB2]
OBJ_FILES = \
	transport.o \
	request.o \
	negprot.o \
	session.o \
	tcon.o \
	create.o \
	close.o \
	connect.o
REQUIRED_SUBSYSTEMS = LIBCLI_RAW LIBPACKET
