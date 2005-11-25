[SUBSYSTEM::LIBCLI_SMB2]
OBJ_FILES = \
	transport.o \
	request.o \
	negprot.o \
	session.o \
	tcon.o \
	create.o \
	close.o \
	connect.o \
	getinfo.o \
	write.o \
	read.o \
	setinfo.o \
	find.o \
	trans.o \
	logoff.o \
	tdis.o \
	flush.o
REQUIRED_SUBSYSTEMS = LIBCLI_RAW LIBPACKET
