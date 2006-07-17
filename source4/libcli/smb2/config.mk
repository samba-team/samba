[SUBSYSTEM::LIBCLI_SMB2]
PRIVATE_PROTO_HEADER = smb2_proto.h
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
	ioctl.o \
	logoff.o \
	tdis.o \
	flush.o \
	lock.o \
	notify.o \
	cancel.o \
	keepalive.o
PUBLIC_DEPENDENCIES = LIBCLI_RAW LIBPACKET gensec
