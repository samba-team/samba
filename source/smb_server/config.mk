# SMB server subsystem

#######################
# Start SUBSYSTEM SMB
[SUBSYSTEM::SMB]
INIT_OBJ_FILES = \
		smb_server.o
ADD_OBJ_FILES = \
		conn.o \
		negprot.o \
		nttrans.o \
		session.o \
		reply.o \
		request.o \
		search.o \
		service.o \
		sesssetup.o \
		srvtime.o \
		trans2.o \
		signing.o \
		management.o
REQUIRED_SUBSYSTEMS = \
		NTVFS LIBPACKET
# End SUBSYSTEM SMB
#######################
