# SMB server subsystem

#######################
# Start SUBSYSTEM SMB
[SUBSYSTEM::SMB]
INIT_OBJ_FILES = \
		smb_server/smb_server.o
ADD_OBJ_FILES = \
		smb_server/conn.o \
		smb_server/connection.o \
		smb_server/negprot.o \
		smb_server/nttrans.o \
		smb_server/password.o \
		smb_server/reply.o \
		smb_server/request.o \
		smb_server/search.o \
		smb_server/service.o \
		smb_server/session.o \
		smb_server/sesssetup.o \
		smb_server/srvtime.o \
		smb_server/trans2.o \
		smb_server/signing.o
REQUIRED_SUBSYSTEMS = \
		NTVFS
# End SUBSYSTEM SMB
#######################
