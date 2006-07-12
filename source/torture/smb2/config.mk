
#################################
# Start SUBSYSTEM TORTURE_SMB2
[MODULE::TORTURE_SMB2]
SUBSYSTEM = torture
INIT_FUNCTION = torture_smb2_init
PRIVATE_PROTO_HEADER = \
		proto.h
OBJ_FILES = \
		connect.o \
		scan.o \
		util.o \
		getinfo.o \
		setinfo.o \
		find.o \
		lock.o \
		notify.o \
		smb2.o
PUBLIC_DEPENDENCIES = \
		LIBCLI_SMB2 POPT_CREDENTIALS
# End SUBSYSTEM TORTURE_SMB2
#################################
