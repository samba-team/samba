################################################
# Start LIBRARY ntvfs_common
[SUBSYSTEM::ntvfs_common]
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		init.o \
		brlock.o \
		opendb.o \
		notify.o
REQUIRED_SUBSYSTEMS = NDR_OPENDB NDR_NOTIFY sys_notify
# End LIBRARY ntvfs_common
################################################
