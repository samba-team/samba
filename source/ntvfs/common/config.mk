################################################
# Start LIBRARY ntvfs_common
[SUBSYSTEM::ntvfs_common]
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		init.o \
		brlock.o \
		brlock_tdb.o \
		opendb.o \
		notify.o
PUBLIC_DEPENDENCIES = NDR_OPENDB NDR_NOTIFY sys_notify share
# End LIBRARY ntvfs_common
################################################
