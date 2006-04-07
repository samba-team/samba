################################################
# Start LIBRARY ntvfs_common
[LIBRARY::ntvfs_common]
PRIVATE_PROTO_HEADER = proto.h
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = Generic Code for use in NTVFS modules
OBJ_FILES = \
		init.o \
		brlock.o \
		opendb.o \
		notify.o
REQUIRED_SUBSYSTEMS = NDR_OPENDB NDR_NOTIFY sys_notify
# End LIBRARY ntvfs_common
################################################
