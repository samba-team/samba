################################################
# Start MODULE ntvfs_common
[MODULE::ntvfs_common]
SUBSYSTEM = ntvfs
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		brlock.o \
		opendb.o \
		notify.o \
		sidmap.o
REQUIRED_SUBSYSTEMS = 
# End MODULE ntvfs_common
################################################
