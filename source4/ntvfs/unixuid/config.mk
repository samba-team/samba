################################################
# Start MODULE ntvfs_unixuid
[MODULE::ntvfs_unixuid]
INIT_FUNCTION = ntvfs_unixuid_init
SUBSYSTEM = NTVFS
OBJ_FILES = \
		vfs_unixuid.o
# End MODULE ntvfs_unixuid
################################################
