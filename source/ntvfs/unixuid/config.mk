################################################
# Start MODULE ntvfs_unixuid
[MODULE::ntvfs_unixuid]
INIT_FUNCTION = ntvfs_unixuid_init
SUBSYSTEM = NTVFS
INIT_OBJ_FILES = \
		ntvfs/unixuid/vfs_unixuid.o
REQUIRED_SUBSYSTEMS = \
		ntvfs_common
# End MODULE ntvfs_unixuid
################################################
