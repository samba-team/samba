################################################
# Start MODULE ntvfs_unixuid
[MODULE::ntvfs_unixuid]
INIT_FUNCTION = ntvfs_unixuid_init
INIT_OBJ_FILES = \
		ntvfs/unixuid/vfs_unixuid.o
# End MODULE ntvfs_unixuid
################################################
