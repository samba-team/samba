################################################
# Start MODULE ntvfs_unixuid
[MODULE::ntvfs_unixuid]
INIT_FUNCTION = ntvfs_unixuid_init
SUBSYSTEM = ntvfs
OBJ_FILES = \
		vfs_unixuid.o
PUBLIC_DEPENDENCIES = SAMDB
# End MODULE ntvfs_unixuid
################################################
