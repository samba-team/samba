################################################
# Start MODULE ntvfs_posix
[MODULE::ntvfs_posix]
SUBSYSTEM = NTVFS
INIT_FUNCTION = ntvfs_posix_init 
PRIVATE_PROTO_HEADER = vfs_posix_proto.h
OBJ_FILES = \
		vfs_posix.o \
		pvfs_util.o \
		pvfs_search.o \
		pvfs_dirlist.o \
		pvfs_fileinfo.o \
		pvfs_unlink.o \
		pvfs_mkdir.o \
		pvfs_open.o \
		pvfs_read.o \
		pvfs_flush.o \
		pvfs_write.o \
		pvfs_fsinfo.o \
		pvfs_qfileinfo.o \
		pvfs_setfileinfo.o \
		pvfs_rename.o \
		pvfs_resolve.o \
		pvfs_shortname.o \
		pvfs_lock.o \
		pvfs_wait.o \
		pvfs_seek.o \
		pvfs_ioctl.o \
		pvfs_xattr.o \
		pvfs_streams.o \
		pvfs_acl.o \
		xattr_system.o \
		xattr_tdb.o
REQUIRED_SUBSYSTEMS = NDR_XATTR ntvfs_common EXT_LIB_XATTR EXT_LIB_BLKID
# End MODULE ntvfs_posix
################################################
