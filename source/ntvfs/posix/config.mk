################################################
# Start MODULE ntvfs_posix
[MODULE::ntvfs_posix]
INIT_OBJ_FILES = \
		ntvfs/posix/vfs_posix.o
ADD_OBJ_FILES = \
		ntvfs/posix/pvfs_util.o \
		ntvfs/posix/pvfs_search.o \
		ntvfs/posix/pvfs_dirlist.o \
		ntvfs/posix/pvfs_fileinfo.o \
		ntvfs/posix/pvfs_unlink.o \
		ntvfs/posix/pvfs_mkdir.o \
		ntvfs/posix/pvfs_open.o \
		ntvfs/posix/pvfs_read.o \
		ntvfs/posix/pvfs_flush.o \
		ntvfs/posix/pvfs_write.o \
		ntvfs/posix/pvfs_fsinfo.o \
		ntvfs/posix/pvfs_qfileinfo.o \
		ntvfs/posix/pvfs_setfileinfo.o \
		ntvfs/posix/pvfs_rename.o \
		ntvfs/posix/pvfs_resolve.o \
		ntvfs/posix/pvfs_shortname.o
# End MODULE ntvfs_posix
################################################
