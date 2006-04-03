################################################
# Start MODULE ntvfs_sys_notify
[MODULE::ntvfs_sys_notify]
SUBSYSTEM = ntvfs
OBJ_FILES = \
		sys_notify.o
# End MODULE ntvfs_sys_notify
################################################


################################################
# Start MODULE ntvfs_inotify
[MODULE::ntvfs_inotify]
SUBSYSTEM = ntvfs
INIT_FUNCTION = ntvfs_inotify_init
OBJ_FILES = \
		inotify.o
# End MODULE ntvfs_inotify
################################################

