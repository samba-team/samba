################################################
# Start MODULE sys_notify_inotify
[MODULE::sys_notify_inotify]
SUBSYSTEM = sys_notify
INIT_FUNCTION = sys_notify_inotify_init
OBJ_FILES = \
		inotify.o
# End MODULE sys_notify_inotify
################################################

################################################
# Start SUBSYSTEM sys_notify
[SUBSYSTEM::sys_notify]
OBJ_FILES = \
		sys_notify.o
PUBLIC_DEPENDENCIES = 
# End SUBSYSTEM sys_notify
################################################
