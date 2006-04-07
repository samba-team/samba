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
[LIBRARY::sys_notify]
PUBLIC_HEADERS = sys_notify.h
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = File System Notify Abstraction Layer
OBJ_FILES = \
		sys_notify.o
REQUIRED_SUBSYSTEMS = 
# End SUBSYSTEM sys_notify
################################################
