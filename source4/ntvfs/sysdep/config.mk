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

################################################
# Start MODULE sys_lease_linux
[MODULE::sys_lease_linux]
SUBSYSTEM = sys_lease
INIT_FUNCTION = sys_lease_linux_init
OBJ_FILES = \
		sys_lease_linux.o
# End MODULE sys_lease_linux
################################################

################################################
# Start SUBSYSTEM sys_lease
[SUBSYSTEM::sys_lease]
OBJ_FILES = \
		sys_lease.o
# End SUBSYSTEM sys_lease
################################################
