# LIB GTK SMB subsystem

##############################
# Start SUBSYSTEM GTKSMB
[SUBSYSTEM::GTKSMB]
INIT_OBJ_FILES = gtk/common/gtk-smb.o
REQUIRED_LIBRARIES = gtk
REQUIRED_SUBSYSTEMS = \
		CHARSET LIBBASIC
# End SUBSYSTEM GTKSMB
##############################

################################################
# Start BINARY gregedit
[BINARY::gregedit]
OBJ_FILES = gtk/tools/gregedit.o
REQUIRED_SUBSYSTEMS = CONFIG LIBCMDLINE REGISTRY GTKSMB
# End BINARY gregedit
################################################

################################################
# Start BINARY gwcrontab
[BINARY::gwcrontab]
OBJ_FILES = gtk/tools/gwcrontab.o
REQUIRED_SUBSYSTEMS = CONFIG LIBCMDLINE LIBRPC LIBSMB GTKSMB
# End BINARY gwcrontab
################################################
