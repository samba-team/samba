# LIB GTK SMB subsystem

##############################
# Start SUBSYSTEM GTKSMB
[LIBRARY::GTKSMB]
MAJOR_VERSION = 0
DESCRIPTION = Common Samba-related widgets for GTK+ applications
MINOR_VERSION = 0
RELEASE_VERSION = 1
NOPROTO = YES
PUBLIC_HEADERS = common/gtk-smb.h common/select.h
INIT_OBJ_FILES = common/gtk-smb.o 
ADD_OBJ_FILES = common/select.o \
		common/gtk_events.o \
		common/credentials.o
REQUIRED_SUBSYSTEMS = CHARSET LIBBASIC EXT_LIB_gtk RPC_NDR_SAMR
# End SUBSYSTEM GTKSMB
##############################

################################################
# Start BINARY gregedit
[BINARY::gregedit]
INSTALLDIR = BINDIR
OBJ_FILES = tools/gregedit.o
REQUIRED_SUBSYSTEMS = CONFIG LIBCMDLINE REGISTRY GTKSMB
MANPAGE = man/gregedit.1
# End BINARY gregedit
################################################

################################################
# Start BINARY gepdump 
[BINARY::gepdump]
INSTALLDIR = BINDIR
OBJ_FILES = tools/gepdump.o
REQUIRED_SUBSYSTEMS = CONFIG LIBCMDLINE GTKSMB RPC_NDR_EPMAPPER RPC_NDR_MGMT
# End BINARY gepdump 
################################################

################################################
# Start BINARY gwcrontab
[BINARY::gwcrontab]
INSTALLDIR = BINDIR
OBJ_FILES = tools/gwcrontab.o
REQUIRED_SUBSYSTEMS = CONFIG LIBCMDLINE GTKSMB RPC_NDR_ATSVC
# End BINARY gwcrontab
################################################

################################################
# Start BINARY gwsam
[BINARY::gwsam]
INSTALLDIR = BINDIR
OBJ_FILES = tools/gwsam.o tools/gwsam_user.o
REQUIRED_SUBSYSTEMS = CONFIG LIBCMDLINE RPC_NDR_SAMR GTKSMB
# End BINARY gwsam
################################################
