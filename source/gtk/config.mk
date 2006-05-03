# LIB GTK SMB subsystem

[LIBRARY::gtksamba]
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = Common Samba-related widgets for GTK+ applications
PUBLIC_HEADERS = common/gtk-smb.h common/select.h
OBJ_FILES = common/gtk-smb.o \
		common/select.o \
		common/gtk_events.o \
		common/credentials.o
PRIVATE_DEPENDENCIES = CHARSET LIBSAMBA-UTIL gtk RPC_NDR_SAMR

[BINARY::gregedit]
INSTALLDIR = BINDIR
OBJ_FILES = tools/gregedit.o
PRIVATE_DEPENDENCIES = LIBSAMBA-CONFIG registry gtksamba
MANPAGE = man/gregedit.1

[BINARY::gepdump]
INSTALLDIR = BINDIR
MANPAGE = man/gepdump.1
OBJ_FILES = tools/gepdump.o
PRIVATE_DEPENDENCIES = LIBSAMBA-CONFIG gtksamba RPC_NDR_EPMAPPER RPC_NDR_MGMT

[BINARY::gwcrontab]
INSTALLDIR = BINDIR
MANPAGE = man/gwcrontab.1
OBJ_FILES = tools/gwcrontab.o
PRIVATE_DEPENDENCIES = LIBSAMBA-CONFIG gtksamba RPC_NDR_ATSVC

[BINARY::gwsvcctl]
INSTALLDIR = BINDIR
MANPAGE = man/gwsvcctl.1
OBJ_FILES = tools/gwsvcctl.o
PRIVATE_DEPENDENCIES = LIBSAMBA-CONFIG gtksamba RPC_NDR_SVCCTL

# This binary is disabled for now as it doesn't do anything useful yet...
[BINARY::gwsam]
#INSTALLDIR = BINDIR
OBJ_FILES = tools/gwsam.o tools/gwsam_user.o
PRIVATE_DEPENDENCIES = LIBSAMBA-CONFIG RPC_NDR_SAMR gtksamba
