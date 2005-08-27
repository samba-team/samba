################################################
# Start SUBSYSTEM LIBSAMBA3
[SUBSYSTEM::LIBSAMBA3]
ADD_OBJ_FILES = \
		lib/samba3/smbpasswd.o \
		lib/samba3/tdbsam.o \
		lib/samba3/policy.o \
		lib/samba3/idmap.o \
		lib/samba3/winsdb.o \
		lib/samba3/samba3.o \
		lib/samba3/group.o \
		lib/samba3/registry.o \
		lib/samba3/secrets.o \
		lib/samba3/share_info.o \
		lib/samba3/upgrade.o
# End SUBSYSTEM LIBSAMBA3
################################################

################################################
# Start BINARY samba3dump
[BINARY::samba3dump]
INSTALLDIR = BINDIR
INIT_OBJ_FILES = \
		lib/samba3/samba3dump.o
REQUIRED_SUBSYSTEMS = LIBBASIC LIBCMDLINE LIBSAMBA3
# End BINARY samba3dump
################################################
