################################################
# Start SUBSYSTEM LIBSAMBA3
[LIBRARY::LIBSAMBA3]
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
DESCRIPTION = Library for reading Samba3 data files
PUBLIC_HEADERS = samba3.h
OBJ_FILES = smbpasswd.o tdbsam.o policy.o \
		idmap.o winsdb.o samba3.o group.o \
		registry.o secrets.o share_info.o
# End SUBSYSTEM LIBSAMBA3
################################################
