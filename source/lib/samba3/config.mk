################################################
# Start SUBSYSTEM LIBSAMBA3
[LIBRARY::LIBSAMBA3]
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = Library for reading Samba3 data files
PRIVATE_PROTO_HEADER = samba3_proto.h
PUBLIC_HEADERS = samba3.h
OBJ_FILES = tdbsam.o policy.o \
		idmap.o winsdb.o samba3.o group.o \
		registry.o secrets.o share_info.o
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL LIBTDB NDR_SECURITY \
					   CREDENTIALS SMBPASSWD LIBSECURITY 
# End SUBSYSTEM LIBSAMBA3
################################################

################################################
# Start SUBSYSTEM LIBSAMBA3
[SUBSYSTEM::SMBPASSWD]
PRIVATE_PROTO_HEADER = samba3_smbpasswd_proto.h
OBJ_FILES = smbpasswd.o
PRIVATE_DEPENDENCIES = CHARSET LIBSAMBA-UTIL
# End SUBSYSTEM LIBSAMBA3
################################################
