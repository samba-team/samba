################################################
# Start SUBSYSTEM LIBSAMBA3
[SUBSYSTEM::SMBPASSWD]
PRIVATE_PROTO_HEADER = samba3_smbpasswd_proto.h
OBJ_FILES = smbpasswd.o
PRIVATE_DEPENDENCIES = CHARSET LIBSAMBA-UTIL
# End SUBSYSTEM LIBSAMBA3
################################################
