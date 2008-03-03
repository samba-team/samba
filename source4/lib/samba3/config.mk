################################################
# Start SUBSYSTEM LIBSAMBA3
[SUBSYSTEM::SMBPASSWD]
PRIVATE_PROTO_HEADER = samba3_smbpasswd_proto.h
PRIVATE_DEPENDENCIES = CHARSET LIBSAMBA-UTIL
# End SUBSYSTEM LIBSAMBA3
################################################

SMBPASSWD_OBJ_FILES = lib/samba3/smbpasswd.o
