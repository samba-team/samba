################################################
# Start LIBRARY ntvfs_common
[SUBSYSTEM::ntvfs_common]
PRIVATE_PROTO_HEADER = proto.h
PUBLIC_DEPENDENCIES = NDR_OPENDB NDR_NOTIFY sys_notify share LIBDBWRAP
PRIVATE_DEPENDENCIES = brlock_ctdb opendb_ctdb
# End LIBRARY ntvfs_common
################################################

ntvfs_common_OBJ_FILES = $(addprefix ntvfs/common/, init.o brlock.o brlock_tdb.o opendb.o opendb_tdb.o notify.o)

