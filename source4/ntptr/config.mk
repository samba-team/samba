# ntptr server subsystem

################################################
# Start MODULE ntptr_simple_ldb
[MODULE::ntptr_simple_ldb]
INIT_FUNCTION = ntptr_simple_ldb_init
SUBSYSTEM = ntptr
PRIVATE_DEPENDENCIES = \
		LIBLDB NDR_SPOOLSS DCERPC_COMMON
# End MODULE ntptr_simple_ldb
################################################

ntptr_simple_ldb_OBJ_FILES = ntptr/simple_ldb/ntptr_simple_ldb.o

################################################
# Start SUBSYSTEM ntptr
[SUBSYSTEM::ntptr]
PRIVATE_PROTO_HEADER = ntptr_proto.h
PUBLIC_DEPENDENCIES = DCERPC_COMMON
#
# End SUBSYSTEM ntptr
################################################

NTPTR_OBJ_FILES = \
		ntptr_base.o \
		ntptr_interface.o
