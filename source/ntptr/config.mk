# ntptr server subsystem

################################################
# Start MODULE ntptr_simple_ldb
[MODULE::ntptr_simple_ldb]
INIT_FUNCTION = ntptr_simple_ldb_init
SUBSYSTEM = ntptr
OBJ_FILES = \
		simple_ldb/ntptr_simple_ldb.o
PRIVATE_DEPENDENCIES = \
		LIBLDB NDR_SPOOLSS DCERPC_COMMON
# End MODULE ntptr_simple_ldb
################################################

################################################
# Start SUBSYSTEM ntptr
[LIBRARY::ntptr]
PRIVATE_PROTO_HEADER = ntptr_proto.h
OBJ_FILES = \
		ntptr_base.o \
		ntptr_interface.o
PUBLIC_DEPENDENCIES = DCERPC_COMMON
#
# End SUBSYSTEM ntptr
################################################
