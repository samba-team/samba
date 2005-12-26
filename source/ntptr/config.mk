# NTPTR Server subsystem

################################################
# Start MODULE ntptr_simple_ldb
[MODULE::ntptr_simple_ldb]
INIT_FUNCTION = ntptr_simple_ldb_init
SUBSYSTEM = NTPTR
OBJ_FILES = \
		simple_ldb/ntptr_simple_ldb.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB
# End MODULE ntptr_simple_ldb
################################################

################################################
# Start SUBSYSTEM NTPTR
[SUBSYSTEM::NTPTR]
INIT_FUNCTION = ntptr_init
OBJ_FILES = \
		ntptr_base.o \
		ntptr_interface.o
#
# End SUBSYSTEM NTPTR
################################################
