# NTPTR Server subsystem

################################################
# Start MODULE ntptr_simple_ldb
[MODULE::ntptr_simple_ldb]
INIT_FUNCTION = ntptr_simple_ldb_init
SUBSYSTEM = NTPTR
INIT_OBJ_FILES = \
		ntptr/simple_ldb/ntptr_simple_ldb.o
REQUIRED_SUBSYSTEMS = \
		LIBLDB
# End MODULE ntptr_simple_ldb
################################################

################################################
# Start SUBSYSTEM NTPTR
[SUBSYSTEM::NTPTR]
INIT_OBJ_FILES = \
		ntptr/ntptr_base.o
ADD_OBJ_FILES = \
		ntptr/ntptr_interface.o
#
# End SUBSYSTEM NTPTR
################################################
