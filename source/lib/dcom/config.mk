################################################
# Start SUBSYSTEM LIBDCOM
[SUBSYSTEM::LIBDCOM]
INIT_OBJ_FILES = \
		lib/dcom/common/main.o \
		lib/dcom/common/tables.o
REQUIRED_SUBSYSTEMS = LIBNDR_RAW LIBNDR_GEN LIBRPC_RAW
#
# End SUBSYSTEM LIBDCOM
################################################
