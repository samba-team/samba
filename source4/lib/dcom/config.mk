################################################
# Start SUBSYSTEM LIBDCOM
[SUBSYSTEM::LIBDCOM]
INIT_OBJ_FILES = \
		lib/dcom/common/main.o \
		lib/dcom/common/tables.o
REQUIRED_SUBSYSTEMS = LIBRPC
#
# End SUBSYSTEM LIBDCOM
################################################
