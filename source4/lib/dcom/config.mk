################################################
# Start SUBSYSTEM LIBDCOM
[SUBSYSTEM::LIBDCOM]
INIT_OBJ_FILES = \
		lib/dcom/common/main.o \
		lib/dcom/common/tables.o \
		lib/dcom/common/rot.o
REQUIRED_SUBSYSTEMS = DCOM_PROXY_DCOM RPC_NDR_REMACT \
					  RPC_NDR_OXIDRESOLVER

[MODULE::DCOM_SIMPLE]
SUBSYSTEM = LIBDCOM
INIT_FUNCTION = dcom_simple_init
INIT_OBJ_FILES = \
		lib/dcom/classes/simple.o
#
# End SUBSYSTEM LIBDCOM
################################################
