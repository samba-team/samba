[SUBSYSTEM::LIBCOM]
INIT_OBJ_FILES = \
		lib/com/tables.o \
		lib/com/rot.o \
		lib/com/main.o

################################################
# Start SUBSYSTEM LIBDCOM
[SUBSYSTEM::LIBDCOM]
INIT_OBJ_FILES = \
		lib/com/dcom/main.o \
		lib/com/dcom/tables.o
REQUIRED_SUBSYSTEMS = LIBCOM DCOM_PROXY_DCOM RPC_NDR_REMACT \
					  RPC_NDR_OXIDRESOLVER
# End SUBSYSTEM LIBDCOM
################################################

[MODULE::com_simple]
SUBSYSTEM = LIBCOM
INIT_OBJ_FILES = lib/com/classes/simple.o
INIT_FUNCTION = com_simple_init
