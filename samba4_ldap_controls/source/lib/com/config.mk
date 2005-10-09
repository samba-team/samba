[SUBSYSTEM::COM]
INIT_OBJ_FILES = \
		lib/com/tables.o \
		lib/com/rot.o \
		lib/com/main.o

[SUBSYSTEM::DCOM]
INIT_OBJ_FILES = \
		lib/com/dcom/main.o \
		lib/com/dcom/tables.o
REQUIRED_SUBSYSTEMS = COM DCOM_PROXY_DCOM RPC_NDR_REMACT \
					  RPC_NDR_OXIDRESOLVER

[MODULE::com_simple]
SUBSYSTEM = COM
INIT_OBJ_FILES = lib/com/classes/simple.o
INIT_FUNCTION = com_simple_init
