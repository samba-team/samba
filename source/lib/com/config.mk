[SUBSYSTEM::COM]
INIT_FUNCTION = com_init
INIT_OBJ_FILES = \
		tables.o \
		rot.o \
		main.o

[SUBSYSTEM::DCOM]
INIT_OBJ_FILES = \
		dcom/main.o \
		dcom/tables.o
REQUIRED_SUBSYSTEMS = COM DCOM_PROXY_DCOM RPC_NDR_REMACT \
					  RPC_NDR_OXIDRESOLVER

[MODULE::com_simple]
SUBSYSTEM = COM
INIT_OBJ_FILES = classes/simple.o
INIT_FUNCTION = com_simple_init
