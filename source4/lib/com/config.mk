[SUBSYSTEM::COM]

COM_OBJ_FILES = $(addprefix lib/com/, tables.o rot.o main.o)

[SUBSYSTEM::DCOM]
PUBLIC_DEPENDENCIES = com DCOM_PROXY_DCOM RPC_NDR_REMACT \
					  RPC_NDR_OXIDRESOLVER

DCOM_OBJ_FILES = $(addprefix lib/com/dcom/, main.o tables.o)

[MODULE::com_simple]
SUBSYSTEM = COM
INIT_FUNCTION = com_simple_init

com_simple_OBJ_FILES = lib/com/classes/simple.o
