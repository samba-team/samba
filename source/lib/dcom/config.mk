################################################
# Start SUBSYSTEM LIBDCOM
#[SUBSYSTEM::LIBDCOM]
#ENABLE = NO
#INIT_OBJ_FILES = \
#		lib/dcom/common/main.o
#REQUIRED_SUBSYSTEMS = LIBCOM DCOM_PROXY_DCOM RPC_NDR_REMACT \
#					  RPC_NDR_OXIDRESOLVER

#[MODULE::DCOM_SIMPLE]
#ENABLE = NO
#SUBSYSTEM = LIBDCOM
#REQUIRED_SUBSYSTEMS = DCOM_PROXY_DCOM
#INIT_FUNCTION = dcom_simple_init
#INIT_OBJ_FILES = \
#		lib/dcom/classes/simple.o
#
# End SUBSYSTEM LIBDCOM
################################################
