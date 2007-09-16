
#################################
# Start SUBSYSTEM TORTURE_WINBIND
[MODULE::TORTURE_WINBIND]
SUBSYSTEM = torture
INIT_FUNCTION = torture_winbind_init
PRIVATE_PROTO_HEADER = \
		proto.h
OBJ_FILES = \
		winbind.o
PRIVATE_DEPENDENCIES = \
		POPT_CREDENTIALS
# End SUBSYSTEM TORTURE_WINBIND
#################################
