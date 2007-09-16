
#################################
# Start SUBSYSTEM TORTURE_WINBIND
[MODULE::TORTURE_WINBIND]
SUBSYSTEM = torture
INIT_FUNCTION = torture_winbind_init
PRIVATE_PROTO_HEADER = \
		proto.h
OBJ_FILES = \
		winbind.o \
		struct_based.o
PRIVATE_DEPENDENCIES = \
		LIBWINBIND-CLIENT
# End SUBSYSTEM TORTURE_WINBIND
#################################
