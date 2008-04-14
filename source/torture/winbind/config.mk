
#################################
# Start SUBSYSTEM TORTURE_WINBIND
[MODULE::TORTURE_WINBIND]
SUBSYSTEM = torture
INIT_FUNCTION = torture_winbind_init
PRIVATE_PROTO_HEADER = \
		proto.h
PRIVATE_DEPENDENCIES = \
		LIBWINBIND-CLIENT
# End SUBSYSTEM TORTURE_WINBIND
#################################

TORTURE_WINBIND_OBJ_FILES = $(addprefix torture/winbind/, winbind.o struct_based.o)

