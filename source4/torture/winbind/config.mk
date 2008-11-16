
#################################
# Start SUBSYSTEM TORTURE_WINBIND
[MODULE::TORTURE_WINBIND]
SUBSYSTEM = smbtorture
INIT_FUNCTION = torture_winbind_init
PRIVATE_DEPENDENCIES = \
		LIBWINBIND-CLIENT torture
# End SUBSYSTEM TORTURE_WINBIND
#################################

TORTURE_WINBIND_OBJ_FILES = $(addprefix $(torturesrcdir)/winbind/, winbind.o struct_based.o)

$(eval $(call proto_header_template,$(torturesrcdir)/winbind/proto.h,$(TORTURE_WINBIND_OBJ_FILES:.o=.c)))

