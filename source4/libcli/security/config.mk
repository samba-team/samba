[SUBSYSTEM::LIBSECURITY]
PUBLIC_DEPENDENCIES = LIBNDR

LIBSECURITY_OBJ_FILES = $(addprefix $(libclisrcdir)/security/, \
					   security_token.o security_descriptor.o \
					   dom_sid.o access_check.o privilege.o sddl.o)

$(eval $(call proto_header_template,$(libclisrcdir)/security/proto.h,$(LIBSECURITY_OBJ_FILES:.o=.c)))
