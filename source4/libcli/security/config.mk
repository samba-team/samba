[SUBSYSTEM::LIBSECURITY]
PUBLIC_DEPENDENCIES = LIBNDR LIBSECURITY_COMMON

LIBSECURITY_OBJ_FILES = $(addprefix $(libclisrcdir)/security/, \
					   security_token.o security_descriptor.o \
					   access_check.o privilege.o sddl.o) \
					   ../libcli/security/secace.o \
					   ../libcli/security/secacl.o

$(eval $(call proto_header_template,$(libclisrcdir)/security/proto.h,$(LIBSECURITY_OBJ_FILES:.o=.c)))
