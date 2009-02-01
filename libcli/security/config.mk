[SUBSYSTEM::LIBSECURITY_COMMON]
PRIVATE_DEPENDENCIES = TALLOC

LIBSECURITY_COMMON_OBJ_FILES = $(addprefix $(libclicommonsrcdir)/security/, \
					dom_sid.o)
