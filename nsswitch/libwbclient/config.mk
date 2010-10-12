[SUBSYSTEM::LIBWBCLIENT]
PUBLIC_DEPENDENCIES = LIBTALLOC

LIBWBCLIENT_OBJ_FILES = $(addprefix $(libwbclientsrcdir)/, wbc_guid.o \
								wbc_idmap.o \
								wbclient.o \
								wbc_pam.o \
								wbc_pwd.o \
								wbc_sid.o \
								wbc_util.o )
