# TORTURE subsystem
[LIBRARY::torture]
PUBLIC_DEPENDENCIES = \
		LIBSAMBA-HOSTCONFIG \
		LIBSAMBA-UTIL \
		LIBTALLOC

PC_FILES += lib/torture/torture.pc
torture_OBJ_FILES = $(addprefix lib/torture/, torture.o)

PUBLIC_HEADERS += lib/torture/torture.h
