# TORTURE subsystem
[LIBRARY::torture]
PUBLIC_DEPENDENCIES = \
		LIBSAMBA-HOSTCONFIG \
		LIBSAMBA-UTIL \
		LIBTALLOC

torture_VERSION = 0.0.1
torture_SO_VERSION = 0

PC_FILES += lib/torture/torture.pc
torture_OBJ_FILES = $(addprefix lib/torture/, torture.o)

PUBLIC_HEADERS += lib/torture/torture.h
