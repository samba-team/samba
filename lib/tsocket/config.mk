[SUBSYSTEM::LIBTSOCKET]
PRIVATE_DEPENDENCIES = LIBTALLOC LIBTEVENT LIBREPLACE_NETWORK

LIBTSOCKET_OBJ_FILES = $(addprefix ../lib/tsocket/, \
					tsocket.o)

PUBLIC_HEADERS += $(addprefix ../lib/tsocket/, \
				 tsocket.h\
				 tsocket_internal.h)

