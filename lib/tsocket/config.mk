[SUBSYSTEM::LIBTSOCKET]
PRIVATE_DEPENDENCIES = LIBTALLOC LIBTEVENT LIBREPLACE_NETWORK

LIBTSOCKET_OBJ_FILES = $(addprefix ../lib/tsocket/, \
					tsocket.o \
					tsocket_helpers.o \
					tsocket_bsd.o \
					tsocket_recvfrom.o \
					tsocket_sendto.o \
					tsocket_connect.o \
					tsocket_writev.o)

PUBLIC_HEADERS += $(addprefix ../lib/tsocket/, \
				 tsocket.h\
				 tsocket_internal.h)

