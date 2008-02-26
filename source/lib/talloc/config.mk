[LIBRARY::LIBTALLOC]
OUTPUT_TYPE = STATIC_LIBRARY
OBJ_FILES = talloc.o
CFLAGS = -Ilib/talloc
PUBLIC_HEADERS = talloc.h


MANPAGES += $(tallocdir)/talloc.3
