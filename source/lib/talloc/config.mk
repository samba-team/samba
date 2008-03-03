[LIBRARY::LIBTALLOC]
OUTPUT_TYPE = STATIC_LIBRARY
CFLAGS = -Ilib/talloc

LIBTALLOC_OBJ_FILES = lib/talloc/talloc.o

MANPAGES += $(tallocdir)/talloc.3
PUBLIC_HEADERS += $(tallocdir)/talloc.h
