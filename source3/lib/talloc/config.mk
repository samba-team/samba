[LIBRARY::LIBTALLOC]
OUTPUT_TYPE = MERGED_OBJ
CFLAGS = -Ilib/talloc

LIBTALLOC_OBJ_FILES = lib/talloc/talloc.o

MANPAGES += $(tallocdir)/talloc.3
