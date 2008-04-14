[PYTHON::swig_ldb]
PUBLIC_DEPENDENCIES = LIBLDB
CFLAGS = -Ilib/ldb/include
SWIG_FILE = ldb.i

swig_ldb_OBJ_FILES = lib/ldb/ldb_wrap.o
