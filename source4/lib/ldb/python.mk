[PYTHON::swig_ldb]
PUBLIC_DEPENDENCIES = LIBLDB
CFLAGS = -Ilib/ldb/include
SWIG_FILE = ldb.i

swig_ldb_OBJ_FILES = lib/ldb/ldb_wrap.o

$(eval $(call python_py_module_template,ldb.py,lib/ldb/ldb.py))
