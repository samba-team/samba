[PYTHON::swig_tdb]
SWIG_FILE = tdb.i
PUBLIC_DEPENDENCIES = LIBTDB DYNCONFIG

swig_tdb_OBJ_FILES = lib/tdb/tdb_wrap.o

$(eval $(call python_py_module_template,tdb.py,lib/tdb/tdb.py))
