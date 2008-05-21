[PYTHON::swig_tdb]
LIBRARY_REALNAME = _tdb.$(SHLIBEXT)
PUBLIC_DEPENDENCIES = LIBTDB DYNCONFIG

swig_tdb_OBJ_FILES = lib/tdb/tdb_wrap.o

$(eval $(call python_py_module_template,tdb.py,lib/tdb/tdb.py))

$(swig_tdb_OBJ_FILES): CFLAGS+="$(CFLAG_NO_UNUSED_MACROS) $(CFLAG_NO_CAST_QUAL)"

