[PYTHON::swig_ldb]
LIBRARY_REALNAME = _ldb.$(SHLIBEXT)
PUBLIC_DEPENDENCIES = LIBLDB
CFLAGS = -Ilib/ldb/include

swig_ldb_OBJ_FILES = lib/ldb/ldb_wrap.o

$(eval $(call python_py_module_template,ldb.py,lib/ldb/ldb.py))

$(swig_ldb_OBJ_FILES): CFLAGS+="$(CFLAG_NO_UNUSED_MACROS) $(CFLAG_NO_CAST_QUAL)"
