[PYTHON::swig_tdb]
LIBRARY_REALNAME = _tdb.$(SHLIBEXT)
PUBLIC_DEPENDENCIES = LIBTDB DYNCONFIG

swig_tdb_OBJ_FILES = $(tdbsrcdir)/tdb_wrap.o

$(eval $(call python_py_module_template,tdb.py,$(tdbsrcdir)/tdb.py))

$(swig_tdb_OBJ_FILES): CFLAGS+=$(CFLAG_NO_UNUSED_MACROS) $(CFLAG_NO_CAST_QUAL)

