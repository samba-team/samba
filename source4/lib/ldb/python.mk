[PYTHON::swig_ldb]
LIBRARY_REALNAME = _ldb.$(SHLIBEXT)
PUBLIC_DEPENDENCIES = LIBLDB

swig_ldb_OBJ_FILES = $(ldbdir)/ldb_wrap.o
$(swig_ldb_OBJ_FILES): CFLAGS+=-I$(ldbdir)/include

$(eval $(call python_py_module_template,ldb.py,$(ldbdir)/ldb.py))

$(swig_ldb_OBJ_FILES): CFLAGS+=$(CFLAG_NO_UNUSED_MACROS) $(CFLAG_NO_CAST_QUAL)
