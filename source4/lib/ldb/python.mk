[PYTHON::swig_ldb]
LIBRARY_REALNAME = _ldb.$(SHLIBEXT)
PUBLIC_DEPENDENCIES = LIBLDB LIBEVENTS

swig_ldb_OBJ_FILES = $(ldbsrcdir)/ldb_wrap.o
$(swig_ldb_OBJ_FILES): CFLAGS+=-I$(ldbsrcdir)/include

$(eval $(call python_py_module_template,ldb.py,$(ldbsrcdir)/ldb.py))

$(swig_ldb_OBJ_FILES): CFLAGS+=$(CFLAG_NO_UNUSED_MACROS) $(CFLAG_NO_CAST_QUAL)
