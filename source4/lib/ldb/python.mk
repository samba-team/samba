[PYTHON::swig_ldb]
LIBRARY_REALNAME = ldb.$(SHLIBEXT)
PUBLIC_DEPENDENCIES = LIBLDB LIBEVENTS PYTALLOC

swig_ldb_OBJ_FILES = $(ldbsrcdir)/pyldb.o
$(swig_ldb_OBJ_FILES): CFLAGS+=-I$(ldbsrcdir)/include

$(swig_ldb_OBJ_FILES): CFLAGS+=$(CFLAG_NO_CAST_QUAL)
