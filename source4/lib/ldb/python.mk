[PYTHON::pyldb]
LIBRARY_REALNAME = ldb.$(SHLIBEXT)
PUBLIC_DEPENDENCIES = LIBLDB PYTALLOC
PRIVATE_DEPENDENCIES = pyldb_util

pyldb_OBJ_FILES = $(ldbsrcdir)/pyldb.o 
$(pyldb_OBJ_FILES): CFLAGS+=-I$(ldbsrcdir)/include

[SUBSYSTEM::pyldb_util]
PUBLIC_DEPENDENCIES = LIBPYTHON
PRIVATE_DEPENDENCIES = LIBLDB

pyldb_util_OBJ_FILES = $(ldbsrcdir)/pyldb_util.o
$(pyldb_OBJ_FILES): CFLAGS+=-I$(ldbsrcdir)/include
