[SUBSYSTEM::LIBPYTHON]
PUBLIC_DEPENDENCIES = EXT_LIB_PYTHON
PRIVATE_DEPENDENCIES = PYTALLOC
INIT_FUNCTION_SENTINEL = { NULL, NULL }

LIBPYTHON_OBJ_FILES = $(addprefix $(pyscriptsrcdir)/, modules.o)

[SUBSYSTEM::PYTALLOC]
PUBLIC_DEPENDENCIES = EXT_LIB_PYTHON LIBTALLOC

PYTALLOC_OBJ_FILES = ../lib/talloc/pytalloc.o

[PYTHON::python_uuid]
PRIVATE_DEPENDENCIES = LIBNDR 

python_uuid_OBJ_FILES = $(pyscriptsrcdir)/uuidmodule.o

[PYTHON::python_misc]
LIBRARY_REALNAME = samba/misc.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = LIBNDR LIBLDB SAMDB CREDENTIALS swig_ldb

python_misc_OBJ_FILES = $(pyscriptsrcdir)/pymisc.o

$(python_misc_OBJ_FILES): CFLAGS+=$(CFLAG_NO_CAST_QUAL) -I$(ldbsrcdir)

_PY_FILES = $(shell find $(pyscriptsrcdir)/samba ../lib/subunit/python -name "*.py")

$(eval $(foreach pyfile, $(_PY_FILES),$(call python_py_module_template,$(patsubst $(pyscriptsrcdir)/%,%,$(pyfile)),$(pyfile))))

EPYDOC_OPTIONS = --no-private --url http://www.samba.org/ --no-sourcecode

epydoc:: pythonmods
	PYTHONPATH=$(pythonbuilddir):../lib/subunit/python epydoc $(EPYDOC_OPTIONS) samba tdb ldb subunit

install:: installpython
