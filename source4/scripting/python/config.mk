[SUBSYSTEM::LIBPYTHON]
PUBLIC_DEPENDENCIES = EXT_LIB_PYTHON
PRIVATE_DEPENDENCIES = PYTALLOC
INIT_FUNCTION_SENTINEL = { NULL, NULL }

LIBPYTHON_OBJ_FILES = $(addprefix $(pyscriptsrcdir)/, modules.o)

[SUBSYSTEM::PYTALLOC]
PUBLIC_DEPENDENCIES = EXT_LIB_PYTHON

PYTALLOC_OBJ_FILES = $(addprefix $(pyscriptsrcdir)/, pytalloc.o)

[PYTHON::python_uuid]
PRIVATE_DEPENDENCIES = LIBNDR 

python_uuid_OBJ_FILES = $(pyscriptsrcdir)/uuidmodule.o

[PYTHON::python_misc]
PRIVATE_DEPENDENCIES = LIBNDR LIBLDB SAMDB CREDENTIALS
SWIG_FILE = misc.i

python_misc_OBJ_FILES = $(pyscriptsrcdir)/misc_wrap.o

$(python_misc_OBJ_FILES): CFLAGS+="$(CFLAG_NO_UNUSED_MACROS) $(CFLAG_NO_CAST_QUAL)"

_PY_FILES = $(shell find $(pyscriptsrcdir) -name "*.py")

$(foreach pyfile, $(_PY_FILES),$(eval $(call python_py_module_template,$(patsubst $(pyscriptsrcdir)/%,%,$(pyfile)),$(pyfile))))

install:: installpython
