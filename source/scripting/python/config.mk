[SUBSYSTEM::LIBPYTHON]
PUBLIC_DEPENDENCIES = EXT_LIB_PYTHON
PRIVATE_DEPENDENCIES = PYTALLOC
INIT_FUNCTION_SENTINEL = { NULL, NULL }

LIBPYTHON_OBJ_FILES = $(addprefix $(pyscriptdir)/, modules.o)

[SUBSYSTEM::PYTALLOC]
PUBLIC_DEPENDENCIES = EXT_LIB_PYTHON

PYTALLOC_OBJ_FILES = $(addprefix $(pyscriptdir)/, pytalloc.o)

[PYTHON::python_uuid]
PRIVATE_DEPENDENCIES = LIBNDR 

python_uuid_OBJ_FILES = $(pyscriptdir)/uuidmodule.o

[PYTHON::python_misc]
PRIVATE_DEPENDENCIES = LIBNDR LIBLDB SAMDB CREDENTIALS
SWIG_FILE = misc.i

python_misc_OBJ_FILES = $(pyscriptdir)/misc_wrap.o

_PY_FILES = $(shell find $(pyscriptdir) -name "*.py")

$(foreach pyfile, $(_PY_FILES),$(eval $(call python_py_module_template,$(patsubst $(pyscriptdir)/%,%,$(pyfile)),$(pyfile))))

install:: installpython
