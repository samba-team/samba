[BINARY::smbpython]
PRIVATE_DEPENDENCIES = LIBPYTHON
OBJ_FILES = smbpython.o

[SUBSYSTEM::LIBPYTHON]
PUBLIC_DEPENDENCIES = EXT_LIB_PYTHON
INIT_FUNCTION_SENTINEL = { NULL, NULL }
OBJ_FILES = modules.o pytalloc.o

[PYTHON::python_uuid]
PRIVATE_DEPENDENCIES = LIBNDR 
OBJ_FILES = uuidmodule.o

[PYTHON::python_misc]
PRIVATE_DEPENDENCIES = LIBNDR LIBLDB SAMDB CREDENTIALS
SWIG_FILE = misc.i

_PY_FILES = $(shell find scripting/python -name "*.py")

$(foreach pyfile, $(_PY_FILES),$(eval $(call python_py_module_template,$(patsubst scripting/python/%,%,$(pyfile)),$(pyfile))))
