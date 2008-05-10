[BINARY::smbpython]
PRIVATE_DEPENDENCIES = LIBPYTHON

smbpython_OBJ_FILES = scripting/python/smbpython.o

[SUBSYSTEM::LIBPYTHON]
PUBLIC_DEPENDENCIES = EXT_LIB_PYTHON
INIT_FUNCTION_SENTINEL = { NULL, NULL }

LIBPYTHON_OBJ_FILES = $(addprefix scripting/python/, modules.o pytalloc.o)

[PYTHON::python_uuid]
PRIVATE_DEPENDENCIES = LIBNDR 

python_uuid_OBJ_FILES = scripting/python/uuidmodule.o

[PYTHON::python_misc]
PRIVATE_DEPENDENCIES = LIBNDR LIBLDB SAMDB CREDENTIALS
SWIG_FILE = misc.i

python_misc_OBJ_FILES = scripting/python/misc_wrap.o

_PY_FILES = $(shell find scripting/python -name "*.py")

$(foreach pyfile, $(_PY_FILES),$(eval $(call python_py_module_template,$(patsubst scripting/python/%,%,$(pyfile)),$(pyfile))))
