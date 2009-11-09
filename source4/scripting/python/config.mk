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

[PYTHON::python_glue]
LIBRARY_REALNAME = samba/glue.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = LIBNDR LIBLDB SAMDB CREDENTIALS pyldb python_dcerpc_misc python_dcerpc_security pyauth pyldb_util pyparam_util

python_glue_OBJ_FILES = $(pyscriptsrcdir)/pyglue.o

$(python_glue_OBJ_FILES): CFLAGS+=-I$(ldbsrcdir)

[PYTHON::python_xattr_native]
LIBRARY_REALNAME = samba/xattr_native.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = LIBNDR LIBLDB SAMDB CREDENTIALS  python_dcerpc_security pyparam_util WRAP_XATTR

python_xattr_native_OBJ_FILES = $(pyscriptsrcdir)/pyxattr_native.o

$(python_xattr_native_OBJ_FILES): CFLAGS+=-I$(ldbsrcdir)

#ntvfs_common pvfs_acl
#$(ntvfs_posix_OBJ_FILES)
[PYTHON::python_xattr_tdb]
LIBRARY_REALNAME = samba/xattr_tdb.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = LIBNDR LIBLDB python_dcerpc_security pyparam_util share
#dcerpc_server

python_xattr_tdb_OBJ_FILES = $(pyscriptsrcdir)/pyxattr_tdb.o  $(ntvfssrcdir)/posix/xattr_tdb.o
#{$(ntvfssrcdir)/ntvfs_interface.o
#$(ntvfs_posix_OBJ_FILES)

$(python_xattr_tdb_OBJ_FILES): CFLAGS+=-I$(ldbsrcdir)

_PY_FILES = $(shell find $(pyscriptsrcdir)/samba ../lib/subunit/python -name "*.py")

$(eval $(foreach pyfile, $(_PY_FILES),$(call python_py_module_template,$(patsubst $(pyscriptsrcdir)/%,%,$(subst ../lib/subunit/python,,$(pyfile))),$(pyfile))))

EPYDOC_OPTIONS = --no-private --url http://www.samba.org/ --no-sourcecode

epydoc:: pythonmods
	PYTHONPATH=$(pythonbuilddir):../lib/subunit/python epydoc $(EPYDOC_OPTIONS) samba tdb ldb subunit testtools

install:: installpython
