[PYTHON::python_param]
PRIVATE_DEPENDENCIES = LIBSAMBA-CONFIG 
OBJ_FILES = parammodule.o

[PYTHON::python_uuid]
PRIVATE_DEPENDENCIES = LIBNDR 
OBJ_FILES = uuidmodule.o

[PYTHON::python_misc]
PRIVATE_DEPENDENCIES = LIBNDR LIBLDB
SWIG_FILE = misc.i

# Swig extensions
swig: pythonmods

.SUFFIXES: _wrap.c .i

.i_wrap.c:
	$(SWIG) -Wall -I$(srcdir)/scripting/swig -python -keyword $<

realdistclean::
	@echo "Removing SWIG output files"
	@-rm -f bin/python/*
	# FIXME: Remove _wrap.c files

pythonmods: $(PYTHON_DSOS)

PYDOCTOR_MODULES=bin/python/ldb.py bin/python/auth.py bin/python/credentials.py bin/python/registry.py bin/python/tdb.py bin/python/security.py

pydoctor:: pythonmods
	LD_LIBRARY_PATH=bin/shared PYTHONPATH=bin/python pydoctor --make-html --docformat=restructuredtext --add-package scripting/python/samba/ $(addprefix --add-module , $(PYDOCTOR_MODULES))
