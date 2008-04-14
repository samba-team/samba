[BINARY::smbpython]
PRIVATE_DEPENDENCIES = LIBPYTHON

smbpython_OBJ_FILES = smbpython.o

[SUBSYSTEM::LIBPYTHON]
PUBLIC_DEPENDENCIES = EXT_LIB_PYTHON
INIT_FUNCTION_SENTINEL = { NULL, NULL }

LIBPYTHON_OBJ_FILES = modules.o pytalloc.o

[PYTHON::python_uuid]
PRIVATE_DEPENDENCIES = LIBNDR 

python_uuid_OBJ_FILES = uuidmodule.o

[PYTHON::python_misc]
PRIVATE_DEPENDENCIES = LIBNDR LIBLDB SAMDB CREDENTIALS
SWIG_FILE = misc.i

PYDOCTOR_MODULES=bin/python/ldb.py bin/python/auth.py bin/python/credentials.py bin/python/registry.py bin/python/tdb.py bin/python/security.py bin/python/events.py bin/python/net.py

pythonmods:: $(PYTHON_PYS) $(PYTHON_MODS)

bin/python/%.py: 
	mkdir -p $(@D)
	cp $< $@

installpython:: pythonmods
	@$(SHELL) $(srcdir)/script/installpython.sh \
		$(INSTALLPERMS) \
		$(DESTDIR)$(PYTHONDIR) \
		scripting/python bin/python

clean::
	@echo "Removing python modules"
	@rm -rf bin/python/*
