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

# Swig extensions
swig:: pythonmods

.SUFFIXES: _wrap.c .i

.i_wrap.c:
	[ "$(SWIG)" == "no" ] || $(SWIG) -O -Wall -I$(srcdir)/scripting/swig -python -keyword $<

realdistclean::
	@echo "Removing SWIG output files"
	@-rm -rf bin/python/*
	# FIXME: Remove _wrap.c files

pythonmods:: $(PYTHON_DSOS) $(PYTHON_PYS)

PYDOCTOR_MODULES=bin/python/ldb.py bin/python/auth.py bin/python/credentials.py bin/python/registry.py bin/python/tdb.py bin/python/security.py bin/python/events.py bin/python/net.py

pydoctor:: pythonmods
	LD_LIBRARY_PATH=bin/shared PYTHONPATH=bin/python pydoctor --project-name=Samba --make-html --docformat=restructuredtext --add-package scripting/python/samba/ $(addprefix --add-module , $(PYDOCTOR_MODULES))

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
	@rm -f bin/python/*
