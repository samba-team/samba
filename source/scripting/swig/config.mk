# Swig extensions
swig: pythonmods

pythonmods: $(PYTHON_DSOS)
	
.SUFFIXES: _wrap.c .i

.i_wrap.c:
	swig -Wall -I$(srcdir)/scripting/swig -python $<

clean::
	@echo "Removing SWIG output files"
	@-rm -f bin/python/*
	# FIXME: Remove _wrap.c files

PYDOCTOR_MODULES=bin/python/ldb.py bin/python/auth.py bin/python/credentials.py bin/python/registry.py

pydoctor::
	LD_LIBRARY_PATH=bin/shared PYTHONPATH=bin/python pydoctor --make-html --docformat=restructedtext --add-package scripting/python/samba/ $(addprefix --add-module , $(PYDOCTOR_MODULES))
