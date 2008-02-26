pythonbuilddir = $(builddir)/bin/python

# Install Python
# Arguments: Module path, source location
define python_module_template

$$(pythonbuilddir)/$(1): $(2) ;
	mkdir -p $$(@D)
	cp $$< $$@

installpython:: $$(pythonbuilddir)/$(1) ;
	cp $$< $$(DESTDIR)$$(PYTHONDIR)/$(1)

uninstallpython:: 
	rm -f $$(DESTDIR)$$(PYTHONDIR)/$(1) ;

pythonmods:: $$(pythonbuilddir)/$(1) ;

endef

# Swig extensions
swig:: pythonmods

.SUFFIXES: _wrap.c .i

.i_wrap.c:
	[ "$(SWIG)" == "no" ] || $(SWIG) -O -Wall -I$(srcdir)/scripting/swig -python -keyword $<

realdistclean::
	@echo "Removing SWIG output files"
	# FIXME: Remove _wrap.c files

pythonmods::

clean::
	@echo "Removing python modules"
	@rm -rf $(pythonbuilddir)
