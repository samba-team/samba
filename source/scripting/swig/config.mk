# Swig extensions
swig: lib/tdb/swig/_tdb.$(SHLIBEXT) lib/ldb/swig/_ldb.$(SHLIBEXT) \
	libcli/swig/_libcli_nbt.$(SHLIBEXT) libcli/swig/_libcli_smb.$(SHLIBEXT)

.SUFFIXES: _wrap.c .i

.i_wrap.c:
	swig -I$(srcdir)/scripting/swig -python $<

clean::
	@echo "Removing SWIG output files"
	@-rm -f scripting/swig/tdb.pyc scripting/swig/tdb.py

# Swig testing
swigtest: swig
	./selftest/test_swig.sh
