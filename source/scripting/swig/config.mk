#######################
# Start LIBRARY swig_dcerpc
[LIBRARY::swig_dcerpc]
LIBRARY_REALNAME = _dcerpc.$(SHLIBEXT)
PUBLIC_DEPENDENCIES = LIBCLI_SMB NDR_MISC LIBSAMBA-UTIL LIBSAMBA-CONFIG dcerpc_samr RPC_NDR_LSA DYNCONFIG
OBJ_FILES = dcerpc_wrap.o
# End LIBRARY swig_dcerpc
#######################

# Swig extensions
swig: lib/tdb/swig/_tdb.$(SHLIBEXT) lib/ldb/swig/_ldb.$(SHLIBEXT) \
	libcli/swig/_libcli_nbt.$(SHLIBEXT)

.SUFFIXES: _wrap.c .i

.i_wrap.c:
	swig -I$(srcdir)/scripting/swig -python $<

SWIG_INCLUDES = librpc/gen_ndr/samr.i librpc/gen_ndr/lsa.i librpc/gen_ndr/spoolss.i

scripting/swig/dcerpc_wrap.c: scripting/swig/dcerpc.i scripting/swig/samba.i scripting/swig/status_codes.i $(SWIG_INCLUDES)

clean::
	@echo "Removing SWIG output files"
	@-rm -f scripting/swig/tdb.pyc scripting/swig/tdb.py

# Swig testing

swigtest: swig
	./script/tests/test_swig.sh
