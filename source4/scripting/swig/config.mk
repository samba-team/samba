#######################
# Start LIBRARY swig_tdb
[LIBRARY::swig_tdb]
LIBRARY_REALNAME = _tdb.$(SHLIBEXT)
OBJ_FILES = tdb_wrap.o
REQUIRED_SUBSYSTEMS = LIBTDB DYNCONFIG
# End LIBRARY swig_tdb
#######################

#######################
# Start LIBRARY swig_ldb
[LIBRARY::swig_ldb]
REQUIRED_SUBSYSTEMS = ldb DYNCONFIG
LIBRARY_REALNAME = _ldb.$(SHLIBEXT)
OBJ_FILES = ldb_wrap.o
# End LIBRARY swig_ldb
#######################

#######################
# Start LIBRARY swig_dcerpc
[LIBRARY::swig_dcerpc]
LIBRARY_REALNAME = _dcerpc.$(SHLIBEXT)
REQUIRED_SUBSYSTEMS = LIBCLI NDR_MISC LIBSAMBA-UTIL LIBSAMBA-CONFIG RPC_NDR_SAMR RPC_NDR_LSA DYNCONFIG
OBJ_FILES = dcerpc_wrap.o
# End LIBRARY swig_dcerpc
#######################

# Swig extensions
swig: scripting/swig/_tdb.$(SHLIBEXT) scripting/swig/_ldb.$(SHLIBEXT)

.SUFFIXES: _wrap.c .i

.i_wrap.c:
	swig -python $<

SWIG_INCLUDES = librpc/gen_ndr/samr.i librpc/gen_ndr/lsa.i librpc/gen_ndr/spoolss.i

scripting/swig/dcerpc_wrap.c: scripting/swig/dcerpc.i scripting/swig/samba.i scripting/swig/status_codes.i $(SWIG_INCLUDES)

clean::
	-rm -f scripting/swig/tdb.pyc scripting/swig/tdb.py

# Swig testing

swigtest: swig
	./script/tests/test_swig.sh
