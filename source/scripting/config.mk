include ejs/config.mk

#######################
# Start LIBRARY swig_tdb
[LIBRARY::swig_tdb]
REQUIRED_SUBSYSTEMS = LIBTDB
# End LIBRARY swig_tdb
#######################

#######################
# Start LIBRARY swig_ldb
[LIBRARY::swig_ldb]
REQUIRED_SUBSYSTEMS = ldb
# End LIBRARY swig_ldb
#######################

#######################
# Start LIBRARY swig_dcerpc
[LIBRARY::swig_dcerpc]
REQUIRED_SUBSYSTEMS = LIBCLI NDR_MISC LIBBASIC CONFIG RPC_NDR_SAMR RPC_NDR_LSA
# End LIBRARY swig_dcerpc
#######################

# Swig extensions
swig: scripting/swig/_tdb.so scripting/swig/_ldb.so scripting/swig/_dcerpc.so

scripting/swig/tdb_wrap.c: scripting/swig/tdb.i
	swig -python scripting/swig/tdb.i

scripting/swig/_tdb.so: scripting/swig/tdb_wrap.o $(LIBRARY_swig_tdb_DEPEND_LIST)
	$(SHLD) $(SHLD_FLAGS) -o scripting/swig/_tdb.so scripting/swig/tdb_wrap.o \
		$(LIBRARY_swig_tdb_LINK_LIST) $(LIBRARY_swig_tdb_LINK_FLAGS)

scripting/swig/ldb_wrap.c: scripting/swig/ldb.i
	swig -python scripting/swig/ldb.i

scripting/swig/_ldb.so: scripting/swig/ldb_wrap.o $(LIBRARY_swig_ldb_DEPEND_LIST)
	$(SHLD) $(SHLD_FLAGS) -o scripting/swig/_ldb.so scripting/swig/ldb_wrap.o \
		$(LIBRARY_swig_ldb_LINK_LIST) $(LIBRARY_swig_ldb_LINK_FLAGS)

SWIG_INCLUDES = librpc/gen_ndr/samr.i librpc/gen_ndr/lsa.i librpc/gen_ndr/spoolss.i

scripting/swig/dcerpc_wrap.c: scripting/swig/dcerpc.i scripting/swig/samba.i scripting/swig/status_codes.i $(SWIG_INCLUDES)
	swig -python scripting/swig/dcerpc.i

scripting/swig/_dcerpc.so: scripting/swig/dcerpc_wrap.o $(LIBRARY_swig_dcerpc_DEPEND_LIST)
	$(SHLD) $(SHLD_FLAGS) -o scripting/swig/_dcerpc.so scripting/swig/dcerpc_wrap.o $(LIBRARY_swig_dcerpc_LINK_LIST) $(LIBRARY_swig_dcerpc_LINK_FLAGS)

swig_clean:
	-rm -f scripting/swig/_tdb.so scripting/swig/tdb.pyc scripting/swig/tdb.py scripting/swig/tdb_wrap.c scripting/swig/tdb_wrap.o
