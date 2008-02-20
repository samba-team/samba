LDB_LIB = $(STATICLIB)

LIB_FLAGS=$(LDFLAGS) -Llib $(LDB_LIB) $(LIBS) $(POPT_LIBS) $(TALLOC_LIBS) \
		  $(TDB_LIBS) $(LDAP_LIBS) $(LIBDL)

LDB_TDB_DIR=ldb_tdb
LDB_TDB_OBJ=$(LDB_TDB_DIR)/ldb_tdb.o \
	$(LDB_TDB_DIR)/ldb_pack.o $(LDB_TDB_DIR)/ldb_search.o $(LDB_TDB_DIR)/ldb_index.o \
	$(LDB_TDB_DIR)/ldb_cache.o $(LDB_TDB_DIR)/ldb_tdb_wrap.o

LDB_MAP_DIR=ldb_map
LDB_MAP_OBJ=$(LDB_MAP_DIR)/ldb_map.o $(LDB_MAP_DIR)/ldb_map_inbound.o \
	    $(LDB_MAP_DIR)/ldb_map_outbound.o

COMDIR=common
COMMON_OBJ=$(COMDIR)/ldb.o $(COMDIR)/ldb_ldif.o \
	   $(COMDIR)/ldb_parse.o $(COMDIR)/ldb_msg.o $(COMDIR)/ldb_utf8.o \
	   $(COMDIR)/ldb_debug.o $(COMDIR)/ldb_modules.o \
	   $(COMDIR)/ldb_dn.o $(COMDIR)/ldb_match.o $(COMDIR)/ldb_attributes.o \
	   $(COMDIR)/attrib_handlers.o $(COMDIR)/ldb_controls.o $(COMDIR)/qsort.o

MODDIR=modules
MODULES_OBJ=$(MODDIR)/operational.o $(MODDIR)/rdn_name.o \
	   $(MODDIR)/paged_results.o $(MODDIR)/sort.o $(MODDIR)/asq.o

NSSDIR=nssldb
NSS_OBJ= $(NSSDIR)/ldb-nss.o $(NSSDIR)/ldb-pwd.o $(NSSDIR)/ldb-grp.o
NSS_LIB = lib/libnss_ldb.$(SHLIBEXT).2

lib/libldb.a: $(OBJS)
	ar -rv $@ $(OBJS)
	@-ranlib $@

sample.$(SHLIBEXT): tests/sample_module.o
	$(MDLD) $(MDLD_FLAGS) -o $@ tests/sample_module.o

bin/ldbadd: tools/ldbadd.o tools/cmdline.o $(LIBS)
	$(CC) -o bin/ldbadd tools/ldbadd.o tools/cmdline.o $(LIB_FLAGS) $(LD_EXPORT_DYNAMIC)

bin/ldbsearch: tools/ldbsearch.o tools/cmdline.o $(LIBS)
	$(CC) -o bin/ldbsearch tools/ldbsearch.o tools/cmdline.o $(LIB_FLAGS) $(LD_EXPORT_DYNAMIC)

bin/ldbdel: tools/ldbdel.o tools/cmdline.o $(LIBS)
	$(CC) -o bin/ldbdel tools/ldbdel.o tools/cmdline.o $(LIB_FLAGS) $(LD_EXPORT_DYNAMIC)

bin/ldbmodify: tools/ldbmodify.o tools/cmdline.o $(LIBS)
	$(CC) -o bin/ldbmodify tools/ldbmodify.o tools/cmdline.o $(LIB_FLAGS) $(LD_EXPORT_DYNAMIC)

bin/ldbedit: tools/ldbedit.o tools/cmdline.o $(LIBS)
	$(CC) -o bin/ldbedit tools/ldbedit.o tools/cmdline.o $(LIB_FLAGS) $(LD_EXPORT_DYNAMIC)

bin/ldbrename: tools/ldbrename.o tools/cmdline.o $(LIBS)
	$(CC) -o bin/ldbrename tools/ldbrename.o tools/cmdline.o $(LIB_FLAGS) $(LD_EXPORT_DYNAMIC)

bin/ldbtest: tools/ldbtest.o tools/cmdline.o $(LIBS)
	$(CC) -o bin/ldbtest tools/ldbtest.o tools/cmdline.o $(LIB_FLAGS) $(LD_EXPORT_DYNAMIC)

bin/oLschema2ldif: tools/oLschema2ldif.o tools/cmdline.o tools/convert.o $(LIBS)
	$(CC) -o bin/oLschema2ldif tools/oLschema2ldif.o tools/cmdline.o tools/convert.o $(LIB_FLAGS)

examples/ldbreader: examples/ldbreader.o $(LIBS)
	$(CC) -o examples/ldbreader examples/ldbreader.o $(LIB_FLAGS)

examples/ldifreader: examples/ldifreader.o $(LIBS)
	$(CC) -o examples/ldifreader examples/ldifreader.o $(LIB_FLAGS)

# Python bindings
build-python:: _ldb.$(SHLIBEXT)

ldb_wrap.o: $(ldbdir)/ldb_wrap.c
	$(CC) $(PICFLAG) -c $(ldbdir)/ldb_wrap.c $(CFLAGS) `$(PYTHON_CONFIG) --cflags`
	
_ldb.$(SHLIBEXT): $(LIBS) ldb_wrap.o
	$(SHLD) $(SHLD_FLAGS) -o _ldb.$(SHLIBEXT) ldb_wrap.o $(LIB_FLAGS)

install-python:: build-python
	mkdir -p $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(0, prefix='$(prefix)')"` \
		$(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1, prefix='$(prefix)')"`
	cp $(ldbdir)/ldb.py $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(0, prefix='$(prefix)')"`
	cp _ldb.$(SHLIBEXT) $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1, prefix='$(prefix)')"`

install-swig::
	cp ldb.i `$(SWIG) -swiglib`

check-python:: build-python
	LD_LIBRARY_PATH=lib PYTHONPATH=.:$(ldbdir) $(PYTHON) $(ldbdir)/tests/python/api.py

clean::
	rm -f _ldb.$(SHLIBEXT)
