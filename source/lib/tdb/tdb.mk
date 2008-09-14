dirs::
	@mkdir -p bin common tools

PROGS = bin/tdbtool$(EXEEXT) bin/tdbdump$(EXEEXT) bin/tdbbackup$(EXEEXT)
PROGS_NOINSTALL = bin/tdbtest$(EXEEXT) bin/tdbtorture$(EXEEXT)
ALL_PROGS = $(PROGS) $(PROGS_NOINSTALL)

TDB_SONAME = libtdb.$(SHLIBEXT).1
TDB_SOLIB = libtdb.$(SHLIBEXT).$(PACKAGE_VERSION)

TDB_LIB = libtdb.a

bin/tdbtest$(EXEEXT): tools/tdbtest.o $(TDB_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o bin/tdbtest tools/tdbtest.o -L. -ltdb -lgdbm

bin/tdbtool$(EXEEXT): tools/tdbtool.o $(TDB_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o bin/tdbtool tools/tdbtool.o -L. -ltdb

bin/tdbtorture$(EXEEXT): tools/tdbtorture.o $(TDB_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o bin/tdbtorture tools/tdbtorture.o -L. -ltdb

bin/tdbdump$(EXEEXT): tools/tdbdump.o $(TDB_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o bin/tdbdump tools/tdbdump.o -L. -ltdb

bin/tdbbackup$(EXEEXT): tools/tdbbackup.o $(TDB_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o bin/tdbbackup tools/tdbbackup.o -L. -ltdb

test:: bin/tdbtorture$(EXEEXT) $(TDB_SONAME)
	$(LIB_PATH_VAR)=. bin/tdbtorture$(EXEEXT)

clean:: 
	rm -f test.db test.tdb torture.tdb test.gdbm
	rm -f $(TDB_SONAME) $(TDB_SOLIB) libtdb.a libtdb.$(SHLIBEXT)
	rm -f $(ALL_PROGS) tdb.pc

build-python:: _tdb.$(SHLIBEXT) 

tdb_wrap.o: $(tdbdir)/tdb_wrap.c
	$(CC) $(PICFLAG) -c $(tdbdir)/tdb_wrap.c $(CFLAGS) `$(PYTHON_CONFIG) --cflags`

_tdb.$(SHLIBEXT): libtdb.$(SHLIBEXT) tdb_wrap.o
	$(SHLD) $(SHLD_FLAGS) -o $@ tdb_wrap.o -L. -ltdb `$(PYTHON_CONFIG) --ldflags`

install:: installdirs installbin installheaders installlibs \
		  $(PYTHON_INSTALL_TARGET)

install-python:: build-python
	mkdir -p $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(0, prefix='$(prefix)')"` \
		$(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1, prefix='$(prefix)')"`
	cp $(tdbdir)/tdb.py $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(0, prefix='$(prefix)')"`
	cp _tdb.$(SHLIBEXT) $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1, prefix='$(prefix)')"`

check-python:: build-python $(TDB_SONAME)
	$(LIB_PATH_VAR)=. PYTHONPATH=".:$(tdbdir)" $(PYTHON) $(tdbdir)/python/tests/simple.py

install-swig::
	mkdir -p $(DESTDIR)`$(SWIG) -swiglib`
	cp tdb.i $(DESTDIR)`$(SWIG) -swiglib`

clean::
	rm -f _tdb.$(SHLIBEXT)

installdirs::
	mkdir -p $(DESTDIR)$(bindir)
	mkdir -p $(DESTDIR)$(includedir)
	mkdir -p $(DESTDIR)$(libdir) 
	mkdir -p $(DESTDIR)$(libdir)/pkgconfig

installbin:: all installdirs
	cp $(PROGS) $(DESTDIR)$(bindir)

installheaders:: installdirs
	cp $(srcdir)/include/tdb.h $(DESTDIR)$(includedir)

installlibs:: all installdirs
	cp tdb.pc $(DESTDIR)$(libdir)/pkgconfig
	cp libtdb.a $(TDB_SOLIB) $(DESTDIR)$(libdir)

libtdb.a: $(TDB_OBJ)
	ar -rv libtdb.a $(TDB_OBJ)

libtdb.$(SHLIBEXT): $(TDB_SOLIB)
	ln -fs $< $@

$(TDB_SONAME): $(TDB_SOLIB)
	ln -fs $< $@
