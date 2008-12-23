dirs::
	@mkdir -p bin common tools

PROGS = bin/tdbtool$(EXEEXT) bin/tdbdump$(EXEEXT) bin/tdbbackup$(EXEEXT)
PROGS_NOINSTALL = bin/tdbtest$(EXEEXT) bin/tdbtorture$(EXEEXT)
ALL_PROGS = $(PROGS) $(PROGS_NOINSTALL)

TDB_SONAME = libtdb.$(SHLIBEXT).1
TDB_SOLIB = libtdb.$(SHLIBEXT).$(PACKAGE_VERSION)
TDB_STLIB = libtdb.a

TDB_LIB = $(TDB_STLIB) 

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
	rm -f $(TDB_SONAME) $(TDB_SOLIB) $(TDB_STLIB) libtdb.$(SHLIBEXT)
	rm -f $(ALL_PROGS) tdb.pc

build-python:: tdb.$(SHLIBEXT) 

pytdb.o: $(tdbdir)/pytdb.c
	$(CC) $(PICFLAG) -c $(tdbdir)/pytdb.c $(CFLAGS) `$(PYTHON_CONFIG) --cflags`

tdb.$(SHLIBEXT): libtdb.$(SHLIBEXT) pytdb.o
	$(SHLD) $(SHLD_FLAGS) -o $@ pytdb.o -L. -ltdb `$(PYTHON_CONFIG) --ldflags`

install:: installdirs installbin installheaders installlibs \
		  $(PYTHON_INSTALL_TARGET)

install-python:: build-python
	mkdir -p $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1, prefix='$(prefix)')"`
	cp tdb.$(SHLIBEXT) $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1, prefix='$(prefix)')"`

check-python:: build-python $(TDB_SONAME)
	$(LIB_PATH_VAR)=. PYTHONPATH=".:$(tdbdir)" $(PYTHON) $(tdbdir)/python/tests/simple.py

clean::
	rm -f tdb.$(SHLIBEXT)

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
	cp $(TDB_STLIB) $(TDB_SOLIB) $(DESTDIR)$(libdir)

$(TDB_STLIB): $(TDB_OBJ)
	ar -rv $(TDB_STLIB) $(TDB_OBJ)

libtdb.$(SHLIBEXT): $(TDB_SOLIB)
	ln -fs $< $@

$(TDB_SONAME): $(TDB_SOLIB)
	ln -fs $< $@
