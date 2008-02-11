dirs::
	@mkdir -p bin common tools

PROGS = bin/tdbtool$(EXEEXT) bin/tdbdump$(EXEEXT) bin/tdbbackup$(EXEEXT)
PROGS_NOINSTALL = bin/tdbtest$(EXEEXT) bin/tdbtorture$(EXEEXT)
ALL_PROGS = $(PROGS) $(PROGS_NOINSTALL)

SONAME = libtdb.$(SHLIBEXT).1
SOLIB = libtdb.$(SHLIBEXT).$(PACKAGE_VERSION)

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

test:: bin/tdbtorture$(EXEEXT)
	bin/tdbtorture$(EXEEXT)

clean:: 
	rm -f test.db test.tdb torture.tdb test.gdbm
	rm -f $(SONAME) $(SOLIB) libtdb.a libtdb.$(SHLIBEXT)
	rm -f $(ALL_PROGS) tdb.pc

build-python:: libtdb.$(SHLIBEXT) tdb_wrap.c
	./setup.py build

install:: installdirs installbin installheaders installlibs \
		  $(PYTHON_INSTALL_TARGET)

installpython:: build-python
	./setup.py install --prefix=$(DESTDIR)$(prefix)

check-python:: build-python
	# FIXME: Should be more portable:
	LD_LIBRARY_PATH=. PYTHONPATH=.:build/lib.linux-i686-2.4 trial python/tests/simple.py

install-swig::
	mkdir -p $(DESTDIR)`$(SWIG) -swiglib`
	cp tdb.i $(DESTDIR)`$(SWIG) -swiglib`

clean-python::
	./setup.py clean

installdirs::
	mkdir -p $(DESTDIR)$(bindir)
	mkdir -p $(DESTDIR)$(includedir)
	mkdir -p $(DESTDIR)$(libdir) 
	mkdir -p $(DESTDIR)$(libdir)/pkgconfig

installbin:: installdirs
	cp $(PROGS) $(DESTDIR)$(bindir)

installheaders:: installdirs
	cp $(srcdir)/include/tdb.h $(DESTDIR)$(includedir)

installlibs:: installdirs
	cp tdb.pc $(DESTDIR)$(libdir)/pkgconfig
	cp libtdb.a $(SOLIB) $(DESTDIR)$(libdir)

libtdb.a: $(TDB_OBJ)
	ar -rv libtdb.a $(TDB_OBJ)

libtdb.$(SHLIBEXT): $(SOLIB)
	ln -fs $< $@

$(SONAME): $(SOLIB)
	ln -fs $< $@


