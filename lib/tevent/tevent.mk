TEVENT_SOBASE = libtevent.$(SHLIBEXT)
TEVENT_SONAME = $(TEVENT_SOBASE).0
TEVENT_SOLIB = $(TEVENT_SOBASE).$(PACKAGE_VERSION)
TEVENT_STLIB = libtevent.a

$(TEVENT_STLIB): $(TEVENT_OBJ)
	ar -rv $(TEVENT_STLIB) $(TEVENT_OBJ)

$(TEVENT_SOBASE): $(TEVENT_SOLIB)
	ln -fs $< $@

$(TEVENT_SONAME): $(TEVENT_SOLIB)
	ln -fs $< $@

dirs::
	@mkdir -p lib

installdirs::
	mkdir -p $(DESTDIR)$(includedir)
	mkdir -p $(DESTDIR)$(libdir)
	mkdir -p $(DESTDIR)$(libdir)/pkgconfig

installheaders:: installdirs
	cp $(srcdir)/tevent.h $(DESTDIR)$(includedir)

installlibs:: installdirs
	cp tevent.pc $(DESTDIR)$(libdir)/pkgconfig
	cp $(TEVENT_STLIB) $(TEVENT_SOLIB) $(DESTDIR)$(libdir)

install:: all installdirs installheaders installlibs $(PYTHON_INSTALL_TARGET)

clean::
	rm -f $(TEVENT_SOBASE) $(TEVENT_SONAME) $(TEVENT_SOLIB) $(TEVENT_STLIB)
	rm -f tevent.pc
	rm -f tevent.$(SHLIBEXT)

#python stuff

check-python:: build-python
	$(LIB_PATH_VAR)=. PYTHONPATH=".:$(teventdir)" $(PYTHON) $(teventdir)/tests.py

build-python:: tevent.$(SHLIBEXT)

pytevent.o: $(teventdir)/pytevent.c
	$(CC) $(PICFLAG) -c $(teventdir)/pytevent.c $(CFLAGS) `$(PYTHON_CONFIG) --cflags`

tevent.$(SHLIBEXT): $(TEVENT_SOBASE) $(TEVENT_SONAME) pytevent.o
	$(SHLD) $(SHLD_FLAGS) -o $@ pytevent.o -L. -ltevent `$(PYTHON_CONFIG) --libs`

install-python:: build-python
	mkdir -p $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(0, prefix='$(prefix)')"` \
		$(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1, prefix='$(prefix)')"`
	cp tevent.$(SHLIBEXT) $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1, prefix='$(prefix)')"`

