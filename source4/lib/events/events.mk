
EVENTS_SONAME = libevents.$(SHLIBEXT).0
EVENTS_SOLIB = libevents.$(SHLIBEXT).$(PACKAGE_VERSION)

libevents.a: $(EVENTS_OBJ)
	ar -rv libevents.a $(EVENTS_OBJ)

libevents.$(SHLIBEXT): $(EVENTS_SOLIB)
	ln -fs $< $@

$(EVENTS_SONAME): $(EVENTS_SOLIB)
	ln -fs $< $@

dirs::
	@mkdir -p lib

installdirs::
	mkdir -p $(DESTDIR)$(includedir)
	mkdir -p $(DESTDIR)$(libdir)
	mkdir -p $(DESTDIR)$(libdir)/pkgconfig

installheaders:: installdirs
	cp $(srcdir)/events.h $(DESTDIR)$(includedir)

installlibs:: installdirs
	cp events.pc $(DESTDIR)$(libdir)/pkgconfig
	cp libevents.a $(EVENTS_SOLIB) $(DESTDIR)$(libdir)

install:: all installdirs installheaders installlibs $(PYTHON_INSTALL_TARGET)

clean::
	rm -f $(EVENTS_SONAME) $(EVENTS_SOLIB) libevents.a libevents.$(SHLIBEXT)
	rm -f events.pc
	rm -f _libevents.$(SHLIBEXT)


#python stuff

check-python:: build-python
	$(LIB_PATH_VAR)=. PYTHONPATH=".:$(eventsdir)" $(PYTHON) $(eventsdir)/python/tests/simple.py

install-swig::
	mkdir -p $(DESTDIR)`$(SWIG) -swiglib`
	cp events.i $(DESTDIR)`$(SWIG) -swiglib`

build-python:: _libevents.$(SHLIBEXT)

events_wrap.o: $(eventsdir)/events_wrap.c
	$(CC) $(PICFLAG) -c $(eventsdir)/events_wrap.c $(CFLAGS) `$(PYTHON_CONFIG) --cflags`

_libevents.$(SHLIBEXT): libevents.$(SHLIBEXT) events_wrap.o
	$(SHLD) $(SHLD_FLAGS) -o $@ events_wrap.o -L. -levents `$(PYTHON_CONFIG) --libs`

install-python:: build-python
	mkdir -p $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(0, prefix='$(prefix)')"` \
		$(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1, prefix='$(prefix)')"`
	cp $(eventsdir)/events.py $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(0, prefix='$(prefix)')"`
	cp _libevents.$(SHLIBEXT) $(DESTDIR)`$(PYTHON) -c "import distutils.sysconfig; print distutils.sysconfig.get_python_lib(1, prefix='$(prefix)')"`

