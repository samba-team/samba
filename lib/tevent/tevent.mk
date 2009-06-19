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
