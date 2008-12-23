TALLOC_OBJ = $(tallocdir)/talloc.o 

TALLOC_SOLIB = libtalloc.$(SHLIBEXT).$(PACKAGE_VERSION)
TALLOC_SONAME = libtalloc.$(SHLIBEXT).1
TALLOC_STLIB = libtalloc.a

all:: $(TALLOC_STLIB) $(TALLOC_SOLIB) testsuite

testsuite:: $(LIBOBJ) testsuite.o testsuite_main.o
	$(CC) $(CFLAGS) -o testsuite testsuite.o testsuite_main.o $(LIBOBJ) $(LIBS)

$(TALLOC_STLIB): $(LIBOBJ)
	ar -rv $@ $(LIBOBJ)
	@-ranlib $@

install:: all 
	${INSTALLCMD} -d $(DESTDIR)$(libdir)
	${INSTALLCMD} -d $(DESTDIR)$(libdir)/pkgconfig
	${INSTALLCMD} -m 755 $(TALLOC_STLIB) $(DESTDIR)$(libdir)
	${INSTALLCMD} -m 755 $(TALLOC_SOLIB) $(DESTDIR)$(libdir)
	${INSTALLCMD} -d $(DESTDIR)${includedir}
	${INSTALLCMD} -m 644 $(srcdir)/talloc.h $(DESTDIR)$(includedir)
	${INSTALLCMD} -m 644 talloc.pc $(DESTDIR)$(libdir)/pkgconfig
	if [ -f talloc.3 ];then ${INSTALLCMD} -d $(DESTDIR)$(mandir)/man3; fi
	if [ -f talloc.3 ];then ${INSTALLCMD} -m 644 talloc.3 $(DESTDIR)$(mandir)/man3; fi
	which swig >/dev/null 2>&1 && ${INSTALLCMD} -d $(DESTDIR)`swig -swiglib` || true
	which swig >/dev/null 2>&1 && ${INSTALLCMD} -m 644 talloc.i $(DESTDIR)`swig -swiglib` || true

doc:: talloc.3 talloc.3.html

clean::
	rm -f *~ $(LIBOBJ) $(TALLOC_SOLIB) $(TALLOC_STLIB) testsuite testsuite.o testsuite_main.o *.gc?? talloc.3 talloc.3.html

test:: testsuite
	./testsuite

gcov::
	gcov talloc.c
