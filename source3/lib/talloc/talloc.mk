TALLOC_OBJ = $(tallocdir)/talloc.o 

SOLIB = libtalloc.$(SHLIBEXT).$(PACKAGE_VERSION)
SONAME = libtalloc.$(SHLIBEXT).1

all:: libtalloc.a $(SOLIB) testsuite

testsuite:: $(LIBOBJ) testsuite.o
	$(CC) $(CFLAGS) -o testsuite testsuite.o $(LIBOBJ) $(LIBS)

libtalloc.a: $(LIBOBJ)
	ar -rv $@ $(LIBOBJ)
	@-ranlib $@

install:: all 
	${INSTALLCMD} -d $(DESTDIR)$(libdir)
	${INSTALLCMD} -d $(DESTDIR)$(libdir)/pkgconfig
	${INSTALLCMD} -m 755 libtalloc.a $(DESTDIR)$(libdir)
	${INSTALLCMD} -m 755 $(SOLIB) $(DESTDIR)$(libdir)
	${INSTALLCMD} -d $(DESTDIR)${includedir}
	${INSTALLCMD} -m 644 $(srcdir)/talloc.h $(DESTDIR)$(includedir)
	${INSTALLCMD} -m 644 talloc.pc $(DESTDIR)$(libdir)/pkgconfig
	if [ -f talloc.3 ];then ${INSTALLCMD} -d $(DESTDIR)$(mandir)/man3; fi
	if [ -f talloc.3 ];then ${INSTALLCMD} -m 644 talloc.3 $(DESTDIR)$(mandir)/man3; fi
	which swig >/dev/null 2>&1 && ${INSTALLCMD} -d $(DESTDIR)`swig -swiglib` || true
	which swig >/dev/null 2>&1 && ${INSTALLCMD} -m 644 talloc.i $(DESTDIR)`swig -swiglib` || true

doc:: talloc.3 talloc.3.html

clean::
	rm -f *~ $(LIBOBJ) $(SOLIB) libtalloc.a testsuite testsuite.o *.gc?? talloc.3 talloc.3.html

test:: testsuite
	./testsuite

gcov::
	gcov talloc.c
