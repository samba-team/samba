# $Id$

AUTOMAKE_OPTIONS = no-dependencies

lib_LIBRARIES = libasn1.a

libasn1_a_SOURCES = der_get.c der_put.c der_free.c der_length.c

noinst_PROGRAMS = asn1_compile

asn1_compile_SOURCES = parse.y lex.l main.c hash.c symbol.c gen.c

asn1_compile_LDADD = @LEXLIB@

CLEANFILES = lex.c parse.c parse.h asn1.h `cat asn1_files` asn1_files

parse.c: parse.y
	$(YACC) -d $(YFLAGS) $(srcdir)/parse.y
	mv y.tab.c parse.c

parse.h: parse.c
	mv y.tab.h parse.h

lex.c: lex.l
	$(LEX) $(LFLAGS) -t $(srcdir)/lex.l > lex.c

lex.o: parse.h

libasn1.a: asn1_compile $(libasn1_a_OBJECTS) $(libasn1_a_DEPENDENCIES)
	./asn1_compile $(srcdir)/k5.asn1
	o=`sed -e 's/\.c/.o/g' asn1_files`; \
	$(MAKE) $$o; \
	rm -f libasn1.a; \
	$(AR) cru libasn1.a $(libasn1_a_OBJECTS) $(libasn1_a_LIBADD) $$o; \
	$(RANLIB) libasn1.a
