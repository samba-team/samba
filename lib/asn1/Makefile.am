# $Id$

AUTOMAKE_OPTIONS = no-dependencies

lib_LIBRARIES = libasn1.a

libasn1_a_SOURCES = asn1.c der_get.c der_put.c der_free.c


noinst_PROGRAMS = asn1_compile

asn1_compile_SOURCES = parse.y lex.l main.c hash.c symbol.c gen.c

asn1_compile_LDADD = @LEXLIB@

parse.c: parse.y
	$(YACC) -d $(YFLAGS) $(srcdir)/parse.y
	mv y.tab.c parse.c

parse.h: parse.c
	mv y.tab.h parse.h

lex.c: lex.l
	$(LEX) $(LFLAGS) -t $(srcdir)/lex.l > lex.c

lex.o: parse.h

asn1.c: asn1_compile k5.asn1
	./asn1_compile $(srcdir)/k5.asn1

