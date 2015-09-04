BISON=bison
FLEX=flex
SED=sed

PARSER=sparql_parser
LEXER=sparql_lexer

all: $(PARSER).c $(LEXER).c

$(PARSER).c: $(PARSER).y
	$(BISON) -d -o $@ $<

$(LEXER).c: $(LEXER).l
	$(FLEX) -o $@ $<
	$(SED) -i s/malloc/SMB_MALLOC/g $@
	$(SED) -i s/realloc/SMB_REALLOC/g $@
