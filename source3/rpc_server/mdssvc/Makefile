BISON=bison
FLEX=flex

PARSER=sparql_parser
LEXER=sparql_lexer

all: $(PARSER).c $(LEXER).c

$(PARSER).c: $(PARSER).y
	$(BISON) -d -o $@ $<

$(LEXER).c: $(LEXER).l
	$(FLEX) -o $@ $<
