/* $Id$ */

%{
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include "symbol.h"
#include "parse.h"

static unsigned lineno = 1;
static char filename[256];
%}

%%
INTEGER			{ return INTEGER; }
SEQUENCE		{ return SEQUENCE; }
OF			{ return OF; }
OCTET			{ return OCTET; }
STRING			{ return STRING; }
GeneralizedTime		{ return GeneralizedTime; }
GeneralString		{ return GeneralString; }
BIT			{ return BIT; }
APPLICATION		{ return APPLICATION; }
OPTIONAL		{ return OPTIONAL; }
BEGIN			{ return TBEGIN; }
END			{ return END; }
DEFINITIONS		{ return DEFINITIONS; }
[][|{},()]		{ return *yytext; }
::=			{ return EEQUAL; }
--[^\n]*\n		{ ; }
-?[0-9]+		{ yylval.constant = atoi(yytext); return CONSTANT; }
[A-Za-z][-A-Za-z0-9_]*	{ yylval.name =  strdup (yytext); return IDENTIFIER; }
[ \t]			;
\n			{ lineno++; }
.			{ fprintf(stderr, "Ignoring char(%c)\n", *yytext); }
%%

int
yywrap () 
{
     return 1;
}

void
error_message (char *format, ...)
{
     va_list args;

     va_start (args, format);
     fprintf (stderr, ":%d: ", lineno);
     vfprintf (stderr, format, args);
     va_end (args);
}
