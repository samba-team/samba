/* 
   Unix SMB/CIFS implementation.
   Copyright (C) 2006 Wilco Baan Hofman <wilco@baanhofman.nl>
   Copyright (C) 2006 Jelmer Vernooij <jelmer@samba.org>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


%{
#include "includes.h"
#include "lib/policy/parse_adm.h"
void error_message (const char *format, ...);
int yyparse (void);

static int lineno = 1;
static bool utf16 = false;

#define YY_INPUT(buf,result,max_size) \
{ \
	if (utf16) { \
		uint16_t v; \
		if (fread(&v, 2, 1, yyin) < 1) \
			result = YY_NULL; \
		else \
			result = push_codepoint(buf, v); \
	} else { \
		int c = getc(yyin); \
		result = (c == EOF) ? YY_NULL : (buf[0] = c, 1); \
	} \
}

%}

%%

ACTIONLIST { return ACTIONLIST; }
CATEGORY { return CATEGORY; }
CHECKBOX { return CHECKBOX; }
CLASS { return CLASS; }
DELETE { return DEL; }
DEFAULT { return DEFAULT; }
DROPDOWNLIST { return DROPDOWNLIST; }
EDITTEXT { return EDITTEXT; }
END { return END; }
EXPLAIN { return EXPLAIN; }
ITEMLIST { return ITEMLIST; }
KEYNAME { return KEYNAME; }
MACHINE { return MACHINE; }
MIN { return MINIMUM; }
MAX { return MAXIMUM; }
NAME { return NAME; }
NUMERIC { return NUMERIC; }
PART { return PART; }
POLICY { return POLICY; }
REQUIRED { return REQUIRED; }
SPIN { return SPIN; }
SUPPORTED { return SUPPORTED; }
TEXT { return TEXT; }
USER { return USER; }
VALUE { return VALUE; }
VALUENAME { return VALUENAME; }
VALUEON { return VALUEON; }
VALUEOFF { return VALUEOFF; }
=		{ return EQUALS; }
\[strings\]	{ return STRINGSSECTION; }

[0-9]+ {
	char *e, *y = yytext;
	yylval.integer = strtol((const char *)yytext, &e, 0);
	if(e == y)
		error_message("malformed constant (%s)", yytext);
	else
		return INTEGER;
		}

[A-Za-z\\{}][{}\-\\A-Za-z0-9_]* { 
	yylval.text = strdup ((const char *)yytext);
	return LITERAL;
	}

"!!"[A-Za-z][-A-Za-z0-9_]*  {
	yylval.text = strdup ((const char *)yytext);
	return LOOKUPLITERAL;
	}
[ \t]+
\n			{ lineno++; }
;[^\n]*\n		{ lineno++; }
\"([^\n]+)\n		{ lineno++; yylval.text = strdup((const char *)yytext); return LITERAL; }
%%

#ifndef yywrap /* XXX */
int
yywrap () 
{
     return 1;
}
#endif


void
error_message (const char *format, ...)
{
	va_list args;

	va_start (args, format);
	fprintf (stderr, "%d:", lineno);
	vfprintf (stderr, format, args);
	va_end (args);
}

struct adm_file *adm_read_file(const char *file)
{
	uint8_t c[2];
	yyin = fopen(file, "r");
	if (yyin == NULL)
		return NULL;

	c[0] = getc(yyin);
	c[1] = getc(yyin);
	if (c[0] == 0xff && c[1] == 0xfe) {
		utf16 = true;
	} else {
		rewind(yyin);
	}

	yyparse();

	return NULL; /* FIXME */
}
