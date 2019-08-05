/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines / Elasticsearch backend

   Copyright (C) Ralph Boehme			2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

%{
#include "includes.h"
#include "rpc_server/mdssvc/es_parser.tab.h"

#define YY_NO_INPUT
#define mdsyylalloc SMB_MALLOC
#define mdsyylrealloc SMB_REALLOC

static char *strip_quote(const char *phrase);
%}

%option nounput noyyalloc noyyrealloc prefix="mdsyyl"

ASC     [a-zA-Z0-9_\*\:\-\.]
U       [\x80-\xbf]
U2      [\xc2-\xdf]
U3      [\xe0-\xef]
U4      [\xf0-\xf4]
SPECIAL [\!\#\$\%\&\'\(\)\+\,\.\/\;\<\=\>\?\@\[\]\^\`\{\}\|\~\\]
ESCHAR  [\"\*]
BLANK   [ \t\n]

UANY    {ASC}|{U2}{U}|{U3}{U}{U}|{U4}{U}{U}{U}
UONLY   {U2}{U}|{U3}{U}{U}|{U4}{U}{U}{U}
UPHRASE {UANY}|{SPECIAL}|{BLANK}|\\{ESCHAR}

%%
InRange           return FUNC_INRANGE;
\$time\.iso       return DATE_ISO;
false             {mdsyyllval.bval = false; return BOOLEAN;}
true              {mdsyyllval.bval = true; return BOOLEAN;}
\"                return QUOTE;
\(                return OBRACE;
\)                return CBRACE;
\&\&              return AND;
\|\|              return OR;
\=\=              return EQUAL;
\!\=              return UNEQUAL;
\=                return EQUAL;
\<                return LT;
\>                return GT;
\,                return COMMA;
{UANY}+           {mdsyyllval.sval = talloc_strdup(talloc_tos(), yytext); return WORD;}
\"{UPHRASE}+\"    {mdsyyllval.sval = strip_quote(yytext); return PHRASE;}
{BLANK}           /* ignore */
%%

static char *strip_quote(const char *phrase)
{
	size_t phrase_len = 0;
	char *stripped_phrase = NULL;

	if (phrase == NULL) {
		return NULL;
	}

	phrase_len = strlen(phrase);
	if (phrase_len < 2 ||
	    phrase[0] != '\"' ||
	    phrase[phrase_len - 1] != '\"')
	{
		return talloc_strdup(talloc_tos(), phrase);
	}

	phrase++;

	stripped_phrase = talloc_strndup(talloc_tos(), phrase, phrase_len - 2);
	if (stripped_phrase == NULL) {
		return NULL;
	}
	return stripped_phrase;
}
