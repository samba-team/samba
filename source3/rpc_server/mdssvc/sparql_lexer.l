/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines

   Copyright (C) Ralph Boehme			2012-2014

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
#include "rpc_server/mdssvc/sparql_parser.tab.h"

#define YY_NO_INPUT
%}

%option nounput noyyalloc noyyrealloc prefix="mdsyy"

ASC     [a-zA-Z0-9_\*\:\-\.]
U       [\x80-\xbf]
U2      [\xc2-\xdf]
U3      [\xe0-\xef]
U4      [\xf0-\xf4]

UANY    {ASC}|{U2}{U}|{U3}{U}{U}|{U4}{U}{U}{U}
UONLY   {U2}{U}|{U3}{U}{U}|{U4}{U}{U}{U}

%%
InRange           return FUNC_INRANGE;
\$time\.iso       return DATE_ISO;
false             {mdsyylval.bval = false; return BOOL;}
true              {mdsyylval.bval = true; return BOOL;}
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
{UANY}+           {mdsyylval.sval = talloc_strdup(talloc_tos(), mdsyytext); return WORD;}
[ \t\n]           /* ignore */
%%

void *yyalloc(yy_size_t bytes)
{
    return SMB_MALLOC(bytes);
}

void *yyrealloc(void *ptr, yy_size_t bytes)
{
    return SMB_REALLOC(ptr, bytes);
}
