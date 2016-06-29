/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c) Noel Power
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

%{

#include "includes.h"
#include "libcli/wsp/wsp_aqs.h"
#include "libcli/wsp/wsp_aqs_parser.tab.h"


#include <stdio.h>

#define YY_NO_INPUT

%}

%option warn nodefault nounput

%option reentrant noyywrap never-interactive nounistd
%option bison-bridge

LPAREN	"("
RPAREN	")"
AND	"AND"
OR	"OR"
NOT	"NOT"
EQ	"=="
NE	"!="
GE	">="
LE	"<="
LESS	"<"
GREATER	">"
COMMA	","
WHERE	"WHERE"
SELECT	"SELECT"
PROP_EQUALS	":"
TRUE	"true"
FALSE	"false"

TODAY		"today"
YESTERDAY	"yesterday"
THISWEEK	"thisweek"
LASTWEEK	"lastweek"
THISMONTH	"thismonth"
LASTMONTH	"lastmonth"
THISYEAR	"thisyear"
LASTYEAR	"lastyear"

EMPTY		"empty"
TINY		"tiny"
SMALL		"small"
MEDIUM		"medium"
LARGE		"large"
HUGE		"huge"
GIGANTIC	"gigantic"

STARTS_WITH "$<"
EQUALS      "$="
K	    "K"
M	    "M"
G	    "G"
T	    "T"
KB	    "KB"
MB	    "MB"
GB	    "GB"
TB	    "TB"
RANGE	    "-"


NUMBER		[0-9]+
WS		[ \r\n\t]*
IDENTIFIER	[a-z\."A-Z_][a-z\."A-Z_0-9]*
STRING_LITERAL  L?\"(\\.|[^\\"])*\"

%%

{WS}		{ /* Skip blanks. */ }

{NUMBER}        { sscanf(yytext, "%"PRId64, &yylval->num); return TOKEN_NUMBER; }

{AND}		{ return TOKEN_AND; }
{OR}		{ return TOKEN_OR; }
{NOT}		{ return TOKEN_NOT; }
{EQ}		{ return TOKEN_EQ; }
{NE}		{ return TOKEN_NE; }
{GE}		{ return TOKEN_GE; }
{LE}		{ return TOKEN_LE; }
{LESS}		{ return TOKEN_LT; }
{GREATER}	{ return TOKEN_GT; }
{LPAREN}	{ return TOKEN_LPAREN; }
{RPAREN}	{ return TOKEN_RPAREN; }
{COMMA}		{ return TOKEN_COMMA; }
{WHERE}		{ return TOKEN_WHERE; }
{SELECT}	{ return TOKEN_SELECT; }
{TRUE}		{ return TOKEN_TRUE; }
{FALSE}		{ return TOKEN_FALSE; }
{PROP_EQUALS}	{ return TOKEN_PROP_EQUALS; }

{STARTS_WITH}	{ return TOKEN_STARTS_WITH;}
{EQUALS}	{ return TOKEN_EQUALS;}

{K}	{ return TOKEN_K; }
{M}	{ return TOKEN_M; }
{G}	{ return TOKEN_G; }
{T}	{ return TOKEN_T; }
{KB}	{ return TOKEN_KB; }
{MB}	{ return TOKEN_MB; }
{GB}	{ return TOKEN_GB; }
{TB}	{ return TOKEN_TB; }
{RANGE}	{ return TOKEN_RANGE; }
{TODAY} { return TOKEN_TODAY; }
{YESTERDAY} { return TOKEN_YESTERDAY;}
{THISWEEK} { return TOKEN_THISWEEK;}
{LASTWEEK} { return TOKEN_LASTWEEK;}
{THISMONTH} { return TOKEN_THISMONTH; }
{LASTMONTH} { return TOKEN_LASTMONTH; }
{THISYEAR} { return TOKEN_THISYEAR; }
{LASTYEAR} { return TOKEN_LASTYEAR; }
{EMPTY}    { return TOKEN_EMPTY; }
{TINY}     { return TOKEN_TINY; }
{SMALL}    { return TOKEN_SMALL; }
{MEDIUM}   { return TOKEN_MEDIUM; }
{LARGE}    { return TOKEN_LARGE; }
{HUGE}     { return TOKEN_HUGE; }
{GIGANTIC} { return TOKEN_GIGANTIC; }


{STRING_LITERAL} { yylval->strval = talloc_asprintf(talloc_tos(), "%s", yytext); return TOKEN_STRING_LITERAL; }

{IDENTIFIER}	{ yylval->strval = talloc_asprintf(talloc_tos(), "%s", yytext); return TOKEN_IDENTIFIER; }
.               {  }

%%

