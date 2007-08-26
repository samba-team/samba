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

   For more information on the .ADM file format:
   http://msdn2.microsoft.com/en-us/library/aa372405.aspx 
*/

%{
#include "config.h"
void error_message (const char *format, ...);
int yyparse (void);
void yyerror (const char *s);
extern int yylex (void);

%}

%union {
	char *text;
	int integer;
}

%token CATEGORY
%token CLASS
%token USER
%token MACHINE
%token POLICY
%token KEYNAME
%token EXPLAIN
%token VALUENAME
%token VALUEON VALUEOFF
%token PART
%token ITEMLIST
%token NAME
%token VALUE
%token NUMERIC EDITTEXT TEXT DROPDOWNLIST CHECKBOX
%token MINIMUM MAXIMUM DEFAULT
%token END
%token ACTIONLIST
%token DEL
%token SUPPORTED
%token <text> LITERAL
%token <integer> INTEGER
%token <text> LOOKUPLITERAL
%token CLIENTEXT
%token REQUIRED
%token NOSORT
%token SPIN
%token EQUALS
%token STRINGSSECTION

%start admfile

%% 

admfile: classes strings;

classes: /* empty */ | class classes;

class: CLASS classvalue categories;
classvalue: USER|MACHINE;

categories: /* empty */ | category categories;

string: LITERAL | LOOKUPLITERAL;

category: CATEGORY string categoryitems END CATEGORY;

categoryitem: explain | category | policy | keyname;
categoryitems: categoryitem categoryitems | /* empty */ ;

policy: POLICY string policyitems END POLICY;
policyitem: explain | keyname | valuename | valueon | valueoff | min | max | defaultvalue | supported | part;
policyitems: policyitem policyitems | /* empty */;

valuetype: NUMERIC | EDITTEXT | TEXT | DROPDOWNLIST | CHECKBOX;

part: PART string valuetype partitems END PART;

spin: SPIN INTEGER;

partitem: keyname | valuename | valueon | valueoff | min | max | defaultvalue | itemlist | REQUIRED | spin;
partitems: partitem partitems | /* empty */;

min: MINIMUM INTEGER;
max: MAXIMUM INTEGER;
defaultvalue: DEFAULT INTEGER;

explain: EXPLAIN string;
value: DEL | NUMERIC INTEGER;

valueon: VALUEON value;
valueoff: VALUEOFF value;

valuename: VALUENAME string;
keyname: KEYNAME string;

itemlist: ITEMLIST items END ITEMLIST;
itemname: NAME string;
itemvalue: VALUE value;

item: itemname | itemvalue | DEFAULT | actionlist;
items: /* empty */ | item items;

supported: SUPPORTED string;

actionlist: ACTIONLIST actions END ACTIONLIST;
actions: valuename actions | itemvalue actions | /* empty */;

variable: LITERAL EQUALS LITERAL;
variables: variable variables | /* empty */;
strings: STRINGSSECTION variables;

%%

void
yyerror (const char *s)
{
     error_message ("%s\n", s);
}



