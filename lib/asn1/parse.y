/* $Id$ */

%{
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "symbol.h"
#include "lex.h"
#include "gen.h"

static Type *new_type (Typetype t);
void yyerror (char *);
%}

%union {
  int constant;
  char *name;
  Type *type;
  Member *member;
}

%token INTEGER SEQUENCE OF OCTET STRING GeneralizedTime GeneralString
%token BIT APPLICATION OPTIONAL EEQUAL TBEGIN END DEFINITIONS
%token <name> IDENTIFIER 
%token <constant> CONSTANT
%token IDENTIFIER CONSTANT

%type <constant> constant optional2
%type <type> type
%type <member> memberdecls memberdecl bitdecls bitdecl

%start envelope

%%

envelope	: IDENTIFIER DEFINITIONS EEQUAL TBEGIN specification END {}
		;

specification	:
		| specification declaration
		;

declaration	: type_decl
		| constant_decl
		;

type_decl	: IDENTIFIER EEQUAL type
		{
		  Symbol *s = addsym ($1);
		  s->stype = Stype;
		  s->type = $3;
		  generate_type (s);
		}
		;

constant_decl	: IDENTIFIER type EEQUAL constant
		{
		  Symbol *s = addsym ($1);
		  s->stype = SConstant;
		  s->constant = $4;
		  generate_constant (s);
		}
		;

type		: INTEGER     { $$ = new_type(TInteger); }
		| OCTET STRING { $$ = new_type(TOctetString); }
		| GeneralString { $$ = new_type(TGeneralString); }
		| GeneralizedTime { $$ = new_type(TGeneralizedTime); }
		| SEQUENCE OF type
		{
		  $$ = new_type(TSequenceOf);
		  $$->subtype = $3;
		}
		| SEQUENCE '{' memberdecls '}'
		{
		  $$ = new_type(TSequence);
		  $$->members = $3;
		}
		| BIT STRING '{' bitdecls '}'
		{
		  $$ = new_type(TBitString);
		  $$->members = $4;
		}
		| IDENTIFIER
		{
		  Symbol *s = addsym($1);
		  $$ = new_type(TType);
		  if(s->stype != Stype)
		    error_message ("%s is not a type\n", $1);
		  else
		    $$->symbol = s;
		}
		| '[' APPLICATION constant ']' type
		{
		  $$ = new_type(TApplication);
		  $$->subtype = $5;
		  $$->application = $3;
		}
		;

memberdecls	: { $$ = NULL; }
		| memberdecl	{ $$ = $1; }
		| memberdecls ',' memberdecl { $$ = $1; append($$, $3); }
		;

memberdecl	: IDENTIFIER '[' constant ']' type optional2
		{
		  $$ = malloc(sizeof(*$$));
		  $$->name = $1;
		  $$->gen_name = strdup($1);
		  output_name ($$->gen_name);
		  $$->val = $3;
		  $$->optional = $6;
		  $$->type = $5;
		  $$->next = $$->prev = $$;
		}
		;

optional2	: { $$ = 0; }
		| OPTIONAL { $$ = 1; }
		;

bitdecls	: { $$ = NULL; }
		| bitdecl { $$ = $1; }
		| bitdecls ',' bitdecl { $$ = $1; append($$, $3); }
		;

bitdecl		: IDENTIFIER '(' constant ')'
		{
		  $$ = malloc(sizeof(*$$));
		  $$->name = $1;
		  $$->gen_name = strdup($1);
		  output_name ($$->gen_name);
		  $$->val = $3;
		  $$->optional = 0;
		  $$->type = NULL;
		  $$->prev = $$->next = $$;
		}
		;

constant	: CONSTANT	{ $$ = $1; }
		| IDENTIFIER	{
				  Symbol *s = addsym($1);
				  if(s->stype != SConstant)
				    error_message ("%s is not a constant\n",
						   s->name);
				  else
				    $$ = s->constant;
				}
		;
%%

void
yyerror (char *s)
{
     error_message ("%s\n", s);
}

static Type *
new_type (Typetype tt)
{
  Type *t = malloc(sizeof(*t));
  t->type = tt;
  t->application = 0;
  t->members = NULL;
  t->subtype = NULL;
  t->symbol  = NULL;
}

static void
append (Member *l, Member *r)
{
  l->prev->next = r;
  r->prev = l->prev;
  l->prev = r;
  r->next = l;
}
