/* $Id$ */

#ifndef _SYMBOL_H
#define _SYMBOL_H

enum typetype { TInteger, TOctetString, TBitString, TSequence, TSequenceOf,
		TGeneralizedTime, TGeneralString, TApplication, TType };

typedef enum typetype Typetype;

struct type;

struct member {
  char *name;
  char *gen_name;
  int val;
  int optional;
  struct type *type;
  struct member *next, *prev;
};

typedef struct member Member;

struct symbol;

struct type {
  Typetype type;
  int application;
  Member *members;
  struct type *subtype;
  struct symbol *symbol;
};

typedef struct type Type;

struct symbol {
  char *name;
  char *gen_name;
  enum { SUndefined, SConstant, Stype } stype;
  int constant;
  Type *type;
};

typedef struct symbol Symbol;

void initsym ();
Symbol *addsym (char *);
void output_name (char *);
#endif
