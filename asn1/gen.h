/* $Id$ */

#include <stdio.h>
#include "symbol.h"

void init_generate (char *);
void close_generate ();
void generate_constant (Symbol *);
void generate_type (Symbol *);

extern FILE *headerfile, *codefile;
