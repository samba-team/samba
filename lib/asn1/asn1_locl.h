/* $Id$ */

#ifndef __ASN1_LOCL_H__
#define __ASN1_LOCL_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <roken.h>
#include "gen.h"
#include "hash.h"
#include "symbol.h"

void generate_type (Symbol *);
void generate_constant (Symbol *);
void generate_type_encode (Symbol *s);
void generate_type_decode (Symbol *s);
void generate_seq_type_decode (Symbol *s);
void generate_type_free (Symbol *s);
void generate_type_length (Symbol *s);
void generate_type_copy (Symbol *s);
void generate_type_maybe (Symbol *s);

void init_generate (char *filename);
void close_generate(void);
int yyparse(void);

extern FILE *headerfile, *codefile, *logfile;

#endif /* __ASN1_LOCL_H__ */
