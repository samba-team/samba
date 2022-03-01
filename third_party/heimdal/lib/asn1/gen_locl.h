/*
 * Copyright (c) 1997-2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $Id$ */

#ifndef __GEN_LOCL_H__
#define __GEN_LOCL_H__

#include <config.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <err.h>
#include <roken.h>
#include <getarg.h>
#include "hash.h"
#include "symbol.h"
#include "asn1-common.h"
#include "der.h"
#include "der-private.h"

/*
 * XXX We need to move all module state out of globals and into a struct that
 * we pass around when parsing and compiling a module, and also that we keep on
 * a linked list of parsed modules.
 *
 * This is needed to:
 *
 *  - implement IMPORTS correctly, because we need to know the type of a symbol
 *    in order to emit an extern declaration of it
 *  - implement value parsing
 *  - implement an ASN.1 library that does value parsing
 *
 * Value parsing, in particular, would be fantastic.  We could then have
 * options in hxtool(1) to load arbitrary ASN.1 modules and then parse SAN
 * values given in ASN.1 value syntax on the command-line or in files.  Eat
 * your heart out OpenSSL if we do this!
 *
 * As well we'll need a `-I' option to the compiler so it knows where to find
 * modules to IMPORT FROM.
 */
typedef struct asn1_module {
    /* Name of ASN.1 module file: */
    const char *orig_filename;
    /* Name of file to always include for common type definitions: */
    const char *type_file_string;
    /* Name of public header file for module: */
    const char *header;
    /* Name of private header file for module: */
    const char *privheader;
    /* Basename of module: */
    const char *headerbase;
    /* Open stdio file handles for output: */
    FILE *jsonfile;
    FILE *privheaderfile;
    FILE *headerfile;
    FILE *oidsfile;
    FILE *codefile;
    FILE *logfile;
    FILE *templatefile;
    /* Module contents: */
    struct sexport *exports;
    struct import *imports;
    Hashtab *htab;  /* symbols */
    /* Template state: */
    struct templatehead *template;
    struct tlisthead *tlistmaster;
    /* CLI options and flags needed everywhere: */
    getarg_strings preserve;
    getarg_strings seq;
    const char *enum_prefix;
    unsigned int one_code_file:1;
    unsigned int support_ber:1;
    unsigned int parse_units_flag:1;
    unsigned int prefix_enum:1; /* Should be a getarg_strings of bitrsting types to do this for */
    unsigned int rfc1510_bitstring:1; /* Should be a getarg_strings of bitrsting types to do this for */
} *asn1_module;

void generate_type (const Symbol *);
void generate_type_header_forwards(const Symbol *);
void generate_constant (const Symbol *);
void generate_type_encode (const Symbol *);
void generate_type_decode (const Symbol *);
void generate_type_free (const Symbol *);
void generate_type_length (const Symbol *);
void generate_type_print_stub(const Symbol *);
void generate_type_copy (const Symbol *);
void generate_type_seq (const Symbol *);
void generate_glue (const Type *, const char*);

const char *classname(Der_class);
const char *valuename(Der_class, int);

void gen_compare_defval(const char *, struct value *);
void gen_assign_defval(const char *, struct value *);

int objid_cmp(struct objid *, struct objid *);

void init_generate (const char *, const char *);
const char *get_filename (void);
void close_generate(void);
void add_import(const char *);
void add_export(const char *);
int is_export(const char *);
int yyparse(void);
int is_primitive_type(const Type *);
int is_tagged_type(const Type *);

int preserve_type(const char *);
int seq_type(const char *);

struct decoration {
    char *field_type;           /* C type name */
    char *field_name;           /* C struct field name */
    char *copy_function_name;   /* copy constructor function name */
    char *free_function_name;   /* destructor function name */
    char *header_name;          /* header name */
    unsigned int decorated:1;
    unsigned int first:1;       /* optional */
    unsigned int opt:1;         /* optional */
    unsigned int ext:1;         /* external */
    unsigned int ptr:1;         /* external, pointer */
    unsigned int void_star:1;   /* external, void * */
    unsigned int struct_star:1; /* external, struct foo * */
};
int decorate_type(const char *, struct decoration *, ssize_t *);

void generate_header_of_codefile(const char *);
void close_codefile(void);

void get_open_type_defn_fields(const Type *, Member **, Member **, Field **,
                               Field **, int *);
void sort_object_set(IOSObjectSet *, Field *, IOSObject ***, size_t *);
int object_cmp(const void *, const void *);

int is_template_compat (const Symbol *);
void generate_template(const Symbol *);
void generate_template_type_forward(const char *);
void generate_template_objectset_forwards(const Symbol *);
void gen_template_import(const Symbol *);

struct objid **objid2list(struct objid *);

extern FILE *jsonfile, *privheaderfile, *headerfile, *codefile, *logfile, *templatefile;
extern const char *fuzzer_string;
extern int support_ber;
extern int template_flag;
extern int rfc1510_bitstring;
extern int one_code_file;
extern int original_order;
extern int parse_units_flag;
extern char *type_file_string;

extern int error_flag;

#endif /* __GEN_LOCL_H__ */
