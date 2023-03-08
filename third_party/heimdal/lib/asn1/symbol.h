/*
 * Copyright (c) 1997 - 2005 Kungliga Tekniska Högskolan
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

#ifndef _SYMBOL_H
#define _SYMBOL_H

#include <heimqueue.h>

enum typetype {
    TBitString,
    TBoolean,
    TChoice,
    TEnumerated,
    TGeneralString,
    TTeletexString,
    TGeneralizedTime,
    TIA5String,
    TInteger,
    TNull,
    TOID,
    TOctetString,
    TPrintableString,
    TSequence,
    TSequenceOf,
    TSet,
    TSetOf,
    TTag,
    TType,
    TUTCTime,
    TUTF8String,
    TBMPString,
    TUniversalString,
    TVisibleString
};

typedef enum typetype Typetype;

struct type;
struct value;
struct typereference;

struct value {
    enum { booleanvalue,
	   nullvalue,
	   integervalue,
	   stringvalue,
	   objectidentifiervalue
    } type;
    union {
	int booleanvalue;
	int64_t integervalue;
	char *stringvalue;
	struct objid *objectidentifiervalue;
    } u;
    struct symbol *s;
};

struct member {
    char *name;
    char *gen_name;
    char *label;
    int64_t val;
    int optional;
    int ellipsis;
    struct type *type;
    HEIM_TAILQ_ENTRY(member) members;
    struct value *defval;
};

typedef struct member Member;

HEIM_TAILQ_HEAD(memhead, member);

struct symbol;

struct tagtype {
    int tagclass;
    int tagvalue;
    enum { TE_IMPLICIT, TE_EXPLICIT } tagenv;
};

struct range {
    /*
     * We can't represent unsigned 64-bit ranges because max might be
     * negative...
     */
    int64_t min;
    int64_t max;
};

enum ctype { CT_CONTENTS, CT_USER, CT_TABLE_CONSTRAINT, CT_RANGE } ;

struct constraint_spec;

struct iosclassfield {
    char *name;
    struct type *type;
    struct value *defval;
    HEIM_TAILQ_ENTRY(iosclassfield) fields;
    unsigned long id;
    unsigned int optional:1;
    unsigned int unique:1;
};

typedef struct iosclassfield Field;
HEIM_TAILQ_HEAD(fieldhead, iosclassfield);

struct iosobjectfield {
    char *name;
    struct type *type;
    struct value *value;
    HEIM_TAILQ_ENTRY(iosobjectfield) objfields;
    unsigned long id;
};

typedef struct iosobjectfield ObjectField;
HEIM_TAILQ_HEAD(objfieldhead, iosobjectfield);

struct iosclass {
    struct symbol *symbol;
    struct fieldhead *fields;
    unsigned long id;
};

typedef struct iosclass IOSClass;

struct iosobject {
    struct symbol *symbol;
    struct objfieldhead *objfields;
    ObjectField *typeidf;
    IOSClass *iosclass;
    HEIM_TAILQ_ENTRY(iosobject) objects;
    unsigned long id;
    unsigned int ellipsis:1;
    unsigned int optional:1;
};

typedef struct iosobject IOSObject;
HEIM_TAILQ_HEAD(objectshead, iosobject);

struct iosobjectset {
    struct symbol *symbol;
    IOSClass *iosclass;
    struct objectshead *objects;
    unsigned long id;
};

typedef struct iosobjectset IOSObjectSet;

struct typereference {
    /*
     * For now we don't support link fields, so we don't support chains of more
     * than one field.
     */
    IOSClass *iosclass;
    Field *field;
};

struct type {
    Typetype type;
    struct memhead *members;
    struct symbol *symbol;
    struct type *subtype;
    struct typereference typeref; /* For type fields */
    IOSClass *formal_parameter;
    IOSObjectSet *actual_parameter;
    struct tagtype tag;
    struct range *range;
    struct constraint_spec *constraint;
    unsigned long id;
    unsigned int implicit_choice:1;
};

typedef struct type Type;

struct component_relation_constraint {
    char *objectname;
    char *membername;
};

struct constraint_spec {
    enum ctype ctype;
    union {
	struct {
	    Type *type;
	    struct value *encoding;
            struct component_relation_constraint crel;
	} content;
        struct range *range;
    } u;
};

struct objid {
    const char *label;
    int value;
    struct objid *next;
};

struct symbol {
    char *name;
    char *gen_name;
    enum { SUndefined, SValue, Stype, Sparamtype, Sclass, Sobj, Sobjset } stype;
    struct value *value;
    Type *type;
    IOSClass *iosclass;
    IOSObject *object;
    IOSObjectSet *objectset;
    HEIM_TAILQ_ENTRY(symbol) symlist;
    unsigned int emitted_declaration:1;
    unsigned int emitted_definition:1;
    unsigned int emitted_tag_enums:1;
    unsigned int emitted_template:1;
};

typedef struct symbol Symbol;

//HEIM_TAILQ_HEAD(symhead, symbol);
struct symhead {
    struct symbol *tqh_first;
    struct symbol **tqh_last;
};

extern struct symhead symbols;

void initsym (void);
Symbol *addsym (char *);
Symbol *getsym(char *name);
void output_name (char *);
int checkundefined(void);
void generate_types(void);
void emitted_declaration(const Symbol *);
void emitted_definition(const Symbol *);
void emitted_tag_enums(const Symbol *);
#endif
