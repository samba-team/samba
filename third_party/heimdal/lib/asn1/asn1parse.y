/*
 * Copyright (c) 1997 - 2007 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

%{

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "symbol.h"
#include "lex.h"
#include "gen_locl.h"
#include "der.h"

static Type *new_type (Typetype t);
/*static IOSClass *new_class(struct fieldhead *);*/
/*static IOSObject *new_object(struct objfieldhead *);*/
/*IOSObjectSet *new_object_set(struct objectshead *);*/
static struct objectshead *add_object_set_spec(struct objectshead *, IOSObject *);
static ObjectField *new_field_setting(char *, Type *, struct value *);
static struct objfieldhead *add_field_setting(struct objfieldhead *, ObjectField *);
static struct fieldhead *add_field_spec(struct fieldhead *, Field *);
static Field *new_type_field(char *, int, Type *);
static Field *new_fixed_type_value_field(char *, Type *, int, int, struct value *);
static Type *parametrize_type(Type *, IOSClass *);
static Type *type_from_class_field(IOSClass *, const char *);
static void validate_object_set(IOSObjectSet *);
/*static Type *type_from_object(const char *, const char *);*/
static struct constraint_spec *new_constraint_spec(enum ctype);
static Type *new_tag(int tagclass, int tagvalue, int tagenv, Type *oldtype);
void yyerror (const char *);
#define yyerror yyerror
static struct objid *new_objid(const char *label, int value);
static void add_oid_to_tail(struct objid *, struct objid *);
static void fix_labels(Symbol *s);

struct string_list {
    char *string;
    struct string_list *next;
};

static int default_tag_env = TE_EXPLICIT;
static unsigned long idcounter;

/* Declarations for Bison */
#define YYMALLOC malloc
#define YYFREE   free

%}

%union {
    int64_t constant;
    struct value *value;
    struct range *range;
    char *name;
    Type *type;
    IOSClass *class;
    IOSObjectSet *objectset;
    IOSObject *object;
    Field *field;
    ObjectField *objfield;
    Member *member;
    IOSClass *formalparam;
    struct objid *objid;
    char *defval;
    struct string_list *sl;
    struct tagtype tag;
    struct memhead *members;
    struct fieldhead *fields;
    struct objectshead *objects;
    struct objfieldhead *objfields;
    struct constraint_spec *constraint_spec;
}

%token kw_ABSENT
%token kw_ABSTRACT_SYNTAX
%token kw_ALL
%token kw_APPLICATION
%token kw_AUTOMATIC
%token kw_BEGIN
%token kw_BIT
%token kw_BMPString
%token kw_BOOLEAN
%token kw_BY
%token kw_CHARACTER
%token kw_CHOICE
%token kw_CLASS
%token kw_COMPONENT
%token kw_COMPONENTS
%token kw_CONSTRAINED
%token kw_CONTAINING
%token kw_DEFAULT
%token kw_DEFINITIONS
%token kw_EMBEDDED
%token kw_ENCODED
%token kw_END
%token kw_ENUMERATED
%token kw_EXCEPT
%token kw_EXPLICIT
%token kw_EXPORTS
%token kw_EXTENSIBILITY
%token kw_EXTERNAL
%token kw_FALSE
%token kw_FROM
%token kw_GeneralString
%token kw_GeneralizedTime
%token kw_GraphicString
%token kw_IA5String
%token kw_IDENTIFIER
%token kw_IMPLICIT
%token kw_IMPLIED
%token kw_IMPORTS
%token kw_INCLUDES
%token kw_INSTANCE
%token kw_INTEGER
%token kw_INTERSECTION
%token kw_ISO646String
%token kw_MAX
%token kw_MIN
%token kw_MINUS_INFINITY
%token kw_NULL
%token kw_NumericString
%token kw_OBJECT
%token kw_OCTET
%token kw_OF
%token kw_OPTIONAL
%token kw_ObjectDescriptor
%token kw_PATTERN
%token kw_PDV
%token kw_PLUS_INFINITY
%token kw_PRESENT
%token kw_PRIVATE
%token kw_PrintableString
%token kw_REAL
%token kw_RELATIVE_OID
%token kw_SEQUENCE
%token kw_SET
%token kw_SIZE
%token kw_STRING
%token kw_SYNTAX
%token kw_T61String
%token kw_TAGS
%token kw_TRUE
%token kw_TYPE_IDENTIFIER
%token kw_TeletexString
%token kw_UNION
%token kw_UNIQUE
%token kw_UNIVERSAL
%token kw_UTCTime
%token kw_UTF8String
%token kw_UniversalString
%token kw_VideotexString
%token kw_VisibleString
%token kw_WITH

%token RANGE
%token EEQUAL
%token ELLIPSIS

%token <name> TYPE_IDENTIFIER  referencename
%token <name> CLASS_IDENTIFIER
%token <name> VALUE_IDENTIFIER
%token <name> STRING

%token <constant> NUMBER
%type <constant> SignedNumber
%type <constant> Class tagenv
%type <constant> DummyReference

%type <name> Identifier

/*
 * The NULL keyword being both a value and a type causes a reduce/reduce
 * conflict in the FieldSetting production since its alternatives are
 *
 *	'&' Identifier Type
 *
 * and
 *
 *	'&' Identifier Value
 *
 * and NULL is both a type and a value.
 *
 * For now we work around this by having a ValueExNull production that excludes
 * the NULL value.  To really get past this will require unifying the type and
 * value types (e.g., via type punning).
 */
%type <value> Value ValueExNull
%type <value> BuiltinValue BuiltinValueExNull
%type <value> IntegerValue
%type <value> BooleanValue
%type <value> ObjectIdentifierValue
%type <value> CharacterStringValue
%type <value> NullValue
%type <value> DefinedValue
%type <value> ReferencedValue
%type <value> Valuereference

%type <class> DefinedObjectClass ParamGovernor
%type <class> ObjectClassDefn
%type <class> Parameter

%type <type> Type
%type <type> BuiltinType
%type <type> BitStringType
%type <type> BooleanType
%type <type> ChoiceType
%type <type> ConstrainedType
%type <type> UnconstrainedType
%type <type> EnumeratedType
%type <type> IntegerType
%type <type> NullType
%type <type> OctetStringType
%type <type> SequenceType
%type <type> SequenceOfType
%type <type> SetType
%type <type> SetOfType
%type <type> TaggedType
%type <type> ReferencedType
%type <type> DefinedType
%type <type> UsefulType
%type <type> ObjectIdentifierType
%type <type> CharacterStringType
%type <type> RestrictedCharactedStringType
%type <type> ObjectClassFieldType
%type <type> ParameterizedType
/*%type <type> TypeFromObject*/

%type <objectset> ObjectSet DefinedObjectSet
%type <objectset> ActualParameter
%type <object> Object DefinedObject ObjectDefn
%type <objfield> FieldSetting

%type <tag> Tag

%type <field> FieldSpec TypeFieldSpec FixedTypeValueFieldSpec
%type <fields> FieldSpecList
%type <member> ComponentType
%type <member> NamedBit
%type <member> NamedNumber
%type <member> NamedType
%type <members> ComponentTypeList
%type <members> Enumerations
%type <members> NamedBitList
%type <members> NamedNumberList
%type <objects> ObjectSetSpec
%type <objfields> FieldSettings

%type <objid> objid objid_list objid_element objid_opt
%type <range> range size

%type <sl> referencenames

%type <constraint_spec> Constraint
%type <constraint_spec> ConstraintSpec
%type <constraint_spec> SubtypeConstraint
%type <constraint_spec> GeneralConstraint
%type <constraint_spec> ContentsConstraint
%type <constraint_spec> UserDefinedConstraint
%type <constraint_spec> SimpleTableConstraint TableConstraint
%type <constraint_spec> ComponentRelationConstraint


%start ModuleDefinition

%%

/*
 * We have sinned by allowing types to have names that start with lower-case,
 * and values that have names that start with upper-case.
 *
 * UPDATE: We sin no more.  However, parts of this block comment are still
 * relevant.
 *
 * That worked when we only supported basic X.680 because the rules for
 * TypeAssignment and ValueAssignment are clearly unambiguous in spite of the
 * case issue.
 *
 * We now pay the price because X.681 adds productions where the only thing we
 * have to help us distinguish certain rules is the form of an identifier: the
 * case of its first letter.
 *
 * We have cleansed our sin by not allowing wrong-case identifiers any more.
 *
 * Some historical instances of this sin in-tree:
 *
 *  - DOMAIN-X500-COMPRESS  (value (enum) but name starts with upper-case)
 *  - krb5int32		    (type         but name starts with lower-case)
 *  - krb5uint32	    (type         but name starts with lower-case)
 *  - hdb_keyset	    (type         but name starts with lower-case)
 *  - hdb_entry		    (type         but name starts with lower-case)
 *  - hdb_entry_alias       (type         but name starts with lower-case)
 *  - HDB_DB_FORMAT INTEGER (value (int)  but name starts with upper-case)
 *
 * We have fixed all of these and others, in some cases leaving behind aliases
 * in header files as needed.
 *
 * We have one shift/reduce conflict (shift ObjectClassAssignment, reduce
 * TypeAssignment) and one reduce/reduce conflict (ObjectAssignment vs
 * ValueAssignment) that we avoid by requiring CLASS names to start with an
 * underscore.
 *
 * In the FieldSetting rule, also, we get a reduce/reduce conflict if we use
 * `Identifier' instead of `TYPE_IDENTIFIER' for type field settings and
 * `VALUE_IDENTIFIER' for value field settings, and then we can't make
 * progress.
 *
 * Looking forward, we may not (will not) be able to distinguish ValueSet and
 * ObjectSet field settings from each other either, and we may not (will not)
 * be able distinguish Object and Value field settings from each other as well.
 * To deal with those we will have to run-time type-tag and type-pun the C
 * structures for valueset/objectset and value/object, and have one rule for
 * each of those that inspects the type of the item to decide what kind of
 * setting it is.
 *
 * Sadly, the extended syntax for ASN.1 (x.680 + x.681/2/3) appears to have
 * ambiguities that cannot be resolved with bison/yacc.
 */
Identifier	: TYPE_IDENTIFIER { $$ = $1; }
		| VALUE_IDENTIFIER { $$ = $1; };

ModuleDefinition: Identifier objid_opt kw_DEFINITIONS TagDefault ExtensionDefault
			EEQUAL kw_BEGIN ModuleBody kw_END
		{
                    struct objid **o = objid2list($2);
                    size_t i;

                    fprintf(jsonfile,
                            "{\"module\":\"%s\",\"tagging\":\"%s\",\"objid\":[", $1,
                            default_tag_env == TE_EXPLICIT ? "explicit" : "implicit");

                    for (i = 0; o && o[i]; i++) {
                        fprintf(jsonfile, "%s{\"value\":%d", i ? "," : "", o[i]->value);
                        if (o[i]->label)
                            fprintf(jsonfile, ",\"label\":\"%s\"", o[i]->label);
                        fprintf(jsonfile, "}");
                    }
                    fprintf(jsonfile, "]}\n");
                    free(o);
		}
		;

TagDefault	: kw_EXPLICIT kw_TAGS
			{ default_tag_env = TE_EXPLICIT; }
		| kw_IMPLICIT kw_TAGS
			{ default_tag_env = TE_IMPLICIT; }
		| kw_AUTOMATIC kw_TAGS
		      { lex_error_message("automatic tagging is not supported"); }
		| /* empty */
		;

ExtensionDefault: kw_EXTENSIBILITY kw_IMPLIED
		      { lex_error_message("no extensibility options supported"); }
		| /* empty */
		;

ModuleBody	: Exports Imports AssignmentList
		| /* empty */
		;

Imports		: kw_IMPORTS SymbolsImported ';'
		| /* empty */
		;

SymbolsImported	: SymbolsFromModuleList
		| /* empty */
		;

SymbolsFromModuleList: SymbolsFromModule
		| SymbolsFromModuleList SymbolsFromModule
		;

SymbolsFromModule: referencenames kw_FROM Identifier objid_opt
		{
		    /*
                     * FIXME We really could use knowing what kind of thing the
                     * identifier identifies -- a type, a value, what?
		     *
		     * Our sin of allowing type names to start with lower-case
		     * and values with upper-case means we can't tell.  So we
		     * assume it's types only, but that means we can't import
		     * OID values, but we really want to!
                     *
                     * One thing we could do is not force `s->stype = Stype'
                     * here, instead set it to a new `Sunknown' value so that
                     * the first place that refers to this symbol with enough
                     * context to imply a symbol type can set it.
		     */
		    struct string_list *sl;
		    for(sl = $1; sl != NULL; sl = sl->next) {
			Symbol *s = addsym(sl->string);
			s->stype = Stype;
			gen_template_import(s);
		    }
		    add_import($3);
		}
		;

Exports		: kw_EXPORTS referencenames ';'
		{
		    struct string_list *sl;
		    for(sl = $2; sl != NULL; sl = sl->next)
			add_export(sl->string);
		}
		| kw_EXPORTS kw_ALL
		| /* empty */
		;

AssignmentList	: Assignment
		| Assignment AssignmentList
		;

Assignment	: TypeAssignment
		| ValueAssignment
		| ParameterizedTypeAssignment
		| ObjectClassAssignment
		| ObjectAssignment
		| ObjectSetAssignment
	     /* | ParameterizedAssignment // from X.683 */
		;

referencenames	: Identifier ',' referencenames
		{
		    $$ = emalloc(sizeof(*$$));
		    $$->string = $1;
		    $$->next = $3;
		}
		| Identifier
		{
		    $$ = emalloc(sizeof(*$$));
		    $$->string = $1;
		    $$->next = NULL;
		}
		;

DefinedObjectClass
		: CLASS_IDENTIFIER
		{
		    Symbol *s = addsym($1);
		    if(s->stype != Sclass)
		      lex_error_message ("%s is not a class\n", $1);
		    $$ = s->iosclass;
		};

ObjectClassAssignment
		: CLASS_IDENTIFIER EEQUAL ObjectClassDefn
		{
		    Symbol *s = addsym($1);
		    s->stype = Sclass;
		    s->iosclass = $3;
		    s->iosclass->symbol = s;
		    fix_labels(s);
		}
		| CLASS_IDENTIFIER EEQUAL DefinedObjectClass
		{
		    Symbol *s = addsym($1);
		    s->stype = Sclass;
		    s->iosclass = $3;
		}
	     /* | ParameterizedObjectClass */
		;

ObjectClassDefn : kw_CLASS '{' FieldSpecList '}'
		{
		    $$ = ecalloc(1, sizeof(*$$));
		    $$->fields = $3;
		    $$->id = idcounter++;
		};

ObjectAssignment: VALUE_IDENTIFIER DefinedObjectClass EEQUAL Object
		{
		    Symbol *s = addsym($1);
		    s->stype = Sobj;
		    s->object = $4;
		    s->object->iosclass = $2;
		    if (!s->object->symbol)
			s->object->symbol = s;
		    fix_labels(s);
		}
		;

ObjectSetAssignment
		: TYPE_IDENTIFIER DefinedObjectClass EEQUAL ObjectSet
		{
		    Symbol *s = addsym($1);
		    s->stype = Sobjset;
		    s->iosclass = $2;
		    s->objectset = $4;
                    s->objectset->symbol = s->objectset->symbol ? s->objectset->symbol : s;
		    s->objectset->iosclass = $2;
                    validate_object_set($4);
                    generate_template_objectset_forwards(s);
		}
		;

ObjectSet       : '{' ObjectSetSpec '}'
		{
		    $$ = ecalloc(1, sizeof(*$$));
		    $$->objects = $2;
		    $$->id = idcounter++;
		}
		;

ObjectSetSpec   : DefinedObject
		{ $$ = add_object_set_spec(NULL, $1); }
		| ObjectSetSpec '|' DefinedObject
		{ $$ = add_object_set_spec($1, $3); }
		;

Object		: DefinedObject
		| ObjectDefn
	     /* | ObjectFromObject      */
	     /* | ParameterizedObject   */
		;

DefinedObject	: VALUE_IDENTIFIER
		{
		  Symbol *s = addsym($1);
		  if(s->stype != Sobj)
		    lex_error_message ("%s is not an object\n", $1);
		  $$ = s->object;
		}
		;

DefinedObjectSet: TYPE_IDENTIFIER
		{
		  Symbol *s = addsym($1);
		  if(s->stype != Sobjset && s->stype != SUndefined)
		    lex_error_message ("%s is not an object set\n", $1);
		  $$ = s->objectset;
		}
		;


ObjectDefn	: '{' FieldSettings '}' /* DefaultSyntax */
		{
		    $$ = ecalloc(1, sizeof(*$$));
		    $$->objfields = $2;
		    $$->id = idcounter++;
		}
	     /* | DefinedSyntax */
		;

FieldSettings	: FieldSetting
		{
		$$ = add_field_setting(NULL, $1);
		}
		| FieldSettings ',' FieldSetting
		{
		$$ = add_field_setting($1, $3);
		}
		;

/* See note on `Identifier' */
FieldSetting	: '&' Identifier Type
		{ $$ = new_field_setting($2, $3, NULL); }
		| '&' Identifier ValueExNull
		{ $$ = new_field_setting($2, NULL, $3); }
	     /* | '&' TYPE_IDENTIFIER ValueSet   */
	     /* | '&' VALUE_IDENTIFIER Object     */
	     /* | '&' TYPE_IDENTIFIER ObjectSet  */
		;

/* Fields of a class */
FieldSpecList	: FieldSpec
		{ $$ = add_field_spec(NULL, $1); }
		| FieldSpecList ',' FieldSpec
		{ $$ = add_field_spec($1, $3); };

/*
 * Fields of a CLASS
 *
 * There are seven kinds of class/object fields:
 *
 *  - type fields,
 *  - fixed-type value fields,
 *  - fixed-type value set fields,
 *  - variable-type value fields
 *  - variable-type value set fields
 *  - object fields
 *  - object set fields
 *
 * We care only to support the bare minimum to treat open types as a CHOICE of
 * sorts and automatically encode/decode values in open types.  That's: type
 * fields and fixed-type value fields.
 */
FieldSpec	: TypeFieldSpec
		| FixedTypeValueFieldSpec
	     /* | VariableTypeValueFieldSpec    */
	     /* | VariableTypeValueSetFieldSpec */
	     /* | FixedTypeValueSetFieldSpec    */
	     /* | ObjectFieldSpec               */
	     /* | ObjectSetFieldSpec            */
		;
TypeFieldSpec	: '&' Identifier
		{ $$ = new_type_field($2, 0, NULL); }
		| '&' Identifier kw_OPTIONAL
		{ $$ = new_type_field($2, 1, NULL); }
		| '&' Identifier kw_DEFAULT Type
		{ $$ = new_type_field($2, 1, $4); }
		;

FixedTypeValueFieldSpec
		: '&' Identifier Type
		{ $$ = new_fixed_type_value_field($2, $3, 0, 0, NULL); }
		| '&' Identifier Type kw_UNIQUE
		{ $$ = new_fixed_type_value_field($2, $3, 1, 0, NULL); }
		| '&' Identifier Type kw_UNIQUE kw_OPTIONAL
		{ $$ = new_fixed_type_value_field($2, $3, 1, 1, NULL); }
		| '&' Identifier Type kw_UNIQUE kw_DEFAULT Value
		{ $$ = new_fixed_type_value_field($2, $3, 1, 0, $6); }
		| '&' Identifier Type kw_OPTIONAL
		{ $$ = new_fixed_type_value_field($2, $3, 0, 1, NULL); }
		| '&' Identifier Type kw_DEFAULT Value
		{ $$ = new_fixed_type_value_field($2, $3, 0, 0, $5); };

/*
 * Now we need a bit of X.683, just enough to parse PKIX.
 *
 * E.g., we need to parse this sort of type definition, which isn't quite the
 * final type definition because the ExtensionSet will be provided later.
 *
 *-- <- ObjectClassDefn ->
 *   EXTENSION ::= CLASS {
 *       &id  OBJECT IDENTIFIER UNIQUE,
 *    -- ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *    -- FixedTypeValueFieldSpec
 *
 *       &ExtnType,
 *    -- ^^^^^^^^^
 *    -- TypeFieldSpec
 *
 *       &Critical    BOOLEAN DEFAULT {TRUE | FALSE }
 *    -- ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *    -- FixedTypeValueFieldSpec
 *   } WITH SYNTAX {
 *       SYNTAX &ExtnType IDENTIFIED BY &id
 *       [CRITICALITY &Critical]
 *   }
 *
 *-- <--------- ParameterizedTypeAssignment -------->
 *   -- NOTE: The name of this type has to be Extension, really.
 *   --       But the name of the Extension type with the actual
 *   --       parameter provided also has to be Extension.
 *   --       We could disallow that and require that the various
 *   --       Extension types all have different names, then we'd
 *   --       let the one with the actual parameter in PKIX be the
 *   --       one named Extension.  Or we could find a way to let
 *   --       them all share one symbol name, or at least two:
 *   --       the one with the formal parameter, and just one with
 *   --       an actual parameter.
 *   --
 *   --       Also, IMPORTing types that have formal parameters is
 *   --       almost certainly going to require parsing the IMPORTed
 *   --       module.  Until we do that, users will be able to work
 *   --       around that by just copying CLASSes and pameterized
 *   --       type definitions around.  But when we do start parsing
 *   --       IMPORTed modules we might need to do something about
 *   --       many types possibly having the same names, though we
 *   --       might do nothing and simply say "don't do that!".
 *   Extension{EXTENSION:ExtensionSet} ::= SEQUENCE {
 *                    -- ^^^^^^^^^^^^
 *                    -- is a DummyReference, which is a Reference, basically
 *                    -- it is an object set variable which will have an object
 *                    -- set value supplied where constrained types are defined
 *                    -- from this one, possibly anonymous types where
 *                    -- SEQUENCE/SET members of this type are defined.
 *          -- ^^^^^^^^^
 *          -- is a ParamGovernor, really, just Governor, either a Type or
 *          -- DefinedObjectClass (we only need DefinedObjectClass)
 *          -- ^^^^^^^^^^^^^^^^^^^^^^
 *          -- is a Parameter
 *         -- ^^^^^^^^^^^^^^^^^^^^^^^^
 *         -- is a ParameterList (we need only support one param though)
 *      extnID      EXTENSION.&id({ExtensionSet}),
 *                            -- ^^^^^^^^^^^^^^^^
 *                            -- simple table constraint limiting id to OIDs
 *                            -- from ExtensionSet
 *               -- ^^^^^^^^^^^^^
 *               -- a reference to the id field of the EXTENSION CLASS
 *      critical    BOOLEAN DEFAULT FALSE,
 *      extnValue   OCTET STRING (CONTAINING
 *                   -- ObjectClassFieldType
 *                   -- vvvvvvvvvvvvvvvvvvv
 *                      EXTENSION.&ExtnType({ExtensionSet}{@extnID}))
 *                                                     -- ^^^^^^^^^
 *                                                     -- AtNotation
 *                                       -- ^^^^^^^^^^^^^^
 *                                       -- DefinedObjectSet
 *                                       -- ^^^^^^^^^^^^^^^^^^^^^^^^
 *                                       -- ComponentRelationConstraint
 *                                       -- says that extnValue will contain
 *                                       -- a value of a type identified by
 *                                       -- the OID in extnID in the object
 *                                       -- set ExtensionSet (which is a set
 *                                       -- of {OID, type} objects)
 *                                      -- ^^^^^^^^^^^^^^^^^^^^^^^^^^
 *                                      -- ConstraintSpec
 *                   -- ^^^^^^^^^^^^^^^^^^^
 *                   -- another type ref
 *   }
 *
 * Then later we'll see (ParameterizedType, a part of DefinedType):
 *
 *   TBSCertificate  ::=  SEQUENCE  {
 *      ...
 *                        -- Here is where the object set is linked into the
 *                        -- whole thing, making *magic* possible.  This is
 *                        -- where the real Extensions type is defined.  Sadly
 *                        -- this might mean we can't have a C type named
 *                        -- Extensions.  Hmmm.  We might need an ASN.1
 *                        -- extension that lets use do this:
 *                        --
 *                        --    Extension ::= Extension{{CertExtensions}}
 *                        --
 *                        -- or
 *                        --
 *                        --    Extension ::= ParameterizedExtension{{CertExtensions}}
 *                        --
 *                        -- and then rename the Extension type above to this.
 *                        -- Then we can define Extensions as a SEQUENCE OF
 *                        -- that.
 *                        --
 *                        -- <-   ParameterizedType    ->
 *      extensions      [3]  Extensions{{CertExtensions}} OPTIONAL
 *                                    -- ^^^^^^^^^^^^^^
 *                                    -- ObjectSetSpec
 *                                   -- ^^^^^^^^^^^^^^^^
 *                                   -- ObjectSet
 *                                  -- ^^^^^^^^^^^^^^^^^^
 *                                  -- ActualParameterList
 *                        -- ^^^^^^^^^^
 *                        -- Type
 *   }
 *
 * Then:
 *
 *   -- Object set, limits what Extensions can be in TBSCertificate.
 *-- <-   ObjectSetAssignment    ->
 *   CertExtensions EXTENSION ::= {
 *               -- ^^^^^^^^^
 *               -- DefinedObjectClass
 *-- ^^^^^^^^^^^^^^
 *-- objectsetreference, for us, IDENTIFIER
 *      ext-AuthorityKeyIdentifier | ext-SubjectKeyIdentifier | ...
 *   }
 *
 * and:
 *
 *   -- ObjectAssignment (with defined syntax, which we're not going to support):
 *   --
 *   -- Defines one particular object in the CertExtensions object set.
 *   -- We don't need th SYNTAX bits though -- ETOOMUCHWORK.
 *   -- This says that the OID id-ce-authorityKeyIdentifier means the extnValue
 *   -- is a DER-encoded AuthorityKeyIdentifier.
 *   ext-AuthorityKeyIdentifier EXTENSION ::= { SYNTAX
 *       AuthorityKeyIdentifier IDENTIFIED BY
 *       id-ce-authorityKeyIdentifier }
 *   id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
 *
 *   -- ObjectAssignment (with default syntax):
 *   ext-AuthorityKeyIdentifier EXTENSION ::= {
 *       -- fields don't have to be in order since we have the field names
 *       &extnId id-ce-authorityKeyIdentifier,
 *       &extnValue AuthorityKeyIdentifier
 *   }
 *
 *   -- Plain old type def using only X.680
 *   AuthorityKeyIdentifier ::= SEQUENCE {
 *       keyIdentifier             [0] KeyIdentifier            OPTIONAL,
 *       authorityCertIssuer       [1] GeneralNames             OPTIONAL,
 *       authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
 *
 * In terms of compilation, we'll want to support only the template backend,
 * though we'll generate the same C types for both, the template backend and
 * the codegen backend.
 *
 * The generators should see a type for Extension that includes a) the
 * parametrization (relating members in the SEQUENCE to fields in the CLASS),
 * and b) the object set CertExtensions for the _same_ class.
 *
 *  - The C types for ASN.1 parametrized types with object set parameters
 *    should be laid out just as before, but with additional fields:
 *
 *      typedef struct Extension {
 *        heim_oid extnID;
 *        int *critical;
 *        heim_octet_string extnValue;
 *        // NEW FIELDS BELOW
 *        enum {
 *          opentypechoice_unknown_Extension = 0
 *          opentypechoice_Extension_id_ce_authorityKeyIdentifier,
 *          ...
 *        } _element;
 *        union {
 *          // er, what should this be named?! we have no name information
 *          // and naming it after its object value name is probably not a good
 *          // idea or not easy.  We do have the OID value and possible name
 *          // though, so we should use that:
 *          AuthorityKeyIdentifier id_ce_authorityKeyIdentifier;
 *          ...
 *        } _u;
 *      } Extension;
 *
 * - The template for this should consist of new struct asn1_template entries
 *   following the ones for the normal fields of Extension.  The first of these
 *   should have an OP that indicates that the following N entries correspond
 *   to the object set that specifies this open type, then the following N
 *   entries should each point to an object in the object set.  Or maybe the
 *   object set should be a separate template -- either way.  We'll also want a
 *   flag to indicate whether the object set is sorted (none of the type IDs
 *   are IMPORTed) or not (some of the type IDs are IMPORTed) so we can binary
 *   search the object set at encode/decode time.
 *
 *   Hmm, we can assume the object sets are already sorted when there's
 *   IMPORTed IDs -- the author can do it.  Yes, they're sets, but lexically
 *   they must be in some order.
 *
 *   I like that, actually, requiring that the module author manually sort the
 *   object sets, at least when they refer to type IDs that are IMPORTed.  Or
 *   maybe forbid object sets that use IMPORTed type IDs -- the module author
 *   can always copy their definitions anyways.
 */

TypeAssignment	: Identifier EEQUAL Type
		{
		    Symbol *s = addsym($1);
		    s->stype = Stype;
		    s->type = $3;
		    fix_labels(s);

		    /*
		     * Hack: make sure that non-anonymous enumeration types get
		     * a symbol tacked on so we can generate a template for
		     * their members for value printing.
		     */
		    if (s->type->type == TTag && $3->symbol == NULL &&
			$3->subtype != NULL && $3->subtype->type == TInteger &&
			$3->subtype->symbol == NULL) {
			$3->subtype->symbol = s;
		    }
		    if (original_order)
			generate_type(s);
		    else
			generate_type_header_forwards(s);
		}
		;

ParameterizedTypeAssignment
		/* For now we'll only support one parameter -- enough for PKIX */
		: Identifier '{' Parameter '}' EEQUAL Type
		{
		    char *pname = NULL;
		    Symbol *s;

		    if (asprintf(&pname, "%s{%s:x}", $1, $3->symbol->name) == -1 ||
			pname == NULL)
			err(1, "Out of memory");
		    s = addsym(pname);
		    free($1);
		    s->stype = Sparamtype;
		    s->type = parametrize_type($6, $3);
		    s->type->symbol = s;
		    fix_labels(s);
		}
		;

/*
 * We're not going to support governor variables for now.  We don't need to.
 *
 * Also, we're not going to support more than one formal parameter.
 * Correspondingly we'll only support a single actual parameter (the count of
 * formal and actual parameters has to match, naturally).
 */

Parameter       : ParamGovernor ':' DummyReference
		{ $$ = $1; };
	     /* | DummyReference */
		;

DummyReference  : TYPE_IDENTIFIER { $$ = idcounter++; };

ParamGovernor   : DefinedObjectClass
		{ $$ = $1; }
	     /* | DummyGovernor */
	     /* | Type */
		;

UnconstrainedType : BitStringType
                  | BooleanType
                  | CharacterStringType
                  | ChoiceType
                  | EnumeratedType
                  | IntegerType
                  | NullType
                  | ObjectIdentifierType
                  | OctetStringType
                  | SequenceType
                  | SetType
                  | ObjectClassFieldType; /* X.681 */

Type		: BuiltinType | ReferencedType | ConstrainedType ;

BuiltinType	: BitStringType
		| BooleanType
		| CharacterStringType
		| ChoiceType
		| EnumeratedType
		| IntegerType
		| NullType
		| ObjectIdentifierType
		| OctetStringType
		| SequenceType
		| SequenceOfType
		| SetType
		| SetOfType
		| TaggedType
		| ObjectClassFieldType  /* X.681 */
	     /* | InstanceOfType        // X.681 */
		;

ObjectClassFieldType
		: DefinedObjectClass '.' '&' Identifier
		{ $$ = type_from_class_field($1, $4); };

BooleanType	: kw_BOOLEAN
		{
			$$ = new_tag(ASN1_C_UNIV, UT_Boolean,
				     TE_EXPLICIT, new_type(TBoolean));
		}
		;

             /*
              * The spec says the values in a ValueRange are Values, but a) all
              * the various value ranges do not involve OBJECT IDENTIFIER, b)
              * we only support integer value ranges at this time (as opposed
              * to, e.g., time ranges, and we don't even support time values at
              * this time), c) allowing OBJECT IDENTIFIER here causes a
              * shift-reduce conflict, so we limit ourselves to integer values
              * in ranges.  We could always define IntegerValueRange,
              * TimeValueRange, etc. when we add support for more value types.
              */
range		: IntegerValue RANGE IntegerValue
		{
		    if($1->type != integervalue)
			lex_error_message("Non-integer used in first part of range");
		    if($1->type != integervalue)
			lex_error_message("Non-integer in second part of range");
		    $$ = ecalloc(1, sizeof(*$$));
		    $$->min = $1->u.integervalue;
		    $$->max = $3->u.integervalue;
		}
		| IntegerValue RANGE kw_MAX
		{
		    if($1->type != integervalue)
			lex_error_message("Non-integer in first part of range");
		    $$ = ecalloc(1, sizeof(*$$));
		    $$->min = $1->u.integervalue;
		    $$->max = INT_MAX;
		}
		| kw_MIN RANGE IntegerValue
		{
		    if($3->type != integervalue)
			lex_error_message("Non-integer in second part of range");
		    $$ = ecalloc(1, sizeof(*$$));
		    $$->min = INT_MIN;
		    $$->max = $3->u.integervalue;
		}
		| IntegerValue
		{
		    if($1->type != integervalue)
			lex_error_message("Non-integer used in limit");
		    $$ = ecalloc(1, sizeof(*$$));
		    $$->min = $1->u.integervalue;
		    $$->max = $1->u.integervalue;
		}
		;


IntegerType	: kw_INTEGER
		{
			$$ = new_tag(ASN1_C_UNIV, UT_Integer,
				     TE_EXPLICIT, new_type(TInteger));
		}
		| kw_INTEGER '{' NamedNumberList '}'
		{
		  $$ = new_type(TInteger);
		  $$->members = $3;
		  $$ = new_tag(ASN1_C_UNIV, UT_Integer, TE_EXPLICIT, $$);
		}
		;

NamedNumberList	: NamedNumber
		{
			$$ = emalloc(sizeof(*$$));
			HEIM_TAILQ_INIT($$);
			HEIM_TAILQ_INSERT_HEAD($$, $1, members);
		}
		| NamedNumberList ',' NamedNumber
		{
			HEIM_TAILQ_INSERT_TAIL($1, $3, members);
			$$ = $1;
		}
		| NamedNumberList ',' ELLIPSIS
			{ $$ = $1; } /* XXX used for Enumerations */
		;

NamedNumber	: Identifier '(' SignedNumber ')'
		{
			$$ = emalloc(sizeof(*$$));
			$$->name = $1;
			$$->gen_name = estrdup($1);
			output_name ($$->gen_name);
			$$->val = $3;
			$$->optional = 0;
			$$->ellipsis = 0;
			$$->type = NULL;
		}
		| Identifier '(' DefinedValue ')'
		{
			if ($3->type != integervalue)
			    lex_error_message("Named number %s not a numeric value",
					      $3->s->name);
			$$ = emalloc(sizeof(*$$));
			$$->name = $1;
			$$->gen_name = estrdup($1);
			output_name ($$->gen_name);
			$$->val = $3->u.integervalue;
			$$->optional = 0;
			$$->ellipsis = 0;
			$$->type = NULL;
		}
		;

EnumeratedType	: kw_ENUMERATED '{' Enumerations '}'
		{
		  $$ = new_type(TInteger);
		  $$->members = $3;
		  $$ = new_tag(ASN1_C_UNIV, UT_Enumerated, TE_EXPLICIT, $$);
		}
		;

Enumerations	: NamedNumberList /* XXX */
		;

BitStringType	: kw_BIT kw_STRING
		{
		  $$ = new_type(TBitString);
		  $$->members = emalloc(sizeof(*$$->members));
		  HEIM_TAILQ_INIT($$->members);
		  $$ = new_tag(ASN1_C_UNIV, UT_BitString, TE_EXPLICIT, $$);
		}
		| kw_BIT kw_STRING '{' NamedBitList '}'
		{
		  $$ = new_type(TBitString);
		  $$->members = $4;
		  $$ = new_tag(ASN1_C_UNIV, UT_BitString, TE_EXPLICIT, $$);
		}
		;

ObjectIdentifierType: kw_OBJECT kw_IDENTIFIER
		{
			$$ = new_tag(ASN1_C_UNIV, UT_OID,
				     TE_EXPLICIT, new_type(TOID));
		}
		;
OctetStringType	: kw_OCTET kw_STRING size
		{
		    Type *t = new_type(TOctetString);
		    t->range = $3;
		    if (t->range) {
			if (t->range->min < 0)
			    lex_error_message("can't use a negative SIZE range "
					      "length for OCTET STRING");
		    }
		    $$ = new_tag(ASN1_C_UNIV, UT_OctetString,
				 TE_EXPLICIT, t);
		}
		;

NullType	: kw_NULL
		{
			$$ = new_tag(ASN1_C_UNIV, UT_Null,
				     TE_EXPLICIT, new_type(TNull));
		}
		;

size		:
		{ $$ = NULL; }
		| kw_SIZE '(' range ')'
		{ $$ = $3; }
		;


SequenceType	: kw_SEQUENCE '{' /* ComponentTypeLists */ ComponentTypeList '}'
		{
		  $$ = new_type(TSequence);
		  $$->members = $3;
		  $$ = new_tag(ASN1_C_UNIV, UT_Sequence, default_tag_env, $$);
		}
		| kw_SEQUENCE '{' '}'
		{
		  $$ = new_type(TSequence);
		  $$->members = NULL;
		  $$ = new_tag(ASN1_C_UNIV, UT_Sequence, default_tag_env, $$);
		}
		;

SequenceOfType	: kw_SEQUENCE size kw_OF Type
		{
		  $$ = new_type(TSequenceOf);
		  $$->range = $2;
		  if ($$->range) {
		      if ($$->range->min < 0)
			  lex_error_message("can't use a negative SIZE range "
					    "length for SEQUENCE OF");
		    }

		  $$->subtype = $4;
		  $$ = new_tag(ASN1_C_UNIV, UT_Sequence, default_tag_env, $$);
		}
		;

SetType		: kw_SET '{' /* ComponentTypeLists */ ComponentTypeList '}'
		{
		  $$ = new_type(TSet);
		  $$->members = $3;
		  $$ = new_tag(ASN1_C_UNIV, UT_Set, default_tag_env, $$);
		}
		| kw_SET '{' '}'
		{
		  $$ = new_type(TSet);
		  $$->members = NULL;
		  $$ = new_tag(ASN1_C_UNIV, UT_Set, default_tag_env, $$);
		}
		;

SetOfType	: kw_SET kw_OF Type
		{
		  $$ = new_type(TSetOf);
		  $$->subtype = $3;
		  $$ = new_tag(ASN1_C_UNIV, UT_Set, default_tag_env, $$);
		}
		;

ChoiceType	: kw_CHOICE '{' /* AlternativeTypeLists */ ComponentTypeList '}'
		{
		  $$ = new_type(TChoice);
		  $$->members = $3;
		}
		;

ReferencedType	: DefinedType
		| UsefulType
	     /* | TypeFromObject           // X.681 */
	     /* | ValueSetFromObjects      // X.681 */
		;

/*
TypeFromObject	: VALUE_IDENTIFIER '.' '&' TYPE_IDENTIFIER
		{ $$ = type_from_object($1, $4); };
 */

DefinedType	: TYPE_IDENTIFIER
		{
		  Symbol *s = addsym($1);
		  $$ = new_type(TType);
		  if(s->stype != Stype && s->stype != SUndefined)
		    lex_error_message ("%s is not a type\n", $1);
		  else
		    $$->symbol = s;
		}
		| ParameterizedType
		{ $$ = $1; }
		;

		/*
                 * Should be ActualParameterList, but we'll do just one for now
                 * as that's enough for PKIX.
		 */
ParameterizedType
		: Identifier '{' ActualParameter '}' /* XXX ActualParameterList */
		{
		  Symbol *s, *ps;
		  char *pname = NULL;

		  if ($3 == NULL) {
                    lex_error_message("Unknown ActualParameter object set parametrizing %s\n", $1);
                    exit(1);
                  }

		  /* Lookup the type from a ParameterizedTypeAssignment */
		  if (asprintf(&pname, "%s{%s:x}", $1,
			       $3->iosclass->symbol->name) == -1 ||
		      pname == NULL)
		      err(1, "Out of memory");
		  ps = addsym(pname);
		  if (ps->stype != Sparamtype)
		    lex_error_message ("%s is not a parameterized type\n", $1);

		  s = addsym($1);
		  $$ = ps->type; /* XXX copy, probably */
		  if (!ps->type)
		    errx(1, "Wrong class (%s) parameter for parameterized "
		         "type %s", $3->iosclass->symbol->name, $1);
		  s->stype = Stype;
		  if(s->stype != Stype && s->stype != SUndefined)
		    lex_error_message ("%s is not a type\n", $1);
		  else
		    $$->symbol = s;
		  $$->actual_parameter = $3;
		  if ($$->type == TTag)
		    $$->subtype->actual_parameter = $3;
		}

/*
 * Per X.683 $1 for ActualParameter should be any of: a Type, a Value, a
 * ValueSet, a DefinedObjectClass, an Object, or an ObjectSet.  For PKIX we
 * need nothing more than an ObjectSet here.
 *
 * Also, we can't lexically or syntactically tell the difference between all
 * these things, though fortunately we can for ObjectSet.
 */
ActualParameter : DefinedObjectSet
		{ $$ = $1; };

UsefulType	: kw_GeneralizedTime
		{
			$$ = new_tag(ASN1_C_UNIV, UT_GeneralizedTime,
				     TE_EXPLICIT, new_type(TGeneralizedTime));
		}
		| kw_UTCTime
		{
			$$ = new_tag(ASN1_C_UNIV, UT_UTCTime,
				     TE_EXPLICIT, new_type(TUTCTime));
		}
		;

ConstrainedType	: UnconstrainedType Constraint
		{
		    $$ = $1;
                    if ($2->ctype == CT_RANGE) {
                        if ($1->type != TTag || $1->subtype->type != TInteger)
                            lex_error_message("RANGE constraints apply only to INTEGER types");
                        $$->subtype->range = $2->u.range;
                        free($2);
                    } else {
                        $$->constraint = $2;
                    }
		    /* if (Constraint.type == contentConstraint) {
		       assert(Constraint.u.constraint.type == octetstring|bitstring-w/o-NamedBitList); // remember to check type reference too
		       if (Constraint.u.constraint.type) {
		         assert((Constraint.u.constraint.type.length % 8) == 0);
		       }
		      }
		      if (Constraint.u.constraint.encoding) {
		        type == der-oid|ber-oid
		      }
		    */
		}
		;


Constraint	: '(' ConstraintSpec ')'
		{
		    $$ = $2;
		}
		;

ConstraintSpec	: SubtypeConstraint | GeneralConstraint
		;

SubtypeConstraint: range
		{
                        $$ = new_constraint_spec(CT_RANGE);
                        $$->u.range = $1;
		}

GeneralConstraint: ContentsConstraint
		| UserDefinedConstraint
		| TableConstraint
		;

ContentsConstraint: kw_CONTAINING Type
		{
		    $$ = new_constraint_spec(CT_CONTENTS);
		    $$->u.content.type = $2;
		    $$->u.content.encoding = NULL;
		}
		| kw_ENCODED kw_BY Value
		{
		    if ($3->type != objectidentifiervalue)
			lex_error_message("Non-OID used in ENCODED BY constraint");
		    $$ = new_constraint_spec(CT_CONTENTS);
		    $$->u.content.type = NULL;
		    $$->u.content.encoding = $3;
		}
		| kw_CONTAINING Type kw_ENCODED kw_BY Value
		{
		    if ($5->type != objectidentifiervalue)
			lex_error_message("Non-OID used in ENCODED BY constraint");
		    $$ = new_constraint_spec(CT_CONTENTS);
		    $$->u.content.type = $2;
		    $$->u.content.encoding = $5;
		}
		;

UserDefinedConstraint: kw_CONSTRAINED kw_BY '{' '}'
		{
		    $$ = new_constraint_spec(CT_USER);
		}
		;

TableConstraint : SimpleTableConstraint
		{ $$ = $1; }
		| ComponentRelationConstraint
		{ $$ = $1; };

SimpleTableConstraint
		: '{' TYPE_IDENTIFIER '}'
		{
		    $$ = ecalloc(1, sizeof(*$$));
		    $$->ctype = CT_TABLE_CONSTRAINT;
		    $$->u.content.crel.objectname = $2;
		    $$->u.content.crel.membername = 0;
		};

/*
 * In X.682, ComponentRelationConstraint is a fantastically more complicated
 * production.  The stuff in the second set of braces is a list of AtNotation,
 * and AtNotation is '@' followed by some number of '.'s, followed by a
 * ComponentIdList, which is a non-empty set of identifiers separated by '.'s.
 * The number of '.'s is a "level" used to identify a SET, SEQUENCE, or CHOICE
 * where the path of member identifiers is rooted that ultimately identifies
 * the field providing the constraint.
 *
 * So in
 *
 *  extnValue   OCTET STRING
 *    (CONTAINING
 *	EXTENSION.&ExtnType({ExtensionSet}{@extnID}))
 *	^^^^^^^^^^^^^^^^^^^
 *	ObjectClassFieldType
 *	meaning the open type field
 *	&ExtnType of EXTENSION
 *	                   ^^^^^^^^^^^^^^^^^^^^^^^^^
 *	                   GeneralConstraint
 *	                    ^^^^^^^^^^^^^^^^^^^^^^^
 *	                    ComponentRelationConstraint
 *	                    ^^^^^^^^^^^^^^
 *	                    DefinedObjectSet
 *	                                  ^^^^^^^^
 *	                                   '{' AtNotation ','  +  '}'
 *
 * we have EXTENSION.&ExtnType is the ObjectClassFieldType, and
 * ({ExtensionSet}{@extnID}) is the ComponentRelationConstraint on the
 * extnValue member, where {ExtensionSet} is the DummyReference from the formal
 * parameter of the enclosing parameterized type, and {@extnID} is the
 * AtNotation list identifying the field of the class/objects-in-the-object-set
 * that will be identifying the type of the extnValue field.
 *
 * We need just the one AtNotation component.
 */
ComponentRelationConstraint
		: '{' TYPE_IDENTIFIER '}' '{' '@' Identifier '}'
		{
		    $$ = ecalloc(1, sizeof(*$$));
		    $$->ctype = CT_TABLE_CONSTRAINT;
		    $$->u.content.crel.objectname = $2;
		    $$->u.content.crel.membername = $6;
		};

TaggedType	: Tag tagenv Type
		{
			$$ = new_type(TTag);
			$$->tag = $1;
			$$->tag.tagenv = $2;
			if (template_flag) {
			    $$->subtype = $3;
			} else if ($2 == TE_IMPLICIT) {
			    Type *t = $3;

			    /*
			     * FIXME We shouldn't do this... The logic for
			     * dealing with IMPLICIT tags belongs elsewhere.
			     */
			    while (t->type == TType) {
				if (t->subtype)
				    t = t->subtype;
				else if (t->symbol && t->symbol->type)
				    t = t->symbol->type;
				else
				    break;
			    }
			    /*
			     * IMPLICIT tags of CHOICE types are EXPLICIT
			     * instead.
			     */
			    if (t->type == TChoice) {
				$$->implicit_choice = 1;
				$$->tag.tagenv = TE_EXPLICIT;
			    }
			    if($3->type == TTag && $2 == TE_IMPLICIT) {
				$$->subtype = $3->subtype;
				free($3);
			    } else {
				$$->subtype = $3;
			    }
			} else {
			    $$->subtype = $3;
			}
		}
		;

Tag		: '[' Class NUMBER ']'
		{
			$$.tagclass = $2;
			$$.tagvalue = $3;
			$$.tagenv = default_tag_env;
		}
		;

Class		: /* */
		{
			$$ = ASN1_C_CONTEXT;
		}
		| kw_UNIVERSAL
		{
			$$ = ASN1_C_UNIV;
		}
		| kw_APPLICATION
		{
			$$ = ASN1_C_APPL;
		}
		| kw_PRIVATE
		{
			$$ = ASN1_C_PRIVATE;
		}
		;

tagenv		: /* */
		{
			$$ = default_tag_env;
		}
		| kw_EXPLICIT
		{
			$$ = default_tag_env;
		}
		| kw_IMPLICIT
		{
			$$ = TE_IMPLICIT;
		}
		;


ValueAssignment	: VALUE_IDENTIFIER Type EEQUAL Value
		{
			Symbol *s;
			s = addsym ($1);

			s->stype = SValue;
			s->value = $4;
			generate_constant (s);
			/*
			 * Save this value's name so we can know some name for
			 * this value wherever _a_ name may be needed for it.
			 *
			 * This is useful for OIDs used as type IDs in objects
			 * sets of classes with open types.  We'll generate
			 * enum labels from those OIDs' names.
			 */
                        s->value->s = s;
		}
		;

CharacterStringType: RestrictedCharactedStringType
		;

RestrictedCharactedStringType: kw_GeneralString
		{
			$$ = new_tag(ASN1_C_UNIV, UT_GeneralString,
				     TE_EXPLICIT, new_type(TGeneralString));
		}
		| kw_TeletexString
		{
			$$ = new_tag(ASN1_C_UNIV, UT_TeletexString,
				     TE_EXPLICIT, new_type(TTeletexString));
		}
		| kw_UTF8String
		{
			$$ = new_tag(ASN1_C_UNIV, UT_UTF8String,
				     TE_EXPLICIT, new_type(TUTF8String));
		}
		| kw_PrintableString
		{
			$$ = new_tag(ASN1_C_UNIV, UT_PrintableString,
				     TE_EXPLICIT, new_type(TPrintableString));
		}
		| kw_VisibleString
		{
			$$ = new_tag(ASN1_C_UNIV, UT_VisibleString,
				     TE_EXPLICIT, new_type(TVisibleString));
		}
		| kw_IA5String
		{
			$$ = new_tag(ASN1_C_UNIV, UT_IA5String,
				     TE_EXPLICIT, new_type(TIA5String));
		}
		| kw_BMPString
		{
			$$ = new_tag(ASN1_C_UNIV, UT_BMPString,
				     TE_EXPLICIT, new_type(TBMPString));
		}
		| kw_UniversalString
		{
			$$ = new_tag(ASN1_C_UNIV, UT_UniversalString,
				     TE_EXPLICIT, new_type(TUniversalString));
		}

		;

ComponentTypeList: ComponentType
		{
			$$ = emalloc(sizeof(*$$));
			HEIM_TAILQ_INIT($$);
			HEIM_TAILQ_INSERT_HEAD($$, $1, members);
		}
		| ComponentTypeList ',' ComponentType
		{
			HEIM_TAILQ_INSERT_TAIL($1, $3, members);
			$$ = $1;
		}
		| ComponentTypeList ',' ELLIPSIS
		{
		        struct member *m = ecalloc(1, sizeof(*m));
			m->name = estrdup("...");
			m->gen_name = estrdup("asn1_ellipsis");
			m->ellipsis = 1;
			HEIM_TAILQ_INSERT_TAIL($1, m, members);
			$$ = $1;
		}
		;

NamedType	: Identifier Type
		{
		  $$ = emalloc(sizeof(*$$));
		  $$->name = $1;
		  $$->gen_name = estrdup($1);
		  output_name ($$->gen_name);
		  $$->type = $2;
		  $$->ellipsis = 0;
		}
		;

ComponentType	: NamedType
		{
			$$ = $1;
			$$->optional = 0;
			$$->defval = NULL;
		}
		| NamedType kw_OPTIONAL
		{
			$$ = $1;
			$$->optional = 1;
			$$->defval = NULL;
		}
		| NamedType kw_DEFAULT Value
		{
			$$ = $1;
			$$->optional = 0;
			$$->defval = $3;
		}
		;

NamedBitList	: NamedBit
		{
			$$ = emalloc(sizeof(*$$));
			HEIM_TAILQ_INIT($$);
			HEIM_TAILQ_INSERT_HEAD($$, $1, members);
		}
		| NamedBitList ',' NamedBit
		{
			HEIM_TAILQ_INSERT_TAIL($1, $3, members);
			$$ = $1;
		}
		;

NamedBit	: Identifier '(' NUMBER ')'
		{
		  $$ = emalloc(sizeof(*$$));
		  $$->name = $1;
		  $$->gen_name = estrdup($1);
		  output_name ($$->gen_name);
		  $$->val = $3;
		  $$->optional = 0;
		  $$->ellipsis = 0;
		  $$->type = NULL;
		}
		;

objid_opt	: objid
		| /* empty */ { $$ = NULL; }
		;

objid		: '{' objid_list '}'
		{
			$$ = $2;
		}
		;

objid_list	:  /* empty */
		{
			$$ = NULL;
		}
		| objid_element objid_list
		{
		        if ($2) {
				$$ = $2;
				add_oid_to_tail($2, $1);
			} else {
				$$ = $1;
			}
		}
		;

objid_element	: Identifier '(' NUMBER ')'
		{
			$$ = new_objid($1, $3);
		}
		| Identifier
		{
		    Symbol *s = addsym($1);
		    if(s->stype != SValue ||
		       s->value->type != objectidentifiervalue) {
			lex_error_message("%s is not an object identifier\n",
				      s->name);
			exit(1);
		    }
		    $$ = s->value->u.objectidentifiervalue;
		}
		| NUMBER
		{
		    $$ = new_objid(NULL, $1);
		}
		;

Value		: BuiltinValue
		| ReferencedValue
		;

ValueExNull	: BuiltinValueExNull
		| ReferencedValue
		;

BuiltinValue	: BooleanValue
		| CharacterStringValue
		| IntegerValue
		| ObjectIdentifierValue
		| NullValue
		;

BuiltinValueExNull
		: BooleanValue
		| CharacterStringValue
		| IntegerValue
		| ObjectIdentifierValue
		;

ReferencedValue	: DefinedValue
		;

DefinedValue	: Valuereference
		;

Valuereference	: VALUE_IDENTIFIER
		{
			Symbol *s = addsym($1);
			if(s->stype != SValue)
				lex_error_message ("%s is not a value\n",
						s->name);
			else
				$$ = s->value;
		}
		;

CharacterStringValue: STRING
		{
			$$ = emalloc(sizeof(*$$));
			$$->type = stringvalue;
			$$->u.stringvalue = $1;
		}
		;

BooleanValue	: kw_TRUE
		{
			$$ = emalloc(sizeof(*$$));
			$$->type = booleanvalue;
			$$->u.booleanvalue = 1;
		}
		| kw_FALSE
		{
			$$ = emalloc(sizeof(*$$));
			$$->type = booleanvalue;
			$$->u.booleanvalue = 0;
		}
		;

IntegerValue	: SignedNumber
		{
			$$ = emalloc(sizeof(*$$));
			$$->type = integervalue;
			$$->u.integervalue = $1;
		}
		;

SignedNumber	: NUMBER
		;

NullValue	: kw_NULL
		{
		}
		;

ObjectIdentifierValue: objid
		{
			$$ = emalloc(sizeof(*$$));
			$$->type = objectidentifiervalue;
			$$->u.objectidentifiervalue = $1;
		}
		;

%%

void
yyerror (const char *s)
{
     lex_error_message ("%s\n", s);
}

static Type *
new_tag(int tagclass, int tagvalue, int tagenv, Type *oldtype)
{
    Type *t;
    if(oldtype->type == TTag && oldtype->tag.tagenv == TE_IMPLICIT) {
	t = oldtype;
	oldtype = oldtype->subtype; /* XXX */
    } else
	t = new_type (TTag);

    t->tag.tagclass = tagclass;
    t->tag.tagvalue = tagvalue;
    t->tag.tagenv = tagenv;
    t->subtype = oldtype;
    return t;
}

static struct objid *
new_objid(const char *label, int value)
{
    struct objid *s;
    s = emalloc(sizeof(*s));
    s->label = label;
    s->value = value;
    s->next = NULL;
    return s;
}

static void
add_oid_to_tail(struct objid *head, struct objid *tail)
{
    struct objid *o;
    o = head;
    while (o->next)
	o = o->next;
    o->next = tail;
}

static Type *
new_type (Typetype tt)
{
    Type *t = ecalloc(1, sizeof(*t));
    t->type = tt;
    t->id = idcounter++;
    return t;
}

static struct constraint_spec *
new_constraint_spec(enum ctype ct)
{
    struct constraint_spec *c = ecalloc(1, sizeof(*c));
    c->ctype = ct;
    return c;
}

static void fix_labels2(Type *t, const char *prefix);
static void fix_labels1(struct memhead *members, const char *prefix)
{
    Member *m;

    if(members == NULL)
	return;
    HEIM_TAILQ_FOREACH(m, members, members) {
	if (asprintf(&m->label, "%s_%s", prefix, m->gen_name) < 0)
	    errx(1, "malloc");
	if (m->label == NULL)
	    errx(1, "malloc");
	if(m->type != NULL)
	    fix_labels2(m->type, m->label);
    }
}

static void fix_labels2(Type *t, const char *prefix)
{
    for(; t; t = t->subtype)
	fix_labels1(t->members, prefix);
}

static void
fix_labels(Symbol *s)
{
    char *p = NULL;
    if (asprintf(&p, "choice_%s", s->gen_name) < 0 || p == NULL)
	errx(1, "malloc");
    if (s->type)
	fix_labels2(s->type, p);
    free(p);
}

static struct objectshead *
add_object_set_spec(struct objectshead *lst, IOSObject *o)
{
    if (lst == NULL) {
	lst = emalloc(sizeof(*lst));
	HEIM_TAILQ_INIT(lst);
	HEIM_TAILQ_INSERT_HEAD(lst, o, objects);
    } else {
	HEIM_TAILQ_INSERT_TAIL(lst, o, objects);
    }
    return lst;
}

static struct objfieldhead *
add_field_setting(struct objfieldhead *lst, ObjectField *f)
{
    if (lst == NULL) {
	lst = emalloc(sizeof(*lst));
	HEIM_TAILQ_INIT(lst);
	HEIM_TAILQ_INSERT_HEAD(lst, f, objfields);
    } else {
	HEIM_TAILQ_INSERT_TAIL(lst, f, objfields);
    }
    return lst;
}

static struct fieldhead *
add_field_spec(struct fieldhead *lst, Field *f)
{
    if (lst == NULL) {
	lst = emalloc(sizeof(*lst));
	HEIM_TAILQ_INIT(lst);
	HEIM_TAILQ_INSERT_HEAD(lst, f, fields);
    } else {
	HEIM_TAILQ_INSERT_TAIL(lst, f, fields);
    }
    return lst;
}

static ObjectField *
new_field_setting(char *n, Type *t, struct value *v)
{
    ObjectField *of;

    of = ecalloc(1, sizeof(*of));
    of->value = v;
    of->type = t;
    of->name = n;
    return of;
}

static Field *
new_type_field(char *n, int optional, Type *t)
{
    Field *f;

    f = ecalloc(1, sizeof(*f));
    f->optional = optional;
    f->unique = 0;
    f->defval = 0;
    f->type = t;
    f->name = n;
    return f;
}

static Field *
new_fixed_type_value_field(char *n, Type *t, int unique, int optional, struct value *defval)
{
    Field *f;

    f = ecalloc(1, sizeof(*f));
    f->optional = optional;
    f->unique = unique;
    f->defval = defval;
    f->type = t;
    f->name = n;
    return f;
}

static Type *
parametrize_type(Type *t, IOSClass *c)
{
    Type *type;

    type = new_type(TType);
    *type = *t; /* XXX Copy, or use subtype; this only works as long as we don't cleanup! */
    type->formal_parameter = c;
    return type;
}

static Type *
type_from_class_field(IOSClass *c, const char *n)
{
    Field *f;
    Type *t;

    HEIM_TAILQ_FOREACH(f, c->fields, fields) {
	if (strcmp(f->name, n) == 0) {
	    t = new_type(TType);
	    if (f->type) {
		*t = *f->type;
	    } else {
		Symbol *s = addsym("HEIM_ANY");
		if(s->stype != Stype && s->stype != SUndefined)
		    errx(1, "Do not define HEIM_ANY, only import it\n");
		s->stype = Stype;
		t->symbol = s;
	    }
	    t->typeref.iosclass = c;
	    t->typeref.field = f;
	    return t;
	}
    }
    return NULL;
}

static void
validate_object_set(IOSObjectSet *os)
{
    IOSObject **objects;
    ObjectField *of;
    IOSObject *o;
    Field *cf;
    size_t nobjs, i;

    /* Check unique fields */
    HEIM_TAILQ_FOREACH(cf, os->iosclass->fields, fields) {
        if (!cf->unique)
            continue;
        if (!cf->type)
            errx(1, "Type fields of classes can't be UNIQUE (%s)",
                 os->iosclass->symbol->name);
        sort_object_set(os, cf, &objects, &nobjs);
        for (i = 0; i < nobjs; i++) {
            HEIM_TAILQ_FOREACH(of, objects[i]->objfields, objfields) {
                if (strcmp(cf->name, of->name) != 0)
                    continue;
                if (!of->value)
                    errx(1, "Value not specified for required UNIQUE field %s of object %s",
                         cf->name, objects[i]->symbol->name);
                break;
            }
            if (i == 0)
                continue;
            if (object_cmp(&objects[i - 1], &objects[i]) == 0)
                errx(1, "Duplicate values of UNIQUE field %s of objects %s and %s",
                     cf->name, objects[i - 1]->symbol->name,
                     objects[i]->symbol->name);
        }
        free(objects);
    }

    /* Check required fields */
    HEIM_TAILQ_FOREACH(cf, os->iosclass->fields, fields) {
        if (cf->optional || cf->defval || !cf->type)
            continue;
        HEIM_TAILQ_FOREACH(o, os->objects, objects) {
            int specified = 0;

            HEIM_TAILQ_FOREACH(of, o->objfields, objfields) {
                if (strcmp(of->name, cf->name) != 0)
                    continue;
                if (of->value)
                    specified = 1;
                break;
            }
            if (!specified)
                errx(1, "Value not specified for required non-UNIQUE field %s of object %s",
                     cf->name, o->symbol->name);
        }
    }
}
