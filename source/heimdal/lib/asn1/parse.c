/* A Bison parser, made by GNU Bison 2.1.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Written by Richard Stallman by simplifying the original so called
   ``semantic'' parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.1"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     kw_ABSENT = 258,
     kw_ABSTRACT_SYNTAX = 259,
     kw_ALL = 260,
     kw_APPLICATION = 261,
     kw_AUTOMATIC = 262,
     kw_BEGIN = 263,
     kw_BIT = 264,
     kw_BMPString = 265,
     kw_BOOLEAN = 266,
     kw_BY = 267,
     kw_CHARACTER = 268,
     kw_CHOICE = 269,
     kw_CLASS = 270,
     kw_COMPONENT = 271,
     kw_COMPONENTS = 272,
     kw_CONSTRAINED = 273,
     kw_CONTAINING = 274,
     kw_DEFAULT = 275,
     kw_DEFINITIONS = 276,
     kw_EMBEDDED = 277,
     kw_ENCODED = 278,
     kw_END = 279,
     kw_ENUMERATED = 280,
     kw_EXCEPT = 281,
     kw_EXPLICIT = 282,
     kw_EXPORTS = 283,
     kw_EXTENSIBILITY = 284,
     kw_EXTERNAL = 285,
     kw_FALSE = 286,
     kw_FROM = 287,
     kw_GeneralString = 288,
     kw_GeneralizedTime = 289,
     kw_GraphicString = 290,
     kw_IA5String = 291,
     kw_IDENTIFIER = 292,
     kw_IMPLICIT = 293,
     kw_IMPLIED = 294,
     kw_IMPORTS = 295,
     kw_INCLUDES = 296,
     kw_INSTANCE = 297,
     kw_INTEGER = 298,
     kw_INTERSECTION = 299,
     kw_ISO646String = 300,
     kw_MAX = 301,
     kw_MIN = 302,
     kw_MINUS_INFINITY = 303,
     kw_NULL = 304,
     kw_NumericString = 305,
     kw_OBJECT = 306,
     kw_OCTET = 307,
     kw_OF = 308,
     kw_OPTIONAL = 309,
     kw_ObjectDescriptor = 310,
     kw_PATTERN = 311,
     kw_PDV = 312,
     kw_PLUS_INFINITY = 313,
     kw_PRESENT = 314,
     kw_PRIVATE = 315,
     kw_PrintableString = 316,
     kw_REAL = 317,
     kw_RELATIVE_OID = 318,
     kw_SEQUENCE = 319,
     kw_SET = 320,
     kw_SIZE = 321,
     kw_STRING = 322,
     kw_SYNTAX = 323,
     kw_T61String = 324,
     kw_TAGS = 325,
     kw_TRUE = 326,
     kw_TYPE_IDENTIFIER = 327,
     kw_TeletexString = 328,
     kw_UNION = 329,
     kw_UNIQUE = 330,
     kw_UNIVERSAL = 331,
     kw_UTCTime = 332,
     kw_UTF8String = 333,
     kw_UniversalString = 334,
     kw_VideotexString = 335,
     kw_VisibleString = 336,
     kw_WITH = 337,
     RANGE = 338,
     EEQUAL = 339,
     ELLIPSIS = 340,
     IDENTIFIER = 341,
     referencename = 342,
     STRING = 343,
     NUMBER = 344
   };
#endif
/* Tokens.  */
#define kw_ABSENT 258
#define kw_ABSTRACT_SYNTAX 259
#define kw_ALL 260
#define kw_APPLICATION 261
#define kw_AUTOMATIC 262
#define kw_BEGIN 263
#define kw_BIT 264
#define kw_BMPString 265
#define kw_BOOLEAN 266
#define kw_BY 267
#define kw_CHARACTER 268
#define kw_CHOICE 269
#define kw_CLASS 270
#define kw_COMPONENT 271
#define kw_COMPONENTS 272
#define kw_CONSTRAINED 273
#define kw_CONTAINING 274
#define kw_DEFAULT 275
#define kw_DEFINITIONS 276
#define kw_EMBEDDED 277
#define kw_ENCODED 278
#define kw_END 279
#define kw_ENUMERATED 280
#define kw_EXCEPT 281
#define kw_EXPLICIT 282
#define kw_EXPORTS 283
#define kw_EXTENSIBILITY 284
#define kw_EXTERNAL 285
#define kw_FALSE 286
#define kw_FROM 287
#define kw_GeneralString 288
#define kw_GeneralizedTime 289
#define kw_GraphicString 290
#define kw_IA5String 291
#define kw_IDENTIFIER 292
#define kw_IMPLICIT 293
#define kw_IMPLIED 294
#define kw_IMPORTS 295
#define kw_INCLUDES 296
#define kw_INSTANCE 297
#define kw_INTEGER 298
#define kw_INTERSECTION 299
#define kw_ISO646String 300
#define kw_MAX 301
#define kw_MIN 302
#define kw_MINUS_INFINITY 303
#define kw_NULL 304
#define kw_NumericString 305
#define kw_OBJECT 306
#define kw_OCTET 307
#define kw_OF 308
#define kw_OPTIONAL 309
#define kw_ObjectDescriptor 310
#define kw_PATTERN 311
#define kw_PDV 312
#define kw_PLUS_INFINITY 313
#define kw_PRESENT 314
#define kw_PRIVATE 315
#define kw_PrintableString 316
#define kw_REAL 317
#define kw_RELATIVE_OID 318
#define kw_SEQUENCE 319
#define kw_SET 320
#define kw_SIZE 321
#define kw_STRING 322
#define kw_SYNTAX 323
#define kw_T61String 324
#define kw_TAGS 325
#define kw_TRUE 326
#define kw_TYPE_IDENTIFIER 327
#define kw_TeletexString 328
#define kw_UNION 329
#define kw_UNIQUE 330
#define kw_UNIVERSAL 331
#define kw_UTCTime 332
#define kw_UTF8String 333
#define kw_UniversalString 334
#define kw_VideotexString 335
#define kw_VisibleString 336
#define kw_WITH 337
#define RANGE 338
#define EEQUAL 339
#define ELLIPSIS 340
#define IDENTIFIER 341
#define referencename 342
#define STRING 343
#define NUMBER 344




/* Copy the first part of user declarations.  */
#line 36 "parse.y"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "symbol.h"
#include "lex.h"
#include "gen_locl.h"
#include "der.h"

RCSID("$Id: parse.y,v 1.28 2006/04/28 10:51:35 lha Exp $");

static Type *new_type (Typetype t);
static struct constraint_spec *new_constraint_spec(enum ctype);
static Type *new_tag(int tagclass, int tagvalue, int tagenv, Type *oldtype);
void yyerror (const char *);
static struct objid *new_objid(const char *label, int value);
static void add_oid_to_tail(struct objid *, struct objid *);
static void fix_labels(Symbol *s);

struct string_list {
    char *string;
    struct string_list *next;
};



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 1
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 65 "parse.y"
typedef union YYSTYPE {
    int constant;
    struct value *value;
    struct range range;
    char *name;
    Type *type;
    Member *member;
    struct objid *objid;
    char *defval;
    struct string_list *sl;
    struct tagtype tag;
    struct memhead *members;
    struct constraint_spec *constraint_spec;
} YYSTYPE;
/* Line 196 of yacc.c.  */
#line 307 "parse.c"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 219 of yacc.c.  */
#line 319 "parse.c"

#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T) && (defined (__STDC__) || defined (__cplusplus))
# include <stddef.h> /* INFRINGES ON USER NAME SPACE */
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#ifndef YY_
# if YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

#if ! defined (yyoverflow) || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if defined (__STDC__) || defined (__cplusplus)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     define YYINCLUDED_STDLIB_H
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2005 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM ((YYSIZE_T) -1)
#  endif
#  ifdef __cplusplus
extern "C" {
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if (! defined (malloc) && ! defined (YYINCLUDED_STDLIB_H) \
	&& (defined (__STDC__) || defined (__cplusplus)))
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if (! defined (free) && ! defined (YYINCLUDED_STDLIB_H) \
	&& (defined (__STDC__) || defined (__cplusplus)))
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifdef __cplusplus
}
#  endif
# endif
#endif /* ! defined (yyoverflow) || YYERROR_VERBOSE */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (defined (YYSTYPE_IS_TRIVIAL) && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short int yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short int) + sizeof (YYSTYPE))			\
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined (__GNUC__) && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif

#if defined (__STDC__) || defined (__cplusplus)
   typedef signed char yysigned_char;
#else
   typedef short int yysigned_char;
#endif

/* YYFINAL -- State number of the termination state. */
#define YYFINAL  4
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   168

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  98
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  67
/* YYNRULES -- Number of rules. */
#define YYNRULES  130
/* YYNRULES -- Number of states. */
#define YYNSTATES  201

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   344

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      92,    93,     2,     2,    91,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    90,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    96,     2,    97,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    94,     2,    95,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned short int yyprhs[] =
{
       0,     0,     3,    12,    15,    18,    21,    22,    25,    26,
      29,    30,    34,    35,    37,    38,    40,    43,    48,    50,
      53,    55,    57,    61,    63,    67,    69,    71,    73,    75,
      77,    79,    81,    83,    85,    87,    89,    91,    93,    95,
      97,    99,   101,   103,   109,   111,   114,   119,   121,   125,
     129,   134,   139,   141,   144,   150,   153,   156,   158,   163,
     167,   171,   176,   180,   184,   189,   191,   193,   195,   197,
     199,   202,   206,   208,   210,   212,   215,   219,   225,   230,
     234,   239,   240,   242,   244,   246,   247,   249,   251,   256,
     258,   260,   262,   264,   266,   268,   270,   272,   276,   280,
     283,   285,   288,   292,   294,   298,   303,   305,   306,   310,
     311,   314,   319,   321,   323,   325,   327,   329,   331,   333,
     335,   337,   339,   341,   343,   345,   347,   349,   351,   353,
     355
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const short int yyrhs[] =
{
      99,     0,    -1,    86,    21,   100,   101,    84,     8,   102,
      24,    -1,    27,    70,    -1,    38,    70,    -1,     7,    70,
      -1,    -1,    29,    39,    -1,    -1,   103,   107,    -1,    -1,
      40,   104,    90,    -1,    -1,   105,    -1,    -1,   106,    -1,
     105,   106,    -1,   109,    32,    86,   150,    -1,   108,    -1,
     108,   107,    -1,   110,    -1,   142,    -1,    86,    91,   109,
      -1,    86,    -1,    86,    84,   111,    -1,   112,    -1,   129,
      -1,   132,    -1,   120,    -1,   113,    -1,   143,    -1,   128,
      -1,   118,    -1,   115,    -1,   123,    -1,   121,    -1,   122,
      -1,   124,    -1,   125,    -1,   126,    -1,   127,    -1,   138,
      -1,    11,    -1,    92,   154,    83,   154,    93,    -1,    43,
      -1,    43,   114,    -1,    43,    94,   116,    95,    -1,   117,
      -1,   116,    91,   117,    -1,   116,    91,    85,    -1,    86,
      92,   162,    93,    -1,    25,    94,   119,    95,    -1,   116,
      -1,     9,    67,    -1,     9,    67,    94,   148,    95,    -1,
      51,    37,    -1,    52,    67,    -1,    49,    -1,    64,    94,
     145,    95,    -1,    64,    94,    95,    -1,    64,    53,   111,
      -1,    65,    94,   145,    95,    -1,    65,    94,    95,    -1,
      65,    53,   111,    -1,    14,    94,   145,    95,    -1,   130,
      -1,   131,    -1,    86,    -1,    34,    -1,    77,    -1,   111,
     133,    -1,    92,   134,    93,    -1,   135,    -1,   136,    -1,
     137,    -1,    19,   111,    -1,    23,    12,   154,    -1,    19,
     111,    23,    12,   154,    -1,    18,    12,    94,    95,    -1,
     139,   141,   111,    -1,    96,   140,    89,    97,    -1,    -1,
      76,    -1,     6,    -1,    60,    -1,    -1,    27,    -1,    38,
      -1,    86,   111,    84,   154,    -1,   144,    -1,    33,    -1,
      78,    -1,    61,    -1,    36,    -1,    10,    -1,    79,    -1,
     147,    -1,   145,    91,   147,    -1,   145,    91,    85,    -1,
      86,   111,    -1,   146,    -1,   146,    54,    -1,   146,    20,
     154,    -1,   149,    -1,   148,    91,   149,    -1,    86,    92,
      89,    93,    -1,   151,    -1,    -1,    94,   152,    95,    -1,
      -1,   153,   152,    -1,    86,    92,    89,    93,    -1,    86,
      -1,    89,    -1,   155,    -1,   156,    -1,   160,    -1,   159,
      -1,   161,    -1,   164,    -1,   163,    -1,   157,    -1,   158,
      -1,    86,    -1,    88,    -1,    71,    -1,    31,    -1,   162,
      -1,    89,    -1,    49,    -1,   151,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned short int yyrline[] =
{
       0,   231,   231,   238,   239,   241,   243,   246,   248,   251,
     252,   255,   256,   259,   260,   263,   264,   267,   278,   279,
     282,   283,   286,   292,   300,   310,   311,   312,   315,   316,
     317,   318,   319,   320,   321,   322,   323,   324,   325,   326,
     327,   328,   331,   338,   348,   353,   360,   368,   374,   379,
     383,   396,   404,   407,   414,   422,   428,   435,   442,   448,
     456,   464,   470,   478,   486,   493,   494,   497,   508,   513,
     520,   536,   542,   545,   546,   549,   555,   563,   573,   579,
     592,   601,   604,   608,   612,   619,   622,   626,   633,   644,
     647,   652,   657,   662,   667,   672,   680,   686,   691,   702,
     713,   719,   725,   733,   739,   746,   759,   760,   763,   770,
     773,   784,   788,   799,   805,   806,   809,   810,   811,   812,
     813,   816,   819,   822,   833,   841,   847,   855,   863,   866,
     871
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "kw_ABSENT", "kw_ABSTRACT_SYNTAX",
  "kw_ALL", "kw_APPLICATION", "kw_AUTOMATIC", "kw_BEGIN", "kw_BIT",
  "kw_BMPString", "kw_BOOLEAN", "kw_BY", "kw_CHARACTER", "kw_CHOICE",
  "kw_CLASS", "kw_COMPONENT", "kw_COMPONENTS", "kw_CONSTRAINED",
  "kw_CONTAINING", "kw_DEFAULT", "kw_DEFINITIONS", "kw_EMBEDDED",
  "kw_ENCODED", "kw_END", "kw_ENUMERATED", "kw_EXCEPT", "kw_EXPLICIT",
  "kw_EXPORTS", "kw_EXTENSIBILITY", "kw_EXTERNAL", "kw_FALSE", "kw_FROM",
  "kw_GeneralString", "kw_GeneralizedTime", "kw_GraphicString",
  "kw_IA5String", "kw_IDENTIFIER", "kw_IMPLICIT", "kw_IMPLIED",
  "kw_IMPORTS", "kw_INCLUDES", "kw_INSTANCE", "kw_INTEGER",
  "kw_INTERSECTION", "kw_ISO646String", "kw_MAX", "kw_MIN",
  "kw_MINUS_INFINITY", "kw_NULL", "kw_NumericString", "kw_OBJECT",
  "kw_OCTET", "kw_OF", "kw_OPTIONAL", "kw_ObjectDescriptor", "kw_PATTERN",
  "kw_PDV", "kw_PLUS_INFINITY", "kw_PRESENT", "kw_PRIVATE",
  "kw_PrintableString", "kw_REAL", "kw_RELATIVE_OID", "kw_SEQUENCE",
  "kw_SET", "kw_SIZE", "kw_STRING", "kw_SYNTAX", "kw_T61String", "kw_TAGS",
  "kw_TRUE", "kw_TYPE_IDENTIFIER", "kw_TeletexString", "kw_UNION",
  "kw_UNIQUE", "kw_UNIVERSAL", "kw_UTCTime", "kw_UTF8String",
  "kw_UniversalString", "kw_VideotexString", "kw_VisibleString", "kw_WITH",
  "RANGE", "EEQUAL", "ELLIPSIS", "IDENTIFIER", "referencename", "STRING",
  "NUMBER", "';'", "','", "'('", "')'", "'{'", "'}'", "'['", "']'",
  "$accept", "ModuleDefinition", "TagDefault", "ExtensionDefault",
  "ModuleBody", "Imports", "SymbolsImported", "SymbolsFromModuleList",
  "SymbolsFromModule", "AssignmentList", "Assignment", "referencenames",
  "TypeAssignment", "Type", "BuiltinType", "BooleanType", "range",
  "IntegerType", "NamedNumberList", "NamedNumber", "EnumeratedType",
  "Enumerations", "BitStringType", "ObjectIdentifierType",
  "OctetStringType", "NullType", "SequenceType", "SequenceOfType",
  "SetType", "SetOfType", "ChoiceType", "ReferencedType", "DefinedType",
  "UsefulType", "ConstrainedType", "Constraint", "ConstraintSpec",
  "GeneralConstraint", "ContentsConstraint", "UserDefinedConstraint",
  "TaggedType", "Tag", "Class", "tagenv", "ValueAssignment",
  "CharacterStringType", "RestrictedCharactedStringType",
  "ComponentTypeList", "NamedType", "ComponentType", "NamedBitList",
  "NamedBit", "objid_opt", "objid", "objid_list", "objid_element", "Value",
  "BuiltinValue", "ReferencedValue", "DefinedValue", "Valuereference",
  "CharacterStringValue", "BooleanValue", "IntegerValue", "SignedNumber",
  "NullValue", "ObjectIdentifierValue", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const unsigned short int yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
      59,    44,    40,    41,   123,   125,    91,    93
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    98,    99,   100,   100,   100,   100,   101,   101,   102,
     102,   103,   103,   104,   104,   105,   105,   106,   107,   107,
     108,   108,   109,   109,   110,   111,   111,   111,   112,   112,
     112,   112,   112,   112,   112,   112,   112,   112,   112,   112,
     112,   112,   113,   114,   115,   115,   115,   116,   116,   116,
     117,   118,   119,   120,   120,   121,   122,   123,   124,   124,
     125,   126,   126,   127,   128,   129,   129,   130,   131,   131,
     132,   133,   134,   135,   135,   136,   136,   136,   137,   138,
     139,   140,   140,   140,   140,   141,   141,   141,   142,   143,
     144,   144,   144,   144,   144,   144,   145,   145,   145,   146,
     147,   147,   147,   148,   148,   149,   150,   150,   151,   152,
     152,   153,   153,   153,   154,   154,   155,   155,   155,   155,
     155,   156,   157,   158,   159,   160,   160,   161,   162,   163,
     164
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     8,     2,     2,     2,     0,     2,     0,     2,
       0,     3,     0,     1,     0,     1,     2,     4,     1,     2,
       1,     1,     3,     1,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     5,     1,     2,     4,     1,     3,     3,
       4,     4,     1,     2,     5,     2,     2,     1,     4,     3,
       3,     4,     3,     3,     4,     1,     1,     1,     1,     1,
       2,     3,     1,     1,     1,     2,     3,     5,     4,     3,
       4,     0,     1,     1,     1,     0,     1,     1,     4,     1,
       1,     1,     1,     1,     1,     1,     1,     3,     3,     2,
       1,     2,     3,     1,     3,     4,     1,     0,     3,     0,
       2,     4,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       0,     0,     0,     6,     1,     0,     0,     0,     8,     5,
       3,     4,     0,     0,     7,     0,    10,    14,     0,     0,
      23,     0,    13,    15,     0,     2,     0,     9,    18,    20,
      21,     0,    11,    16,     0,     0,    94,    42,     0,     0,
      90,    68,    93,    44,    57,     0,     0,    92,     0,     0,
      69,    91,    95,     0,    67,    81,     0,    25,    29,    33,
      32,    28,    35,    36,    34,    37,    38,    39,    40,    31,
      26,    65,    66,    27,    41,    85,    30,    89,    19,    22,
     107,    53,     0,     0,     0,     0,    45,    55,    56,     0,
       0,     0,     0,    24,    83,    84,    82,     0,     0,     0,
      70,    86,    87,     0,   109,    17,   106,     0,     0,     0,
     100,    96,     0,    52,    47,     0,   126,   129,   125,   123,
     124,   128,   130,     0,   114,   115,   121,   122,   117,   116,
     118,   127,   120,   119,     0,    60,    59,     0,    63,    62,
       0,     0,    88,     0,     0,     0,     0,    72,    73,    74,
      79,   112,   113,     0,   109,     0,     0,   103,    99,     0,
      64,     0,   101,     0,     0,    51,     0,    46,    58,    61,
      80,     0,    75,     0,    71,     0,   108,   110,     0,     0,
      54,    98,    97,   102,     0,    49,    48,     0,     0,     0,
      76,     0,     0,   104,    50,    43,    78,     0,   111,   105,
      77
};

/* YYDEFGOTO[NTERM-NUM]. */
static const short int yydefgoto[] =
{
      -1,     2,     8,    13,    18,    19,    21,    22,    23,    27,
      28,    24,    29,    56,    57,    58,    86,    59,   113,   114,
      60,   115,    61,    62,    63,    64,    65,    66,    67,    68,
      69,    70,    71,    72,    73,   100,   146,   147,   148,   149,
      74,    75,    97,   103,    30,    76,    77,   109,   110,   111,
     156,   157,   105,   122,   153,   154,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -99
static const short int yypact[] =
{
     -46,    20,    13,    21,   -99,    11,    23,    25,    54,   -99,
     -99,   -99,    58,     6,   -99,    90,   -34,    15,    80,    19,
      16,    18,    15,   -99,    74,   -99,    -7,   -99,    19,   -99,
     -99,    15,   -99,   -99,    24,    42,   -99,   -99,    17,    26,
     -99,   -99,   -99,   -73,   -99,    76,    50,   -99,   -45,   -44,
     -99,   -99,   -99,    51,   -99,     4,   -67,   -99,   -99,   -99,
     -99,   -99,   -99,   -99,   -99,   -99,   -99,   -99,   -99,   -99,
     -99,   -99,   -99,   -99,   -99,   -16,   -99,   -99,   -99,   -99,
      27,    28,    33,    37,    47,    37,   -99,   -99,   -99,    51,
     -72,    51,   -71,    22,   -99,   -99,   -99,    35,    47,    12,
     -99,   -99,   -99,    51,     2,   -99,   -99,    39,    51,   -75,
      -8,   -99,    34,    36,   -99,    43,   -99,   -99,   -99,   -99,
     -99,   -99,   -99,    48,   -99,   -99,   -99,   -99,   -99,   -99,
     -99,   -99,   -99,   -99,   -57,    22,   -99,   -48,    22,   -99,
     -22,    45,   -99,   120,    51,   122,    46,   -99,   -99,   -99,
      22,    52,   -99,    53,     2,    57,    -9,   -99,    22,   -53,
     -99,    47,   -99,    56,   -19,   -99,    47,   -99,   -99,   -99,
     -99,    49,   -18,    47,   -99,    61,   -99,   -99,    62,    39,
     -99,   -99,   -99,   -99,    59,   -99,   -99,    60,    63,   128,
     -99,    64,    66,   -99,   -99,   -99,   -99,    47,   -99,   -99,
     -99
};

/* YYPGOTO[NTERM-NUM].  */
static const yysigned_char yypgoto[] =
{
     -99,   -99,   -99,   -99,   -99,   -99,   -99,   -99,   124,   126,
     -99,   125,   -99,   -52,   -99,   -99,   -99,   -99,    70,    -4,
     -99,   -99,   -99,   -99,   -99,   -99,   -99,   -99,   -99,   -99,
     -99,   -99,   -99,   -99,   -99,   -99,   -99,   -99,   -99,   -99,
     -99,   -99,   -99,   -99,   -99,   -99,   -99,   -37,   -99,     3,
     -99,   -15,   -99,    81,     9,   -99,   -98,   -99,   -99,   -99,
     -99,   -99,   -99,   -99,     5,   -99,   -99
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -13
static const short int yytable[] =
{
     142,    93,    35,    36,    37,   189,    17,    38,    89,    91,
      94,   101,   161,     4,   108,   108,   159,    98,    39,    84,
     160,    85,   102,   136,   139,    99,    40,    41,     5,    42,
     143,   144,   181,   108,   164,   145,    43,   135,   167,   138,
       1,     3,    44,   159,    45,    46,   162,   168,     6,    90,
      92,   150,   -12,   137,    47,   140,   158,    48,    49,     7,
      35,    36,    37,   183,    95,    38,   185,   112,   187,   159,
      50,    51,    52,   169,    99,   190,    39,    53,   116,    54,
      96,     9,   179,    12,    40,    41,   180,    42,   151,    55,
      15,   152,   172,    10,    43,    11,   117,    14,    16,   200,
      44,    20,    45,    46,    25,    26,    34,    31,    32,    81,
      80,    82,    47,    87,    99,    48,    49,    88,   118,   108,
      83,   104,   107,   112,   141,   155,   163,   164,    50,    51,
      52,   166,   171,   119,   173,   120,   121,    54,   165,   174,
     197,   104,   170,   188,   175,   121,    33,    55,   176,   178,
     191,   192,   194,   195,    78,   134,    79,   198,   196,   199,
     186,   106,   182,   177,   193,     0,     0,     0,   184
};

static const short int yycheck[] =
{
      98,    53,     9,    10,    11,    23,    40,    14,    53,    53,
       6,    27,    20,     0,    86,    86,    91,    84,    25,    92,
      95,    94,    38,    95,    95,    92,    33,    34,     7,    36,
      18,    19,    85,    86,    91,    23,    43,    89,    95,    91,
      86,    21,    49,    91,    51,    52,    54,    95,    27,    94,
      94,   103,    86,    90,    61,    92,   108,    64,    65,    38,
       9,    10,    11,   161,    60,    14,    85,    86,   166,    91,
      77,    78,    79,    95,    92,   173,    25,    84,    31,    86,
      76,    70,    91,    29,    33,    34,    95,    36,    86,    96,
      84,    89,   144,    70,    43,    70,    49,    39,     8,   197,
      49,    86,    51,    52,    24,    86,    32,    91,    90,    67,
      86,    94,    61,    37,    92,    64,    65,    67,    71,    86,
      94,    94,    94,    86,    89,    86,    92,    91,    77,    78,
      79,    83,    12,    86,    12,    88,    89,    86,    95,    93,
      12,    94,    97,    94,    92,    89,    22,    96,    95,    92,
      89,    89,    93,    93,    28,    85,    31,    93,    95,    93,
     164,    80,   159,   154,   179,    -1,    -1,    -1,   163
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,    86,    99,    21,     0,     7,    27,    38,   100,    70,
      70,    70,    29,   101,    39,    84,     8,    40,   102,   103,
      86,   104,   105,   106,   109,    24,    86,   107,   108,   110,
     142,    91,    90,   106,    32,     9,    10,    11,    14,    25,
      33,    34,    36,    43,    49,    51,    52,    61,    64,    65,
      77,    78,    79,    84,    86,    96,   111,   112,   113,   115,
     118,   120,   121,   122,   123,   124,   125,   126,   127,   128,
     129,   130,   131,   132,   138,   139,   143,   144,   107,   109,
      86,    67,    94,    94,    92,    94,   114,    37,    67,    53,
      94,    53,    94,   111,     6,    60,    76,   140,    84,    92,
     133,    27,    38,   141,    94,   150,   151,    94,    86,   145,
     146,   147,    86,   116,   117,   119,    31,    49,    71,    86,
      88,    89,   151,   154,   155,   156,   157,   158,   159,   160,
     161,   162,   163,   164,   116,   111,    95,   145,   111,    95,
     145,    89,   154,    18,    19,    23,   134,   135,   136,   137,
     111,    86,    89,   152,   153,    86,   148,   149,   111,    91,
      95,    20,    54,    92,    91,    95,    83,    95,    95,    95,
      97,    12,   111,    12,    93,    92,    95,   152,    92,    91,
      95,    85,   147,   154,   162,    85,   117,   154,    94,    23,
     154,    89,    89,   149,    93,    93,    95,    12,    93,    93,
     154
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (0)


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (N)								\
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (0)
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
              (Loc).first_line, (Loc).first_column,	\
              (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)		\
do {								\
  if (yydebug)							\
    {								\
      YYFPRINTF (stderr, "%s ", Title);				\
      yysymprint (stderr,					\
                  Type, Value);	\
      YYFPRINTF (stderr, "\n");					\
    }								\
} while (0)

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_stack_print (short int *bottom, short int *top)
#else
static void
yy_stack_print (bottom, top)
    short int *bottom;
    short int *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (/* Nothing. */; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_reduce_print (int yyrule)
#else
static void
yy_reduce_print (yyrule)
    int yyrule;
#endif
{
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu), ",
             yyrule - 1, yylno);
  /* Print the symbols being reduced, and their result.  */
  for (yyi = yyprhs[yyrule]; 0 <= yyrhs[yyi]; yyi++)
    YYFPRINTF (stderr, "%s ", yytname[yyrhs[yyi]]);
  YYFPRINTF (stderr, "-> %s\n", yytname[yyr1[yyrule]]);
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (Rule);		\
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      size_t yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

#endif /* YYERROR_VERBOSE */



#if YYDEBUG
/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yysymprint (FILE *yyoutput, int yytype, YYSTYPE *yyvaluep)
#else
static void
yysymprint (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);


# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  switch (yytype)
    {
      default:
        break;
    }
  YYFPRINTF (yyoutput, ")");
}

#endif /* ! YYDEBUG */
/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
        break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM);
# else
int yyparse ();
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM)
# else
int yyparse (YYPARSE_PARAM)
  void *YYPARSE_PARAM;
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
  int yystate;
  int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  short int yyssa[YYINITDEPTH];
  short int *yyss = yyssa;
  short int *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp;



#define YYPOPSTACK   (yyvsp--, yyssp--)

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* When reducing, the number of symbols on the RHS of the reduced
     rule.  */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short int *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	short int *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a look-ahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to look-ahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a look-ahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;


  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 233 "parse.y"
    {
			checkundefined();
		}
    break;

  case 4:
#line 240 "parse.y"
    { error_message("implicit tagging is not supported"); }
    break;

  case 5:
#line 242 "parse.y"
    { error_message("automatic tagging is not supported"); }
    break;

  case 7:
#line 247 "parse.y"
    { error_message("no extensibility options supported"); }
    break;

  case 17:
#line 268 "parse.y"
    { 
		    struct string_list *sl;
		    for(sl = (yyvsp[-3].sl); sl != NULL; sl = sl->next) {
			Symbol *s = addsym(sl->string);
			s->stype = Stype;
		    }
		    add_import((yyvsp[-1].name));
		}
    break;

  case 22:
#line 287 "parse.y"
    {
		    (yyval.sl) = emalloc(sizeof(*(yyval.sl)));
		    (yyval.sl)->string = (yyvsp[-2].name);
		    (yyval.sl)->next = (yyvsp[0].sl);
		}
    break;

  case 23:
#line 293 "parse.y"
    {
		    (yyval.sl) = emalloc(sizeof(*(yyval.sl)));
		    (yyval.sl)->string = (yyvsp[0].name);
		    (yyval.sl)->next = NULL;
		}
    break;

  case 24:
#line 301 "parse.y"
    {
		    Symbol *s = addsym ((yyvsp[-2].name));
		    s->stype = Stype;
		    s->type = (yyvsp[0].type);
		    fix_labels(s);
		    generate_type (s);
		}
    break;

  case 42:
#line 332 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_Boolean, 
				     TE_EXPLICIT, new_type(TBoolean));
		}
    break;

  case 43:
#line 339 "parse.y"
    {
			if((yyvsp[-3].value)->type != integervalue || 
			   (yyvsp[-1].value)->type != integervalue)
				error_message("Non-integer value used in range");
			(yyval.range).min = (yyvsp[-3].value)->u.integervalue;
			(yyval.range).max = (yyvsp[-1].value)->u.integervalue;
		}
    break;

  case 44:
#line 349 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_Integer, 
				     TE_EXPLICIT, new_type(TInteger));
		}
    break;

  case 45:
#line 354 "parse.y"
    {
			(yyval.type) = new_type(TInteger);
			(yyval.type)->range = emalloc(sizeof(*(yyval.type)->range));
			*((yyval.type)->range) = (yyvsp[0].range);
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_Integer, TE_EXPLICIT, (yyval.type));
		}
    break;

  case 46:
#line 361 "parse.y"
    {
		  (yyval.type) = new_type(TInteger);
		  (yyval.type)->members = (yyvsp[-1].members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Integer, TE_EXPLICIT, (yyval.type));
		}
    break;

  case 47:
#line 369 "parse.y"
    {
			(yyval.members) = emalloc(sizeof(*(yyval.members)));
			ASN1_TAILQ_INIT((yyval.members));
			ASN1_TAILQ_INSERT_HEAD((yyval.members), (yyvsp[0].member), members);
		}
    break;

  case 48:
#line 375 "parse.y"
    {
			ASN1_TAILQ_INSERT_TAIL((yyvsp[-2].members), (yyvsp[0].member), members);
			(yyval.members) = (yyvsp[-2].members);
		}
    break;

  case 49:
#line 380 "parse.y"
    { (yyval.members) = (yyvsp[-2].members); }
    break;

  case 50:
#line 384 "parse.y"
    {
			(yyval.member) = emalloc(sizeof(*(yyval.member)));
			(yyval.member)->name = (yyvsp[-3].name);
			(yyval.member)->gen_name = estrdup((yyvsp[-3].name));
			output_name ((yyval.member)->gen_name);
			(yyval.member)->val = (yyvsp[-1].constant);
			(yyval.member)->optional = 0;
			(yyval.member)->ellipsis = 0;
			(yyval.member)->type = NULL;
		}
    break;

  case 51:
#line 397 "parse.y"
    {
		  (yyval.type) = new_type(TInteger);
		  (yyval.type)->members = (yyvsp[-1].members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Enumerated, TE_EXPLICIT, (yyval.type));
		}
    break;

  case 53:
#line 408 "parse.y"
    {
		  (yyval.type) = new_type(TBitString);
		  (yyval.type)->members = emalloc(sizeof(*(yyval.type)->members));
		  ASN1_TAILQ_INIT((yyval.type)->members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_BitString, TE_EXPLICIT, (yyval.type));
		}
    break;

  case 54:
#line 415 "parse.y"
    {
		  (yyval.type) = new_type(TBitString);
		  (yyval.type)->members = (yyvsp[-1].members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_BitString, TE_EXPLICIT, (yyval.type));
		}
    break;

  case 55:
#line 423 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_OID, 
				     TE_EXPLICIT, new_type(TOID));
		}
    break;

  case 56:
#line 429 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_OctetString, 
				     TE_EXPLICIT, new_type(TOctetString));
		}
    break;

  case 57:
#line 436 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_Null, 
				     TE_EXPLICIT, new_type(TNull));
		}
    break;

  case 58:
#line 443 "parse.y"
    {
		  (yyval.type) = new_type(TSequence);
		  (yyval.type)->members = (yyvsp[-1].members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Sequence, TE_EXPLICIT, (yyval.type));
		}
    break;

  case 59:
#line 449 "parse.y"
    {
		  (yyval.type) = new_type(TSequence);
		  (yyval.type)->members = NULL;
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Sequence, TE_EXPLICIT, (yyval.type));
		}
    break;

  case 60:
#line 457 "parse.y"
    {
		  (yyval.type) = new_type(TSequenceOf);
		  (yyval.type)->subtype = (yyvsp[0].type);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Sequence, TE_EXPLICIT, (yyval.type));
		}
    break;

  case 61:
#line 465 "parse.y"
    {
		  (yyval.type) = new_type(TSet);
		  (yyval.type)->members = (yyvsp[-1].members);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Set, TE_EXPLICIT, (yyval.type));
		}
    break;

  case 62:
#line 471 "parse.y"
    {
		  (yyval.type) = new_type(TSet);
		  (yyval.type)->members = NULL;
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Set, TE_EXPLICIT, (yyval.type));
		}
    break;

  case 63:
#line 479 "parse.y"
    {
		  (yyval.type) = new_type(TSetOf);
		  (yyval.type)->subtype = (yyvsp[0].type);
		  (yyval.type) = new_tag(ASN1_C_UNIV, UT_Set, TE_EXPLICIT, (yyval.type));
		}
    break;

  case 64:
#line 487 "parse.y"
    {
		  (yyval.type) = new_type(TChoice);
		  (yyval.type)->members = (yyvsp[-1].members);
		}
    break;

  case 67:
#line 498 "parse.y"
    {
		  Symbol *s = addsym((yyvsp[0].name));
		  (yyval.type) = new_type(TType);
		  if(s->stype != Stype && s->stype != SUndefined)
		    error_message ("%s is not a type\n", (yyvsp[0].name));
		  else
		    (yyval.type)->symbol = s;
		}
    break;

  case 68:
#line 509 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_GeneralizedTime, 
				     TE_EXPLICIT, new_type(TGeneralizedTime));
		}
    break;

  case 69:
#line 514 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_UTCTime, 
				     TE_EXPLICIT, new_type(TUTCTime));
		}
    break;

  case 70:
#line 521 "parse.y"
    {
		    /* if (Constraint.type == contentConstrant) {
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
    break;

  case 71:
#line 537 "parse.y"
    {
		    (yyval.constraint_spec) = (yyvsp[-1].constraint_spec);
		}
    break;

  case 75:
#line 550 "parse.y"
    {
		    (yyval.constraint_spec) = new_constraint_spec(CT_CONTENTS);
		    (yyval.constraint_spec)->u.content.type = (yyvsp[0].type);
		    (yyval.constraint_spec)->u.content.encoding = NULL;
		}
    break;

  case 76:
#line 556 "parse.y"
    {
		    if ((yyvsp[0].value)->type != objectidentifiervalue)
			error_message("Non-OID used in ENCODED BY constraint");
		    (yyval.constraint_spec) = new_constraint_spec(CT_CONTENTS);
		    (yyval.constraint_spec)->u.content.type = NULL;
		    (yyval.constraint_spec)->u.content.encoding = (yyvsp[0].value);
		}
    break;

  case 77:
#line 564 "parse.y"
    {
		    if ((yyvsp[0].value)->type != objectidentifiervalue)
			error_message("Non-OID used in ENCODED BY constraint");
		    (yyval.constraint_spec) = new_constraint_spec(CT_CONTENTS);
		    (yyval.constraint_spec)->u.content.type = (yyvsp[-3].type);
		    (yyval.constraint_spec)->u.content.encoding = (yyvsp[0].value);
		}
    break;

  case 78:
#line 574 "parse.y"
    {
		    (yyval.constraint_spec) = new_constraint_spec(CT_USER);
		}
    break;

  case 79:
#line 580 "parse.y"
    {
			(yyval.type) = new_type(TTag);
			(yyval.type)->tag = (yyvsp[-2].tag);
			(yyval.type)->tag.tagenv = (yyvsp[-1].constant);
			if((yyvsp[0].type)->type == TTag && (yyvsp[-1].constant) == TE_IMPLICIT) {
				(yyval.type)->subtype = (yyvsp[0].type)->subtype;
				free((yyvsp[0].type));
			} else
				(yyval.type)->subtype = (yyvsp[0].type);
		}
    break;

  case 80:
#line 593 "parse.y"
    {
			(yyval.tag).tagclass = (yyvsp[-2].constant);
			(yyval.tag).tagvalue = (yyvsp[-1].constant);
			(yyval.tag).tagenv = TE_EXPLICIT;
		}
    break;

  case 81:
#line 601 "parse.y"
    {
			(yyval.constant) = ASN1_C_CONTEXT;
		}
    break;

  case 82:
#line 605 "parse.y"
    {
			(yyval.constant) = ASN1_C_UNIV;
		}
    break;

  case 83:
#line 609 "parse.y"
    {
			(yyval.constant) = ASN1_C_APPL;
		}
    break;

  case 84:
#line 613 "parse.y"
    {
			(yyval.constant) = ASN1_C_PRIVATE;
		}
    break;

  case 85:
#line 619 "parse.y"
    {
			(yyval.constant) = TE_EXPLICIT;
		}
    break;

  case 86:
#line 623 "parse.y"
    {
			(yyval.constant) = TE_EXPLICIT;
		}
    break;

  case 87:
#line 627 "parse.y"
    {
			(yyval.constant) = TE_IMPLICIT;
		}
    break;

  case 88:
#line 634 "parse.y"
    {
			Symbol *s;
			s = addsym ((yyvsp[-3].name));

			s->stype = SValue;
			s->value = (yyvsp[0].value);
			generate_constant (s);
		}
    break;

  case 90:
#line 648 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_GeneralString, 
				     TE_EXPLICIT, new_type(TGeneralString));
		}
    break;

  case 91:
#line 653 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_UTF8String, 
				     TE_EXPLICIT, new_type(TUTF8String));
		}
    break;

  case 92:
#line 658 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_PrintableString, 
				     TE_EXPLICIT, new_type(TPrintableString));
		}
    break;

  case 93:
#line 663 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_IA5String, 
				     TE_EXPLICIT, new_type(TIA5String));
		}
    break;

  case 94:
#line 668 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_BMPString, 
				     TE_EXPLICIT, new_type(TBMPString));
		}
    break;

  case 95:
#line 673 "parse.y"
    {
			(yyval.type) = new_tag(ASN1_C_UNIV, UT_UniversalString, 
				     TE_EXPLICIT, new_type(TUniversalString));
		}
    break;

  case 96:
#line 681 "parse.y"
    {
			(yyval.members) = emalloc(sizeof(*(yyval.members)));
			ASN1_TAILQ_INIT((yyval.members));
			ASN1_TAILQ_INSERT_HEAD((yyval.members), (yyvsp[0].member), members);
		}
    break;

  case 97:
#line 687 "parse.y"
    {
			ASN1_TAILQ_INSERT_TAIL((yyvsp[-2].members), (yyvsp[0].member), members);
			(yyval.members) = (yyvsp[-2].members);
		}
    break;

  case 98:
#line 692 "parse.y"
    {
		        struct member *m = ecalloc(1, sizeof(*m));
			m->name = estrdup("...");
			m->gen_name = estrdup("asn1_ellipsis");
			m->ellipsis = 1;
			ASN1_TAILQ_INSERT_TAIL((yyvsp[-2].members), m, members);
			(yyval.members) = (yyvsp[-2].members);
		}
    break;

  case 99:
#line 703 "parse.y"
    {
		  (yyval.member) = emalloc(sizeof(*(yyval.member)));
		  (yyval.member)->name = (yyvsp[-1].name);
		  (yyval.member)->gen_name = estrdup((yyvsp[-1].name));
		  output_name ((yyval.member)->gen_name);
		  (yyval.member)->type = (yyvsp[0].type);
		  (yyval.member)->ellipsis = 0;
		}
    break;

  case 100:
#line 714 "parse.y"
    {
			(yyval.member) = (yyvsp[0].member);
			(yyval.member)->optional = 0;
			(yyval.member)->defval = NULL;
		}
    break;

  case 101:
#line 720 "parse.y"
    {
			(yyval.member) = (yyvsp[-1].member);
			(yyval.member)->optional = 1;
			(yyval.member)->defval = NULL;
		}
    break;

  case 102:
#line 726 "parse.y"
    {
			(yyval.member) = (yyvsp[-2].member);
			(yyval.member)->optional = 0;
			(yyval.member)->defval = (yyvsp[0].value);
		}
    break;

  case 103:
#line 734 "parse.y"
    {
			(yyval.members) = emalloc(sizeof(*(yyval.members)));
			ASN1_TAILQ_INIT((yyval.members));
			ASN1_TAILQ_INSERT_HEAD((yyval.members), (yyvsp[0].member), members);
		}
    break;

  case 104:
#line 740 "parse.y"
    {
			ASN1_TAILQ_INSERT_TAIL((yyvsp[-2].members), (yyvsp[0].member), members);
			(yyval.members) = (yyvsp[-2].members);
		}
    break;

  case 105:
#line 747 "parse.y"
    {
		  (yyval.member) = emalloc(sizeof(*(yyval.member)));
		  (yyval.member)->name = (yyvsp[-3].name);
		  (yyval.member)->gen_name = estrdup((yyvsp[-3].name));
		  output_name ((yyval.member)->gen_name);
		  (yyval.member)->val = (yyvsp[-1].constant);
		  (yyval.member)->optional = 0;
		  (yyval.member)->ellipsis = 0;
		  (yyval.member)->type = NULL;
		}
    break;

  case 107:
#line 760 "parse.y"
    { (yyval.objid) = NULL; }
    break;

  case 108:
#line 764 "parse.y"
    {
			(yyval.objid) = (yyvsp[-1].objid);
		}
    break;

  case 109:
#line 770 "parse.y"
    {
			(yyval.objid) = NULL;
		}
    break;

  case 110:
#line 774 "parse.y"
    {
		        if ((yyvsp[0].objid)) {
				(yyval.objid) = (yyvsp[0].objid);
				add_oid_to_tail((yyvsp[0].objid), (yyvsp[-1].objid));
			} else {
				(yyval.objid) = (yyvsp[-1].objid);
			}
		}
    break;

  case 111:
#line 785 "parse.y"
    {
			(yyval.objid) = new_objid((yyvsp[-3].name), (yyvsp[-1].constant));
		}
    break;

  case 112:
#line 789 "parse.y"
    {
		    Symbol *s = addsym((yyvsp[0].name));
		    if(s->stype != SValue ||
		       s->value->type != objectidentifiervalue) {
			error_message("%s is not an object identifier\n", 
				      s->name);
			exit(1);
		    }
		    (yyval.objid) = s->value->u.objectidentifiervalue;
		}
    break;

  case 113:
#line 800 "parse.y"
    {
		    (yyval.objid) = new_objid(NULL, (yyvsp[0].constant));
		}
    break;

  case 123:
#line 823 "parse.y"
    {
			Symbol *s = addsym((yyvsp[0].name));
			if(s->stype != SValue)
				error_message ("%s is not a value\n",
						s->name);
			else
				(yyval.value) = s->value;
		}
    break;

  case 124:
#line 834 "parse.y"
    {
			(yyval.value) = emalloc(sizeof(*(yyval.value)));
			(yyval.value)->type = stringvalue;
			(yyval.value)->u.stringvalue = (yyvsp[0].name);
		}
    break;

  case 125:
#line 842 "parse.y"
    {
			(yyval.value) = emalloc(sizeof(*(yyval.value)));
			(yyval.value)->type = booleanvalue;
			(yyval.value)->u.booleanvalue = 0;
		}
    break;

  case 126:
#line 848 "parse.y"
    {
			(yyval.value) = emalloc(sizeof(*(yyval.value)));
			(yyval.value)->type = booleanvalue;
			(yyval.value)->u.booleanvalue = 0;
		}
    break;

  case 127:
#line 856 "parse.y"
    {
			(yyval.value) = emalloc(sizeof(*(yyval.value)));
			(yyval.value)->type = integervalue;
			(yyval.value)->u.integervalue = (yyvsp[0].constant);
		}
    break;

  case 129:
#line 867 "parse.y"
    {
		}
    break;

  case 130:
#line 872 "parse.y"
    {
			(yyval.value) = emalloc(sizeof(*(yyval.value)));
			(yyval.value)->type = objectidentifiervalue;
			(yyval.value)->u.objectidentifiervalue = (yyvsp[0].objid);
		}
    break;


      default: break;
    }

/* Line 1126 of yacc.c.  */
#line 2238 "parse.c"

  yyvsp -= yylen;
  yyssp -= yylen;


  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (YYPACT_NINF < yyn && yyn < YYLAST)
	{
	  int yytype = YYTRANSLATE (yychar);
	  YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
	  YYSIZE_T yysize = yysize0;
	  YYSIZE_T yysize1;
	  int yysize_overflow = 0;
	  char *yymsg = 0;
#	  define YYERROR_VERBOSE_ARGS_MAXIMUM 5
	  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
	  int yyx;

#if 0
	  /* This is so xgettext sees the translatable formats that are
	     constructed on the fly.  */
	  YY_("syntax error, unexpected %s");
	  YY_("syntax error, unexpected %s, expecting %s");
	  YY_("syntax error, unexpected %s, expecting %s or %s");
	  YY_("syntax error, unexpected %s, expecting %s or %s or %s");
	  YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
#endif
	  char *yyfmt;
	  char const *yyf;
	  static char const yyunexpected[] = "syntax error, unexpected %s";
	  static char const yyexpecting[] = ", expecting %s";
	  static char const yyor[] = " or %s";
	  char yyformat[sizeof yyunexpected
			+ sizeof yyexpecting - 1
			+ ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
			   * (sizeof yyor - 1))];
	  char const *yyprefix = yyexpecting;

	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  int yyxbegin = yyn < 0 ? -yyn : 0;

	  /* Stay within bounds of both yycheck and yytname.  */
	  int yychecklim = YYLAST - yyn;
	  int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
	  int yycount = 1;

	  yyarg[0] = yytname[yytype];
	  yyfmt = yystpcpy (yyformat, yyunexpected);

	  for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	      {
		if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
		  {
		    yycount = 1;
		    yysize = yysize0;
		    yyformat[sizeof yyunexpected - 1] = '\0';
		    break;
		  }
		yyarg[yycount++] = yytname[yyx];
		yysize1 = yysize + yytnamerr (0, yytname[yyx]);
		yysize_overflow |= yysize1 < yysize;
		yysize = yysize1;
		yyfmt = yystpcpy (yyfmt, yyprefix);
		yyprefix = yyor;
	      }

	  yyf = YY_(yyformat);
	  yysize1 = yysize + yystrlen (yyf);
	  yysize_overflow |= yysize1 < yysize;
	  yysize = yysize1;

	  if (!yysize_overflow && yysize <= YYSTACK_ALLOC_MAXIMUM)
	    yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg)
	    {
	      /* Avoid sprintf, as that infringes on the user's name space.
		 Don't have undefined behavior even if the translation
		 produced a string with the wrong number of "%s"s.  */
	      char *yyp = yymsg;
	      int yyi = 0;
	      while ((*yyp = *yyf))
		{
		  if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		    {
		      yyp += yytnamerr (yyp, yyarg[yyi++]);
		      yyf += 2;
		    }
		  else
		    {
		      yyp++;
		      yyf++;
		    }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    {
	      yyerror (YY_("syntax error"));
	      goto yyexhaustedlab;
	    }
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror (YY_("syntax error"));
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
        {
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
        }
      else
	{
	  yydestruct ("Error: discarding", yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse look-ahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (0)
     goto yyerrorlab;

yyvsp -= yylen;
  yyssp -= yylen;
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping", yystos[yystate], yyvsp);
      YYPOPSTACK;
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;


  /* Shift the error token. */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK;
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}


#line 879 "parse.y"


void
yyerror (const char *s)
{
     error_message ("%s\n", s);
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
    ASN1_TAILQ_FOREACH(m, members, members) {
	asprintf(&m->label, "%s_%s", prefix, m->gen_name);
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
    char *p;
    asprintf(&p, "choice_%s", s->gen_name);
    if (p == NULL)
	errx(1, "malloc");
    fix_labels2(s->type, p);
    free(p);
}

