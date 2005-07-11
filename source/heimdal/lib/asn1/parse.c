/* A Bison parser, made by GNU Bison 1.875d.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004 Free Software Foundation, Inc.

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
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

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
     INTEGER = 258,
     SEQUENCE = 259,
     CHOICE = 260,
     OF = 261,
     OCTET = 262,
     STRING = 263,
     GeneralizedTime = 264,
     GeneralString = 265,
     BIT = 266,
     APPLICATION = 267,
     OPTIONAL = 268,
     EEQUAL = 269,
     TBEGIN = 270,
     END = 271,
     DEFINITIONS = 272,
     ENUMERATED = 273,
     UTF8String = 274,
     NULLTYPE = 275,
     EXTERNAL = 276,
     DEFAULT = 277,
     DOTDOT = 278,
     DOTDOTDOT = 279,
     BOOLEAN = 280,
     IMPORTS = 281,
     FROM = 282,
     OBJECT = 283,
     IDENTIFIER = 284,
     IDENT = 285,
     CONSTANT = 286
   };
#endif
#define INTEGER 258
#define SEQUENCE 259
#define CHOICE 260
#define OF 261
#define OCTET 262
#define STRING 263
#define GeneralizedTime 264
#define GeneralString 265
#define BIT 266
#define APPLICATION 267
#define OPTIONAL 268
#define EEQUAL 269
#define TBEGIN 270
#define END 271
#define DEFINITIONS 272
#define ENUMERATED 273
#define UTF8String 274
#define NULLTYPE 275
#define EXTERNAL 276
#define DEFAULT 277
#define DOTDOT 278
#define DOTDOTDOT 279
#define BOOLEAN 280
#define IMPORTS 281
#define FROM 282
#define OBJECT 283
#define IDENTIFIER 284
#define IDENT 285
#define CONSTANT 286




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

RCSID("$Id: parse.y,v 1.23 2004/10/13 17:41:48 lha Exp $");

static Type *new_type (Typetype t);
void yyerror (char *);

static void append (Member *l, Member *r);



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 56 "parse.y"
typedef union YYSTYPE {
  int constant;
  char *name;
  Type *type;
  Member *member;
  char *defval;
} YYSTYPE;
/* Line 191 of yacc.c.  */
#line 166 "$base.c"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 214 of yacc.c.  */
#line 178 "$base.c"

#if ! defined (yyoverflow) || YYERROR_VERBOSE

# ifndef YYFREE
#  define YYFREE free
# endif
# ifndef YYMALLOC
#  define YYMALLOC malloc
# endif

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   define YYSTACK_ALLOC alloca
#  endif
# else
#  if defined (alloca) || defined (_ALLOCA_H)
#   define YYSTACK_ALLOC alloca
#  else
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
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
	  register YYSIZE_T yyi;		\
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
#define YYLAST   107

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  42
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  17
/* YYNRULES -- Number of rules. */
#define YYNRULES  48
/* YYNRULES -- Number of states. */
#define YYNSTATES  100

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   286

#define YYTRANSLATE(YYX) 						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    40,     2,     2,     2,     2,     2,
      34,    35,     2,     2,    32,    41,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    33,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    38,     2,    39,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    36,     2,    37,     2,     2,     2,     2,
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
      25,    26,    27,    28,    29,    30,    31
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned char yyprhs[] =
{
       0,     0,     3,    10,    11,    14,    16,    18,    20,    24,
      26,    32,    36,    41,    43,    50,    55,    58,    63,    66,
      68,    70,    72,    74,    78,    83,    88,    94,    96,   102,
     104,   105,   107,   111,   115,   121,   124,   127,   129,   131,
     134,   139,   140,   142,   146,   150,   155,   157,   160
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const yysigned_char yyrhs[] =
{
      43,     0,    -1,    30,    17,    14,    15,    44,    16,    -1,
      -1,    44,    45,    -1,    47,    -1,    48,    -1,    49,    -1,
      30,    32,    46,    -1,    30,    -1,    26,    46,    27,    30,
      33,    -1,    30,    14,    50,    -1,    30,    50,    14,    58,
      -1,     3,    -1,     3,    34,    58,    23,    58,    35,    -1,
       3,    36,    56,    37,    -1,    28,    29,    -1,    18,    36,
      56,    37,    -1,     7,     8,    -1,    10,    -1,    19,    -1,
      20,    -1,     9,    -1,     4,     6,    50,    -1,     4,    36,
      51,    37,    -1,     5,    36,    51,    37,    -1,    11,     8,
      36,    56,    37,    -1,    30,    -1,    38,    12,    58,    39,
      50,    -1,    25,    -1,    -1,    53,    -1,    51,    32,    24,
      -1,    51,    32,    53,    -1,    30,    38,    58,    39,    50,
      -1,    52,    54,    -1,    52,    55,    -1,    52,    -1,    13,
      -1,    22,    58,    -1,    22,    40,    30,    40,    -1,    -1,
      57,    -1,    56,    32,    24,    -1,    56,    32,    57,    -1,
      30,    34,    58,    35,    -1,    31,    -1,    41,    31,    -1,
      30,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned char yyrline[] =
{
       0,    85,    85,    88,    89,    92,    93,    94,    97,   102,
     109,   113,   122,   131,   132,   140,   145,   146,   151,   152,
     153,   154,   155,   156,   161,   166,   171,   176,   185,   191,
     194,   195,   196,   197,   200,   215,   217,   219,   224,   227,
     229,   233,   234,   235,   236,   239,   252,   253,   254
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "INTEGER", "SEQUENCE", "CHOICE", "OF",
  "OCTET", "STRING", "GeneralizedTime", "GeneralString", "BIT",
  "APPLICATION", "OPTIONAL", "EEQUAL", "TBEGIN", "END", "DEFINITIONS",
  "ENUMERATED", "UTF8String", "NULLTYPE", "EXTERNAL", "DEFAULT", "DOTDOT",
  "DOTDOTDOT", "BOOLEAN", "IMPORTS", "FROM", "OBJECT", "IDENTIFIER",
  "IDENT", "CONSTANT", "','", "';'", "'('", "')'", "'{'", "'}'", "'['",
  "']'", "'\"'", "'-'", "$accept", "envelope", "specification",
  "declaration", "referencenames", "imports_decl", "type_decl",
  "constant_decl", "type", "memberdecls", "memberdeclstart", "memberdecl",
  "optional2", "defvalue", "bitdecls", "bitdecl", "constant", 0
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
     285,   286,    44,    59,    40,    41,   123,   125,    91,    93,
      34,    45
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    42,    43,    44,    44,    45,    45,    45,    46,    46,
      47,    48,    49,    50,    50,    50,    50,    50,    50,    50,
      50,    50,    50,    50,    50,    50,    50,    50,    50,    50,
      51,    51,    51,    51,    52,    53,    53,    53,    54,    55,
      55,    56,    56,    56,    56,    57,    58,    58,    58
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     6,     0,     2,     1,     1,     1,     3,     1,
       5,     3,     4,     1,     6,     4,     2,     4,     2,     1,
       1,     1,     1,     3,     4,     4,     5,     1,     5,     1,
       0,     1,     3,     3,     5,     2,     2,     1,     1,     2,
       4,     0,     1,     3,     3,     4,     1,     2,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       0,     0,     0,     0,     1,     0,     3,     0,     2,     0,
       0,     4,     5,     6,     7,     9,     0,    13,     0,     0,
       0,    22,    19,     0,     0,     0,    20,    21,    29,     0,
      27,     0,     0,     0,     0,     0,    41,     0,    30,    30,
      18,     0,    11,    41,    16,     0,     0,     8,     0,    48,
      46,     0,     0,     0,     0,    42,    23,     0,     0,    37,
      31,     0,    41,     0,     0,    12,    10,    47,     0,     0,
       0,    15,     0,     0,    24,    38,     0,    35,    36,    25,
       0,    17,     0,     0,     0,    43,    44,     0,    32,    33,
       0,    39,    26,    28,    14,    45,     0,     0,    34,    40
};

/* YYDEFGOTO[NTERM-NUM]. */
static const yysigned_char yydefgoto[] =
{
      -1,     2,     7,    11,    16,    12,    13,    14,    32,    58,
      59,    60,    77,    78,    54,    55,    52
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -38
static const yysigned_char yypact[] =
{
     -26,    12,    22,    16,   -38,    32,   -38,     5,   -38,    20,
      -2,   -38,   -38,   -38,   -38,    27,    41,    42,    13,    45,
      69,   -38,   -38,    71,    35,    46,   -38,   -38,   -38,    54,
     -38,    72,    73,    20,    55,    26,    56,    35,    58,    58,
     -38,    53,   -38,    56,   -38,    26,    26,   -38,    57,   -38,
     -38,    60,    70,    61,    -5,   -38,   -38,    59,    11,     2,
     -38,    34,    56,    37,    62,   -38,   -38,   -38,    26,    26,
     -10,   -38,    26,    40,   -38,   -38,    21,   -38,   -38,   -38,
      43,   -38,    35,    63,    64,   -38,   -38,    65,   -38,   -38,
      66,   -38,   -38,   -38,   -38,   -38,    35,    52,   -38,   -38
};

/* YYPGOTO[NTERM-NUM].  */
static const yysigned_char yypgoto[] =
{
     -38,   -38,   -38,   -38,    67,   -38,   -38,   -38,   -24,    68,
     -38,    29,   -38,   -38,   -37,    24,   -35
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const unsigned char yytable[] =
{
      42,    17,    18,    19,     1,    20,    63,    21,    22,    23,
      64,    65,    24,    56,    85,    75,    25,    26,    27,    37,
      53,     8,     4,    28,    76,    80,    29,    70,    30,     3,
       5,     9,    71,    83,    84,    10,    31,    87,    17,    18,
      19,    91,    20,    73,    21,    22,    23,     6,    74,    38,
      15,    49,    50,    25,    26,    27,    49,    50,    93,    33,
      28,    90,    51,    29,    88,    30,    73,    51,    34,    70,
      57,    79,    98,    31,    81,    70,    35,    40,    36,    41,
      92,    39,    43,    44,    45,    48,    53,    46,    57,    62,
      66,    67,    99,    68,    86,    69,    97,    72,    94,    95,
      47,    82,    89,     0,    96,     0,     0,    61
};

static const yysigned_char yycheck[] =
{
      24,     3,     4,     5,    30,     7,    43,     9,    10,    11,
      45,    46,    14,    37,    24,    13,    18,    19,    20,     6,
      30,    16,     0,    25,    22,    62,    28,    32,    30,    17,
      14,    26,    37,    68,    69,    30,    38,    72,     3,     4,
       5,    76,     7,    32,     9,    10,    11,    15,    37,    36,
      30,    30,    31,    18,    19,    20,    30,    31,    82,    32,
      25,    40,    41,    28,    24,    30,    32,    41,    27,    32,
      30,    37,    96,    38,    37,    32,    34,     8,    36,     8,
      37,    36,    36,    29,    12,    30,    30,    14,    30,    36,
      33,    31,    40,    23,    70,    34,    30,    38,    35,    35,
      33,    39,    73,    -1,    39,    -1,    -1,    39
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,    30,    43,    17,     0,    14,    15,    44,    16,    26,
      30,    45,    47,    48,    49,    30,    46,     3,     4,     5,
       7,     9,    10,    11,    14,    18,    19,    20,    25,    28,
      30,    38,    50,    32,    27,    34,    36,     6,    36,    36,
       8,     8,    50,    36,    29,    12,    14,    46,    30,    30,
      31,    41,    58,    30,    56,    57,    50,    30,    51,    52,
      53,    51,    36,    56,    58,    58,    33,    31,    23,    34,
      32,    37,    38,    32,    37,    13,    22,    54,    55,    37,
      56,    37,    39,    58,    58,    24,    57,    58,    24,    53,
      40,    58,    37,    50,    35,    35,    39,    30,    50,    40
};

#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

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
    { 								\
      yyerror ("syntax error: cannot back up");\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)		\
   ((Current).first_line   = (Rhs)[1].first_line,	\
    (Current).first_column = (Rhs)[1].first_column,	\
    (Current).last_line    = (Rhs)[N].last_line,	\
    (Current).last_column  = (Rhs)[N].last_column)
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

# define YYDSYMPRINT(Args)			\
do {						\
  if (yydebug)					\
    yysymprint Args;				\
} while (0)

# define YYDSYMPRINTF(Title, Token, Value, Location)		\
do {								\
  if (yydebug)							\
    {								\
      YYFPRINTF (stderr, "%s ", Title);				\
      yysymprint (stderr, 					\
                  Token, Value);	\
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
  unsigned int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %u), ",
             yyrule - 1, yylno);
  /* Print the symbols being reduced, and their result.  */
  for (yyi = yyprhs[yyrule]; 0 <= yyrhs[yyi]; yyi++)
    YYFPRINTF (stderr, "%s ", yytname [yyrhs[yyi]]);
  YYFPRINTF (stderr, "-> %s\n", yytname [yyr1[yyrule]]);
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
# define YYDSYMPRINT(Args)
# define YYDSYMPRINTF(Title, Token, Value, Location)
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
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if defined (YYMAXDEPTH) && YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

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
  register const char *yys = yystr;

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
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

#endif /* !YYERROR_VERBOSE */



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
    {
      YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
# ifdef YYPRINT
      YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
    }
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

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
yydestruct (int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yytype, yyvaluep)
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

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



/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
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
  
  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
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
  register short int *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;



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
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	short int *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
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
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
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
      YYDSYMPRINTF ("Next token is", yytoken, &yylval, &yylloc);
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

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %s, ", yytname[yytoken]));

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
#line 85 "parse.y"
    {}
    break;

  case 8:
#line 98 "parse.y"
    {
			Symbol *s = addsym(yyvsp[-2].name);
			s->stype = Stype;
		}
    break;

  case 9:
#line 103 "parse.y"
    {
			Symbol *s = addsym(yyvsp[0].name);
			s->stype = Stype;
		}
    break;

  case 10:
#line 110 "parse.y"
    { add_import(yyvsp[-1].name); }
    break;

  case 11:
#line 114 "parse.y"
    {
		  Symbol *s = addsym (yyvsp[-2].name);
		  s->stype = Stype;
		  s->type = yyvsp[0].type;
		  generate_type (s);
		}
    break;

  case 12:
#line 123 "parse.y"
    {
		  Symbol *s = addsym (yyvsp[-3].name);
		  s->stype = SConstant;
		  s->constant = yyvsp[0].constant;
		  generate_constant (s);
		}
    break;

  case 13:
#line 131 "parse.y"
    { yyval.type = new_type(TInteger); }
    break;

  case 14:
#line 132 "parse.y"
    {
		    if(yyvsp[-3].constant != 0)
			error_message("Only 0 supported as low range");
		    if(yyvsp[-1].constant != INT_MIN && yyvsp[-1].constant != UINT_MAX && yyvsp[-1].constant != INT_MAX)
			error_message("Only %u supported as high range",
				      UINT_MAX);
		    yyval.type = new_type(TUInteger);
		}
    break;

  case 15:
#line 141 "parse.y"
    {
			yyval.type = new_type(TInteger);
			yyval.type->members = yyvsp[-1].member;
                }
    break;

  case 16:
#line 145 "parse.y"
    { yyval.type = new_type(TOID); }
    break;

  case 17:
#line 147 "parse.y"
    {
			yyval.type = new_type(TEnumerated);
			yyval.type->members = yyvsp[-1].member;
		}
    break;

  case 18:
#line 151 "parse.y"
    { yyval.type = new_type(TOctetString); }
    break;

  case 19:
#line 152 "parse.y"
    { yyval.type = new_type(TGeneralString); }
    break;

  case 20:
#line 153 "parse.y"
    { yyval.type = new_type(TUTF8String); }
    break;

  case 21:
#line 154 "parse.y"
    { yyval.type = new_type(TNull); }
    break;

  case 22:
#line 155 "parse.y"
    { yyval.type = new_type(TGeneralizedTime); }
    break;

  case 23:
#line 157 "parse.y"
    {
		  yyval.type = new_type(TSequenceOf);
		  yyval.type->subtype = yyvsp[0].type;
		}
    break;

  case 24:
#line 162 "parse.y"
    {
		  yyval.type = new_type(TSequence);
		  yyval.type->members = yyvsp[-1].member;
		}
    break;

  case 25:
#line 167 "parse.y"
    {
		  yyval.type = new_type(TChoice);
		  yyval.type->members = yyvsp[-1].member;
		}
    break;

  case 26:
#line 172 "parse.y"
    {
		  yyval.type = new_type(TBitString);
		  yyval.type->members = yyvsp[-1].member;
		}
    break;

  case 27:
#line 177 "parse.y"
    {
		  Symbol *s = addsym(yyvsp[0].name);
		  yyval.type = new_type(TType);
		  if(s->stype != Stype)
		    error_message ("%s is not a type\n", yyvsp[0].name);
		  else
		    yyval.type->symbol = s;
		}
    break;

  case 28:
#line 186 "parse.y"
    {
		  yyval.type = new_type(TApplication);
		  yyval.type->subtype = yyvsp[0].type;
		  yyval.type->application = yyvsp[-2].constant;
		}
    break;

  case 29:
#line 191 "parse.y"
    { yyval.type = new_type(TBoolean); }
    break;

  case 30:
#line 194 "parse.y"
    { yyval.member = NULL; }
    break;

  case 31:
#line 195 "parse.y"
    { yyval.member = yyvsp[0].member; }
    break;

  case 32:
#line 196 "parse.y"
    { yyval.member = yyvsp[-2].member; }
    break;

  case 33:
#line 197 "parse.y"
    { yyval.member = yyvsp[-2].member; append(yyval.member, yyvsp[0].member); }
    break;

  case 34:
#line 201 "parse.y"
    {
		  yyval.member = malloc(sizeof(*yyval.member));
		  yyval.member->name = yyvsp[-4].name;
		  yyval.member->gen_name = strdup(yyvsp[-4].name);
		  output_name (yyval.member->gen_name);
		  yyval.member->val = yyvsp[-2].constant;
		  yyval.member->optional = 0;
		  yyval.member->defval = NULL;
		  yyval.member->type = yyvsp[0].type;
		  yyval.member->next = yyval.member->prev = yyval.member;
		}
    break;

  case 35:
#line 216 "parse.y"
    { yyvsp[-1].member->optional = yyvsp[0].constant ; yyval.member = yyvsp[-1].member; }
    break;

  case 36:
#line 218 "parse.y"
    { yyvsp[-1].member->defval = yyvsp[0].defval ; yyval.member = yyvsp[-1].member; }
    break;

  case 37:
#line 220 "parse.y"
    { yyval.member = yyvsp[0].member; }
    break;

  case 38:
#line 224 "parse.y"
    { yyval.constant = 1; }
    break;

  case 39:
#line 228 "parse.y"
    { asprintf(&yyval.defval, "%d", yyvsp[0].constant); }
    break;

  case 40:
#line 230 "parse.y"
    { yyval.defval = strdup (yyvsp[-1].name); }
    break;

  case 41:
#line 233 "parse.y"
    { yyval.member = NULL; }
    break;

  case 42:
#line 234 "parse.y"
    { yyval.member = yyvsp[0].member; }
    break;

  case 43:
#line 235 "parse.y"
    { yyval.member = yyvsp[-2].member; }
    break;

  case 44:
#line 236 "parse.y"
    { yyval.member = yyvsp[-2].member; append(yyval.member, yyvsp[0].member); }
    break;

  case 45:
#line 240 "parse.y"
    {
		  yyval.member = malloc(sizeof(*yyval.member));
		  yyval.member->name = yyvsp[-3].name;
		  yyval.member->gen_name = strdup(yyvsp[-3].name);
		  output_name (yyval.member->gen_name);
		  yyval.member->val = yyvsp[-1].constant;
		  yyval.member->optional = 0;
		  yyval.member->type = NULL;
		  yyval.member->prev = yyval.member->next = yyval.member;
		}
    break;

  case 46:
#line 252 "parse.y"
    { yyval.constant = yyvsp[0].constant; }
    break;

  case 47:
#line 253 "parse.y"
    { yyval.constant = -yyvsp[0].constant; }
    break;

  case 48:
#line 254 "parse.y"
    {
				  Symbol *s = addsym(yyvsp[0].name);
				  if(s->stype != SConstant)
				    error_message ("%s is not a constant\n",
						   s->name);
				  else
				    yyval.constant = s->constant;
				}
    break;


    }

/* Line 1010 of yacc.c.  */
#line 1431 "$base.c"

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
	  YYSIZE_T yysize = 0;
	  int yytype = YYTRANSLATE (yychar);
	  const char* yyprefix;
	  char *yymsg;
	  int yyx;

	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  int yyxbegin = yyn < 0 ? -yyn : 0;

	  /* Stay within bounds of both yycheck and yytname.  */
	  int yychecklim = YYLAST - yyn;
	  int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
	  int yycount = 0;

	  yyprefix = ", expecting ";
	  for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	      {
		yysize += yystrlen (yyprefix) + yystrlen (yytname [yyx]);
		yycount += 1;
		if (yycount == 5)
		  {
		    yysize = 0;
		    break;
		  }
	      }
	  yysize += (sizeof ("syntax error, unexpected ")
		     + yystrlen (yytname[yytype]));
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "syntax error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[yytype]);

	      if (yycount < 5)
		{
		  yyprefix = ", expecting ";
		  for (yyx = yyxbegin; yyx < yyxend; ++yyx)
		    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
		      {
			yyp = yystpcpy (yyp, yyprefix);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yyprefix = " or ";
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("syntax error; also virtual memory exhausted");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror ("syntax error");
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* If at end of input, pop the error token,
	     then the rest of the stack, then return failure.  */
	  if (yychar == YYEOF)
	     for (;;)
	       {
		 YYPOPSTACK;
		 if (yyssp == yyss)
		   YYABORT;
		 YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
		 yydestruct (yystos[*yyssp], yyvsp);
	       }
        }
      else
	{
	  YYDSYMPRINTF ("Error: discarding", yytoken, &yylval, &yylloc);
	  yydestruct (yytoken, &yylval);
	  yychar = YYEMPTY;

	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

#ifdef __GNUC__
  /* Pacify GCC when the user code never invokes YYERROR and the label
     yyerrorlab therefore never appears in user code.  */
  if (0)
     goto yyerrorlab;
#endif

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

      YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
      yydestruct (yystos[yystate], yyvsp);
      YYPOPSTACK;
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;


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
/*----------------------------------------------.
| yyoverflowlab -- parser overflow comes here.  |
`----------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}


#line 263 "parse.y"


void
yyerror (char *s)
{
     error_message ("%s\n", s);
}

static Type *
new_type (Typetype tt)
{
  Type *t = malloc(sizeof(*t));
  if (t == NULL) {
      error_message ("out of memory in malloc(%lu)", 
		     (unsigned long)sizeof(*t));
      exit (1);
  }
  t->type = tt;
  t->application = 0;
  t->members = NULL;
  t->subtype = NULL;
  t->symbol  = NULL;
  return t;
}

static void
append (Member *l, Member *r)
{
  l->prev->next = r;
  r->prev = l->prev;
  l->prev = r;
  r->next = l;
}

