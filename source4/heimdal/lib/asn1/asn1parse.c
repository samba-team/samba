#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20101229

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)

#define YYPREFIX "yy"

#define YYPURE 0


#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "symbol.h"
#include "lex.h"
#include "gen_locl.h"
#include "der.h"

RCSID("$Id$");

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

/* Declarations for Bison */
#define YYMALLOC malloc
#define YYFREE   free

#ifdef YYSTYPE
#undef  YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
#endif
#ifndef YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
typedef union {
    int constant;
    struct value *value;
    struct range *range;
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
#endif /* !YYSTYPE_IS_DECLARED */
/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
# ifdef YYPARSE_PARAM_TYPE
#  define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
# else
#  define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
# endif
#else
# define YYPARSE_DECL() yyparse(void)
#endif

/* Parameters sent to lex. */
#ifdef YYLEX_PARAM
# define YYLEX_DECL() yylex(void *YYLEX_PARAM)
# define YYLEX yylex(YYLEX_PARAM)
#else
# define YYLEX_DECL() yylex(void)
# define YYLEX yylex()
#endif

/* Parameters sent to yyerror. */
#define YYERROR_DECL() yyerror(const char *s)
#define YYERROR_CALL(msg) yyerror(msg)

extern int YYPARSE_DECL();

#define kw_ABSENT 257
#define kw_ABSTRACT_SYNTAX 258
#define kw_ALL 259
#define kw_APPLICATION 260
#define kw_AUTOMATIC 261
#define kw_BEGIN 262
#define kw_BIT 263
#define kw_BMPString 264
#define kw_BOOLEAN 265
#define kw_BY 266
#define kw_CHARACTER 267
#define kw_CHOICE 268
#define kw_CLASS 269
#define kw_COMPONENT 270
#define kw_COMPONENTS 271
#define kw_CONSTRAINED 272
#define kw_CONTAINING 273
#define kw_DEFAULT 274
#define kw_DEFINITIONS 275
#define kw_EMBEDDED 276
#define kw_ENCODED 277
#define kw_END 278
#define kw_ENUMERATED 279
#define kw_EXCEPT 280
#define kw_EXPLICIT 281
#define kw_EXPORTS 282
#define kw_EXTENSIBILITY 283
#define kw_EXTERNAL 284
#define kw_FALSE 285
#define kw_FROM 286
#define kw_GeneralString 287
#define kw_GeneralizedTime 288
#define kw_GraphicString 289
#define kw_IA5String 290
#define kw_IDENTIFIER 291
#define kw_IMPLICIT 292
#define kw_IMPLIED 293
#define kw_IMPORTS 294
#define kw_INCLUDES 295
#define kw_INSTANCE 296
#define kw_INTEGER 297
#define kw_INTERSECTION 298
#define kw_ISO646String 299
#define kw_MAX 300
#define kw_MIN 301
#define kw_MINUS_INFINITY 302
#define kw_NULL 303
#define kw_NumericString 304
#define kw_OBJECT 305
#define kw_OCTET 306
#define kw_OF 307
#define kw_OPTIONAL 308
#define kw_ObjectDescriptor 309
#define kw_PATTERN 310
#define kw_PDV 311
#define kw_PLUS_INFINITY 312
#define kw_PRESENT 313
#define kw_PRIVATE 314
#define kw_PrintableString 315
#define kw_REAL 316
#define kw_RELATIVE_OID 317
#define kw_SEQUENCE 318
#define kw_SET 319
#define kw_SIZE 320
#define kw_STRING 321
#define kw_SYNTAX 322
#define kw_T61String 323
#define kw_TAGS 324
#define kw_TRUE 325
#define kw_TYPE_IDENTIFIER 326
#define kw_TeletexString 327
#define kw_UNION 328
#define kw_UNIQUE 329
#define kw_UNIVERSAL 330
#define kw_UTCTime 331
#define kw_UTF8String 332
#define kw_UniversalString 333
#define kw_VideotexString 334
#define kw_VisibleString 335
#define kw_WITH 336
#define RANGE 337
#define EEQUAL 338
#define ELLIPSIS 339
#define IDENTIFIER 340
#define referencename 341
#define STRING 342
#define NUMBER 343
#define YYERRCODE 256
static const short yylhs[] = {                           -1,
    0,   56,   56,   56,   56,   57,   57,   58,   58,   60,
   60,   62,   62,   63,   63,   64,   59,   59,   59,   61,
   61,   65,   65,   50,   50,   66,   14,   14,   14,   15,
   15,   15,   15,   15,   15,   15,   15,   15,   15,   15,
   15,   15,   15,   17,   48,   48,   48,   48,   21,   21,
   21,   43,   43,   43,   38,   20,   41,   16,   16,   32,
   23,   22,   49,   49,   24,   24,   25,   26,   26,   27,
   18,   29,   29,   30,   31,   31,   19,   51,   52,   53,
   53,   54,   54,   54,   55,   28,   35,    2,    2,    2,
    2,    3,    3,    3,   67,   33,   34,   34,   34,   34,
   34,   34,   34,   34,   40,   40,   40,   39,   36,   36,
   36,   42,   42,   37,   47,   47,   44,   45,   45,   46,
   46,   46,    4,    4,    5,    5,    5,    5,    5,   12,
   11,   13,    9,    7,    7,    6,    1,   10,    8,
};
static const short yylen[] = {                            2,
    9,    2,    2,    2,    0,    2,    0,    3,    0,    3,
    0,    1,    0,    1,    2,    4,    3,    2,    0,    1,
    2,    1,    1,    3,    1,    3,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    5,    5,    5,    3,    1,    2,
    4,    1,    3,    3,    4,    4,    1,    2,    5,    2,
    3,    1,    0,    2,    4,    3,    4,    4,    3,    3,
    4,    1,    1,    1,    1,    1,    2,    3,    1,    1,
    1,    2,    3,    5,    4,    3,    4,    0,    1,    1,
    1,    0,    1,    1,    4,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    3,    3,    2,    1,    2,
    3,    1,    3,    4,    1,    0,    3,    0,    2,    4,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,
};
static const short yydefred[] = {                         0,
    0,    0,    0,  115,    0,    0,  122,    0,    0,    0,
    0,  117,  119,    0,    0,    0,    0,    0,    4,    2,
    3,    0,    0,  120,    6,    0,    0,    0,    0,    0,
   18,    0,    0,    1,    0,    0,    0,   17,    0,    0,
    0,   14,    0,    8,    0,   22,   23,   24,    0,   10,
   15,    0,  103,   44,    0,    0,   97,   75,  102,    0,
   62,    0,    0,  100,    0,    0,   98,   76,   99,  104,
  101,    0,   74,    0,    0,   27,   30,   31,   33,   29,
   34,   35,   36,   38,   39,   40,   41,   42,   43,   28,
   72,   73,   37,   32,   96,    0,   21,    0,    0,    0,
    0,    0,    0,   50,   60,    0,    0,    0,    0,    0,
    0,    0,   90,   91,   89,    0,    0,    0,   77,   93,
   94,    0,   16,    0,    0,  105,    0,    0,    0,   52,
    0,    0,  135,    0,  138,  134,  132,  133,  137,  136,
    0,  123,  127,  125,  128,  126,  129,  130,  124,  131,
  139,    0,   61,   64,   66,    0,    0,    0,   69,    0,
    0,   95,    0,    0,    0,    0,   79,   80,   81,    0,
    0,  112,    0,    0,    0,  110,    0,   71,    0,   56,
    0,    0,    0,   48,   51,   65,    0,   68,   87,    0,
    0,    0,   78,    0,    0,   59,  111,  107,  106,    0,
   54,   53,    0,    0,    0,    0,    0,   83,    0,  113,
   55,   47,   46,   45,   85,    0,  114,   84,
};
static const short yydgoto[] = {                          2,
  140,  116,  122,  141,  142,  143,  144,  145,  146,  147,
  148,  149,  150,   75,   76,   77,   78,   79,   80,   81,
   82,   83,   84,   85,   86,   87,   88,   89,   90,   91,
   92,   93,   94,   95,   96,  126,  172,  130,  127,  128,
  131,  173,  132,  151,    8,    9,    5,  104,  109,   39,
  119,  166,  167,  168,  169,   17,   23,   29,   30,   36,
   44,   40,   41,   42,   45,   46,   47,
};
static const short yysindex[] = {                      -295,
  -74,    0, -289,    0, -216,   23,    0,  -61, -289, -221,
 -277,    0,    0, -259, -257, -256, -214,   31,    0,    0,
    0, -220, -264,    0,    0, -187, -206, -232, -201, -213,
    0,   34,   25,    0, -258, -251, -258,    0, -188,   40,
 -258,    0,   63,    0, -251,    0,    0,    0, -239,    0,
    0, -218,    0,    0,  -19,  -17,    0,    0,    0,  -12,
    0, -184, -212,    0, -106, -111,    0,    0,    0,    0,
    0,  112,    0, -228,  -37,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -242,    0,  -74,  -10, -223,
 -215, -116, -215,    0,    0, -198,   87, -105, -179,  112,
 -100,   89,    0,    0,    0, -211,   -4, -225,    0,    0,
    0,  112,    0, -210,  112,    0, -238,  -13,   91,    0,
    9,   92,    0, -202,    0,    0,    0,    0,    0,    0,
  -33,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  -11,    0,    0,    0,   -9,  112,   89,    0,   -7,
   44,    0, -128,  112, -127,   99,    0,    0,    0,   89,
  101,    0,   -2,   89,   -4,    0, -283,    0, -200,    0,
 -278,   -4,   -8,    0,    0,    0,   89,    0,    0,   19,
  -27,   -4,    0, -199, -210,    0,    0,    0,    0,  104,
    0,    0,  105,  106,  107,   24, -115,    0,  109,    0,
    0,    0,    0,    0,    0,   -4,    0,    0,
};
static const short yyrindex[] = {                         0,
 -123,    0,   28,    0,    0, -110,    0,    0,   28, -245,
    0,    0,    0,    0,    0,    0, -183,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -248,    0,    0, -182,
    0,  -41,    0,    0,   97,    0,    0,    0,    0,    0,
   98,    0,    0,    0, -119,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  -30,
    0,    0,    0,    0, -147,    0,    0,    0,    0,    0,
    0,    0,    0, -181,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  169,    0,  -49,  -40,    0,
    0,    0,    0,    0,    0,  -35,    0,    0,    0,    0,
    0, -244,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   -1,    0,    0,    0,
    0,   36,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  -25,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  -20,
    0,    0,    0,  -42,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  -15,    0,    0,    0,
  122,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,
};
static const short yygindex[] = {                         0,
  -14,    0,    0,  -95,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  -31,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   -6,  -29,   -5,    0,  -53,
    0,    0,   61,   22,  158,    0,   70,   65,   64,   16,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  128,    0,    0,  133,    0,    0,    0,
};
#define YYTABLESIZE 509
static const short yytable[] = {                         58,
   58,  108,  118,   58,   63,   63,    3,  184,   63,  116,
   49,  111,  118,   49,  121,   70,  108,   25,   70,  155,
   86,  162,    4,   86,  159,   67,   31,  102,   67,    9,
  177,  113,  181,   26,  177,  175,  177,    5,  120,   14,
  112,  195,  109,   33,    1,   19,  163,  164,    3,  121,
    6,  165,   48,    7,  156,  198,  125,  160,   10,   15,
  201,  129,   11,   12,   19,   18,   20,   21,   22,  176,
   16,   24,   25,   26,   27,   28,   34,   37,  158,  197,
   35,   32,  108,   38,   58,  114,  203,  205,   43,   63,
  170,   19,    5,  174,   49,   26,  208,   49,   50,   70,
   98,  115,   99,  100,   86,  101,  105,   32,  106,   67,
  103,  178,  124,  185,    3,  186,  125,  188,    3,    4,
  218,  107,  196,  109,  129,  187,  102,  157,  118,  171,
  179,  161,  191,  180,  182,  181,  189,  190,  192,  193,
  194,  206,  139,  209,  211,  212,  213,  214,  215,  217,
  216,  116,  118,   74,    7,   13,   12,   11,   20,   63,
   57,   88,   82,  152,  200,  210,   13,  123,  133,  153,
  199,  154,   97,   51,    0,  202,    0,    0,    0,    0,
    0,    0,    0,    0,  134,    0,  135,    0,    0,    0,
    0,    0,    0,    0,    0,  110,    0,    0,    0,    0,
    0,    0,   74,    0,    0,    0,    0,    0,  136,    0,
    0,    0,    0,  107,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  137,    0,  138,  139,    0,    0,  121,
    0,  108,  121,   58,  125,    0,   58,   58,   63,  125,
    0,   63,   63,   49,   25,    0,   49,   49,   70,  207,
    0,   70,   70,   86,    0,    0,   86,   86,   67,   92,
    0,   67,   67,    0,    0,  108,    0,   58,    0,    0,
    0,    0,   63,    0,    0,    0,  133,   49,    0,    0,
  133,    0,   70,    0,    0,    0,    0,   86,    0,    0,
  116,  204,   67,    0,  135,    0,    0,   58,  135,   58,
  117,    0,   63,  183,   63,    0,    0,   49,    0,   49,
    0,    0,   70,    0,   70,    0,  136,   86,    0,   86,
  136,    0,   67,    0,   67,   52,   53,   54,    0,    0,
   55,  137,    0,  138,  139,  137,    0,  138,  139,    0,
    0,   56,    0,    0,    0,    0,    0,    0,    0,   57,
   58,    0,   59,    0,    0,    0,    0,    0,    0,   60,
    0,    0,    0,    0,    0,   61,    0,   62,   63,    0,
    0,    0,    0,    0,   52,   53,   54,   64,    0,   55,
   65,   66,    0,    0,    0,    0,    0,    0,    0,   67,
   56,    0,    0,   68,   69,   70,    0,   71,   57,   58,
   72,   59,   73,    0,    0,    0,    0,    0,   60,    0,
    0,    0,    0,    0,   61,    0,   62,   63,    0,    0,
    0,    0,    0,    0,    0,    0,   64,    0,    0,   65,
   66,   92,   92,   92,    0,    0,   92,    0,   67,    0,
    0,    0,   68,   69,   70,    0,   71,   92,    0,    0,
    0,   73,    0,    0,    0,   92,   92,    0,   92,    0,
    0,    0,    0,    0,    0,   92,    0,    0,    0,    0,
    0,   92,    0,   92,   92,    0,    0,    0,    0,    0,
    0,    0,    0,   92,    0,    0,   92,   92,    0,    0,
    0,    0,    0,    0,    0,   92,    0,    0,    0,   92,
   92,   92,    0,   92,    0,    0,    0,    0,   92,
};
static const short yycheck[] = {                         40,
   41,   44,   40,   44,   40,   41,  123,   41,   44,   59,
   41,  123,   40,   44,  125,   41,  123,   59,   44,  125,
   41,  117,    1,   44,  125,   41,  259,   40,   44,  278,
   44,  260,   44,  278,   44,  274,   44,  283,  281,  261,
   72,   44,   44,   28,  340,  294,  272,  273,  123,  292,
  340,  277,   37,  343,  108,  339,  340,  111,  275,  281,
  339,  340,   40,  125,  324,  343,  324,  324,  283,  308,
  292,   41,  293,  338,  262,  282,  278,   44,  110,  175,
  294,  340,  125,   59,  125,  314,  182,  183,  340,  125,
  122,  340,  338,  125,  125,  340,  192,  286,   59,  125,
  340,  330,  321,  123,  125,  123,  291,  340,  321,  125,
  123,  125,  123,  125,  123,  125,  340,  125,  123,   98,
  216,  320,  125,  125,  340,  157,   40,  307,   40,  340,
   40,  343,  164,  125,  337,   44,   93,  266,  266,   41,
   40,  123,  343,  343,   41,   41,   41,   41,  125,   41,
  266,  275,  125,   91,  338,   59,   59,  340,  278,  307,
  125,  343,   41,  103,  179,  195,    9,   98,  285,  106,
  177,  107,   45,   41,   -1,  181,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  301,   -1,  303,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  307,   -1,   -1,   -1,   -1,
   -1,   -1,   91,   -1,   -1,   -1,   -1,   -1,  325,   -1,
   -1,   -1,   -1,  320,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  340,   -1,  342,  343,   -1,   -1,  340,
   -1,  274,  343,  274,  340,   -1,  277,  278,  274,  340,
   -1,  277,  278,  274,  286,   -1,  277,  278,  274,  277,
   -1,  277,  278,  274,   -1,   -1,  277,  278,  274,   91,
   -1,  277,  278,   -1,   -1,  308,   -1,  308,   -1,   -1,
   -1,   -1,  308,   -1,   -1,   -1,  285,  308,   -1,   -1,
  285,   -1,  308,   -1,   -1,   -1,   -1,  308,   -1,   -1,
  340,  300,  308,   -1,  303,   -1,   -1,  338,  303,  340,
  338,   -1,  338,  337,  340,   -1,   -1,  338,   -1,  340,
   -1,   -1,  338,   -1,  340,   -1,  325,  338,   -1,  340,
  325,   -1,  338,   -1,  340,  263,  264,  265,   -1,   -1,
  268,  340,   -1,  342,  343,  340,   -1,  342,  343,   -1,
   -1,  279,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  287,
  288,   -1,  290,   -1,   -1,   -1,   -1,   -1,   -1,  297,
   -1,   -1,   -1,   -1,   -1,  303,   -1,  305,  306,   -1,
   -1,   -1,   -1,   -1,  263,  264,  265,  315,   -1,  268,
  318,  319,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  327,
  279,   -1,   -1,  331,  332,  333,   -1,  335,  287,  288,
  338,  290,  340,   -1,   -1,   -1,   -1,   -1,  297,   -1,
   -1,   -1,   -1,   -1,  303,   -1,  305,  306,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  315,   -1,   -1,  318,
  319,  263,  264,  265,   -1,   -1,  268,   -1,  327,   -1,
   -1,   -1,  331,  332,  333,   -1,  335,  279,   -1,   -1,
   -1,  340,   -1,   -1,   -1,  287,  288,   -1,  290,   -1,
   -1,   -1,   -1,   -1,   -1,  297,   -1,   -1,   -1,   -1,
   -1,  303,   -1,  305,  306,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  315,   -1,   -1,  318,  319,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  327,   -1,   -1,   -1,  331,
  332,  333,   -1,  335,   -1,   -1,   -1,   -1,  340,
};
#define YYFINAL 2
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 343
#if YYDEBUG
static const char *yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,"'('","')'",0,0,"','",0,0,0,0,0,0,0,0,0,0,0,0,0,0,"';'",0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'['",0,"']'",0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"kw_ABSENT","kw_ABSTRACT_SYNTAX","kw_ALL","kw_APPLICATION","kw_AUTOMATIC",
"kw_BEGIN","kw_BIT","kw_BMPString","kw_BOOLEAN","kw_BY","kw_CHARACTER",
"kw_CHOICE","kw_CLASS","kw_COMPONENT","kw_COMPONENTS","kw_CONSTRAINED",
"kw_CONTAINING","kw_DEFAULT","kw_DEFINITIONS","kw_EMBEDDED","kw_ENCODED",
"kw_END","kw_ENUMERATED","kw_EXCEPT","kw_EXPLICIT","kw_EXPORTS",
"kw_EXTENSIBILITY","kw_EXTERNAL","kw_FALSE","kw_FROM","kw_GeneralString",
"kw_GeneralizedTime","kw_GraphicString","kw_IA5String","kw_IDENTIFIER",
"kw_IMPLICIT","kw_IMPLIED","kw_IMPORTS","kw_INCLUDES","kw_INSTANCE",
"kw_INTEGER","kw_INTERSECTION","kw_ISO646String","kw_MAX","kw_MIN",
"kw_MINUS_INFINITY","kw_NULL","kw_NumericString","kw_OBJECT","kw_OCTET","kw_OF",
"kw_OPTIONAL","kw_ObjectDescriptor","kw_PATTERN","kw_PDV","kw_PLUS_INFINITY",
"kw_PRESENT","kw_PRIVATE","kw_PrintableString","kw_REAL","kw_RELATIVE_OID",
"kw_SEQUENCE","kw_SET","kw_SIZE","kw_STRING","kw_SYNTAX","kw_T61String",
"kw_TAGS","kw_TRUE","kw_TYPE_IDENTIFIER","kw_TeletexString","kw_UNION",
"kw_UNIQUE","kw_UNIVERSAL","kw_UTCTime","kw_UTF8String","kw_UniversalString",
"kw_VideotexString","kw_VisibleString","kw_WITH","RANGE","EEQUAL","ELLIPSIS",
"IDENTIFIER","referencename","STRING","NUMBER",
};
static const char *yyrule[] = {
"$accept : ModuleDefinition",
"ModuleDefinition : IDENTIFIER objid_opt kw_DEFINITIONS TagDefault ExtensionDefault EEQUAL kw_BEGIN ModuleBody kw_END",
"TagDefault : kw_EXPLICIT kw_TAGS",
"TagDefault : kw_IMPLICIT kw_TAGS",
"TagDefault : kw_AUTOMATIC kw_TAGS",
"TagDefault :",
"ExtensionDefault : kw_EXTENSIBILITY kw_IMPLIED",
"ExtensionDefault :",
"ModuleBody : Exports Imports AssignmentList",
"ModuleBody :",
"Imports : kw_IMPORTS SymbolsImported ';'",
"Imports :",
"SymbolsImported : SymbolsFromModuleList",
"SymbolsImported :",
"SymbolsFromModuleList : SymbolsFromModule",
"SymbolsFromModuleList : SymbolsFromModuleList SymbolsFromModule",
"SymbolsFromModule : referencenames kw_FROM IDENTIFIER objid_opt",
"Exports : kw_EXPORTS referencenames ';'",
"Exports : kw_EXPORTS kw_ALL",
"Exports :",
"AssignmentList : Assignment",
"AssignmentList : Assignment AssignmentList",
"Assignment : TypeAssignment",
"Assignment : ValueAssignment",
"referencenames : IDENTIFIER ',' referencenames",
"referencenames : IDENTIFIER",
"TypeAssignment : IDENTIFIER EEQUAL Type",
"Type : BuiltinType",
"Type : ReferencedType",
"Type : ConstrainedType",
"BuiltinType : BitStringType",
"BuiltinType : BooleanType",
"BuiltinType : CharacterStringType",
"BuiltinType : ChoiceType",
"BuiltinType : EnumeratedType",
"BuiltinType : IntegerType",
"BuiltinType : NullType",
"BuiltinType : ObjectIdentifierType",
"BuiltinType : OctetStringType",
"BuiltinType : SequenceType",
"BuiltinType : SequenceOfType",
"BuiltinType : SetType",
"BuiltinType : SetOfType",
"BuiltinType : TaggedType",
"BooleanType : kw_BOOLEAN",
"range : '(' Value RANGE Value ')'",
"range : '(' Value RANGE kw_MAX ')'",
"range : '(' kw_MIN RANGE Value ')'",
"range : '(' Value ')'",
"IntegerType : kw_INTEGER",
"IntegerType : kw_INTEGER range",
"IntegerType : kw_INTEGER '{' NamedNumberList '}'",
"NamedNumberList : NamedNumber",
"NamedNumberList : NamedNumberList ',' NamedNumber",
"NamedNumberList : NamedNumberList ',' ELLIPSIS",
"NamedNumber : IDENTIFIER '(' SignedNumber ')'",
"EnumeratedType : kw_ENUMERATED '{' Enumerations '}'",
"Enumerations : NamedNumberList",
"BitStringType : kw_BIT kw_STRING",
"BitStringType : kw_BIT kw_STRING '{' NamedBitList '}'",
"ObjectIdentifierType : kw_OBJECT kw_IDENTIFIER",
"OctetStringType : kw_OCTET kw_STRING size",
"NullType : kw_NULL",
"size :",
"size : kw_SIZE range",
"SequenceType : kw_SEQUENCE '{' ComponentTypeList '}'",
"SequenceType : kw_SEQUENCE '{' '}'",
"SequenceOfType : kw_SEQUENCE size kw_OF Type",
"SetType : kw_SET '{' ComponentTypeList '}'",
"SetType : kw_SET '{' '}'",
"SetOfType : kw_SET kw_OF Type",
"ChoiceType : kw_CHOICE '{' ComponentTypeList '}'",
"ReferencedType : DefinedType",
"ReferencedType : UsefulType",
"DefinedType : IDENTIFIER",
"UsefulType : kw_GeneralizedTime",
"UsefulType : kw_UTCTime",
"ConstrainedType : Type Constraint",
"Constraint : '(' ConstraintSpec ')'",
"ConstraintSpec : GeneralConstraint",
"GeneralConstraint : ContentsConstraint",
"GeneralConstraint : UserDefinedConstraint",
"ContentsConstraint : kw_CONTAINING Type",
"ContentsConstraint : kw_ENCODED kw_BY Value",
"ContentsConstraint : kw_CONTAINING Type kw_ENCODED kw_BY Value",
"UserDefinedConstraint : kw_CONSTRAINED kw_BY '{' '}'",
"TaggedType : Tag tagenv Type",
"Tag : '[' Class NUMBER ']'",
"Class :",
"Class : kw_UNIVERSAL",
"Class : kw_APPLICATION",
"Class : kw_PRIVATE",
"tagenv :",
"tagenv : kw_EXPLICIT",
"tagenv : kw_IMPLICIT",
"ValueAssignment : IDENTIFIER Type EEQUAL Value",
"CharacterStringType : RestrictedCharactedStringType",
"RestrictedCharactedStringType : kw_GeneralString",
"RestrictedCharactedStringType : kw_TeletexString",
"RestrictedCharactedStringType : kw_UTF8String",
"RestrictedCharactedStringType : kw_PrintableString",
"RestrictedCharactedStringType : kw_VisibleString",
"RestrictedCharactedStringType : kw_IA5String",
"RestrictedCharactedStringType : kw_BMPString",
"RestrictedCharactedStringType : kw_UniversalString",
"ComponentTypeList : ComponentType",
"ComponentTypeList : ComponentTypeList ',' ComponentType",
"ComponentTypeList : ComponentTypeList ',' ELLIPSIS",
"NamedType : IDENTIFIER Type",
"ComponentType : NamedType",
"ComponentType : NamedType kw_OPTIONAL",
"ComponentType : NamedType kw_DEFAULT Value",
"NamedBitList : NamedBit",
"NamedBitList : NamedBitList ',' NamedBit",
"NamedBit : IDENTIFIER '(' NUMBER ')'",
"objid_opt : objid",
"objid_opt :",
"objid : '{' objid_list '}'",
"objid_list :",
"objid_list : objid_element objid_list",
"objid_element : IDENTIFIER '(' NUMBER ')'",
"objid_element : IDENTIFIER",
"objid_element : NUMBER",
"Value : BuiltinValue",
"Value : ReferencedValue",
"BuiltinValue : BooleanValue",
"BuiltinValue : CharacterStringValue",
"BuiltinValue : IntegerValue",
"BuiltinValue : ObjectIdentifierValue",
"BuiltinValue : NullValue",
"ReferencedValue : DefinedValue",
"DefinedValue : Valuereference",
"Valuereference : IDENTIFIER",
"CharacterStringValue : STRING",
"BooleanValue : kw_TRUE",
"BooleanValue : kw_FALSE",
"IntegerValue : SignedNumber",
"SignedNumber : NUMBER",
"NullValue : kw_NULL",
"ObjectIdentifierValue : objid",

};
#endif
/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 500
#define YYMAXDEPTH  500
#endif
#endif

#define YYINITSTACKSIZE 500

int      yydebug;
int      yynerrs;

typedef struct {
    unsigned stacksize;
    short    *s_base;
    short    *s_mark;
    short    *s_last;
    YYSTYPE  *l_base;
    YYSTYPE  *l_mark;
} YYSTACKDATA;
int      yyerrflag;
int      yychar;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* variables for the parser stack */
static YYSTACKDATA yystack;

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
    fix_labels2(s->type, p);
    free(p);
}

#if YYDEBUG
#include <stdio.h>		/* needed for printf */
#endif

#include <stdlib.h>	/* needed for malloc, etc */
#include <string.h>	/* needed for memset */

/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(YYSTACKDATA *data)
{
    int i;
    unsigned newsize;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = data->stacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = data->s_mark - data->s_base;
    newss = (short *)realloc(data->s_base, newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    data->s_base = newss;
    data->s_mark = newss + i;

    newvs = (YYSTYPE *)realloc(data->l_base, newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    data->l_base = newvs;
    data->l_mark = newvs + i;

    data->stacksize = newsize;
    data->s_last = data->s_base + newsize - 1;
    return 0;
}

#if YYPURE || defined(YY_NO_LEAKS)
static void yyfreestack(YYSTACKDATA *data)
{
    free(data->s_base);
    free(data->l_base);
    memset(data, 0, sizeof(*data));
}
#else
#define yyfreestack(data) /* nothing */
#endif

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

#if YYPURE
    memset(&yystack, 0, sizeof(yystack));
#endif

    if (yystack.s_base == NULL && yygrowstack(&yystack)) goto yyoverflow;
    yystack.s_mark = yystack.s_base;
    yystack.l_mark = yystack.l_base;
    yystate = 0;
    *yystack.s_mark = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
        {
            goto yyoverflow;
        }
        yystate = yytable[yyn];
        *++yystack.s_mark = yytable[yyn];
        *++yystack.l_mark = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;

    yyerror("syntax error");

    goto yyerrlab;

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yystack.s_mark]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yystack.s_mark, yytable[yyn]);
#endif
                if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
                {
                    goto yyoverflow;
                }
                yystate = yytable[yyn];
                *++yystack.s_mark = yytable[yyn];
                *++yystack.l_mark = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yystack.s_mark);
#endif
                if (yystack.s_mark <= yystack.s_base) goto yyabort;
                --yystack.s_mark;
                --yystack.l_mark;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yystack.l_mark[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 1:
	{
			checkundefined();
		}
break;
case 3:
	{ lex_error_message("implicit tagging is not supported"); }
break;
case 4:
	{ lex_error_message("automatic tagging is not supported"); }
break;
case 6:
	{ lex_error_message("no extensibility options supported"); }
break;
case 16:
	{
		    struct string_list *sl;
		    for(sl = yystack.l_mark[-3].sl; sl != NULL; sl = sl->next) {
			Symbol *s = addsym(sl->string);
			s->stype = Stype;
			gen_template_import(s);
		    }
		    add_import(yystack.l_mark[-1].name);
		}
break;
case 17:
	{
		    struct string_list *sl;
		    for(sl = yystack.l_mark[-1].sl; sl != NULL; sl = sl->next)
			add_export(sl->string);
		}
break;
case 24:
	{
		    yyval.sl = emalloc(sizeof(*yyval.sl));
		    yyval.sl->string = yystack.l_mark[-2].name;
		    yyval.sl->next = yystack.l_mark[0].sl;
		}
break;
case 25:
	{
		    yyval.sl = emalloc(sizeof(*yyval.sl));
		    yyval.sl->string = yystack.l_mark[0].name;
		    yyval.sl->next = NULL;
		}
break;
case 26:
	{
		    Symbol *s = addsym (yystack.l_mark[-2].name);
		    s->stype = Stype;
		    s->type = yystack.l_mark[0].type;
		    fix_labels(s);
		    generate_type (s);
		}
break;
case 44:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_Boolean,
				     TE_EXPLICIT, new_type(TBoolean));
		}
break;
case 45:
	{
		    if(yystack.l_mark[-3].value->type != integervalue)
			lex_error_message("Non-integer used in first part of range");
		    if(yystack.l_mark[-3].value->type != integervalue)
			lex_error_message("Non-integer in second part of range");
		    yyval.range = ecalloc(1, sizeof(*yyval.range));
		    yyval.range->min = yystack.l_mark[-3].value->u.integervalue;
		    yyval.range->max = yystack.l_mark[-1].value->u.integervalue;
		}
break;
case 46:
	{
		    if(yystack.l_mark[-3].value->type != integervalue)
			lex_error_message("Non-integer in first part of range");
		    yyval.range = ecalloc(1, sizeof(*yyval.range));
		    yyval.range->min = yystack.l_mark[-3].value->u.integervalue;
		    yyval.range->max = yystack.l_mark[-3].value->u.integervalue - 1;
		}
break;
case 47:
	{
		    if(yystack.l_mark[-1].value->type != integervalue)
			lex_error_message("Non-integer in second part of range");
		    yyval.range = ecalloc(1, sizeof(*yyval.range));
		    yyval.range->min = yystack.l_mark[-1].value->u.integervalue + 2;
		    yyval.range->max = yystack.l_mark[-1].value->u.integervalue;
		}
break;
case 48:
	{
		    if(yystack.l_mark[-1].value->type != integervalue)
			lex_error_message("Non-integer used in limit");
		    yyval.range = ecalloc(1, sizeof(*yyval.range));
		    yyval.range->min = yystack.l_mark[-1].value->u.integervalue;
		    yyval.range->max = yystack.l_mark[-1].value->u.integervalue;
		}
break;
case 49:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_Integer,
				     TE_EXPLICIT, new_type(TInteger));
		}
break;
case 50:
	{
			yyval.type = new_type(TInteger);
			yyval.type->range = yystack.l_mark[0].range;
			yyval.type = new_tag(ASN1_C_UNIV, UT_Integer, TE_EXPLICIT, yyval.type);
		}
break;
case 51:
	{
		  yyval.type = new_type(TInteger);
		  yyval.type->members = yystack.l_mark[-1].members;
		  yyval.type = new_tag(ASN1_C_UNIV, UT_Integer, TE_EXPLICIT, yyval.type);
		}
break;
case 52:
	{
			yyval.members = emalloc(sizeof(*yyval.members));
			ASN1_TAILQ_INIT(yyval.members);
			ASN1_TAILQ_INSERT_HEAD(yyval.members, yystack.l_mark[0].member, members);
		}
break;
case 53:
	{
			ASN1_TAILQ_INSERT_TAIL(yystack.l_mark[-2].members, yystack.l_mark[0].member, members);
			yyval.members = yystack.l_mark[-2].members;
		}
break;
case 54:
	{ yyval.members = yystack.l_mark[-2].members; }
break;
case 55:
	{
			yyval.member = emalloc(sizeof(*yyval.member));
			yyval.member->name = yystack.l_mark[-3].name;
			yyval.member->gen_name = estrdup(yystack.l_mark[-3].name);
			output_name (yyval.member->gen_name);
			yyval.member->val = yystack.l_mark[-1].constant;
			yyval.member->optional = 0;
			yyval.member->ellipsis = 0;
			yyval.member->type = NULL;
		}
break;
case 56:
	{
		  yyval.type = new_type(TInteger);
		  yyval.type->members = yystack.l_mark[-1].members;
		  yyval.type = new_tag(ASN1_C_UNIV, UT_Enumerated, TE_EXPLICIT, yyval.type);
		}
break;
case 58:
	{
		  yyval.type = new_type(TBitString);
		  yyval.type->members = emalloc(sizeof(*yyval.type->members));
		  ASN1_TAILQ_INIT(yyval.type->members);
		  yyval.type = new_tag(ASN1_C_UNIV, UT_BitString, TE_EXPLICIT, yyval.type);
		}
break;
case 59:
	{
		  yyval.type = new_type(TBitString);
		  yyval.type->members = yystack.l_mark[-1].members;
		  yyval.type = new_tag(ASN1_C_UNIV, UT_BitString, TE_EXPLICIT, yyval.type);
		}
break;
case 60:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_OID,
				     TE_EXPLICIT, new_type(TOID));
		}
break;
case 61:
	{
		    Type *t = new_type(TOctetString);
		    t->range = yystack.l_mark[0].range;
		    yyval.type = new_tag(ASN1_C_UNIV, UT_OctetString,
				 TE_EXPLICIT, t);
		}
break;
case 62:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_Null,
				     TE_EXPLICIT, new_type(TNull));
		}
break;
case 63:
	{ yyval.range = NULL; }
break;
case 64:
	{ yyval.range = yystack.l_mark[0].range; }
break;
case 65:
	{
		  yyval.type = new_type(TSequence);
		  yyval.type->members = yystack.l_mark[-1].members;
		  yyval.type = new_tag(ASN1_C_UNIV, UT_Sequence, TE_EXPLICIT, yyval.type);
		}
break;
case 66:
	{
		  yyval.type = new_type(TSequence);
		  yyval.type->members = NULL;
		  yyval.type = new_tag(ASN1_C_UNIV, UT_Sequence, TE_EXPLICIT, yyval.type);
		}
break;
case 67:
	{
		  yyval.type = new_type(TSequenceOf);
		  yyval.type->range = yystack.l_mark[-2].range;
		  yyval.type->subtype = yystack.l_mark[0].type;
		  yyval.type = new_tag(ASN1_C_UNIV, UT_Sequence, TE_EXPLICIT, yyval.type);
		}
break;
case 68:
	{
		  yyval.type = new_type(TSet);
		  yyval.type->members = yystack.l_mark[-1].members;
		  yyval.type = new_tag(ASN1_C_UNIV, UT_Set, TE_EXPLICIT, yyval.type);
		}
break;
case 69:
	{
		  yyval.type = new_type(TSet);
		  yyval.type->members = NULL;
		  yyval.type = new_tag(ASN1_C_UNIV, UT_Set, TE_EXPLICIT, yyval.type);
		}
break;
case 70:
	{
		  yyval.type = new_type(TSetOf);
		  yyval.type->subtype = yystack.l_mark[0].type;
		  yyval.type = new_tag(ASN1_C_UNIV, UT_Set, TE_EXPLICIT, yyval.type);
		}
break;
case 71:
	{
		  yyval.type = new_type(TChoice);
		  yyval.type->members = yystack.l_mark[-1].members;
		}
break;
case 74:
	{
		  Symbol *s = addsym(yystack.l_mark[0].name);
		  yyval.type = new_type(TType);
		  if(s->stype != Stype && s->stype != SUndefined)
		    lex_error_message ("%s is not a type\n", yystack.l_mark[0].name);
		  else
		    yyval.type->symbol = s;
		}
break;
case 75:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_GeneralizedTime,
				     TE_EXPLICIT, new_type(TGeneralizedTime));
		}
break;
case 76:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_UTCTime,
				     TE_EXPLICIT, new_type(TUTCTime));
		}
break;
case 77:
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
case 78:
	{
		    yyval.constraint_spec = yystack.l_mark[-1].constraint_spec;
		}
break;
case 82:
	{
		    yyval.constraint_spec = new_constraint_spec(CT_CONTENTS);
		    yyval.constraint_spec->u.content.type = yystack.l_mark[0].type;
		    yyval.constraint_spec->u.content.encoding = NULL;
		}
break;
case 83:
	{
		    if (yystack.l_mark[0].value->type != objectidentifiervalue)
			lex_error_message("Non-OID used in ENCODED BY constraint");
		    yyval.constraint_spec = new_constraint_spec(CT_CONTENTS);
		    yyval.constraint_spec->u.content.type = NULL;
		    yyval.constraint_spec->u.content.encoding = yystack.l_mark[0].value;
		}
break;
case 84:
	{
		    if (yystack.l_mark[0].value->type != objectidentifiervalue)
			lex_error_message("Non-OID used in ENCODED BY constraint");
		    yyval.constraint_spec = new_constraint_spec(CT_CONTENTS);
		    yyval.constraint_spec->u.content.type = yystack.l_mark[-3].type;
		    yyval.constraint_spec->u.content.encoding = yystack.l_mark[0].value;
		}
break;
case 85:
	{
		    yyval.constraint_spec = new_constraint_spec(CT_USER);
		}
break;
case 86:
	{
			yyval.type = new_type(TTag);
			yyval.type->tag = yystack.l_mark[-2].tag;
			yyval.type->tag.tagenv = yystack.l_mark[-1].constant;
			if(yystack.l_mark[0].type->type == TTag && yystack.l_mark[-1].constant == TE_IMPLICIT) {
				yyval.type->subtype = yystack.l_mark[0].type->subtype;
				free(yystack.l_mark[0].type);
			} else
				yyval.type->subtype = yystack.l_mark[0].type;
		}
break;
case 87:
	{
			yyval.tag.tagclass = yystack.l_mark[-2].constant;
			yyval.tag.tagvalue = yystack.l_mark[-1].constant;
			yyval.tag.tagenv = TE_EXPLICIT;
		}
break;
case 88:
	{
			yyval.constant = ASN1_C_CONTEXT;
		}
break;
case 89:
	{
			yyval.constant = ASN1_C_UNIV;
		}
break;
case 90:
	{
			yyval.constant = ASN1_C_APPL;
		}
break;
case 91:
	{
			yyval.constant = ASN1_C_PRIVATE;
		}
break;
case 92:
	{
			yyval.constant = TE_EXPLICIT;
		}
break;
case 93:
	{
			yyval.constant = TE_EXPLICIT;
		}
break;
case 94:
	{
			yyval.constant = TE_IMPLICIT;
		}
break;
case 95:
	{
			Symbol *s;
			s = addsym (yystack.l_mark[-3].name);

			s->stype = SValue;
			s->value = yystack.l_mark[0].value;
			generate_constant (s);
		}
break;
case 97:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_GeneralString,
				     TE_EXPLICIT, new_type(TGeneralString));
		}
break;
case 98:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_TeletexString,
				     TE_EXPLICIT, new_type(TTeletexString));
		}
break;
case 99:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_UTF8String,
				     TE_EXPLICIT, new_type(TUTF8String));
		}
break;
case 100:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_PrintableString,
				     TE_EXPLICIT, new_type(TPrintableString));
		}
break;
case 101:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_VisibleString,
				     TE_EXPLICIT, new_type(TVisibleString));
		}
break;
case 102:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_IA5String,
				     TE_EXPLICIT, new_type(TIA5String));
		}
break;
case 103:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_BMPString,
				     TE_EXPLICIT, new_type(TBMPString));
		}
break;
case 104:
	{
			yyval.type = new_tag(ASN1_C_UNIV, UT_UniversalString,
				     TE_EXPLICIT, new_type(TUniversalString));
		}
break;
case 105:
	{
			yyval.members = emalloc(sizeof(*yyval.members));
			ASN1_TAILQ_INIT(yyval.members);
			ASN1_TAILQ_INSERT_HEAD(yyval.members, yystack.l_mark[0].member, members);
		}
break;
case 106:
	{
			ASN1_TAILQ_INSERT_TAIL(yystack.l_mark[-2].members, yystack.l_mark[0].member, members);
			yyval.members = yystack.l_mark[-2].members;
		}
break;
case 107:
	{
		        struct member *m = ecalloc(1, sizeof(*m));
			m->name = estrdup("...");
			m->gen_name = estrdup("asn1_ellipsis");
			m->ellipsis = 1;
			ASN1_TAILQ_INSERT_TAIL(yystack.l_mark[-2].members, m, members);
			yyval.members = yystack.l_mark[-2].members;
		}
break;
case 108:
	{
		  yyval.member = emalloc(sizeof(*yyval.member));
		  yyval.member->name = yystack.l_mark[-1].name;
		  yyval.member->gen_name = estrdup(yystack.l_mark[-1].name);
		  output_name (yyval.member->gen_name);
		  yyval.member->type = yystack.l_mark[0].type;
		  yyval.member->ellipsis = 0;
		}
break;
case 109:
	{
			yyval.member = yystack.l_mark[0].member;
			yyval.member->optional = 0;
			yyval.member->defval = NULL;
		}
break;
case 110:
	{
			yyval.member = yystack.l_mark[-1].member;
			yyval.member->optional = 1;
			yyval.member->defval = NULL;
		}
break;
case 111:
	{
			yyval.member = yystack.l_mark[-2].member;
			yyval.member->optional = 0;
			yyval.member->defval = yystack.l_mark[0].value;
		}
break;
case 112:
	{
			yyval.members = emalloc(sizeof(*yyval.members));
			ASN1_TAILQ_INIT(yyval.members);
			ASN1_TAILQ_INSERT_HEAD(yyval.members, yystack.l_mark[0].member, members);
		}
break;
case 113:
	{
			ASN1_TAILQ_INSERT_TAIL(yystack.l_mark[-2].members, yystack.l_mark[0].member, members);
			yyval.members = yystack.l_mark[-2].members;
		}
break;
case 114:
	{
		  yyval.member = emalloc(sizeof(*yyval.member));
		  yyval.member->name = yystack.l_mark[-3].name;
		  yyval.member->gen_name = estrdup(yystack.l_mark[-3].name);
		  output_name (yyval.member->gen_name);
		  yyval.member->val = yystack.l_mark[-1].constant;
		  yyval.member->optional = 0;
		  yyval.member->ellipsis = 0;
		  yyval.member->type = NULL;
		}
break;
case 116:
	{ yyval.objid = NULL; }
break;
case 117:
	{
			yyval.objid = yystack.l_mark[-1].objid;
		}
break;
case 118:
	{
			yyval.objid = NULL;
		}
break;
case 119:
	{
		        if (yystack.l_mark[0].objid) {
				yyval.objid = yystack.l_mark[0].objid;
				add_oid_to_tail(yystack.l_mark[0].objid, yystack.l_mark[-1].objid);
			} else {
				yyval.objid = yystack.l_mark[-1].objid;
			}
		}
break;
case 120:
	{
			yyval.objid = new_objid(yystack.l_mark[-3].name, yystack.l_mark[-1].constant);
		}
break;
case 121:
	{
		    Symbol *s = addsym(yystack.l_mark[0].name);
		    if(s->stype != SValue ||
		       s->value->type != objectidentifiervalue) {
			lex_error_message("%s is not an object identifier\n",
				      s->name);
			exit(1);
		    }
		    yyval.objid = s->value->u.objectidentifiervalue;
		}
break;
case 122:
	{
		    yyval.objid = new_objid(NULL, yystack.l_mark[0].constant);
		}
break;
case 132:
	{
			Symbol *s = addsym(yystack.l_mark[0].name);
			if(s->stype != SValue)
				lex_error_message ("%s is not a value\n",
						s->name);
			else
				yyval.value = s->value;
		}
break;
case 133:
	{
			yyval.value = emalloc(sizeof(*yyval.value));
			yyval.value->type = stringvalue;
			yyval.value->u.stringvalue = yystack.l_mark[0].name;
		}
break;
case 134:
	{
			yyval.value = emalloc(sizeof(*yyval.value));
			yyval.value->type = booleanvalue;
			yyval.value->u.booleanvalue = 0;
		}
break;
case 135:
	{
			yyval.value = emalloc(sizeof(*yyval.value));
			yyval.value->type = booleanvalue;
			yyval.value->u.booleanvalue = 0;
		}
break;
case 136:
	{
			yyval.value = emalloc(sizeof(*yyval.value));
			yyval.value->type = integervalue;
			yyval.value->u.integervalue = yystack.l_mark[0].constant;
		}
break;
case 138:
	{
		}
break;
case 139:
	{
			yyval.value = emalloc(sizeof(*yyval.value));
			yyval.value->type = objectidentifiervalue;
			yyval.value->u.objectidentifiervalue = yystack.l_mark[0].objid;
		}
break;
    }
    yystack.s_mark -= yym;
    yystate = *yystack.s_mark;
    yystack.l_mark -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yystack.s_mark = YYFINAL;
        *++yystack.l_mark = yyval;
        if (yychar < 0)
        {
            if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yystack.s_mark, yystate);
#endif
    if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
    {
        goto yyoverflow;
    }
    *++yystack.s_mark = (short) yystate;
    *++yystack.l_mark = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    yyfreestack(&yystack);
    return (1);

yyaccept:
    yyfreestack(&yystack);
    return (0);
}
