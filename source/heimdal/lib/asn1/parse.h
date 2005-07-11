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




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 56 "parse.y"
typedef union YYSTYPE {
  int constant;
  char *name;
  Type *type;
  Member *member;
  char *defval;
} YYSTYPE;
/* Line 1285 of yacc.c.  */
#line 107 "parse.h"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;



