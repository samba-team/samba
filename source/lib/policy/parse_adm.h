/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

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

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     CATEGORY = 258,
     CLASS = 259,
     USER = 260,
     MACHINE = 261,
     POLICY = 262,
     KEYNAME = 263,
     EXPLAIN = 264,
     VALUENAME = 265,
     VALUEON = 266,
     VALUEOFF = 267,
     PART = 268,
     ITEMLIST = 269,
     NAME = 270,
     VALUE = 271,
     NUMERIC = 272,
     EDITTEXT = 273,
     TEXT = 274,
     DROPDOWNLIST = 275,
     CHECKBOX = 276,
     MINIMUM = 277,
     MAXIMUM = 278,
     DEFAULT = 279,
     END = 280,
     ACTIONLIST = 281,
     DEL = 282,
     SUPPORTED = 283,
     LITERAL = 284,
     INTEGER = 285,
     LOOKUPLITERAL = 286,
     CLIENTEXT = 287,
     REQUIRED = 288,
     NOSORT = 289,
     SPIN = 290,
     EQUALS = 291,
     STRINGSSECTION = 292
   };
#endif
/* Tokens.  */
#define CATEGORY 258
#define CLASS 259
#define USER 260
#define MACHINE 261
#define POLICY 262
#define KEYNAME 263
#define EXPLAIN 264
#define VALUENAME 265
#define VALUEON 266
#define VALUEOFF 267
#define PART 268
#define ITEMLIST 269
#define NAME 270
#define VALUE 271
#define NUMERIC 272
#define EDITTEXT 273
#define TEXT 274
#define DROPDOWNLIST 275
#define CHECKBOX 276
#define MINIMUM 277
#define MAXIMUM 278
#define DEFAULT 279
#define END 280
#define ACTIONLIST 281
#define DEL 282
#define SUPPORTED 283
#define LITERAL 284
#define INTEGER 285
#define LOOKUPLITERAL 286
#define CLIENTEXT 287
#define REQUIRED 288
#define NOSORT 289
#define SPIN 290
#define EQUALS 291
#define STRINGSSECTION 292




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 33 "lib/policy/parse_adm.y"
{
	char *text;
	int integer;
}
/* Line 1489 of yacc.c.  */
#line 128 "lib/policy/parse_adm.y"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

