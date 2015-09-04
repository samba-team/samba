/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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

#ifndef YY_YY_SPARQL_PARSER_H_INCLUDED
# define YY_YY_SPARQL_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    WORD = 258,
    BOOL = 259,
    FUNC_INRANGE = 260,
    DATE_ISO = 261,
    OBRACE = 262,
    CBRACE = 263,
    EQUAL = 264,
    UNEQUAL = 265,
    GT = 266,
    LT = 267,
    COMMA = 268,
    QUOTE = 269,
    AND = 270,
    OR = 271
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE YYSTYPE;
union YYSTYPE
{
#line 61 "sparql_parser.y" /* yacc.c:1909  */

	int ival;
	const char *sval;
	bool bval;
	time_t tval;

#line 78 "sparql_parser.h" /* yacc.c:1909  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);
/* "%code provides" blocks.  */
#line 53 "sparql_parser.y" /* yacc.c:1909  */

	#include <stdbool.h>
	#include "mdssvc.h"
	#define SPRAW_TIME_OFFSET 978307200
	extern int yywrap(void);
	extern bool map_spotlight_to_sparql_query(struct sl_query *slq);

#line 97 "sparql_parser.h" /* yacc.c:1909  */

#endif /* !YY_YY_SPARQL_PARSER_H_INCLUDED  */
