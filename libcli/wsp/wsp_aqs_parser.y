/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c) Noel Power
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

%{

#include "includes.h"
#include "libcli/wsp/wsp_aqs.h"
#include "libcli/wsp/wsp_aqs_parser.tab.h"
#include "libcli/wsp/wsp_aqs_lexer.h"

static int yyerror(t_select_stmt **stmt, yyscan_t scanner, const char *msg)
{
	fprintf(stderr,"Error :%s\n",msg); return 0;
}
%}
%code requires {

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif

}

%define api.pure
%lex-param   { yyscan_t scanner }
%parse-param { t_select_stmt **select }
%parse-param { yyscan_t scanner }

%union {
	char *strval;
	int64_t num;
	t_value_holder *value;
	t_select_stmt *select_stmt;
	t_select_stmt *query_stmt;
	t_basic_restr *bas_rest;
	t_basic_query *bas_query;
	t_restr *restr;
	t_query       *query;
	t_col_list *columns;
	daterange_type daterange;
	sizerange_type sizerange;
	t_optype prop_op;
}

%left "AND" TOKEN_AND
%left "OR" TOKEN_OR
%left "!=" TOKEN_NE
%left ">=" TOKEN_GE
%left "<=" TOKEN_LE
%left "<" TOKEN_LT
%left ">" TOKEN_GT
%right "NOT" TOKEN_NOT
%right "==" TOKEN_EQ
%right ":" TOKEN_PROP_EQUALS

%right "$<" TOKEN_STARTS_WITH
%right "$=" TOKEN_EQUALS

%token TOKEN_LPAREN
%token TOKEN_RPAREN
%token TOKEN_AND
%token TOKEN_OR
%token TOKEN_WHERE
%token TOKEN_SELECT
%token TOKEN_TRUE
%token TOKEN_FALSE
%token TOKEN_COMMA
%token TOKEN_STARTS_WITH
%token TOKEN_EQUALS
%token TOKEN_MATCHES
%token TOKEN_K
%token TOKEN_M
%token TOKEN_G
%token TOKEN_T
%token TOKEN_KB
%token TOKEN_MB
%token TOKEN_GB
%token TOKEN_TB
%token TOKEN_RANGE
%token TOKEN_TODAY
%token TOKEN_YESTERDAY
%token TOKEN_THISWEEK
%token TOKEN_LASTWEEK
%token TOKEN_THISMONTH
%token TOKEN_LASTMONTH
%token TOKEN_THISYEAR
%token TOKEN_LASTYEAR
%token TOKEN_EMPTY
%token TOKEN_TINY
%token TOKEN_SMALL
%token TOKEN_MEDIUM
%token TOKEN_LARGE
%token TOKEN_HUGE
%token TOKEN_GIGANTIC

%token <num> TOKEN_NUMBER
%token <strval> TOKEN_IDENTIFIER
%token <strval> TOKEN_STRING_LITERAL

%type <strval> prop
%type <bas_rest> basic_restr
%type <restr> restr
%type <bas_query> basic_query
%type <query> query
%type <columns> cols
%type <strval> col
%type <select_stmt> select_stmt
%type <value> simple_value
%type <value> value
%type <daterange> date_shortcut
%type <prop_op> property_op
%type <prop_op> content_op
%type <sizerange> size_shortcut

%%

input:
	select_stmt {
		*select = $1;
	}
;

select_stmt:
	TOKEN_SELECT cols[C] TOKEN_WHERE query[Q] {
		$$ = create_select(talloc_tos(), $C, $Q );
		if (!$$) {
			 YYERROR;
		}
	}
	| query[Q] {
		$$ = create_select(talloc_tos(), NULL, $Q );
		if (!$$) {
			 YYERROR;
		}
	}
	;

cols :
	col[C] {
		$$ = create_cols(talloc_tos(), $1, NULL);
		if (!$$) {
			 YYERROR;
		}
	}
	| col[C] TOKEN_COMMA cols[CS]  {
		$$ = create_cols(talloc_tos(), $C, $CS);
		if (!$$) {
			 YYERROR;
		}
	}
	;

col:
	TOKEN_IDENTIFIER[I] {
		$$ = $I;
		if (!$$) {
			 YYERROR;
		}
	}
	;

query:
	basic_query {
		$$ = create_query_node(talloc_tos(), eVALUE, NULL, NULL, $1);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_LPAREN query[Q] TOKEN_RPAREN {
		$$ = $Q;
		if (!$$) {
			 YYERROR;
		}
	}
	| query[L] TOKEN_AND query[R] {
		$$ = create_query_node(talloc_tos(), eAND, $L, $R, NULL);
		if (!$$) {
			 YYERROR;
		}
	}
	| query[L] TOKEN_OR query[R] {
		$$ = create_query_node(talloc_tos(), eOR, $L, $R, NULL);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_NOT query[R] {
		$$ = create_query_node(talloc_tos(), eNOT, NULL, $R, NULL);
		if (!$$) {
			 YYERROR;
		}
	}
	;

basic_query:
	prop[P] TOKEN_PROP_EQUALS basic_restr[V] {
		$$ = create_basic_query(talloc_tos(), $P, $V);
		if (!$$) {
			 YYERROR;
		}
	}
	;

prop: TOKEN_IDENTIFIER[I] {
		$$ = $I;
		if (!$$) {
			 YYERROR;
		}
	}
	;

basic_restr:
	value[V] {
		$$ = create_basic_restr(talloc_tos(), RTPROPERTY, eEQ, $V);
		if (!$$) {
			 YYERROR;
		}
	}
	| property_op[P] value[T] {
		$$ = create_basic_restr(talloc_tos(), RTPROPERTY, $P, $T);
		if (!$$) {
			 YYERROR;
		}
	}
	| content_op[P] value[T] {
		$$ = create_basic_restr(talloc_tos(), RTCONTENT, $P, $T);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_LPAREN restr[R] TOKEN_RPAREN {
		t_value_holder *holder = talloc_zero(talloc_tos(), t_value_holder);
		holder->type = RESTR;
		holder->value.restr_tree = $R;
		$$ = create_basic_restr(talloc_tos(), RTNONE, eEQ, holder);
		if (!$$) {
			 YYERROR;
		}
	}
	;

property_op:
	TOKEN_EQ { $$ = eEQ; }
	| TOKEN_NE { $$ = eNE; }
	| TOKEN_GE { $$ = eGE; }
	| TOKEN_LE { $$ = eLE; }
	| TOKEN_LT { $$ = eLT; }
	| TOKEN_GT { $$ = eGT; }
	;

content_op:
	TOKEN_STARTS_WITH { $$ = eSTARTSWITH; }
	| TOKEN_EQUALS { $$ = eEQUALS; }
	;

value:
	simple_value[V] { $$ = $V;}
	| simple_value[L] TOKEN_RANGE simple_value[R] {
		$$ = create_value_range(talloc_tos(), $L, $R);
		if (!$$) {
			 YYERROR;
		}
	}
	| date_shortcut[D] {
		$$ = create_date_range_shortcut(talloc_tos(), $D);
		if (!$$) {
			 YYERROR;
		}
	}
	| size_shortcut[S] {
		$$ = create_size_range_shortcut(talloc_tos(), $S);
		if (!$$) {
			 YYERROR;
		}
	}
	;

date_shortcut:
	TOKEN_TODAY { $$ = eTODAY; }
	| TOKEN_YESTERDAY { $$ = eYESTERDAY; }
	| TOKEN_THISWEEK { $$ = eTHISWEEK; }
	| TOKEN_LASTWEEK { $$ = eLASTWEEK; }
	| TOKEN_THISMONTH { $$ = eTHISMONTH; }
	| TOKEN_LASTMONTH { $$ = eTHISMONTH; }
	| TOKEN_THISYEAR { $$ = eTHISYEAR; }
	| TOKEN_LASTYEAR { $$ = eLASTYEAR; }
	;

size_shortcut:
	TOKEN_EMPTY { $$ = eEMPTY; }
	| TOKEN_TINY { $$ = eTINY; }
	| TOKEN_SMALL { $$ = eSMALL; }
	| TOKEN_MEDIUM { $$ = eMEDIUM; }
	| TOKEN_LARGE { $$ = eLARGE; }
	| TOKEN_HUGE { $$ = eHUGE; }
	| TOKEN_GIGANTIC { $$ = eGIGANTIC; }
	;

simple_value:
	TOKEN_NUMBER[N] {
		$$ = create_num_val(talloc_tos(), $N);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_NUMBER[N] TOKEN_K {
		$$ = create_num_val(talloc_tos(), $N * 1024);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_NUMBER[N] TOKEN_M {
		$$ = create_num_val( talloc_tos(), $N * 1024 * 1024);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_NUMBER[N] TOKEN_G {
		$$ = create_num_val(talloc_tos(), $N * 1024 * 1024 * 1024);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_NUMBER[N] TOKEN_T {
		$$ = create_num_val(talloc_tos(),
				    $N * 1024 * 1024 * 1024 * 1024);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_NUMBER[N] TOKEN_KB {
		$$ = create_num_val(talloc_tos(), $N * 1000);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_NUMBER[N] TOKEN_MB {
		$$ = create_num_val( talloc_tos(), $N * 1000 * 1000);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_NUMBER[N] TOKEN_GB {
		$$ = create_num_val(talloc_tos(), $N * 1000 * 1000 * 1000);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_NUMBER[N] TOKEN_TB {
		$$ = create_num_val(talloc_tos(),
				    $N * 1000 * 1000 * 1000 * 1000);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_TRUE {
		$$ = create_bool_val(talloc_tos(), true);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_FALSE {
		$$ = create_num_val(talloc_tos(), false);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_STRING_LITERAL[S] {
		char *tmp_str = talloc_strdup(talloc_tos(), $S+1);
		tmp_str[strlen(tmp_str)-1] = '\0';
		$$ = create_string_val(talloc_tos(), tmp_str);
		if (!$$) {
			 YYERROR;
		}
	}
	| TOKEN_IDENTIFIER[I] {
		$$ = create_string_val(talloc_tos(), $I);
		if (!$$) {
			 YYERROR;
		}
	}
	;

restr: basic_restr[V] {
		$$ = create_restr(talloc_tos(), eVALUE, NULL, NULL, $V);
		if (!$$) {
			 YYERROR;
		}
	}
	| restr[L] TOKEN_AND restr[R] {
		$$ = create_restr(talloc_tos(), eAND, $L, $R, NULL);
		if (!$$) {
			 YYERROR;
		}
	}
	| restr[L] TOKEN_OR restr[R] {
		$$ = create_restr(talloc_tos(), eOR, $L, $R, NULL);
		if (!$$) {
			 YYERROR;
		}
	}
	;
%%
