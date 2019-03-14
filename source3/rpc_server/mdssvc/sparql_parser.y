/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines

   Copyright (C) Ralph Boehme 2012-2014

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

%{
	#include "includes.h"
	#include "rpc_server/mdssvc/mdssvc.h"
	#include "rpc_server/mdssvc/mdssvc_tracker.h"
	#include "rpc_server/mdssvc/sparql_parser.tab.h"
	#include "rpc_server/mdssvc/sparql_mapping.h"

	#define YYMALLOC SMB_MALLOC
	#define YYREALLOC SMB_REALLOC

	struct yy_buffer_state;
	typedef struct yy_buffer_state *YY_BUFFER_STATE;
	extern int mdsyylex (void);
	extern void mdsyyerror (char const *);
	extern void *mdsyyterminate(void);
	extern YY_BUFFER_STATE mdsyy_scan_string( const char *str);
	extern void mdsyy_delete_buffer ( YY_BUFFER_STATE buffer );

	/* forward declarations */
	static const char *map_expr(const char *attr, char op, const char *val);
	static const char *map_daterange(const char *dateattr,
					 time_t date1, time_t date2);
	static time_t isodate2unix(const char *s);

	/* global vars, eg needed by the lexer */
	struct sparql_parser_state {
		TALLOC_CTX *frame;
		YY_BUFFER_STATE s;
		char var;
		const char *result;
	} *global_sparql_parser_state;
%}

%code provides {
	#include <stdbool.h>
	#include "rpc_server/mdssvc/mdssvc.h"
	#define SPRAW_TIME_OFFSET 978307200
	extern int mdsyywrap(void);
	extern bool map_spotlight_to_sparql_query(struct sl_query *slq);
}

%union {
	int ival;
	const char *sval;
	bool bval;
	time_t tval;
}

%name-prefix "mdsyy"
%expect 5
%error-verbose

%type <sval> match expr line function
%type <tval> date

%token <sval> WORD
%token <bval> BOOL
%token FUNC_INRANGE
%token DATE_ISO
%token OBRACE CBRACE EQUAL UNEQUAL GT LT COMMA QUOTE
%left AND
%left OR
%%

input:
/* empty */
| input line
;

line:
expr {
	global_sparql_parser_state->result = $1;
}
;

expr:
BOOL {
	/*
	 * We can't properly handle these in expressions, fortunately this
	 * is probably only ever used by OS X as sole element in an
	 * expression ie "False" (when Finder window selected our share
	 * but no search string entered yet). Packet traces showed that OS
	 * X Spotlight server then returns a failure (ie -1) which is what
	 * we do here too by calling YYABORT.
	 */
	YYABORT;
}
/*
 * We have "match OR match" and "expr OR expr", because the former is
 * supposed to catch and coalesque expressions of the form
 *
 *   MDSattribute1="hello"||MDSattribute2="hello"
 *
 * into a single SPARQL expression for the case where both
 * MDSattribute1 and MDSattribute2 map to the same SPARQL attibute,
 * which is eg the case for "*" and "kMDItemTextContent" which both
 * map to SPARQL "fts:match".
 */

| match OR match {
	if (strcmp($1, $3) != 0) {
		$$ = talloc_asprintf(talloc_tos(), "{ %s } UNION { %s }", $1, $3);
	} else {
		$$ = talloc_asprintf(talloc_tos(), "%s", $1);
	}
}
| match {
	$$ = $1;
}
| function {
	$$ = $1;
}
| OBRACE expr CBRACE {
	$$ = talloc_asprintf(talloc_tos(), "%s", $2);
}
| expr AND expr {
	$$ = talloc_asprintf(talloc_tos(), "%s . %s", $1, $3);
}
| expr OR expr {
	if (strcmp($1, $3) != 0) {
		$$ = talloc_asprintf(talloc_tos(), "{ %s } UNION { %s }", $1, $3);
	} else {
		$$ = talloc_asprintf(talloc_tos(), "%s", $1);
	}
}
;

match:
WORD EQUAL QUOTE WORD QUOTE {
	$$ = map_expr($1, '=', $4);
	if ($$ == NULL) YYABORT;
}
| WORD UNEQUAL QUOTE WORD QUOTE {
	$$ = map_expr($1, '!', $4);
	if ($$ == NULL) YYABORT;
}
| WORD LT QUOTE WORD QUOTE {
	$$ = map_expr($1, '<', $4);
	if ($$ == NULL) YYABORT;
}
| WORD GT QUOTE WORD QUOTE {
	$$ = map_expr($1, '>', $4);
	if ($$ == NULL) YYABORT;
}
| WORD EQUAL QUOTE WORD QUOTE WORD {
	$$ = map_expr($1, '=', $4);
	if ($$ == NULL) YYABORT;
}
| WORD UNEQUAL QUOTE WORD QUOTE WORD {
	$$ = map_expr($1, '!', $4);
	if ($$ == NULL) YYABORT;
}
| WORD LT QUOTE WORD QUOTE WORD {
	$$ = map_expr($1, '<', $4);
	if ($$ == NULL) YYABORT;
}
| WORD GT QUOTE WORD QUOTE WORD {
	$$ = map_expr($1, '>', $4);
	if ($$ == NULL) YYABORT;
}
;

function:
FUNC_INRANGE OBRACE WORD COMMA date COMMA date CBRACE {
	$$ = map_daterange($3, $5, $7);
	if ($$ == NULL) YYABORT;
}
;

date:
DATE_ISO OBRACE WORD CBRACE    {$$ = isodate2unix($3);}
| WORD                         {$$ = atoi($1) + SPRAW_TIME_OFFSET;}
;

%%

static time_t isodate2unix(const char *s)
{
	struct tm tm;
	const char *p;

	p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
	if (p == NULL) {
		return (time_t)-1;
	}
	return mktime(&tm);
}

static const char *map_daterange(const char *dateattr,
				 time_t date1, time_t date2)
{
	struct sparql_parser_state *s = global_sparql_parser_state;
	int result = 0;
	char *sparql = NULL;
	const struct sl_attr_map *p;
	struct tm *tmp;
	char buf1[64], buf2[64];

	if (s->var == 'z') {
		return NULL;
	}

	tmp = localtime(&date1);
	if (tmp == NULL) {
		return NULL;
	}
	result = strftime(buf1, sizeof(buf1), "%Y-%m-%dT%H:%M:%SZ", tmp);
	if (result == 0) {
		return NULL;
	}

	tmp = localtime(&date2);
	if (tmp == NULL) {
		return NULL;
	}
	result = strftime(buf2, sizeof(buf2), "%Y-%m-%dT%H:%M:%SZ", tmp);
	if (result == 0) {
		return NULL;
	}

	p = sl_attr_map_by_spotlight(dateattr);
	if (p == NULL) {
		return NULL;
	}

	sparql = talloc_asprintf(talloc_tos(),
				 "?obj %s ?%c FILTER (?%c > '%s' && ?%c < '%s')",
				 p->sparql_attr,
				 s->var,
				 s->var,
				 buf1,
				 s->var,
				 buf2);
	if (sparql == NULL) {
		return NULL;
	}

	s->var++;
	return sparql;
}

static char *map_type_search(const char *attr, char op, const char *val)
{
	char *result = NULL;
	const char *sparqlAttr;
	const struct sl_type_map *p;

	p = sl_type_map_by_spotlight(val);
	if (p == NULL) {
		return NULL;
	}

	switch (p->type) {
	case kMDTypeMapRDF:
		sparqlAttr = "rdf:type";
		break;
	case kMDTypeMapMime:
		sparqlAttr = "nie:mimeType";
		break;
	default:
		return NULL;
	}

	result = talloc_asprintf(talloc_tos(), "?obj %s '%s'",
				 sparqlAttr,
				 p->sparql_type);
	if (result == NULL) {
		return NULL;
	}

	return result;
}

static const char *map_expr(const char *attr, char op, const char *val)
{
	struct sparql_parser_state *s = global_sparql_parser_state;
	int result = 0;
	char *sparql = NULL;
	const struct sl_attr_map *p;
	time_t t;
	struct tm *tmp;
	char buf1[64];
	char *q;
	const char *start;

	if (s->var == 'z') {
		return NULL;
	}

	p = sl_attr_map_by_spotlight(attr);
	if (p == NULL) {
		return NULL;
	}

	if ((p->type != ssmt_type) && (p->sparql_attr == NULL)) {
		yyerror("unsupported Spotlight attribute");
		return NULL;
	}

	switch (p->type) {
	case ssmt_bool:
		sparql = talloc_asprintf(talloc_tos(), "?obj %s '%s'",
					 p->sparql_attr, val);
		if (sparql == NULL) {
			return NULL;
		}
		break;

	case ssmt_num:
		sparql = talloc_asprintf(talloc_tos(),
					 "?obj %s ?%c FILTER(?%c %c%c '%s')",
					 p->sparql_attr,
					 s->var,
					 s->var,
					 op,
					 /* append '=' to '!' */
					 op == '!' ? '=' : ' ',
					 val);
		if (sparql == NULL) {
			return NULL;
		}
		s->var++;
		break;

	case ssmt_str:
		q = talloc_strdup(talloc_tos(), "");
		if (q == NULL) {
			return NULL;
		}
		start = val;
		while (*val) {
			if (*val != '*') {
				val++;
				continue;
			}
			if (val > start) {
				q = talloc_strndup_append(q, start, val - start);
				if (q == NULL) {
					return NULL;
				}
			}
			q = talloc_strdup_append(q, ".*");
			if (q == NULL) {
				return NULL;
			}
			val++;
			start = val;
		}
		if (val > start) {
			q = talloc_strndup_append(q, start, val - start);
			if (q == NULL) {
				return NULL;
			}
		}
		sparql = talloc_asprintf(talloc_tos(),
					 "?obj %s ?%c "
					 "FILTER(regex(?%c, '^%s$', 'i'))",
					 p->sparql_attr,
					 s->var,
					 s->var,
					 q);
		TALLOC_FREE(q);
		if (sparql == NULL) {
			return NULL;
		}
		s->var++;
		break;

	case ssmt_fts:
		sparql = talloc_asprintf(talloc_tos(), "?obj %s '%s'",
					 p->sparql_attr, val);
		if (sparql == NULL) {
			return NULL;
		}
		break;

	case ssmt_date:
		t = atoi(val) + SPRAW_TIME_OFFSET;
		tmp = localtime(&t);
		if (tmp == NULL) {
			return NULL;
		}
		result = strftime(buf1, sizeof(buf1),
				  "%Y-%m-%dT%H:%M:%SZ", tmp);
		if (result == 0) {
			return NULL;
		}
		sparql = talloc_asprintf(talloc_tos(),
					 "?obj %s ?%c FILTER(?%c %c '%s')",
					 p->sparql_attr,
					 s->var,
					 s->var,
					 op,
					 buf1);
		if (sparql == NULL) {
			return NULL;
		}
		s->var++;
		break;

	case ssmt_type:
		sparql = map_type_search(attr, op, val);
		if (sparql == NULL) {
			return NULL;
		}
		break;

	default:
		return NULL;
	}

	return sparql;
}

void mdsyyerror(const char *str)
{
	DEBUG(1, ("mdsyyerror: %s\n", str));
}

int mdsyywrap(void)
{
	return 1;
}

/**
 * Map a Spotlight RAW query string to a SPARQL query string
 **/
bool map_spotlight_to_sparql_query(struct sl_query *slq)
{
	struct sl_tracker_query *tq = talloc_get_type_abort(
		slq->backend_private, struct sl_tracker_query);
	struct sparql_parser_state s = {
		.frame = talloc_stackframe(),
		.var = 'a',
	};
	int result;

	s.s = mdsyy_scan_string(slq->query_string);
	if (s.s == NULL) {
		TALLOC_FREE(s.frame);
		return false;
	}
	global_sparql_parser_state = &s;
	result = mdsyyparse();
	global_sparql_parser_state = NULL;
	mdsyy_delete_buffer(s.s);

	if (result != 0) {
		TALLOC_FREE(s.frame);
		return false;
	}

	tq->sparql_query = talloc_asprintf(slq,
		"SELECT ?url WHERE { %s . ?obj nie:url ?url . "
		"FILTER(tracker:uri-is-descendant('file://%s/', ?url)) }",
		s.result, tq->path_scope);
	TALLOC_FREE(s.frame);
	if (tq->sparql_query == NULL) {
		return false;
	}

	return true;
}
