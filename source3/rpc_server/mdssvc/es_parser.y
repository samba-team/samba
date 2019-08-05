/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines / Elasticsearch backend

   Copyright (C) Ralph Boehme			2019

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
	#include "rpc_server/mdssvc/mdssvc_es.h"
	#include "rpc_server/mdssvc/es_parser.tab.h"
	#include "rpc_server/mdssvc/es_mapping.h"
	#include <jansson.h>

	/*
	 * allow building with -O3 -Wp,-D_FORTIFY_SOURCE=2
	 *
	 * /tmp/samba-testbase/.../mdssvc/es_parser.y: In function
	 * ‘mdsyylparse’:
	 * es_parser.tab.c:1124:6: error: assuming pointer wraparound
	 * does not occur when comparing P +- C1 with P +- C2
	 * [-Werror=strict-overflow]
	 *
	 * The generated code in es_parser.tab.c looks like this:
	 *
	 *   if (yyss + yystacksize - 1 <= yyssp)
	 */
	#pragma GCC diagnostic ignored "-Wstrict-overflow"

	#define YYMALLOC SMB_MALLOC
	#define YYREALLOC SMB_REALLOC

	struct yy_buffer_state;
	typedef struct yy_buffer_state *YY_BUFFER_STATE;
	int mdsyyllex(void);
	void mdsyylerror(char const *);
	void *mdsyylterminate(void);
	YY_BUFFER_STATE mdsyyl_scan_string(const char *str);
	void mdsyyl_delete_buffer(YY_BUFFER_STATE buffer);

	/* forward declarations */
	static char *isodate_to_sldate(const char *s);
	static char *map_expr(const struct es_attr_map *attr,
			      char op,
			      const char *val1,
			      const char *val2);

	/* global vars, eg needed by the lexer */
	struct es_parser_state {
		TALLOC_CTX *frame;
		json_t *kmd_map;
		json_t *mime_map;
		YY_BUFFER_STATE s;
		const char *result;
	} *global_es_parser_state;
%}

%code provides {
	#include <stdbool.h>
	#include <jansson.h>
	#include "rpc_server/mdssvc/mdssvc.h"

	/* 2001-01-01T00:00:00Z - Unix Epoch = SP_RAW_TIME_OFFSET */
	#define SP_RAW_TIME_OFFSET 978307200

	int mdsyylwrap(void);
	bool map_spotlight_to_es_query(TALLOC_CTX *mem_ctx,
				       json_t *mappings,
				       const char *path_scope,
				       const char *query_string,
				       char **_es_query);
}

%union {
	bool bval;
	const char *sval;
	struct es_attr_map *attr_map;
}

%name-prefix "mdsyyl"
%expect 1
%error-verbose

%type <sval> match expr line function value isodate
%type <attr_map> attribute

%token <sval> WORD PHRASE
%token <bval> BOOLEAN
%token FUNC_INRANGE
%token DATE_ISO
%token OBRACE CBRACE EQUAL UNEQUAL GT LT COMMA QUOTE
%left OR
%left AND
%%

input:
/* empty */
| input line
;

line:
expr {
	global_es_parser_state->result = $1;
}
;

expr:
OBRACE expr CBRACE {
	if ($2 == NULL) YYABORT;
	$$ = talloc_asprintf(talloc_tos(), "(%s)", $2);
	if ($$ == NULL) YYABORT;
}
| expr AND expr {
	$$ = talloc_asprintf(talloc_tos(), "(%s) AND (%s)", $1, $3);
	if ($$ == NULL) YYABORT;
}
| expr OR expr {
	$$ = talloc_asprintf(talloc_tos(), "%s OR %s", $1, $3);
	if ($$ == NULL) YYABORT;
}
| match {
	$$ = $1;
}
| BOOLEAN {
	/*
	 * We can't properly handle these in expressions, fortunately this
	 * is probably only ever used by OS X as sole element in an
	 * expression ie "False" (when Finder window selected our share
	 * but no search string entered yet). Packet traces showed that OS
	 * X Spotlight server then returns a failure (ie -1) which is what
	 * we do here too by calling YYABORT.
	 */
	YYABORT;
};

match:
attribute EQUAL value {
	$$ = map_expr($1, '=', $3, NULL);
	if ($$ == NULL) YYABORT;
}
| attribute UNEQUAL value {
	$$ = map_expr($1, '!', $3, NULL);
	if ($$ == NULL) YYABORT;
}
| attribute LT value {
	$$ = map_expr($1, '<', $3, NULL);
	if ($$ == NULL) YYABORT;
}
| attribute GT value {
	$$ = map_expr($1, '>', $3, NULL);
	if ($$ == NULL) YYABORT;
}
| function {
	$$ = $1;
}
| match WORD {
	$$ = $1;
};

function:
FUNC_INRANGE OBRACE attribute COMMA WORD COMMA WORD CBRACE {
	$$ = map_expr($3, '~', $5, $7);
	if ($$ == NULL) YYABORT;
};

attribute:
WORD {
	$$ = es_map_sl_attr(global_es_parser_state->frame,
			    global_es_parser_state->kmd_map,
			    $1);
	if ($$ == NULL) YYABORT;
};

value:
PHRASE {
	$$ = $1;
}
| isodate {
	$$ = $1;
};

isodate:
DATE_ISO OBRACE WORD CBRACE {
	$$ = isodate_to_sldate($3);
	if ($$ == NULL) YYABORT;
};

%%

/*
 * Spotlight has two date formats:
 * - seconds since 2001-01-01 00:00:00Z
 * - as string "$time.iso(%Y-%m-%dT%H:%M:%SZ)"
 * This function converts the latter to the former as string, so the parser
 * can work on a uniform format.
 */
static char *isodate_to_sldate(const char *isodate)
{
	struct es_parser_state *s = global_es_parser_state;
	struct tm tm;
	const char *p = NULL;
	char *tstr = NULL;
	time_t t;

	p = strptime(isodate, "%Y-%m-%dT%H:%M:%SZ", &tm);
	if (p == NULL) {
		DBG_ERR("strptime [%s] failed\n", isodate);
		return NULL;
	}

	t = timegm(&tm);
	t -= SP_RAW_TIME_OFFSET;

	tstr = talloc_asprintf(s->frame, "%jd", (intmax_t)t);
	if (tstr == NULL) {
		return NULL;
	}

	return tstr;
}

static char *map_type(const struct es_attr_map *attr,
		      char op,
		      const char *val)
{
	struct es_parser_state *s = global_es_parser_state;
	const char *mime_type_list = NULL;
	char *esc_mime_type_list = NULL;
	const char *not = NULL;
	const char *end = NULL;
	char *es = NULL;

	mime_type_list = es_map_sl_type(s->mime_map, val);
	if (mime_type_list == NULL) {
		DBG_ERR("Mapping type [%s] failed\n", val);
		return NULL;
	}

	esc_mime_type_list = es_escape_str(s->frame,
					   mime_type_list,
					   "* ");
	if (esc_mime_type_list == NULL) {
		return NULL;
	}

	switch (op) {
	case '=':
		not = "";
		end = "";
		break;
	case '!':
		not = "(NOT ";
		end = ")";
		break;
	default:
		DBG_ERR("Mapping type [%s] unexpected op [%c]\n", val, op);
		return NULL;
	}
	es = talloc_asprintf(s->frame,
			     "%s%s:(%s)%s",
			     not,
			     attr->name,
			     esc_mime_type_list,
			     end);
	if (es == NULL) {
		return NULL;
	}

	return es;
}

static char *map_num(const struct es_attr_map *attr,
		     char op,
		     const char *val1,
		     const char *val2)
{
	struct es_parser_state *s = global_es_parser_state;
	char *es = NULL;

	switch (op) {
	case '>':
		es = talloc_asprintf(s->frame,
				     "%s:{%s TO *}",
				     attr->name,
				     val1);
		break;
	case '<':
		es = talloc_asprintf(s->frame,
				     "%s:{* TO %s}",
				     attr->name,
				     val1);
		break;
	case '~':
		es = talloc_asprintf(s->frame,
				     "%s:[%s TO %s]",
				     attr->name,
				     val1,
				     val2);
		break;
	case '=':
		es = talloc_asprintf(s->frame,
				     "%s:%s",
				     attr->name,
				     val1);
		break;
	case '!':
		es = talloc_asprintf(s->frame,
				     "(NOT %s:%s)",
				     attr->name,
				     val1);
		break;
	default:
		DBG_ERR("Mapping num unexpected op [%c]\n", op);
		return NULL;
	}
	if (es == NULL) {
		return NULL;
	}

	return es;
}

static char *map_fts(const struct es_attr_map *attr,
		     char op,
		     const char *val)
{
	struct es_parser_state *s = global_es_parser_state;
	const char *not = NULL;
	const char *end = NULL;
	char *esval = NULL;
	char *es = NULL;

	esval = es_escape_str(s->frame, val, "*\\\"");
	if (esval == NULL) {
		yyerror("es_escape_str failed");
		return NULL;
	}

	switch (op) {
	case '=':
		not = "";
		end = "";
		break;
	case '!':
		not = "(NOT ";
		end = ")";
		break;
	default:
		DBG_ERR("Mapping fts [%s] unexpected op [%c]\n", val, op);
		return NULL;
	}
	es = talloc_asprintf(s->frame,
			     "%s%s%s",
			     not,
			     esval,
			     end);
	if (es == NULL) {
		return NULL;
	}
	return es;
}

static char *map_str(const struct es_attr_map *attr,
		     char op,
		     const char *val)
{
	struct es_parser_state *s = global_es_parser_state;
	char *esval = NULL;
	char *es = NULL;
	const char *not = NULL;
	const char *end = NULL;

	esval = es_escape_str(s->frame, val, "*\\\"");
	if (esval == NULL) {
		yyerror("es_escape_str failed");
		return NULL;
	}

	switch (op) {
	case '=':
		not = "";
		end = "";
		break;
	case '!':
		not = "(NOT ";
		end = ")";
		break;
	default:
		DBG_ERR("Mapping string [%s] unexpected op [%c]\n", val, op);
		return NULL;
	}

	es = talloc_asprintf(s->frame,
			     "%s%s:%s%s",
			     not,
			     attr->name,
			     esval,
			     end);
	if (es == NULL) {
		return NULL;
	}
	return es;
}

/*
 * Convert Spotlight date seconds since 2001-01-01 00:00:00Z
 * to a date string in the format %Y-%m-%dT%H:%M:%SZ.
 */
static char *map_sldate_to_esdate(TALLOC_CTX *mem_ctx,
				  const char *sldate)
{
	struct tm *tm = NULL;
	char *esdate = NULL;
	char buf[21];
	size_t len;
	time_t t;
	int error;

	t = (time_t)smb_strtoull(sldate, NULL, 10, &error, SMB_STR_STANDARD);
	if (error != 0) {
		DBG_ERR("smb_strtoull [%s] failed\n", sldate);
		return NULL;
	}
	t += SP_RAW_TIME_OFFSET;

	tm = gmtime(&t);
	if (tm == NULL) {
		DBG_ERR("localtime [%s] failed\n", sldate);
		return NULL;
	}

	len = strftime(buf, sizeof(buf),
		       "%Y-%m-%dT%H:%M:%SZ", tm);
	if (len != 20) {
		DBG_ERR("strftime [%s] failed\n", sldate);
		return NULL;
	}

	esdate = es_escape_str(mem_ctx, buf, NULL);
	if (esdate == NULL) {
		yyerror("es_escape_str failed");
		return NULL;
	}
	return esdate;
}

static char *map_date(const struct es_attr_map *attr,
		      char op,
		      const char *sldate1,
		      const char *sldate2)
{
	struct es_parser_state *s = global_es_parser_state;
	char *esdate1 = NULL;
	char *esdate2 = NULL;
	char *es = NULL;

	if (op == '~' && sldate2 == NULL) {
		DBG_ERR("Date range query, but second date is NULL\n");
		return NULL;
	}

	esdate1 = map_sldate_to_esdate(s->frame, sldate1);
	if (esdate1 == NULL) {
		DBG_ERR("map_sldate_to_esdate [%s] failed\n", sldate1);
		return NULL;
	}
	if (sldate2 != NULL) {
		esdate2 = map_sldate_to_esdate(s->frame, sldate2);
		if (esdate2 == NULL) {
			DBG_ERR("map_sldate_to_esdate [%s] failed\n", sldate2);
			return NULL;
		}
	}

	switch (op) {
	case '>':
		es = talloc_asprintf(s->frame,
				     "%s:{%s TO *}",
				     attr->name,
				     esdate1);
		break;
	case '<':
		es = talloc_asprintf(s->frame,
				     "%s:{* TO %s}",
				     attr->name,
				     esdate1);
		break;
	case '~':
		es = talloc_asprintf(s->frame,
				     "%s:[%s TO %s]",
				     attr->name,
				     esdate1,
				     esdate2);
		break;
	case '=':
		es = talloc_asprintf(s->frame,
				     "%s:%s",
				     attr->name,
				     esdate1);
		break;
	case '!':
		es = talloc_asprintf(s->frame,
				     "(NOT %s:%s)",
				     attr->name,
				     esdate1);
		break;
	}
	if (es == NULL) {
		return NULL;
	}
	return es;
}

static char *map_expr(const struct es_attr_map *attr,
		      char op,
		      const char *val1,
		      const char *val2)
{
	char *es = NULL;

	switch (attr->type) {
	case ssmt_type:
		es = map_type(attr, op, val1);
		break;
	case ssmt_num:
		es = map_num(attr, op, val1, val2);
		break;
	case ssmt_fts:
		es = map_fts(attr, op, val1);
		break;
	case ssmt_str:
		es = map_str(attr, op, val1);
		break;
	case ssmt_date:
		es = map_date(attr, op, val1, val2);
		break;
	default:
		break;
	}
	if (es == NULL) {
		DBG_ERR("Mapping [%s %c %s (%s)] failed\n",
			attr->name, op, val1, val2 ? val2 : "");
		return NULL;
	}

	return es;
}

void mdsyylerror(const char *str)
{
	DBG_ERR("Parser failed: %s\n", str);
}

int mdsyylwrap(void)
{
	return 1;
}

/**
 * Map a Spotlight RAW query string to a ES query string
 **/
bool map_spotlight_to_es_query(TALLOC_CTX *mem_ctx,
			       json_t *mappings,
			       const char *path_scope,
			       const char *query_string,
			       char **_es_query)
{
	struct es_parser_state s = {
		.frame = talloc_stackframe(),
	};
	int result;
	char *es_query = NULL;

	s.kmd_map = json_object_get(mappings, "attribute_mappings");
	if (s.kmd_map == NULL) {
		DBG_ERR("Failed to load attribute_mappings from JSON\n");
		return false;
	}
	s.mime_map = json_object_get(mappings, "mime_mappings");
	if (s.mime_map == NULL) {
		DBG_ERR("Failed to load mime_mappings from JSON\n");
		return false;
	}

	s.s = mdsyyl_scan_string(query_string);
	if (s.s == NULL) {
		DBG_WARNING("Failed to parse [%s]\n", query_string);
		TALLOC_FREE(s.frame);
		return false;
	}
	global_es_parser_state = &s;
	result = mdsyylparse();
	global_es_parser_state = NULL;
	mdsyyl_delete_buffer(s.s);

	if (result != 0) {
		TALLOC_FREE(s.frame);
		return false;
	}

	es_query = talloc_asprintf(mem_ctx,
				   "(%s) AND path.real.fulltext:\\\"%s\\\"",
				   s.result, path_scope);
	TALLOC_FREE(s.frame);
	if (es_query == NULL) {
		return false;
	}

	*_es_query = es_query;
	return true;
}
