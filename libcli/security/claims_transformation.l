/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2025

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
#define CLAIMS_TRANSFORMATION_INTERNALS 1
#include "libcli/security/claims_transformation.h"
#include "libcli/security/claims_transformation.tab.h"

#undef strcasecmp

static char *strip_quote(const char *phrase);

#define YYSTYPE __CLAIMS_TF_YY_STYPE
#define YYLTYPE __CLAIMS_TF_YY_LTYPE

_PRIVATE_ int __claims_tf_yy_lex(
	YYSTYPE * yylval_param,
	YYLTYPE * yylloc_param,
	struct claims_tf_parser_state *ctf_ps,
	yyscan_t yyscanner);

#define YY_DECL int __claims_tf_yy_lex \
	(YYSTYPE * yylval_param, \
	YYLTYPE * yylloc_param, \
	struct claims_tf_parser_state *ctf_ps, \
	yyscan_t yyscanner)

#define YY_USER_ACTION do { \
	size_t __idx; \
	yylloc->first_line = yylloc->last_line; \
	yylloc->first_column = yylloc->last_column; \
	for (__idx = 0; yytext[__idx] != '\0'; __idx++) { \
		if (yytext[__idx] == '\n') { \
			yylloc->last_line++; \
			yylloc->last_column = 0; \
		} else { \
			yylloc->last_column++; \
		} \
	} \
	ctf_ps->error.first_line = yylloc->first_line; \
	ctf_ps->error.first_column = yylloc->first_column; \
	ctf_ps->error.last_line = yylloc->last_line; \
	ctf_ps->error.last_column = yylloc->last_column; \
} while(0);

%}

%option prefix="__claims_tf_yy_"
%option case-insensitive
%option bison-bridge
%option bison-locations
%option reentrant

%option noyywrap
%option nounput
%option noyyalloc
%option noyyrealloc
%option noyyfree

%option noinput
%option nounput
%option noyylineno
%option noyy_push_state
%option noyy_pop_state
%option noyy_top_state
%option noyyget_leng
%option noyyget_text
%option noyyget_lineno
%option noyyset_lineno
%option noyyget_in
%option noyyset_in
%option noyyget_out
%option noyyset_out
%option noyyget_lval
%option noyyset_lval
%option noyyget_lloc
%option noyyset_lloc
%option noyyget_debug
%option noyyset_debug

%%
\=\>                       return CLAIMS_TF_YY_IMPLY;
\;                         return CLAIMS_TF_YY_SEMICOLON;
\:                         return CLAIMS_TF_YY_COLON;
\,                         return CLAIMS_TF_YY_COMMA;
\.                         return CLAIMS_TF_YY_DOT;
\[                         return CLAIMS_TF_YY_O_SQ_BRACKET;
\]                         return CLAIMS_TF_YY_C_SQ_BRACKET;
\(                         return CLAIMS_TF_YY_O_BRACKET;
\)                         return CLAIMS_TF_YY_C_BRACKET;
\=\=                       return CLAIMS_TF_YY_EQ;
\!\=                       return CLAIMS_TF_YY_NEQ;
\=\~                       return CLAIMS_TF_YY_REGEXP_MATCH;
\!\~                       return CLAIMS_TF_YY_REGEXP_NOT_MATCH;
\=                         return CLAIMS_TF_YY_ASSIGN;
\&\&                       return CLAIMS_TF_YY_AND;
issue                      return CLAIMS_TF_YY_ISSUE;
type                       return CLAIMS_TF_YY_TYPE;
value                      return CLAIMS_TF_YY_VALUE;
valuetype                  return CLAIMS_TF_YY_VALUE_TYPE;
claim                      return CLAIMS_TF_YY_CLAIM;
[_A-Za-z][_A-Za-z0-9]*     {yylval->sval = talloc_strdup(talloc_tos(), yytext); return CLAIMS_TF_YY_IDENTIFIER;}
\"[^\"\n]*\"               {yylval->sval = strip_quote(yytext); return CLAIMS_TF_YY_STRING;}
[ \t\n]                    /* ignore */
%%



static char *strip_quote(const char *phrase)
{
	size_t phrase_len = 0;
	char *stripped_phrase = NULL;

	if (phrase == NULL) {
		return NULL;
	}

	phrase_len = strlen(phrase);
	if (phrase_len < 2 ||
	    phrase[0] != '\"' ||
	    phrase[phrase_len - 1] != '\"')
	{
		return talloc_strdup(talloc_tos(), phrase);
	}

	phrase++;

	stripped_phrase = talloc_strndup(talloc_tos(), phrase, phrase_len - 2);
	if (stripped_phrase == NULL) {
		return NULL;
	}
	return stripped_phrase;
}

_PRIVATE_ void *yyalloc(yy_size_t bytes, yyscan_t yyscanner)
{
	return talloc_size(yyscanner, bytes);
}

_PRIVATE_ void *yyrealloc(void *ptr, yy_size_t bytes, yyscan_t yyscanner)
{
	return talloc_realloc_size(yyscanner, ptr, bytes);
}

_PRIVATE_ void yyfree(void *ptr, yyscan_t yyscanner)
{
	if (ptr == yyscanner) {
		talloc_free(yyscanner);
	} else {
		talloc_unlink(yyscanner, ptr);
	}
}

_PRIVATE_ enum CLAIM_TYPE claims_tf_type_from_string(const char *str)
{
	int cmp;

	cmp = strcasecmp(str, "int64");
	if (cmp == 0) {
		return CLAIM_TYPE_INT64;
	}

	cmp = strcasecmp(str, "uint64");
	if (cmp == 0) {
		return CLAIM_TYPE_UINT64;
	}

	cmp = strcasecmp(str, "string");
	if (cmp == 0) {
		return CLAIM_TYPE_STRING;
	}

	cmp = strcasecmp(str, "boolean");
	if (cmp == 0) {
		return CLAIM_TYPE_STRING;
	}

	return 0;
}

static bool claims_tf_rule_verify_conditions(const struct claims_tf_rule *rule)
{
	uint32_t csi;

	/*
	 * TODO: do we need to verify that all
	 * optional condition_set identifiers
	 * are unique?
	 *
	 * At least the powershell commands
	 * on Windows don't verify this.
	 */

	for (csi = 0; csi < rule->num_condition_sets; csi++) {
		const struct claims_tf_condition_set *cs =
			&rule->condition_sets[csi];
		uint32_t ci;

		for (ci = 0; ci < cs->num_conditions; ci++) {
			const struct claims_tf_condition *c =
				&cs->conditions[ci];
			enum CLAIM_TYPE vt;

			if (c->string == NULL) {
				return false;
			}

			if (c->property != CLAIMS_TF_PROPERTY_VALUE_TYPE) {
				continue;
			}

			vt = claims_tf_type_from_string(c->string);
			if (vt == 0) {
				return false;
			}
		}
	}

	return true;
}

static bool claims_tf_rule_verify_vt_action(const struct claims_tf_rule *rule,
				      const struct claims_tf_property *property)
{
	if (property->ref.property == CLAIMS_TF_PROPERTY_INVALID) {
		enum CLAIM_TYPE vt;

		if (property->string == NULL) {
			return false;
		}

		vt = claims_tf_type_from_string(property->string);
		if (vt == 0) {
			return false;
		}

		return true;
	}

	if (property->ref.property != CLAIMS_TF_PROPERTY_VALUE_TYPE) {
		return false;
	}

	return true;
}

static bool claims_tf_rule_verify_action(const struct claims_tf_rule *rule,
				   const struct claims_tf_property *property)
{
	uint32_t csi;

	if (property->ref.property == CLAIMS_TF_PROPERTY_INVALID) {
		if (property->string == NULL) {
			return false;
		}
		return true;
	}

	if (property->ref.identifier == NULL) {
		return false;
	}

	for (csi = 0; csi < rule->num_condition_sets; csi++) {
		const struct claims_tf_condition_set *cs =
			&rule->condition_sets[csi];
		bool ok;

		if (cs->opt_identifier == NULL) {
			continue;
		}

		ok = strequal(property->ref.identifier,
			      cs->opt_identifier);
		if (ok) {
			return true;
		}
	}

	return false;
}

_PUBLIC_ bool claims_tf_rule_set_parse_blob(const DATA_BLOB *blob,
				      TALLOC_CTX *mem_ctx,
				      struct claims_tf_rule_set **_rule_set,
				      char **_error_string)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct claims_tf_parser_state *ctf_ps = NULL;
	yyscan_t scanner = NULL;
	YY_BUFFER_STATE buf = NULL;
	uint32_t ri;
	int rc;

#if __CLAIMS_TF_YY_DEBUG != 0
	__claims_tf_yy_debug = 1;
#endif

	rc = yylex_init(&scanner);
	if (rc != 0) {
		if (_error_string != NULL) {
			*_error_string = talloc_asprintf(mem_ctx,
						"yylex_init failed rc=%d",
						rc);
		}

		TALLOC_FREE(frame);
		return false;
	}

	buf = yy_scan_bytes((const char *)blob->data,
			    blob->length,
			    scanner);
	if (buf == NULL) {
		if (_error_string != NULL) {
			*_error_string = talloc_asprintf(mem_ctx,
						"yy_scan_bytes(length=%zu) failed",
						blob->length);
		}

		yylex_destroy(scanner);
		TALLOC_FREE(frame);
		return false;
	}

	ctf_ps = talloc_zero(frame, struct claims_tf_parser_state);
	if (ctf_ps == NULL) {
		if (_error_string != NULL) {
			*_error_string = talloc_asprintf(mem_ctx,
						"talloc_zero failed");
		}

		yy_delete_buffer(buf, scanner);
		yylex_destroy(scanner);
		TALLOC_FREE(frame);
		return false;
	}

	rc = __claims_tf_yy_parse(ctf_ps, scanner);
	if (rc != 0) {
		if (_error_string != NULL && ctf_ps->error.string != NULL) {
			*_error_string = talloc_asprintf(mem_ctx,
						"__claims_tf_yy_parse() failed rc=%d "
						"fl=%d,fc=%d,ll=%d,lc=%d: %s",
						rc,
						ctf_ps->error.first_line,
						ctf_ps->error.first_column,
						ctf_ps->error.last_line,
						ctf_ps->error.last_column,
						ctf_ps->error.string);
		} else if (_error_string != NULL) {
			*_error_string = talloc_asprintf(mem_ctx,
						"__claims_tf_yy_parse() failed rc=%d",
						rc);
		}

		yy_delete_buffer(buf, scanner);
		yylex_destroy(scanner);
		TALLOC_FREE(frame);
		return false;
	}

	yy_delete_buffer(buf, scanner);
	yylex_destroy(scanner);

	for (ri = 0; ri < ctf_ps->rule_set->num_rules; ri++) {
		const struct claims_tf_rule *r =
			&ctf_ps->rule_set->rules[ri];
		bool ok;

		ok = claims_tf_rule_verify_conditions(r);
		if (!ok) {
			if (_error_string != NULL) {
				*_error_string = talloc_asprintf(mem_ctx,
						"rule[%"PRIu32"] "
						"has invalid conditions",
						ri);
			}
			TALLOC_FREE(frame);
			return false;
		}

		ok = claims_tf_rule_verify_vt_action(r, &r->action.value_type);
		if (!ok) {
			if (_error_string != NULL) {
				*_error_string = talloc_asprintf(mem_ctx,
						"rule[%"PRIu32"] "
						"action.value_type invalid value type specifier",
						ri);
			}
			TALLOC_FREE(frame);
			return false;
		}

		/*
		 * Now verify that identifiers used
		 * in rule actions are also used
		 * as condition_set identifier.
		 */

		ok = claims_tf_rule_verify_action(r, &r->action.type);
		if (!ok) {
			if (_error_string != NULL) {
				*_error_string = talloc_asprintf(mem_ctx,
						"rule[%"PRIu32"] "
						"action.type invalid tidentifier %s",
						ri, r->action.type.ref.identifier);
			}
			TALLOC_FREE(frame);
			return false;
		}

		ok = claims_tf_rule_verify_action(r, &r->action.value);
		if (!ok) {
			if (_error_string != NULL) {
				*_error_string = talloc_asprintf(mem_ctx,
						"rule[%"PRIu32"] "
						"action.value invalid tidentifier %s",
						ri, r->action.type.ref.identifier);
			}
			TALLOC_FREE(frame);
			return false;
		}

		ok = claims_tf_rule_verify_action(r, &r->action.value_type);
		if (!ok) {
			if (_error_string != NULL) {
				*_error_string = talloc_asprintf(mem_ctx,
						"rule[%"PRIu32"] "
						"action.value_type invalid tidentifier %s",
						ri, r->action.type.ref.identifier);
			}
			TALLOC_FREE(frame);
			return false;
		}
	}

	*_rule_set = talloc_move(mem_ctx, &ctf_ps->rule_set);
	TALLOC_FREE(frame);

	if (_error_string != NULL) {
		*_error_string = NULL;
	}

	return true;
}
