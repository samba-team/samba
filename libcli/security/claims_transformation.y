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
#pragma GCC diagnostic ignored "-Wstrict-overflow"

/* forward declarations */
struct claims_tf_parser_state;

static struct claims_tf_rule_set *
claims_tf_rule_set_prepare(struct claims_tf_parser_state *ctf_ps,
			   struct claims_tf_rule_ctr *list);
static struct claims_tf_rule_ctr *
claims_tf_rule_ctr_prepare(struct claims_tf_parser_state *ctf_ps,
			   struct claims_tf_rule *rule,
			   struct claims_tf_rule_ctr *next);
static struct claims_tf_rule *
claims_tf_rule_prepare(struct claims_tf_parser_state *ctf_ps,
		       const struct claim_copy *c_copy,
		       const struct claim_new *c_new);
static struct claims_tf_rule *
claims_tf_rule_attach_conditions(struct claims_tf_rule *rule,
				 struct claims_tf_condition_set_ctr *list);
static struct claims_tf_condition_set_ctr *
claims_tf_condition_set_ctr_prepare(struct claims_tf_parser_state *ctf_ps,
				    struct claims_tf_condition_set *set,
				    struct claims_tf_condition_set_ctr *prev);
static struct claims_tf_condition_set *
claims_tf_condition_set_prepare(struct claims_tf_parser_state *ctf_ps,
				const struct claims_tf_condition_ctr *list,
				const char *identifier);
static struct claims_tf_condition_ctr *
claims_tf_condition_ctr_prepare(struct claims_tf_parser_state *ctf_ps,
				struct claims_tf_condition *c1,
				struct claims_tf_condition *c2);
static struct claims_tf_condition_ctr *
claims_tf_condition_ctr_attach_prev(struct claims_tf_condition_ctr *ctr,
				    struct claims_tf_condition_ctr *prev);
static struct claims_tf_condition *
claims_tf_condition_prepare(struct claims_tf_parser_state *ctf_ps,
			    enum claims_tf_property_enum property,
			    enum claims_tf_condition_operator operator,
			    const struct Literal *expr);

static void __claims_tf_yy_error(__CLAIMS_TF_YY_LTYPE *llocp,
				 struct claims_tf_parser_state *ctf_ps,
				 void *yyscanner,
				 const char *str);

_PRIVATE_ int __claims_tf_yy_lex(__CLAIMS_TF_YY_STYPE * yylval_param,
				 __CLAIMS_TF_YY_LTYPE * yylloc_param ,
				 struct claims_tf_parser_state *ctf_ps,
				 void *yyscanner);
%}

%code provides {
}

%union {
	int ival;
	const char *sval;
	struct claims_tf_rule_set *rule_set;
	struct claims_tf_rule_ctr *rule_ctr;
	struct claims_tf_rule *rule;
	struct claims_tf_condition_set_ctr *condition_set_ctr;
	struct claims_tf_condition_set *condition_set;
	struct claims_tf_condition_ctr *condition_ctr;
	struct claims_tf_condition *condition;
	struct claim_prop prop;
	struct Cond_oper oper;
	struct Expr expr;
	struct Literal literal;
	struct claim_copy c_copy;
	struct claim_new c_new;
	struct claim_value_assign value_assign;
	struct claim_val_assign val_assign;
	struct claim_val_type_assign val_type_assign;
	struct claim_type_assign type_assign;
}

%define api.prefix {__claims_tf_yy_}
%define parse.error verbose

/* %define parse.trace */

%define api.pure full
%locations
%lex-param {struct claims_tf_parser_state *ctf_ps}
%lex-param {void *yyscanner}
%parse-param {struct claims_tf_parser_state *ctf_ps}
%parse-param {void *yyscanner}


%type <ival> CLAIMS_TF_YY_TYPE CLAIMS_TF_YY_VALUE CLAIMS_TF_YY_EQ CLAIMS_TF_YY_NEQ CLAIMS_TF_YY_REGEXP_MATCH CLAIMS_TF_YY_REGEXP_NOT_MATCH
%type <sval> CLAIMS_TF_YY_IDENTIFIER CLAIMS_TF_YY_STRING
%type <rule_set> Rule_set
%type <rule_ctr> Rules
%type <rule> Rule Issue_params Rule_action Rule_body
%type <condition_set_ctr> Conditions Sel_condition_list
%type <condition_set> Sel_condition
%type <condition_ctr> Sel_condition_body Opt_cond_list Cond_list Cond Value_cond
%type <condition> Type_cond Val_cond Val_type_cond
%type <prop> claim_prop
%type <oper> Cond_oper
%type <expr> Expr
%type <literal> Literal
%type <c_copy> claim_copy
%type <c_new> claim_new claim_prop_assign_list
%type <value_assign> claim_value_assign
%type <val_assign> claim_val_assign
%type <val_type_assign> claim_val_type_assign
%type <type_assign> claim_type_assign

%token CLAIMS_TF_YY_IMPLY
%token CLAIMS_TF_YY_SEMICOLON
%token CLAIMS_TF_YY_COLON
%token CLAIMS_TF_YY_COMMA
%token CLAIMS_TF_YY_DOT
%token CLAIMS_TF_YY_O_SQ_BRACKET
%token CLAIMS_TF_YY_C_SQ_BRACKET
%token CLAIMS_TF_YY_O_BRACKET
%token CLAIMS_TF_YY_C_BRACKET
%token CLAIMS_TF_YY_EQ
%token CLAIMS_TF_YY_NEQ
%token CLAIMS_TF_YY_REGEXP_MATCH
%token CLAIMS_TF_YY_REGEXP_NOT_MATCH
%token CLAIMS_TF_YY_ASSIGN
%token CLAIMS_TF_YY_AND
%token CLAIMS_TF_YY_ISSUE
%token CLAIMS_TF_YY_TYPE
%token CLAIMS_TF_YY_VALUE
%token CLAIMS_TF_YY_VALUE_TYPE
%token CLAIMS_TF_YY_CLAIM
%token CLAIMS_TF_YY_IDENTIFIER
%token CLAIMS_TF_YY_STRING

%%

Rule_set:
%empty {
	$$ = claims_tf_rule_set_prepare(ctf_ps, NULL);
	if ($$ == NULL) {
		YYERROR;
	}
}
| Rules {
	$$ = claims_tf_rule_set_prepare(ctf_ps, $1);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

Rules:
Rule {
	$$ = claims_tf_rule_ctr_prepare(ctf_ps, $1, NULL);
	if ($$ == NULL) {
		YYERROR;
	}
}
|
Rule Rules {
	$$ = claims_tf_rule_ctr_prepare(ctf_ps, $1, $2);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

Rule:
Rule_body {
	$$ = $1;
}
;

Rule_body:
Conditions CLAIMS_TF_YY_IMPLY Rule_action CLAIMS_TF_YY_SEMICOLON {
	$$ = claims_tf_rule_attach_conditions($3, $1);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

Conditions:
%empty {
	$$ = NULL;
}
|
Sel_condition_list {
	$$ = $1;
}
;

Sel_condition_list:
Sel_condition {
	$$ = claims_tf_condition_set_ctr_prepare(ctf_ps, $1, NULL);
	if ($$ == NULL) {
		YYERROR;
	}
}
|
Sel_condition_list CLAIMS_TF_YY_AND Sel_condition {
	$$ = claims_tf_condition_set_ctr_prepare(ctf_ps, $3, $1);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

Sel_condition:
Sel_condition_body {
	$$ = claims_tf_condition_set_prepare(ctf_ps, $1, NULL);
	if ($$ == NULL) {
		YYERROR;
	}
}
|
CLAIMS_TF_YY_IDENTIFIER CLAIMS_TF_YY_COLON Sel_condition_body {
	if ($1 == NULL) {
		YYERROR;
	}
	$$ = claims_tf_condition_set_prepare(ctf_ps, $3, $1);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

Sel_condition_body:
CLAIMS_TF_YY_O_SQ_BRACKET Opt_cond_list CLAIMS_TF_YY_C_SQ_BRACKET {
	$$ = $2;
}
;

Opt_cond_list:
%empty {
	$$ = NULL;
}
|
Cond_list {
	$$ = $1;
}
;

Cond_list:
Cond {
	$$ = $1;
}
|
Cond_list CLAIMS_TF_YY_COMMA Cond {
	$$ = claims_tf_condition_ctr_attach_prev($3, $1);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

Cond:
Value_cond {
	$$ = $1;
}
|
Type_cond {
	$$ = claims_tf_condition_ctr_prepare(ctf_ps, $1, NULL);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

Type_cond:
CLAIMS_TF_YY_TYPE Cond_oper Literal {
	$$ = claims_tf_condition_prepare(ctf_ps,
					 CLAIMS_TF_PROPERTY_TYPE,
					 $2.operator,
					 &$3);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

Value_cond:
Val_cond CLAIMS_TF_YY_COMMA Val_type_cond {
	$$ = claims_tf_condition_ctr_prepare(ctf_ps, $1, $3);
	if ($$ == NULL) {
		YYERROR;
	}
}
|
Val_type_cond CLAIMS_TF_YY_COMMA Val_cond {
	$$ = claims_tf_condition_ctr_prepare(ctf_ps, $1, $3);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

Val_cond:
CLAIMS_TF_YY_VALUE Cond_oper Literal {
	$$ = claims_tf_condition_prepare(ctf_ps,
					 CLAIMS_TF_PROPERTY_VALUE,
					 $2.operator,
					 &$3);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

Val_type_cond:
CLAIMS_TF_YY_VALUE_TYPE Cond_oper Literal {
	$$ = claims_tf_condition_prepare(ctf_ps,
					 CLAIMS_TF_PROPERTY_VALUE_TYPE,
					 $2.operator,
					 &$3);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

claim_prop:
CLAIMS_TF_YY_TYPE {
	$$ = (struct claim_prop) { .property = CLAIMS_TF_PROPERTY_TYPE, };
}
|
CLAIMS_TF_YY_VALUE {
	$$ = (struct claim_prop) { .property = CLAIMS_TF_PROPERTY_VALUE, };
}
|
CLAIMS_TF_YY_VALUE_TYPE {
	$$ = (struct claim_prop) { .property = CLAIMS_TF_PROPERTY_VALUE_TYPE, };
}
;

Cond_oper:
CLAIMS_TF_YY_EQ {
	$$ = (struct Cond_oper) { .operator = CLAIMS_TF_CONDITION_OPERATOR_EQ, };
}
|
CLAIMS_TF_YY_NEQ {
	$$ = (struct Cond_oper) { .operator = CLAIMS_TF_CONDITION_OPERATOR_NEQ, };
}
|
CLAIMS_TF_YY_REGEXP_MATCH {
	$$ = (struct Cond_oper) { .operator = CLAIMS_TF_CONDITION_OPERATOR_REGEXP_MATCH, };
}
|
CLAIMS_TF_YY_REGEXP_NOT_MATCH {
	$$ = (struct Cond_oper) { .operator = CLAIMS_TF_CONDITION_OPERATOR_REGEXP_NOT_MATCH, };
}
;

Expr:
Literal {
	$$ = (struct Expr) {
		.has_literal = true,
		.literal = $1,
	};
}
|
CLAIMS_TF_YY_IDENTIFIER CLAIMS_TF_YY_DOT claim_prop {
	if ($1 == NULL) {
		YYERROR;
	}
	$$ = (struct Expr) {
		.claim = {
			.identifier = $1,
			.property = $3.property,
		},
	};
}
;

Literal:
CLAIMS_TF_YY_STRING {
	$$ = (struct Literal) { .str = $1, };
}
;

Rule_action:
CLAIMS_TF_YY_ISSUE CLAIMS_TF_YY_O_BRACKET Issue_params CLAIMS_TF_YY_C_BRACKET {
	$$ = $3;
}
;

Issue_params:
claim_copy {
	$$ = claims_tf_rule_prepare(ctf_ps, &$1, NULL);
	if ($$ == NULL) {
		YYERROR;
	}
}
|
claim_new {
	$$ = claims_tf_rule_prepare(ctf_ps, NULL, &$1);
	if ($$ == NULL) {
		YYERROR;
	}
}
;

claim_copy:
CLAIMS_TF_YY_CLAIM CLAIMS_TF_YY_ASSIGN CLAIMS_TF_YY_IDENTIFIER {
	$$ = (struct claim_copy) { .identifier = $3, };
}
;

claim_new:
claim_prop_assign_list {
	$$ = $1;
}
;

claim_prop_assign_list:
claim_value_assign CLAIMS_TF_YY_COMMA claim_type_assign {
	$$ = (struct claim_new) {
		.type = $3,
		.value = $1,
	};
}
|
claim_type_assign CLAIMS_TF_YY_COMMA claim_value_assign {
	$$ = (struct claim_new) {
		.type = $1,
		.value = $3,
	};
}
;

claim_value_assign:
claim_val_assign CLAIMS_TF_YY_COMMA claim_val_type_assign {
	$$ = (struct claim_value_assign) {
		.vt = $3,
		.val = $1,
	};
}
|
claim_val_type_assign CLAIMS_TF_YY_COMMA claim_val_assign {
	$$ = (struct claim_value_assign) {
		.vt = $1,
		.val = $3,
	};
}
;

claim_val_assign:
CLAIMS_TF_YY_VALUE CLAIMS_TF_YY_ASSIGN Expr {
	$$ = (struct claim_val_assign) { .expr = $3, };
}
;

claim_val_type_assign:
CLAIMS_TF_YY_VALUE_TYPE CLAIMS_TF_YY_ASSIGN Expr {
	if ($3.has_literal) {
		const char *lstr = $3.literal.str;
		enum CLAIM_TYPE vt;

		if (lstr == NULL) {
			YYERROR;
		}

		vt = claims_tf_type_from_string(lstr);
		if (vt == 0) {
			ctf_ps->error.string = talloc_asprintf(ctf_ps,
							       "Invalid "
							       "ValueType "
							       "string[%s]",
							       lstr);
			YYERROR;
		}
	} else {
		if ($3.claim.property != CLAIMS_TF_PROPERTY_VALUE_TYPE) {
			const char *istr = $3.claim.identifier;

			if (istr == NULL) {
				istr = "<NULL>";
			}

			ctf_ps->error.string = talloc_asprintf(ctf_ps,
							       "ValueType "
							       "requires "
							       "%s.ValueType",
							       istr);
			YYERROR;
		}
	}
	$$ = (struct claim_val_type_assign) { .expr = $3, };
}
;

claim_type_assign:
CLAIMS_TF_YY_TYPE CLAIMS_TF_YY_ASSIGN Expr {
	$$ = (struct claim_type_assign) { .expr = $3, };
}
;


%%

static struct claims_tf_rule_set *
claims_tf_rule_set_prepare(struct claims_tf_parser_state *ctf_ps,
			   struct claims_tf_rule_ctr *list)
{
	struct claims_tf_rule_set *rule_set = NULL;
	struct claims_tf_rule_ctr *cr = NULL;
	size_t num_rules = 0;
	struct claims_tf_rule *rules = NULL;
	size_t i;

	if (ctf_ps == NULL) {
		return NULL;
	}
	if (ctf_ps->rule_set != NULL) {
		return NULL;
	}

	rule_set = talloc_zero(ctf_ps,
			       struct claims_tf_rule_set);
	if (rule_set == NULL) {
		return NULL;
	}

	for (cr = list; cr != NULL; cr = cr->next) {
		if (cr->rule == NULL) {
			TALLOC_FREE(rule_set);
			return NULL;
		}

		num_rules += 1;
	}

	if (num_rules >= UINT32_MAX) {
		TALLOC_FREE(rule_set);
		return NULL;
	}
	if (num_rules > 0) {
		rules = talloc_zero_array(rule_set,
					  struct claims_tf_rule,
					  num_rules);
		if (rules == NULL) {
			TALLOC_FREE(rule_set);
			return NULL;
		}
	}

	i = 0;
	for (cr = list; cr != NULL; cr = cr->next) {
		SMB_ASSERT(i < num_rules);
		talloc_steal(rule_set, cr->rule);
		rules[i] = *cr->rule;
		i += 1;
	}
	SMB_ASSERT(i == num_rules);
	rule_set->num_rules = num_rules;
	rule_set->rules = rules;

	ctf_ps->rule_set = rule_set;
	return rule_set;
}

static bool claims_tf_property_from_expr(TALLOC_CTX *mem_ctx,
					 const struct Expr *expr,
					 struct claims_tf_property *prop)
{
	if (expr->has_literal) {
		if (expr->literal.str == NULL) {
			return false;
		}

		*prop = (struct claims_tf_property) {
			.string = talloc_strdup(mem_ctx, expr->literal.str),
		};
		if (prop->string == NULL) {
			return false;
		}

		return true;
	}

	if (expr->claim.identifier == NULL) {
		return false;
	}

	*prop = (struct claims_tf_property) {
		.ref = {
			.identifier = talloc_strdup(mem_ctx,
						    expr->claim.identifier),
			.property = expr->claim.property,
		},
	};
	if (prop->ref.identifier == NULL) {
		return false;
	}

	return true;
}

static struct claims_tf_rule_ctr *
claims_tf_rule_ctr_prepare(struct claims_tf_parser_state *ctf_ps,
			   struct claims_tf_rule *rule,
			   struct claims_tf_rule_ctr *next)
{
	struct claims_tf_rule_ctr *rule_ctr = NULL;

	if (ctf_ps == NULL) {
		return NULL;
	}

	rule_ctr = talloc_zero(ctf_ps, struct claims_tf_rule_ctr);
	if (rule_ctr == NULL) {
		return NULL;
	}

	rule_ctr->rule = talloc_steal(rule_ctr, rule);
	rule_ctr->next = talloc_steal(rule_ctr, next);

	return rule_ctr;
}

static struct claims_tf_rule *
claims_tf_rule_prepare(struct claims_tf_parser_state *ctf_ps,
		       const struct claim_copy *c_copy,
		       const struct claim_new *c_new)
{
	struct claims_tf_rule *rule = NULL;
	const struct Expr *type_expr = NULL;
	const struct Expr *vt_expr = NULL;
	const struct Expr *val_expr = NULL;
	bool ok;

	if (ctf_ps == NULL) {
		return NULL;
	}

	rule = talloc_zero(ctf_ps, struct claims_tf_rule);
	if (rule == NULL) {
		return NULL;
	}

	if (c_copy != NULL) {
		const char *identifier = NULL;

		if (c_copy->identifier == NULL) {
			TALLOC_FREE(rule);
			return NULL;
		}

		identifier = talloc_strdup(rule, c_copy->identifier);
		if (identifier == NULL) {
			TALLOC_FREE(rule);
			return NULL;
		}

		/*
		 * Copy all properties from the given claim identifier
		 */
		rule->action.type.ref = (struct claims_tf_property_ref) {
			.identifier = identifier,
			.property = CLAIMS_TF_PROPERTY_TYPE,
		};
		rule->action.value_type.ref = (struct claims_tf_property_ref) {
			.identifier = identifier,
			.property = CLAIMS_TF_PROPERTY_VALUE_TYPE,
		};
		rule->action.value.ref = (struct claims_tf_property_ref) {
			.identifier = identifier,
			.property = CLAIMS_TF_PROPERTY_VALUE,
		};

		return rule;
	}

	if (c_new == NULL) {
		TALLOC_FREE(rule);
		return NULL;
	}

	type_expr = &c_new->type.expr;
	vt_expr = &c_new->value.vt.expr;
	val_expr = &c_new->value.val.expr;

	ok = claims_tf_property_from_expr(rule, type_expr, &rule->action.type);
	if (!ok) {
		TALLOC_FREE(rule);
		return NULL;
	}

	ok = claims_tf_property_from_expr(rule, vt_expr, &rule->action.value_type);
	if (!ok) {
		TALLOC_FREE(rule);
		return NULL;
	}

	ok = claims_tf_property_from_expr(rule, val_expr, &rule->action.value);
	if (!ok) {
		TALLOC_FREE(rule);
		return NULL;
	}

	return rule;
}

static struct claims_tf_rule *
claims_tf_rule_attach_conditions(struct claims_tf_rule *rule,
				 struct claims_tf_condition_set_ctr *list)
{
	struct claims_tf_condition_set_ctr *cl = NULL;
	size_t num_condition_sets = 0;
	struct claims_tf_condition_set *condition_sets = NULL;
	size_t i;

	if (rule == NULL) {
		return NULL;
	}

	for (cl = list; cl != NULL; cl = cl->prev) {
		if (cl->set == NULL) {
			TALLOC_FREE(rule);
			return NULL;
		}
		num_condition_sets += 1;
	}

	if (num_condition_sets >= UINT32_MAX) {
		TALLOC_FREE(rule);
		return NULL;
	}

	if (num_condition_sets != 0) {
		condition_sets = talloc_zero_array(rule,
						   struct claims_tf_condition_set,
						   num_condition_sets);
		if (condition_sets == NULL) {
			TALLOC_FREE(rule);
			return NULL;
		}
	}

	/*
	 * list is a list from tail to head.
	 *
	 * But we want rule->condition_sets to have
	 * head at index 0.
	 */
	i = num_condition_sets;
	for (cl = list; cl != NULL; cl = cl->prev) {
		SMB_ASSERT(i > 0);
		i -= 1;
		talloc_steal(rule, cl->set);
		condition_sets[i] = *cl->set;
	}
	SMB_ASSERT(i == 0);
	rule->num_condition_sets = num_condition_sets;
	rule->condition_sets = condition_sets;

	return rule;
}

static struct claims_tf_condition_set_ctr *
claims_tf_condition_set_ctr_prepare(struct claims_tf_parser_state *ctf_ps,
				    struct claims_tf_condition_set *set,
				    struct claims_tf_condition_set_ctr *prev)
{
	struct claims_tf_condition_set_ctr *condition_set_ctr = NULL;

	if (ctf_ps == NULL) {
		return NULL;
	}

	condition_set_ctr = talloc_zero(ctf_ps, struct claims_tf_condition_set_ctr);
	if (condition_set_ctr == NULL) {
		return NULL;
	}

	condition_set_ctr->set = talloc_steal(condition_set_ctr, set);
	condition_set_ctr->prev = talloc_steal(condition_set_ctr, prev);

	return condition_set_ctr;
}

static struct claims_tf_condition_set *
claims_tf_condition_set_prepare(struct claims_tf_parser_state *ctf_ps,
				const struct claims_tf_condition_ctr *list,
				const char *identifier)
{
	struct claims_tf_condition_set *condition_set = NULL;
	const struct claims_tf_condition_ctr *cl = NULL;
	size_t num_conditions = 0;
	struct claims_tf_condition *conditions = NULL;
	size_t i;

	if (ctf_ps == NULL) {
		return NULL;
	}

	condition_set = talloc_zero(ctf_ps, struct claims_tf_condition_set);
	if (condition_set == NULL) {
		return NULL;
	}

	if (identifier != NULL) {
		condition_set->opt_identifier = talloc_strdup(condition_set,
							      identifier);
		if (condition_set->opt_identifier == NULL) {
			TALLOC_FREE(condition_set);
			return NULL;
		}
	}

	for (cl = list; cl != NULL; cl = cl->prev) {
		if (cl->c1 == NULL) {
			TALLOC_FREE(condition_set);
			return NULL;
		}

		if (cl->c2 != NULL) {
			num_conditions += 1;
		}
		num_conditions += 1;
	}

	if (num_conditions >= UINT32_MAX) {
		TALLOC_FREE(condition_set);
		return NULL;
	}

	if (num_conditions > 0) {
		conditions = talloc_zero_array(condition_set,
					       struct claims_tf_condition,
					       num_conditions);
		if (conditions == NULL) {
			TALLOC_FREE(condition_set);
			return NULL;
		}
	}

	/*
	 * list is a list from tail to head.
	 *
	 * But we want rule->condition_sets to have
	 * head at index 0.
	 */
	i = num_conditions;
	for (cl = list; cl != NULL; cl = cl->prev) {
		if (cl->c2 != NULL) {
			SMB_ASSERT(i > 0);
			i -= 1;
			talloc_steal(condition_set, cl->c2);
			conditions[i] = *cl->c2;
		}
		SMB_ASSERT(i > 0);
		i -= 1;
		talloc_steal(condition_set, cl->c1);
		conditions[i] = *cl->c1;
	}
	SMB_ASSERT(i == 0);
	condition_set->num_conditions = num_conditions;
	condition_set->conditions = conditions;

	return condition_set;
}

static struct claims_tf_condition_ctr *
claims_tf_condition_ctr_prepare(struct claims_tf_parser_state *ctf_ps,
				struct claims_tf_condition *c1,
				struct claims_tf_condition *c2)
{
	struct claims_tf_condition_ctr *condition_ctr = NULL;

	if (ctf_ps == NULL) {
		return NULL;
	}

	condition_ctr = talloc_zero(ctf_ps, struct claims_tf_condition_ctr);
	if (condition_ctr == NULL) {
		return NULL;
	}

	condition_ctr->c1 = talloc_steal(condition_ctr, c1);
	condition_ctr->c2 = talloc_steal(condition_ctr, c2);

	return condition_ctr;
}

static struct claims_tf_condition_ctr *
claims_tf_condition_ctr_attach_prev(struct claims_tf_condition_ctr *ctr,
				    struct claims_tf_condition_ctr *prev)
{
	ctr->prev = talloc_steal(ctr, prev);
	return ctr;
}

static struct claims_tf_condition *
claims_tf_condition_prepare(struct claims_tf_parser_state *ctf_ps,
			    enum claims_tf_property_enum property,
			    enum claims_tf_condition_operator operator,
			    const struct Literal *expr)
{
	struct claims_tf_condition *condition = NULL;
	const char *match = NULL;

	if (ctf_ps == NULL) {
		return NULL;
	}

	condition = talloc_zero(ctf_ps, struct claims_tf_condition);
	if (condition == NULL) {
		return NULL;
	}

	match = expr->str;

	if (match == NULL) {
		TALLOC_FREE(condition);
		return NULL;
	}

	if (property == CLAIMS_TF_PROPERTY_VALUE_TYPE) {
		enum CLAIM_TYPE vt;

		vt = claims_tf_type_from_string(match);
		if (vt == 0) {
			ctf_ps->error.string = talloc_asprintf(ctf_ps,
							       "Invalid "
							       "ValueType "
							       "string[%s]",
							       match);
			TALLOC_FREE(condition);
			return NULL;
		}
	}

	condition->property = property;
	condition->operator = operator;
	condition->string = talloc_strdup(condition, match);
	if (condition->string == NULL) {
		TALLOC_FREE(condition);
		return NULL;
	}

	return condition;
}

static void __claims_tf_yy_error(__CLAIMS_TF_YY_LTYPE *llocp,
				 struct claims_tf_parser_state *ctf_ps,
				 void *yyscanner,
				 const char *str)
{
	ctf_ps->error.first_line = llocp->first_line;
	ctf_ps->error.first_column = llocp->first_column;
	ctf_ps->error.last_line = llocp->last_line;
	ctf_ps->error.last_column = llocp->last_column;
	ctf_ps->error.string = talloc_strdup(ctf_ps, str);
}
