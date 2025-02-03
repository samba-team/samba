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

#ifndef _LIBCLI_SECURITY_CLAIMS_TRANSFORMATION_H_
#define _LIBCLI_SECURITY_CLAIMS_TRANSFORMATION_H_

#include "librpc/gen_ndr/claims.h"

struct claims_tf_claim {
	const char *type;
	enum CLAIM_TYPE value_type;
	union {
		int64_t ival;
		uint64_t uval;
		const char *string;
		bool bval;
	} value;
};

bool claims_tf_rule_set_parse_blob(const DATA_BLOB *blob,
				   TALLOC_CTX *mem_ctx,
				   struct claims_tf_rule_set **__rule_set,
				   char **_error_string);

char *claims_tf_policy_wrap_xml(TALLOC_CTX *mem_ctx,
				const char *rules_string);

bool claims_tf_policy_unwrap_xml(const DATA_BLOB *attr_val,
				 DATA_BLOB *rules);

#ifdef CLAIMS_TRANSFORMATION_INTERNALS

struct claims_tf_parser_state {
	struct claims_tf_rule_set *rule_set;
	struct {
		int first_line;
		int first_column;
		int last_line;
		int last_column;
		char *string;
	} error;
};

struct claims_tf_condition_ctr {
	struct claims_tf_condition_ctr *prev;
	struct claims_tf_condition *c1;
	struct claims_tf_condition *c2;
};
struct claims_tf_condition_set_ctr {
	struct claims_tf_condition_set_ctr *prev;
	struct claims_tf_condition_set *set;
};
struct claims_tf_rule_ctr {
	struct claims_tf_rule *rule;
	struct claims_tf_rule_ctr *next;
};

struct claim_copy {
	const char *identifier;
};

struct Cond_oper {
	/*
	 * CLAIMS_TF_YY_EQ               => CLAIMS_TF_CONDITION_OPERATOR_EQ
	 * CLAIMS_TF_YY_NEQ              => CLAIMS_TF_CONDITION_OPERATOR_NEQ
	 * CLAIMS_TF_YY_REGEXP_MATCH     => CLAIMS_TF_CONDITION_OPERATOR_REGEXP_MATCH
	 * CLAIMS_TF_YY_REGEXP_NOT_MATCH => CLAIMS_TF_CONDITION_OPERATOR_REGEXP_NOT_MATCH
	 */
	enum claims_tf_condition_operator operator;
};

struct Literal {
	const char *str;
};

struct claim_prop {
	/*
	 * CLAIMS_TF_YY_{TYPE,VALUE,VALUE_TYPE}
	 * =>
	 * CLAIMS_TF_PROPERTY_{TYPE,VALUE,VALUE_TYPE}
	 *
	 * Here we only have TYPE or VALUE
	 */
	enum claims_tf_property_enum property;
};

struct Expr {
	bool has_literal;
	struct Literal literal;
	struct {
		const char *identifier;
		/*
		 * CLAIMS_TF_YY_{TYPE,VALUE,VALUE_TYPE}
		 * =>
		 * CLAIMS_TF_PROPERTY_{TYPE,VALUE,VALUE_TYPE}
		 *
		 * Here we only have TYPE or VALUE
		 */
		enum claims_tf_property_enum property;
	} claim;
};

struct claim_type_assign {
	struct Expr expr;
};

struct claim_val_type_assign {
	struct Expr expr;
};

struct claim_val_assign {
	struct Expr expr;
};

struct claim_value_assign {
	struct claim_val_type_assign vt;
	struct claim_val_assign val;
};

struct claim_new {
	struct claim_type_assign type;
	struct claim_value_assign value;
};

_PRIVATE_ enum CLAIM_TYPE claims_tf_type_from_string(const char *str);

#endif /* CLAIMS_TRANSFORMATION_INTERNALS */
#endif /* _LIBCLI_SECURITY_CLAIMS_TRANSFORMATION_H_ */
