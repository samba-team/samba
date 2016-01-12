/*
   Unix SMB/CIFS implementation.

   ldb database library - Extended match rules

   Copyright (C) 2014 Samuel Cabrero <samuelcabrero@kernevil.me>

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

#include "includes.h"
#include <ldb_module.h>
#include "dsdb/samdb/samdb.h"
#include "ldb_matching_rules.h"

static int ldb_eval_transitive_filter_helper(TALLOC_CTX *mem_ctx,
					     struct ldb_context *ldb,
					     const char *attr,
					     const struct dsdb_dn *dn_to_match,
					     const char *dn_oid,
					     struct dsdb_dn *to_visit,
					     struct dsdb_dn ***visited,
					     unsigned int *visited_count,
					     bool *matched)
{
	TALLOC_CTX *tmp_ctx;
	int ret, i, j;
	struct ldb_result *res;
	struct ldb_message *msg;
	struct ldb_message_element *el;
	const char *attrs[] = { attr, NULL };

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Fetch the entry to_visit
	 *
	 * NOTE: This is a new LDB search from the TOP of the module
	 * stack.  This means that this search runs the whole stack
	 * from top to bottom.
	 *
	 * This may seem to be in-efficient, but it is also the only
	 * way to ensure that the ACLs for this search are applied
	 * correctly.
	 *
	 * Note also that we don't have the original request
	 * here, so we can not apply controls or timeouts here.
	 */
	ret = dsdb_search_dn(ldb, tmp_ctx, &res, to_visit->dn, attrs, 0);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}
	if (res->count != 1) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	msg = res->msgs[0];

	/* Fetch the attribute to match from the entry being visited */
	el = ldb_msg_find_element(msg, attr);
	if (el == NULL) {
		/* This entry does not have the attribute to match */
		talloc_free(tmp_ctx);
		*matched = false;
		return LDB_SUCCESS;
	}

	/*
	 * If the value to match is present in the attribute values of the
	 * current entry being visited, set matched to true and return OK
	 */
	for (i=0; i<el->num_values; i++) {
		struct dsdb_dn *dn;
		dn = dsdb_dn_parse(tmp_ctx, ldb, &el->values[i], dn_oid);
		if (dn == NULL) {
			talloc_free(tmp_ctx);
			*matched = false;
			return LDB_ERR_INVALID_DN_SYNTAX;
		}

		if (ldb_dn_compare(dn_to_match->dn, dn->dn) == 0) {
			talloc_free(tmp_ctx);
			*matched = true;
			return LDB_SUCCESS;
		}
	}

	/*
	 * If arrived here, the value to match is not in the values of the
	 * entry being visited. Add the entry being visited (to_visit)
	 * to the visited array. The array is (re)allocated in the parent
	 * memory context.
	 */
	if (visited == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	} else if (*visited == NULL) {
		*visited = talloc_array(mem_ctx, struct dsdb_dn *, 1);
		if (*visited == NULL) {
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		(*visited)[0] = to_visit;
		(*visited_count) = 1;
	} else {
		*visited = talloc_realloc(mem_ctx, *visited, struct dsdb_dn *,
					 (*visited_count) + 1);
		if (*visited == NULL) {
			talloc_free(tmp_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		(*visited)[(*visited_count)] = to_visit;
		(*visited_count)++;
	}

	/*
	 * steal to_visit into visited array context, as it has to live until
	 * the array is freed.
	 */
	talloc_steal(*visited, to_visit);

	/*
	 * Iterate over the values of the attribute of the entry being
	 * visited (to_visit) and follow them, calling this function
	 * recursively.
	 * If the value is in the visited array, skip it.
	 * Otherwise, follow the link and visit it.
	 */
	for (i=0; i<el->num_values; i++) {
		struct dsdb_dn *next_to_visit;
		bool skip = false;

		next_to_visit = dsdb_dn_parse(tmp_ctx, ldb, &el->values[i], dn_oid);
		if (next_to_visit == NULL) {
			talloc_free(tmp_ctx);
			*matched = false;
			return LDB_ERR_INVALID_DN_SYNTAX;
		}

		/*
		 * If the value is already in the visited array, skip it.
		 * Note the last element of the array is ignored because it is
		 * the current entry DN.
		 */
		for (j=0; j < (*visited_count) - 1; j++) {
			struct dsdb_dn *visited_dn = (*visited)[j];
			if (ldb_dn_compare(visited_dn->dn,
					   next_to_visit->dn) == 0) {
				skip = true;
				break;
			}
		}
		if (skip) {
			talloc_free(next_to_visit);
			continue;
		}

		/* If the value is not in the visited array, evaluate it */
		ret = ldb_eval_transitive_filter_helper(tmp_ctx, ldb, attr,
							dn_to_match, dn_oid,
							next_to_visit,
							visited, visited_count,
							matched);
		if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ret;
		}
		if (*matched) {
			talloc_free(tmp_ctx);
			return LDB_SUCCESS;
		}
	}

	talloc_free(tmp_ctx);
	*matched = false;
	return LDB_SUCCESS;
}

/*
 * This function parses the linked attribute value to match, whose syntax
 * will be one of the different DN syntaxes, into a ldb_dn struct.
 */
static int ldb_eval_transitive_filter(TALLOC_CTX *mem_ctx,
				      struct ldb_context *ldb,
				      const char *attr,
				      const struct ldb_val *value_to_match,
				      struct dsdb_dn *current_object_dn,
				      bool *matched)
{
	const struct dsdb_schema *schema;
	const struct dsdb_attribute *schema_attr;
	struct dsdb_dn *dn_to_match;
	const char *dn_oid;
	unsigned int count;
	struct dsdb_dn **visited;

	schema = dsdb_get_schema(ldb, mem_ctx);
	if (schema == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	schema_attr = dsdb_attribute_by_lDAPDisplayName(schema, attr);
	if (schema_attr == NULL) {
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	/* This is the DN syntax of the attribute being matched */
	dn_oid = schema_attr->syntax->ldap_oid;

	/*
	 * Build a ldb_dn struct holding the value to match, which is the
	 * value entered in the search filter
	 */
	dn_to_match = dsdb_dn_parse(mem_ctx, ldb, value_to_match, dn_oid);
	if (dn_to_match == NULL) {
		*matched = false;
		return LDB_SUCCESS;
	}

	return ldb_eval_transitive_filter_helper(mem_ctx, ldb, attr,
						 dn_to_match, dn_oid,
						 current_object_dn,
						 &visited, &count, matched);
}

/*
 * This rule provides recursive search of a link attribute
 *
 * Documented in [MS-ADTS] section 3.1.1.3.4.4.3 LDAP_MATCHING_RULE_TRANSITIVE_EVAL
 * This allows a search filter such as:
 *
 * member:1.2.840.113556.1.4.1941:=cn=user,cn=users,dc=samba,dc=example,dc=com
 *
 * This searches not only the member attribute, but also any member
 * attributes that point at an object with this member in them.  All the
 * various DN syntax types are supported, not just plain DNs.
 *
 */
static int ldb_comparator_trans(struct ldb_context *ldb,
				const char *oid,
				const struct ldb_message *msg,
				const char *attribute_to_match,
				const struct ldb_val *value_to_match,
				bool *matched)
{
	const struct dsdb_schema *schema;
	const struct dsdb_attribute *schema_attr;
	struct ldb_dn *msg_dn;
	struct dsdb_dn *dsdb_msg_dn;
	TALLOC_CTX *tmp_ctx;
	int ret;

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * If the target attribute to match is not a linked attribute, then
	 * the filter evaluates to undefined
	 */
	schema = dsdb_get_schema(ldb, tmp_ctx);
	if (schema == NULL) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	schema_attr = dsdb_attribute_by_lDAPDisplayName(schema, attribute_to_match);
	if (schema_attr == NULL) {
		talloc_free(tmp_ctx);
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	/*
	 * This extended match filter is only valid for linked attributes,
	 * following the MS definition (the schema attribute has a linkID
	 * defined). See dochelp request 114111212024789 on cifs-protocols
	 * mailing list.
	 */
	if (schema_attr->linkID == 0) {
		*matched = false;
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	/* Duplicate original msg dn as the msg must not be modified */
	msg_dn = ldb_dn_copy(tmp_ctx, msg->dn);
	if (msg_dn == NULL) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * Build a dsdb dn from the message copied DN, which should be a plain
	 * DN syntax.
	 */
	dsdb_msg_dn = dsdb_dn_construct(tmp_ctx, msg_dn, data_blob_null,
					LDB_SYNTAX_DN);
	if (dsdb_msg_dn == NULL) {
		*matched = false;
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	ret = ldb_eval_transitive_filter(tmp_ctx, ldb,
					 attribute_to_match,
					 value_to_match,
					 dsdb_msg_dn, matched);
	talloc_free(tmp_ctx);
	return ret;
}


int ldb_register_samba_matching_rules(struct ldb_context *ldb)
{
	struct ldb_extended_match_rule *transitive_eval;
	int ret;

	transitive_eval = talloc_zero(ldb, struct ldb_extended_match_rule);
	transitive_eval->oid = SAMBA_LDAP_MATCH_RULE_TRANSITIVE_EVAL;
	transitive_eval->callback = ldb_comparator_trans;
	ret = ldb_register_extended_match_rule(ldb, transitive_eval);
	if (ret != LDB_SUCCESS) {
		talloc_free(transitive_eval);
		return ret;
	}

	return LDB_SUCCESS;
}
