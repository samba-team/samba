/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004-2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb expression matching
 *
 *  Description: ldb expression matching 
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"


/*
  check if the scope matches in a search result
*/
static int ldb_match_scope(const char *dn, const char *base, enum ldb_scope scope)
{
	size_t dn_len, base_len;

	if (base == NULL) {
		return 1;
	}

	base_len = strlen(base);
	dn_len = strlen(dn);

	if (scope != LDB_SCOPE_ONELEVEL && ldb_dn_cmp(dn, base) == 0) {
		return 1;
	}

	if (base_len+1 >= dn_len) {
		return 0;
	}

	switch (scope) {
	case LDB_SCOPE_BASE:
		break;

	case LDB_SCOPE_ONELEVEL:
		if (ldb_dn_cmp(dn + (dn_len - base_len), base) == 0 &&
		    dn[dn_len - base_len - 1] == ',' &&
		    strchr(dn, ',') == &dn[dn_len - base_len - 1]) {
			return 1;
		}
		break;
		
	case LDB_SCOPE_SUBTREE:
	default:
		if (ldb_dn_cmp(dn + (dn_len - base_len), base) == 0 &&
		    dn[dn_len - base_len - 1] == ',') {
			return 1;
		}
		break;
	}

	return 0;
}


/*
  match a leaf node
*/
static int ldb_match_leaf(struct ldb_context *ldb, 
			  struct ldb_message *msg,
			  struct ldb_parse_tree *tree,
			  const char *base,
			  enum ldb_scope scope)
{
	unsigned int i;
	struct ldb_message_element *el;
	const struct ldb_attrib_handler *h;

	if (!ldb_match_scope(msg->dn, base, scope)) {
		return 0;
	}

	if (ldb_attr_cmp(tree->u.simple.attr, "dn") == 0) {
		if (strcmp(tree->u.simple.value.data, "*") == 0) {
			return 1;
		}
		return ldb_dn_cmp(msg->dn, tree->u.simple.value.data) == 0;
	}

	el = ldb_msg_find_element(msg, tree->u.simple.attr);
	if (el == NULL) {
		return 0;
	}

	if (strcmp(tree->u.simple.value.data, "*") == 0) {
		return 1;
	}

	h = ldb_attrib_handler(ldb, el->name);

	for (i=0;i<el->num_values;i++) {
		if (h->comparison_fn(ldb, ldb, &tree->u.simple.value, 
				     &el->values[i]) == 0) {
			return 1;
		}
	}

	return 0;
}


/*
  bitwise-and comparator
*/
static int ldb_comparator_and(struct ldb_val *v1, struct ldb_val *v2)
{
	uint64_t i1, i2;
	i1 = strtoull(v1->data, NULL, 0);
	i2 = strtoull(v2->data, NULL, 0);
	return ((i1 & i2) == i2);
}

/*
  bitwise-or comparator
*/
static int ldb_comparator_or(struct ldb_val *v1, struct ldb_val *v2)
{
	uint64_t i1, i2;
	i1 = strtoull(v1->data, NULL, 0);
	i2 = strtoull(v2->data, NULL, 0);
	return ((i1 & i2) != 0);
}


/*
  extended match, handles things like bitops
*/
static int ldb_match_extended(struct ldb_context *ldb, 
			      struct ldb_message *msg,
			      struct ldb_parse_tree *tree,
			      const char *base,
			      enum ldb_scope scope)
{
	int i;
	const struct {
		const char *oid;
		int (*comparator)(struct ldb_val *, struct ldb_val *);
	} rules[] = {
		{ LDB_OID_COMPARATOR_AND, ldb_comparator_and},
		{ LDB_OID_COMPARATOR_OR, ldb_comparator_or}
	};
	int (*comp)(struct ldb_val *, struct ldb_val *) = NULL;
	struct ldb_message_element *el;

	if (tree->u.extended.dnAttributes) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "ldb: dnAttributes extended match not supported yet");
		return -1;
	}
	if (tree->u.extended.rule_id == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "ldb: no-rule extended matches not supported yet");
		return -1;
	}
	if (tree->u.extended.attr == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "ldb: no-attribute extended matches not supported yet");
		return -1;
	}

	for (i=0;i<ARRAY_SIZE(rules);i++) {
		if (strcmp(rules[i].oid, tree->u.extended.rule_id) == 0) {
			comp = rules[i].comparator;
			break;
		}
	}
	if (comp == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "ldb: unknown extended rule_id %s\n",
			  tree->u.extended.rule_id);
		return -1;
	}

	/* find the message element */
	el = ldb_msg_find_element(msg, tree->u.extended.attr);
	if (el == NULL) {
		return 0;
	}

	for (i=0;i<el->num_values;i++) {
		int ret = comp(&el->values[i], &tree->u.extended.value);
		if (ret == -1 || ret == 1) return ret;
	}

	return 0;
}

/*
  return 0 if the given parse tree matches the given message. Assumes
  the message is in sorted order

  return 1 if it matches, and 0 if it doesn't match

  this is a recursive function, and does short-circuit evaluation
 */
int ldb_match_message(struct ldb_context *ldb, 
		      struct ldb_message *msg,
		      struct ldb_parse_tree *tree,
		      const char *base,
		      enum ldb_scope scope)
{
	unsigned int i;
	int v;

	switch (tree->operation) {
	case LDB_OP_SIMPLE:
		break;

	case LDB_OP_EXTENDED:
		return ldb_match_extended(ldb, msg, tree, base, scope);

	case LDB_OP_NOT:
		return ! ldb_match_message(ldb, msg, tree->u.not.child, base, scope);

	case LDB_OP_AND:
		for (i=0;i<tree->u.list.num_elements;i++) {
			v = ldb_match_message(ldb, msg, tree->u.list.elements[i],
					       base, scope);
			if (!v) return 0;
		}
		return 1;

	case LDB_OP_OR:
		for (i=0;i<tree->u.list.num_elements;i++) {
			v = ldb_match_message(ldb, msg, tree->u.list.elements[i],
					      base, scope);
			if (v) return 1;
		}
		return 0;
	}

	return ldb_match_leaf(ldb, msg, tree, base, scope);
}
