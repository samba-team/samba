/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

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
 *  Description: ldb expression matching for tdb backend
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"


/*
  see if two ldb_val structures contain the same data
  return 1 for a match, 0 for a mis-match
*/
int ldb_val_equal(const struct ldb_val *v1, const struct ldb_val *v2)
{
	if (v1->length != v2->length) return 0;

	if (v1->length == 0) return 1;

	if (memcmp(v1->data, v2->data, v1->length) == 0) {
		return 1;
	}

	return 0;
}

/*
  check if the scope matches in a search result
*/
static int scope_match(const char *dn, const char *base, enum ldb_scope scope)
{
	size_t dn_len, base_len;

	if (base == NULL) {
		return 1;
	}

	base_len = strlen(base);
	dn_len = strlen(dn);

	if (strcmp(dn, base) == 0) {
		return 1;
	}

	if (base_len+1 >= dn_len) {
		return 0;
	}

	switch (scope) {
	case LDB_SCOPE_BASE:
		break;

	case LDB_SCOPE_ONELEVEL:
		if (strcmp(dn + (dn_len - base_len), base) == 0 &&
		    dn[dn_len - base_len - 1] == ',' &&
		    strchr(dn, ',') == &dn[dn_len - base_len - 1]) {
			return 1;
		}
		break;
		
	case LDB_SCOPE_SUBTREE:
	default:
		if (strcmp(dn + (dn_len - base_len), base) == 0 &&
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
static int match_leaf(struct ldb_context *ldb, 
		      struct ldb_message *msg,
		      struct ldb_parse_tree *tree,
		      const char *base,
		      enum ldb_scope scope)
{
	int i, j;

	if (!scope_match(msg->dn, base, scope)) {
		return 0;
	}

	if (strcmp(tree->u.simple.attr, "dn") == 0) {
		if (strcmp(tree->u.simple.value.data, "*") == 0) {
			return 1;
		}
		return strcmp(msg->dn, tree->u.simple.value.data) == 0;
	}

	for (i=0;i<msg->num_elements;i++) {
		if (strcmp(msg->elements[i].name, tree->u.simple.attr) == 0) {
			if (strcmp(tree->u.simple.value.data, "*") == 0) {
				return 1;
			}
			for (j=0;j<msg->elements[i].num_values;j++) {
				if (ldb_val_equal(&msg->elements[i].values[j], 
						  &tree->u.simple.value)) {
					return 1;
				}
			}
		}
	}

	return 0;
}

/*
  return 0 if the given parse tree matches the given message. Assumes
  the message is in sorted order

  return 1 if it matches, and 0 if it doesn't match

  this is a recursive function, and does short-circuit evaluation
 */
int ldb_message_match(struct ldb_context *ldb, 
		      struct ldb_message *msg,
		      struct ldb_parse_tree *tree,
		      const char *base,
		      enum ldb_scope scope)
{
	int v, i;

	switch (tree->operation) {
	case LDB_OP_SIMPLE:
		break;

	case LDB_OP_NOT:
		return ! ldb_message_match(ldb, msg, tree->u.not.child, base, scope);

	case LDB_OP_AND:
		for (i=0;i<tree->u.list.num_elements;i++) {
			v = ldb_message_match(ldb, msg, tree->u.list.elements[i],
					      base, scope);
			if (!v) return 0;
		}
		return 1;

	case LDB_OP_OR:
		for (i=0;i<tree->u.list.num_elements;i++) {
			v = ldb_message_match(ldb, msg, tree->u.list.elements[i],
					      base, scope);
			if (v) return 1;
		}
		return 0;
	}

	return match_leaf(ldb, msg, tree, base, scope);
}
