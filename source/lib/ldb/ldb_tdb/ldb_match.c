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
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/ldb_tdb/ldb_tdb.h"
#include "ldb/include/ldb_parse.h"
#include <fnmatch.h>

/*
  see if two ldb_val structures contain the same data as integers
  return 1 for a match, 0 for a mis-match
*/
static int ltdb_val_equal_integer(const struct ldb_val *v1, const struct ldb_val *v2)
{
	int i1, i2;

	i1 = strtol(v1->data, NULL, 0);
	i2 = strtol(v2->data, NULL, 0);

	return i1 == i2;
}

/*
  see if two ldb_val structures contain the same data as case insensitive strings
  return 1 for a match, 0 for a mis-match
*/
static int ltdb_val_equal_case_insensitive(const struct ldb_val *v1, 
					  const struct ldb_val *v2)
{
	if (v1->length != v2->length) {
		return 0;
	}
	if (strncasecmp(v1->data, v2->data, v1->length) == 0) {
		return 1;
	}
	return 0;
}

/*
  see if two ldb_val structures contain the same data with wildcards 
  and case insensitive
  return 1 for a match, 0 for a mis-match
*/
static int ltdb_val_equal_wildcard_ci(struct ldb_module *module,
				     const struct ldb_val *v1, 
				     const struct ldb_val *v2)
{
	struct ldb_context *ldb = module->ldb;
	char *s1, *s2;
	int ret;

	if (!v1->data || !v2->data) {
		return v1->data == v2->data;
	}

	s1 = ldb_casefold(ldb, v1->data);
	if (!s1) {
		return -1;
	}

	s2 = ldb_casefold(ldb, v2->data);
	if (!s2) {
		talloc_free(s1);
		return -1;
	}

	ret = fnmatch(s2, s1, 0);

	talloc_free(s1);
	talloc_free(s2);

	if (ret == 0) {
		return 1;
	}

	return 0;
}

/*
  see if two ldb_val structures contain the same data with wildcards
  return 1 for a match, 0 for a mis-match
*/
static int ltdb_val_equal_wildcard(struct ldb_module *module,
				  const struct ldb_val *v1, 
				  const struct ldb_val *v2,
				  int flags)
{
	if (flags & LTDB_FLAG_CASE_INSENSITIVE) {
		return ltdb_val_equal_wildcard_ci(module, v1, v2);
	}
	if (!v1->data || !v2->data) {
		return v1->data == v2->data;
	}
	if (fnmatch(v2->data, v1->data, 0) == 0) {
		return 1;
	}
	return 0;
}


/*
  see if two objectclasses are considered equal. This handles
  the subclass attributes

  v1 contains the in-database value, v2 contains the value
  that the user gave

  return 1 for a match, 0 for a mis-match
*/
static int ltdb_val_equal_objectclass(struct ldb_module *module, 
				     const struct ldb_val *v1, const struct ldb_val *v2)
{
	struct ltdb_private *ltdb = module->private_data;
	unsigned int i;

	if (ltdb_val_equal_case_insensitive(v1, v2) == 1) {
		return 1;
	}

	for (i=0;i<ltdb->cache->subclasses->num_elements;i++) {
		struct ldb_message_element *el = &ltdb->cache->subclasses->elements[i];
		if (ldb_attr_cmp(el->name, v2->data) == 0) {
			unsigned int j;
			for (j=0;j<el->num_values;j++) {
				if (ltdb_val_equal_objectclass(module, v1, &el->values[j])) {
					return 1;
				}
			}
		}
	}

	return 0;
}
				     

/*
  see if two ldb_val structures contain the same data
  
  v1 contains the in-database value, v2 contains the value
  that the user gave
  
  return 1 for a match, 0 for a mis-match
*/
int ltdb_val_equal(struct ldb_module *module,
		  const char *attr_name,
		  const struct ldb_val *v1, const struct ldb_val *v2)
{
	int flags = ltdb_attribute_flags(module, attr_name);

	if (flags & LTDB_FLAG_OBJECTCLASS) {
		return ltdb_val_equal_objectclass(module, v1, v2);
	}

	if (flags & LTDB_FLAG_INTEGER) {
		return ltdb_val_equal_integer(v1, v2);
	}

	if (flags & LTDB_FLAG_WILDCARD) {
		return ltdb_val_equal_wildcard(module, v1, v2, flags);
	}

	if (flags & LTDB_FLAG_CASE_INSENSITIVE) {
		return ltdb_val_equal_case_insensitive(v1, v2);
	}

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
static int match_leaf(struct ldb_module *module, 
		      struct ldb_message *msg,
		      struct ldb_parse_tree *tree,
		      const char *base,
		      enum ldb_scope scope)
{
	unsigned int i, j;

	if (!scope_match(msg->dn, base, scope)) {
		return 0;
	}

	if (ldb_attr_cmp(tree->u.simple.attr, "dn") == 0) {
		if (strcmp(tree->u.simple.value.data, "*") == 0) {
			return 1;
		}
		return ldb_dn_cmp(msg->dn, tree->u.simple.value.data) == 0;
	}

	for (i=0;i<msg->num_elements;i++) {
		if (ldb_attr_cmp(msg->elements[i].name, tree->u.simple.attr) == 0) {
			if (strcmp(tree->u.simple.value.data, "*") == 0) {
				return 1;
			}
			for (j=0;j<msg->elements[i].num_values;j++) {
				if (ltdb_val_equal(module, msg->elements[i].name,
						  &msg->elements[i].values[j], 
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
int ltdb_message_match(struct ldb_module *module, 
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

	case LDB_OP_NOT:
		return ! ltdb_message_match(module, msg, tree->u.not.child, base, scope);

	case LDB_OP_AND:
		for (i=0;i<tree->u.list.num_elements;i++) {
			v = ltdb_message_match(module, msg, tree->u.list.elements[i],
					      base, scope);
			if (!v) return 0;
		}
		return 1;

	case LDB_OP_OR:
		for (i=0;i<tree->u.list.num_elements;i++) {
			v = ltdb_message_match(module, msg, tree->u.list.elements[i],
					      base, scope);
			if (v) return 1;
		}
		return 0;
	}

	return match_leaf(module, msg, tree, base, scope);
}
