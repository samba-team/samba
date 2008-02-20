/* 
   ldb database library

   Copyright (C) Amdrew Bartlett <abartlet@samba.org> 2007
   Copyright (C) Andrew Tridgell  2004
    
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

/*
 *  Name: ldb
 *
 *  Component: ldb anr module
 *
 *  Description: module to implement 'ambiguous name resolution'
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb_includes.h"
#include "dsdb/samdb/samdb.h"

/**
 * Make a and 'and' or 'or' tree from the two supplied elements 
 */
struct ldb_parse_tree *make_parse_list(struct ldb_module *module,
				       TALLOC_CTX *mem_ctx, enum ldb_parse_op op, 
				       struct ldb_parse_tree *first_arm, struct ldb_parse_tree *second_arm)
{
	struct ldb_parse_tree *list;

	list = talloc(mem_ctx, struct ldb_parse_tree);
	if (list == NULL){
		ldb_oom(module->ldb);
		return NULL;
	}
	list->operation = op;
	
	list->u.list.num_elements = 2;
	list->u.list.elements = talloc_array(list, struct ldb_parse_tree *, 2);
	if (!list->u.list.elements) {
		ldb_oom(module->ldb);
		return NULL;
	}
	list->u.list.elements[0] = talloc_steal(list, first_arm);
	list->u.list.elements[1] = talloc_steal(list, second_arm);
	return list;
}

/**
 * Make an equality or prefix match tree, from the attribute, operation and matching value supplied
 */
struct ldb_parse_tree *make_match_tree(struct ldb_module *module,
				       TALLOC_CTX *mem_ctx, enum ldb_parse_op op, 
				       const char *attr, const DATA_BLOB *match)
{
	struct ldb_parse_tree *match_tree;

	match_tree = talloc(mem_ctx, struct ldb_parse_tree);
	
	/* Depending on what type of match was selected, fill in the right part of the union */
	 
	match_tree->operation = op;
	switch (op) {
	case LDB_OP_SUBSTRING:
		match_tree->u.substring.attr = attr;
		
		match_tree->u.substring.start_with_wildcard = 0;
		match_tree->u.substring.end_with_wildcard = 1;
		match_tree->u.substring.chunks = talloc_array(match_tree, struct ldb_val *, 2);
		
		if (match_tree->u.substring.chunks == NULL){
			ldb_oom(module->ldb);
			return NULL;
		}
		match_tree->u.substring.chunks[0] = match;
		match_tree->u.substring.chunks[1] = NULL;
		break;
	case LDB_OP_EQUALITY:
		match_tree->u.equality.attr = attr;
		match_tree->u.equality.value = *match;
		break;
	}
	return match_tree;
}

struct anr_context {
	bool found_anr;
	struct ldb_module *module;
};

/**
 * Given the match for an 'ambigious name resolution' query, create a
 * parse tree with an 'or' of all the anr attributes in the schema.  
 */

typedef struct ldb_parse_tree *(*anr_parse_tree_callback_t)(TALLOC_CTX *mem_ctx,
							   const struct ldb_val *match,
							   void *context);


/**
 * Callback function to do the heavy lifting for the for the parse tree walker 
 */
struct ldb_parse_tree *anr_replace_callback(TALLOC_CTX *mem_ctx,
					    const struct ldb_val *match,
					    void *context)
{
	struct ldb_parse_tree *tree = NULL;
	struct anr_context *anr_context = talloc_get_type(context, struct anr_context);
	struct ldb_module *module = anr_context->module;
	struct ldb_parse_tree *match_tree;
	uint8_t *p;
	enum ldb_parse_op op;
	struct dsdb_attribute *cur;
	const struct dsdb_schema *schema = dsdb_get_schema(module->ldb);
	if (!schema) {
		ldb_asprintf_errstring(module->ldb, "no schema with which to construct anr filter");
		return NULL;
	}

	anr_context->found_anr = true;

	if (match->length > 1 && match->data[0] == '=') {
		DATA_BLOB *match2 = talloc(tree, DATA_BLOB);
		*match2 = data_blob_const(match->data+1, match->length - 1);
		if (match2 == NULL){
			ldb_oom(module->ldb);
			return NULL;
		}
		match = match2;
		op = LDB_OP_EQUALITY;
	} else {
		op = LDB_OP_SUBSTRING;
	}
	for (cur = schema->attributes; cur; cur = cur->next) {
		if (!(cur->searchFlags & 0x4)) continue;
		match_tree = make_match_tree(module, mem_ctx, op, cur->lDAPDisplayName, match);

		if (tree) {
			/* Inject an 'or' with the current tree */
			tree = make_parse_list(module, mem_ctx,  LDB_OP_OR, tree, match_tree);
			if (tree == NULL) {
				ldb_oom(module->ldb);
				return NULL;
			}
		} else {
			tree = match_tree;
		}
	}

	
	/* If the search term has a space in it, 
	   split it up at the first space.  */
	
	p = memchr(match->data, ' ', match->length);

	if (p) {
		struct ldb_parse_tree *first_split_filter, *second_split_filter, *split_filters, *match_tree_1, *match_tree_2;
		DATA_BLOB *first_match = talloc(tree, DATA_BLOB);
		DATA_BLOB *second_match = talloc(tree, DATA_BLOB);
		if (!first_match || !second_match) {
			ldb_oom(module->ldb);
			return NULL;
		}
		*first_match = data_blob_const(match->data, p-match->data);
		*second_match = data_blob_const(p+1, match->length - (p-match->data) - 1);
		
		/* Add (|(&(givenname=first)(sn=second))(&(givenname=second)(sn=first))) */

		match_tree_1 = make_match_tree(module, mem_ctx, op, "givenName", first_match);
		match_tree_2 = make_match_tree(module, mem_ctx, op, "sn", second_match);

		first_split_filter = make_parse_list(module, context,  LDB_OP_AND, match_tree_1, match_tree_2);
		if (first_split_filter == NULL){
			ldb_oom(module->ldb);
			return NULL;
		}
		
		match_tree_1 = make_match_tree(module, mem_ctx, op, "sn", first_match);
		match_tree_2 = make_match_tree(module, mem_ctx, op, "givenName", second_match);

		second_split_filter = make_parse_list(module, context,  LDB_OP_AND, match_tree_1, match_tree_2);
		if (second_split_filter == NULL){
			ldb_oom(module->ldb);
			return NULL;
		}

		split_filters = make_parse_list(module, mem_ctx,  LDB_OP_OR, 
						first_split_filter, second_split_filter);
		if (split_filters == NULL) {
			ldb_oom(module->ldb);
			return NULL;
		}

		if (tree) {
			/* Inject an 'or' with the current tree */
			tree = make_parse_list(module, mem_ctx,  LDB_OP_OR, tree, split_filters);
		} else {
			tree = split_filters;
		}
	}
	return tree;
}

/*
  replace any occurances of an attribute with a new, generated attribute tree
*/
struct ldb_parse_tree *anr_replace_subtrees(struct ldb_parse_tree *tree, 
					    const char *attr, 
					    anr_parse_tree_callback_t callback,
					    void *context)
{
	int i;
	switch (tree->operation) {
	case LDB_OP_AND:
	case LDB_OP_OR:
		for (i=0;i<tree->u.list.num_elements;i++) {
			tree->u.list.elements[i] = anr_replace_subtrees(tree->u.list.elements[i],
									attr, callback, context);
			if (!tree->u.list.elements[i]) {
				return NULL;
			}
		}
		break;
	case LDB_OP_NOT:
		tree->u.isnot.child = anr_replace_subtrees(tree->u.isnot.child, attr, callback, context);
			if (!tree->u.isnot.child) {
				return NULL;
			}
		break;
	case LDB_OP_EQUALITY:
		if (ldb_attr_cmp(tree->u.equality.attr, attr) == 0) {
			tree = callback(tree, &tree->u.equality.value, 
					context);
			if (!tree) {
				return NULL;
			}
		}
		break;
	case LDB_OP_SUBSTRING:
		if (ldb_attr_cmp(tree->u.substring.attr, attr) == 0) {
			if (tree->u.substring.start_with_wildcard == 0 &&
			    tree->u.substring.end_with_wildcard == 1 && 
			    tree->u.substring.chunks[0] != NULL && 
			    tree->u.substring.chunks[1] == NULL) {
				tree = callback(tree, tree->u.substring.chunks[0], context);
				if (!tree) {
					return NULL;
				}
			}
		}
		break;
	}
	return tree;
}

/* search */
static int anr_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_parse_tree *anr_tree;
	struct anr_context *context = talloc(req, struct anr_context);
	if (!context) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	context->module = module;
	context->found_anr = false;

	/* Yes, this is a problem with req->op.search.tree being const... */
	anr_tree = anr_replace_subtrees(req->op.search.tree, "anr", anr_replace_callback, context);
	if (!anr_tree) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (context->found_anr) {
		/* The above function modifies the tree if it finds "anr", so no
		 * point just setting this on the down_req */
		req->op.search.tree = talloc_steal(req, anr_tree);

	}
	return ldb_next_request(module, req);
}

_PUBLIC_ const struct ldb_module_ops ldb_anr_module_ops = {
	.name		   = "anr",
	.search = anr_search
};
