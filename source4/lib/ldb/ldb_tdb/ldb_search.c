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
 *  Component: ldb search functions
 *
 *  Description: functions to search ldb+tdb databases
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/ldb_tdb/ldb_tdb.h"

/*
  free a message that has all parts separately allocated
*/
static void msg_free_all_parts(struct ldb_context *ldb, struct ldb_message *msg)
{
	int i, j;
	ldb_free(ldb, msg->dn);
	for (i=0;i<msg->num_elements;i++) {
		ldb_free(ldb, msg->elements[i].name);
		for (j=0;j<msg->elements[i].num_values;j++) {
			ldb_free(ldb, msg->elements[i].values[j].data);
		}
		ldb_free(ldb, msg->elements[i].values);
	}
	ldb_free(ldb, msg->elements);
	ldb_free(ldb, msg);
}


/*
  duplicate a ldb_val structure
*/
struct ldb_val ldb_val_dup(struct ldb_context *ldb,
			   const struct ldb_val *v)
{
	struct ldb_val v2;
	v2.length = v->length;
	if (v->length == 0) {
		v2.data = NULL;
		return v2;
	}

	/* the +1 is to cope with buggy C library routines like strndup
	   that look one byte beyond */
	v2.data = ldb_malloc(ldb, v->length+1);
	if (!v2.data) {
		v2.length = 0;
		return v2;
	}

	memcpy(v2.data, v->data, v->length);
	((char *)v2.data)[v->length] = 0;
	return v2;
}



/*
  add one element to a message
*/
static int msg_add_element(struct ldb_context *ldb, 
			   struct ldb_message *ret, const struct ldb_message_element *el)
{
	int i;
	struct ldb_message_element *e2, *elnew;

	e2 = ldb_realloc_p(ldb, ret->elements, struct ldb_message_element, ret->num_elements+1);
	if (!e2) {
		return -1;
	}
	ret->elements = e2;
	
	elnew = &e2[ret->num_elements];

	elnew->name = ldb_strdup(ldb, el->name);
	if (!elnew->name) {
		return -1;
	}

	if (el->num_values) {
		elnew->values = ldb_malloc_array_p(ldb, struct ldb_val, el->num_values);
		if (!elnew->values) {
			return -1;
		}
	} else {
		elnew->values = NULL;
	}

	for (i=0;i<el->num_values;i++) {
		elnew->values[i] = ldb_val_dup(ldb, &el->values[i]);
		if (elnew->values[i].length != el->values[i].length) {
			return -1;
		}
	}

	elnew->num_values = el->num_values;

	ret->num_elements++;

	return 0;
}

/*
  add all elements from one message into another
 */
static int msg_add_all_elements(struct ldb_context *ldb, struct ldb_message *ret,
				const struct ldb_message *msg)
{
	int i;
	for (i=0;i<msg->num_elements;i++) {
		if (msg_add_element(ldb, ret, &msg->elements[i]) != 0) {
			return -1;
		}
	}

	return 0;
}


/*
  pull the specified list of attributes from a message
 */
static struct ldb_message *ltdb_pull_attrs(struct ldb_context *ldb, 
					   const struct ldb_message *msg, 
					   char * const *attrs)
{
	struct ldb_message *ret;
	int i;

	ret = ldb_malloc_p(ldb, struct ldb_message);
	if (!ret) {
		return NULL;
	}

	ret->dn = ldb_strdup(ldb, msg->dn);
	if (!ret->dn) {
		ldb_free(ldb, ret);
		return NULL;
	}

	ret->num_elements = 0;
	ret->elements = NULL;
	ret->private_data = NULL;

	if (!attrs) {
		if (msg_add_all_elements(ldb, ret, msg) != 0) {
			msg_free_all_parts(ldb, ret);
			return NULL;
		}
		return ret;
	}

	for (i=0;attrs[i];i++) {
		struct ldb_message_element *el;

		if (strcmp(attrs[i], "*") == 0) {
			if (msg_add_all_elements(ldb, ret, msg) != 0) {
				msg_free_all_parts(ldb, ret);
				return NULL;
			}
			continue;
		}

		el = ldb_msg_find_element(msg, attrs[i]);
		if (!el) {
			continue;
		}
		if (msg_add_element(ldb, ret, el) != 0) {
			msg_free_all_parts(ldb, ret);
			return NULL;				
		}
	}

	return ret;
}



/*
  see if a ldb_val is a wildcard
  return 1 if yes, 0 if no
*/
int ltdb_has_wildcard(struct ldb_context *ldb, const char *attr_name, 
		      const struct ldb_val *val)
{
	int flags;

	/* all attribute types recognise the "*" wildcard */
	if (val->length == 1 && strncmp((char *)val->data, "*", 1) == 0) {
		return 1;
	}

	if (strpbrk(val->data, "*?") == NULL) {
		return 0;
	}

	flags = ltdb_attribute_flags(ldb, attr_name);
	if (flags & LTDB_FLAG_WILDCARD) {
		return 1;
	}

	return 0;
}


/*
  free the results of a ltdb_search_dn1 search
*/
void ltdb_search_dn1_free(struct ldb_context *ldb, struct ldb_message *msg)
{
	int i;
	ldb_free(ldb, msg->private_data);
	for (i=0;i<msg->num_elements;i++) {
		ldb_free(ldb, msg->elements[i].values);
	}
	ldb_free(ldb, msg->elements);
	memset(msg, 0, sizeof(*msg));
}


/*
  search the database for a single simple dn, returning all attributes
  in a single message

  return 1 on success, 0 on record-not-found and -1 on error
*/
int ltdb_search_dn1(struct ldb_context *ldb, const char *dn, struct ldb_message *msg)
{
	struct ltdb_private *ltdb = ldb->private_data;
	int ret;
	TDB_DATA tdb_key, tdb_data, tdb_data2;

	/* form the key */
	tdb_key = ltdb_key(ldb, dn);
	if (!tdb_key.dptr) {
		return -1;
	}

	tdb_data = tdb_fetch(ltdb->tdb, tdb_key);
	ldb_free(ldb, tdb_key.dptr);
	if (!tdb_data.dptr) {
		return 0;
	}

	tdb_data2.dptr = ldb_malloc(ldb, tdb_data.dsize);
	if (!tdb_data2.dptr) {
		free(tdb_data.dptr);
		return -1;
	}
	memcpy(tdb_data2.dptr, tdb_data.dptr, tdb_data.dsize);
	free(tdb_data.dptr);
	tdb_data2.dsize = tdb_data.dsize;

	msg->private_data = tdb_data2.dptr;
	msg->num_elements = 0;
	msg->elements = NULL;

	ret = ltdb_unpack_data(ldb, &tdb_data2, msg);
	if (ret == -1) {
		free(tdb_data2.dptr);
		return -1;		
	}

	if (!msg->dn) {
		msg->dn = ldb_strdup(ldb, dn);
	}
	if (!msg->dn) {
		ldb_free(ldb, tdb_data2.dptr);
		return -1;
	}

	return 1;
}


/*
  search the database for a single simple dn
*/
int ltdb_search_dn(struct ldb_context *ldb, char *dn,
		   char * const attrs[], struct ldb_message ***res)
{
	int ret;
	struct ldb_message msg, *msg2;

	ret = ltdb_search_dn1(ldb, dn, &msg);
	if (ret != 1) {
		return ret;
	}

	msg2 = ltdb_pull_attrs(ldb, &msg, attrs);

	ltdb_search_dn1_free(ldb, &msg);

	if (!msg2) {
		return -1;		
	}

	*res = ldb_malloc_array_p(ldb, struct ldb_message *, 2);
	if (! *res) {
		msg_free_all_parts(ldb, msg2);
		return -1;		
	}

	(*res)[0] = msg2;
	(*res)[1] = NULL;

	return 1;
}


/*
  add a set of attributes from a record to a set of results
  return 0 on success, -1 on failure
*/
int ltdb_add_attr_results(struct ldb_context *ldb, struct ldb_message *msg,
			  char * const attrs[], 
			  unsigned int *count, 
			  struct ldb_message ***res)
{
	struct ldb_message *msg2;
	struct ldb_message **res2;

	/* pull the attributes that the user wants */
	msg2 = ltdb_pull_attrs(ldb, msg, attrs);
	if (!msg2) {
		return -1;
	}

	/* add to the results list */
	res2 = ldb_realloc_p(ldb, *res, struct ldb_message *, (*count)+2);
	if (!res2) {
		msg_free_all_parts(ldb, msg2);
		return -1;
	}

	(*res) = res2;

	(*res)[*count] = msg2;
	(*res)[(*count)+1] = NULL;
	(*count)++;

	return 0;
}


/*
  internal search state during a full db search
*/
struct ltdb_search_info {
	struct ldb_context *ldb;
	struct ldb_parse_tree *tree;
	const char *base;
	enum ldb_scope scope;
	char * const *attrs;
	struct ldb_message **msgs;
	int failures;
	int count;
};


/*
  search function for a non-indexed search
 */
static int search_func(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *state)
{
	struct ltdb_search_info *sinfo = state;
	struct ldb_message msg;
	int ret;

	if (key.dsize < 4 || 
	    strncmp(key.dptr, "DN=", 3) != 0) {
		return 0;
	}

	/* unpack the record */
	ret = ltdb_unpack_data(sinfo->ldb, &data, &msg);
	if (ret == -1) {
		sinfo->failures++;
		return 0;
	}

	if (!msg.dn) {
		msg.dn = key.dptr + 3;
	}

	/* see if it matches the given expression */
	if (!ldb_message_match(sinfo->ldb, &msg, sinfo->tree, 
			       sinfo->base, sinfo->scope)) {
		ltdb_unpack_data_free(sinfo->ldb, &msg);
		return 0;
	}

	ret = ltdb_add_attr_results(sinfo->ldb, &msg, sinfo->attrs, &sinfo->count, &sinfo->msgs);

	if (ret == -1) {
		sinfo->failures++;
	}

	ltdb_unpack_data_free(sinfo->ldb, &msg);

	return ret;
}


/*
  free a set of search results
*/
int ltdb_search_free(struct ldb_context *ldb, struct ldb_message **msgs)
{
	struct ltdb_private *ltdb = ldb->private_data;
	int i;

	ltdb->last_err_string = NULL;
	
	if (!msgs) return 0;

	for (i=0;msgs[i];i++) {
		msg_free_all_parts(ldb, msgs[i]);
	}

	ldb_free(ldb, msgs);

	return 0;
}

/*
  search the database with a LDAP-like expression.
  this is the "full search" non-indexed varient
*/
static int ltdb_search_full(struct ldb_context *ldb, 
			    const char *base,
			    enum ldb_scope scope,
			    struct ldb_parse_tree *tree,
			    char * const attrs[], struct ldb_message ***res)
{
	struct ltdb_private *ltdb = ldb->private_data;
	int ret;
	struct ltdb_search_info sinfo;

	sinfo.tree = tree;
	sinfo.ldb = ldb;
	sinfo.scope = scope;
	sinfo.base = base;
	sinfo.attrs = attrs;
	sinfo.msgs = NULL;
	sinfo.count = 0;
	sinfo.failures = 0;

	ret = tdb_traverse(ltdb->tdb, search_func, &sinfo);

	if (ret == -1) {
		ltdb_search_free(ldb, sinfo.msgs);
		return -1;
	}

	*res = sinfo.msgs;
	return sinfo.count;
}


/*
  search the database with a LDAP-like expression.
  choses a search method
*/
int ltdb_search(struct ldb_context *ldb, const char *base,
		enum ldb_scope scope, const char *expression,
		char * const attrs[], struct ldb_message ***res)
{
	struct ltdb_private *ltdb = ldb->private_data;
	struct ldb_parse_tree *tree;
	int ret;

	ltdb->last_err_string = NULL;

	if (ltdb_cache_load(ldb) != 0) {
		return -1;
	}

	*res = NULL;

	/* form a parse tree for the expression */
	tree = ldb_parse_tree(ldb, expression);
	if (!tree) {
		ltdb->last_err_string = "expression parse failed";
		return -1;
	}

	if (tree->operation == LDB_OP_SIMPLE && 
	    ldb_attr_cmp(tree->u.simple.attr, "dn") == 0 &&
	    !ltdb_has_wildcard(ldb, tree->u.simple.attr, &tree->u.simple.value)) {
		/* yay! its a nice simple one */
		ret = ltdb_search_dn(ldb, tree->u.simple.value.data, attrs, res);
	} else {
		ret = ltdb_search_indexed(ldb, base, scope, tree, attrs, res);
		if (ret == -1) {
			ret = ltdb_search_full(ldb, base, scope, tree, attrs, res);
		}
	}

	ldb_parse_tree_free(ldb, tree);

	return ret;
}

