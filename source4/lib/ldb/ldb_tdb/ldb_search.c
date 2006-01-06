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
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "ldb/ldb_tdb/ldb_tdb.h"

/*
  add one element to a message
*/
static int msg_add_element(struct ldb_context *ldb, 
			   struct ldb_message *ret, 
			   const struct ldb_message_element *el,
			   int check_duplicates)
{
	unsigned int i;
	struct ldb_message_element *e2, *elnew;

	if (check_duplicates && ldb_msg_find_element(ret, el->name)) {
		/* its already there */
		return 0;
	}

	e2 = talloc_realloc(ret, ret->elements, struct ldb_message_element, ret->num_elements+1);
	if (!e2) {
		return -1;
	}
	ret->elements = e2;
	
	elnew = &e2[ret->num_elements];

	elnew->name = talloc_strdup(ret->elements, el->name);
	if (!elnew->name) {
		return -1;
	}

	if (el->num_values) {
		elnew->values = talloc_array(ret->elements, struct ldb_val, el->num_values);
		if (!elnew->values) {
			return -1;
		}
	} else {
		elnew->values = NULL;
	}

	for (i=0;i<el->num_values;i++) {
		elnew->values[i] = ldb_val_dup(elnew->values, &el->values[i]);
		if (elnew->values[i].length != el->values[i].length) {
			return -1;
		}
	}

	elnew->num_values = el->num_values;

	ret->num_elements++;

	return 0;
}

/*
  add the special distinguishedName element
*/
static int msg_add_distinguished_name(struct ldb_module *module, struct ldb_message *msg)
{
	struct ldb_message_element el;
	struct ldb_val val;
	int ret;

	el.flags = 0;
	el.name = "distinguishedName";
	el.num_values = 1;
	el.values = &val;
	val.data = (uint8_t *)ldb_dn_linearize(msg, msg->dn);
	val.length = strlen((char *)val.data);
	
	ret = msg_add_element(module->ldb, msg, &el, 1);
	return ret;
}

/*
  add all elements from one message into another
 */
static int msg_add_all_elements(struct ldb_module *module, struct ldb_message *ret,
				const struct ldb_message *msg)
{
	struct ldb_context *ldb = module->ldb;
	unsigned int i;
	int check_duplicates = (ret->num_elements != 0);

	if (msg_add_distinguished_name(module, ret) != 0) {
		return -1;
	}

	for (i=0;i<msg->num_elements;i++) {
		const struct ldb_attrib_handler *h;
		h = ldb_attrib_handler(ldb, msg->elements[i].name);
		if (h->flags & LDB_ATTR_FLAG_HIDDEN) {
			continue;
		}
		if (msg_add_element(ldb, ret, &msg->elements[i],
				    check_duplicates) != 0) {
			return -1;
		}
	}

	return 0;
}


/*
  pull the specified list of attributes from a message
 */
static struct ldb_message *ltdb_pull_attrs(struct ldb_module *module, 
					   const struct ldb_message *msg, 
					   const char * const *attrs)
{
	struct ldb_context *ldb = module->ldb;
	struct ldb_message *ret;
	int i;

	ret = talloc(ldb, struct ldb_message);
	if (!ret) {
		return NULL;
	}

	ret->dn = ldb_dn_copy(ret, msg->dn);
	if (!ret->dn) {
		talloc_free(ret);
		return NULL;
	}

	ret->num_elements = 0;
	ret->elements = NULL;

	if (!attrs) {
		if (msg_add_all_elements(module, ret, msg) != 0) {
			talloc_free(ret);
			return NULL;
		}
		return ret;
	}

	for (i=0;attrs[i];i++) {
		struct ldb_message_element *el;

		if (strcmp(attrs[i], "*") == 0) {
			if (msg_add_all_elements(module, ret, msg) != 0) {
				talloc_free(ret);
				return NULL;
			}
			continue;
		}

		if (ldb_attr_cmp(attrs[i], "distinguishedName") == 0) {
			if (msg_add_distinguished_name(module, ret) != 0) {
				return NULL;
			}
			continue;
		}

		el = ldb_msg_find_element(msg, attrs[i]);
		if (!el) {
			continue;
		}
		if (msg_add_element(ldb, ret, el, 1) != 0) {
			talloc_free(ret);
			return NULL;				
		}
	}

	return ret;
}


/*
  search the database for a single simple dn, returning all attributes
  in a single message

  return 1 on success, 0 on record-not-found and -1 on error
*/
int ltdb_search_dn1(struct ldb_module *module, const struct ldb_dn *dn, struct ldb_message *msg)
{
	struct ltdb_private *ltdb = module->private_data;
	int ret;
	TDB_DATA tdb_key, tdb_data, tdb_data2;

	memset(msg, 0, sizeof(*msg));

	/* form the key */
	tdb_key = ltdb_key(module, dn);
	if (!tdb_key.dptr) {
		return -1;
	}

	tdb_data = tdb_fetch(ltdb->tdb, tdb_key);
	talloc_free(tdb_key.dptr);
	if (!tdb_data.dptr) {
		return 0;
	}

	tdb_data2.dptr = talloc_memdup(msg, tdb_data.dptr, tdb_data.dsize);
	free(tdb_data.dptr);
	if (!tdb_data2.dptr) {
		return -1;
	}
	tdb_data2.dsize = tdb_data.dsize;

	msg->num_elements = 0;
	msg->elements = NULL;

	ret = ltdb_unpack_data(module, &tdb_data2, msg);
	if (ret == -1) {
		talloc_free(tdb_data2.dptr);
		return -1;		
	}

	if (!msg->dn) {
		msg->dn = ldb_dn_copy(tdb_data2.dptr, dn);
	}
	if (!msg->dn) {
		talloc_free(tdb_data2.dptr);
		return -1;
	}

	return 1;
}

/* the lock key for search locking. Note that this is not a DN, its
   just an arbitrary key to give to tdb. Also note that as we and
   using transactions for all write operations and transactions take
   care of their own locks, we don't need to do any locking anywhere
   other than in ldb_search() */
#define LDBLOCK	"INT_LDBLOCK"

/*
  lock the database for read - use by ltdb_search
*/
static int ltdb_lock_read(struct ldb_module *module)
{
	struct ltdb_private *ltdb = module->private_data;
	TDB_DATA key;

	key.dptr = discard_const(LDBLOCK);
	key.dsize = strlen(LDBLOCK);

	return tdb_chainlock_read(ltdb->tdb, key);
}

/*
  unlock the database after a ltdb_lock_read()
*/
static int ltdb_unlock_read(struct ldb_module *module)
{
	struct ltdb_private *ltdb = module->private_data;
	TDB_DATA key;

	key.dptr = discard_const(LDBLOCK);
	key.dsize = strlen(LDBLOCK);

	return tdb_chainunlock_read(ltdb->tdb, key);
}

/*
  add a set of attributes from a record to a set of results
  return 0 on success, -1 on failure
*/
int ltdb_add_attr_results(struct ldb_module *module, struct ldb_message *msg,
			  const char * const attrs[], 
			  unsigned int *count, 
			  struct ldb_message ***res)
{
	struct ldb_context *ldb = module->ldb;
	struct ldb_message *msg2;
	struct ldb_message **res2;

	/* pull the attributes that the user wants */
	msg2 = ltdb_pull_attrs(module, msg, attrs);
	if (!msg2) {
		return -1;
	}

	/* add to the results list */
	res2 = talloc_realloc(ldb, *res, struct ldb_message *, (*count)+2);
	if (!res2) {
		talloc_free(msg2);
		return -1;
	}

	(*res) = res2;

	(*res)[*count] = talloc_steal(*res, msg2);
	(*res)[(*count)+1] = NULL;
	(*count)++;

	return 0;
}


/*
  internal search state during a full db search
*/
struct ltdb_search_info {
	struct ldb_module *module;
	struct ldb_parse_tree *tree;
	const struct ldb_dn *base;
	enum ldb_scope scope;
	const char * const *attrs;
	struct ldb_message **msgs;
	unsigned int failures;
	unsigned int count;
};


/*
  search function for a non-indexed search
 */
static int search_func(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *state)
{
	struct ltdb_search_info *sinfo = state;
	struct ldb_message *msg;
	int ret;

	if (key.dsize < 4 || 
	    strncmp((char *)key.dptr, "DN=", 3) != 0) {
		return 0;
	}

	msg = talloc(sinfo, struct ldb_message);
	if (msg == NULL) {
		return -1;
	}

	/* unpack the record */
	ret = ltdb_unpack_data(sinfo->module, &data, msg);
	if (ret == -1) {
		sinfo->failures++;
		talloc_free(msg);
		return 0;
	}

	if (!msg->dn) {
		msg->dn = ldb_dn_explode(msg, (char *)key.dptr + 3);
		if (msg->dn == NULL) {
			talloc_free(msg);
			return -1;
		}
	}

	/* see if it matches the given expression */
	if (!ldb_match_msg(sinfo->module->ldb, msg, sinfo->tree, 
			       sinfo->base, sinfo->scope)) {
		talloc_free(msg);
		return 0;
	}

	ret = ltdb_add_attr_results(sinfo->module, msg, sinfo->attrs, &sinfo->count, &sinfo->msgs);

	if (ret == -1) {
		sinfo->failures++;
	}

	talloc_free(msg);

	return ret;
}


/*
  search the database with a LDAP-like expression.
  this is the "full search" non-indexed variant
*/
static int ltdb_search_full(struct ldb_module *module, 
			    const struct ldb_dn *base,
			    enum ldb_scope scope,
			    struct ldb_parse_tree *tree,
			    const char * const attrs[], struct ldb_result **res)
{
	struct ltdb_private *ltdb = module->private_data;
	struct ldb_result *result;
	int ret;
	struct ltdb_search_info *sinfo;

	result = talloc(ltdb, struct ldb_result);
	if (result == NULL) {
		return LDB_ERR_OTHER;
	}

	sinfo = talloc(ltdb, struct ltdb_search_info);
	if (sinfo == NULL) {
		talloc_free(result);
		return LDB_ERR_OTHER;
	}

	sinfo->tree = tree;
	sinfo->module = module;
	sinfo->scope = scope;
	sinfo->base = base;
	sinfo->attrs = attrs;
	sinfo->msgs = NULL;
	sinfo->count = 0;
	sinfo->failures = 0;

	ret = tdb_traverse_read(ltdb->tdb, search_func, sinfo);

	if (ret == -1) {
		talloc_free(result);
		talloc_free(sinfo);
		return -1;
	}

	result->controls = NULL;
	result->msgs = talloc_steal(result, sinfo->msgs);
	result->count = sinfo->count;
	*res = result;

	talloc_free(sinfo);

	return LDB_SUCCESS;
}


/*
  search the database with a LDAP-like expression.
  choses a search method
*/
int ltdb_search_bytree(struct ldb_module *module, const struct ldb_dn *base,
		       enum ldb_scope scope, struct ldb_parse_tree *tree,
		       const char * const attrs[], struct ldb_result **res)
{
	int ret;

	if ((base == NULL || base->comp_num == 0) &&
	    (scope == LDB_SCOPE_BASE || scope == LDB_SCOPE_ONELEVEL)) return -1;

	if (ltdb_lock_read(module) != 0) {
		return -1;
	}

	if (ltdb_cache_load(module) != 0) {
		ltdb_unlock_read(module);
		return -1;
	}

	*res = NULL;

	ret = ltdb_search_indexed(module, base, scope, tree, attrs, res);
	if (ret == -1) {
		ret = ltdb_search_full(module, base, scope, tree, attrs, res);
	}

	ltdb_unlock_read(module);

	return ret;
}


