/* 
   ldb database library

   Copyright (C) Andrew Tridgell 2005

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
  handle operational attributes
 */

/*
  createTimestamp: HIDDEN, searchable, ldaptime, alias for whenCreated
  modifyTimestamp: HIDDEN, searchable, ldaptime, alias for whenChanged

     for the above two, we do the search as normal, and if
     createTimestamp or modifyTimestamp is asked for, then do
     additional searches for whenCreated and whenChanged and fill in
     the resulting values

     we also need to replace these with the whenCreated/whenChanged
     equivalent in the search expression trees

  whenCreated: not-HIDDEN, CONSTRUCTED, SEARCHABLE
  whenChanged: not-HIDDEN, CONSTRUCTED, SEARCHABLE

     on init we need to setup attribute handlers for these so
     comparisons are done correctly. The resolution is 1 second.

     on add we need to add both the above, for current time

     on modify we need to change whenChanged


  subschemaSubentry: HIDDEN, not-searchable, 
                     points at DN CN=Aggregate,CN=Schema,CN=Configuration,$BASEDN

     for this one we do the search as normal, then add the static
     value if requested. How do we work out the $BASEDN from inside a
     module?
     

  structuralObjectClass: HIDDEN, CONSTRUCTED, not-searchable. always same as objectclass?

     for this one we do the search as normal, then if requested ask
     for objectclass, change the attribute name, and add it

  allowedAttributesEffective: HIDDEN, CONSTRUCTED, not-searchable, 
     list of attributes that can be modified - requires schema lookup


  attributeTypes: in schema only
  objectClasses: in schema only
  matchingRules: in schema only
  matchingRuleUse: in schema only
  creatorsName: not supported by w2k3?
  modifiersName: not supported by w2k3?
*/


#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include <time.h>

/*
  construct a canonical name from a message
*/
static int construct_canonical_name(struct ldb_module *module, struct ldb_message *msg)
{
	char *canonicalName;
	canonicalName = ldb_dn_canonical_string(msg, msg->dn);
	if (canonicalName == NULL) {
		return -1;
	}
	return ldb_msg_add_string(msg, "canonicalName", canonicalName);
}

/*
  a list of attribute names that should be substituted in the parse
  tree before the search is done
*/
static const struct {
	const char *attr;
	const char *replace;
} parse_tree_sub[] = {
	{ "createTimestamp", "whenCreated" },
	{ "modifyTimestamp", "whenChanged" }
};


/*
  a list of attribute names that are hidden, but can be searched for
  using another (non-hidden) name to produce the correct result
*/
static const struct {
	const char *attr;
	const char *replace;
	int (*constructor)(struct ldb_module *, struct ldb_message *);
} search_sub[] = {
	{ "createTimestamp", "whenCreated", NULL },
	{ "modifyTimestamp", "whenChanged", NULL },
	{ "structuralObjectClass", "objectClass", NULL },
	{ "canonicalName", "distinguishedName", construct_canonical_name }
};

/*
  post process a search result record. For any search_sub[] attributes that were
  asked for, we need to call the appropriate copy routine to copy the result
  into the message, then remove any attributes that we added to the search but were
  not asked for by the user
*/
static int operational_search_post_process(struct ldb_module *module,
					   struct ldb_message *msg, 
					   const char * const *attrs)
{
	int i, a=0;

	for (a=0;attrs && attrs[a];a++) {
		for (i=0;i<ARRAY_SIZE(search_sub);i++) {
			if (ldb_attr_cmp(attrs[a], search_sub[i].attr) != 0) {
				continue;
			}

			/* construct the new attribute, using either a supplied 
			   constructor or a simple copy */
			if (search_sub[i].constructor) {
				if (search_sub[i].constructor(module, msg) != 0) {
					goto failed;
				}
			} else if (ldb_msg_copy_attr(msg,
						     search_sub[i].replace,
						     search_sub[i].attr) != 0) {
				goto failed;
			}

			/* remove the added search attribute, unless it was asked for 
			   by the user */
			if (search_sub[i].replace == NULL ||
			    ldb_attr_in_list(attrs, search_sub[i].replace) ||
			    ldb_attr_in_list(attrs, "*")) {
				continue;
			}

			ldb_msg_remove_attr(msg, search_sub[i].replace);
		}
	}

	return 0;

failed:
	ldb_debug_set(module->ldb, LDB_DEBUG_WARNING, 
		      "operational_search_post_process failed for attribute '%s'\n", 
		      attrs[a]);
	return -1;
}

/*
  hook search operations
*/
static int operational_search_bytree(struct ldb_module *module, struct ldb_request *req)
{
	int i, r, a;
	int ret;
	const char * const *attrs = req->op.search.attrs;
	const char **search_attrs = NULL;

	req->op.search.res = NULL;

	/* replace any attributes in the parse tree that are
	   searchable, but are stored using a different name in the
	   backend */
	for (i=0;i<ARRAY_SIZE(parse_tree_sub);i++) {
		ldb_parse_tree_attr_replace(req->op.search.tree, 
					    parse_tree_sub[i].attr, 
					    parse_tree_sub[i].replace);
	}

	/* in the list of attributes we are looking for, rename any
	   attributes to the alias for any hidden attributes that can
	   be fetched directly using non-hidden names */
	for (a=0;attrs && attrs[a];a++) {
		for (i=0;i<ARRAY_SIZE(search_sub);i++) {
			if (ldb_attr_cmp(attrs[a], search_sub[i].attr) == 0 &&
			    search_sub[i].replace) {
				if (!search_attrs) {
					search_attrs = ldb_attr_list_copy(req, attrs);
					if (search_attrs == NULL) {
						goto failed;
					}
				}
				search_attrs[a] = search_sub[i].replace;
			}
		}
	}
	
	/* use new set of attrs if any */
	if (search_attrs) req->op.search.attrs = search_attrs;
	/* perform the search */
	ret = ldb_next_request(module, req);
	/* set back saved attrs if needed */
	if (search_attrs) req->op.search.attrs = attrs;

	/* check operation result */
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* for each record returned post-process to add any derived
	   attributes that have been asked for */
	for (r = 0; r < req->op.search.res->count; r++) {
		if (operational_search_post_process(module, req->op.search.res->msgs[r], attrs) != 0) {
			goto failed;
		}
	}

	/* all done */
	talloc_free(search_attrs);
	return ret;

failed:
	talloc_free(search_attrs);
	talloc_free(req->op.search.res);
	ldb_oom(module->ldb);
	return LDB_ERR_OTHER;
}

/*
  add a time element to a record
*/
static int add_time_element(struct ldb_message *msg, const char *attr, time_t t)
{
	struct ldb_message_element *el;
	char *s;

	if (ldb_msg_find_element(msg, attr) != NULL) {
		return 0;
	}

	s = ldb_timestring(msg, t);
	if (s == NULL) {
		return -1;
	}

	if (ldb_msg_add_string(msg, attr, s) != 0) {
		return -1;
	}

	el = ldb_msg_find_element(msg, attr);
	/* always set as replace. This works because on add ops, the flag
	   is ignored */
	el->flags = LDB_FLAG_MOD_REPLACE;

	return 0;
}


/*
  hook add record ops
*/
static int operational_add(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.add.message;
	time_t t = time(NULL);
	struct ldb_message *msg2;
	int ret;

	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
	}

	/* we have to copy the message as the caller might have it as a const */
	msg2 = ldb_msg_copy_shallow(module, msg);
	if (msg2 == NULL) {
		return -1;
	}
	if (add_time_element(msg2, "whenCreated", t) != 0 ||
	    add_time_element(msg2, "whenChanged", t) != 0) {
		talloc_free(msg2);
		return -1;
	}
	/* use the new structure for the call chain below this point */
	req->op.add.message = msg2;
	/* go on with the call chain */
	ret = ldb_next_request(module, req);
	/* put back saved message */
	req->op.add.message = msg;
	/* free temproary compy */
	talloc_free(msg2);
	return ret;
}

/*
  hook modify record ops
*/
static int operational_modify(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.mod.message;
	time_t t = time(NULL);
	struct ldb_message *msg2;
	int ret;

	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
	}

	/* we have to copy the message as the caller might have it as a const */
	msg2 = ldb_msg_copy_shallow(module, msg);
	if (msg2 == NULL) {
		return -1;
	}
	if (add_time_element(msg2, "whenChanged", t) != 0) {
		talloc_free(msg2);
		return -1;
	}
	/* use the new structure for the call chain below this point */
	req->op.mod.message = msg2;
	/* go on with the call chain */
	ret = ldb_next_request(module, req);
	/* put back saved message */
	req->op.mod.message = msg;
	/* free temproary compy */
	talloc_free(msg2);
	return ret;
}


static int operational_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return operational_search_bytree(module, req);

	case LDB_REQ_ADD:
		return operational_add(module, req);

	case LDB_REQ_MODIFY:
		return operational_modify(module, req);

	default:
		return ldb_next_request(module, req);

	}
}

static const struct ldb_module_ops operational_ops = {
	.name              = "operational",
	.request           = operational_request
};


/* the init function */
struct ldb_module *operational_module_init(struct ldb_context *ldb, const char *options[])
{
	struct ldb_module *ctx;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	ctx->private_data = NULL;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &operational_ops;

	/* setup some standard attribute handlers */
	ldb_set_attrib_handler_syntax(ldb, "whenCreated", LDB_SYNTAX_UTC_TIME);
	ldb_set_attrib_handler_syntax(ldb, "whenChanged", LDB_SYNTAX_UTC_TIME);
	ldb_set_attrib_handler_syntax(ldb, "subschemaSubentry", LDB_SYNTAX_DN);
	ldb_set_attrib_handler_syntax(ldb, "structuralObjectClass", LDB_SYNTAX_OBJECTCLASS);

	return ctx;
}
