/* 
   ldb database library

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Simo Sorce 2006

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
#include "ldb/include/includes.h"

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
	return ldb_msg_add_steal_string(msg, "canonicalName", canonicalName);
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
  add a uint64_t element to a record
*/
static int add_uint64_element(struct ldb_message *msg, const char *attr, uint64_t v)
{
	struct ldb_message_element *el;

	if (ldb_msg_find_element(msg, attr) != NULL) {
		return 0;
	}

	if (ldb_msg_add_fmt(msg, attr, "%llu", v) != 0) {
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

	/* see if the backend can give us the USN */
	if (module->ldb->sequence_number != NULL) {
		uint64_t seq_num = module->ldb->sequence_number(module->ldb);
		if (add_uint64_element(msg2, "uSNCreated", seq_num) != 0 ||
		    add_uint64_element(msg2, "uSNChanged", seq_num) != 0) {
			talloc_free(msg2);
			return -1;
		}
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

	/* update the records USN if possible */
	if (module->ldb->sequence_number != NULL &&
	    add_uint64_element(msg2, "uSNChanged", 
			       module->ldb->sequence_number(module->ldb)) != 0) {
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

/*
  hook search operations
*/

struct operational_async_context {

	struct ldb_module *module;
	void *up_context;
	int (*up_callback)(struct ldb_context *, void *, struct ldb_async_result *);
	int timeout;

	const char * const *attrs;
};

static int operational_async_callback(struct ldb_context *ldb, void *context, struct ldb_async_result *ares)
{
	struct operational_async_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, talloc_asprintf(ldb, "NULL Context or Result in callback"));
		goto error;
	}

	ac = talloc_get_type(context, struct operational_async_context);

	if (ares->type == LDB_REPLY_ENTRY) {
		/* for each record returned post-process to add any derived
		   attributes that have been asked for */
		if (operational_search_post_process(ac->module, ares->message, ac->attrs) != 0) {
			goto error;
		}
	}

	return ac->up_callback(ldb, ac->up_context, ares);

error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

static int operational_search_async(struct ldb_module *module, struct ldb_request *req)
{
	struct operational_async_context *ac;
	struct ldb_request *down_req;
	const char **search_attrs = NULL;
	int i, a, ret;

	req->async.handle = NULL;

	ac = talloc(req, struct operational_async_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->up_context = req->async.context;
	ac->up_callback = req->async.callback;
	ac->timeout = req->async.timeout;
	ac->attrs = req->op.search.attrs;

	down_req = talloc_zero(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	down_req->operation = req->operation;
	down_req->op.search.base = req->op.search.base;
	down_req->op.search.scope = req->op.search.scope;
	down_req->op.search.tree = req->op.search.tree;

	/*  FIXME: I hink we should copy the tree and keep the original
	 *  unmodified. SSS */
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
	for (a=0;ac->attrs && ac->attrs[a];a++) {
		for (i=0;i<ARRAY_SIZE(search_sub);i++) {
			if (ldb_attr_cmp(ac->attrs[a], search_sub[i].attr) == 0 &&
			    search_sub[i].replace) {
				if (!search_attrs) {
					search_attrs = ldb_attr_list_copy(req, ac->attrs);
					if (search_attrs == NULL) {
						return LDB_ERR_OPERATIONS_ERROR;
					}
				}
				search_attrs[a] = search_sub[i].replace;
			}
		}
	}
	
	/* use new set of attrs if any */
	if (search_attrs) down_req->op.search.attrs = search_attrs;
	else down_req->op.search.attrs = req->op.search.attrs;
	
	down_req->controls = req->controls;
	down_req->creds = req->creds;

	down_req->async.context = ac;
	down_req->async.callback = operational_async_callback;
	down_req->async.timeout = req->async.timeout;

	/* perform the search */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->async.handle = down_req->async.handle;
	}

	return ret;
}

/*
  hook add record ops
*/
static int operational_add_async(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_request *down_req;
	struct ldb_message *msg;
	time_t t = time(NULL);
	int ret;

	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	down_req = talloc(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* we have to copy the message as the caller might have it as a const */
	msg = ldb_msg_copy_shallow(down_req, req->op.add.message);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	if (add_time_element(msg, "whenCreated", t) != 0 ||
	    add_time_element(msg, "whenChanged", t) != 0) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* see if the backend can give us the USN */
	if (module->ldb->sequence_number != NULL) {
		uint64_t seq_num = module->ldb->sequence_number(module->ldb);
		if (add_uint64_element(msg, "uSNCreated", seq_num) != 0 ||
		    add_uint64_element(msg, "uSNChanged", seq_num) != 0) {
			talloc_free(down_req);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	down_req->op.add.message = msg;
	
	down_req->controls = req->controls;
	down_req->creds = req->creds;

	down_req->async.context = req->async.context;
	down_req->async.callback = req->async.callback;
	down_req->async.timeout = req->async.timeout;

	/* go on with the call chain */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->async.handle = down_req->async.handle;
	}

	return ret;
}

/*
  hook modify record ops
*/
static int operational_modify_async(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_request *down_req;
	struct ldb_message *msg;
	time_t t = time(NULL);
	int ret;

	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	down_req = talloc(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* we have to copy the message as the caller might have it as a const */
	msg = ldb_msg_copy_shallow(down_req, req->op.mod.message);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	if (add_time_element(msg, "whenChanged", t) != 0) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* update the records USN if possible */
	if (module->ldb->sequence_number != NULL &&
	    add_uint64_element(msg, "uSNChanged", 
			       module->ldb->sequence_number(module->ldb)) != 0) {
		talloc_free(down_req);
		return -1;
	}

	down_req->op.mod.message = msg;
	
	down_req->controls = req->controls;
	down_req->creds = req->creds;

	down_req->async.context = req->async.context;
	down_req->async.callback = req->async.callback;
	down_req->async.timeout = req->async.timeout;

	/* go on with the call chain */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->async.handle = down_req->async.handle;
	}

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

	case LDB_ASYNC_SEARCH:
		return operational_search_async(module, req);

	case LDB_ASYNC_ADD:
		return operational_add_async(module, req);

	case LDB_ASYNC_MODIFY:
		return operational_modify_async(module, req);

	default:
		return ldb_next_request(module, req);

	}
}

static int operational_init(struct ldb_module *ctx)
{
	/* setup some standard attribute handlers */
	ldb_set_attrib_handler_syntax(ctx->ldb, "whenCreated", LDB_SYNTAX_UTC_TIME);
	ldb_set_attrib_handler_syntax(ctx->ldb, "whenChanged", LDB_SYNTAX_UTC_TIME);
	ldb_set_attrib_handler_syntax(ctx->ldb, "subschemaSubentry", LDB_SYNTAX_DN);
	ldb_set_attrib_handler_syntax(ctx->ldb, "structuralObjectClass", LDB_SYNTAX_OBJECTCLASS);

	return ldb_next_init(ctx);
}

static const struct ldb_module_ops operational_ops = {
	.name              = "operational",
	.request           = operational_request,
	.init_context	   = operational_init
};

int ldb_operational_init(void)
{
	return ldb_register_module(&operational_ops);
}
