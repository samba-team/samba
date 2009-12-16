/*
   ldb database library

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Simo Sorce 2006-2008
   Copyright (C) Matthias Dieter Wallnöfer 2009

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

  structuralObjectClass: HIDDEN, CONSTRUCTED, not-searchable. always same as objectclass?

     for this one we do the search as normal, then if requested ask
     for objectclass, change the attribute name, and add it

  primaryGroupToken: HIDDEN, CONSTRUCTED, SEARCHABLE

     contains the RID of a certain group object
    

  attributeTypes: in schema only
  objectClasses: in schema only
  matchingRules: in schema only
  matchingRuleUse: in schema only
  creatorsName: not supported by w2k3?
  modifiersName: not supported by w2k3?
*/

#include "includes.h"
#include "ldb_includes.h"
#include "ldb_module.h"

#include "librpc/gen_ndr/ndr_misc.h"
#include "param/param.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

struct operational_data {
	struct ldb_dn *aggregate_dn;
};

/*
  construct a canonical name from a message
*/
static int construct_canonical_name(struct ldb_module *module,
	struct ldb_message *msg)
{
	char *canonicalName;
	canonicalName = ldb_dn_canonical_string(msg, msg->dn);
	if (canonicalName == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	return ldb_msg_add_steal_string(msg, "canonicalName", canonicalName);
}

/*
  construct a primary group token for groups from a message
*/
static int construct_primary_group_token(struct ldb_module *module,
					 struct ldb_message *msg)
{
	struct ldb_context *ldb;
	uint32_t primary_group_token;
	
	ldb = ldb_module_get_ctx(module);
	if (ldb_match_msg_objectclass(msg, "group") == 1) {
		primary_group_token
			= samdb_result_rid_from_sid(ldb, msg, "objectSid", 0);
		if (primary_group_token == 0) {
			return LDB_SUCCESS;
		}

		return samdb_msg_add_int(ldb, ldb, msg, "primaryGroupToken",
			primary_group_token);
	} else {
		return LDB_SUCCESS;
	}
}

static int construct_parent_guid(struct ldb_module *module,
				 struct ldb_message *msg)
{
	struct ldb_result *res;
	const struct ldb_val *parent_guid;
	const char *attrs[] = { "objectGUID", NULL };
	int ret;
	struct ldb_val v;

	/* TODO:  In the future, this needs to honour the partition boundaries */
	struct ldb_dn *parent_dn = ldb_dn_get_parent(msg, msg->dn);

	if (parent_dn == NULL) {
		DEBUG(4,(__location__ ": Failed to find parent for dn %s\n",
					 ldb_dn_get_linearized(msg->dn)));
		return LDB_SUCCESS;
	}

	ret = dsdb_module_search_dn(module, msg, &res, parent_dn, attrs, DSDB_SEARCH_SHOW_DELETED);
	talloc_free(parent_dn);
	/* if there is no parentGUID for this object, then return */
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		DEBUG(4,(__location__ ": Parent dn for %s does not exist \n",
			 ldb_dn_get_linearized(msg->dn)));
		return LDB_SUCCESS;
	} else if (ret != LDB_SUCCESS) {
		return ret;
	}

	parent_guid = ldb_msg_find_ldb_val(res->msgs[0], "objectGUID");
	if (!parent_guid) {
		talloc_free(res);
		return LDB_SUCCESS;
	}

	v = data_blob_dup_talloc(res, parent_guid);
	if (!v.data) {
		talloc_free(res);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ldb_msg_add_steal_value(msg, "parentGUID", &v);
	talloc_free(res);
	return ret;
}

/*
  construct a subSchemaSubEntry
*/
static int construct_subschema_subentry(struct ldb_module *module,
					struct ldb_message *msg)
{
	struct operational_data *data = talloc_get_type(ldb_module_get_private(module), struct operational_data);
	char *subSchemaSubEntry;
	if (data && data->aggregate_dn) {
		subSchemaSubEntry = ldb_dn_alloc_linearized(msg, data->aggregate_dn);
		return ldb_msg_add_steal_string(msg, "subSchemaSubEntry", subSchemaSubEntry);
	}
	return LDB_SUCCESS;
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
	const char *extra_attr;
	int (*constructor)(struct ldb_module *, struct ldb_message *);
} search_sub[] = {
	{ "createTimestamp", "whenCreated", NULL , NULL },
	{ "modifyTimestamp", "whenChanged", NULL , NULL },
	{ "structuralObjectClass", "objectClass", NULL , NULL },
	{ "canonicalName", "distinguishedName", NULL , construct_canonical_name },
	{ "primaryGroupToken", "objectClass", "objectSid", construct_primary_group_token },
	{ "parentGUID", NULL, NULL, construct_parent_guid },
	{ "subSchemaSubEntry", NULL, NULL, construct_subschema_subentry }
};


enum op_remove {
	OPERATIONAL_REMOVE_ALWAYS, /* remove always */
	OPERATIONAL_REMOVE_UNASKED,/* remove if not requested */
	OPERATIONAL_SD_FLAGS	   /* show if SD_FLAGS_OID set, or asked for */
};

/*
  a list of attributes that may need to be removed from the
  underlying db return
*/
static const struct {
	const char *attr;
	enum op_remove op;
} operational_remove[] = {
	{ "nTSecurityDescriptor",    OPERATIONAL_SD_FLAGS },
	{ "parentGUID",              OPERATIONAL_REMOVE_ALWAYS  },
	{ "replPropertyMetaData",    OPERATIONAL_REMOVE_UNASKED },
	{ "unicodePwd",              OPERATIONAL_REMOVE_UNASKED },
	{ "dBCSPwd",                 OPERATIONAL_REMOVE_UNASKED },
	{ "ntPwdHistory",            OPERATIONAL_REMOVE_UNASKED },
	{ "lmPwdHistory",            OPERATIONAL_REMOVE_UNASKED },
	{ "supplementalCredentials", OPERATIONAL_REMOVE_UNASKED }
};


/*
  post process a search result record. For any search_sub[] attributes that were
  asked for, we need to call the appropriate copy routine to copy the result
  into the message, then remove any attributes that we added to the search but
  were not asked for by the user
*/
static int operational_search_post_process(struct ldb_module *module,
					   struct ldb_message *msg,
					   const char * const *attrs,
					   bool sd_flags_set)
{
	struct ldb_context *ldb;
	int i, a=0;

	ldb = ldb_module_get_ctx(module);

	/* removed any attrs that should not be shown to the user */
	for (i=0; i<ARRAY_SIZE(operational_remove); i++) {
		switch (operational_remove[i].op) {
		case OPERATIONAL_REMOVE_UNASKED:
			if (ldb_attr_in_list(attrs, operational_remove[i].attr)) {
				continue;
			}
		case OPERATIONAL_REMOVE_ALWAYS:
			ldb_msg_remove_attr(msg, operational_remove[i].attr);
			break;
		case OPERATIONAL_SD_FLAGS:
			if (sd_flags_set ||
			    ldb_attr_in_list(attrs, operational_remove[i].attr)) {
				continue;
			}
			ldb_msg_remove_attr(msg, operational_remove[i].attr);
			break;
		}
	}

	for (a=0;attrs && attrs[a];a++) {
		for (i=0;i<ARRAY_SIZE(search_sub);i++) {
			if (ldb_attr_cmp(attrs[a], search_sub[i].attr) != 0) {
				continue;
			}

			/* construct the new attribute, using either a supplied
			   constructor or a simple copy */
			if (search_sub[i].constructor != NULL) {
				if (search_sub[i].constructor(module, msg) != LDB_SUCCESS) {
					goto failed;
				}
			} else if (ldb_msg_copy_attr(msg,
						     search_sub[i].replace,
						     search_sub[i].attr) != LDB_SUCCESS) {
				goto failed;
			}

			/* remove the added search attribute, unless it was
 			   asked for by the user */
			if (search_sub[i].replace != NULL && 
			    !ldb_attr_in_list(attrs, search_sub[i].replace) &&
			    !ldb_attr_in_list(attrs, "*")) {
				ldb_msg_remove_attr(msg, search_sub[i].replace);
			}
			if (search_sub[i].extra_attr != NULL && 
			    !ldb_attr_in_list(attrs, search_sub[i].extra_attr) &&
			    !ldb_attr_in_list(attrs, "*")) {
				ldb_msg_remove_attr(msg, search_sub[i].extra_attr);
			}
		}
	}

	return 0;

failed:
	ldb_debug_set(ldb, LDB_DEBUG_WARNING,
		      "operational_search_post_process failed for attribute '%s'",
		      attrs[a]);
	return -1;
}


/*
  hook search operations
*/

struct operational_context {
	struct ldb_module *module;
	struct ldb_request *req;

	const char * const *attrs;
	bool sd_flags_set;
};

static int operational_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct operational_context *ac;
	int ret;

	ac = talloc_get_type(req->context, struct operational_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		/* for each record returned post-process to add any derived
		   attributes that have been asked for */
		ret = operational_search_post_process(ac->module,
						      ares->message,
						      ac->attrs,
						      ac->sd_flags_set);
		if (ret != 0) {
			return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
		}
		return ldb_module_send_entry(ac->req, ares->message, ares->controls);

	case LDB_REPLY_REFERRAL:
		/* ignore referrals */
		break;

	case LDB_REPLY_DONE:

		return ldb_module_done(ac->req, ares->controls,
					ares->response, LDB_SUCCESS);
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

static int operational_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct operational_context *ac;
	struct ldb_request *down_req;
	const char **search_attrs = NULL;
	int i, a;
	int ret;

	ldb = ldb_module_get_ctx(module);

	ac = talloc(req, struct operational_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->req = req;
	ac->attrs = req->op.search.attrs;

	/*  FIXME: We must copy the tree and keep the original
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

				if (search_sub[i].extra_attr) {
					const char **search_attrs2;
					/* Only adds to the end of the list */
					search_attrs2 = ldb_attr_list_copy_add(req, search_attrs
									       ? search_attrs
									       : ac->attrs, 
									       search_sub[i].extra_attr);
					if (search_attrs2 == NULL) {
						return LDB_ERR_OPERATIONS_ERROR;
					}
					/* may be NULL, talloc_free() doesn't mind */
					talloc_free(search_attrs);
					search_attrs = search_attrs2;
				}

				if (!search_attrs) {
					search_attrs = ldb_attr_list_copy(req, ac->attrs);
					if (search_attrs == NULL) {
						return LDB_ERR_OPERATIONS_ERROR;
					}
				}
				/* Despite the ldb_attr_list_copy_add, this is safe as that fn only adds to the end */
				search_attrs[a] = search_sub[i].replace;
			}
		}
	}

	/* remember if the SD_FLAGS_OID was set */
	ac->sd_flags_set = (ldb_request_get_control(req, LDB_CONTROL_SD_FLAGS_OID) != NULL);

	ret = ldb_build_search_req_ex(&down_req, ldb, ac,
					req->op.search.base,
					req->op.search.scope,
					req->op.search.tree,
					/* use new set of attrs if any */
					search_attrs == NULL?req->op.search.attrs:search_attrs,
					req->controls,
					ac, operational_callback,
					req);
	if (ret != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* perform the search */
	return ldb_next_request(module, down_req);
}

static int operational_init(struct ldb_module *ctx)
{
	struct operational_data *data;
	struct ldb_context *ldb = ldb_module_get_ctx(ctx);
	int ret = ldb_next_init(ctx);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	data = talloc(ctx, struct operational_data);
	if (!data) {
		ldb_module_oom(ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	data->aggregate_dn = samdb_aggregate_schema_dn(ldb, data);
	if (!data->aggregate_dn) {
		ldb_set_errstring(ldb, "Could not build aggregate schema DN");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb_module_set_private(ctx, data);

	return LDB_SUCCESS;
}

const struct ldb_module_ops ldb_operational_module_ops = {
	.name              = "operational",
	.search            = operational_search,
	.init_context	   = operational_init
};
