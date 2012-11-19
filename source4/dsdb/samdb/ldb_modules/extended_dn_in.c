/* 
   ldb database library

   Copyright (C) Simo Sorce 2005-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2007-2008

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
 *  Component: ldb extended dn control module
 *
 *  Description: this module interprets DNs of the form <SID=S-1-2-4456> into normal DNs.
 *
 *  Authors: Simo Sorce
 *           Andrew Bartlett
 */

#include "includes.h"
#include <ldb.h>
#include <ldb_errors.h>
#include <ldb_module.h>
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"

/*
  TODO: if relax is not set then we need to reject the fancy RMD_* and
  DELETED extended DN codes
 */

/* search */
struct extended_search_context {
	struct ldb_module *module;
	struct ldb_request *req;
	struct ldb_dn *basedn;
	struct ldb_dn *dn;
	char *wellknown_object;
	int extended_type;
};

static const char *wkattr[] = {
	"wellKnownObjects",
	"otherWellKnownObjects",
	NULL
};
/* An extra layer of indirection because LDB does not allow the original request to be altered */

static int extended_final_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	int ret = LDB_ERR_OPERATIONS_ERROR;
	struct extended_search_context *ac;
	ac = talloc_get_type(req->context, struct extended_search_context);

	if (ares->error != LDB_SUCCESS) {
		ret = ldb_module_done(ac->req, ares->controls,
				      ares->response, ares->error);
	} else {
		switch (ares->type) {
		case LDB_REPLY_ENTRY:
			
			ret = ldb_module_send_entry(ac->req, ares->message, ares->controls);
			break;
		case LDB_REPLY_REFERRAL:
			
			ret = ldb_module_send_referral(ac->req, ares->referral);
			break;
		case LDB_REPLY_DONE:
			
			ret = ldb_module_done(ac->req, ares->controls,
					      ares->response, ares->error);
			break;
		}
	}
	return ret;
}

static int extended_base_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct extended_search_context *ac;
	struct ldb_request *down_req;
	struct ldb_message_element *el;
	int ret;
	unsigned int i, j;
	size_t wkn_len = 0;
	char *valstr = NULL;
	const char *found = NULL;

	ac = talloc_get_type(req->context, struct extended_search_context);

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
		if (ac->basedn) {
			/* we have more than one match! This can
			   happen as S-1-5-17 appears twice in a
			   normal provision. We need to return
			   NO_SUCH_OBJECT */
			const char *str = talloc_asprintf(req, "Duplicate base-DN matches found for '%s'",
							  ldb_dn_get_extended_linearized(req, ac->dn, 1));
			ldb_set_errstring(ldb_module_get_ctx(ac->module), str);
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_ERR_NO_SUCH_OBJECT);
		}

		if (!ac->wellknown_object) {
			ac->basedn = talloc_steal(ac, ares->message->dn);
			break;
		}

		wkn_len = strlen(ac->wellknown_object);

		for (j=0; wkattr[j]; j++) {

			el = ldb_msg_find_element(ares->message, wkattr[j]);
			if (!el) {
				ac->basedn = NULL;
				continue;
			}

			for (i=0; i < el->num_values; i++) {
				valstr = talloc_strndup(ac,
							(const char *)el->values[i].data,
							el->values[i].length);
				if (!valstr) {
					ldb_oom(ldb_module_get_ctx(ac->module));
					return ldb_module_done(ac->req, NULL, NULL,
							LDB_ERR_OPERATIONS_ERROR);
				}

				if (strncasecmp(valstr, ac->wellknown_object, wkn_len) != 0) {
					talloc_free(valstr);
					continue;
				}

				found = &valstr[wkn_len];
				break;
			}
			if (found) {
				break;
			}
		}

		if (!found) {
			break;
		}

		ac->basedn = ldb_dn_new(ac, ldb_module_get_ctx(ac->module), found);
		talloc_free(valstr);
		if (!ac->basedn) {
			ldb_oom(ldb_module_get_ctx(ac->module));
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_ERR_OPERATIONS_ERROR);
		}

		break;

	case LDB_REPLY_REFERRAL:
		break;

	case LDB_REPLY_DONE:

		if (!ac->basedn) {
			const char *str = talloc_asprintf(req, "Base-DN '%s' not found",
							  ldb_dn_get_extended_linearized(req, ac->dn, 1));
			ldb_set_errstring(ldb_module_get_ctx(ac->module), str);
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_ERR_NO_SUCH_OBJECT);
		}

		switch (ac->req->operation) {
		case LDB_SEARCH:
			ret = ldb_build_search_req_ex(&down_req,
						      ldb_module_get_ctx(ac->module), ac->req,
						      ac->basedn,
						      ac->req->op.search.scope,
						      ac->req->op.search.tree,
						      ac->req->op.search.attrs,
						      ac->req->controls,
						      ac, extended_final_callback, 
						      ac->req);
			LDB_REQ_SET_LOCATION(down_req);
			break;
		case LDB_ADD:
		{
			struct ldb_message *add_msg = ldb_msg_copy_shallow(ac, ac->req->op.add.message);
			if (!add_msg) {
				ldb_oom(ldb_module_get_ctx(ac->module));
				return ldb_module_done(ac->req, NULL, NULL,
						       LDB_ERR_OPERATIONS_ERROR);
			}
			
			add_msg->dn = ac->basedn;

			ret = ldb_build_add_req(&down_req,
						ldb_module_get_ctx(ac->module), ac->req,
						add_msg, 
						ac->req->controls,
						ac, extended_final_callback, 
						ac->req);
			LDB_REQ_SET_LOCATION(down_req);
			break;
		}
		case LDB_MODIFY:
		{
			struct ldb_message *mod_msg = ldb_msg_copy_shallow(ac, ac->req->op.mod.message);
			if (!mod_msg) {
				ldb_oom(ldb_module_get_ctx(ac->module));
				return ldb_module_done(ac->req, NULL, NULL,
						       LDB_ERR_OPERATIONS_ERROR);
			}
			
			mod_msg->dn = ac->basedn;

			ret = ldb_build_mod_req(&down_req,
						ldb_module_get_ctx(ac->module), ac->req,
						mod_msg, 
						ac->req->controls,
						ac, extended_final_callback, 
						ac->req);
			LDB_REQ_SET_LOCATION(down_req);
			break;
		}
		case LDB_DELETE:
			ret = ldb_build_del_req(&down_req,
						ldb_module_get_ctx(ac->module), ac->req,
						ac->basedn, 
						ac->req->controls,
						ac, extended_final_callback, 
						ac->req);
			LDB_REQ_SET_LOCATION(down_req);
			break;
		case LDB_RENAME:
			ret = ldb_build_rename_req(&down_req,
						   ldb_module_get_ctx(ac->module), ac->req,
						   ac->basedn, 
						   ac->req->op.rename.newdn,
						   ac->req->controls,
						   ac, extended_final_callback, 
						   ac->req);
			LDB_REQ_SET_LOCATION(down_req);
			break;
		default:
			return ldb_module_done(ac->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
		}
		
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}

		return ldb_next_request(ac->module, down_req);
	}
	talloc_free(ares);
	return LDB_SUCCESS;
}


/*
  windows ldap searchs don't allow a baseDN with more
  than one extended component, or an extended
  component and a string DN

  We only enforce this over ldap, not for internal
  use, as there are just too many places where we
  internally want to use a DN that has come from a
  search with extended DN enabled, or comes from a DRS
  naming context.

  Enforcing this would also make debugging samba much
  harder, as we'd need to use ldb_dn_minimise() in a
  lot of places, and that would lose the DN string
  which is so useful for working out what a request is
  for
*/
static bool ldb_dn_match_allowed(struct ldb_dn *dn, struct ldb_request *req)
{
	int num_components = ldb_dn_get_comp_num(dn);
	int num_ex_components = ldb_dn_get_extended_comp_num(dn);

	if (num_ex_components == 0) {
		return true;
	}

	if ((num_components != 0 || num_ex_components != 1) &&
	    ldb_req_is_untrusted(req)) {
		return false;
	}
	return true;
}


struct extended_dn_filter_ctx {
	bool test_only;
	bool matched;
	struct ldb_module *module;
	struct ldb_request *req;
	struct dsdb_schema *schema;
};

/*
  create a always non-matching node from a equality node
 */
static void set_parse_tree_false(struct ldb_parse_tree *tree)
{
	const char *attr = tree->u.equality.attr;
	struct ldb_val value = tree->u.equality.value;
	tree->operation = LDB_OP_EXTENDED;
	tree->u.extended.attr = attr;
	tree->u.extended.value = value;
	tree->u.extended.rule_id = SAMBA_LDAP_MATCH_ALWAYS_FALSE;
	tree->u.extended.dnAttributes = 0;
}

/*
  called on all nodes in the parse tree
 */
static int extended_dn_filter_callback(struct ldb_parse_tree *tree, void *private_context)
{
	struct extended_dn_filter_ctx *filter_ctx;
	int ret;
	struct ldb_dn *dn;
	const struct ldb_val *sid_val, *guid_val;
	const char *no_attrs[] = { NULL };
	struct ldb_result *res;
	const struct dsdb_attribute *attribute;
	bool has_extended_component;
	enum ldb_scope scope;
	struct ldb_dn *base_dn;
	const char *expression;
	uint32_t dsdb_flags;

	if (tree->operation != LDB_OP_EQUALITY) {
		return LDB_SUCCESS;
	}

	filter_ctx = talloc_get_type_abort(private_context, struct extended_dn_filter_ctx);

	if (filter_ctx->test_only && filter_ctx->matched) {
		/* the tree already matched */
		return LDB_SUCCESS;
	}

	if (!filter_ctx->schema) {
		/* Schema not setup yet */
		return LDB_SUCCESS;
	}
	attribute = dsdb_attribute_by_lDAPDisplayName(filter_ctx->schema, tree->u.equality.attr);
	if (attribute == NULL) {
		return LDB_SUCCESS;
	}

	if (attribute->dn_format != DSDB_NORMAL_DN) {
		return LDB_SUCCESS;
	}

	has_extended_component = (memchr(tree->u.equality.value.data, '<',
					 tree->u.equality.value.length) != NULL);

	if (!attribute->one_way_link && !has_extended_component) {
		return LDB_SUCCESS;
	}

	dn = ldb_dn_from_ldb_val(filter_ctx, ldb_module_get_ctx(filter_ctx->module), &tree->u.equality.value);
	if (dn == NULL) {
		/* testing against windows shows that we don't raise
		   an error here */
		return LDB_SUCCESS;
	}

	guid_val = ldb_dn_get_extended_component(dn, "GUID");
	sid_val  = ldb_dn_get_extended_component(dn, "SID");

	if (!guid_val && !sid_val && (attribute->searchFlags & SEARCH_FLAG_ATTINDEX)) {
		/* if it is indexed, then fixing the string DN will do
		   no good here, as we will not find the attribute in
		   the index. So for now fall through to a standard DN
		   component comparison */
		return LDB_SUCCESS;
	}

	if (filter_ctx->test_only) {
		/* we need to copy the tree */
		filter_ctx->matched = true;
		return LDB_SUCCESS;
	}

	if (!ldb_dn_match_allowed(dn, filter_ctx->req)) {
		/* we need to make this element of the filter always
		   be false */
		set_parse_tree_false(tree);
		return LDB_SUCCESS;
	}

	dsdb_flags = DSDB_FLAG_NEXT_MODULE |
		DSDB_FLAG_AS_SYSTEM |
		DSDB_SEARCH_SHOW_RECYCLED |
		DSDB_SEARCH_SHOW_EXTENDED_DN;

	if (guid_val) {
		expression = talloc_asprintf(filter_ctx, "objectGUID=%s", ldb_binary_encode(filter_ctx, *guid_val));
		scope = LDB_SCOPE_SUBTREE;
		base_dn = NULL;
		dsdb_flags |= DSDB_SEARCH_SEARCH_ALL_PARTITIONS;
	} else if (sid_val) {
		expression = talloc_asprintf(filter_ctx, "objectSID=%s", ldb_binary_encode(filter_ctx, *sid_val));
		scope = LDB_SCOPE_SUBTREE;
		base_dn = NULL;
		dsdb_flags |= DSDB_SEARCH_SEARCH_ALL_PARTITIONS;
	} else {
		/* fallback to searching using the string DN as the base DN */
		expression = "objectClass=*";
		base_dn = dn;
		scope = LDB_SCOPE_BASE;
	}

	ret = dsdb_module_search(filter_ctx->module,
				 filter_ctx,
				 &res,
				 base_dn,
				 scope,
				 no_attrs,
				 dsdb_flags,
				 filter_ctx->req,
				 "%s", expression);
	if (scope == LDB_SCOPE_BASE && ret == LDB_ERR_NO_SUCH_OBJECT) {
		/* note that this will need to change for multi-domain
		   support */
		set_parse_tree_false(tree);
		return LDB_SUCCESS;
	}

	if (ret != LDB_SUCCESS) {
		return LDB_SUCCESS;
	}


	if (res->count != 1) {
		return LDB_SUCCESS;
	}

	/* replace the search expression element with the matching DN */
	tree->u.equality.value.data = (uint8_t *)talloc_strdup(tree,
							       ldb_dn_get_extended_linearized(tree, res->msgs[0]->dn, 1));
	if (tree->u.equality.value.data == NULL) {
		return ldb_oom(ldb_module_get_ctx(filter_ctx->module));
	}
	tree->u.equality.value.length = strlen((const char *)tree->u.equality.value.data);
	talloc_free(res);

	filter_ctx->matched = true;
	return LDB_SUCCESS;
}

/*
  fix the parse tree to change any extended DN components to their
  caconical form
 */
static int extended_dn_fix_filter(struct ldb_module *module, struct ldb_request *req)
{
	struct extended_dn_filter_ctx *filter_ctx;
	int ret;

	filter_ctx = talloc_zero(req, struct extended_dn_filter_ctx);
	if (filter_ctx == NULL) {
		return ldb_module_oom(module);
	}

	/* first pass through the existing tree to see if anything
	   needs to be modified. Filtering DNs on the input side is rare,
	   so this avoids copying the parse tree in most cases */
	filter_ctx->test_only = true;
	filter_ctx->matched   = false;
	filter_ctx->module    = module;
	filter_ctx->req       = req;
	filter_ctx->schema    = dsdb_get_schema(ldb_module_get_ctx(module), filter_ctx);

	ret = ldb_parse_tree_walk(req->op.search.tree, extended_dn_filter_callback, filter_ctx);
	if (ret != LDB_SUCCESS) {
		talloc_free(filter_ctx);
		return ret;
	}

	if (!filter_ctx->matched) {
		/* nothing matched, no need for a new parse tree */
		talloc_free(filter_ctx);
		return LDB_SUCCESS;
	}

	filter_ctx->test_only = false;
	filter_ctx->matched   = false;

	req->op.search.tree = ldb_parse_tree_copy_shallow(req, req->op.search.tree);
	if (req->op.search.tree == NULL) {
		return ldb_oom(ldb_module_get_ctx(module));
	}

	ret = ldb_parse_tree_walk(req->op.search.tree, extended_dn_filter_callback, filter_ctx);
	if (ret != LDB_SUCCESS) {
		talloc_free(filter_ctx);
		return ret;
	}

	talloc_free(filter_ctx);
	return LDB_SUCCESS;
}

/*
  fix DNs and filter expressions to cope with the semantics of
  extended DNs
 */
static int extended_dn_in_fix(struct ldb_module *module, struct ldb_request *req, struct ldb_dn *dn)
{
	struct extended_search_context *ac;
	struct ldb_request *down_req;
	int ret;
	struct ldb_dn *base_dn = NULL;
	enum ldb_scope base_dn_scope = LDB_SCOPE_BASE;
	const char *base_dn_filter = NULL;
	const char * const *base_dn_attrs = NULL;
	char *wellknown_object = NULL;
	static const char *no_attr[] = {
		NULL
	};
	bool all_partitions = false;

	if (req->operation == LDB_SEARCH) {
		ret = extended_dn_fix_filter(module, req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (!ldb_dn_has_extended(dn)) {
		/* Move along there isn't anything to see here */
		return ldb_next_request(module, req);
	} else {
		/* It looks like we need to map the DN */
		const struct ldb_val *sid_val, *guid_val, *wkguid_val;
		uint32_t dsdb_flags = 0;

		if (!ldb_dn_match_allowed(dn, req)) {
			return ldb_error(ldb_module_get_ctx(module),
					 LDB_ERR_INVALID_DN_SYNTAX, "invalid number of DN components");
		}

		sid_val = ldb_dn_get_extended_component(dn, "SID");
		guid_val = ldb_dn_get_extended_component(dn, "GUID");
		wkguid_val = ldb_dn_get_extended_component(dn, "WKGUID");

		/*
		  prioritise the GUID - we have had instances of
		  duplicate SIDs in the database in the
		  ForeignSecurityPrinciples due to provision errors
		 */
		if (guid_val) {
			all_partitions = true;
			base_dn = NULL;
			base_dn_filter = talloc_asprintf(req, "(objectGUID=%s)",
							 ldb_binary_encode(req, *guid_val));
			if (!base_dn_filter) {
				return ldb_oom(ldb_module_get_ctx(module));
			}
			base_dn_scope = LDB_SCOPE_SUBTREE;
			base_dn_attrs = no_attr;

		} else if (sid_val) {
			all_partitions = true;
			base_dn = NULL;
			base_dn_filter = talloc_asprintf(req, "(objectSid=%s)",
							 ldb_binary_encode(req, *sid_val));
			if (!base_dn_filter) {
				return ldb_oom(ldb_module_get_ctx(module));
			}
			base_dn_scope = LDB_SCOPE_SUBTREE;
			base_dn_attrs = no_attr;

		} else if (wkguid_val) {
			char *wkguid_dup;
			char *tail_str;
			char *p;

			wkguid_dup = talloc_strndup(req, (char *)wkguid_val->data, wkguid_val->length);

			p = strchr(wkguid_dup, ',');
			if (!p) {
				return ldb_error(ldb_module_get_ctx(module), LDB_ERR_INVALID_DN_SYNTAX,
						 "Invalid WKGUID format");
			}

			p[0] = '\0';
			p++;

			wellknown_object = talloc_asprintf(req, "B:32:%s:", wkguid_dup);
			if (!wellknown_object) {
				return ldb_oom(ldb_module_get_ctx(module));
			}

			tail_str = p;

			base_dn = ldb_dn_new(req, ldb_module_get_ctx(module), tail_str);
			talloc_free(wkguid_dup);
			if (!base_dn) {
				return ldb_oom(ldb_module_get_ctx(module));
			}
			base_dn_filter = talloc_strdup(req, "(objectClass=*)");
			if (!base_dn_filter) {
				return ldb_oom(ldb_module_get_ctx(module));
			}
			base_dn_scope = LDB_SCOPE_BASE;
			base_dn_attrs = wkattr;
		} else {
			return ldb_error(ldb_module_get_ctx(module), LDB_ERR_INVALID_DN_SYNTAX,
					 "Invalid extended DN component");
		}

		ac = talloc_zero(req, struct extended_search_context);
		if (ac == NULL) {
			return ldb_oom(ldb_module_get_ctx(module));
		}
		
		ac->module = module;
		ac->req = req;
		ac->dn = dn;
		ac->basedn = NULL;  /* Filled in if the search finds the DN by SID/GUID etc */
		ac->wellknown_object = wellknown_object;
		
		/* If the base DN was an extended DN (perhaps a well known
		 * GUID) then search for that, so we can proceed with the original operation */

		ret = ldb_build_search_req(&down_req,
					   ldb_module_get_ctx(module), ac,
					   base_dn,
					   base_dn_scope,
					   base_dn_filter,
					   base_dn_attrs,
					   NULL,
					   ac, extended_base_callback,
					   req);
		LDB_REQ_SET_LOCATION(down_req);
		if (ret != LDB_SUCCESS) {
			return ldb_operr(ldb_module_get_ctx(module));
		}

		dsdb_flags = DSDB_FLAG_AS_SYSTEM |
			DSDB_SEARCH_SHOW_RECYCLED |
			DSDB_SEARCH_SHOW_EXTENDED_DN;
		if (all_partitions) {
			dsdb_flags |= DSDB_SEARCH_SEARCH_ALL_PARTITIONS;
		}

		ret = dsdb_request_add_controls(down_req, dsdb_flags);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		/* perform the search */
		return ldb_next_request(module, down_req);
	}
}

static int extended_dn_in_search(struct ldb_module *module, struct ldb_request *req)
{
	return extended_dn_in_fix(module, req, req->op.search.base);
}

static int extended_dn_in_modify(struct ldb_module *module, struct ldb_request *req)
{
	return extended_dn_in_fix(module, req, req->op.mod.message->dn);
}

static int extended_dn_in_del(struct ldb_module *module, struct ldb_request *req)
{
	return extended_dn_in_fix(module, req, req->op.del.dn);
}

static int extended_dn_in_rename(struct ldb_module *module, struct ldb_request *req)
{
	return extended_dn_in_fix(module, req, req->op.rename.olddn);
}

static const struct ldb_module_ops ldb_extended_dn_in_module_ops = {
	.name		   = "extended_dn_in",
	.search            = extended_dn_in_search,
	.modify            = extended_dn_in_modify,
	.del               = extended_dn_in_del,
	.rename            = extended_dn_in_rename,
};

int ldb_extended_dn_in_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_extended_dn_in_module_ops);
}
