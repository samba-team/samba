/*
  ldb database library

  Copyright (C) Simo Sorce 2006-2008
  Copyright (C) Nadezhda Ivanova 2010

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
 *  Component: ldb ACL Read module
 *
 *  Description: Module that performs authorisation access checks on read requests
 *               Only DACL checks implemented at this point
 *
 *  Author: Nadezhda Ivanova
 */

#include "includes.h"
#include "ldb_module.h"
#include "auth/auth.h"
#include "libcli/security/security.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "param/param.h"
#include "dsdb/samdb/ldb_modules/util.h"

struct aclread_context {
	struct ldb_module *module;
	struct ldb_request *req;
	const char * const *attrs;
	const struct dsdb_schema *schema;
	uint32_t sd_flags;
	bool added_nTSecurityDescriptor;
	bool added_instanceType;
	bool added_objectSid;
	bool added_objectClass;
	bool indirsync;

	bool do_list_object_initialized;
	bool do_list_object;
	bool base_invisible;
	uint64_t num_entries;

	/* cache on the last parent we checked in this search */
	struct ldb_dn *last_parent_dn;
	int last_parent_check_ret;
};

struct aclread_private {
	bool enabled;

	/* cache of the last SD we read during any search */
	struct security_descriptor *sd_cached;
	struct ldb_val sd_cached_blob;
};

static void aclread_mark_inaccesslible(struct ldb_message_element *el) {
	el->flags |= LDB_FLAG_INTERNAL_INACCESSIBLE_ATTRIBUTE;
}

static bool aclread_is_inaccessible(struct ldb_message_element *el) {
	return el->flags & LDB_FLAG_INTERNAL_INACCESSIBLE_ATTRIBUTE;
}

/*
 * the object has a parent, so we have to check for visibility
 *
 * This helper function uses a per-search cache to avoid checking the
 * parent object for each of many possible children.  This is likely
 * to help on SCOPE_ONE searches and on typical tree structures for
 * SCOPE_SUBTREE, where an OU has many users as children.
 *
 * We rely for safety on the DB being locked for reads during the full
 * search.
 */
static int aclread_check_parent(struct aclread_context *ac,
				struct ldb_message *msg,
				struct ldb_request *req)
{
	int ret;
	struct ldb_dn *parent_dn = NULL;

	/* We may have a cached result from earlier in this search */
	if (ac->last_parent_dn != NULL) {
		/*
		 * We try the no-allocation ldb_dn_compare_base()
		 * first however it will not tell parents and
		 * grand-parents apart
		 */
		int cmp_base = ldb_dn_compare_base(ac->last_parent_dn,
						   msg->dn);
		if (cmp_base == 0) {
			/* Now check if it is a direct parent */
			parent_dn = ldb_dn_get_parent(ac, msg->dn);
			if (parent_dn == NULL) {
				return ldb_oom(ldb_module_get_ctx(ac->module));
			}
			if (ldb_dn_compare(ac->last_parent_dn,
					   parent_dn) == 0) {
				TALLOC_FREE(parent_dn);

				/*
				 * If we checked the same parent last
				 * time, then return the cached
				 * result.
				 *
				 * The cache is valid as long as the
				 * search as the DB is read locked and
				 * the session_info (connected user)
				 * is constant.
				 */
				return ac->last_parent_check_ret;
			}
		}
	}

	{
		TALLOC_CTX *frame = NULL;
		frame = talloc_stackframe();

		/*
		 * This may have been set in the block above, don't
		 * re-parse
		 */
		if (parent_dn == NULL) {
			parent_dn = ldb_dn_get_parent(ac, msg->dn);
			if (parent_dn == NULL) {
				TALLOC_FREE(frame);
				return ldb_oom(ldb_module_get_ctx(ac->module));
			}
		}
		ret = dsdb_module_check_access_on_dn(ac->module,
						     frame,
						     parent_dn,
						     SEC_ADS_LIST,
						     NULL, req);
		talloc_unlink(ac, ac->last_parent_dn);
		ac->last_parent_dn = parent_dn;
		ac->last_parent_check_ret = ret;

		TALLOC_FREE(frame);
	}
	return ret;
}

static int aclread_check_object_visible(struct aclread_context *ac,
					struct ldb_message *msg,
					struct ldb_request *req)
{
	uint32_t instanceType;
	int ret;

	/* get the object instance type */
	instanceType = ldb_msg_find_attr_as_uint(msg,
						 "instanceType", 0);
	if (instanceType & INSTANCE_TYPE_IS_NC_HEAD) {
		/*
		 * NC_HEAD objects are always visible
		 */
		return LDB_SUCCESS;
	}

	ret = aclread_check_parent(ac, msg, req);
	if (ret == LDB_SUCCESS) {
		/*
		 * SEC_ADS_LIST (List Children) alone
		 * on the parent is enough to make the
		 * object visible.
		 */
		return LDB_SUCCESS;
	}
	if (ret != LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		return ret;
	}

	if (!ac->do_list_object_initialized) {
		/*
		 * We only call dsdb_do_list_object() once
		 * and only when needed in order to
		 * check the dSHeuristics for fDoListObject.
		 */
		ac->do_list_object = dsdb_do_list_object(ac->module, ac, req);
		ac->do_list_object_initialized = true;
	}

	if (ac->do_list_object) {
		TALLOC_CTX *frame = talloc_stackframe();
		struct ldb_dn *parent_dn = NULL;

		/*
		 * Here we're in "List Object" mode (fDoListObject=true).
		 *
		 * If SEC_ADS_LIST (List Children) is not
		 * granted on the parent, we need to check if
		 * SEC_ADS_LIST_OBJECT (List Object) is granted
		 * on the parent and also on the object itself.
		 *
		 * We could optimize this similar to aclread_check_parent(),
		 * but that would require quite a bit of restructuring,
		 * so that we cache the granted access bits instead
		 * of just the result for 'SEC_ADS_LIST (List Children)'.
		 *
		 * But as this is the uncommon case and
		 * 'SEC_ADS_LIST (List Children)' is most likely granted
		 * on most of the objects, we'll just implement what
		 * we have to.
		 */

		parent_dn = ldb_dn_get_parent(frame, msg->dn);
		if (parent_dn == NULL) {
			TALLOC_FREE(frame);
			return ldb_oom(ldb_module_get_ctx(ac->module));
		}
		ret = dsdb_module_check_access_on_dn(ac->module,
						     frame,
						     parent_dn,
						     SEC_ADS_LIST_OBJECT,
						     NULL, req);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(frame);
			return ret;
		}
		ret = dsdb_module_check_access_on_dn(ac->module,
						     frame,
						     msg->dn,
						     SEC_ADS_LIST_OBJECT,
						     NULL, req);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(frame);
			return ret;
		}

		TALLOC_FREE(frame);
		return LDB_SUCCESS;
	}

	return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
}

/*
 * The sd returned from this function is valid until the next call on
 * this module context
 *
 * This helper function uses a cache on the module private data to
 * speed up repeated use of the same SD.
 */

static int aclread_get_sd_from_ldb_message(struct aclread_context *ac,
					   struct ldb_message *acl_res,
					   struct security_descriptor **sd)
{
	struct ldb_message_element *sd_element;
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct aclread_private *private_data
		= talloc_get_type(ldb_module_get_private(ac->module),
				  struct aclread_private);
	enum ndr_err_code ndr_err;

	sd_element = ldb_msg_find_element(acl_res, "nTSecurityDescriptor");
	if (sd_element == NULL) {
		return ldb_error(ldb, LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS,
				 "nTSecurityDescriptor is missing");
	}

	if (sd_element->num_values != 1) {
		return ldb_operr(ldb);
	}

	/*
	 * The time spent in ndr_pull_security_descriptor() is quite
	 * expensive, so we check if this is the same binary blob as last
	 * time, and if so return the memory tree from that previous parse.
	 */

	if (private_data->sd_cached != NULL &&
	    private_data->sd_cached_blob.data != NULL &&
	    ldb_val_equal_exact(&sd_element->values[0],
				&private_data->sd_cached_blob)) {
		*sd = private_data->sd_cached;
		return LDB_SUCCESS;
	}

	*sd = talloc(private_data, struct security_descriptor);
	if(!*sd) {
		return ldb_oom(ldb);
	}
	ndr_err = ndr_pull_struct_blob(&sd_element->values[0], *sd, *sd,
			     (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(*sd);
		return ldb_operr(ldb);
	}

	talloc_unlink(private_data, private_data->sd_cached_blob.data);
	if (ac->added_nTSecurityDescriptor) {
		private_data->sd_cached_blob = sd_element->values[0];
		talloc_steal(private_data, sd_element->values[0].data);
	} else {
		private_data->sd_cached_blob = ldb_val_dup(private_data,
							   &sd_element->values[0]);
		if (private_data->sd_cached_blob.data == NULL) {
			TALLOC_FREE(*sd);
			return ldb_operr(ldb);
		}
	}

	talloc_unlink(private_data, private_data->sd_cached);
	private_data->sd_cached = *sd;

	return LDB_SUCCESS;
}

/*
 * Returns the access mask required to read a given attribute
 */
static uint32_t get_attr_access_mask(const struct dsdb_attribute *attr,
				     uint32_t sd_flags)
{

	uint32_t access_mask = 0;
	bool is_sd;

	/* nTSecurityDescriptor is a special case */
	is_sd = (ldb_attr_cmp("nTSecurityDescriptor",
			      attr->lDAPDisplayName) == 0);

	if (is_sd) {
		if (sd_flags & (SECINFO_OWNER|SECINFO_GROUP)) {
			access_mask |= SEC_STD_READ_CONTROL;
		}
		if (sd_flags & SECINFO_DACL) {
			access_mask |= SEC_STD_READ_CONTROL;
		}
		if (sd_flags & SECINFO_SACL) {
			access_mask |= SEC_FLAG_SYSTEM_SECURITY;
		}
	} else {
		access_mask = SEC_ADS_READ_PROP;
	}

	if (attr->searchFlags & SEARCH_FLAG_CONFIDENTIAL) {
		access_mask |= SEC_ADS_CONTROL_ACCESS;
	}

	return access_mask;
}

/* helper struct for traversing the attributes in the search-tree */
struct parse_tree_aclread_ctx {
	struct aclread_context *ac;
	TALLOC_CTX *mem_ctx;
	struct dom_sid *sid;
	struct ldb_dn *dn;
	struct security_descriptor *sd;
	const struct dsdb_class *objectclass;
	bool suppress_result;
};

/*
 * Checks that the user has sufficient access rights to view an attribute
 */
static int check_attr_access_rights(TALLOC_CTX *mem_ctx, const char *attr_name,
				    struct aclread_context *ac,
				    struct security_descriptor *sd,
				    const struct dsdb_class *objectclass,
				    struct dom_sid *sid, struct ldb_dn *dn)
{
	int ret;
	const struct dsdb_attribute *attr = NULL;
	uint32_t access_mask;
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);

	attr = dsdb_attribute_by_lDAPDisplayName(ac->schema, attr_name);
	if (!attr) {
		ldb_debug_set(ldb,
			      LDB_DEBUG_TRACE,
			      "acl_read: %s cannot find attr[%s] in schema,"
			      "ignoring\n",
			      ldb_dn_get_linearized(dn), attr_name);
		return LDB_SUCCESS;
	}

	access_mask = get_attr_access_mask(attr, ac->sd_flags);

	/* the access-mask should be non-zero. Skip attribute otherwise */
	if (access_mask == 0) {
		DBG_ERR("Could not determine access mask for attribute %s\n",
			attr_name);
		return LDB_SUCCESS;
	}

	ret = acl_check_access_on_attribute(ac->module, mem_ctx, sd, sid,
					    access_mask, attr, objectclass);

	if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		return ret;
	}

	if (ret != LDB_SUCCESS) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "acl_read: %s check attr[%s] gives %s - %s\n",
			      ldb_dn_get_linearized(dn), attr_name,
			      ldb_strerror(ret), ldb_errstring(ldb));
		return ret;
	}

	return LDB_SUCCESS;
}

/*
 * Returns the attribute name for this particular level of a search operation
 * parse-tree.
 */
static const char * parse_tree_get_attr(struct ldb_parse_tree *tree)
{
	const char *attr = NULL;

	switch (tree->operation) {
	case LDB_OP_EQUALITY:
	case LDB_OP_GREATER:
	case LDB_OP_LESS:
	case LDB_OP_APPROX:
		attr = tree->u.equality.attr;
		break;
	case LDB_OP_SUBSTRING:
		attr = tree->u.substring.attr;
		break;
	case LDB_OP_PRESENT:
		attr = tree->u.present.attr;
		break;
	case LDB_OP_EXTENDED:
		attr = tree->u.extended.attr;
		break;

	/* we'll check LDB_OP_AND/_OR/_NOT children later on in the walk */
	default:
		break;
	}
	return attr;
}

/*
 * Checks a single attribute in the search parse-tree to make sure the user has
 * sufficient rights to view it.
 */
static int parse_tree_check_attr_access(struct ldb_parse_tree *tree,
					void *private_context)
{
	struct parse_tree_aclread_ctx *ctx = NULL;
	const char *attr_name = NULL;
	int ret;
	static const char * const attrs_always_present[] = {
		"objectClass",
		"distinguishedName",
		"name",
		"objectGUID",
		NULL
	};

	ctx = (struct parse_tree_aclread_ctx *)private_context;

	/*
	 * we can skip any further checking if we already know that this object
	 * shouldn't be visible in this user's search
	 */
	if (ctx->suppress_result) {
		return LDB_SUCCESS;
	}

	/* skip this level of the search-tree if it has no attribute to check */
	attr_name = parse_tree_get_attr(tree);
	if (attr_name == NULL) {
		return LDB_SUCCESS;
	}

	/*
	 * If the search filter is checking for an attribute's presence, and the
	 * attribute is always present, we can skip access rights checks. Every
	 * object has these attributes, and so there's no security reason to
	 * hide their presence.
	 * Note: the acl.py tests (e.g. test_search1()) rely on this exception.
	 * I.e. even if we lack Read Property (RP) rights for a child object, it
	 * should still appear as a visible object in 'objectClass=*' searches,
	 * so long as we have List Contents (LC) rights for the object.
	 */
	if (tree->operation == LDB_OP_PRESENT &&
	    is_attr_in_list(attrs_always_present, attr_name)) {
		return LDB_SUCCESS;
	}

	ret = check_attr_access_rights(ctx->mem_ctx, attr_name, ctx->ac,
				       ctx->sd, ctx->objectclass, ctx->sid,
				       ctx->dn);

	/*
	 * if the user does not have the rights to view this attribute, then we
	 * should not return the object as a search result, i.e. act as if the
	 * object doesn't exist (for this particular user, at least)
	 */
	if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		ctx->suppress_result = true;
		return LDB_SUCCESS;
	}

	return ret;
}

/*
 * Traverse the search-tree to check that the user has sufficient access rights
 * to view all the attributes.
 */
static int check_search_ops_access(struct aclread_context *ac,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor *sd,
				   const struct dsdb_class *objectclass,
				   struct dom_sid *sid, struct ldb_dn *dn,
				   bool *suppress_result)
{
	int ret;
	struct parse_tree_aclread_ctx ctx = { 0 };
	struct ldb_parse_tree *tree = ac->req->op.search.tree;

	ctx.ac = ac;
	ctx.mem_ctx = mem_ctx;
	ctx.suppress_result = false;
	ctx.sid = sid;
	ctx.dn = dn;
	ctx.sd = sd;
	ctx.objectclass = objectclass;

	/* walk the search tree, checking each attribute as we go */
	ret = ldb_parse_tree_walk(tree, parse_tree_check_attr_access, &ctx);

	/* return whether this search result should be hidden to this user */
	*suppress_result = ctx.suppress_result;
	return ret;
}

static int aclread_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct aclread_context *ac;
	struct ldb_message *ret_msg;
	struct ldb_message *msg;
	int ret;
	size_t num_of_attrs = 0;
	unsigned int i, k = 0;
	struct security_descriptor *sd = NULL;
	struct dom_sid *sid = NULL;
	TALLOC_CTX *tmp_ctx;
	const struct dsdb_class *objectclass;
	bool suppress_result = false;

	ac = talloc_get_type(req->context, struct aclread_context);
	ldb = ldb_module_get_ctx(ac->module);
	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR );
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
				       ares->response, ares->error);
	}
	tmp_ctx = talloc_new(ac);
	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		msg = ares->message;
		ret = aclread_get_sd_from_ldb_message(ac, msg, &sd);
		if (ret != LDB_SUCCESS) {
			ldb_debug_set(ldb, LDB_DEBUG_FATAL,
				      "acl_read: cannot get descriptor of %s: %s\n",
				      ldb_dn_get_linearized(msg->dn), ldb_strerror(ret));
			ret = LDB_ERR_OPERATIONS_ERROR;
			goto fail;
		} else if (sd == NULL) {
			ldb_debug_set(ldb, LDB_DEBUG_FATAL,
				      "acl_read: cannot get descriptor of %s (attribute not found)\n",
				      ldb_dn_get_linearized(msg->dn));
			ret = LDB_ERR_OPERATIONS_ERROR;
			goto fail;
		}
		/*
		 * Get the most specific structural object class for the ACL check
		 */
		objectclass = dsdb_get_structural_oc_from_msg(ac->schema, msg);
		if (objectclass == NULL) {
			ldb_asprintf_errstring(ldb, "acl_read: Failed to find a structural class for %s",
					       ldb_dn_get_linearized(msg->dn));
			ret = LDB_ERR_OPERATIONS_ERROR;
			goto fail;
		}

		sid = samdb_result_dom_sid(tmp_ctx, msg, "objectSid");
		if (!ldb_dn_is_null(msg->dn)) {
			/*
			 * this is a real object, so we have
			 * to check for visibility
			 */
			ret = aclread_check_object_visible(ac, msg, req);
			if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
				talloc_free(tmp_ctx);
				return LDB_SUCCESS;
			} else if (ret != LDB_SUCCESS) {
				ldb_debug_set(ldb, LDB_DEBUG_FATAL,
					      "acl_read: %s check parent %s - %s\n",
					      ldb_dn_get_linearized(msg->dn),
					      ldb_strerror(ret),
					      ldb_errstring(ldb));
				goto fail;
			}
		}

		/* for every element in the message check RP */
		for (i=0; i < msg->num_elements; i++) {
			const struct dsdb_attribute *attr;
			bool is_sd, is_objectsid, is_instancetype, is_objectclass;
			uint32_t access_mask;
			attr = dsdb_attribute_by_lDAPDisplayName(ac->schema,
								 msg->elements[i].name);
			if (!attr) {
				ldb_debug_set(ldb, LDB_DEBUG_FATAL,
					      "acl_read: %s cannot find attr[%s] in of schema\n",
					      ldb_dn_get_linearized(msg->dn),
					      msg->elements[i].name);
				ret = LDB_ERR_OPERATIONS_ERROR;
				goto fail;
			}
			is_sd = ldb_attr_cmp("nTSecurityDescriptor",
					      msg->elements[i].name) == 0;
			is_objectsid = ldb_attr_cmp("objectSid",
						    msg->elements[i].name) == 0;
			is_instancetype = ldb_attr_cmp("instanceType",
						       msg->elements[i].name) == 0;
			is_objectclass = ldb_attr_cmp("objectClass",
						      msg->elements[i].name) == 0;
			/* these attributes were added to perform access checks and must be removed */
			if (is_objectsid && ac->added_objectSid) {
				aclread_mark_inaccesslible(&msg->elements[i]);
				continue;
			}
			if (is_instancetype && ac->added_instanceType) {
				aclread_mark_inaccesslible(&msg->elements[i]);
				continue;
			}
			if (is_objectclass && ac->added_objectClass) {
				aclread_mark_inaccesslible(&msg->elements[i]);
				continue;
			}
			if (is_sd && ac->added_nTSecurityDescriptor) {
				aclread_mark_inaccesslible(&msg->elements[i]);
				continue;
			}

			access_mask = get_attr_access_mask(attr, ac->sd_flags);

			if (access_mask == 0) {
				aclread_mark_inaccesslible(&msg->elements[i]);
				continue;
			}

			ret = acl_check_access_on_attribute(ac->module,
							    tmp_ctx,
							    sd,
							    sid,
							    access_mask,
							    attr,
							    objectclass);

			/*
			 * Dirsync control needs the replpropertymetadata attribute
			 * so return it as it will be removed by the control
			 * in anycase.
			 */
			if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
				bool in_search_filter;

				/* check if attr is part of the search filter */
				in_search_filter = dsdb_attr_in_parse_tree(ac->req->op.search.tree,
								msg->elements[i].name);

				if (in_search_filter) {

					/*
					 * We are doing dirysnc answers
					 * and the object shouldn't be returned (normally)
					 * but we will return it without replPropertyMetaData
					 * so that the dirysync module will do what is needed
					 * (remove the object if it is not deleted, or return
					 * just the objectGUID if it's deleted).
					 */
					if (ac->indirsync) {
						ldb_msg_remove_attr(msg, "replPropertyMetaData");
						break;
					} else {

						/* do not return this entry */
						talloc_free(tmp_ctx);
						return LDB_SUCCESS;
					}
				} else {
					aclread_mark_inaccesslible(&msg->elements[i]);
				}
			} else if (ret != LDB_SUCCESS) {
				ldb_debug_set(ldb, LDB_DEBUG_FATAL,
					      "acl_read: %s check attr[%s] gives %s - %s\n",
					      ldb_dn_get_linearized(msg->dn),
					      msg->elements[i].name,
					      ldb_strerror(ret),
					      ldb_errstring(ldb));
				goto fail;
			}
		}

		/*
		 * check access rights for the search attributes, as well as the
		 * attribute values actually being returned
		 */
		ret = check_search_ops_access(ac, tmp_ctx, sd, objectclass, sid,
					      msg->dn, &suppress_result);
		if (ret != LDB_SUCCESS) {
			ldb_debug_set(ldb, LDB_DEBUG_FATAL,
				      "acl_read: %s check search ops %s - %s\n",
				      ldb_dn_get_linearized(msg->dn),
				      ldb_strerror(ret), ldb_errstring(ldb));
			goto fail;
		}

		if (suppress_result) {

			/*
			 * As per the above logic, we strip replPropertyMetaData
			 * out of the msg so that the dirysync module will do
			 * what is needed (return just the objectGUID if it's,
			 * deleted, or remove the object if it is not).
			 */
			if (ac->indirsync) {
				ldb_msg_remove_attr(msg, "replPropertyMetaData");
			} else {
				talloc_free(tmp_ctx);
				return LDB_SUCCESS;
			}
		}

		for (i=0; i < msg->num_elements; i++) {
			if (!aclread_is_inaccessible(&msg->elements[i])) {
				num_of_attrs++;
			}
		}
		/*create a new message to return*/
		ret_msg = ldb_msg_new(ac->req);
		ret_msg->dn = msg->dn;
		talloc_steal(ret_msg, msg->dn);
		ret_msg->num_elements = num_of_attrs;
		if (num_of_attrs > 0) {
			ret_msg->elements = talloc_array(ret_msg,
							 struct ldb_message_element,
							 num_of_attrs);
			if (ret_msg->elements == NULL) {
				return ldb_oom(ldb);
			}
			for (i=0; i < msg->num_elements; i++) {
				bool to_remove = aclread_is_inaccessible(&msg->elements[i]);
				if (!to_remove) {
					ret_msg->elements[k] = msg->elements[i];
					talloc_steal(ret_msg->elements, msg->elements[i].name);
					talloc_steal(ret_msg->elements, msg->elements[i].values);
					k++;
				}
			}
			/*
			 * This should not be needed, but some modules
			 * may allocate values on the wrong context...
			 */
			talloc_steal(ret_msg->elements, msg);
		} else {
			ret_msg->elements = NULL;
		}
		talloc_free(tmp_ctx);

		ac->num_entries++;
		return ldb_module_send_entry(ac->req, ret_msg, ares->controls);
	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(ac->req, ares->referral);
	case LDB_REPLY_DONE:
		if (ac->base_invisible && ac->num_entries == 0) {
			/*
			 * If the base is invisible and we didn't
			 * returned any object, we need to return
			 * NO_SUCH_OBJECT.
			 */
			return ldb_module_done(ac->req,
					       NULL, NULL,
					       LDB_ERR_NO_SUCH_OBJECT);
		}
		return ldb_module_done(ac->req, ares->controls,
					ares->response, LDB_SUCCESS);

	}
	return LDB_SUCCESS;
fail:
	talloc_free(tmp_ctx);
	return ldb_module_done(ac->req, NULL, NULL, ret);
}


static int aclread_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	int ret;
	struct aclread_context *ac;
	struct ldb_request *down_req;
	struct ldb_control *as_system = ldb_request_get_control(req, LDB_CONTROL_AS_SYSTEM_OID);
	uint32_t flags = ldb_req_get_custom_flags(req);
	struct ldb_result *res;
	struct aclread_private *p;
	bool need_sd = false;
	bool explicit_sd_flags = false;
	bool is_untrusted = ldb_req_is_untrusted(req);
	static const char * const _all_attrs[] = { "*", NULL };
	bool all_attrs = false;
	const char * const *attrs = NULL;
	static const char *acl_attrs[] = {
		"instanceType",
		NULL
	};

	ldb = ldb_module_get_ctx(module);
	p = talloc_get_type(ldb_module_get_private(module), struct aclread_private);

	/* skip access checks if we are system or system control is supplied
	 * or this is not LDAP server request */
	if (!p || !p->enabled ||
	    dsdb_module_am_system(module)
	    || as_system || !is_untrusted) {
		return ldb_next_request(module, req);
	}
	/* no checks on special dn */
	if (ldb_dn_is_special(req->op.search.base)) {
		return ldb_next_request(module, req);
	}

	ac = talloc_zero(req, struct aclread_context);
	if (ac == NULL) {
		return ldb_oom(ldb);
	}
	ac->module = module;
	ac->req = req;
	ac->schema = dsdb_get_schema(ldb, req);
	if (flags & DSDB_ACL_CHECKS_DIRSYNC_FLAG) {
		ac->indirsync = true;
	} else {
		ac->indirsync = false;
	}
	if (!ac->schema) {
		return ldb_operr(ldb);
	}

	attrs = req->op.search.attrs;
	if (attrs == NULL) {
		all_attrs = true;
		attrs = _all_attrs;
	} else if (ldb_attr_in_list(attrs, "*")) {
		all_attrs = true;
	}

	/*
	 * In theory we should also check for the SD control but control verification is
	 * expensive so we'd better had the ntsecuritydescriptor to the list of
	 * searched attribute and then remove it !
	 */
	ac->sd_flags = dsdb_request_sd_flags(ac->req, &explicit_sd_flags);

	if (ldb_attr_in_list(attrs, "nTSecurityDescriptor")) {
		need_sd = false;
	} else if (explicit_sd_flags && all_attrs) {
		need_sd = false;
	} else {
		need_sd = true;
	}

	if (!all_attrs) {
		if (!ldb_attr_in_list(attrs, "instanceType")) {
			attrs = ldb_attr_list_copy_add(ac, attrs, "instanceType");
			if (attrs == NULL) {
				return ldb_oom(ldb);
			}
			ac->added_instanceType = true;
		}
		if (!ldb_attr_in_list(req->op.search.attrs, "objectSid")) {
			attrs = ldb_attr_list_copy_add(ac, attrs, "objectSid");
			if (attrs == NULL) {
				return ldb_oom(ldb);
			}
			ac->added_objectSid = true;
		}
		if (!ldb_attr_in_list(req->op.search.attrs, "objectClass")) {
			attrs = ldb_attr_list_copy_add(ac, attrs, "objectClass");
			if (attrs == NULL) {
				return ldb_oom(ldb);
			}
			ac->added_objectClass = true;
		}
	}

	if (need_sd) {
		attrs = ldb_attr_list_copy_add(ac, attrs, "nTSecurityDescriptor");
		if (attrs == NULL) {
			return ldb_oom(ldb);
		}
		ac->added_nTSecurityDescriptor = true;
	}

	ac->attrs = req->op.search.attrs;

	/* check accessibility of base */
	if (!ldb_dn_is_null(req->op.search.base)) {
		ret = dsdb_module_search_dn(module, req, &res, req->op.search.base,
					    acl_attrs,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_FLAG_AS_SYSTEM |
					    DSDB_SEARCH_SHOW_RECYCLED,
					    req);
		if (ret != LDB_SUCCESS) {
			return ldb_error(ldb, ret,
					"acl_read: Error retrieving instanceType for base.");
		}
		ret = aclread_check_object_visible(ac, res->msgs[0], req);
		if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
			if (req->op.search.scope == LDB_SCOPE_BASE) {
				return ldb_module_done(req, NULL, NULL,
						       LDB_ERR_NO_SUCH_OBJECT);
			}
			/*
			 * Defer LDB_ERR_NO_SUCH_OBJECT,
			 * we may return sub objects
			 */
			ac->base_invisible = true;
		} else if (ret != LDB_SUCCESS) {
			return ldb_module_done(req, NULL, NULL, ret);
		}
	}

	ret = ldb_build_search_req_ex(&down_req,
				      ldb, ac,
				      req->op.search.base,
				      req->op.search.scope,
				      req->op.search.tree,
				      attrs,
				      req->controls,
				      ac, aclread_callback,
				      req);

	if (ret != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ldb_next_request(module, down_req);
}

static int aclread_init(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct aclread_private *p = talloc_zero(module, struct aclread_private);
	if (p == NULL) {
		return ldb_module_oom(module);
	}
	p->enabled = lpcfg_parm_bool(ldb_get_opaque(ldb, "loadparm"), NULL, "acl", "search", true);
	ldb_module_set_private(module, p);
	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_aclread_module_ops = {
	.name		   = "aclread",
	.search            = aclread_search,
	.init_context      = aclread_init
};

int ldb_aclread_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_aclread_module_ops);
}
