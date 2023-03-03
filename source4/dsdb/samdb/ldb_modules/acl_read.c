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
#include "lib/util/binsearch.h"

#undef strcasecmp

struct ldb_attr_vec {
	const char** attrs;
	size_t len;
	size_t capacity;
};

struct aclread_context {
	struct ldb_module *module;
	struct ldb_request *req;
	const struct dsdb_schema *schema;
	uint32_t sd_flags;
	bool added_nTSecurityDescriptor;
	bool added_instanceType;
	bool added_objectSid;
	bool added_objectClass;

	bool do_list_object_initialized;
	bool do_list_object;
	bool base_invisible;
	uint64_t num_entries;

	/* cache on the last parent we checked in this search */
	struct ldb_dn *last_parent_dn;
	int last_parent_check_ret;

	bool am_administrator;

	bool got_tree_attrs;
	struct ldb_attr_vec tree_attrs;
};

struct aclread_private {
	bool enabled;

	/* cache of the last SD we read during any search */
	struct security_descriptor *sd_cached;
	struct ldb_val sd_cached_blob;
	const char **password_attrs;
};

struct access_check_context {
	struct security_descriptor *sd;
	struct dom_sid sid_buf;
	const struct dom_sid *sid;
	const struct dsdb_class *objectclass;
};

static void acl_element_mark_access_checked(struct ldb_message_element *el)
{
	el->flags |= LDB_FLAG_INTERNAL_ACCESS_CHECKED;
}

static bool acl_element_is_access_checked(const struct ldb_message_element *el)
{
	return (el->flags & LDB_FLAG_INTERNAL_ACCESS_CHECKED) != 0;
}

static bool attr_in_vec(const struct ldb_attr_vec *vec, const char *attr)
{
	const char **found = NULL;

	if (vec == NULL) {
		return false;
	}

	BINARY_ARRAY_SEARCH_V(vec->attrs,
			      vec->len,
			      attr,
			      ldb_attr_cmp,
			      found);
	return found != NULL;
}

static int acl_attr_cmp_fn(const char *a, const char **b)
{
	return ldb_attr_cmp(a, *b);
}

static int attr_vec_add_unique(TALLOC_CTX *mem_ctx,
			       struct ldb_attr_vec *vec,
			       const char *attr)
{
	const char **exact = NULL;
	const char **next = NULL;
	size_t next_idx = 0;

	BINARY_ARRAY_SEARCH_GTE(vec->attrs,
				vec->len,
				attr,
				acl_attr_cmp_fn,
				exact,
				next);
	if (exact != NULL) {
		return LDB_SUCCESS;
	}

	if (vec->len == SIZE_MAX) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (next != NULL) {
		next_idx = next - vec->attrs;
	}

	if (vec->len >= vec->capacity) {
		const char **attrs = NULL;

		if (vec->capacity == 0) {
			vec->capacity = 4;
		} else {
			if (vec->capacity > SIZE_MAX / 2) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
			vec->capacity *= 2;
		}

		attrs = talloc_realloc(mem_ctx, vec->attrs, const char *, vec->capacity);
		if (attrs == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		vec->attrs = attrs;
	}
	SMB_ASSERT(vec->len < vec->capacity);

	if (next == NULL) {
		vec->attrs[vec->len++] = attr;
	} else {
		size_t count = (vec->len - next_idx) * sizeof (vec->attrs[0]);
		memmove(&vec->attrs[next_idx + 1],
			&vec->attrs[next_idx],
			count);

		vec->attrs[next_idx] = attr;
		++vec->len;
	}

	return LDB_SUCCESS;
}

static bool ldb_attr_always_present(const char *attr)
{
	static const char * const attrs_always_present[] = {
		"objectClass",
		"distinguishedName",
		"name",
		"objectGUID",
		NULL
	};

	return ldb_attr_in_list(attrs_always_present, attr);
}

static bool ldb_attr_always_visible(const char *attr)
{
	static const char * const attrs_always_visible[] = {
		"isDeleted",
		"isRecycled",
		NULL
	};

	return ldb_attr_in_list(attrs_always_visible, attr);
}

/* Collect a list of attributes required to match a given parse tree. */
static int ldb_parse_tree_collect_acl_attrs(struct ldb_module *module,
					    TALLOC_CTX *mem_ctx,
					    struct ldb_attr_vec *attrs,
					    const struct ldb_parse_tree *tree)
{
	const char *attr = NULL;
	unsigned int i;
	int ret;

	if (tree == NULL) {
		return 0;
	}

	switch (tree->operation) {
	case LDB_OP_OR:
	case LDB_OP_AND:		/* attributes stored in list of subtrees */
		for (i = 0; i < tree->u.list.num_elements; i++) {
			ret = ldb_parse_tree_collect_acl_attrs(module, mem_ctx,
							       attrs, tree->u.list.elements[i]);
			if (ret) {
				return ret;
			}
		}
		return 0;

	case LDB_OP_NOT:		/* attributes stored in single subtree */
		return ldb_parse_tree_collect_acl_attrs(module, mem_ctx, attrs, tree->u.isnot.child);

	case LDB_OP_PRESENT:
		/*
		 * If the search filter is checking for an attribute's presence,
		 * and the attribute is always present, we can skip access
		 * rights checks. Every object has these attributes, and so
		 * there's no security reason to hide their presence.
		 * Note: the acl.py tests (e.g. test_search1()) rely on this
		 * exception.  I.e. even if we lack Read Property (RP) rights
		 * for a child object, it should still appear as a visible
		 * object in 'objectClass=*' searches, so long as we have List
		 * Contents (LC) rights for the object.
		 */
		if (ldb_attr_always_present(tree->u.present.attr)) {
			/* No need to check this attribute. */
			return 0;
		}

		FALL_THROUGH;
	case LDB_OP_EQUALITY:
		if (ldb_attr_always_visible(tree->u.present.attr)) {
			/* No need to check this attribute. */
			return 0;
		}

		FALL_THROUGH;
	default:			/* single attribute in tree */
		attr = ldb_parse_tree_get_attr(tree);
		return attr_vec_add_unique(mem_ctx, attrs, attr);
	}
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
					   const struct ldb_message *acl_res,
					   struct security_descriptor **sd)
{
	struct ldb_message_element *sd_element;
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct aclread_private *private_data
		= talloc_get_type_abort(ldb_module_get_private(ac->module),
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
	private_data->sd_cached_blob = ldb_val_dup(private_data,
						   &sd_element->values[0]);
	if (private_data->sd_cached_blob.data == NULL) {
		TALLOC_FREE(*sd);
		return ldb_operr(ldb);
	}

	talloc_unlink(private_data, private_data->sd_cached);
	private_data->sd_cached = *sd;

	return LDB_SUCCESS;
}

/* Check whether the attribute is a password attribute. */
static bool attr_is_secret(const char *attr, const struct aclread_private *private_data)
{
	unsigned i;

	if (private_data->password_attrs == NULL) {
		return false;
	}

	for (i = 0; private_data->password_attrs[i] != NULL; ++i) {
		const char *password_attr = private_data->password_attrs[i];
		if (ldb_attr_cmp(attr, password_attr) != 0) {
			continue;
		}

		return true;
	}

	return false;
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

/*
 * Checks that the user has sufficient access rights to view an attribute, else
 * marks it as inaccessible.
 */
static int acl_redact_attr(TALLOC_CTX *mem_ctx,
			   struct ldb_message_element *el,
			   struct aclread_context *ac,
			   const struct aclread_private *private_data,
			   const struct ldb_message *msg,
			   const struct dsdb_schema *schema,
			   const struct security_descriptor *sd,
			   const struct dom_sid *sid,
			   const struct dsdb_class *objectclass)
{
	int ret;
	const struct dsdb_attribute *attr = NULL;
	uint32_t access_mask;
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);

	if (attr_is_secret(el->name, private_data)) {
		ldb_msg_element_mark_inaccessible(el);
		return LDB_SUCCESS;
	}

	/* Look up the attribute in the schema. */
	attr = dsdb_attribute_by_lDAPDisplayName(schema, el->name);
	if (!attr) {
		ldb_debug_set(ldb,
			      LDB_DEBUG_FATAL,
			      "acl_read: %s cannot find attr[%s] in schema\n",
			      ldb_dn_get_linearized(msg->dn), el->name);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	access_mask = get_attr_access_mask(attr, ac->sd_flags);
	if (access_mask == 0) {
		DBG_ERR("Could not determine access mask for attribute %s\n",
			el->name);
		ldb_msg_element_mark_inaccessible(el);
		return LDB_SUCCESS;
	}

	/* We must check whether the user has rights to view the attribute. */

	ret = acl_check_access_on_attribute(ac->module, mem_ctx, sd, sid,
					    access_mask, attr, objectclass);

	if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
		ldb_msg_element_mark_inaccessible(el);
	} else if (ret != LDB_SUCCESS) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "acl_read: %s check attr[%s] gives %s - %s\n",
			      ldb_dn_get_linearized(msg->dn), el->name,
			      ldb_strerror(ret), ldb_errstring(ldb));
		return ret;
	}

	return LDB_SUCCESS;
}

static int setup_access_check_context(struct aclread_context *ac,
				      const struct ldb_message *msg,
				      struct access_check_context *ctx)
{
	int ret;

	/*
	 * Fetch the schema so we can check which attributes are
	 * considered confidential.
	 */
	if (ac->schema == NULL) {
		struct ldb_context *ldb = ldb_module_get_ctx(ac->module);

		/* Cache the schema for later use. */
		ac->schema = dsdb_get_schema(ldb, ac);

		if (ac->schema == NULL) {
			return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
					 "aclread_callback: Error obtaining schema.");
		}
	}

	/* Fetch the object's security descriptor. */
	ret = aclread_get_sd_from_ldb_message(ac, msg, &ctx->sd);
	if (ret != LDB_SUCCESS) {
		ldb_debug_set(ldb_module_get_ctx(ac->module), LDB_DEBUG_FATAL,
			      "acl_read: cannot get descriptor of %s: %s\n",
			      ldb_dn_get_linearized(msg->dn), ldb_strerror(ret));
		return LDB_ERR_OPERATIONS_ERROR;
	} else if (ctx->sd == NULL) {
		ldb_debug_set(ldb_module_get_ctx(ac->module), LDB_DEBUG_FATAL,
			      "acl_read: cannot get descriptor of %s (attribute not found)\n",
			      ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/*
	 * Get the most specific structural object class for the ACL check
	 */
	ctx->objectclass = dsdb_get_structural_oc_from_msg(ac->schema, msg);
	if (ctx->objectclass == NULL) {
		ldb_asprintf_errstring(ldb_module_get_ctx(ac->module),
				       "acl_read: Failed to find a structural class for %s",
				       ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Fetch the object's SID. */
	ret = samdb_result_dom_sid_buf(msg, "objectSid", &ctx->sid_buf);
	if (ret == LDB_SUCCESS) {
		ctx->sid = &ctx->sid_buf;
	} else if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE) {
		/* This is expected. */
		ctx->sid = NULL;
	} else {
		ldb_asprintf_errstring(ldb_module_get_ctx(ac->module),
				       "acl_read: Failed to parse objectSid as dom_sid for %s",
				       ldb_dn_get_linearized(msg->dn));
		return ret;
	}

	return LDB_SUCCESS;
}

/*
 * Whether this attribute was added to perform access checks and must be
 * removed.
 */
static bool should_remove_attr(const char *attr, const struct aclread_context *ac)
{
	if (ac->added_nTSecurityDescriptor &&
	    ldb_attr_cmp("nTSecurityDescriptor", attr) == 0)
	{
		return true;
	}

	if (ac->added_objectSid &&
	    ldb_attr_cmp("objectSid", attr) == 0)
	{
		return true;
	}

	if (ac->added_instanceType &&
	    ldb_attr_cmp("instanceType", attr) == 0)
	{
		return true;
	}

	if (ac->added_objectClass &&
	    ldb_attr_cmp("objectClass", attr) == 0)
	{
		return true;
	}

	return false;
}

static int aclread_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct aclread_context *ac;
	struct aclread_private *private_data = NULL;
	struct ldb_message *msg;
	int ret;
	unsigned int i;
	struct access_check_context acl_ctx;

	ac = talloc_get_type_abort(req->context, struct aclread_context);
	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR );
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
				       ares->response, ares->error);
	}
	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		msg = ares->message;

		if (!ldb_dn_is_null(msg->dn)) {
			/*
			 * this is a real object, so we have
			 * to check for visibility
			 */
			ret = aclread_check_object_visible(ac, msg, req);
			if (ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS) {
				return LDB_SUCCESS;
			} else if (ret != LDB_SUCCESS) {
				struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
				ldb_debug_set(ldb, LDB_DEBUG_FATAL,
					      "acl_read: %s check parent %s - %s\n",
					      ldb_dn_get_linearized(msg->dn),
					      ldb_strerror(ret),
					      ldb_errstring(ldb));
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

		/* for every element in the message check RP */
		for (i = 0; i < msg->num_elements; ++i) {
			struct ldb_message_element *el = &msg->elements[i];

			/* Remove attributes added to perform access checks. */
			if (should_remove_attr(el->name, ac)) {
				ldb_msg_element_mark_inaccessible(el);
				continue;
			}

			if (acl_element_is_access_checked(el)) {
				/* We will have already checked this attribute. */
				continue;
			}

			/*
			 * We need to fetch the security descriptor to check
			 * this attribute.
			 */
			break;
		}

		if (i == msg->num_elements) {
			/* All elements have been checked. */
			goto reply_entry_done;
		}

		ret = setup_access_check_context(ac, msg, &acl_ctx);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		private_data = talloc_get_type_abort(ldb_module_get_private(ac->module),
						     struct aclread_private);

		for (/* begin where we left off */; i < msg->num_elements; ++i) {
			struct ldb_message_element *el = &msg->elements[i];

			/* Remove attributes added to perform access checks. */
			if (should_remove_attr(el->name, ac)) {
				ldb_msg_element_mark_inaccessible(el);
				continue;
			}

			if (acl_element_is_access_checked(el)) {
				/* We will have already checked this attribute. */
				continue;
			}

			/*
			 * We need to check whether the attribute is secret,
			 * confidential, or access-controlled.
			 */
			ret = acl_redact_attr(ac,
					      el,
					      ac,
					      private_data,
					      msg,
					      ac->schema,
					      acl_ctx.sd,
					      acl_ctx.sid,
					      acl_ctx.objectclass);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req, NULL, NULL, ret);
			}
		}

	reply_entry_done:
		ldb_msg_remove_inaccessible(msg);

		ac->num_entries++;
		return ldb_module_send_entry(ac->req, msg, ares->controls);
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
}


static int aclread_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	int ret;
	struct aclread_context *ac;
	struct ldb_request *down_req;
	struct ldb_control *as_system = ldb_request_get_control(req, LDB_CONTROL_AS_SYSTEM_OID);
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

	ac->am_administrator = dsdb_module_am_administrator(module);

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

	/*
	 * We provide 'ac' as the control value, which is then used by the
	 * callback to avoid double-work.
	 */
	ret = ldb_request_add_control(down_req, DSDB_CONTROL_ACL_READ_OID, false, ac);
	if (ret != LDB_SUCCESS) {
			return ldb_error(ldb, ret,
					"acl_read: Error adding acl_read control.");
	}

	return ldb_next_request(module, down_req);
}

/*
 * Here we mark inaccessible attributes known to be looked for in the
 * filter. This only redacts attributes found in the search expression. If any
 * extended attribute match rules examine different attributes without their own
 * access control checks, a security bypass is possible.
 */
static int acl_redact_msg_for_filter(struct ldb_module *module, struct ldb_request *req, struct ldb_message *msg)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct aclread_private *private_data = NULL;
	struct ldb_control *control = NULL;
	struct aclread_context *ac = NULL;
	struct access_check_context acl_ctx;
	int ret;
	unsigned i;

	/*
	 * The private data contains a list of attributes which are to be
	 * considered secret.
	 */
	private_data = talloc_get_type(ldb_module_get_private(module), struct aclread_private);
	if (private_data == NULL) {
		return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
				 "aclread_private data is missing");
	}
	if (!private_data->enabled) {
		return LDB_SUCCESS;
	}

	control = ldb_request_get_control(req, DSDB_CONTROL_ACL_READ_OID);
	if (control == NULL) {
		/*
		 * We've bypassed the acl_read module for this request, and
		 * should skip redaction in this case.
		 */
		return LDB_SUCCESS;
	}

	ac = talloc_get_type_abort(control->data, struct aclread_context);

	if (!ac->got_tree_attrs) {
		ret = ldb_parse_tree_collect_acl_attrs(module, ac, &ac->tree_attrs, req->op.search.tree);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		ac->got_tree_attrs = true;
	}

	for (i = 0; i < msg->num_elements; ++i) {
		struct ldb_message_element *el = &msg->elements[i];

		/* Is the attribute mentioned in the search expression? */
		if (attr_in_vec(&ac->tree_attrs, el->name)) {
			/*
			 * We need to fetch the security descriptor to check
			 * this element.
			 */
			break;
		}

		/*
		 * This attribute is not in the search filter, so we can leave
		 * handling it till aclread_callback(), by which time we know
		 * this object is a match. This saves work checking ACLs if the
		 * search is unindexed and most objects don't match the filter.
		 */
	}

	if (i == msg->num_elements) {
		/* All elements have been checked. */
		return LDB_SUCCESS;
	}

	ret = setup_access_check_context(ac, msg, &acl_ctx);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* For every element in the message and the parse tree, check RP. */

	for (/* begin where we left off */; i < msg->num_elements; ++i) {
		struct ldb_message_element *el = &msg->elements[i];

		/* Is the attribute mentioned in the search expression? */
		if (!attr_in_vec(&ac->tree_attrs, el->name)) {
			/*
			 * If not, leave it for later and check the next
			 * attribute.
			 */
			continue;
		}

		/*
		 * We need to check whether the attribute is secret,
		 * confidential, or access-controlled.
		 */
		ret = acl_redact_attr(ac,
				      el,
				      ac,
				      private_data,
				      msg,
				      ac->schema,
				      acl_ctx.sd,
				      acl_ctx.sid,
				      acl_ctx.objectclass);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		acl_element_mark_access_checked(el);
	}

	return LDB_SUCCESS;
}

static int aclread_init(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	unsigned int i, n, j;
	TALLOC_CTX *mem_ctx = NULL;
	int ret;
	bool userPassword_support;
	static const char * const attrs[] = { "passwordAttribute", NULL };
	static const char * const secret_attrs[] = {
		DSDB_SECRET_ATTRIBUTES
	};
	struct ldb_result *res;
	struct ldb_message *msg;
	struct ldb_message_element *password_attributes;
	struct aclread_private *p = talloc_zero(module, struct aclread_private);
	if (p == NULL) {
		return ldb_module_oom(module);
	}
	p->enabled = lpcfg_parm_bool(ldb_get_opaque(ldb, "loadparm"), NULL, "acl", "search", true);

	ret = ldb_mod_register_control(module, LDB_CONTROL_SD_FLAGS_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "acl_module_init: Unable to register sd_flags control with rootdse!\n");
		return ldb_operr(ldb);
	}

	ldb_module_set_private(module, p);

	mem_ctx = talloc_new(module);
	if (!mem_ctx) {
		return ldb_oom(ldb);
	}

	ret = dsdb_module_search_dn(module, mem_ctx, &res,
				    ldb_dn_new(mem_ctx, ldb, "@KLUDGEACL"),
				    attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM,
				    NULL);
	if (ret != LDB_SUCCESS) {
		goto done;
	}
	if (res->count == 0) {
		goto done;
	}

	if (res->count > 1) {
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	msg = res->msgs[0];

	password_attributes = ldb_msg_find_element(msg, "passwordAttribute");
	if (!password_attributes) {
		goto done;
	}
	p->password_attrs = talloc_array(p, const char *,
			password_attributes->num_values +
			ARRAY_SIZE(secret_attrs) + 1);
	if (!p->password_attrs) {
		talloc_free(mem_ctx);
		return ldb_oom(ldb);
	}

	n = 0;
	for (i=0; i < password_attributes->num_values; i++) {
		p->password_attrs[n] = (const char *)password_attributes->values[i].data;
		talloc_steal(p->password_attrs, password_attributes->values[i].data);
		n++;
	}

	for (i=0; i < ARRAY_SIZE(secret_attrs); i++) {
		bool found = false;

		for (j=0; j < n; j++) {
			if (strcasecmp(p->password_attrs[j], secret_attrs[i]) == 0) {
				found = true;
				break;
			}
		}

		if (found) {
			continue;
		}

		p->password_attrs[n] = talloc_strdup(p->password_attrs,
						     secret_attrs[i]);
		if (p->password_attrs[n] == NULL) {
			talloc_free(mem_ctx);
			return ldb_oom(ldb);
		}
		n++;
	}
	p->password_attrs[n] = NULL;

	ret = ldb_register_redact_callback(ldb, acl_redact_msg_for_filter, module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

done:
	talloc_free(mem_ctx);
	ret = ldb_next_init(module);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (p->password_attrs != NULL) {
		/*
		 * Check this after the modules have be initialised so we can
		 * actually read the backend DB.
		 */
		userPassword_support = dsdb_user_password_support(module,
								  module,
								  NULL);
		if (!userPassword_support) {
			/*
			 * Remove the userPassword attribute, as it is not
			 * considered secret.
			 */
			for (i = 0; p->password_attrs[i] != NULL; ++i) {
				if (ldb_attr_cmp(p->password_attrs[i], "userPassword") == 0) {
					break;
				}
			}

			/* Shift following elements backwards by one. */
			for (; p->password_attrs[i] != NULL; ++i) {
				p->password_attrs[i] = p->password_attrs[i + 1];
			}
		}
	}
	return ret;
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
