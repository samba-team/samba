/*
   ldb database library

   Copyright (C) Simo Sorce  2006-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2007
   Copyright (C) Nadezhda Ivanova  2009

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
 *  Component: DS Security descriptor module
 *
 *  Description:
 *  - Calculate the security descriptor of a newly created object
 *  - Perform sd recalculation on a move operation
 *  - Handle sd modification invariants
 *
 *  Author: Nadezhda Ivanova
 */

#include "includes.h"
#include <ldb_module.h>
#include "util/dlinklist.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "auth/auth.h"
#include "param/param.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "lib/util/binsearch.h"

struct descriptor_changes {
	struct descriptor_changes *prev, *next;
	struct descriptor_changes *children;
	struct ldb_dn *nc_root;
	struct ldb_dn *dn;
	bool force_self;
	bool force_children;
	struct ldb_dn *stopped_dn;
};

struct descriptor_data {
	TALLOC_CTX *trans_mem;
	struct descriptor_changes *changes;
};

struct descriptor_context {
	struct ldb_module *module;
	struct ldb_request *req;
	struct ldb_message *msg;
	struct ldb_reply *search_res;
	struct ldb_reply *search_oc_res;
	struct ldb_val *parentsd_val;
	struct ldb_message_element *sd_element;
	struct ldb_val *sd_val;
	uint32_t sd_flags;
	int (*step_fn)(struct descriptor_context *);
};

static struct dom_sid *get_default_ag(TALLOC_CTX *mem_ctx,
			       struct ldb_dn *dn,
			       struct security_token *token,
			       struct ldb_context *ldb)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	const struct dom_sid *domain_sid = samdb_domain_sid(ldb);
	struct dom_sid *da_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_ADMINS);
	struct dom_sid *ea_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_ENTERPRISE_ADMINS);
	struct dom_sid *sa_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_SCHEMA_ADMINS);
	struct dom_sid *dag_sid;
	struct ldb_dn *nc_root;
	int ret;

	ret = dsdb_find_nc_root(ldb, tmp_ctx, dn, &nc_root);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return NULL;
	}

	if (ldb_dn_compare(nc_root, ldb_get_schema_basedn(ldb)) == 0) {
		if (security_token_has_sid(token, sa_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, sa_sid);
		} else if (security_token_has_sid(token, ea_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, ea_sid);
		} else if (security_token_has_sid(token, da_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, da_sid);
		} else if (security_token_is_system(token)) {
			dag_sid = dom_sid_dup(mem_ctx, sa_sid);
		} else {
			dag_sid = NULL;
		}
	} else if (ldb_dn_compare(nc_root, ldb_get_config_basedn(ldb)) == 0) {
		if (security_token_has_sid(token, ea_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, ea_sid);
		} else if (security_token_has_sid(token, da_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, da_sid);
		} else if (security_token_is_system(token)) {
			dag_sid = dom_sid_dup(mem_ctx, ea_sid);
		} else {
			dag_sid = NULL;
		}
	} else if (ldb_dn_compare(nc_root, ldb_get_default_basedn(ldb)) == 0) {
		if (security_token_has_sid(token, da_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, da_sid);
		} else if (security_token_has_sid(token, ea_sid)) {
				dag_sid = dom_sid_dup(mem_ctx, ea_sid);
		} else if (security_token_is_system(token)) {
			dag_sid = dom_sid_dup(mem_ctx, da_sid);
		} else {
			dag_sid = NULL;
		}
	} else {
		dag_sid = NULL;
	}

	talloc_free(tmp_ctx);
	return dag_sid;
}

static struct security_descriptor *get_sd_unpacked(struct ldb_module *module, TALLOC_CTX *mem_ctx,
					    const struct dsdb_class *objectclass)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct security_descriptor *sd;
	const struct dom_sid *domain_sid = samdb_domain_sid(ldb);

	if (!objectclass->defaultSecurityDescriptor || !domain_sid) {
		return NULL;
	}

	sd = sddl_decode(mem_ctx,
			 objectclass->defaultSecurityDescriptor,
			 domain_sid);
	return sd;
}

static struct dom_sid *get_default_group(TALLOC_CTX *mem_ctx,
					 struct ldb_context *ldb,
					 struct dom_sid *dag)
{
	/*
	 * This depends on the function level of the DC
	 * which is 2008R2 in our case. Which means it is
	 * higher than 2003 and we should use the
	 * "default administrator group" also as owning group.
	 *
	 * This matches dcpromo for a 2003 domain
	 * on a Windows 2008R2 DC.
	 */
	return dag;
}

static struct security_descriptor *descr_handle_sd_flags(TALLOC_CTX *mem_ctx,
							 struct security_descriptor *new_sd,
							 struct security_descriptor *old_sd,
							 uint32_t sd_flags)
{
	struct security_descriptor *final_sd; 
	/* if there is no control or control == 0 modify everything */
	if (!sd_flags) {
		return new_sd;
	}

	final_sd = talloc_zero(mem_ctx, struct security_descriptor);
	final_sd->revision = SECURITY_DESCRIPTOR_REVISION_1;
	final_sd->type = SEC_DESC_SELF_RELATIVE;

	if (sd_flags & (SECINFO_OWNER)) {
		if (new_sd->owner_sid) {
			final_sd->owner_sid = talloc_memdup(mem_ctx, new_sd->owner_sid, sizeof(struct dom_sid));
		}
		final_sd->type |= new_sd->type & SEC_DESC_OWNER_DEFAULTED;
	}
	else if (old_sd) {
		if (old_sd->owner_sid) {
			final_sd->owner_sid = talloc_memdup(mem_ctx, old_sd->owner_sid, sizeof(struct dom_sid));
		}
		final_sd->type |= old_sd->type & SEC_DESC_OWNER_DEFAULTED;
	}

	if (sd_flags & (SECINFO_GROUP)) {
		if (new_sd->group_sid) {
			final_sd->group_sid = talloc_memdup(mem_ctx, new_sd->group_sid, sizeof(struct dom_sid));
		}
		final_sd->type |= new_sd->type & SEC_DESC_GROUP_DEFAULTED;
	} 
	else if (old_sd) {
		if (old_sd->group_sid) {
			final_sd->group_sid = talloc_memdup(mem_ctx, old_sd->group_sid, sizeof(struct dom_sid));
		}
		final_sd->type |= old_sd->type & SEC_DESC_GROUP_DEFAULTED;
	}

	if (sd_flags & (SECINFO_SACL)) {
		final_sd->sacl = security_acl_dup(mem_ctx,new_sd->sacl);
		final_sd->type |= new_sd->type & (SEC_DESC_SACL_PRESENT |
			SEC_DESC_SACL_DEFAULTED|SEC_DESC_SACL_AUTO_INHERIT_REQ |
			SEC_DESC_SACL_AUTO_INHERITED|SEC_DESC_SACL_PROTECTED |
			SEC_DESC_SERVER_SECURITY);
	} 
	else if (old_sd && old_sd->sacl) {
		final_sd->sacl = security_acl_dup(mem_ctx,old_sd->sacl);
		final_sd->type |= old_sd->type & (SEC_DESC_SACL_PRESENT |
			SEC_DESC_SACL_DEFAULTED|SEC_DESC_SACL_AUTO_INHERIT_REQ |
			SEC_DESC_SACL_AUTO_INHERITED|SEC_DESC_SACL_PROTECTED |
			SEC_DESC_SERVER_SECURITY);
	}

	if (sd_flags & (SECINFO_DACL)) {
		final_sd->dacl = security_acl_dup(mem_ctx,new_sd->dacl);
		final_sd->type |= new_sd->type & (SEC_DESC_DACL_PRESENT |
			SEC_DESC_DACL_DEFAULTED|SEC_DESC_DACL_AUTO_INHERIT_REQ |
			SEC_DESC_DACL_AUTO_INHERITED|SEC_DESC_DACL_PROTECTED |
			SEC_DESC_DACL_TRUSTED);
	} 
	else if (old_sd && old_sd->dacl) {
		final_sd->dacl = security_acl_dup(mem_ctx,old_sd->dacl);
		final_sd->type |= old_sd->type & (SEC_DESC_DACL_PRESENT |
			SEC_DESC_DACL_DEFAULTED|SEC_DESC_DACL_AUTO_INHERIT_REQ |
			SEC_DESC_DACL_AUTO_INHERITED|SEC_DESC_DACL_PROTECTED |
			SEC_DESC_DACL_TRUSTED);
	}
	/* not so sure about this */
	final_sd->type |= new_sd->type & SEC_DESC_RM_CONTROL_VALID;
	return final_sd;
}

static DATA_BLOB *get_new_descriptor(struct ldb_module *module,
				     struct ldb_dn *dn,
				     TALLOC_CTX *mem_ctx,
				     const struct dsdb_class *objectclass,
				     const struct ldb_val *parent,
				     const struct ldb_val *object,
				     const struct ldb_val *old_sd,
				     uint32_t sd_flags)
{
	struct security_descriptor *user_descriptor = NULL, *parent_descriptor = NULL;
	struct security_descriptor *old_descriptor = NULL;
	struct security_descriptor *new_sd, *final_sd;
	DATA_BLOB *linear_sd;
	enum ndr_err_code ndr_err;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct auth_session_info *session_info
		= ldb_get_opaque(ldb, "sessionInfo");
	const struct dom_sid *domain_sid = samdb_domain_sid(ldb);
	char *sddl_sd;
	struct dom_sid *default_owner;
	struct dom_sid *default_group;
	struct security_descriptor *default_descriptor = NULL;
	struct GUID *object_list = NULL;

	if (objectclass != NULL) {
		default_descriptor = get_sd_unpacked(module, mem_ctx, objectclass);
		object_list = talloc_zero_array(mem_ctx, struct GUID, 2);
		if (object_list == NULL) {
			return NULL;
		}
		object_list[0] = objectclass->schemaIDGUID;
	}

	if (object) {
		user_descriptor = talloc(mem_ctx, struct security_descriptor);
		if (!user_descriptor) {
			return NULL;
		}
		ndr_err = ndr_pull_struct_blob(object, user_descriptor, 
					       user_descriptor,
					       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(user_descriptor);
			return NULL;
		}
	} else {
		user_descriptor = default_descriptor;
	}

	if (old_sd) {
		old_descriptor = talloc(mem_ctx, struct security_descriptor);
		if (!old_descriptor) {
			return NULL;
		}
		ndr_err = ndr_pull_struct_blob(old_sd, old_descriptor, 
					       old_descriptor,
					       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(old_descriptor);
			return NULL;
		}
	}

	if (parent) {
		parent_descriptor = talloc(mem_ctx, struct security_descriptor);
		if (!parent_descriptor) {
			return NULL;
		}
		ndr_err = ndr_pull_struct_blob(parent, parent_descriptor, 
					       parent_descriptor,
					       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(parent_descriptor);
			return NULL;
		}
	}

	if (user_descriptor && default_descriptor &&
	    (user_descriptor->dacl == NULL))
	{
		user_descriptor->dacl = default_descriptor->dacl;
		user_descriptor->type |= default_descriptor->type & (
			SEC_DESC_DACL_PRESENT |
			SEC_DESC_DACL_DEFAULTED|SEC_DESC_DACL_AUTO_INHERIT_REQ |
			SEC_DESC_DACL_AUTO_INHERITED|SEC_DESC_DACL_PROTECTED |
			SEC_DESC_DACL_TRUSTED);
	}

	if (user_descriptor && default_descriptor &&
	    (user_descriptor->sacl == NULL))
	{
		user_descriptor->sacl = default_descriptor->sacl;
		user_descriptor->type |= default_descriptor->type & (
			SEC_DESC_SACL_PRESENT |
			SEC_DESC_SACL_DEFAULTED|SEC_DESC_SACL_AUTO_INHERIT_REQ |
			SEC_DESC_SACL_AUTO_INHERITED|SEC_DESC_SACL_PROTECTED |
			SEC_DESC_SERVER_SECURITY);
	}


	if (!(sd_flags & SECINFO_OWNER) && user_descriptor) {
		user_descriptor->owner_sid = NULL;

		/*
		 * We need the correct owner sid
		 * when calculating the DACL or SACL
		 */
		if (old_descriptor) {
			user_descriptor->owner_sid = old_descriptor->owner_sid;
		}
	}
	if (!(sd_flags & SECINFO_GROUP) && user_descriptor) {
		user_descriptor->group_sid = NULL;

		/*
		 * We need the correct group sid
		 * when calculating the DACL or SACL
		 */
		if (old_descriptor) {
			user_descriptor->group_sid = old_descriptor->group_sid;
		}
	}
	if (!(sd_flags & SECINFO_DACL) && user_descriptor) {
		user_descriptor->dacl = NULL;

		/*
		 * We add SEC_DESC_DACL_PROTECTED so that
		 * create_security_descriptor() skips
		 * the unused inheritance calculation
		 */
		user_descriptor->type |= SEC_DESC_DACL_PROTECTED;
	}
	if (!(sd_flags & SECINFO_SACL) && user_descriptor) {
		user_descriptor->sacl = NULL;

		/*
		 * We add SEC_DESC_SACL_PROTECTED so that
		 * create_security_descriptor() skips
		 * the unused inheritance calculation
		 */
		user_descriptor->type |= SEC_DESC_SACL_PROTECTED;
	}

	default_owner = get_default_ag(mem_ctx, dn,
				       session_info->security_token, ldb);
	default_group = get_default_group(mem_ctx, ldb, default_owner);
	new_sd = create_security_descriptor(mem_ctx,
					    parent_descriptor,
					    user_descriptor,
					    true,
					    object_list,
					    SEC_DACL_AUTO_INHERIT |
					    SEC_SACL_AUTO_INHERIT,
					    session_info->security_token,
					    default_owner, default_group,
					    map_generic_rights_ds);
	if (!new_sd) {
		return NULL;
	}
	final_sd = descr_handle_sd_flags(mem_ctx, new_sd, old_descriptor, sd_flags);

	if (!final_sd) {
		return NULL;
	}

	if (final_sd->dacl) {
		final_sd->dacl->revision = SECURITY_ACL_REVISION_ADS;
	}
	if (final_sd->sacl) {
		final_sd->sacl->revision = SECURITY_ACL_REVISION_ADS;
	}

	sddl_sd = sddl_encode(mem_ctx, final_sd, domain_sid);
	DEBUG(10, ("Object %s created with desriptor %s\n\n", ldb_dn_get_linearized(dn), sddl_sd));

	linear_sd = talloc(mem_ctx, DATA_BLOB);
	if (!linear_sd) {
		return NULL;
	}

	ndr_err = ndr_push_struct_blob(linear_sd, mem_ctx,
				       final_sd,
				       (ndr_push_flags_fn_t)ndr_push_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NULL;
	}

	return linear_sd;
}

static DATA_BLOB *descr_get_descriptor_to_show(struct ldb_module *module,
					       TALLOC_CTX *mem_ctx,
					       struct ldb_val *sd,
					       uint32_t sd_flags)
{
	struct security_descriptor *old_sd, *final_sd;
	DATA_BLOB *linear_sd;
	enum ndr_err_code ndr_err;

	old_sd = talloc(mem_ctx, struct security_descriptor);
	if (!old_sd) {
		return NULL;
	}
	ndr_err = ndr_pull_struct_blob(sd, old_sd, 
				       old_sd,
				       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(old_sd);
		return NULL;
	}

	final_sd = descr_handle_sd_flags(mem_ctx, old_sd, NULL, sd_flags);

	if (!final_sd) {
		return NULL;
	}

	linear_sd = talloc(mem_ctx, DATA_BLOB);
	if (!linear_sd) {
		return NULL;
	}

	ndr_err = ndr_push_struct_blob(linear_sd, mem_ctx,
				       final_sd,
				       (ndr_push_flags_fn_t)ndr_push_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NULL;
	}

	return linear_sd;
}

static struct descriptor_context *descriptor_init_context(struct ldb_module *module,
							  struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct descriptor_context *ac;

	ldb = ldb_module_get_ctx(module);

	ac = talloc_zero(req, struct descriptor_context);
	if (ac == NULL) {
		ldb_set_errstring(ldb, "Out of Memory");
		return NULL;
	}

	ac->module = module;
	ac->req = req;
	return ac;
}

static int descriptor_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct descriptor_context *ac;
	struct ldb_val *sd_val = NULL;
	struct ldb_message_element *sd_el;
	DATA_BLOB *show_sd;
	int ret = LDB_SUCCESS;

	ac = talloc_get_type(req->context, struct descriptor_context);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto fail;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		sd_el = ldb_msg_find_element(ares->message, "nTSecurityDescriptor");
		if (sd_el) {
			sd_val = sd_el->values;
		}

		if (sd_val) {
			show_sd = descr_get_descriptor_to_show(ac->module, ac->req,
							       sd_val, ac->sd_flags);
			if (!show_sd) {
				ret = LDB_ERR_OPERATIONS_ERROR;
				goto fail;
			}
			ldb_msg_remove_attr(ares->message, "nTSecurityDescriptor");
			ret = ldb_msg_add_steal_value(ares->message, "nTSecurityDescriptor", show_sd);
			if (ret != LDB_SUCCESS) {
				goto fail;
			}
		}
		return ldb_module_send_entry(ac->req, ares->message, ares->controls);

	case LDB_REPLY_REFERRAL:
		return ldb_module_send_referral(ac->req, ares->referral);

	case LDB_REPLY_DONE:
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

fail:
	talloc_free(ares);
	return ldb_module_done(ac->req, NULL, NULL, ret);
}

static int descriptor_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_request *add_req;
	struct ldb_message *msg;
	struct ldb_result *parent_res;
	const struct ldb_val *parent_sd = NULL;
	const struct ldb_val *user_sd;
	struct ldb_dn *dn = req->op.add.message->dn;
	struct ldb_dn *parent_dn, *nc_root;
	struct ldb_message_element *objectclass_element, *sd_element;
	int ret;
	const struct dsdb_schema *schema;
	DATA_BLOB *sd;
	const struct dsdb_class *objectclass;
	static const char * const parent_attrs[] = { "nTSecurityDescriptor", NULL };
	uint32_t instanceType;
	bool isNC = false;
	uint32_t sd_flags = dsdb_request_sd_flags(req, NULL);

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(dn)) {
		return ldb_next_request(module, req);
	}

	user_sd = ldb_msg_find_ldb_val(req->op.add.message, "nTSecurityDescriptor");
	sd_element = ldb_msg_find_element(req->op.add.message, "nTSecurityDescriptor");
	/* nTSecurityDescriptor without a value is an error, letting through so it is handled */
	if (user_sd == NULL && sd_element) {
		return ldb_next_request(module, req);
	}

	ldb_debug(ldb, LDB_DEBUG_TRACE,"descriptor_add: %s\n", ldb_dn_get_linearized(dn));

	instanceType = ldb_msg_find_attr_as_uint(req->op.add.message, "instanceType", 0);

	if (instanceType & INSTANCE_TYPE_IS_NC_HEAD) {
		isNC = true;
	}

	if (!isNC) {
		ret = dsdb_find_nc_root(ldb, req, dn, &nc_root);
		if (ret != LDB_SUCCESS) {
			ldb_debug(ldb, LDB_DEBUG_TRACE,"descriptor_add: Could not find NC root for %s\n",
				ldb_dn_get_linearized(dn));
			return ret;
		}

		if (ldb_dn_compare(dn, nc_root) == 0) {
			DEBUG(0, ("Found DN %s being a NC by the old method\n", ldb_dn_get_linearized(dn)));
			isNC = true;
		}
	}

	if (isNC) {
		DEBUG(2, ("DN: %s is a NC\n", ldb_dn_get_linearized(dn)));
	}
	if (!isNC) {
		/* if the object has a parent, retrieve its SD to
		 * use for calculation. Unfortunately we do not yet have
		 * instanceType, so we use dsdb_find_nc_root. */

		parent_dn = ldb_dn_get_parent(req, dn);
		if (parent_dn == NULL) {
			return ldb_oom(ldb);
		}

		/* we aren't any NC */
		ret = dsdb_module_search_dn(module, req, &parent_res, parent_dn,
					    parent_attrs,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_FLAG_AS_SYSTEM |
					    DSDB_SEARCH_SHOW_RECYCLED,
					    req);
		if (ret != LDB_SUCCESS) {
			ldb_debug(ldb, LDB_DEBUG_TRACE,"descriptor_add: Could not find SD for %s\n",
				  ldb_dn_get_linearized(parent_dn));
			return ret;
		}
		if (parent_res->count != 1) {
			return ldb_operr(ldb);
		}
		parent_sd = ldb_msg_find_ldb_val(parent_res->msgs[0], "nTSecurityDescriptor");
	}

	schema = dsdb_get_schema(ldb, req);

	objectclass_element = ldb_msg_find_element(req->op.add.message, "objectClass");
	if (objectclass_element == NULL) {
		return ldb_operr(ldb);
	}

	objectclass = dsdb_get_last_structural_class(schema,
						     objectclass_element);
	if (objectclass == NULL) {
		return ldb_operr(ldb);
	}

	/*
	 * The SD_FLAG control is ignored on add
	 * and we default to all bits set.
	 */
	sd_flags = SECINFO_OWNER|SECINFO_GROUP|SECINFO_SACL|SECINFO_DACL;

	sd = get_new_descriptor(module, dn, req,
				objectclass, parent_sd,
				user_sd, NULL, sd_flags);
	if (sd == NULL) {
		return ldb_operr(ldb);
	}
	msg = ldb_msg_copy_shallow(req, req->op.add.message);
	if (msg == NULL) {
		return ldb_oom(ldb);
	}
	if (sd_element != NULL) {
		sd_element->values[0] = *sd;
	} else {
		ret = ldb_msg_add_steal_value(msg,
					      "nTSecurityDescriptor",
					      sd);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	ret = ldb_build_add_req(&add_req, ldb, req,
				msg,
				req->controls,
				req, dsdb_next_callback,
				req);
	LDB_REQ_SET_LOCATION(add_req);
	if (ret != LDB_SUCCESS) {
		return ldb_error(ldb, ret,
				 "descriptor_add: Error creating new add request.");
	}

	return ldb_next_request(module, add_req);
}

static int descriptor_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_request *mod_req;
	struct ldb_message *msg;
	struct ldb_result *current_res, *parent_res;
	const struct ldb_val *old_sd = NULL;
	const struct ldb_val *parent_sd = NULL;
	const struct ldb_val *user_sd;
	struct ldb_dn *dn = req->op.mod.message->dn;
	struct ldb_dn *parent_dn;
	struct ldb_message_element *objectclass_element, *sd_element;
	int ret;
	uint32_t instanceType;
	bool explicit_sd_flags = false;
	uint32_t sd_flags = dsdb_request_sd_flags(req, &explicit_sd_flags);
	const struct dsdb_schema *schema;
	DATA_BLOB *sd;
	const struct dsdb_class *objectclass;
	static const char * const parent_attrs[] = { "nTSecurityDescriptor", NULL };
	static const char * const current_attrs[] = { "nTSecurityDescriptor",
						      "instanceType",
						      "objectClass", NULL };
	struct ldb_control *sd_propagation_control;
	int cmp_ret = -1;

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(dn)) {
		return ldb_next_request(module, req);
	}

	sd_propagation_control = ldb_request_get_control(req,
					DSDB_CONTROL_SEC_DESC_PROPAGATION_OID);
	if (sd_propagation_control != NULL) {
		if (sd_propagation_control->data != module) {
			return ldb_operr(ldb);
		}
		if (req->op.mod.message->num_elements != 0) {
			return ldb_operr(ldb);
		}
		if (explicit_sd_flags) {
			return ldb_operr(ldb);
		}
		if (sd_flags != 0xF) {
			return ldb_operr(ldb);
		}
		if (sd_propagation_control->critical == 0) {
			return ldb_operr(ldb);
		}

		sd_propagation_control->critical = 0;
	}

	sd_element = ldb_msg_find_element(req->op.mod.message, "nTSecurityDescriptor");
	if (sd_propagation_control == NULL && sd_element == NULL) {
		return ldb_next_request(module, req);
	}

	/*
	 * nTSecurityDescriptor with DELETE is not supported yet.
	 * TODO: handle this correctly.
	 */
	if (sd_propagation_control == NULL &&
	    LDB_FLAG_MOD_TYPE(sd_element->flags) == LDB_FLAG_MOD_DELETE)
	{
		return ldb_module_error(module,
					LDB_ERR_UNWILLING_TO_PERFORM,
					"MOD_DELETE for nTSecurityDescriptor "
					"not supported yet");
	}

	user_sd = ldb_msg_find_ldb_val(req->op.mod.message, "nTSecurityDescriptor");
	/* nTSecurityDescriptor without a value is an error, letting through so it is handled */
	if (sd_propagation_control == NULL && user_sd == NULL) {
		return ldb_next_request(module, req);
	}

	ldb_debug(ldb, LDB_DEBUG_TRACE,"descriptor_modify: %s\n", ldb_dn_get_linearized(dn));

	ret = dsdb_module_search_dn(module, req, &current_res, dn,
				    current_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED,
				    req);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,"descriptor_modify: Could not find %s\n",
			  ldb_dn_get_linearized(dn));
		return ret;
	}

	instanceType = ldb_msg_find_attr_as_uint(current_res->msgs[0],
						 "instanceType", 0);
	/* if the object has a parent, retrieve its SD to
	 * use for calculation */
	if (!ldb_dn_is_null(current_res->msgs[0]->dn) &&
	    !(instanceType & INSTANCE_TYPE_IS_NC_HEAD)) {
		parent_dn = ldb_dn_get_parent(req, dn);
		if (parent_dn == NULL) {
			return ldb_oom(ldb);
		}
		ret = dsdb_module_search_dn(module, req, &parent_res, parent_dn,
					    parent_attrs,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_FLAG_AS_SYSTEM |
					    DSDB_SEARCH_SHOW_RECYCLED,
					    req);
		if (ret != LDB_SUCCESS) {
			ldb_debug(ldb, LDB_DEBUG_ERROR, "descriptor_modify: Could not find SD for %s\n",
				  ldb_dn_get_linearized(parent_dn));
			return ret;
		}
		if (parent_res->count != 1) {
			return ldb_operr(ldb);
		}
		parent_sd = ldb_msg_find_ldb_val(parent_res->msgs[0], "nTSecurityDescriptor");
	}

	schema = dsdb_get_schema(ldb, req);

	objectclass_element = ldb_msg_find_element(current_res->msgs[0], "objectClass");
	if (objectclass_element == NULL) {
		return ldb_operr(ldb);
	}

	objectclass = dsdb_get_last_structural_class(schema,
						     objectclass_element);
	if (objectclass == NULL) {
		return ldb_operr(ldb);
	}

	old_sd = ldb_msg_find_ldb_val(current_res->msgs[0], "nTSecurityDescriptor");
	if (old_sd == NULL) {
		return ldb_operr(ldb);
	}

	if (sd_propagation_control != NULL) {
		/*
		 * This just triggers a recalculation of the
		 * inherited aces.
		 */
		user_sd = old_sd;
	}

	sd = get_new_descriptor(module, dn, req,
				objectclass, parent_sd,
				user_sd, old_sd, sd_flags);
	if (sd == NULL) {
		return ldb_operr(ldb);
	}
	msg = ldb_msg_copy_shallow(req, req->op.mod.message);
	if (msg == NULL) {
		return ldb_oom(ldb);
	}
	cmp_ret = data_blob_cmp(old_sd, sd);
	if (sd_propagation_control != NULL) {
		if (cmp_ret == 0) {
			/*
			 * The nTSecurityDescriptor is unchanged,
			 * which means we can stop the processing.
			 *
			 * We mark the control as critical again,
			 * as we have not processed it, so the caller
			 * can tell that the descriptor was unchanged.
			 */
			sd_propagation_control->critical = 1;
			return ldb_module_done(req, NULL, NULL, LDB_SUCCESS);
		}

		ret = ldb_msg_add_empty(msg, "nTSecurityDescriptor",
					LDB_FLAG_MOD_REPLACE,
					&sd_element);
		if (ret != LDB_SUCCESS) {
			return ldb_oom(ldb);
		}
		ret = ldb_msg_add_value(msg, "nTSecurityDescriptor",
					sd, NULL);
		if (ret != LDB_SUCCESS) {
			return ldb_oom(ldb);
		}
	} else if (cmp_ret != 0) {
		struct ldb_dn *nc_root;

		ret = dsdb_find_nc_root(ldb, msg, dn, &nc_root);
		if (ret != LDB_SUCCESS) {
			return ldb_oom(ldb);
		}

		ret = dsdb_module_schedule_sd_propagation(module, nc_root,
							  dn, false);
		if (ret != LDB_SUCCESS) {
			return ldb_operr(ldb);
		}
		sd_element->values[0] = *sd;
	} else {
		sd_element->values[0] = *sd;
	}

	ret = ldb_build_mod_req(&mod_req, ldb, req,
				msg,
				req->controls,
				req,
				dsdb_next_callback,
				req);
	LDB_REQ_SET_LOCATION(mod_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, mod_req);
}

static int descriptor_search(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_context *ldb;
	struct ldb_request *down_req;
	struct descriptor_context *ac;
	bool explicit_sd_flags = false;
	uint32_t sd_flags = dsdb_request_sd_flags(req, &explicit_sd_flags);
	bool show_sd = explicit_sd_flags;

	if (!show_sd &&
	    ldb_attr_in_list(req->op.search.attrs, "nTSecurityDescriptor"))
	{
		show_sd = true;
	}

	if (!show_sd) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);
	ac = descriptor_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}
	ac->sd_flags = sd_flags;

	ret = ldb_build_search_req_ex(&down_req, ldb, ac,
				      req->op.search.base,
				      req->op.search.scope,
				      req->op.search.tree,
				      req->op.search.attrs,
				      req->controls,
				      ac, descriptor_search_callback,
				      ac->req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, down_req);
}

static int descriptor_rename(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_dn *olddn = req->op.rename.olddn;
	struct ldb_dn *newdn = req->op.rename.newdn;
	int ret;

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.rename.olddn)) {
		return ldb_next_request(module, req);
	}

	ldb_debug(ldb, LDB_DEBUG_TRACE,"descriptor_rename: %s\n",
		  ldb_dn_get_linearized(olddn));

	if (ldb_dn_compare(olddn, newdn) != 0) {
		struct ldb_dn *nc_root;

		ret = dsdb_find_nc_root(ldb, req, newdn, &nc_root);
		if (ret != LDB_SUCCESS) {
			return ldb_oom(ldb);
		}

		ret = dsdb_module_schedule_sd_propagation(module, nc_root,
							  newdn, true);
		if (ret != LDB_SUCCESS) {
			return ldb_operr(ldb);
		}
	}

	return ldb_next_request(module, req);
}

static int descriptor_extended_sec_desc_propagation(struct ldb_module *module,
						    struct ldb_request *req)
{
	struct descriptor_data *descriptor_private =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct descriptor_data);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_extended_sec_desc_propagation_op *op;
	TALLOC_CTX *parent_mem = NULL;
	struct descriptor_changes *parent_change = NULL;
	struct descriptor_changes *c;
	int ret;

	op = talloc_get_type(req->op.extended.data,
			     struct dsdb_extended_sec_desc_propagation_op);
	if (op == NULL) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "descriptor_extended_sec_desc_propagation: "
			  "invalid extended data\n");
		return LDB_ERR_PROTOCOL_ERROR;
	}

	if (descriptor_private->trans_mem == NULL) {
		return ldb_module_operr(module);
	}

	parent_mem = descriptor_private->trans_mem;

	for (c = descriptor_private->changes; c; c = c->next) {
		ret = ldb_dn_compare(c->nc_root, op->nc_root);
		if (ret != 0) {
			continue;
		}

		ret = ldb_dn_compare(c->dn, op->dn);
		if (ret == 0) {
			if (op->include_self) {
				c->force_self = true;
			} else {
				c->force_children = true;
			}
			return ldb_module_done(req, NULL, NULL, LDB_SUCCESS);
		}

		ret = ldb_dn_compare_base(c->dn, op->dn);
		if (ret != 0) {
			continue;
		}

		parent_mem = c;
		parent_change = c;
		break;
	}

	c = talloc_zero(parent_mem, struct descriptor_changes);
	if (c == NULL) {
		return ldb_module_oom(module);
	}
	c->nc_root = ldb_dn_copy(c, op->nc_root);
	if (c->nc_root == NULL) {
		return ldb_module_oom(module);
	}
	c->dn = ldb_dn_copy(c, op->dn);
	if (c->dn == NULL) {
		return ldb_module_oom(module);
	}
	if (op->include_self) {
		c->force_self = true;
	} else {
		c->force_children = true;
	}

	if (parent_change != NULL) {
		DLIST_ADD_END(parent_change->children, c, NULL);
	} else {
		DLIST_ADD_END(descriptor_private->changes, c, NULL);
	}

	return ldb_module_done(req, NULL, NULL, LDB_SUCCESS);
}

static int descriptor_extended(struct ldb_module *module, struct ldb_request *req)
{
	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_SEC_DESC_PROPAGATION_OID) == 0) {
		return descriptor_extended_sec_desc_propagation(module, req);
	}

	return ldb_next_request(module, req);
}

static int descriptor_init(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	int ret;
	struct descriptor_data *descriptor_private;

	ret = ldb_mod_register_control(module, LDB_CONTROL_SD_FLAGS_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			"descriptor: Unable to register control with rootdse!\n");
		return ldb_operr(ldb);
	}

	descriptor_private = talloc_zero(module, struct descriptor_data);
	if (descriptor_private == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ldb_module_set_private(module, descriptor_private);

	return ldb_next_init(module);
}

static int descriptor_sd_propagation_object(struct ldb_module *module,
					    struct ldb_message *msg,
					    bool *stop)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_request *sub_req;
	struct ldb_result *mod_res;
	struct ldb_control *sd_propagation_control;
	int ret;

	*stop = false;

	mod_res = talloc_zero(msg, struct ldb_result);
	if (mod_res == NULL) {
		return ldb_module_oom(module);
	}

	ret = ldb_build_mod_req(&sub_req, ldb, mod_res,
				msg,
				NULL,
				mod_res,
				ldb_modify_default_callback,
				NULL);
	LDB_REQ_SET_LOCATION(sub_req);
	if (ret != LDB_SUCCESS) {
		return ldb_module_operr(module);
	}

	ldb_req_mark_trusted(sub_req);

	ret = ldb_request_add_control(sub_req,
				      DSDB_CONTROL_SEC_DESC_PROPAGATION_OID,
				      true, module);
	if (ret != LDB_SUCCESS) {
		return ldb_module_operr(module);
	}

	sd_propagation_control = ldb_request_get_control(sub_req,
					DSDB_CONTROL_SEC_DESC_PROPAGATION_OID);
	if (sd_propagation_control == NULL) {
		return ldb_module_operr(module);
	}

	ret = dsdb_request_add_controls(sub_req,
					DSDB_FLAG_AS_SYSTEM |
					DSDB_SEARCH_SHOW_RECYCLED);
	if (ret != LDB_SUCCESS) {
		return ldb_module_operr(module);
	}

	ret = descriptor_modify(module, sub_req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(sub_req->handle, LDB_WAIT_ALL);
	}
	if (ret != LDB_SUCCESS) {
		return ldb_module_operr(module);
	}

	if (sd_propagation_control->critical != 0) {
		*stop = true;
	}

	talloc_free(mod_res);

	return LDB_SUCCESS;
}

static int descriptor_sd_propagation_msg_sort(struct ldb_message **m1,
					      struct ldb_message **m2)
{
	struct ldb_dn *dn1 = (*m1)->dn;
	struct ldb_dn *dn2 = (*m2)->dn;

	/*
	 * This sorts in tree order, parents first
	 */
	return ldb_dn_compare(dn2, dn1);
}

static int descriptor_sd_propagation_dn_sort(struct ldb_dn *dn1,
					     struct ldb_dn *dn2)
{
	/*
	 * This sorts in tree order, parents first
	 */
	return ldb_dn_compare(dn2, dn1);
}

static int descriptor_sd_propagation_recursive(struct ldb_module *module,
					       struct descriptor_changes *change)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_result *res = NULL;
	unsigned int i;
	const char * const no_attrs[] = { "@__NONE__", NULL };
	struct descriptor_changes *c;
	struct descriptor_changes *stopped_stack = NULL;
	enum ldb_scope scope;
	int ret;

	/*
	 * First confirm this object has children, or exists (depending on change->force_self)
	 * 
	 * LDB_SCOPE_SUBTREE searches are expensive.
	 *
	 * Note: that we do not search for deleted/recycled objects
	 */
	ret = dsdb_module_search(module,
				 change,
				 &res,
				 change->dn,
				 LDB_SCOPE_ONELEVEL,
				 no_attrs,
				 DSDB_FLAG_NEXT_MODULE |
				 DSDB_FLAG_AS_SYSTEM,
				 NULL, /* parent_req */
				 "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (res->count == 0 && !change->force_self) {
		TALLOC_FREE(res);
		return LDB_SUCCESS;
	} else if (res->count == 0 && change->force_self) {
		scope = LDB_SCOPE_BASE;
	} else {
		scope = LDB_SCOPE_SUBTREE;
	}

	/*
	 * Note: that we do not search for deleted/recycled objects
	 */
	ret = dsdb_module_search(module,
				 change,
				 &res,
				 change->dn,
				 scope,
				 no_attrs,
				 DSDB_FLAG_NEXT_MODULE |
				 DSDB_FLAG_AS_SYSTEM,
				 NULL, /* parent_req */
				 "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	TYPESAFE_QSORT(res->msgs, res->count,
		       descriptor_sd_propagation_msg_sort);

	for (c = change->children; c; c = c->next) {
		struct ldb_message *msg = NULL;

		BINARY_ARRAY_SEARCH_P(res->msgs, res->count, dn, c->dn,
				      descriptor_sd_propagation_dn_sort,
				      msg);

		if (msg == NULL) {
			ldb_debug(ldb, LDB_DEBUG_WARNING,
				"descriptor_sd_propagation_recursive: "
				"%s not found under %s",
				ldb_dn_get_linearized(c->dn),
				ldb_dn_get_linearized(change->dn));
			continue;
		}

		msg->elements = (struct ldb_message_element *)c;
	}

	DLIST_ADD(stopped_stack, change);

	if (change->force_self) {
		i = 0;
	} else {
		i = 1;
	}

	for (; i < res->count; i++) {
		struct descriptor_changes *cur;
		bool stop = false;

		cur = talloc_get_type(res->msgs[i]->elements,
				      struct descriptor_changes);
		res->msgs[i]->elements = NULL;
		res->msgs[i]->num_elements = 0;

		if (cur != NULL) {
			DLIST_REMOVE(change->children, cur);
		}

		for (c = stopped_stack; c; c = stopped_stack) {
			ret = ldb_dn_compare_base(c->dn,
						  res->msgs[i]->dn);
			if (ret == 0) {
				break;
			}

			c->stopped_dn = NULL;
			DLIST_REMOVE(stopped_stack, c);
		}

		if (cur != NULL) {
			DLIST_ADD(stopped_stack, cur);
		}

		if (stopped_stack->stopped_dn != NULL) {
			ret = ldb_dn_compare_base(stopped_stack->stopped_dn,
						  res->msgs[i]->dn);
			if (ret == 0) {
				continue;
			}
			stopped_stack->stopped_dn = NULL;
		}

		ret = descriptor_sd_propagation_object(module, res->msgs[i],
						       &stop);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		if (cur != NULL && cur->force_children) {
			continue;
		}

		if (stop) {
			stopped_stack->stopped_dn = res->msgs[i]->dn;
			continue;
		}
	}

	TALLOC_FREE(res);
	return LDB_SUCCESS;
}

static int descriptor_start_transaction(struct ldb_module *module)
{
	struct descriptor_data *descriptor_private =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct descriptor_data);

	if (descriptor_private->trans_mem != NULL) {
		return ldb_module_operr(module);
	}

	descriptor_private->trans_mem = talloc_new(descriptor_private);
	if (descriptor_private->trans_mem == NULL) {
		return ldb_module_oom(module);
	}
	descriptor_private->changes = NULL;

	return ldb_next_start_trans(module);
}

static int descriptor_prepare_commit(struct ldb_module *module)
{
	struct descriptor_data *descriptor_private =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct descriptor_data);
	struct descriptor_changes *c, *n;
	int ret;

	for (c = descriptor_private->changes; c; c = n) {
		n = c->next;
		DLIST_REMOVE(descriptor_private->changes, c);

		ret = descriptor_sd_propagation_recursive(module, c);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			continue;
		}
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return ldb_next_prepare_commit(module);
}

static int descriptor_end_transaction(struct ldb_module *module)
{
	struct descriptor_data *descriptor_private =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct descriptor_data);

	TALLOC_FREE(descriptor_private->trans_mem);
	descriptor_private->changes = NULL;

	return ldb_next_end_trans(module);
}

static int descriptor_del_transaction(struct ldb_module *module)
{
	struct descriptor_data *descriptor_private =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct descriptor_data);

	TALLOC_FREE(descriptor_private->trans_mem);
	descriptor_private->changes = NULL;

	return ldb_next_del_trans(module);
}

static const struct ldb_module_ops ldb_descriptor_module_ops = {
	.name              = "descriptor",
	.search            = descriptor_search,
	.add               = descriptor_add,
	.modify            = descriptor_modify,
	.rename            = descriptor_rename,
	.init_context      = descriptor_init,
	.extended          = descriptor_extended,
	.start_transaction = descriptor_start_transaction,
	.prepare_commit    = descriptor_prepare_commit,
	.end_transaction   = descriptor_end_transaction,
	.del_transaction   = descriptor_del_transaction,
};

int ldb_descriptor_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_descriptor_module_ops);
}
