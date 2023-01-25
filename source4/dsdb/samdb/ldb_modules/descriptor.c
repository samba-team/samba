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
#include "lib/util/util_tdb.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_rbt.h"

struct descriptor_changes {
	struct descriptor_changes *prev, *next;
	struct ldb_dn *nc_root;
	struct GUID guid;
	struct GUID parent_guid;
	bool force_self;
	bool force_children;
	struct ldb_dn *stopped_dn;
	size_t ref_count;
	size_t sort_count;
};

struct descriptor_transaction {
	TALLOC_CTX *mem;
	struct {
		/*
		 * We used to have a list of changes, appended with each
		 * DSDB_EXTENDED_SEC_DESC_PROPAGATION_OID operation.
		 *
		 * But the main problem was that a replication
		 * cycle (mainly the initial replication) calls
		 * DSDB_EXTENDED_SEC_DESC_PROPAGATION_OID for the
		 * same object[GUID] more than once. With
		 * DRSUAPI_DRS_GET_TGT we'll get the naming
		 * context head object and other top level
		 * containers, every often.
		 *
		 * It means we'll process objects more
		 * than once and waste a lot of time
		 * doing the same work again and again.
		 *
		 * We use an objectGUID based map in order to
		 * avoid registering objects more than once.
		 * In an domain with 22000 object it can
		 * reduce the work from 4 hours down to ~ 3.5 minutes.
		 */
		struct descriptor_changes *list;
		struct db_context *map;
		size_t num_registrations;
		size_t num_registered;
		size_t num_toplevel;
		size_t num_processed;
	} changes;
	struct {
		struct db_context *map;
		size_t num_processed;
		size_t num_skipped;
	} objects;
};

struct descriptor_data {
	struct descriptor_transaction transaction;
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
			       const struct security_token *token,
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

static struct security_descriptor *get_new_descriptor_nonlinear(struct ldb_module *module,
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
	enum ndr_err_code ndr_err;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct auth_session_info *session_info
		= ldb_get_opaque(ldb, DSDB_SESSION_INFO);
	const struct dom_sid *domain_sid = samdb_domain_sid(ldb);
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

	{
		TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
		DBG_DEBUG("Object %s created with descriptor %s\n\n",
			  ldb_dn_get_linearized(dn),
			  sddl_encode(tmp_ctx, final_sd, domain_sid));
		TALLOC_FREE(tmp_ctx);
	}

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
	struct security_descriptor *final_sd = NULL;
	enum ndr_err_code ndr_err;
	DATA_BLOB *linear_sd = talloc(mem_ctx, DATA_BLOB);

	if (!linear_sd) {
		return NULL;
	}

	final_sd = get_new_descriptor_nonlinear(module,
						dn,
						mem_ctx,
						objectclass,
						parent,
						object,
						old_sd,
						sd_flags);
	if (final_sd == NULL) {
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

static bool can_write_owner(TALLOC_CTX *mem_ctx,
			    struct ldb_context *ldb,
			    struct ldb_dn *dn,
			    const struct security_token *security_token,
			    const struct dom_sid *owner_sid)
{
	const struct dom_sid *default_owner = NULL;

	/* If the user possesses SE_RESTORE_PRIVILEGE, the write is allowed. */
	bool ok = security_token_has_privilege(security_token, SEC_PRIV_RESTORE);
	if (ok) {
		return true;
	}

	/* The user can write their own SID to a security descriptor. */
	ok = security_token_is_sid(security_token, owner_sid);
	if (ok) {
		return true;
	}

        /*
	 * The user can write the SID of the "default administrators group" that
	 * they are a member of.
	 */
	default_owner = get_default_ag(mem_ctx, dn,
				       security_token, ldb);
	if (default_owner != NULL) {
		ok = security_token_is_sid(security_token, owner_sid);
	}

	return ok;
}

static int descriptor_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_request *add_req;
	struct ldb_message *msg;
	struct ldb_result *parent_res;
	const struct ldb_val *parent_sd = NULL;
	const struct ldb_val *user_sd = NULL;
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
	enum ndr_err_code ndr_err;
	struct dsdb_control_calculated_default_sd *control_sd = NULL;
	uint32_t sd_flags = dsdb_request_sd_flags(req, NULL);
	struct security_descriptor *user_descriptor = NULL;

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

	control_sd = talloc(req, struct dsdb_control_calculated_default_sd);
	if (control_sd == NULL) {
		return ldb_operr(ldb);
	}
	control_sd->specified_sd = false;
	control_sd->specified_sacl = false;
	if (user_sd != NULL) {
		user_descriptor = talloc(req, struct security_descriptor);
		if (user_descriptor == NULL) {
			return ldb_operr(ldb);
		}
		ndr_err = ndr_pull_struct_blob(user_sd, user_descriptor,
					       user_descriptor,
					       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(user_descriptor);
			return ldb_operr(ldb);
		}
		/*
		 * calculate the permissions needed, since in acl we no longer have
		 * access to the original user descriptor
		 */
		control_sd->specified_sd = true;
		control_sd->specified_sacl = user_descriptor->sacl != NULL;

		if (user_descriptor->owner_sid != NULL) {
			/* Verify the owner of the security descriptor. */

			const struct auth_session_info *session_info
				= ldb_get_opaque(ldb, DSDB_SESSION_INFO);

			bool ok = can_write_owner(req,
						  ldb,
						  dn,
						  session_info->security_token,
						  user_descriptor->owner_sid);
			talloc_free(user_descriptor);
			if (!ok) {
				return dsdb_module_werror(module,
							  LDB_ERR_CONSTRAINT_VIOLATION,
							  WERR_INVALID_OWNER,
							  "invalid addition of owner SID");
			}
		}
	}

	sd = get_new_descriptor(module, dn, req,
				objectclass, parent_sd,
				user_sd, NULL, sd_flags);
	if (sd == NULL) {
		return ldb_operr(ldb);
	}

	control_sd->default_sd = get_new_descriptor_nonlinear(module,
							      dn,
							      req,
							      objectclass,
							      parent_sd,
							      NULL,
							      NULL,
							      sd_flags);
	if (control_sd->default_sd == NULL) {
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

	dom_sid_parse("S-1-0-0", control_sd->default_sd->owner_sid);
	ret = ldb_request_add_control(add_req,
				      DSDB_CONTROL_CALCULATED_DEFAULT_SD_OID,
				      false, (void *)control_sd);
	if (ret != LDB_SUCCESS) {
		return ldb_module_operr(module);
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
	const struct ldb_val *user_sd = NULL;
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
	struct GUID parent_guid = { .time_low = 0 };
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

	if (sd_flags & SECINFO_OWNER && user_sd != NULL) {
		/* Verify the new owner of the security descriptor. */

		struct security_descriptor *user_descriptor = NULL;
		enum ndr_err_code ndr_err;
		const struct auth_session_info *session_info;
		bool ok;

		user_descriptor = talloc(req, struct security_descriptor);

		if (user_descriptor == NULL) {
			return ldb_operr(ldb);
		}
		ndr_err = ndr_pull_struct_blob(user_sd, user_descriptor,
					       user_descriptor,
					       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(user_descriptor);
			return ldb_operr(ldb);
		}

		session_info = ldb_get_opaque(ldb, DSDB_SESSION_INFO);

		ok = can_write_owner(req,
				     ldb,
				     dn,
				     session_info->security_token,
				     user_descriptor->owner_sid);
		talloc_free(user_descriptor);
		if (!ok) {
			return dsdb_module_werror(module,
						  LDB_ERR_CONSTRAINT_VIOLATION,
						  WERR_INVALID_OWNER,
						  "invalid modification of owner SID");
		}
	}

	ldb_debug(ldb, LDB_DEBUG_TRACE,"descriptor_modify: %s\n", ldb_dn_get_linearized(dn));

	ret = dsdb_module_search_dn(module, req, &current_res, dn,
				    current_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED |
				    DSDB_SEARCH_SHOW_EXTENDED_DN,
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
		NTSTATUS status;

		parent_dn = ldb_dn_get_parent(req, dn);
		if (parent_dn == NULL) {
			return ldb_oom(ldb);
		}
		ret = dsdb_module_search_dn(module, req, &parent_res, parent_dn,
					    parent_attrs,
					    DSDB_FLAG_NEXT_MODULE |
					    DSDB_FLAG_AS_SYSTEM |
					    DSDB_SEARCH_SHOW_RECYCLED |
					    DSDB_SEARCH_SHOW_EXTENDED_DN,
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

		status = dsdb_get_extended_dn_guid(parent_res->msgs[0]->dn,
						   &parent_guid,
						   "GUID");
		if (!NT_STATUS_IS_OK(status)) {
			return ldb_operr(ldb);
		}
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

	sd = get_new_descriptor(module, current_res->msgs[0]->dn, req,
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

		ret = ldb_msg_append_value(msg, "nTSecurityDescriptor",
					   sd, LDB_FLAG_MOD_REPLACE);
		if (ret != LDB_SUCCESS) {
			return ldb_oom(ldb);
		}
	} else if (cmp_ret != 0) {
		struct GUID guid;
		struct ldb_dn *nc_root;
		NTSTATUS status;

		ret = dsdb_find_nc_root(ldb,
					msg,
					current_res->msgs[0]->dn,
					&nc_root);
		if (ret != LDB_SUCCESS) {
			return ldb_oom(ldb);
		}

		status = dsdb_get_extended_dn_guid(current_res->msgs[0]->dn,
						   &guid,
						   "GUID");
		if (!NT_STATUS_IS_OK(status)) {
			return ldb_operr(ldb);
		}

		/*
		 * Force SD propagation on children of this record
		 */
		ret = dsdb_module_schedule_sd_propagation(module,
							  nc_root,
							  guid,
							  parent_guid,
							  false);
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

static int descriptor_rename_callback(struct ldb_request *req,
				      struct ldb_reply *ares)
{
	struct descriptor_context *ac = NULL;
	struct ldb_context *ldb = NULL;
	struct ldb_dn *newdn = req->op.rename.newdn;
	struct GUID guid;
	struct ldb_dn *nc_root;
	struct GUID parent_guid = { .time_low = 0 };
	int ret;

	ac = talloc_get_type_abort(req->context, struct descriptor_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	ret = dsdb_module_guid_by_dn(ac->module,
				     newdn,
				     &guid,
				     req);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL,
				       ret);
	}
	ret = dsdb_find_nc_root(ldb, req, newdn, &nc_root);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL,
				       ret);
	}

	/*
	 * After a successful rename, force SD propagation on this
	 * record (get a new inherited SD from the potentially new
	 * parent
	 *
	 * We don't know the parent guid here (it is filled in as
	 * all-zero in the initialiser above), but we're not in a hot
	 * code path here, as the "descriptor" module is located above
	 * the "repl_meta_data", only originating changes are handled
	 * here.
	 *
	 * If it turns out to be a problem we may search for the new
	 * parent guid.
	 */

	ret = dsdb_module_schedule_sd_propagation(ac->module,
						  nc_root,
						  guid,
						  parent_guid,
						  true);
	if (ret != LDB_SUCCESS) {
		ret = ldb_operr(ldb);
		return ldb_module_done(ac->req, NULL, NULL,
				       ret);
	}

	return ldb_module_done(ac->req, ares->controls,
			       ares->response, ares->error);
}




static int descriptor_rename(struct ldb_module *module, struct ldb_request *req)
{
	struct descriptor_context *ac = NULL;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_dn *olddn = req->op.rename.olddn;
	struct ldb_dn *newdn = req->op.rename.newdn;
	struct ldb_request *down_req;
	int ret;

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.rename.olddn)) {
		return ldb_next_request(module, req);
	}

	ldb_debug(ldb, LDB_DEBUG_TRACE,"descriptor_rename: %s\n",
		  ldb_dn_get_linearized(olddn));

	if (ldb_dn_compare(olddn, newdn) == 0) {
		/* No special work required for a case-only rename */
		return ldb_next_request(module, req);
	}

	ac = descriptor_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	ret = ldb_build_rename_req(&down_req, ldb, ac,
				   req->op.rename.olddn,
				   req->op.rename.newdn,
				   req->controls,
				   ac, descriptor_rename_callback,
				   req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, down_req);
}

static void descriptor_changes_parser(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct descriptor_changes **c_ptr = (struct descriptor_changes **)private_data;
	uintptr_t ptr = 0;

	SMB_ASSERT(data.dsize == sizeof(ptr));

	memcpy(&ptr, data.dptr, data.dsize);

	*c_ptr = talloc_get_type_abort((void *)ptr, struct descriptor_changes);
}

static void descriptor_object_parser(TDB_DATA key, TDB_DATA data, void *private_data)
{
	SMB_ASSERT(data.dsize == 0);
}

static int descriptor_extended_sec_desc_propagation(struct ldb_module *module,
						    struct ldb_request *req)
{
	struct descriptor_data *descriptor_private =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct descriptor_data);
	struct descriptor_transaction *t = &descriptor_private->transaction;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_extended_sec_desc_propagation_op *op;
	struct descriptor_changes *c = NULL;
	TDB_DATA key;
	NTSTATUS status;

	op = talloc_get_type(req->op.extended.data,
			     struct dsdb_extended_sec_desc_propagation_op);
	if (op == NULL) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "descriptor_extended_sec_desc_propagation: "
			  "invalid extended data\n");
		return LDB_ERR_PROTOCOL_ERROR;
	}

	if (t->mem == NULL) {
		return ldb_module_operr(module);
	}

	if (GUID_equal(&op->parent_guid, &op->guid)) {
		/*
		 * This is an unexpected situation,
		 * it should never happen!
		 */
		DBG_ERR("ERROR: Object %s is its own parent (nc_root=%s)\n",
			GUID_string(t->mem, &op->guid),
			ldb_dn_get_extended_linearized(t->mem, op->nc_root, 1));
		return ldb_module_operr(module);
	}

	/*
	 * First we check if we already have an registration
	 * for the given object.
	 */

	key = make_tdb_data((const void*)&op->guid, sizeof(op->guid));
	status = dbwrap_parse_record(t->changes.map, key,
				     descriptor_changes_parser, &c);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		c = NULL;
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "dbwrap_parse_record() - %s\n",
			  nt_errstr(status));
		return ldb_module_operr(module);
	}

	if (c == NULL) {
		/*
		 * Create a new structure if we
		 * don't know about the object yet.
		 */

		c = talloc_zero(t->mem, struct descriptor_changes);
		if (c == NULL) {
			return ldb_module_oom(module);
		}
		c->nc_root = ldb_dn_copy(c, op->nc_root);
		if (c->nc_root == NULL) {
			return ldb_module_oom(module);
		}
		c->guid = op->guid;
	}

	if (ldb_dn_compare(c->nc_root, op->nc_root) != 0) {
		/*
		 * This is an unexpected situation,
		 * we don't expect the nc root to change
		 * during a replication cycle.
		 */
		DBG_ERR("ERROR: Object %s nc_root changed %s => %s\n",
			GUID_string(c, &c->guid),
			ldb_dn_get_extended_linearized(c, c->nc_root, 1),
			ldb_dn_get_extended_linearized(c, op->nc_root, 1));
		return ldb_module_operr(module);
	}

	c->ref_count += 1;

	/*
	 * always use the last known parent_guid.
	 */
	c->parent_guid = op->parent_guid;

	/*
	 * Note that we only set, but don't clear values here,
	 * it means c->force_self and c->force_children can
	 * both be true in the end.
	 */
	if (op->include_self) {
		c->force_self = true;
	} else {
		c->force_children = true;
	}

	if (c->ref_count == 1) {
		struct TDB_DATA val = make_tdb_data((const void*)&c, sizeof(c));

		/*
		 * Remember the change by objectGUID in order
		 * to avoid processing it more than once.
		 */

		status = dbwrap_store(t->changes.map, key, val, TDB_INSERT);
		if (!NT_STATUS_IS_OK(status)) {
			ldb_debug(ldb, LDB_DEBUG_FATAL,
				  "dbwrap_parse_record() - %s\n",
				  nt_errstr(status));
			return ldb_module_operr(module);
		}

		DLIST_ADD_END(t->changes.list, c);
		t->changes.num_registered += 1;
	}
	t->changes.num_registrations += 1;

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
	struct descriptor_data *descriptor_private =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct descriptor_data);
	struct descriptor_transaction *t = &descriptor_private->transaction;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_request *sub_req;
	struct ldb_result *mod_res;
	struct ldb_control *sd_propagation_control;
	struct GUID guid;
	int ret;
	TDB_DATA key;
	TDB_DATA empty_val = { .dsize = 0, };
	NTSTATUS status;
	struct descriptor_changes *c = NULL;

	*stop = false;

	/*
	 * We get the GUID of the object
	 * in order to have the cache key
	 * for the object.
	 */

	status = dsdb_get_extended_dn_guid(msg->dn, &guid, "GUID");
	if (!NT_STATUS_IS_OK(status)) {
		return ldb_operr(ldb);
	}
	key = make_tdb_data((const void*)&guid, sizeof(guid));

	/*
	 * Check if we already processed this object.
	 */
	status = dbwrap_parse_record(t->objects.map, key,
				     descriptor_object_parser, NULL);
	if (NT_STATUS_IS_OK(status)) {
		/*
		 * All work is already one
		 */
		t->objects.num_skipped += 1;
		*stop = true;
		return LDB_SUCCESS;
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "dbwrap_parse_record() - %s\n",
			  nt_errstr(status));
		return ldb_module_operr(module);
	}

	t->objects.num_processed += 1;

	/*
	 * Remember that we're processing this object.
	 */
	status = dbwrap_store(t->objects.map, key, empty_val, TDB_INSERT);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "dbwrap_parse_record() - %s\n",
			  nt_errstr(status));
		return ldb_module_operr(module);
	}

	/*
	 * Check that if there's a descriptor_change in our list,
	 * which we may be able to remove from the pending list
	 * when we processed the object.
	 */

	status = dbwrap_parse_record(t->changes.map, key, descriptor_changes_parser, &c);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		c = NULL;
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		ldb_debug(ldb, LDB_DEBUG_FATAL,
			  "dbwrap_parse_record() - %s\n",
			  nt_errstr(status));
		return ldb_module_operr(module);
	}

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
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "descriptor_modify on %s failed: %s",
				       ldb_dn_get_linearized(msg->dn),
				       ldb_errstring(ldb_module_get_ctx(module)));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (sd_propagation_control->critical != 0) {
		if (c == NULL) {
			/*
			 * If we don't have a
			 * descriptor_changes structure
			 * we're done.
			 */
			*stop = true;
		} else if (!c->force_children) {
			/*
			 * If we don't need to
			 * propagate to children,
			 * we're done.
			 */
			*stop = true;
		}
	}

	if (c != NULL && !c->force_children) {
		/*
		 * Remove the pending change,
		 * we already done all required work,
		 * there's no need to do it again.
		 *
		 * Note DLIST_REMOVE() is a noop
		 * if the element is not part of
		 * the list.
		 */
		DLIST_REMOVE(t->changes.list, c);
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

static int descriptor_sd_propagation_recursive(struct ldb_module *module,
					       struct descriptor_changes *change)
{
	struct descriptor_data *descriptor_private =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct descriptor_data);
	struct descriptor_transaction *t = &descriptor_private->transaction;
	struct ldb_result *guid_res = NULL;
	struct ldb_result *res = NULL;
	unsigned int i;
	const char * const no_attrs[] = { "@__NONE__", NULL };
	struct ldb_dn *stopped_dn = NULL;
	struct GUID_txt_buf guid_buf;
	int ret;
	bool stop = false;

	t->changes.num_processed += 1;

	/*
	 * First confirm this object has children, or exists
	 * (depending on change->force_self)
	 * 
	 * LDB_SCOPE_SUBTREE searches are expensive.
	 *
	 * We know this is safe against a rename race as we are in the
	 * prepare_commit(), so must be in a transaction.
	 */

	/* Find the DN by GUID, as this is stable under rename */
	ret = dsdb_module_search(module,
				 change,
				 &guid_res,
				 change->nc_root,
				 LDB_SCOPE_SUBTREE,
				 no_attrs,
				 DSDB_FLAG_NEXT_MODULE |
				 DSDB_FLAG_AS_SYSTEM |
				 DSDB_SEARCH_SHOW_DELETED |
				 DSDB_SEARCH_SHOW_RECYCLED |
				 DSDB_SEARCH_SHOW_EXTENDED_DN,
				 NULL, /* parent_req */
				 "(objectGUID=%s)",
				 GUID_buf_string(&change->guid,
						 &guid_buf));

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (guid_res->count != 1) {
		/*
		 * We were just given this GUID during the same
		 * transaction, if it is missing this is a big
		 * problem.
		 *
		 * Cleanup of tombstones does not trigger this module
		 * as it just does a delete.
		 */
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "failed to find GUID %s under %s "
				       "for transaction-end SD inheritance: %d results",
				       GUID_buf_string(&change->guid,
						       &guid_buf),
				       ldb_dn_get_linearized(change->nc_root),
				       guid_res->count);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * OK, so there was a parent, are there children?  Note: that
	 * this time we do not search for deleted/recycled objects
	 */
	ret = dsdb_module_search(module,
				 change,
				 &res,
				 guid_res->msgs[0]->dn,
				 LDB_SCOPE_ONELEVEL,
				 no_attrs,
				 DSDB_FLAG_NEXT_MODULE |
				 DSDB_FLAG_AS_SYSTEM,
				 NULL, /* parent_req */
				 "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		/*
		 * LDB_ERR_NO_SUCH_OBJECT, say if the DN was a deleted
		 * object, is ignored by the caller
		 */
		return ret;
	}

	if (res->count == 0 && !change->force_self) {
		/* All done, no children */
		TALLOC_FREE(res);
		return LDB_SUCCESS;
	}

	/*
	 * First, if we are in force_self mode (eg renamed under new
	 * parent) then apply the SD to the top object
	 */
	if (change->force_self) {
		ret = descriptor_sd_propagation_object(module,
						       guid_res->msgs[0],
						       &stop);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(guid_res);
			return ret;
		}

		if (stop == true && !change->force_children) {
			/* There was no change, nothing more to do */
			TALLOC_FREE(guid_res);
			return LDB_SUCCESS;
		}

		if (res->count == 0) {
			/* All done! */
			TALLOC_FREE(guid_res);
			return LDB_SUCCESS;
		}
	}

	/*
	 * Look for children
	 *
	 * Note: that we do not search for deleted/recycled objects
	 */
	ret = dsdb_module_search(module,
				 change,
				 &res,
				 guid_res->msgs[0]->dn,
				 LDB_SCOPE_SUBTREE,
				 no_attrs,
				 DSDB_FLAG_NEXT_MODULE |
				 DSDB_FLAG_AS_SYSTEM |
				 DSDB_SEARCH_SHOW_EXTENDED_DN,
				 NULL, /* parent_req */
				 "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	TYPESAFE_QSORT(res->msgs, res->count,
		       descriptor_sd_propagation_msg_sort);

	/* We start from 1, the top object has been done */
	for (i = 1; i < res->count; i++) {
		/*
		 * ldb_dn_compare_base() does not match for NULL but
		 * this is clearer
		 */
		if (stopped_dn != NULL) {
			ret = ldb_dn_compare_base(stopped_dn,
						  res->msgs[i]->dn);
			/*
			 * Skip further processing of this
			 * sub-subtree
			 */
			if (ret == 0) {
				continue;
			}
		}
		ret = descriptor_sd_propagation_object(module,
						       res->msgs[i],
						       &stop);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		if (stop) {
			/*
			 * If this child didn't change, then nothing
			 * under it needs to change
			 *
			 * res has been sorted into tree order so the
			 * next few entries can be skipped
			 */
			stopped_dn = res->msgs[i]->dn;
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
	struct descriptor_transaction *t = &descriptor_private->transaction;

	if (t->mem != NULL) {
		return ldb_module_operr(module);
	}

	*t = (struct descriptor_transaction) { .mem = NULL, };
	t->mem = talloc_new(descriptor_private);
	if (t->mem == NULL) {
		return ldb_module_oom(module);
	}
	t->changes.map = db_open_rbt(t->mem);
	if (t->changes.map == NULL) {
		TALLOC_FREE(t->mem);
		*t = (struct descriptor_transaction) { .mem = NULL, };
		return ldb_module_oom(module);
	}
	t->objects.map = db_open_rbt(t->mem);
	if (t->objects.map == NULL) {
		TALLOC_FREE(t->mem);
		*t = (struct descriptor_transaction) { .mem = NULL, };
		return ldb_module_oom(module);
	}

	return ldb_next_start_trans(module);
}

static int descriptor_prepare_commit(struct ldb_module *module)
{
	struct descriptor_data *descriptor_private =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct descriptor_data);
	struct descriptor_transaction *t = &descriptor_private->transaction;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct descriptor_changes *c, *n;
	int ret;

	DBG_NOTICE("changes: num_registrations=%zu\n",
		   t->changes.num_registrations);
	DBG_NOTICE("changes: num_registered=%zu\n",
		   t->changes.num_registered);

	/*
	 * The security descriptor propagation
	 * needs to apply the inheritance from
	 * an object to itself and/or all it's
	 * children.
	 *
	 * In the initial replication during
	 * a join, we have every object in our
	 * list.
	 *
	 * In order to avoid useless work it's
	 * better to start with toplevel objects and
	 * move down to the leaf object from there.
	 *
	 * So if the parent_guid is also in our list,
	 * we better move the object behind its parent.
	 *
	 * It allows that the recursive processing of
	 * the parent already does the work needed
	 * for the child.
	 *
	 * If we have a list for this directory tree:
	 *
	 *  A
	 *    -> B
	 *        -> C
	 *            -> D
	 *                -> E
	 *
	 * The initial list would have the order D, E, B, A, C
	 *
	 * By still processing from the front, we ensure that,
	 * when D is found to be below C, that E follows because
	 * we keep peeling items off the front for checking and
	 * move them behind their parent.
	 *
	 * So we would go:
	 *
	 * E B A C D
	 *
	 * B A C D E
	 *
	 * A B C D E
	 */
	for (c = t->changes.list; c; c = n) {
		struct descriptor_changes *pc = NULL;
		n = c->next;

		if (c->sort_count >= t->changes.num_registered) {
			/*
			 * This should never happen, but it's
			 * a sanity check in order to avoid
			 * endless loops. Just stop sorting.
			 */
			break;
		}

		/*
		 * Check if we have the parent also in the list.
		 */
		if (!GUID_all_zero((const void*)&c->parent_guid)) {
			TDB_DATA pkey;
			NTSTATUS status;

			pkey = make_tdb_data((const void*)&c->parent_guid,
					     sizeof(c->parent_guid));

			status = dbwrap_parse_record(t->changes.map, pkey,
						     descriptor_changes_parser, &pc);
			if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
				pc = NULL;
				status = NT_STATUS_OK;
			}
			if (!NT_STATUS_IS_OK(status)) {
				ldb_debug(ldb, LDB_DEBUG_FATAL,
					  "dbwrap_parse_record() - %s\n",
					  nt_errstr(status));
				return ldb_module_operr(module);
			}
		}

		if (pc == NULL) {
			/*
			 * There is no parent in the list
			 */
			t->changes.num_toplevel += 1;
			continue;
		}

		/*
		 * Move the child after the parent
		 *
		 * Note that we do that multiple times
		 * in case the parent already moved itself.
		 *
		 * See the comment above the loop.
		 */
		DLIST_REMOVE(t->changes.list, c);
		DLIST_ADD_AFTER(t->changes.list, c, pc);

		/*
		 * Remember how often we moved the object
		 * in order to avoid endless loops.
		 */
		c->sort_count += 1;
	}

	DBG_NOTICE("changes: num_toplevel=%zu\n", t->changes.num_toplevel);

	while (t->changes.list != NULL) {
		c = t->changes.list;

		DLIST_REMOVE(t->changes.list, c);

		/*
		 * Note that descriptor_sd_propagation_recursive()
		 * may also remove other elements of the list,
		 * so we can't use a next pointer
		 */
		ret = descriptor_sd_propagation_recursive(module, c);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			continue;
		}
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	DBG_NOTICE("changes: num_processed=%zu\n", t->changes.num_processed);
	DBG_NOTICE("objects: num_processed=%zu\n", t->objects.num_processed);
	DBG_NOTICE("objects: num_skipped=%zu\n", t->objects.num_skipped);

	return ldb_next_prepare_commit(module);
}

static int descriptor_end_transaction(struct ldb_module *module)
{
	struct descriptor_data *descriptor_private =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct descriptor_data);
	struct descriptor_transaction *t = &descriptor_private->transaction;

	TALLOC_FREE(t->mem);
	*t = (struct descriptor_transaction) { .mem = NULL, };

	return ldb_next_end_trans(module);
}

static int descriptor_del_transaction(struct ldb_module *module)
{
	struct descriptor_data *descriptor_private =
		talloc_get_type_abort(ldb_module_get_private(module),
		struct descriptor_data);
	struct descriptor_transaction *t = &descriptor_private->transaction;

	TALLOC_FREE(t->mem);
	*t = (struct descriptor_transaction) { .mem = NULL, };

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
