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
#include "util.h"

struct descriptor_data {
	int _dummy;
};

struct descriptor_context {
	struct ldb_module *module;
	struct ldb_request *req;
	struct ldb_reply *search_res;
	struct ldb_reply *search_oc_res;
	struct ldb_val *parentsd_val;
	struct ldb_val *sd_val;
	int (*step_fn)(struct descriptor_context *);
};

struct dom_sid *get_default_ag(TALLOC_CTX *mem_ctx,
			       struct ldb_dn *dn,
			       struct security_token *token,
			       struct ldb_context *ldb)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct ldb_dn *root_base_dn = ldb_get_root_basedn(ldb);
	struct ldb_dn *schema_base_dn = ldb_get_schema_basedn(ldb);
	struct ldb_dn *config_base_dn = ldb_get_config_basedn(ldb);
	const struct dom_sid *domain_sid = samdb_domain_sid(ldb);
	struct dom_sid *da_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_ADMINS);
	struct dom_sid *ea_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_ENTERPRISE_ADMINS);
	struct dom_sid *sa_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_SCHEMA_ADMINS);
	struct dom_sid *dag_sid;

	/* FIXME: this has to be fixed regarding the forest DN (root DN) and
	 * the domain DN (default DN) - they aren't always the same. */

	if (ldb_dn_compare_base(schema_base_dn, dn) == 0){
		if (security_token_has_sid(token, sa_sid))
			dag_sid = dom_sid_dup(mem_ctx, sa_sid);
		else if (security_token_has_sid(token, ea_sid))
			dag_sid = dom_sid_dup(mem_ctx, ea_sid);
		else if (security_token_has_sid(token, da_sid))
			dag_sid = dom_sid_dup(mem_ctx, da_sid);
		else
			dag_sid = NULL;
	}
	else if (ldb_dn_compare_base(config_base_dn, dn) == 0){
		if (security_token_has_sid(token, ea_sid))
			dag_sid = dom_sid_dup(mem_ctx, ea_sid);
		else if (security_token_has_sid(token, da_sid))
			dag_sid = dom_sid_dup(mem_ctx, da_sid);
		else
			dag_sid = NULL;
	}
	else if (ldb_dn_compare_base(root_base_dn, dn) == 0){
		if (security_token_has_sid(token, da_sid))
			dag_sid = dom_sid_dup(mem_ctx, da_sid);
		else if (security_token_has_sid(token, ea_sid))
				dag_sid = dom_sid_dup(mem_ctx, ea_sid);
		else
			dag_sid = NULL;
	}
	else
		dag_sid = NULL;

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
	if (dsdb_functional_level(ldb) >= DS_DOMAIN_FUNCTION_2008) {
		return dag;
	}

	return NULL;
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
		final_sd->owner_sid = talloc_memdup(mem_ctx, new_sd->owner_sid, sizeof(struct dom_sid));
		final_sd->type |= new_sd->type & SEC_DESC_OWNER_DEFAULTED;
	}
	else if (old_sd) {
		final_sd->owner_sid = talloc_memdup(mem_ctx, old_sd->owner_sid, sizeof(struct dom_sid));
		final_sd->type |= old_sd->type & SEC_DESC_OWNER_DEFAULTED;
	}

	if (sd_flags & (SECINFO_GROUP)) {
		final_sd->group_sid = talloc_memdup(mem_ctx, new_sd->group_sid, sizeof(struct dom_sid));
		final_sd->type |= new_sd->type & SEC_DESC_GROUP_DEFAULTED;
	} 
	else if (old_sd) {
		final_sd->group_sid = talloc_memdup(mem_ctx, old_sd->group_sid, sizeof(struct dom_sid));
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
				     struct ldb_val *object,
				     struct ldb_val *old_sd,
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
		user_descriptor = get_sd_unpacked(module, mem_ctx, objectclass);
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

	default_owner = get_default_ag(mem_ctx, dn,
				       session_info->security_token, ldb);
	default_group = get_default_group(mem_ctx, ldb, default_owner);
	new_sd = create_security_descriptor(mem_ctx, parent_descriptor, user_descriptor, true,
					    NULL, SEC_DACL_AUTO_INHERIT|SEC_SACL_AUTO_INHERIT,
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

static int get_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct descriptor_context *ac;
	int ret;

	ac = talloc_get_type(req->context, struct descriptor_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS &&
	    ares->error != LDB_ERR_NO_SUCH_OBJECT) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	ldb_reset_err_string(ldb);

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (ac->search_res != NULL) {
			ldb_set_errstring(ldb, "Too many results");
			talloc_free(ares);
			return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
		}

		ac->search_res = talloc_steal(ac, ares);
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);
		ret = ac->step_fn(ac);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
		break;
	}

	return LDB_SUCCESS;
}

static int get_search_oc_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct descriptor_context *ac;
	int ret;

	ac = talloc_get_type(req->context, struct descriptor_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS &&
	    ares->error != LDB_ERR_NO_SUCH_OBJECT) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	ldb_reset_err_string(ldb);

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (ac->search_oc_res != NULL) {
			ldb_set_errstring(ldb, "Too many results");
			talloc_free(ares);
			return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
		}

		ac->search_oc_res = talloc_steal(ac, ares);
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);
		ret = ac->step_fn(ac);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
		break;
	}

	return LDB_SUCCESS;
}


static int descriptor_op_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct descriptor_context *ac;

	ac = talloc_get_type(req->context, struct descriptor_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		return ldb_module_send_referral(ac->req, ares->referral);
	}

	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	return ldb_module_done(ac->req, ares->controls,
				ares->response, ares->error);
}

static int descriptor_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct descriptor_context *ac;
	struct ldb_control *sd_control;
	struct ldb_val *sd_val = NULL;
	struct ldb_message_element *sd_el;
	DATA_BLOB *show_sd;
	int ret;
	uint32_t sd_flags = 0;

	ac = talloc_get_type(req->context, struct descriptor_context);

	if (!ares) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto fail;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	sd_control = ldb_request_get_control(ac->req, LDB_CONTROL_SD_FLAGS_OID);
	if (sd_control) {
		struct ldb_sd_flags_control *sdctr = (struct ldb_sd_flags_control *)sd_control->data;
		sd_flags = sdctr->secinfo_flags;
		/* we only care for the last 4 bits */
		sd_flags = sd_flags & 0x0000000F;
		if (sd_flags == 0) {
			/* MS-ADTS 3.1.1.3.4.1.11 says that no bits
			   equals all 4 bits */
			sd_flags = 0xF;
		}
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (sd_flags != 0) {
			sd_el = ldb_msg_find_element(ares->message, "nTSecurityDescriptor");
			if (sd_el) {
				sd_val = sd_el->values;
			}
		}
		if (sd_val) {
			show_sd = descr_get_descriptor_to_show(ac->module, ac->req,
							       sd_val, sd_flags);
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
		/* ignore referrals */
		break;

	case LDB_REPLY_DONE:
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	talloc_free(ares);
	return LDB_SUCCESS;
fail:
	return ldb_module_done(ac->req, NULL, NULL, ret);
}

static int descriptor_do_mod(struct descriptor_context *ac)
{
	struct ldb_context *ldb;
	const struct dsdb_schema *schema;
	struct ldb_request *mod_req;
	struct ldb_message_element *objectclass_element, *tmp_element, *oldsd_el;
	struct ldb_val *oldsd_val = NULL;
	int ret;
	DATA_BLOB *sd;
	const struct dsdb_class *objectclass;
	struct ldb_message *msg;
	struct ldb_control *sd_control;
	struct ldb_control *sd_control2;
	int flags = 0;
	uint32_t sd_flags = 0;

	ldb = ldb_module_get_ctx(ac->module);
	schema = dsdb_get_schema(ldb, ac);
	msg = ldb_msg_copy_shallow(ac, ac->req->op.mod.message);
	objectclass_element = ldb_msg_find_element(ac->search_oc_res->message, "objectClass");
	objectclass = get_last_structural_class(schema, objectclass_element);

	if (!objectclass) {
		ldb_asprintf_errstring(ldb, "No last structural objectclass found on %s",
				       ldb_dn_get_linearized(ac->search_oc_res->message->dn));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	sd_control = ldb_request_get_control(ac->req, LDB_CONTROL_SD_FLAGS_OID);
	sd_control2 = ldb_request_get_control(ac->req, LDB_CONTROL_RECALCULATE_SD_OID);
	if (sd_control) {
		struct ldb_sd_flags_control *sdctr = (struct ldb_sd_flags_control *)sd_control->data;
		sd_flags = sdctr->secinfo_flags;
		/* we only care for the last 4 bits */
		sd_flags = sd_flags & 0x0000000F;
	}
	if (sd_flags != 0) {
		oldsd_el = ldb_msg_find_element(ac->search_oc_res->message, "nTSecurityDescriptor");
		if (oldsd_el) {
			oldsd_val = oldsd_el->values;
		}
	}
	sd = get_new_descriptor(ac->module, msg->dn, ac, objectclass,
				ac->parentsd_val, ac->sd_val, oldsd_val, sd_flags);
	if (ac->sd_val) {
		tmp_element = ldb_msg_find_element(msg, "ntSecurityDescriptor");
		flags = tmp_element->flags;
		ldb_msg_remove_attr(msg, "nTSecurityDescriptor");
	}

	if (sd) {
		ret = ldb_msg_add_steal_value(msg, "nTSecurityDescriptor", sd);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		tmp_element = ldb_msg_find_element(msg, "ntSecurityDescriptor");
		if (sd_control2) {
			tmp_element->flags = LDB_FLAG_MOD_REPLACE;
		} else {
			tmp_element->flags = flags;
		}
	}
	ret = ldb_build_mod_req(&mod_req, ldb, ac,
				msg,
				ac->req->controls,
				ac, descriptor_op_callback,
				ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	/* mark it non-critical, so we don't get an error from the
	   backend, but mark that we've handled it */
	if (sd_control) {
		sd_control->critical = 0;
	}

	return ldb_next_request(ac->module, mod_req);
}

static int descriptor_do_add(struct descriptor_context *ac)
{
	struct ldb_context *ldb;
	const struct dsdb_schema *schema;
	struct ldb_request *add_req;
	struct ldb_message_element *objectclass_element, *sd_element = NULL;
	struct ldb_message *msg;
	TALLOC_CTX *mem_ctx;
	int ret;
	DATA_BLOB *sd;
	const struct dsdb_class *objectclass;
	static const char *const attrs[] = { "objectClass", "nTSecurityDescriptor", NULL };
	struct ldb_request *search_req;

	ldb = ldb_module_get_ctx(ac->module);
	schema = dsdb_get_schema(ldb, ac);
	mem_ctx = talloc_new(ac);
	if (mem_ctx == NULL) {
		return ldb_oom(ldb);
	}
	switch (ac->req->operation) {
	case LDB_ADD:
		msg = ldb_msg_copy_shallow(ac, ac->req->op.add.message);
		objectclass_element = ldb_msg_find_element(msg, "objectClass");
		objectclass = get_last_structural_class(schema, objectclass_element);

		if (!objectclass) {
			ldb_asprintf_errstring(ldb, "No last structural objectclass found on %s", ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		break;
	case LDB_MODIFY:
		msg = ldb_msg_copy_shallow(ac, ac->req->op.mod.message);
		break;
	default:
		return ldb_operr(ldb);
	}


	/* get the security descriptor values*/
	sd_element = ldb_msg_find_element(msg, "nTSecurityDescriptor");
	if (sd_element) {
		ac->sd_val = talloc_memdup(ac, &sd_element->values[0], sizeof(struct ldb_val));
	}
	/* NC's have no parent */
	/* FIXME: this has to be made dynamic at some point */
	if ((ldb_dn_compare(msg->dn, (ldb_get_schema_basedn(ldb))) == 0) ||
	    (ldb_dn_compare(msg->dn, (ldb_get_config_basedn(ldb))) == 0) ||
	    (ldb_dn_compare(msg->dn, (ldb_get_default_basedn(ldb))) == 0) ||
	    (ldb_dn_compare(msg->dn, (ldb_get_root_basedn(ldb))) == 0)) {
		ac->parentsd_val = NULL;
	} else if (ac->search_res != NULL) {
		struct ldb_message_element *parent_element = ldb_msg_find_element(ac->search_res->message, "nTSecurityDescriptor");
		if (parent_element) {
			ac->parentsd_val = talloc_memdup(ac, &parent_element->values[0], sizeof(struct ldb_val));
		}
	}

	if (ac->req->operation == LDB_ADD) {
	/* get the parent descriptor and the one provided. If not provided, get the default.*/
	/* convert to security descriptor and calculate */
		sd = get_new_descriptor(ac->module, msg->dn, mem_ctx, objectclass,
					ac->parentsd_val, ac->sd_val, NULL, 0);
		if (ac->sd_val) {
			ldb_msg_remove_attr(msg, "nTSecurityDescriptor");
		}

		if (sd) {
			ret = ldb_msg_add_steal_value(msg, "nTSecurityDescriptor", sd);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}

		talloc_free(mem_ctx);
		ret = ldb_msg_sanity_check(ldb, msg);

		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb, "No last structural objectclass found on %s",
					       ldb_dn_get_linearized(msg->dn));
			return ret;
		}

		ret = ldb_build_add_req(&add_req, ldb, ac,
					msg,
					ac->req->controls,
					ac, descriptor_op_callback,
					ac->req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		return ldb_next_request(ac->module, add_req);
	} else {
		ret = ldb_build_search_req(&search_req, ldb,
				   ac, msg->dn, LDB_SCOPE_BASE,
				   "(objectClass=*)", attrs,
				   NULL,
				   ac, get_search_oc_callback,
				   ac->req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		ac->step_fn = descriptor_do_mod;
		return ldb_next_request(ac->module, search_req);
	}
}

static int descriptor_change(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_control *sd_control;
	struct ldb_request *search_req;
	struct descriptor_context *ac;
	struct ldb_dn *parent_dn, *dn;
	struct ldb_message_element *sd_element;
	int ret;
	static const char * const descr_attrs[] = { "nTSecurityDescriptor", NULL };

	ldb = ldb_module_get_ctx(module);

	switch (req->operation) {
	case LDB_ADD:
		dn = req->op.add.message->dn;
		break;
	case LDB_MODIFY:
		dn = req->op.mod.message->dn;
		sd_element = ldb_msg_find_element(req->op.mod.message, "nTSecurityDescriptor");
		/* This control allow forcing the recalculation of the SD */
		sd_control = ldb_request_get_control(req, LDB_CONTROL_RECALCULATE_SD_OID);
		if (!sd_element && !sd_control) {
			return ldb_next_request(module, req);
		}
		break;
	default:
		return ldb_operr(ldb);
	}
	ldb_debug(ldb, LDB_DEBUG_TRACE,"descriptor_change: %s\n", ldb_dn_get_linearized(dn));

	if (ldb_dn_is_special(dn)) {
		return ldb_next_request(module, req);
	}

	ac = descriptor_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	/* If there isn't a parent, just go on to the add processing */
	if (ldb_dn_get_comp_num(dn) == 1) {
		return descriptor_do_add(ac);
	}

	/* get copy of parent DN */
	parent_dn = ldb_dn_get_parent(ac, dn);
	if (parent_dn == NULL) {
		return ldb_oom(ldb);
	}

	ret = ldb_build_search_req(&search_req, ldb,
				   ac, parent_dn, LDB_SCOPE_BASE,
				   "(objectClass=*)", descr_attrs,
				   NULL,
				   ac, get_search_callback,
				   req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	talloc_steal(search_req, parent_dn);

	ac->step_fn = descriptor_do_add;

	return ldb_next_request(ac->module, search_req);
}

static int descriptor_search(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_context *ldb;
	struct ldb_control *sd_control;
	struct ldb_request *down_req;
	struct descriptor_context *ac;

	sd_control = ldb_request_get_control(req, LDB_CONTROL_SD_FLAGS_OID);
	if (!sd_control) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);
	ac = descriptor_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	ret = ldb_build_search_req_ex(&down_req, ldb, ac,
				      req->op.search.base,
				      req->op.search.scope,
				      req->op.search.tree,
				      req->op.search.attrs,
				      req->controls,
				      ac, descriptor_search_callback,
				      ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	/* mark it as handled */
	if (sd_control) {
		sd_control->critical = 0;
	}

	return ldb_next_request(ac->module, down_req);
}
/* TODO */
static int descriptor_rename(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	ldb_debug(ldb, LDB_DEBUG_TRACE,"descriptor_rename: %s\n", ldb_dn_get_linearized(req->op.rename.olddn));
	return ldb_next_request(module, req);
}

static int descriptor_init(struct ldb_module *module)
{
	int ret = ldb_mod_register_control(module, LDB_CONTROL_SD_FLAGS_OID);
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			"descriptor: Unable to register control with rootdse!\n");
		return ldb_operr(ldb);
	}
	return ldb_next_init(module);
}


_PUBLIC_ const struct ldb_module_ops ldb_descriptor_module_ops = {
	.name	       = "descriptor",
	.search        = descriptor_search,
	.add           = descriptor_change,
	.modify        = descriptor_change,
	.rename        = descriptor_rename,
	.init_context  = descriptor_init
};
