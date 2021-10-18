/*
  ACL utility functions

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
 *  Name: acl_util
 *
 *  Component: ldb ACL modules
 *
 *  Description: Some auxiliary functions used for access checking
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

struct security_token *acl_user_token(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct auth_session_info *session_info
		= (struct auth_session_info *)ldb_get_opaque(
			ldb,
			DSDB_SESSION_INFO);
	if(!session_info) {
		return NULL;
	}
	return session_info->security_token;
}

/* performs an access check from inside the module stack
 * given the dn of the object to be checked, the required access
 * guid is either the guid of the extended right, or NULL
 */

int dsdb_module_check_access_on_dn(struct ldb_module *module,
				   TALLOC_CTX *mem_ctx,
				   struct ldb_dn *dn,
				   uint32_t access_mask,
				   const struct GUID *guid,
				   struct ldb_request *parent)
{
	int ret;
	struct ldb_result *acl_res;
	static const char *acl_attrs[] = {
		"nTSecurityDescriptor",
		"objectSid",
		NULL
	};
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct auth_session_info *session_info
		= (struct auth_session_info *)ldb_get_opaque(
			ldb,
			DSDB_SESSION_INFO);
	if(!session_info) {
		return ldb_operr(ldb);
	}
	ret = dsdb_module_search_dn(module, mem_ctx, &acl_res, dn,
				    acl_attrs,
				    DSDB_FLAG_NEXT_MODULE |
				    DSDB_FLAG_AS_SYSTEM |
				    DSDB_SEARCH_SHOW_RECYCLED,
				    parent);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       "access_check: failed to find object %s\n",
				       ldb_dn_get_linearized(dn));
		return ret;
	}
	return dsdb_check_access_on_dn_internal(ldb, acl_res,
						mem_ctx,
						session_info->security_token,
						dn,
						access_mask,
						guid);
}

int acl_check_access_on_attribute(struct ldb_module *module,
				  TALLOC_CTX *mem_ctx,
				  struct security_descriptor *sd,
				  struct dom_sid *rp_sid,
				  uint32_t access_mask,
				  const struct dsdb_attribute *attr,
				  const struct dsdb_class *objectclass)
{
	int ret;
	NTSTATUS status;
	uint32_t access_granted;
	struct object_tree *root = NULL;
	struct object_tree *new_node = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct security_token *token = acl_user_token(module);

	if (!insert_in_object_tree(tmp_ctx,
				   &objectclass->schemaIDGUID,
				   access_mask, NULL,
				   &root)) {
		DEBUG(10, ("acl_search: cannot add to object tree class schemaIDGUID\n"));
		goto fail;
	}
	new_node = root;

	if (!GUID_all_zero(&attr->attributeSecurityGUID)) {
		if (!insert_in_object_tree(tmp_ctx,
					   &attr->attributeSecurityGUID,
					   access_mask, new_node,
					   &new_node)) {
			DEBUG(10, ("acl_search: cannot add to object tree securityGUID\n"));
			goto fail;
		}
	}

	if (!insert_in_object_tree(tmp_ctx,
				   &attr->schemaIDGUID,
				   access_mask, new_node,
				   &new_node)) {
		DEBUG(10, ("acl_search: cannot add to object tree attributeGUID\n"));
		goto fail;
	}

	status = sec_access_check_ds(sd, token,
				     access_mask,
				     &access_granted,
				     root,
				     rp_sid);
	if (!NT_STATUS_IS_OK(status)) {
		ret = LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}
	else {
		ret = LDB_SUCCESS;
	}
	talloc_free(tmp_ctx);
	return ret;
fail:
	talloc_free(tmp_ctx);
	return ldb_operr(ldb_module_get_ctx(module));
}

int acl_check_access_on_objectclass(struct ldb_module *module,
				    TALLOC_CTX *mem_ctx,
				    struct security_descriptor *sd,
				    struct dom_sid *rp_sid,
				    uint32_t access_mask,
				    const struct dsdb_class *objectclass)
{
	int ret;
	NTSTATUS status;
	uint32_t access_granted;
	struct object_tree *root = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct security_token *token = acl_user_token(module);

	if (!insert_in_object_tree(tmp_ctx,
				   &objectclass->schemaIDGUID,
				   access_mask, NULL,
				   &root)) {
		DEBUG(10, ("acl_search: cannot add to object tree class schemaIDGUID\n"));
		goto fail;
	}

	status = sec_access_check_ds(sd, token,
				     access_mask,
				     &access_granted,
				     root,
				     rp_sid);
	if (!NT_STATUS_IS_OK(status)) {
		ret = LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	} else {
		ret = LDB_SUCCESS;
	}
	talloc_free(tmp_ctx);
	return ret;
fail:
	talloc_free(tmp_ctx);
	return ldb_operr(ldb_module_get_ctx(module));
}

/* checks for validated writes */
int acl_check_extended_right(TALLOC_CTX *mem_ctx,
			     struct ldb_module *module,
			     struct ldb_request *req,
			     const struct dsdb_class *objectclass,
			     struct security_descriptor *sd,
			     struct security_token *token,
			     const char *ext_right,
			     uint32_t right_type,
			     struct dom_sid *sid)
{
	struct GUID right;
	NTSTATUS status;
	uint32_t access_granted;
	struct object_tree *root = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	static const char *no_attrs[] = { NULL };
	struct ldb_result *extended_rights_res = NULL;
	struct ldb_dn *extended_rights_dn = NULL;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	int ret = 0;

	/*
	 * Find the extended right and check if applies to
	 * the objectclass of the object
	 */
	extended_rights_dn = samdb_extended_rights_dn(ldb, req);
	if (!extended_rights_dn) {
		ldb_set_errstring(ldb,
			"access_check: CN=Extended-Rights dn could not be generated!");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Note: we are checking only the structural object class. */
	ret = dsdb_module_search(module, req, &extended_rights_res,
				 extended_rights_dn, LDB_SCOPE_ONELEVEL,
				 no_attrs,
				 DSDB_FLAG_NEXT_MODULE |
				 DSDB_FLAG_AS_SYSTEM,
				 req,
				 "(&(rightsGuid=%s)(appliesTo=%s))",
				 ext_right,
				 GUID_string(tmp_ctx,
					     &(objectclass->schemaIDGUID)));

	if (ret != LDB_SUCCESS) {
		return ret;
	} else if (extended_rights_res->count == 0 ) {
		ldb_debug(ldb, LDB_DEBUG_TRACE,
			  "acl_check_extended_right: Could not find appliesTo for %s\n",
			  ext_right);
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}

	GUID_from_string(ext_right, &right);

	if (!insert_in_object_tree(tmp_ctx, &right, right_type,
				   NULL, &root)) {
		DEBUG(10, ("acl_ext_right: cannot add to object tree\n"));
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	status = sec_access_check_ds(sd, token,
				     right_type,
				     &access_granted,
				     root,
				     sid);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}
	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}

const char *acl_user_name(TALLOC_CTX *mem_ctx, struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct auth_session_info *session_info
		= (struct auth_session_info *)ldb_get_opaque(
			ldb,
			DSDB_SESSION_INFO);
	if (!session_info) {
		return "UNKNOWN (NULL)";
	}

	return talloc_asprintf(mem_ctx, "%s\\%s",
			       session_info->info->domain_name,
			       session_info->info->account_name);
}

uint32_t dsdb_request_sd_flags(struct ldb_request *req, bool *explicit)
{
	struct ldb_control *sd_control;
	uint32_t sd_flags = 0;

	if (explicit) {
		*explicit = false;
	}

	sd_control = ldb_request_get_control(req, LDB_CONTROL_SD_FLAGS_OID);
	if (sd_control != NULL && sd_control->data != NULL) {
		struct ldb_sd_flags_control *sdctr = (struct ldb_sd_flags_control *)sd_control->data;

		sd_flags = sdctr->secinfo_flags;

		if (explicit) {
			*explicit = true;
		}

		/* mark it as handled */
		sd_control->critical = 0;
	}

	/* we only care for the last 4 bits */
	sd_flags &= 0x0000000F;

	/*
	 * MS-ADTS 3.1.1.3.4.1.11 says that no bits
	 * equals all 4 bits
	 */
	if (sd_flags == 0) {
		sd_flags = SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL | SECINFO_SACL;
	}

	return sd_flags;
}

int dsdb_module_schedule_sd_propagation(struct ldb_module *module,
					struct ldb_dn *nc_root,
					struct GUID guid,
					bool include_self)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct dsdb_extended_sec_desc_propagation_op *op;
	int ret;

	op = talloc_zero(module, struct dsdb_extended_sec_desc_propagation_op);
	if (op == NULL) {
		return ldb_oom(ldb);
	}

	op->nc_root = nc_root;
	op->guid = guid;
	op->include_self = include_self;

	ret = dsdb_module_extended(module, op, NULL,
				   DSDB_EXTENDED_SEC_DESC_PROPAGATION_OID,
				   op,
				   DSDB_FLAG_TOP_MODULE |
				   DSDB_FLAG_AS_SYSTEM |
				   DSDB_FLAG_TRUSTED,
				   NULL);
	TALLOC_FREE(op);
	return ret;
}
