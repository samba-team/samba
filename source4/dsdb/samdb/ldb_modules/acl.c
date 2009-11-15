/*
   ldb database library

   Copyright (C) Simo Sorce 2006-2008
   Copyright (C) Nadezhda Ivanova 2009
   Copyright (C) Anatoliy Atanasov  2009

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
 *  Component: ldb ACL module
 *
 *  Description: Module that performs authorisation access checks based on the
 *               account's security context and the DACL of the object being polled.
 *               Only DACL checks implemented at this point
 *
 *  Authors: Nadezhda Ivanova, Anatoliy Atanasov
 */

#include "includes.h"
#include "ldb_module.h"
#include "auth/auth.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "param/param.h"

struct extended_access_check_attribute {
	const char *oa_name;
	const uint32_t requires_rights;
};

struct acl_private{
	bool perform_check;
};

bool is_root_base_dn(struct ldb_context *ldb, struct ldb_dn *dn_to_check)
{
	int result;
	struct ldb_dn *root_base_dn = ldb_get_root_basedn(ldb);
	result = ldb_dn_compare(root_base_dn,dn_to_check);
	return (result==0);
}

static enum security_user_level what_is_user(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct auth_session_info *session_info
		= (struct auth_session_info *)ldb_get_opaque(ldb, "sessionInfo");
	return security_session_user_level(session_info);
}

static struct security_token *acl_user_token(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct auth_session_info *session_info
		= (struct auth_session_info *)ldb_get_opaque(ldb, "sessionInfo");
	if(!session_info) {
		return NULL;
	}
	return session_info->security_token;
}

static int acl_module_init(struct ldb_module *module)
{
	struct ldb_context *ldb;
	struct acl_private *data;
	int ret;

	ldb = ldb_module_get_ctx(module);

	ret = ldb_mod_register_control(module, LDB_CONTROL_SD_FLAGS_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "acl_module_init: Unable to register control with rootdse!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	data = talloc(module, struct acl_private);
	data->perform_check = lp_parm_bool(ldb_get_opaque(ldb, "loadparm"),
				  NULL, "acl", "perform", false);
	ldb_module_set_private(module, data);

	return ldb_next_init(module);
}

static int get_sd_from_result(TALLOC_CTX *mem_ctx,
			      struct ldb_result *acl_res,
			      struct security_descriptor **sd)
{
	struct ldb_message_element *sd_element;
	enum ndr_err_code ndr_err;

	sd_element = ldb_msg_find_element(acl_res->msgs[0], "ntSecurityDescriptor");
	if (!sd_element) {
		return LDB_SUCCESS;
	}
	*sd = talloc(mem_ctx, struct security_descriptor);
	if(!*sd) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ndr_err = ndr_pull_struct_blob(&sd_element->values[0], *sd, NULL, *sd,
				       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
	       return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

static const struct GUID *get_oc_guid_from_result(struct ldb_module *module,
					    struct ldb_result *acl_res)
{
	struct ldb_message_element *oc_el;
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	oc_el = ldb_msg_find_element(acl_res->msgs[0], "objectClass");
	if (!oc_el) {
		return NULL;
	}

	return class_schemaid_guid_by_lDAPDisplayName(dsdb_get_schema(ldb),
						      (char *)oc_el->values[oc_el->num_values-1].data);
}

static void acl_debug(struct security_descriptor *sd,
		      struct security_token *token,
		      struct ldb_dn *dn,
		      bool denied,
		      int level)
{
	if (denied) {
		DEBUG(level, ("Access on %s denied", ldb_dn_get_linearized(dn)));
	} else {
		DEBUG(level, ("Access on %s granted", ldb_dn_get_linearized(dn)));
	}

	DEBUG(level,("Security context: %s\n",
		     ndr_print_struct_string(0,(ndr_print_fn_t)ndr_print_security_token,"", token)));
	DEBUG(level,("Security descriptor: %s\n",
		     ndr_print_struct_string(0,(ndr_print_fn_t)ndr_print_security_descriptor,"", sd)));
}

static int check_access_on_dn(struct ldb_module *module,
			      TALLOC_CTX *mem_ctx,
			      struct ldb_dn *dn,
			      uint32_t access,
			      struct object_tree *tree)
{
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_result *acl_res;
	struct security_descriptor *sd = NULL;
	NTSTATUS status;
	uint32_t access_granted;
	static const char *acl_attrs[] = {
		"nTSecurityDescriptor",
		NULL
	};

	ret = ldb_search(ldb, mem_ctx, &acl_res, dn, LDB_SCOPE_BASE, acl_attrs, NULL);
	/* we sould be able to find the parent */
	if (ret != LDB_SUCCESS) {
		DEBUG(10,("acl: failed to find object %s\n", ldb_dn_get_linearized(dn)));
		return ret;
	}

	ret = get_sd_from_result(mem_ctx, acl_res, &sd);
	if (ret != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/* Theoretically we pass the check if the object has no sd */
	if (!sd) {
		return LDB_SUCCESS;
	}
	status = sec_access_check_ds(sd, acl_user_token(module),
				     access,
				     &access_granted,
				     tree);
	if (!NT_STATUS_IS_OK(status)) {
		acl_debug(sd,
			  acl_user_token(module),
			  dn,
			  true,
			  10);
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}
	return LDB_SUCCESS;
}

static int acl_add(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_dn *parent = ldb_dn_get_parent(req, req->op.add.message->dn);
	struct ldb_context *ldb;
	struct ldb_message_element *oc_el;
	const struct GUID *guid;
	struct object_tree *root = NULL;
	struct object_tree *new_node = NULL;

	if (what_is_user(module) == SECURITY_SYSTEM) {
		return ldb_next_request(module, req);
	}

	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}
	ldb = ldb_module_get_ctx(module);
	/* Creating an NC. There is probably something we should do here,
	 * but we will establish that later */
	if ((ldb_dn_compare(req->op.add.message->dn, (ldb_get_schema_basedn(ldb))) == 0) ||
	    (ldb_dn_compare(req->op.add.message->dn, (ldb_get_config_basedn(ldb))) == 0) ||
	    (ldb_dn_compare(req->op.add.message->dn, (ldb_get_root_basedn(ldb))) == 0)) {
		return ldb_next_request(module, req);
	}

	oc_el = ldb_msg_find_element(req->op.add.message, "objectClass");
	if (!oc_el || oc_el->num_values == 0) {
		DEBUG(10,("acl:operation error %s\n", ldb_dn_get_linearized(req->op.add.message->dn)));
		return ldb_module_done(req, NULL, NULL, LDB_ERR_OPERATIONS_ERROR);
	}

	guid = class_schemaid_guid_by_lDAPDisplayName(dsdb_get_schema(ldb),
						      (char *)oc_el->values[oc_el->num_values-1].data);

	if (!insert_in_object_tree(req, guid, SEC_ADS_CREATE_CHILD, &root, &new_node)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = check_access_on_dn(module, req, parent, SEC_ADS_CREATE_CHILD, root);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, req);
}

static int acl_modify(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct dsdb_schema *schema = dsdb_get_schema(ldb);
	int i;
	bool modify_sd = false;
	const struct GUID *guid;
	uint32_t access_granted;
	struct object_tree *root = NULL;
	struct object_tree *new_node = NULL;
	NTSTATUS status;
	struct ldb_result *acl_res;
	struct security_descriptor *sd;
	TALLOC_CTX *tmp_ctx = talloc_new(req);
	static const char *acl_attrs[] = {
		"nTSecurityDescriptor",
		"objectClass",
		NULL
	};

	DEBUG(10, ("ldb:acl_modify: %s\n", req->op.mod.message->elements[0].name));
	if (what_is_user(module) == SECURITY_SYSTEM) {
		return ldb_next_request(module, req);
	}
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}
	ret = ldb_search(ldb, req, &acl_res, req->op.mod.message->dn,
			 LDB_SCOPE_BASE, acl_attrs, NULL);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = get_sd_from_result(req, acl_res, &sd);
	if (ret != LDB_SUCCESS) {
		DEBUG(10, ("acl_modify: cannot get descriptor\n"));
		return ret;
	}
	/* Theoretically we pass the check if the object has no sd */
	if (!sd) {
		return LDB_SUCCESS;
	}

	guid = get_oc_guid_from_result(module,acl_res);
	if (!guid) {
		DEBUG(10, ("acl_modify: cannot get guid\n"));
		goto fail;
	}

	if (!insert_in_object_tree(tmp_ctx, guid, SEC_ADS_WRITE_PROP,
				 &root, &new_node)) {
		DEBUG(10, ("acl_modify: cannot add to object tree\n"));
		goto fail;
	}
	for (i=0; i < req->op.mod.message->num_elements; i++){
		const struct dsdb_attribute *attr;
		/* clearTextPassword is not in schema */
		if (strcmp("clearTextPassword", req->op.mod.message->elements[i].name) == 0) {
			attr = dsdb_attribute_by_lDAPDisplayName(schema, "unicodePwd");
		} else {
			attr = dsdb_attribute_by_lDAPDisplayName(schema,
								 req->op.mod.message->elements[i].name);
		}
		if (strcmp("nTSecurityDescriptor", req->op.mod.message->elements[i].name) == 0) {
			modify_sd = true;
		} else {

			if (!attr) {
				DEBUG(10, ("acl_modify: cannot find attribute %s\n",
					   req->op.mod.message->elements[i].name));
				goto fail;
			}
			if (!insert_in_object_tree(tmp_ctx,
						   &attr->attributeSecurityGUID, SEC_ADS_WRITE_PROP,
						   &new_node, &new_node)) {
				DEBUG(10, ("acl_modify: cannot add to object tree securityGUID\n"));
				goto fail;
			}

			if (!insert_in_object_tree(tmp_ctx,
						   &attr->schemaIDGUID, SEC_ADS_WRITE_PROP, &new_node, &new_node)) {
				DEBUG(10, ("acl_modify: cannot add to object tree attributeGUID\n"));
				goto fail;
			}
		}
	}

	if (root->num_of_children > 0) {
		status = sec_access_check_ds(sd, acl_user_token(module),
					     SEC_ADS_WRITE_PROP,
					     &access_granted,
					     root);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("Object %s nas no write property access\n",
				  ldb_dn_get_linearized(req->op.mod.message->dn)));
			acl_debug(sd,
				  acl_user_token(module),
				  req->op.mod.message->dn,
				  true,
				  10);
			talloc_free(tmp_ctx);
			return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
		}
	}
	if (modify_sd) {
		status = sec_access_check_ds(sd, acl_user_token(module),
				     SEC_STD_WRITE_DAC,
				     &access_granted,
				     NULL);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("Object %s nas no write dacl access\n",
				   ldb_dn_get_linearized(req->op.mod.message->dn)));
			acl_debug(sd,
				  acl_user_token(module),
				  req->op.mod.message->dn,
				  true,
				  10);
			talloc_free(tmp_ctx);
			return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
		}
	}

	talloc_free(tmp_ctx);
	return ldb_next_request(module, req);
fail:
	talloc_free(tmp_ctx);
	return LDB_ERR_OPERATIONS_ERROR;
}

/* similar to the modify for the time being.
 * We need to concider the special delete tree case, though - TODO */
static int acl_delete(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_dn *parent = ldb_dn_get_parent(req, req->op.del.dn);
	struct ldb_context *ldb;

	DEBUG(10, ("ldb:acl_delete: %s\n", ldb_dn_get_linearized(req->op.del.dn)));
	if (what_is_user(module) == SECURITY_SYSTEM) {
		return ldb_next_request(module, req);
	}

	if (ldb_dn_is_special(req->op.del.dn)) {
		return ldb_next_request(module, req);
	}
	ldb = ldb_module_get_ctx(module);
	/* first check if we have delete object right */
	ret = check_access_on_dn(module, req, req->op.del.dn, SEC_STD_DELETE, NULL);
	if (ret == LDB_SUCCESS) {
		return ldb_next_request(module, req);
	}

	/* Nope, we don't have delete object. Lets check if we have delete child on the parent */
	/* No parent, so check fails */
	if ((ldb_dn_compare(req->op.del.dn, (ldb_get_schema_basedn(ldb))) == 0) ||
	    (ldb_dn_compare(req->op.del.dn, (ldb_get_config_basedn(ldb))) == 0) ||
	    (ldb_dn_compare(req->op.del.dn, (ldb_get_root_basedn(ldb))) == 0)) {
		DEBUG(10,("acl:deleting an NC\n"));
		return ldb_module_done(req, NULL, NULL, LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS);
	}

	ret = check_access_on_dn(module, req, parent, SEC_ADS_DELETE_CHILD, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(module, req);
}

static int acl_rename(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	struct ldb_dn *oldparent = ldb_dn_get_parent(req, req->op.rename.olddn);
	struct ldb_dn *newparent = ldb_dn_get_parent(req, req->op.rename.newdn);
	struct ldb_context *ldb;
	struct security_descriptor *sd = NULL;
	struct ldb_result *acl_res;
	const struct GUID *guid;
	struct object_tree *root = NULL;
	struct object_tree *new_node = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(req);
	NTSTATUS status;
	uint32_t access_granted;
	static const char *acl_attrs[] = {
		"nTSecurityDescriptor",
		"objectClass",
		NULL
	};

	DEBUG(10, ("ldb:acl_rename: %s\n", ldb_dn_get_linearized(req->op.rename.olddn)));
	if (what_is_user(module) == SECURITY_SYSTEM) {
		return ldb_next_request(module, req);
	}
	if (ldb_dn_is_special(req->op.rename.olddn)) {
		return ldb_next_request(module, req);
	}
	ldb = ldb_module_get_ctx(module);

	/* search to include deleted objects */
	ret = ldb_search(ldb, req, &acl_res, req->op.rename.olddn,
			 LDB_SCOPE_BASE, acl_attrs, NULL);
	/* we sould be able to find the parent */
	if (ret != LDB_SUCCESS) {
		DEBUG(10,("acl: failed to find object %s\n",
			  ldb_dn_get_linearized(req->op.rename.olddn)));
		return ret;
	}

	guid = get_oc_guid_from_result(module,acl_res);
	if (!insert_in_object_tree(tmp_ctx, guid, SEC_ADS_WRITE_PROP,
				   &root, &new_node)) {
		return LDB_ERR_OPERATIONS_ERROR;
	};

	guid = attribute_schemaid_guid_by_lDAPDisplayName(dsdb_get_schema(ldb),
							  "name");
	if (!insert_in_object_tree(tmp_ctx, guid, SEC_ADS_WRITE_PROP,
				   &new_node, &new_node)) {
		return LDB_ERR_OPERATIONS_ERROR;
	};

	ret = get_sd_from_result(req, acl_res, &sd);

	if (ret != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/* Theoretically we pass the check if the object has no sd */
	if (!sd) {
		return LDB_SUCCESS;
	}
	status = sec_access_check_ds(sd, acl_user_token(module),
				     SEC_ADS_WRITE_PROP,
				     &access_granted,
				     root);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Object %s nas no wp on name\n",
			   ldb_dn_get_linearized(req->op.rename.olddn)));
		acl_debug(sd,
			  acl_user_token(module),
			  req->op.rename.olddn,
			  true,
			  10);
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}

	if (ldb_dn_compare(oldparent, newparent) == 0) {
		/* regular rename, not move, nothing more to do */
		return ldb_next_request(module, req);
	}

	/* What exactly to do in this case? It would fail anyway.. */
	if ((ldb_dn_compare(req->op.rename.newdn, (ldb_get_schema_basedn(ldb))) == 0) ||
	    (ldb_dn_compare(req->op.rename.newdn, (ldb_get_config_basedn(ldb))) == 0) ||
	    (ldb_dn_compare(req->op.rename.newdn, (ldb_get_root_basedn(ldb))) == 0)) {
		DEBUG(10,("acl:moving as an NC\n"));
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
		}
	/* new parent should have create child */
	talloc_free(tmp_ctx);
	tmp_ctx = talloc_new(req);
	root = NULL;
	new_node = NULL;
	guid = get_oc_guid_from_result(module,acl_res);
	if (!guid) {
		DEBUG(10,("acl:renamed object has no object class\n"));
		return ldb_module_done(req, NULL, NULL,  LDB_ERR_OPERATIONS_ERROR);
	}
	if (!insert_in_object_tree(tmp_ctx, guid, SEC_ADS_CREATE_CHILD,
				   &root, &new_node)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = check_access_on_dn(module, req, newparent, SEC_ADS_CREATE_CHILD, root);
	if (ret != LDB_SUCCESS) {
		DEBUG(10,("acl:access_denied renaming %s", ldb_dn_get_linearized(req->op.rename.olddn)));
		return ret;
	}
	/* do we have delete object on the object? */

	status = sec_access_check_ds(sd, acl_user_token(module),
				     SEC_STD_DELETE,
				     &access_granted,
				     NULL);

	if (NT_STATUS_IS_OK(status)) {
		return ldb_next_request(module, req);
	}
	/* what about delete child on the current parent */
	ret = check_access_on_dn(module, req, oldparent, SEC_ADS_DELETE_CHILD, NULL);
	if (ret != LDB_SUCCESS) {
		DEBUG(10,("acl:access_denied renaming %s", ldb_dn_get_linearized(req->op.rename.olddn)));
		return ldb_module_done(req, NULL, NULL, ret);
	}
	return ldb_next_request(module, req);
}

_PUBLIC_ const struct ldb_module_ops ldb_acl_module_ops = {
	.name		   = "acl",
	.add               = acl_add,
	.modify            = acl_modify,
	.del               = acl_delete,
	.rename            = acl_rename,
	.init_context	   = acl_module_init
};
