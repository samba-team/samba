/*
   ldb database library

   Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2014

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
 *  Name: tombstone_reanimate
 *
 *  Component: Handle Tombstone reanimation requests
 *
 *  Description:
 *  	Tombstone reanimation requests are plain ldap modify request like:
 *  	  dn: CN=tombi 1\0ADEL:e6e17ff7-8986-4cdd-87ad-afb683ccbb89,CN=Deleted Objects,DC=samba4,DC=devel
 *  	  changetype: modify
 *  	  delete: isDeleted
 *  	  -
 *  	  replace: distinguishedName
 *  	  distinguishedName: CN=Tombi 1,CN=Users,DC=samba4,DC=devel
 *  	  -
 *
 *	Usually we don't allow distinguishedName modifications (see rdn_name.c)
 *	Reanimating Tombstones is described here:
 *	  - http://msdn.microsoft.com/en-us/library/cc223467.aspx
 *
 *  Author: Kamen Mazdrashki
 */


#include "includes.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "auth/auth.h"
#include "param/param.h"
#include "../libds/common/flags.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "libds/common/flag_mapping.h"

struct tr_context {
	struct ldb_module *module;

	struct ldb_request *req;
	const struct ldb_message *req_msg;

	struct ldb_result *search_res;
	const struct ldb_message *search_msg;

	struct ldb_message *mod_msg;
	struct ldb_result *mod_res;
	struct ldb_request *mod_req;

	struct ldb_dn *rename_dn;
	struct ldb_result *rename_res;
	struct ldb_request *rename_req;

	const struct dsdb_schema *schema;
};

static struct tr_context *tr_init_context(struct ldb_module *module,
					  struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct tr_context *ac;

	ac = talloc_zero(req, struct tr_context);
	if (ac == NULL) {
		ldb_oom(ldb);
		return NULL;
	}

	ac->module = module;
	ac->req = req;
	ac->req_msg = req->op.mod.message;
	ac->schema = dsdb_get_schema(ldb, ac);

	return ac;
}


static bool is_tombstone_reanimate_request(struct ldb_request *req,
					   const struct ldb_message_element **pel_dn)
{
	struct ldb_message_element *el_dn;
	struct ldb_message_element *el_deleted;

	/* check distinguishedName requirement */
	el_dn = ldb_msg_find_element(req->op.mod.message, "distinguishedName");
	if (el_dn == NULL) {
		return false;
	}
	if (el_dn->flags != LDB_FLAG_MOD_REPLACE) {
		return false;
	}
	if (el_dn->num_values != 1) {
		return false;
	}

	/* check isDeleted requirement */
	el_deleted = ldb_msg_find_element(req->op.mod.message, "isDeleted");
	if (el_deleted == NULL) {
		return false;
	}

	if (el_deleted->flags != LDB_FLAG_MOD_DELETE) {
		return false;
	}

	*pel_dn = el_dn;
	return true;
}

/**
 * Local rename implementation based on dsdb_module_rename()
 * so we could fine tune it and add more controls
 */
static int tr_prepare_rename(struct tr_context *ac,
			     const struct ldb_message_element *new_dn)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	int ret;

	ac->rename_dn = ldb_dn_from_ldb_val(ac, ldb, &new_dn->values[0]);
	if (ac->rename_dn == NULL) {
		return ldb_module_oom(ac->module);
	}

	ac->rename_res = talloc_zero(ac, struct ldb_result);
	if (ac->rename_res == NULL) {
		return ldb_module_oom(ac->module);
	}

	ret = ldb_build_rename_req(&ac->rename_req, ldb, ac,
				   ac->req_msg->dn,
				   ac->rename_dn,
				   NULL,
				   ac->rename_res,
				   ldb_modify_default_callback,
				   ac->req);
	LDB_REQ_SET_LOCATION(ac->rename_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ret;
}

/**
 * Local rename implementation based on dsdb_module_modify()
 * so we could fine tune it and add more controls
 */
static int tr_do_down_req(struct tr_context *ac, struct ldb_request *down_req)
{
	int ret;

	/* We need this since object is 'delete' atm */
	ret = ldb_request_add_control(down_req,
				      LDB_CONTROL_SHOW_DELETED_OID,
				      false, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* mark request as part of Tombstone reanimation */
	ret = ldb_request_add_control(down_req,
				      DSDB_CONTROL_RESTORE_TOMBSTONE_OID,
				      false, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Run request from Next module */
	ret = ldb_next_request(ac->module, down_req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(down_req->handle, LDB_WAIT_ALL);
	}

	return ret;
}

static int tr_prepare_attributes(struct tr_context *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	int ret;
	struct ldb_message_element *el = NULL;
	uint32_t account_type, user_account_control;
	struct ldb_dn *objectcategory = NULL;

	ac->mod_msg = ldb_msg_copy_shallow(ac, ac->req_msg);
	if (ac->mod_msg == NULL) {
		return ldb_oom(ldb);
	}

	ac->mod_res = talloc_zero(ac, struct ldb_result);
	if (ac->mod_res == NULL) {
		return ldb_oom(ldb);
	}

	ret = ldb_build_mod_req(&ac->mod_req, ldb, ac,
				ac->mod_msg,
				NULL,
				ac->mod_res,
				ldb_modify_default_callback,
				ac->req);
	LDB_REQ_SET_LOCATION(ac->mod_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* - remove distinguishedName - we don't need it */
	ldb_msg_remove_attr(ac->mod_msg, "distinguishedName");

	/* remove isRecycled */
	ret = ldb_msg_add_empty(ac->mod_msg, "isRecycled",
				LDB_FLAG_MOD_DELETE, NULL);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Failed to reset isRecycled attribute: %s", ldb_strerror(ret));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* objectClass is USER */
	if (samdb_find_attribute(ldb, ac->search_msg, "objectclass", "user") != NULL) {
		uint32_t primary_group_rid;
		/* restoring 'user' instance attribute is heavily borrowed from samldb.c */

		/* Default values */
		ret = dsdb_user_obj_set_defaults(ldb, ac->mod_msg, ac->mod_req);
		if (ret != LDB_SUCCESS) return ret;

		/* "userAccountControl" must exists on deleted object */
		user_account_control = ldb_msg_find_attr_as_uint(ac->search_msg,
							"userAccountControl",
							(uint32_t)-1);
		if (user_account_control == (uint32_t)-1) {
			return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
					 "reanimate: No 'userAccountControl' attribute found!");
		}

		/* restore "sAMAccountType" */
		ret = dsdb_user_obj_set_account_type(ldb, ac->mod_msg,
						     user_account_control, NULL);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		/* "userAccountControl" -> "primaryGroupID" mapping */
		ret = dsdb_user_obj_set_primary_group_id(ldb, ac->mod_msg,
							 user_account_control,
							 &primary_group_rid);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		/*
		 * Older AD deployments don't know about the
		 * RODC group
		 */
		if (primary_group_rid == DOMAIN_RID_READONLY_DCS) {
			/* TODO:  check group exists */
		}

	}

	/* objectClass is GROUP */
	if (samdb_find_attribute(ldb, ac->search_msg, "objectclass", "group") != NULL) {
		/* "groupType" -> "sAMAccountType" */
		uint32_t group_type;

		el = ldb_msg_find_element(ac->search_msg, "groupType");
		if (el == NULL) {
			return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
					 "reanimate: Unexpected: missing groupType attribute.");
		}

		group_type = ldb_msg_find_attr_as_uint(ac->search_msg,
						       "groupType", 0);

		account_type = ds_gtype2atype(group_type);
		if (account_type == 0) {
			return ldb_error(ldb, LDB_ERR_UNWILLING_TO_PERFORM,
					 "reanimate: Unrecognized account type!");
		}
		ret = samdb_msg_add_uint(ldb, ac->mod_msg, ac->mod_msg,
					 "sAMAccountType", account_type);
		if (ret != LDB_SUCCESS) {
			return ldb_error(ldb, LDB_ERR_OPERATIONS_ERROR,
					 "reanimate: Failed to add sAMAccountType to restored object.");
		}
		el = ldb_msg_find_element(ac->mod_msg, "sAMAccountType");
		el->flags = LDB_FLAG_MOD_REPLACE;

		/* Default values set by Windows */
		ret = samdb_find_or_add_attribute(ldb, ac->mod_msg,
						  "adminCount", "0");
		if (ret != LDB_SUCCESS) return ret;
		ret = samdb_find_or_add_attribute(ldb, ac->mod_msg,
						  "operatorCount", "0");
		if (ret != LDB_SUCCESS) return ret;
	}

	/* - restore objectCategory if not present */
	objectcategory = ldb_msg_find_attr_as_dn(ldb, ac, ac->search_msg,
						 "objectCategory");
	if (objectcategory == NULL) {
		const char *value;

		ret = dsdb_make_object_category(ldb, ac->schema, ac->search_msg,
						ac->mod_msg, &value);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ret = ldb_msg_add_string(ac->mod_msg, "objectCategory", value);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		el = ldb_msg_find_element(ac->mod_msg, "objectCategory");
		el->flags = LDB_FLAG_MOD_ADD;
	}

	return LDB_SUCCESS;
}

/**
 * Handle special LDAP modify request to restore deleted objects
 */
static int tombstone_reanimate_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	const struct ldb_message_element *el_dn = NULL;
	struct tr_context *ac = NULL;
	int ret;

	ldb_debug(ldb, LDB_DEBUG_TRACE, "%s\n", __PRETTY_FUNCTION__);

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	/* Check if this is a reanimate request */
	if (!is_tombstone_reanimate_request(req, &el_dn)) {
		return ldb_next_request(module, req);
	}

	ac = tr_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	/* Load original object */
	ret = dsdb_module_search_dn(module, ac, &ac->search_res,
				    ac->req_msg->dn, NULL,
				    DSDB_FLAG_TOP_MODULE |
				    DSDB_SEARCH_SHOW_DELETED,
				    req);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}
	ac->search_msg = ac->search_res->msgs[0];

	/* check if it a Deleted Object */
	if (!ldb_msg_find_attr_as_bool(ac->search_msg, "isDeleted", false)) {
		return ldb_error(ldb, LDB_ERR_UNWILLING_TO_PERFORM, "Trying to restore not deleted object\n");
	}

	/* Simple implementation */

	/* prepare attributed depending on objectClass */
	ret = tr_prepare_attributes(ac);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Rename request to modify distinguishedName */
	ret = tr_prepare_rename(ac, el_dn);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* restore attributed depending on objectClass */
	ret = tr_do_down_req(ac, ac->mod_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Rename request to modify distinguishedName */
	ret = tr_do_down_req(ac, ac->rename_req);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Renaming object to %s has failed with %s\n", el_dn->values[0].data, ldb_strerror(ret));
		if (ret != LDB_ERR_ENTRY_ALREADY_EXISTS && ret != LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS ) {
			/* Windows returns Operations Error in case we can't rename the object */
			return LDB_ERR_OPERATIONS_ERROR;
		}
		return ret;
	}

	return ldb_module_done(ac->req, NULL, NULL, LDB_SUCCESS);
}


static const struct ldb_module_ops ldb_reanimate_module_ops = {
	.name		= "tombstone_reanimate",
	.modify		= tombstone_reanimate_modify,
};

int ldb_tombstone_reanimate_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_reanimate_module_ops);
}
