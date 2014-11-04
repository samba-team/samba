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

struct tr_context {

	struct ldb_module *module;
	struct ldb_request *req;
	const struct dsdb_schema *schema;

	struct ldb_reply *search_res;
	struct ldb_reply *search_res2;

	int (*step_fn)(struct tr_context *);
};

static struct tr_context *tr_init_context(struct ldb_module *module,
					  struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct tr_context *ac;

	ldb = ldb_module_get_ctx(module);

	ac = talloc_zero(req, struct tr_context);
	if (ac == NULL) {
		ldb_oom(ldb);
		return NULL;
	}

	ac->module = module;
	ac->req = req;
	ac->schema = dsdb_get_schema(ldb, ac);

	return ac;
}


static bool is_tombstone_reanimate_request(struct ldb_request *req, struct ldb_message_element **pel_dn)
{
	struct ldb_message_element *el_dn;
	struct ldb_message_element *el_deleted;

	/* check distinguishedName requirement */
	el_dn = ldb_msg_find_element(req->op.mod.message, "distinguishedName");
	if (el_dn == NULL || el_dn->flags != LDB_FLAG_MOD_REPLACE) {
		return false;
	}

	/* check isDeleted requirement */
	el_deleted = ldb_msg_find_element(req->op.mod.message, "isDeleted");
	if (el_deleted == NULL || el_deleted->flags != LDB_FLAG_MOD_DELETE) {
		return false;
	}

	*pel_dn = el_dn;
	return true;
}

/**
 * Local rename implementation based on dsdb_module_rename()
 * so we could fine tune it and add more controls
 */
static int _tr_do_rename(struct ldb_module *module, struct ldb_request *parent_req,
			 struct ldb_dn *dn_from, struct ldb_dn *dn_to)
{
	int			ret;
	struct ldb_request	*req;
	struct ldb_context	*ldb = ldb_module_get_ctx(module);
	TALLOC_CTX		*tmp_ctx = talloc_new(parent_req);
	struct ldb_result	*res;

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb_module_get_ctx(module));
	}

	ret = ldb_build_rename_req(&req, ldb, tmp_ctx,
				   dn_from,
				   dn_to,
				   NULL,
				   res,
				   ldb_modify_default_callback,
				   parent_req);
	LDB_REQ_SET_LOCATION(req);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = dsdb_request_add_controls(req, DSDB_SEARCH_SHOW_DELETED);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* mark request as part of Tombstone reanimation */
	ret = ldb_request_add_control(req, DSDB_CONTROL_RESTORE_TOMBSTONE_OID, false, NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/*
	 * Run request from the top module
	 * so we get show_deleted control OID resolved
	 */
	ret = ldb_request(ldb_module_get_ctx(module), req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	talloc_free(tmp_ctx);
	return ret;
}

/**
 * Local rename implementation based on dsdb_module_modify()
 * so we could fine tune it and add more controls
 */
static int _tr_do_modify(struct ldb_module *module, struct ldb_request *parent_req, struct ldb_message *msg)
{
	int			ret;
	struct ldb_request	*mod_req;
	struct ldb_context	*ldb = ldb_module_get_ctx(module);
	TALLOC_CTX		*tmp_ctx = talloc_new(parent_req);
	struct ldb_result	*res;

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb_module_get_ctx(module));
	}

	ret = ldb_build_mod_req(&mod_req, ldb, tmp_ctx,
				msg,
				NULL,
				res,
				ldb_modify_default_callback,
				parent_req);
	LDB_REQ_SET_LOCATION(mod_req);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* mark request as part of Tombstone reanimation */
	ret = ldb_request_add_control(mod_req, DSDB_CONTROL_RESTORE_TOMBSTONE_OID, false, NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	/* Run request from Next module */
	ret = ldb_next_request(module, mod_req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(mod_req->handle, LDB_WAIT_ALL);
	}

	talloc_free(tmp_ctx);
	return ret;
}

/**
 * Handle special LDAP modify request to restore deleted objects
 */
static int tombstone_reanimate_modify(struct ldb_module *module, struct ldb_request *req)
{
	int				ret;
	struct ldb_context		*ldb;
	struct ldb_dn			*dn_new;
	struct ldb_dn			*objectcategory;
	struct ldb_message_element	*el_dn = NULL;
	struct ldb_message		*msg;
	struct ldb_result		*res_obj;
	struct tr_context		*ac;

	ldb = ldb_module_get_ctx(module);

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
	ret = dsdb_module_search_dn(module, req, &res_obj, req->op.mod.message->dn, NULL, DSDB_FLAG_TOP_MODULE | DSDB_SEARCH_SHOW_DELETED, req);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
	}
	/* check if it a Deleted Object */
	if (!ldb_msg_find_attr_as_bool(res_obj->msgs[0], "isDeleted", false)) {
		return ldb_error(ldb, LDB_ERR_UNWILLING_TO_PERFORM, "Trying to restore not deleted object\n");
	}

	/* Simple implementation */
	/* Rename request to modify distinguishedName */
	dn_new = ldb_dn_from_ldb_val(req, ldb, &el_dn->values[0]);
	if (dn_new == NULL) {
		return ldb_oom(ldb);
	}
	ret = _tr_do_rename(module, req, req->op.mod.message->dn, dn_new);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Renaming object to %s has failed with %s\n", el_dn->values[0].data, ldb_strerror(ret));
		if (ret != LDB_ERR_ENTRY_ALREADY_EXISTS) {
			/* Windows returns Operations Error in case we can't rename the object */
			return LDB_ERR_OPERATIONS_ERROR;
		}
		return ret;
	}

	/* Modify request to: */
	msg = ldb_msg_copy_shallow(ac, req->op.mod.message);
	if (msg == NULL) {
		return ldb_module_oom(ac->module);
	}
	msg->dn = dn_new;
	/* - delete isDeleted */
	ldb_msg_remove_attr(msg, "distinguishedName");

	/* - restore objectCategory if not present */
	objectcategory = ldb_msg_find_attr_as_dn(ldb, ac, msg,
						 "objectCategory");
	if (objectcategory == NULL) {
		const char *value;

		ret = dsdb_make_object_category(ldb, ac->schema, res_obj->msgs[0], msg, &value);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		ret = ldb_msg_add_string(msg, "objectCategory", value);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		msg->elements[msg->num_elements-1].flags = LDB_FLAG_MOD_ADD;
	}
	ret = _tr_do_modify(module, req, msg);
	if (ret != LDB_SUCCESS) {
		return ldb_operr(ldb);
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
