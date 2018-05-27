/* 
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006-2007
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
   Copyright (C) Matthias Dieter WallnÃ¶fer <mdw@samba.org> 2010-2011

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
 *  Component: ldb subtree rename module
 *
 *  Description: Rename a subtree in LDB
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include <ldb.h>
#include <ldb_module.h>
#include "libds/common/flags.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"

struct subtree_rename_context {
	struct ldb_module *module;
	struct ldb_request *req;
	bool base_renamed;
};

static struct subtree_rename_context *subren_ctx_init(struct ldb_module *module,
						      struct ldb_request *req)
{
	struct subtree_rename_context *ac;


	ac = talloc_zero(req, struct subtree_rename_context);
	if (ac == NULL) {
		return NULL;
	}

	ac->module = module;
	ac->req = req;
	ac->base_renamed = false;

	return ac;
}

static int subtree_rename_search_onelevel_callback(struct ldb_request *req,
						   struct ldb_reply *ares)
{
	struct subtree_rename_context *ac;
	int ret;

	ac = talloc_get_type(req->context, struct subtree_rename_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ac->base_renamed == false) {
		ac->base_renamed = true;

		ret = dsdb_module_rename(ac->module,
					 ac->req->op.rename.olddn,
					 ac->req->op.rename.newdn,
					 DSDB_FLAG_NEXT_MODULE, req);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
	{
		struct ldb_dn *old_dn = NULL;
		struct ldb_dn *new_dn = NULL;

		old_dn = ares->message->dn;
		new_dn = ldb_dn_copy(ares, old_dn);
		if (!new_dn) {
			return ldb_module_oom(ac->module);
		}

		if ( ! ldb_dn_remove_base_components(new_dn,
				ldb_dn_get_comp_num(ac->req->op.rename.olddn))) {
			return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
		}

		if ( ! ldb_dn_add_base(new_dn, ac->req->op.rename.newdn)) {
			return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
		}
		ret = dsdb_module_rename(ac->module, old_dn, new_dn, DSDB_FLAG_OWN_MODULE, req);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}

		talloc_free(ares);

		return LDB_SUCCESS;
	}
	case LDB_REPLY_REFERRAL:
		/* ignore */
		break;
	case LDB_REPLY_DONE:
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL, LDB_SUCCESS);
	default:
	{
		struct ldb_context *ldb = ldb_module_get_ctx(ac->module);

		ldb_asprintf_errstring(ldb, "Invalid LDB reply type %d", ares->type);
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	}

	return LDB_SUCCESS;
}

/* rename */
static int subtree_rename(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	static const char * const no_attrs[] = {NULL};
	struct ldb_request *search_req;
	struct subtree_rename_context *ac;
	int ret;

	if (ldb_dn_is_special(req->op.rename.olddn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	/*
	 * This gets complex:  We need to:
	 *  - Do a search for all entries under this entry
	 *  - Wait for these results to appear
	 *  - Do our own rename (in first callback)
	 *  - In the callback for each result, issue a dsdb_module_rename()
	 */

	ac = subren_ctx_init(module, req);
	if (!ac) {
		return ldb_oom(ldb);
	}

	ret = ldb_build_search_req(&search_req, ldb_module_get_ctx(ac->module), ac,
				   ac->req->op.rename.olddn,
				   LDB_SCOPE_ONELEVEL,
				   "(objectClass=*)",
				   no_attrs,
				   NULL,
				   ac,
				   subtree_rename_search_onelevel_callback,
				   req);
	LDB_REQ_SET_LOCATION(search_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_request_add_control(search_req, LDB_CONTROL_SHOW_RECYCLED_OID,
				      true, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, search_req);
}

static const struct ldb_module_ops ldb_subtree_rename_module_ops = {
	.name		   = "subtree_rename",
	.rename            = subtree_rename
};

int ldb_subtree_rename_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_subtree_rename_module_ops);
}
