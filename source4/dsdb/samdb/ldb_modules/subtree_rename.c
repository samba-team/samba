/* 
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006-2007
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
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

#include "ldb_includes.h"

struct subtree_rename_context {
	struct ldb_module *module;
	struct ldb_handle *handle;
	struct ldb_request *orig_req;

	struct ldb_request **down_req;
	int num_requests;
	int finished_requests;
};

struct subtree_rename_search_context {
	struct ldb_module *module;
	struct ldb_request *orig_req;
	struct ldb_handle *handle;

	struct ldb_request **down_req;
	int num_requests;
	int finished_requests;
};

static struct subtree_rename_context *subtree_rename_init_handle(struct ldb_request *req, 
								 struct ldb_module *module)
{
	struct subtree_rename_context *ac;
	struct ldb_handle *h;

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct subtree_rename_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		talloc_free(h);
		return NULL;
	}

	h->private_data	= ac;

	ac->module = module;
	ac->handle = h;
	ac->orig_req = req;

	req->handle = h;

	return ac;
}


static int subtree_rename_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares) 
{
	/* OK, we have one of *many* search results here:

	   We should also get the entry we tried to rename.  This
	   callback handles this and everything below it.
	 */

	if (ares->type == LDB_REPLY_ENTRY) {
		/* And it is an actual entry: now create a rename from it */
		struct subtree_rename_context *ac = talloc_get_type(context, struct subtree_rename_context);
		struct ldb_request *req;
		int ret;

		TALLOC_CTX *mem_ctx = talloc_new(ac);
		
		struct ldb_dn *newdn = ldb_dn_copy(mem_ctx, ares->message->dn);
		if (!newdn) {
			ldb_oom(ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
			
		ldb_dn_remove_base_components(newdn, ldb_dn_get_comp_num(ac->orig_req->op.rename.olddn));

		if (!ldb_dn_add_base(newdn, ac->orig_req->op.rename.newdn)) {
			ldb_oom(ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = ldb_build_rename_req(&req, ldb, mem_ctx,
					   ares->message->dn,
					   newdn,
					   NULL,
					   NULL,
					   NULL);
		
		if (ret != LDB_SUCCESS) return ret;

		talloc_steal(req, newdn);

		req->handle = ac->handle;

		ac->down_req = talloc_realloc(ac, ac->down_req, 
					      struct ldb_request *, ac->num_requests + 1);
		if (!ac->down_req) {
			ldb_oom(ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ac->down_req[ac->num_requests] = req;
		
		return ldb_next_request(ac->module, req);

	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;

}

/* rename */
static int subtree_rename(struct ldb_module *module, struct ldb_request *req)
{
	const char *attrs[] = { NULL };
	struct ldb_request *new_req;
	struct subtree_rename_context *ac;
	int ret;
	struct ldb_search_options_control *search_options;
	if (ldb_dn_is_special(req->op.mod.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	/* This gets complex:  We need to:
	   - Do a search for all entires under this entry 
	   - Wait for these results to appear
	   - In the callback for each result, issue a modify request
	    - That will include this rename, we hope
	   - Wait for each modify result
	   - Regain our sainity 
	*/

	ac = subtree_rename_init_handle(req, module);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&new_req, module->ldb, req,
				   req->op.rename.olddn, 
				   LDB_SCOPE_SUBTREE,
				   "objectClass=*",
				   attrs,
				   req->controls,
				   ac, 
				   subtree_rename_search_callback);

	/* We want to find any partitions under this entry.  That way,
	 * if we try and rename a whole partition, the partitions
	 * module should cause us to fail the lot */
	search_options = talloc(ac, struct ldb_search_options_control);
	if (!search_options) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	search_options->search_options = LDB_SEARCH_OPTION_PHANTOM_ROOT;

	ret = ldb_request_add_control(new_req, LDB_CONTROL_SEARCH_OPTIONS_OID, false, search_options);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	new_req->handle = req->handle;

	ac->down_req = talloc_realloc(ac, ac->down_req, 
					struct ldb_request *, ac->num_requests + 1);
	if (!ac->down_req) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->down_req[ac->num_requests] = new_req;
	if (req == NULL) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	return ldb_next_request(module, req);
}

static int subtree_rename_wait_none(struct ldb_handle *handle) {
	struct subtree_rename_context *ac;
	int i, ret;
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;
	handle->status = LDB_SUCCESS;

	ac = talloc_get_type(handle->private_data, struct subtree_rename_context);

	for (i=0; i < ac->num_requests; i++) {
		ret = ldb_wait(ac->down_req[i]->handle, LDB_WAIT_NONE);
		
		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->down_req[i]->handle->status != LDB_SUCCESS) {
			handle->status = ac->down_req[i]->handle->status;
			goto done;
		}
		
		if (ac->down_req[i]->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}
	}

	ret = LDB_SUCCESS;

done:
	handle->state = LDB_ASYNC_DONE;
	return ret;

}

static int subtree_rename_wait_all(struct ldb_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = subtree_rename_wait_none(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int subtree_rename_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return subtree_rename_wait_all(handle);
	} else {
		return subtree_rename_wait_none(handle);
	}
}

static const struct ldb_module_ops subtree_rename_ops = {
	.name		   = "subtree_rename",
	.rename            = subtree_rename,
	.wait              = subtree_rename_wait,
};

int ldb_subtree_rename_init(void)
{
	return ldb_register_module(&subtree_rename_ops);
}
