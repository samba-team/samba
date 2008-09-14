/* 
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006-2007
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007

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
 *  Component: ldb subtree delete (prevention) module
 *
 *  Description: Prevent deletion of a subtree in LDB
 *
 *  Author: Andrew Bartlett
 */

#include "ldb_includes.h"

struct subtree_delete_context {
	enum sd_step {SD_SEARCH, SD_DO_DEL} step;

	struct ldb_module *module;
	struct ldb_handle *handle;
	struct ldb_request *orig_req;

	struct ldb_request *search_req;
	struct ldb_request *down_req;

	int num_children;
};

static struct subtree_delete_context *subtree_delete_init_handle(struct ldb_request *req, 
								 struct ldb_module *module)
{
	struct subtree_delete_context *ac;
	struct ldb_handle *h;

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct subtree_delete_context);
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

static int subtree_delete_check_for_children(struct subtree_delete_context *ac)
{
	if (ac->num_children > 0) {
		ldb_asprintf_errstring(ac->module->ldb, "Cannot delete %s, not a leaf node (has %d children)\n",
				       ldb_dn_get_linearized(ac->orig_req->op.del.dn), ac->num_children);
		return LDB_ERR_NOT_ALLOWED_ON_NON_LEAF;
	} else {
		struct ldb_request *req = talloc(ac, struct ldb_request);
		if (!req) {
			ldb_oom(ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		*req = *ac->orig_req;
		
		/* Ensure any (io) errors during the search for
		 * children don't propgate back in the error string */
		ldb_set_errstring(ac->module->ldb, NULL);

		ac->down_req = req;
		ac->step = SD_DO_DEL;
		return ldb_next_request(ac->module, req);
	}
}

static int subtree_delete_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares) 
{
	struct subtree_delete_context *ac = talloc_get_type(context, struct subtree_delete_context);
	TALLOC_CTX *mem_ctx = talloc_new(ac);
    
	if (!mem_ctx) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/* OK, we have one of *many* search results here:

	   We should also get the entry we tried to rename.  This
	   callback handles this and everything below it.
	 */

	/* Only entries are interesting, and we handle the case of the parent seperatly */
	if (ares->type == LDB_REPLY_ENTRY
	    && ldb_dn_compare(ares->message->dn, ac->orig_req->op.del.dn) != 0) {
		/* And it is an actual entry: now object bitterly that we are not a leaf node */
		ac->num_children++;
	}
	talloc_free(ares);
	return LDB_SUCCESS;
}

/* rename */
static int subtree_delete(struct ldb_module *module, struct ldb_request *req)
{
	const char *attrs[] = { NULL };
	struct ldb_request *new_req;
	struct subtree_delete_context *ac;
	int ret;
	if (ldb_dn_is_special(req->op.rename.olddn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	/* This gets complex:  We need to:
	   - Do a search for all entires under this entry 
	   - Wait for these results to appear
	   - In the callback for each result, count the children (if any)
	   - return an error if there are any
	*/

	ac = subtree_delete_init_handle(req, module);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&new_req, module->ldb, req,
				   req->op.del.dn, 
				   LDB_SCOPE_SUBTREE,
				   "(objectClass=*)",
				   attrs,
				   req->controls,
				   ac, 
				   subtree_delete_search_callback);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_set_timeout_from_prev_req(module->ldb, req, new_req);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->search_req = new_req;
	if (req == NULL) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	return ldb_next_request(module, new_req);
}


static int subtree_delete_wait_none(struct ldb_handle *handle) {
	struct subtree_delete_context *ac;
	int ret = LDB_ERR_OPERATIONS_ERROR;
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;
	handle->status = LDB_SUCCESS;

	ac = talloc_get_type(handle->private_data, struct subtree_delete_context);

	switch (ac->step) {
	case SD_SEARCH:
		ret = ldb_wait(ac->search_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_OBJECT) {
			handle->status = ret;
			goto done;
		}
		if (ac->search_req->handle->status != LDB_SUCCESS
			&& ac->search_req->handle->status != LDB_ERR_NO_SUCH_OBJECT) {
			handle->status = ac->search_req->handle->status;
			goto done;
		}

		return subtree_delete_check_for_children(ac);

	case SD_DO_DEL:
		ret = ldb_wait(ac->down_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->down_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->down_req->handle->status;
			goto done;
		}

		if (ac->down_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;
	}
done:
	handle->state = LDB_ASYNC_DONE;
	return ret;
}

static int subtree_delete_wait_all(struct ldb_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = subtree_delete_wait_none(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int subtree_delete_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return subtree_delete_wait_all(handle);
	} else {
		return subtree_delete_wait_none(handle);
	}
}

const struct ldb_module_ops ldb_subtree_delete_module_ops = {
	.name		   = "subtree_delete",
	.del               = subtree_delete,
	.wait              = subtree_delete_wait,
};
